//! Canonical File IRP dispatch for regular files on the mounted FAT volume.
//!
//! The installed layer is immutable. CREATE owns both a generation-fenced File context and an
//! installed open with independent handle-sharing and body references. CLEANUP releases sharing;
//! CLOSE releases the body and File context. Position and mode survive CLEANUP for pointer-owned
//! operations. No later operation re-resolves the name to select a different backing file.

use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;
use core::sync::atomic::{AtomicU64, Ordering};

use nt_io_abi::major;
use nt_io_manager::{
    DispatchContext, DispatchOutcome, DriverCompletion, DriverDispatchBackend, IoParameters, IrpId,
    IrpProjection,
};
use nt_status::NtStatus;

use crate::fs_loader::{
    fat_open_path_metadata_from, fat_read_file_range, fat_visit_directory_checked, FatOpenMetadata,
};

pub(crate) mod mounted_installed_read {
    pub(crate) use nt_fs::{ReadCompletions, ReadError, ReadSectorClaim};
}
use mounted_installed_read::ReadCompletions;
pub(crate) type MountedReadQueue = Rc<RefCell<ReadCompletions>>;
#[path = "mounted_create_lookup.rs"]
pub(crate) mod mounted_create_lookup;
use mounted_create_lookup::{CreateLookupFound, CreateLookupQueue};
#[path = "mounted_directory_lookup.rs"]
pub(crate) mod mounted_directory_lookup;
use mounted_directory_lookup::DirectoryLookupQueue;

const RESIDENT_BUSY: NtStatus = NtStatus(0x8000_0011u32 as i32);

static CREATE_DECISION_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static CREATE_BUSY_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);

struct CompletedCreate {
    owner: CapturedCreate,
    completion: DriverCompletion,
    published: bool,
}

pub(crate) struct CapturedCreate {
    irp: IrpId,
    file: nt_io_manager::FileId,
    name: Vec<u16>,
    relative: Vec<u8>,
    parameters: nt_io_manager::CreateParameters,
}

pub(crate) type MountedCreateQueue = Rc<RefCell<CreateLookupQueue<CapturedCreate>>>;

#[derive(Clone, Copy)]
struct OverlayCreateSpec {
    installed: Option<FatOpenMetadata>,
    copy_action: Option<nt_fs::InstalledFileOpenAction>,
    materialize_parent: bool,
    is_directory: bool,
}

enum CreateDecision {
    Dispatch(DispatchOutcome),
    Prepare(OverlayCreateSpec),
}

pub(crate) struct PreparedCreateOwner {
    owner: CapturedCreate,
    context: nt_fs::LayeredOpenContextId,
    spec: OverlayCreateSpec,
}

pub(crate) type MountedOverlayQueue = Rc<RefCell<nt_fs::OverlayPreparations<PreparedCreateOwner>>>;

pub(crate) struct CapturedDirectory {
    irp: IrpId,
    file: nt_io_manager::FileId,
    context: nt_fs::LayeredOpenContextId,
    relative: Vec<u8>,
    overlay_file: Option<u64>,
    parameters: nt_io_manager::DirectoryQueryParameters,
    return_single: bool,
    restart_scan: bool,
    output: Vec<u8>,
}

pub(crate) type MountedDirectoryQueue = Rc<RefCell<DirectoryLookupQueue<CapturedDirectory>>>;

struct CompletedDirectory {
    owner: CapturedDirectory,
    completion: DriverCompletion,
    published: bool,
}

#[path = "mounted_directory_query.rs"]
mod directory_query;
#[path = "mounted_directory_source.rs"]
mod directory_source;

// Directory and installed-file handles encode a 16-bit slot index plus a 16-bit generation.
// This is the identity-schema ceiling, not an eagerly allocated resource reservation.
const OPEN_CAP: usize = nt_fs::MAX_FAT_OPEN_SLOTS;
const PATH_CAP: usize = nt_fs::LAYERED_OPEN_NAME_CAP;

fn capture_manager_owned_query_fields(
    class: u32,
    input: &[u8],
    metadata: &mut nt_fs::QueryMetadata,
) -> Result<(), NtStatus> {
    if class == nt_fs::FILE_ALL_INFORMATION {
        nt_fs::capture_file_all_io_manager_information(input, metadata).map_err(status)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct MountedBinding {
    context: nt_fs::LayeredOpenContextId,
    /// A volume File participates in volume sharing until CLEANUP; its context remains until CLOSE.
    volume_share: Option<nt_fs::FileShareAccess>,
    installed_open: Option<u32>,
    installed_handle_open: bool,
    directory_open: Option<u32>,
    overlay_open: bool,
    is_directory: bool,
    granted_access: u32,
    create_options: u32,
    installed_directory_cluster: Option<u32>,
    directory_query: nt_fs::DirectoryQueryState,
}

pub(crate) struct MountedVolumeBackend {
    fs: crate::Fat32,
    opens: nt_fs::LayeredOpenTable<OPEN_CAP>,
    shares: nt_fs::ReadOnlyFileOpenTable<OPEN_CAP>,
    directories: nt_fs::DirectoryOpenTable<OPEN_CAP>,
    bindings: Vec<Option<MountedBinding>>,
    read_completions: MountedReadQueue,
    pending_creates: MountedCreateQueue,
    pending_overlays: MountedOverlayQueue,
    create_completions: Vec<CompletedCreate>,
    pending_directories: MountedDirectoryQueue,
    directory_completions: Vec<CompletedDirectory>,
}

impl MountedVolumeBackend {
    pub(crate) fn new(fs: crate::Fat32, pending_creates: MountedCreateQueue,
        pending_overlays: MountedOverlayQueue, read_completions: MountedReadQueue,
        pending_directories: MountedDirectoryQueue) -> Self {
        Self {
            fs,
            opens: nt_fs::LayeredOpenTable::new(),
            shares: nt_fs::ReadOnlyFileOpenTable::new(),
            directories: nt_fs::DirectoryOpenTable::new(),
            bindings: Vec::new(),
            read_completions,
            pending_creates,
            pending_overlays,
            create_completions: Vec::new(),
            pending_directories,
            directory_completions: Vec::new(),
        }
    }

    fn note_create_capacity_failure(&self, stage: &[u8], file_id: u64, error: NtStatus) {
        if error != NtStatus::INSUFFICIENT_RESOURCES { return; }
        crate::print_str(b"[mounted-create-capacity] stage=");
        crate::print_str(stage);
        crate::print_str(b" file=");
        crate::print_u64(file_id);
        crate::print_str(b" binding-slots=");
        crate::print_u64(self.bindings.len() as u64);
        crate::print_str(b" live-bindings=");
        crate::print_u64(self.bindings.iter().filter(|row| row.is_some()).count() as u64);
        crate::print_str(b" schema-slots=");
        crate::print_u64(OPEN_CAP as u64);
        crate::print_str(b"\n");
    }

    fn reserve_open_context(
        &mut self,
        file_id: u64,
        units: &[u16],
    ) -> Result<nt_fs::LayeredOpenContextId, NtStatus> {
        let context = match self.opens.reserve(file_id, units) {
            Ok(context) => context,
            Err(error) => {
                let error = status(error);
                self.note_create_capacity_failure(b"context", file_id, error);
                return Err(error);
            }
        };
        let index = context_index(context).expect("context index fits shared handle schema");
        if index >= self.bindings.len() {
            let additional = index + 1 - self.bindings.len();
            if self.bindings.try_reserve(additional).is_err() {
                self.opens.cancel(context, file_id).expect("unpublished context reservation");
                self.note_create_capacity_failure(b"binding", file_id, NtStatus::INSUFFICIENT_RESOURCES);
                return Err(NtStatus::INSUFFICIENT_RESOURCES);
            }
            self.bindings.resize(index + 1, None);
        }
        assert!(self.bindings[index].is_none(), "new context cannot reuse a retained binding");
        Ok(context)
    }

    fn create_lookup(&self, relative: &[u8]) -> Result<nt_fs::FatPathLookup, NtStatus> {
        let geometry = nt_fs::FatPathGeometry {
            fat_start_sector: self.fs.fat_start,
            data_start_sector: self.fs.data_start,
            total_sectors: self.fs.total_sectors,
            sectors_per_cluster: self.fs.spc,
        };
        nt_fs::FatPathLookup::new(geometry, self.fs.root_cl, relative)
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)
    }

    fn create(&mut self, irp: &IrpProjection) -> Result<DispatchOutcome, NtStatus> {
        let Some(file_id) = irp.file_id else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        let Some(name) = irp.file_name.as_ref() else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        let IoParameters::Create(parameters) = &irp.parameters else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        if parameters.ea_length != 0
            || parameters.create_options.bits() & nt_fs::FILE_OPEN_BY_FILE_ID != 0
        {
            return Err(NtStatus::NOT_SUPPORTED);
        }
        let access = parameters.desired_access.bits();
        let share = parameters.share_access.bits();
        let options = parameters.create_options.bits();
        nt_fs::validate_file_create_parameters(
            access,
            parameters.file_attributes,
            share,
            parameters.create_disposition,
            options,
        )
        .map_err(status)?;

        // The IRP retains the parent File through completion. Resolve its generation-fenced
        // driver open, while the child's FILE_OBJECT.FileName stays relative in the I/O Manager.
        let mut effective_name = [0u16; PATH_CAP];
        let units = if let Some(parent_file) = parameters.related_file {
            let (context, parent) = self
                .opens
                .get_by_file_id(parent_file.raw())
                .map_err(status)?;
            self.bindings[context_index(context).ok_or(NtStatus::INVALID_HANDLE)?]
                .filter(|binding| binding.context == context && binding.is_directory)
                .ok_or(status(nt_fs::STATUS_NOT_A_DIRECTORY))?;
            let length = nt_fs::join_layered_relative_name_into(
                parent.name,
                name.as_units(),
                &mut effective_name,
            )
            .map_err(status)?;
            &effective_name[..length]
        } else {
            name.as_units()
        };
        // An empty FILE_OBJECT.FileName without a related File opens the volume itself.
        // It has no component whose spelling could be folded; a single '\\' names the root
        // directory and continues through ordinary path lookup below.
        if units.is_empty() && parameters.related_file.is_none() {
            return self.create_volume(file_id.raw(), units, parameters);
        }
        if irp.create_case_sensitive {
            return Err(NtStatus::NOT_SUPPORTED);
        }
        // The retained full name is device-relative; the bounded FAT canonicalizer is only used
        // for lookup and sharing, not to replace the child's FILE_OBJECT spelling.
        let relative_name = units.strip_prefix(&[b'\\' as u16]).unwrap_or(units);
        let mut folded = [0; PATH_CAP];
        let mut relative = [0; PATH_CAP];
        let length = if relative_name.is_empty() {
            0
        } else {
            nt_fs::nt_file_relative_path_into(relative_name, &mut folded, &mut relative)
                .ok_or(NtStatus::OBJECT_NAME_INVALID)?
        };
        let relative = &relative[..length];

        let physical_mount = unsafe { crate::fs_loader::exec_fs_mount_identity() }
            .ok_or(NtStatus::DEVICE_NOT_READY)?;
        let route_kind = crate::fs_loader::exec_block_route_kind(physical_mount)
            .ok_or(NtStatus::DEVICE_NOT_READY)?;
        let journal_owned = crate::writable_fs::registry_journal::owns_volume();
        if route_kind != nt_fs::BlockSourceKind::Boot || journal_owned {
            let mut owned_name = Vec::new();
            owned_name.try_reserve_exact(units.len()).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
            owned_name.extend_from_slice(units);
            let mut owned_relative = Vec::new();
            owned_relative.try_reserve_exact(relative.len()).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
            owned_relative.extend_from_slice(relative);
            let owner = CapturedCreate { irp: irp.irp_id, file: file_id,
                name: owned_name, relative: owned_relative, parameters: *parameters };
            if journal_owned && route_kind == nt_fs::BlockSourceKind::Boot {
                self.pending_creates.borrow_mut().capture_deferred_boot(
                    irp.irp_id.raw(), physical_mount.value(), owner)
                    .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
            } else if relative.is_empty() {
                self.pending_creates.borrow_mut().capture_resolved_root(
                    irp.irp_id.raw(), physical_mount.value(), owner)
                    .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
            } else {
                let lookup = self.create_lookup(relative)?;
                self.pending_creates.borrow_mut().capture(
                    irp.irp_id.raw(), physical_mount.value(), owner, lookup)
                    .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
            }
            if route_kind == nt_fs::BlockSourceKind::Native {
                crate::service_sec_image::mounted_installer_file_trace::ingress(
                    irp.irp_id.raw(), file_id.raw(), physical_mount.value(), irp.major);
            }
            crate::service_sec_image::request_mounted_native_timer_rearm();
            return Ok(DispatchOutcome::Pending);
        }
        let installed = unsafe { fat_open_path_metadata_from(&self.fs, self.fs.root_cl, relative) };
        match self.create_decided(file_id.raw(), units, relative, installed, parameters, false)? {
            CreateDecision::Dispatch(outcome) => Ok(outcome),
            CreateDecision::Prepare(_) => unreachable!("Boot CREATE does not prepare native I/O"),
        }
    }

    fn create_volume(
        &mut self,
        file_id: u64,
        units: &[u16],
        parameters: &nt_io_manager::CreateParameters,
    ) -> Result<DispatchOutcome, NtStatus> {
        let options = parameters.create_options.bits();
        if options & nt_fs::FILE_DIRECTORY_FILE != 0 {
            return Err(status(nt_fs::STATUS_NOT_A_DIRECTORY));
        }
        if !matches!(parameters.create_disposition, nt_fs::FILE_OPEN | nt_fs::FILE_OPEN_IF) {
            return Err(NtStatus::ACCESS_DENIED);
        }
        let requested = nt_fs::FileShareAccess::new(
            parameters.desired_access.bits(), parameters.share_access.bits(),
        );
        if self.bindings.iter().flatten().filter_map(|binding| binding.volume_share)
            .any(|existing| !requested.compatible_with(existing))
        {
            return Err(status(nt_fs::STATUS_SHARING_VIOLATION));
        }
        let context = self.reserve_open_context(file_id, units)?;
        self.opens.finish(context, file_id, nt_fs::LayeredOpenSource::Volume)
            .expect("reserved volume File context");
        let index = context_index(context).expect("bounded layered context");
        self.bindings[index] = Some(MountedBinding {
            context,
            volume_share: Some(requested),
            installed_open: None,
            installed_handle_open: false,
            directory_open: None,
            overlay_open: false,
            is_directory: false,
            granted_access: parameters.desired_access.bits(),
            create_options: options,
            installed_directory_cluster: None,
            directory_query: nt_fs::DirectoryQueryState::default(),
        });
        Ok(DispatchOutcome::Completed {
            status: NtStatus::SUCCESS,
            information: nt_fs::FILE_OPENED as u64,
            file_context: Some(context.raw()),
        })
    }

    fn create_decided(
        &mut self,
        file_id: u64,
        units: &[u16],
        relative: &[u8],
        installed: Option<FatOpenMetadata>,
        parameters: &nt_io_manager::CreateParameters,
        resident_only: bool,
    ) -> Result<CreateDecision, NtStatus> {
        let access = parameters.desired_access.bits();
        let share = parameters.share_access.bits();
        let options = parameters.create_options.bits();
        let overlay = unsafe {
            if resident_only {
                crate::writable_fs::query_metadata_relative_if_mounted(relative)
            } else {
                crate::writable_fs::query_metadata_relative(relative)
            }
        }.map_err(status)?;
        if options & nt_fs::FILE_DIRECTORY_FILE != 0
            || overlay.is_some_and(|entry| entry.is_directory)
            || (overlay.is_none() && installed.is_some_and(|entry| entry.metadata.is_directory))
        {
            return self.create_directory(
                file_id,
                units,
                relative,
                installed,
                overlay,
                parameters,
                resident_only,
            );
        }
        let decision = nt_fs::layered_file_open_decision(
            Ok(overlay.is_some()),
            installed.is_some(),
            access,
            parameters.create_disposition,
            options,
        )
        .map_err(status)?;
        if resident_only
            && matches!(decision,
                nt_fs::LayeredFileOpenDecision::UseOverlay
                | nt_fs::LayeredFileOpenDecision::CreateOverlay
                | nt_fs::LayeredFileOpenDecision::Installed(
                    nt_fs::InstalledFileOpenAction::CopyContents
                    | nt_fs::InstalledFileOpenAction::CopyMetadata))
            && CREATE_DECISION_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 64
        {
            crate::print_str(b"[mounted-create-decision] path=\"");
            crate::print_str(&relative[..relative.len().min(120)]);
            crate::print_str(b"\" installed/overlay=");
            crate::print_u64(installed.is_some() as u64);
            crate::print_str(b"/");
            crate::print_u64(overlay.is_some() as u64);
            crate::print_str(b" access/disposition/options=");
            crate::print_u64(access as u64);
            crate::print_str(b"/");
            crate::print_u64(parameters.create_disposition as u64);
            crate::print_str(b"/");
            crate::print_u64(options as u64);
            crate::print_str(b" decision=");
            crate::print_str(match decision {
                nt_fs::LayeredFileOpenDecision::UseOverlay => b"use-overlay".as_slice(),
                nt_fs::LayeredFileOpenDecision::CreateOverlay => b"create-overlay".as_slice(),
                nt_fs::LayeredFileOpenDecision::Installed(nt_fs::InstalledFileOpenAction::ReadOnly) => b"installed-read".as_slice(),
                nt_fs::LayeredFileOpenDecision::Installed(nt_fs::InstalledFileOpenAction::CopyContents) => b"copy-contents".as_slice(),
                nt_fs::LayeredFileOpenDecision::Installed(nt_fs::InstalledFileOpenAction::CopyMetadata) => b"copy-metadata".as_slice(),
                nt_fs::LayeredFileOpenDecision::Installed(nt_fs::InstalledFileOpenAction::NameCollision) => b"collision".as_slice(),
            });
            crate::print_str(b"\n");
        }
        match decision {
            nt_fs::LayeredFileOpenDecision::Installed(nt_fs::InstalledFileOpenAction::ReadOnly) => {
                self.create_installed(
                    file_id,
                    units,
                    relative,
                    installed.unwrap(),
                    access,
                    share,
                    options,
                ).map(CreateDecision::Dispatch)
            }
            nt_fs::LayeredFileOpenDecision::Installed(
                nt_fs::InstalledFileOpenAction::NameCollision,
            ) => Err(NtStatus::OBJECT_NAME_COLLISION),
            nt_fs::LayeredFileOpenDecision::Installed(action) => self.create_overlay(
                file_id,
                units,
                relative,
                installed,
                Some(action),
                true,
                false,
                parameters,
                resident_only,
            ),
            nt_fs::LayeredFileOpenDecision::UseOverlay
            | nt_fs::LayeredFileOpenDecision::CreateOverlay => self.create_overlay(
                file_id,
                units,
                relative,
                installed,
                None,
                matches!(decision, nt_fs::LayeredFileOpenDecision::CreateOverlay),
                false,
                parameters,
                resident_only,
            ),
        }
    }

    /// This is called only by the outer I/O service turn, never from completion polling.
    fn service_resolved_create(&mut self) -> usize {
        let Some(mut resolved) = self.pending_creates.borrow_mut().take_resolved() else { return 0; };
        let deferred_boot = matches!(resolved.result, Ok(CreateLookupFound::DeferredBoot));
        if deferred_boot {
            if crate::writable_fs::registry_journal::owns_volume() {
                self.pending_creates.borrow_mut().restore_resolved(resolved)
                    .expect("journal-owned CREATE retains its exact pending owner");
                return 0;
            }
            let route = unsafe { crate::fs_loader::exec_fs_mount_identity() }
                .filter(|mount| mount.value() == resolved.mount)
                .and_then(crate::fs_loader::exec_block_route_kind);
            let Some(route) = route else {
                self.pending_creates.borrow_mut().restore_resolved(resolved)
                    .expect("unavailable mount retains its exact pending CREATE");
                return 0;
            };
            if route != nt_fs::BlockSourceKind::Boot {
                if resolved.payload.relative.is_empty() {
                    resolved.result = Ok(CreateLookupFound::Root);
                    self.pending_creates.borrow_mut().restore_resolved(resolved)
                        .expect("pending root CREATE retains its owner across route change");
                } else {
                    let lookup = match self.create_lookup(&resolved.payload.relative) {
                        Ok(lookup) => lookup,
                        Err(_) => {
                            resolved.result = Err(nt_fs::FatPathError::NoCapacity);
                            self.pending_creates.borrow_mut().restore_resolved(resolved)
                                .expect("failed lookup admission retains terminal CREATE");
                            return 1;
                        }
                    };
                    let irp = resolved.irp;
                    let mount = resolved.mount;
                    self.pending_creates.borrow_mut().restore_resolved(resolved)
                        .expect("pending CREATE retains its owner across route change");
                    self.pending_creates.borrow_mut().activate_deferred_boot(irp, mount, lookup)
                        .expect("restored deferred CREATE can activate only its exact lookup");
                    crate::service_sec_image::request_mounted_native_timer_rearm();
                }
                return 1;
            }
        }
        if self.create_completions.try_reserve(1).is_err() {
            self.pending_creates.borrow_mut().restore_resolved(resolved)
                .expect("a removed queue entry retains its allocation");
            return 0;
        }
        let installed = match resolved.result {
            Ok(CreateLookupFound::Path(record)) => record.map(FatOpenMetadata::from_record),
            Ok(CreateLookupFound::Root) => Some(crate::fs_loader::fat_root_metadata(&self.fs)),
            Ok(CreateLookupFound::DeferredBoot) => {
                if resolved.payload.relative.is_empty() {
                    Some(crate::fs_loader::fat_root_metadata(&self.fs))
                } else {
                    unsafe { fat_open_path_metadata_from(&self.fs, self.fs.root_cl,
                        &resolved.payload.relative) }
                }
            },
            Err(error) => {
                let status = match error {
                    nt_fs::FatPathError::NoCapacity => NtStatus::INSUFFICIENT_RESOURCES,
                    _ => NtStatus(nt_fs::STATUS_DATA_ERROR as i32),
                };
                self.create_completions.push(CompletedCreate {
                    completion: DriverCompletion {
                        irp_id: resolved.payload.irp, status, information: 0,
                        file_context: None,
                    }, owner: resolved.payload, published: false,
                });
                return 1;
            }
        };
        let owner = &resolved.payload;
        let outcome = self.create_decided(owner.file.raw(), &owner.name, &owner.relative,
            installed, &owner.parameters, !deferred_boot);
        if let Ok(CreateDecision::Prepare(spec)) = &outcome {
                let mut spec = *spec;
                let mut parent_len = spec.materialize_parent.then(||
                    resolved.payload.relative.iter().rposition(|byte| *byte == b'\\')).flatten();
                if let Some(len) = parent_len {
                    if len >= PATH_CAP {
                        self.complete_failed_create(resolved.payload, NtStatus::OBJECT_NAME_INVALID);
                        return 1;
                    }
                    match unsafe { crate::writable_fs::query_metadata_relative_if_mounted(
                        &resolved.payload.relative[..len]) } {
                        Ok(Some(metadata)) if metadata.is_directory => {
                            spec.materialize_parent = false;
                            parent_len = None;
                        }
                        Ok(Some(_)) => {
                            self.complete_failed_create(resolved.payload, status(nt_fs::STATUS_NOT_A_DIRECTORY));
                            return 1;
                        }
                        Ok(None) => {},
                        Err(raw) if status(raw) == RESIDENT_BUSY => {
                            self.pending_creates.borrow_mut().restore_resolved(resolved)
                                .expect("busy parent lookup retains exact CREATE");
                            return 0;
                        }
                        Err(raw) => {
                            self.complete_failed_create(resolved.payload, status(raw));
                            return 1;
                        }
                    }
                }
                let file = resolved.payload.file.raw();
                let context = match self.reserve_open_context(file, &resolved.payload.name) {
                    Ok(context) => context,
                    Err(error) => {
                        self.complete_failed_create(resolved.payload, error);
                        return 1;
                    }
                };
                let mut parent = [0u8; PATH_CAP];
                if let Some(len) = parent_len {
                    parent[..len].copy_from_slice(&resolved.payload.relative[..len]);
                }
                let copy = match (spec.installed, spec.copy_action) {
                    (Some(source), Some(nt_fs::InstalledFileOpenAction::CopyContents)) => {
                        nt_fs::OverlayCopyPlan::Contents {
                            first_cluster: source.first_cluster,
                            length: match u32::try_from(source.metadata.end_of_file) {
                                Ok(length) => length,
                                Err(_) => {
                                    self.opens.cancel(context, file).expect("unpublished context");
                                    self.complete_failed_create(resolved.payload, NtStatus::INSUFFICIENT_RESOURCES);
                                    return 1;
                                }
                            },
                        }
                    }
                    (Some(_), Some(nt_fs::InstalledFileOpenAction::CopyMetadata)) =>
                        nt_fs::OverlayCopyPlan::MetadataOnly,
                    _ => nt_fs::OverlayCopyPlan::None,
                };
                let geometry = nt_fs::FatPathGeometry {
                    fat_start_sector: self.fs.fat_start, data_start_sector: self.fs.data_start,
                    total_sectors: self.fs.total_sectors, sectors_per_cluster: self.fs.spc,
                };
                let captured = PreparedCreateOwner { owner: resolved.payload, context, spec };
                let result = self.pending_overlays.borrow_mut().capture_owned(
                    resolved.irp, resolved.mount, captured, geometry, self.fs.root_cl,
                    parent_len.map(|len| &parent[..len]), copy);
                if let Err((error, captured)) = result {
                    self.opens.cancel(context, file).expect("unpublished context");
                    self.complete_failed_create(captured.owner, overlay_prepare_status(error));
                } else {
                    crate::service_sec_image::request_mounted_native_timer_rearm();
                }
                return 1;
        }
        if matches!(outcome, Err(RESIDENT_BUSY)) {
            if CREATE_BUSY_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 16 {
                crate::print_str(b"[mounted-create-busy] irp=");
                crate::print_u64(resolved.irp);
                crate::print_str(b" mount=");
                crate::print_u64(resolved.mount);
                crate::print_str(b" path=\"");
                crate::print_str(&owner.relative[..owner.relative.len().min(120)]);
                crate::print_str(b"\" deferred-boot=");
                crate::print_u64(deferred_boot as u64);
                crate::print_str(b" journal-owned=");
                crate::print_u64(crate::writable_fs::registry_journal::owns_volume() as u64);
                crate::print_str(b"\n");
            }
            self.pending_creates.borrow_mut().restore_resolved(resolved)
                .expect("a removed queue entry retains its allocation");
            return 0;
        }
        let (status, information, file_context) = match outcome {
            Ok(CreateDecision::Dispatch(DispatchOutcome::Completed { status, information, file_context })) =>
                (status, information, file_context),
            Ok(CreateDecision::Dispatch(DispatchOutcome::Failed { status })) | Err(status) => (status, 0, None),
            Ok(CreateDecision::Dispatch(DispatchOutcome::Pending)) => panic!("mounted CREATE decision cannot nest pending work"),
            Ok(CreateDecision::Prepare(_)) => unreachable!("prepared CREATE owner transferred"),
        };
        self.create_completions.push(CompletedCreate {
            completion: DriverCompletion {
                irp_id: resolved.payload.irp, status, information, file_context,
            }, owner: resolved.payload, published: false,
        });
        1
    }

    fn complete_failed_create(&mut self, owner: CapturedCreate, status: NtStatus) {
        self.create_completions.push(CompletedCreate {
            completion: DriverCompletion { irp_id: owner.irp, status, information: 0,
                file_context: None }, owner, published: false,
        });
    }

    fn service_prepared_overlay(&mut self) -> usize {
        if !self.pending_overlays.borrow().has_ready() ||
            self.create_completions.try_reserve(1).is_err() { return 0; }
        // The storage handoff owns Draining -> Native publication. A sectorless upper open
        // can become ready before that handoff; retain its IRP until the exact route is live.
        let ready_mount = self.pending_overlays.borrow().next_ready_identity()
            .map(|(_, mount)| mount);
        let route = unsafe { crate::fs_loader::exec_fs_mount_identity() }
            .filter(|mount| Some(mount.value()) == ready_mount)
            .and_then(crate::fs_loader::exec_block_route_kind);
        if route == Some(nt_fs::BlockSourceKind::Draining) { return 0; }
        // Only the journal's exact owner can wake a ready Native request. A retired mount has
        // no such signaler, even if the journal happens to be busy on a different volume.
        let resident = if route == Some(nt_fs::BlockSourceKind::Native) {
            unsafe { crate::writable_fs::prepared_overlay_resident() }
        } else {
            Err(nt_fs::STATUS_DEVICE_NOT_READY)
        };
        if resident == Ok(false) { return 0; }
        let Some(prepared) = self.pending_overlays.borrow_mut().take_next_ready() else {
            return 0;
        };
        let captured = prepared.payload;
        let file = captured.owner.file.raw();
        let context = captured.context;
        let terminal = if let Err(status) = resident {
            Err(NtStatus(status as i32))
        } else if unsafe { crate::fs_loader::exec_fs_mount_identity() }
            .is_none_or(|mount| mount.value() != prepared.mount ||
                crate::fs_loader::exec_block_route_kind(mount) != Some(nt_fs::BlockSourceKind::Native))
        {
            Err(NtStatus::DEVICE_NOT_READY)
        } else {
            match prepared.result {
                Err(error) => Err(overlay_prepare_status(error)),
                Ok(inputs) => self.finish_prepared_overlay(&captured, prepared.copy, inputs),
            }
        };
        match terminal {
            Ok((overlay_file, information)) => {
                self.opens.finish(context, file,
                    nt_fs::LayeredOpenSource::Overlay { file_id: overlay_file })
                    .expect("exact prepared CREATE context");
                let index = context_index(context).expect("bounded layered context");
                debug_assert!(self.bindings[index].is_none());
                self.bindings[index] = Some(MountedBinding {
                    context, volume_share: None, installed_open: None, installed_handle_open: false,
                    directory_open: None, overlay_open: true,
                    is_directory: captured.spec.is_directory,
                    granted_access: captured.owner.parameters.desired_access.bits(),
                    create_options: captured.owner.parameters.create_options.bits(),
                    installed_directory_cluster: captured.spec.installed
                        .filter(|source| captured.spec.is_directory && source.metadata.is_directory)
                        .map(|source| source.first_cluster),
                    directory_query: nt_fs::DirectoryQueryState::default(),
                });
                self.create_completions.push(CompletedCreate {
                    completion: DriverCompletion { irp_id: captured.owner.irp,
                        status: NtStatus::SUCCESS, information,
                        file_context: Some(context.raw()) },
                    owner: captured.owner, published: false,
                });
            }
            Err(status) => {
                self.opens.cancel(context, file).expect("unpublished prepared CREATE context");
                self.complete_failed_create(captured.owner, status);
            }
        }
        1
    }

    fn finish_prepared_overlay(&mut self, captured: &PreparedCreateOwner,
        copy: nt_fs::OverlayCopyPlan, inputs: nt_fs::PreparedOverlay)
        -> Result<(u64, u64), NtStatus>
    {
        let owner = &captured.owner;
        let relative = &owner.relative;
        let spec = captured.spec;
        if let Some(source) = spec.installed {
            if spec.is_directory {
                self.directories.check_share(relative, source.metadata,
                    owner.parameters.desired_access.bits(), owner.parameters.share_access.bits())
                    .map_err(status)?;
            } else {
                self.shares.check_share(relative, source.metadata,
                    owner.parameters.desired_access.bits(), owner.parameters.share_access.bits())
                    .map_err(status)?;
            }
        }
        let parent = relative.iter().rposition(|byte| *byte == b'\\')
            .filter(|_| spec.materialize_parent).map(|end| &relative[..end]);
        if parent.is_some() && inputs.parent.is_none() {
            return Err(NtStatus::OBJECT_PATH_NOT_FOUND);
        }
        let import = match (spec.installed, copy) {
            (Some(source), nt_fs::OverlayCopyPlan::Contents { .. }) =>
                Some((source.metadata, inputs.contents)),
            (Some(source), nt_fs::OverlayCopyPlan::MetadataOnly) => {
                let mut metadata = source.metadata;
                metadata.allocation_size = 0;
                metadata.end_of_file = 0;
                metadata.valid_data_length = 0;
                Some((metadata, Vec::new()))
            }
            _ => None,
        };
        let parameters = &owner.parameters;
        let (status, opened, information) = unsafe {
            crate::writable_fs::create_prepared_overlay_relative_if_mounted(relative, parent,
                import, parameters.desired_access.bits(), parameters.file_attributes,
                parameters.share_access.bits(), parameters.create_disposition,
                parameters.create_options.bits())
        };
        if status != nt_fs::STATUS_SUCCESS { return Err(NtStatus(status as i32)); }
        Ok((opened.expect("successful prepared CREATE owns File"), information))
    }

    fn service_resolved_directory(&mut self) -> usize {
        let Some(mut resolved) = self.pending_directories.borrow_mut().take_resolved() else { return 0; };
        if self.directory_completions.try_reserve(1).is_err() {
            self.pending_directories.borrow_mut().restore_resolved(resolved)
                .expect("removed directory lookup retains queue capacity");
            return 0;
        }
        let outcome = match &resolved.result {
            Err(error) => Err(match error {
                nt_fs::FatPathError::NoCapacity => NtStatus::INSUFFICIENT_RESOURCES,
                _ => status(nt_fs::STATUS_DATA_ERROR),
            }),
            Ok(installed) => {
                let owner = &mut resolved.payload;
                let overlay = unsafe {
                    if let Some(file) = owner.overlay_file {
                        crate::writable_fs::directory_entries_opened_if_mounted(file).map(Some)
                    } else {
                        crate::writable_fs::directory_entries_relative_if_mounted(&owner.relative)
                    }
                }.map_err(status);
                match overlay {
                    Err(error) => Err(error),
                    Ok(overlay) => (|| -> Result<(NtStatus, u64), NtStatus> {
                        let entries = nt_fs::merge_layered_directory_entries(
                            installed, overlay.as_deref().unwrap_or(&[])).map_err(status)?;
                        self.opens.get(owner.context, owner.file.raw()).map_err(status)?;
                        let index = context_index(owner.context).ok_or(NtStatus::INVALID_HANDLE)?;
                        let binding = self.bindings[index].as_mut()
                            .filter(|binding| binding.context == owner.context)
                            .ok_or(NtStatus::INVALID_HANDLE)?;
                        let mut query = binding.directory_query;
                        let result = nt_fs::query_directory(&mut query, &entries,
                            owner.parameters.information_class, owner.return_single,
                            owner.parameters.pattern.as_ref().map(|pattern| pattern.as_units()),
                            owner.restart_scan, &mut owner.output);
                        binding.directory_query = query;
                        Ok((status(result.status), result.information as u64))
                    })(),
                }
            }
        };
        if matches!(outcome, Err(RESIDENT_BUSY)) {
            self.pending_directories.borrow_mut().restore_resolved(resolved)
                .expect("removed directory lookup retains queue capacity");
            return 0;
        }
        let (status, information) = match outcome {
            Ok(value) => value,
            Err(error) => (error, 0),
        };
        self.directory_completions.push(CompletedDirectory {
            completion: DriverCompletion { irp_id: resolved.payload.irp, status,
                information, file_context: None },
            owner: resolved.payload, published: false,
        });
        1
    }

    fn create_directory(
        &mut self,
        file_id: u64,
        units: &[u16],
        relative: &[u8],
        installed: Option<FatOpenMetadata>,
        overlay: Option<nt_fs::FileMetadata>,
        parameters: &nt_io_manager::CreateParameters,
        resident_only: bool,
    ) -> Result<CreateDecision, NtStatus> {
        let access = parameters.desired_access.bits();
        let share = parameters.share_access.bits();
        let options = parameters.create_options.bits();
        let decision = nt_fs::layered_directory_open_decision(
            installed.map(|entry| entry.metadata.is_directory),
            overlay.map(|entry| entry.is_directory),
            parameters.create_disposition,
            options,
            relative.is_empty(),
        ).map_err(status)?;
        match decision {
            nt_fs::LayeredDirectoryOpenDecision::Installed => {
                let source = installed.expect("directory policy selected installed backing");
                // Directory ADD_FILE/ADD_SUBDIRECTORY grants apply to layered children, not writes
                // to immutable FAT bytes. Deleting a lower entry still requires whiteout support.
                if options & nt_fs::FILE_DELETE_ON_CLOSE != 0 {
                    return Err(NtStatus::NOT_SUPPORTED);
                }
                self.create_installed_directory(
                    file_id, units, relative, source, access, share, options,
                ).map(CreateDecision::Dispatch)
            }
            nt_fs::LayeredDirectoryOpenDecision::Overlay => {
                if let Some(source) = installed.filter(|source| source.metadata.is_directory) {
                    self.directories
                        .check_share(relative, source.metadata, access, share)
                        .map_err(status)?;
                }
                self.create_overlay(
                    file_id, units, relative, installed, None, false, true, parameters, resident_only,
                )
            }
            nt_fs::LayeredDirectoryOpenDecision::CreateOverlay => self.create_overlay(
                file_id, units, relative, None, None, true, true, parameters, resident_only,
            ),
        }
    }

    fn create_installed_directory(
        &mut self,
        file_id: u64,
        units: &[u16],
        relative: &[u8],
        installed: FatOpenMetadata,
        access: u32,
        share: u32,
        options: u32,
    ) -> Result<DispatchOutcome, NtStatus> {
        let context = self.reserve_open_context(file_id, units)?;
        let directory_open = match self.directories.create(
            installed.first_cluster,
            relative,
            access,
            share,
            options,
            installed.metadata,
            installed.alternate_name,
        ) {
            Ok(open) => open,
            Err(error) => {
                self.note_create_capacity_failure(b"directory", file_id, status(error));
                self.opens
                    .cancel(context, file_id)
                    .expect("owned reservation");
                return Err(status(error));
            }
        };
        self.opens
            .finish(
                context,
                file_id,
                nt_fs::LayeredOpenSource::Installed {
                    first_cluster: installed.first_cluster,
                    metadata: installed.metadata,
                    alternate_name: installed.alternate_name,
                },
            )
            .expect("owned reservation");
        let index = context_index(context).expect("bounded layered table context index");
        debug_assert!(self.bindings[index].is_none());
        self.bindings[index] = Some(MountedBinding {
            context,
            volume_share: None,
            installed_open: None,
            installed_handle_open: false,
            directory_open: Some(directory_open),
            overlay_open: false,
            is_directory: true,
            granted_access: access,
            create_options: options,
            installed_directory_cluster: Some(installed.first_cluster),
            directory_query: nt_fs::DirectoryQueryState::default(),
        });
        Ok(DispatchOutcome::Completed {
            status: NtStatus::SUCCESS,
            information: nt_fs::FILE_OPENED as u64,
            file_context: Some(context.raw()),
        })
    }

    fn create_installed(
        &mut self,
        file_id: u64,
        units: &[u16],
        relative: &[u8],
        installed: FatOpenMetadata,
        access: u32,
        share: u32,
        options: u32,
    ) -> Result<DispatchOutcome, NtStatus> {
        let context = self.reserve_open_context(file_id, units)?;
        let installed_open = match self.shares.create(
            installed.first_cluster,
            installed.metadata.end_of_file.min(u32::MAX as u64) as u32,
            relative,
            access,
            share,
            options,
            installed.metadata,
            installed.alternate_name,
        ) {
            Ok(installed_open) => installed_open,
            Err(error) => {
                self.note_create_capacity_failure(b"installed-file", file_id, status(error));
                self.opens
                    .cancel(context, file_id)
                    .expect("owned reservation");
                return Err(status(error));
            }
        };
        if let Err(error) = self.shares.retain_io(installed_open) {
            self.shares.release(installed_open).expect("unpublished installed handle");
            self.opens.cancel(context, file_id).expect("owned reservation");
            return Err(status(error));
        }
        self.opens
            .finish(
                context,
                file_id,
                nt_fs::LayeredOpenSource::Installed {
                    first_cluster: installed.first_cluster,
                    metadata: installed.metadata,
                    alternate_name: installed.alternate_name,
                },
            )
            .expect("owned reservation");
        let index = context_index(context).expect("bounded layered table context index");
        debug_assert!(self.bindings[index].is_none());
        self.bindings[index] = Some(MountedBinding {
            context,
            volume_share: None,
            installed_open: Some(installed_open),
            installed_handle_open: true,
            directory_open: None,
            overlay_open: false,
            is_directory: false,
            granted_access: access,
            create_options: options,
            installed_directory_cluster: None,
            directory_query: nt_fs::DirectoryQueryState::default(),
        });
        Ok(DispatchOutcome::Completed {
            status: NtStatus::SUCCESS,
            information: nt_fs::FILE_OPENED as u64,
            file_context: Some(context.raw()),
        })
    }

    fn create_overlay(
        &mut self,
        file_id: u64,
        units: &[u16],
        relative: &[u8],
        installed: Option<FatOpenMetadata>,
        copy_action: Option<nt_fs::InstalledFileOpenAction>,
        materialize_parent: bool,
        is_directory: bool,
        parameters: &nt_io_manager::CreateParameters,
        resident_only: bool,
    ) -> Result<CreateDecision, NtStatus> {
        // Native CREATE owns its immutable inputs in OverlayPreparations. This backend turn
        // must not enter lower FAT or snapshot I/O while the I/O Manager is borrowed.
        if resident_only {
            return Ok(CreateDecision::Prepare(OverlayCreateSpec { installed, copy_action,
                materialize_parent, is_directory }));
        }
        let context = self.reserve_open_context(file_id, units)?;
        let access = parameters.desired_access.bits();
        let share = parameters.share_access.bits();
        let options = parameters.create_options.bits();
        if let Some(source) = installed {
            if let Err(error) = self.shares.check_share(relative, source.metadata, access, share) {
                self.opens.cancel(context, file_id).expect("unpublished overlay context");
                return Err(status(error));
            }
        }
        let result = (|| -> Result<(u64, u64), NtStatus> {
            if let Some(parent) = relative
                .iter()
                .rposition(|byte| *byte == b'\\')
                .filter(|_| materialize_parent)
                .map(|end| &relative[..end])
            {
                let parent_entry =
                    unsafe { fat_open_path_metadata_from(&self.fs, self.fs.root_cl, parent) };
                if parent_entry.is_some_and(|entry| entry.metadata.is_directory) {
                    unsafe { crate::writable_fs::ensure_installed_directory_relative(parent) }
                        .map_err(status)?;
                }
            }
            if let (Some(source), Some(action)) = (installed, copy_action) {
                let mode = match action {
                    nt_fs::InstalledFileOpenAction::CopyContents => {
                        crate::writable_fs::InstalledFileCopyUp::PreserveContents
                    }
                    nt_fs::InstalledFileOpenAction::CopyMetadata => {
                        crate::writable_fs::InstalledFileCopyUp::MetadataOnly
                    }
                    _ => return Err(NtStatus::INVALID_PARAMETER),
                };
                unsafe {
                    crate::writable_fs::copy_up_installed_file_from(
                        &self.fs, relative, source, mode,
                    )
                }
                .map_err(status)?;
            }
            let (result, opened, information) = unsafe {
                crate::writable_fs::create(
                    relative,
                    access,
                    parameters.file_attributes,
                    share,
                    parameters.create_disposition,
                    options,
                )
            };
            if result != nt_fs::STATUS_SUCCESS {
                return Err(status(result));
            }
            Ok((
                opened.expect("successful overlay CREATE owns a File"),
                information,
            ))
        })();
        let (overlay_file, information) = match result {
            Ok(result) => result,
            Err(error) => {
                self.note_create_capacity_failure(b"overlay", file_id, error);
                self.opens
                    .cancel(context, file_id)
                    .expect("owned reservation");
                return Err(error);
            }
        };
        self.opens
            .finish(
                context,
                file_id,
                nt_fs::LayeredOpenSource::Overlay {
                    file_id: overlay_file,
                },
            )
            .expect("owned reservation");
        let index = context_index(context).expect("bounded layered table context index");
        debug_assert!(self.bindings[index].is_none());
        self.bindings[index] = Some(MountedBinding {
            context,
            volume_share: None,
            installed_open: None,
            installed_handle_open: false,
            directory_open: None,
            overlay_open: true,
            is_directory,
            granted_access: access,
            create_options: options,
            installed_directory_cluster: installed
                .filter(|source| is_directory && source.metadata.is_directory)
                .map(|source| source.first_cluster),
            directory_query: nt_fs::DirectoryQueryState::default(),
        });
        Ok(CreateDecision::Dispatch(DispatchOutcome::Completed {
            status: NtStatus::SUCCESS,
            information,
            file_context: Some(context.raw()),
        }))
    }

    fn binding(
        &self,
        irp: &IrpProjection,
    ) -> Result<(nt_fs::LayeredOpenContextId, MountedBinding), NtStatus> {
        let file_id = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        let context = nt_fs::LayeredOpenContextId::from_raw(irp.user_data);
        self.opens.get(context, file_id.raw()).map_err(status)?;
        let binding = self.bindings[context_index(context).ok_or(NtStatus::INVALID_HANDLE)?]
            .filter(|binding| binding.context == context)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        Ok((context, binding))
    }

    /// Resolve the File body retained by CREATE, never the path used to open it.
    fn opened_overlay_file(
        &self,
        context: nt_fs::LayeredOpenContextId,
        binding: MountedBinding,
        file_id: nt_io_manager::FileId,
    ) -> Result<u64, NtStatus> {
        if binding.is_directory {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        let nt_fs::LayeredOpenSource::Overlay { file_id: overlay_file } = self
            .opens
            .get(context, file_id.raw())
            .map_err(status)?
            .source
        else {
            return Err(NtStatus::ACCESS_DENIED);
        };
        if !binding.overlay_open {
            return Err(NtStatus::INVALID_HANDLE);
        }
        Ok(overlay_file)
    }

    fn read(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        let (context, binding) = self.binding(irp)?;
        if binding.is_directory {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        if binding.granted_access & (nt_fs::FILE_READ_DATA | nt_fs::FILE_EXECUTE | 0x8000_0000) == 0
        {
            return Err(NtStatus::ACCESS_DENIED);
        }
        let IoParameters::Read(parameters) = &irp.parameters else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        if parameters.length as usize > ctx.system_buffer.len() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if parameters.length == 0 {
            return Ok(DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: None,
            });
        }
        let file_id = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        let record = self.opens.get(context, file_id.raw()).map_err(status)?;
        if let nt_fs::LayeredOpenSource::Overlay {
            file_id: overlay_file,
        } = record.source
        {
            if !binding.overlay_open {
                return Err(NtStatus::INVALID_HANDLE);
            }
            let info = unsafe { crate::writable_fs::file_object_information(overlay_file) }
                .map_err(status)?;
            let synchronous = binding.create_options
                & (nt_fs::FILE_SYNCHRONOUS_IO_ALERT | nt_fs::FILE_SYNCHRONOUS_IO_NONALERT)
                != 0;
            let resolved = nt_io_manager::resolve_regular_file_read_offset(
                Some(parameters.offset as i64),
                synchronous,
                info.current_offset,
            )?;
            let (result, transferred) = unsafe {
                crate::writable_fs::read_completed_into(
                    overlay_file,
                    resolved,
                    synchronous,
                    &mut ctx.system_buffer[..parameters.length as usize],
                )
            };
            return Ok(DispatchOutcome::Completed {
                status: status(result),
                information: transferred as u64,
                file_context: None,
            });
        }
        let nt_fs::LayeredOpenSource::Installed {
            first_cluster,
            metadata,
            ..
        } = record.source
        else {
            return Err(NtStatus::INVALID_HANDLE);
        };
        let installed_open = binding.installed_open.ok_or(NtStatus::INVALID_HANDLE)?;
        let offset = u32::try_from(parameters.offset).map_err(|_| NtStatus::INVALID_PARAMETER)?;
        self.shares.get(installed_open).map_err(status)?;
        let eof = metadata.end_of_file.min(u32::MAX as u64) as u32;
        if offset >= eof {
            return Err(NtStatus::END_OF_FILE);
        }
        let expected = (parameters.length as usize).min((eof - offset) as usize);
        let physical_mount = unsafe { crate::fs_loader::exec_fs_mount_identity() }
            .ok_or(NtStatus::DEVICE_NOT_READY)?;
        let route_kind = crate::fs_loader::exec_block_route_kind(physical_mount)
            .ok_or(NtStatus::DEVICE_NOT_READY)?;
        if route_kind != nt_fs::BlockSourceKind::Boot {
            let geometry = nt_fs::FatPathGeometry {
                fat_start_sector: self.fs.fat_start,
                data_start_sector: self.fs.data_start,
                total_sectors: self.fs.total_sectors,
                sectors_per_cluster: self.fs.spc,
            };
            let position = (self.shares.get(installed_open).map_err(status)?.create_options
                & (nt_fs::FILE_SYNCHRONOUS_IO_ALERT | nt_fs::FILE_SYNCHRONOUS_IO_NONALERT) != 0)
                .then_some((installed_open, u64::from(offset) + expected as u64));
            self.read_completions.borrow_mut().capture_range(irp.irp_id.raw(),
                physical_mount.value(), file_id.raw(), geometry, first_cluster, offset,
                expected, position).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
            crate::service_sec_image::request_mounted_native_timer_rearm();
            return Ok(DispatchOutcome::Pending);
        }
        let written = unsafe {
            fat_read_file_range(
                &self.fs,
                first_cluster,
                eof,
                offset,
                &mut ctx.system_buffer[..expected],
            )
        };
        if written != expected {
            return Err(status(nt_fs::STATUS_DATA_ERROR));
        }
        if self.shares.get(installed_open).map_err(status)?.create_options
            & (nt_fs::FILE_SYNCHRONOUS_IO_ALERT | nt_fs::FILE_SYNCHRONOUS_IO_NONALERT)
            != 0
        {
            self.shares
                .get_mut(installed_open)
                .map_err(status)?
                .current_offset = u64::from(offset) + written as u64;
        }
        Ok(DispatchOutcome::Completed {
            status: NtStatus::SUCCESS,
            information: written as u64,
            file_context: None,
        })
    }

    fn query(
        &self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        let (context, binding) = self.binding(irp)?;
        let IoParameters::QueryInformation(parameters) = &irp.parameters else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        let capacity = (parameters.length as usize).min(ctx.system_buffer.len());
        let output = &mut ctx.system_buffer[..capacity];
        let file_id = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        let record = self.opens.get(context, file_id.raw()).map_err(status)?;
        let (metadata, alternate_name, current_offset, mode) = match record.source {
            nt_fs::LayeredOpenSource::Volume => return Err(NtStatus::INVALID_DEVICE_REQUEST),
            nt_fs::LayeredOpenSource::Installed {
                metadata,
                alternate_name,
                ..
            } => {
                if binding.is_directory {
                    let open = self
                        .directories
                        .get(binding.directory_open.ok_or(NtStatus::INVALID_HANDLE)?)
                        .map_err(status)?;
                    (
                        metadata,
                        alternate_name,
                        0,
                        nt_fs::file_mode_from_create_options(open.create_options),
                    )
                } else {
                    let open = self
                        .shares
                        .get(binding.installed_open.ok_or(NtStatus::INVALID_HANDLE)?)
                        .map_err(status)?;
                    (
                        metadata,
                        alternate_name,
                        open.current_offset,
                        nt_fs::file_mode_from_create_options(open.create_options),
                    )
                }
            }
            nt_fs::LayeredOpenSource::Overlay {
                file_id: overlay_file,
            } => {
                if !binding.overlay_open {
                    return Err(NtStatus::INVALID_HANDLE);
                }
                let info = unsafe { crate::writable_fs::file_object_information(overlay_file) }
                    .map_err(status)?;
                let short =
                    unsafe { crate::writable_fs::short_name(overlay_file) }.map_err(status)?;
                (info.metadata, short, info.current_offset, info.mode)
            }
        };
        let mut query = metadata.query_metadata();
        query.file_id = record
            .source
            .file_internal_index(metadata.file_id)
            .map_err(status)?;
        query.current_byte_offset = current_offset;
        query.access_flags = binding.granted_access;
        query.mode = mode;
        capture_manager_owned_query_fields(parameters.info_class, output, &mut query)?;
        let result = match parameters.info_class {
            nt_fs::FILE_NAME_INFORMATION | nt_fs::FILE_ALL_INFORMATION => {
                nt_fs::encode_named_query_information(
                    parameters.info_class,
                    query,
                    record.name,
                    output,
                )
                .map_err(status)?
            }
            nt_fs::FILE_ALTERNATE_NAME_INFORMATION => nt_fs::encode_named_query_information(
                parameters.info_class,
                query,
                alternate_name.units(),
                output,
            )
            .map_err(status)?,
            nt_fs::FILE_STREAM_INFORMATION => {
                nt_fs::encode_stream_information(query, output).map_err(status)?
            }
            nt_fs::FILE_REPARSE_POINT_INFORMATION => {
                let information =
                    nt_fs::encode_reparse_point_information(query, output).map_err(status)?;
                nt_fs::QueryInformationResult {
                    status: nt_fs::STATUS_SUCCESS,
                    information,
                }
            }
            _ => {
                let information =
                    nt_fs::encode_query_information(parameters.info_class, query, output)
                        .map_err(status)?;
                nt_fs::QueryInformationResult {
                    status: nt_fs::STATUS_SUCCESS,
                    information,
                }
            }
        };
        Ok(DispatchOutcome::Completed {
            status: status(result.status),
            information: result.information as u64,
            file_context: None,
        })
    }

    fn query_volume_information(
        &self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        // Query the volume that owns the exact opened File, including its retained generation.
        let _ = self.binding(irp)?;
        let IoParameters::QueryVolumeInformation(parameters) = &irp.parameters else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        if parameters.length as usize > ctx.system_buffer.len() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let output = &mut ctx.system_buffer[..parameters.length as usize];
        let result = unsafe {
            crate::fat_volume_information::encode_query(
                &self.fs,
                parameters.information_class,
                output,
            )
        }
        .map_err(status)?;
        Ok(DispatchOutcome::Completed {
            status: status(result.status),
            information: result.information as u64,
            file_context: None,
        })
    }

    fn filesystem_control(
        &self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        let (context, _) = self.binding(irp)?;
        let file_id = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        if self.opens.get(context, file_id.raw()).map_err(status)?.source
            != nt_fs::LayeredOpenSource::Volume
        {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        let IoParameters::DeviceControl(parameters) = &irp.parameters else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        let output_len = parameters.output_len as usize;
        if output_len > ctx.system_buffer.len() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let written = nt_fs::encode_fat_volume_fsctl(
            parameters.ioctl_code,
            parameters.input_len,
            &mut ctx.system_buffer[..output_len],
            self.fs.volume_dirty,
        )
        .map_err(status)?;
        // Native acceptance: this marker only follows an exact generation-bound volume File
        // and a successful buffered dirty query. Compare it with [fat-mount-bpb] from the
        // sector read at mount, and with the guest's successful NtFsControlFile receipt.
        let reported = u32::from_le_bytes(
            ctx.system_buffer[..4].try_into().expect("successful dirty FSCTL wrote four bytes")
        );
        if written != 4 || reported != u32::from(self.fs.volume_dirty) {
            return Err(status(nt_fs::STATUS_DATA_ERROR));
        }
        crate::print_str(b"[mounted-volume-fsctl-dirty] file=");
        crate::print_u64(file_id.raw());
        crate::print_str(b" context=");
        crate::print_u64(context.raw());
        crate::print_str(b" status=0 information=");
        crate::print_u64(written as u64);
        crate::print_str(b" dirty=");
        crate::print_u64(u64::from(reported));
        crate::print_str(b"\n");
        Ok(DispatchOutcome::Completed {
            status: NtStatus::SUCCESS,
            information: written as u64,
            file_context: None,
        })
    }

    fn write(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        let (context, binding) = self.binding(irp)?;
        if binding.is_directory {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        let IoParameters::Write(parameters) = &irp.parameters else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        if parameters.length as usize > ctx.system_buffer.len() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let write_access =
            nt_fs::FILE_WRITE_DATA | nt_fs::FILE_APPEND_DATA | 0x4000_0000 | 0x1000_0000;
        if binding.granted_access & write_access == 0 {
            return Err(NtStatus::ACCESS_DENIED);
        }
        let file_id = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        let overlay_file = self.opened_overlay_file(context, binding, file_id)?;
        let info =
            unsafe { crate::writable_fs::file_object_information(overlay_file) }.map_err(status)?;
        let synchronous = binding.create_options
            & (nt_fs::FILE_SYNCHRONOUS_IO_ALERT | nt_fs::FILE_SYNCHRONOUS_IO_NONALERT)
            != 0;
        let append_only = binding.granted_access & nt_fs::FILE_APPEND_DATA != 0
            && binding.granted_access & (nt_fs::FILE_WRITE_DATA | 0x4000_0000 | 0x1000_0000) == 0;
        let resolved = nt_io_manager::resolve_regular_file_write_offset(
            Some(parameters.offset as i64),
            synchronous,
            info.current_offset,
            info.metadata.end_of_file,
            append_only,
        )?;
        let (result, written) = unsafe {
            crate::writable_fs::write_completed(
                overlay_file,
                resolved,
                synchronous,
                &ctx.system_buffer[..parameters.length as usize],
            )
        };
        Ok(DispatchOutcome::Completed {
            status: status(result),
            information: written as u64,
            file_context: None,
        })
    }

    fn flush(&mut self, irp: &IrpProjection) -> Result<DispatchOutcome, NtStatus> {
        let (context, binding) = self.binding(irp)?;
        if !matches!(irp.parameters, IoParameters::FlushBuffers) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if !nt_fs::file_flush_access_allowed(binding.granted_access, false) {
            return Err(NtStatus::ACCESS_DENIED);
        }
        let file_id = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        let overlay_file = self.opened_overlay_file(context, binding, file_id)?;
        let result = unsafe { crate::writable_fs::flush(overlay_file) };
        Ok(DispatchOutcome::Completed {
            status: status(result),
            information: 0,
            file_context: None,
        })
    }

    fn set_information(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        let (context, binding) = self.binding(irp)?;
        let IoParameters::SetInformation(parameters) = irp.parameters else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        // EventLog clears a corrupt log with FileEndOfFileInformation. Other classes need
        // their own target-File and access contracts before they can be routed here.
        if parameters.info_class != nt_fs::FILE_END_OF_FILE_INFORMATION {
            return Err(NtStatus::NOT_SUPPORTED);
        }
        if parameters.target_file.is_some()
            || !matches!(parameters.control, nt_io_manager::SetInformationControl::None)
            || parameters.length != 8
            || ctx.system_buffer.len() < 8
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let write_access = nt_fs::FILE_WRITE_DATA | 0x4000_0000 | 0x1000_0000;
        if binding.granted_access & write_access == 0 {
            return Err(NtStatus::ACCESS_DENIED);
        }
        let file_id = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        let overlay_file = self.opened_overlay_file(context, binding, file_id)?;
        let result = unsafe {
            crate::writable_fs::set_information(
                overlay_file, parameters.info_class, &ctx.system_buffer[..8],
            )
        };
        Ok(DispatchOutcome::Completed {
            status: status(result),
            information: 0,
            file_context: None,
        })
    }

    fn cleanup_or_close(
        &mut self,
        irp: &IrpProjection,
        close: bool,
    ) -> Result<DispatchOutcome, NtStatus> {
        let (context, binding) = self.binding(irp)?;
        let index = context_index(context).ok_or(NtStatus::INVALID_HANDLE)?;
        if binding.volume_share.is_some() {
            self.bindings[index].as_mut().expect("validated binding").volume_share = None;
        }
        if binding.installed_handle_open {
            let installed_open = binding.installed_open.ok_or(NtStatus::INVALID_HANDLE)?;
            self.shares.release(installed_open).map_err(status)?;
            self.bindings[index]
                .as_mut()
                .expect("validated binding")
                .installed_handle_open = false;
        }
        if let Some(directory_open) = binding.directory_open {
            self.directories.release(directory_open).map_err(status)?;
            self.bindings[index]
                .as_mut()
                .expect("validated binding")
                .directory_open = None;
        }
        let file_id = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        if let nt_fs::LayeredOpenSource::Overlay {
            file_id: overlay_file,
        } = self
            .opens
            .get(context, file_id.raw())
            .map_err(status)?
            .source
        {
            if binding.overlay_open {
                unsafe { crate::writable_fs::close_checked(overlay_file) }.map_err(status)?;
                self.bindings[index]
                    .as_mut()
                    .expect("validated binding")
                    .overlay_open = false;
            }
        }
        if close {
            if let Some(installed_open) = binding.installed_open {
                self.shares.release_io(installed_open).map_err(status)?;
                self.bindings[index].as_mut().expect("validated binding").installed_open = None;
            }
            self.opens.release(context, file_id.raw()).map_err(status)?;
            self.bindings[index] = None;
        }
        Ok(DispatchOutcome::Completed {
            status: NtStatus::SUCCESS,
            information: 0,
            file_context: None,
        })
    }
}

impl DriverDispatchBackend for MountedVolumeBackend {
    fn immutable_file_extent(&self, file_id: nt_io_manager::FileId, file_context: u64) -> Option<u64> {
        let context = nt_fs::LayeredOpenContextId::from_raw(file_context);
        let extent = self.opens.immutable_installed_file_extent(context, file_id.raw())?;
        let binding = self.bindings.get(context_index(context)?)?.as_ref()?;
        if binding.context != context || binding.is_directory || binding.overlay_open {
            return None;
        }
        self.shares.get(binding.installed_open?).ok()?;
        Some(extent)
    }

    fn dispatch_irp(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        match irp.major {
            major::IRP_MJ_CREATE => self.create(irp),
            major::IRP_MJ_READ => self.read(ctx, irp),
            major::IRP_MJ_WRITE => self.write(ctx, irp),
            major::IRP_MJ_FLUSH_BUFFERS => self.flush(irp),
            major::IRP_MJ_SET_INFORMATION => self.set_information(ctx, irp),
            major::IRP_MJ_QUERY_INFORMATION => self.query(ctx, irp),
            major::IRP_MJ_QUERY_VOLUME_INFORMATION => self.query_volume_information(ctx, irp),
            major::IRP_MJ_FILE_SYSTEM_CONTROL => self.filesystem_control(ctx, irp),
            major::IRP_MJ_DIRECTORY_CONTROL => self.query_directory(ctx, irp),
            major::IRP_MJ_CLEANUP => self.cleanup_or_close(irp, false),
            major::IRP_MJ_CLOSE => self.cleanup_or_close(irp, true),
            _ => Err(NtStatus::NOT_SUPPORTED),
        }
    }

    fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
        Err(NtStatus::NOT_SUPPORTED)
    }

    fn service_pending(&mut self) -> usize {
        let mut progress = self.service_resolved_create();
        progress += self.service_prepared_overlay();
        progress += self.service_resolved_directory();
        let pending_position = self.read_completions.borrow().pending_position();
        if let Some((irp, open, next)) = pending_position {
            if let Ok(entry) = self.shares.get_mut(open) {
                entry.current_offset = next;
                self.read_completions.borrow_mut().mark_position_committed(irp)
                    .expect("terminal read position owner is retained");
                progress += 1;
            }
        }
        progress
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        if let Some(ready) = self.create_completions.iter_mut().find(|item| !item.published) {
            ready.published = true;
            return Some(ready.completion);
        }
        if let Some(ready) = self.directory_completions.iter_mut().find(|item| !item.published) {
            ready.published = true;
            return Some(ready.completion);
        }
        self.read_completions.borrow_mut().next_completion().map(|(irp, status, transferred)| DriverCompletion {
            irp_id: IrpId(irp),
            status: NtStatus(status),
            information: transferred as u64,
            file_context: None,
        })
    }

    fn copy_completion_output(
        &mut self,
        irp_id: IrpId,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, NtStatus> {
        let offset = usize::try_from(offset).map_err(|_| NtStatus::INVALID_PARAMETER)?;
        if let Some(item) = self.directory_completions.iter().find(|item| item.owner.irp == irp_id) {
            if !item.published { return Err(NtStatus::INVALID_PARAMETER); }
            let transferred = usize::try_from(item.completion.information)
                .map_err(|_| NtStatus::INVALID_PARAMETER)?;
            let remaining = transferred.checked_sub(offset).ok_or(NtStatus::INVALID_PARAMETER)?;
            let copied = remaining.min(output.len());
            output[..copied].copy_from_slice(&item.owner.output[offset..offset + copied]);
            return Ok(copied);
        }
        self.read_completions.borrow().copy(irp_id.raw(), offset, output)
            .map_err(|_| NtStatus::INVALID_PARAMETER)
    }

    fn acknowledge_completion(&mut self, irp_id: IrpId) -> Result<(), NtStatus> {
        if let Some(index) = self.create_completions.iter().position(|item| item.owner.irp == irp_id) {
            self.create_completions.swap_remove(index);
            return Ok(());
        }
        if let Some(index) = self.directory_completions.iter().position(|item| item.owner.irp == irp_id) {
            if !self.directory_completions[index].published { return Err(NtStatus::INVALID_PARAMETER); }
            self.directory_completions.swap_remove(index);
            return Ok(());
        }
        self.read_completions.borrow_mut().ack(irp_id.raw())
            .map_err(|_| NtStatus::INVALID_PARAMETER)
    }
}

fn context_index(context: nt_fs::LayeredOpenContextId) -> Option<usize> {
    let index = (context.raw() as u32).checked_sub(1)? as usize;
    (index < OPEN_CAP).then_some(index)
}

fn status(raw: u32) -> NtStatus {
    NtStatus(raw as i32)
}

fn overlay_prepare_status(error: nt_fs::OverlayPrepareError) -> NtStatus {
    match error {
        nt_fs::OverlayPrepareError::NoCapacity => NtStatus::INSUFFICIENT_RESOURCES,
        nt_fs::OverlayPrepareError::ParentMissing => NtStatus::OBJECT_PATH_NOT_FOUND,
        nt_fs::OverlayPrepareError::ParentNotDirectory => status(nt_fs::STATUS_NOT_A_DIRECTORY),
        _ => status(nt_fs::STATUS_DATA_ERROR),
    }
}
