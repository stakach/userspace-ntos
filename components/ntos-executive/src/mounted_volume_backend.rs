//! Canonical File IRP dispatch for regular files on the mounted FAT volume.
//!
//! The installed layer is immutable. CREATE owns both a generation-fenced File context and an
//! installed open with independent handle-sharing and body references. CLEANUP releases sharing;
//! CLOSE releases the body and File context. Position and mode survive CLEANUP for pointer-owned
//! operations. No later operation re-resolves the name to select a different backing file.

use alloc::vec::Vec;

use nt_io_abi::major;
use nt_io_manager::{
    DispatchContext, DispatchOutcome, DriverCompletion, DriverDispatchBackend, IoParameters, IrpId,
    IrpProjection,
};
use nt_status::NtStatus;

use crate::fs_loader::{
    fat_open_path_metadata_from, fat_read_file_range, fat_visit_directory_checked, FatOpenMetadata,
};

// Directory and installed-file handles encode a 16-bit slot index plus a 16-bit generation.
// This is the identity-schema ceiling, not an eagerly allocated resource reservation.
const OPEN_CAP: usize = nt_fs::MAX_FAT_OPEN_SLOTS;
const PATH_CAP: usize = nt_fs::LAYERED_OPEN_NAME_CAP;

#[derive(Clone, Copy)]
struct MountedBinding {
    context: nt_fs::LayeredOpenContextId,
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
}

impl MountedVolumeBackend {
    pub(crate) fn new(fs: crate::Fat32) -> Self {
        Self {
            fs,
            opens: nt_fs::LayeredOpenTable::new(),
            shares: nt_fs::ReadOnlyFileOpenTable::new(),
            directories: nt_fs::DirectoryOpenTable::new(),
            bindings: Vec::new(),
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
            || irp.create_case_sensitive
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

        let installed = unsafe { fat_open_path_metadata_from(&self.fs, self.fs.root_cl, relative) };
        let overlay =
            unsafe { crate::writable_fs::query_metadata_relative(relative) }.map_err(status)?;
        if options & nt_fs::FILE_DIRECTORY_FILE != 0
            || overlay.is_some_and(|entry| entry.is_directory)
            || (overlay.is_none() && installed.is_some_and(|entry| entry.metadata.is_directory))
        {
            return self.create_directory(
                file_id.raw(),
                units,
                relative,
                installed,
                overlay,
                parameters,
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
        match decision {
            nt_fs::LayeredFileOpenDecision::Installed(nt_fs::InstalledFileOpenAction::ReadOnly) => {
                self.create_installed(
                    file_id.raw(),
                    units,
                    relative,
                    installed.unwrap(),
                    access,
                    share,
                    options,
                )
            }
            nt_fs::LayeredFileOpenDecision::Installed(
                nt_fs::InstalledFileOpenAction::NameCollision,
            ) => Err(NtStatus::OBJECT_NAME_COLLISION),
            nt_fs::LayeredFileOpenDecision::Installed(action) => self.create_overlay(
                file_id.raw(),
                units,
                relative,
                installed,
                Some(action),
                true,
                false,
                parameters,
            ),
            nt_fs::LayeredFileOpenDecision::UseOverlay
            | nt_fs::LayeredFileOpenDecision::CreateOverlay => self.create_overlay(
                file_id.raw(),
                units,
                relative,
                installed,
                None,
                matches!(decision, nt_fs::LayeredFileOpenDecision::CreateOverlay),
                false,
                parameters,
            ),
        }
    }

    fn create_directory(
        &mut self,
        file_id: u64,
        units: &[u16],
        relative: &[u8],
        installed: Option<FatOpenMetadata>,
        overlay: Option<nt_fs::FileMetadata>,
        parameters: &nt_io_manager::CreateParameters,
    ) -> Result<DispatchOutcome, NtStatus> {
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
                )
            }
            nt_fs::LayeredDirectoryOpenDecision::Overlay => {
                if let Some(source) = installed.filter(|source| source.metadata.is_directory) {
                    self.directories
                        .check_share(relative, source.metadata, access, share)
                        .map_err(status)?;
                }
                self.create_overlay(
                    file_id, units, relative, installed, None, false, true, parameters,
                )
            }
            nt_fs::LayeredDirectoryOpenDecision::CreateOverlay => self.create_overlay(
                file_id, units, relative, None, None, true, true, parameters,
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
    ) -> Result<DispatchOutcome, NtStatus> {
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
        Ok(DispatchOutcome::Completed {
            status: NtStatus::SUCCESS,
            information,
            file_context: Some(context.raw()),
        })
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

    fn query_directory(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        let (context, binding) = self.binding(irp)?;
        if !binding.is_directory {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        if !nt_io_manager::directory_notify_access_granted(
            nt_types::AccessMask::from_bits_retain(binding.granted_access),
        ) {
            return Err(NtStatus::ACCESS_DENIED);
        }
        let IoParameters::QueryDirectory(parameters) = &irp.parameters else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        if irp.minor != nt_io_manager::IRP_MN_QUERY_DIRECTORY {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        if irp.flags.contains(nt_io_manager::StackFlags::INDEX_SPECIFIED)
            || parameters.file_index != 0
        {
            return Err(NtStatus::NOT_SUPPORTED);
        }
        let length = parameters.length as usize;
        if length > ctx.system_buffer.len() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let file_id = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        let record = self.opens.get(context, file_id.raw()).map_err(status)?;
        let mut installed = Vec::new();
        if let Some(cluster) = binding.installed_directory_cluster {
            let mut allocation_error = None;
            let end = unsafe {
                fat_visit_directory_checked(&self.fs, cluster, |entry, _| {
                    if installed.try_reserve(1).is_err() {
                        allocation_error = Some(nt_fs::STATUS_INSUFFICIENT_RESOURCES);
                        return false;
                    }
                    installed.push(entry);
                    true
                })
            }
            .map_err(status)?;
            if let Some(error) = allocation_error {
                return Err(status(error));
            }
            if end != nt_fs::FatDirectoryWalkEnd::Complete {
                return Err(status(nt_fs::STATUS_DATA_ERROR));
            }
        }
        let overlay = match record.source {
            nt_fs::LayeredOpenSource::Overlay { file_id } => {
                if !binding.overlay_open {
                    return Err(NtStatus::INVALID_HANDLE);
                }
                Some(unsafe { crate::writable_fs::directory_entries_opened(file_id) }.map_err(status)?)
            }
            nt_fs::LayeredOpenSource::Installed { .. } => {
                let open = self
                    .directories
                    .get(binding.directory_open.ok_or(NtStatus::INVALID_HANDLE)?)
                    .map_err(status)?;
                unsafe { crate::writable_fs::directory_entries_relative(open.volume_relative_path()) }
                    .map_err(status)?
            }
        };
        let entries = nt_fs::merge_layered_directory_entries(
            &installed,
            overlay.as_deref().unwrap_or(&[]),
        )
        .map_err(status)?;
        let mut query = binding.directory_query;
        let result = nt_fs::query_directory(
            &mut query,
            &entries,
            parameters.information_class,
            irp.flags.contains(nt_io_manager::StackFlags::RETURN_SINGLE_ENTRY),
            parameters.pattern.as_ref().map(|pattern| pattern.as_units()),
            irp.flags.contains(nt_io_manager::StackFlags::RESTART_SCAN),
            &mut ctx.system_buffer[..length],
        );
        self.bindings[context_index(context).ok_or(NtStatus::INVALID_HANDLE)?]
            .as_mut()
            .expect("validated binding")
            .directory_query = query;
        Ok(DispatchOutcome::Completed {
            status: status(result.status),
            information: result.information as u64,
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
        let nt_fs::LayeredOpenSource::Overlay {
            file_id: overlay_file,
        } = self
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

    fn cleanup_or_close(
        &mut self,
        irp: &IrpProjection,
        close: bool,
    ) -> Result<DispatchOutcome, NtStatus> {
        let (context, binding) = self.binding(irp)?;
        let index = context_index(context).ok_or(NtStatus::INVALID_HANDLE)?;
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
    fn dispatch_irp(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        match irp.major {
            major::IRP_MJ_CREATE => self.create(irp),
            major::IRP_MJ_READ => self.read(ctx, irp),
            major::IRP_MJ_WRITE => self.write(ctx, irp),
            major::IRP_MJ_QUERY_INFORMATION => self.query(ctx, irp),
            major::IRP_MJ_DIRECTORY_CONTROL => self.query_directory(ctx, irp),
            major::IRP_MJ_CLEANUP => self.cleanup_or_close(irp, false),
            major::IRP_MJ_CLOSE => self.cleanup_or_close(irp, true),
            _ => Err(NtStatus::NOT_SUPPORTED),
        }
    }

    fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
        Err(NtStatus::NOT_SUPPORTED)
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        None
    }
}

fn context_index(context: nt_fs::LayeredOpenContextId) -> Option<usize> {
    let index = (context.raw() as u32).checked_sub(1)? as usize;
    (index < OPEN_CAP).then_some(index)
}

fn status(raw: u32) -> NtStatus {
    NtStatus(raw as i32)
}
