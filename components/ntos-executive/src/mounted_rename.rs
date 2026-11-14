//! Rename on the mounted volume: the I/O Manager's target-directory CREATE and the source
//! File's `FileRenameInformation`.
//!
//! The I/O Manager opens the directory that will hold the new name with
//! `SL_OPEN_TARGET_DIRECTORY`, then sends the source File a SET_INFORMATION naming that target
//! File. Policy across the installed and writable layers is `nt_fs`'s; this module only binds it
//! to the Files this backend opened.

use super::*;

/// What an `SL_OPEN_TARGET_DIRECTORY` CREATE learned about its name before opening the parent.
#[derive(Clone, Copy)]
pub(super) struct TargetDirectory {
    /// Length of the parent's volume-relative path within the captured name.
    pub(super) parent_len: usize,
    /// `FILE_EXISTS` or `FILE_DOES_NOT_EXIST` for the final component.
    pub(super) information: u32,
    /// The installed entry holding the final component, if any.
    installed_target: Option<nt_fs::FileMetadata>,
}

impl TargetDirectory {
    pub(super) fn rename_target(self) -> RenameTarget {
        RenameTarget { installed: self.installed_target }
    }
}

/// Retained on the parent File a rename names as its target. The installed layer is immutable,
/// so this fact stays true for the File's lifetime; the writable layer is consulted live.
#[derive(Clone, Copy)]
pub(super) struct RenameTarget {
    installed: Option<nt_fs::FileMetadata>,
}

impl RenameTarget {
    fn has_installed_entry(self) -> bool {
        self.installed.is_some()
    }
}

static PROFILE_HIVE_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
const PROFILE_HIVE_TRACE_CAP: u64 = 32;

/// A default or per-user profile hive (`ntuser.dat`, its `.bak`, its `.LOG`), by final component.
fn is_profile_hive_name(name: &[u16]) -> bool {
    const PREFIX: &[u8] = b"ntuser.";
    let leaf = name
        .rsplit(|unit| *unit == b'\\' as u16)
        .next()
        .unwrap_or(name);
    leaf.len() > PREFIX.len()
        && leaf.iter().zip(PREFIX).all(|(unit, byte)| {
            u8::try_from(*unit).is_ok_and(|unit| unit.eq_ignore_ascii_case(byte))
        })
}

pub(super) fn print_name(name: &[u16]) {
    for unit in name.iter().take(120) {
        crate::debug_put_char(u8::try_from(*unit).ok().filter(u8::is_ascii_graphic).unwrap_or(b'?'));
    }
}

/// One bounded line per terminal CREATE of a profile hive: the next boot's first question is
/// which of setup's file calls failed, and with what status.
pub(super) fn trace_profile_hive_create(
    name: &[u16],
    parameters: &nt_io_manager::CreateParameters,
    target_directory: bool,
    status: NtStatus,
    information: u64,
) {
    if !is_profile_hive_name(name)
        || PROFILE_HIVE_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) >= PROFILE_HIVE_TRACE_CAP
    {
        return;
    }
    crate::print_str(b"[profile-hive] create path=\"");
    print_name(name);
    crate::print_str(b"\" target-directory=");
    crate::print_u64(target_directory as u64);
    crate::print_str(b" access=");
    crate::print_hex(parameters.desired_access.bits());
    crate::print_str(b" disposition=");
    crate::print_u64(parameters.create_disposition as u64);
    crate::print_str(b" options=");
    crate::print_hex(parameters.create_options.bits());
    crate::print_str(b" status=");
    crate::print_hex(status.raw() as u32);
    crate::print_str(b" information=");
    crate::print_u64(information);
    crate::print_str(b"\n");
}

fn trace_profile_hive_rename(source: &[u16], target: &[u16], replace: bool, status: NtStatus) {
    if !(is_profile_hive_name(source) || is_profile_hive_name(target))
        || PROFILE_HIVE_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) >= PROFILE_HIVE_TRACE_CAP
    {
        return;
    }
    crate::print_str(b"[profile-hive] rename path=\"");
    print_name(source);
    crate::print_str(b"\" to=\"");
    print_name(target);
    crate::print_str(b"\" class=");
    crate::print_u64(nt_fs::FILE_RENAME_INFORMATION as u64);
    crate::print_str(b" replace=");
    crate::print_u64(replace as u64);
    crate::print_str(b" status=");
    crate::print_hex(status.raw() as u32);
    crate::print_str(b"\n");
}

impl MountedVolumeBackend {
    /// The installed directory that holds `relative`'s final component, read inline. Only the
    /// Boot route may call this; the native route learns it from its retained path walk.
    pub(super) fn boot_installed_parent(
        &self,
        relative: &[u8],
    ) -> Result<Option<FatOpenMetadata>, NtStatus> {
        let (parent, _) = nt_fs::rename_target_parent(relative).map_err(status)?;
        Ok(if parent.is_empty() {
            Some(crate::fs_loader::fat_root_metadata(&self.fs))
        } else {
            unsafe { fat_open_path_metadata_from(&self.fs, self.fs.root_cl, parent) }
        })
    }

    /// `SL_OPEN_TARGET_DIRECTORY`: open the directory that holds the name's final component and
    /// report whether that component exists. The File keeps the caller's full name, which is the
    /// new name the following rename gives its source.
    pub(super) fn create_target_directory(
        &mut self,
        file_id: u64,
        units: &[u16],
        relative: &[u8],
        installed_parent: Option<FatOpenMetadata>,
        installed_target: Option<FatOpenMetadata>,
        parameters: &nt_io_manager::CreateParameters,
        resident_only: bool,
    ) -> Result<CreateDecision, NtStatus> {
        let (parent, _) = nt_fs::rename_target_parent(relative).map_err(status)?;
        let query = |path: &[u8]| unsafe {
            if resident_only {
                crate::writable_fs::query_metadata_relative_if_mounted(path)
            } else {
                crate::writable_fs::query_metadata_relative(path)
            }
        };
        let overlay_parent = query(parent).map_err(status)?;
        let overlay_target = query(relative).map_err(status)?;
        let open = nt_fs::layered_target_directory_open(
            installed_parent.map(|entry| entry.metadata.is_directory),
            overlay_parent.map(|entry| entry.is_directory),
            installed_target.is_some(),
            overlay_target.is_some(),
        )
        .map_err(status)?;
        let target = TargetDirectory {
            parent_len: parent.len(),
            information: open.information,
            installed_target: installed_target.map(|entry| entry.metadata),
        };
        // The parent is an existing directory whatever disposition the rename's CREATE carried.
        let mut directory = *parameters;
        directory.create_disposition = nt_fs::FILE_OPEN;
        directory.create_options = nt_io_manager::CreateOptions::from_bits_retain(
            parameters.create_options.bits() | nt_fs::FILE_DIRECTORY_FILE,
        );
        let access = directory.desired_access.bits();
        let share = directory.share_access.bits();
        let opened = match open.backing {
            nt_fs::LayeredDirectoryOpenDecision::Installed => {
                let source = installed_parent.expect("target policy selected the installed parent");
                CreateDecision::Dispatch(self.create_installed_directory(
                    file_id, units, parent, source, access, share,
                    directory.create_options.bits(),
                )?)
            }
            nt_fs::LayeredDirectoryOpenDecision::Overlay => {
                if let Some(source) = installed_parent.filter(|source| source.metadata.is_directory) {
                    self.directories
                        .check_share(parent, source.metadata, access, share)
                        .map_err(status)?;
                }
                self.create_overlay(
                    file_id, units, parent, installed_parent, None, false, true, &directory,
                    resident_only,
                )?
            }
            nt_fs::LayeredDirectoryOpenDecision::CreateOverlay => {
                unreachable!("a target-directory open never creates its parent")
            }
        };
        Ok(self.publish_target_directory(opened, target))
    }

    /// Turn the parent directory's ordinary open into the target-directory result: the final
    /// component's existence as `Information`, and the rename facts on the published File.
    fn publish_target_directory(
        &mut self,
        opened: CreateDecision,
        target: TargetDirectory,
    ) -> CreateDecision {
        match opened {
            // The retained native CREATE publishes its File when its preparation completes.
            CreateDecision::Prepare(spec) => {
                CreateDecision::Prepare(OverlayCreateSpec { target: Some(target), ..spec })
            }
            CreateDecision::Dispatch(DispatchOutcome::Completed {
                status,
                file_context: Some(context),
                ..
            }) => {
                let index = context_index(nt_fs::LayeredOpenContextId::from_raw(context))
                    .expect("bounded layered table context index");
                self.bindings[index]
                    .as_mut()
                    .expect("a completed directory open published its binding")
                    .rename_target = Some(target.rename_target());
                CreateDecision::Dispatch(DispatchOutcome::Completed {
                    status,
                    information: u64::from(target.information),
                    file_context: Some(context),
                })
            }
            failed => failed,
        }
    }

    /// `FileRenameInformation` on a File this backend opened, naming the target File the I/O
    /// Manager opened with `SL_OPEN_TARGET_DIRECTORY`.
    pub(super) fn rename(
        &mut self,
        irp: &IrpProjection,
        context: nt_fs::LayeredOpenContextId,
        binding: MountedBinding,
        parameters: nt_io_manager::SetInformationParameters,
    ) -> Result<DispatchOutcome, NtStatus> {
        let nt_io_manager::SetInformationControl::ReplaceIfExists(replace_if_exists) =
            parameters.control
        else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        // A simple rename carries no target File: its new name is relative to the source's own
        // directory. Deciding it needs that directory's installed entries, which this backend
        // only reads on behalf of a target-directory CREATE.
        let Some(target_file) = parameters.target_file else {
            return Err(NtStatus::NOT_SUPPORTED);
        };
        if binding.granted_access & (nt_fs::DELETE | 0x1000_0000) == 0 {
            return Err(NtStatus::ACCESS_DENIED);
        }
        let file_id = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        let source = self.opens.get(context, file_id.raw()).map_err(status)?;
        let overlay_source = match source.source {
            nt_fs::LayeredOpenSource::Overlay { file_id } if binding.overlay_open => Some(file_id),
            _ => None,
        };
        let mut source_name = Vec::new();
        source_name
            .try_reserve_exact(source.name.len())
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        source_name.extend_from_slice(source.name);

        let (target_context, target) = self.opens.get_by_file_id(target_file.raw()).map_err(status)?;
        let target_binding = self.bindings[context_index(target_context).ok_or(NtStatus::INVALID_HANDLE)?]
            .filter(|binding| binding.context == target_context)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        // Only a File opened as a rename's target directory names a new entry.
        let Some(rename_target) = target_binding.rename_target else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        let mut target_name = Vec::new();
        target_name
            .try_reserve_exact(target.name.len())
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        target_name.extend_from_slice(target.name);

        let result = self.rename_to(
            binding, overlay_source, target_binding, rename_target, &target_name, replace_if_exists,
        );
        let terminal = match result {
            Ok(status) | Err(status) => status,
        };
        if terminal == NtStatus::SUCCESS {
            self.opens
                .rename(context, file_id.raw(), &target_name)
                .expect("the renamed File's published context and a name of admitted length");
            // The File now lives under the target name, which the installed layer may hold too.
            let index = context_index(context).expect("bounded layered table context index");
            self.bindings[index]
                .as_mut()
                .expect("the renamed File's published binding")
                .shadows_installed = rename_target.has_installed_entry();
        }
        trace_profile_hive_rename(&source_name, &target_name, replace_if_exists, terminal);
        result.map(|status| DispatchOutcome::Completed {
            status,
            information: 0,
            file_context: None,
        })
    }

    fn rename_to(
        &mut self,
        binding: MountedBinding,
        overlay_source: Option<u64>,
        target_binding: MountedBinding,
        rename_target: RenameTarget,
        target_name: &[u16],
        replace_if_exists: bool,
    ) -> Result<NtStatus, NtStatus> {
        let relative_name = target_name.strip_prefix(&[b'\\' as u16]).unwrap_or(target_name);
        let mut folded = [0; PATH_CAP];
        let mut relative = [0; PATH_CAP];
        let length = nt_fs::nt_file_relative_path_into(relative_name, &mut folded, &mut relative)
            .ok_or(NtStatus::OBJECT_NAME_INVALID)?;
        let relative = &relative[..length];
        let (parent, _) = nt_fs::rename_target_parent(relative).map_err(status)?;

        // A writable entry under the target name shadows the installed one; the writable
        // filesystem then decides collision, replacement and open handles for its own entry.
        let overlay_target =
            unsafe { crate::writable_fs::query_metadata_relative_if_mounted(relative) }
                .map_err(status)?;
        let installed_target = rename_target.installed.filter(|_| overlay_target.is_none());
        nt_fs::layered_rename_decision(nt_fs::LayeredRename {
            source_in_overlay: overlay_source.is_some(),
            source_shadows_installed: binding.shadows_installed,
            source_is_directory: binding.is_directory,
            installed_target: installed_target.map(|metadata| metadata.is_directory),
            installed_target_open: installed_target
                .is_some_and(|metadata| self.shares.has_open_handle(relative, metadata)),
            replace_if_exists,
        })
        .map_err(status)?;
        let overlay_source = overlay_source.expect("rename policy admitted a writable source");

        // The writable filesystem resolves the new name in its own tree, so a parent that so
        // far exists only in the installed layer is materialised there first. The target File
        // holds that installed directory open, which is the proof it exists.
        if !target_binding.overlay_open && !parent.is_empty() {
            unsafe { crate::writable_fs::ensure_installed_directory_relative(parent) }
                .map_err(status)?;
        }
        let mut name = Vec::new();
        name.try_reserve_exact(target_name.len() * 2)
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        for unit in target_name {
            name.extend_from_slice(&unit.to_le_bytes());
        }
        Ok(status(unsafe {
            crate::writable_fs::rename(
                overlay_source,
                nt_fs::FileRenameRoot::VolumeRoot,
                &name,
                replace_if_exists,
            )
        }))
    }
}
