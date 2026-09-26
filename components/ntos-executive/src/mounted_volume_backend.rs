//! Canonical File IRP dispatch for regular files on the mounted FAT volume.
//!
//! The installed layer is immutable. CREATE owns both a generation-fenced File context and a
//! share-access open; CLEANUP drops the share open and CLOSE drops the File context. No later
//! operation re-resolves the name to select a different backing file.

use alloc::vec::Vec;

use nt_io_abi::major;
use nt_io_manager::{
    DispatchContext, DispatchOutcome, DriverCompletion, DriverDispatchBackend, IoParameters, IrpId,
    IrpProjection,
};
use nt_status::NtStatus;

use crate::fs_loader::{fat_open_path_metadata_from, fat_read_file_range, FatOpenMetadata};

const OPEN_CAP: usize = 64;
const PATH_CAP: usize = nt_fs::LAYERED_OPEN_NAME_CAP;

#[derive(Clone, Copy)]
struct MountedBinding {
    context: nt_fs::LayeredOpenContextId,
    share_open: Option<u32>,
    directory_open: Option<u32>,
    overlay_open: bool,
    is_directory: bool,
    granted_access: u32,
    create_options: u32,
}

pub(crate) struct MountedVolumeBackend {
    fs: crate::Fat32,
    opens: nt_fs::LayeredOpenTable<OPEN_CAP>,
    shares: nt_fs::ReadOnlyFileOpenTable<OPEN_CAP>,
    directories: nt_fs::DirectoryOpenTable<OPEN_CAP>,
    bindings: Vec<Option<MountedBinding>>,
}

impl MountedVolumeBackend {
    pub(crate) fn new(fs: crate::Fat32) -> Result<Self, NtStatus> {
        let mut bindings = Vec::new();
        bindings
            .try_reserve_exact(OPEN_CAP)
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        bindings.resize(OPEN_CAP, None);
        Ok(Self {
            fs,
            opens: nt_fs::LayeredOpenTable::new(),
            shares: nt_fs::ReadOnlyFileOpenTable::new(),
            directories: nt_fs::DirectoryOpenTable::new(),
            bindings,
        })
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
        if parameters.related_file.is_some()
            || parameters.ea_length != 0
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

        // FILE_OBJECT.FileName is device-relative. Preserve it verbatim in the File context, but
        // use the existing bounded FAT canonicalizer for lookup and sharing.
        let units = name.as_units();
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
        if options & nt_fs::FILE_NON_DIRECTORY_FILE != 0 {
            return Err(status(nt_fs::STATUS_FILE_IS_A_DIRECTORY));
        }
        if overlay.is_some_and(|entry| !entry.is_directory)
            || (overlay.is_none() && installed.is_some_and(|entry| !entry.metadata.is_directory))
        {
            return Err(status(nt_fs::STATUS_NOT_A_DIRECTORY));
        }
        if overlay.is_none() && installed.is_none() {
            return Err(NtStatus::NOT_SUPPORTED);
        }
        if relative.is_empty() && options & nt_fs::FILE_DELETE_ON_CLOSE != 0 {
            return Err(status(nt_fs::STATUS_CANNOT_DELETE));
        }
        if !matches!(
            parameters.create_disposition,
            nt_fs::FILE_CREATE | nt_fs::FILE_OPEN | nt_fs::FILE_OPEN_IF
        ) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if parameters.create_disposition == nt_fs::FILE_CREATE {
            return Err(NtStatus::OBJECT_NAME_COLLISION);
        }
        if let Some(source) = installed.filter(|source| source.metadata.is_directory) {
            self.directories
                .check_share(relative, source.metadata, access, share)
                .map_err(status)?;
            let action = nt_fs::installed_file_open_action(
                access,
                parameters.create_disposition,
                options & !nt_fs::FILE_DIRECTORY_FILE,
            )
            .map_err(status)?;
            if action != nt_fs::InstalledFileOpenAction::ReadOnly {
                return Err(NtStatus::NOT_SUPPORTED);
            }
            if overlay.is_none() || relative.is_empty() {
                return self.create_installed_directory(
                    file_id, units, relative, source, access, share, options,
                );
            }
        }
        self.create_overlay(
            file_id, units, relative, installed, None, false, true, parameters,
        )
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
        let context = self.opens.reserve(file_id, units).map_err(status)?;
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
            share_open: None,
            directory_open: Some(directory_open),
            overlay_open: false,
            is_directory: true,
            granted_access: access,
            create_options: options,
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
        let context = self.opens.reserve(file_id, units).map_err(status)?;
        let share_open = match self.shares.create(
            installed.first_cluster,
            installed.metadata.end_of_file.min(u32::MAX as u64) as u32,
            relative,
            access,
            share,
            options,
            installed.metadata,
            installed.alternate_name,
        ) {
            Ok(share_open) => share_open,
            Err(error) => {
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
            share_open: Some(share_open),
            directory_open: None,
            overlay_open: false,
            is_directory: false,
            granted_access: access,
            create_options: options,
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
        let access = parameters.desired_access.bits();
        let share = parameters.share_access.bits();
        let options = parameters.create_options.bits();
        if let Some(source) = installed {
            self.shares
                .check_share(relative, source.metadata, access, share)
                .map_err(status)?;
        }
        let context = self.opens.reserve(file_id, units).map_err(status)?;
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
            share_open: None,
            directory_open: None,
            overlay_open: true,
            is_directory,
            granted_access: access,
            create_options: options,
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
        let share_open = binding.share_open.ok_or(NtStatus::INVALID_HANDLE)?;
        let offset = u32::try_from(parameters.offset).map_err(|_| NtStatus::INVALID_PARAMETER)?;
        self.shares.get(share_open).map_err(status)?;
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
        if self.shares.get(share_open).map_err(status)?.create_options
            & (nt_fs::FILE_SYNCHRONOUS_IO_ALERT | nt_fs::FILE_SYNCHRONOUS_IO_NONALERT)
            != 0
        {
            self.shares
                .get_mut(share_open)
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
                        .get(binding.share_open.ok_or(NtStatus::INVALID_HANDLE)?)
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
        if let Some(share_open) = binding.share_open {
            self.shares.release(share_open).map_err(status)?;
            self.bindings[index]
                .as_mut()
                .expect("validated binding")
                .share_open = None;
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
