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

use crate::fs_loader::{fat_open_path_metadata_from, fat_read_file_range};

const OPEN_CAP: usize = 64;
const PATH_CAP: usize = nt_fs::LAYERED_OPEN_NAME_CAP;

#[derive(Clone, Copy)]
struct InstalledBinding {
    context: nt_fs::LayeredOpenContextId,
    share_open: Option<u32>,
    granted_access: u32,
}

pub(crate) struct MountedVolumeBackend {
    fs: crate::Fat32,
    opens: nt_fs::LayeredOpenTable<OPEN_CAP>,
    shares: nt_fs::ReadOnlyFileOpenTable<OPEN_CAP>,
    bindings: Vec<Option<InstalledBinding>>,
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
        let length = nt_fs::nt_file_relative_path_into(relative_name, &mut folded, &mut relative)
            .ok_or(NtStatus::OBJECT_NAME_INVALID)?;
        let relative = &relative[..length];

        let installed =
            match unsafe { fat_open_path_metadata_from(&self.fs, self.fs.root_cl, relative) } {
                Some(installed) => installed,
                None if parameters.create_disposition == nt_fs::FILE_OPEN => {
                    return Err(NtStatus::OBJECT_NAME_NOT_FOUND);
                }
                None => return Err(NtStatus::NOT_SUPPORTED),
            };
        if installed.metadata.is_directory {
            return Err(status(nt_fs::STATUS_FILE_IS_A_DIRECTORY));
        }
        match nt_fs::installed_file_open_action(access, parameters.create_disposition, options)
            .map_err(status)?
        {
            nt_fs::InstalledFileOpenAction::NameCollision => {
                return Err(NtStatus::OBJECT_NAME_COLLISION);
            }
            nt_fs::InstalledFileOpenAction::ReadOnly => {}
            nt_fs::InstalledFileOpenAction::CopyContents
            | nt_fs::InstalledFileOpenAction::CopyMetadata => {
                return Err(NtStatus::NOT_SUPPORTED);
            }
        }

        let share_open = self
            .shares
            .create(
                installed.first_cluster,
                installed.metadata.end_of_file.min(u32::MAX as u64) as u32,
                relative,
                access,
                share,
                options,
                installed.metadata,
                installed.alternate_name,
            )
            .map_err(status)?;
        let context = match self.opens.insert(
            file_id.raw(),
            nt_fs::LayeredOpenSource::Installed {
                first_cluster: installed.first_cluster,
                metadata: installed.metadata,
                alternate_name: installed.alternate_name,
            },
            units,
        ) {
            Ok(context) => context,
            Err(error) => {
                let _ = self.shares.release(share_open);
                return Err(status(error));
            }
        };
        let index = context_index(context).expect("bounded layered table context index");
        debug_assert!(self.bindings[index].is_none());
        self.bindings[index] = Some(InstalledBinding {
            context,
            share_open: Some(share_open),
            granted_access: access,
        });
        Ok(DispatchOutcome::Completed {
            status: NtStatus::SUCCESS,
            information: nt_fs::FILE_OPENED as u64,
            file_context: Some(context.raw()),
        })
    }

    fn binding(
        &self,
        irp: &IrpProjection,
    ) -> Result<(nt_fs::LayeredOpenContextId, InstalledBinding), NtStatus> {
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
        let share_open = binding.share_open.ok_or(NtStatus::INVALID_HANDLE)?;
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
        let offset = u32::try_from(parameters.offset).map_err(|_| NtStatus::INVALID_PARAMETER)?;
        let file_id = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        let record = self.opens.get(context, file_id.raw()).map_err(status)?;
        let nt_fs::LayeredOpenSource::Installed {
            first_cluster,
            metadata,
            ..
        } = record.source
        else {
            return Err(NtStatus::INVALID_HANDLE);
        };
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
        let share_open = binding.share_open.ok_or(NtStatus::INVALID_HANDLE)?;
        let IoParameters::QueryInformation(parameters) = &irp.parameters else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        let capacity = (parameters.length as usize).min(ctx.system_buffer.len());
        let output = &mut ctx.system_buffer[..capacity];
        let file_id = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        let record = self.opens.get(context, file_id.raw()).map_err(status)?;
        let nt_fs::LayeredOpenSource::Installed {
            metadata,
            alternate_name,
            ..
        } = record.source
        else {
            return Err(NtStatus::INVALID_HANDLE);
        };
        let open = self.shares.get(share_open).map_err(status)?;
        let mut query = metadata.query_metadata();
        query.current_byte_offset = open.current_offset;
        query.access_flags = binding.granted_access;
        query.mode = open.create_options;
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
        if close {
            let file_id = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
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
