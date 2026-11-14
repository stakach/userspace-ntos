//! File information on a File the mounted volume opened: `IRP_MJ_SET_INFORMATION`, and the
//! boot-log record of the information classes this volume refused.
//!
//! Policy across the installed and writable layers is `nt_fs`'s; the writable filesystem
//! validates and applies each class to its own File. This module binds both to the Files this
//! backend opened.

use super::*;

/// Distinct refusals a boot log names, one line each.
const REFUSAL_TRACE_CAP: usize = 32;

/// The information classes this volume refused, per direction, already written to the log.
#[derive(Default)]
pub(super) struct InformationRefusals {
    query: nt_fs::RefusalLedger<REFUSAL_TRACE_CAP>,
    set: nt_fs::RefusalLedger<REFUSAL_TRACE_CAP>,
}

fn terminal_status(outcome: &Result<DispatchOutcome, NtStatus>) -> Option<NtStatus> {
    match outcome {
        Ok(DispatchOutcome::Completed { status, .. })
        | Ok(DispatchOutcome::Failed { status })
        | Err(status) => Some(*status),
        Ok(DispatchOutcome::Pending) => None,
    }
}

impl MountedVolumeBackend {
    /// One line per `(class, status)` for an information class this volume does not serve, so
    /// a boot log lists the remaining gaps once however often a caller retries them.
    fn trace_information_refusal(
        &self,
        operation: &[u8],
        irp: &IrpProjection,
        class: u32,
        status: NtStatus,
    ) {
        crate::print_str(b"[mounted-file-information] unsupported ");
        crate::print_str(operation);
        crate::print_str(b" class=");
        crate::print_u64(u64::from(class));
        crate::print_str(b" status=");
        crate::print_hex(status.raw() as u32);
        if let Ok((context, binding)) = self.binding(irp) {
            let record = irp
                .file_id
                .and_then(|file| self.opens.get(context, file.raw()).ok());
            crate::print_str(b" backing=");
            crate::print_str(match record.map(|record| record.source) {
                Some(nt_fs::LayeredOpenSource::Volume) => b"volume".as_slice(),
                Some(nt_fs::LayeredOpenSource::Installed { .. }) => b"installed".as_slice(),
                Some(nt_fs::LayeredOpenSource::Overlay { .. }) => b"writable".as_slice(),
                None => b"?".as_slice(),
            });
            crate::print_str(b" directory=");
            crate::print_u64(binding.is_directory as u64);
            crate::print_str(b" shadows-installed=");
            crate::print_u64(binding.shadows_installed as u64);
            crate::print_str(b" path=\"");
            mounted_rename::print_name(record.map_or(&[], |record| record.name));
            crate::print_str(b"\"");
        }
        crate::print_str(b"\n");
    }

    /// Record a query the backend refused because it does not encode the class.
    pub(super) fn note_query_refusal(
        &mut self,
        irp: &IrpProjection,
        outcome: &Result<DispatchOutcome, NtStatus>,
    ) {
        let IoParameters::QueryInformation(parameters) = &irp.parameters else {
            return;
        };
        let class = parameters.info_class;
        let Some(refused) = terminal_status(outcome)
            .filter(|refused| refused.raw() as u32 == nt_fs::STATUS_INVALID_INFO_CLASS)
        else {
            return;
        };
        if self.information_refusals.query.first_report(class, refused.raw() as u32) {
            self.trace_information_refusal(b"query", irp, class, refused);
        }
    }

    pub(super) fn set_information(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        let (context, binding) = self.binding(irp)?;
        let IoParameters::SetInformation(parameters) = irp.parameters else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        let class = parameters.info_class;
        let outcome = if class == nt_fs::FILE_RENAME_INFORMATION {
            self.rename(irp, context, binding, parameters)
        } else {
            self.set_file_information(ctx, irp, context, binding, parameters)
        };
        // STATUS_NOT_SUPPORTED is the class, or the layering, this volume cannot yet serve.
        if let Some(refused) =
            terminal_status(&outcome).filter(|refused| *refused == NtStatus::NOT_SUPPORTED)
        {
            if self.information_refusals.set.first_report(class, refused.raw() as u32) {
                self.trace_information_refusal(b"set", irp, class, refused);
            }
        }
        outcome
    }

    /// Every set class except rename: decide it against the layers, then let the owner of the
    /// File's state apply it.
    fn set_file_information(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
        context: nt_fs::LayeredOpenContextId,
        binding: MountedBinding,
        parameters: nt_io_manager::SetInformationParameters,
    ) -> Result<DispatchOutcome, NtStatus> {
        let class = parameters.info_class;
        let length = parameters.length as usize;
        if parameters.target_file.is_some()
            || !matches!(parameters.control, nt_io_manager::SetInformationControl::None)
            || length > ctx.system_buffer.len()
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let payload = &ctx.system_buffer[..length];
        let file_id = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        let source = self.opens.get(context, file_id.raw()).map_err(status)?.source;
        // The I/O Manager checks a handle's grant; a kernel caller names this File directly.
        if nt_io_manager::set_information_contract(class).is_some_and(|contract| {
            !contract.access_granted(nt_types::AccessMask::from_bits_retain(binding.granted_access))
        }) {
            return Err(NtStatus::ACCESS_DENIED);
        }
        let action = nt_fs::layered_set_information_decision(
            nt_fs::LayeredSetInformation {
                class,
                backing: match source {
                    nt_fs::LayeredOpenSource::Volume => nt_fs::LayeredFileBacking::Volume,
                    nt_fs::LayeredOpenSource::Installed { .. } => {
                        nt_fs::LayeredFileBacking::Installed
                    }
                    nt_fs::LayeredOpenSource::Overlay { .. } => nt_fs::LayeredFileBacking::Writable,
                },
                is_directory: binding.is_directory,
                shadows_installed: binding.shadows_installed,
            },
            payload,
        )
        .map_err(status)?;
        let result = match action {
            nt_fs::LayeredSetInformationAction::Writable => {
                let nt_fs::LayeredOpenSource::Overlay { file_id: overlay_file } = source else {
                    unreachable!("set-information policy selected the writable filesystem");
                };
                if !binding.overlay_open {
                    return Err(NtStatus::INVALID_HANDLE);
                }
                status(unsafe { crate::writable_fs::set_information(overlay_file, class, payload) })
            }
            nt_fs::LayeredSetInformationAction::InstalledPosition(offset) => {
                let installed_open = binding.installed_open.ok_or(NtStatus::INVALID_HANDLE)?;
                self.shares.get_mut(installed_open).map_err(status)?.current_offset = offset;
                NtStatus::SUCCESS
            }
            nt_fs::LayeredSetInformationAction::Unchanged => NtStatus::SUCCESS,
        };
        Ok(DispatchOutcome::Completed {
            status: result,
            information: 0,
            file_context: None,
        })
    }
}
