//! `IRP_MJ_SET_INFORMATION` on a File the mounted volume opened.

use super::*;

impl MountedVolumeBackend {
    pub(super) fn set_information(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        let (context, binding) = self.binding(irp)?;
        let IoParameters::SetInformation(parameters) = irp.parameters else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        if parameters.info_class == nt_fs::FILE_RENAME_INFORMATION {
            return self.rename(irp, context, binding, parameters);
        }
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
}
