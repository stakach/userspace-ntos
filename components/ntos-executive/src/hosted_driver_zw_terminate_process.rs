//! Kernel-mode `ZwTerminateProcess` for hosted drivers.
//!
//! The handle is decoded by ProcessManager under the authenticated native caller, so only a
//! real Process handle in the caller's (or, for OBJ_KERNEL_HANDLE, System's) table can name a
//! target. Termination applies NtTerminateProcess's remote policy at once; the hosted
//! mechanisms are reclaimed by `provider_process_termination` on the service loop.

use super::*;
use nt_process::native_handle::PsHandleType;

pub(super) const LABEL: u64 = 0x7DB;

/// `NTSTATUS ZwTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)`.
pub(super) extern "win64" fn zw_terminate_process(handle: u64, exit_status: i32) -> i32 {
    let (label, status, unused0, unused1, unused2) = unsafe {
        call_on4((LABEL << 12) | 2, handle, u64::from(exit_status as u32), 0, 0)
    };
    if label != 0 || unused0 != 0 || unused1 != 0 || unused2 != 0 {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, handle, label, status]); }
    }
    status as u32 as i32
}

pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    handle: u64,
    exit_status: u64,
    reply_cap: u64,
) -> i32 {
    if instance_for_pump_channel(ch, reply_cap).is_none() {
        return STATUS_ACCESS_DENIED;
    }
    let Ok(exit_status) = u32::try_from(exit_status) else { return STATUS_INVALID_PARAMETER };
    // NULL asks to terminate every other thread of the caller's own process (System here);
    // that is the critical initial process and has no driver-callable form.
    if handle == 0 {
        return STATUS_INVALID_HANDLE;
    }
    let caller = match unsafe { crate::provider_registry_caller::resolve(ch) } {
        Ok(caller) => caller,
        Err(status) => return status as i32,
    };
    let handler = match crate::service_sec_image::registry_live_handler_pointer() {
        Ok(handler) => unsafe { &mut *handler },
        Err(status) => return status as i32,
    };
    let target = (|| {
        handler.pm.validate_native_handle_caller(caller)?;
        let mut reference = handler.pm.reference_native_ps_handle(
            caller, handle, Some(PsHandleType::Process), nt_process::PROCESS_TERMINATE,
        )?;
        let object = reference.object();
        reference.release(&mut handler.pm)?;
        match object {
            nt_process::HandleObject::Process(pid) => Ok(pid),
            _ => Err(nt_process::native_handle::STATUS_OBJECT_TYPE_MISMATCH),
        }
    })();
    let pid = match target {
        Ok(pid) => pid,
        Err(status) => return status as i32,
    };
    if let Err(status) = crate::provider_process_termination::reserve() {
        return status as i32;
    }
    match unsafe { handler.terminate_process_for_provider(pid, exit_status) } {
        Ok(Some((process_index, identity))) => {
            crate::provider_process_termination::record(process_index, identity);
            STATUS_SUCCESS
        }
        Ok(None) => STATUS_SUCCESS,
        Err(status) => status as i32,
    }
}
