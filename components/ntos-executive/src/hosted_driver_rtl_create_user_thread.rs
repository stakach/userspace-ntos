//! Kernel-mode `RtlCreateUserThread` for hosted drivers (ConDrv's console control delivery).
//!
//! The root resolves the process handle under the authenticated kernel caller and builds the
//! thread with the same constructor-stack mechanism NtCreateThreadEx commits. The handle and
//! ClientId are returned only after that mechanism exists.

use super::*;

pub(super) const LABEL: u64 = 0x7DC;

/// `NTSTATUS RtlCreateUserThread(HANDLE Process, PSECURITY_DESCRIPTOR, BOOLEAN CreateSuspended,
/// ULONG StackZeroBits, SIZE_T MaximumStackSize, SIZE_T CommittedStackSize,
/// PUSER_THREAD_START_ROUTINE StartAddress, PVOID Parameter, PHANDLE ThreadHandle,
/// PCLIENT_ID ClientId)`.
pub(super) extern "win64" fn rtl_create_user_thread(
    process: u64,
    security_descriptor: u64,
    create_suspended: u8,
    stack_zero_bits: u32,
    maximum_stack_size: u64,
    committed_stack_size: u64,
    start_address: u64,
    parameter: u64,
    thread_handle: u64,
    client_id: u64,
) -> i32 {
    if thread_handle != 0 {
        unsafe { write_unaligned(thread_handle as *mut u64, 0); }
    }
    // The worker-window stack is fixed and kernel-built; caller stack geometry and an explicit
    // security descriptor are refused rather than silently ignored.
    if security_descriptor != 0 || stack_zero_bits != 0
        || maximum_stack_size != 0 || committed_stack_size != 0
    {
        return STATUS_NOT_SUPPORTED;
    }
    let (label, status, handle, pid, tid) = unsafe {
        call_on4(
            (LABEL << 12) | 4,
            process,
            start_address,
            parameter,
            u64::from(create_suspended != 0),
        )
    };
    let status = status as u32 as i32;
    if label != 0 || (status == STATUS_SUCCESS) != (handle != 0 && pid != 0 && tid != 0) {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, process, label, status as u32 as u64]); }
    }
    if status != STATUS_SUCCESS {
        return status;
    }
    unsafe {
        if client_id != 0 {
            write_unaligned(client_id as *mut u64, pid);
            write_unaligned((client_id + 8) as *mut u64, tid);
        }
        if thread_handle != 0 {
            write_unaligned(thread_handle as *mut u64, handle);
        } else {
            // NT closes the handle when the caller did not ask for it.
            let closed = s_zw_close(handle);
            if closed != STATUS_SUCCESS {
                crate::provider_bugcheck::report(0xc4, [LABEL, handle, closed as u32 as u64, 1]);
            }
        }
    }
    STATUS_SUCCESS
}

pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    process: u64,
    start_address: u64,
    parameter: u64,
    create_suspended: u64,
    reply_cap: u64,
) -> (i32, u64, u64, u64) {
    if instance_for_pump_channel(ch, reply_cap).is_none() {
        return (STATUS_ACCESS_DENIED, 0, 0, 0);
    }
    if create_suspended > 1 {
        return (STATUS_INVALID_PARAMETER, 0, 0, 0);
    }
    let caller = match unsafe { crate::provider_registry_caller::resolve(ch) } {
        Ok(caller) => caller,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    let handler = match crate::service_sec_image::registry_live_handler_pointer() {
        Ok(handler) => unsafe { &mut *handler },
        Err(status) => return (status as i32, 0, 0, 0),
    };
    match unsafe {
        handler.create_user_thread_for_provider(
            caller, process, start_address, parameter, create_suspended != 0,
        )
    } {
        Ok((handle, pid, tid)) => (STATUS_SUCCESS, handle, pid, tid),
        Err(status) => (status as i32, 0, 0, 0),
    }
}
