//! Generic driver priority changes through the canonical PM/native TCB effect owner.

use super::*;

/// `KPRIORITY KeSetPriorityThread(PKTHREAD Thread, KPRIORITY Priority)`.
pub(super) extern "win64" fn ke_set_priority_thread(thread: u64, priority: i32) -> i32 {
    let (_label, status, previous, _, _) = unsafe {
        call_on4(
            (FSD_SERVICE_KE_SET_PRIORITY_THREAD_LABEL << 12) | 2,
            thread,
            priority as u32 as u64,
            0,
            0,
        )
    };
    if status as u32 as i32 != STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(
            0xc4, [FSD_SERVICE_KE_SET_PRIORITY_THREAD_LABEL, thread, priority as u32 as u64, status],
        ); }
    }
    previous as u32 as i32
}

/// The physical caller and retained registry requestor are checked before accessing the
/// canonical PM thread. A system worker has its own PM ETHREAD and a separate physical TCB.
pub(crate) fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    thread: u64,
    priority: i32,
    caller_badge: u64,
    active_reply_cap: u64,
) -> (i32, u64) {
    let Some((instance, inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return (STATUS_INVALID_PARAMETER, 0);
    };
    let Some(physical) = hosted_driver_caller(instance, inst, caller_badge) else {
        return (STATUS_INVALID_HANDLE, 0);
    };
    let caller = match unsafe { crate::provider_registry_caller::resolve(channel) } {
        Ok(caller) => caller,
        Err(status) => return (status as i32, 0),
    };
    let verified = unsafe { crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.validate_native_handle_caller(caller)?;
        let lifetime = caller.original_thread();
        if pm.thread_kernel_object(lifetime.thread_id()) != Some(thread)
            || !pm.validate_thread_lifetime(lifetime)
        {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        Ok(())
    }) };
    if let Err(status) = verified {
        return (status as i32, 0);
    }
    if let Some(runtime) = physical.runtime {
        let result = unsafe {
            hosted_driver_worker_priority::dispatch(
                runtime, caller.original_thread(), thread, priority,
            )
        };
        return match result {
            Ok(previous) => (STATUS_SUCCESS, previous as u32 as u64),
            Err(status) => (status as i32, 0),
        };
    }
    // Primary dispatches reuse native_thread_priority::dispatch and its retained PM/TCB owner.
    // No component pointer or scheduler handle crosses this IPC boundary.
    unsafe { crate::service_sec_image::service_hosted_driver_thread_priority(thread, priority) }
}
