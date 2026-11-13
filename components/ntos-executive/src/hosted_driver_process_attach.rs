//! Exact same-process KAPC_STATE pairing for generic hosted drivers.
//!
//! A foreign-process attach requires a mapped client address-space window. Until one is
//! owned by this provider, that path fails terminally instead of claiming an attach.

use super::*;
use nt_kernel_exec::apc_state;

const APC_PROCESS_OFF: u64 = apc_state::KAPC_PROCESS_OFFSET as u64;
const ATTACH_BUGCHECK: u64 = 0x4b41_5443;

#[derive(Clone, Copy)]
struct SameProcessAttach {
    instance: usize,
    route: nt_component_suspension::peer_registry::PeerRoute,
    thread: nt_process::ThreadLifetime,
    apc_state: u64,
}

static mut ATTACHMENTS: Vec<SameProcessAttach> = Vec::new();

fn exchange(operation: u64, process: u64, apc_state: u64) -> u64 {
    let (_label, status, marker, _, _) = unsafe {
        call_on4(
            (FSD_SERVICE_KE_STACK_ATTACH_LABEL << 12) | 3,
            operation, process, apc_state, 0,
        )
    };
    if status as u32 as i32 != STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(
            0xc4, [ATTACH_BUGCHECK, operation, process, status],
        ); }
    }
    marker
}

/// `VOID KeStackAttachProcess(PRKPROCESS Process, PRKAPC_STATE ApcState)`.
pub(super) extern "win64" fn ke_stack_attach_process(process: u64, apc_state: u64) {
    if process == 0 || apc_state == 0 || apc_state & 7 != 0
        || apc_state.checked_add(APC_PROCESS_OFF + 8).is_none()
    {
        unsafe { crate::provider_bugcheck::report(0xc4, [ATTACH_BUGCHECK, 1, process, apc_state]); }
    }
    let marker = exchange(1, process, apc_state);
    if marker != 1 {
        unsafe { crate::provider_bugcheck::report(0xc4, [ATTACH_BUGCHECK, 1, marker, apc_state]); }
    }
    unsafe { write_volatile((apc_state + APC_PROCESS_OFF) as *mut u64, marker); }
}

/// `VOID KeUnstackDetachProcess(PRKAPC_STATE ApcState)`.
pub(super) extern "win64" fn ke_unstack_detach_process(apc_state: u64) {
    if apc_state == 0 || apc_state & 7 != 0
        || apc_state.checked_add(APC_PROCESS_OFF + 8).is_none()
    {
        unsafe { crate::provider_bugcheck::report(0xc4, [ATTACH_BUGCHECK, 2, apc_state, 0]); }
    }
    let marker = unsafe { read_volatile((apc_state + APC_PROCESS_OFF) as *const u64) };
    if marker != 1 || exchange(2, 0, apc_state) != 1 {
        unsafe { crate::provider_bugcheck::report(0xc4, [ATTACH_BUGCHECK, 2, apc_state, marker]); }
    }
}

/// The root owns the stack pairing. Component pointers are only compared as opaque tokens.
pub(crate) fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    operation: u64,
    process: u64,
    apc_state: u64,
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
    let lifetime = caller.original_thread();
    let original = unsafe { crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.validate_native_handle_caller(caller)?;
        pm.process_kernel_object(lifetime.process_id())
            .ok_or(nt_process::STATUS_INVALID_HANDLE)
    }) };
    let original = match original { Ok(value) => value, Err(status) => return (status as i32, 0) };
    if apc_state == 0 || apc_state & 7 != 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let records = unsafe { &mut *core::ptr::addr_of_mut!(ATTACHMENTS) };
    match operation {
        1 => {
            if process != original { return (STATUS_NOT_SUPPORTED, 0); }
            if records.iter().any(|row| row.instance == instance
                && row.route == physical.route && row.apc_state == apc_state)
            {
                return (STATUS_INVALID_PARAMETER, 0);
            }
            if records.try_reserve(1).is_err() { return (STATUS_INSUFFICIENT_RESOURCES, 0); }
            records.push(SameProcessAttach {
                instance, route: physical.route, thread: lifetime, apc_state,
            });
            (STATUS_SUCCESS, 1)
        }
        2 => {
            if process != 0 { return (STATUS_INVALID_PARAMETER, 0); }
            let Some(index) = records.iter().position(|row| row.instance == instance
                && row.route == physical.route && row.thread == lifetime
                && row.apc_state == apc_state)
            else { return (STATUS_INVALID_HANDLE, 0); };
            records.swap_remove(index);
            (STATUS_SUCCESS, 1)
        }
        _ => (STATUS_INVALID_PARAMETER, 0),
    }
}
