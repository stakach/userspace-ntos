//! Hosted-driver anonymous Event creation backed by the executive EventStore
//! and the caller's canonical ProcessManager handle table.

use super::*;
use nt_ntdll_layout::ObjectAttributes;

pub(super) const LABEL: u64 = 0x7C6;

fn anonymous_attributes(pointer: u64) -> Result<u32, i32> {
    if pointer == 0 {
        return Ok(0);
    }
    // The caller is a native driver executing in this component's address
    // space. Capture the fixed-size structure before provider IPC; no driver
    // address is ever dereferenced by the executive.
    let attributes = unsafe { read_unaligned(pointer as *const ObjectAttributes) };
    if attributes.length as usize != core::mem::size_of::<ObjectAttributes>() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if attributes.object_name != 0 || attributes.root_directory != 0
        || attributes.security_descriptor != 0 || attributes.security_quality_of_service != 0
    {
        return Err(STATUS_NOT_SUPPORTED);
    }
    if attributes.attributes & !nt_process::native_handle::OBJ_KERNEL_HANDLE != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(attributes.attributes)
}

/// `NTSTATUS ZwCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
/// EVENT_TYPE, BOOLEAN)`.
pub(super) extern "win64" fn zw_create_event(
    handle_out: *mut u64,
    desired_access: u32,
    object_attributes: u64,
    event_type: u32,
    initial_state: u8,
) -> i32 {
    if handle_out.is_null() {
        return STATUS_ACCESS_VIOLATION;
    }
    unsafe { write_unaligned(handle_out, 0); }
    let attributes = match anonymous_attributes(object_attributes) {
        Ok(attributes) => attributes,
        Err(status) => return status,
    };
    let packed = u64::from(desired_access) | (u64::from(event_type) << 32);
    unsafe {
        let (words, raw, handle, unused0, unused1) = call_on4_raw(
            (LABEL << 12) | 4,
            packed,
            u64::from(attributes),
            u64::from(initial_state != 0),
            0,
        );
        let canonical_status = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        if words != 4 || !canonical_status || unused0 != 0 || unused1 != 0
            || (raw as u32 as i32 == STATUS_SUCCESS) != (handle != 0)
        {
            crate::provider_bugcheck::report(0xc4, [LABEL, packed, words, raw]);
        }
        if raw as u32 as i32 == STATUS_SUCCESS {
            write_unaligned(handle_out, handle);
        }
        raw as u32 as i32
    }
}

/// The pump authenticates badge and Reply before calling this endpoint. The
/// provider revalidates the exact driver instance and native caller. Named
/// Event creation remains an explicit unsupported operation until its name
/// and security descriptor can be captured into this driver-domain broker.
pub(crate) fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    packed: u64,
    attributes: u64,
    initial_state: u64,
    active_reply_cap: u64,
) -> (i32, u64) {
    let Some((_instance, _inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return (STATUS_INVALID_HANDLE, 0);
    };
    let access = packed as u32;
    let event_type = (packed >> 32) as u32;
    if event_type > 1 || initial_state > 1 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    if attributes & !u64::from(nt_process::native_handle::OBJ_KERNEL_HANDLE) != 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let caller = match unsafe { crate::provider_registry_caller::resolve(channel) } {
        Ok(caller) => caller,
        Err(status) => return (status as i32, 0),
    };
    let verified = unsafe {
        crate::service_sec_image::with_provider_process_manager(|pm| {
            pm.validate_native_handle_caller(caller)
        })
    };
    if let Err(status) = verified {
        return (status as i32, 0);
    }
    let handler = match crate::service_sec_image::registry_live_handler_pointer() {
        Ok(handler) => handler,
        Err(status) => return (status as i32, 0),
    };
    unsafe {
        let handler = &mut *handler;
        let pi = handler.pi_for_pid(caller.effective_process());
        if pi.is_some_and(|pi|
            handler.pm_pid_for_pi(pi) != Some(caller.effective_process())) {
            return (STATUS_INVALID_HANDLE, 0);
        }
        match handler.provider_create_event_with_attributes(
            caller,
            pi,
            access,
            event_type,
            initial_state != 0,
            attributes as u32,
        ) {
            Ok(handle) if handle != 0 => (STATUS_SUCCESS, handle),
            Ok(_) => (nt_process::STATUS_INSUFFICIENT_RESOURCES as i32, 0),
            Err(status) => (status as i32, 0),
        }
    }
}
