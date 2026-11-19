//! Native ObjectHandleFlagInformation adapter for win32k's kernel stack buffer.

use super::*;

/// `ObSetHandleAttributes(HANDLE, POBJECT_HANDLE_FLAG_INFORMATION, KPROCESSOR_MODE)`.
/// The pinned caller supplies a two-byte kernel stack value; the flags belong to the exact
/// entry in the caller's ProcessManager table.
pub(super) extern "win64" fn set_handle_attributes(
    handle: u64,
    information: u64,
    previous_mode: u8,
) -> i32 {
    if previous_mode != 0 {
        return STATUS_INVALID_PARAMETER_I32;
    }
    if information == 0 || information.checked_add(1).is_none() {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    let encoded = unsafe { core::ptr::read_unaligned(information as *const u16) };
    let (status, _, _, _) = unsafe {
        win32k_ps_broker_call(W32_PS_OP_SET_OBJECT_HANDLE_FLAGS, handle, u64::from(encoded))
    };
    status
}

pub(super) fn query_information(
    handle: u64,
    information: u64,
    length: u32,
    return_length: u64,
) -> i32 {
    if return_length != 0 {
        unsafe { write_unaligned(return_length as *mut u32, 2) };
    }
    if length != 2 {
        return nt_process::STATUS_INFO_LENGTH_MISMATCH as i32;
    }
    if information == 0 {
        return 0xC000_0005u32 as i32; // STATUS_ACCESS_VIOLATION
    }
    let (status, encoded, _, _) = unsafe {
        win32k_ps_broker_call(W32_PS_OP_QUERY_OBJECT_HANDLE_FLAGS, handle, 0)
    };
    if status != 0 {
        return status;
    }
    if encoded > u16::MAX as u64 {
        unsafe { crate::provider_bugcheck::report(0xc4, [W32_PS_LABEL, handle, 4, encoded]) };
    }
    unsafe { write_unaligned(information as *mut u16, encoded as u16) };
    0
}

/// Win32k supplies a kernel buffer, not a user pointer. Capture both bytes before IPC so
/// the request no longer depends on the caller's stack while the executive mutates the
/// authenticated handle table.
pub(super) extern "win64" fn set_information_object(
    handle: u64,
    class: u32,
    information: u64,
    length: u32,
) -> i32 {
    if class != 4 {
        return nt_process::STATUS_INVALID_INFO_CLASS as i32;
    }
    if length != 2 {
        return nt_process::STATUS_INFO_LENGTH_MISMATCH as i32;
    }
    if information == 0 || information.checked_add(1).is_none() {
        return 0xC000_0005u32 as i32; // STATUS_ACCESS_VIOLATION
    }
    let encoded = unsafe { core::ptr::read_unaligned(information as *const u16) };
    let (status, _, _, _) = unsafe {
        win32k_ps_broker_call(W32_PS_OP_SET_OBJECT_HANDLE_FLAGS, handle, u64::from(encoded))
    };
    status
}
