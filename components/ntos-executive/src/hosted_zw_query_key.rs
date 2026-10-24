//! Hosted-driver `ZwQueryKey` over the same authenticated registry handle table
//! used by its other Zw registry calls.

use super::*;

pub(super) const HOSTED_REGISTRY_OP_QUERY_KEY: u64 = 17;

/// The enclosing registry broker has authenticated the physical call, native
/// caller, and retained Reply. Only a copied information buffer crosses back
/// into the component's shared argument frame.
pub(super) unsafe fn service(
    caller: nt_process::native_handle::NativeHandleCaller,
    arg: u64,
    handle: u64,
    information_class: u64,
) -> (i32, u64, u64) {
    let Ok(class) = u32::try_from(information_class) else {
        return (STATUS_INVALID_PARAMETER, 0, 0);
    };
    let Ok(slot) = driver_registry_handle_slot(caller, handle, 1) else {
        return (STATUS_INVALID_HANDLE, 0, 0);
    };
    let (encoded, minimum) = match driver_registry_operations::query_key(slot.target, class) {
        Ok(result) => result,
        Err(status) => return (status, 0, 0),
    };
    if encoded.len() > HOSTED_REGISTRY_VALUE_SCRATCH_MAX || minimum > encoded.len() {
        return (STATUS_BUFFER_TOO_SMALL, encoded.len() as u64, minimum as u64);
    }
    core::ptr::copy_nonoverlapping(
        encoded.as_ptr(),
        (arg + HOSTED_REGISTRY_ARG_DATA_OFF) as *mut u8,
        encoded.len(),
    );
    write_volatile((arg + HOSTED_REGISTRY_ARG_DATA_LEN) as *mut u32, encoded.len() as u32);
    (STATUS_SUCCESS, encoded.len() as u64, minimum as u64)
}

/// `NTSTATUS ZwQueryKey(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG)`.
pub(super) extern "win64" fn s_zw_query_key(
    handle: u64,
    information_class: u32,
    information: u64,
    length: u32,
    result_length: u64,
) -> i32 {
    unsafe {
        if result_length == 0 {
            return STATUS_ACCESS_VIOLATION;
        }
        let (status, required, minimum) = hosted_registry_broker_call(
            HOSTED_REGISTRY_OP_QUERY_KEY,
            handle,
            information_class as u64,
            0,
        );
        if status != STATUS_SUCCESS {
            write_unaligned(
                result_length as *mut u32,
                if status == STATUS_BUFFER_TOO_SMALL {
                    u32::try_from(required).unwrap_or(0)
                } else {
                    0
                },
            );
            return status;
        }
        let (Ok(required), Ok(minimum)) = (usize::try_from(required), usize::try_from(minimum))
        else {
            return STATUS_INVALID_PARAMETER;
        };
        if required > HOSTED_REGISTRY_VALUE_SCRATCH_MAX
            || required > u32::MAX as usize
            || minimum > required
        {
            return STATUS_INVALID_PARAMETER;
        }
        write_unaligned(result_length as *mut u32, required as u32);
        if (length as usize) < minimum {
            return STATUS_BUFFER_TOO_SMALL;
        }
        let copy_len = (length as usize).min(required);
        if copy_len != 0 {
            if information == 0 {
                return STATUS_ACCESS_VIOLATION;
            }
            core::ptr::copy_nonoverlapping(
                (FSD_ARG_VADDR + HOSTED_REGISTRY_ARG_DATA_OFF) as *const u8,
                information as *mut u8,
                copy_len,
            );
        }
        if copy_len < required {
            STATUS_BUFFER_OVERFLOW as i32
        } else {
            STATUS_SUCCESS
        }
    }
}
