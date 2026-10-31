//! Native value enumeration for hosted drivers, over the existing registry handle authority.

use super::*;

/// The sync broker has already authenticated the physical ingress, Reply and registry caller.
/// No value bytes or raw pointers cross the component boundary; only the encoded result is staged
/// in the caller's ARG frame after the native handle's read access is checked.
pub(super) unsafe fn service(
    caller: nt_process::native_handle::NativeHandleCaller,
    arg: u64,
    handle: u64,
    index: u64,
    class: u64,
) -> (i32, u64, u64) {
    let Ok(index) = u32::try_from(index) else {
        return (STATUS_INVALID_PARAMETER, 0, 0);
    };
    let Ok(slot) = driver_registry_handle_slot(caller, handle, 1) else {
        return (STATUS_INVALID_HANDLE, 0, 0);
    };
    let (encoded, minimum) =
        match driver_registry_operations::enumerate_value(slot.target, index, class) {
            Ok(result) => result,
            Err(status) => return (status, 0, 0),
        };
    if encoded.len() > HOSTED_REGISTRY_VALUE_SCRATCH_MAX || minimum > encoded.len() {
        return (
            STATUS_BUFFER_TOO_SMALL,
            encoded.len() as u64,
            minimum as u64,
        );
    }
    core::ptr::copy_nonoverlapping(
        encoded.as_ptr(),
        (arg + HOSTED_REGISTRY_ARG_DATA_OFF) as *mut u8,
        encoded.len(),
    );
    write_volatile(
        (arg + HOSTED_REGISTRY_ARG_DATA_LEN) as *mut u32,
        encoded.len() as u32,
    );
    (STATUS_SUCCESS, encoded.len() as u64, minimum as u64)
}

/// `NTSTATUS ZwEnumerateValueKey(HANDLE, ULONG, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG,
/// PULONG)`; kbdclass and mouclass use KeyValueBasicInformation for DEVICEMAP port names.
pub(super) extern "win64" fn s_zw_enumerate_value_key(
    handle: u64,
    index: u32,
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
            HOSTED_REGISTRY_OP_ENUMERATE_VALUE,
            handle,
            index as u64,
            information_class as u64,
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
        if required > HOSTED_REGISTRY_VALUE_SCRATCH_MAX || minimum > required {
            return STATUS_INVALID_PARAMETER;
        }
        write_unaligned(result_length as *mut u32, required as u32);
        if (length as usize) < minimum {
            return STATUS_BUFFER_TOO_SMALL;
        }
        let copy_len = (length as usize).min(required);
        if copy_len != 0 && information == 0 {
            return STATUS_ACCESS_VIOLATION;
        }
        let source = registry_arg_data_slice(required as u32);
        let mut empty = [];
        let output = if copy_len == 0 {
            &mut empty[..]
        } else {
            core::slice::from_raw_parts_mut(information as *mut u8, copy_len)
        };
        let Some(result) =
            nt_config_abi::key_value_copy::copy_value_information(source, minimum, output)
        else {
            return STATUS_INVALID_PARAMETER;
        };
        match result.status {
            nt_config_abi::key_value_copy::CopyStatus::Success => STATUS_SUCCESS,
            nt_config_abi::key_value_copy::CopyStatus::BufferOverflow => {
                STATUS_BUFFER_OVERFLOW as i32
            }
            nt_config_abi::key_value_copy::CopyStatus::BufferTooSmall => STATUS_BUFFER_TOO_SMALL,
        }
    }
}
