//! Win32k File ObjectNameInformation from the live filesystem name and Device identity.

use super::*;
use nt_io_manager::file_object_name::{
    file_name_information_units, write_file_object_name, FileObjectNameError,
    FILE_OBJECT_NAME_SCRATCH_BYTES,
};

const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const STATUS_INVALID_PARAMETER_LOCAL: i32 = 0xC000_000Du32 as i32;
const STATUS_NOT_SUPPORTED_LOCAL: i32 = 0xC000_00BBu32 as i32;
const STATUS_DATA_ERROR_LOCAL: i32 = 0xC000_003Eu32 as i32;
const STATUS_NAME_TOO_LONG_LOCAL: i32 = 0xC000_0106u32 as i32;
const STATUS_BUFFER_OVERFLOW_LOCAL: i32 = 0x8000_0005u32 as i32;
const STATUS_INSUFFICIENT_RESOURCES_LOCAL: i32 = 0xC000_009Au32 as i32;

unsafe fn format_name(
    device_name: &[u16],
    file_name: &[u8],
    information: u64,
    length: u32,
    return_length: u64,
) -> i32 {
    let capacity = (length as usize).min(u16::MAX as usize + 18);
    let mut output = Vec::new();
    if output.try_reserve_exact(capacity).is_err() {
        return STATUS_INSUFFICIENT_RESOURCES_LOCAL;
    }
    output.resize(capacity, 0);
    match write_file_object_name(device_name, file_name, information, &mut output) {
        Ok(used) => {
            core::ptr::copy_nonoverlapping(output.as_ptr(), information as *mut u8, used);
            if return_length != 0 {
                write_unaligned(return_length as *mut u32, used as u32);
            }
            0
        }
        Err(FileObjectNameError::BufferTooSmall { required }) => {
            if return_length != 0 {
                write_unaligned(return_length as *mut u32, required as u32);
            }
            if length < 16 {
                STATUS_INFO_LENGTH_MISMATCH
            } else {
                STATUS_BUFFER_OVERFLOW_LOCAL
            }
        }
        Err(FileObjectNameError::NameTooLong) => STATUS_NAME_TOO_LONG_LOCAL,
        Err(_) => STATUS_DATA_ERROR_LOCAL,
    }
}

/// `ZwQueryObject` for File ObjectNameInformation. Other object classes are not yet backed by
/// this provider adapter and fail explicitly rather than returning an invented object record.
pub(super) extern "win64" fn query_object(
    handle: u64,
    class: u32,
    information: u64,
    length: u32,
    return_length: u64,
) -> i32 {
    if class != 1 {
        return STATUS_NOT_SUPPORTED_LOCAL;
    }
    if handle == 0 {
        return STATUS_INVALID_PARAMETER_LOCAL;
    }
    if length < 16 {
        if return_length != 0 {
            unsafe { write_unaligned(return_length as *mut u32, 16) };
        }
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if information == 0 {
        return STATUS_INVALID_PARAMETER_LOCAL;
    }
    unsafe {
        let device_packet = pool_alloc(FILE_OBJECT_NAME_SCRATCH_BYTES as u64);
        if device_packet == 0 {
            return STATUS_INSUFFICIENT_RESOURCES_LOCAL;
        }
        let (status, device_bytes, file_id, _) = win32k_file_object_broker_call(
            W32_FILE_OBJECT_DEVICE_NAME,
            device_packet,
            FILE_OBJECT_NAME_SCRATCH_BYTES as u64,
            handle,
        );
        if status != 0 {
            if !provider_pool_free(device_packet) {
                crate::provider_bugcheck::report(
                    0xc4,
                    [W32_FILE_OBJECT_LABEL, device_packet, 0, 0],
                );
            }
            return status;
        }
        let count = read_unaligned(device_packet as *const u32) as usize;
        if count % 2 != 0
            || count > FILE_OBJECT_NAME_SCRATCH_BYTES - 4
            || count as u64 != device_bytes
            || file_id == 0
        {
            crate::provider_bugcheck::report(
                0xc4,
                [
                    W32_FILE_OBJECT_LABEL,
                    device_packet,
                    count as u64,
                    device_bytes,
                ],
            );
        }
        let mut device_name = Vec::new();
        if device_name.try_reserve_exact(count / 2).is_err() {
            if !provider_pool_free(device_packet) {
                crate::provider_bugcheck::report(
                    0xc4,
                    [W32_FILE_OBJECT_LABEL, device_packet, 3, 0],
                );
            }
            return STATUS_INSUFFICIENT_RESOURCES_LOCAL;
        }
        for offset in (0..count).step_by(2) {
            device_name.push(read_unaligned(
                (device_packet + 4 + offset as u64) as *const u16,
            ));
        }
        if !provider_pool_free(device_packet) {
            crate::provider_bugcheck::report(0xc4, [W32_FILE_OBJECT_LABEL, device_packet, 1, 0]);
        }

        let file_info = pool_alloc(FILE_OBJECT_NAME_SCRATCH_BYTES as u64);
        if file_info == 0 {
            return STATUS_INSUFFICIENT_RESOURCES_LOCAL;
        }
        let mut iosb = [0u64; 2];
        let query_status = file_query::query_information_expected(
            handle,
            iosb.as_mut_ptr() as u64,
            file_info,
            FILE_OBJECT_NAME_SCRATCH_BYTES as u32,
            9, // FileNameInformation
            file_id,
        );
        let result = if query_status == 0 {
            let source =
                core::slice::from_raw_parts(file_info as *const u8, FILE_OBJECT_NAME_SCRATCH_BYTES);
            match file_name_information_units(source, iosb[1]) {
                Ok(file_name) => {
                    format_name(&device_name, file_name, information, length, return_length)
                }
                Err(_) => STATUS_DATA_ERROR_LOCAL,
            }
        } else if matches!(
            query_status as u32,
            0xC000_000D | 0xC000_0010 | 0xC000_0002 | 0xC000_0003
        ) {
            format_name(&device_name, &[], information, length, return_length)
        } else {
            query_status
        };
        if !provider_pool_free(file_info) {
            crate::provider_bugcheck::report(0xc4, [W32_FILE_OBJECT_LABEL, file_info, 2, 0]);
        }
        result
    }
}
