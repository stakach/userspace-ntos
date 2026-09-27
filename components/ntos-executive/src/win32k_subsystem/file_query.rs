//! Kernel-mode File-information and directory queries from win32k's provider lane.

use super::*;
use nt_io_manager::file_directory_query_wire::{self as directory_wire, DirectoryQueryRequest};
use nt_io_manager::file_read_query_wire::{self as wire, FileReadQueryRequest};

unsafe fn acknowledge_delivery(packet: u64, handle: u64) {
    let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
        (W32_FILE_QUERY_DELIVERED_LABEL << 12) | 4,
        packet,
        handle,
        0,
        0,
    );
    if words != 1 || raw as u32 != nt_process::STATUS_SUCCESS {
        crate::provider_bugcheck::report(
            0xc4,
            [W32_FILE_QUERY_DELIVERED_LABEL, packet, words, raw],
        );
    }
}

pub(super) extern "win64" fn query_information(
    handle: u64,
    iosb: u64,
    output: u64,
    length: u32,
    class: u32,
) -> i32 {
    query_information_expected(handle, iosb, output, length, class, 0)
}

pub(super) fn query_information_expected(
    handle: u64,
    iosb: u64,
    output: u64,
    length: u32,
    class: u32,
    expected_file: u64,
) -> i32 {
    let Some(contract) = nt_io_manager::query_information_contract(class) else {
        return 0xC000_0003u32 as i32;
    };
    if (length as usize) < contract.minimum_length() {
        return 0xC000_0004u32 as i32;
    }
    if iosb == 0 || output == 0 {
        return STATUS_INVALID_PARAMETER_I32;
    }
    let total = match wire::packet_len(length) {
        Ok(total) if (total as u64) < WIN32K_POOL_FRAMES * 0x1000 => total,
        _ => return 0xC000_0206u32 as i32,
    };
    unsafe {
        let packet = pool_alloc(total as u64);
        if packet == 0 {
            return 0xC000_009Au32 as i32;
        }
        if wire::encode_request(
            FileReadQueryRequest::Query { class, length },
            core::slice::from_raw_parts_mut(packet as *mut u8, total),
        )
        .is_err()
        {
            if !provider_pool_free(packet) {
                crate::provider_bugcheck::report(0xc4, [W32_FILE_QUERY_LABEL, packet, 0, 0]);
            }
            return STATUS_INVALID_PARAMETER_I32;
        }
        let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
            (W32_FILE_QUERY_LABEL << 12) | 4,
            packet,
            total as u64,
            handle,
            expected_file,
        );
        if words != 1 {
            crate::provider_bugcheck::report(0xc4, [W32_FILE_QUERY_LABEL, packet, words, raw]);
        }
        if raw != raw as u32 as u64 && raw != raw as u32 as i32 as i64 as u64 {
            crate::provider_bugcheck::report(0xc4, [W32_FILE_QUERY_LABEL, packet, raw, 2]);
        }
        let completed = read_unaligned((packet + 24) as *const u32) == 1;
        let result = if completed {
            let (status, information, bytes) = match wire::decode_completion(
                core::slice::from_raw_parts(packet as *const u8, total),
            ) {
                Ok(completion) => completion,
                Err(_) => {
                    crate::provider_bugcheck::report(0xc4, [W32_FILE_QUERY_LABEL, packet, raw, 0])
                }
            };
            if status != raw as u32 {
                crate::provider_bugcheck::report(
                    0xc4,
                    [W32_FILE_QUERY_LABEL, packet, raw, status as u64],
                );
            }
            let copied = if nt_io_completion::file_io_status_copies_output(status) {
                nt_io_manager::completion_output_transfer_len(information, length as u64) as usize
            } else {
                0
            };
            if copied != 0 {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), output as *mut u8, copied);
            }
            write_unaligned(iosb as *mut u32, status);
            write_unaligned((iosb + 8) as *mut u64, information);
            acknowledge_delivery(packet, handle);
            status as i32
        } else {
            raw as u32 as i32
        };
        if !provider_pool_free(packet) {
            crate::provider_bugcheck::report(0xc4, [W32_FILE_QUERY_LABEL, packet, raw, 1]);
        }
        result
    }
}

pub(super) extern "win64" fn query_directory(
    handle: u64,
    event: u64,
    apc_routine: u64,
    apc_context: u64,
    iosb: u64,
    output: u64,
    length: u32,
    class: u32,
    return_single_entry: u8,
    file_name: u64,
    restart_scan: u8,
) -> i32 {
    if event != 0 || apc_routine != 0 || apc_context != 0 {
        return 0xC000_00BBu32 as i32;
    }
    if class != nt_fs::FILE_DIRECTORY_INFORMATION {
        return 0xC000_0003u32 as i32;
    }
    if iosb == 0 || output == 0 {
        return STATUS_INVALID_PARAMETER_I32;
    }
    let mut pattern = Vec::new();
    if file_name != 0 {
        let byte_len = unsafe { read_unaligned(file_name as *const u16) } as usize;
        let max_len = unsafe { read_unaligned((file_name + 2) as *const u16) } as usize;
        let buffer = unsafe { read_unaligned((file_name + 8) as *const u64) };
        if byte_len & 1 != 0
            || byte_len > max_len
            || byte_len / 2 > nt_fs::MAX_DIRECTORY_NAME
            || (byte_len != 0 && buffer == 0)
        {
            return STATUS_INVALID_PARAMETER_I32;
        }
        if pattern.try_reserve_exact(byte_len / 2).is_err() {
            return 0xC000_009Au32 as i32;
        }
        for offset in (0..byte_len).step_by(2) {
            pattern.push(unsafe { read_unaligned((buffer + offset as u64) as *const u16) });
        }
    }
    let total = match directory_wire::packet_len(length, pattern.len()) {
        Ok(total) if (total as u64) < WIN32K_POOL_FRAMES * 0x1000 => total,
        _ => return 0xC000_0206u32 as i32,
    };
    unsafe {
        let packet = pool_alloc(total as u64);
        if packet == 0 {
            return 0xC000_009Au32 as i32;
        }
        let request = DirectoryQueryRequest {
            output_len: length,
            restart_scan: restart_scan != 0,
            return_single_entry: return_single_entry != 0,
            pattern: (file_name != 0).then_some(pattern.as_slice()),
        };
        if directory_wire::encode_request(
            request,
            core::slice::from_raw_parts_mut(packet as *mut u8, total),
        )
        .is_err()
        {
            if !provider_pool_free(packet) {
                crate::provider_bugcheck::report(0xc4, [W32_FILE_QUERY_LABEL, packet, 0, 0]);
            }
            return STATUS_INVALID_PARAMETER_I32;
        }
        let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
            (W32_FILE_QUERY_LABEL << 12) | 4,
            packet,
            total as u64,
            handle,
            0,
        );
        if words != 1 || (raw != raw as u32 as u64 && raw != raw as u32 as i32 as i64 as u64) {
            crate::provider_bugcheck::report(0xc4, [W32_FILE_QUERY_LABEL, packet, words, raw]);
        }
        let result = if read_unaligned((packet + 24) as *const u32) == 1 {
            let (status, information, bytes) = match directory_wire::decode_completion(
                core::slice::from_raw_parts(packet as *const u8, total),
            ) {
                Ok(completion) => completion,
                Err(_) => {
                    crate::provider_bugcheck::report(0xc4, [W32_FILE_QUERY_LABEL, packet, raw, 0])
                }
            };
            if status != raw as u32 {
                crate::provider_bugcheck::report(
                    0xc4,
                    [W32_FILE_QUERY_LABEL, packet, raw, status as u64],
                );
            }
            if nt_io_completion::file_io_status_copies_output(status) && information != 0 {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    output as *mut u8,
                    information as usize,
                );
            }
            write_unaligned(iosb as *mut u32, status);
            write_unaligned((iosb + 8) as *mut u64, information);
            acknowledge_delivery(packet, handle);
            status as i32
        } else {
            raw as u32 as i32
        };
        if !provider_pool_free(packet) {
            crate::provider_bugcheck::report(0xc4, [W32_FILE_QUERY_LABEL, packet, raw, 1]);
        }
        result
    }
}
