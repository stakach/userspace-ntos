//! Kernel-mode File-information queries from win32k's authenticated provider lane.

use super::*;
use nt_io_manager::file_read_query_wire::{self as wire, FileReadQueryRequest};

pub(super) extern "win64" fn query_information(
    handle: u64,
    iosb: u64,
    output: u64,
    length: u32,
    class: u32,
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
        ).is_err() {
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
                Err(_) => crate::provider_bugcheck::report(0xc4, [W32_FILE_QUERY_LABEL, packet, raw, 0]),
            };
            if status != raw as u32 {
                crate::provider_bugcheck::report(0xc4, [W32_FILE_QUERY_LABEL, packet, raw, status as u64]);
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
