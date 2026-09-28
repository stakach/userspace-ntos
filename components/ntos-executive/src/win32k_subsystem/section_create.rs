//! Create-only, pointer-free native Section request from win32k.

use super::*;
use nt_io_manager::win32k_section_create_wire::{self as wire, SectionCreateRequest};

const LABEL: u64 = W32_SECTION_CREATE_LABEL;
const CREATE: u64 = 1;
const PUBLISH: u64 = 2;
const ABORT: u64 = 3;
const ACK: u64 = 4;

unsafe fn call(op: u64, first: u64, second: u64) -> (i32, u64, u64) {
    let (words, raw, out1, out2, spare) =
        crate::driver_launch::call_on4_raw((LABEL << 12) | 4, op, first, second, 0);
    let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
    if words != 4
        || !canonical
        || spare != 0
        || ((raw as u32 as i32) < 0 && (out1 != 0 || out2 != 0))
    {
        crate::provider_bugcheck::report(0xc4, [LABEL, op, words, raw]);
    }
    (raw as u32 as i32, out1, out2)
}

unsafe fn abort(token: u64, handle: u64) {
    let (status, first, second) = call(ABORT, token, handle);
    if status != 0 || first != 0 || second != 0 {
        crate::provider_bugcheck::report(0xc4, [LABEL, ABORT, token, status as u32 as u64]);
    }
}

#[allow(dead_code)] // Kept behind the strict win32k import gate until Section mapping is live.
pub(super) extern "win64" fn create(
    handle_out: *mut u64,
    desired_access: u32,
    object_attributes: u64,
    maximum_size: u64,
    page_protection: u32,
    allocation_attributes: u32,
    file_handle: u64,
) -> i32 {
    unsafe {
        if handle_out.is_null() {
            return STATUS_ACCESS_VIOLATION_I32;
        }
        let attributes = if object_attributes == 0 {
            None
        } else {
            if read_unaligned(object_attributes as *const u32) < 0x30 {
                return STATUS_INVALID_PARAMETER_I32;
            }
            let root = read_unaligned((object_attributes + 8) as *const u64);
            let name = read_unaligned((object_attributes + 16) as *const u64);
            let security = read_unaligned((object_attributes + 32) as *const u64);
            let qos = read_unaligned((object_attributes + 40) as *const u64);
            if root != 0 || name != 0 || security != 0 || qos != 0 {
                return STATUS_NOT_SUPPORTED_I32;
            }
            Some(read_unaligned((object_attributes + 24) as *const u32))
        };
        let max = (maximum_size != 0).then(|| read_unaligned(maximum_size as *const u64));
        let request = SectionCreateRequest {
            desired_access,
            object_attributes: attributes,
            maximum_size: max,
            page_protection,
            allocation_attributes,
            file_handle,
        };
        let packet = pool_alloc(wire::PACKET_BYTES as u64);
        if packet == 0 {
            return 0xC000_009Au32 as i32;
        }
        wire::encode(
            request,
            core::slice::from_raw_parts_mut(packet as *mut u8, wire::PACKET_BYTES),
        )
        .expect("fixed Section packet has the exact wire length");
        let (status, token, handle) = call(CREATE, packet, wire::PACKET_BYTES as u64);
        assert!(
            provider_pool_free(packet),
            "Section packet allocation must retire"
        );
        if status < 0 {
            return status;
        }
        if status != 0 || token == 0 || handle == 0 {
            crate::provider_bugcheck::report(0xc4, [LABEL, CREATE, token, handle]);
        }
        write_unaligned(handle_out, handle);
        let (status, first, second) = call(PUBLISH, token, handle);
        if status < 0 {
            write_unaligned(handle_out, 0);
            abort(token, handle);
            return status;
        }
        if status != 0 || first != 0 || second != 0 {
            crate::provider_bugcheck::report(0xc4, [LABEL, PUBLISH, token, status as u32 as u64]);
        }
        let (status, first, second) = call(ACK, token, handle);
        if status != 0 || first != 0 || second != 0 {
            crate::provider_bugcheck::report(0xc4, [LABEL, ACK, token, status as u32 as u64]);
        }
        0
    }
}
