//! Pointer-free native Section map request from win32k.

use super::*;
use nt_io_manager::win32k_section_map_wire::{self as wire, SectionMapRequest};

const LABEL: u64 = W32_SECTION_MAP_LABEL;
const MAP: u64 = 1;
const PUBLISH: u64 = 2;
const ABORT: u64 = 3;
const ACK: u64 = 4;

unsafe fn call(op: u64, first: u64, second: u64) -> (i32, u64, u64, u64) {
    let (words, raw, out1, out2, out3) =
        crate::driver_launch::call_on4_raw((LABEL << 12) | 4, op, first, second, 0);
    let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
    if words != 4
        || !canonical
        || (op != MAP && out3 != 0)
        || ((raw as u32 as i32) < 0 && (out1 != 0 || out2 != 0 || out3 != 0))
    {
        crate::provider_bugcheck::report(0xc4, [LABEL, op, words, raw]);
    }
    (raw as u32 as i32, out1, out2, out3)
}

unsafe fn abort(token: u64, base: u64) {
    let (status, first, second, third) = call(ABORT, token, base);
    if status != 0 || first != 0 || second != 0 || third != 0 {
        crate::provider_bugcheck::report(0xc4, [LABEL, ABORT, token, status as u32 as u64]);
    }
}

pub(super) extern "win64" fn map(
    section_handle: u64,
    process_handle: u64,
    base_address: *mut u64,
    zero_bits: u64,
    commit_size: u64,
    section_offset: *const u64,
    view_size: *mut u64,
    inherit_disposition: u32,
    allocation_type: u32,
    win32_protect: u32,
) -> i32 {
    unsafe {
        if base_address.is_null() || view_size.is_null() {
            return STATUS_ACCESS_VIOLATION_I32;
        }
        let request = SectionMapRequest {
            section_handle,
            process_handle,
            base_address: read_unaligned(base_address),
            zero_bits,
            commit_size,
            section_offset: (!section_offset.is_null()).then(|| read_unaligned(section_offset)),
            view_size: read_unaligned(view_size),
            inherit_disposition,
            allocation_type,
            win32_protect,
        };
        let packet = pool_alloc(wire::PACKET_BYTES as u64);
        if packet == 0 {
            return 0xC000_009Au32 as i32;
        }
        wire::encode(
            request,
            core::slice::from_raw_parts_mut(packet as *mut u8, wire::PACKET_BYTES),
        )
        .expect("fixed Section map packet has the exact wire length");
        let (status, token, base, size) = call(MAP, packet, wire::PACKET_BYTES as u64);
        assert!(provider_pool_free(packet), "Section map packet allocation must retire");
        if status < 0 {
            return status;
        }
        if status != 0 || token == 0 || base == 0 || size == 0 {
            crate::provider_bugcheck::report(0xc4, [LABEL, MAP, token, base]);
        }
        write_unaligned(base_address, base);
        write_unaligned(view_size, size);
        let (status, first, second, third) = call(PUBLISH, token, base);
        if status < 0 {
            write_unaligned(base_address, 0);
            write_unaligned(view_size, 0);
            abort(token, base);
            return status;
        }
        if status != 0 || first != 0 || second != 0 || third != 0 {
            crate::provider_bugcheck::report(0xc4, [LABEL, PUBLISH, token, status as u32 as u64]);
        }
        let (status, first, second, third) = call(ACK, token, base);
        if status != 0 || first != 0 || second != 0 || third != 0 {
            crate::provider_bugcheck::report(0xc4, [LABEL, ACK, token, status as u32 as u64]);
        }
        0
    }
}
