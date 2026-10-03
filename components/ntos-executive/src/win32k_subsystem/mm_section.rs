//! Kernel Section object requests, distinct from native handle-based Zw operations.

use super::*;
use nt_io_manager::win32k_mm_section_wire::{self as wire, MmSectionCreateRequest};

use wire::{OP_CREATE_OBJECT as CREATE, OP_REFERENCE as REFERENCE,
    OP_DEREFERENCE as DEREFERENCE, OP_MAP as MAP, OP_UNMAP as UNMAP};

unsafe fn call(op: u64, first: u64, second: u64) -> (i32, u64, u64) {
    let (words, raw, out1, out2, spare) = crate::driver_launch::call_on4_raw(
        (W32_SECTION_CREATE_LABEL << 12) | 4, op, first, second, 0);
    let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
    if words != 4 || !canonical || spare != 0
        || ((raw as u32 as i32) < 0 && (out1 != 0 || out2 != 0))
    {
        crate::provider_bugcheck::report(0xc4, [W32_SECTION_CREATE_LABEL, op, words, raw]);
    }
    (raw as u32 as i32, out1, out2)
}

pub(super) unsafe fn create(
    section_out: *mut u64, access: u32, attributes: u64, maximum_size: u64,
    protection: u32, allocation_attributes: u32, file_handle: u64, file_object: u64,
) -> i32 {
    if section_out.is_null() { return STATUS_ACCESS_VIOLATION_I32; }
    let base = match section_create::capture_request(access, attributes, maximum_size,
        protection, allocation_attributes, file_handle) {
        Ok(base) => base,
        Err(status) => return status,
    };
    let packet = pool_alloc(wire::PACKET_BYTES as u64);
    if packet == 0 { return STATUS_INSUFFICIENT_RESOURCES_I32; }
    wire::encode(MmSectionCreateRequest { base, file_object },
        core::slice::from_raw_parts_mut(packet as *mut u8, wire::PACKET_BYTES))
        .expect("fixed kernel Section packet length");
    let (status, token, object) = call(CREATE, packet, wire::PACKET_BYTES as u64);
    if status != 0 {
        print_str(b"[kernel-section-create] status="); print_hex(status as u32);
        print_str(b" file-handle="); crate::print_hex_u64(file_handle);
        print_str(b" file-object="); crate::print_hex_u64(file_object);
        print_str(b" protection="); print_hex(protection);
        print_str(b"\n");
    }
    assert!(provider_pool_free(packet), "kernel Section request packet retirement");
    if status < 0 { return status; }
    if status != 0 || token == 0 || object == 0 {
        crate::provider_bugcheck::report(0xc4, [W32_SECTION_CREATE_LABEL, CREATE, token, object]);
    }
    write_unaligned(section_out, object);
    let (status, first, second) = call(2, token, object);
    if status < 0 {
        write_unaligned(section_out, 0);
        let (aborted, first, second) = call(3, token, object);
        if aborted != 0 || first != 0 || second != 0 {
            crate::provider_bugcheck::report(0xc4, [W32_SECTION_CREATE_LABEL, 3, token, object]);
        }
        return status;
    }
    if status != 0 || first != 0 || second != 0 {
        crate::provider_bugcheck::report(0xc4, [W32_SECTION_CREATE_LABEL, 2, token, object]);
    }
    let (status, first, second) = call(4, token, object);
    if status != 0 || first != 0 || second != 0 {
        crate::provider_bugcheck::report(0xc4, [W32_SECTION_CREATE_LABEL, 4, token, object]);
    }
    0
}

pub(super) unsafe fn reference(object: u64, release: bool) -> Result<u64, i32> {
    let (status, count, spare) = call(if release { DEREFERENCE } else { REFERENCE }, object, 0);
    if status != 0 { return Err(status); }
    if spare != 0 {
        crate::provider_bugcheck::report(0xc4, [W32_SECTION_CREATE_LABEL, object, count, spare]);
    }
    Ok(count)
}

pub(super) unsafe fn map(object: u64, size: u64) -> Result<(u64, u64), i32> {
    let requested_size = size;
    let (status, base, size) = call(MAP, object, size);
    if status != 0 {
        print_str(b"[kernel-section-map-failure] status="); print_hex(status as u32);
        print_str(b" object="); crate::print_hex_u64(object);
        print_str(b" requested-size="); crate::print_hex_u64(requested_size);
        print_str(b"\n");
    }
    if status != 0 { return Err(status); }
    if base == 0 || size == 0 {
        crate::provider_bugcheck::report(0xc4, [W32_SECTION_CREATE_LABEL, MAP, object, base]);
    }
    Ok((base, size))
}

pub(super) unsafe fn unmap(base: u64) -> i32 {
    let (status, first, second) = call(UNMAP, base, 0);
    if status == 0 && (first != 0 || second != 0) {
        crate::provider_bugcheck::report(0xc4, [W32_SECTION_CREATE_LABEL, UNMAP, base, first]);
    }
    status
}
