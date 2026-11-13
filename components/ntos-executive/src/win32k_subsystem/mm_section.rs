//! Kernel Section object requests, distinct from native handle-based Zw operations.

use super::*;
use nt_io_manager::win32k_mm_section_wire::{self as wire, MmSectionCreateRequest};

use wire::{OP_CREATE_OBJECT as CREATE, OP_REFERENCE as REFERENCE,
    OP_DEREFERENCE as DEREFERENCE, OP_MAP as MAP, OP_UNMAP as UNMAP,
    OP_MAP_CLIENT as MAP_CLIENT, OP_UNMAP_CLIENT as UNMAP_CLIENT};

// Bounded boot timing for the Section path used by CSRSS font initialization.
// These counters are observations only; the exact Section and FileObject identities
// stay with the existing provider owners.
static CREATE_TIMING_ORDINAL: AtomicU64 = AtomicU64::new(0);
static MAP_TIMING_ORDINAL: AtomicU64 = AtomicU64::new(0);
const TIMING_LIMIT: u64 = 64;

fn trace_timing(
    phase: &[u8], ordinal: u64, file_object: u64, object: u64, bytes: u64,
    status: i32, start_tsc: u64, end_tsc: u64,
) {
    if ordinal > TIMING_LIMIT { return; }
    print_str(b"[font-mm-section] phase="); print_str(phase);
    print_str(b" ordinal="); crate::print_u64(ordinal);
    print_str(b" file-object="); crate::print_hex_u64(file_object);
    print_str(b" section-object="); crate::print_hex_u64(object);
    print_str(b" bytes="); crate::print_u64(bytes);
    print_str(b" status="); print_hex(status as u32);
    print_str(b" start-tsc="); crate::print_u64(start_tsc);
    print_str(b" end-tsc="); crate::print_u64(end_tsc);
    print_str(b"\n");
}

unsafe fn call_with_options(op: u64, first: u64, second: u64, options: u64) -> (i32, u64, u64) {
    let (words, raw, out1, out2, spare) = crate::driver_launch::call_on4_raw(
        (W32_SECTION_CREATE_LABEL << 12) | 4, op, first, second, options);
    let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
    if words != 4 || !canonical || spare != 0
        || ((raw as u32 as i32) < 0 && (out1 != 0 || out2 != 0))
    {
        crate::provider_bugcheck::report(0xc4, [W32_SECTION_CREATE_LABEL, op, words, raw]);
    }
    (raw as u32 as i32, out1, out2)
}

unsafe fn call(op: u64, first: u64, second: u64) -> (i32, u64, u64) {
    call_with_options(op, first, second, 0)
}

pub(super) unsafe fn create(
    section_out: *mut u64, access: u32, attributes: u64, maximum_size: u64,
    protection: u32, allocation_attributes: u32, file_handle: u64, file_object: u64,
) -> i32 {
    if section_out.is_null() { return STATUS_ACCESS_VIOLATION_I32; }
    let ordinal = CREATE_TIMING_ORDINAL.fetch_add(1, Ordering::Relaxed) + 1;
    let trace = ordinal <= TIMING_LIMIT;
    let started = trace.then(crate::driver_launch::read_ordered_tsc);
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
    if let Some(started) = started {
        trace_timing(b"create", ordinal, file_object, object, 0, status,
            started, crate::driver_launch::read_ordered_tsc());
    }
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
    let publish_started = trace.then(crate::driver_launch::read_ordered_tsc);
    let (status, first, second) = call(2, token, object);
    if let Some(started) = publish_started {
        trace_timing(b"publish", ordinal, file_object, object, 0, status,
            started, crate::driver_launch::read_ordered_tsc());
    }
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
    let ack_started = trace.then(crate::driver_launch::read_ordered_tsc);
    let (status, first, second) = call(4, token, object);
    if let Some(started) = ack_started {
        trace_timing(b"ack", ordinal, file_object, object, 0, status,
            started, crate::driver_launch::read_ordered_tsc());
    }
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
    let ordinal = MAP_TIMING_ORDINAL.fetch_add(1, Ordering::Relaxed) + 1;
    let started = (ordinal <= TIMING_LIMIT).then(crate::driver_launch::read_ordered_tsc);
    let (status, base, size) = call(MAP, object, size);
    if let Some(started) = started {
        trace_timing(b"map", ordinal, 0, object, requested_size, status,
            started, crate::driver_launch::read_ordered_tsc());
    }
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

pub(super) unsafe fn map_client(
    object: u64, process: u64, requested_size: u64, protection: u32,
) -> Result<(u64, u64), i32> {
    let options = requested_size.checked_shl(8)
        .filter(|packed| *packed >> 8 == requested_size)
        .ok_or(STATUS_INVALID_PARAMETER_I32)? | u64::from(protection);
    let (status, base, size) = call_with_options(MAP_CLIENT, object, process, options);
    if status != 0 { return Err(status); }
    if base == 0 || size == 0 {
        crate::provider_bugcheck::report(0xc4, [W32_SECTION_CREATE_LABEL, MAP_CLIENT, object, base]);
    }
    Ok((base, size))
}

pub(super) unsafe fn unmap_client(process: u64, base: u64) -> i32 {
    let (status, first, second) = call(UNMAP_CLIENT, process, base);
    if status == 0 && (first != 0 || second != 0) {
        crate::provider_bugcheck::report(0xc4, [W32_SECTION_CREATE_LABEL, UNMAP_CLIENT, base, first]);
    }
    status
}
