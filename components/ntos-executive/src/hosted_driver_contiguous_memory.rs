//! Component-facing NT contiguous-memory API. Physical RAM and frame caps live in the executive.

use super::*;

#[derive(Clone, Copy)]
struct Allocation { address: u64, length: u64, cache: u32 }
static mut ALLOCATIONS: Vec<Allocation> = Vec::new();

unsafe fn call(op: u64, a1: u64, a2: u64, a3: u64) -> (i32, u64, u64, u64) {
    let (info, status, v1, v2, v3) = call_on4_raw(
        (FSD_SERVICE_DEVICE_LABEL << 12) | 4, op, a1, a2, a3);
    if info >> 12 != 0 || info & 0x7f != 4 || v2 != 0 || v3 != 0 {
        // A malformed reply cannot establish whether COMMIT or FREE took effect. Halt this
        // provider rather than replaying a native allocation or freeing a possibly live run.
        crate::provider_bugcheck::report(0xc4, [0x434f_4e54, op, info, status]);
    }
    (status as u32 as i32, v1, v2, v3)
}

pub(super) extern "win64" fn mm_allocate_contiguous_memory_specify_cache(
    length: u64, low: u64, high: u64, boundary: u64, cache: u32,
) -> u64 {
    if length == 0 || low > high || cache != nt_hal_abi::MM_CACHED
        || boundary != 0 && (!boundary.is_power_of_two() || boundary < 4096) {
        print_str(b"[contiguous-component] rejected arguments len=");
        print_u64(length); print_str(b" cache="); print_u64(cache as u64);
        print_str(b"\n");
        return 0;
    }
    unsafe {
        let _guard = component_device_reply_lock();
        let ledger = &mut *core::ptr::addr_of_mut!(ALLOCATIONS);
        if ledger.try_reserve(1).is_err() { return 0; }
        print_str(b"[contiguous-component] request len="); print_u64(length);
        print_str(b" low=0x"); print_hex64(low);
        print_str(b" high=0x"); print_hex64(high);
        print_str(b" boundary=0x"); print_hex64(boundary);
        print_str(b" cache="); print_u64(cache as u64); print_str(b"\n");
        let (status, ticket, _, _) = call(HOSTED_DEVICE_OP_CONTIGUOUS_PREPARE,
            length, low, high);
        print_str(b"[contiguous-component] prepare status=0x");
        print_hex64(status as u32 as u64); print_str(b" ticket="); print_u64(ticket);
        print_str(b"\n");
        if status != STATUS_SUCCESS || ticket == 0 { return 0; }
        let (status, address, _, _) = call(HOSTED_DEVICE_OP_CONTIGUOUS_COMMIT,
            ticket, boundary, cache as u64);
        print_str(b"[contiguous-component] commit status=0x");
        print_hex64(status as u32 as u64); print_str(b" address=0x");
        print_hex64(address); print_str(b"\n");
        if status != STATUS_SUCCESS { return 0; }
        if address == 0 || address & 0xfff != 0 {
            crate::provider_bugcheck::report(0xc4, [0x434f_4e54, address, 1, ticket]);
        }
        ledger.push(Allocation { address, length, cache });
        address
    }
}

unsafe fn free(address: u64, length: Option<u64>, cache: Option<u32>) {
    let _guard = component_device_reply_lock();
    let ledger = &mut *core::ptr::addr_of_mut!(ALLOCATIONS);
    let Some(index) = ledger.iter().position(|row| row.address == address) else {
        crate::provider_bugcheck::report(0xc4, [0x434f_4e54, address, 2, 0]);
    };
    let row = ledger[index];
    if length.is_some_and(|n| n != row.length)
        || cache.is_some_and(|value| value != row.cache) {
        crate::provider_bugcheck::report(0xc4, [0x434f_4e54, address, 3, row.length]);
    }
    let (status, _, _, _) = call(HOSTED_DEVICE_OP_CONTIGUOUS_FREE,
        address, length.unwrap_or(0), cache.map_or(u64::MAX, u64::from));
    if status != STATUS_SUCCESS {
        crate::provider_bugcheck::report(0xc4, [0x434f_4e54, address, 4, status as u32 as u64]);
    }
    ledger.swap_remove(index);
}

pub(super) extern "win64" fn mm_free_contiguous_memory(address: u64) {
    if address != 0 { unsafe { free(address, None, None) }; }
}

pub(super) extern "win64" fn mm_free_contiguous_memory_specify_cache(
    address: u64, length: u64, cache: u32,
) {
    if address != 0 { unsafe { free(address, Some(length), Some(cache)) }; }
}

/// Generic ExFreePool cannot recycle the separately owned physical RAM aperture.
pub(super) unsafe fn owns_allocation(address: u64) -> bool {
    let _guard = component_device_reply_lock();
    (&*core::ptr::addr_of!(ALLOCATIONS)).iter().any(|row| row.address == address)
}
