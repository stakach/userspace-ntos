//! Component contiguous physical allocation backed by verified mapped frames.

use super::*;

const PAGE: u64 = 4096;

#[derive(Clone, Copy)]
struct Allocation {
    address: u64,
    backing: u64,
    length: u64,
    cache: u32,
}

static mut ALLOCATIONS: Vec<Allocation> = Vec::new();

/// Physical contiguity is checked from the component's actual frame-cap map.
/// If the fixed pool cannot furnish such a run, NT allocation failure is
/// returned; no ordinary virtual pool allocation is exposed as DMA memory.
pub(super) extern "win64" fn mm_allocate_contiguous_memory_specify_cache(
    length: u64, low: u64, high: u64, boundary: u64, cache: u32,
) -> u64 {
    if length == 0 || low > high || cache != nt_hal_abi::MM_CACHED
        || (boundary != 0 && (!boundary.is_power_of_two() || boundary < PAGE))
    { return 0; }
    let Some(pages) = length.checked_add(PAGE - 1).map(|n| n / PAGE) else { return 0; };
    let Some(rounded) = pages.checked_mul(PAGE) else { return 0; };
    let Some(bytes) = rounded.checked_add(PAGE - 1) else { return 0; };
    if bytes > FSD_POOL_FRAMES * PAGE { return 0; }
    unsafe {
        let _guard = component_device_reply_lock();
        let ledger = &mut *core::ptr::addr_of_mut!(ALLOCATIONS);
        if ledger.try_reserve(1).is_err() { return 0; }
        let backing = pool_alloc(bytes);
        if backing == 0 { return 0; }
        let Some(address) = backing.checked_add(PAGE - 1).map(|n| n & !(PAGE - 1)) else {
            pool_free(backing);
            return 0;
        };
        if component_pool_allocation_capacity(backing)
            .and_then(|capacity| backing.checked_add(capacity))
            .is_none_or(|end| address.checked_add(rounded).is_none_or(|stop| stop > end))
        {
            pool_free(backing);
            return 0;
        }
        let mut physical = Vec::new();
        if physical.try_reserve_exact(pages as usize).is_err() {
            pool_free(backing);
            return 0;
        }
        for page in 0..pages {
            let Some(va) = address.checked_add(page * PAGE) else {
                pool_free(backing);
                return 0;
            };
            let Some(pa) = hosted_component_physical_address(va) else {
                pool_free(backing);
                return 0;
            };
            physical.push(pa);
        }
        if nt_mdl::contiguous::validate_page_run(&physical, low, high, boundary).is_none() {
            pool_free(backing);
            return 0;
        }
        core::ptr::write_bytes(address as *mut u8, 0, rounded as usize);
        ledger.push(Allocation { address, backing, length, cache });
        address
    }
}

fn free(address: u64, length: Option<u64>, cache: Option<u32>) {
    unsafe {
        let _guard = component_device_reply_lock();
        let ledger = &mut *core::ptr::addr_of_mut!(ALLOCATIONS);
        let Some(index) = ledger.iter().position(|row| row.address == address) else {
            crate::provider_bugcheck::report(0xc4, [0x434f_4e54, address, 1, 0]);
        };
        let row = ledger[index];
        if length.is_some_and(|n| n != row.length)
            || cache.is_some_and(|value| value != row.cache)
            || component_pool_allocation_capacity(row.backing).is_none()
        {
            crate::provider_bugcheck::report(0xc4, [0x434f_4e54, address, 2, row.backing]);
        }
        ledger.swap_remove(index);
        pool_free(row.backing);
    }
}

pub(super) extern "win64" fn mm_free_contiguous_memory(address: u64) {
    if address != 0 { free(address, None, None); }
}

pub(super) extern "win64" fn mm_free_contiguous_memory_specify_cache(
    address: u64, length: u64, cache: u32,
) {
    if address != 0 { free(address, Some(length), Some(cache)); }
}

/// Prevent a generic ExFreePool path from recycling a retained contiguous run.
pub(super) unsafe fn owns_allocation(address: u64) -> bool {
    let _guard = component_device_reply_lock();
    (&*core::ptr::addr_of!(ALLOCATIONS)).iter().any(|row|
        row.address == address || row.backing == address)
}
