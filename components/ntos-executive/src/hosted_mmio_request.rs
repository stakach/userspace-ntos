//! Hosted driver MMIO map and unmap request boundary.

use super::*;

static HOSTED_MMIO_MAP_SUCCESS_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static HOSTED_MMIO_MAP_FAILURE_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
const HOSTED_MMIO_MAP_TRACE_CAP: u64 = 32;

fn trace_hosted_mm_map_io_space(phys: u64, length: u64, cache: u32, result: u64, decision: &[u8]) {
    let counter = if result == 0 {
        &HOSTED_MMIO_MAP_FAILURE_TRACE_COUNT
    } else {
        &HOSTED_MMIO_MAP_SUCCESS_TRACE_COUNT
    };
    let trace = counter.fetch_add(1, Ordering::Relaxed);
    if trace >= HOSTED_MMIO_MAP_TRACE_CAP {
        return;
    }
    print_str(b"[hosted-mmio] MmMapIoSpace phys=");
    print_hex64(phys);
    print_str(b" len=");
    print_u64(length);
    print_str(b" cache=");
    print_u64(cache as u64);
    print_str(b" result=");
    print_hex64(result);
    print_str(b" decision=");
    print_str(decision);
    print_str(b"\n");
}

/// `PVOID MmMapIoSpace(PHYSICAL_ADDRESS, SIZE_T, MEMORY_CACHING_TYPE)` — return the component VA
/// for a BAR range the executive already granted to this hosted driver. Requests outside the active
/// grant fail with NULL; there is no success fallback.
pub(super) fn map_io_space(phys: u64, length: u64, cache: u32) -> u64 {
    unsafe {
        let shared = hosted_component_resource_shared_va();
        if length == 0 || phys.checked_add(length).is_none() {
            trace_hosted_mm_map_io_space(phys, length, cache, 0, b"range");
            return 0;
        }
        if let Some(resource) = find_shared_address_resource_by_range(
            shared,
            SH_RESOURCE_ADDRESS_KIND_MEMORY,
            phys,
            length,
            true,
        ) {
            if cache != MM_NON_CACHED {
                trace_hosted_mm_map_io_space(phys, length, cache, 0, b"cache-mismatch");
                return 0;
            }
            if resource.va == 0 || resource.map_len > resource.len {
                trace_hosted_mm_map_io_space(phys, length, cache, 0, b"invalid-grant");
                return 0;
            }
            let result = submit_mmio_map_request(phys, length, cache).unwrap_or(0);
            trace_hosted_mm_map_io_space(phys, length, cache, result, b"resource-request");
            return result;
        }
        if let Some(projected) = hosted_driver_contiguous_memory::map_physical(phys, length, cache)
        {
            trace_hosted_mm_map_io_space(phys, length, cache, projected, b"contiguous-owned");
            return projected;
        }
            // A live GOP/Dxg registration may own the scanout without a PnP memory grant.
            // The same authenticated root request path checks its publication and records an
            // independent receipt even when the generation's VA projection already exists.
            if let Some(projected) = submit_mmio_map_request(phys, length, cache) {
                trace_hosted_mm_map_io_space(phys, length, cache, projected, b"gop-bar");
                return projected;
            }
            trace_hosted_mm_map_io_space(phys, length, cache, 0, b"not-assigned");
            return 0;
    }
}

/// `void MmUnmapIoSpace(PVOID, SIZE_T)` — revoke the recorded projection. The VSpace mapping is
/// owned by the executive grant and is torn down with the component.
pub(super) fn unmap_io_space(base: u64, length: u64) {
    unsafe {
        if hosted_driver_contiguous_memory::unmap_physical(base, length) {
            return;
        }
        let _ = submit_mmio_unmap_request(base, length);
    }
}
