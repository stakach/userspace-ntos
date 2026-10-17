//! Component-owned physical pages and PFN-backed MDLs for hosted display drivers.

use super::*;

const PAGE: u64 = 4096;
const MDL_OWNER_MAGIC: u64 = 0x4D44_4C50_4859_5331;
const MM_DONT_ZERO_ALLOCATION: u32 = 1;
const MM_ALLOCATE_FROM_LOCAL_NODE_ONLY: u32 = 2;
const MM_ALLOCATE_FULLY_REQUIRED: u32 = 4;
const MM_ALLOCATE_NO_WAIT: u32 = 8;
const MM_ALLOCATE_PREFER_CONTIGUOUS: u32 = 0x10;
const MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS: u32 = 0x20;
const KNOWN_FLAGS: u32 = MM_DONT_ZERO_ALLOCATION
    | MM_ALLOCATE_FROM_LOCAL_NODE_ONLY
    | MM_ALLOCATE_FULLY_REQUIRED
    | MM_ALLOCATE_NO_WAIT
    | MM_ALLOCATE_PREFER_CONTIGUOUS
    | MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS;

/// `PMDL MmAllocatePagesForMdlEx(PHYSICAL_ADDRESS, PHYSICAL_ADDRESS, PHYSICAL_ADDRESS,
/// SIZE_T, MEMORY_CACHING_TYPE, ULONG)`. The pool is mapped into this exact driver's
/// VSpace, so each PFN is obtained from the published component frame mapping.
pub(super) extern "win64" fn mm_allocate_pages_for_mdl_ex(
    low: u64,
    high: u64,
    skip: u64,
    byte_count: u64,
    cache: u32,
    flags: u32,
) -> u64 {
    if byte_count == 0 || byte_count > u32::MAX as u64 || low > high
        || cache != nt_hal_abi::MM_CACHED || flags & !KNOWN_FLAGS != 0
        || skip != 0
    {
        return 0;
    }
    let Some(pages) = byte_count.checked_add(PAGE - 1).map(|v| v / PAGE) else {
        return 0;
    };
    let Some(backing_bytes) = pages.checked_mul(PAGE).and_then(|v| v.checked_add(PAGE - 1)) else {
        return 0;
    };
    let Some(mdl_bytes) = pages.checked_mul(8)
        .and_then(|v| v.checked_add(nt_mdl::MDL_SIZE as u64 + 24)) else {
        return 0;
    };
    // MDL.Size is a signed 16-bit ABI field. The pool itself is an 8 MiB finite grant.
    if mdl_bytes > i16::MAX as u64 || backing_bytes > FSD_POOL_FRAMES * PAGE {
        return 0;
    }
    unsafe {
        let backing = pool_alloc(backing_bytes);
        if backing == 0 {
            return 0;
        }
        let Some(base) = backing.checked_add(PAGE - 1).map(|v| v & !(PAGE - 1)) else {
            pool_free(backing);
            return 0;
        };
        let mdl = pool_alloc(mdl_bytes);
        if mdl == 0 {
            pool_free(backing);
            return 0;
        }
        let mut previous = None;
        for i in 0..pages {
            let va = base + i * PAGE;
            let Some(physical) = hosted_component_physical_address(va) else {
                pool_free(mdl);
                pool_free(backing);
                return 0;
            };
            if physical & (PAGE - 1) != 0 || physical < low
                || physical.checked_add(PAGE - 1).is_none_or(|end| end > high)
                || ((flags & MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS) != 0
                    && previous.is_some_and(|prev: u64| prev.checked_add(PAGE) != Some(physical)))
            {
                pool_free(mdl);
                pool_free(backing);
                return 0;
            }
            previous = Some(physical);
            write_unaligned((mdl + nt_mdl::MDL_SIZE as u64 + i * 8) as *mut u64, physical / PAGE);
        }
        if flags & MM_DONT_ZERO_ALLOCATION == 0 {
            core::ptr::write_bytes(base as *mut u8, 0, (pages * PAGE) as usize);
        }
        // The tail lives in the same exact pool allocation as the MDL and is not part of
        // the driver-visible header/PFN array. It retains the allocation base for release.
        let owner = mdl + nt_mdl::MDL_SIZE as u64 + pages * 8;
        write_unaligned(owner as *mut u64, MDL_OWNER_MAGIC);
        write_unaligned((owner + 8) as *mut u64, backing);
        write_unaligned((owner + 16) as *mut u64, pages);
        core::ptr::write_bytes(mdl as *mut u8, 0, nt_mdl::MDL_SIZE);
        write_unaligned((mdl + nt_mdl::MDL_OFF_SIZE) as *mut i16, (nt_mdl::MDL_SIZE as u64 + pages * 8) as i16);
        write_unaligned((mdl + nt_mdl::MDL_OFF_FLAGS) as *mut i16,
            nt_mdl::MDL_PAGES_LOCKED | nt_mdl::MDL_MAPPED_TO_SYSTEM_VA);
        write_unaligned((mdl + nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA) as *mut u64, base);
        write_unaligned((mdl + nt_mdl::MDL_OFF_START_VA) as *mut u64, base);
        write_unaligned((mdl + nt_mdl::MDL_OFF_BYTE_COUNT) as *mut u32, byte_count as u32);
        mdl
    }
}

/// `VOID MmFreePagesFromMdl(PMDL)`. The caller frees the MDL header separately.
pub(super) extern "win64" fn mm_free_pages_from_mdl(mdl: u64) {
    if mdl == 0 {
        return;
    }
    unsafe {
        let Some(capacity) = component_pool_allocation_capacity(mdl) else {
            crate::provider_bugcheck::report(0xC4, [0x4D44_4C50, mdl, 1, 0]);
        };
        let size = read_unaligned((mdl + nt_mdl::MDL_OFF_SIZE) as *const i16);
        if size < nt_mdl::MDL_SIZE as i16 || (size as u64 - nt_mdl::MDL_SIZE as u64) % 8 != 0
            || (size as u64).checked_add(24).is_none_or(|end| end > capacity)
        {
            crate::provider_bugcheck::report(0xC4, [0x4D44_4C50, mdl, 2, size as u64]);
        }
        let owner = mdl + size as u64;
        let magic = read_unaligned(owner as *const u64);
        let backing = read_unaligned((owner + 8) as *const u64);
        let pages = read_unaligned((owner + 16) as *const u64);
        if magic != MDL_OWNER_MAGIC || backing == 0
            || pages != (size as u64 - nt_mdl::MDL_SIZE as u64) / 8
            || component_pool_allocation_capacity(backing).is_none()
        {
            crate::provider_bugcheck::report(0xC4, [0x4D44_4C50, mdl, 3, backing]);
        }
        write_unaligned(owner as *mut u64, 0);
        write_unaligned((owner + 8) as *mut u64, 0);
        write_unaligned((mdl + nt_mdl::MDL_OFF_FLAGS) as *mut i16, 0);
        write_unaligned((mdl + nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA) as *mut u64, 0);
        write_unaligned((mdl + nt_mdl::MDL_OFF_START_VA) as *mut u64, 0);
        write_unaligned((mdl + nt_mdl::MDL_OFF_BYTE_COUNT) as *mut u32, 0);
        pool_free(backing);
    }
}
