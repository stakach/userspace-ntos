//! Caching requirements for physical memory already granted to an isolated driver.

use super::*;

/// `NTSTATUS HalGetMemoryCachingRequirements(PHYSICAL_ADDRESS, SIZE_T, MEMORY_CACHING_TYPE *)`.
pub(super) extern "win64" fn hal_get_memory_caching_requirements(
    physical_address: u64,
    length: u64,
    cache_type: u64,
) -> i32 {
    if cache_type == 0 || length == 0 || physical_address.checked_add(length).is_none() {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        // The PnP resource grant is the sole authority for the mapping's cache policy.
        // ACPI initializes its output to MmNonCached before making this query.
        if find_shared_address_resource_by_range(
            FSD_SHARED_VADDR,
            SH_RESOURCE_ADDRESS_KIND_MEMORY,
            physical_address,
            length,
            true,
        )
        .is_none()
        {
            return STATUS_NOT_SUPPORTED;
        }
        write_unaligned(cache_type as *mut u32, nt_hal_abi::MM_NON_CACHED);
    }
    STATUS_SUCCESS
}
