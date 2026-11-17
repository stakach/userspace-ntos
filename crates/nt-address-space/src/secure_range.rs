//! `MmSecureVirtualMemory` admission: the interval must lie in one allocation that grants the
//! promised access on every page.

use crate::{
    vm_access_page_plan, FaultAccess, SecuredVirtualMemoryAccess, VmBasicInformation, PAGE_SIZE,
    STATUS_ACCESS_VIOLATION, STATUS_INVALID_PAGE_PROTECTION, STATUS_INVALID_PARAMETER,
};

/// Map the `ProbeMode` protection of `MmSecureVirtualMemory` to the lease it requests.
pub fn secure_access_for_protection(protection: u32) -> Result<SecuredVirtualMemoryAccess, u32> {
    match protection {
        crate::PAGE_READONLY => Ok(SecuredVirtualMemoryAccess::ReadOnly),
        crate::PAGE_READWRITE => Ok(SecuredVirtualMemoryAccess::ReadWrite),
        _ => Err(STATUS_INVALID_PAGE_PROTECTION),
    }
}

/// Validate `[address, address + size)` against the owning process's memory information.
///
/// `query` returns the `MEMORY_BASIC_INFORMATION` region containing an address, exactly as
/// `NtQueryVirtualMemory` reports it. Memory outside the process's address space is `MEM_FREE`
/// there, so it is refused with `STATUS_ACCESS_VIOLATION`.
pub fn validate_secure_range(
    address: u64,
    size: u64,
    access: SecuredVirtualMemoryAccess,
    address_limit: u64,
    mut query: impl FnMut(u64) -> Result<VmBasicInformation, u32>,
) -> Result<(), u32> {
    let end = address
        .checked_add(size)
        .filter(|end| size != 0 && *end <= address_limit)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let fault_access = match access {
        SecuredVirtualMemoryAccess::ReadOnly => FaultAccess::Read,
        SecuredVirtualMemoryAccess::ReadWrite => FaultAccess::Write,
    };
    let mut information = query(address)?;
    let allocation_base = information.allocation_base;
    let mut cursor = address;
    while cursor < end {
        if information.allocation_base != allocation_base
            || vm_access_page_plan(cursor & !(PAGE_SIZE - 1), information, fault_access).is_err()
        {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let region_end = information
            .base_address
            .checked_add(information.region_size)
            .filter(|region_end| *region_end > cursor)
            .ok_or(STATUS_ACCESS_VIOLATION)?;
        cursor = region_end.min(end);
        if cursor < end {
            information = query(cursor)?;
        }
    }
    Ok(())
}
