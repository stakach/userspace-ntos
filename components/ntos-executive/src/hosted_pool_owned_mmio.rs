//! Logical MmMapIoSpace receipts over a hosted driver's existing WB pool mapping.
//!
//! The root holds the shared pool lock for cap lookup, allocation validation and ledger
//! publication. No new PageMap or cache alias is created. The same lock protects every
//! low-level pool free, so a live or uncertain receipt fences allocation reuse.

use super::*;
use nt_hosted_runtime::{MmioRequest, MmioRequestBacking, PoolOwnedRamSource};

fn source(
    instance: usize,
    inst: DriverInstance,
    domain: nt_io_manager::HostedDomainIdentity,
    identity: nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity,
) -> PoolOwnedRamSource {
    PoolOwnedRamSource {
        instance,
        domain_id: domain.domain_id.raw(),
        domain_cookie: domain.cookie,
        pool_va_base: FSD_POOL_VADDR,
        pool_cap_base: inst.pool_frame_base,
        pool_frames: FSD_POOL_FRAMES,
        allocation_base: identity.component_address,
        allocation_capacity: identity.capacity,
        allocation_generation: identity.pool_generation,
    }
}

/// `Ok(None)` means the physical page is not in this caller's pool. An in-pool page with a
/// freed, stale or overrun allocation is a terminal refusal, not a fallback to another owner.
pub(super) unsafe fn map_owned_pool(
    instance: usize,
    inst: DriverInstance,
    physical: u64,
    length: u64,
    requested_cache: u32,
) -> Result<Option<u64>, nt_status::NtStatus> {
    if length == 0 || physical.checked_add(length).is_none() {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    if inst.pool_frame_base == 0 {
        return Ok(None);
    }
    let first_page = physical & !0xfff;
    let page_offset = physical & 0xfff;
    for index in 0..FSD_POOL_FRAMES {
        let cap = inst
            .pool_frame_base
            .checked_add(index)
            .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
        let actual =
            get_frame_paddr_checked(cap).map_err(|_| nt_status::NtStatus::INVALID_HANDLE)?;
        if actual != first_page {
            continue;
        }
        // Only a cap match enters the pool-specific authority path. A GOP provider that has
        // no live pool domain must still be able to use its separate MMIO publication.
        let domain = instance_domain_identity(inst).ok_or(nt_status::NtStatus::ACCESS_DENIED)?;
        if !inst.used || inst.exec_pool_va == 0 {
            return Err(nt_status::NtStatus::ACCESS_DENIED);
        }
        let _pool =
            hosted_instance_pool_lock(inst.exec_pool_va).ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
        if get_frame_paddr_checked(cap).ok() != Some(first_page) {
            return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
        }
        if !matches!(
            requested_cache,
            nt_hal_abi::MM_NON_CACHED | nt_hal_abi::MM_CACHED
        ) {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        let address = FSD_POOL_VADDR
            .checked_add(index * 0x1000)
            .and_then(|base| base.checked_add(page_offset))
            .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
        let identity =
            hosted_source_irp_ledger::pool_range_identity_unlocked(inst, address, length)
                .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        let published = source(instance, inst, domain, identity);
        let effective_cache = nt_hal_abi::MM_CACHED;
        let (request, mapped) = MmioRequest::from_pool_owned(
            published,
            published.owner(),
            physical,
            length,
            requested_cache,
            effective_cache,
            |cap| get_frame_paddr_checked(cap).ok(),
        )
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        let receipt = super::requests_mut()
            .prepare(request)
            .map_err(|_| nt_status::NtStatus::DEVICE_BUSY)?;
        if super::requests_mut()
            .complete(
                receipt,
                mapped,
                MmioRequestBacking::PoolOwned {
                    allocation_base: identity.component_address,
                    allocation_generation: identity.pool_generation,
                    effective_cache,
                },
            )
            .is_err()
        {
            let _ = super::requests_mut().cancel_prepared(receipt);
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        return Ok(Some(mapped));
    }
    Ok(None)
}

/// Retire one exact call; persistent WB pool frames remain mapped in both VSpaces.
/// `Ok(false)` means this VA is outside the caller's pool and may belong to GOP.
pub(super) unsafe fn unmap_owned_pool(
    instance: usize,
    inst: DriverInstance,
    address: u64,
    length: u64,
) -> Result<bool, nt_status::NtStatus> {
    let end = address
        .checked_add(length)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    if address < FSD_POOL_VADDR || address >= FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000 {
        return Ok(false);
    }
    if length == 0 || end > FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000 {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let domain = instance_domain_identity(inst).ok_or(nt_status::NtStatus::ACCESS_DENIED)?;
    let _pool =
        hosted_instance_pool_lock(inst.exec_pool_va).ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let identity = hosted_source_irp_ledger::pool_range_identity_unlocked(inst, address, length)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let owner = source(instance, inst, domain, identity).owner();
    let (receipt, backing) = super::requests_mut()
        .begin_unmap(owner, address, length)
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if backing
        != (MmioRequestBacking::PoolOwned {
            allocation_base: identity.component_address,
            allocation_generation: identity.pool_generation,
            effective_cache: nt_hal_abi::MM_CACHED,
        })
    {
        let _ = super::requests_mut().mark_unmap_uncertain(receipt);
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    super::requests_mut()
        .acknowledge_unmap(receipt)
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    Ok(true)
}

/// Called with the shared pool lock held by every path into the low-level free.
pub(in crate::driver_launch) unsafe fn has_source_rows(
    inst: DriverInstance,
    allocation_base: u64,
) -> bool {
    let requests = super::requests_mut();
    if requests.live_count() == 0 {
        return false;
    }
    let Some(identity) =
        hosted_source_irp_ledger::exact_pool_identity_unlocked(inst, allocation_base, 1)
    else {
        return true;
    };
    requests.has_pool_source_rows(
        inst.pool_frame_base,
        identity.component_address,
        identity.capacity,
    )
}

/// Retain the exact component VSpace and all its pool frame caps while any request remains.
pub(in crate::driver_launch) unsafe fn blocks_instance_retirement(inst: DriverInstance) -> bool {
    super::requests_mut().has_pool_cap_rows(inst.pool_frame_base)
}
