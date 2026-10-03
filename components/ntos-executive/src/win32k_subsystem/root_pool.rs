//! Root-owned shared allocations never access component-private allocation metadata.
//!
//! Private catalog admission requires an unpinned, newly allocated shared block under the
//! physical pool lock. These receipts instead install an exclusive native pin before publishing
//! any address, so private input, Event, and Timer lookup cannot adopt their backing. Embedded
//! File/device objects are exposed only through canonical projections and their retirement
//! preflights, not through component-private allocation leases.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootPoolError {
    BusyNoEffect,
    InvalidIdentity,
    InsufficientResources,
    Indeterminate,
}

#[derive(Clone, Copy)]
pub(crate) struct RootProviderPoolAllocation {
    packet: ProviderPoolPacketLease,
    pin: SharedPoolPin,
}

impl RootProviderPoolAllocation {
    pub(crate) fn address(self) -> u64 {
        self.packet.address()
    }
    pub(crate) fn length(self) -> u64 {
        self.packet.length as u64
    }
    pub(crate) fn packet_lease(self) -> ProviderPoolPacketLease {
        self.packet
    }
}

fn pool_error(error: shared_pool::PoolError) -> RootPoolError {
    match error {
        shared_pool::PoolError::OutOfMemory
        | shared_pool::PoolError::GenerationExhausted
        | shared_pool::PoolError::ArenaExhausted
        | shared_pool::PoolError::PinExhausted => RootPoolError::InsufficientResources,
        shared_pool::PoolError::Corrupt => RootPoolError::Indeterminate,
        _ => RootPoolError::InvalidIdentity,
    }
}

unsafe fn validate_packet_range(lease: ProviderPoolPacketLease) -> Result<(), RootPoolError> {
    if !provider_pool_contains(lease.pointer)
        || lease.length == 0
        || lease.length as u64 > lease.capacity
        || !lease.pointer.checked_add(lease.capacity).is_some_and(|end| {
            end <= WIN32K_POOL_VADDR + WIN32K_POOL_FRAMES * 0x1000
        })
        || registered_provider_wait_domain() != Some(lease.provider)
        || !provider_pool_ready()
    {
        return Err(RootPoolError::InvalidIdentity);
    }
    Ok(())
}

// The caller owns the physical pool lock; this helper never enters a private catalog.
unsafe fn validate_packet_locked(lease: ProviderPoolPacketLease) -> Result<(), RootPoolError> {
    if registered_provider_wait_domain() != Some(lease.provider) {
        return Err(RootPoolError::InvalidIdentity);
    }
    let memory = ProviderPoolMemory;
    let offset = lease.pointer - WIN32K_POOL_VADDR;
    let identity = shared_pool::allocation_identity(&memory, offset).map_err(pool_error)?;
    let capacity = shared_pool::allocation_capacity(&memory, offset).map_err(pool_error)?;
    if identity != lease.allocation || capacity != lease.capacity {
        return Err(RootPoolError::InvalidIdentity);
    }
    Ok(())
}

pub(crate) unsafe fn try_capture_root_provider_pool_packet(
    lease: ProviderPoolPacketLease,
) -> Result<Vec<u8>, RootPoolError> {
    validate_packet_range(lease)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(lease.length).map_err(|_| RootPoolError::InsufficientResources)?;
    bytes.resize(lease.length, 0);
    let _pool = try_provider_pool_lock().ok_or(RootPoolError::BusyNoEffect)?;
    validate_packet_locked(lease)?;
    core::ptr::copy_nonoverlapping(lease.pointer as *const u8, bytes.as_mut_ptr(), lease.length);
    Ok(bytes)
}

pub(crate) unsafe fn try_publish_root_provider_pool_packet(
    lease: ProviderPoolPacketLease,
    bytes: &[u8],
) -> Result<(), RootPoolError> {
    if bytes.len() != lease.length {
        return Err(RootPoolError::InvalidIdentity);
    }
    validate_packet_range(lease)?;
    let _pool = try_provider_pool_lock().ok_or(RootPoolError::BusyNoEffect)?;
    validate_packet_locked(lease)?;
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), lease.pointer as *mut u8, bytes.len());
    Ok(())
}

pub(crate) unsafe fn try_allocate_root_provider_pool_allocation(
    length: u64,
) -> Result<RootProviderPoolAllocation, RootPoolError> {
    let length = usize::try_from(length).map_err(|_| RootPoolError::InsufficientResources)?;
    if length == 0 || length as u64 >= WIN32K_POOL_FRAMES * 0x1000 {
        return Err(RootPoolError::InsufficientResources);
    }
    let provider = registered_provider_wait_domain().ok_or(RootPoolError::InvalidIdentity)?;
    if !provider_pool_ready() {
        return Err(RootPoolError::InvalidIdentity);
    }
    let _pool = try_provider_pool_lock().ok_or(RootPoolError::BusyNoEffect)?;
    if registered_provider_wait_domain() != Some(provider) {
        return Err(RootPoolError::InvalidIdentity);
    }
    let mut memory = ProviderPoolMemory;
    let allocation = match shared_pool::allocate(&mut memory, length as u64, true) {
        Ok(allocation) => allocation,
        Err(shared_pool::PoolError::Corrupt) => {
            // The allocator may already have changed a header; never replay this allocation.
            crate::provider_bugcheck::report(0xc4, [length as u64, 0, 0, 115]);
        }
        Err(error) => return Err(pool_error(error)),
    };
    let native = match shared_pool::pin_exclusive(&mut memory, allocation.identity) {
        Ok(pin) => pin,
        Err(shared_pool::PoolError::Corrupt) => {
            crate::provider_bugcheck::report(0xc4, [allocation.payload_offset, length as u64, 0, 116]);
        }
        Err(error) => {
            // Known pin refusal precedes mutation; rollback remains inside this same lock.
            if shared_pool::free(&mut memory, allocation.payload_offset).is_err() {
                crate::provider_bugcheck::report(0xc4, [allocation.payload_offset, length as u64, 0, 117]);
            }
            return Err(pool_error(error));
        }
    };
    Ok(RootProviderPoolAllocation {
        packet: ProviderPoolPacketLease {
            pointer: WIN32K_POOL_VADDR + allocation.payload_offset,
            length,
            provider,
            allocation: allocation.identity,
            capacity: allocation.capacity,
        },
        pin: SharedPoolPin { provider, allocation: allocation.identity, native },
    })
}

/// Only `Ok` consumes the caller's owned receipt; Busy and preflight failures retain it.
pub(crate) unsafe fn try_retire_root_provider_pool_allocation(
    allocation: RootProviderPoolAllocation,
) -> Result<(), RootPoolError> {
    let lease = allocation.packet;
    if allocation.pin.provider != lease.provider || allocation.pin.allocation != lease.allocation {
        return Err(RootPoolError::InvalidIdentity);
    }
    validate_packet_range(lease)?;
    let _pool = try_provider_pool_lock().ok_or(RootPoolError::BusyNoEffect)?;
    validate_packet_locked(lease)?;
    match shared_pool::retire_pinned(&mut ProviderPoolMemory, allocation.pin.native) {
        Ok(_) => Ok(()),
        Err(shared_pool::PoolError::Corrupt) => {
            // A partially changed free list cannot authorize either reuse or a stale retry.
            crate::provider_bugcheck::report(0xc4, [lease.pointer, lease.length as u64, 0, 118]);
        }
        Err(error) => Err(pool_error(error)),
    }
}

pub(crate) unsafe fn allocate_root_provider_pool_allocation(
    length: u64,
) -> Option<RootProviderPoolAllocation> {
    let length = usize::try_from(length).ok()?;
    if length == 0 {
        return None;
    }
    let provider = registered_provider_wait_domain()?;
    let _pool = provider_pool_lock()?;
    let mut memory = ProviderPoolMemory;
    let allocation = shared_pool::allocate(&mut memory, length as u64, true).ok()?;
    let native = match shared_pool::pin_exclusive(&mut memory, allocation.identity) {
        Ok(pin) => pin,
        Err(_) => {
            if shared_pool::free(&mut memory, allocation.payload_offset).is_err() {
                crate::provider_bugcheck::report(
                    0xc4,
                    [allocation.payload_offset, length as u64, 0, 114],
                );
            }
            return None;
        }
    };
    Some(RootProviderPoolAllocation {
        packet: ProviderPoolPacketLease {
            pointer: WIN32K_POOL_VADDR + allocation.payload_offset,
            length,
            provider,
            allocation: allocation.identity,
            capacity: allocation.capacity,
        },
        pin: SharedPoolPin {
            provider,
            allocation: allocation.identity,
            native,
        },
    })
}

/// The caller must retire canonical object, reference, and Event owners before this native effect.
/// A refusal leaves the exact receipt held; an address alone never authorizes freeing a replacement.
pub(crate) unsafe fn retire_root_provider_pool_allocation(
    allocation: RootProviderPoolAllocation,
) -> bool {
    retire_pinned_root_provider_pool_packet(allocation.packet, allocation.pin)
}
