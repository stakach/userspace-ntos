//! Root-owned shared allocations never access component-private allocation metadata.
//!
//! Private catalog admission requires an unpinned, newly allocated shared block under the
//! physical pool lock. These receipts instead install an exclusive native pin before publishing
//! any address, so private input, Event, and Timer lookup cannot adopt their backing. Embedded
//! File/device objects are exposed only through canonical projections and their retirement
//! preflights, not through component-private allocation leases.

use super::*;

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
