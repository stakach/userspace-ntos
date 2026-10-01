//! Exact provider-owned source IRP lifetime, distinct from hosted-driver IRP transport tickets.
//!
//! The native adapter must hold a provider allocation pin for each row. This ledger does not by
//! itself stop an unmediated `ExFreePool` from retiring the component-local allocation catalog.

use alloc::vec::Vec;
use core::num::NonZeroU64;
use nt_kernel_exec::provider_pool::AllocationIdentity;
use nt_provider_wait::{ProviderAllocationPin, ProviderAllocationSnapshot, ProviderDomainIdentity};

use crate::{WDM_X64_IO_STACK_LOCATION_SIZE, WDM_X64_IRP_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderSourceIrpAllocation {
    pub provider: ProviderDomainIdentity,
    pub catalog: ProviderAllocationSnapshot,
    pub catalog_pin: ProviderAllocationPin,
    pub pool_base: u64,
    pub native: AllocationIdentity,
    pub native_capacity: u64,
    pub bytes: u64,
    pub stack_count: u8,
}

impl ProviderSourceIrpAllocation {
    fn valid(self) -> bool {
        let Some(offset) = self.catalog.base.checked_sub(self.pool_base) else {
            return false;
        };
        let Some(bytes) = (self.stack_count as u64)
            .checked_mul(WDM_X64_IO_STACK_LOCATION_SIZE as u64)
            .and_then(|stacks| stacks.checked_add(WDM_X64_IRP_SIZE as u64))
        else {
            return false;
        };
        self.provider.is_valid()
            && self.catalog.identity.is_valid()
            && self.catalog_pin.identity() == self.catalog.identity
            && self.catalog.identity.arena.generation == self.provider.generation
            && self.pool_base != 0
            && self.catalog.base != 0
            && self
                .catalog
                .base
                .checked_add(self.catalog.capacity)
                .is_some()
            && self.catalog.capacity == self.native_capacity
            && self.native_capacity >= self.bytes
            && self.stack_count != 0
            && self.stack_count != u8::MAX
            && self.bytes == bytes
            && self.bytes <= u16::MAX as u64
            && self.native.allocation_id == offset
            && self.native.allocation_id != 0
            && self.native.allocation_generation != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderSourceIrpTicket {
    pub provider: ProviderDomainIdentity,
    pub serial: NonZeroU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderSourceIrpError {
    InvalidAllocation,
    AddressInUse,
    WrongIdentity,
    Pinned,
    Retiring,
    Exhausted,
}

#[derive(Clone, Copy)]
struct Row {
    allocation: ProviderSourceIrpAllocation,
    ticket: ProviderSourceIrpTicket,
    pins: u32,
    retiring: bool,
}

pub struct ProviderSourceIrpLedger {
    rows: Vec<Row>,
    next_serial: u64,
}

impl Default for ProviderSourceIrpLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderSourceIrpLedger {
    pub const fn new() -> Self {
        Self {
            rows: Vec::new(),
            next_serial: 1,
        }
    }

    /// The native adapter must hold metadata and pool locks while proving both identities.
    pub fn register(
        &mut self,
        allocation: ProviderSourceIrpAllocation,
    ) -> Result<ProviderSourceIrpTicket, ProviderSourceIrpError> {
        if !allocation.valid() {
            return Err(ProviderSourceIrpError::InvalidAllocation);
        }
        if let Some(row) = self.rows.iter().find(|row| {
            row.allocation.pool_base == allocation.pool_base
                && row.allocation.catalog.base == allocation.catalog.base
        }) {
            return if row.allocation == allocation {
                if row.retiring {
                    Err(ProviderSourceIrpError::Retiring)
                } else {
                    Ok(row.ticket)
                }
            } else {
                Err(ProviderSourceIrpError::AddressInUse)
            };
        }
        self.rows
            .try_reserve(1)
            .map_err(|_| ProviderSourceIrpError::Exhausted)?;
        let serial = NonZeroU64::new(self.next_serial).ok_or(ProviderSourceIrpError::Exhausted)?;
        self.next_serial = self
            .next_serial
            .checked_add(1)
            .ok_or(ProviderSourceIrpError::Exhausted)?;
        let ticket = ProviderSourceIrpTicket {
            provider: allocation.provider,
            serial,
        };
        self.rows.push(Row {
            allocation,
            ticket,
            pins: 0,
            retiring: false,
        });
        Ok(ticket)
    }

    pub fn matches(
        &self,
        ticket: ProviderSourceIrpTicket,
        allocation: ProviderSourceIrpAllocation,
    ) -> bool {
        self.rows
            .iter()
            .any(|row| row.ticket == ticket && row.allocation == allocation)
    }

    pub fn allocation_at(
        &self,
        pool_base: u64,
        address: u64,
    ) -> Option<(ProviderSourceIrpTicket, ProviderSourceIrpAllocation)> {
        self.rows
            .iter()
            .find(|row| {
                row.allocation.pool_base == pool_base && row.allocation.catalog.base == address
            })
            .map(|row| (row.ticket, row.allocation))
    }

    pub fn pin(
        &mut self,
        ticket: ProviderSourceIrpTicket,
        allocation: ProviderSourceIrpAllocation,
    ) -> Result<(), ProviderSourceIrpError> {
        let row = self.exact_mut(ticket, allocation)?;
        if row.retiring {
            return Err(ProviderSourceIrpError::Retiring);
        }
        row.pins = row
            .pins
            .checked_add(1)
            .ok_or(ProviderSourceIrpError::Exhausted)?;
        Ok(())
    }

    pub fn unpin(
        &mut self,
        ticket: ProviderSourceIrpTicket,
        allocation: ProviderSourceIrpAllocation,
    ) -> Result<(), ProviderSourceIrpError> {
        let row = self.exact_mut(ticket, allocation)?;
        if row.pins == 0 {
            return Err(ProviderSourceIrpError::WrongIdentity);
        }
        row.pins -= 1;
        Ok(())
    }

    /// Check source-IRP ownership without consuming its retirement opportunity.
    pub fn preflight_free(
        &self,
        ticket: ProviderSourceIrpTicket,
        allocation: ProviderSourceIrpAllocation,
    ) -> Result<(), ProviderSourceIrpError> {
        let row = self
            .rows
            .iter()
            .find(|row| row.ticket == ticket && row.allocation == allocation)
            .ok_or(ProviderSourceIrpError::WrongIdentity)?;
        if row.retiring {
            return Err(ProviderSourceIrpError::Retiring);
        }
        if row.pins != 0 {
            return Err(ProviderSourceIrpError::Pinned);
        }
        Ok(())
    }

    /// Reserve after all fallible no-effect preflights. An uncertain native effect stays reserved.
    pub fn begin_free(
        &mut self,
        ticket: ProviderSourceIrpTicket,
        allocation: ProviderSourceIrpAllocation,
    ) -> Result<(), ProviderSourceIrpError> {
        self.preflight_free(ticket, allocation)?;
        let row = self.exact_mut(ticket, allocation)?;
        row.retiring = true;
        Ok(())
    }

    /// Call only after exact native pool and catalog retirement has completed.
    pub fn finish_free(
        &mut self,
        ticket: ProviderSourceIrpTicket,
        allocation: ProviderSourceIrpAllocation,
    ) -> Result<(), ProviderSourceIrpError> {
        let index = self
            .rows
            .iter()
            .position(|row| row.ticket == ticket && row.allocation == allocation && row.retiring)
            .ok_or(ProviderSourceIrpError::WrongIdentity)?;
        if self.rows[index].pins != 0 {
            return Err(ProviderSourceIrpError::Pinned);
        }
        self.rows.swap_remove(index);
        Ok(())
    }

    fn exact_mut(
        &mut self,
        ticket: ProviderSourceIrpTicket,
        allocation: ProviderSourceIrpAllocation,
    ) -> Result<&mut Row, ProviderSourceIrpError> {
        self.rows
            .iter_mut()
            .find(|row| row.ticket == ticket && row.allocation == allocation)
            .ok_or(ProviderSourceIrpError::WrongIdentity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nt_kernel_exec::provider_pool::AllocationIdentity;
    use nt_provider_wait::{
        ProviderAllocationCatalog, ProviderAllocationError, ProviderArenaIdentity,
        ProviderDomainIdentity,
    };

    fn allocation(
        pool_generation: u64,
        catalog_generation: u64,
    ) -> (ProviderAllocationCatalog, ProviderSourceIrpAllocation) {
        let mut catalog = ProviderAllocationCatalog::new();
        let arena = ProviderArenaIdentity {
            id: 3,
            generation: 7,
        };
        for _ in 1..catalog_generation {
            let prior = catalog.register(arena, 0x1000_2000, 0x200).unwrap();
            catalog.retire(prior.identity).unwrap();
        }
        let snapshot = catalog.register(arena, 0x1000_2000, 0x200).unwrap();
        let (pinned, pin) = catalog.pin_containing(snapshot.base, 0x1b0).unwrap();
        assert_eq!(pinned, snapshot);
        let allocation = ProviderSourceIrpAllocation {
            provider: ProviderDomainIdentity {
                domain: 4,
                generation: 7,
            },
            catalog: snapshot,
            catalog_pin: pin,
            pool_base: 0x1000_0000,
            native: AllocationIdentity {
                allocation_id: 0x2000,
                allocation_generation: pool_generation,
            },
            native_capacity: 0x200,
            bytes: (WDM_X64_IRP_SIZE + 2 * WDM_X64_IO_STACK_LOCATION_SIZE) as u64,
            stack_count: 2,
        };
        (catalog, allocation)
    }

    #[test]
    fn exact_retry_recovers_ticket_but_reused_native_generation_cannot() {
        let mut ledger = ProviderSourceIrpLedger::new();
        let (mut first_catalog, first) = allocation(11, 5);
        let ticket = ledger.register(first).unwrap();
        assert_eq!(ledger.register(first), Ok(ticket));
        let (_reused_catalog, reused) = allocation(12, 6);
        assert_eq!(
            ledger.register(reused),
            Err(ProviderSourceIrpError::AddressInUse)
        );
        assert!(!ledger.matches(ticket, reused));
        ledger.begin_free(ticket, first).unwrap();
        assert_eq!(
            first_catalog.begin_retirement(first.catalog.identity),
            Err(ProviderAllocationError::Pinned)
        );
        assert_eq!(
            ledger.allocation_at(first.pool_base, first.catalog.base),
            Some((ticket, first))
        );
        assert_eq!(
            ledger.register(first),
            Err(ProviderSourceIrpError::Retiring)
        );
        assert_eq!(
            ledger.register(reused),
            Err(ProviderSourceIrpError::AddressInUse)
        );
        first_catalog
            .begin_retirement_from_pin(first.catalog_pin)
            .unwrap();
        first_catalog.retire(first.catalog.identity).unwrap();
        ledger.finish_free(ticket, first).unwrap();
        let next = ledger.register(reused).unwrap();
        assert_ne!(next, ticket);
        assert_eq!(
            ledger.finish_free(ticket, first),
            Err(ProviderSourceIrpError::WrongIdentity)
        );
    }

    #[test]
    fn pinned_irp_cannot_begin_free_and_uncertain_free_stays_reserved() {
        let mut ledger = ProviderSourceIrpLedger::new();
        let (mut catalog, owner) = allocation(11, 5);
        let ticket = ledger.register(owner).unwrap();
        ledger.pin(ticket, owner).unwrap();
        assert_eq!(
            ledger.preflight_free(ticket, owner),
            Err(ProviderSourceIrpError::Pinned)
        );
        assert_eq!(
            ledger.begin_free(ticket, owner),
            Err(ProviderSourceIrpError::Pinned)
        );
        ledger.unpin(ticket, owner).unwrap();
        assert_eq!(ledger.preflight_free(ticket, owner), Ok(()));
        ledger.begin_free(ticket, owner).unwrap();
        assert_eq!(
            ledger.preflight_free(ticket, owner),
            Err(ProviderSourceIrpError::Retiring)
        );
        assert_eq!(
            ledger.pin(ticket, owner),
            Err(ProviderSourceIrpError::Retiring)
        );
        assert_eq!(
            ledger.begin_free(ticket, owner),
            Err(ProviderSourceIrpError::Retiring)
        );
        assert!(ledger.matches(ticket, owner));
        catalog
            .begin_retirement_from_pin(owner.catalog_pin)
            .unwrap();
        catalog.retire(owner.catalog.identity).unwrap();
        ledger.finish_free(ticket, owner).unwrap();
    }

    #[test]
    fn dispatch_lease_release_requires_exact_allocation_identity() {
        let mut ledger = ProviderSourceIrpLedger::new();
        let (_catalog, allocation) = allocation(11, 5);
        let ticket = ledger.register(allocation).unwrap();
        ledger.pin(ticket, allocation).unwrap();
        let changed_generation = ProviderSourceIrpAllocation {
            native: AllocationIdentity {
                allocation_generation: 12,
                ..allocation.native
            },
            ..allocation
        };
        assert_eq!(
            ledger.unpin(ticket, changed_generation),
            Err(ProviderSourceIrpError::WrongIdentity)
        );
        assert_eq!(
            ledger.preflight_free(ticket, allocation),
            Err(ProviderSourceIrpError::Pinned)
        );
        ledger.unpin(ticket, allocation).unwrap();
        assert_eq!(ledger.preflight_free(ticket, allocation), Ok(()));
    }

    #[test]
    fn another_catalog_pin_does_not_strand_source_irp_retirement() {
        let mut ledger = ProviderSourceIrpLedger::new();
        let (mut catalog, owner) = allocation(11, 5);
        let ticket = ledger.register(owner).unwrap();
        let (_, other_pin) = catalog
            .pin_containing(owner.catalog.base, owner.bytes)
            .unwrap();
        assert_eq!(ledger.preflight_free(ticket, owner), Ok(()));
        assert_eq!(
            catalog.begin_retirement_from_pin(owner.catalog_pin),
            Err(ProviderAllocationError::Pinned)
        );
        assert_eq!(ledger.preflight_free(ticket, owner), Ok(()));
        catalog.release_pin(other_pin).unwrap();
        assert_eq!(
            catalog.begin_retirement_from_pin(owner.catalog_pin),
            Ok(owner.catalog)
        );
        ledger.begin_free(ticket, owner).unwrap();
        catalog.retire(owner.catalog.identity).unwrap();
        ledger.finish_free(ticket, owner).unwrap();
    }

    #[test]
    fn invalid_or_mixed_provider_identity_is_not_admitted() {
        let mut ledger = ProviderSourceIrpLedger::new();
        let (_catalog, valid) = allocation(11, 5);
        let bad_pool = ProviderSourceIrpAllocation {
            native: AllocationIdentity {
                allocation_id: 0x3000,
                ..valid.native
            },
            ..valid
        };
        assert_eq!(
            ledger.register(bad_pool),
            Err(ProviderSourceIrpError::InvalidAllocation)
        );
        let bad_domain = ProviderSourceIrpAllocation {
            provider: ProviderDomainIdentity {
                generation: 8,
                ..valid.provider
            },
            ..valid
        };
        assert_eq!(
            ledger.register(bad_domain),
            Err(ProviderSourceIrpError::InvalidAllocation)
        );
        let zero_generation = ProviderSourceIrpAllocation {
            native: AllocationIdentity {
                allocation_generation: 0,
                ..valid.native
            },
            ..valid
        };
        assert_eq!(
            ledger.register(zero_generation),
            Err(ProviderSourceIrpError::InvalidAllocation)
        );
        let wrong_capacity = ProviderSourceIrpAllocation {
            native_capacity: valid.native_capacity - 1,
            ..valid
        };
        assert_eq!(
            ledger.register(wrong_capacity),
            Err(ProviderSourceIrpError::InvalidAllocation)
        );
        let (_other_catalog, other) = allocation(12, 6);
        let wrong_pin = ProviderSourceIrpAllocation {
            catalog_pin: other.catalog_pin,
            ..valid
        };
        assert_eq!(
            ledger.register(wrong_pin),
            Err(ProviderSourceIrpError::InvalidAllocation)
        );
    }

    #[test]
    fn pending_request_packet_can_retire_while_source_irp_remains_pinned() {
        use crate::win32k_source_pnp_wire::{
            decode_response, encode_request, publish_pending, SourcePnpRequest,
            SourcePnpResponse, PACKET_BYTES,
        };

        let mut ledger = ProviderSourceIrpLedger::new();
        let (mut catalog, source) = allocation(11, 5);
        let ticket = ledger.register(source).unwrap();
        ledger.pin(ticket, source).unwrap();
        let packet = catalog
            .register(source.catalog.identity.arena, 0x1000_3000, PACKET_BYTES as u64)
            .unwrap();
        let (_, packet_pin) = catalog.pin_containing(packet.base, PACKET_BYTES as u64).unwrap();
        let mut bytes = [0; PACKET_BYTES];
        encode_request(
            SourcePnpRequest {
                nonce: 1,
                source_irp_va: source.catalog.base,
                source_ticket_serial: ticket.serial.get(),
                native_allocation_generation: source.native.allocation_generation,
                device_object_va: 0x2000,
                relation_type: nt_pnp_abi::TARGET_DEVICE_RELATION,
                event: None,
                iosb_va: 0x3000,
                relation_allocation_va: 0x4000,
                relation_allocation_generation: 6,
            },
            &mut bytes,
        )
        .unwrap();
        publish_pending(&mut bytes, 7).unwrap();
        assert_eq!(decode_response(&bytes), Ok(SourcePnpResponse::Pending { token: 7 }));

        catalog.release_pin(packet_pin).unwrap();
        catalog.retire(packet.identity).unwrap();
        assert!(ledger.matches(ticket, source));
        assert_eq!(ledger.preflight_free(ticket, source), Err(ProviderSourceIrpError::Pinned));

        ledger.unpin(ticket, source).unwrap();
        ledger.begin_free(ticket, source).unwrap();
        catalog.begin_retirement_from_pin(source.catalog_pin).unwrap();
        catalog.retire(source.catalog.identity).unwrap();
        ledger.finish_free(ticket, source).unwrap();
    }
}
