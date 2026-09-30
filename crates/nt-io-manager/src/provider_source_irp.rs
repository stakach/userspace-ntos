//! Exact provider-owned source IRP lifetime, distinct from hosted-driver IRP transport tickets.
//!
//! The native adapter must hold a provider allocation pin for each row. This ledger does not by
//! itself stop an unmediated `ExFreePool` from retiring the component-local allocation catalog.

use alloc::vec::Vec;
use core::num::NonZeroU64;
use nt_kernel_exec::provider_pool::AllocationIdentity;
use nt_provider_wait::{ProviderAllocationSnapshot, ProviderDomainIdentity};

use crate::{WDM_X64_IO_STACK_LOCATION_SIZE, WDM_X64_IRP_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderSourceIrpAllocation {
    pub provider: ProviderDomainIdentity,
    pub catalog: ProviderAllocationSnapshot,
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

    pub fn unpin(&mut self, ticket: ProviderSourceIrpTicket) -> Result<(), ProviderSourceIrpError> {
        let row = self
            .rows
            .iter_mut()
            .find(|row| row.ticket == ticket)
            .ok_or(ProviderSourceIrpError::WrongIdentity)?;
        if row.pins == 0 {
            return Err(ProviderSourceIrpError::WrongIdentity);
        }
        row.pins -= 1;
        Ok(())
    }

    /// Reserve before native free. An uncertain effect leaves this row reserved, never replayable.
    pub fn begin_free(
        &mut self,
        ticket: ProviderSourceIrpTicket,
        allocation: ProviderSourceIrpAllocation,
    ) -> Result<(), ProviderSourceIrpError> {
        let row = self.exact_mut(ticket, allocation)?;
        if row.retiring {
            return Err(ProviderSourceIrpError::Retiring);
        }
        if row.pins != 0 {
            return Err(ProviderSourceIrpError::Pinned);
        }
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
        ProviderAllocationIdentity, ProviderAllocationSnapshot, ProviderArenaIdentity,
        ProviderDomainIdentity,
    };

    fn allocation(pool_generation: u64, catalog_generation: u64) -> ProviderSourceIrpAllocation {
        ProviderSourceIrpAllocation {
            provider: ProviderDomainIdentity {
                domain: 4,
                generation: 7,
            },
            catalog: ProviderAllocationSnapshot {
                identity: ProviderAllocationIdentity {
                    arena: ProviderArenaIdentity {
                        id: 3,
                        generation: 7,
                    },
                    allocation_id: 9,
                    generation: catalog_generation,
                },
                base: 0x1000_2000,
                capacity: 0x200,
            },
            pool_base: 0x1000_0000,
            native: AllocationIdentity {
                allocation_id: 0x2000,
                allocation_generation: pool_generation,
            },
            native_capacity: 0x200,
            bytes: (WDM_X64_IRP_SIZE + 2 * WDM_X64_IO_STACK_LOCATION_SIZE) as u64,
            stack_count: 2,
        }
    }

    #[test]
    fn exact_retry_recovers_ticket_but_reused_native_generation_cannot() {
        let mut ledger = ProviderSourceIrpLedger::new();
        let first = allocation(11, 5);
        let ticket = ledger.register(first).unwrap();
        assert_eq!(ledger.register(first), Ok(ticket));
        let reused = allocation(12, 6);
        assert_eq!(
            ledger.register(reused),
            Err(ProviderSourceIrpError::AddressInUse)
        );
        assert!(!ledger.matches(ticket, reused));
        ledger.begin_free(ticket, first).unwrap();
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
        let owner = allocation(11, 5);
        let ticket = ledger.register(owner).unwrap();
        ledger.pin(ticket, owner).unwrap();
        assert_eq!(
            ledger.begin_free(ticket, owner),
            Err(ProviderSourceIrpError::Pinned)
        );
        ledger.unpin(ticket).unwrap();
        ledger.begin_free(ticket, owner).unwrap();
        assert_eq!(
            ledger.pin(ticket, owner),
            Err(ProviderSourceIrpError::Retiring)
        );
        assert_eq!(
            ledger.begin_free(ticket, owner),
            Err(ProviderSourceIrpError::Retiring)
        );
        assert!(ledger.matches(ticket, owner));
        ledger.finish_free(ticket, owner).unwrap();
    }

    #[test]
    fn invalid_or_mixed_provider_identity_is_not_admitted() {
        let mut ledger = ProviderSourceIrpLedger::new();
        let valid = allocation(11, 5);
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
    }
}
