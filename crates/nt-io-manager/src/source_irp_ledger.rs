//! Generation-bearing ownership for native IRPs allocated inside hosted drivers.
//!
//! The component address is a lookup key within one physical hosted domain, never a transport
//! identity. A forwarded IRP stays pinned until its source-domain completion has finished.

use alloc::vec::Vec;

use crate::retained_query_path_forward::SourceIrpTicket;
use crate::{HostedDomainId, HostedDomainIdentity};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceIrpAllocation {
    pub instance: usize,
    pub domain: HostedDomainIdentity,
    pub component_address: u64,
    pub bytes: u64,
    pub stack_count: u8,
}

impl SourceIrpAllocation {
    fn valid(self) -> bool {
        self.domain.domain_id != HostedDomainId::NULL
            && self.domain.cookie != 0
            && self.component_address != 0
            && self.bytes != 0
            && self.stack_count != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceIrpLedgerError {
    InvalidAllocation,
    AlreadyLive,
    NotFound,
    WrongIdentity,
    Pinned,
    AlreadyDeferred,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceIrpRetirement {
    Retired(SourceIrpTicket),
    Deferred(SourceIrpTicket),
}

#[derive(Clone, Copy, Debug)]
struct Row {
    allocation: SourceIrpAllocation,
    ticket: SourceIrpTicket,
    pins: u32,
    defer_free_armed: bool,
    free_requested: bool,
}

pub struct SourceIrpLedger {
    rows: Vec<Row>,
    next_serial: u64,
}

impl Default for SourceIrpLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceIrpLedger {
    pub const fn new() -> Self {
        Self {
            rows: Vec::new(),
            next_serial: 1,
        }
    }

    pub fn register(
        &mut self,
        allocation: SourceIrpAllocation,
    ) -> Result<SourceIrpTicket, SourceIrpLedgerError> {
        if !allocation.valid() {
            return Err(SourceIrpLedgerError::InvalidAllocation);
        }
        if self.rows.iter().any(|row| {
            row.allocation.instance == allocation.instance
                && row.allocation.domain == allocation.domain
                && row.allocation.component_address == allocation.component_address
        }) {
            return Err(SourceIrpLedgerError::AlreadyLive);
        }
        self.rows
            .try_reserve(1)
            .map_err(|_| SourceIrpLedgerError::Exhausted)?;
        let serial = self.next_serial;
        self.next_serial = serial
            .checked_add(1)
            .ok_or(SourceIrpLedgerError::Exhausted)?;
        let ticket = SourceIrpTicket::new(allocation.domain, serial, serial)
            .ok_or(SourceIrpLedgerError::Exhausted)?;
        self.rows.push(Row {
            allocation,
            ticket,
            pins: 0,
            defer_free_armed: false,
            free_requested: false,
        });
        Ok(ticket)
    }

    pub fn pin(
        &mut self,
        instance: usize,
        domain: HostedDomainIdentity,
        component_address: u64,
    ) -> Result<(SourceIrpTicket, SourceIrpAllocation), SourceIrpLedgerError> {
        let row = self
            .rows
            .iter_mut()
            .find(|row| {
                row.allocation.instance == instance
                    && row.allocation.domain == domain
                    && row.allocation.component_address == component_address
            })
            .ok_or(SourceIrpLedgerError::NotFound)?;
        row.pins = row
            .pins
            .checked_add(1)
            .ok_or(SourceIrpLedgerError::Exhausted)?;
        Ok((row.ticket, row.allocation))
    }

    pub fn matches(
        &self,
        instance: usize,
        allocation: SourceIrpAllocation,
        ticket: SourceIrpTicket,
    ) -> bool {
        self.rows.iter().any(|row| {
            row.allocation.instance == instance
                && row.allocation == allocation
                && row.ticket == ticket
        })
    }

    pub fn allocation_for(
        &self,
        instance: usize,
        domain: HostedDomainIdentity,
        component_address: u64,
    ) -> Option<SourceIrpAllocation> {
        self.rows
            .iter()
            .find(|row| {
                row.allocation.instance == instance
                    && row.allocation.domain == domain
                    && row.allocation.component_address == component_address
            })
            .map(|row| row.allocation)
    }

    pub fn unpin(&mut self, ticket: SourceIrpTicket) -> Result<(), SourceIrpLedgerError> {
        let row = self
            .rows
            .iter_mut()
            .find(|row| row.ticket == ticket)
            .ok_or(SourceIrpLedgerError::WrongIdentity)?;
        if row.pins == 0 {
            return Err(SourceIrpLedgerError::WrongIdentity);
        }
        row.pins -= 1;
        Ok(())
    }

    /// Only a retained cross-domain forward may authorize the source callback to defer free.
    /// Merely holding a pin does not change the ordinary `IoFreeIrp` contract.
    pub fn arm_deferred_free(
        &mut self,
        ticket: SourceIrpTicket,
    ) -> Result<(), SourceIrpLedgerError> {
        let row = self
            .rows
            .iter_mut()
            .find(|row| row.ticket == ticket)
            .ok_or(SourceIrpLedgerError::WrongIdentity)?;
        if row.pins == 0 || row.defer_free_armed || row.free_requested {
            return Err(SourceIrpLedgerError::WrongIdentity);
        }
        row.defer_free_armed = true;
        Ok(())
    }

    pub fn deferred_free_requested(&self, ticket: SourceIrpTicket) -> bool {
        self.rows
            .iter()
            .any(|row| row.ticket == ticket && row.free_requested)
    }

    /// The first free inside Mup's completion callback is retained while the forward owns a pin.
    /// After exact terminal ACK and unpin, a second source-local free retires the allocation.
    pub fn request_free(
        &mut self,
        instance: usize,
        domain: HostedDomainIdentity,
        component_address: u64,
    ) -> Result<SourceIrpRetirement, SourceIrpLedgerError> {
        let index = self
            .rows
            .iter()
            .position(|row| {
                row.allocation.instance == instance
                    && row.allocation.domain == domain
                    && row.allocation.component_address == component_address
            })
            .ok_or(SourceIrpLedgerError::NotFound)?;
        if self.rows[index].pins != 0 {
            if !self.rows[index].defer_free_armed {
                return Err(SourceIrpLedgerError::Pinned);
            }
            if self.rows[index].free_requested {
                return Err(SourceIrpLedgerError::AlreadyDeferred);
            }
            self.rows[index].free_requested = true;
            return Ok(SourceIrpRetirement::Deferred(self.rows[index].ticket));
        }
        Ok(SourceIrpRetirement::Retired(
            self.rows.swap_remove(index).ticket,
        ))
    }

    pub fn retire(
        &mut self,
        instance: usize,
        domain: HostedDomainIdentity,
        component_address: u64,
    ) -> Result<SourceIrpTicket, SourceIrpLedgerError> {
        let index = self
            .rows
            .iter()
            .position(|row| {
                row.allocation.instance == instance
                    && row.allocation.domain == domain
                    && row.allocation.component_address == component_address
            })
            .ok_or(SourceIrpLedgerError::NotFound)?;
        if self.rows[index].pins != 0 {
            return Err(SourceIrpLedgerError::Pinned);
        }
        Ok(self.rows.swap_remove(index).ticket)
    }

    pub fn live_for_instance(&self, instance: usize, domain: HostedDomainIdentity) -> usize {
        self.rows
            .iter()
            .filter(|row| row.allocation.instance == instance && row.allocation.domain == domain)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocation(address: u64, cookie: u64) -> SourceIrpAllocation {
        SourceIrpAllocation {
            instance: 3,
            domain: HostedDomainIdentity {
                domain_id: HostedDomainId(7),
                cookie,
            },
            component_address: address,
            bytes: 0x128,
            stack_count: 2,
        }
    }

    #[test]
    fn address_reuse_never_recovers_a_stale_ticket() {
        let mut ledger = SourceIrpLedger::new();
        let first = allocation(0x2000, 11);
        let first_ticket = ledger.register(first).unwrap();
        assert_eq!(
            ledger.retire(3, first.domain, first.component_address),
            Ok(first_ticket)
        );
        let second_ticket = ledger.register(first).unwrap();
        assert_ne!(first_ticket, second_ticket);
        assert!(!ledger.matches(3, first, first_ticket));
        assert!(ledger.matches(3, first, second_ticket));
        assert_eq!(
            ledger.unpin(first_ticket),
            Err(SourceIrpLedgerError::WrongIdentity)
        );
    }

    #[test]
    fn pinned_irp_cannot_be_freed_or_registered_twice() {
        let mut ledger = SourceIrpLedger::new();
        let owner = allocation(0x2000, 11);
        let ticket = ledger.register(owner).unwrap();
        assert_eq!(
            ledger.register(owner),
            Err(SourceIrpLedgerError::AlreadyLive)
        );
        assert_eq!(
            ledger.pin(3, owner.domain, owner.component_address),
            Ok((ticket, owner))
        );
        assert_eq!(
            ledger.retire(3, owner.domain, owner.component_address),
            Err(SourceIrpLedgerError::Pinned)
        );
        ledger.unpin(ticket).unwrap();
        assert_eq!(
            ledger.retire(3, owner.domain, owner.component_address),
            Ok(ticket)
        );
    }

    #[test]
    fn pointer_and_cookie_are_both_scoped_to_exact_domain() {
        let mut ledger = SourceIrpLedger::new();
        let first = allocation(0x2000, 11);
        let stale_domain = allocation(0x2000, 12);
        let ticket = ledger.register(first).unwrap();
        assert_eq!(
            ledger.pin(3, stale_domain.domain, first.component_address),
            Err(SourceIrpLedgerError::NotFound)
        );
        assert_eq!(
            ledger.pin(4, first.domain, first.component_address),
            Err(SourceIrpLedgerError::NotFound)
        );
        assert!(!ledger.matches(3, stale_domain, ticket));
        assert_eq!(
            ledger.retire(3, stale_domain.domain, first.component_address),
            Err(SourceIrpLedgerError::NotFound)
        );
    }

    #[test]
    fn only_explicitly_armed_forward_can_defer_source_callback_free() {
        let mut ledger = SourceIrpLedger::new();
        let owner = allocation(0x2000, 11);
        let ticket = ledger.register(owner).unwrap();
        ledger
            .pin(3, owner.domain, owner.component_address)
            .unwrap();
        assert_eq!(
            ledger.request_free(3, owner.domain, owner.component_address),
            Err(SourceIrpLedgerError::Pinned),
        );
        ledger.arm_deferred_free(ticket).unwrap();
        assert_eq!(
            ledger.request_free(3, owner.domain, owner.component_address),
            Ok(SourceIrpRetirement::Deferred(ticket)),
        );
        assert!(ledger.deferred_free_requested(ticket));
        assert_eq!(
            ledger.request_free(3, owner.domain, owner.component_address),
            Err(SourceIrpLedgerError::AlreadyDeferred),
        );
        assert_eq!(
            ledger.register(owner),
            Err(SourceIrpLedgerError::AlreadyLive)
        );
        ledger.unpin(ticket).unwrap();
        assert_eq!(
            ledger.request_free(3, owner.domain, owner.component_address),
            Ok(SourceIrpRetirement::Retired(ticket)),
        );
        assert!(!ledger.deferred_free_requested(ticket));
    }

    #[test]
    fn stale_ticket_cannot_arm_reused_irp_address() {
        let mut ledger = SourceIrpLedger::new();
        let owner = allocation(0x2000, 11);
        let stale = ledger.register(owner).unwrap();
        ledger
            .retire(3, owner.domain, owner.component_address)
            .unwrap();
        let live = ledger.register(owner).unwrap();
        ledger
            .pin(3, owner.domain, owner.component_address)
            .unwrap();
        assert_eq!(
            ledger.arm_deferred_free(stale),
            Err(SourceIrpLedgerError::WrongIdentity)
        );
        assert_eq!(
            ledger.request_free(3, owner.domain, owner.component_address),
            Err(SourceIrpLedgerError::Pinned)
        );
        ledger.arm_deferred_free(live).unwrap();
        assert_eq!(
            ledger.request_free(3, owner.domain, owner.component_address),
            Ok(SourceIrpRetirement::Deferred(live))
        );
    }
}
