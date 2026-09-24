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
    Exhausted,
}

#[derive(Clone, Copy, Debug)]
struct Row {
    allocation: SourceIrpAllocation,
    ticket: SourceIrpTicket,
    pins: u32,
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
        self.next_serial = serial.checked_add(1).ok_or(SourceIrpLedgerError::Exhausted)?;
        let ticket = SourceIrpTicket::new(allocation.domain, serial, serial)
            .ok_or(SourceIrpLedgerError::Exhausted)?;
        self.rows.push(Row {
            allocation,
            ticket,
            pins: 0,
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
        row.pins = row.pins.checked_add(1).ok_or(SourceIrpLedgerError::Exhausted)?;
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
        assert_eq!(ledger.retire(3, first.domain, first.component_address), Ok(first_ticket));
        let second_ticket = ledger.register(first).unwrap();
        assert_ne!(first_ticket, second_ticket);
        assert!(!ledger.matches(3, first, first_ticket));
        assert!(ledger.matches(3, first, second_ticket));
        assert_eq!(ledger.unpin(first_ticket), Err(SourceIrpLedgerError::WrongIdentity));
    }

    #[test]
    fn pinned_irp_cannot_be_freed_or_registered_twice() {
        let mut ledger = SourceIrpLedger::new();
        let owner = allocation(0x2000, 11);
        let ticket = ledger.register(owner).unwrap();
        assert_eq!(ledger.register(owner), Err(SourceIrpLedgerError::AlreadyLive));
        assert_eq!(ledger.pin(3, owner.domain, owner.component_address), Ok((ticket, owner)));
        assert_eq!(ledger.retire(3, owner.domain, owner.component_address), Err(SourceIrpLedgerError::Pinned));
        ledger.unpin(ticket).unwrap();
        assert_eq!(ledger.retire(3, owner.domain, owner.component_address), Ok(ticket));
    }

    #[test]
    fn pointer_and_cookie_are_both_scoped_to_exact_domain() {
        let mut ledger = SourceIrpLedger::new();
        let first = allocation(0x2000, 11);
        let stale_domain = allocation(0x2000, 12);
        let ticket = ledger.register(first).unwrap();
        assert_eq!(ledger.pin(3, stale_domain.domain, first.component_address), Err(SourceIrpLedgerError::NotFound));
        assert_eq!(ledger.pin(4, first.domain, first.component_address), Err(SourceIrpLedgerError::NotFound));
        assert!(!ledger.matches(3, stale_domain, ticket));
        assert_eq!(ledger.retire(3, stale_domain.domain, first.component_address), Err(SourceIrpLedgerError::NotFound));
    }
}
