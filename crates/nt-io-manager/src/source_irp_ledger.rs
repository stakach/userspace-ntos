//! Generation-bearing ownership for native IRPs allocated inside hosted components.
//!
//! The component address is a lookup key within one physical hosted domain, never a transport
//! identity. A forwarded IRP stays pinned until its source-domain completion has finished.

use alloc::vec::Vec;

use crate::retained_query_path_forward::SourceIrpTicket;
use crate::{HostedDomainId, HostedDomainIdentity};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceIrpOwner {
    /// Storage allocated by `IoAllocateIrp` in the hosted driver. The driver may request free.
    HostedDriver(usize),
    /// Caller-owned storage projected into a hosted driver for one canonical dispatch.
    /// The driver may forward this IRP, but only the projection owner may retire it.
    HostedCaller(usize),
    Win32k,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceIrpAllocation {
    pub owner: SourceIrpOwner,
    pub domain: HostedDomainIdentity,
    pub component_address: u64,
    pub bytes: u64,
    pub stack_count: u8,
    pub pool_generation: u64,
}

impl SourceIrpAllocation {
    fn valid(self) -> bool {
        self.domain.domain_id != HostedDomainId::NULL
            && self.domain.cookie != 0
            && self.component_address != 0
            && self.bytes != 0
            && self.stack_count != 0
            && self.pool_generation != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceIrpLedgerError {
    InvalidAllocation,
    AlreadyLive,
    NotFound,
    WrongIdentity,
    Pinned,
    RetirementStarted,
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
    retirement_started: bool,
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
        if let Some(row) = self.rows.iter().find(|row| {
            row.allocation.owner == allocation.owner
                && row.allocation.domain == allocation.domain
                && row.allocation.component_address == allocation.component_address
        }) {
            return if row.allocation == allocation && !row.free_requested && !row.retirement_started
            {
                Ok(row.ticket)
            } else {
                Err(SourceIrpLedgerError::AlreadyLive)
            };
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
            retirement_started: false,
            defer_free_armed: false,
            free_requested: false,
        });
        Ok(ticket)
    }

    pub fn pin(
        &mut self,
        owner: SourceIrpOwner,
        domain: HostedDomainIdentity,
        component_address: u64,
    ) -> Result<(SourceIrpTicket, SourceIrpAllocation), SourceIrpLedgerError> {
        let row = self
            .rows
            .iter_mut()
            .find(|row| {
                row.allocation.owner == owner
                    && row.allocation.domain == domain
                    && row.allocation.component_address == component_address
            })
            .ok_or(SourceIrpLedgerError::NotFound)?;
        if row.retirement_started {
            return Err(SourceIrpLedgerError::RetirementStarted);
        }
        row.pins = row
            .pins
            .checked_add(1)
            .ok_or(SourceIrpLedgerError::Exhausted)?;
        Ok((row.ticket, row.allocation))
    }

    pub fn matches(
        &self,
        owner: SourceIrpOwner,
        allocation: SourceIrpAllocation,
        ticket: SourceIrpTicket,
    ) -> bool {
        self.rows.iter().any(|row| {
            row.allocation.owner == owner && row.allocation == allocation && row.ticket == ticket
        })
    }

    pub fn allocation_for(
        &self,
        owner: SourceIrpOwner,
        domain: HostedDomainIdentity,
        component_address: u64,
    ) -> Option<SourceIrpAllocation> {
        self.rows
            .iter()
            .find(|row| {
                row.allocation.owner == owner
                    && row.allocation.domain == domain
                    && row.allocation.component_address == component_address
            })
            .map(|row| row.allocation)
    }

    pub fn registered(
        &self,
        owner: SourceIrpOwner,
        domain: HostedDomainIdentity,
        component_address: u64,
    ) -> Option<(SourceIrpTicket, SourceIrpAllocation)> {
        self.rows
            .iter()
            .find(|row| {
                row.allocation.owner == owner
                    && row.allocation.domain == domain
                    && row.allocation.component_address == component_address
            })
            .map(|row| (row.ticket, row.allocation))
    }

    /// Check an exact allocation before its owner performs an irreversible native free.
    /// The owner must serialize this check and the subsequent `retire` call.
    pub fn retirement_ready(
        &self,
        ticket: SourceIrpTicket,
        allocation: SourceIrpAllocation,
    ) -> Result<(), SourceIrpLedgerError> {
        let row = self
            .rows
            .iter()
            .find(|row| row.ticket == ticket)
            .ok_or(SourceIrpLedgerError::WrongIdentity)?;
        if row.allocation != allocation {
            return Err(SourceIrpLedgerError::WrongIdentity);
        }
        if row.pins != 0 {
            return Err(SourceIrpLedgerError::Pinned);
        }
        Ok(())
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
        if row.pins == 0 || row.retirement_started || row.defer_free_armed || row.free_requested {
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

    /// Resolve one IRP that the exact hosted instance is allowed to forward.
    ///
    /// Driver-allocated and caller-owned projections share the forwarding contract but retain
    /// distinct teardown authority. More than one matching owner is an invalid ambiguity.
    pub fn pin_hosted_forward(
        &mut self,
        instance: usize,
        domain: HostedDomainIdentity,
        component_address: u64,
    ) -> Result<(SourceIrpTicket, SourceIrpAllocation), SourceIrpLedgerError> {
        let mut found = None;
        for (index, row) in self.rows.iter().enumerate() {
            let owned_by_instance = matches!(
                row.allocation.owner,
                SourceIrpOwner::HostedDriver(owner) | SourceIrpOwner::HostedCaller(owner)
                    if owner == instance
            );
            if owned_by_instance
                && row.allocation.domain == domain
                && row.allocation.component_address == component_address
            {
                if found.replace(index).is_some() {
                    return Err(SourceIrpLedgerError::WrongIdentity);
                }
            }
        }
        let row = &mut self.rows[found.ok_or(SourceIrpLedgerError::NotFound)?];
        if row.retirement_started {
            return Err(SourceIrpLedgerError::RetirementStarted);
        }
        row.pins = row
            .pins
            .checked_add(1)
            .ok_or(SourceIrpLedgerError::Exhausted)?;
        Ok((row.ticket, row.allocation))
    }

    /// `IoFreeIrp` authority is limited to storage allocated by the exact hosted driver.
    /// A free inside an explicitly armed completion is deferred; an unpinned free remains live
    /// until the caller completes physical teardown and calls `retire` under the same lock.
    pub fn prepare_driver_free(
        &mut self,
        instance: usize,
        domain: HostedDomainIdentity,
        component_address: u64,
    ) -> Result<SourceIrpRetirement, SourceIrpLedgerError> {
        self.prepare_free(
            SourceIrpOwner::HostedDriver(instance),
            domain,
            component_address,
        )
    }

    fn prepare_free(
        &mut self,
        owner: SourceIrpOwner,
        domain: HostedDomainIdentity,
        component_address: u64,
    ) -> Result<SourceIrpRetirement, SourceIrpLedgerError> {
        let index = self
            .rows
            .iter()
            .position(|row| {
                row.allocation.owner == owner
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
        Ok(SourceIrpRetirement::Retired(self.rows[index].ticket))
    }

    /// Atomically close a caller-owned projection to new pins before native teardown.
    ///
    /// Once this succeeds, an uncertain native free must leave the row closed and retained. The
    /// caller may finish retirement only after receiving an unambiguous native-free acknowledgement.
    pub fn begin_hosted_caller_retirement(
        &mut self,
        ticket: SourceIrpTicket,
        allocation: SourceIrpAllocation,
    ) -> Result<(), SourceIrpLedgerError> {
        if !matches!(allocation.owner, SourceIrpOwner::HostedCaller(_)) {
            return Err(SourceIrpLedgerError::WrongIdentity);
        }
        let row = self
            .rows
            .iter_mut()
            .find(|row| row.ticket == ticket && row.allocation == allocation)
            .ok_or(SourceIrpLedgerError::WrongIdentity)?;
        if row.retirement_started {
            return Err(SourceIrpLedgerError::RetirementStarted);
        }
        if row.pins != 0 {
            return Err(SourceIrpLedgerError::Pinned);
        }
        row.retirement_started = true;
        Ok(())
    }

    /// Remove a closed caller-owned projection after exact native-free acknowledgement.
    pub fn finish_hosted_caller_retirement(
        &mut self,
        ticket: SourceIrpTicket,
        allocation: SourceIrpAllocation,
    ) -> Result<(), SourceIrpLedgerError> {
        if !matches!(allocation.owner, SourceIrpOwner::HostedCaller(_)) {
            return Err(SourceIrpLedgerError::WrongIdentity);
        }
        let index = self
            .rows
            .iter()
            .position(|row| row.ticket == ticket && row.allocation == allocation)
            .ok_or(SourceIrpLedgerError::WrongIdentity)?;
        if !self.rows[index].retirement_started || self.rows[index].pins != 0 {
            return Err(SourceIrpLedgerError::WrongIdentity);
        }
        self.rows.swap_remove(index);
        Ok(())
    }

    /// Remove the exact allocation after its owner has completed native teardown.
    /// The caller must serialize `retirement_ready`, teardown, and this operation.
    pub fn retire(
        &mut self,
        ticket: SourceIrpTicket,
        allocation: SourceIrpAllocation,
    ) -> Result<(), SourceIrpLedgerError> {
        if matches!(allocation.owner, SourceIrpOwner::HostedCaller(_)) {
            return Err(SourceIrpLedgerError::WrongIdentity);
        }
        let index = self
            .rows
            .iter()
            .position(|row| row.ticket == ticket && row.allocation == allocation)
            .ok_or(SourceIrpLedgerError::WrongIdentity)?;
        if self.rows[index].pins != 0 {
            return Err(SourceIrpLedgerError::Pinned);
        }
        self.rows.swap_remove(index);
        Ok(())
    }

    pub fn live_for_owner(&self, owner: SourceIrpOwner, domain: HostedDomainIdentity) -> usize {
        self.rows
            .iter()
            .filter(|row| row.allocation.owner == owner && row.allocation.domain == domain)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocation(address: u64, cookie: u64) -> SourceIrpAllocation {
        SourceIrpAllocation {
            owner: SourceIrpOwner::HostedDriver(3),
            domain: HostedDomainIdentity {
                domain_id: HostedDomainId(7),
                cookie,
            },
            component_address: address,
            bytes: 0x128,
            stack_count: 2,
            pool_generation: 1,
        }
    }

    fn caller_allocation(address: u64, cookie: u64) -> SourceIrpAllocation {
        SourceIrpAllocation {
            owner: SourceIrpOwner::HostedCaller(3),
            ..allocation(address, cookie)
        }
    }

    #[test]
    fn address_reuse_never_recovers_a_stale_ticket() {
        let mut ledger = SourceIrpLedger::new();
        let first = allocation(0x2000, 11);
        let first_ticket = ledger.register(first).unwrap();
        assert_eq!(ledger.retire(first_ticket, first), Ok(()));
        let second_ticket = ledger.register(first).unwrap();
        assert_ne!(first_ticket, second_ticket);
        assert_eq!(
            ledger.retire(first_ticket, first),
            Err(SourceIrpLedgerError::WrongIdentity)
        );
        assert!(!ledger.matches(first.owner, first, first_ticket));
        assert!(ledger.matches(first.owner, first, second_ticket));
        assert_eq!(ledger.live_for_owner(first.owner, first.domain), 1);
        assert_eq!(
            ledger.unpin(first_ticket),
            Err(SourceIrpLedgerError::WrongIdentity)
        );
    }

    #[test]
    fn pinned_irp_cannot_be_freed_and_exact_retry_recovers_its_ticket() {
        let mut ledger = SourceIrpLedger::new();
        let owner = allocation(0x2000, 11);
        let ticket = ledger.register(owner).unwrap();
        assert_eq!(ledger.register(owner), Ok(ticket));
        assert_eq!(
            ledger.pin(owner.owner, owner.domain, owner.component_address),
            Ok((ticket, owner))
        );
        assert_eq!(
            ledger.retire(ticket, owner),
            Err(SourceIrpLedgerError::Pinned)
        );
        ledger.unpin(ticket).unwrap();
        assert_eq!(ledger.retire(ticket, owner), Ok(()));
    }

    #[test]
    fn reused_pool_generation_cannot_impersonate_a_live_source_irp() {
        let mut ledger = SourceIrpLedger::new();
        let first = allocation(0x2000, 11);
        let ticket = ledger.register(first).unwrap();
        let reused = SourceIrpAllocation {
            pool_generation: first.pool_generation + 1,
            ..first
        };
        assert_eq!(
            ledger.register(reused),
            Err(SourceIrpLedgerError::AlreadyLive)
        );
        assert!(!ledger.matches(reused.owner, reused, ticket));
        assert_eq!(
            ledger.retirement_ready(ticket, reused),
            Err(SourceIrpLedgerError::WrongIdentity)
        );
        ledger.retire(ticket, first).unwrap();
        let next = ledger.register(reused).unwrap();
        assert_ne!(next, ticket);
        assert_eq!(ledger.register(reused), Ok(next));
        assert_eq!(
            ledger.retire(ticket, reused),
            Err(SourceIrpLedgerError::WrongIdentity)
        );
    }

    #[test]
    fn zero_native_pool_generation_is_not_an_allocation_identity() {
        let mut ledger = SourceIrpLedger::new();
        let invalid = SourceIrpAllocation {
            pool_generation: 0,
            ..allocation(0x2000, 11)
        };
        assert_eq!(
            ledger.register(invalid),
            Err(SourceIrpLedgerError::InvalidAllocation)
        );
    }

    #[test]
    fn pointer_and_cookie_are_both_scoped_to_exact_domain() {
        let mut ledger = SourceIrpLedger::new();
        let first = allocation(0x2000, 11);
        let stale_domain = allocation(0x2000, 12);
        let ticket = ledger.register(first).unwrap();
        assert_eq!(
            ledger.pin(first.owner, stale_domain.domain, first.component_address),
            Err(SourceIrpLedgerError::NotFound)
        );
        assert_eq!(
            ledger.pin(
                SourceIrpOwner::HostedDriver(4),
                first.domain,
                first.component_address
            ),
            Err(SourceIrpLedgerError::NotFound)
        );
        assert!(!ledger.matches(first.owner, stale_domain, ticket));
        assert_eq!(
            ledger.retire(ticket, stale_domain),
            Err(SourceIrpLedgerError::WrongIdentity)
        );
    }

    #[test]
    fn owners_are_isolated_even_at_the_same_domain_and_address() {
        let mut ledger = SourceIrpLedger::new();
        let driver = allocation(0x2000, 11);
        let win32k = SourceIrpAllocation {
            owner: SourceIrpOwner::Win32k,
            ..driver
        };
        let driver_ticket = ledger.register(driver).unwrap();
        let win32k_ticket = ledger.register(win32k).unwrap();
        assert_eq!(
            ledger.retire(driver_ticket, win32k),
            Err(SourceIrpLedgerError::WrongIdentity)
        );
        assert_ne!(driver_ticket, win32k_ticket);
        assert_eq!(ledger.live_for_owner(driver.owner, driver.domain), 1);
        assert_eq!(ledger.live_for_owner(win32k.owner, win32k.domain), 1);
        assert_eq!(
            ledger.pin(driver.owner, driver.domain, driver.component_address),
            Ok((driver_ticket, driver)),
        );
        assert_eq!(
            ledger.pin(win32k.owner, win32k.domain, win32k.component_address),
            Ok((win32k_ticket, win32k)),
        );
        assert!(!ledger.matches(driver.owner, win32k, win32k_ticket));
        assert!(!ledger.matches(win32k.owner, driver, driver_ticket));
        ledger.unpin(driver_ticket).unwrap();
        assert_eq!(ledger.retire(driver_ticket, driver), Ok(()),);
        assert!(ledger.matches(win32k.owner, win32k, win32k_ticket));
        ledger.unpin(win32k_ticket).unwrap();
        assert_eq!(ledger.retire(win32k_ticket, win32k), Ok(()),);
        let reused = ledger.register(win32k).unwrap();
        assert_ne!(reused, win32k_ticket);
        assert!(!ledger.matches(win32k.owner, win32k, win32k_ticket));
    }

    #[test]
    fn native_free_preflight_requires_exact_live_unpinned_allocation() {
        let mut ledger = SourceIrpLedger::new();
        let owner = allocation(0x2000, 11);
        let ticket = ledger.register(owner).unwrap();
        assert_eq!(ledger.retirement_ready(ticket, owner), Ok(()));
        assert_eq!(
            ledger.retirement_ready(
                ticket,
                SourceIrpAllocation {
                    bytes: owner.bytes + 1,
                    ..owner
                }
            ),
            Err(SourceIrpLedgerError::WrongIdentity),
        );
        ledger
            .pin(owner.owner, owner.domain, owner.component_address)
            .unwrap();
        assert_eq!(
            ledger.retirement_ready(ticket, owner),
            Err(SourceIrpLedgerError::Pinned)
        );
        ledger.unpin(ticket).unwrap();
        ledger.retire(ticket, owner).unwrap();
        assert_eq!(
            ledger.retirement_ready(ticket, owner),
            Err(SourceIrpLedgerError::WrongIdentity)
        );
    }

    #[test]
    fn prepared_free_retains_identity_until_physical_teardown_completes() {
        let mut ledger = SourceIrpLedger::new();
        let owner = allocation(0x2000, 11);
        let ticket = ledger.register(owner).unwrap();
        assert_eq!(
            ledger.prepare_driver_free(3, owner.domain, owner.component_address),
            Ok(SourceIrpRetirement::Retired(ticket))
        );
        assert!(ledger.matches(owner.owner, owner, ticket));
        assert_eq!(ledger.register(owner), Ok(ticket));
        ledger.retire(ticket, owner).unwrap();
        assert!(!ledger.matches(owner.owner, owner, ticket));
    }

    #[test]
    fn only_explicitly_armed_forward_can_defer_source_callback_free() {
        let mut ledger = SourceIrpLedger::new();
        let owner = allocation(0x2000, 11);
        let ticket = ledger.register(owner).unwrap();
        ledger
            .pin(owner.owner, owner.domain, owner.component_address)
            .unwrap();
        assert_eq!(
            ledger.prepare_driver_free(3, owner.domain, owner.component_address),
            Err(SourceIrpLedgerError::Pinned),
        );
        ledger.arm_deferred_free(ticket).unwrap();
        assert_eq!(
            ledger.prepare_driver_free(3, owner.domain, owner.component_address),
            Ok(SourceIrpRetirement::Deferred(ticket)),
        );
        assert!(ledger.deferred_free_requested(ticket));
        assert_eq!(
            ledger.prepare_driver_free(3, owner.domain, owner.component_address),
            Err(SourceIrpLedgerError::AlreadyDeferred),
        );
        assert_eq!(
            ledger.register(owner),
            Err(SourceIrpLedgerError::AlreadyLive)
        );
        ledger.unpin(ticket).unwrap();
        assert_eq!(
            ledger.prepare_driver_free(3, owner.domain, owner.component_address),
            Ok(SourceIrpRetirement::Retired(ticket)),
        );
        assert!(ledger.matches(owner.owner, owner, ticket));
        ledger.retire(ticket, owner).unwrap();
        assert!(!ledger.deferred_free_requested(ticket));
    }

    #[test]
    fn stale_ticket_cannot_arm_reused_irp_address() {
        let mut ledger = SourceIrpLedger::new();
        let owner = allocation(0x2000, 11);
        let stale = ledger.register(owner).unwrap();
        ledger.retire(stale, owner).unwrap();
        let live = ledger.register(owner).unwrap();
        ledger
            .pin(owner.owner, owner.domain, owner.component_address)
            .unwrap();
        assert_eq!(
            ledger.arm_deferred_free(stale),
            Err(SourceIrpLedgerError::WrongIdentity)
        );
        assert_eq!(
            ledger.prepare_driver_free(3, owner.domain, owner.component_address),
            Err(SourceIrpLedgerError::Pinned)
        );
        ledger.arm_deferred_free(live).unwrap();
        assert_eq!(
            ledger.prepare_driver_free(3, owner.domain, owner.component_address),
            Ok(SourceIrpRetirement::Deferred(live))
        );
    }

    #[test]
    fn hosted_caller_forward_pin_preserves_exact_native_generation() {
        let mut ledger = SourceIrpLedger::new();
        let caller = caller_allocation(0x3000, 11);
        let ticket = ledger.register(caller).unwrap();

        assert_eq!(
            ledger.pin_hosted_forward(3, caller.domain, caller.component_address),
            Ok((ticket, caller))
        );
        let reused = SourceIrpAllocation {
            pool_generation: caller.pool_generation + 1,
            ..caller
        };
        assert!(!ledger.matches(caller.owner, reused, ticket));
        assert_eq!(
            ledger.begin_hosted_caller_retirement(ticket, reused),
            Err(SourceIrpLedgerError::WrongIdentity)
        );
        ledger.unpin(ticket).unwrap();
        ledger
            .begin_hosted_caller_retirement(ticket, caller)
            .unwrap();
        ledger
            .finish_hosted_caller_retirement(ticket, caller)
            .unwrap();
    }

    #[test]
    fn hosted_forward_rejects_foreign_instance_and_domain() {
        let mut ledger = SourceIrpLedger::new();
        let caller = caller_allocation(0x3000, 11);
        ledger.register(caller).unwrap();

        assert_eq!(
            ledger.pin_hosted_forward(4, caller.domain, caller.component_address),
            Err(SourceIrpLedgerError::NotFound)
        );
        assert_eq!(
            ledger.pin_hosted_forward(
                3,
                HostedDomainIdentity {
                    domain_id: caller.domain.domain_id,
                    cookie: caller.domain.cookie + 1,
                },
                caller.component_address,
            ),
            Err(SourceIrpLedgerError::NotFound)
        );
    }

    #[test]
    fn pinned_hosted_caller_projection_cannot_be_torn_down() {
        let mut ledger = SourceIrpLedger::new();
        let caller = caller_allocation(0x3000, 11);
        let ticket = ledger.register(caller).unwrap();
        ledger
            .pin_hosted_forward(3, caller.domain, caller.component_address)
            .unwrap();

        assert_eq!(
            ledger.begin_hosted_caller_retirement(ticket, caller),
            Err(SourceIrpLedgerError::Pinned)
        );
        assert_eq!(
            ledger.finish_hosted_caller_retirement(ticket, caller),
            Err(SourceIrpLedgerError::WrongIdentity)
        );
        ledger.unpin(ticket).unwrap();
        assert_eq!(
            ledger.begin_hosted_caller_retirement(ticket, caller),
            Ok(())
        );
        assert_eq!(
            ledger.pin_hosted_forward(3, caller.domain, caller.component_address),
            Err(SourceIrpLedgerError::RetirementStarted)
        );
        assert_eq!(
            ledger.retire(ticket, caller),
            Err(SourceIrpLedgerError::WrongIdentity)
        );
        assert_eq!(
            ledger.finish_hosted_caller_retirement(ticket, caller),
            Ok(())
        );
    }

    #[test]
    fn uncertain_hosted_caller_free_stays_closed_and_retained() {
        let mut ledger = SourceIrpLedger::new();
        let caller = caller_allocation(0x3000, 11);
        let ticket = ledger.register(caller).unwrap();

        assert_eq!(
            ledger.begin_hosted_caller_retirement(ticket, caller),
            Ok(())
        );
        assert!(ledger.matches(caller.owner, caller, ticket));
        assert_eq!(
            ledger.pin_hosted_forward(3, caller.domain, caller.component_address),
            Err(SourceIrpLedgerError::RetirementStarted)
        );
        assert_eq!(
            ledger.pin(caller.owner, caller.domain, caller.component_address),
            Err(SourceIrpLedgerError::RetirementStarted)
        );
        assert_eq!(
            ledger.register(caller),
            Err(SourceIrpLedgerError::AlreadyLive)
        );
        assert_eq!(
            ledger.begin_hosted_caller_retirement(ticket, caller),
            Err(SourceIrpLedgerError::RetirementStarted)
        );

        assert!(ledger.matches(caller.owner, caller, ticket));
        assert_eq!(ledger.live_for_owner(caller.owner, caller.domain), 1);
    }

    #[test]
    fn io_free_irp_authority_excludes_hosted_caller_projection() {
        let mut ledger = SourceIrpLedger::new();
        let caller = caller_allocation(0x3000, 11);
        let caller_ticket = ledger.register(caller).unwrap();

        assert_eq!(
            ledger.prepare_driver_free(3, caller.domain, caller.component_address),
            Err(SourceIrpLedgerError::NotFound)
        );
        assert!(ledger.matches(caller.owner, caller, caller_ticket));

        let driver = allocation(0x4000, 11);
        let driver_ticket = ledger.register(driver).unwrap();
        assert_eq!(
            ledger.prepare_driver_free(3, driver.domain, driver.component_address),
            Ok(SourceIrpRetirement::Retired(driver_ticket))
        );
        ledger.retire(driver_ticket, driver).unwrap();
        ledger
            .begin_hosted_caller_retirement(caller_ticket, caller)
            .unwrap();
        ledger
            .finish_hosted_caller_retirement(caller_ticket, caller)
            .unwrap();
    }
}
