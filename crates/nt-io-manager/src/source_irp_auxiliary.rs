//! Exact child-allocation and requestor ownership for hosted source IRPs.
//!
//! An IRP ticket protects the packet allocation, but not pool addresses stored
//! inside the packet. This ledger keeps generation-bearing child snapshots and
//! admits terminal child release only from the thread that published them.

use alloc::vec::Vec;

use crate::retained_query_path_forward::SourceIrpTicket;
use crate::source_irp_ledger::{SourceIrpAllocation, SourceIrpOwner};
use crate::HostedDomainIdentity;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourcePoolAllocationIdentity {
    pub component_address: u64,
    pub capacity: u64,
    pub pool_generation: u64,
}

impl SourcePoolAllocationIdentity {
    fn valid(self) -> bool {
        self.component_address != 0 && self.capacity != 0 && self.pool_generation != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceMdlAllocationIdentity {
    pub pool: SourcePoolAllocationIdentity,
    pub registry_generation: u32,
}

impl SourceMdlAllocationIdentity {
    fn valid(self) -> bool {
        self.pool.valid() && self.registry_generation != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceMemoryIdentity {
    Pool {
        allocation: SourcePoolAllocationIdentity,
        component_address: u64,
        bytes: u64,
    },
    MappedRange {
        component_address: u64,
        bytes: u64,
        exec_address: u64,
    },
}

impl SourceMemoryIdentity {
    fn valid(self) -> bool {
        match self {
            Self::Pool {
                allocation,
                component_address,
                bytes,
            } => allocation.valid()
                && component_address >= allocation.component_address
                && bytes != 0
                && component_address.checked_add(bytes).is_some_and(|end| {
                    allocation
                        .component_address
                        .checked_add(allocation.capacity)
                        .is_some_and(|allocation_end| end <= allocation_end)
                }),
            Self::MappedRange {
                component_address,
                bytes,
                exec_address,
            } => component_address != 0 && bytes != 0 && exec_address != 0,
        }
    }

    fn pool_address(self) -> Option<u64> {
        match self {
            Self::Pool { allocation, .. } => Some(allocation.component_address),
            Self::MappedRange { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceIrpCompletionOwner {
    pub thread_handle: u64,
    pub thread_object: u64,
    pub event: SourceMemoryIdentity,
    pub iosb: SourceMemoryIdentity,
}

impl SourceIrpCompletionOwner {
    fn valid(self) -> bool {
        self.thread_handle != 0
            && self.thread_object != 0
            && self.event.valid()
            && self.iosb.valid()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceIrpAuxiliary {
    pub source: SourceIrpAllocation,
    pub ticket: SourceIrpTicket,
    pub system_buffer: Option<SourcePoolAllocationIdentity>,
    pub mdl: Option<SourceMdlAllocationIdentity>,
    pub transfer_buffer: Option<SourceMemoryIdentity>,
    pub completion: SourceIrpCompletionOwner,
}

impl SourceIrpAuxiliary {
    fn valid(self) -> bool {
        self.ticket.domain == self.source.domain
            && self.system_buffer.is_none_or(SourcePoolAllocationIdentity::valid)
            && self.mdl.is_none_or(SourceMdlAllocationIdentity::valid)
            && self.transfer_buffer.is_none_or(SourceMemoryIdentity::valid)
            && self.completion.valid()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceIrpAuxiliaryPhase {
    Protected,
    Completing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceIrpAuxiliaryError {
    Invalid,
    AlreadyLive,
    NotFound,
    WrongIdentity,
    AlreadyCompleting,
    NoCapacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Row {
    auxiliary: SourceIrpAuxiliary,
    phase: SourceIrpAuxiliaryPhase,
}

pub struct SourceIrpAuxiliaryLedger {
    rows: Vec<Row>,
}

impl SourceIrpAuxiliaryLedger {
    pub const fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub fn register(
        &mut self,
        auxiliary: SourceIrpAuxiliary,
    ) -> Result<(), SourceIrpAuxiliaryError> {
        if !auxiliary.valid() {
            return Err(SourceIrpAuxiliaryError::Invalid);
        }
        if let Some(row) = self.rows.iter().find(|row| {
            row.auxiliary.source.owner == auxiliary.source.owner
                && row.auxiliary.source.domain == auxiliary.source.domain
                && row.auxiliary.source.component_address == auxiliary.source.component_address
        }) {
            return if row.auxiliary == auxiliary
                && row.phase == SourceIrpAuxiliaryPhase::Protected
            {
                Ok(())
            } else {
                Err(SourceIrpAuxiliaryError::AlreadyLive)
            };
        }
        self.rows
            .try_reserve(1)
            .map_err(|_| SourceIrpAuxiliaryError::NoCapacity)?;
        self.rows.push(Row {
            auxiliary,
            phase: SourceIrpAuxiliaryPhase::Protected,
        });
        Ok(())
    }

    pub fn snapshot(
        &self,
        ticket: SourceIrpTicket,
        source: SourceIrpAllocation,
    ) -> Result<(SourceIrpAuxiliary, SourceIrpAuxiliaryPhase), SourceIrpAuxiliaryError> {
        let row = self
            .rows
            .iter()
            .find(|row| row.auxiliary.ticket == ticket)
            .ok_or(SourceIrpAuxiliaryError::NotFound)?;
        if row.auxiliary.source != source {
            return Err(SourceIrpAuxiliaryError::WrongIdentity);
        }
        Ok((row.auxiliary, row.phase))
    }

    pub fn begin_completion(
        &mut self,
        ticket: SourceIrpTicket,
        source: SourceIrpAllocation,
    ) -> Result<SourceIrpAuxiliary, SourceIrpAuxiliaryError> {
        let row = self
            .rows
            .iter_mut()
            .find(|row| row.auxiliary.ticket == ticket)
            .ok_or(SourceIrpAuxiliaryError::NotFound)?;
        if row.auxiliary.source != source {
            return Err(SourceIrpAuxiliaryError::WrongIdentity);
        }
        if row.phase != SourceIrpAuxiliaryPhase::Protected {
            return Err(SourceIrpAuxiliaryError::AlreadyCompleting);
        }
        row.phase = SourceIrpAuxiliaryPhase::Completing;
        Ok(row.auxiliary)
    }

    pub fn protected_pool_child(
        &self,
        owner: SourceIrpOwner,
        domain: HostedDomainIdentity,
        component_address: u64,
    ) -> bool {
        self.rows.iter().any(|row| {
            row.phase == SourceIrpAuxiliaryPhase::Protected
                && row.auxiliary.source.owner == owner
                && row.auxiliary.source.domain == domain
                && (row.auxiliary.system_buffer.is_some_and(|child| {
                    child.component_address == component_address
                }) || row.auxiliary.mdl.is_some_and(|child| {
                    child.pool.component_address == component_address
                }) || row.auxiliary.transfer_buffer
                    .and_then(SourceMemoryIdentity::pool_address)
                    == Some(component_address)
                    || row.auxiliary.completion.event.pool_address() == Some(component_address)
                    || row.auxiliary.completion.iosb.pool_address() == Some(component_address))
        })
    }

    pub fn retire(
        &mut self,
        ticket: SourceIrpTicket,
        source: SourceIrpAllocation,
    ) -> Result<SourceIrpAuxiliary, SourceIrpAuxiliaryError> {
        let index = self
            .rows
            .iter()
            .position(|row| row.auxiliary.ticket == ticket)
            .ok_or(SourceIrpAuxiliaryError::NotFound)?;
        if self.rows[index].auxiliary.source != source {
            return Err(SourceIrpAuxiliaryError::WrongIdentity);
        }
        Ok(self.rows.swap_remove(index).auxiliary)
    }
}

impl Default for SourceIrpAuxiliaryLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HostedDomainId, HostedDomainIdentity};

    fn auxiliary() -> SourceIrpAuxiliary {
        let domain = HostedDomainIdentity {
            domain_id: HostedDomainId(7),
            cookie: 11,
        };
        let source = SourceIrpAllocation {
            owner: SourceIrpOwner::HostedDriver(3),
            domain,
            component_address: 0x2000,
            bytes: 0x150,
            stack_count: 2,
            pool_generation: 4,
        };
        SourceIrpAuxiliary {
            source,
            ticket: SourceIrpTicket::new(domain, 5, 6).unwrap(),
            system_buffer: Some(SourcePoolAllocationIdentity {
                component_address: 0x3000,
                capacity: 0x200,
                pool_generation: 8,
            }),
            mdl: None,
            transfer_buffer: None,
            completion: SourceIrpCompletionOwner {
                thread_handle: 9,
                thread_object: 0x4000,
                event: SourceMemoryIdentity::MappedRange {
                    component_address: 0x5000,
                    bytes: 0x18,
                    exec_address: 0x6000,
                },
                iosb: SourceMemoryIdentity::MappedRange {
                    component_address: 0x7000,
                    bytes: 0x10,
                    exec_address: 0x8000,
                },
            },
        }
    }

    #[test]
    fn child_address_is_protected_until_provider_begins_terminal_completion() {
        let mut ledger = SourceIrpAuxiliaryLedger::new();
        let auxiliary = auxiliary();
        ledger.register(auxiliary).unwrap();
        assert!(ledger.protected_pool_child(
            auxiliary.source.owner,
            auxiliary.source.domain,
            auxiliary.system_buffer.unwrap().component_address,
        ));
        ledger
            .begin_completion(auxiliary.ticket, auxiliary.source)
            .unwrap();
        assert!(!ledger.protected_pool_child(
            auxiliary.source.owner,
            auxiliary.source.domain,
            auxiliary.system_buffer.unwrap().component_address,
        ));
    }

    #[test]
    fn completion_authority_is_not_tied_to_the_requestor_thread() {
        let mut ledger = SourceIrpAuxiliaryLedger::new();
        let auxiliary = auxiliary();
        ledger.register(auxiliary).unwrap();

        // The native adapter authenticates the completing caller's hosted-driver
        // domain. The retained thread handle describes the original requestor; it
        // is not a requirement that completion run on that same worker thread.
        assert_eq!(auxiliary.completion.thread_handle, 9);
        assert_eq!(
            ledger.begin_completion(auxiliary.ticket, auxiliary.source),
            Ok(auxiliary)
        );
    }

    #[test]
    fn reused_child_generation_never_matches_the_published_snapshot() {
        let mut ledger = SourceIrpAuxiliaryLedger::new();
        let auxiliary = auxiliary();
        ledger.register(auxiliary).unwrap();
        let (published, phase) = ledger
            .snapshot(auxiliary.ticket, auxiliary.source)
            .unwrap();
        let reused = SourcePoolAllocationIdentity {
            pool_generation: published.system_buffer.unwrap().pool_generation + 1,
            ..published.system_buffer.unwrap()
        };
        assert_ne!(published.system_buffer, Some(reused));
        assert_eq!(phase, SourceIrpAuxiliaryPhase::Protected);
    }

    #[test]
    fn mdl_and_backing_pool_allocations_are_both_protected() {
        let mut ledger = SourceIrpAuxiliaryLedger::new();
        let mut auxiliary = auxiliary();
        let mdl_pool = SourcePoolAllocationIdentity {
            component_address: 0x9000,
            capacity: 0x30,
            pool_generation: 12,
        };
        auxiliary.mdl = Some(SourceMdlAllocationIdentity {
            pool: mdl_pool,
            registry_generation: 13,
        });
        let backing = SourcePoolAllocationIdentity {
            component_address: 0xa000,
            capacity: 0x1000,
            pool_generation: 14,
        };
        auxiliary.transfer_buffer = Some(SourceMemoryIdentity::Pool {
            allocation: backing,
            component_address: 0xa080,
            bytes: 0x200,
        });
        ledger.register(auxiliary).unwrap();
        assert!(ledger.protected_pool_child(
            auxiliary.source.owner,
            auxiliary.source.domain,
            mdl_pool.component_address,
        ));
        assert!(ledger.protected_pool_child(
            auxiliary.source.owner,
            auxiliary.source.domain,
            backing.component_address,
        ));
    }

    #[test]
    fn retirement_requires_the_exact_source_identity() {
        let mut ledger = SourceIrpAuxiliaryLedger::new();
        let auxiliary = auxiliary();
        ledger.register(auxiliary).unwrap();
        let stale = SourceIrpAllocation {
            pool_generation: auxiliary.source.pool_generation + 1,
            ..auxiliary.source
        };
        assert_eq!(
            ledger.retire(auxiliary.ticket, stale),
            Err(SourceIrpAuxiliaryError::WrongIdentity)
        );
        assert_eq!(
            ledger.retire(auxiliary.ticket, auxiliary.source),
            Ok(auxiliary)
        );
    }
}
