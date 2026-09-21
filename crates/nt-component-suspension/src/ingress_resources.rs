//! Retained construction ledger for a component ingress endpoint and its distinct Replies.

use alloc::vec::Vec;
use core::convert::Infallible;

#[cfg(test)]
#[path = "ingress_resources_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressResourceKind {
    Endpoint,
    Reply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressResourcePhase {
    Reserved,
    Creating,
    Created,
}

/// Read-only attribution of an owned root slot, not deletion or recycling authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngressResourceRecord {
    pub kind: IngressResourceKind,
    pub slot: u64,
    pub phase: IngressResourcePhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressResourceError<E> {
    InvalidSlots,
    NoCapacity,
    InvalidPhase,
    Invoke(E),
}

/// Owns preallocated, exclusively reserved root slots before any retype effect. Construction
/// performs no native effects. Retain this ledger durably before initializing; callbacks must
/// retype only the exact requested object and must not reenter or release any owned slot.
/// Partial success and uncertain errors cannot replay. Drop never deletes or recycles objects.
///
/// ```compile_fail
/// use nt_component_suspension::IngressResources;
/// fn duplicate(owner: IngressResources) { let _ = owner.clone(); }
/// ```
#[must_use = "retain ingress construction ownership through native initialization"]
pub struct IngressResources {
    endpoint: u64,
    records: Vec<IngressResourceRecord>,
}

impl IngressResources {
    pub fn new(
        endpoint: u64,
        reply_slots: Vec<u64>,
    ) -> Result<Self, (IngressResourceError<Infallible>, Vec<u64>)> {
        if endpoint == 0
            || reply_slots.len() < 2
            || reply_slots.iter().enumerate().any(|(index, reply)| {
                *reply == 0 || *reply == endpoint || reply_slots[..index].contains(reply)
            })
        {
            return Err((IngressResourceError::InvalidSlots, reply_slots));
        }
        let Some(count) = reply_slots.len().checked_add(1) else {
            return Err((IngressResourceError::NoCapacity, reply_slots));
        };
        let mut records = Vec::new();
        if records.try_reserve_exact(count).is_err() {
            return Err((IngressResourceError::NoCapacity, reply_slots));
        }
        records.push(IngressResourceRecord {
            kind: IngressResourceKind::Endpoint,
            slot: endpoint,
            phase: IngressResourcePhase::Reserved,
        });
        for slot in reply_slots {
            records.push(IngressResourceRecord {
                kind: IngressResourceKind::Reply,
                slot,
                phase: IngressResourcePhase::Reserved,
            });
        }
        Ok(Self { endpoint, records })
    }

    pub const fn endpoint(&self) -> u64 {
        self.endpoint
    }

    pub fn records(&self) -> &[IngressResourceRecord] {
        &self.records
    }

    pub fn reply_slots(&self) -> impl Iterator<Item = u64> + '_ {
        self.records
            .iter()
            .filter(|record| record.kind == IngressResourceKind::Reply)
            .map(|record| record.slot)
    }

    pub fn is_ready(&self) -> bool {
        self.records
            .iter()
            .all(|record| record.phase == IngressResourcePhase::Created)
    }

    pub fn initialize<E>(
        &mut self,
        mut create: impl FnMut(IngressResourceKind, u64) -> Result<(), E>,
    ) -> Result<(), IngressResourceError<E>> {
        if self
            .records
            .iter()
            .any(|record| record.phase != IngressResourcePhase::Reserved)
        {
            return Err(IngressResourceError::InvalidPhase);
        }
        for record in &mut self.records {
            record.phase = IngressResourcePhase::Creating;
            create(record.kind, record.slot).map_err(IngressResourceError::Invoke)?;
            record.phase = IngressResourcePhase::Created;
        }
        Ok(())
    }
}
