//! `ObfDereferenceObject` from a DPC on a hosted IRQ lane (IRQL == DISPATCH_LEVEL).
//!
//! As with NT's ObpDeferObjectDeletion, a lane service drops exactly one reference at once but
//! never runs final deletion inside the DPC. The final effect is owned by an entry recorded before
//! the service returns. It becomes runnable on a PASSIVE_LEVEL root worker only after the lane
//! worker has acknowledged that exact service token. An unacknowledged or uncertain exchange
//! parks the entry for good: its effect is never replayed and its storage is never reused.

use alloc::vec::Vec;

use crate::{HostedIrqArenaToken, HostedIrqLaneDirection, HostedIrqLaneIdentity};

/// The driver's local classification of a dereferenced body. Root re-authenticates every kind
/// against its own domain-owned ledger; the word only selects which ledger owns the release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum HostedDereferenceObjectKind {
    /// A DEVICE_OBJECT in the driver's own pool.
    Device = 1,
    /// A consumer FILE_OBJECT projection in the driver's own pool.
    File = 2,
    /// A projected native Event body.
    Event = 3,
    /// Any other body: a Ps handle reference, a Ps lookup reference, or a dynamic object.
    Object = 4,
}

impl HostedDereferenceObjectKind {
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            1 => Some(Self::Device),
            2 => Some(Self::File),
            3 => Some(Self::Event),
            4 => Some(Self::Object),
            _ => None,
        }
    }
}

/// What a lane service did with the one reference it dropped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedLaneDereference {
    /// Other owners remain; the release completed in the service. Carries the remaining count.
    Completed(u32),
    /// The last owner left. Final deletion waits for its PASSIVE_LEVEL worker.
    DeferredFinal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    AwaitingAcknowledgement,
    Ready,
    Uncertain,
}

struct Entry<T> {
    lane: HostedIrqLaneIdentity,
    token: HostedIrqArenaToken,
    phase: Phase,
    payload: T,
}

/// Final deletions queued by lane services, run once each by a PASSIVE_LEVEL worker.
pub struct HostedLaneDeferredDeletions<T> {
    entries: Vec<Entry<T>>,
}

impl<T: Copy> HostedLaneDeferredDeletions<T> {
    pub const fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Reserve the owner slot before any reference count changes.
    pub fn try_reserve(&mut self) -> bool {
        self.entries.try_reserve(1).is_ok()
    }

    /// Record the final deletion owned by one exact lane service. Never allocates: the caller
    /// reserved the slot first. Refuses a token that is not a service of this lane, or a token
    /// that already owns a deletion.
    pub fn record(
        &mut self,
        lane: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
        payload: T,
    ) -> bool {
        if token.direction != HostedIrqLaneDirection::Service
            || token.lane_generation != lane.lane_generation
            || token.transaction == 0
            || token.sequence == 0
            || self.entries.len() == self.entries.capacity()
            || self.entries.iter().any(|entry| entry.lane == lane && entry.token == token)
        {
            return false;
        }
        self.entries.push(Entry {
            lane,
            token,
            phase: Phase::AwaitingAcknowledgement,
            payload,
        });
        true
    }

    /// The root observed the exchange after this service completed. Only a proven worker
    /// acknowledgement makes the deletion runnable; anything else parks it permanently.
    pub fn observe(
        &mut self,
        lane: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
        acknowledged: bool,
    ) -> bool {
        let Some(entry) = self.entries.iter_mut().find(|entry| {
            entry.lane == lane
                && entry.token == token
                && entry.phase == Phase::AwaitingAcknowledgement
        }) else {
            return false;
        };
        entry.phase = if acknowledged { Phase::Ready } else { Phase::Uncertain };
        true
    }

    /// PASSIVE_LEVEL worker: run each acknowledged deletion. An effect that reports success is
    /// removed, so it runs exactly once; a refused effect changed nothing and is retried later.
    pub fn run_ready(&mut self, mut effect: impl FnMut(T) -> bool) -> usize {
        let mut completed = 0;
        let mut index = 0;
        while index < self.entries.len() {
            if self.entries[index].phase == Phase::Ready && effect(self.entries[index].payload) {
                self.entries.swap_remove(index);
                completed += 1;
            } else {
                index += 1;
            }
        }
        completed
    }

    /// Deletions still owned here, including parked uncertain ones.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn has_ready(&self) -> bool {
        self.entries.iter().any(|entry| entry.phase == Phase::Ready)
    }
}

impl<T: Copy> Default for HostedLaneDeferredDeletions<T> {
    fn default() -> Self {
        Self::new()
    }
}
