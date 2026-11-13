//! Retirement receipts for root turns whose parent retires inside a later native effect.

use alloc::vec::Vec;

/// Root registers a parent before that parent's next native effect. The parent's one-use
/// terminal ACK then seals the receipt without allocating, and root consumes it exactly once.
///
/// A watch is keyed by the parent's stable claim, never by its physical witness: a Reply
/// refreshed between registration and the ACK still belongs to the same claim, while a reused
/// slot is a different claim and cannot seal or consume this receipt.
#[derive(Debug)]
pub struct RootChildRetirementWatches<C> {
    watches: Vec<Watch<C>>,
}

#[derive(Debug)]
struct Watch<C> {
    claim: C,
    acknowledged: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootChildRetirementError {
    AlreadyWatched,
    Exhausted,
}

impl<C: Copy + Eq> RootChildRetirementWatches<C> {
    pub const fn new() -> Self {
        Self { watches: Vec::new() }
    }

    /// Reserve the receipt now; sealing it after the provider effect must not allocate.
    pub fn watch(&mut self, claim: C) -> Result<(), RootChildRetirementError> {
        if self.watched(claim) { return Err(RootChildRetirementError::AlreadyWatched); }
        self.watches.try_reserve(1).map_err(|_| RootChildRetirementError::Exhausted)?;
        self.watches.push(Watch { claim, acknowledged: false });
        Ok(())
    }

    pub fn watched(&self, claim: C) -> bool {
        self.watches.iter().any(|watch| watch.claim == claim)
    }

    /// Seal the watched claim's receipt once. An unwatched parent retires without one.
    pub fn acknowledge(&mut self, claim: C) -> bool {
        match self.watches.iter_mut().find(|watch| watch.claim == claim) {
            Some(watch) if !watch.acknowledged => {
                watch.acknowledged = true;
                true
            }
            _ => false,
        }
    }

    pub fn retired(&self, claim: C) -> bool {
        self.watches.iter().any(|watch| watch.claim == claim && watch.acknowledged)
    }

    /// Only a sealed receipt can be consumed, and only once.
    pub fn consume(&mut self, claim: C) -> bool {
        let Some(index) = self.watches.iter()
            .position(|watch| watch.claim == claim && watch.acknowledged)
        else { return false };
        self.watches.swap_remove(index);
        true
    }
}

impl<C: Copy + Eq> Default for RootChildRetirementWatches<C> {
    fn default() -> Self { Self::new() }
}
