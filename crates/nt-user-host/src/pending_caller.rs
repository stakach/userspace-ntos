//! Original logical caller provenance for independently reserved pending-operation owners.
//!
//! The key must contain the owner's full table and generation identity, not just an IRP or slot.
//! This table neither creates owner identities nor retains references or capabilities. Callers
//! reserve storage before dispatch and publish only after the matching operation owner commits.

use alloc::vec::Vec;

use crate::provider_logical_caller::ProviderLogicalCaller;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingCallerError {
    Occupied,
    InvalidSlot,
    AllocationFailed,
    WrongKey,
    InvalidPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Reserved,
    Published,
}

#[derive(Clone, Copy, Debug)]
struct Entry<K> {
    key: K,
    caller: ProviderLogicalCaller,
    phase: Phase,
}

#[derive(Debug)]
pub struct PendingCallerTable<K: Copy + Eq> {
    entries: Vec<Option<Entry<K>>>,
}

impl<K: Copy + Eq> Default for PendingCallerTable<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Copy + Eq> PendingCallerTable<K> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Store the admitted caller before dispatch. A failed reservation leaves existing owners
    /// untouched; neither the key nor the caller may be replaced in an occupied slot.
    pub fn reserve(
        &mut self,
        slot: usize,
        key: K,
        caller: ProviderLogicalCaller,
    ) -> Result<(), PendingCallerError> {
        let required_len = slot.checked_add(1).ok_or(PendingCallerError::InvalidSlot)?;
        if self.entries.get(slot).is_some_and(Option::is_some) {
            return Err(PendingCallerError::Occupied);
        }
        if required_len > self.entries.len() {
            self.entries
                .try_reserve(required_len - self.entries.len())
                .map_err(|_| PendingCallerError::AllocationFailed)?;
            self.entries.resize_with(required_len, || None);
        }
        self.entries[slot] = Some(Entry {
            key,
            caller,
            phase: Phase::Reserved,
        });
        Ok(())
    }

    /// Commit only the phase of the already captured caller, without allocating or recapturing.
    pub fn publish(
        &mut self,
        slot: usize,
        key: K,
    ) -> Result<ProviderLogicalCaller, PendingCallerError> {
        let entry = self.entry_mut(slot, key)?;
        if entry.phase != Phase::Reserved {
            return Err(PendingCallerError::InvalidPhase);
        }
        entry.phase = Phase::Published;
        Ok(entry.caller)
    }

    pub fn get_reserved(&self, slot: usize, key: K) -> Option<ProviderLogicalCaller> {
        self.get_phase(slot, key, Phase::Reserved)
    }

    pub fn get_published(&self, slot: usize, key: K) -> Option<ProviderLogicalCaller> {
        self.get_phase(slot, key, Phase::Published)
    }

    pub fn cancel_reserved(
        &mut self,
        slot: usize,
        key: K,
    ) -> Result<ProviderLogicalCaller, PendingCallerError> {
        self.take_phase(slot, key, Phase::Reserved)
    }

    pub fn retire_published(
        &mut self,
        slot: usize,
        key: K,
    ) -> Result<ProviderLogicalCaller, PendingCallerError> {
        self.take_phase(slot, key, Phase::Published)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(Option::is_none)
    }

    /// Reuse storage only after all reserved and published provenance has been removed. The
    /// independent owner table remains responsible for never reusing a full key after reset.
    pub fn reset(&mut self) -> bool {
        if !self.is_empty() {
            return false;
        }
        self.entries.clear();
        true
    }

    pub fn capacity(&self) -> usize {
        self.entries.capacity()
    }

    fn get_phase(&self, slot: usize, key: K, phase: Phase) -> Option<ProviderLogicalCaller> {
        let entry = self.entries.get(slot)?.as_ref()?;
        (entry.key == key && entry.phase == phase).then_some(entry.caller)
    }

    fn entry_mut(&mut self, slot: usize, key: K) -> Result<&mut Entry<K>, PendingCallerError> {
        self.entries
            .get_mut(slot)
            .and_then(Option::as_mut)
            .filter(|entry| entry.key == key)
            .ok_or(PendingCallerError::WrongKey)
    }

    fn take_phase(
        &mut self,
        slot: usize,
        key: K,
        phase: Phase,
    ) -> Result<ProviderLogicalCaller, PendingCallerError> {
        let entry = self.entry_mut(slot, key)?;
        if entry.phase != phase {
            return Err(PendingCallerError::InvalidPhase);
        }
        let caller = entry.caller;
        self.entries[slot] = None;
        Ok(caller)
    }
}

#[cfg(test)]
#[path = "pending_caller_tests.rs"]
mod tests;
