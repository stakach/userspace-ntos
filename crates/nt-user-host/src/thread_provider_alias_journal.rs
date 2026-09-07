//! Exact pending-thread claims over the bank's existing, uniquely owned leaf aliases.
use super::{
    BankError, ProcessIdentity, ProviderAliasBank, ProviderAliasCapability, ProviderAliasIo,
    ProviderAliasSnapshot,
};
use crate::thread_resources::ThreadMemoryLayout;
use crate::thread_rollback::ThreadRollbackId;
use alloc::vec::Vec;
use core::cell::Cell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Prepared,
    Claimed,
    Retiring,
    Complete,
}

#[derive(Debug)]
struct Entry {
    original: ProviderAliasSnapshot,
    complete: Cell<bool>,
}

/// This metadata never owns or copies release authority. The bank rows retain their real cleanup
/// phases. Callers must exclude new mappings throughout the complete thread geometry, including
/// originally empty coverage, and retain all private/external journals before invoking retirement.
/// Cell allows progress without exposing a mutable pending-runtime projection. No backend reentry
/// into either this journal or the bank is permitted.
#[derive(Debug)]
pub struct ThreadProviderAliasJournal {
    id: ThreadRollbackId,
    layout: ThreadMemoryLayout,
    entries: Vec<Entry>,
    phase: Cell<Phase>,
}

fn process(id: ThreadRollbackId) -> ProcessIdentity {
    let identity = id.identity();
    ProcessIdentity {
        pid: identity.pid,
        generation: identity.process_generation,
    }
}

fn selected(
    bank: &ProviderAliasBank,
    id: ThreadRollbackId,
    layout: ThreadMemoryLayout,
) -> impl Iterator<Item = ProviderAliasSnapshot> + '_ {
    bank.snapshots().filter(move |row| {
        row.request.pi == id.identity().pi && layout.overlaps(row.request.page, 4096)
    })
}

impl ThreadProviderAliasJournal {
    pub fn prepare(
        id: ThreadRollbackId,
        layout: ThreadMemoryLayout,
        bank: &ProviderAliasBank,
    ) -> Result<Self, BankError> {
        bank.admit_process(id.identity().pi, process(id))?;
        let mut entries = Vec::new();
        entries
            .try_reserve(selected(bank, id, layout).count())
            .map_err(|_| BankError::InsufficientResources)?;
        for original in selected(bank, id, layout) {
            if original.claim.is_some() {
                return Err(BankError::Claimed);
            }
            if entries
                .iter()
                .any(|entry: &Entry| entry.original.request.page == original.request.page)
            {
                return Err(BankError::RequestConflict);
            }
            entries.push(Entry {
                original,
                complete: Cell::new(false),
            });
        }
        let journal = Self {
            id,
            layout,
            entries,
            phase: Cell::new(Phase::Prepared),
        };
        journal.revalidate(id, bank)?;
        Ok(journal)
    }

    /// Immutable provenance for joint ownership checks, not a second destruction resource list.
    pub fn original_capabilities(&self) -> impl Iterator<Item = ProviderAliasCapability> + '_ {
        self.entries
            .iter()
            .flat_map(|entry| entry.original.owned_capabilities())
    }

    pub fn original_root_caps(&self) -> impl Iterator<Item = u64> + '_ {
        self.original_capabilities().filter_map(|cap| match cap {
            ProviderAliasCapability::Root(slot) => Some(slot),
            ProviderAliasCapability::Child(_) => None,
        })
    }

    pub fn is_complete(&self) -> bool {
        self.phase.get() == Phase::Complete
    }

    pub fn revalidate(
        &self,
        expected: ThreadRollbackId,
        bank: &ProviderAliasBank,
    ) -> Result<(), BankError> {
        if expected != self.id {
            return Err(BankError::OwnerChanged);
        }
        bank.admit_process(self.id.identity().pi, process(self.id))?;
        let remaining = self.entries.iter().filter(|entry| !entry.complete.get());
        if selected(bank, self.id, self.layout).count() != remaining.clone().count() {
            return Err(BankError::StaleHandle);
        }
        for entry in remaining {
            let row = bank
                .get(entry.original.handle)
                .ok_or(BankError::StaleHandle)?;
            if row.request != entry.original.request || row.releasing {
                return Err(BankError::OwnerChanged);
            }
            match self.phase.get() {
                Phase::Prepared if row.claim.is_some() => return Err(BankError::Claimed),
                Phase::Prepared => {}
                _ if row.claim != Some(self.id) => return Err(BankError::OwnerChanged),
                _ => {}
            }
            if matches!(self.phase.get(), Phase::Prepared | Phase::Claimed)
                && row
                    != (ProviderAliasSnapshot {
                        claim: row.claim,
                        ..entry.original
                    })
            {
                return Err(BankError::StaleHandle);
            }
            // Recycled numbers may legitimately occur elsewhere after a completed phase. Only
            // current retained capability locations participate in retry ownership validation.
            for cap in row.owned_capabilities() {
                if bank
                    .snapshots()
                    .flat_map(ProviderAliasSnapshot::owned_capabilities)
                    .filter(|other| *other == cap)
                    .count()
                    != 1
                {
                    return Err(BankError::SharedCapability(cap));
                }
            }
        }
        Ok(())
    }

    /// Revalidate the complete coverage before the first allocation-free pin. The caller must
    /// perform all cross-journal conflicts before committing claims across their disjoint tables.
    pub fn claim(
        &self,
        expected: ThreadRollbackId,
        bank: &mut ProviderAliasBank,
    ) -> Result<(), BankError> {
        self.revalidate(expected, bank)?;
        if self.phase.get() != Phase::Prepared {
            return Ok(());
        }
        for entry in &self.entries {
            bank.slots[entry.original.handle.index()]
                .row
                .as_mut()
                .expect("validated exact alias row")
                .claim = Some(self.id);
        }
        self.phase.set(Phase::Claimed);
        Ok(())
    }

    /// Drive only the claimed leaf owners after complete journal reconciliation and TCB quiescence.
    /// Failure retains both ownership and the bank's checked phase acknowledgements. Successful
    /// removal and this journal's completion acknowledgement are allocation-free and non-reentrant.
    pub fn retire(
        &self,
        expected: ThreadRollbackId,
        bank: &mut ProviderAliasBank,
        io: &mut impl ProviderAliasIo,
    ) -> Result<(), BankError> {
        self.revalidate(expected, bank)?;
        if self.phase.get() == Phase::Prepared {
            return Err(BankError::NotClaimed);
        }
        if self.is_complete() {
            return Ok(());
        }
        self.phase.set(Phase::Retiring);
        for entry in self.entries.iter().filter(|entry| !entry.complete.get()) {
            if let Err(error) = bank.retire_claimed(entry.original.handle, self.id, io) {
                bank.failures = bank.failures.saturating_add(1);
                return Err(error);
            }
            entry.complete.set(true);
        }
        self.phase.set(Phase::Complete);
        Ok(())
    }
}

#[cfg(test)]
#[path = "thread_provider_alias_journal_tests.rs"]
mod tests;
