//! Exact-attempt claims over external aliases; mapping rows retain the only release authority.
use crate::thread_resources::ThreadMemoryLayout;
use crate::thread_rollback::ThreadRollbackId;
use alloc::vec::Vec;
use core::cell::Cell;
use nt_memory_manager::alias_transition::{
    AliasTransition, AliasTransitionIo, AliasTransitionSnapshot,
};
use nt_memory_manager::retained_alias::AliasRetirementIo;

const INVALID: u32 = nt_memory_manager::STATUS_INVALID_HANDLE;

pub struct ThreadAliasMapping {
    page: u64,
    alias: AliasTransition,
    claim: Option<ThreadRollbackId>,
}

#[cfg(test)]
#[path = "thread_alias_journal_tests.rs"]
mod tests;

impl ThreadAliasMapping {
    pub fn new(page: u64) -> Option<Self> {
        (page & 4095 == 0 && page.checked_add(4096).is_some()).then(|| Self {
            page,
            alias: AliasTransition::empty(),
            claim: None,
        })
    }
    pub fn page(&self) -> u64 {
        self.page
    }
    pub fn is_claimed(&self) -> bool {
        self.claim.is_some()
    }
    pub fn snapshot(&self) -> AliasTransitionSnapshot {
        self.alias.snapshot()
    }
    pub fn live(&self) -> Option<(u64, u64)> {
        if self.is_claimed() {
            None
        } else {
            self.alias.live()
        }
    }
    /// Ordinary removal cannot discard a claim, even if all physical slots are already empty.
    pub fn is_empty(&self) -> bool {
        !self.is_claimed() && self.alias.is_empty()
    }
    fn ordinary(&mut self) -> Result<&mut AliasTransition, u32> {
        if self.is_claimed() {
            Err(INVALID)
        } else {
            Ok(&mut self.alias)
        }
    }
    pub fn replace(&mut self, rights: u64, io: &mut impl AliasTransitionIo) -> Result<(), u32> {
        self.ordinary()?.replace(rights, io)
    }
    pub fn remap(&mut self, rights: u64, io: &mut impl AliasTransitionIo) -> Result<(), u32> {
        self.ordinary()?.remap(rights, io)
    }
    pub fn recover(&mut self, io: &mut impl AliasTransitionIo) -> Result<(), u32> {
        self.ordinary()?.recover(io)
    }
    pub fn retire(&mut self, io: &mut impl AliasRetirementIo) -> Result<(), u32> {
        self.ordinary()?.retire(io)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalError {
    OwnerChanged,
    StaleMappings,
    Claimed,
    SharedCapability(u64),
    InsufficientResources,
    NotClaimed,
    Backend { page: u64, status: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Prepared,
    Claimed,
    Retiring,
    Complete,
}

#[derive(Debug)]
struct Entry {
    page: u64,
    original: AliasTransitionSnapshot,
    complete: Cell<bool>,
}

/// Durable metadata only. The containing pending runtime must retain memory/reservations and
/// exclude alias admission throughout this journal's lifetime. No method transfers a cap out of
/// its mapping row or exposes mutable alias ownership. Cell permits in-place progress without a
/// mutable projection of the containing runtime; backend calls may not reenter either owner/table.
#[derive(Debug)]
pub struct ThreadAliasJournal {
    id: ThreadRollbackId,
    layout: ThreadMemoryLayout,
    entries: Vec<Entry>,
    phase: Cell<Phase>,
}

impl ThreadAliasJournal {
    pub fn prepare(
        id: ThreadRollbackId,
        layout: ThreadMemoryLayout,
        attached_pi: u64,
        mappings: &[ThreadAliasMapping],
    ) -> Result<Self, JournalError> {
        let selected = mappings.iter().filter(|row| {
            attached_pi == id.identity().pi as u64 && layout.overlaps(row.page, 4096)
        });
        let mut entries = Vec::new();
        entries
            .try_reserve(selected.clone().count())
            .map_err(|_| JournalError::InsufficientResources)?;
        for row in selected {
            if row.is_claimed() {
                return Err(JournalError::Claimed);
            }
            if entries.iter().any(|entry: &Entry| entry.page == row.page) {
                return Err(JournalError::StaleMappings);
            }
            entries.push(Entry {
                page: row.page,
                original: row.snapshot(),
                complete: Cell::new(false),
            });
        }
        let journal = Self {
            id,
            layout,
            entries,
            phase: Cell::new(Phase::Prepared),
        };
        journal.revalidate(id, attached_pi, mappings)?;
        Ok(journal)
    }

    /// Immutable provenance, never a generic memory journal's resource list.
    pub fn original_capabilities(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries
            .iter()
            .flat_map(|entry| entry.original.capabilities())
    }

    pub fn is_complete(&self) -> bool {
        self.phase.get() == Phase::Complete
    }

    pub fn revalidate(
        &self,
        expected: ThreadRollbackId,
        attached_pi: u64,
        mappings: &[ThreadAliasMapping],
    ) -> Result<(), JournalError> {
        if expected != self.id {
            return Err(JournalError::OwnerChanged);
        }
        let selected = mappings.iter().filter(|row| {
            attached_pi == self.id.identity().pi as u64 && self.layout.overlaps(row.page, 4096)
        });
        let remaining = self.entries.iter().filter(|entry| !entry.complete.get());
        if selected.clone().count() != remaining.clone().count() {
            return Err(JournalError::StaleMappings);
        }
        for entry in remaining {
            let mut rows = selected.clone().filter(|row| row.page == entry.page);
            let row = rows.next().ok_or(JournalError::StaleMappings)?;
            if rows.next().is_some() {
                return Err(JournalError::StaleMappings);
            }
            match self.phase.get() {
                Phase::Prepared => {
                    if row.claim.is_some() {
                        return Err(JournalError::Claimed);
                    }
                }
                _ => {
                    if row.claim != Some(self.id) {
                        return Err(JournalError::OwnerChanged);
                    }
                }
            }
            if matches!(self.phase.get(), Phase::Prepared | Phase::Claimed)
                && row.snapshot() != entry.original
            {
                return Err(JournalError::StaleMappings);
            }
            // Once cleanup starts, only still-retained slots are owners; recycled numbers may
            // legitimately occur elsewhere. Claims, not refreshed snapshots, authorize retry.
            for cap in row.snapshot().capabilities() {
                if mappings
                    .iter()
                    .flat_map(|other| other.snapshot().capabilities())
                    .filter(|&other| other == cap)
                    .count()
                    != 1
                {
                    return Err(JournalError::SharedCapability(cap));
                }
            }
        }
        Ok(())
    }

    /// Validate every row before publishing any claim. Failure changes neither journal nor rows.
    /// The caller validates private memory/mechanism/registry cap conflicts before this boundary.
    pub fn claim(
        &self,
        expected: ThreadRollbackId,
        attached_pi: u64,
        mappings: &mut [ThreadAliasMapping],
    ) -> Result<(), JournalError> {
        self.revalidate(expected, attached_pi, mappings)?;
        if self.phase.get() != Phase::Prepared {
            return Ok(());
        }
        for entry in &self.entries {
            let row = mappings
                .iter_mut()
                .find(|row| row.page == entry.page)
                .expect("validated selected page");
            row.claim = Some(self.id);
        }
        self.phase.set(Phase::Claimed);
        Ok(())
    }

    /// Only invoke after complete external/private journals and access exclusions are retained
    /// and the TCB is quiescent. This driver never recovers/remaps an alias or frees private backing.
    /// Completed rows are acknowledged and removed allocation-free; failed rows retain their claim.
    pub fn retire<I: AliasRetirementIo>(
        &self,
        expected: ThreadRollbackId,
        attached_pi: u64,
        mappings: &mut Vec<ThreadAliasMapping>,
        mut backend: impl FnMut(u64) -> I,
    ) -> Result<(), JournalError> {
        self.revalidate(expected, attached_pi, mappings)?;
        if self.phase.get() == Phase::Prepared {
            return Err(JournalError::NotClaimed);
        }
        if self.is_complete() {
            return Ok(());
        }
        self.phase.set(Phase::Retiring);
        for entry in self.entries.iter().filter(|entry| !entry.complete.get()) {
            let index = mappings
                .iter()
                .position(|row| row.page == entry.page)
                .expect("validated claimed page");
            mappings[index]
                .alias
                .retire(&mut backend(entry.page))
                .map_err(|status| JournalError::Backend {
                    page: entry.page,
                    status,
                })?;
            entry.complete.set(true);
            mappings.swap_remove(index);
        }
        self.phase.set(Phase::Complete);
        Ok(())
    }
}
