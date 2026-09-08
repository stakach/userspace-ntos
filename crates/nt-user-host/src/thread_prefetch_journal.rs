//! Exact pending-thread identity around the memory manager's opaque prefetch claim journal.
use crate::process_identity::ProcessGeneration;
use crate::thread_resources::ThreadMemoryLayout;
use crate::thread_rollback::ThreadRollbackId;
use nt_memory_manager::prefetch::{
    PrefetchFrames, PrefetchJournal, PrefetchJournalError, PrefetchProcess,
};
use nt_memory_manager::retained_alias::AliasRetirementIo;

#[derive(Debug)]
pub struct ThreadPrefetchJournal {
    id: ThreadRollbackId,
    journal: Ranges,
}

#[derive(Debug)]
enum Ranges {
    WithStack(PrefetchJournal<4>),
    WithoutStack(PrefetchJournal<3>),
}

fn process(id: ThreadRollbackId) -> Option<PrefetchProcess> {
    match id.identity().process_generation {
        ProcessGeneration::Hosted(generation) => Some(PrefetchProcess {
            pi: id.identity().pi as u64,
            generation,
        }),
        ProcessGeneration::Temporary(_) => None,
    }
}

impl ThreadPrefetchJournal {
    pub fn prepare(
        id: ThreadRollbackId,
        layout: ThreadMemoryLayout,
        current: Option<PrefetchProcess>,
        frames: &PrefetchFrames,
    ) -> Result<Self, PrefetchJournalError> {
        if current != process(id) {
            return Err(PrefetchJournalError::OwnerChanged);
        }
        let pi = id.identity().pi as u64;
        let generation = current.map(|p| p.generation);
        let journal = if layout.stack().size == 0 {
            Ranges::WithoutStack(PrefetchJournal::prepare(
                pi,
                generation,
                [layout.ipc(), layout.teb(), layout.trampoline()]
                    .map(|range| (range.base, range.size)),
                frames,
            )?)
        } else {
            Ranges::WithStack(PrefetchJournal::prepare(
                pi,
                generation,
                layout.ranges().map(|range| (range.base, range.size)),
                frames,
            )?)
        };
        Ok(Self { id, journal })
    }

    pub fn original_capabilities(&self) -> impl Iterator<Item = u64> + '_ {
        let (with, without) = match &self.journal {
            Ranges::WithStack(journal) => (Some(journal), None),
            Ranges::WithoutStack(journal) => (None, Some(journal)),
        };
        with.into_iter()
            .flat_map(|journal| journal.original_capabilities())
            .chain(
                without
                    .into_iter()
                    .flat_map(|journal| journal.original_capabilities()),
            )
    }

    pub fn is_complete(&self) -> bool {
        match &self.journal {
            Ranges::WithStack(journal) => journal.is_complete(),
            Ranges::WithoutStack(journal) => journal.is_complete(),
        }
    }

    pub fn revalidate(
        &self,
        id: ThreadRollbackId,
        current: Option<PrefetchProcess>,
        frames: &PrefetchFrames,
    ) -> Result<(), PrefetchJournalError> {
        if id != self.id || current != process(self.id) {
            return Err(PrefetchJournalError::OwnerChanged);
        }
        match &self.journal {
            Ranges::WithStack(journal) => journal.revalidate(frames),
            Ranges::WithoutStack(journal) => journal.revalidate(frames),
        }
    }

    pub fn claim(
        &self,
        id: ThreadRollbackId,
        current: Option<PrefetchProcess>,
        frames: &mut PrefetchFrames,
    ) -> Result<(), PrefetchJournalError> {
        self.revalidate(id, current, frames)?;
        match &self.journal {
            Ranges::WithStack(journal) => journal.claim(frames),
            Ranges::WithoutStack(journal) => journal.claim(frames),
        }
    }

    /// Only after complete disjoint ownership, exclusions and execution quiescence are retained.
    pub fn retire(
        &self,
        id: ThreadRollbackId,
        current: Option<PrefetchProcess>,
        frames: &mut PrefetchFrames,
        io: &mut impl AliasRetirementIo,
    ) -> Result<(), PrefetchJournalError> {
        self.revalidate(id, current, frames)?;
        match &self.journal {
            Ranges::WithStack(journal) => journal.retire(frames, io),
            Ranges::WithoutStack(journal) => journal.retire(frames, io),
        }
    }
}

#[cfg(test)]
#[path = "thread_prefetch_journal_tests.rs"]
mod tests;
