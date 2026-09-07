//! Disjoint cleanup claims over the prefetch table's existing release owners.
use super::*;
use crate::retained_alias::RetainedAliasSnapshot;
use core::cell::Cell;

static NEXT_CLAIM: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefetchJournalError {
    InvalidRange,
    OwnerChanged,
    StaleCoverage,
    Claimed,
    SharedCapability(u64),
    InsufficientResources,
    NotClaimed,
    Backend { page: u64, status: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BackingSnapshot {
    Empty,
    Unmapped(u64),
    AllocatedEmpty(u64),
    Recycle(u64),
    Mapped(RetainedAliasSnapshot),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Snapshot {
    reservation: PrefetchReservation,
    page: u64,
    alias: u64,
    state: State,
    backing: BackingSnapshot,
    cap: Option<u64>,
}

fn snapshot(index: usize, entry: &Entry) -> Snapshot {
    Snapshot {
        reservation: PrefetchReservation {
            id: entry.id,
            index,
        },
        page: entry.page,
        alias: entry.alias,
        state: entry.state,
        backing: match &entry.backing {
            Backing::Empty => BackingSnapshot::Empty,
            Backing::Unmapped(cap) => BackingSnapshot::Unmapped(*cap),
            Backing::AllocatedEmpty(cap) => BackingSnapshot::AllocatedEmpty(*cap),
            Backing::Recycle(cap) => BackingSnapshot::Recycle(*cap),
            Backing::Mapped(alias) => BackingSnapshot::Mapped(alias.snapshot()),
        },
        cap: entry.backing.cap(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Prepared,
    Claimed,
    Retiring,
    Complete,
}

#[derive(Debug)]
struct Held {
    original: Snapshot,
    complete: Cell<bool>,
}

/// A non-cloneable claim journal, not a frame owner. The caller retains its own identity and
/// excludes new admission to these ranges until final commit. None generation asserts absence
/// of all prefetch rows for the PI; it never substitutes another process generation.
#[derive(Debug)]
pub struct PrefetchJournal<const RANGES: usize> {
    claim: u64,
    pi: u64,
    generation: Option<u64>,
    ranges: [(u64, u64); RANGES],
    entries: Vec<Held>,
    phase: Cell<Phase>,
}

impl<const RANGES: usize> PrefetchJournal<RANGES> {
    pub fn prepare(
        pi: u64,
        generation: Option<u64>,
        ranges: [(u64, u64); RANGES],
        frames: &PrefetchFrames,
    ) -> Result<Self, PrefetchJournalError> {
        if generation == Some(0) {
            return Err(PrefetchJournalError::OwnerChanged);
        }
        if ranges.iter().any(|&(base, size)| {
            base & 4095 != 0 || size == 0 || size & 4095 != 0 || base.checked_add(size).is_none()
        }) {
            return Err(PrefetchJournalError::InvalidRange);
        }
        let mut journal = Self {
            claim: allocate_id(&NEXT_CLAIM)
                .map_err(|_| PrefetchJournalError::InsufficientResources)?,
            pi,
            generation,
            ranges,
            entries: Vec::new(),
            phase: Cell::new(Phase::Prepared),
        };
        journal.validate_generation(frames)?;
        let count = frames
            .entries
            .iter()
            .flatten()
            .filter(|entry| journal.selected(entry))
            .count();
        journal
            .entries
            .try_reserve(count)
            .map_err(|_| PrefetchJournalError::InsufficientResources)?;
        for (index, entry) in frames
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| entry.as_ref().map(|entry| (index, entry)))
        {
            if !journal.selected(entry) {
                continue;
            }
            if entry.claim.is_some() {
                return Err(PrefetchJournalError::Claimed);
            }
            journal.entries.push(Held {
                original: snapshot(index, entry),
                complete: Cell::new(false),
            });
        }
        journal.revalidate(frames)?;
        Ok(journal)
    }

    fn selected(&self, entry: &Entry) -> bool {
        entry.process.pi == self.pi
            && self
                .ranges
                .iter()
                .any(|&(base, size)| base < entry.page + 4096 && entry.page < base + size)
    }

    fn validate_generation(&self, frames: &PrefetchFrames) -> Result<(), PrefetchJournalError> {
        if frames.entries.iter().flatten().any(|entry| {
            entry.process.pi == self.pi && Some(entry.process.generation) != self.generation
        }) {
            return Err(PrefetchJournalError::OwnerChanged);
        }
        Ok(())
    }

    pub fn original_capabilities(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries.iter().filter_map(|entry| entry.original.cap)
    }

    pub fn is_complete(&self) -> bool {
        self.phase.get() == Phase::Complete
    }

    pub fn revalidate(&self, frames: &PrefetchFrames) -> Result<(), PrefetchJournalError> {
        self.validate_generation(frames)?;
        let remaining = self.entries.iter().filter(|held| !held.complete.get());
        if frames
            .entries
            .iter()
            .flatten()
            .filter(|entry| self.selected(entry))
            .count()
            != remaining.clone().count()
        {
            return Err(PrefetchJournalError::StaleCoverage);
        }
        for held in remaining {
            let old = held.original;
            let entry = frames
                .entries
                .get(old.reservation.index)
                .and_then(Option::as_ref)
                .filter(|entry| {
                    entry.id == old.reservation.id
                        && entry.page == old.page
                        && entry.alias == old.alias
                })
                .ok_or(PrefetchJournalError::StaleCoverage)?;
            if self.phase.get() == Phase::Prepared {
                if entry.claim.is_some() {
                    return Err(PrefetchJournalError::Claimed);
                }
            } else if entry.claim != Some(self.claim) {
                return Err(PrefetchJournalError::OwnerChanged);
            }
            if matches!(self.phase.get(), Phase::Prepared | Phase::Claimed)
                && snapshot(old.reservation.index, entry) != old
            {
                return Err(PrefetchJournalError::StaleCoverage);
            }
            if let Some(cap) = entry.backing.cap() {
                if frames.capabilities().filter(|&other| other == cap).count() != 1 {
                    return Err(PrefetchJournalError::SharedCapability(cap));
                }
            }
        }
        Ok(())
    }

    /// Allocation-free after full coverage and external ownership conflict validation.
    pub fn claim(&self, frames: &mut PrefetchFrames) -> Result<(), PrefetchJournalError> {
        self.revalidate(frames)?;
        if self.phase.get() != Phase::Prepared {
            return Ok(());
        }
        for held in &self.entries {
            frames
                .exact(held.original.reservation)
                .expect("validated prefetch owner")
                .claim = Some(self.claim);
        }
        self.phase.set(Phase::Claimed);
        Ok(())
    }

    /// Caller must first retain all disjoint journals, exclude access and quiesce execution.
    /// The table remains the only physical release authority; retries follow its current phase.
    pub fn retire(
        &self,
        frames: &mut PrefetchFrames,
        io: &mut impl AliasRetirementIo,
    ) -> Result<(), PrefetchJournalError> {
        self.revalidate(frames)?;
        if self.phase.get() == Phase::Prepared {
            return Err(PrefetchJournalError::NotClaimed);
        }
        if self.is_complete() {
            return Ok(());
        }
        self.phase.set(Phase::Retiring);
        for held in self.entries.iter().filter(|held| !held.complete.get()) {
            frames
                .retire_owned(held.original.reservation, Some(self.claim), io)
                .map_err(|status| PrefetchJournalError::Backend {
                    page: held.original.page,
                    status,
                })?;
            held.complete.set(true);
        }
        self.phase.set(Phase::Complete);
        Ok(())
    }
}
