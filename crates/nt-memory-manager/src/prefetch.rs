//! Persistent root-only prefetch frames with exact reservations and retry-owned cleanup.
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::retained_alias::{AliasRetirementIo, RetainedAlias};

const RESOURCES: u32 = 0xc000_009a;
const INVALID: u32 = 0xc000_000d;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn allocate_id(counter: &AtomicU64) -> Result<u64, u32> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map_err(|_| RESOURCES)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefetchReservation {
    id: u64,
    index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefetchPage {
    pub frame: u64,
    pub alias: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefetchProcess {
    pub pi: u64,
    pub generation: u64,
}

pub trait PrefetchIo: AliasRetirementIo {
    /// Transfer a fresh cap/slot even on allocation failure. A nonzero returned slot is owned
    /// by the registry and must be deletable, including a known-empty slot after failed retype.
    fn allocate(&mut self) -> (u64, u32);
    /// Failure must leave the cap unmapped.
    fn map(&mut self, cap: u64, alias: u64) -> Result<(), u32>;
    fn fill(&mut self, alias: u64) -> Result<(), u32>;
}

#[derive(PartialEq, Eq)]
enum State {
    Reserved,
    Building,
    Published,
    Retiring,
}

enum Backing {
    Empty,
    Unmapped(u64),
    Mapped(RetainedAlias),
}

struct Entry {
    id: u64,
    process: PrefetchProcess,
    page: u64,
    alias: u64,
    state: State,
    backing: Backing,
}

/// Must live in durable storage until every retained entry has been retired successfully.
/// Backend calls must not reenter this registry while a mutable operation is in progress.
pub struct PrefetchFrames {
    entries: Vec<Option<Entry>>,
}

impl PrefetchFrames {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Select the row once, then reserve both key and actual root VA before acquiring a cap.
    /// The caller's address policy must keep this VA disjoint from other scratch consumers.
    pub fn reserve(
        &mut self,
        process: PrefetchProcess,
        page: u64,
        address: impl FnOnce(usize) -> Option<u64>,
    ) -> Result<PrefetchReservation, u32> {
        if process.generation == 0 || page & 0xfff != 0 || page.checked_add(4096).is_none() {
            return Err(INVALID);
        }
        if self.find(process.pi, page).is_some()
            || self
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.process.pi == process.pi && entry.process != process)
        {
            return Err(RESOURCES);
        }
        let index = self
            .entries
            .iter()
            .position(Option::is_none)
            .unwrap_or(self.entries.len());
        let alias = address(index).ok_or(RESOURCES)?;
        if alias == 0 || alias & 0xfff != 0 || alias.checked_add(4096).is_none() {
            return Err(INVALID);
        }
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.alias == alias)
        {
            return Err(RESOURCES);
        }
        if index == self.entries.len() {
            self.entries.try_reserve(1).map_err(|_| RESOURCES)?;
        }
        let id = allocate_id(&NEXT_ID)?;
        let entry = Some(Entry {
            id,
            process,
            page,
            alias,
            state: State::Reserved,
            backing: Backing::Empty,
        });
        if index == self.entries.len() {
            self.entries.push(entry);
        } else {
            self.entries[index] = entry;
        }
        Ok(PrefetchReservation { id, index })
    }

    fn exact(&mut self, reservation: PrefetchReservation) -> Result<&mut Entry, u32> {
        self.entries
            .get_mut(reservation.index)
            .and_then(Option::as_mut)
            .filter(|entry| entry.id == reservation.id)
            .ok_or(crate::STATUS_INVALID_HANDLE)
    }

    fn find(&self, pi: u64, page: u64) -> Option<PrefetchReservation> {
        self.entries.iter().enumerate().find_map(|(index, entry)| {
            entry
                .as_ref()
                .filter(|entry| entry.process.pi == pi && entry.page == page)
                .map(|entry| PrefetchReservation {
                    id: entry.id,
                    index,
                })
        })
    }

    pub fn contains(&self, pi: u64, page: u64) -> bool {
        self.find(pi, page).is_some()
    }

    /// `Err` means an authoritative unavailable record, not absence or permission to use another
    /// source. No capability or address from a reservation/retirement is ordinarily exposed.
    pub fn lookup(&self, process: PrefetchProcess, page: u64) -> Result<Option<PrefetchPage>, u32> {
        let Some(reservation) = self.find(process.pi, page) else {
            return Ok(None);
        };
        let entry = self.entries[reservation.index].as_ref().unwrap();
        if entry.process == process && entry.state == State::Published {
            if let Backing::Mapped(alias) = &entry.backing {
                if alias.is_live() {
                    return Ok(Some(PrefetchPage {
                        frame: alias.cap(),
                        alias: entry.alias,
                    }));
                }
            }
        }
        Err(RESOURCES)
    }

    /// Acquire, adopt, map and fill using the same retained row. Publication cannot allocate or
    /// select another slot. Construction failure attempts cleanup but never discards its owner.
    pub fn build(
        &mut self,
        reservation: PrefetchReservation,
        io: &mut impl PrefetchIo,
    ) -> Result<(), u32> {
        let entry = self.exact(reservation)?;
        if entry.state != State::Reserved {
            return Err(crate::STATUS_INVALID_HANDLE);
        }
        entry.state = State::Building;
        let (cap, status) = io.allocate();
        if cap != 0 {
            entry.backing = Backing::Unmapped(cap);
        }
        let result = if status != 0 {
            Err(status)
        } else if cap == 0 {
            Err(RESOURCES)
        } else {
            io.map(cap, entry.alias).and_then(|()| {
                entry.backing = Backing::Mapped(RetainedAlias::new(cap).unwrap());
                io.fill(entry.alias)
            })
        };
        match result {
            Ok(()) => {
                entry.state = State::Published;
                Ok(())
            }
            Err(status) => {
                let _ = self.retire(reservation, io);
                Err(status)
            }
        }
    }

    pub fn retire(
        &mut self,
        reservation: PrefetchReservation,
        io: &mut impl AliasRetirementIo,
    ) -> Result<(), u32> {
        let entry = self.exact(reservation)?;
        entry.state = State::Retiring;
        match &mut entry.backing {
            Backing::Empty => {}
            Backing::Unmapped(cap) => io.delete(*cap)?,
            Backing::Mapped(alias) => alias.retire(io)?,
        }
        self.entries[reservation.index] = None;
        Ok(())
    }

    /// Retry only cleanup, never revive or silently replace an unfinished reservation.
    pub fn retry_retirement(
        &mut self,
        process: PrefetchProcess,
        page: u64,
        io: &mut impl AliasRetirementIo,
    ) -> Result<(), u32> {
        let Some(reservation) = self.find(process.pi, page) else {
            return Ok(());
        };
        if self.exact(reservation)?.process != process {
            return Err(crate::STATUS_INVALID_HANDLE);
        }
        match self.exact(reservation)?.state {
            State::Published => Ok(()),
            State::Retiring => self.retire(reservation, io),
            _ => Err(RESOURCES),
        }
    }

    /// Hide every process row before the first backend call, including if that call fails.
    pub fn retire_process(
        &mut self,
        process: PrefetchProcess,
        io: &mut impl AliasRetirementIo,
    ) -> (u64, u64) {
        for entry in self
            .entries
            .iter_mut()
            .flatten()
            .filter(|entry| entry.process == process)
        {
            entry.state = State::Retiring;
        }
        let mut released = 0;
        let mut failed = 0;
        for index in 0..self.entries.len() {
            let Some(entry) = self.entries[index]
                .as_ref()
                .filter(|entry| entry.process == process)
            else {
                continue;
            };
            let reservation = PrefetchReservation {
                id: entry.id,
                index,
            };
            if self.retire(reservation, io).is_ok() {
                released += 1;
            } else {
                failed += 1;
            }
        }
        (released, failed)
    }

    pub fn process_is_empty(&self, pi: u64) -> bool {
        !self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.process.pi == pi)
    }
}

impl Default for PrefetchFrames {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "prefetch_tests.rs"]
mod tests;
