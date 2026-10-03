//! Retained provider page reads before a section frame can be published.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::data_section::{DataSectionPageRead, DataSectionReadWindow, DATA_PAGE_SIZE, STATUS_IO_DEVICE_ERROR};
use crate::{RoutedSectionLease, SectionIdentity};

const STATUS_PENDING: u32 = 0x0000_0103;
static NEXT_STORE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingSectionPageReadId {
    store: u64,
    slot: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Reserved,
    Submitted,
    Copying(usize),
    Ready,
    Failed(u32),
    AckedReady,
    AckedFailed(u32),
}

struct Read<R, K> {
    generation: u64,
    section: SectionIdentity,
    lease: RoutedSectionLease,
    page_index: u64,
    plan: DataSectionReadWindow,
    owner: R,
    key: Option<K>,
    phase: Phase,
    bytes: Vec<u8>,
}

pub struct PendingSectionPageReads<R, K> {
    store: u64,
    next_generation: u64,
    rows: Vec<Option<Read<R, K>>>,
}

impl<R, K: Copy + Eq> PendingSectionPageReads<R, K> {
    pub const fn new() -> Self {
        Self {
            store: 0,
            next_generation: 0,
            rows: Vec::new(),
        }
    }

    /// Reserve the staging page and continuation before entering provider I/O.
    pub fn reserve(
        &mut self,
        section: SectionIdentity,
        lease: RoutedSectionLease,
        page_index: u64,
        plan: DataSectionPageRead,
        owner: R,
    ) -> Result<PendingSectionPageReadId, R> {
        self.reserve_window(section, lease, page_index, DataSectionReadWindow::from_page(plan), owner)
    }

    pub fn reserve_window(
        &mut self,
        section: SectionIdentity,
        lease: RoutedSectionLease,
        page_index: u64,
        plan: DataSectionReadWindow,
        owner: R,
    ) -> Result<PendingSectionPageReadId, R> {
        if page_index.checked_mul(DATA_PAGE_SIZE as u64) != Some(plan.offset()) {
            return Err(owner);
        }
        let Some(generation) = self.next_generation.checked_add(1) else {
            return Err(owner);
        };
        let slot = self.rows.iter().position(Option::is_none);
        if slot.is_none() && self.rows.try_reserve(1).is_err() {
            return Err(owner);
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(plan.capacity()).is_err() {
            return Err(owner);
        }
        bytes.resize(plan.capacity(), 0);
        if self.store == 0 {
            let Ok(store) =
                NEXT_STORE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
            else {
                return Err(owner);
            };
            self.store = store;
        }
        self.next_generation = generation;
        let row = Read {
            generation,
            section,
            lease,
            page_index,
            plan,
            owner,
            key: None,
            phase: Phase::Reserved,
            bytes,
        };
        let slot = if let Some(slot) = slot {
            self.rows[slot] = Some(row);
            slot
        } else {
            self.rows.push(Some(row));
            self.rows.len() - 1
        };
        Ok(PendingSectionPageReadId {
            store: self.store,
            slot,
            generation,
        })
    }

    fn row(&self, id: PendingSectionPageReadId) -> Option<&Read<R, K>> {
        if id.store != self.store {
            return None;
        }
        self.rows
            .get(id.slot)?
            .as_ref()
            .filter(|row| row.generation == id.generation)
    }

    fn row_mut(&mut self, id: PendingSectionPageReadId) -> Option<&mut Read<R, K>> {
        if id.store != self.store {
            return None;
        }
        self.rows
            .get_mut(id.slot)?
            .as_mut()
            .filter(|row| row.generation == id.generation)
    }

    pub fn identity(
        &self,
        id: PendingSectionPageReadId,
    ) -> Option<(SectionIdentity, RoutedSectionLease, u64)> {
        self.row(id)
            .map(|row| (row.section, row.lease, row.page_index))
    }

    /// Once dispatch may have entered, only its exact completion can advance this row.
    pub fn bind(&mut self, id: PendingSectionPageReadId, key: K) -> bool {
        if self.rows.iter().flatten().any(|row| row.key == Some(key)) {
            return false;
        }
        let Some(row) = self.row_mut(id) else {
            return false;
        };
        if row.phase != Phase::Reserved {
            return false;
        }
        row.key = Some(key);
        row.phase = Phase::Submitted;
        true
    }

    pub fn cancel_reserved(&mut self, id: PendingSectionPageReadId) -> Option<R> {
        if self.row(id)?.phase != Phase::Reserved {
            return None;
        }
        Some(self.rows[id.slot].take()?.owner)
    }

    /// Finish an inline provider read using the page reserved before dispatch.
    pub fn complete_inline(
        &mut self,
        id: PendingSectionPageReadId,
        status: u32,
        information: u64,
        output: &[u8],
    ) -> Option<(R, Result<Vec<u8>, u32>)> {
        if self.row(id)?.phase != Phase::Reserved {
            return None;
        }
        let mut row = self.rows[id.slot].take()?;
        let result = if information > usize::MAX as u64
            || output.len() < row.plan.length()
        {
            Err(STATUS_IO_DEVICE_ERROR)
        } else {
            row.bytes[..row.plan.length()].copy_from_slice(&output[..row.plan.length()]);
            row.plan.complete(status, information as usize, &mut row.bytes).map(|()| row.bytes)
        };
        Some((row.owner, result))
    }

    /// A pending indication is not terminal; a short success is a terminal failure.
    pub fn terminal(
        &mut self,
        id: PendingSectionPageReadId,
        key: K,
        status: u32,
        information: u64,
    ) -> bool {
        let Some(row) = self.row_mut(id) else {
            return false;
        };
        if row.key != Some(key) || row.phase != Phase::Submitted || status == STATUS_PENDING {
            return false;
        }
        row.phase = if status != 0 {
            Phase::Failed(status)
        } else if information != row.plan.length() as u64 {
            Phase::Failed(STATUS_IO_DEVICE_ERROR)
        } else {
            Phase::Copying(0)
        };
        true
    }

    /// Copy only the next accepted fragment from the exact canonical provider operation.
    pub fn append(
        &mut self,
        id: PendingSectionPageReadId,
        key: K,
        offset: usize,
        data: &[u8],
    ) -> bool {
        let Some(row) = self.row_mut(id) else {
            return false;
        };
        let Phase::Copying(copied) = row.phase else {
            return false;
        };
        if row.key != Some(key)
            || data.is_empty()
            || offset != copied
            || data.len() > row.plan.length() - copied
        {
            return false;
        }
        row.bytes[copied..copied + data.len()].copy_from_slice(data);
        let copied = copied + data.len();
        if copied == row.plan.length() {
            row.plan
                .complete(0, copied, &mut row.bytes)
                .expect("exact staged page");
            row.phase = Phase::Ready;
        } else {
            row.phase = Phase::Copying(copied);
        }
        true
    }

    /// A terminal completion with unreadable output cannot publish a page, but still needs its
    /// exact backend acknowledgement before the owner may be released.
    pub fn fail_copy(&mut self, id: PendingSectionPageReadId, key: K, status: u32) -> bool {
        let Some(row) = self.row_mut(id) else {
            return false;
        };
        if row.key != Some(key) || !matches!(row.phase, Phase::Copying(_)) || status == 0 {
            return false;
        }
        row.phase = Phase::Failed(status);
        true
    }

    pub fn ready_page(&self, id: PendingSectionPageReadId, key: K) -> Option<&[u8]> {
        let row = self.row(id)?;
        (row.key == Some(key) && matches!(row.phase, Phase::Ready | Phase::AckedReady))
            .then_some(row.bytes.as_slice())
    }

    pub fn failure(&self, id: PendingSectionPageReadId, key: K) -> Option<u32> {
        let row = self.row(id)?;
        if row.key != Some(key) {
            return None;
        }
        match row.phase {
            Phase::Failed(status) | Phase::AckedFailed(status) => Some(status),
            _ => None,
        }
    }

    /// Call only after the native owner has acknowledged the completed provider IRP.
    pub fn acknowledge_backend(&mut self, id: PendingSectionPageReadId, key: K) -> bool {
        let Some(row) = self.row_mut(id) else {
            return false;
        };
        if row.key != Some(key) {
            return false;
        }
        row.phase = match row.phase {
            Phase::Ready => Phase::AckedReady,
            Phase::Failed(status) => Phase::AckedFailed(status),
            _ => return false,
        };
        true
    }

    /// Return the non-Copy continuation only after backend output no longer needs its owner.
    pub fn take_acknowledged(
        &mut self,
        id: PendingSectionPageReadId,
        key: K,
    ) -> Option<(R, Result<Vec<u8>, u32>)> {
        let row = self.row(id)?;
        if row.key != Some(key) || !matches!(row.phase, Phase::AckedReady | Phase::AckedFailed(_)) {
            return None;
        }
        let row = self.rows[id.slot].take()?;
        let result = match row.phase {
            Phase::AckedReady => Ok(row.bytes),
            Phase::AckedFailed(status) => Err(status),
            _ => unreachable!(),
        };
        Some((row.owner, result))
    }
}

impl<R, K: Copy + Eq> Default for PendingSectionPageReads<R, K> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "pending_section_pagein_tests.rs"]
mod tests;
