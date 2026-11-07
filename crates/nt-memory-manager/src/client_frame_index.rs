//! Fallible, chunked lookup for dense client-frame rows.
//!
//! Slots hold row indices, never authority. Exact record snapshots remain the authority for
//! reclamation and transfer. Tombstones make removal allocation-free, including after a terminal
//! backend effect; insertion rebuilds the table before publishing another row when needed.
use super::storage::RecordStorage;
use alloc::vec::Vec;

const SLOTS_PER_CHUNK: usize = 256;
const EMPTY: usize = usize::MAX;
const DELETED: usize = usize::MAX - 1;

pub(super) struct FrameKeyIndex {
    chunks: Vec<Vec<usize>>,
    slots: usize,
    used: usize,
}

impl FrameKeyIndex {
    pub(super) const fn new() -> Self {
        Self {
            chunks: Vec::new(),
            slots: 0,
            used: 0,
        }
    }

    fn slot(&self, position: usize) -> usize {
        self.chunks[position / SLOTS_PER_CHUNK][position % SLOTS_PER_CHUNK]
    }

    fn slot_mut(&mut self, position: usize) -> &mut usize {
        &mut self.chunks[position / SLOTS_PER_CHUNK][position % SLOTS_PER_CHUNK]
    }

    fn hash(pi: u64, page: u64) -> usize {
        // Mix both identity words; page addresses usually have many zero low bits.
        let mut key = pi ^ page.rotate_left(29);
        key ^= key >> 30;
        key = key.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        key ^= key >> 27;
        key = key.wrapping_mul(0x94d0_49bb_1331_11eb);
        (key ^ (key >> 31)) as usize
    }

    /// Return the slot and row for an exact key, plus probes for regression measurement.
    pub(super) fn find(
        &self,
        records: &RecordStorage,
        pi: u64,
        page: u64,
    ) -> (Option<(usize, usize)>, usize) {
        if self.slots == 0 {
            return (None, 0);
        }
        let mut position = Self::hash(pi, page) & (self.slots - 1);
        let mut probes = 0;
        loop {
            probes += 1;
            let index = self.slot(position);
            if index == EMPTY {
                return (None, probes);
            }
            if index != DELETED {
                let record = &records[index];
                if record.pi == pi && record.page == page {
                    return (Some((position, index)), probes);
                }
            }
            position = (position + 1) & (self.slots - 1);
        }
    }

    fn place(&mut self, pi: u64, page: u64, index: usize) {
        let mut position = Self::hash(pi, page) & (self.slots - 1);
        let mut first_deleted = None;
        loop {
            match self.slot(position) {
                EMPTY => {
                    let chosen = first_deleted.unwrap_or(position);
                    if first_deleted.is_none() {
                        self.used += 1;
                    }
                    *self.slot_mut(chosen) = index;
                    return;
                }
                DELETED => {
                    if first_deleted.is_none() {
                        first_deleted = Some(position);
                    }
                }
                _ => {}
            }
            position = (position + 1) & (self.slots - 1);
        }
    }

    fn allocate(slots: usize) -> Result<Self, ()> {
        let chunk_count = slots / SLOTS_PER_CHUNK;
        let mut chunks = Vec::new();
        chunks.try_reserve_exact(chunk_count).map_err(|_| ())?;
        for _ in 0..chunk_count {
            let mut chunk = Vec::new();
            chunk.try_reserve_exact(SLOTS_PER_CHUNK).map_err(|_| ())?;
            chunk.resize(SLOTS_PER_CHUNK, EMPTY);
            chunks.push(chunk);
        }
        Ok(Self {
            chunks,
            slots,
            used: 0,
        })
    }

    /// Prepare a table for at least `needed` live rows. A failed allocation leaves this table
    /// and every published row untouched. Rehash may change private slots but never row identity.
    pub(super) fn try_reserve(&mut self, records: &RecordStorage, needed: usize) -> Result<(), ()> {
        let doubled = needed.checked_mul(2).ok_or(())?;
        let target = doubled
            .max(SLOTS_PER_CHUNK)
            .checked_next_power_of_two()
            .ok_or(())?;
        if self.slots >= target && self.used < self.slots / 2 {
            return Ok(());
        }
        let mut replacement = Self::allocate(target.max(self.slots))?;
        for (index, record) in records.iter().enumerate() {
            replacement.place(record.pi, record.page, index);
        }
        *self = replacement;
        Ok(())
    }

    /// Precondition: `try_reserve` succeeded for one additional row.
    pub(super) fn insert(&mut self, pi: u64, page: u64, index: usize) {
        self.place(pi, page, index);
    }

    /// Remove a key and repair the dense row moved into its position. No allocation is allowed.
    pub(super) fn swap_remove(
        &mut self,
        records: &mut RecordStorage,
        index: usize,
    ) -> super::ClientFrameRecord {
        let removed = records[index];
        let last_index = records.len() - 1;
        let removed_slot = self
            .find(records, removed.pi, removed.page)
            .0
            .expect("published frame has index slot")
            .0;
        let moved_slot = if index != last_index {
            let moved = records[last_index];
            Some(
                self.find(records, moved.pi, moved.page)
                    .0
                    .expect("moved frame has index slot")
                    .0,
            )
        } else {
            None
        };
        *self.slot_mut(removed_slot) = DELETED;
        let removed = records.swap_remove(index);
        if let Some(position) = moved_slot {
            *self.slot_mut(position) = index;
        }
        removed
    }
}
