//! Bounded, nonrelocating backing for the allocation catalog's flat record slots.

use alloc::vec::Vec;
use core::ops::{Index, IndexMut};
use super::ProviderAllocationRecord;

const BLOCK_CAPACITY: usize = 256;

pub(super) struct Records {
    blocks: Vec<Vec<ProviderAllocationRecord>>,
    len: usize,
}

impl Records {
    pub(super) const fn new() -> Self {
        Self { blocks: Vec::new(), len: 0 }
    }

    pub(super) fn len(&self) -> usize { self.len }

    pub(super) fn get(&self, slot: usize) -> Option<&ProviderAllocationRecord> {
        if slot >= self.len { return None; }
        self.blocks.get(slot / BLOCK_CAPACITY)?.get(slot % BLOCK_CAPACITY)
    }

    fn get_mut(&mut self, slot: usize) -> Option<&mut ProviderAllocationRecord> {
        if slot >= self.len { return None; }
        self.blocks.get_mut(slot / BLOCK_CAPACITY)?.get_mut(slot % BLOCK_CAPACITY)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &ProviderAllocationRecord> {
        self.blocks.iter().flat_map(|block| block.iter()).take(self.len)
    }

    pub(super) fn try_append(&mut self) -> Result<usize, ()> {
        self.append_with(|| {
            let mut records = Vec::new();
            records.try_reserve_exact(BLOCK_CAPACITY).map_err(|_| ())?;
            records.resize(BLOCK_CAPACITY, ProviderAllocationRecord::EMPTY);
            Ok(records)
        })
    }

    fn append_with(
        &mut self,
        allocate: impl FnOnce() -> Result<Vec<ProviderAllocationRecord>, ()>,
    ) -> Result<usize, ()> {
        let next = self.len.checked_add(1).ok_or(())?;
        if self.len % BLOCK_CAPACITY == 0 {
            self.blocks.try_reserve(1).map_err(|_| ())?;
            let block = allocate()?;
            if block.len() != BLOCK_CAPACITY || block.capacity() > BLOCK_CAPACITY { return Err(()); }
            self.blocks.push(block);
        }
        let slot = self.len;
        self.len = next;
        Ok(slot)
    }

    #[cfg(test)]
    pub(super) fn maximum_block_capacity(&self) -> usize {
        self.blocks.iter().map(|block| block.capacity()).max().unwrap_or(0)
    }
}

impl Index<usize> for Records {
    type Output = ProviderAllocationRecord;
    fn index(&self, slot: usize) -> &Self::Output { self.get(slot).expect("record slot") }
}

impl IndexMut<usize> for Records {
    fn index_mut(&mut self, slot: usize) -> &mut Self::Output {
        self.get_mut(slot).expect("record slot")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_block_allocation_preserves_slots_and_existing_backing() {
        let mut records = Records::new();
        assert_eq!(records.append_with(|| Err(())), Err(()));
        assert_eq!(records.len(), 0);
        assert_eq!(records.maximum_block_capacity(), 0);
        for slot in 0..BLOCK_CAPACITY { assert_eq!(records.try_append(), Ok(slot)); }
        records[0].generation = 91;
        let first = records.get(0).unwrap() as *const ProviderAllocationRecord;
        assert_eq!(records.append_with(|| Err(())), Err(()));
        assert_eq!(records.len(), BLOCK_CAPACITY);
        assert_eq!(records.iter().count(), BLOCK_CAPACITY);
        assert_eq!(records[0].generation, 91);
        assert_eq!(records.get(0).unwrap() as *const ProviderAllocationRecord, first);
        assert_eq!(records.try_append(), Ok(BLOCK_CAPACITY));
        assert_eq!(records.get(0).unwrap() as *const ProviderAllocationRecord, first);
        assert_eq!(records.maximum_block_capacity(), BLOCK_CAPACITY);
    }

    #[test]
    fn append_inside_existing_block_does_not_allocate() {
        let mut records = Records::new();
        records.try_append().unwrap();
        assert_eq!(records.append_with(|| panic!("unexpected block allocation")), Ok(1));
        assert_eq!(records.iter().count(), 2);
        assert!(records.get(2).is_none());
    }
}
