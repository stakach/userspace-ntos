//! Dense frame-owner storage without reallocating every retained record on growth.
use super::ClientFrameRecord;
use alloc::vec::Vec;
use core::ops::{Index, IndexMut};

pub(super) const RECORDS_PER_CHUNK: usize = 256;

pub(super) struct RecordStorage {
    chunks: Vec<Vec<ClientFrameRecord>>,
    len: usize,
}

impl RecordStorage {
    pub(super) const fn new() -> Self {
        Self {
            chunks: Vec::new(),
            len: 0,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn capacity(&self) -> usize {
        self.chunks.len() * RECORDS_PER_CHUNK
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &ClientFrameRecord> {
        self.chunks.iter().flat_map(|chunk| chunk.iter())
    }

    pub(super) fn try_reserve(&mut self, additional: usize) -> Result<(), ()> {
        self.try_reserve_with(additional, || {
            let mut chunk = Vec::new();
            chunk.try_reserve_exact(RECORDS_PER_CHUNK).map_err(|_| ())?;
            Ok(chunk)
        })
    }

    // Previously allocated empty chunks may remain after refusal; semantic records never change.
    pub(super) fn try_reserve_with(
        &mut self,
        additional: usize,
        mut allocate_chunk: impl FnMut() -> Result<Vec<ClientFrameRecord>, ()>,
    ) -> Result<(), ()> {
        let needed = self.len.checked_add(additional).ok_or(())?;
        if needed > isize::MAX as usize / core::mem::size_of::<ClientFrameRecord>() {
            return Err(());
        }
        let chunks = needed.checked_add(RECORDS_PER_CHUNK - 1).ok_or(())? / RECORDS_PER_CHUNK;
        if chunks <= self.chunks.len() {
            return Ok(());
        }
        self.chunks
            .try_reserve_exact(chunks - self.chunks.len())
            .map_err(|_| ())?;
        while self.chunks.len() < chunks {
            let chunk = allocate_chunk()?;
            if !chunk.is_empty() || chunk.capacity() != RECORDS_PER_CHUNK {
                return Err(());
            }
            self.chunks.push(chunk);
        }
        Ok(())
    }

    pub(super) fn push(&mut self, record: ClientFrameRecord) {
        assert!(
            self.len < self.capacity(),
            "frame storage must be reserved before publication"
        );
        self.chunks[self.len / RECORDS_PER_CHUNK].push(record);
        self.len += 1;
    }

    pub(super) fn swap_remove(&mut self, index: usize) -> ClientFrameRecord {
        assert!(index < self.len);
        let removed = self[index];
        let last = self.chunks[(self.len - 1) / RECORDS_PER_CHUNK]
            .pop()
            .unwrap();
        self.len -= 1;
        if index < self.len {
            self[index] = last;
        }
        removed
    }

    #[cfg(test)]
    pub(super) fn largest_backing_bytes(&self) -> usize {
        self.chunks
            .iter()
            .map(|chunk| chunk.capacity() * core::mem::size_of::<ClientFrameRecord>())
            .max()
            .unwrap_or(0)
    }
}

impl Index<usize> for RecordStorage {
    type Output = ClientFrameRecord;
    fn index(&self, index: usize) -> &Self::Output {
        assert!(index < self.len);
        &self.chunks[index / RECORDS_PER_CHUNK][index % RECORDS_PER_CHUNK]
    }
}

impl IndexMut<usize> for RecordStorage {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        assert!(index < self.len);
        &mut self.chunks[index / RECORDS_PER_CHUNK][index % RECORDS_PER_CHUNK]
    }
}
