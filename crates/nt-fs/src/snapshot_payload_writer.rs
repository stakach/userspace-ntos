//! Streaming payload buffering, separate from commit-slot publication and barriers.

use super::{SnapshotBlockDevice, SnapshotBlockStoreError, SnapshotPayloadSink};
use alloc::vec::Vec;
use nt_config_store::codec::Crc32c;

pub(super) const WRITE_BATCH_SECTORS: usize = 4;

/// Bounded whole-sector payload staging for snapshot commits.
pub struct PayloadSectorWriter<'a, D: SnapshotBlockDevice> {
    dev: &'a mut D,
    sector: Vec<u8>,
    sector_size: usize,
    slot_base: u64,
    max_payload_len: usize,
    written: usize,
    sector_index: u64,
    sector_offset: usize,
    crc: Crc32c,
    error: Option<SnapshotBlockStoreError>,
}

impl<'a, D: SnapshotBlockDevice> PayloadSectorWriter<'a, D> {
    pub(super) fn new(
        dev: &'a mut D,
        sector: Vec<u8>,
        sector_size: usize,
        slot_base: u64,
        max_payload_len: usize,
    ) -> Self {
        Self {
            dev,
            sector,
            sector_size,
            slot_base,
            max_payload_len,
            written: 0,
            sector_index: 0,
            sector_offset: 0,
            crc: Crc32c::new(),
            error: None,
        }
    }

    fn fail(&mut self, error: SnapshotBlockStoreError) -> SnapshotBlockStoreError {
        *self.error.get_or_insert(error)
    }

    fn flush_staged(&mut self) -> Result<(), SnapshotBlockStoreError> {
        let sectors = self.sector_offset.div_ceil(self.sector_size);
        let next = self
            .sector_index
            .checked_add(sectors as u64)
            .ok_or_else(|| self.fail(SnapshotBlockStoreError::Corrupt))?;
        let lba = self
            .slot_base
            .checked_add(1)
            .and_then(|base| base.checked_add(self.sector_index))
            .ok_or_else(|| self.fail(SnapshotBlockStoreError::Corrupt))?;
        let len = sectors * self.sector_size;
        self.sector[self.sector_offset..len].fill(0);
        if let Err(error) = self.dev.write_sectors(lba, &self.sector[..len]) {
            return Err(self.fail(error));
        }
        self.sector_index = next;
        self.sector_offset = 0;
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<(Vec<u8>, usize, u32), SnapshotBlockStoreError> {
        // An encoder can ignore a sink error. Never replay its uncertain write or publish a header.
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.sector_offset != 0 {
            self.flush_staged()?;
        }
        self.sector.truncate(self.sector_size);
        Ok((self.sector, self.written, self.crc.finish()))
    }
}

impl<D: SnapshotBlockDevice> SnapshotPayloadSink for PayloadSectorWriter<'_, D> {
    fn write_all(&mut self, mut bytes: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let remaining = self
            .max_payload_len
            .checked_sub(self.written)
            .ok_or_else(|| self.fail(SnapshotBlockStoreError::Corrupt))?;
        if bytes.len() > remaining {
            return Err(self.fail(SnapshotBlockStoreError::Corrupt));
        }
        self.crc.update(bytes);
        while !bytes.is_empty() {
            let copy = bytes.len().min(self.sector.len() - self.sector_offset);
            self.sector[self.sector_offset..self.sector_offset + copy]
                .copy_from_slice(&bytes[..copy]);
            self.sector_offset += copy;
            self.written += copy;
            bytes = &bytes[copy..];
            if self.sector_offset == self.sector.len() {
                self.flush_staged()?;
            }
        }
        Ok(())
    }
}
