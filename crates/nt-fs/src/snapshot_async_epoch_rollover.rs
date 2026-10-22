//! Move-only native rollover after two ACKed folded snapshots.

use alloc::vec::Vec;
use super::*;

const ERASE_BATCH: u64 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    ResetWrite(u32), ResetFlush(u32), EraseTail(u64), EraseFlush,
    EraseFirst, EraseFirstFlush, ReadyWrite(u32), ReadyFlush(u32), Done,
}

/// Holds a validated folded pair while paired RESETTING headers, bounded WAL erasure,
/// and paired READY headers cross exact native provider terminal and ACK barriers.
#[must_use = "retain the exact reserve lease and cursor until terminal ACK or recovery"]
pub struct AsyncWalEpochRollover {
    pair: VerifiedPairedWalSnapshot,
    wal_start: u64,
    wal_sectors: u64,
    next_incarnation: u64,
    sector_size: usize,
    step: Step,
    pending: Option<AsyncSnapshotRequest>,
    sequence: u64,
    buffer: Vec<u8>,
    failed: bool,
}

impl AsyncWalEpochRollover {
    pub fn admit(
        store: SnapshotBlockStore,
        pair: VerifiedPairedWalSnapshot,
        wal_start: u64,
        wal_sectors: u64,
        next_incarnation: u64,
        sector_size: usize,
        device_sectors: u64,
    ) -> Result<Self, (SnapshotBlockStoreError, VerifiedPairedWalSnapshot)> {
        let old = pair.anchor();
        let end = wal_start.checked_add(wal_sectors);
        let store_end = store.start_lba.checked_add(store.sector_count);
        if pair.store != store || old.incarnation == 0 || old.serial == 0
            || next_incarnation == 0 || next_incarnation == old.incarnation
            || wal_sectors == 0 || sector_size < WAL_RESET_HEADER_LEN
            || store.sector_count < 4 || store.sector_count % 2 != 0
            || end.is_none_or(|v| v > device_sectors)
            || store_end.is_none_or(|v| v > device_sectors)
            || wal_start < store_end.unwrap_or(u64::MAX)
            || pair.plans[0].generation == pair.plans[1].generation
            || pair.plans.iter().any(|plan| plan.resetting || plan.wal.is_none_or(|wal| {
                wal.anchor() != old || wal.base_serial != old.serial
            }))
        {
            return Err((SnapshotBlockStoreError::Corrupt, pair));
        }
        let capacity = match sector_size.checked_mul(ERASE_BATCH as usize) {
            Some(capacity) => capacity,
            None => return Err((SnapshotBlockStoreError::InvalidGeometry, pair)),
        };
        let mut buffer = Vec::new();
        if buffer.try_reserve_exact(capacity).is_err() {
            return Err((SnapshotBlockStoreError::OutOfMemory, pair));
        }
        buffer.resize(capacity, 0);
        Ok(Self { pair, wal_start, wal_sectors, next_incarnation, sector_size,
            step: Step::ResetWrite(0), pending: None, sequence: 1, buffer, failed: false })
    }

    fn header(&mut self, slot: u32, resetting: bool) {
        let plan = self.pair.plans[slot as usize];
        self.buffer[..self.sector_size].fill(0);
        encode_header(&mut self.buffer[..self.sector_size], SlotHeader {
            slot, generation: plan.generation, payload_len: plan.payload_len as u64,
            payload_crc: plan.payload_crc, payload_sectors: plan.payload_sectors,
            wal: Some(WalSnapshotManifest { incarnation: self.next_incarnation,
                base_serial: 0, high_water_serial: 0, high_water_end_lba: 0 }),
            resetting,
        });
    }

    pub fn enter_next(&mut self) -> Result<Option<AsyncSnapshotRequest>, AsyncSnapshotCommitError> {
        if self.failed { return Err(AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Io)); }
        if self.pending.is_some() { return Err(AsyncSnapshotCommitError::Outstanding); }
        if self.step == Step::Done { return Ok(None); }
        let (kind, lba, bytes) = match self.step {
            Step::ResetWrite(slot) | Step::ReadyWrite(slot) => {
                self.header(slot, matches!(self.step, Step::ResetWrite(_)));
                (AsyncSnapshotIoKind::Write,
                    self.pair.store.slot_lba(self.pair.store.sector_count / 2, slot)
                        .map_err(AsyncSnapshotCommitError::Store)?, self.sector_size)
            }
            Step::EraseTail(remaining) => {
                self.buffer.fill(0);
                let count = (remaining - 1).min(ERASE_BATCH);
                let offset = remaining - count;
                (AsyncSnapshotIoKind::Write, self.wal_start + offset,
                    count as usize * self.sector_size)
            }
            Step::EraseFirst => {
                self.buffer.fill(0);
                (AsyncSnapshotIoKind::Write, self.wal_start, self.sector_size)
            }
            _ => (AsyncSnapshotIoKind::Flush, 0, 0),
        };
        let request = AsyncSnapshotRequest { sequence: self.sequence, kind, lba, bytes };
        self.sequence = self.sequence.checked_add(1).ok_or(AsyncSnapshotCommitError::Exhausted)?;
        self.pending = Some(request);
        Ok(Some(request))
    }

    pub fn pending(&self) -> Option<AsyncSnapshotRequest> { self.pending }
    pub fn is_done(&self) -> bool { !self.failed && self.pending.is_none() && self.step == Step::Done }
    pub fn write_bytes(&self, request: AsyncSnapshotRequest) -> Option<&[u8]> {
        (self.pending == Some(request) && request.kind == AsyncSnapshotIoKind::Write)
            .then(|| &self.buffer[..request.bytes])
    }
    pub fn release_unentered(&mut self, request: AsyncSnapshotRequest)
        -> Result<(), AsyncSnapshotCommitError>
    {
        if self.failed { return Err(AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Io)); }
        if self.pending != Some(request) { return Err(AsyncSnapshotCommitError::WrongTicket); }
        self.pending = None;
        Ok(())
    }

    /// # Safety
    /// `settled = true` requires exact provider terminal and ACK for this request under
    /// the original exclusive reserve lease; a local reply is insufficient.
    pub unsafe fn complete(&mut self, request: AsyncSnapshotRequest, settled: bool)
        -> Result<(), AsyncSnapshotCommitError>
    {
        if self.failed { return Err(AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Io)); }
        if self.pending != Some(request) { return Err(AsyncSnapshotCommitError::WrongTicket); }
        if !settled {
            self.failed = true;
            return Err(AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Io));
        }
        self.pending = None;
        self.step = match self.step {
            Step::ResetWrite(slot) => Step::ResetFlush(slot),
            Step::ResetFlush(0) => Step::ResetWrite(1),
            Step::ResetFlush(1) => if self.wal_sectors == 1 {
                Step::EraseFlush
            } else {
                Step::EraseTail(self.wal_sectors)
            },
            Step::EraseTail(remaining) => {
                let offset = remaining - (remaining - 1).min(ERASE_BATCH);
                if offset > 1 { Step::EraseTail(offset) } else { Step::EraseFlush }
            }
            Step::EraseFlush => Step::EraseFirst,
            Step::EraseFirst => Step::EraseFirstFlush,
            Step::EraseFirstFlush => Step::ReadyWrite(0),
            Step::ReadyWrite(slot) => Step::ReadyFlush(slot),
            Step::ReadyFlush(0) => Step::ReadyWrite(1),
            Step::ReadyFlush(1) => Step::Done,
            _ => return Err(AsyncSnapshotCommitError::WrongTicket),
        };
        Ok(())
    }

    /// Return the new empty epoch only after all native effects were ACKed.
    pub fn finish(self) -> Result<(crate::RegistryWalContinuation, VerifiedPairedWalSnapshot), Self> {
        if !self.is_done() { return Err(self); }
        let mut pair = self.pair;
        let empty = WalSnapshotManifest { incarnation: self.next_incarnation,
            base_serial: 0, high_water_serial: 0, high_water_end_lba: 0 };
        for plan in &mut pair.plans {
            plan.wal = Some(empty);
            plan.resetting = false;
        }
        pair.manifest = empty;
        Ok((crate::RegistryWalContinuation::empty(self.next_incarnation), pair))
    }
}
