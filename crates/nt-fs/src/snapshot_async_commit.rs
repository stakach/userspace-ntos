//! One move-only I/O sequence for an owned v2 snapshot payload.
//!
//! The synchronous block runner and an eventual native SRB continuation consume the same
//! requests. Each read, write, and cache barrier is entered once; an uncertain completion
//! retains its exact ticket and never causes a second physical request.

use super::*;

const BATCH_SECTORS: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsyncSnapshotIoKind {
    Read,
    Write,
    Flush,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsyncSnapshotRequest {
    pub sequence: u64,
    pub kind: AsyncSnapshotIoKind,
    pub lba: u64,
    pub bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsyncSnapshotCommitError {
    Outstanding,
    WrongTicket,
    WrongKind,
    Incomplete,
    Exhausted,
    Store(SnapshotBlockStoreError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Preflush,
    Header(u32),
    PayloadScan {
        slot: u32,
        sector: u32,
        remaining: usize,
    },
    PayloadWrite(u32),
    PayloadFlush,
    HeaderWrite,
    FinalFlush,
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanResult {
    Unscanned,
    Empty,
    Corrupt,
    Valid(SlotReadPlan),
}

/// This owner is intentionally neither `Clone` nor `Copy`. The caller retains it, the exact
/// reserve lease, and any pending native SRB across completion turns.
pub struct AsyncSnapshotCommit<P: AsRef<[u8]>> {
    store: SnapshotBlockStore,
    payload: P,
    manifest: WalSnapshotManifest,
    sector_size: usize,
    slot_sectors: u64,
    phase: Phase,
    pending: Option<AsyncSnapshotRequest>,
    sequence: u64,
    scan: [ScanResult; 2],
    header_plans: [Option<SlotReadPlan>; 2],
    scan_crc: Crc32c,
    target_slot: u32,
    generation: u64,
    write_buffer: Vec<u8>,
    failure: Option<SnapshotBlockStoreError>,
    uncertain: bool,
}

impl<P: AsRef<[u8]>> AsyncSnapshotCommit<P> {
    pub fn new(
        store: SnapshotBlockStore,
        payload: P,
        manifest: WalSnapshotManifest,
        sector_size: usize,
        device_sectors: u64,
    ) -> Result<Self, SnapshotBlockStoreError> {
        if !manifest.valid() {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        if sector_size < WAL_HEADER_LEN
            || store.sector_count < 4
            || store.sector_count % 2 != 0
            || store
                .start_lba
                .checked_add(store.sector_count)
                .is_none_or(|end| end > device_sectors)
        {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        let slot_sectors = store.sector_count / 2;
        let payload_sectors = payload.as_ref().len().div_ceil(sector_size);
        if payload_sectors as u64 > slot_sectors - 1 {
            return Err(SnapshotBlockStoreError::OutOfSpace);
        }
        u32::try_from(payload_sectors).map_err(|_| SnapshotBlockStoreError::OutOfSpace)?;
        let mut write_buffer = Vec::new();
        write_buffer
            .try_reserve_exact(
                sector_size
                    .checked_mul(BATCH_SECTORS as usize)
                    .ok_or(SnapshotBlockStoreError::InvalidGeometry)?,
            )
            .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
        Ok(Self {
            store,
            payload,
            manifest,
            sector_size,
            slot_sectors,
            phase: Phase::Preflush,
            pending: None,
            sequence: 1,
            scan: [ScanResult::Unscanned; 2],
            header_plans: [None; 2],
            scan_crc: Crc32c::new(),
            target_slot: 0,
            generation: 0,
            write_buffer,
            failure: None,
            uncertain: false,
        })
    }

    pub fn pending(&self) -> Option<AsyncSnapshotRequest> {
        self.pending
    }

    pub fn is_done(&self) -> bool {
        self.phase == Phase::Done && self.pending.is_none()
    }

    fn slot_base(&self, slot: u32) -> u64 {
        self.store.start_lba + self.slot_sectors * u64::from(slot)
    }

    fn next_header(&mut self, slot: u32) -> Result<(), AsyncSnapshotCommitError> {
        self.pending = None;
        if slot < 2 {
            self.phase = Phase::Header(slot);
        } else {
            if let Err(error) = self.select_target() {
                if let AsyncSnapshotCommitError::Store(store_error) = error {
                    self.failure = Some(store_error);
                }
                return Err(error);
            }
        }
        Ok(())
    }

    fn select_target(&mut self) -> Result<(), AsyncSnapshotCommitError> {
        let latest = self
            .scan
            .iter()
            .filter_map(|entry| match entry {
                ScanResult::Valid(plan) => Some(*plan),
                _ => None,
            })
            .max_by_key(|plan| plan.generation);
        if latest.is_none() && self.scan.iter().any(|entry| *entry == ScanResult::Corrupt) {
            return Err(AsyncSnapshotCommitError::Store(
                SnapshotBlockStoreError::Corrupt,
            ));
        }
        let (target, generation) = match latest {
            Some(plan) if plan.resetting => {
                return Err(AsyncSnapshotCommitError::Store(
                    SnapshotBlockStoreError::Corrupt,
                ));
            }
            Some(plan) => (
                1 - plan.slot,
                plan.generation
                    .checked_add(1)
                    .ok_or(AsyncSnapshotCommitError::Store(
                        SnapshotBlockStoreError::OutOfSpace,
                    ))?,
            ),
            None => (0, 1),
        };
        for slot in 0..2 {
            match self.scan[slot] {
                ScanResult::Valid(plan) => {
                    if plan.resetting {
                        return Err(AsyncSnapshotCommitError::Store(
                            SnapshotBlockStoreError::Corrupt,
                        ));
                    }
                    if let Some(previous) = plan.wal {
                        if self.manifest.anchor() != previous.anchor()
                            || self.manifest.base_serial < previous.base_serial
                        {
                            return Err(AsyncSnapshotCommitError::Store(
                                SnapshotBlockStoreError::Corrupt,
                            ));
                        }
                    }
                }
                ScanResult::Corrupt if slot as u32 == target => {
                    let selected = latest.ok_or(AsyncSnapshotCommitError::Store(
                        SnapshotBlockStoreError::Corrupt,
                    ))?;
                    let selected_wal = selected.wal.ok_or(AsyncSnapshotCommitError::Store(
                        SnapshotBlockStoreError::Corrupt,
                    ))?;
                    let companion = self.header_plans[slot].and_then(|plan| plan.wal).ok_or(
                        AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Corrupt),
                    )?;
                    same_anchor_wal_companion(
                        selected.generation,
                        selected_wal,
                        self.header_plans[slot].unwrap().generation,
                        companion,
                    )
                    .map_err(AsyncSnapshotCommitError::Store)?;
                    if self.manifest.anchor() != selected_wal.anchor()
                        || self.manifest.base_serial < selected_wal.base_serial
                    {
                        return Err(AsyncSnapshotCommitError::Store(
                            SnapshotBlockStoreError::Corrupt,
                        ));
                    }
                }
                ScanResult::Corrupt | ScanResult::Unscanned => {
                    return Err(AsyncSnapshotCommitError::Store(
                        SnapshotBlockStoreError::Corrupt,
                    ));
                }
                ScanResult::Empty => {}
            }
        }
        self.target_slot = target;
        self.generation = generation;
        self.phase = if self.payload.as_ref().is_empty() {
            Phase::PayloadFlush
        } else {
            Phase::PayloadWrite(0)
        };
        Ok(())
    }

    /// Enter exactly one I/O before dispatch. A pending request makes every new entry refuse.
    pub fn enter_next(&mut self) -> Result<Option<AsyncSnapshotRequest>, AsyncSnapshotCommitError> {
        if self.pending.is_some() {
            return Err(AsyncSnapshotCommitError::Outstanding);
        }
        if let Some(error) = self.failure {
            return Err(AsyncSnapshotCommitError::Store(error));
        }
        let (kind, lba, bytes) = match self.phase {
            Phase::Preflush | Phase::PayloadFlush | Phase::FinalFlush => {
                (AsyncSnapshotIoKind::Flush, 0, 0)
            }
            Phase::Header(slot) => (
                AsyncSnapshotIoKind::Read,
                self.slot_base(slot),
                self.sector_size,
            ),
            Phase::PayloadScan {
                slot,
                sector,
                remaining: _,
            } => {
                let plan = self.header_plans[slot as usize].ok_or(
                    AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Corrupt),
                )?;
                let sectors = (plan.payload_sectors - sector).min(BATCH_SECTORS);
                (
                    AsyncSnapshotIoKind::Read,
                    self.slot_base(slot) + 1 + u64::from(sector),
                    sectors as usize * self.sector_size,
                )
            }
            Phase::PayloadWrite(sector) => {
                let total = self.payload.as_ref().len().div_ceil(self.sector_size) as u32;
                let sectors = (total - sector).min(BATCH_SECTORS);
                let offset = sector as usize * self.sector_size;
                let bytes = sectors as usize * self.sector_size;
                self.write_buffer.resize(bytes, 0);
                self.write_buffer.fill(0);
                let source = &self.payload.as_ref()[offset..];
                let copy = source.len().min(bytes);
                self.write_buffer[..copy].copy_from_slice(&source[..copy]);
                (
                    AsyncSnapshotIoKind::Write,
                    self.slot_base(self.target_slot) + 1 + u64::from(sector),
                    bytes,
                )
            }
            Phase::HeaderWrite => {
                self.write_buffer.resize(self.sector_size, 0);
                self.write_buffer.fill(0);
                encode_header(
                    &mut self.write_buffer,
                    SlotHeader {
                        slot: self.target_slot,
                        generation: self.generation,
                        payload_len: self.payload.as_ref().len() as u64,
                        payload_crc: crc32c(self.payload.as_ref()),
                        payload_sectors: self.payload.as_ref().len().div_ceil(self.sector_size)
                            as u32,
                        wal: Some(self.manifest),
                        resetting: false,
                    },
                );
                (
                    AsyncSnapshotIoKind::Write,
                    self.slot_base(self.target_slot),
                    self.sector_size,
                )
            }
            Phase::Done => return Ok(None),
        };
        let sequence = self.sequence;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(AsyncSnapshotCommitError::Exhausted)?;
        let request = AsyncSnapshotRequest {
            sequence,
            kind,
            lba,
            bytes,
        };
        self.pending = Some(request);
        Ok(Some(request))
    }

    pub fn write_bytes(&self, request: AsyncSnapshotRequest) -> Option<&[u8]> {
        (self.pending == Some(request) && request.kind == AsyncSnapshotIoKind::Write)
            .then_some(self.write_buffer.as_slice())
    }

    /// A local admission refusal before dispatch has no physical effect. Retain the phase and
    /// mint a different sequence on retry so a stale claim cannot complete the new command.
    pub fn release_unentered(&mut self, request: AsyncSnapshotRequest)
        -> Result<(), AsyncSnapshotCommitError>
    {
        if self.uncertain { return Err(AsyncSnapshotCommitError::Outstanding); }
        if let Some(error) = self.failure { return Err(AsyncSnapshotCommitError::Store(error)); }
        if self.pending != Some(request) { return Err(AsyncSnapshotCommitError::WrongTicket); }
        self.pending = None;
        Ok(())
    }

    pub fn lose(&mut self, request: AsyncSnapshotRequest) -> Result<(), AsyncSnapshotCommitError> {
        if self.pending != Some(request) {
            return Err(AsyncSnapshotCommitError::WrongTicket);
        }
        // A late exact terminal+ACK may still resolve this request, but it cannot be released
        // or retried while the effect remains uncertain.
        self.uncertain = true;
        Ok(())
    }

    fn check_completion(
        &self,
        request: AsyncSnapshotRequest,
        kind: AsyncSnapshotIoKind,
    ) -> Result<(), AsyncSnapshotCommitError> {
        if let Some(error) = self.failure {
            Err(AsyncSnapshotCommitError::Store(error))
        } else if self.pending != Some(request) {
            Err(AsyncSnapshotCommitError::WrongTicket)
        } else if request.kind != kind {
            Err(AsyncSnapshotCommitError::WrongKind)
        } else {
            Ok(())
        }
    }

    pub fn complete_read(
        &mut self,
        request: AsyncSnapshotRequest,
        bytes: &[u8],
    ) -> Result<(), AsyncSnapshotCommitError> {
        self.check_completion(request, AsyncSnapshotIoKind::Read)?;
        if bytes.len() != request.bytes {
            return Err(AsyncSnapshotCommitError::Incomplete);
        }
        match self.phase {
            Phase::Header(slot) => {
                let plan = match decode_header(bytes) {
                    Err(SnapshotBlockStoreError::Corrupt) => {
                        self.scan[slot as usize] = ScanResult::Corrupt;
                        None
                    }
                    Err(error) => return Err(AsyncSnapshotCommitError::Store(error)),
                    Ok(None) => {
                        self.scan[slot as usize] = ScanResult::Empty;
                        None
                    }
                    Ok(Some(header)) => {
                        if header.slot != slot
                            || header.payload_sectors as u64 > self.slot_sectors - 1
                        {
                            self.scan[slot as usize] = ScanResult::Corrupt;
                            None
                        } else {
                            let payload_len = usize::try_from(header.payload_len).ok();
                            let capacity =
                                (header.payload_sectors as usize).checked_mul(self.sector_size);
                            if payload_len
                                .zip(capacity)
                                .is_none_or(|(len, capacity)| len > capacity)
                            {
                                self.scan[slot as usize] = ScanResult::Corrupt;
                                None
                            } else {
                                Some(SlotReadPlan {
                                    slot,
                                    generation: header.generation,
                                    payload_len: payload_len.unwrap(),
                                    payload_crc: header.payload_crc,
                                    payload_sectors: header.payload_sectors,
                                    wal: header.wal,
                                    resetting: header.resetting,
                                })
                            }
                        }
                    }
                };
                if let Some(plan) = plan {
                    self.header_plans[slot as usize] = Some(plan);
                    self.scan_crc = Crc32c::new();
                    if plan.payload_sectors == 0 {
                        self.scan[slot as usize] =
                            if core::mem::replace(&mut self.scan_crc, Crc32c::new()).finish()
                                == plan.payload_crc
                                && plan.payload_len == 0
                            {
                                ScanResult::Valid(plan)
                            } else {
                                ScanResult::Corrupt
                            };
                        self.next_header(slot + 1)?;
                    } else {
                        self.phase = Phase::PayloadScan {
                            slot,
                            sector: 0,
                            remaining: plan.payload_len,
                        };
                    }
                } else {
                    self.next_header(slot + 1)?;
                }
            }
            Phase::PayloadScan {
                slot,
                sector,
                remaining,
            } => {
                let plan = self.header_plans[slot as usize].ok_or(
                    AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Corrupt),
                )?;
                let copy = remaining.min(bytes.len());
                self.scan_crc.update(&bytes[..copy]);
                let remaining = remaining - copy;
                let sector = sector + (bytes.len() / self.sector_size) as u32;
                if sector == plan.payload_sectors {
                    self.scan[slot as usize] = if remaining == 0
                        && core::mem::replace(&mut self.scan_crc, Crc32c::new()).finish()
                            == plan.payload_crc
                    {
                        ScanResult::Valid(plan)
                    } else {
                        ScanResult::Corrupt
                    };
                    self.next_header(slot + 1)?;
                } else {
                    self.phase = Phase::PayloadScan {
                        slot,
                        sector,
                        remaining,
                    };
                }
            }
            _ => return Err(AsyncSnapshotCommitError::WrongKind),
        }
        self.pending = None;
        self.uncertain = false;
        Ok(())
    }

    pub fn complete_effect(
        &mut self,
        request: AsyncSnapshotRequest,
        transferred: usize,
    ) -> Result<(), AsyncSnapshotCommitError> {
        if let Some(error) = self.failure { return Err(AsyncSnapshotCommitError::Store(error)); }
        if self.pending != Some(request) {
            return Err(AsyncSnapshotCommitError::WrongTicket);
        }
        if request.kind == AsyncSnapshotIoKind::Read {
            return Err(AsyncSnapshotCommitError::WrongKind);
        }
        if transferred != request.bytes {
            return Err(AsyncSnapshotCommitError::Incomplete);
        }
        self.phase = match self.phase {
            Phase::Preflush => Phase::Header(0),
            Phase::PayloadWrite(sector) => {
                let next = sector + (request.bytes / self.sector_size) as u32;
                if next == self.payload.as_ref().len().div_ceil(self.sector_size) as u32 {
                    Phase::PayloadFlush
                } else {
                    Phase::PayloadWrite(next)
                }
            }
            Phase::PayloadFlush => Phase::HeaderWrite,
            Phase::HeaderWrite => Phase::FinalFlush,
            Phase::FinalFlush => Phase::Done,
            _ => return Err(AsyncSnapshotCommitError::WrongKind),
        };
        self.pending = None;
        self.uncertain = false;
        Ok(())
    }

    pub fn finish(self) -> Result<u64, Self> {
        if self.is_done() {
            Ok(self.generation)
        } else {
            Err(self)
        }
    }

    /// A WAL checkpoint starts with a paired, payload-valid reserve. Its scan validates the
    /// unchanged slot; the exact payload and acknowledged final header/flush prove the new one.
    /// No post-commit physical read is needed to publish the refreshed in-process pair.
    /// # Safety
    /// All completed native reads, writes, and flushes must have reached exact provider
    /// terminal completion and ACK under one reserve lease. A local reply is not a barrier.
    pub unsafe fn finish_with_paired_proof(self) -> Result<(u64, VerifiedPairedWalSnapshot), Self> {
        unsafe { self.finish_with_payload_and_paired_proof() }
            .map(|(_payload, generation, proof)| (generation, proof))
    }

    /// Preserve the exact captured payload for a second folded snapshot pass. The proof is
    /// minted only after the same terminal and ACK precondition as `finish_with_paired_proof`.
    /// # Safety
    /// Every completed native request must have reached exact provider terminal and ACK under
    /// the same exclusive reserve lease.
    pub unsafe fn finish_with_payload_and_paired_proof(self)
        -> Result<(P, u64, VerifiedPairedWalSnapshot), Self>
    {
        if !self.is_done() || self.failure.is_some() { return Err(self); }
        let other = 1 - self.target_slot;
        let ScanResult::Valid(unchanged) = self.scan[other as usize] else { return Err(self); };
        let Some(payload_sectors) = u32::try_from(
            self.payload.as_ref().len().div_ceil(self.sector_size)).ok() else { return Err(self); };
        let published = SlotReadPlan {
            slot: self.target_slot, generation: self.generation,
            payload_len: self.payload.as_ref().len(),
            payload_crc: crc32c(self.payload.as_ref()), payload_sectors,
            wal: Some(self.manifest), resetting: false,
        };
        let plans = if self.target_slot == 0 { [published, unchanged] }
            else { [unchanged, published] };
        let Ok(manifest) = SnapshotBlockStore::paired_manifest(plans) else { return Err(self); };
        let proof = VerifiedPairedWalSnapshot { store: self.store, plans, manifest };
        Ok((self.payload, self.generation, proof))
    }

    /// The old synchronous entry point consumes precisely these same requests. Native callers
    /// instead retain this owner and feed authenticated SRB completions from the outer pump.
    pub fn run_sync<D: SnapshotBlockDevice>(
        mut self,
        dev: &mut D,
    ) -> Result<u64, SnapshotBlockStoreError> {
        while let Some(request) = self.enter_next().map_err(|error| match error {
            AsyncSnapshotCommitError::Store(error) => error,
            _ => SnapshotBlockStoreError::Corrupt,
        })? {
            match request.kind {
                AsyncSnapshotIoKind::Read => {
                    // `new` reserved one full batch before any I/O. Reads and writes never
                    // overlap, so reuse that buffer rather than allocating after Preflush.
                    let mut bytes = core::mem::take(&mut self.write_buffer);
                    bytes.resize(request.bytes, 0);
                    dev.read_sectors(request.lba, &mut bytes)?;
                    self.complete_read(request, &bytes)
                        .map_err(|_| SnapshotBlockStoreError::Corrupt)?;
                    self.write_buffer = bytes;
                }
                AsyncSnapshotIoKind::Write => {
                    dev.write_sectors(
                        request.lba,
                        self.write_bytes(request)
                            .ok_or(SnapshotBlockStoreError::Corrupt)?,
                    )?;
                    self.complete_effect(request, request.bytes)
                        .map_err(|_| SnapshotBlockStoreError::Corrupt)?;
                }
                AsyncSnapshotIoKind::Flush => {
                    dev.flush()?;
                    self.complete_effect(request, 0)
                        .map_err(|_| SnapshotBlockStoreError::Corrupt)?;
                }
            }
        }
        self.finish().map_err(|_| SnapshotBlockStoreError::Corrupt)
    }
}
