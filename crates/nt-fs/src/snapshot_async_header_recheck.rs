//! Exact two-header recheck under a retained paired snapshot proof.

use super::*;

/// Exact unchanged headers observed under the exclusive reserve. Carry this with that reserve
/// through the disjoint WAL marker; only the native anchor owner may consume its proof.
#[must_use = "retain with the exact reserve through WAL anchor publication"]
pub struct RecheckedPairedWalSnapshot {
    pub(super) store: SnapshotBlockStore,
    pub(super) pair: VerifiedPairedWalSnapshot,
    pub(super) sector_size: usize,
    pub(super) device_sectors: u64,
}

impl RecheckedPairedWalSnapshot {
    pub fn anchor(&self) -> WalSnapshotAnchor { self.pair.anchor() }
    pub fn manifest(&self) -> WalSnapshotManifest { self.pair.manifest() }
    /// Return an untouched proof if admission failed before any anchor write entered.
    pub fn into_pair(self) -> VerifiedPairedWalSnapshot { self.pair }
}

/// This owner never rereads payloads; the exclusive reserve and paired proof retain their CRC
/// authority. It yields one header read at a time and refuses a changed physical header.
#[must_use = "retain with the exact snapshot reserve until both headers match"]
pub struct AsyncSnapshotHeaderRecheck {
    store: SnapshotBlockStore,
    proof: Option<VerifiedPairedWalSnapshot>,
    sector_size: usize,
    device_sectors: u64,
    slot_sectors: u64,
    next_slot: u32,
    pending: Option<AsyncSnapshotRequest>,
    sequence: u64,
    failure: Option<SnapshotBlockStoreError>,
}

impl AsyncSnapshotHeaderRecheck {
    pub fn new(store: SnapshotBlockStore, proof: VerifiedPairedWalSnapshot,
        sector_size: usize, device_sectors: u64)
        -> Result<Self, (SnapshotBlockStoreError, VerifiedPairedWalSnapshot)>
    {
        if proof.store != store || sector_size < WAL_HEADER_LEN
            || store.sector_count < 4 || store.sector_count % 2 != 0
            || store.start_lba.checked_add(store.sector_count)
                .is_none_or(|end| end > device_sectors)
        {
            return Err((SnapshotBlockStoreError::InvalidGeometry, proof));
        }
        Ok(Self { store, proof: Some(proof), sector_size, device_sectors,
            slot_sectors: store.sector_count / 2, next_slot: 0,
            pending: None, sequence: 1, failure: None })
    }

    pub fn pending(&self) -> Option<AsyncSnapshotRequest> { self.pending }
    pub fn is_done(&self) -> bool {
        self.next_slot == 2 && self.pending.is_none() && self.failure.is_none()
    }

    pub fn enter_next(&mut self)
        -> Result<Option<AsyncSnapshotRequest>, AsyncSnapshotCommitError>
    {
        if self.pending.is_some() { return Err(AsyncSnapshotCommitError::Outstanding); }
        if let Some(error) = self.failure { return Err(AsyncSnapshotCommitError::Store(error)); }
        if self.next_slot == 2 { return Ok(None); }
        let request = AsyncSnapshotRequest {
            sequence: self.sequence,
            kind: AsyncSnapshotIoKind::Read,
            lba: self.store.start_lba + self.slot_sectors * u64::from(self.next_slot),
            bytes: self.sector_size,
        };
        self.sequence = self.sequence.checked_add(1)
            .ok_or(AsyncSnapshotCommitError::Exhausted)?;
        self.pending = Some(request);
        Ok(Some(request))
    }

    pub fn release_unentered(&mut self, request: AsyncSnapshotRequest)
        -> Result<(), AsyncSnapshotCommitError>
    {
        if let Some(error) = self.failure { return Err(AsyncSnapshotCommitError::Store(error)); }
        if self.pending != Some(request) { return Err(AsyncSnapshotCommitError::WrongTicket); }
        self.pending = None;
        Ok(())
    }

    pub fn complete_read(&mut self, request: AsyncSnapshotRequest, bytes: &[u8])
        -> Result<(), AsyncSnapshotCommitError>
    {
        if let Some(error) = self.failure { return Err(AsyncSnapshotCommitError::Store(error)); }
        if self.pending != Some(request) { return Err(AsyncSnapshotCommitError::WrongTicket); }
        if request.kind != AsyncSnapshotIoKind::Read { return Err(AsyncSnapshotCommitError::WrongKind); }
        if bytes.len() != request.bytes { return Err(AsyncSnapshotCommitError::Incomplete); }
        let proof = self.proof.as_ref().expect("recheck retains paired proof");
        let checked = SnapshotBlockStore::slot_plan_from_sector(
            self.next_slot, self.sector_size, self.slot_sectors, bytes);
        if checked != Ok(Some(proof.plans[self.next_slot as usize])) {
            let error = checked.err().unwrap_or(SnapshotBlockStoreError::Corrupt);
            self.failure = Some(error);
            return Err(AsyncSnapshotCommitError::Store(error));
        }
        self.pending = None;
        self.next_slot += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Result<(VerifiedPairedWalSnapshot, WalSnapshotManifest), Self> {
        if self.next_slot != 2 || self.pending.is_some() || self.failure.is_some() {
            return Err(self);
        }
        let proof = self.proof.take().expect("completed recheck retains paired proof");
        let manifest = proof.manifest;
        Ok((proof, manifest))
    }

    /// All completed operations were reads. After an exact unentered local refusal has been
    /// released, return the original paired proof so the same reserve can retry admission.
    pub fn abort_no_effect(mut self) -> Result<VerifiedPairedWalSnapshot, Self> {
        if self.pending.is_some() || self.failure.is_some() { return Err(self); }
        Ok(self.proof.take().expect("recheck retains paired proof"))
    }

    /// # Safety
    /// Every completed read must have been the exact reserve read returned by the native
    /// provider after terminal completion and ACK, while the same exclusive lease was held.
    pub unsafe fn finish_proven(self) -> Result<RecheckedPairedWalSnapshot, Self> {
        let store = self.store;
        let sector_size = self.sector_size;
        let device_sectors = self.device_sectors;
        self.finish().map(|(pair, _)| RecheckedPairedWalSnapshot {
            store, pair, sector_size, device_sectors,
        })
    }
}
