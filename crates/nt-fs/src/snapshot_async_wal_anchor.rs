//! Native two-header WAL anchor publication under one retained physical reserve.

use super::*;

/// Move-only publication authority for the newly committed WAL record. The record bytes came
/// from the same verified WAL prefix whose anchor crossed both native header barriers.
#[must_use = "consume only for the matching durable mutation publication"]
pub struct AnchoredWalPublication {
    continuation: crate::RegistryWalContinuation,
    pair: VerifiedPairedWalSnapshot,
    payload: Vec<u8>,
}

impl AnchoredWalPublication {
    pub(super) fn from_parts(
        continuation: crate::RegistryWalContinuation,
        pair: VerifiedPairedWalSnapshot,
        payload: Vec<u8>,
    ) -> Self {
        Self { continuation, pair, payload }
    }

    pub fn anchor(&self) -> WalSnapshotAnchor { self.continuation.anchor() }
    pub fn payload(&self) -> &[u8] { &self.payload }
    pub fn into_parts(self) -> (crate::RegistryWalContinuation, VerifiedPairedWalSnapshot, Vec<u8>) {
        (self.continuation, self.pair, self.payload)
    }
}

#[must_use = "retain until both exact native header writes and flushes complete"]
pub struct AsyncWalSnapshotAnchorUpdate<D: SnapshotBlockDevice> {
    inner: WalSnapshotAnchorUpdate<D>,
    sector: Vec<u8>,
    slot_sectors: u64,
    step: u8,
    pending: Option<AsyncSnapshotRequest>,
    sequence: u64,
    failed: bool,
}

impl<D: SnapshotBlockDevice> AsyncWalSnapshotAnchorUpdate<D> {
    pub fn admit_verified_wal_pair(
        store: SnapshotBlockStore,
        verified: crate::RegistryWalVerifiedDevice<D>,
        rechecked: RecheckedPairedWalSnapshot,
    ) -> Result<Self, (SnapshotBlockStoreError, crate::RegistryWalVerifiedDevice<D>, RecheckedPairedWalSnapshot)> {
        let size = rechecked.sector_size;
        let mut sector = Vec::new();
        if sector.try_reserve_exact(size).is_err() {
            return Err((SnapshotBlockStoreError::OutOfMemory, verified, rechecked));
        }
        sector.resize(size, 0);
        let inner = WalSnapshotAnchorUpdate::admit_rechecked_wal_pair(
            store, verified, rechecked)?;
        Ok(Self { inner, sector, slot_sectors: store.sector_count / 2,
            step: 0, pending: None, sequence: 1, failed: false })
    }

    pub fn enter_next(&mut self) -> Result<Option<AsyncSnapshotRequest>, AsyncSnapshotCommitError> {
        if self.failed { return Err(AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Io)); }
        if self.pending.is_some() { return Err(AsyncSnapshotCommitError::Outstanding); }
        if self.step == 4 { return Ok(None); }
        let write = self.step % 2 == 0;
        let slot = u32::from(self.step / 2);
        let request = AsyncSnapshotRequest {
            sequence: self.sequence,
            kind: if write { AsyncSnapshotIoKind::Write } else { AsyncSnapshotIoKind::Flush },
            lba: if write { self.inner.async_header_lba(self.slot_sectors, slot)
                .map_err(AsyncSnapshotCommitError::Store)? } else { 0 },
            bytes: if write { self.sector.len() } else { 0 },
        };
        self.sequence = self.sequence.checked_add(1).ok_or(AsyncSnapshotCommitError::Exhausted)?;
        if write { self.inner.encode_async_header(slot as usize, &mut self.sector); }
        self.pending = Some(request);
        Ok(Some(request))
    }

    pub fn pending(&self) -> Option<AsyncSnapshotRequest> { self.pending }
    pub fn is_done(&self) -> bool { !self.failed && self.step == 4 && self.pending.is_none() }
    pub fn is_failed(&self) -> bool { self.failed }

    pub fn write_bytes(&self, request: AsyncSnapshotRequest) -> Option<&[u8]> {
        (self.pending == Some(request) && request.kind == AsyncSnapshotIoKind::Write)
            .then_some(self.sector.as_slice())
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
    /// `settled = true` requires the exact physical write or flush to have reached provider
    /// terminal completion and acknowledgement for this request. A reply alone is insufficient.
    pub unsafe fn complete(&mut self, request: AsyncSnapshotRequest, settled: bool)
        -> Result<(), AsyncSnapshotCommitError>
    {
        if self.failed { return Err(AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Io)); }
        if self.pending != Some(request) { return Err(AsyncSnapshotCommitError::WrongTicket); }
        if !settled {
            self.failed = true;
            self.inner.fail_async_headers();
            return Err(AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Io));
        }
        self.pending = None;
        self.step += 1;
        if self.step == 4 { self.inner.complete_async_headers(); }
        Ok(())
    }

    pub fn into_continuation_and_pair(self)
        -> Result<(D, crate::RegistryWalContinuation, VerifiedPairedWalSnapshot), Self>
    {
        if self.failed || self.step != 4 || self.pending.is_some() { return Err(self); }
        match self.inner.into_continuation_pair_and_payload() {
            Ok((device, token, pair, _payload)) => Ok((device, token, pair)),
            Err(_) => unreachable!("completed async anchor must release exact proof"),
        }
    }

    /// Only a newly marked record may mint a publication authority; a recovered prefix has no
    /// current mutation payload even if its numeric anchor is valid.
    pub fn into_anchored_publication(self) -> Result<(D, AnchoredWalPublication), Self> {
        if self.failed || self.step != 4 || self.pending.is_some()
            || !self.inner.has_newly_committed_payload() { return Err(self); }
        match self.inner.into_continuation_pair_and_payload() {
            Ok((device, continuation, pair, Some(payload))) =>
                Ok((device, AnchoredWalPublication::from_parts(continuation, pair, payload))),
            _ => unreachable!("completed native anchor retains newly committed payload"),
        }
    }

    #[cfg(test)]
    pub(super) fn device_for_test(&mut self) -> &mut D { self.inner.device_for_test() }
}
