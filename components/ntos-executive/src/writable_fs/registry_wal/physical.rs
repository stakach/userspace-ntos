//! Move-only mount-scoped SYSTEM WAL device, paired snapshot proof, and native I/O.
//!
//! CM receipts and acknowledgement belong to the mutation Journal in the parent module.

use super::*;
use nt_fs::{
    OwnedBoundedBlockRange, RegistryWal, RegistryWalError, RegistryWalState,
    RegistryWalContinuation, RegistryWalVerifiedDevice, WalSnapshotAnchor,
    WalSnapshotAnchorUpdate,
};

type WalDevice = OwnedBoundedBlockRange<snapshot_storage::Lease>;

enum Stage {
    Wal(RegistryWal<WalDevice>),
    Verified(RegistryWalVerifiedDevice<snapshot_storage::Lease>),
    Anchoring(WalSnapshotAnchorUpdate<snapshot_storage::Lease>),
    AsyncAnchoring(nt_fs::AsyncWalSnapshotAnchorUpdate<snapshot_storage::Lease>),
    Anchored(snapshot_storage::Lease, RegistryWalContinuation, nt_fs::VerifiedPairedWalSnapshot),
    Aborted(snapshot_storage::Lease, RegistryWalContinuation, nt_fs::VerifiedPairedWalSnapshot),
}

pub(super) enum PairAuthority {
    Plain(nt_fs::VerifiedPairedWalSnapshot),
    Rechecked(nt_fs::RecheckedPairedWalSnapshot),
}

impl PairAuthority {
    pub(super) fn into_pair(self) -> nt_fs::VerifiedPairedWalSnapshot {
        match self { Self::Plain(pair) => pair, Self::Rechecked(proof) => proof.into_pair() }
    }
}

/// Owns the exact physical reserve and recovery authority until a settled terminal release.
#[must_use = "retain the physical WAL owner across every uncertain effect"]
pub(super) struct Owner {
    store: nt_fs::SnapshotBlockStore,
    stage: Option<Stage>,
    pair: Option<PairAuthority>,
    mount: nt_memory_manager::SectionMountId,
    snapshot_physical_start: u64,
    wal_physical_start: u64,
    wal_sectors: u64,
    anchor_entered: bool,
}

impl Drop for Owner {
    fn drop(&mut self) {
        if let Some(stage) = self.stage.take() {
            core::mem::forget(stage);
            panic!("dropping unresolved native SYSTEM WAL owner");
        }
    }
}

fn status(error: RegistryWalError) -> u32 {
    match error {
        RegistryWalError::OutOfSpace
        | RegistryWalError::OutOfMemory
        | RegistryWalError::GenerationExhausted => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
        RegistryWalError::Storage(error) => snapshot_store_error_status(error),
        RegistryWalError::InvalidGeometry
        | RegistryWalError::WrongIncarnation
        | RegistryWalError::Corrupt
        | RegistryWalError::InvalidState => nt_fs::STATUS_DATA_ERROR,
        RegistryWalError::Uncertain => nt_fs::STATUS_DEVICE_NOT_READY,
    }
}

fn anchor_request(request: nt_fs::AsyncWalIoRequest) -> nt_fs::AsyncSnapshotRequest {
    nt_fs::AsyncSnapshotRequest { sequence: request.sequence,
        kind: match request.kind { nt_fs::AsyncWalIoKind::Write => nt_fs::AsyncSnapshotIoKind::Write,
            nt_fs::AsyncWalIoKind::Flush => nt_fs::AsyncSnapshotIoKind::Flush },
        lba: request.lba, bytes: request.bytes }
}

/// Return an untouched live proof to its exact mounted reserve. If that identity has changed,
/// retain the lease and proof instead of permitting a fresh scan to hide the contradiction.
pub(super) fn restore_continuation(
    lease: snapshot_storage::Lease,
    continuation: RegistryWalContinuation,
    pair: nt_fs::VerifiedPairedWalSnapshot,
) -> Result<(), u32> {
    match snapshot_storage::install_wal_continuation(&lease, continuation, pair) {
        Ok(()) => {
            drop(lease);
            Ok(())
        }
        Err((status, continuation, pair)) => {
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            core::mem::forget(continuation);
            core::mem::forget(pair);
            core::mem::forget(lease);
            Err(status)
        }
    }
}

impl Owner {
    pub(crate) fn mount(&self) -> nt_memory_manager::SectionMountId { self.mount }

    pub(super) fn has_wal_stage(&self) -> bool {
        matches!(self.stage.as_ref(), Some(Stage::Wal(_)))
    }

    pub(super) fn frame_room(&self) -> Result<nt_fs::RegistryWalFrameRoom, u32> {
        let Some(Stage::Wal(wal)) = self.stage.as_ref() else {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        };
        wal.frame_room().map_err(status)
    }

    pub(crate) fn native_io_active(&self) -> bool {
        match self.stage.as_ref() {
            Some(Stage::Wal(wal)) =>
                wal.async_active() && wal.state() != RegistryWalState::Uncertain,
            Some(Stage::AsyncAnchoring(_)) => true,
            _ => false,
        }
    }

    pub(crate) fn claim_native_io(&mut self) -> Result<Option<(nt_fs::AsyncWalIoRequest, nt_fs::BlockOperation, Vec<u8>)>, u32> {
        if let Some(Stage::AsyncAnchoring(update)) = self.stage.as_mut() {
            let request = match update.enter_next() {
                Ok(Some(request)) => request,
                Ok(None) => return Ok(None),
                Err(nt_fs::AsyncSnapshotCommitError::Outstanding) => return Ok(None),
                Err(_) => return Err(nt_fs::STATUS_DEVICE_NOT_READY),
            };
            let converted = nt_fs::AsyncWalIoRequest {
                sequence: request.sequence,
                kind: if request.kind == nt_fs::AsyncSnapshotIoKind::Write {
                    nt_fs::AsyncWalIoKind::Write
                } else { nt_fs::AsyncWalIoKind::Flush },
                lba: request.lba, bytes: request.bytes,
            };
            let (operation, input) = if request.kind == nt_fs::AsyncSnapshotIoKind::Write {
                let sectors = u32::try_from(request.bytes / 512).ok().filter(|sectors| {
                    *sectors != 0 && request.bytes == *sectors as usize * 512
                        && request.lba.checked_add(u64::from(*sectors))
                            .is_some_and(|end| end <= self.store.sector_count())
                });
                let lba = sectors.and_then(|_| self.snapshot_physical_start.checked_add(request.lba));
                let (Some(sectors), Some(lba)) = (sectors, lba) else {
                    let _ = unsafe { update.complete(request, false) };
                    WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
                    return Err(nt_fs::STATUS_INVALID_PARAMETER);
                };
                let bytes = update.write_bytes(request).expect("exact pending anchor write");
                let mut input = Vec::new();
                if input.try_reserve_exact(bytes.len()).is_err() {
                    update.release_unentered(request).expect("unentered anchor allocation");
                    return Err(nt_fs::STATUS_INSUFFICIENT_RESOURCES);
                }
                input.extend_from_slice(bytes);
                (nt_fs::BlockOperation::Write { lba, sectors }, input)
            } else { (nt_fs::BlockOperation::Flush, Vec::new()) };
            return Ok(Some((converted, operation, input)));
        }
        let Some(Stage::Wal(wal)) = self.stage.as_mut() else { return Ok(None); };
        if !wal.async_active() || wal.state() == RegistryWalState::Uncertain { return Ok(None); }
        let request = match wal.enter_next_async() {
            Ok(Some(request)) => request,
            Ok(None) | Err(RegistryWalError::InvalidState) => return Ok(None),
            Err(error) => return Err(status(error)),
        };
        let operation = match request.kind {
            nt_fs::AsyncWalIoKind::Flush => nt_fs::BlockOperation::Flush,
            nt_fs::AsyncWalIoKind::Write => {
                let sectors = u32::try_from(request.bytes / 512).unwrap_or(0);
                if sectors == 0 || request.lba.checked_add(u64::from(sectors))
                    .is_none_or(|end| end > self.wal_sectors) {
                    wal.release_unentered_async(request).expect("invalid unentered WAL step");
                    return Err(nt_fs::STATUS_INVALID_PARAMETER);
                }
                let Some(lba) = self.wal_physical_start.checked_add(request.lba) else {
                    wal.release_unentered_async(request).expect("unentered WAL LBA overflow");
                    return Err(nt_fs::STATUS_INVALID_PARAMETER);
                };
                nt_fs::BlockOperation::Write { lba, sectors }
            }
        };
        let mut input = Vec::new();
        if let Some(bytes) = wal.async_write_bytes(request) {
            if input.try_reserve_exact(bytes.len()).is_err() {
                wal.release_unentered_async(request).expect("unentered WAL allocation refused");
                return Err(nt_fs::STATUS_INSUFFICIENT_RESOURCES);
            }
            input.extend_from_slice(bytes);
        }
        Ok(Some((request, operation, input)))
    }

    pub(crate) fn mark_native_io_entered(&mut self, request: nt_fs::AsyncWalIoRequest) -> Result<(), u32> {
        if let Some(Stage::AsyncAnchoring(update)) = self.stage.as_ref() {
            if self.anchor_entered || update.pending() != Some(anchor_request(request)) {
                return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
            }
            self.anchor_entered = true;
            return Ok(());
        }
        let Some(Stage::Wal(wal)) = self.stage.as_mut() else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
        wal.mark_entered_async(request).map_err(status)
    }

    pub(crate) fn release_unentered_native_io(&mut self, request: nt_fs::AsyncWalIoRequest) -> Result<(), u32> {
        if let Some(Stage::AsyncAnchoring(update)) = self.stage.as_mut() {
            if self.anchor_entered { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); }
            return update.release_unentered(anchor_request(request))
                .map_err(|_| nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        let Some(Stage::Wal(wal)) = self.stage.as_mut() else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
        wal.release_unentered_async(request).map_err(status)
    }

    pub(crate) fn refuse_unentered_native_io(&mut self, request: nt_fs::AsyncWalIoRequest) -> Result<nt_fs::AsyncWalRefusal, u32> {
        if let Some(Stage::AsyncAnchoring(update)) = self.stage.as_mut() {
            if self.anchor_entered || update.pending() != Some(anchor_request(request)) {
                return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
            }
            let _ = unsafe { update.complete(anchor_request(request), false) };
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            return Ok(nt_fs::AsyncWalRefusal::RetainedEffects);
        }
        let Some(Stage::Wal(wal)) = self.stage.as_mut() else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
        let result = wal.refuse_unentered_async(request).map_err(status)?;
        if result == nt_fs::AsyncWalRefusal::RetainedEffects {
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
        }
        Ok(result)
    }

    pub(crate) fn complete_native_io(&mut self, request: nt_fs::AsyncWalIoRequest,
        result: Result<&[u8], nt_status::NtStatus>) -> Result<super::super::native_snapshot_io::SnapshotCompletion, u32> {
        use super::super::native_snapshot_io::SnapshotCompletion;
        if let Some(Stage::AsyncAnchoring(update)) = self.stage.as_mut() {
            if !self.anchor_entered || update.pending() != Some(anchor_request(request)) {
                return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
            }
            let settled = matches!(result, Ok(bytes) if bytes.is_empty());
            // The outer native block executor invokes this only after exact terminal + ACK.
            let completed = unsafe { update.complete(anchor_request(request), settled) };
            if completed.is_err() {
                WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
                return Ok(SnapshotCompletion::Failed(nt_fs::STATUS_DEVICE_NOT_READY));
            }
            self.anchor_entered = false;
            return Ok(SnapshotCompletion::Settled);
        }
        let Some(Stage::Wal(wal)) = self.stage.as_mut() else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
        let settled = match result {
            Ok(bytes) if bytes.is_empty() => Ok(()),
            _ => Err(nt_fs::SnapshotBlockStoreError::Io),
        };
        if let Err(error) = wal.complete_async(request, settled) {
            if error == RegistryWalError::InvalidState {
                return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
            }
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            return Ok(SnapshotCompletion::Failed(status(error)));
        }
        Ok(SnapshotCompletion::Settled)
    }

    /// Resume the exact mounted WAL and reserve one physical frame before any write.
    pub(super) unsafe fn admit_authority(
        bytes: Vec<u8>,
        lease: snapshot_storage::Lease,
        continuation: RegistryWalContinuation,
        authority: PairAuthority,
        manifest: nt_fs::WalSnapshotManifest,
    ) -> Result<Self, u32> {
        let mut owner = unsafe { Self::resume_authority(lease, continuation, authority, manifest) }?;
        if let Err(error) = owner.begin_payload(bytes) {
            // BEGIN has no native effect. Restore this exact continuation before another
            // writer may acquire the reserve; retain the owner if publication fails.
            if let Err(release_error) = owner.release_aborted() {
                core::mem::forget(owner);
                return Err(release_error);
            }
            return Err(error);
        }
        Ok(owner)
    }

    /// Keep the mount lease and paired-header authority while collecting several CM journals.
    /// The caller must validate its exact CM mount/binding before accepting a mutation slot.
    ///
    /// # Safety
    /// `lease` must be the same exclusive physical reserve that minted `continuation`, and
    /// `authority` must prove both snapshot headers still name `manifest` under that lease.
    pub(super) unsafe fn resume_authority(
        lease: snapshot_storage::Lease,
        continuation: RegistryWalContinuation,
        authority: PairAuthority,
        manifest: nt_fs::WalSnapshotManifest,
    ) -> Result<Self, u32> {
        let mut authority = Some(authority);
        let store = lease.store();
        let expected = WalSnapshotAnchor {
            incarnation: manifest.incarnation,
            serial: manifest.high_water_serial,
            end_lba: manifest.high_water_end_lba,
        };
        let mount = *lease.identity();
        let geometry = snapshot_storage::wal_bounds(&lease).and_then(|(start, sectors)| {
            let physical = snapshot_storage::physical_lba(&lease, start)?;
            let last = start.checked_add(sectors - 1).ok_or(nt_fs::STATUS_INVALID_PARAMETER)?;
            snapshot_storage::physical_lba(&lease, last)?;
            Ok((physical, sectors))
        });
        let (wal_physical_start, wal_sectors) = match geometry {
            Ok(geometry) => geometry,
            Err(error) => {
                restore_continuation(lease, continuation, authority.take().unwrap().into_pair())?;
                return Err(error);
            }
        };
        let snapshot_physical_start = match snapshot_storage::physical_lba(&lease, 0) {
            Ok(lba) => lba,
            Err(error) => {
                restore_continuation(lease, continuation, authority.take().unwrap().into_pair())?;
                return Err(error);
            }
        };
        let range = match snapshot_storage::owned_wal_region(lease) {
            Ok(range) => range,
            Err((error, lease)) => {
                restore_continuation(lease, continuation, authority.take().unwrap().into_pair())?;
                return Err(error);
            }
        };
        // Boot's full scan and paired-header barrier minted this one-use, mount-bound proof.
        // No physical WAL writer can intervene while the reserve lease is held here.
        // SAFETY: the caller owns the exact mount lease and paired-header proof;
        // this method does not release either before resuming the continuation.
        let wal = match unsafe { RegistryWal::resume_from_continuation(range, continuation, expected) } {
            Ok(wal) => wal,
            Err((error, range, continuation)) => {
                restore_continuation(range.into_device(), continuation,
                    authority.take().unwrap().into_pair())?;
                WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
                return Err(status(error));
            }
        };
        Ok(Self {
            store,
            stage: Some(Stage::Wal(wal)),
            pair: authority,
            mount,
            snapshot_physical_start,
            wal_physical_start,
            wal_sectors,
            anchor_entered: false,
        })
    }

    /// Reserve one sealed frame on the same ready WAL and mount lease. This is a pure
    /// in-memory transition; PREPARE begins the first native effect later.
    pub(super) fn begin_payload(&mut self, bytes: Vec<u8>) -> Result<(), u32> {
        let Some(Stage::Wal(wal)) = self.stage.as_mut() else {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        };
        wal.begin(bytes).map_err(status)
    }

    /// Durable PREPARE plus payload. A failure leaves this owner and lease unchanged.
    pub(crate) fn prepare(&mut self) -> Result<(), u32> {
        let Some(Stage::Wal(wal)) = self.stage.as_mut() else {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        };
        if crate::fs_loader::exec_block_route_kind(self.mount) == Some(nt_fs::BlockSourceKind::Draining) {
            return Err(snapshot_storage::BUSY);
        }
        if crate::fs_loader::exec_block_route_kind(self.mount) == Some(nt_fs::BlockSourceKind::Native) {
            if wal.state() == RegistryWalState::Uncertain { return Err(nt_fs::STATUS_DEVICE_NOT_READY); }
            if wal.state() == RegistryWalState::Prepared { return Ok(()); }
            if wal.async_active() { return Err(snapshot_storage::BUSY); }
            wal.start_async_prepare().map_err(status)?;
            return Err(snapshot_storage::BUSY);
        }
        wal.prepare().map_err(status)
    }

    /// Refuse a marker before its exact CM receipt has been checked by the Journal.
    pub(super) fn can_commit_marker(&self, allow_settled: bool) -> Result<(), u32> {
        let Some(Stage::Wal(wal)) = self.stage.as_ref() else {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        };
        if !(wal.state() == RegistryWalState::Prepared
            || (wal.state() == RegistryWalState::Ready && allow_settled)) {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        if crate::fs_loader::exec_block_route_kind(self.mount) == Some(nt_fs::BlockSourceKind::Draining) {
            return Err(snapshot_storage::BUSY);
        }
        Ok(())
    }

    /// The Journal records its validated receipt before this may enter a physical effect.
    pub(super) fn commit_marker(&mut self) -> Result<(), u32> {
        let Some(Stage::Wal(wal)) = self.stage.as_mut() else {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        };
        if crate::fs_loader::exec_block_route_kind(self.mount) == Some(nt_fs::BlockSourceKind::Native) {
            if wal.state() == RegistryWalState::Uncertain { return Err(nt_fs::STATUS_DEVICE_NOT_READY); }
            if wal.state() != RegistryWalState::Ready {
                if !wal.async_active() { wal.start_async_commit().map_err(status)?; }
                return Err(snapshot_storage::BUSY);
            }
        } else {
            wal.commit().map_err(status)?;
        }
        let Some(Stage::Wal(wal)) = self.stage.take() else { unreachable!() };
        let verified = wal.into_verified_device()
            .expect("settled marker has a verified prefix")
            .into_full_device();
        self.stage = Some(Stage::Verified(verified));
        Ok(())
    }

    /// Advance both v2 headers from the same verified WAL device. An uncertain barrier
    /// stays in `Anchoring` and cannot be retried as a fresh write or released.
    pub(crate) fn anchor(&mut self) -> Result<(), u32> {
        if matches!(self.stage.as_ref(), Some(Stage::Verified(_))) {
            let Some(Stage::Verified(verified)) = self.stage.take() else { unreachable!() };
            let authority = self.pair.take().expect("verified pair retained through WAL marker");
            match (crate::fs_loader::exec_block_route_kind(self.mount), authority) {
                (Some(nt_fs::BlockSourceKind::Native), PairAuthority::Rechecked(proof)) => {
                    let update = match nt_fs::AsyncWalSnapshotAnchorUpdate::admit_verified_wal_pair(
                        self.store, verified, proof) {
                        Ok(update) => update,
                        Err((error, verified, proof)) => {
                            self.stage = Some(Stage::Verified(verified));
                            self.pair = Some(PairAuthority::Rechecked(proof));
                            return Err(snapshot_store_error_status(error));
                        }
                    };
                    self.stage = Some(Stage::AsyncAnchoring(update));
                }
                (Some(nt_fs::BlockSourceKind::Boot), PairAuthority::Plain(pair)) => {
                    let update = match WalSnapshotAnchorUpdate::admit_verified_wal_pair(
                        self.store, verified, pair) {
                        Ok(update) => update,
                        Err((error, verified, pair)) => {
                            self.stage = Some(Stage::Verified(verified));
                            self.pair = Some(PairAuthority::Plain(pair));
                            return Err(snapshot_store_error_status(error));
                        }
                    };
                    self.stage = Some(Stage::Anchoring(update));
                }
                (_, authority) => {
                    self.stage = Some(Stage::Verified(verified));
                    self.pair = Some(authority);
                    return Err(nt_fs::STATUS_DEVICE_NOT_READY);
                }
            }
        }
        if let Some(Stage::AsyncAnchoring(update)) = self.stage.as_ref() {
            if !update.is_done() { return Err(snapshot_storage::BUSY); }
            let Some(Stage::AsyncAnchoring(update)) = self.stage.take() else { unreachable!() };
            let (lease, continuation, pair) = match update.into_continuation_and_pair() {
                Ok(parts) => parts,
                Err(_) => unreachable!("both native WAL anchor barriers completed"),
            };
            SYSTEM_WAL_FOLD_REQUIRED.store(true, Ordering::Release);
            self.stage = Some(Stage::Anchored(lease, continuation, pair));
            return Ok(());
        }
        let Some(Stage::Anchoring(update)) = self.stage.as_mut() else {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        };
        update.advance().map_err(snapshot_store_error_status)?;
        SYSTEM_WAL_FOLD_REQUIRED.store(true, Ordering::Release);
        let Some(Stage::Anchoring(update)) = self.stage.take() else { unreachable!() };
        let (lease, continuation, pair) = update.into_continuation_and_pair()
            .expect("both WAL anchors durably advanced");
        self.stage = Some(Stage::Anchored(lease, continuation, pair));
        Ok(())
    }

    /// Clear a prepared, uncommitted frame after an exact CM ABORT receipt was retained.
    pub(super) fn abort_prepared(&mut self) -> Result<(), u32> {
        let Some(Stage::Wal(wal)) = self.stage.as_mut() else {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        };
        if crate::fs_loader::exec_block_route_kind(self.mount) == Some(nt_fs::BlockSourceKind::Draining) {
            if wal.state() == RegistryWalState::PendingPrepare && !wal.async_active() {
                wal.cancel_pending().map_err(status)?;
                return Ok(());
            }
            return Err(snapshot_storage::BUSY);
        }
        if crate::fs_loader::exec_block_route_kind(self.mount) == Some(nt_fs::BlockSourceKind::Native) {
            match wal.state() {
                RegistryWalState::PendingPrepare if wal.async_active() => return Err(snapshot_storage::BUSY),
                RegistryWalState::PendingPrepare => wal.cancel_pending().map_err(status)?,
                RegistryWalState::Prepared => {
                    if !wal.async_active() { wal.start_async_abort_prepared().map_err(status)?; }
                    return Err(snapshot_storage::BUSY);
                }
                RegistryWalState::Ready => {},
                RegistryWalState::Uncertain => return Err(nt_fs::STATUS_DEVICE_NOT_READY),
                _ => return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST),
            }
            Ok(())
        } else {
            match wal.state() {
                RegistryWalState::PendingPrepare => wal.cancel_pending(),
                RegistryWalState::Prepared => wal.abort_prepared(),
                _ => Err(RegistryWalError::InvalidState),
            }.map_err(status)
        }
    }

    /// Restore the settled marked prefix only after the Journal matches the exact CM ACK.
    pub(super) fn release_anchored(&mut self) -> Result<(), u32> {
        if !matches!(self.stage.as_ref(), Some(Stage::Anchored(_, _, _))) {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        let Some(Stage::Anchored(lease, continuation, pair)) = self.stage.take() else {
            unreachable!("checked anchored WAL owner")
        };
        match snapshot_storage::install_wal_continuation(&lease, continuation, pair) {
            Ok(()) => { drop(lease); Ok(()) }
            Err((status, continuation, pair)) => {
                self.stage = Some(Stage::Anchored(lease, continuation, pair));
                Err(status)
            }
        }
    }

    /// Return an aborted frame's unchanged authority after the exact CM ABORT ACK.
    pub(super) fn release_aborted(&mut self) -> Result<(), u32> {
        if matches!(self.stage.as_ref(), Some(Stage::Wal(wal)) if wal.state() == RegistryWalState::Ready) {
            let Some(Stage::Wal(wal)) = self.stage.take() else { unreachable!() };
            let (range, continuation) = wal.into_continuation()
                .expect("confirmed WAL abort is settled");
            let pair = self.pair.take().expect("unchanged pair retained through WAL abort").into_pair();
            self.stage = Some(Stage::Aborted(range.into_device(), continuation, pair));
        }
        if !matches!(self.stage.as_ref(), Some(Stage::Aborted(_, _, _))) {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        let Some(Stage::Aborted(lease, continuation, pair)) = self.stage.take() else {
            unreachable!("checked aborted WAL owner")
        };
        match snapshot_storage::install_wal_continuation(&lease, continuation, pair) {
            Ok(()) => { drop(lease); Ok(()) }
            Err((status, continuation, pair)) => {
                // The exact abort was acknowledged, but native authority publication failed.
                // Keep the lease and proof in this owner for the same terminal redrive.
                self.stage = Some(Stage::Aborted(lease, continuation, pair));
                Err(status)
            }
        }
    }
}
