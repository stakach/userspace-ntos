//! Retained native SYSTEM fold: two identical snapshots, optional WAL rollover, CM ACK.

use super::*;
use alloc::vec::Vec;
use nt_fs::{AsyncSnapshotCommit, AsyncSnapshotIoKind, AsyncSnapshotRequest,
    AsyncWalEpochRollover};

type Commit = AsyncSnapshotCommit<snapshot_capture::CapturedSnapshot>;

enum Cursor { First(Commit), Second(Commit), Rollover(AsyncWalEpochRollover) }

impl Cursor {
    fn enter_next(&mut self) -> Result<Option<AsyncSnapshotRequest>, nt_fs::AsyncSnapshotCommitError> {
        match self { Self::First(c) | Self::Second(c) => c.enter_next(), Self::Rollover(c) => c.enter_next() }
    }
    fn pending(&self) -> Option<AsyncSnapshotRequest> {
        match self { Self::First(c) | Self::Second(c) => c.pending(), Self::Rollover(c) => c.pending() }
    }
    fn is_done(&self) -> bool {
        match self { Self::First(c) | Self::Second(c) => c.is_done(), Self::Rollover(c) => c.is_done() }
    }
    fn write_bytes(&self, request: AsyncSnapshotRequest) -> Option<&[u8]> {
        match self { Self::First(c) | Self::Second(c) => c.write_bytes(request), Self::Rollover(c) => c.write_bytes(request) }
    }
    fn release_unentered(&mut self, request: AsyncSnapshotRequest)
        -> Result<(), nt_fs::AsyncSnapshotCommitError> {
        match self { Self::First(c) | Self::Second(c) => c.release_unentered(request),
            Self::Rollover(c) => c.release_unentered(request) }
    }
    fn lose(&mut self, request: AsyncSnapshotRequest) {
        match self { Self::First(c) | Self::Second(c) => { let _ = c.lose(request); },
            Self::Rollover(c) => { let _ = unsafe { c.complete(request, false) }; } }
    }
    unsafe fn complete(&mut self, request: AsyncSnapshotRequest, bytes: &[u8])
        -> Result<(), nt_fs::AsyncSnapshotCommitError> {
        match self {
            Self::First(c) | Self::Second(c) => match request.kind {
                AsyncSnapshotIoKind::Read => c.complete_read(request, bytes),
                _ if bytes.is_empty() => c.complete_effect(request, request.bytes),
                _ => Err(nt_fs::AsyncSnapshotCommitError::Incomplete),
            },
            Self::Rollover(c) if bytes.is_empty() => unsafe { c.complete(request, true) },
            Self::Rollover(_) => Err(nt_fs::AsyncSnapshotCommitError::Incomplete),
        }
    }
}

struct Active {
    id: u64,
    prepared: Option<nt_config_client::PreparedSystemHiveCheckpoint>,
    lease: snapshot_storage::Lease,
    token: nt_fs::RegistryWalContinuation,
    old_pair: Option<nt_fs::VerifiedPairedWalSnapshot>,
    manifest: nt_fs::WalSnapshotManifest,
    bytes: usize,
    cursor: Option<Cursor>,
    entered: bool,
    failed: bool,
}

enum Work {
    Rechecking { id: u64, prepared: Option<nt_config_client::PreparedSystemHiveCheckpoint>,
        manifest: nt_fs::WalSnapshotManifest },
    Active(Active),
    // A local pre-write contradiction also retains the physical owner until boot recovery.
    Stalled { _lease: snapshot_storage::Lease, _token: nt_fs::RegistryWalContinuation,
        _pair: Option<nt_fs::VerifiedPairedWalSnapshot>,
        _prepared: Option<nt_config_client::PreparedSystemHiveCheckpoint> },
}

static mut WORK: Option<Work> = None;

#[must_use = "retain through native provider terminal and ACK"]
pub(crate) struct FoldTicket { id: u64, request: AsyncSnapshotRequest }

fn fold_manifest(old: nt_fs::WalSnapshotManifest) -> nt_fs::WalSnapshotManifest {
    nt_fs::WalSnapshotManifest { incarnation: old.incarnation,
        base_serial: old.high_water_serial, high_water_serial: old.high_water_serial,
        high_water_end_lba: old.high_water_end_lba }
}

unsafe fn advance_recheck() -> Result<(), u32> {
    let slot = &mut *core::ptr::addr_of_mut!(WORK);
    let Some(Work::Rechecking { id, .. }) = slot.as_ref() else { return Ok(()); };
    let id = *id;
    let (lease, token, proof) = match snapshot_storage::take_rechecked_wal_continuation(id) {
        Ok(Some(parts)) => parts,
        Ok(None) => return Err(snapshot_storage::BUSY),
        Err(status) => {
            if snapshot_storage::recheck_was_aborted_no_effect(id) {
                let _ = slot.take();
            }
            return Err(status);
        }
    };
    let Some(Work::Rechecking { mut prepared, manifest, .. }) = slot.take()
        else { unreachable!() };
    let pair = proof.into_pair();
    if pair.manifest() != manifest || pair.anchor() != token.anchor() {
        *slot = Some(Work::Stalled { _lease: lease, _token: token, _pair: Some(pair),
            _prepared: prepared });
        return Err(block(nt_fs::STATUS_DATA_ERROR));
    }
    let Some(fs) = (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).as_ref() else {
        *slot = Some(Work::Stalled { _lease: lease, _token: token, _pair: Some(pair),
            _prepared: prepared });
        return Err(block(nt_fs::STATUS_DEVICE_NOT_READY));
    };
    // Derive an independent volume from the exact resident image. It has its own node tree,
    // mount manager, and empty handle table; only this private volume sees the prepared bytes
    // while native writes and CM acknowledgement are pending.
    let baseline = match snapshot_capture::CapturedSnapshot::capture(&lease, fs) {
        Ok(image) => image,
        Err(status) => {
            *slot = Some(Work::Stalled { _lease: lease, _token: token, _pair: Some(pair),
                _prepared: prepared });
            return Err(block(status));
        }
    };
    let mut staged = match nt_fs::FileSystem::from_volume_snapshot(baseline.as_slice()) {
        Ok(fs) => fs,
        Err(_) => {
            *slot = Some(Work::Stalled { _lease: lease, _token: token, _pair: Some(pair),
                _prepared: prepared });
            return Err(block(nt_fs::STATUS_DATA_ERROR));
        }
    };
    drop(baseline);
    if let Err(status) = stage_prepared_checkpoint(&mut staged, &prepared) {
        *slot = Some(Work::Stalled { _lease: lease, _token: token, _pair: Some(pair),
            _prepared: prepared });
        return Err(block(status));
    }
    let image = match snapshot_capture::CapturedSnapshot::capture(&lease, &staged) {
        Ok(image) => image,
        Err(status) => {
            *slot = Some(Work::Stalled { _lease: lease, _token: token, _pair: Some(pair),
                _prepared: prepared });
            return Err(block(status));
        }
    };
    let bytes = image.as_slice().len();
    let commit = match AsyncSnapshotCommit::new(lease.store(), image, fold_manifest(manifest),
        lease.sector_size(), lease.sector_count()) {
        Ok(commit) => commit,
        Err(error) => {
            *slot = Some(Work::Stalled { _lease: lease, _token: token, _pair: Some(pair),
                _prepared: prepared });
            return Err(block(snapshot_store_error_status(error)));
        }
    };
    *slot = Some(Work::Active(Active { id, prepared, lease, token, old_pair: Some(pair),
        manifest, bytes, cursor: Some(Cursor::First(commit)), entered: false, failed: false }));
    Ok(())
}

pub(super) unsafe fn fold_system_wal_native() -> Result<bool, u32> {
    let _durable = crate::allocator::enter_durable();
    if (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).is_none()
        || legacy_snapshot_writes_allowed()
        || WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire) {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    }
    if (&*core::ptr::addr_of!(WORK)).is_some() {
        advance_recheck()?;
        return Err(snapshot_storage::BUSY);
    }
    let lease = snapshot_storage::acquire()?;
    let manifest = snapshot_storage::cached_wal_manifest(&lease).map_err(block)?;
    let prepared = crate::config_manager_prepare_system_hive_checkpoint()
        .map_err(|status| status as u32)?;
    if prepared.is_none() && SYSTEM_WAL_FOLD_REQUIRED.load(Ordering::Acquire) {
        return Err(block(nt_fs::STATUS_DATA_ERROR));
    }
    if prepared.is_none() && manifest.base_serial == manifest.high_water_serial {
        return Ok(false);
    }
    let id = snapshot_storage::begin_wal_continuation_recheck_with_lease(lease)?;
    *core::ptr::addr_of_mut!(WORK) = Some(Work::Rechecking { id, prepared, manifest });
    mark_snapshot_dirty();
    Err(snapshot_storage::BUSY)
}

pub(crate) unsafe fn claim_next() -> Option<native_snapshot_io::SnapshotClaim> {
    let _durable = crate::allocator::enter_durable();
    if advance_recheck().is_err() { return None; }
    let Some(Work::Active(active)) = (&mut *core::ptr::addr_of_mut!(WORK)).as_mut()
        else { return None; };
    if active.entered || active.failed { return None; }
    let request = match active.cursor.as_mut().expect("active fold cursor").enter_next() {
        Ok(Some(request)) => request,
        Ok(None) | Err(nt_fs::AsyncSnapshotCommitError::Outstanding) => return None,
        Err(_) => { active.failed = true; block(nt_fs::STATUS_DEVICE_NOT_READY); return None; }
    };
    let operation = match request.kind {
        AsyncSnapshotIoKind::Flush => nt_fs::BlockOperation::Flush,
        AsyncSnapshotIoKind::Read | AsyncSnapshotIoKind::Write => {
            let sectors = u32::try_from(request.bytes / 512).ok().filter(|count| {
                *count > 0 && *count as usize * 512 == request.bytes
                    && request.lba.checked_add(u64::from(*count))
                        .is_some_and(|end| end <= active.lease.sector_count())
            });
            let lba = sectors.and_then(|_| snapshot_storage::physical_lba(&active.lease, request.lba).ok());
            let (Some(sectors), Some(lba)) = (sectors, lba) else {
                active.failed = true; block(nt_fs::STATUS_INVALID_PARAMETER); return None;
            };
            if request.kind == AsyncSnapshotIoKind::Read {
                nt_fs::BlockOperation::Read { lba, sectors }
            } else { nt_fs::BlockOperation::Write { lba, sectors } }
        }
    };
    let mut input = Vec::new();
    let input_len = active.cursor.as_ref().expect("active fold cursor")
        .write_bytes(request).map(<[u8]>::len);
    if let Some(len) = input_len {
        if input.try_reserve_exact(len).is_err() {
            let _ = active.cursor.as_mut().expect("active fold cursor").release_unentered(request);
            return None;
        }
        let bytes = active.cursor.as_ref().expect("active fold cursor")
            .write_bytes(request).expect("checked fold write buffer");
        input.extend_from_slice(bytes);
    }
    Some(native_snapshot_io::SnapshotClaim::from_fold(*active.lease.identity(), operation,
        input, FoldTicket { id: active.id, request }))
}

pub(crate) unsafe fn mark_entered(ticket: &FoldTicket) -> Result<(), u32> {
    let Some(Work::Active(active)) = (&mut *core::ptr::addr_of_mut!(WORK)).as_mut()
        else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if active.id != ticket.id || active.entered || active.failed
        || active.cursor.as_ref().expect("active fold cursor").pending() != Some(ticket.request) {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    active.entered = true;
    Ok(())
}

pub(crate) unsafe fn release_unentered(ticket: FoldTicket) -> Result<(), u32> {
    let Some(Work::Active(active)) = (&mut *core::ptr::addr_of_mut!(WORK)).as_mut()
        else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if active.id != ticket.id || active.entered || active.failed {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    active.cursor.as_mut().expect("active fold cursor").release_unentered(ticket.request)
        .map_err(|_| nt_fs::STATUS_INVALID_DEVICE_REQUEST)
}

pub(crate) unsafe fn refuse_unentered(ticket: FoldTicket, status: nt_status::NtStatus)
    -> Result<(), u32> {
    let Some(Work::Active(active)) = (&mut *core::ptr::addr_of_mut!(WORK)).as_mut()
        else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if active.id != ticket.id || active.entered || active.failed {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    active.cursor.as_mut().expect("active fold cursor").lose(ticket.request);
    active.failed = true;
    block(status.0 as u32);
    Ok(())
}

pub(crate) unsafe fn complete(ticket: FoldTicket, result: Result<&[u8], nt_status::NtStatus>)
    -> Result<(), u32> {
    let slot = &mut *core::ptr::addr_of_mut!(WORK);
    let Some(Work::Active(active)) = slot.as_mut()
        else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if active.id != ticket.id || !active.entered || active.failed
        || active.cursor.as_ref().expect("active fold cursor").pending() != Some(ticket.request) {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    let completed = match result {
        Ok(bytes) => unsafe { active.cursor.as_mut().expect("active fold cursor").complete(ticket.request, bytes) },
        Err(_) => Err(nt_fs::AsyncSnapshotCommitError::Store(nt_fs::SnapshotBlockStoreError::Io)),
    };
    if completed.is_err() {
        active.failed = true;
        return Err(block(nt_fs::STATUS_DEVICE_NOT_READY));
    }
    active.entered = false;
    if !active.cursor.as_ref().expect("active fold cursor").is_done() { return Ok(()); }
    let Some(Work::Active(mut active)) = slot.take() else { unreachable!() };
    match active.cursor.take().expect("completed fold cursor") {
        Cursor::First(commit) => {
            // Every request above was completed by the native executor after terminal + ACK.
            let (image, generation, pair) = match unsafe { commit.finish_with_payload_and_paired_proof() } {
                Ok(parts) => parts,
                Err(commit) => {
                    active.cursor = Some(Cursor::First(commit));
                    active.failed = true;
                    *slot = Some(Work::Active(active));
                    return Err(block(nt_fs::STATUS_DATA_ERROR));
                }
            };
            if pair.anchor() != active.token.anchor() {
                active.old_pair = Some(pair);
                return Err(stall(slot, active, nt_fs::STATUS_DATA_ERROR));
            }
            active.old_pair = None;
            WRITABLE_FS_SNAPSHOT_COMMITS.fetch_add(1, Ordering::Relaxed);
            WRITABLE_FS_SNAPSHOT_COMMIT_GENERATION.store(generation, Ordering::Relaxed);
            WRITABLE_FS_SNAPSHOT_COMMIT_BYTES.store(active.bytes as u64, Ordering::Relaxed);
            let second = match AsyncSnapshotCommit::new(active.lease.store(), image,
                fold_manifest(active.manifest), active.lease.sector_size(), active.lease.sector_count()) {
                Ok(second) => second,
                Err(error) => return Err(stall(slot, active, snapshot_store_error_status(error))),
            };
            active.cursor = Some(Cursor::Second(second));
            *slot = Some(Work::Active(active));
        }
        Cursor::Second(commit) => {
            let (_image, generation, pair) = match unsafe { commit.finish_with_payload_and_paired_proof() } {
                Ok(parts) => parts,
                Err(commit) => {
                    active.cursor = Some(Cursor::Second(commit));
                    active.failed = true;
                    *slot = Some(Work::Active(active));
                    return Err(block(nt_fs::STATUS_DATA_ERROR));
                }
            };
            WRITABLE_FS_SNAPSHOT_COMMITS.fetch_add(1, Ordering::Relaxed);
            WRITABLE_FS_SNAPSHOT_COMMIT_GENERATION.store(generation, Ordering::Relaxed);
            WRITABLE_FS_SNAPSHOT_COMMIT_BYTES.store(active.bytes as u64, Ordering::Relaxed);
            if pair.anchor() != active.token.anchor() {
                active.old_pair = Some(pair);
                return Err(stall(slot, active, nt_fs::STATUS_DATA_ERROR));
            }
            active.old_pair = Some(pair);
            let (start, sectors) = match snapshot_storage::wal_bounds(&active.lease) {
                Ok(bounds) => bounds,
                Err(status) => return Err(stall(slot, active, status)),
            };
            if needs_epoch_rollover(active.manifest.high_water_end_lba, sectors) {
                let Some(next) = active.manifest.incarnation.checked_add(1) else {
                    return Err(stall(slot, active, nt_fs::STATUS_DATA_ERROR));
                };
                let pair = active.old_pair.take().expect("second folded pair retained");
                let cursor = match AsyncWalEpochRollover::admit(active.lease.store(), pair,
                    start, sectors, next, active.lease.sector_size(), active.lease.sector_count())
                { Ok(cursor) => cursor,
                    Err((error, pair)) => {
                        active.old_pair = Some(pair);
                        return Err(stall(slot, active, snapshot_store_error_status(error)));
                    }
                };
                active.cursor = Some(Cursor::Rollover(cursor));
                *slot = Some(Work::Active(active));
            } else {
                let pair = active.old_pair.take().expect("second folded pair retained");
                publish_ready(active, None, pair);
            }
        }
        Cursor::Rollover(cursor) => {
            let (next, pair) = match cursor.finish() {
                Ok(parts) => parts,
                Err(cursor) => {
                    active.cursor = Some(Cursor::Rollover(cursor));
                    active.failed = true;
                    *slot = Some(Work::Active(active));
                    return Err(block(nt_fs::STATUS_DATA_ERROR));
                }
            };
            publish_ready(active, Some(next), pair);
        }
    }
    Ok(())
}

fn stall(slot: &mut Option<Work>, active: Active, status: u32) -> u32 {
    *slot = Some(Work::Stalled { _lease: active.lease, _token: active.token,
        _pair: active.old_pair, _prepared: active.prepared });
    block(status)
}

unsafe fn publish_ready(active: Active,
    next: Option<nt_fs::RegistryWalContinuation>,
    pair: nt_fs::VerifiedPairedWalSnapshot,
) {
    let old = if next.is_none() { Some(active.token) } else { None };
    *core::ptr::addr_of_mut!(FOLD_WORK) = Some(FoldWork {
        prepared: active.prepared, lease: active.lease,
        old_continuation: old, old_pair: active.old_pair,
        next_continuation: next, next_pair: Some(pair),
        publish_prepared_after_ack: true, phase: Phase::Acknowledging,
    });
}
