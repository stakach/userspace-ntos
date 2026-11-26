//! Retained native snapshot checkpoint after the boot AHCI route has drained.

use super::*;
use alloc::vec::Vec;
use nt_fs::{AsyncSnapshotCommit, AsyncSnapshotIoKind, AsyncSnapshotRequest};

type Commit = AsyncSnapshotCommit<snapshot_capture::CapturedSnapshot>;

enum Work {
    Rechecking { id: u64, started_ticks: u64, start_after_print: bool, trace: bool,
        capture_epoch: nt_fs::SnapshotCaptureEpoch<'static> },
    /// The exact header read was refused before entry and restored its original WAL proof.
    /// The outer I/O pump may see the refusal first; retain it for the service boundary.
    NoEffectRefused { id: u64, status: u32 },
    Committing {
        capture_epoch: nt_fs::SnapshotCaptureEpoch<'static>,
        id: u64,
        started_ticks: u64,
        start_after_print: bool,
        trace: bool,
        write_sectors: u64,
        lease: snapshot_storage::Lease,
        token: nt_fs::RegistryWalContinuation,
        commit: Commit,
        bytes: usize,
        entered: bool,
        failed: bool,
        /// Native requests this commit has completed.
        settled: u64,
    },
    Done { generation: u64, bytes: usize },
}

static mut WORK: Option<Work> = None;
static CHECKPOINT_MEASURES: AtomicU64 = AtomicU64::new(0);
static CHECKPOINT_MEASURE_LIMIT_REPORTED: AtomicBool = AtomicBool::new(false);

fn reserve_trace() -> bool {
    const LIMIT: u64 = 2048;
    CHECKPOINT_MEASURES.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |used| (used < LIMIT).then_some(used + 1)).is_ok()
}

fn trace_started(id: u64, epoch: u64, trace: bool) {
    if trace {
        print_str(b"[writable-fs-checkpoint-measure] begin id/epoch=");
        print_u64(id); print_str(b"/"); print_u64(epoch); print_str(b"\n");
    } else if !CHECKPOINT_MEASURE_LIMIT_REPORTED.swap(true, Ordering::AcqRel) {
        print_str(b"[writable-fs-checkpoint-measure] trace-limit-exhausted=2048\n");
    }
}

pub(super) unsafe fn print_quiesce_owner() {
    let work = (&*core::ptr::addr_of!(WORK)).as_ref();
    print_str(b"[quiesce-native-checkpoint] phase=");
    print_str(match work {
        None => b"absent",
        Some(Work::Rechecking { .. }) => b"rechecking",
        Some(Work::NoEffectRefused { .. }) => b"no-effect-refused",
        Some(Work::Committing { .. }) => b"committing",
        Some(Work::Done { .. }) => b"done",
    });
    let (id, lease, entered, failed) = match work {
        Some(Work::Rechecking { id, .. }) => (*id, false, false, false),
        Some(Work::NoEffectRefused { id, .. }) => (*id, false, false, false),
        Some(Work::Committing { id, entered, failed, .. }) =>
            (*id, true, *entered, *failed),
        Some(Work::Done { .. }) | None => (0, false, false, false),
    };
    print_str(b" id="); print_u64(id);
    print_str(b" local-lease="); print_u64(u64::from(lease));
    print_str(b" entered="); print_u64(u64::from(entered));
    print_str(b" failed="); print_u64(u64::from(failed));
    if let Some(Work::NoEffectRefused { status, .. }) = work {
        print_str(b" refusal=0x"); print_hex(*status);
    }
    print_str(b"\n");
}

pub(super) unsafe fn progress() -> super::CheckpointProgress {
    match (&*core::ptr::addr_of!(WORK)).as_ref() {
        None => (0, 0, 0),
        Some(Work::Rechecking { id, .. }) => (1, *id, 0),
        Some(Work::NoEffectRefused { id, .. }) => (4, *id, 0),
        Some(Work::Committing { id, settled, .. }) => (2, *id, *settled),
        Some(Work::Done { generation, .. }) => (3, *generation, 0),
    }
}

#[must_use = "retain through exact native terminal and ACK"]
pub(super) struct CheckpointTicket { id: u64, request: AsyncSnapshotRequest }

fn block(status: u32) -> u32 {
    WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
    status
}

/// Progress admission only from the outer service turn. The recheck owner holds the reserve
/// while its two native header reads are outstanding; no synchronous disk access occurs here.
unsafe fn advance_recheck() -> Result<(), u32> {
    if volume_owner::owns_volume() { return Err(snapshot_storage::BUSY); }
    let _durable = crate::allocator::enter_durable();
    let slot = &mut *core::ptr::addr_of_mut!(WORK);
    let Some(Work::Rechecking { id, started_ticks, start_after_print, trace, .. }) = slot.as_ref()
        else { return Ok(()); };
    let (id, started_ticks, start_after_print, trace) =
        (*id, *started_ticks, *start_after_print, *trace);
    let (lease, token, proof) = match snapshot_storage::take_rechecked_wal_continuation(id) {
        Ok(Some(parts)) => parts,
        Ok(None) => return Err(snapshot_storage::BUSY),
        Err(status) => {
            if snapshot_storage::recheck_was_aborted_no_effect(id) {
                SNAPSHOT_PUBLICATION.abort_unwritten_checkpoint();
                // The header owner restored its exact WAL proof and released the lease before
                // reporting this refusal. Keep one receipt for the service boundary even if
                // the outer I/O pump encountered it first; no new owner may hide the refusal.
                if matches!(slot.as_ref(), Some(Work::Rechecking { id: current, .. }) if *current == id) {
                    *slot = Some(Work::NoEffectRefused { id, status });
                    print_str(b"[writable-fs-checkpoint] no-effect-header-refusal id/status=");
                    print_u64(id); print_str(b"/0x"); print_hex(status); print_str(b"\n");
                }
            } else {
                // A failed entered read or inconsistent proof may still own the reserve. Keep
                // the work slot and forbid a new publisher until recovery establishes state.
                SNAPSHOT_PUBLICATION.mark_dirty();
                block(status);
            }
            return Err(status);
        }
    };
    if !proof.manifest().ordinary_checkpoint_ready() {
        SNAPSHOT_PUBLICATION.mark_dirty();
        let status = super::restore_unwritten_checkpoint_authority(lease,
            Some((token, proof.into_pair())), snapshot_storage::BUSY);
        *slot = None;
        return Err(status);
    }
    let Some(fs) = (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).as_ref() else {
        SNAPSHOT_PUBLICATION.mark_dirty();
        let status = super::restore_unwritten_checkpoint_authority(lease,
            Some((token, proof.into_pair())), nt_fs::STATUS_INVALID_HANDLE);
        *slot = None;
        return Err(status);
    };
    let image = match snapshot_capture::CapturedSnapshot::capture(&lease, fs) {
        Ok(image) => image,
        Err(status) => {
            SNAPSHOT_PUBLICATION.mark_dirty();
            let status = super::restore_unwritten_checkpoint_authority(lease,
                Some((token, proof.into_pair())), status);
            *slot = None;
            return Err(status);
        }
    };
    let bytes = image.as_slice().len();
    // The two headers were just rechecked unchanged under this exclusive reserve against a
    // pair whose payloads were CRC-verified this boot, so no payload sector is reread. The
    // commit retains the proof through every native effect.
    let manifest = proof.manifest();
    let mut commit = match AsyncSnapshotCommit::new_from_rechecked_pair(image, manifest, proof) {
        Ok(commit) => commit,
        Err((error, _image, proof)) => {
            SNAPSHOT_PUBLICATION.mark_dirty();
            let status = super::restore_unwritten_checkpoint_authority(lease,
                Some((token, proof.into_pair())), snapshot_store_error_status(error));
            *slot = None;
            return Err(status);
        }
    };
    commit.set_max_batch_sectors(crate::driver_launch::native_storage_transfer_sectors())
        .expect("a fresh snapshot commit has no request in flight");
    let Some(Work::Rechecking { capture_epoch, .. }) = slot.take() else { unreachable!() };
    *slot = Some(Work::Committing { id, started_ticks, start_after_print, trace, write_sectors: 0,
        capture_epoch, lease, token, commit, bytes, entered: false, failed: false, settled: 0 });
    Ok(())
}

pub(super) unsafe fn checkpoint_dirty_native() -> Result<bool, u32> {
    if volume_owner::owns_volume() { return Err(snapshot_storage::BUSY); }
    if (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).is_none() {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    }
    if legacy_snapshot_writes_allowed() || WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire) {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    }
    let slot = &mut *core::ptr::addr_of_mut!(WORK);
    if let Some(Work::NoEffectRefused { status, .. }) = slot.as_ref() {
        let status = *status;
        // Permanent local refusals are delivered exactly once before a fresh attempt. BUSY
        // never reaches this state: the header owner retains its request and ID for retry.
        *slot = None;
        return Err(status);
    }
    if matches!(slot.as_ref(), Some(Work::Done { .. })) {
        let Some(Work::Done { generation, bytes }) = slot.take() else { unreachable!() };
        WRITABLE_FS_SNAPSHOT_COMMITS.fetch_add(1, Ordering::Relaxed);
        WRITABLE_FS_SNAPSHOT_COMMIT_GENERATION.store(generation, Ordering::Relaxed);
        WRITABLE_FS_SNAPSHOT_COMMIT_BYTES.store(bytes as u64, Ordering::Relaxed);
        return Ok(true);
    }
    if slot.is_some() {
        advance_recheck()?;
        return Err(snapshot_storage::BUSY);
    }
    // Do not let a clean observation or a new snapshot bypass a published SYSTEM
    // batch. The native claim pump completes its marker and paired anchors first.
    super::system_wal_batch_native::request_drain_if_active()?;
    // Clean observations still acquire the exact reserve as a durability exclusion barrier.
    if !SNAPSHOT_PUBLICATION.is_dirty() {
        let lease = snapshot_storage::acquire()?;
        drop(lease);
        return Ok(false);
    }
    // The ordinary image retains its selected replay base. If the WAL has advanced, the
    // two-slot fold must first publish an image with that prefix applied. Keep the dirty bit
    // and continuation intact while the service owner arranges that fold.
    let lease = snapshot_storage::acquire()?;
    let manifest = snapshot_storage::cached_wal_manifest(&lease).map_err(block)?;
    if !manifest.ordinary_checkpoint_ready() {
        return Err(snapshot_storage::BUSY);
    }
    let capture_epoch = SNAPSHOT_PUBLICATION.begin_dirty_capture()
        .map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?
        .ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    let id = snapshot_storage::begin_wal_continuation_recheck_with_lease(lease)?;
    let started_ticks = crate::disk_census_ticks();
    let epoch = super::checkpoint_epochs().0;
    let trace = reserve_trace();
    *slot = Some(Work::Rechecking { id, started_ticks, start_after_print: false, trace,
        capture_epoch });
    trace_started(id, epoch, trace);
    if let Some(Work::Rechecking { id: retained_id, started_ticks,
        start_after_print, .. }) = (&mut *core::ptr::addr_of_mut!(WORK)).as_mut()
    {
        if *retained_id == id {
            *started_ticks = crate::disk_census_ticks();
            *start_after_print = true;
        }
    }
    Err(snapshot_storage::BUSY)
}

/// The header recheck this checkpoint is waiting on, while it is rechecking.
pub(super) unsafe fn recheck_id() -> Option<u64> {
    match (&*core::ptr::addr_of!(WORK)).as_ref() {
        Some(Work::Rechecking { id, .. }) => Some(*id),
        _ => None,
    }
}

/// This checkpoint holds the snapshot reserve (rechecking or committing).
pub(super) unsafe fn holds_reserve() -> bool {
    matches!((&*core::ptr::addr_of!(WORK)).as_ref(),
        Some(Work::Rechecking { .. } | Work::Committing { .. }))
}

/// This checkpoint holds the snapshot reserve and has work only the outer owner may claim.
pub(super) unsafe fn outer_io_queued() -> bool {
    match (&*core::ptr::addr_of!(WORK)).as_ref() {
        Some(Work::Rechecking { id, .. }) => snapshot_storage::header_outer_io_queued(*id),
        Some(Work::Committing { commit, entered, failed, .. }) =>
            !*entered && !*failed && commit.pending().is_none() && !commit.is_done(),
        Some(Work::NoEffectRefused { .. } | Work::Done { .. }) | None => false,
    }
}

pub(super) unsafe fn claim_next() -> Option<native_snapshot_io::SnapshotClaim> {
    let _durable = crate::allocator::enter_durable();
    if advance_recheck().is_err() { return None; }
    let Some(Work::Committing { id, lease, commit, entered, failed, .. }) =
        (&mut *core::ptr::addr_of_mut!(WORK)).as_mut() else { return None; };
    if *entered || *failed { return None; }
    let request = match commit.enter_next() {
        Ok(Some(request)) => request,
        Ok(None) | Err(nt_fs::AsyncSnapshotCommitError::Outstanding) => return None,
        Err(_) => { *failed = true; block(nt_fs::STATUS_DEVICE_NOT_READY); return None; }
    };
    let operation = match request.kind {
        AsyncSnapshotIoKind::Flush => nt_fs::BlockOperation::Flush,
        AsyncSnapshotIoKind::Read | AsyncSnapshotIoKind::Write => {
            let sectors = u32::try_from(request.bytes / 512).ok().filter(|sectors| {
                *sectors != 0 && request.bytes == *sectors as usize * 512
                    && lease.store().contains_sector_range(request.lba, u64::from(*sectors))
            });
            let lba = sectors.and_then(|_| snapshot_storage::physical_lba(lease, request.lba).ok());
            let (Some(sectors), Some(lba)) = (sectors, lba) else {
                *failed = true;
                block(nt_fs::STATUS_INVALID_PARAMETER);
                return None;
            };
            match request.kind {
                AsyncSnapshotIoKind::Read => nt_fs::BlockOperation::Read { lba, sectors },
                AsyncSnapshotIoKind::Write => nt_fs::BlockOperation::Write { lba, sectors },
                _ => unreachable!(),
            }
        }
    };
    let mut input = Vec::new();
    if let Some(bytes) = commit.write_bytes(request) {
        if input.try_reserve_exact(bytes.len()).is_err() {
            commit.release_unentered(request).expect("unentered snapshot allocation");
            return None;
        }
        input.extend_from_slice(bytes);
    }
    Some(native_snapshot_io::SnapshotClaim::from_checkpoint(*lease.identity(),
        operation, input, CheckpointTicket { id: *id, request }))
}

pub(super) unsafe fn mark_entered(ticket: &CheckpointTicket) -> Result<(), u32> {
    let Some(Work::Committing { id, commit, entered, failed, .. }) =
        (&mut *core::ptr::addr_of_mut!(WORK)).as_mut() else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if *id != ticket.id || *entered || *failed || commit.pending() != Some(ticket.request) {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    *entered = true;
    Ok(())
}

pub(super) unsafe fn release_unentered(ticket: CheckpointTicket) -> Result<(), u32> {
    let Some(Work::Committing { id, commit, entered, failed, .. }) =
        (&mut *core::ptr::addr_of_mut!(WORK)).as_mut() else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if *id != ticket.id || *entered || *failed { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); }
    commit.release_unentered(ticket.request)
        .map_err(|_| nt_fs::STATUS_INVALID_DEVICE_REQUEST)
}

pub(super) unsafe fn refuse_unentered(ticket: CheckpointTicket, status: nt_status::NtStatus)
    -> Result<(), u32>
{
    let Some(Work::Committing { id, commit, entered, failed, .. }) =
        (&mut *core::ptr::addr_of_mut!(WORK)).as_mut() else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if *id != ticket.id || *entered || *failed { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); }
    commit.lose(ticket.request).map_err(|_| nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    *failed = true;
    block(status.0 as u32);
    Ok(())
}

pub(super) unsafe fn complete(ticket: CheckpointTicket,
    result: Result<&[u8], nt_status::NtStatus>) -> Result<super::native_snapshot_io::SnapshotCompletion, u32>
{
    use super::native_snapshot_io::SnapshotCompletion;
    let slot = &mut *core::ptr::addr_of_mut!(WORK);
    let Some(Work::Committing { id, lease, commit, entered, failed, settled,
        write_sectors, .. }) = slot.as_mut()
        else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if *id != ticket.id || !*entered || *failed || commit.pending() != Some(ticket.request) {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    let completed = match (ticket.request.kind, result) {
        (AsyncSnapshotIoKind::Read, Ok(bytes)) => commit.complete_read(ticket.request, bytes),
        (AsyncSnapshotIoKind::Write | AsyncSnapshotIoKind::Flush, Ok(bytes)) if bytes.is_empty() =>
            commit.complete_effect(ticket.request, ticket.request.bytes),
        _ => Err(nt_fs::AsyncSnapshotCommitError::Store(nt_fs::SnapshotBlockStoreError::Io)),
    };
    if completed.is_err() {
        *failed = true;
        return Ok(SnapshotCompletion::Failed(block(nt_fs::STATUS_DEVICE_NOT_READY)));
    }
    if ticket.request.kind == AsyncSnapshotIoKind::Write {
        let sector_size = lease.sector_size();
        *write_sectors = write_sectors.saturating_add(
            (ticket.request.bytes / sector_size) as u64);
    }
    *entered = false;
    *settled += 1;
    if !commit.is_done() { return Ok(SnapshotCompletion::Settled); }
    let Some(Work::Committing { capture_epoch, lease, token, commit, bytes, started_ticks,
        start_after_print, trace,
        write_sectors, .. }) = slot.take()
        else { unreachable!() };
    // Every cursor completion above came from exact native provider terminal + ACK.
    let (generation, pair) = match unsafe { commit.finish_with_paired_proof() } {
        Ok(result) => result,
        Err(commit) => {
            core::mem::forget(commit);
            core::mem::forget(lease);
            core::mem::forget(token);
            return Ok(SnapshotCompletion::Failed(block(nt_fs::STATUS_DATA_ERROR)));
        }
    };
    if pair.anchor() != token.anchor() {
        core::mem::forget(lease);
        core::mem::forget(token);
        core::mem::forget(pair);
        return Ok(SnapshotCompletion::Failed(block(nt_fs::STATUS_DATA_ERROR)));
    }
    if let Err((status, token, pair)) = snapshot_storage::install_wal_continuation(&lease, token, pair) {
        core::mem::forget(lease);
        core::mem::forget(token);
        core::mem::forget(pair);
        return Ok(SnapshotCompletion::Failed(block(status)));
    }
    if capture_epoch.publish().is_err() {
        core::mem::forget(lease);
        return Ok(SnapshotCompletion::Failed(block(nt_fs::STATUS_DATA_ERROR)));
    }
    drop(lease);
    *slot = Some(Work::Done { generation, bytes });
    // Rechecking was installed before its begin print. A matching owner refreshes its clock
    // afterward; a reentrant owner retains the earlier safe clock and reports that fact.
    let elapsed_ticks = crate::disk_census_ticks().wrapping_sub(started_ticks);
    if trace {
        print_str(b"[writable-fs-checkpoint-measure] published id/generation/bytes/write-sectors/elapsed-tsc/start-after-begin-print=");
        for value in [ticket.id, generation, bytes as u64, write_sectors, elapsed_ticks,
            u64::from(start_after_print)] {
            print_str(b"/"); print_u64(value);
        }
        print_str(b"\n");
    }
    Ok(SnapshotCompletion::Settled)
}
