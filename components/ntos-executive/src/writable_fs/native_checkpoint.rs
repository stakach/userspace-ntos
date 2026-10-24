//! Retained native snapshot checkpoint after the boot AHCI route has drained.

use super::*;
use alloc::vec::Vec;
use nt_fs::{AsyncSnapshotCommit, AsyncSnapshotIoKind, AsyncSnapshotRequest};

type Commit = AsyncSnapshotCommit<snapshot_capture::CapturedSnapshot>;

enum Work {
    Rechecking { id: u64 },
    Committing {
        id: u64,
        lease: snapshot_storage::Lease,
        token: nt_fs::RegistryWalContinuation,
        old_proof: nt_fs::RecheckedPairedWalSnapshot,
        commit: Commit,
        bytes: usize,
        entered: bool,
        failed: bool,
    },
    Done { generation: u64, bytes: usize },
}

static mut WORK: Option<Work> = None;

#[must_use = "retain through exact native terminal and ACK"]
pub(super) struct CheckpointTicket { id: u64, request: AsyncSnapshotRequest }

fn block(status: u32) -> u32 {
    WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
    status
}

/// Progress admission only from the outer service turn. The recheck owner holds the reserve
/// while its two native header reads are outstanding; no synchronous disk access occurs here.
unsafe fn advance_recheck() -> Result<(), u32> {
    let _durable = crate::allocator::enter_durable();
    let slot = &mut *core::ptr::addr_of_mut!(WORK);
    let Some(Work::Rechecking { id }) = slot.as_ref() else { return Ok(()); };
    let id = *id;
    let Some((lease, token, proof)) = snapshot_storage::take_rechecked_wal_continuation(id)?
        else { return Err(snapshot_storage::BUSY); };
    let Some(fs) = (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).as_ref() else {
        WRITABLE_FS_SNAPSHOT_DIRTY.store(true, Ordering::Release);
        let status = super::restore_unwritten_checkpoint_authority(lease,
            Some((token, proof.into_pair())), nt_fs::STATUS_INVALID_HANDLE);
        *slot = None;
        return Err(status);
    };
    let image = match snapshot_capture::CapturedSnapshot::capture(&lease, fs) {
        Ok(image) => image,
        Err(status) => {
            WRITABLE_FS_SNAPSHOT_DIRTY.store(true, Ordering::Release);
            let status = super::restore_unwritten_checkpoint_authority(lease,
                Some((token, proof.into_pair())), status);
            *slot = None;
            return Err(status);
        }
    };
    let bytes = image.as_slice().len();
    let commit = match AsyncSnapshotCommit::new(lease.store(), image,
        proof.manifest(), lease.sector_size(), lease.sector_count()) {
        Ok(commit) => commit,
        Err(error) => {
            WRITABLE_FS_SNAPSHOT_DIRTY.store(true, Ordering::Release);
            let status = super::restore_unwritten_checkpoint_authority(lease,
                Some((token, proof.into_pair())), snapshot_store_error_status(error));
            *slot = None;
            return Err(status);
        }
    };
    *slot = Some(Work::Committing { id, lease, token, old_proof: proof,
        commit, bytes, entered: false, failed: false });
    Ok(())
}

pub(super) unsafe fn checkpoint_dirty_native() -> Result<bool, u32> {
    if (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).is_none() {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    }
    if legacy_snapshot_writes_allowed() || WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire) {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    }
    let slot = &mut *core::ptr::addr_of_mut!(WORK);
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
    // Clean observations still acquire the exact reserve as a durability exclusion barrier.
    if !WRITABLE_FS_SNAPSHOT_DIRTY.load(Ordering::Acquire) {
        let lease = snapshot_storage::acquire()?;
        drop(lease);
        return Ok(false);
    }
    let id = snapshot_storage::begin_wal_continuation_recheck()?;
    WRITABLE_FS_SNAPSHOT_DIRTY.store(false, Ordering::Release);
    *slot = Some(Work::Rechecking { id });
    Err(snapshot_storage::BUSY)
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
                    && request.lba.checked_add(u64::from(*sectors))
                        .is_some_and(|end| end <= lease.store().sector_count())
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
    result: Result<&[u8], nt_status::NtStatus>) -> Result<(), u32>
{
    let slot = &mut *core::ptr::addr_of_mut!(WORK);
    let Some(Work::Committing { id, commit, entered, failed, .. }) = slot.as_mut()
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
        return Err(block(nt_fs::STATUS_DEVICE_NOT_READY));
    }
    *entered = false;
    if !commit.is_done() { return Ok(()); }
    let Some(Work::Committing { lease, token, old_proof, commit, bytes, .. }) = slot.take()
        else { unreachable!() };
    // Every cursor completion above came from exact native provider terminal + ACK.
    let (generation, pair) = match unsafe { commit.finish_with_paired_proof() } {
        Ok(result) => result,
        Err(commit) => {
            core::mem::forget(commit);
            core::mem::forget(lease);
            core::mem::forget(token);
            core::mem::forget(old_proof);
            return Err(block(nt_fs::STATUS_DATA_ERROR));
        }
    };
    if pair.anchor() != token.anchor() {
        core::mem::forget(lease);
        core::mem::forget(token);
        core::mem::forget(old_proof);
        core::mem::forget(pair);
        return Err(block(nt_fs::STATUS_DATA_ERROR));
    }
    drop(old_proof);
    if let Err((status, token, pair)) = snapshot_storage::install_wal_continuation(&lease, token, pair) {
        core::mem::forget(lease);
        core::mem::forget(token);
        core::mem::forget(pair);
        return Err(block(status));
    }
    drop(lease);
    *slot = Some(Work::Done { generation, bytes });
    Ok(())
}
