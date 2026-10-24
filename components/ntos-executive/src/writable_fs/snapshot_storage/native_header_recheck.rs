//! Retained native header recheck before transferring a paired WAL snapshot proof.

use super::*;

#[must_use = "retain until exact native terminal and acknowledgement"]
pub(crate) struct SnapshotStorageTicket {
    owner_id: u64,
    request: nt_fs::AsyncSnapshotRequest,
}

enum HeaderState {
    Running(nt_fs::AsyncSnapshotHeaderRecheck),
    Ready(nt_fs::RecheckedPairedWalSnapshot),
    Transitioning,
    Aborted,
}

struct PendingHeader {
    id: u64,
    lease: Option<Lease>,
    token: Option<nt_fs::RegistryWalContinuation>,
    state: HeaderState,
    entered: bool,
    failed: Option<u32>,
}

static mut PENDING_HEADER: Option<PendingHeader> = None;
static mut NEXT_HEADER_ID: u64 = 1;
static LAST_NO_EFFECT_ABORT_ID: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// True only after the original pair/token were restored under the exact lease and the
/// refused native read was proven unentered. Callers may then release their preparation.
pub(crate) fn recheck_was_aborted_no_effect(id: u64) -> bool {
    id != 0 && LAST_NO_EFFECT_ABORT_ID.load(Ordering::Acquire) == id
}

/// Move the mounted proof and exact reserve lease into one asynchronous recheck owner.
/// A refused admission restores the original proof before any native effect enters.
pub(crate) unsafe fn begin_wal_continuation_recheck() -> Result<u64, u32> {
    let lease = acquire()?;
    begin_wal_continuation_recheck_with_lease(lease)
}

/// Fold admission first holds this lease while CM chooses the matching checkpoint generation.
/// Transfer that same physical owner into native header recheck without an exclusion gap.
pub(crate) unsafe fn begin_wal_continuation_recheck_with_lease(lease: Lease) -> Result<u64, u32> {
    if (&*core::ptr::addr_of!(PENDING_HEADER)).is_some() { return Err(BUSY); }
    let mount = checked_mount(&lease)?;
    let slot = &mut *core::ptr::addr_of_mut!(WAL_CONTINUATION);
    let Some(cached) = slot.as_ref() else { return Err(nt_fs::STATUS_DEVICE_NOT_READY); };
    if cached.mount != mount || cached.token.anchor() != cached.pair.anchor() {
        return Err(nt_fs::STATUS_DATA_ERROR);
    }
    let id = *core::ptr::addr_of!(NEXT_HEADER_ID);
    let next = id.checked_add(1).ok_or(nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
    let cached = slot.take().expect("checked mounted continuation");
    let recheck = match nt_fs::AsyncSnapshotHeaderRecheck::new(
        lease.store(), cached.pair, lease.sector_size(), lease.sector_count()) {
        Ok(owner) => owner,
        Err((error, pair)) => {
            *slot = Some(MountedWalContinuation { mount, token: cached.token, pair });
            return Err(super::super::snapshot_store_error_status(error));
        }
    };
    *core::ptr::addr_of_mut!(NEXT_HEADER_ID) = next;
    *core::ptr::addr_of_mut!(PENDING_HEADER) = Some(PendingHeader {
        id, lease: Some(lease), token: Some(cached.token),
        state: HeaderState::Running(recheck), entered: false, failed: None,
    });
    Ok(id)
}

pub(crate) unsafe fn claim_next_storage_io()
    -> Option<crate::writable_fs::native_snapshot_io::SnapshotClaim>
{
    let owner = (&mut *core::ptr::addr_of_mut!(PENDING_HEADER)).as_mut()?;
    if owner.failed.is_some() { return None; }
    let HeaderState::Running(recheck) = &mut owner.state else { return None; };
    let request = match recheck.enter_next() { Ok(Some(request)) => request, _ => return None };
    let lease = owner.lease.as_ref().expect("header owner retains reserve lease");
    let lba = match physical_lba(lease, request.lba) {
        Ok(lba) => lba,
        Err(_) => {
            recheck.release_unentered(request).expect("unentered header request");
            owner.failed = Some(nt_fs::STATUS_INVALID_PARAMETER);
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            return None;
        }
    };
    let sectors = match u32::try_from(request.bytes / 512) {
        Ok(sectors) if sectors != 0 && usize::try_from(sectors).ok()
            .and_then(|sectors| sectors.checked_mul(512)) == Some(request.bytes) => sectors,
        _ => {
            recheck.release_unentered(request).expect("unentered header request");
            owner.failed = Some(nt_fs::STATUS_INVALID_PARAMETER);
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            return None;
        }
    };
    Some(crate::writable_fs::native_snapshot_io::SnapshotClaim::from_storage(
        *lease.identity(), nt_fs::BlockOperation::Read { lba, sectors },
        alloc::vec::Vec::new(), SnapshotStorageTicket { owner_id: owner.id, request }))
}

pub(crate) unsafe fn mark_storage_io_entered(ticket: &SnapshotStorageTicket) -> Result<(), u32> {
    let owner = (&mut *core::ptr::addr_of_mut!(PENDING_HEADER)).as_mut()
        .ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    let HeaderState::Running(recheck) = &owner.state else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if owner.id != ticket.owner_id || owner.entered || owner.failed.is_some()
        || recheck.pending() != Some(ticket.request) {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    owner.entered = true;
    Ok(())
}

pub(crate) unsafe fn release_unentered_storage_io(ticket: SnapshotStorageTicket) -> Result<(), u32> {
    let owner = (&mut *core::ptr::addr_of_mut!(PENDING_HEADER)).as_mut()
        .ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    let HeaderState::Running(recheck) = &mut owner.state else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if owner.id != ticket.owner_id || owner.entered || owner.failed.is_some() {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    recheck.release_unentered(ticket.request)
        .map_err(|_| nt_fs::STATUS_INVALID_DEVICE_REQUEST)
}

/// A definite local refusal before the exact request enters has no disk effect. Completed
/// earlier reads are also no-effect, so restore the original pair under the same lease and
/// report the refusal once to the waiting owner. An entered/uncertain request cannot use this.
pub(crate) unsafe fn refuse_unentered_storage_io(
    ticket: SnapshotStorageTicket, status: nt_status::NtStatus,
) -> Result<(), u32> {
    let owner = (&mut *core::ptr::addr_of_mut!(PENDING_HEADER)).as_mut()
        .ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    let HeaderState::Running(recheck) = &mut owner.state else {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    };
    if owner.id != ticket.owner_id || owner.entered || owner.failed.is_some()
        || recheck.pending() != Some(ticket.request) {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    recheck.release_unentered(ticket.request)
        .map_err(|_| nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    let HeaderState::Running(recheck) = core::mem::replace(&mut owner.state, HeaderState::Transitioning)
        else { unreachable!() };
    let pair = match recheck.abort_no_effect() {
        Ok(pair) => pair,
        Err(recheck) => {
            owner.state = HeaderState::Running(recheck);
            owner.failed = Some(nt_fs::STATUS_DATA_ERROR);
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            return Err(nt_fs::STATUS_DATA_ERROR);
        }
    };
    let lease = owner.lease.take().expect("no-effect header owner retains lease");
    let token = owner.token.take().expect("no-effect header owner retains token");
    if let Err((error, token, pair)) = install_wal_continuation(&lease, token, pair) {
        core::mem::forget(lease);
        core::mem::forget(token);
        core::mem::forget(pair);
        owner.failed = Some(error);
        WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
        return Err(error);
    }
    drop(lease);
    LAST_NO_EFFECT_ABORT_ID.store(owner.id, Ordering::Release);
    owner.failed = Some(status.0 as u32);
    owner.state = HeaderState::Aborted;
    Ok(())
}

pub(crate) unsafe fn complete_storage_io(ticket: SnapshotStorageTicket,
    result: Result<&[u8], nt_status::NtStatus>) -> Result<(), u32>
{
    let owner = (&mut *core::ptr::addr_of_mut!(PENDING_HEADER)).as_mut()
        .ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    let HeaderState::Running(recheck) = &mut owner.state else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if owner.id != ticket.owner_id || !owner.entered || owner.failed.is_some()
        || recheck.pending() != Some(ticket.request) {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(_) => {
            owner.failed = Some(nt_fs::STATUS_DEVICE_NOT_READY);
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            return Err(nt_fs::STATUS_DEVICE_NOT_READY);
        }
    };
    if recheck.complete_read(ticket.request, bytes).is_err() {
        owner.failed = Some(nt_fs::STATUS_DATA_ERROR);
        WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
        return Err(nt_fs::STATUS_DATA_ERROR);
    }
    owner.entered = false;
    if recheck.is_done() {
        let HeaderState::Running(recheck) = core::mem::replace(&mut owner.state,
            HeaderState::Transitioning) else { unreachable!() };
        // The two read completions came through the outer native executor after exact ACK.
        owner.state = match unsafe { recheck.finish_proven() } {
            Ok(proof) => HeaderState::Ready(proof),
            Err(recheck) => HeaderState::Running(recheck),
        };
    }
    Ok(())
}

/// Transfer the exact lease and proof only after both authenticated native reads completed.
pub(crate) unsafe fn take_rechecked_wal_continuation(id: u64)
    -> Result<Option<(Lease, nt_fs::RegistryWalContinuation,
        nt_fs::RecheckedPairedWalSnapshot)>, u32>
{
    let slot = &mut *core::ptr::addr_of_mut!(PENDING_HEADER);
    let Some(owner) = slot.as_ref() else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if owner.id != id { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); }
    if matches!(&owner.state, HeaderState::Aborted) {
        let status = owner.failed.expect("aborted header retains refusal status");
        let _ = slot.take();
        return Err(status);
    }
    if let Some(error) = owner.failed { return Err(error); }
    if !matches!(&owner.state, HeaderState::Ready(..)) { return Ok(None); }
    let mut owner = slot.take().expect("checked ready header owner");
    let HeaderState::Ready(proof) = owner.state else { unreachable!() };
    let lease = owner.lease.take().expect("ready header owner retains lease");
    let token = owner.token.take().expect("ready header owner retains WAL token");
    if token.anchor() != manifest_anchor(proof.manifest()) || token.anchor() != proof.anchor() {
        WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
        core::mem::forget(lease);
        core::mem::forget(token);
        core::mem::forget(proof);
        return Err(nt_fs::STATUS_DATA_ERROR);
    }
    Ok(Some((lease, token, proof)))
}
