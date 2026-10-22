//! Retained native publication of a non-SYSTEM hive log record.

use super::*;
use alloc::{string::String, vec::Vec};
use nt_fs::{
    AnchoredWalPublication, AsyncSnapshotIoKind, AsyncSnapshotRequest,
    AsyncWalIoKind, AsyncWalIoRequest, AsyncWalRefusal, AsyncWalSnapshotAnchorUpdate,
    BlockOperation, OwnedBoundedBlockRange, RecheckedPairedWalSnapshot,
    SnapshotBlockStoreError, RegistryWalState,
};
use nt_memory_manager::SectionMountId;

type Wal = RegistryWal<OwnedBoundedBlockRange<snapshot_storage::Lease>>;
type Anchor = AsyncWalSnapshotAnchorUpdate<snapshot_storage::Lease>;

struct Baseline {
    file_id: u64,
    length: u64,
    last_sequence: u64,
    needs_checkpoint: bool,
}

enum Phase {
    Baseline { started: bool },
    Rechecking { recheck_id: u64 },
    Wal { wal: Wal, proof: RecheckedPairedWalSnapshot,
        store: nt_fs::SnapshotBlockStore,
        mount: SectionMountId, base_lba: u64, snapshot_lba: u64, entered: bool },
    Anchor { update: Anchor, mount: SectionMountId,
        base_lba: u64, entered: bool },
    Ready { lease: snapshot_storage::Lease,
        anchored: Option<AnchoredWalPublication> },
    AwaitInstall { lease: snapshot_storage::Lease },
    Released,
    Failed,
}

struct Journal {
    id: u64,
    path: String,
    record: Vec<u8>,
    encoded: Vec<u8>,
    new_log_len: u64,
    baseline: Baseline,
    phase: Phase,
    failed: Option<u32>,
    wal_entered_ever: bool,
}

static mut JOURNAL: Option<Journal> = None;
static mut NEXT_ID: u64 = 1;

#[derive(Clone, Copy)]
enum HiveRequest { Wal(AsyncWalIoRequest), Anchor(AsyncSnapshotRequest) }

#[must_use = "retain until exact native terminal and acknowledgement"]
pub(crate) struct HiveTicket { id: u64, request: HiveRequest }

impl HiveTicket {
    pub(crate) fn owner_id(&self) -> u64 { self.id }
    pub(crate) fn enters_wal_effect(&self) -> bool { matches!(self.request, HiveRequest::Wal(_)) }
}

pub(crate) struct NativeHiveJournalReceipt {
    pub(crate) id: u64,
    pub(crate) file_id: u64,
    pub(crate) expected_log_len: u64,
    pub(crate) log_path: String,
    pub(crate) anchored: AnchoredWalPublication,
}

fn clone_owned(bytes: &[u8]) -> Result<Vec<u8>, u32> {
    let mut result = Vec::new();
    result.try_reserve_exact(bytes.len()).map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
    result.extend_from_slice(bytes);
    Ok(result)
}

fn clone_path(path: &str) -> Result<String, u32> {
    let mut result = String::new();
    result.try_reserve_exact(path.len()).map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
    result.push_str(path);
    Ok(result)
}

unsafe fn restore_unentered_wal(
    mut wal: Wal, proof: RecheckedPairedWalSnapshot, status: u32,
) -> (u32, bool) {
    if wal.state() == RegistryWalState::PendingPrepare && wal.cancel_pending().is_err() {
        core::mem::forget(wal);
        core::mem::forget(proof);
        return (block(nt_fs::STATUS_DATA_ERROR), false);
    }
    let (range, continuation) = match wal.into_continuation() {
        Ok(parts) => parts,
        Err(wal) => {
            core::mem::forget(wal);
            core::mem::forget(proof);
            return (block(nt_fs::STATUS_DATA_ERROR), false);
        }
    };
    let lease = range.into_device();
    if let Err((error, continuation, pair)) =
        snapshot_storage::install_wal_continuation(&lease, continuation, proof.into_pair()) {
        core::mem::forget(lease);
        core::mem::forget(continuation);
        core::mem::forget(pair);
        return (block(error), false);
    }
    drop(lease);
    (status, true)
}

unsafe fn restore_unentered_recheck(
    lease: snapshot_storage::Lease,
    continuation: nt_fs::RegistryWalContinuation,
    proof: RecheckedPairedWalSnapshot,
    status: u32,
) -> (u32, bool) {
    if let Err((error, continuation, pair)) =
        snapshot_storage::install_wal_continuation(&lease, continuation, proof.into_pair()) {
        core::mem::forget(lease);
        core::mem::forget(continuation);
        core::mem::forget(pair);
        return (block(error), false);
    }
    drop(lease);
    (status, true)
}

unsafe fn inspect_baseline(path: &str, record: &[u8]) -> Result<Baseline, u32> {
    let fs = writable_fs()?;
    if fs.existing_file_id(path).is_none() {
        let created = fs.zw_create_file(path, nt_fs::FILE_WRITE_DATA | nt_fs::SYNCHRONIZE,
            0, 0, nt_fs::FILE_OPEN_IF, nt_fs::FILE_NON_DIRECTORY_FILE);
        if created.status != nt_fs::STATUS_SUCCESS { return Err(created.status); }
        let close = fs.zw_close(created.handle);
        if close != nt_fs::STATUS_SUCCESS { return Err(close); }
        mark_snapshot_dirty();
    }
    let fs = writable_fs()?;
    let file_id = fs.existing_file_id(path).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let length = fs.file_len(path).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let entry = baselines().iter().find(|entry| entry.path == path);
    if let Some(entry) = entry {
        if entry.has_wal_records && (entry.file_id != file_id || length < entry.expected_len) {
            return Err(block(nt_fs::STATUS_DATA_ERROR));
        }
        if entry.has_wal_records && entry.file_id == file_id && entry.expected_len == length {
            let (_, last_sequence) = nt_hive_core::complete_log_sequence_span_from(
                record, entry.last_sequence).map_err(semantic_error)?;
            return Ok(Baseline { file_id, length, last_sequence, needs_checkpoint: false });
        }
    }
    // A new or externally changed stream needs an immutable snapshot before WAL writes.
    mark_snapshot_dirty();
    Ok(Baseline { file_id, length, last_sequence: 0, needs_checkpoint: true })
}

unsafe fn finish_baseline(journal: &mut Journal) -> Result<(), u32> {
    let baseline = &mut journal.baseline;
    if !baseline.needs_checkpoint { return Ok(()); }
    let fs = writable_fs()?;
    if fs.existing_file_id(&journal.path) != Some(baseline.file_id)
        || fs.file_len(&journal.path) != Some(baseline.length) {
        return Err(block(nt_fs::STATUS_DATA_ERROR));
    }
    baseline.last_sequence = validate_first_record(fs, &journal.path,
        baseline.length, &journal.record)?;
    let (first, _) = nt_hive_core::complete_log_sequence_span(&journal.record)
        .map_err(semantic_error)?;
    if let Some(entry) = baselines().iter_mut().find(|entry| entry.path == journal.path) {
        entry.file_id = baseline.file_id;
        entry.expected_len = baseline.length;
        entry.last_sequence = first - 1;
        entry.has_wal_records = false;
    } else {
        baselines().try_reserve(1).map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
        baselines().push(LogBaseline { path: clone_path(&journal.path)?,
            file_id: baseline.file_id, expected_len: baseline.length,
            last_sequence: first - 1, has_wal_records: false });
    }
    baseline.needs_checkpoint = false;
    Ok(())
}

/// Admit one exact record. The caller retains its prepared CM mutation until the receipt is
/// published; a BUSY result means this owner was not admitted and may be retried unchanged.
pub(crate) unsafe fn begin_native_hive_journal(path: &str, record: &[u8]) -> Result<u64, u32> {
    let _durable = crate::allocator::enter_durable();
    if (&*core::ptr::addr_of!(JOURNAL)).is_some() { return Err(snapshot_storage::BUSY); }
    ensure_mounted()?;
    if record.is_empty() || legacy_snapshot_writes_allowed()
        || WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire) {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    let path = clone_path(path)?;
    let record = clone_owned(record)?;
    let baseline = inspect_baseline(&path, &record)?;
    let new_log_len = baseline.length.checked_add(u64::try_from(record.len())
        .map_err(|_| nt_fs::STATUS_INVALID_PARAMETER)?)
        .ok_or(nt_fs::STATUS_INVALID_PARAMETER)?;
    let encoded = nt_fs::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: baseline.file_id, expected_log_len: baseline.length,
        path: &path, record: &record,
    }).map_err(|error| match error {
        nt_fs::VolumeWalPayloadError::OutOfMemory => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
        _ => nt_fs::STATUS_INVALID_PARAMETER,
    })?;
    let id = *core::ptr::addr_of!(NEXT_ID);
    let next = id.checked_add(1)
        .ok_or(nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
    writable_fs()?.protect_wal_log(&path, baseline.file_id)?;
    *core::ptr::addr_of_mut!(NEXT_ID) = next;
    *core::ptr::addr_of_mut!(JOURNAL) = Some(Journal { id, path, record, encoded,
        new_log_len, baseline,
        phase: Phase::Baseline { started: false }, failed: None,
        wal_entered_ever: false });
    Ok(id)
}

pub(crate) unsafe fn poll_native_hive_journal(id: u64)
    -> Result<Option<NativeHiveJournalReceipt>, u32>
{
    let _durable = crate::allocator::enter_durable();
    let slot = &mut *core::ptr::addr_of_mut!(JOURNAL);
    let Some(journal) = slot.as_mut() else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if journal.id != id { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); }
    if let Some(status) = journal.failed { return Err(status); }
    match &mut journal.phase {
        Phase::Baseline { started } => {
            if journal.baseline.needs_checkpoint {
                if !*started { *started = true; }
                match super::native_checkpoint::checkpoint_dirty_native() {
                    Ok(_) => finish_baseline(journal)?,
                    Err(status) if status == snapshot_storage::BUSY => return Ok(None),
                    Err(status) => return Err(status),
                }
            }
            let recheck_id = match snapshot_storage::begin_wal_continuation_recheck() {
                Ok(id) => id,
                Err(status) if status == snapshot_storage::BUSY => return Ok(None),
                Err(status) => return Err(status),
            };
            journal.phase = Phase::Rechecking { recheck_id };
        }
        Phase::Rechecking { recheck_id } => {
            let recheck_id = *recheck_id;
            let (lease, continuation, proof) = match
                snapshot_storage::take_rechecked_wal_continuation(recheck_id) {
                Ok(Some(parts)) => parts,
                Ok(None) => return Ok(None),
                Err(status) => {
                    if snapshot_storage::recheck_was_aborted_no_effect(recheck_id) {
                        journal.phase = Phase::Released;
                    }
                    journal.failed = Some(status);
                    return Err(status);
                }
            };
            let mount = *lease.identity();
            let store = lease.store();
            let snapshot_lba = match snapshot_storage::physical_lba(&lease, 0) {
                Ok(lba) => lba,
                Err(status) => {
                    let (status, restored) = restore_unentered_recheck(
                        lease, continuation, proof, status);
                    journal.phase = if restored { Phase::Released } else { Phase::Failed };
                    journal.failed = Some(status);
                    return Err(block(status));
                }
            };
            let base_lba = match snapshot_storage::physical_lba(&lease,
                crate::fs_loader::WRITABLE_SNAPSHOT_RESERVE_SECTORS as u64) {
                Ok(lba) => lba,
                Err(status) => {
                    let (status, restored) = restore_unentered_recheck(
                        lease, continuation, proof, status);
                    journal.phase = if restored { Phase::Released } else { Phase::Failed };
                    journal.failed = Some(status);
                    return Err(status);
                }
            };
            let anchored = proof.anchor();
            let range = match snapshot_storage::owned_wal_region(lease) {
                Ok(range) => range,
                Err((status, lease)) => {
                    let (status, restored) = restore_unentered_recheck(
                        lease, continuation, proof, status);
                    journal.phase = if restored { Phase::Released } else { Phase::Failed };
                    journal.failed = Some(status);
                    return Err(status);
                }
            };
            let mut wal = match RegistryWal::resume_from_continuation(range, continuation, anchored) {
                Ok(wal) => wal,
                Err((error, range, continuation)) => {
                    let (status, restored) = restore_unentered_recheck(
                        range.into_device(), continuation, proof, wal_status(error));
                    journal.phase = if restored { Phase::Released } else { Phase::Failed };
                    journal.failed = Some(status);
                    return Err(status);
                }
            };
            if let Err(error) = wal.begin(core::mem::take(&mut journal.encoded)) {
                let (status, restored) = restore_unentered_wal(wal, proof, wal_status(error));
                journal.phase = if restored { Phase::Released } else { Phase::Failed };
                journal.failed = Some(status);
                return Err(status);
            }
            if let Err(error) = wal.start_async_prepare() {
                let (status, restored) = restore_unentered_wal(wal, proof, wal_status(error));
                journal.phase = if restored { Phase::Released } else { Phase::Failed };
                journal.failed = Some(status);
                return Err(status);
            }
            journal.phase = Phase::Wal { wal, proof, store, mount, base_lba,
                snapshot_lba, entered: false };
        }
        Phase::Ready { .. } => {
            let log_path = clone_path(&journal.path)?;
            let Phase::Ready { lease, anchored } = core::mem::replace(&mut journal.phase,
                Phase::Failed) else { unreachable!() };
            let anchored = anchored.ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
            journal.phase = Phase::AwaitInstall { lease };
            return Ok(Some(NativeHiveJournalReceipt { id, file_id: journal.baseline.file_id,
                expected_log_len: journal.baseline.length,
                log_path, anchored }));
        }
        Phase::Wal { .. } | Phase::Anchor { .. } | Phase::AwaitInstall { .. } => {}
        Phase::Released | Phase::Failed => return Err(nt_fs::STATUS_DEVICE_NOT_READY),
    }
    Ok(None)
}

pub(crate) unsafe fn native_hive_journal_has_entered_wal(id: u64) -> bool {
    (&*core::ptr::addr_of!(JOURNAL)).as_ref()
        .is_some_and(|journal| journal.id == id && journal.wal_entered_ever)
}

/// Release a purely local admission before the reserve has transferred to this journal.
/// A header recheck or later phase still owns the physical reserve and cannot be erased by a
/// failed caller reply, even when no WAL write has entered yet.
pub(crate) unsafe fn abort_unentered_native_hive_journal(id: u64) -> Result<(), u32> {
    let slot = &mut *core::ptr::addr_of_mut!(JOURNAL);
    let journal = slot.as_ref().ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    if journal.id != id || journal.wal_entered_ever {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    if !matches!(journal.phase, Phase::Baseline { .. } | Phase::Released) {
        return Err(snapshot_storage::BUSY);
    }
    *slot = None;
    Ok(())
}

pub(crate) unsafe fn claim_next_native_hive_io()
    -> Option<(HiveTicket, SectionMountId, BlockOperation, Vec<u8>)>
{
    let _durable = crate::allocator::enter_durable();
    let journal = (&mut *core::ptr::addr_of_mut!(JOURNAL)).as_mut()?;
    if journal.failed.is_some() { return None; }
    match &mut journal.phase {
        Phase::Wal { wal, mount, base_lba, entered, .. } => {
            if *entered { return None; }
            if !wal.async_active() && wal.state() == RegistryWalState::Prepared {
                if let Err(error) = wal.start_async_commit() {
                    journal.failed = Some(block(wal_status(error)));
                    return None;
                }
            }
            let request = match wal.enter_next_async() {
                Ok(Some(request)) => request,
                Ok(None) => return None,
                Err(error) => { journal.failed = Some(block(wal_status(error))); return None; }
            };
            let operation = match request.kind {
                AsyncWalIoKind::Flush => BlockOperation::Flush,
                AsyncWalIoKind::Write => {
                    let sectors = u32::try_from(request.bytes / 512).unwrap_or(0);
                    if sectors == 0 || request.bytes != sectors as usize * 512
                        || request.lba.checked_add(u64::from(sectors))
                            .is_none_or(|end| end > crate::fs_loader::WRITABLE_SNAPSHOT_RESERVE_SECTORS as u64) {
                        let _ = wal.release_unentered_async(request);
                        journal.failed = Some(block(nt_fs::STATUS_INVALID_PARAMETER));
                        return None;
                    }
                    let Some(lba) = base_lba.checked_add(request.lba) else {
                        let _ = wal.release_unentered_async(request);
                        journal.failed = Some(block(nt_fs::STATUS_INVALID_PARAMETER));
                        return None;
                    };
                    BlockOperation::Write { lba, sectors }
                }
            };
            let input = match wal.async_write_bytes(request) {
                Some(bytes) => match clone_owned(bytes) {
                    Ok(input) => input,
                    Err(_) => { let _ = wal.release_unentered_async(request); return None; }
                },
                None => Vec::new(),
            };
            Some((HiveTicket { id: journal.id, request: HiveRequest::Wal(request) },
                *mount, operation, input))
        }
        Phase::Anchor { update, mount, base_lba, entered } => {
            if *entered { return None; }
            let request = match update.enter_next() {
                Ok(Some(request)) => request,
                Ok(None) => return None,
                Err(_) => { journal.failed = Some(block(nt_fs::STATUS_DEVICE_NOT_READY));
                    return None; }
            };
            let operation = match request.kind {
                AsyncSnapshotIoKind::Flush => BlockOperation::Flush,
                AsyncSnapshotIoKind::Write => {
                    let sectors = u32::try_from(request.bytes / 512).unwrap_or(0);
                    if sectors == 0 || request.bytes != sectors as usize * 512
                        || request.lba.checked_add(u64::from(sectors))
                            .is_none_or(|end| end > crate::fs_loader::WRITABLE_SNAPSHOT_RESERVE_SECTORS as u64) {
                        let _ = update.release_unentered(request);
                        journal.failed = Some(block(nt_fs::STATUS_INVALID_PARAMETER));
                        return None;
                    }
                    let Some(lba) = base_lba.checked_add(request.lba) else {
                        let _ = update.release_unentered(request);
                        journal.failed = Some(block(nt_fs::STATUS_INVALID_PARAMETER));
                        return None;
                    };
                    BlockOperation::Write { lba, sectors }
                }
                AsyncSnapshotIoKind::Read => {
                    let _ = update.release_unentered(request);
                    journal.failed = Some(block(nt_fs::STATUS_INVALID_DEVICE_REQUEST));
                    return None;
                }
            };
            let input = match update.write_bytes(request) {
                Some(bytes) => match clone_owned(bytes) {
                    Ok(input) => input,
                    Err(_) => { let _ = update.release_unentered(request); return None; }
                },
                None => Vec::new(),
            };
            Some((HiveTicket { id: journal.id, request: HiveRequest::Anchor(request) },
                *mount, operation, input))
        }
        _ => None,
    }
}

pub(crate) unsafe fn mark_native_hive_io_entered(ticket: &HiveTicket) -> Result<(), u32> {
    let journal = (&mut *core::ptr::addr_of_mut!(JOURNAL)).as_mut()
        .ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    if journal.id != ticket.id { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); }
    match (&mut journal.phase, ticket.request) {
        (Phase::Wal { wal, entered, .. }, HiveRequest::Wal(request)) if !*entered => {
            wal.mark_entered_async(request).map_err(wal_status)?;
            *entered = true;
            journal.wal_entered_ever = true;
            Ok(())
        }
        (Phase::Anchor { update, entered, .. }, HiveRequest::Anchor(request))
            if !*entered && update.pending() == Some(request) => {
            *entered = true;
            Ok(())
        }
        _ => Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST),
    }
}

pub(crate) unsafe fn release_unentered_native_hive_io(ticket: HiveTicket) -> Result<(), u32> {
    let journal = (&mut *core::ptr::addr_of_mut!(JOURNAL)).as_mut()
        .ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    if journal.id != ticket.id { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); }
    match (&mut journal.phase, ticket.request) {
        (Phase::Wal { wal, entered, .. }, HiveRequest::Wal(request)) if !*entered =>
            wal.release_unentered_async(request).map_err(wal_status),
        (Phase::Anchor { update, entered, .. }, HiveRequest::Anchor(request)) if !*entered =>
            update.release_unentered(request).map_err(|_| nt_fs::STATUS_INVALID_DEVICE_REQUEST),
        _ => Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST),
    }
}

pub(crate) unsafe fn refuse_unentered_native_hive_io(
    ticket: HiveTicket, status: nt_status::NtStatus,
) -> Result<(), u32> {
    let slot = &mut *core::ptr::addr_of_mut!(JOURNAL);
    let journal = slot.as_mut()
        .ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    if journal.id != ticket.id { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); }
    let mut restore_no_effect = false;
    match (&mut journal.phase, ticket.request) {
        (Phase::Wal { wal, entered, .. }, HiveRequest::Wal(request)) if !*entered => {
            match wal.refuse_unentered_async(request).map_err(wal_status)? {
                AsyncWalRefusal::NoEffect => restore_no_effect = true,
                AsyncWalRefusal::RetainedEffects => {
                    journal.failed = Some(block(status.0 as u32));
                }
            }
        }
        (Phase::Anchor { update, entered, .. }, HiveRequest::Anchor(request)) if !*entered => {
            // Earlier WAL marker and possibly the first anchor already crossed native ACK.
            // Retire only this unentered request; keep the exact update and reserve pinned.
            update.release_unentered(request)
                .map_err(|_| nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
            journal.failed = Some(block(status.0 as u32));
        }
        _ => return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST),
    }
    if restore_no_effect {
        let Phase::Wal { wal, proof, .. } =
            core::mem::replace(&mut journal.phase, Phase::Failed) else { unreachable!() };
        let (settled, restored) = restore_unentered_wal(wal, proof, status.0 as u32);
        journal.phase = if restored { Phase::Released } else { Phase::Failed };
        journal.failed = Some(settled);
    }
    Ok(())
}

pub(crate) unsafe fn complete_native_hive_io(
    ticket: HiveTicket, result: Result<&[u8], nt_status::NtStatus>,
) -> Result<(), u32> {
    let _durable = crate::allocator::enter_durable();
    let journal = (&mut *core::ptr::addr_of_mut!(JOURNAL)).as_mut()
        .ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    if journal.id != ticket.id { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); }
    match (&mut journal.phase, ticket.request) {
        (Phase::Wal { wal, entered, .. }, HiveRequest::Wal(request)) if *entered => {
            let effect = match result {
                Ok(bytes) if bytes.is_empty() => Ok(()),
                _ => Err(SnapshotBlockStoreError::Io),
            };
            if let Err(error) = wal.complete_async(request, effect) {
                journal.failed = Some(block(wal_status(error)));
                return Err(journal.failed.unwrap());
            }
            *entered = false;
            if wal.async_active() || wal.state() != RegistryWalState::Ready { return Ok(()); }
            let Phase::Wal { wal, proof, store, mount, snapshot_lba, .. } =
                core::mem::replace(&mut journal.phase, Phase::Failed) else { unreachable!() };
            let verified = match wal.into_verified_device() {
                Ok(verified) => verified.into_full_device(),
                Err(wal) => { core::mem::forget(wal); core::mem::forget(proof);
                    return Err(block(nt_fs::STATUS_DATA_ERROR)); }
            };
            let update = match AsyncWalSnapshotAnchorUpdate::admit_verified_wal_pair(
                store, verified, proof) {
                Ok(update) => update,
                Err((error, verified, proof)) => {
                    core::mem::forget(verified);
                    core::mem::forget(proof);
                    return Err(block(snapshot_store_error_status(error)));
                }
            };
            journal.phase = Phase::Anchor { update, mount,
                base_lba: snapshot_lba, entered: false };
            Ok(())
        }
        (Phase::Anchor { update, entered, .. }, HiveRequest::Anchor(request)) if *entered => {
            let settled = matches!(result, Ok(bytes) if bytes.is_empty());
            if update.complete(request, settled).is_err() {
                journal.failed = Some(block(nt_fs::STATUS_DEVICE_NOT_READY));
                return Err(journal.failed.unwrap());
            }
            *entered = false;
            if !update.is_done() { return Ok(()); }
            let Phase::Anchor { update, .. } =
                core::mem::replace(&mut journal.phase, Phase::Failed) else { unreachable!() };
            let (lease, anchored) = match update.into_anchored_publication() {
                Ok(parts) => parts,
                Err(update) => { core::mem::forget(update);
                    return Err(block(nt_fs::STATUS_DATA_ERROR)); }
            };
            let payload = HiveLogWalPayload { file_id: journal.baseline.file_id,
                expected_log_len: journal.baseline.length,
                path: &journal.path, record: &journal.record };
            let live = match writable_fs() {
                Ok(fs) => fs.replay_hive_log_wal_payload(payload),
                Err(_) => {
                    core::mem::forget(lease);
                    core::mem::forget(anchored);
                    return Err(block(nt_fs::STATUS_INVALID_HANDLE));
                }
            };
            if let Err(error) = live {
                core::mem::forget(lease);
                core::mem::forget(anchored);
                return Err(block(match error {
                    nt_fs::HiveLogWalReplayError::OutOfMemory => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
                    _ => nt_fs::STATUS_DATA_ERROR,
                }));
            }
            let Some(entry) = baselines().iter_mut().find(|entry|
                entry.path == journal.path && entry.file_id == journal.baseline.file_id) else {
                core::mem::forget(lease);
                core::mem::forget(anchored);
                return Err(block(nt_fs::STATUS_DATA_ERROR));
            };
            entry.expected_len = journal.new_log_len;
            entry.last_sequence = journal.baseline.last_sequence;
            entry.has_wal_records = true;
            journal.phase = Phase::Ready { lease, anchored: Some(anchored) };
            Ok(())
        }
        _ => Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST),
    }
}

pub(crate) unsafe fn install_native_hive_publication(
    id: u64, continuation: nt_fs::RegistryWalContinuation,
    pair: nt_fs::VerifiedPairedWalSnapshot,
) -> Result<(), (u32, nt_fs::RegistryWalContinuation, nt_fs::VerifiedPairedWalSnapshot)> {
    let slot = &mut *core::ptr::addr_of_mut!(JOURNAL);
    let Some(journal) = slot.as_ref() else {
        return Err((nt_fs::STATUS_INVALID_DEVICE_REQUEST, continuation, pair));
    };
    if journal.id != id { return Err((nt_fs::STATUS_INVALID_DEVICE_REQUEST, continuation, pair)); }
    let Phase::AwaitInstall { lease } = &journal.phase else {
        return Err((nt_fs::STATUS_INVALID_DEVICE_REQUEST, continuation, pair));
    };
    if let Err((status, continuation, pair)) =
        snapshot_storage::install_wal_continuation(lease, continuation, pair) {
        return Err((block(status), continuation, pair));
    }
    let Some(Journal { phase: Phase::AwaitInstall { lease }, record, .. }) = slot.take()
        else { unreachable!("checked installed hive WAL owner") };
    drop(lease);
    OVERLAY_WRITES.fetch_add(1, Ordering::Relaxed);
    OVERLAY_BYTES_WRITTEN.fetch_add(record.len() as u64, Ordering::Relaxed);
    mark_runtime_dirty();
    Ok(())
}
