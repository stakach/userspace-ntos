//! Strict non-SYSTEM hive-log publication through the mounted v2 sector WAL.

use super::*;
use nt_fs::{
    HiveLogWalPayload, RegistryWal, RegistryWalContinuation, RegistryWalError,
    WalSnapshotAnchor, WalSnapshotAnchorUpdate,
};

struct LogBaseline {
    path: alloc::string::String,
    file_id: u64,
    expected_len: u64,
    last_sequence: u64,
    has_wal_records: bool,
}

// This module uses the executive's serialized filesystem admission. The cache is only a live
// accelerator: boot validates the actual snapshot and WAL from the physical reserve again.
static mut LOG_BASELINES: alloc::vec::Vec<LogBaseline> = alloc::vec::Vec::new();

unsafe fn baselines() -> &'static mut alloc::vec::Vec<LogBaseline> {
    &mut *core::ptr::addr_of_mut!(LOG_BASELINES)
}

/// Call only after the fold has installed the exact continuation for two payload-valid slots
/// whose base includes the previous global WAL high-water. A later log replacement/truncation can
/// then take a new baseline without replaying the retired records against a different stream.
pub(super) unsafe fn note_volume_wal_folded() {
    for baseline in baselines() {
        baseline.has_wal_records = false;
    }
}

fn wal_status(error: RegistryWalError) -> u32 {
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

fn block(status: u32) -> u32 {
    WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
    status
}

fn restore_continuation(
    lease: snapshot_storage::Lease,
    continuation: RegistryWalContinuation,
) -> Result<(), u32> {
    match snapshot_storage::install_wal_continuation(&lease, continuation) {
        Ok(()) => {
            drop(lease);
            Ok(())
        }
        Err((status, continuation)) => {
            core::mem::forget(continuation);
            core::mem::forget(lease);
            Err(block(status))
        }
    }
}

fn semantic_error(_: nt_hive_core::HiveLogReplayError) -> u32 {
    nt_fs::STATUS_DATA_ERROR
}

/// A core checkpoint carries its sequence. An installed REGF source (or an absent writable
/// primary still sourced from the installed media) starts the mutable journal at sequence zero.
fn primary_sequence(fs: &nt_fs::FileSystem, log_path: &str) -> Result<u64, u32> {
    let image_path = log_path.strip_suffix(".LOG").ok_or(nt_fs::STATUS_INVALID_PARAMETER)?;
    let Some(image) = fs.try_file_bytes_owned(image_path)? else { return Ok(0); };
    if let Ok(hive) = nt_hive_core::decode_image(&image) {
        return Ok(hive.sequence);
    }
    if nt_hive_regf::RegfHive::new(&image).is_some() {
        return Ok(0);
    }
    Err(nt_fs::STATUS_DATA_ERROR)
}

pub(super) fn validate_first_record(
    fs: &nt_fs::FileSystem,
    path: &str,
    expected_log_len: u64,
    record: &[u8],
) -> Result<u64, u32> {
    let primary = primary_sequence(fs, path)?;
    let sidecar = fs.try_file_bytes_owned(path)?.ok_or(nt_fs::STATUS_OBJECT_NAME_NOT_FOUND)?;
    let prefix_len = usize::try_from(expected_log_len).map_err(|_| nt_fs::STATUS_DATA_ERROR)?;
    let prefix = sidecar.get(..prefix_len).ok_or(nt_fs::STATUS_DATA_ERROR)?;
    nt_hive_core::validate_first_hive_wal_append(primary, prefix, record)
        .map_err(semantic_error)
}

/// Establish one durable baseline for each exact path/file identity, then use only small WAL
/// records while the live length follows our own appends. Unrelated dirty files do not force a
/// new hive baseline. The filesystem protects the exact log node before the first WAL effect.
unsafe fn prepare_log_baseline(path: &str, record: &[u8]) -> Result<(u64, u64, u64), u32> {
    let fs = writable_fs()?;
    if fs.existing_file_id(path).is_none() {
        // Use the ordinary filesystem create contract: a missing parent must fail, and no
        // installed-volume provisioning may silently invent a Config/profile directory.
        let created = fs.zw_create_file(
            path,
            nt_fs::FILE_WRITE_DATA | nt_fs::SYNCHRONIZE,
            0,
            0,
            nt_fs::FILE_OPEN_IF,
            nt_fs::FILE_NON_DIRECTORY_FILE,
        );
        if created.status != nt_fs::STATUS_SUCCESS {
            return Err(created.status);
        }
        let close = fs.zw_close(created.handle);
        if close != nt_fs::STATUS_SUCCESS { return Err(close); }
        mark_snapshot_dirty();
    }
    let fs = writable_fs()?;
    let file_id = fs.existing_file_id(path).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let length = fs.file_len(path).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let index = baselines().iter().position(|entry| entry.path == path);
    if let Some(index) = index {
        let entry = &baselines()[index];
        // A completed fold releases this file's write protection. Equal length alone cannot
        // authenticate bytes written by another owner after that boundary.
        if entry.has_wal_records && entry.file_id == file_id && entry.expected_len == length {
            let (_, last_sequence) = nt_hive_core::complete_log_sequence_span_from(
                record, entry.last_sequence,
            ).map_err(semantic_error)?;
            return Ok((file_id, length, last_sequence));
        }
        // A replaced or truncated stream can make an older WAL suffix contradict the new
        // snapshot. Only a coordinated two-slot fold may retire those records first.
        if entry.has_wal_records && (entry.file_id != file_id || length < entry.expected_len) {
            return Err(block(nt_fs::STATUS_DATA_ERROR));
        }
    } else {
        let mut name = alloc::string::String::new();
        name.try_reserve_exact(path.len()).map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
        name.push_str(path);
        baselines().try_reserve(1).map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
        // Commit before publishing this cache entry: a failed baseline remains unproven.
        mark_snapshot_dirty();
        checkpoint_dirty_volume()?;
        if baselines().iter().any(|entry| entry.path == path) {
            return Err(block(nt_fs::STATUS_DATA_ERROR));
        }
        let last_sequence = validate_first_record(writable_fs()?, path, length, record)?;
        let (first_sequence, _) = nt_hive_core::complete_log_sequence_span(record)
            .map_err(semantic_error)?;
        baselines().push(LogBaseline {
            path: name, file_id, expected_len: length,
            last_sequence: first_sequence - 1,
            has_wal_records: false,
        });
        return Ok((file_id, length, last_sequence));
    }
    // A genuine external append (or a changed identity before any WAL record) needs a fresh
    // durable baseline, but it does not affect the normal repeated-mutation path above.
    mark_snapshot_dirty();
    checkpoint_dirty_volume()?;
    let last_sequence = validate_first_record(writable_fs()?, path, length, record)?;
    let (first_sequence, _) = nt_hive_core::complete_log_sequence_span(record)
        .map_err(semantic_error)?;
    let entry = baselines().iter_mut().find(|entry| entry.path == path)
        .ok_or_else(|| block(nt_fs::STATUS_DATA_ERROR))?;
    entry.file_id = file_id;
    entry.expected_len = length;
    entry.last_sequence = first_sequence - 1;
    Ok((file_id, length, last_sequence))
}

/// No caller may observe success until the marker, both header anchors, and the matching live
/// append have completed. Any uncertain physical effect retains its exact reserve until reboot.
pub(super) unsafe fn commit_non_system_hive_log_wal(path: &str, record: &[u8]) -> u32 {
    // Log baseline names and the applied live file survive the provider's request scope.
    let _durable = crate::allocator::enter_durable();
    if record.is_empty() || legacy_snapshot_writes_allowed()
        || WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire)
    {
        return nt_fs::STATUS_INVALID_DEVICE_REQUEST;
    }
    if let Err(status) = ensure_mounted() {
        return status;
    }
    let (file_id, expected_log_len, last_sequence) = match prepare_log_baseline(path, record) {
        Ok(baseline) => baseline,
        Err(status) => return status,
    };
    let payload = HiveLogWalPayload { file_id, expected_log_len, path, record };
    let encoded = match nt_fs::encode_hive_log_wal_payload(payload) {
        Ok(bytes) => bytes,
        Err(nt_fs::VolumeWalPayloadError::OutOfMemory) => return nt_fs::STATUS_INSUFFICIENT_RESOURCES,
        Err(_) => return nt_fs::STATUS_INVALID_PARAMETER,
    };

    let mut lease = match snapshot_storage::acquire() {
        Ok(lease) => lease,
        Err(status) => return status,
    };
    let store = lease.store();
    let manifest = match store.current_paired_wal_journal_manifest(&mut lease) {
        Ok(manifest) => manifest,
        Err(error) => return block(snapshot_store_error_status(error)),
    };
    let anchored = WalSnapshotAnchor {
        incarnation: manifest.incarnation,
        serial: manifest.high_water_serial,
        end_lba: manifest.high_water_end_lba,
    };
    let continuation = match snapshot_storage::take_wal_continuation(&lease, anchored) {
        Ok(continuation) => continuation,
        Err(status) => return block(status),
    };
    let range = match snapshot_storage::owned_wal_region(lease) {
        Ok(range) => range,
        Err((status, lease)) => {
            if let Err(error) = restore_continuation(lease, continuation) { return error; }
            return status;
        }
    };
    let mut wal = match unsafe { RegistryWal::resume_from_continuation(range, continuation, anchored) } {
        Ok(wal) => wal,
        Err((error, range, continuation)) => {
            let lease = range.into_device();
            if let Err(status) = restore_continuation(lease, continuation) { return status; }
            return block(wal_status(error));
        }
    };
    if let Err(error) = wal.begin(encoded) {
        let (range, continuation) = wal.into_continuation()
            .expect("failed WAL reservation has no physical effect");
        if let Err(status) = restore_continuation(range.into_device(), continuation) { return status; }
        return wal_status(error);
    }
    if let Err(status) = writable_fs().and_then(|fs| fs.protect_wal_log(path, file_id)) {
        let (range, continuation) = wal.into_continuation()
            .expect("unprepared WAL reservation has no physical effect");
        if let Err(error) = restore_continuation(range.into_device(), continuation) { return error; }
        return status;
    }
    if let Err(error) = wal.prepare() {
        core::mem::forget(wal);
        return block(wal_status(error));
    }
    if let Err(error) = wal.commit() {
        core::mem::forget(wal);
        return block(wal_status(error));
    }
    let verified = match wal.into_verified_device() {
        Ok(verified) => verified.into_full_device(),
        Err(wal) => {
            core::mem::forget(wal);
            return block(nt_fs::STATUS_DATA_ERROR);
        }
    };
    let mut update = match WalSnapshotAnchorUpdate::admit_verified_wal(store, verified) {
        Ok(update) => update,
        Err((error, verified)) => {
            core::mem::forget(verified);
            return block(snapshot_store_error_status(error));
        }
    };
    if let Err(error) = update.advance() {
        core::mem::forget(update);
        return block(snapshot_store_error_status(error));
    }
    let (lease, continuation) = match update.into_continuation() {
        Ok(complete) => complete,
        Err(update) => {
            core::mem::forget(update);
            return block(nt_fs::STATUS_DATA_ERROR);
        }
    };
    let applied = writable_fs().and_then(|fs| {
        fs.replay_hive_log_wal_payload(payload).map_err(|error| match error {
            nt_fs::HiveLogWalReplayError::OutOfMemory => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
            _ => nt_fs::STATUS_DATA_ERROR,
        })
    });
    if let Err(status) = applied {
        core::mem::forget(continuation);
        core::mem::forget(lease);
        return block(status);
    }
    let Some(entry) = baselines().iter_mut()
        .find(|entry| entry.path == path && entry.file_id == file_id)
    else {
        core::mem::forget(continuation);
        core::mem::forget(lease);
        return block(nt_fs::STATUS_DATA_ERROR);
    };
    entry.expected_len = expected_log_len + record.len() as u64;
    entry.last_sequence = last_sequence;
    entry.has_wal_records = true;
    if let Err((status, continuation)) = snapshot_storage::install_wal_continuation(&lease, continuation) {
        core::mem::forget(continuation);
        core::mem::forget(lease);
        return block(status);
    }
    drop(lease);
    OVERLAY_WRITES.fetch_add(1, Ordering::Relaxed);
    OVERLAY_BYTES_WRITTEN.fetch_add(record.len() as u64, Ordering::Relaxed);
    mark_runtime_dirty();
    nt_fs::STATUS_SUCCESS
}
