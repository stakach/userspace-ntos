//! Strict non-SYSTEM hive-log publication through the mounted v2 sector WAL.

use super::*;
use nt_fs::{
    HiveLogWalPayload, RegistryWal, RegistryWalError,
};

#[path = "hive_wal_native.rs"]
mod native;
pub(crate) use native::*;
#[path = "hive_wal_boot.rs"]
mod boot;
pub(crate) use boot::*;

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

fn semantic_error(_: nt_hive_core::HiveLogReplayError) -> u32 {
    nt_fs::STATUS_DATA_ERROR
}

struct Baseline {
    file_id: u64,
    length: u64,
    last_sequence: u64,
    needs_checkpoint: bool,
}

fn clone_path(path: &str) -> Result<alloc::string::String, u32> {
    let mut result = alloc::string::String::new();
    result.try_reserve_exact(path.len()).map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
    result.push_str(path);
    Ok(result)
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

unsafe fn finish_baseline(path: &str, record: &[u8], baseline: &mut Baseline) -> Result<(), u32> {
    if !baseline.needs_checkpoint { return Ok(()); }
    let fs = writable_fs()?;
    if fs.existing_file_id(path) != Some(baseline.file_id)
        || fs.file_len(path) != Some(baseline.length) {
        return Err(block(nt_fs::STATUS_DATA_ERROR));
    }
    baseline.last_sequence = validate_first_record(fs, path, baseline.length, record)?;
    let (first, _) = nt_hive_core::complete_log_sequence_span(record)
        .map_err(semantic_error)?;
    if let Some(entry) = baselines().iter_mut().find(|entry| entry.path == path) {
        entry.file_id = baseline.file_id;
        entry.expected_len = baseline.length;
        entry.last_sequence = first - 1;
        entry.has_wal_records = false;
    } else {
        baselines().try_reserve(1).map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
        baselines().push(LogBaseline { path: clone_path(path)?,
            file_id: baseline.file_id, expected_len: baseline.length,
            last_sequence: first - 1, has_wal_records: false });
    }
    baseline.needs_checkpoint = false;
    Ok(())
}

enum ReplayMountError {
    /// Boot setup reports the failed mount admission itself.
    AsReported,
    /// Preserve the Native journal's existing post-anchor invalid-handle status.
    NativeInvalidHandle,
}

/// The physical WAL record and both paired anchors are already durable. Only then may the
/// mounted sidecar and its live sequence baseline advance to the exact encoded append.
unsafe fn replay_anchored_record(
    path: &str, record: &[u8], baseline: &Baseline, new_log_len: u64,
    mount_error: ReplayMountError,
) -> Result<(), u32> {
    let payload = HiveLogWalPayload { file_id: baseline.file_id,
        expected_log_len: baseline.length, path, record };
    let fs = writable_fs().map_err(|status| block(match mount_error {
        ReplayMountError::AsReported => status,
        ReplayMountError::NativeInvalidHandle => nt_fs::STATUS_INVALID_HANDLE,
    }))?;
    fs.replay_hive_log_wal_payload(payload).map_err(|error| block(match error {
        nt_fs::HiveLogWalReplayError::OutOfMemory => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
        _ => nt_fs::STATUS_DATA_ERROR,
    }))?;
    let entry = baselines().iter_mut().find(|entry|
        entry.path == path && entry.file_id == baseline.file_id)
        .ok_or_else(|| block(nt_fs::STATUS_DATA_ERROR))?;
    entry.expected_len = new_log_len;
    entry.last_sequence = baseline.last_sequence;
    entry.has_wal_records = true;
    Ok(())
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
