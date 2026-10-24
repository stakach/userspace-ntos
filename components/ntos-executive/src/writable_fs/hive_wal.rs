//! Strict non-SYSTEM hive-log publication through the mounted v2 sector WAL.

use super::*;
use nt_fs::{
    HiveLogWalPayload, RegistryWal, RegistryWalError,
};

#[path = "hive_wal_native.rs"]
mod native;
pub(crate) use native::*;

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
