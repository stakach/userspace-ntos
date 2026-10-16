//! Typed payloads within the physical registry WAL. The sector WAL supplies checksums and
//! durability; this codec only separates legacy SYSTEM records from other hive log appends.

use alloc::vec::Vec;

const SYSTEM_MAGIC: &[u8; 8] = b"CMWAL001";
const HIVE_LOG_MAGIC: &[u8; 8] = b"NTHLOG01";
const HIVE_LOG_HEADER_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeWalPayloadError {
    Empty,
    UnknownKind,
    InvalidIdentity,
    InvalidPath,
    InvalidLength,
    OutOfMemory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiveLogWalReplay {
    Appended,
    AlreadyPresent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiveLogWalReplayError {
    InvalidPayload,
    MissingFile,
    ForeignIdentity,
    UnexpectedLength,
    ContradictoryBytes,
    OutOfMemory,
}

/// A durable append is bound to one persisted file identity and its exact previous length.
/// Replay must check both against the unpublished snapshot before applying these bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HiveLogWalPayload<'a> {
    pub file_id: u64,
    pub expected_log_len: u64,
    pub path: &'a str,
    pub record: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeWalPayload<'a> {
    /// Existing v2 disks contain raw `CMWAL001` records; retain their exact bytes.
    System(&'a [u8]),
    HiveLog(HiveLogWalPayload<'a>),
}

pub(crate) fn validate_hive_log(record: HiveLogWalPayload<'_>) -> Result<(), VolumeWalPayloadError> {
    if record.file_id == 0 {
        return Err(VolumeWalPayloadError::InvalidIdentity);
    }
    if !record.path.starts_with('\\')
        || !record.path.ends_with(".LOG")
        || record.path.contains('\0')
    {
        return Err(VolumeWalPayloadError::InvalidPath);
    }
    if record.record.is_empty()
        || record.expected_log_len.checked_add(record.record.len() as u64).is_none()
    {
        return Err(VolumeWalPayloadError::InvalidLength);
    }
    Ok(())
}

pub fn encode_hive_log_wal_payload(
    record: HiveLogWalPayload<'_>,
) -> Result<Vec<u8>, VolumeWalPayloadError> {
    validate_hive_log(record)?;
    let path_len = u32::try_from(record.path.len()).map_err(|_| VolumeWalPayloadError::InvalidLength)?;
    let record_len = u32::try_from(record.record.len()).map_err(|_| VolumeWalPayloadError::InvalidLength)?;
    let total = HIVE_LOG_HEADER_BYTES
        .checked_add(record.path.len())
        .and_then(|len| len.checked_add(record.record.len()))
        .ok_or(VolumeWalPayloadError::InvalidLength)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(|_| VolumeWalPayloadError::OutOfMemory)?;
    bytes.extend_from_slice(HIVE_LOG_MAGIC);
    bytes.extend_from_slice(&record.file_id.to_le_bytes());
    bytes.extend_from_slice(&record.expected_log_len.to_le_bytes());
    bytes.extend_from_slice(&path_len.to_le_bytes());
    bytes.extend_from_slice(&record_len.to_le_bytes());
    bytes.extend_from_slice(record.path.as_bytes());
    bytes.extend_from_slice(record.record);
    Ok(bytes)
}

pub fn decode_volume_wal_payload(bytes: &[u8]) -> Result<VolumeWalPayload<'_>, VolumeWalPayloadError> {
    if bytes.is_empty() {
        return Err(VolumeWalPayloadError::Empty);
    }
    if bytes.starts_with(SYSTEM_MAGIC) {
        return Ok(VolumeWalPayload::System(bytes));
    }
    if !bytes.starts_with(HIVE_LOG_MAGIC) {
        return Err(VolumeWalPayloadError::UnknownKind);
    }
    if bytes.len() < HIVE_LOG_HEADER_BYTES {
        return Err(VolumeWalPayloadError::InvalidLength);
    }
    let file_id = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let expected_log_len = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let path_len = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
    let record_len = u32::from_le_bytes(bytes[28..32].try_into().unwrap()) as usize;
    let path_end = HIVE_LOG_HEADER_BYTES.checked_add(path_len)
        .ok_or(VolumeWalPayloadError::InvalidLength)?;
    let end = path_end.checked_add(record_len).ok_or(VolumeWalPayloadError::InvalidLength)?;
    if end != bytes.len() {
        return Err(VolumeWalPayloadError::InvalidLength);
    }
    let path = core::str::from_utf8(&bytes[HIVE_LOG_HEADER_BYTES..path_end])
        .map_err(|_| VolumeWalPayloadError::InvalidPath)?;
    let record = HiveLogWalPayload { file_id, expected_log_len, path, record: &bytes[path_end..] };
    validate_hive_log(record)?;
    Ok(VolumeWalPayload::HiveLog(record))
}

#[cfg(test)]
#[path = "volume_wal_payload_tests.rs"]
mod tests;
