//! A committed namespace creation before later content deltas for the same file.

use alloc::vec::Vec;

use crate::status::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_VALID_FLAGS};
use crate::volume_wal_payload::VolumeWalPayloadError;

pub(crate) const FILE_CREATE_MAGIC: &[u8; 8] = b"NTFCRT01";
const HEADER_BYTES: usize = 80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileCreateWalPayload<'a> {
    pub sequence: u64,
    pub file_id: u64,
    pub parent_file_id: u64,
    pub path: &'a str,
    pub attributes: u32,
    pub is_directory: bool,
    /// Creation, access, write, and change times, in that order.
    pub times: [u64; 4],
}

pub(crate) fn validate(record: FileCreateWalPayload<'_>) -> Result<(), VolumeWalPayloadError> {
    if record.sequence == 0 {
        return Err(VolumeWalPayloadError::InvalidSequence);
    }
    if record.file_id == 0 || record.file_id == u64::MAX {
        return Err(VolumeWalPayloadError::InvalidIdentity);
    }
    if !record.path.starts_with('\\') || record.path.contains('\0')
        || record.path.ends_with('\\') || record.path.contains("\\\\")
    {
        return Err(VolumeWalPayloadError::InvalidPath);
    }
    if record.attributes & !FILE_ATTRIBUTE_VALID_FLAGS != 0
        || (record.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != record.is_directory
    {
        return Err(VolumeWalPayloadError::InvalidIdentity);
    }
    Ok(())
}

pub fn encode_file_create_wal_payload(
    record: FileCreateWalPayload<'_>,
) -> Result<Vec<u8>, VolumeWalPayloadError> {
    validate(record)?;
    let path_len = u32::try_from(record.path.len())
        .map_err(|_| VolumeWalPayloadError::InvalidLength)?;
    let total = HEADER_BYTES.checked_add(record.path.len())
        .ok_or(VolumeWalPayloadError::InvalidLength)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(|_| VolumeWalPayloadError::OutOfMemory)?;
    bytes.extend_from_slice(FILE_CREATE_MAGIC);
    bytes.extend_from_slice(&record.sequence.to_le_bytes());
    bytes.extend_from_slice(&record.file_id.to_le_bytes());
    bytes.extend_from_slice(&record.parent_file_id.to_le_bytes());
    bytes.extend_from_slice(&record.attributes.to_le_bytes());
    bytes.extend_from_slice(&u32::from(record.is_directory).to_le_bytes());
    bytes.extend_from_slice(&path_len.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    for time in record.times {
        bytes.extend_from_slice(&time.to_le_bytes());
    }
    bytes.extend_from_slice(record.path.as_bytes());
    Ok(bytes)
}

pub fn decode_file_create_wal_payload(
    bytes: &[u8],
) -> Result<FileCreateWalPayload<'_>, VolumeWalPayloadError> {
    if !bytes.starts_with(FILE_CREATE_MAGIC) {
        return Err(VolumeWalPayloadError::UnknownKind);
    }
    if bytes.len() < HEADER_BYTES {
        return Err(VolumeWalPayloadError::InvalidLength);
    }
    let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let path_len = u32_at(40) as usize;
    if HEADER_BYTES.checked_add(path_len) != Some(bytes.len()) {
        return Err(VolumeWalPayloadError::InvalidLength);
    }
    if u32_at(36) > 1 || u32_at(44) != 0 {
        return Err(VolumeWalPayloadError::UnknownKind);
    }
    let path = core::str::from_utf8(&bytes[HEADER_BYTES..])
        .map_err(|_| VolumeWalPayloadError::InvalidPath)?;
    let record = FileCreateWalPayload {
        sequence: u64_at(8),
        file_id: u64_at(16),
        parent_file_id: u64_at(24),
        path,
        attributes: u32_at(32),
        is_directory: u32_at(36) != 0,
        times: [u64_at(48), u64_at(56), u64_at(64), u64_at(72)],
    };
    validate(record)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode_volume_wal_payload, VolumeWalPayload};

    const PATH: &str = r"\??\C:\ReactOS\System32\Config\SOFTWARE";

    fn record() -> FileCreateWalPayload<'static> {
        FileCreateWalPayload {
            sequence: 3, file_id: 42, parent_file_id: 41, path: PATH,
            attributes: crate::FILE_ATTRIBUTE_HIDDEN, is_directory: false,
            times: [11, 12, 13, 14],
        }
    }

    #[test]
    fn typed_create_payload_round_trips_and_rejects_partial_or_foreign_fields() {
        let bytes = encode_file_create_wal_payload(record()).unwrap();
        assert_eq!(decode_file_create_wal_payload(&bytes), Ok(record()));
        assert_eq!(decode_volume_wal_payload(&bytes), Ok(VolumeWalPayload::FileCreate(record())));
        for end in [8, HEADER_BYTES - 1, bytes.len() - 1] {
            assert_eq!(decode_file_create_wal_payload(&bytes[..end]), Err(VolumeWalPayloadError::InvalidLength));
        }
        let mut forged = bytes.clone();
        forged[16..24].fill(0);
        assert_eq!(decode_file_create_wal_payload(&forged), Err(VolumeWalPayloadError::InvalidIdentity));
        forged = bytes.clone();
        forged[8..16].fill(0);
        assert_eq!(decode_file_create_wal_payload(&forged), Err(VolumeWalPayloadError::InvalidSequence));
        forged = bytes.clone();
        forged[44] = 1;
        assert_eq!(decode_file_create_wal_payload(&forged), Err(VolumeWalPayloadError::UnknownKind));
    }
}
