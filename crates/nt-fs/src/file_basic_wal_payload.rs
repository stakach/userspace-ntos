//! Resolved basic-information state of one persisted file or directory.
//!
//! The physical volume WAL owns frame integrity and commit. This record contains stored values,
//! never the caller's FILE_BASIC_INFORMATION sentinels or a clock to sample during replay.

use alloc::vec::Vec;

use crate::status::FILE_ATTRIBUTE_VALID_FLAGS;
use crate::volume_wal_payload::VolumeWalPayloadError;

pub(crate) const FILE_BASIC_MAGIC: &[u8; 8] = b"NTFBAS01";
const HEADER_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileBasicWalPayload<'a> {
    pub sequence: u64,
    pub file_id: u64,
    pub path: &'a str,
    /// Exact stored attributes, including any valid bits retained by a time-only update.
    pub attributes: u32,
    /// Resolved creation, access, write, and change times, in that order.
    pub times: [u64; 4],
}

pub(crate) fn validate(record: FileBasicWalPayload<'_>) -> Result<(), VolumeWalPayloadError> {
    if record.sequence == 0 {
        return Err(VolumeWalPayloadError::InvalidSequence);
    }
    if record.file_id == 0 || record.file_id == u64::MAX {
        return Err(VolumeWalPayloadError::InvalidIdentity);
    }
    if !record.path.starts_with('\\') || record.path.ends_with('\\')
        || record.path.contains("\\\\") || record.path.contains('\0')
    {
        return Err(VolumeWalPayloadError::InvalidPath);
    }
    if record.attributes & !FILE_ATTRIBUTE_VALID_FLAGS != 0 {
        return Err(VolumeWalPayloadError::InvalidIdentity);
    }
    Ok(())
}

pub fn encode_file_basic_wal_payload(
    record: FileBasicWalPayload<'_>,
) -> Result<Vec<u8>, VolumeWalPayloadError> {
    validate(record)?;
    let path_len = u32::try_from(record.path.len())
        .map_err(|_| VolumeWalPayloadError::InvalidLength)?;
    let total = HEADER_BYTES.checked_add(record.path.len())
        .ok_or(VolumeWalPayloadError::InvalidLength)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(|_| VolumeWalPayloadError::OutOfMemory)?;
    bytes.extend_from_slice(FILE_BASIC_MAGIC);
    bytes.extend_from_slice(&record.sequence.to_le_bytes());
    bytes.extend_from_slice(&record.file_id.to_le_bytes());
    bytes.extend_from_slice(&record.attributes.to_le_bytes());
    bytes.extend_from_slice(&path_len.to_le_bytes());
    for time in record.times {
        bytes.extend_from_slice(&time.to_le_bytes());
    }
    bytes.extend_from_slice(record.path.as_bytes());
    Ok(bytes)
}

pub fn decode_file_basic_wal_payload(
    bytes: &[u8],
) -> Result<FileBasicWalPayload<'_>, VolumeWalPayloadError> {
    if !bytes.starts_with(FILE_BASIC_MAGIC) {
        return Err(VolumeWalPayloadError::UnknownKind);
    }
    if bytes.len() < HEADER_BYTES {
        return Err(VolumeWalPayloadError::InvalidLength);
    }
    let path_len = u32::from_le_bytes(bytes[28..32].try_into().unwrap()) as usize;
    if HEADER_BYTES.checked_add(path_len) != Some(bytes.len()) {
        return Err(VolumeWalPayloadError::InvalidLength);
    }
    let path = core::str::from_utf8(&bytes[HEADER_BYTES..])
        .map_err(|_| VolumeWalPayloadError::InvalidPath)?;
    let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let record = FileBasicWalPayload {
        sequence: u64_at(8),
        file_id: u64_at(16),
        path,
        attributes: u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
        times: [u64_at(32), u64_at(40), u64_at(48), u64_at(56)],
    };
    validate(record)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode_volume_wal_payload, VolumeWalPayload};

    const PATH: &str = r"\??\C:\Users\Default\ntuser.dat";

    fn record() -> FileBasicWalPayload<'static> {
        FileBasicWalPayload {
            sequence: 1, file_id: 42, path: PATH,
            attributes: crate::FILE_ATTRIBUTE_HIDDEN, times: [11, 12, 13, 14],
        }
    }

    #[test]
    fn basic_state_round_trips_and_refuses_torn_or_foreign_fields() {
        let bytes = encode_file_basic_wal_payload(record()).unwrap();
        assert_eq!(decode_file_basic_wal_payload(&bytes), Ok(record()));
        assert_eq!(decode_volume_wal_payload(&bytes), Ok(VolumeWalPayload::FileBasic(record())));
        for end in [8, HEADER_BYTES - 1, bytes.len() - 1] {
            assert_eq!(decode_file_basic_wal_payload(&bytes[..end]),
                Err(VolumeWalPayloadError::InvalidLength));
        }
        let mut forged = bytes.clone();
        forged[8..16].fill(0);
        assert_eq!(decode_file_basic_wal_payload(&forged),
            Err(VolumeWalPayloadError::InvalidSequence));
        forged = bytes.clone();
        forged[16..24].fill(0);
        assert_eq!(decode_file_basic_wal_payload(&forged),
            Err(VolumeWalPayloadError::InvalidIdentity));
        forged = bytes.clone();
        forged[24..28].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        assert_eq!(decode_file_basic_wal_payload(&forged),
            Err(VolumeWalPayloadError::InvalidIdentity));
        assert!(encode_file_basic_wal_payload(FileBasicWalPayload {
            attributes: crate::FILE_ATTRIBUTE_NORMAL, ..record()
        }).is_ok());
        forged = bytes.clone();
        forged[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode_file_basic_wal_payload(&forged),
            Err(VolumeWalPayloadError::InvalidLength));
        forged = bytes.clone();
        forged.push(0);
        assert_eq!(decode_file_basic_wal_payload(&forged),
            Err(VolumeWalPayloadError::InvalidLength));
    }
}
