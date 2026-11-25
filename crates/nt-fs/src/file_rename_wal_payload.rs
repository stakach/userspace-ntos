//! One committed volume rename, including the exact entry it replaced.

use alloc::vec::Vec;

use crate::{parse_short_name_information, FileShortName, VolumeWalPayloadError, MAX_SHORT_NAME};

pub(crate) const FILE_RENAME_MAGIC: &[u8; 8] = b"NTFRNM01";
const HEADER_BYTES: usize = 72 + MAX_SHORT_NAME * 2;

/// Zero `replaced_file_id` means the destination name was absent before the move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileRenameWalPayload<'a> {
    pub sequence: u64,
    pub source_file_id: u64,
    pub source_parent_file_id: u64,
    pub target_parent_file_id: u64,
    pub replaced_file_id: u64,
    pub source_path: &'a str,
    pub target_path: &'a str,
    pub moved_short_name: FileShortName,
    pub change_time: u64,
}

fn valid_path(path: &str) -> bool {
    path.starts_with('\\') && !path.ends_with('\\')
        && !path.contains("\\\\") && !path.contains('\0')
}

pub(crate) fn validate(record: FileRenameWalPayload<'_>) -> Result<(), VolumeWalPayloadError> {
    if record.sequence == 0 {
        return Err(VolumeWalPayloadError::InvalidSequence);
    }
    if record.source_file_id == 0 || record.source_file_id == u64::MAX
        || record.replaced_file_id == u64::MAX
    {
        return Err(VolumeWalPayloadError::InvalidIdentity);
    }
    if !valid_path(record.source_path) || !valid_path(record.target_path)
        || record.source_path.eq_ignore_ascii_case(record.target_path)
    {
        return Err(VolumeWalPayloadError::InvalidPath);
    }
    let short = record.moved_short_name.units();
    let mut information = [0u8; 4 + MAX_SHORT_NAME * 2];
    information[..4].copy_from_slice(&((short.len() * 2) as u32).to_le_bytes());
    for (index, unit) in short.iter().copied().enumerate() {
        information[4 + index * 2..6 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    if parse_short_name_information(&information[..4 + short.len() * 2]).is_err() {
        return Err(VolumeWalPayloadError::InvalidIdentity);
    }
    Ok(())
}

pub fn encode_file_rename_wal_payload(
    record: FileRenameWalPayload<'_>,
) -> Result<Vec<u8>, VolumeWalPayloadError> {
    validate(record)?;
    let source_len = u32::try_from(record.source_path.len())
        .map_err(|_| VolumeWalPayloadError::InvalidLength)?;
    let target_len = u32::try_from(record.target_path.len())
        .map_err(|_| VolumeWalPayloadError::InvalidLength)?;
    let total = HEADER_BYTES.checked_add(record.source_path.len())
        .and_then(|len| len.checked_add(record.target_path.len()))
        .ok_or(VolumeWalPayloadError::InvalidLength)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(|_| VolumeWalPayloadError::OutOfMemory)?;
    bytes.extend_from_slice(FILE_RENAME_MAGIC);
    bytes.extend_from_slice(&record.sequence.to_le_bytes());
    bytes.extend_from_slice(&record.source_file_id.to_le_bytes());
    bytes.extend_from_slice(&record.source_parent_file_id.to_le_bytes());
    bytes.extend_from_slice(&record.target_parent_file_id.to_le_bytes());
    bytes.extend_from_slice(&record.replaced_file_id.to_le_bytes());
    bytes.extend_from_slice(&record.change_time.to_le_bytes());
    bytes.extend_from_slice(&source_len.to_le_bytes());
    bytes.extend_from_slice(&target_len.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&((record.moved_short_name.units().len() * 2) as u32).to_le_bytes());
    for unit in record.moved_short_name.units() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.resize(HEADER_BYTES, 0);
    bytes.extend_from_slice(record.source_path.as_bytes());
    bytes.extend_from_slice(record.target_path.as_bytes());
    Ok(bytes)
}

pub fn decode_file_rename_wal_payload(
    bytes: &[u8],
) -> Result<FileRenameWalPayload<'_>, VolumeWalPayloadError> {
    if !bytes.starts_with(FILE_RENAME_MAGIC) {
        return Err(VolumeWalPayloadError::UnknownKind);
    }
    if bytes.len() < HEADER_BYTES {
        return Err(VolumeWalPayloadError::InvalidLength);
    }
    let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let source_len = u32_at(56) as usize;
    let target_len = u32_at(60) as usize;
    let source_end = HEADER_BYTES.checked_add(source_len)
        .ok_or(VolumeWalPayloadError::InvalidLength)?;
    if source_end.checked_add(target_len) != Some(bytes.len()) {
        return Err(VolumeWalPayloadError::InvalidLength);
    }
    if u32_at(64) != 0 {
        return Err(VolumeWalPayloadError::UnknownKind);
    }
    let short_bytes = u32_at(68) as usize;
    if short_bytes > MAX_SHORT_NAME * 2 || short_bytes & 1 != 0
        || bytes[72 + short_bytes..HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(VolumeWalPayloadError::InvalidIdentity);
    }
    let moved_short_name = parse_short_name_information(&bytes[68..HEADER_BYTES])
        .map_err(|_| VolumeWalPayloadError::InvalidIdentity)?;
    let source_path = core::str::from_utf8(&bytes[HEADER_BYTES..source_end])
        .map_err(|_| VolumeWalPayloadError::InvalidPath)?;
    let target_path = core::str::from_utf8(&bytes[source_end..])
        .map_err(|_| VolumeWalPayloadError::InvalidPath)?;
    let record = FileRenameWalPayload {
        sequence: u64_at(8),
        source_file_id: u64_at(16),
        source_parent_file_id: u64_at(24),
        target_parent_file_id: u64_at(32),
        replaced_file_id: u64_at(40),
        change_time: u64_at(48),
        source_path,
        target_path,
        moved_short_name,
    };
    validate(record)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode_volume_wal_payload, VolumeWalPayload};

    fn record() -> FileRenameWalPayload<'static> {
        FileRenameWalPayload {
            sequence: 1,
            source_file_id: 45,
            source_parent_file_id: 9,
            target_parent_file_id: 9,
            replaced_file_id: 46,
            source_path: r"\??\C:\Users\Default\ntuser.dat",
            target_path: r"\??\C:\Users\Default\ntuser.bak",
            moved_short_name: FileShortName::EMPTY,
            change_time: 123,
        }
    }

    #[test]
    fn typed_rename_round_trips_and_rejects_torn_or_forged_fields() {
        let bytes = encode_file_rename_wal_payload(record()).unwrap();
        assert_eq!(decode_file_rename_wal_payload(&bytes), Ok(record()));
        assert_eq!(decode_volume_wal_payload(&bytes), Ok(VolumeWalPayload::FileRename(record())));
        for end in [8, HEADER_BYTES - 1, bytes.len() - 1] {
            assert_eq!(decode_file_rename_wal_payload(&bytes[..end]),
                Err(VolumeWalPayloadError::InvalidLength));
        }
        let mut forged = bytes.clone();
        forged[16..24].fill(0);
        assert_eq!(decode_file_rename_wal_payload(&forged),
            Err(VolumeWalPayloadError::InvalidIdentity));
        forged = bytes.clone();
        forged[8..16].fill(0);
        assert_eq!(decode_file_rename_wal_payload(&forged),
            Err(VolumeWalPayloadError::InvalidSequence));
        forged = bytes.clone();
        forged[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(decode_file_rename_wal_payload(&forged),
            Err(VolumeWalPayloadError::InvalidIdentity));
        forged = bytes.clone();
        forged[64] = 1;
        assert_eq!(decode_file_rename_wal_payload(&forged),
            Err(VolumeWalPayloadError::UnknownKind));
        forged = bytes.clone();
        forged[HEADER_BYTES - 1] = 1;
        assert_eq!(decode_file_rename_wal_payload(&forged),
            Err(VolumeWalPayloadError::InvalidIdentity));
        forged = bytes.clone();
        forged[56..60].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode_file_rename_wal_payload(&forged),
            Err(VolumeWalPayloadError::InvalidLength));
        forged = bytes.clone();
        forged.push(0);
        assert_eq!(decode_file_rename_wal_payload(&forged),
            Err(VolumeWalPayloadError::InvalidLength));
    }
}
