use super::*;
use crate::{FileSystem, MemFs};

const LOG_PATH: &str = r"\??\C:\ReactOS\System32\Config\SOFTWARE.LOG";
const LOG_RECORD: &[u8] = b"HLR1 example mutation";

fn hive_record() -> HiveLogWalPayload<'static> {
    HiveLogWalPayload {
        file_id: 42,
        expected_log_len: 8192,
        path: LOG_PATH,
        record: LOG_RECORD,
    }
}

#[test]
fn hive_log_payload_round_trips_exact_identity_offset_path_and_bytes() {
    let bytes = encode_hive_log_wal_payload(hive_record()).unwrap();
    assert_eq!(decode_volume_wal_payload(&bytes), Ok(VolumeWalPayload::HiveLog(hive_record())));
    assert_eq!(bytes.len(), HIVE_LOG_HEADER_BYTES + LOG_PATH.len() + LOG_RECORD.len());
}

#[test]
fn mixed_system_and_hive_log_payloads_remain_distinct_in_wal_order() {
    let system_a = b"CMWAL001 first SYSTEM mutation";
    let hive = encode_hive_log_wal_payload(hive_record()).unwrap();
    let system_b = b"CMWAL001 second SYSTEM mutation";
    let records: [&[u8]; 3] = [system_a, &hive, system_b];
    let decoded = records.map(|bytes| decode_volume_wal_payload(bytes).unwrap());
    assert_eq!(decoded[0], VolumeWalPayload::System(system_a));
    assert_eq!(decoded[1], VolumeWalPayload::HiveLog(hive_record()));
    assert_eq!(decoded[2], VolumeWalPayload::System(system_b));
}

#[test]
fn hive_log_payload_rejects_truncation_trailing_bytes_and_forged_lengths() {
    let bytes = encode_hive_log_wal_payload(hive_record()).unwrap();
    for end in [8, HIVE_LOG_HEADER_BYTES - 1, bytes.len() - 1] {
        assert_eq!(decode_volume_wal_payload(&bytes[..end]), Err(VolumeWalPayloadError::InvalidLength));
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(decode_volume_wal_payload(&extra), Err(VolumeWalPayloadError::InvalidLength));

    let mut path_too_long = bytes.clone();
    path_too_long[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode_volume_wal_payload(&path_too_long), Err(VolumeWalPayloadError::InvalidLength));
    let mut record_too_long = bytes.clone();
    record_too_long[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode_volume_wal_payload(&record_too_long), Err(VolumeWalPayloadError::InvalidLength));
}

#[test]
fn hive_log_payload_rejects_missing_identity_bad_path_and_offset_overflow() {
    let mut record = hive_record();
    record.file_id = 0;
    assert_eq!(encode_hive_log_wal_payload(record), Err(VolumeWalPayloadError::InvalidIdentity));
    record = hive_record();
    record.path = "SOFTWARE.LOG";
    assert_eq!(encode_hive_log_wal_payload(record), Err(VolumeWalPayloadError::InvalidPath));
    record = hive_record();
    record.expected_log_len = u64::MAX;
    assert_eq!(encode_hive_log_wal_payload(record), Err(VolumeWalPayloadError::InvalidLength));

    let mut bytes = encode_hive_log_wal_payload(hive_record()).unwrap();
    bytes[8..16].fill(0);
    assert_eq!(decode_volume_wal_payload(&bytes), Err(VolumeWalPayloadError::InvalidIdentity));
    let mut bytes = encode_hive_log_wal_payload(hive_record()).unwrap();
    bytes[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(decode_volume_wal_payload(&bytes), Err(VolumeWalPayloadError::InvalidLength));
    let mut bytes = encode_hive_log_wal_payload(hive_record()).unwrap();
    bytes[HIVE_LOG_HEADER_BYTES] = 0xff;
    assert_eq!(decode_volume_wal_payload(&bytes), Err(VolumeWalPayloadError::InvalidPath));
}

#[test]
fn unknown_or_empty_wal_payload_cannot_be_misrouted_as_system() {
    assert_eq!(decode_volume_wal_payload(b""), Err(VolumeWalPayloadError::Empty));
    assert_eq!(decode_volume_wal_payload(b"HLR1"), Err(VolumeWalPayloadError::UnknownKind));
    assert_eq!(decode_volume_wal_payload(b"NTHLOG01"), Err(VolumeWalPayloadError::InvalidLength));
}

fn snapshot_with_log(bytes: &[u8]) -> FileSystem {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(LOG_PATH, bytes));
    fs
}

fn record_for<'a>(fs: &FileSystem, expected_log_len: u64, record: &'a [u8]) -> HiveLogWalPayload<'a> {
    HiveLogWalPayload {
        file_id: fs.existing_file_id(LOG_PATH).unwrap(),
        expected_log_len,
        path: LOG_PATH,
        record,
    }
}

#[test]
fn replay_requires_existing_file_and_exact_persisted_identity() {
    let mut missing = FileSystem::new(MemFs::new());
    assert_eq!(missing.existing_file_id(LOG_PATH), None);
    assert_eq!(missing.replay_hive_log_wal_payload(hive_record()), Err(HiveLogWalReplayError::MissingFile));

    let mut fs = snapshot_with_log(b"base");
    let actual = fs.existing_file_id(LOG_PATH).unwrap();
    let foreign = HiveLogWalPayload { file_id: actual + 1, expected_log_len: 4, path: LOG_PATH, record: LOG_RECORD };
    assert_eq!(fs.replay_hive_log_wal_payload(foreign), Err(HiveLogWalReplayError::ForeignIdentity));
    assert_eq!(fs.file_bytes_owned(LOG_PATH).unwrap(), b"base");
}

#[test]
fn replay_appends_exact_bytes_and_skips_identical_record_in_newer_snapshot() {
    let mut fs = snapshot_with_log(b"base");
    let record = record_for(&fs, 4, LOG_RECORD);
    assert_eq!(fs.replay_hive_log_wal_payload(record), Ok(HiveLogWalReplay::Appended));
    assert_eq!(fs.file_bytes_owned(LOG_PATH).unwrap(), [b"base".as_slice(), LOG_RECORD].concat());

    let snapshot = fs.export_volume_snapshot().unwrap();
    let mut restored = FileSystem::from_volume_snapshot(&snapshot).unwrap();
    assert_eq!(restored.existing_file_id(LOG_PATH), Some(record.file_id));
    assert_eq!(restored.replay_hive_log_wal_payload(record), Ok(HiveLogWalReplay::AlreadyPresent));
    assert_eq!(restored.file_bytes_owned(LOG_PATH), fs.file_bytes_owned(LOG_PATH));
}

#[test]
fn replay_rejects_short_or_conflicting_snapshot_without_mutation() {
    let mut fs = snapshot_with_log(b"ab");
    let record = record_for(&fs, 4, LOG_RECORD);
    assert_eq!(fs.replay_hive_log_wal_payload(record), Err(HiveLogWalReplayError::UnexpectedLength));
    assert_eq!(fs.file_bytes_owned(LOG_PATH).unwrap(), b"ab");

    let mut fs = snapshot_with_log(b"baseH");
    let record = record_for(&fs, 4, LOG_RECORD);
    assert_eq!(fs.replay_hive_log_wal_payload(record), Err(HiveLogWalReplayError::ContradictoryBytes));
    assert_eq!(fs.file_bytes_owned(LOG_PATH).unwrap(), b"baseH");

    let mut fs = snapshot_with_log(b"baseHLR1 wrong mutation");
    let record = record_for(&fs, 4, LOG_RECORD);
    assert_eq!(fs.replay_hive_log_wal_payload(record), Err(HiveLogWalReplayError::ContradictoryBytes));
    assert_eq!(fs.file_bytes_owned(LOG_PATH).unwrap(), b"baseHLR1 wrong mutation");
}

#[test]
fn replay_preserves_order_and_can_skip_older_records_in_a_later_snapshot() {
    let mut fs = snapshot_with_log(b"base");
    let first_bytes = b"HLR1 first";
    let second_bytes = b"HLR1 second";
    let first = record_for(&fs, 4, first_bytes);
    let second = record_for(&fs, 4 + first_bytes.len() as u64, second_bytes);
    assert_eq!(fs.replay_hive_log_wal_payload(second), Err(HiveLogWalReplayError::UnexpectedLength));
    assert_eq!(fs.replay_hive_log_wal_payload(first), Ok(HiveLogWalReplay::Appended));
    assert_eq!(fs.replay_hive_log_wal_payload(second), Ok(HiveLogWalReplay::Appended));

    let snapshot = fs.export_volume_snapshot().unwrap();
    let mut restored = FileSystem::from_volume_snapshot(&snapshot).unwrap();
    assert_eq!(restored.replay_hive_log_wal_payload(first), Ok(HiveLogWalReplay::AlreadyPresent));
    assert_eq!(restored.replay_hive_log_wal_payload(second), Ok(HiveLogWalReplay::AlreadyPresent));
    assert_eq!(restored.file_bytes_owned(LOG_PATH).unwrap(),
        [b"base".as_slice(), first_bytes, second_bytes].concat());
}
