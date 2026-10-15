use super::registry_wal::{encode_record, scan_records, WalError};
use super::{encode_log_record, try_replay_log, Hive, HiveKind, HiveLogOp};

#[test]
fn complete_records_scan_only_in_exact_mount_generation_order() {
    let mut log = encode_record(7, 10, b"first").unwrap();
    log.extend_from_slice(&encode_record(7, 11, b"second").unwrap());
    let scan = scan_records(&log, 7, 10).unwrap();
    assert_eq!(scan.records.len(), 2);
    assert_eq!(scan.records[0].payload, b"first");
    assert_eq!(scan.records[1].payload, b"second");
    assert_eq!(scan.next_generation, 12);
    assert_eq!(scan.complete_bytes, log.len());
    assert!(!scan.torn_tail);
}

#[test]
fn verified_wal_payload_composes_with_existing_hive_log_replay() {
    let payload = encode_log_record(&HiveLogOp::CreateKey { path: "Recovered" }, 1);
    let envelope = encode_record(7, 10, &payload).unwrap();
    let scan = scan_records(&envelope, 7, 10).unwrap();
    let mut hive = Hive::new(HiveKind::System);
    assert_eq!(try_replay_log(&mut hive, scan.records[0].payload, 0), Ok(1));
    assert!(hive.open_key("Recovered").is_some());
}

#[test]
fn torn_tail_exposes_only_verified_prefix() {
    let first = encode_record(7, 10, b"first").unwrap();
    let second = encode_record(7, 11, b"second").unwrap();
    for end in 1..second.len() {
        let mut log = first.clone();
        log.extend_from_slice(&second[..end]);
        let scan = scan_records(&log, 7, 10).unwrap();
        assert_eq!(scan.records.len(), 1);
        assert_eq!(scan.complete_bytes, first.len());
        assert!(scan.torn_tail);
    }
}

#[test]
fn complete_corruption_and_stale_identity_fail_closed() {
    let first = encode_record(7, 10, b"first").unwrap();
    assert_eq!(scan_records(&first, 8, 10), Err(WalError::WrongMount));
    assert_eq!(scan_records(&first, 7, 11), Err(WalError::GenerationGap));
    let mut corrupt = first.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert_eq!(scan_records(&corrupt, 7, 10), Err(WalError::BadChecksum));
    let mut corrupt_header = first;
    corrupt_header[8] ^= 1;
    assert_eq!(scan_records(&corrupt_header, 7, 10), Err(WalError::BadChecksum));
}

#[test]
fn impossible_generation_and_empty_payload_are_rejected() {
    assert_eq!(encode_record(7, u64::MAX, b"x"), Err(WalError::GenerationOverflow));
    assert_eq!(encode_record(7, 10, b""), Err(WalError::EmptyPayload));
    assert_eq!(encode_record(0, 10, b"x"), Err(WalError::WrongMount));
}
