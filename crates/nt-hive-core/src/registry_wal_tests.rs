use super::registry_wal::{encode_record, scan_records, WalError};
use super::{
    complete_log_sequence_span, complete_log_sequence_span_from, encode_log_record,
    try_replay_log, try_replay_log_complete, validate_first_hive_wal_append,
    Hive, HiveKind, HiveLogOp, HiveManager, MemoryHiveIoProvider,
};

#[test]
fn replay_uses_durable_record_sequence_after_a_noop_and_multikey_apply() {
    let mut hive = Hive::new(HiveKind::Software);
    hive.create_key("Existing");
    hive.finish_clean_import();
    let noop = encode_log_record(&HiveLogOp::CreateKey { path: "Existing" }, 1);
    assert_eq!(try_replay_log(&mut hive, &noop, 0), Ok(1));
    assert_eq!(hive.sequence, 1, "the next append must use the durable sequence 2");
    let mut nested_hive = Hive::new(HiveKind::Software);
    let nested = encode_log_record(&HiveLogOp::CreateKey { path: "A\\B" }, 1);
    assert_eq!(try_replay_log(&mut nested_hive, &nested, 0), Ok(1));
    assert_eq!(nested_hive.sequence, 1, "one record owns one sequence despite creating two cells");
    nested_hive.clear_dirty();
    assert_eq!(nested_hive.dirty_count(), 0, "replayed cells belong to the durable baseline");
    hive.clear_dirty();
    assert_eq!(hive.dirty_count(), 0, "replayed cells belong to the durable baseline");

    let provider = MemoryHiveIoProvider::new();
    let mut manager = HiveManager::for_live_hive(provider, &hive);
    manager.mutate_with_live_apply(
        &mut hive, HiveLogOp::CreateKey { path: "Existing" },
        |hive| { hive.create_key("Existing"); true },
    ).unwrap();
    assert_eq!(hive.sequence, 2, "a durable no-op record still advances the next live sequence");
}

#[test]
fn manager_appends_after_replayed_noop_and_compound_record_survive_restart() {
    use super::{encode_image, HiveIoProvider, RegistryValueType};

    let mut original = Hive::new(HiveKind::Software);
    original.create_key("Existing");
    original.finish_clean_import();
    let mut provider = MemoryHiveIoProvider::with_image(encode_image(&original));
    provider.append_log_record(&encode_log_record(
        &HiveLogOp::CreateKey { path: "Existing" }, 1,
    )).unwrap();
    provider.append_log_record(&encode_log_record(
        &HiveLogOp::CreateKey { path: "A\\B" }, 2,
    )).unwrap();

    let mut manager = HiveManager::new(provider);
    let mut live = manager.boot(HiveKind::Software).unwrap();
    assert_eq!(live.sequence, 2);
    manager.mutate(&mut live, HiveLogOp::SetValue {
        path: "A\\B", name: "Answer", value_type: RegistryValueType::Dword,
        data: &42u32.to_le_bytes(),
    }).unwrap();
    assert_eq!(live.sequence, 3);

    manager.provider_mut().crash();
    let mut rebooted_manager = HiveManager::new(manager.into_provider());
    let rebooted = rebooted_manager.boot(HiveKind::Software).unwrap();
    let key = rebooted.open_key("A\\B").unwrap();
    assert_eq!(rebooted.sequence, 3);
    assert_eq!(rebooted.query_dword(key, "Answer"), Some(42));
}

#[test]
fn first_typed_hive_wal_append_bridges_primary_and_complete_sidecar() {
    let record = |sequence| encode_log_record(
        &HiveLogOp::CreateKey { path: "Recovered" }, sequence,
    );
    let mut old_sidecar = record(5);
    old_sidecar.extend_from_slice(&record(6));
    old_sidecar.extend_from_slice(&record(7));
    old_sidecar.extend_from_slice(&record(8));
    assert_eq!(validate_first_hive_wal_append(7, &old_sidecar, &record(9)), Ok(9));
    assert_eq!(validate_first_hive_wal_append(7, &old_sidecar[..old_sidecar.len() - record(8).len()], &record(8)), Ok(8));
    assert_eq!(validate_first_hive_wal_append(7, &[], &record(8)), Ok(8));
    assert_eq!(validate_first_hive_wal_append(7, &[], &record(9)), Err(super::HiveLogReplayError::SequenceGap));
    assert_eq!(validate_first_hive_wal_append(7, &old_sidecar, &record(10)), Err(super::HiveLogReplayError::SequenceGap));
    assert_eq!(validate_first_hive_wal_append(7, &record(9), &record(10)), Err(super::HiveLogReplayError::SequenceGap));
    assert_eq!(
        validate_first_hive_wal_append(7, &old_sidecar[..old_sidecar.len() - 1], &record(9)),
        Err(super::HiveLogReplayError::Truncated),
    );
}

#[test]
fn first_append_accepts_complete_legacy_duplicate_before_next_sequence() {
    let record = |sequence| encode_log_record(
        &HiveLogOp::CreateKey { path: "Recovered" }, sequence,
    );
    let mut sidecar = record(1);
    sidecar.extend_from_slice(&record(2));
    sidecar.extend_from_slice(&record(2));
    assert_eq!(validate_first_hive_wal_append(0, &sidecar, &record(3)), Ok(3));
    assert_eq!(
        validate_first_hive_wal_append(0, &sidecar, &record(4)),
        Err(super::HiveLogReplayError::SequenceGap),
    );
    sidecar.push(0x48);
    assert_eq!(
        validate_first_hive_wal_append(0, &sidecar, &record(3)),
        Err(super::HiveLogReplayError::Truncated),
    );
}

#[test]
fn first_append_after_fold_rejects_a_same_length_rewritten_sidecar() {
    let record = |sequence| encode_log_record(
        &HiveLogOp::CreateKey { path: "Recovered" }, sequence,
    );
    let former = record(8);
    let rewritten = record(6);
    assert_eq!(former.len(), rewritten.len());
    assert_eq!(validate_first_hive_wal_append(7, &former, &record(9)), Ok(9));
    assert_eq!(
        validate_first_hive_wal_append(7, &rewritten, &record(9)),
        Err(super::HiveLogReplayError::SequenceGap),
    );
}

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
fn committed_wal_frame_cannot_hide_a_truncated_hive_log_mutation() {
    let semantic = encode_log_record(&HiveLogOp::CreateKey { path: "Recovered" }, 1);
    let envelope = encode_record(7, 10, &semantic[..semantic.len() - 1]).unwrap();
    let scan = scan_records(&envelope, 7, 10).unwrap();
    assert_eq!(scan.records.len(), 1, "the WAL frame and checksum are durable and valid");
    assert_eq!(
        complete_log_sequence_span(scan.records[0].payload),
        Err(super::HiveLogReplayError::Truncated),
    );
    let mut hive = Hive::new(HiveKind::System);
    assert_eq!(
        try_replay_log_complete(&mut hive, scan.records[0].payload, 0),
        Err(super::HiveLogReplayError::Truncated),
    );
    assert!(hive.open_key("Recovered").is_none());
}

#[test]
fn committed_wal_payloads_require_contiguous_semantic_sequences() {
    let first = encode_log_record(&HiveLogOp::CreateKey { path: "First" }, 11);
    let skipped = encode_log_record(&HiveLogOp::CreateKey { path: "Skipped" }, 13);
    let mut one_payload = first.clone();
    one_payload.extend_from_slice(&skipped);
    assert_eq!(
        complete_log_sequence_span_from(&one_payload, 10),
        Err(super::HiveLogReplayError::SequenceGap),
        "a complete WAL frame cannot omit a semantic mutation inside its payload",
    );
    assert_eq!(complete_log_sequence_span_from(&first, 10), Ok((11, 11)));
    assert_eq!(
        complete_log_sequence_span_from(&skipped, 11),
        Err(super::HiveLogReplayError::SequenceGap),
        "separate committed WAL frames must also have adjacent semantic sequences",
    );
    let envelope = encode_record(7, 10, &skipped).unwrap();
    let scan = scan_records(&envelope, 7, 10).unwrap();
    assert_eq!(scan.records.len(), 1);
    assert_eq!(
        try_replay_log_complete(&mut Hive::new(HiveKind::System), scan.records[0].payload, 10),
        Err(super::HiveLogReplayError::SequenceGap),
    );
}

#[test]
fn shutdown_proves_complete_hive_sidecar_through_live_sequence() {
    let first = encode_log_record(&HiveLogOp::CreateKey { path: "Default\\One" }, 1);
    let second = encode_log_record(&HiveLogOp::CreateKey { path: "Default\\Two" }, 2);
    let third = encode_log_record(&HiveLogOp::CreateKey { path: "Default\\Three" }, 3);
    let mut sidecar = first.clone();
    sidecar.extend_from_slice(&second);
    assert_eq!(super::complete_hive_log_end_sequence(0, &sidecar), Ok(2));

    // A newer primary can legitimately cover complete records still in the sidecar.
    sidecar.extend_from_slice(&third);
    assert_eq!(super::complete_hive_log_end_sequence(2, &sidecar), Ok(3));
    assert_eq!(super::complete_hive_log_end_sequence(3, &sidecar), Ok(3));

    let mut torn = first.clone();
    torn.extend_from_slice(&second[..second.len() - 1]);
    assert_eq!(super::complete_hive_log_end_sequence(0, &torn),
        Err(super::HiveLogReplayError::Truncated));
    let mut gap = first;
    gap.extend_from_slice(&third);
    assert_eq!(super::complete_hive_log_end_sequence(0, &gap),
        Err(super::HiveLogReplayError::SequenceGap));
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
