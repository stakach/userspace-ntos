use super::*;
use crate::{CellId, HiveSetValueError, HiveValueJournalPhase, RegistryValueType, SetValueError};
use alloc::vec;

#[derive(Default)]
struct ObservedProvider {
    image: Option<Vec<u8>>,
    log: Vec<u8>,
    append_calls: usize,
    flush_calls: usize,
    image_writes: usize,
    truncate_calls: usize,
    fail_after_append: bool,
    fail_after_flush: bool,
    persisted: bool,
}

impl HiveIoProvider for ObservedProvider {
    fn provider_kind(&self) -> HiveIoProviderKind {
        HiveIoProviderKind::Memory
    }

    fn read_primary_image(&mut self) -> Result<Option<Vec<u8>>, HiveIoError> {
        Ok(self.image.clone())
    }

    fn write_primary_image_atomic(&mut self, bytes: &[u8]) -> Result<(), HiveIoError> {
        self.image_writes += 1;
        self.image = Some(bytes.to_vec());
        Ok(())
    }

    fn read_log(&mut self) -> Result<Vec<u8>, HiveIoError> {
        Ok(self.log.clone())
    }

    fn append_log_record(&mut self, bytes: &[u8]) -> Result<(), HiveIoError> {
        self.append_calls += 1;
        self.log.extend_from_slice(bytes);
        if self.fail_after_append {
            Err(HiveIoError::Io)
        } else {
            Ok(())
        }
    }

    fn truncate_log(&mut self) -> Result<(), HiveIoError> {
        self.truncate_calls += 1;
        self.log.clear();
        Ok(())
    }

    fn flush_image(&mut self) -> Result<(), HiveIoError> {
        self.flush_calls += 1;
        Ok(())
    }

    fn flush_log(&mut self) -> Result<(), HiveIoError> {
        self.flush_calls += 1;
        self.persisted = true;
        if self.fail_after_flush {
            Err(HiveIoError::Io)
        } else {
            Ok(())
        }
    }

    fn get_status(&self) -> Result<HiveIoStatus, HiveIoError> {
        Ok(HiveIoStatus {
            image_present: self.image.is_some(),
            log_len: self.log.len(),
        })
    }
}

fn clean_hive() -> (Hive, CellId) {
    let mut hive = Hive::new(HiveKind::System);
    let key = hive.create_key("Target");
    hive.set_value(key, "Original", RegistryValueType::Binary, vec![1]);
    hive.finish_clean_import();
    (hive, key)
}

#[test]
fn strict_set_value_commit_matches_durable_replay_without_replacing_identity() {
    let (constructed, _) = clean_hive();
    // Decode assigns compact cell identities; start both live and replay from that same arena.
    let mut hive = decode_image(&encode_image(&constructed)).unwrap();
    let key = hive.open_key("Target").unwrap();
    let original = hive.value_ref_by_index(key, 0).unwrap().0;
    let before = encode_image(&hive);
    let mut manager = HiveManager::for_live_hive(ObservedProvider::default(), &hive);
    let receipt = manager
        .try_set_value(
            &mut hive,
            key,
            "Target",
            "ORIGINAL",
            RegistryValueType::Dword,
            &[2; 4],
        )
        .unwrap();
    assert_eq!(receipt.value, original);
    assert!(receipt.durable);
    assert_eq!(hive.value(original).unwrap().name, "Original");
    assert_eq!(
        hive.query_value(key, "original"),
        Some((RegistryValueType::Dword, &[2; 4][..]))
    );
    assert!(hive.retained_value_journal().is_none());
    assert_eq!(manager.provider().append_calls, 1);
    assert_eq!(manager.provider().flush_calls, 1);
    assert!(manager.provider().persisted);
    let mut replayed = decode_image(&before).unwrap();
    let base = replayed.sequence;
    replay_log(&mut replayed, &manager.provider().log, base);
    assert_eq!(encode_image(&hive), encode_image(&replayed));
}

#[test]
fn lazy_set_value_publishes_after_append_ack_without_claiming_durability() {
    let (mut hive, key) = clean_hive();
    let mut manager = HiveManager::for_live_hive(ObservedProvider::default(), &hive)
        .with_flush_mode(FlushMode::Lazy);
    let receipt = manager
        .try_set_value(
            &mut hive,
            key,
            "Target",
            "New",
            RegistryValueType::Binary,
            &[3],
        )
        .unwrap();
    assert!(!receipt.durable);
    assert_eq!(
        hive.query_value(key, "New"),
        Some((RegistryValueType::Binary, &[3][..]))
    );
    assert!(hive.retained_value_journal().is_none());
    assert_eq!(manager.provider().append_calls, 1);
    assert_eq!(manager.provider().flush_calls, 0);
    assert!(!manager.provider().persisted);
}

#[test]
fn entered_append_and_flush_errors_retain_exact_record_and_block_recreated_manager() {
    for flush_error in [false, true] {
        let (mut hive, key) = clean_hive();
        let before = encode_image(&hive);
        let expected_sequence = hive.sequence + 1;
        let expected_record = encode_log_record(
            &HiveLogOp::SetValue {
                path: "Target",
                name: "Original",
                value_type: RegistryValueType::Dword,
                data: &[9; 4],
            },
            expected_sequence,
        );
        let provider = ObservedProvider {
            fail_after_append: !flush_error,
            fail_after_flush: flush_error,
            ..ObservedProvider::default()
        };
        let mut manager = HiveManager::for_live_hive(provider, &hive);
        assert!(matches!(
            manager.try_set_value(
                &mut hive,
                key,
                "Target",
                "Original",
                RegistryValueType::Dword,
                &[9; 4]
            ),
            Err(HiveSetValueError::Io(HiveIoError::Io))
        ));
        assert_eq!(encode_image(&hive), before);
        assert_eq!(
            hive.query_value(key, "Original"),
            Some((RegistryValueType::Binary, &[1][..]))
        );
        let retained = hive.retained_value_journal().unwrap();
        assert_eq!(retained.sequence, expected_sequence);
        assert_eq!(
            retained.phase,
            if flush_error {
                HiveValueJournalPhase::FlushEntered
            } else {
                HiveValueJournalPhase::AppendEntered
            }
        );
        assert_eq!(retained.record, expected_record);
        assert_eq!(manager.provider().log, expected_record);
        assert_eq!(manager.provider().append_calls, 1);
        assert_eq!(manager.provider().flush_calls, usize::from(flush_error));
        assert_eq!(manager.provider().persisted, flush_error);

        let provider = manager.into_provider();
        let mut manager = HiveManager::for_live_hive(provider, &hive);
        assert!(matches!(
            manager.try_set_value(
                &mut hive,
                key,
                "Target",
                "Another",
                RegistryValueType::Binary,
                &[4]
            ),
            Err(HiveSetValueError::RetainedPublication)
        ));
        assert!(manager
            .mutate(
                &mut hive,
                HiveLogOp::SetValue {
                    path: "Target",
                    name: "Another",
                    value_type: RegistryValueType::Binary,
                    data: &[4]
                }
            )
            .is_err());
        let mut apply_called = false;
        assert!(manager
            .mutate_with_live_apply(
                &mut hive,
                HiveLogOp::SetValue {
                    path: "Target",
                    name: "Another",
                    value_type: RegistryValueType::Binary,
                    data: &[4]
                },
                |_| {
                    apply_called = true;
                    true
                }
            )
            .is_err());
        assert!(!apply_called);
        assert!(manager.flush(&mut hive).is_err());
        assert!(manager.try_flush(&mut hive).is_err());
        assert_eq!(manager.provider().append_calls, 1);
        assert_eq!(manager.provider().flush_calls, usize::from(flush_error));
        assert_eq!(manager.provider().image_writes, 0);
        assert_eq!(manager.provider().truncate_calls, 0);
        assert_eq!(manager.provider().log, expected_record);
        assert_eq!(encode_image(&hive), before);
        let retained = hive.retained_value_journal().unwrap();
        assert_eq!(retained.sequence, expected_sequence);
        assert_eq!(retained.record, expected_record);
    }
}

#[test]
fn volatile_set_value_uses_no_provider_and_preserves_durable_sequence() {
    let mut hive = Hive::new(HiveKind::System);
    let root = hive.root();
    let mut tx = hive.begin_transaction();
    let key = tx
        .try_create_child_with_options(root, "Transient".into(), None, vec![1], true)
        .unwrap();
    tx.commit();
    hive.finish_clean_import();
    let before = encode_image(&hive);
    let mut manager = HiveManager::for_live_hive(
        ObservedProvider {
            fail_after_append: true,
            fail_after_flush: true,
            ..ObservedProvider::default()
        },
        &hive,
    );
    let receipt = manager
        .try_set_value(
            &mut hive,
            key,
            "Transient",
            "Value",
            RegistryValueType::Binary,
            &[6],
        )
        .unwrap();
    assert!(!receipt.durable);
    assert_eq!(
        hive.query_value(key, "Value"),
        Some((RegistryValueType::Binary, &[6][..]))
    );
    assert_eq!(hive.sequence, 0);
    assert_eq!(hive.dirty_count(), 0);
    assert_eq!(encode_image(&hive), before);
    assert!(hive.retained_value_journal().is_none());
    assert_eq!(manager.provider().append_calls, 0);
    assert_eq!(manager.provider().flush_calls, 0);
}

#[test]
fn path_mismatch_and_preparation_overflow_never_enter_provider() {
    let (mut hive, key) = clean_hive();
    let mut manager = HiveManager::for_live_hive(ObservedProvider::default(), &hive);
    let before = encode_image(&hive);
    assert!(matches!(
        manager.try_set_value(
            &mut hive,
            key,
            "Missing",
            "Value",
            RegistryValueType::Binary,
            &[1]
        ),
        Err(HiveSetValueError::PathMismatch)
    ));
    assert_eq!(encode_image(&hive), before);
    hive.next_id = u64::MAX;
    assert!(matches!(
        manager.try_set_value(
            &mut hive,
            key,
            "Target",
            "New",
            RegistryValueType::Binary,
            &[1]
        ),
        Err(HiveSetValueError::Prepare(
            SetValueError::InsufficientResources
        ))
    ));
    assert_eq!(encode_image(&hive), before);
    assert!(hive.retained_value_journal().is_none());
    assert_eq!(manager.provider().append_calls, 0);
    assert_eq!(manager.provider().flush_calls, 0);
}

#[test]
fn exhausted_journal_sequence_rejects_before_provider_entry() {
    let (mut hive, key) = clean_hive();
    hive.sequence = u64::MAX - 1;
    let before = encode_image(&hive);
    let mut manager = HiveManager::for_live_hive(ObservedProvider::default(), &hive);
    assert!(matches!(
        manager.try_set_value(
            &mut hive,
            key,
            "Target",
            "Original",
            RegistryValueType::Binary,
            &[2]
        ),
        Err(HiveSetValueError::SequenceOverflow)
    ));
    assert_eq!(encode_image(&hive), before);
    assert!(hive.retained_value_journal().is_none());
    assert_eq!(manager.provider().append_calls, 0);
    assert_eq!(manager.provider().flush_calls, 0);
}

#[test]
fn stale_and_new_managers_cannot_publish_records_with_old_sequences() {
    let (mut hive, key) = clean_hive();
    let mut first = HiveManager::for_live_hive(ObservedProvider::default(), &hive);
    let mut stale = HiveManager::for_live_hive(ObservedProvider::default(), &hive);
    first
        .try_set_value(
            &mut hive,
            key,
            "Target",
            "Original",
            RegistryValueType::Binary,
            &[2],
        )
        .unwrap();
    let before = encode_image(&hive);
    let mut fresh = HiveManager::new(ObservedProvider::default());
    for manager in [&mut stale, &mut fresh] {
        assert!(matches!(
            manager.try_set_value(
                &mut hive,
                key,
                "Target",
                "Original",
                RegistryValueType::Binary,
                &[3],
            ),
            Err(HiveSetValueError::SequenceMismatch)
        ));
        assert_eq!(manager.provider().append_calls, 0);
        assert_eq!(manager.provider().flush_calls, 0);
        assert!(manager.provider().log.is_empty());
        assert_eq!(encode_image(&hive), before);
        assert!(hive.retained_value_journal().is_none());
    }
}
