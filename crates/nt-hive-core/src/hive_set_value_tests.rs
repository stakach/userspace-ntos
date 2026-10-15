use super::*;
use crate::{encode_image, HiveKind};
use alloc::vec;

#[test]
fn dropping_prepared_create_preserves_all_logical_state() {
    let mut hive = Hive::new(HiveKind::System);
    let root = hive.root();
    hive.finish_clean_import();
    let before = encode_image(&hive);
    let cells = hive.cells.len();
    let blobs = hive.value_blobs.len();
    let next_id = hive.next_id;
    let prepared = hive
        .try_prepare_set_value(root, "Value", RegistryValueType::Binary, vec![1, 2, 3])
        .unwrap();
    drop(prepared);
    assert_eq!(encode_image(&hive), before);
    assert_eq!(hive.cells.len(), cells);
    assert_eq!(hive.value_blobs.len(), blobs);
    assert_eq!(hive.next_id, next_id);
    assert_eq!(hive.value_count(root), 0);
    assert_eq!(hive.dirty_count(), 0);
}

#[test]
fn dropping_prepared_replacement_retains_type_payload_and_spelling() {
    let mut hive = Hive::new(HiveKind::System);
    let root = hive.root();
    hive.set_value(root, "Original", RegistryValueType::Binary, vec![1]);
    hive.finish_clean_import();
    let before = encode_image(&hive);
    let blobs = hive.value_blobs.len();
    drop(
        hive.try_prepare_set_value(root, "ORIGINAL", RegistryValueType::Dword, vec![2; 4])
            .unwrap(),
    );
    assert_eq!(encode_image(&hive), before);
    assert_eq!(hive.value_blobs.len(), blobs);
    assert_eq!(
        hive.query_value(root, "original"),
        Some((RegistryValueType::Binary, &[1][..]))
    );
    assert_eq!(hive.dirty_count(), 0);
}

#[test]
fn commit_matches_legacy_new_and_case_insensitive_replacement_semantics() {
    let mut hive = Hive::new(HiveKind::System);
    let root = hive.root();
    hive.finish_clean_import();
    let mut legacy = hive.clone();
    for (name, ty, data) in [
        ("Original", RegistryValueType::Binary, vec![1]),
        ("ORIGINAL", RegistryValueType::Dword, vec![2; 4]),
        ("", RegistryValueType::Binary, vec![3]),
    ] {
        let id = hive
            .try_prepare_set_value(root, name, ty, data.clone())
            .unwrap()
            .commit();
        assert!(legacy.set_value(root, name, ty, data));
        assert_eq!(encode_image(&hive), encode_image(&legacy));
        assert_eq!(hive.dirty_count(), legacy.dirty_count());
        assert_eq!(hive.value(id).unwrap().parent_key, root);
    }
    let id = hive.value_id_by_name(root, "original").unwrap();
    assert_eq!(hive.value(id).unwrap().name, "Original");
    assert_eq!(hive.value_count(root), 2);
}

#[test]
fn prepared_edits_reuse_content_interned_payloads() {
    let mut hive = Hive::new(HiveKind::System);
    let root = hive.root();
    let first = hive
        .try_prepare_set_value(root, "First", RegistryValueType::Binary, vec![7])
        .unwrap()
        .commit();
    let second = hive
        .try_prepare_set_value(root, "Second", RegistryValueType::Binary, vec![7])
        .unwrap()
        .commit();
    assert_eq!(hive.value_blobs.len(), 1);
    assert_eq!(
        hive.value(first).unwrap().data_blob,
        hive.value(second).unwrap().data_blob
    );
    let replaced = hive
        .try_prepare_set_value(root, "FIRST", RegistryValueType::Dword, vec![7])
        .unwrap()
        .commit();
    assert_eq!(replaced, first);
    assert_eq!(hive.value_blobs.len(), 1);
}

#[test]
fn missing_key_is_rejected_before_interning_or_publication() {
    let mut hive = Hive::new(HiveKind::System);
    let before = encode_image(&hive);
    let blobs = hive.value_blobs.len();
    assert!(matches!(
        hive.try_prepare_set_value(
            CellId(u64::MAX),
            "Value",
            RegistryValueType::Binary,
            vec![1]
        ),
        Err(SetValueError::KeyNotFound)
    ));
    assert_eq!(encode_image(&hive), before);
    assert_eq!(hive.value_blobs.len(), blobs);
}

#[test]
fn sequence_id_and_arena_exhaustion_leave_logical_state_unchanged() {
    for mode in 0..4 {
        let mut hive = Hive::new(HiveKind::System);
        let root = hive.root();
        match mode {
            0 => hive.sequence = u64::MAX,
            1 => hive.next_id = u64::MAX,
            2 => hive.next_id = usize::MAX as u64 - 1,
            _ => hive.next_id = root.0,
        }
        let before = encode_image(&hive);
        let cells = hive.cells.len();
        let blobs = hive.value_blobs.len();
        let next_id = hive.next_id;
        assert!(matches!(
            hive.try_prepare_set_value(root, "Value", RegistryValueType::Binary, vec![1]),
            Err(SetValueError::InsufficientResources)
        ));
        assert_eq!(encode_image(&hive), before);
        assert_eq!(hive.cells.len(), cells);
        assert_eq!(hive.value_blobs.len(), blobs);
        assert_eq!(hive.next_id, next_id);
    }
}

#[test]
fn replacement_does_not_require_a_new_cell_id_but_checks_sequence() {
    let mut hive = Hive::new(HiveKind::System);
    let root = hive.root();
    hive.set_value(root, "Value", RegistryValueType::Binary, vec![1]);
    let id = hive.value_id_by_name(root, "Value").unwrap();
    hive.next_id = u64::MAX;
    assert_eq!(
        hive.try_prepare_set_value(root, "value", RegistryValueType::Binary, vec![2])
            .unwrap()
            .commit(),
        id
    );
    hive.sequence = u64::MAX;
    let before = encode_image(&hive);
    assert!(matches!(
        hive.try_prepare_set_value(root, "value", RegistryValueType::Binary, vec![3]),
        Err(SetValueError::InsufficientResources)
    ));
    assert_eq!(encode_image(&hive), before);
}

#[test]
fn volatile_prepared_edits_do_not_advance_or_dirty_durable_state() {
    let mut hive = Hive::new(HiveKind::System);
    let root = hive.root();
    let mut tx = hive.begin_transaction();
    let volatile = tx
        .try_create_child_with_options(root, "Volatile".into(), None, vec![1], true)
        .unwrap();
    tx.commit();
    hive.finish_clean_import();
    hive.sequence = u64::MAX;
    hive.clear_dirty();
    let before = encode_image(&hive);
    let id = hive
        .try_prepare_set_value(volatile, "Value", RegistryValueType::Binary, vec![1])
        .unwrap()
        .commit();
    assert_eq!(
        hive.try_prepare_set_value(volatile, "VALUE", RegistryValueType::Dword, vec![2; 4])
            .unwrap()
            .commit(),
        id
    );
    assert_eq!(hive.sequence, u64::MAX);
    assert_eq!(hive.dirty_count(), 0);
    assert_eq!(encode_image(&hive), before);
    assert_eq!(
        hive.query_value(volatile, "Value"),
        Some((RegistryValueType::Dword, &[2; 4][..]))
    );
}
