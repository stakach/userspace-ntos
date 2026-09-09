use super::*;
use crate::{encode_image, Hive, HiveKind};
use alloc::vec;

fn create(
    tx: &mut HiveTransaction<'_>,
    parent: CellId,
    name: &str,
) -> Result<CellId, CreateChildError> {
    tx.try_create_child(parent, name.into(), Some("class".into()), vec![1, 2, 3])
}

#[test]
fn commit_publishes_class_and_security_together_and_drop_restores_exact_image() {
    let mut hive = Hive::new(HiveKind::System);
    let root = hive.root();
    let before = encode_image(&hive);
    {
        let mut tx = hive.begin_transaction();
        let child = create(&mut tx, root, "child").unwrap();
        assert_eq!(tx.hive().key_class(child), Some("class"));
        assert_eq!(
            tx.hive().key_security_descriptor(child),
            Some(&[1, 2, 3][..])
        );
    }
    assert_eq!(encode_image(&hive), before);
    let mut tx = hive.begin_transaction();
    let child = create(&mut tx, root, "child").unwrap();
    tx.commit();
    assert_eq!(hive.open_key("child"), Some(child));
    assert_eq!(hive.key_class(child), Some("class"));
    assert_eq!(hive.key_security_descriptor(child), Some(&[1, 2, 3][..]));
}

#[test]
fn rejected_names_missing_parent_collision_and_missing_security_leave_no_mutation() {
    let mut hive = Hive::new(HiveKind::System);
    let root = hive.root();
    hive.create_key("existing");
    let before = encode_image(&hive);
    let mut tx = hive.begin_transaction();
    for name in ["", "a\\b", "a\0b"] {
        assert_eq!(
            create(&mut tx, root, name),
            Err(CreateChildError::InvalidName)
        );
    }
    assert_eq!(
        create(&mut tx, CellId(999), "child"),
        Err(CreateChildError::ParentNotFound)
    );
    assert_eq!(
        create(&mut tx, root, "EXISTING"),
        Err(CreateChildError::NameCollision)
    );
    assert_eq!(
        tx.try_create_child(root, "child".into(), None, Vec::new()),
        Err(CreateChildError::EmptySecurityDescriptor)
    );
    tx.commit();
    assert_eq!(encode_image(&hive), before);
}

#[test]
fn mixed_edits_and_multiple_children_rollback_to_original_parent_and_watermarks() {
    for edit_first in [false, true] {
        let mut hive = Hive::new(HiveKind::System);
        let root = hive.root();
        hive.set_key_class(root, Some("old"));
        hive.set_key_security_descriptor(root, b"old security");
        hive.finish_clean_import();
        let before = encode_image(&hive);
        {
            let mut tx = hive.begin_transaction();
            if edit_first {
                tx.set_key_class(root, Some("changed"));
            }
            let a = create(&mut tx, root, "a").unwrap();
            create(&mut tx, root, "b").unwrap();
            create(&mut tx, a, "nested").unwrap();
            tx.set_key_class(root, Some("later"));
            tx.delete_key(a).unwrap_err();
        }
        assert_eq!(encode_image(&hive), before);
        assert_eq!(hive.dirty_count(), 0);
    }
}

#[test]
fn cell_and_sequence_exhaustion_fail_before_linking_or_dirtying() {
    for sequence in [false, true] {
        let mut hive = Hive::new(HiveKind::System);
        let root = hive.root();
        if sequence {
            hive.sequence = u64::MAX;
        } else {
            hive.next_id = u64::MAX;
        }
        let before = encode_image(&hive);
        let mut tx = hive.begin_transaction();
        assert_eq!(
            create(&mut tx, root, "child"),
            Err(CreateChildError::InsufficientResources)
        );
        tx.commit();
        assert_eq!(encode_image(&hive), before);
        assert!(hive.open_key("child").is_none());
    }
}

#[test]
fn arena_capacity_overflow_is_a_checked_error_before_publication() {
    let mut hive = Hive::new(HiveKind::System);
    let root = hive.root();
    hive.next_id = usize::MAX as u64 - 1;
    let before = encode_image(&hive);
    let mut tx = hive.begin_transaction();
    assert_eq!(
        create(&mut tx, root, "child"),
        Err(CreateChildError::InsufficientResources)
    );
    tx.commit();
    assert_eq!(encode_image(&hive), before);
}
