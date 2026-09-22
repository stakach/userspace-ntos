use super::*;
use crate::{encode_image, Hive, HiveKind};
use alloc::vec;

#[test]
fn volatile_tree_is_live_but_never_changes_durable_image_or_sequence() {
    let mut hive = Hive::new(HiveKind::System);
    let root = hive.root();
    hive.create_key("Stable");
    hive.clear_dirty();
    let before = encode_image(&hive);
    let sequence = hive.sequence;
    let mut tx = hive.begin_transaction();
    let volatile = tx
        .try_create_child_with_options(
            root,
            "Transient".into(),
            Some("class".into()),
            vec![1],
            true,
        )
        .unwrap();
    assert_eq!(
        tx.try_create_child(volatile, "Invalid".into(), None, vec![1]),
        Err(CreateChildError::ChildMustBeVolatile)
    );
    let child = tx
        .try_create_child_with_options(volatile, "Nested".into(), None, vec![2], true)
        .unwrap();
    assert!(tx.set_value(
        child,
        "Value",
        crate::RegistryValueType::Binary,
        vec![1, 2, 3]
    ));
    assert!(tx.set_key_class(child, Some("changed")));
    assert!(tx.set_key_security_descriptor(child, &[3]));
    tx.commit();
    assert!(hive.is_volatile(child));
    assert_eq!(hive.sequence, sequence);
    assert_eq!(hive.dirty_count(), 0);
    assert_eq!(encode_image(&hive), before);
    assert_eq!(
        crate::try_encode_subtree_image(&hive, root).unwrap(),
        before
    );
    assert!(crate::try_encode_subtree_image(&hive, volatile).is_err());
    assert_eq!(
        crate::decode_image(&encode_image(&hive))
            .unwrap()
            .open_key("Transient"),
        None
    );
    assert!(hive.delete_value(child, "Value"));
    hive.delete_key(child).unwrap();
    hive.delete_key(volatile).unwrap();
    assert_eq!(hive.sequence, sequence);
    assert_eq!(encode_image(&hive), before);
    hive.set_value(root, "Durable", crate::RegistryValueType::Dword, vec![0; 4]);
    assert_eq!(hive.sequence, sequence + 1);
}

#[test]
fn volatile_creation_and_mutation_rollback_restore_live_tree() {
    let mut hive = Hive::new(HiveKind::System);
    let root = hive.root();
    let mut tx = hive.begin_transaction();
    let key = tx
        .try_create_child_with_options(root, "Transient".into(), None, vec![1], true)
        .unwrap();
    tx.commit();
    let sequence = hive.sequence;
    {
        let mut tx = hive.begin_transaction();
        tx.set_value(
            key,
            "Uncommitted",
            crate::RegistryValueType::Binary,
            vec![2],
        );
        tx.try_create_child_with_options(key, "Uncommitted".into(), None, vec![3], true)
            .unwrap();
    }
    assert!(hive.query_value(key, "Uncommitted").is_none());
    assert!(hive.open_subkey(key, "Uncommitted").is_none());
    assert!(hive.is_volatile(key));
    assert_eq!(hive.sequence, sequence);
}

#[test]
fn stable_parent_mutations_and_checkpoint_preserve_live_volatile_tree() {
    let mut hive = Hive::new(HiveKind::System);
    let root = hive.root();
    let mut tx = hive.begin_transaction();
    let key = tx
        .try_create_child_with_options(root, "Transient".into(), None, vec![1], true)
        .unwrap();
    tx.set_value(key, "Volatile", crate::RegistryValueType::Binary, vec![3]);
    tx.commit();
    let start = hive.sequence;
    hive.set_value(root, "Stable", crate::RegistryValueType::Binary, vec![5]);
    hive.set_key_class(root, Some("stable class"));
    hive.set_key_security_descriptor(root, &[7]);
    assert_eq!(hive.sequence, start + 3);
    let persisted = encode_image(&hive);
    let restored = crate::decode_image(&persisted).unwrap();
    assert_eq!(restored.key_class(restored.root()), Some("stable class"));
    assert_eq!(
        restored.key_security_descriptor(restored.root()),
        Some(&[7][..])
    );
    assert_eq!(
        restored.query_value(restored.root(), "Stable").unwrap().1,
        &[5]
    );
    assert!(restored.open_key("Transient").is_none());
    assert!(hive.acknowledge_checkpoint(hive.sequence, hive.generation + 1));
    assert_eq!(hive.query_value(key, "Volatile").unwrap().1, &[3]);
    assert!(hive.is_volatile(key));
    let checkpoint_sequence = hive.sequence;
    hive.delete_key(key).unwrap();
    assert_eq!(hive.sequence, checkpoint_sequence);
    assert_eq!(hive.dirty_count(), 0);
    assert!(hive.delete_value(root, "Stable"));
    assert_eq!(hive.sequence, checkpoint_sequence + 1);
    assert!(hive.dirty_count() != 0);
}

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
