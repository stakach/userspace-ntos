//! A retained provider effect must remain owned even through legacy domain entrypoints.

use crate::*;
use alloc::{vec, vec::Vec};

const MOUNT: &str = r"\Registry\User\Retained";
const TARGET: &str = r"\Registry\User\Retained\Target";

#[test]
fn owned_deletions_publish_only_after_exact_anchor_and_keep_missing_semantics() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Software);
    let root = hive.root();
    let leaf = hive.create_key("Leaf");
    assert!(hive.set_value(leaf, "Name", RegistryValueType::Binary, vec![7]));
    hive.finish_clean_import();
    set.mount(MOUNT, 7, hive).unwrap();
    let before = encode_image(set.hive(7).unwrap());

    assert!(matches!(set.prepare_owned_delete_value(7, leaf, "Leaf", "Missing"),
        Err(DeleteValueEditError::ValueNotFound)));
    assert!(matches!(set.prepare_owned_delete_key(7, root, ""),
        Err(DeleteKeyEditError::CannotDelete)));
    assert!(matches!(set.prepare_owned_delete_key(7, leaf, "Wrong"),
        Err(DeleteKeyEditError::NotFound)));
    let mut value = set.prepare_owned_delete_value(7, leaf, "Leaf", "name").unwrap();
    let first = value.sequence();
    assert_eq!(value.record(), encode_log_record(&HiveLogOp::DeleteValue {
        path: "Leaf", name: "name",
    }, first));
    assert_eq!(encode_image(set.hive(7).unwrap()), before);
    assert!(set.hive_mut(7).is_none());
    let (error, returned) = unsafe { set.publish_owned_delete_value_unchecked(value, first) }.unwrap_err();
    assert_eq!(error, DeleteValueEditError::RetainedPublication);
    value = returned;
    unsafe { value.mark_entered(); }
    let (error, value) = set.release_unentered_owned_delete_value(value).unwrap_err();
    assert_eq!(error, DeleteValueEditError::RetainedPublication);
    let (error, value) = unsafe { set.publish_owned_delete_value_unchecked(value, first + 1) }.unwrap_err();
    assert_eq!(error, DeleteValueEditError::RetainedPublication);
    assert_eq!(encode_image(set.hive(7).unwrap()), before);
    unsafe { set.publish_owned_delete_value_unchecked(value, first) }.unwrap();
    assert_eq!(set.hive(7).unwrap().query_value(leaf, "Name"), None);

    let mut key = set.prepare_owned_delete_key(7, leaf, "Leaf").unwrap();
    let second = key.sequence();
    assert_eq!(second, first + 1);
    assert_eq!(key.record(), encode_log_record(&HiveLogOp::DeleteKey { path: "Leaf" }, second));
    assert!(set.hive(7).unwrap().open_subkey(root, "Leaf").is_some());
    unsafe { key.mark_entered(); }
    let (error, key) = set.release_unentered_owned_delete_key(key).unwrap_err();
    assert_eq!(error, DeleteKeyEditError::RetainedPublication);
    unsafe { set.publish_owned_delete_key_unchecked(key, second) }.unwrap();
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Leaf"), None);
    assert!(!set.has_retained_publication(7));
}

#[test]
fn owned_delete_key_rejects_nonleaf_and_unentered_release_restores_mutability() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Software);
    let parent = hive.create_key("Parent");
    hive.create_key("Parent\\Child");
    hive.finish_clean_import();
    set.mount(MOUNT, 7, hive).unwrap();
    assert!(matches!(set.prepare_owned_delete_key(7, parent, "Parent"),
        Err(DeleteKeyEditError::CannotDelete)));
    let root = set.hive(7).unwrap().root();
    let mut value_hive = Hive::new(HiveKind::Security);
    let value_root = value_hive.root();
    assert!(value_hive.set_value(value_root, "Value", RegistryValueType::Binary, vec![1]));
    value_hive.finish_clean_import();
    set.mount(r"\Registry\Machine\Security", 8, value_hive).unwrap();
    let before = encode_image(set.hive(8).unwrap());
    let pending = set.prepare_owned_delete_value(8, value_root, "", "Value").unwrap();
    assert!(matches!(set.prepare_owned_delete_key(8, value_root, ""),
        Err(DeleteKeyEditError::RetainedPublication)));
    set.release_unentered_owned_delete_value(pending).unwrap();
    assert_eq!(encode_image(set.hive(8).unwrap()), before);
    assert!(set.hive_mut(8).is_some());
    assert!(set.hive(7).unwrap().key(root).is_some());
}

#[test]
fn owned_delete_key_removes_leaf_values_only_after_anchor() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Software);
    let leaf = hive.create_key("Leaf");
    assert!(hive.set_value(leaf, "First", RegistryValueType::Binary, vec![1]));
    assert!(hive.set_value(leaf, "Second", RegistryValueType::Dword, vec![2, 0, 0, 0]));
    hive.finish_clean_import();
    let root = hive.root();
    set.mount(MOUNT, 7, hive).unwrap();
    let before = encode_image(set.hive(7).unwrap());
    let mut owner = set.prepare_owned_delete_key(7, leaf, "Leaf").unwrap();
    assert_eq!(encode_image(set.hive(7).unwrap()), before);
    assert_eq!(set.hive(7).unwrap().query_value(leaf, "First").unwrap().1, &[1]);
    unsafe { owner.mark_entered(); }
    let sequence = owner.sequence();
    unsafe { set.publish_owned_delete_key_unchecked(owner, sequence) }.unwrap();
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Leaf"), None);
    assert_eq!(set.hive(7).unwrap().query_value(leaf, "First"), None);
    assert_eq!(set.hive(7).unwrap().query_value(leaf, "Second"), None);
    assert!(set.hive_mut(7).is_some());
}

#[test]
fn owned_deletion_rejects_another_mounts_receipt_and_volatile_keys() {
    fn mounted() -> (MutableHiveSet, CellId) {
        let mut set = MutableHiveSet::new();
        let mut hive = Hive::new(HiveKind::Software);
        let key = hive.create_key("Leaf");
        assert!(hive.set_value(key, "Value", RegistryValueType::Binary, vec![3]));
        hive.finish_clean_import();
        set.mount(MOUNT, 7, hive).unwrap();
        (set, key)
    }
    let (mut set, key) = mounted();
    let (mut other, _) = mounted();
    let before = encode_image(set.hive(7).unwrap());
    let mut owner = set.prepare_owned_delete_value(7, key, "Leaf", "Value").unwrap();
    let sequence = owner.sequence();
    unsafe { owner.mark_entered(); }
    let (error, owner) = unsafe { other.publish_owned_delete_value_unchecked(owner, sequence) }.unwrap_err();
    assert_eq!(error, DeleteValueEditError::RetainedPublication);
    assert_eq!(encode_image(set.hive(7).unwrap()), before);
    unsafe { set.publish_owned_delete_value_unchecked(owner, sequence) }.unwrap();

    let (mut set, _) = mounted();
    let root = set.hive(7).unwrap().root();
    let volatile = {
        let mut tx = set.hive_mut(7).unwrap().begin_transaction();
        let key = tx.try_create_child_with_options(root, "Transient".into(), None, vec![1], true)
            .unwrap();
        tx.commit();
        key
    };
    assert!(matches!(set.prepare_owned_delete_value(7, volatile, "Transient", "Absent"),
        Err(DeleteValueEditError::KeyMustBeDurable)));
    assert!(matches!(set.prepare_owned_delete_key(7, volatile, "Transient"),
        Err(DeleteKeyEditError::KeyMustBeDurable)));
}

struct AmbiguousAppend {
    inner: MemoryHiveIoProvider,
    calls: usize,
}

impl HiveIoProvider for AmbiguousAppend {
    fn provider_kind(&self) -> HiveIoProviderKind {
        HiveIoProviderKind::Memory
    }
    fn read_primary_image(&mut self) -> Result<Option<Vec<u8>>, HiveIoError> {
        self.inner.read_primary_image()
    }
    fn write_primary_image_atomic(&mut self, bytes: &[u8]) -> Result<(), HiveIoError> {
        self.inner.write_primary_image_atomic(bytes)
    }
    fn read_log(&mut self) -> Result<Vec<u8>, HiveIoError> {
        self.inner.read_log()
    }
    fn append_log_record(&mut self, bytes: &[u8]) -> Result<(), HiveIoError> {
        self.calls += 1;
        self.inner.append_log_record(bytes)?;
        Err(HiveIoError::Io)
    }
    fn truncate_log(&mut self) -> Result<(), HiveIoError> {
        self.inner.truncate_log()
    }
    fn flush_image(&mut self) -> Result<(), HiveIoError> {
        self.inner.flush_image()
    }
    fn flush_log(&mut self) -> Result<(), HiveIoError> {
        self.inner.flush_log()
    }
    fn get_status(&self) -> Result<HiveIoStatus, HiveIoError> {
        self.inner.get_status()
    }
}

fn retained_hive() -> (Hive, CellId) {
    let mut hive = Hive::new(HiveKind::Software);
    let target = hive.create_key("Target");
    assert!(hive.set_value(target, "Original", RegistryValueType::Binary, vec![1]));
    hive.finish_clean_import();
    let mut manager = HiveManager::for_live_hive(
        AmbiguousAppend {
            inner: MemoryHiveIoProvider::new(),
            calls: 0,
        },
        &hive,
    );
    assert!(matches!(
        manager.try_set_value(
            &mut hive,
            target,
            "Target",
            "Original",
            RegistryValueType::Binary,
            &[2]
        ),
        Err(HiveSetValueError::Io(HiveIoError::Io))
    ));
    assert_eq!(manager.provider().calls, 1);
    assert!(hive.retained_value_journal().is_some());
    (hive, target)
}

#[test]
fn owned_prepared_value_waits_for_exact_durable_publication() {
    let mut set = MutableHiveSet::new();
    let mut user = Hive::new(HiveKind::Software);
    let key = user.create_key("Target");
    user.finish_clean_import();
    set.mount(MOUNT, 7, user).unwrap();
    set.mount(r"\Registry\User\Other", 8, Hive::new(HiveKind::Software))
        .unwrap();

    let prepared = set
        .prepare_owned_set_value(7, key, "Target", "Value", RegistryValueType::Binary, vec![2])
        .unwrap();
    let sequence = prepared.sequence();
    assert_eq!(prepared.record(), encode_log_record(
        &HiveLogOp::SetValue {
            path: "Target", name: "Value", value_type: RegistryValueType::Binary, data: &[2],
        }, sequence,
    ));
    assert_eq!(set.hive(7).unwrap().query_value(key, "Value"), None);
    assert!(set.hive_mut(7).is_none());
    assert!(set.hive_mut(8).is_some());
    assert!(matches!(
        set.prepare_owned_set_value(7, key, "Target", "Other", RegistryValueType::Binary, vec![3]),
        Err(SetValueError::RetainedPublication)
    ));
    // No physical entry occurred, so releasing the owner cannot publish the edit.
    set.release_unentered_owned_set_value(prepared).unwrap();
    assert_eq!(set.hive(7).unwrap().query_value(key, "Value"), None);
    assert!(set.hive_mut(7).is_some());
}

#[test]
fn second_owned_edit_waits_for_first_publication_without_losing_its_input() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Software);
    let key = hive.create_key("Target");
    hive.finish_clean_import();
    set.mount(MOUNT, 7, hive).unwrap();

    let mut first = set.prepare_owned_set_value(
        7, key, "Target", "First", RegistryValueType::Binary, vec![1],
    ).unwrap();
    let second_data = vec![2, 3, 4];
    assert!(set.has_retained_publication(7));
    assert_eq!(set.hive(7).unwrap().query_value(key, "First"), None);
    assert_eq!(second_data, [2, 3, 4]);

    // The provider has acknowledged this exact first record and its paired anchor.
    unsafe { first.mark_entered(); }
    let first_sequence = first.sequence();
    unsafe { set.publish_owned_set_value_unchecked(first, first_sequence) }.unwrap();
    assert!(!set.has_retained_publication(7));

    let mut second = set.prepare_owned_set_value(
        7, key, "Target", "Second", RegistryValueType::Binary, second_data,
    ).unwrap();
    assert_eq!(second.sequence(), first_sequence + 1);
    unsafe { second.mark_entered(); }
    let second_sequence = second.sequence();
    unsafe { set.publish_owned_set_value_unchecked(second, second_sequence) }.unwrap();
    assert_eq!(set.hive(7).unwrap().query_value(key, "First").unwrap().1, &[1]);
    assert_eq!(set.hive(7).unwrap().query_value(key, "Second").unwrap().1, &[2, 3, 4]);
}

#[test]
fn queued_child_and_value_take_consecutive_sequences_after_publication() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Security);
    let existing = hive.create_key("Existing");
    hive.finish_clean_import();
    let root = hive.root();
    set.mount(r"\Registry\Machine\Security", 7, hive).unwrap();

    let mut child = set.prepare_owned_create_child(
        7, root, "", "Policy", None, vec![1, 2, 3],
    ).unwrap();
    let queued_value = vec![4, 5, 6];
    assert!(set.has_retained_publication(7));
    assert!(matches!(
        set.prepare_owned_set_value(
            7, existing, "Existing", "Deferred", RegistryValueType::Binary, vec![9],
        ),
        Err(SetValueError::RetainedPublication)
    ));
    assert_eq!(queued_value, [4, 5, 6]);

    unsafe { child.mark_entered(); }
    let first_sequence = child.sequence();
    unsafe { set.publish_owned_create_child_unchecked(child, first_sequence) }.unwrap();
    let mut value = set.prepare_owned_set_value(
        7, existing, "Existing", "Deferred", RegistryValueType::Binary, queued_value,
    ).unwrap();
    assert_eq!(value.sequence(), first_sequence + 1);
    unsafe { value.mark_entered(); }
    let second_sequence = value.sequence();
    unsafe { set.publish_owned_set_value_unchecked(value, second_sequence) }.unwrap();
    assert!(set.hive(7).unwrap().open_subkey(root, "Policy").is_some());
    assert_eq!(set.hive(7).unwrap().query_value(existing, "Deferred").unwrap().1, &[4, 5, 6]);
}

#[test]
fn owned_prepared_child_keeps_restored_hive_unchanged_until_durable_publication() {
    let mut set = MutableHiveSet::new();
    let mut security = Hive::new(HiveKind::Security);
    security.finish_clean_import();
    let security = decode_image(&encode_image(&security)).unwrap();
    let root = security.root();
    set.mount(r"\Registry\Machine\Security", 7, security).unwrap();

    let before = encode_image(set.hive(7).unwrap());
    let prepared = set
        .prepare_owned_create_child(7, root, "", "Policy", None, vec![1, 2, 3])
        .unwrap();
    assert_eq!(prepared.record(), encode_log_record(
        &HiveLogOp::CreateChild {
            parent: "", name: "Policy", class_name: None, descriptor: &[1, 2, 3],
        },
        prepared.sequence(),
    ));
    assert_eq!(encode_image(set.hive(7).unwrap()), before);
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Policy"), None);
    assert!(set.hive_mut(7).is_none());

    set.release_unentered_owned_create_child(prepared).unwrap();
    assert_eq!(encode_image(set.hive(7).unwrap()), before);
    assert!(set.hive_mut(7).is_some());
}

#[test]
fn entered_child_requires_exact_owner_and_sequence_before_publication() {
    fn mounted() -> MutableHiveSet {
        let mut set = MutableHiveSet::new();
        let mut hive = Hive::new(HiveKind::Security);
        hive.finish_clean_import();
        set.mount(r"\Registry\Machine\Security", 7, hive).unwrap();
        set
    }

    let mut set = mounted();
    let mut other = mounted();
    let root = set.hive(7).unwrap().root();
    let baseline = encode_image(set.hive(7).unwrap());
    let child = set.prepare_owned_create_child(
        7, root, "", "Policy", Some("policy class"), vec![1, 2, 3],
    ).unwrap();
    let other_child = other.prepare_owned_create_child(
        7, root, "", "Elsewhere", None, vec![4],
    ).unwrap();
    let sequence = child.sequence();
    let link_capacity = set.hive(7).unwrap().key(root).unwrap().subkeys.capacity();
    let (error, returned) = unsafe {
        set.publish_owned_create_child_unchecked(child, sequence)
    }.unwrap_err();
    assert_eq!(error, CreateChildError::RetainedPublication);
    let mut child = returned;
    assert_eq!(encode_image(set.hive(7).unwrap()), baseline);
    unsafe { child.mark_entered(); }

    // The physical effect is now uncertain: release and wrong receipt attempts keep ownership.
    let (error, child) = set.release_unentered_owned_create_child(child).unwrap_err();
    assert_eq!(error, CreateChildError::RetainedPublication);
    let (error, child) = unsafe {
        other.publish_owned_create_child_unchecked(child, sequence)
    }.unwrap_err();
    assert_eq!(error, CreateChildError::RetainedPublication);
    let (error, child) = unsafe {
        set.publish_owned_create_child_unchecked(child, sequence + 1)
    }.unwrap_err();
    assert_eq!(error, CreateChildError::RetainedPublication);
    assert!(set.hive_mut(7).is_none());
    assert_eq!(encode_image(set.hive(7).unwrap()), baseline);
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Policy"), None);

    // The exact durable receipt permits one allocation-free in-memory publication.
    let id = unsafe { set.publish_owned_create_child_unchecked(child, sequence) }.unwrap();
    let hive = set.hive(7).unwrap();
    assert_eq!(hive.key(root).unwrap().subkeys.capacity(), link_capacity);
    assert_eq!(hive.open_subkey(root, "Policy"), Some(id));
    assert_eq!(hive.key_class(id), Some("policy class"));
    assert_eq!(hive.key_security_descriptor(id), Some(&[1, 2, 3][..]));
    assert_eq!(hive.sequence, sequence);
    assert!(hive.dirty_count() > 0);
    assert!(set.hive_mut(7).is_some());
    other.release_unentered_owned_create_child(other_child).unwrap();
}

#[test]
fn restored_descriptorless_key_waits_for_exact_durable_security_publication() {
    let mut set = MutableHiveSet::new();
    let mut security = Hive::new(HiveKind::Security);
    security.create_key("Policy");
    security.finish_clean_import();
    let security = decode_image(&encode_image(&security)).unwrap();
    let policy = security.open_key("Policy").unwrap();
    set.mount(r"\Registry\Machine\Security", 7, security).unwrap();

    let before = encode_image(set.hive(7).unwrap());
    let mut prepared = set.prepare_owned_set_key_security(
        7, policy, "Policy", vec![1, 2, 3]).unwrap();
    assert_eq!(prepared.record(), encode_log_record(
        &HiveLogOp::SetKeySecurityDescriptor {
            path: "Policy", descriptor: &[1, 2, 3],
        },
        prepared.sequence(),
    ));
    assert_eq!(encode_image(set.hive(7).unwrap()), before);
    assert_eq!(set.hive(7).unwrap().key_security_descriptor(policy), None);
    assert!(set.hive_mut(7).is_none());
    unsafe { prepared.mark_entered(); }
    let (error, prepared) = set.release_unentered_owned_set_key_security(prepared).unwrap_err();
    assert_eq!(error, SetKeySecurityError::RetainedPublication);
    assert_eq!(encode_image(set.hive(7).unwrap()), before);
    let sequence = prepared.sequence();
    let (error, prepared) = unsafe {
        set.publish_owned_set_key_security_unchecked(prepared, sequence + 1)
    }.unwrap_err();
    assert_eq!(error, SetKeySecurityError::RetainedPublication);
    assert_eq!(set.hive(7).unwrap().key_security_descriptor(policy), None);
    unsafe { set.publish_owned_set_key_security_unchecked(prepared, sequence) }.unwrap();
    assert_eq!(set.hive(7).unwrap().key_security_descriptor(policy), Some(&[1, 2, 3][..]));
    assert!(set.hive_mut(7).is_some());
}

#[test]
fn retained_security_rejects_wrong_owner_and_volatile_key() {
    fn mounted() -> (MutableHiveSet, CellId) {
        let mut set = MutableHiveSet::new();
        let mut hive = Hive::new(HiveKind::Security);
        let key = hive.create_key("Policy");
        hive.finish_clean_import();
        set.mount(r"\Registry\Machine\Security", 7, hive).unwrap();
        (set, key)
    }

    let (mut set, key) = mounted();
    let (mut other, _) = mounted();
    let before = encode_image(set.hive(7).unwrap());
    let owner = set.prepare_owned_set_key_security(7, key, "Policy", vec![1]).unwrap();
    let other_owner = other.prepare_owned_set_key_security(7, key, "Policy", vec![2]).unwrap();
    let sequence = owner.sequence();
    let (error, mut owner) = unsafe {
        set.publish_owned_set_key_security_unchecked(owner, sequence)
    }.unwrap_err();
    assert_eq!(error, SetKeySecurityError::RetainedPublication);
    unsafe { owner.mark_entered(); }
    let (error, owner) = unsafe {
        other.publish_owned_set_key_security_unchecked(owner, sequence)
    }.unwrap_err();
    assert_eq!(error, SetKeySecurityError::RetainedPublication);
    assert_eq!(encode_image(set.hive(7).unwrap()), before);
    unsafe { set.publish_owned_set_key_security_unchecked(owner, sequence) }.unwrap();
    assert_eq!(set.hive(7).unwrap().key_security_descriptor(key), Some(&[1][..]));
    other.release_unentered_owned_set_key_security(other_owner).unwrap();

    let (mut set, _) = mounted();
    let root = set.hive(7).unwrap().root();
    let volatile = {
        let mut tx = set.hive_mut(7).unwrap().begin_transaction();
        let key = tx.try_create_child_with_options(root, "Transient".into(), None, vec![3], true)
            .unwrap();
        tx.commit();
        key
    };
    assert!(matches!(
        set.prepare_owned_set_key_security(7, volatile, "Transient", vec![4]),
        Err(SetKeySecurityError::KeyMustBeDurable)
    ));
    assert!(set.hive_mut(7).is_some());
}

#[test]
fn unentered_security_owner_releases_without_publishing() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Security);
    let key = hive.create_key("Policy");
    hive.finish_clean_import();
    set.mount(r"\Registry\Machine\Security", 7, hive).unwrap();
    let before = encode_image(set.hive(7).unwrap());
    let prepared = set.prepare_owned_set_key_security(7, key, "Policy", vec![1]).unwrap();
    set.release_unentered_owned_set_key_security(prepared).unwrap();
    assert_eq!(encode_image(set.hive(7).unwrap()), before);
    assert_eq!(set.hive(7).unwrap().key_security_descriptor(key), None);
    assert!(set.hive_mut(7).is_some());
}

struct Snapshot {
    image: Vec<u8>,
    record: Vec<u8>,
    phase: HiveValueJournalPhase,
    journal_sequence: u64,
    cells: usize,
    blobs: usize,
    next_id: u64,
    dirty: usize,
}

impl Snapshot {
    fn capture(hive: &Hive) -> Self {
        let retained = hive.retained_value_journal().unwrap();
        Self {
            image: encode_image(hive),
            record: retained.record.to_vec(),
            phase: retained.phase,
            journal_sequence: retained.sequence,
            cells: hive.cells.len(),
            blobs: hive.value_blobs.len(),
            next_id: hive.next_id,
            dirty: hive.dirty_count(),
        }
    }

    fn assert_unchanged(&self, hive: &Hive) {
        assert_eq!(encode_image(hive), self.image);
        assert_eq!(hive.cells.len(), self.cells);
        assert_eq!(hive.value_blobs.len(), self.blobs);
        assert_eq!(hive.next_id, self.next_id);
        assert_eq!(hive.dirty_count(), self.dirty);
        let retained = hive.retained_value_journal().unwrap();
        assert_eq!(retained.record, self.record);
        assert_eq!(retained.phase, self.phase);
        assert_eq!(retained.sequence, self.journal_sequence);
    }
}

#[test]
fn retained_effect_refuses_direct_value_mutators() {
    for operation in 0..4 {
        let (mut hive, key) = retained_hive();
        let before = Snapshot::capture(&hive);
        let source = hive.value_ref_by_index(key, 0).unwrap().0;
        let accepted = match operation {
            0 => hive.set_value(key, "Other", RegistryValueType::Binary, vec![3]),
            1 => hive.set_value_from_existing_value(key, "Copy", RegistryValueType::Binary, source),
            2 => hive.delete_value(key, "Original"),
            _ => hive.set_dword(key, "Original", 3),
        };
        assert!(
            !accepted,
            "value operation {operation} bypassed retained ownership"
        );
        before.assert_unchanged(&hive);
    }
}

#[test]
fn retained_effect_refuses_direct_key_metadata_mutators() {
    for operation in 0..3 {
        let (mut hive, key) = retained_hive();
        let before = Snapshot::capture(&hive);
        let accepted = match operation {
            0 => hive.set_key_class(key, Some("Changed")),
            1 => hive.set_key_security_descriptor(key, &[3]),
            _ => hive.set_key_kind(key, KeyKind::SymbolicLink),
        };
        assert!(
            !accepted,
            "key metadata operation {operation} bypassed retained ownership"
        );
        before.assert_unchanged(&hive);
    }
}

#[test]
fn retained_effect_refuses_direct_key_deletion() {
    let (mut hive, key) = retained_hive();
    let before = Snapshot::capture(&hive);
    assert!(hive.delete_key(key).is_err());
    before.assert_unchanged(&hive);
}

#[test]
fn retained_effect_refuses_transaction_mutators_before_commit() {
    for operation in 0..5 {
        let (mut hive, key) = retained_hive();
        let before = Snapshot::capture(&hive);
        let mut transaction = hive.begin_transaction();
        let refused = match operation {
            0 => !transaction.set_value(key, "Other", RegistryValueType::Binary, vec![3]),
            1 => !transaction.delete_value(key, "Original"),
            2 => !transaction.set_key_class(key, Some("Changed")),
            3 => !transaction.set_key_security_descriptor(key, &[3]),
            _ => transaction.delete_key(key).is_err(),
        };
        transaction.commit();
        assert!(
            refused,
            "transaction operation {operation} bypassed retained ownership"
        );
        before.assert_unchanged(&hive);
    }
}

#[test]
fn retained_effect_refuses_checked_child_creation() {
    for volatile in [false, true] {
        let (mut hive, key) = retained_hive();
        let before = Snapshot::capture(&hive);
        let mut transaction = hive.begin_transaction();
        let result =
            transaction.try_create_child_with_options(key, "Child".into(), None, vec![3], volatile);
        transaction.commit();
        assert!(result.is_err());
        before.assert_unchanged(&hive);
    }
}

#[test]
fn retained_effect_refuses_checkpoint_acknowledgement() {
    let (mut hive, _) = retained_hive();
    let before = Snapshot::capture(&hive);
    assert!(!hive.acknowledge_checkpoint(hive.sequence, hive.generation + 1));
    before.assert_unchanged(&hive);
}

#[test]
fn retained_mount_refuses_option_creation_wrappers_without_panicking() {
    for immediate in [false, true] {
        let (hive, key) = retained_hive();
        let before = Snapshot::capture(&hive);
        let mut set = MutableHiveSet::new();
        set.mount(MOUNT, 7, hive).unwrap();
        let result = if immediate {
            set.create_subkey(ResolvedHiveKey { hive: 7, key }, "Child")
        } else {
            set.create_key(r"\Registry\User\Retained\Target\Child")
        };
        assert!(result.is_none());
        before.assert_unchanged(set.hive(7).unwrap());
        assert_eq!(
            set.resolve_key(TARGET),
            Some(ResolvedHiveKey { hive: 7, key })
        );
    }
}

#[test]
fn retained_mount_refuses_unmount_without_detaching_or_losing_owner() {
    let (hive, key) = retained_hive();
    let before = Snapshot::capture(&hive);
    let mut set = MutableHiveSet::new();
    set.mount(MOUNT, 7, hive).unwrap();
    assert!(set.unmount(MOUNT).is_none());
    before.assert_unchanged(set.hive(7).unwrap());
    assert_eq!(
        set.resolve_key(TARGET),
        Some(ResolvedHiveKey { hive: 7, key })
    );
}

#[test]
fn retained_mount_refuses_replacement_and_id_rebinding() {
    for (path, id) in [(MOUNT, 7), (MOUNT, 8), (r"\Registry\User\Other", 7)] {
        let (hive, key) = retained_hive();
        let before = Snapshot::capture(&hive);
        let mut set = MutableHiveSet::new();
        set.mount(MOUNT, 7, hive).unwrap();
        assert!(set.mount(path, id, Hive::new(HiveKind::Software)).is_err());
        before.assert_unchanged(set.hive(7).unwrap());
        assert_eq!(
            set.resolve_key(TARGET),
            Some(ResolvedHiveKey { hive: 7, key })
        );
        if id == 8 {
            assert!(set.hive(8).is_none());
        }
    }
}

#[test]
fn retained_mount_refuses_dirty_clear_acknowledgement() {
    let (hive, _) = retained_hive();
    let before = Snapshot::capture(&hive);
    let mut set = MutableHiveSet::new();
    set.mount(MOUNT, 7, hive).unwrap();
    assert!(!set.clear_hive_dirty(7));
    before.assert_unchanged(set.hive(7).unwrap());
}

#[test]
fn retained_effect_refuses_payload_compaction() {
    let (mut hive, _) = retained_hive();
    let before = Snapshot::capture(&hive);
    assert_eq!(
        hive.compact_value_blobs(),
        Err(HiveValueBlobCompactError::RetainedPublication)
    );
    before.assert_unchanged(&hive);
}

#[test]
fn retained_mount_refuses_cross_hive_payload_copy() {
    let (hive, key) = retained_hive();
    let before = Snapshot::capture(&hive);
    let mut source = Hive::new(HiveKind::Software);
    let source_key = source.root();
    assert!(source.set_value(source_key, "Source", RegistryValueType::Binary, vec![9]));
    let source_value = source.value_ref_by_index(source_key, 0).unwrap().0;
    let mut set = MutableHiveSet::new();
    set.mount(MOUNT, 7, hive).unwrap();
    set.mount(r"\Registry\User\Source", 8, source).unwrap();
    assert!(!set.set_value_from_existing_value(
        ResolvedHiveKey { hive: 7, key },
        "Copy",
        RegistryValueType::Binary,
        ResolvedHiveValue {
            hive: 8,
            value: source_value
        },
    ));
    before.assert_unchanged(set.hive(7).unwrap());
    assert_eq!(
        set.query_value(
            ResolvedHiveKey {
                hive: 8,
                key: source_key
            },
            "Source"
        ),
        Some((RegistryValueType::Binary, &[9][..])),
    );
}

#[test]
fn retained_effect_refuses_overlay_composition_in_either_input() {
    for retained_base in [false, true] {
        let (retained, _) = retained_hive();
        let clean = Hive::new(HiveKind::Software);
        let before = Snapshot::capture(&retained);
        let clean_before = encode_image(&clean);
        let result = if retained_base {
            compose_hive_overlay(&retained, &clean)
        } else {
            compose_hive_overlay(&clean, &retained)
        };
        assert!(result.is_err());
        before.assert_unchanged(&retained);
        assert_eq!(encode_image(&clean), clean_before);
    }
}
