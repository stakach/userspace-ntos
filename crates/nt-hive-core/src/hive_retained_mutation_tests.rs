//! A retained provider effect must remain owned even through legacy domain entrypoints.

use crate::*;
use alloc::{vec, vec::Vec};

const MOUNT: &str = r"\Registry\User\Retained";
const TARGET: &str = r"\Registry\User\Retained\Target";

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
