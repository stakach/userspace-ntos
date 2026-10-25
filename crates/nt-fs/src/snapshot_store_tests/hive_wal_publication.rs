use crate::snapshot_test_device::CachedDisk;
use crate::{
    publish_anchored_hive_child, publish_anchored_hive_delete_key,
    publish_anchored_hive_delete_value, publish_anchored_hive_security,
    publish_anchored_hive_value, AnchoredWalPublication, AsyncSnapshotHeaderRecheck,
    AsyncSnapshotIoKind, AsyncWalSnapshotAnchorUpdate, HiveLogWalPayload, OwnedBoundedBlockRange,
    RegistryWal, SnapshotBlockDevice, SnapshotBlockStore, WalSnapshotAnchorUpdate,
    WalSnapshotManifest, HiveWalPublicationError,
};
use nt_hive_core::{Hive, HiveKind, MutableHiveSet, RegistryValueType};

const LOG: &str = r"\Registry\User\Retained.LOG";
const SECURITY_LOG: &str = r"\Registry\Machine\Security.LOG";

fn anchored_payload(payload: alloc::vec::Vec<u8>) -> (CachedDisk, AnchoredWalPublication) {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::with_sectors(32);
    let manifest = WalSnapshotManifest { incarnation: 77, base_serial: 0,
        high_water_serial: 0, high_water_end_lba: 0 };
    store.commit_next_with_wal_manifest(&mut disk, b"old", manifest).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"new", manifest).unwrap();
    let pair = store.verify_paired_wal_snapshot(&mut disk).unwrap();
    let mut recheck = AsyncSnapshotHeaderRecheck::new(store, pair, 512, 32).ok().unwrap();
    while let Some(request) = recheck.enter_next().unwrap() {
        let mut sector = [0; 512];
        disk.read_sector(request.lba, &mut sector).unwrap();
        recheck.complete_read(request, &sector).unwrap();
    }
    let range = OwnedBoundedBlockRange::new(disk, 16, 16).ok().unwrap();
    let mut wal = RegistryWal::recover(range, 77).unwrap();
    wal.begin(payload).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let verified = wal.into_verified_device().unwrap().into_full_device();
    let mut update = AsyncWalSnapshotAnchorUpdate::admit_verified_wal_pair(
        store, verified, unsafe { recheck.finish_proven() }.ok().unwrap()).ok().unwrap();
    while let Some(request) = update.enter_next().unwrap() {
        match request.kind {
            AsyncSnapshotIoKind::Write => {
                let bytes = update.write_bytes(request).unwrap().to_vec();
                update.device_for_test().write_sector(request.lba, &bytes).unwrap();
            }
            AsyncSnapshotIoKind::Flush => update.device_for_test().flush().unwrap(),
            AsyncSnapshotIoKind::Read => unreachable!(),
        }
        unsafe { update.complete(request, true) }.unwrap();
    }
    update.into_anchored_publication().ok().unwrap()
}

#[test]
fn boot_anchor_mints_new_hive_record_only_after_both_durable_headers() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::with_sectors(32);
    let manifest = WalSnapshotManifest { incarnation: 77, base_serial: 0,
        high_water_serial: 0, high_water_end_lba: 0 };
    store.commit_next_with_wal_manifest(&mut disk, b"old", manifest).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"new", manifest).unwrap();
    let pair = store.verify_paired_wal_snapshot(&mut disk).unwrap();
    let range = OwnedBoundedBlockRange::new(disk, 16, 16).ok().unwrap();
    let mut wal = RegistryWal::recover(range, 77).unwrap();
    let payload = alloc::vec![0x5a; 600];
    wal.begin(payload.clone()).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let verified = wal.into_verified_device().unwrap().into_full_device();
    let mut update = WalSnapshotAnchorUpdate::admit_verified_wal_pair(store, verified, pair)
        .ok().unwrap();
    update.advance().unwrap();
    let (mut disk, receipt) = update.into_anchored_publication().ok().unwrap();
    assert_eq!(receipt.payload(), payload);
    let (continuation, pair, _) = receipt.into_parts();
    assert_eq!(continuation.anchor(), pair.anchor());
    disk.power_cut();
    assert_eq!(store.read_latest_wal(&mut disk).unwrap().unwrap().anchor, pair.anchor());
}

#[test]
fn failed_second_header_flush_cannot_mint_hive_publication() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::with_sectors(32);
    let manifest = WalSnapshotManifest { incarnation: 77, base_serial: 0,
        high_water_serial: 0, high_water_end_lba: 0 };
    store.commit_next_with_wal_manifest(&mut disk, b"old", manifest).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"new", manifest).unwrap();
    let pair = store.verify_paired_wal_snapshot(&mut disk).unwrap();
    let range = OwnedBoundedBlockRange::new(disk, 16, 16).ok().unwrap();
    let mut wal = RegistryWal::recover(range, 77).unwrap();
    wal.begin(alloc::vec![0x5a; 600]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let verified = wal.into_verified_device().unwrap().into_full_device();
    let mut update = WalSnapshotAnchorUpdate::admit_verified_wal_pair(store, verified, pair)
        .ok().unwrap();
    // The two barriers are write, flush, write, flush. A failed final flush may
    // have persisted the second header, so neither owner nor receipt can escape.
    let second_flush = update.device_for_test().events.len() + 3;
    update.device_for_test().fail_event = Some(second_flush);
    assert_eq!(update.advance(), Err(crate::SnapshotBlockStoreError::Io));
    let mut update = update.into_anchored_publication().err().unwrap();
    assert_eq!(update.device_for_test().events.last(), Some(&crate::snapshot_test_device::Event::Flush));
    core::mem::forget(update);
}

#[test]
fn exact_anchored_hive_record_publishes_reserved_value_once() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Software);
    let key = hive.create_key("Target");
    hive.finish_clean_import();
    set.mount(r"\Registry\User\Retained", 7, hive).unwrap();
    let prepared = set.prepare_owned_set_value(
        7, key, "Target", "Value", RegistryValueType::Binary, alloc::vec![2]).unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 9, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (_disk, receipt) = anchored_payload(payload);
    assert_eq!(set.hive(7).unwrap().query_value(key, "Value"), None);
    let (_value, continuation, pair) = publish_anchored_hive_value(
        &mut set, prepared, receipt, 9, 0, LOG).ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());
    assert_eq!(set.hive(7).unwrap().query_value(key, "Value"),
        Some((RegistryValueType::Binary, &[2][..])));
}

#[test]
fn foreign_log_identity_retains_owner_and_cannot_publish() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Software);
    let key = hive.create_key("Target");
    hive.finish_clean_import();
    set.mount(r"\Registry\User\Retained", 7, hive).unwrap();
    let prepared = set.prepare_owned_set_value(
        7, key, "Target", "Value", RegistryValueType::Binary, alloc::vec![2]).unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 10, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (disk, receipt) = anchored_payload(payload);
    let (_, prepared, receipt) = publish_anchored_hive_value(
        &mut set, prepared, receipt, 9, 0, LOG).err().unwrap();
    assert_eq!(set.hive(7).unwrap().query_value(key, "Value"), None);
    assert!(set.release_unentered_owned_set_value(prepared).is_err());
    assert!(set.hive_mut(7).is_none());
    core::mem::forget(receipt);
    core::mem::forget(disk);
}

#[test]
fn exact_anchored_security_child_replays_only_after_publication() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Security);
    let root = hive.root();
    hive.finish_clean_import();
    set.mount(r"\Registry\Machine\Security", 7, hive).unwrap();
    let prepared = set.prepare_owned_create_child(
        7, root, "", "Policy", None, alloc::vec![1, 2, 3]).unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 9, expected_log_len: 0, path: SECURITY_LOG, record: prepared.record(),
    }).unwrap();
    let (_disk, receipt) = anchored_payload(payload);
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Policy"), None);
    let (child, continuation, pair) = publish_anchored_hive_child(
        &mut set, prepared, receipt, 9, 0, SECURITY_LOG).ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Policy"), Some(child));
}

#[test]
fn foreign_anchored_child_record_keeps_original_hive_owner_pinned() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Security);
    let root = hive.root();
    hive.finish_clean_import();
    set.mount(r"\Registry\Machine\Security", 7, hive).unwrap();
    let prepared = set.prepare_owned_create_child(
        7, root, "", "Policy", None, alloc::vec![1, 2, 3]).unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 10, expected_log_len: 0, path: SECURITY_LOG, record: prepared.record(),
    }).unwrap();
    let (disk, receipt) = anchored_payload(payload);
    let (_, prepared, receipt) = publish_anchored_hive_child(
        &mut set, prepared, receipt, 9, 0, SECURITY_LOG).err().unwrap();
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Policy"), None);
    assert!(set.release_unentered_owned_create_child(prepared).is_err());
    assert!(set.hive_mut(7).is_none());
    core::mem::forget(receipt);
    core::mem::forget(disk);
}

#[test]
fn exact_anchored_security_repair_publishes_after_durable_record() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Security);
    let policy = hive.create_key("Policy");
    hive.finish_clean_import();
    set.mount(r"\Registry\Machine\Security", 7, hive).unwrap();
    let prepared = set.prepare_owned_set_key_security(
        7, policy, "Policy", alloc::vec![1, 2, 3]).unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 9, expected_log_len: 0, path: SECURITY_LOG, record: prepared.record(),
    }).unwrap();
    let (_disk, receipt) = anchored_payload(payload);
    assert_eq!(set.hive(7).unwrap().key_security_descriptor(policy), None);
    let (continuation, pair) = publish_anchored_hive_security(
        &mut set, prepared, receipt, 9, 0, SECURITY_LOG).ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());
    assert_eq!(set.hive(7).unwrap().key_security_descriptor(policy), Some(&[1, 2, 3][..]));
}

#[test]
fn foreign_anchored_security_record_keeps_descriptor_unpublished() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Security);
    let policy = hive.create_key("Policy");
    hive.finish_clean_import();
    set.mount(r"\Registry\Machine\Security", 7, hive).unwrap();
    let prepared = set.prepare_owned_set_key_security(
        7, policy, "Policy", alloc::vec![1, 2, 3]).unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 10, expected_log_len: 0, path: SECURITY_LOG, record: prepared.record(),
    }).unwrap();
    let (disk, receipt) = anchored_payload(payload);
    let (_, prepared, receipt) = publish_anchored_hive_security(
        &mut set, prepared, receipt, 9, 0, SECURITY_LOG).err().unwrap();
    assert_eq!(set.hive(7).unwrap().key_security_descriptor(policy), None);
    assert!(set.release_unentered_owned_set_key_security(prepared).is_err());
    assert!(set.hive_mut(7).is_none());
    core::mem::forget(receipt);
    core::mem::forget(disk);
}

fn mounted_leaf_for_deletion() -> (MutableHiveSet, nt_hive_core::CellId, nt_hive_core::CellId) {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Software);
    let root = hive.root();
    let leaf = hive.create_key("Leaf");
    assert!(hive.set_value(leaf, "Obsolete", RegistryValueType::Binary, alloc::vec![4]));
    hive.finish_clean_import();
    set.mount(r"\Registry\User\Retained", 7, hive).unwrap();
    (set, root, leaf)
}

#[test]
fn exact_anchor_publishes_delete_value_only_after_paired_headers() {
    let (mut set, _, leaf) = mounted_leaf_for_deletion();
    let prepared = set.prepare_owned_delete_value(7, leaf, "Leaf", "Obsolete").unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 9, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (_disk, receipt) = anchored_payload(payload);
    assert!(set.hive(7).unwrap().query_value(leaf, "Obsolete").is_some());
    let (continuation, pair) = publish_anchored_hive_delete_value(
        &mut set, prepared, receipt, 9, 0, LOG).ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());
    assert_eq!(set.hive(7).unwrap().query_value(leaf, "Obsolete"), None);
}

#[test]
fn wrong_delete_value_payload_retains_both_move_only_owners() {
    let (mut set, _, leaf) = mounted_leaf_for_deletion();
    let prepared = set.prepare_owned_delete_value(7, leaf, "Leaf", "Obsolete").unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 10, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (disk, receipt) = anchored_payload(payload);
    let (error, prepared, receipt) = publish_anchored_hive_delete_value(
        &mut set, prepared, receipt, 9, 0, LOG).err().unwrap();
    assert_eq!(error, HiveWalPublicationError::WrongPayload);
    assert!(set.hive(7).unwrap().query_value(leaf, "Obsolete").is_some());
    assert!(set.release_unentered_owned_delete_value(prepared).is_err());
    assert!(set.hive_mut(7).is_none());
    core::mem::forget(receipt);
    core::mem::forget(disk);
}

#[test]
fn wrong_delete_value_hive_retains_both_move_only_owners() {
    let (mut set, _, leaf) = mounted_leaf_for_deletion();
    let mut other = MutableHiveSet::new();
    let prepared = set.prepare_owned_delete_value(7, leaf, "Leaf", "Obsolete").unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 9, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (disk, receipt) = anchored_payload(payload);
    let (error, prepared, receipt) = publish_anchored_hive_delete_value(
        &mut other, prepared, receipt, 9, 0, LOG).err().unwrap();
    assert_eq!(error, HiveWalPublicationError::WrongHiveOwner);
    assert!(set.hive(7).unwrap().query_value(leaf, "Obsolete").is_some());
    assert!(set.release_unentered_owned_delete_value(prepared).is_err());
    assert!(set.hive_mut(7).is_none());
    core::mem::forget(receipt);
    core::mem::forget(disk);
}

#[test]
fn exact_anchor_publishes_delete_key_and_its_values_only_after_paired_headers() {
    let (mut set, root, leaf) = mounted_leaf_for_deletion();
    let prepared = set.prepare_owned_delete_key(7, leaf, "Leaf").unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 9, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (_disk, receipt) = anchored_payload(payload);
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Leaf"), Some(leaf));
    let (continuation, pair) = publish_anchored_hive_delete_key(
        &mut set, prepared, receipt, 9, 0, LOG).ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Leaf"), None);
    assert_eq!(set.hive(7).unwrap().query_value(leaf, "Obsolete"), None);
}

#[test]
fn wrong_delete_key_payload_retains_both_move_only_owners() {
    let (mut set, root, leaf) = mounted_leaf_for_deletion();
    let prepared = set.prepare_owned_delete_key(7, leaf, "Leaf").unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 10, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (disk, receipt) = anchored_payload(payload);
    let (error, prepared, receipt) = publish_anchored_hive_delete_key(
        &mut set, prepared, receipt, 9, 0, LOG).err().unwrap();
    assert_eq!(error, HiveWalPublicationError::WrongPayload);
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Leaf"), Some(leaf));
    assert!(set.release_unentered_owned_delete_key(prepared).is_err());
    assert!(set.hive_mut(7).is_none());
    core::mem::forget(receipt);
    core::mem::forget(disk);
}

#[test]
fn wrong_delete_key_hive_retains_both_move_only_owners() {
    let (mut set, root, leaf) = mounted_leaf_for_deletion();
    let mut other = MutableHiveSet::new();
    let prepared = set.prepare_owned_delete_key(7, leaf, "Leaf").unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 9, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (disk, receipt) = anchored_payload(payload);
    let (error, prepared, receipt) = publish_anchored_hive_delete_key(
        &mut other, prepared, receipt, 9, 0, LOG).err().unwrap();
    assert_eq!(error, HiveWalPublicationError::WrongHiveOwner);
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Leaf"), Some(leaf));
    assert!(set.release_unentered_owned_delete_key(prepared).is_err());
    assert!(set.hive_mut(7).is_none());
    core::mem::forget(receipt);
    core::mem::forget(disk);
}
