use crate::snapshot_test_device::CachedDisk;
use crate::{
    publish_anchored_hive_value, AnchoredWalPublication, AsyncSnapshotHeaderRecheck,
    AsyncSnapshotIoKind, AsyncWalSnapshotAnchorUpdate, HiveLogWalPayload, OwnedBoundedBlockRange,
    RegistryWal, SnapshotBlockDevice, SnapshotBlockStore, WalSnapshotManifest,
};
use nt_hive_core::{Hive, HiveKind, MutableHiveSet, RegistryValueType};

const LOG: &str = r"\Registry\User\Retained.LOG";

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
