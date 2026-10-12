use super::*;
use crate::RegistryWal;

fn base() -> WalSnapshotManifest {
    WalSnapshotManifest {
        incarnation: 77,
        base_serial: 0,
        high_water_serial: 0,
        high_water_end_lba: 0,
    }
}

fn two_v2_slots() -> (SnapshotBlockStore, CachedDisk) {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store
        .commit_next_with_wal_manifest(&mut disk, b"older", base())
        .unwrap();
    store
        .commit_next_with_wal_manifest(&mut disk, b"newer", base())
        .unwrap();
    disk.events.clear();
    (store, disk)
}

fn one_committed_wal() -> RegistryWal<CachedDisk> {
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(16), 77).unwrap();
    wal.begin(alloc::vec![7; 1536]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    wal
}

#[test]
fn v1_header_bytes_and_reads_remain_unchanged() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store.commit_next(&mut disk, b"legacy").unwrap();
    assert_eq!(&disk.stable[8..12], &[48, 0, 1, 0]);
    assert_eq!(
        store.read_latest(&mut disk).unwrap().unwrap().payload,
        b"legacy"
    );
    assert_eq!(
        store.read_latest_wal(&mut disk),
        Err(SnapshotBlockStoreError::Corrupt)
    );
}

#[test]
fn v2_manifest_survives_both_snapshot_slots() {
    let (store, mut disk) = two_v2_slots();
    let restored = store.read_latest_wal(&mut disk).unwrap().unwrap();
    assert_eq!(restored.snapshot.payload, b"newer");
    assert_eq!(restored.selected_base_serial, 0);
    assert_eq!(
        restored.anchor,
        WalSnapshotAnchor {
            incarnation: 77,
            serial: 0,
            end_lba: 0
        }
    );
}

#[test]
fn anchor_advances_only_after_two_header_barriers() {
    let (store, disk) = two_v2_slots();
    let next = WalSnapshotAnchor {
        incarnation: 77,
        serial: 1,
        end_lba: 5,
    };
    let mut update = WalSnapshotAnchorUpdate::admit(store, disk, next)
        .ok()
        .unwrap();
    update.advance().unwrap();
    let mut disk = update.into_device().unwrap();
    assert_eq!(
        disk.events,
        [Event::Write(0), Event::Flush, Event::Write(8), Event::Flush]
    );
    disk.power_cut();
    let restored = store.read_latest_wal(&mut disk).unwrap().unwrap();
    assert_eq!(restored.anchor, next);
    let missing = RegistryWal::recover(CachedDisk::with_sectors(16), 77).unwrap();
    assert_eq!(
        restored.verify_recovered_wal(&missing),
        Err(SnapshotBlockStoreError::Corrupt)
    );
    assert_eq!(restored.verify_recovered_wal(&one_committed_wal()), Ok(()));
}

#[test]
fn power_cut_between_header_updates_keeps_newer_high_water_visible() {
    let (store, mut disk) = two_v2_slots();
    disk.fail_event = Some(3);
    let next = WalSnapshotAnchor {
        incarnation: 77,
        serial: 1,
        end_lba: 5,
    };
    let mut update = WalSnapshotAnchorUpdate::admit(store, disk, next)
        .ok()
        .unwrap();
    assert_eq!(update.advance(), Err(SnapshotBlockStoreError::Io));
    let mut disk = update.into_device_for_test();
    disk.power_cut();
    assert_eq!(
        store.read_latest_wal(&mut disk).unwrap().unwrap().anchor,
        next
    );
}

#[test]
fn fallback_payload_keeps_the_anchored_serial() {
    let (store, disk) = two_v2_slots();
    let next = WalSnapshotAnchor {
        incarnation: 77,
        serial: 1,
        end_lba: 5,
    };
    let mut update = WalSnapshotAnchorUpdate::admit(store, disk, next)
        .ok()
        .unwrap();
    update.advance().unwrap();
    let mut disk = update.into_device().unwrap();
    disk.corrupt(9);
    let restored = store.read_latest_wal(&mut disk).unwrap().unwrap();
    assert_eq!(restored.snapshot.payload, b"older");
    assert_eq!(restored.anchor, next);
    let missing = RegistryWal::recover(CachedDisk::with_sectors(16), 77).unwrap();
    assert_eq!(
        restored.verify_recovered_wal(&missing),
        Err(SnapshotBlockStoreError::Corrupt)
    );
}

#[test]
fn anchored_suffix_erasure_is_rejected_after_power_cut() {
    use crate::BoundedBlockRange;
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::with_sectors(48);
    store
        .commit_next_with_wal_manifest(&mut disk, b"older", base())
        .unwrap();
    store
        .commit_next_with_wal_manifest(&mut disk, b"newer", base())
        .unwrap();
    {
        let view = BoundedBlockRange::new(&mut disk, 16, 32).unwrap();
        let mut wal = RegistryWal::recover(view, 77).unwrap();
        wal.begin(alloc::vec![7; 512]).unwrap();
        wal.prepare().unwrap();
        wal.commit().unwrap();
        drop(wal.into_device().unwrap());
    }
    let anchor = WalSnapshotAnchor {
        incarnation: 77,
        serial: 1,
        end_lba: 3,
    };
    let mut update = WalSnapshotAnchorUpdate::admit(store, disk, anchor)
        .ok()
        .unwrap();
    update.advance().unwrap();
    let mut disk = update.into_device().unwrap();
    disk.power_cut();
    let restored = store.read_latest_wal(&mut disk).unwrap().unwrap();
    {
        let view = BoundedBlockRange::new(&mut disk, 16, 32).unwrap();
        let wal = RegistryWal::recover(view, 77).unwrap();
        assert_eq!(restored.verify_recovered_wal(&wal), Ok(()));
    }
    disk.stable[16 * 512..19 * 512].fill(0);
    disk.cache[16 * 512..19 * 512].fill(0);
    let view = BoundedBlockRange::new(&mut disk, 16, 32).unwrap();
    let erased = RegistryWal::recover(view, 77).unwrap();
    assert_eq!(
        restored.verify_recovered_wal(&erased),
        Err(SnapshotBlockStoreError::Corrupt)
    );
}

#[test]
fn one_v2_slot_cannot_admit_an_anchor_update() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store
        .commit_next_with_wal_manifest(&mut disk, b"only", base())
        .unwrap();
    let next = WalSnapshotAnchor {
        incarnation: 77,
        serial: 1,
        end_lba: 5,
    };
    assert!(matches!(
        WalSnapshotAnchorUpdate::admit(store, disk, next),
        Err((SnapshotBlockStoreError::Corrupt, _))
    ));
}

#[test]
fn mixed_legacy_and_v2_slots_cannot_enter_wal_recovery() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store.commit_next(&mut disk, b"legacy").unwrap();
    store
        .commit_next_with_wal_manifest(&mut disk, b"candidate", base())
        .unwrap();
    assert_eq!(
        store.read_latest_wal(&mut disk),
        Err(SnapshotBlockStoreError::Corrupt)
    );
}

#[test]
fn snapshot_commit_cannot_advance_only_one_anchor_copy() {
    let (store, mut disk) = two_v2_slots();
    let changed = WalSnapshotManifest {
        high_water_serial: 1,
        high_water_end_lba: 5,
        ..base()
    };
    disk.events.clear();
    assert_eq!(
        store.commit_next_with_wal_manifest(&mut disk, b"bad", changed),
        Err(SnapshotBlockStoreError::Corrupt)
    );
    assert_eq!(disk.events, [Event::Flush]);
}

#[test]
fn snapshot_commit_cannot_erase_the_only_advanced_anchor_copy() {
    let (store, mut disk) = two_v2_slots();
    disk.fail_event = Some(3);
    let next = WalSnapshotAnchor {
        incarnation: 77,
        serial: 1,
        end_lba: 3,
    };
    let mut update = WalSnapshotAnchorUpdate::admit(store, disk, next)
        .ok()
        .unwrap();
    assert_eq!(update.advance(), Err(SnapshotBlockStoreError::Io));
    let mut disk = update.into_device_for_test();
    disk.power_cut();
    disk.events.clear();
    disk.fail_event = None;
    assert_eq!(
        store.commit_next_with_wal_manifest(&mut disk, b"would erase anchor", base()),
        Err(SnapshotBlockStoreError::Corrupt)
    );
    assert_eq!(disk.events, [Event::Flush]);
    assert_eq!(
        store.read_latest_wal(&mut disk).unwrap().unwrap().anchor,
        next
    );
}

#[test]
fn anchored_serial_requires_its_own_exact_endpoint() {
    let (store, disk) = two_v2_slots();
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(16), 77).unwrap();
    for byte in [7, 8] {
        wal.begin(alloc::vec![byte; 512]).unwrap();
        wal.prepare().unwrap();
        wal.commit().unwrap();
    }
    let next = WalSnapshotAnchor {
        incarnation: 77,
        serial: 1,
        end_lba: 4,
    };
    let mut update = WalSnapshotAnchorUpdate::admit(store, disk, next)
        .ok()
        .unwrap();
    update.advance().unwrap();
    let mut disk = update.into_device().unwrap();
    let restored = store.read_latest_wal(&mut disk).unwrap().unwrap();
    assert_eq!(
        restored.verify_recovered_wal(&wal),
        Err(SnapshotBlockStoreError::Corrupt)
    );
}

#[test]
fn recovery_can_anchor_a_verified_committed_prefix_before_new_mutations() {
    let (store, disk) = two_v2_slots();
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(16), 77).unwrap();
    for byte in [7, 8] {
        wal.begin(alloc::vec![byte; 512]).unwrap();
        wal.prepare().unwrap();
        wal.commit().unwrap();
    }
    let next = WalSnapshotAnchor {
        incarnation: 77,
        serial: 2,
        end_lba: 6,
    };
    let (error, disk) = WalSnapshotAnchorUpdate::admit(store, disk, next)
        .err()
        .unwrap();
    assert_eq!(error, SnapshotBlockStoreError::Corrupt);
    let mut update = WalSnapshotAnchorUpdate::admit_verified_prefix(store, disk, next, &wal)
        .ok()
        .unwrap();
    update.advance().unwrap();
    let mut disk = update.into_device().unwrap();
    assert_eq!(
        store.read_latest_wal(&mut disk).unwrap().unwrap().anchor,
        next
    );
}

#[test]
fn recovery_repairs_one_advanced_header_with_verified_wal() {
    let (store, mut disk) = two_v2_slots();
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(16), 77).unwrap();
    wal.begin(alloc::vec![7; 512]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let next = WalSnapshotAnchor {
        incarnation: 77,
        serial: 1,
        end_lba: 3,
    };
    disk.fail_event = Some(3);
    let mut interrupted = WalSnapshotAnchorUpdate::admit(store, disk, next)
        .ok()
        .unwrap();
    assert_eq!(interrupted.advance(), Err(SnapshotBlockStoreError::Io));
    let mut disk = interrupted.into_device_for_test();
    disk.power_cut();
    disk.fail_event = None;
    let mut repair = WalSnapshotAnchorUpdate::admit_verified_prefix(store, disk, next, &wal)
        .ok()
        .unwrap();
    repair.advance().unwrap();
    let mut disk = repair.into_device().unwrap();
    assert_eq!(
        store.read_latest_wal(&mut disk).unwrap().unwrap().anchor,
        next
    );
}
