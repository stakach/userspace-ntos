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
fn boot_system_log_replays_only_suffix_after_selected_snapshot_base() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    let manifest = WalSnapshotManifest {
        incarnation: 77,
        base_serial: 1,
        high_water_serial: 2,
        high_water_end_lba: 6,
    };
    store
        .commit_next_with_wal_manifest(&mut disk, b"older", manifest)
        .unwrap();
    store
        .commit_next_with_wal_manifest(&mut disk, b"newer", manifest)
        .unwrap();
    let selected = store.read_latest_wal(&mut disk).unwrap().unwrap();

    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(16), 77).unwrap();
    for payload in [b"already-in-snapshot".as_slice(), b"new-mutation".as_slice()] {
        wal.begin(payload.to_vec()).unwrap();
        wal.prepare().unwrap();
        wal.commit().unwrap();
    }
    assert_eq!(
        selected.verified_boot_system_log(b"snapshot-log", &wal),
        Ok(b"snapshot-lognew-mutation".to_vec())
    );
}

#[test]
fn boot_system_log_refuses_erased_anchored_suffix() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    let manifest = WalSnapshotManifest {
        incarnation: 77,
        base_serial: 0,
        high_water_serial: 1,
        high_water_end_lba: 3,
    };
    store
        .commit_next_with_wal_manifest(&mut disk, b"older", manifest)
        .unwrap();
    store
        .commit_next_with_wal_manifest(&mut disk, b"newer", manifest)
        .unwrap();
    let selected = store.read_latest_wal(&mut disk).unwrap().unwrap();
    let erased = RegistryWal::recover(CachedDisk::with_sectors(16), 77).unwrap();
    assert_eq!(
        selected.verified_boot_system_log(b"snapshot-log", &erased),
        Err(SnapshotBlockStoreError::Corrupt)
    );
}

#[test]
fn streamed_v2_checkpoint_preserves_a_complete_slot_at_each_write_barrier() {
    let manifest = base();
    for partial_flush in [false, true] {
        for fail_event in 0..5 {
            let (store, mut disk) = two_v2_slots();
            disk.fail_event = Some(fail_event);
            disk.partial_flush = partial_flush;
            assert_eq!(
                store.commit_next_streaming_with_wal_manifest(
                    &mut disk,
                    5,
                    crc32c(b"third"),
                    manifest,
                    |writer| writer.write_all(b"third"),
                ),
                Err(SnapshotBlockStoreError::Io)
            );
            disk.power_cut();
            let restored = store.read_latest_wal(&mut disk).unwrap().unwrap();
            assert!(restored.snapshot.payload == b"newer" || restored.snapshot.payload == b"third");
            assert_eq!(restored.anchor.incarnation, manifest.incarnation);
            assert_eq!(restored.anchor.serial, 0);
        }
    }
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
    let metadata = store.read_latest_metadata(&mut disk).unwrap().unwrap();
    assert_eq!(metadata.format, SnapshotReadFormat::Legacy);
    assert_eq!(metadata.generation, 1);
    assert_eq!(metadata.payload_len, b"legacy".len());
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
fn v2_checkpoint_cannot_regress_an_applied_wal_base() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    let mut manifest = WalSnapshotManifest {
        incarnation: 77,
        base_serial: 0,
        high_water_serial: 1,
        high_water_end_lba: 3,
    };
    store
        .commit_next_with_wal_manifest(&mut disk, b"before", manifest)
        .unwrap();
    manifest.base_serial = 1;
    store
        .commit_next_with_wal_manifest(&mut disk, b"applied", manifest)
        .unwrap();
    disk.events.clear();

    manifest.base_serial = 0;
    assert_eq!(
        store.commit_next_with_wal_manifest(&mut disk, b"regressed", manifest),
        Err(SnapshotBlockStoreError::Corrupt)
    );
    assert!(!disk.events.iter().any(|event| matches!(event, Event::Write(_))));
    assert_eq!(
        store.read_latest_wal(&mut disk).unwrap().unwrap().snapshot.payload,
        b"applied"
    );
}

#[test]
fn recovered_newer_snapshot_cannot_require_a_reclaimed_wal_prefix() {
    let older = WalSnapshotManifest {
        incarnation: 77,
        base_serial: 1,
        high_water_serial: 1,
        high_water_end_lba: 3,
    };
    let newer = WalSnapshotManifest { base_serial: 0, ..older };
    assert_eq!(
        wal_recovery_floor(newer, Some(older)),
        Err(SnapshotBlockStoreError::Corrupt)
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
fn metadata_selector_rejects_mixed_slots_before_streaming_payload() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store.commit_next(&mut disk, b"legacy").unwrap();
    store
        .commit_next_with_wal_manifest(&mut disk, b"candidate", base())
        .unwrap();
    assert_eq!(store.read_latest_metadata(&mut disk), Err(SnapshotBlockStoreError::Corrupt));
    let mut called = false;
    let result = store.read_latest_streaming_with_metadata(&mut disk, |_| {
        called = true;
        Ok(())
    });
    assert_eq!(result, Err(SnapshotBlockStoreError::Corrupt));
    assert!(!called);
}

#[test]
fn damaged_v2_header_cannot_downgrade_to_valid_legacy_slot() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store.commit_next(&mut disk, b"legacy").unwrap();
    store
        .commit_next_with_wal_manifest(&mut disk, b"candidate", base())
        .unwrap();
    disk.corrupt(8);
    assert_eq!(store.read_latest_metadata(&mut disk), Err(SnapshotBlockStoreError::Corrupt));
}

#[test]
fn metadata_selector_keeps_legacy_payload_fallback() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store.commit_next(&mut disk, b"older").unwrap();
    store.commit_next(&mut disk, b"newer").unwrap();
    disk.corrupt(9);
    let metadata = store.read_latest_metadata(&mut disk).unwrap().unwrap();
    assert_eq!(metadata.generation, 1);
    assert_eq!(metadata.format, SnapshotReadFormat::Legacy);
}

#[test]
fn metadata_and_streaming_payload_select_the_same_v2_generation() {
    let (store, mut disk) = two_v2_slots();
    let metadata = store.read_latest_metadata(&mut disk).unwrap().unwrap();
    let (streamed, payload) = store
        .read_latest_streaming_with_metadata(&mut disk, |reader| {
            let mut payload = alloc::vec![0; reader.remaining()];
            reader.read_exact(&mut payload)?;
            Ok(payload)
        })
        .unwrap()
        .unwrap();
    assert_eq!(metadata, streamed);
    assert_eq!(payload, b"newer");
    assert_eq!(
        metadata.format,
        SnapshotReadFormat::Wal {
            selected_base_serial: 0,
            anchor: WalSnapshotAnchor {
                incarnation: 77,
                serial: 0,
                end_lba: 0,
            },
        }
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
