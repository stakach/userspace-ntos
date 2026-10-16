use super::*;
use crate::RegistryWal;
use crate::{OwnedBoundedBlockRange, SnapshotReserve, WalSnapshotBaselineRepair};
extern crate std;

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

#[test]
fn paired_wal_journal_manifest_requires_two_payload_valid_slots() {
    let (store, mut disk) = two_v2_slots();
    disk.read_attempts = 0;
    assert_eq!(store.current_paired_wal_journal_manifest(&mut disk), Ok(base()));
    assert_eq!(disk.read_attempts, 4, "one header and one payload read per slot");

    disk.corrupt(1);
    assert_eq!(
        store.current_paired_wal_journal_manifest(&mut disk),
        Err(SnapshotBlockStoreError::Corrupt)
    );
}

#[test]
fn generic_v2_checkpoint_uses_selected_base_and_both_exact_anchor_copies() {
    let (store, mut disk) = two_v2_slots();
    assert_eq!(store.current_wal_checkpoint_manifest(&mut disk), Ok(base()));

    let mut folded = base();
    folded.base_serial = 1;
    folded.high_water_serial = 1;
    folded.high_water_end_lba = 3;
    let (store, mut disk) = two_v2_slots();
    let mut update = WalSnapshotAnchorUpdate::admit(
        store,
        disk,
        WalSnapshotAnchor { incarnation: 77, serial: 1, end_lba: 3 },
    )
    .ok()
    .unwrap();
    update.advance().unwrap();
    disk = update.into_device().unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"folded", folded).unwrap();
    assert_eq!(store.current_wal_checkpoint_manifest(&mut disk), Ok(folded));

    disk.events.clear();
    let manifest = store.current_wal_checkpoint_manifest(&mut disk).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"unrelated-file", manifest).unwrap();
    disk.power_cut();
    let restored = store.read_latest_wal(&mut disk).unwrap().unwrap();
    assert_eq!(restored.snapshot.payload, b"unrelated-file");
    assert_eq!(restored.selected_base_serial, 1);
    assert_eq!(restored.anchor.serial, 1);
}

#[test]
fn generic_v2_checkpoint_refuses_partial_anchor_and_legacy_pair_before_write() {
    let (store, mut disk) = two_v2_slots();
    disk.fail_event = Some(3);
    let mut update = WalSnapshotAnchorUpdate::admit(
        store,
        disk,
        WalSnapshotAnchor { incarnation: 77, serial: 1, end_lba: 3 },
    )
    .ok()
    .unwrap();
    assert_eq!(update.advance(), Err(SnapshotBlockStoreError::Io));
    let mut disk = update.into_device_for_test();
    disk.power_cut();
    disk.fail_event = None;
    disk.events.clear();
    assert_eq!(store.current_wal_checkpoint_manifest(&mut disk), Err(SnapshotBlockStoreError::Corrupt));
    assert!(!disk.events.iter().any(|event| matches!(event, Event::Write(_))));

    let mut disk = CachedDisk::new();
    store.commit_next(&mut disk, b"legacy").unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"mixed", base()).unwrap();
    disk.events.clear();
    assert_eq!(store.current_wal_checkpoint_manifest(&mut disk), Err(SnapshotBlockStoreError::Corrupt));
    assert!(!disk.events.iter().any(|event| matches!(event, Event::Write(_))));
}

#[test]
fn streamed_v2_boot_recovers_the_surviving_slot_after_a_torn_companion_payload() {
    let (store, mut disk) = two_v2_slots();
    // The generic writer first reuses slot 0. A failed payload barrier may persist that
    // payload while leaving its old, checksum-valid v2 header in place.
    disk.fail_event = Some(2);
    disk.partial_flush = true;
    assert_eq!(
        store.commit_next_with_wal_manifest(&mut disk, b"third", base()),
        Err(SnapshotBlockStoreError::Io)
    );
    disk.power_cut();
    assert_eq!(store.read_latest_wal(&mut disk).unwrap().unwrap().snapshot.payload, b"newer");

    let (metadata, payload) = store
        .read_latest_streaming_with_metadata(&mut disk, |reader| {
            let mut payload = alloc::vec![0; reader.remaining()];
            reader.read_exact(&mut payload)?;
            Ok(payload)
        })
        .unwrap()
        .unwrap();
    assert_eq!(metadata.generation, 2);
    assert_eq!(metadata.format, SnapshotReadFormat::Wal {
        selected_base_serial: 0,
        anchor: WalSnapshotAnchor { incarnation: 77, serial: 0, end_lba: 0 },
    });
    assert_eq!(payload, b"newer");
}

#[test]
fn generic_v2_checkpoint_repairs_a_torn_same_anchor_companion_under_the_same_device() {
    let (store, mut disk) = two_v2_slots();
    disk.fail_event = Some(2);
    disk.partial_flush = true;
    assert_eq!(
        store.commit_next_with_wal_manifest(&mut disk, b"third", base()),
        Err(SnapshotBlockStoreError::Io)
    );
    disk.power_cut();
    disk.events.clear();

    let manifest = store.current_wal_checkpoint_manifest(&mut disk).unwrap();
    assert_eq!(manifest, base());
    store
        .commit_next_with_wal_manifest(&mut disk, b"repaired", manifest)
        .unwrap();
    disk.power_cut();
    let restored = store.read_latest_wal(&mut disk).unwrap().unwrap();
    assert_eq!(restored.snapshot.payload, b"repaired");
    assert_eq!(restored.anchor, WalSnapshotAnchor { incarnation: 77, serial: 0, end_lba: 0 });
}

#[test]
fn wal_writer_refuses_torn_companion_before_marking_any_record() {
    let (store, mut disk) = two_v2_slots();
    disk.fail_event = Some(2);
    disk.partial_flush = true;
    assert_eq!(
        store.commit_next_with_wal_manifest(&mut disk, b"third", base()),
        Err(SnapshotBlockStoreError::Io)
    );
    disk.power_cut();
    disk.events.clear();
    let manifest = store.current_wal_checkpoint_manifest(&mut disk).unwrap();
    assert_eq!(manifest, base());
    assert_eq!(
        store.validate_wal_journal_manifest(&mut disk, manifest),
        Err(SnapshotBlockStoreError::Corrupt)
    );
    assert!(!disk.events.iter().any(|event| matches!(event, Event::Write(_))));
}

#[test]
fn torn_v2_companion_with_a_different_anchor_still_refuses_streaming_boot_and_checkpoint() {
    let (store, mut disk) = two_v2_slots();
    disk.fail_event = Some(3);
    let mut update = WalSnapshotAnchorUpdate::admit(
        store,
        disk,
        WalSnapshotAnchor { incarnation: 77, serial: 1, end_lba: 3 },
    )
    .ok()
    .unwrap();
    assert_eq!(update.advance(), Err(SnapshotBlockStoreError::Io));
    let mut disk = update.into_device_for_test();
    disk.power_cut();
    disk.corrupt(1);
    disk.events.clear();

    assert_eq!(store.read_latest_wal(&mut disk), Err(SnapshotBlockStoreError::Corrupt));
    assert_eq!(store.current_wal_checkpoint_manifest(&mut disk), Err(SnapshotBlockStoreError::Corrupt));
    let mut decoded = false;
    let result = store.read_latest_streaming_with_metadata(&mut disk, |_| {
        decoded = true;
        Ok(())
    });
    assert_eq!(result, Err(SnapshotBlockStoreError::Corrupt));
    assert!(!decoded);
    assert!(!disk.events.iter().any(|event| matches!(event, Event::Write(_))));
}

#[test]
fn interrupted_empty_wal_baseline_can_repair_the_mixed_pair() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store.commit_next(&mut disk, b"older").unwrap();
    store.commit_next(&mut disk, b"current").unwrap();
    store
        .commit_next_with_wal_manifest(&mut disk, b"current", base())
        .unwrap();
    disk.power_cut();
    assert_eq!(
        store.read_latest_wal(&mut disk),
        Err(SnapshotBlockStoreError::Corrupt)
    );

    assert_eq!(store.repair_empty_wal_baseline(&mut disk, 77), Ok(Some(4)));
    disk.power_cut();
    let restored = store.read_latest_wal(&mut disk).unwrap().unwrap();
    assert_eq!(restored.snapshot.payload, b"current");
    assert_eq!(restored.snapshot.generation, 4);
    assert_eq!(restored.anchor.incarnation, 77);
    assert_eq!(restored.anchor.serial, 0);
}

#[test]
fn boot_recovery_probe_identifies_only_an_empty_wal_migration() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::with_sectors(32);
    store.commit_next(&mut disk, b"older").unwrap();
    store.commit_next(&mut disk, b"current").unwrap();
    assert_eq!(store.boot_recovery_state(&mut disk), Ok(BootSnapshotRecovery::Ready));
    store.commit_next_with_wal_manifest(&mut disk, b"current", base()).unwrap();
    disk.power_cut();
    disk.events.clear();
    assert_eq!(store.boot_recovery_state(&mut disk), Ok(BootSnapshotRecovery::InterruptedEmptyBaseline { incarnation: 77 }));
    assert!(!disk.events.iter().any(|event| matches!(event, Event::Write(_))));

    let mut advanced = base();
    advanced.high_water_serial = 1;
    advanced.high_water_end_lba = 3;
    let mut disk = CachedDisk::with_sectors(32);
    store.commit_next(&mut disk, b"legacy").unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"newer", advanced).unwrap();
    disk.events.clear();
    assert_eq!(store.boot_recovery_state(&mut disk), Err(SnapshotBlockStoreError::Corrupt));
    assert!(!disk.events.iter().any(|event| matches!(event, Event::Write(_))));
}

#[test]
fn empty_wal_baseline_repair_survives_each_write_and_barrier_cut() {
    let store = SnapshotBlockStore::new(0, 16);
    for partial_flush in [false, true] {
        for failed_event in 0..6 {
            let mut disk = CachedDisk::new();
            store.commit_next(&mut disk, b"legacy").unwrap();
            store
                .commit_next_with_wal_manifest(&mut disk, b"v2-baseline", base())
                .unwrap();
            disk.events.clear();
            disk.fail_event = Some(failed_event);
            disk.partial_flush = partial_flush;
            let _ = store.repair_empty_wal_baseline(&mut disk, 77);
            disk.power_cut();
            store.repair_empty_wal_baseline(&mut disk, 77).unwrap();
            disk.power_cut();
            let selected = store.read_latest_wal(&mut disk).unwrap().unwrap();
            assert_eq!(selected.snapshot.payload, b"v2-baseline");
            assert_eq!(selected.anchor.serial, 0);
        }
    }
}

#[test]
fn empty_wal_baseline_repair_refuses_stale_or_advanced_mixed_slots_before_write() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store.commit_next(&mut disk, b"legacy").unwrap();
    store
        .commit_next_with_wal_manifest(&mut disk, b"newer", base())
        .unwrap();
    disk.events.clear();
    assert_eq!(
        store.repair_empty_wal_baseline(&mut disk, 88),
        Err(SnapshotBlockStoreError::Corrupt)
    );
    assert!(!disk
        .events
        .iter()
        .any(|event| matches!(event, Event::Write(_))));

    let mut advanced = base();
    advanced.high_water_serial = 1;
    advanced.high_water_end_lba = 3;
    let mut disk = CachedDisk::new();
    store.commit_next(&mut disk, b"legacy").unwrap();
    store
        .commit_next_with_wal_manifest(&mut disk, b"newer", advanced)
        .unwrap();
    disk.events.clear();
    assert_eq!(
        store.repair_empty_wal_baseline(&mut disk, 77),
        Err(SnapshotBlockStoreError::Corrupt)
    );
    assert!(!disk
        .events
        .iter()
        .any(|event| matches!(event, Event::Write(_))));
}

#[test]
fn owned_empty_wal_baseline_repair_keeps_the_verified_physical_lease() {
    let store = SnapshotBlockStore::new(0, 16);
    let reserve = SnapshotReserve::new(CachedDisk::with_sectors(32), 81, store);
    let mut lease = reserve.try_acquire().unwrap();
    store.commit_next(&mut lease, b"legacy").unwrap();
    store
        .commit_next_with_wal_manifest(&mut lease, b"baseline", base())
        .unwrap();
    let bounded = OwnedBoundedBlockRange::new(lease, 16, 16).ok().unwrap();
    let verified = RegistryWal::recover(bounded, 77)
        .unwrap()
        .into_verified_device()
        .unwrap()
        .into_full_device();
    let mut repair = WalSnapshotBaselineRepair::admit(store, verified).ok().unwrap();
    assert!(reserve.try_acquire().is_none());
    assert_eq!(repair.repair(), Ok(Some(3)));
    let mut lease = repair.into_verified_device().unwrap().into_device();
    assert_eq!(store.read_latest_wal(&mut lease).unwrap().unwrap().snapshot.payload, b"baseline");
}

#[test]
fn owned_migration_commits_current_volume_to_both_v2_slots_before_releasing_lease() {
    let store = SnapshotBlockStore::new(0, 16);
    let reserve = SnapshotReserve::new(CachedDisk::with_sectors(32), 83, store);
    let fs = crate::FileSystem::new(crate::MemFs::new());
    let expected = fs.export_volume_snapshot().unwrap();
    let mut lease = reserve.try_acquire().unwrap();
    fs.commit_volume_snapshot(&store, &mut lease).unwrap();
    fs.commit_volume_snapshot(&store, &mut lease).unwrap();
    let wal = OwnedBoundedBlockRange::new(lease, 16, 16).ok().unwrap();
    let verified = RegistryWal::recover(wal, 77)
        .unwrap()
        .into_verified_device()
        .unwrap()
        .into_full_device();
    let mut migration = WalSnapshotBaselineRepair::admit(store, verified).ok().unwrap();
    assert!(reserve.try_acquire().is_none());
    assert_eq!(migration.migrate(&fs), Ok(4));
    let mut lease = migration.into_verified_device().unwrap().into_device();
    lease.test_device_mut().power_cut();
    let selected = store.read_latest_wal(&mut lease).unwrap().unwrap();
    assert_eq!(selected.snapshot.payload, expected);
    assert_eq!(selected.snapshot.generation, 4);
    assert_eq!(selected.anchor.incarnation, 77);
    assert_eq!(selected.anchor.serial, 0);
    drop(lease);
    assert!(reserve.try_acquire().is_some());
}

#[test]
fn owned_empty_reserve_initialization_creates_two_v2_slots_before_release() {
    let store = SnapshotBlockStore::new(0, 16);
    let reserve = SnapshotReserve::new(CachedDisk::with_sectors(32), 85, store);
    let fs = crate::FileSystem::new(crate::MemFs::new());
    let expected = fs.export_volume_snapshot().unwrap();
    let lease = reserve.try_acquire().unwrap();
    let wal = OwnedBoundedBlockRange::new(lease, 16, 16).ok().unwrap();
    let verified = RegistryWal::recover(wal, 77).unwrap()
        .into_verified_device().unwrap().into_full_device();
    let mut initialization = WalSnapshotBaselineRepair::admit(store, verified).ok().unwrap();
    assert!(reserve.try_acquire().is_none());
    assert_eq!(initialization.initialize(&fs), Ok(2));
    let mut lease = initialization.into_verified_device().unwrap().into_device();
    lease.test_device_mut().power_cut();
    let selected = store.read_latest_wal(&mut lease).unwrap().unwrap();
    assert_eq!(selected.snapshot.payload, expected);
    assert_eq!(selected.anchor.incarnation, 77);
    assert_eq!(selected.anchor.serial, 0);
    assert_eq!(store.current_wal_checkpoint_manifest(&mut lease), Ok(base()));
}

#[test]
fn first_boot_single_v2_slot_is_repaired_after_power_loss() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::with_sectors(32);
    store.commit_next_with_wal_manifest(&mut disk, b"first-boot", base()).unwrap();
    disk.power_cut();
    assert_eq!(store.boot_recovery_state(&mut disk),
        Ok(BootSnapshotRecovery::InterruptedEmptyBaseline { incarnation: 77 }));
    let wal = OwnedBoundedBlockRange::new(disk, 16, 16).ok().unwrap();
    let verified = RegistryWal::recover(wal, 77).unwrap()
        .into_verified_device().unwrap().into_full_device();
    let mut repair = WalSnapshotBaselineRepair::admit(store, verified).ok().unwrap();
    assert_eq!(repair.repair(), Ok(Some(2)));
    let mut disk = repair.into_verified_device().unwrap().into_device();
    disk.power_cut();
    assert_eq!(store.current_wal_checkpoint_manifest(&mut disk), Ok(base()));
    assert_eq!(store.read_latest_wal(&mut disk).unwrap().unwrap().snapshot.payload, b"first-boot");
}

#[test]
fn composed_system_primary_and_empty_sidecar_survive_migration_crash_cuts() {
    const PRIMARY: &str = r"\??\C:\SYSTEM";
    const LOG: &str = r"\??\C:\SYSTEM.LOG";
    fn replace(fs: &mut crate::FileSystem, path: &str, bytes: &[u8]) {
        let opened = fs.zw_create_file(
            path, crate::FILE_WRITE_DATA | crate::SYNCHRONIZE, 0, 0,
            crate::FILE_OPEN_IF, crate::FILE_NON_DIRECTORY_FILE,
        );
        assert_eq!(opened.status, crate::STATUS_SUCCESS);
        assert_eq!(fs.replace_file_data_owned(opened.handle, bytes.to_vec()), crate::STATUS_SUCCESS);
        assert_eq!(fs.zw_close(opened.handle), crate::STATUS_SUCCESS);
    }
    let store = SnapshotBlockStore::new(0, 128);
    for partial_flush in [false, true] {
        for failed_event in 0..8 {
            let mut fs = crate::FileSystem::new(crate::MemFs::new());
            replace(&mut fs, PRIMARY, b"old-primary");
            replace(&mut fs, LOG, b"complete-v1-sidecar");
            let mut disk = CachedDisk::with_sectors(256);
            fs.commit_volume_snapshot(&store, &mut disk).unwrap();
            fs.commit_volume_snapshot(&store, &mut disk).unwrap();

            // This is the image after semantic composition of the v1 primary and LOG.
            replace(&mut fs, PRIMARY, b"composed-system-image");
            replace(&mut fs, LOG, b"");
            disk.events.clear();
            disk.fail_event = Some(failed_event);
            disk.partial_flush = partial_flush;
            let _ = fs.commit_volume_snapshot_with_wal_manifest(&store, &mut disk, base());
            disk.power_cut();
            disk.fail_event = None;
            match store.boot_recovery_state(&mut disk).unwrap() {
                BootSnapshotRecovery::Ready
                | BootSnapshotRecovery::InterruptedEmptyBaseline { incarnation: 77 } => {}
                state => panic!("unexpected recovery state: {state:?}"),
            }
            let range = OwnedBoundedBlockRange::new(disk, 128, 128).ok().unwrap();
            let verified = RegistryWal::recover(range, 77).unwrap()
                .into_verified_device().unwrap().into_full_device();
            let mut migration = WalSnapshotBaselineRepair::admit(store, verified).ok().unwrap();
            migration.migrate(&fs).unwrap();
            let mut disk = migration.into_verified_device().unwrap().into_device();
            disk.power_cut();
            let (restored, metadata) = crate::FileSystem::restore_volume_snapshot_with_metadata_from_store(
                &store, &mut disk,
            ).unwrap().unwrap();
            assert_eq!(restored.try_file_bytes_owned(PRIMARY).unwrap(), Some(b"composed-system-image".to_vec()));
            assert_eq!(restored.try_file_bytes_owned(LOG).unwrap(), Some(alloc::vec::Vec::new()));
            assert!(matches!(metadata.format, SnapshotReadFormat::Wal { selected_base_serial: 0, .. }));
        }
    }
}

#[test]
fn failed_first_v2_migration_write_retains_the_exact_lease() {
    let store = SnapshotBlockStore::new(0, 16);
    let reserve = SnapshotReserve::new(CachedDisk::with_sectors(32), 84, store);
    let fs = crate::FileSystem::new(crate::MemFs::new());
    let mut lease = reserve.try_acquire().unwrap();
    fs.commit_volume_snapshot(&store, &mut lease).unwrap();
    fs.commit_volume_snapshot(&store, &mut lease).unwrap();
    let fail = lease.test_device_mut().events.len() + 2;
    lease.test_device_mut().fail_event = Some(fail);
    let wal = OwnedBoundedBlockRange::new(lease, 16, 16).ok().unwrap();
    let verified = RegistryWal::recover(wal, 77)
        .unwrap()
        .into_verified_device()
        .unwrap()
        .into_full_device();
    let mut migration = WalSnapshotBaselineRepair::admit(store, verified).ok().unwrap();
    assert_eq!(migration.migrate(&fs), Err(SnapshotBlockStoreError::Io));
    let retained = migration.into_verified_device().err().unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(retained))).is_err());
    assert!(reserve.try_acquire().is_none());
}

#[test]
fn uncertain_baseline_repair_retains_the_same_reserve_lease() {
    let store = SnapshotBlockStore::new(0, 16);
    let reserve = SnapshotReserve::new(CachedDisk::with_sectors(32), 82, store);
    let mut lease = reserve.try_acquire().unwrap();
    store.commit_next(&mut lease, b"legacy").unwrap();
    store
        .commit_next_with_wal_manifest(&mut lease, b"baseline", base())
        .unwrap();
    let next = lease.test_device_mut().events.len();
    lease.test_device_mut().fail_event = Some(next + 3);
    lease.test_device_mut().partial_flush = true;
    let bounded = OwnedBoundedBlockRange::new(lease, 16, 16).ok().unwrap();
    let verified = RegistryWal::recover(bounded, 77)
        .unwrap()
        .into_verified_device()
        .unwrap()
        .into_full_device();
    let mut repair = WalSnapshotBaselineRepair::admit(store, verified).ok().unwrap();
    assert_eq!(repair.repair(), Err(SnapshotBlockStoreError::Io));
    let retained = repair.into_verified_device().err().unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(retained))).is_err());
    assert!(reserve.try_acquire().is_none());
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
    for payload in [
        b"already-in-snapshot".as_slice(),
        b"new-mutation".as_slice(),
    ] {
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
fn streamed_boot_snapshot_metadata_replays_only_verified_wal_suffix() {
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
    let (metadata, payload) = store
        .read_latest_streaming_with_metadata(&mut disk, |reader| {
            let mut payload = alloc::vec![0; reader.remaining()];
            reader.read_exact(&mut payload)?;
            Ok(payload)
        })
        .unwrap()
        .unwrap();
    assert_eq!(payload, b"newer");
    assert_eq!(metadata.generation, 2);

    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(16), 77).unwrap();
    for journal in [b"already-in-snapshot".as_slice(), b"new-mutation".as_slice()] {
        wal.begin(journal.to_vec()).unwrap();
        wal.prepare().unwrap();
        wal.commit().unwrap();
    }
    assert_eq!(
        metadata.verified_boot_system_log(b"snapshot-log", &wal),
        Ok(b"snapshot-lognew-mutation".to_vec())
    );
}

#[test]
fn streamed_boot_snapshot_metadata_refuses_missing_anchored_suffix() {
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
    let (metadata, _) = store
        .read_latest_streaming_with_metadata(&mut disk, |reader| {
            let mut payload = alloc::vec![0; reader.remaining()];
            reader.read_exact(&mut payload)?;
            Ok(payload)
        })
        .unwrap()
        .unwrap();
    let erased = RegistryWal::recover(CachedDisk::with_sectors(16), 77).unwrap();
    assert_eq!(
        metadata.verified_boot_system_log(b"snapshot-log", &erased),
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
    assert!(!disk
        .events
        .iter()
        .any(|event| matches!(event, Event::Write(_))));
    assert_eq!(
        store
            .read_latest_wal(&mut disk)
            .unwrap()
            .unwrap()
            .snapshot
            .payload,
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
    let newer = WalSnapshotManifest {
        base_serial: 0,
        ..older
    };
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
    assert_eq!(
        store.read_latest_metadata(&mut disk),
        Err(SnapshotBlockStoreError::Corrupt)
    );
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
    assert_eq!(
        store.read_latest_metadata(&mut disk),
        Err(SnapshotBlockStoreError::Corrupt)
    );
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
