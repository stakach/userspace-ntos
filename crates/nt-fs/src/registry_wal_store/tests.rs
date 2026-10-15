use super::*;
use crate::snapshot_test_device::CachedDisk;
use crate::{BoundedBlockRange, OwnedBoundedBlockRange, SnapshotBlockStore, SnapshotReserve, WalSnapshotAnchor};
extern crate std;

fn disk() -> CachedDisk {
    CachedDisk::with_sectors(32)
}

#[test]
fn settled_wal_anchor_is_exact_and_unavailable_during_an_effect() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    assert_eq!(wal.settled_anchor(), Some(WalSnapshotAnchor {
        incarnation: 77, serial: 0, end_lba: 0,
    }));
    wal.begin(alloc::vec![0x51; 512]).unwrap();
    assert_eq!(wal.settled_anchor(), None);
    wal.prepare().unwrap();
    assert_eq!(wal.settled_anchor(), None);
    wal.commit().unwrap();
    assert_eq!(wal.settled_anchor(), Some(WalSnapshotAnchor {
        incarnation: 77, serial: 1, end_lba: 3,
    }));
}

#[test]
fn unstarted_wal_record_can_be_cancelled_without_reusing_an_effect() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(alloc::vec![0x51; 512]).unwrap();
    wal.cancel_pending().unwrap();
    assert_eq!(wal.state(), RegistryWalState::Ready);
    assert!(wal.records().is_empty());
    assert_eq!(wal.settled_anchor(), Some(WalSnapshotAnchor {
        incarnation: 77, serial: 0, end_lba: 0,
    }));
    assert!(wal.into_device().is_ok());
}

#[test]
fn only_marked_records_survive_each_power_cut_boundary() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(alloc::vec![0x51; 600]).unwrap();
    wal.prepare().unwrap();
    let mut disk = wal.into_device_for_test();
    disk.power_cut();
    let mut wal = RegistryWal::recover(disk, 77).unwrap();
    assert!(wal.records().is_empty());
    assert_eq!(wal.state(), RegistryWalState::RecoveredUncommitted);
    wal.clear_recovered_tail().unwrap();

    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(alloc::vec![0x51; 600]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let mut disk = wal.into_device().unwrap();
    disk.power_cut();
    let wal = RegistryWal::recover(disk, 77).unwrap();
    assert_eq!(
        wal.records(),
        &[RegistryWalRecord {
            serial: 1,
            payload: alloc::vec![0x51; 600]
        }]
    );
}

#[test]
fn failed_marker_barrier_does_not_publish_unacknowledged_tail() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(alloc::vec![0x51; 600]).unwrap();
    wal.prepare().unwrap();
    wal.device_mut_for_test().fail_event = Some(5);
    assert_eq!(
        wal.commit(),
        Err(RegistryWalError::Storage(SnapshotBlockStoreError::Io))
    );
    assert_eq!(wal.state(), RegistryWalState::Uncertain);
    let mut disk = wal.into_device_for_test();
    disk.power_cut();
    let mut wal = RegistryWal::recover(disk, 77).unwrap();
    assert!(wal.records().is_empty());
    wal.clear_recovered_tail().unwrap();
}

#[test]
fn longer_unmarked_frame_must_be_cleared_before_shorter_reuse() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(alloc::vec![0x51; 1500]).unwrap();
    wal.prepare().unwrap();
    let mut disk = wal.into_device_for_test();
    disk.power_cut();
    let mut recovered = RegistryWal::recover(disk, 77).unwrap();
    assert_eq!(recovered.state(), RegistryWalState::RecoveredUncommitted);
    assert_eq!(
        recovered.begin(alloc::vec![1]),
        Err(RegistryWalError::InvalidState)
    );
    recovered.clear_recovered_tail().unwrap();
    recovered.begin(alloc::vec![7; 100]).unwrap();
    recovered.prepare().unwrap();
    recovered.commit().unwrap();
    let mut disk = recovered.into_device().unwrap();
    disk.power_cut();
    assert_eq!(
        RegistryWal::recover(disk, 77).unwrap().records(),
        &[RegistryWalRecord {
            serial: 1,
            payload: alloc::vec![7; 100]
        }]
    );
}

#[test]
fn failed_recovered_tail_clear_retains_uncertain_owner() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(alloc::vec![0x51; 1500]).unwrap();
    wal.prepare().unwrap();
    let mut disk = wal.into_device_for_test();
    disk.power_cut();
    let mut recovered = RegistryWal::recover(disk, 77).unwrap();
    let next_event = recovered.device_mut_for_test().events.len();
    recovered.device_mut_for_test().fail_event = Some(next_event);
    assert_eq!(
        recovered.clear_recovered_tail(),
        Err(RegistryWalError::Storage(SnapshotBlockStoreError::Io))
    );
    assert_eq!(recovered.state(), RegistryWalState::Uncertain);
    assert_eq!(
        recovered.begin(alloc::vec![1]),
        Err(RegistryWalError::Uncertain)
    );
    core::mem::forget(recovered);
}

#[test]
fn uncertain_marker_may_replay_after_reboot_but_cannot_be_retried_live() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(alloc::vec![0x51; 600]).unwrap();
    wal.prepare().unwrap();
    wal.device_mut_for_test().fail_event = Some(5);
    wal.device_mut_for_test().partial_flush = true;
    assert_eq!(
        wal.commit(),
        Err(RegistryWalError::Storage(SnapshotBlockStoreError::Io))
    );
    assert_eq!(wal.begin(alloc::vec![2]), Err(RegistryWalError::Uncertain));
    let mut disk = wal.into_device_for_test();
    disk.power_cut();
    assert_eq!(
        RegistryWal::recover(disk, 77).unwrap().records(),
        &[RegistryWalRecord {
            serial: 1,
            payload: alloc::vec![0x51; 600]
        }]
    );
}

#[test]
fn confirmed_precommit_abort_clears_prepared_frame_before_reuse() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(alloc::vec![1; 512]).unwrap();
    wal.prepare().unwrap();
    wal.abort_prepared().unwrap();
    wal.begin(alloc::vec![2; 512]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let mut disk = wal.into_device().unwrap();
    disk.power_cut();
    assert_eq!(
        RegistryWal::recover(disk, 77).unwrap().records(),
        &[RegistryWalRecord {
            serial: 1,
            payload: alloc::vec![2; 512]
        }]
    );
}

#[test]
fn confirmed_abort_clears_every_reserved_sector() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(alloc::vec![1; 600]).unwrap();
    wal.prepare().unwrap();
    wal.abort_prepared().unwrap();
    let mut disk = wal.into_device().unwrap();
    disk.power_cut();
    assert!(disk.stable[..4 * 512].iter().all(|byte| *byte == 0));
    assert!(RegistryWal::recover(disk, 77).unwrap().records().is_empty());
}

#[test]
fn interrupted_abort_clear_remains_recoverable_or_empty() {
    for (failed_event, partial) in [(7, false), (9, false), (9, true)] {
        let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
        wal.begin(alloc::vec![1; 600]).unwrap();
        wal.prepare().unwrap();
        wal.device_mut_for_test().fail_event = Some(failed_event);
        wal.device_mut_for_test().partial_flush = partial;
        assert_eq!(
            wal.abort_prepared(),
            Err(RegistryWalError::Storage(SnapshotBlockStoreError::Io))
        );
        assert_eq!(wal.state(), RegistryWalState::Uncertain);
        let mut disk = wal.into_device_for_test();
        disk.power_cut();
        let mut recovered = RegistryWal::recover(disk, 77).unwrap();
        assert!(recovered.records().is_empty());
        if recovered.state() == RegistryWalState::RecoveredUncommitted {
            recovered.clear_recovered_tail().unwrap();
        }
        assert_eq!(recovered.state(), RegistryWalState::Ready);
    }
}

#[test]
fn errors_retain_the_exact_pending_effect_and_exclude_replay() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(alloc::vec![0x31; 600]).unwrap();
    wal.device_mut_for_test().fail_event = Some(3);
    wal.device_mut_for_test().partial_flush = true;
    assert_eq!(
        wal.prepare(),
        Err(RegistryWalError::Storage(SnapshotBlockStoreError::Io))
    );
    assert_eq!(wal.state(), RegistryWalState::Uncertain);
    assert_eq!(wal.begin(alloc::vec![9]), Err(RegistryWalError::Uncertain));
    assert_eq!(wal.commit(), Err(RegistryWalError::Uncertain));
    let retained = wal.into_device().err().unwrap();
    core::mem::forget(retained);
}

#[test]
fn dropping_uncertain_owner_does_not_release_snapshot_lease() {
    let reserve = SnapshotReserve::new(
        CachedDisk::with_sectors(48),
        7,
        SnapshotBlockStore::new(0, 32),
    );
    let lease = reserve.try_acquire().unwrap();
    let mut wal = RegistryWal::recover(lease, 77).unwrap();
    wal.begin(alloc::vec![1; 512]).unwrap();
    wal.device_mut_for_test().test_device_mut().fail_event = Some(2);
    assert_eq!(
        wal.prepare(),
        Err(RegistryWalError::Storage(SnapshotBlockStoreError::Io))
    );
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(wal))).is_err());
    assert!(reserve.try_acquire().is_none());
}

#[test]
fn corrupt_committed_payload_and_wrong_incarnation_fail_closed() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(alloc::vec![0x51; 600]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let disk = wal.into_device().unwrap();
    assert!(matches!(
        RegistryWal::recover(disk, 78),
        Err(RegistryWalError::WrongIncarnation)
    ));

    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(alloc::vec![0x51; 600]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let mut disk = wal.into_device().unwrap();
    disk.corrupt(1);
    assert!(matches!(
        RegistryWal::recover(disk, 77),
        Err(RegistryWalError::Corrupt)
    ));
}

#[test]
fn two_commits_recover_in_serial_order_and_bad_marker_is_corruption() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    for byte in [1, 2] {
        wal.begin(alloc::vec![byte; 512]).unwrap();
        wal.prepare().unwrap();
        wal.commit().unwrap();
    }
    let mut disk = wal.into_device().unwrap();
    disk.power_cut();
    assert_eq!(
        RegistryWal::recover(disk, 77).unwrap().records(),
        &[
            RegistryWalRecord {
                serial: 1,
                payload: alloc::vec![1; 512]
            },
            RegistryWalRecord {
                serial: 2,
                payload: alloc::vec![2; 512]
            },
        ]
    );

    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(alloc::vec![1; 512]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let mut disk = wal.into_device().unwrap();
    disk.corrupt(2);
    assert!(matches!(
        RegistryWal::recover(disk, 77),
        Err(RegistryWalError::Corrupt)
    ));
}

#[test]
fn zeroed_committed_header_and_dirty_suffix_fail_closed() {
    let mut wal = RegistryWal::recover(self::disk(), 77).unwrap();
    wal.begin(alloc::vec![0; 512]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let mut disk = wal.into_device().unwrap();
    disk.stable[..512].fill(0);
    disk.cache[..512].fill(0);
    assert!(matches!(
        RegistryWal::recover(disk, 77),
        Err(RegistryWalError::Corrupt)
    ));

    let mut disk = self::disk();
    disk.stable[2 * 512] = 1;
    disk.cache[2 * 512] = 1;
    assert!(matches!(
        RegistryWal::recover(disk, 77),
        Err(RegistryWalError::Corrupt)
    ));
}

#[test]
fn capacity_is_checked_before_writing_and_commits_are_ordered() {
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(4), 77).unwrap();
    assert_eq!(
        wal.begin(alloc::vec![0x51; 1025]),
        Err(RegistryWalError::OutOfSpace)
    );
    assert!(wal.device_mut_for_test().events.is_empty());
    wal.begin(alloc::vec![1; 512]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    assert_eq!(
        wal.begin(alloc::vec![2; 512]),
        Err(RegistryWalError::OutOfSpace)
    );
    let disk = wal.into_device().unwrap();
    assert_eq!(
        disk.events,
        alloc::vec![
            crate::snapshot_test_device::Event::Write(0),
            crate::snapshot_test_device::Event::Write(1),
            crate::snapshot_test_device::Event::Flush,
            crate::snapshot_test_device::Event::Write(2),
            crate::snapshot_test_device::Event::Flush,
        ]
    );
}

#[test]
fn bounded_view_never_writes_snapshot_slots() {
    let reserve = SnapshotReserve::new(
        CachedDisk::with_sectors(48),
        7,
        SnapshotBlockStore::new(0, 32),
    );
    let mut lease = reserve.try_acquire().unwrap();
    let view = BoundedBlockRange::new(&mut lease, 32, 16).unwrap();
    let mut wal = RegistryWal::recover(view, 77).unwrap();
    wal.begin(alloc::vec![3; 700]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    drop(wal.into_device().unwrap());
    assert!(lease
        .test_device_mut()
        .events
        .iter()
        .all(|event| match event {
            crate::snapshot_test_device::Event::Write(lba) => (32..48).contains(lba),
            crate::snapshot_test_device::Event::Flush => true,
        }));
    lease.test_device_mut().power_cut();
    let view = BoundedBlockRange::new(&mut lease, 32, 16).unwrap();
    assert_eq!(
        RegistryWal::recover(view, 77).unwrap().records(),
        &[RegistryWalRecord {
            serial: 1,
            payload: alloc::vec![3; 700]
        }]
    );
}

#[test]
fn verified_prefix_transfers_the_same_owned_lease_for_anchor_publication() {
    let reserve = SnapshotReserve::new(
        CachedDisk::with_sectors(48),
        13,
        SnapshotBlockStore::new(0, 32),
    );
    let lease = reserve.try_acquire().unwrap();
    let owned = match OwnedBoundedBlockRange::new(lease, 32, 16) {
        Ok(owned) => owned,
        Err((error, _)) => panic!("valid WAL range: {error:?}"),
    };
    let mut wal = RegistryWal::recover(owned, 77).unwrap();
    wal.begin(alloc::vec![0x51; 600]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();

    let verified = wal.into_verified_device().unwrap();
    assert_eq!(verified.anchor(), WalSnapshotAnchor {
        incarnation: 77,
        serial: 1,
        end_lba: 4,
    });
    assert!(reserve.try_acquire().is_none());
    let lease = verified.into_device().into_device();
    assert_eq!(*lease.identity(), 13);
    drop(lease);
    assert!(reserve.try_acquire().is_some());
}

#[test]
fn uncertain_prefix_transfer_refuses_to_release_the_owned_lease() {
    let mut disk = CachedDisk::with_sectors(48);
    disk.fail_event = Some(2);
    let reserve = SnapshotReserve::new(disk, 14, SnapshotBlockStore::new(0, 32));
    let lease = reserve.try_acquire().unwrap();
    let owned = match OwnedBoundedBlockRange::new(lease, 32, 16) {
        Ok(owned) => owned,
        Err((error, _)) => panic!("valid WAL range: {error:?}"),
    };
    let mut wal = RegistryWal::recover(owned, 77).unwrap();
    wal.begin(alloc::vec![0x51; 512]).unwrap();
    assert_eq!(wal.prepare(), Err(RegistryWalError::Storage(SnapshotBlockStoreError::Io)));
    let retained = wal.into_verified_device().err().unwrap();
    assert_eq!(retained.state(), RegistryWalState::Uncertain);
    assert!(reserve.try_acquire().is_none());
    core::mem::forget(retained);
    assert!(reserve.try_acquire().is_none());
}

#[test]
fn verified_wal_device_advances_anchor_using_the_same_physical_lease() {
    use crate::{WalSnapshotAnchorUpdate, WalSnapshotManifest};

    let store = SnapshotBlockStore::new(0, 16);
    let reserve = SnapshotReserve::new(CachedDisk::with_sectors(32), 15, store);
    let mut lease = reserve.try_acquire().unwrap();
    let baseline = WalSnapshotManifest {
        incarnation: 77,
        base_serial: 0,
        high_water_serial: 0,
        high_water_end_lba: 0,
    };
    store.commit_next_with_wal_manifest(&mut lease, b"older", baseline).unwrap();
    store.commit_next_with_wal_manifest(&mut lease, b"newer", baseline).unwrap();
    let owned = match OwnedBoundedBlockRange::new(lease, 16, 16) {
        Ok(owned) => owned,
        Err((error, _)) => panic!("valid WAL range: {error:?}"),
    };
    let mut wal = RegistryWal::recover(owned, 77).unwrap();
    wal.begin(alloc::vec![7; 512]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let verified = wal.into_verified_device().unwrap();
    let mut update = WalSnapshotAnchorUpdate::admit_verified_wal(
        store,
        verified.into_full_device(),
    ).ok().unwrap();
    assert!(reserve.try_acquire().is_none());
    update.advance().unwrap();
    let mut lease = update.into_device().unwrap();
    assert_eq!(store.read_latest_wal(&mut lease).unwrap().unwrap().anchor,
        WalSnapshotAnchor { incarnation: 77, serial: 1, end_lba: 3 });
}

#[test]
fn rejected_anchor_admission_returns_verified_owner_with_lease_held() {
    use crate::{WalSnapshotAnchorUpdate, WalSnapshotManifest};

    let store = SnapshotBlockStore::new(0, 16);
    let reserve = SnapshotReserve::new(CachedDisk::with_sectors(32), 16, store);
    let mut lease = reserve.try_acquire().unwrap();
    let incompatible = WalSnapshotManifest {
        incarnation: 88,
        base_serial: 0,
        high_water_serial: 0,
        high_water_end_lba: 0,
    };
    store.commit_next_with_wal_manifest(&mut lease, b"older", incompatible).unwrap();
    store.commit_next_with_wal_manifest(&mut lease, b"newer", incompatible).unwrap();
    let owned = match OwnedBoundedBlockRange::new(lease, 16, 16) {
        Ok(owned) => owned,
        Err((error, _)) => panic!("valid WAL range: {error:?}"),
    };
    let mut wal = RegistryWal::recover(owned, 77).unwrap();
    wal.begin(alloc::vec![7; 512]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let verified = wal.into_verified_device().unwrap().into_full_device();
    let (error, verified) = match WalSnapshotAnchorUpdate::admit_verified_wal(store, verified) {
        Ok(_) => panic!("wrong incarnation must not advance anchor"),
        Err(error) => error,
    };
    assert_eq!(error, SnapshotBlockStoreError::Corrupt);
    assert!(reserve.try_acquire().is_none());
    drop(verified.into_device());
    assert!(reserve.try_acquire().is_some());
}

#[test]
fn uncertain_anchor_write_keeps_the_original_wal_reserve_lease() {
    use crate::{WalSnapshotAnchorUpdate, WalSnapshotManifest};

    let store = SnapshotBlockStore::new(0, 16);
    let reserve = SnapshotReserve::new(CachedDisk::with_sectors(32), 17, store);
    let mut lease = reserve.try_acquire().unwrap();
    let baseline = WalSnapshotManifest {
        incarnation: 77,
        base_serial: 0,
        high_water_serial: 0,
        high_water_end_lba: 0,
    };
    store.commit_next_with_wal_manifest(&mut lease, b"older", baseline).unwrap();
    store.commit_next_with_wal_manifest(&mut lease, b"newer", baseline).unwrap();
    // A one-sector WAL append emits five events. Fail the first anchor header
    // write after that append has reached its marker barrier.
    let fail_event = lease.test_device_mut().events.len() + 5;
    lease.test_device_mut().fail_event = Some(fail_event);
    let owned = OwnedBoundedBlockRange::new(lease, 16, 16).ok().unwrap();
    let mut wal = RegistryWal::recover(owned, 77).unwrap();
    wal.begin(alloc::vec![7; 512]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let verified = wal.into_verified_device().unwrap().into_full_device();
    let mut update = WalSnapshotAnchorUpdate::admit_verified_wal(store, verified)
        .ok()
        .unwrap();
    assert_eq!(update.advance(), Err(SnapshotBlockStoreError::Io));
    let retained = update.into_device().err().unwrap();
    assert!(reserve.try_acquire().is_none());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(retained))).is_err());
    assert!(reserve.try_acquire().is_none());
}
