use super::*;
use crate::{OwnedBoundedBlockRange, RegistryWal, SnapshotReserve, WalSnapshotEpochRollover};

struct BatchCountDisk {
    inner: CachedDisk,
    single_writes: usize,
    range_writes: usize,
}

impl SnapshotBlockDevice for BatchCountDisk {
    fn sector_size(&self) -> usize { self.inner.sector_size() }
    fn sector_count(&self) -> u64 { self.inner.sector_count() }
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        self.inner.read_sector(lba, out)
    }
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        self.single_writes += 1;
        self.inner.write_sector(lba, data)
    }
    fn write_sectors(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        self.range_writes += 1;
        self.inner.write_sectors(lba, data)
    }
    fn flush(&mut self) -> Result<(), SnapshotBlockStoreError> { self.inner.flush() }
}

#[test]
fn rollover_erases_large_old_wal_in_bounded_reverse_ranges() {
    let store = SnapshotBlockStore::new(0, 16);
    let reserve = SnapshotReserve::new(BatchCountDisk {
        inner: CachedDisk::with_sectors(16 + 128),
        single_writes: 0,
        range_writes: 0,
    }, 83u64, store);
    let mut lease = reserve.try_acquire().unwrap();
    let initial = WalSnapshotManifest {
        incarnation: 77, base_serial: 0,
        high_water_serial: 0, high_water_end_lba: 0,
    };
    store.commit_next_with_wal_manifest(&mut lease, b"old", initial).unwrap();
    store.commit_next_with_wal_manifest(&mut lease, b"old", initial).unwrap();
    let range = OwnedBoundedBlockRange::new(lease, 16, 128).ok().unwrap();
    let mut wal = RegistryWal::recover(range, 77).unwrap();
    wal.begin(alloc::vec![7; 512]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let verified = wal.into_verified_device().unwrap().into_full_device();
    let mut anchor = WalSnapshotAnchorUpdate::admit_verified_wal(store, verified).ok().unwrap();
    anchor.advance().unwrap();
    let mut lease = anchor.into_device().unwrap();
    let folded = WalSnapshotManifest {
        incarnation: 77, base_serial: 1,
        high_water_serial: 1, high_water_end_lba: 3,
    };
    store.commit_next_with_wal_manifest(&mut lease, b"folded", folded).unwrap();
    store.commit_next_with_wal_manifest(&mut lease, b"folded", folded).unwrap();
    let range = OwnedBoundedBlockRange::new(lease, 16, 128).ok().unwrap();
    let verified = RegistryWal::recover(range, 77).unwrap().into_verified_device().unwrap();
    let mut rollover = WalSnapshotEpochRollover::admit(store, verified, 88).ok().unwrap();
    rollover.device_mut_for_test().test_device_mut().single_writes = 0;
    rollover.device_mut_for_test().test_device_mut().range_writes = 0;
    rollover.publish_resetting().unwrap();
    rollover.finish().unwrap();
    let (mut lease, next) = rollover.into_continuation().ok().unwrap();
    assert_eq!(next.anchor(), WalSnapshotAnchor { incarnation: 88, serial: 0, end_lba: 0 });
    assert!(lease.test_device_mut().range_writes >= 1);
    assert!(lease.test_device_mut().single_writes < 16);
}

fn old_epoch(folded: bool) -> (SnapshotBlockStore, SnapshotReserve<CachedDisk, u64>) {
    let store = SnapshotBlockStore::new(0, 16);
    let reserve = SnapshotReserve::new(CachedDisk::with_sectors(32), 83, store);
    let mut lease = reserve.try_acquire().unwrap();
    let initial = WalSnapshotManifest {
        incarnation: 77,
        base_serial: 0,
        high_water_serial: 0,
        high_water_end_lba: 0,
    };
    store.commit_next_with_wal_manifest(&mut lease, b"old", initial).unwrap();
    store.commit_next_with_wal_manifest(&mut lease, b"old", initial).unwrap();
    let range = OwnedBoundedBlockRange::new(lease, 16, 16).ok().unwrap();
    let mut wal = RegistryWal::recover(range, 77).unwrap();
    wal.begin(alloc::vec![7; 512]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let verified = wal.into_verified_device().unwrap().into_full_device();
    let mut anchor = WalSnapshotAnchorUpdate::admit_verified_wal(store, verified).ok().unwrap();
    anchor.advance().unwrap();
    let mut lease = anchor.into_device().unwrap();
    if folded {
        let complete = WalSnapshotManifest {
            incarnation: 77,
            base_serial: 1,
            high_water_serial: 1,
            high_water_end_lba: 3,
        };
        store.commit_next_with_wal_manifest(&mut lease, b"folded", complete).unwrap();
        store.commit_next_with_wal_manifest(&mut lease, b"folded", complete).unwrap();
    }
    drop(lease);
    (store, reserve)
}

#[test]
fn wal_epoch_rollover_refuses_unfolded_or_unanchored_prefix_before_write() {
    let (store, reserve) = old_epoch(false);
    let lease = reserve.try_acquire().unwrap();
    let range = OwnedBoundedBlockRange::new(lease, 16, 16).ok().unwrap();
    let mut verified = RegistryWal::recover(range, 77).unwrap()
        .into_verified_device().unwrap();
    verified.device_mut().parent_device_mut().test_device_mut().events.clear();
    let (error, verified) = WalSnapshotEpochRollover::admit(store, verified, 88)
        .err().unwrap();
    assert_eq!(error, SnapshotBlockStoreError::Corrupt);
    let mut verified = verified.into_full_device();
    assert!(!verified.device_mut().test_device_mut().events.iter()
        .any(|event| matches!(event, Event::Write(_))));
}

#[test]
fn wal_epoch_rollover_repairs_mixed_resetting_slots_before_erasing_old_wal() {
    let (store, reserve) = old_epoch(true);
    let lease = reserve.try_acquire().unwrap();
    let range = OwnedBoundedBlockRange::new(lease, 16, 16).ok().unwrap();
    let verified = RegistryWal::recover(range, 77).unwrap()
        .into_verified_device().unwrap();
    let mut rollover = WalSnapshotEpochRollover::admit(store, verified, 88)
        .ok().unwrap();
    assert!(reserve.try_acquire().is_none());
    rollover.publish_resetting().unwrap();
    let mut lease = rollover.into_device_for_test();
    lease.test_device_mut().power_cut();
    assert_eq!(store.read_latest_wal(&mut lease), Err(SnapshotBlockStoreError::Corrupt));
    let mut resumed = WalSnapshotEpochRollover::resume(store, lease, 16, 16).ok().unwrap();
    resumed.finish().unwrap();
    let mut lease = resumed.into_device().ok().unwrap();
    lease.test_device_mut().power_cut();
    let selected = store.read_latest_wal(&mut lease).unwrap().unwrap();
    assert_eq!(selected.snapshot.payload, b"folded");
    assert_eq!(selected.selected_base_serial, 0);
    assert_eq!(selected.anchor, WalSnapshotAnchor {
        incarnation: 88, serial: 0, end_lba: 0,
    });
    let range = OwnedBoundedBlockRange::new(lease, 16, 16).ok().unwrap();
    let wal = RegistryWal::recover(range, 88).unwrap();
    assert!(wal.records().is_empty());
}

#[test]
fn wal_epoch_rollover_recovers_every_reset_and_erasure_barrier_cut() {
    for partial_flush in [false, true] {
        for failed_event in 0..24 {
            let (store, reserve) = old_epoch(true);
            let lease = reserve.try_acquire().unwrap();
            let range = OwnedBoundedBlockRange::new(lease, 16, 16).ok().unwrap();
            let verified = RegistryWal::recover(range, 77).unwrap()
                .into_verified_device().unwrap();
            let mut first = WalSnapshotEpochRollover::admit(store, verified, 88)
                .ok().unwrap();
            first.publish_resetting().unwrap();
            let mut lease = first.into_device_for_test();
            lease.test_device_mut().power_cut();
            lease.test_device_mut().events.clear();
            let mut resumed = WalSnapshotEpochRollover::resume(store, lease, 16, 16)
                .ok().unwrap();
            // The owner keeps the lease if any write or durability barrier is uncertain.
            // Simulate a power cut and recover using only the persisted phase headers.
            resumed.device_mut_for_test().test_device_mut().fail_event = Some(failed_event);
            resumed.device_mut_for_test().test_device_mut().partial_flush = partial_flush;
            let _ = resumed.finish();
            let mut lease = resumed.into_device_for_test();
            lease.test_device_mut().power_cut();
            lease.test_device_mut().events.clear();
            if store.read_latest_wal(&mut lease).is_err() {
                let mut recovery = WalSnapshotEpochRollover::resume(store, lease, 16, 16)
                    .ok().unwrap();
                recovery.finish().unwrap();
                lease = recovery.into_device().ok().unwrap();
                lease.test_device_mut().power_cut();
            }
            let selected = store.read_latest_wal(&mut lease).unwrap().unwrap();
            assert_eq!(selected.snapshot.payload, b"folded");
            assert_eq!(selected.anchor.incarnation, 88);
            assert_eq!(selected.anchor.serial, 0);
            let range = OwnedBoundedBlockRange::new(lease, 16, 16).ok().unwrap();
            assert!(RegistryWal::recover(range, 88).unwrap().records().is_empty());
        }
    }
}
