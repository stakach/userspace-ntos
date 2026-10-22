use super::*;
use crate::{OwnedBoundedBlockRange, RegistryWal};

#[test]
fn native_anchor_requires_rechecked_pair_and_two_exact_write_flush_pairs() {
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
    let rechecked = recheck.finish_proven().ok().unwrap();
    let range = OwnedBoundedBlockRange::new(disk, 16, 16).ok().unwrap();
    let mut wal = RegistryWal::recover(range, 77).unwrap();
    wal.begin(alloc::vec![0x51; 512]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let verified = wal.into_verified_device().unwrap().into_full_device();
    let mut update = AsyncWalSnapshotAnchorUpdate::admit_verified_wal_pair(
        store, verified, rechecked).ok().unwrap();
    for (step, expected) in [
        (AsyncSnapshotIoKind::Write, 0), (AsyncSnapshotIoKind::Flush, 0),
        (AsyncSnapshotIoKind::Write, 8), (AsyncSnapshotIoKind::Flush, 0),
    ].into_iter().enumerate() {
        let request = update.enter_next().unwrap().unwrap();
        assert_eq!((request.kind, request.lba), expected);
        assert_eq!(update.enter_next(), Err(AsyncSnapshotCommitError::Outstanding));
        if step % 2 == 0 {
            let bytes = update.write_bytes(request).unwrap().to_vec();
            assert_eq!(bytes.len(), 512);
            update.device_for_test().write_sector(request.lba, &bytes).unwrap();
        } else {
            update.device_for_test().flush().unwrap();
        }
        update.complete(request, true).unwrap();
    }
    assert_eq!(update.enter_next(), Ok(None));
    let (mut disk, continuation, pair) = update.into_continuation_and_pair().ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());
    disk.power_cut();
    assert_eq!(store.read_latest_wal(&mut disk).unwrap().unwrap().anchor, pair.anchor());
}

#[test]
fn native_anchor_uncertain_completion_cannot_be_replayed_or_published() {
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
    wal.begin(alloc::vec![0x51; 512]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let verified = wal.into_verified_device().unwrap().into_full_device();
    let mut update = AsyncWalSnapshotAnchorUpdate::admit_verified_wal_pair(
        store, verified, recheck.finish_proven().ok().unwrap()).ok().unwrap();
    let request = update.enter_next().unwrap().unwrap();
    assert_eq!(update.complete(request, false),
        Err(AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Io)));
    assert_eq!(update.complete(request, true),
        Err(AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Io)));
    assert_eq!(update.enter_next(),
        Err(AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Io)));
    let retained = match update.into_continuation_and_pair() {
        Ok(_) => panic!("uncertain anchor published a continuation"),
        Err(retained) => retained,
    };
    // The unresolved owner intentionally remains pinned until recovery.
    core::mem::forget(retained);
}
