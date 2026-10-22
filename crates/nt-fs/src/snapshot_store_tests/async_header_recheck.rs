use super::*;

fn manifest() -> WalSnapshotManifest {
    WalSnapshotManifest { incarnation: 17, base_serial: 0,
        high_water_serial: 0, high_water_end_lba: 0 }
}

#[test]
fn async_header_recheck_reads_exact_pair_and_rejects_changed_header() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store.commit_next_with_wal_manifest(&mut disk, b"older", manifest()).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"newer", manifest()).unwrap();
    let proof = store.verify_paired_wal_snapshot(&mut disk).unwrap();
    let mut recheck = AsyncSnapshotHeaderRecheck::new(
        store, proof, disk.sector_size(), disk.sector_count()).ok().unwrap();
    let first = recheck.enter_next().unwrap().unwrap();
    assert_eq!((first.kind, first.lba, first.bytes), (AsyncSnapshotIoKind::Read, 0, 512));
    assert_eq!(recheck.enter_next(), Err(AsyncSnapshotCommitError::Outstanding));
    let mut bytes = [0; 512];
    disk.read_sector(first.lba, &mut bytes).unwrap();
    recheck.complete_read(first, &bytes).unwrap();
    let second = recheck.enter_next().unwrap().unwrap();
    assert_eq!(second.lba, 8);
    disk.read_sector(second.lba, &mut bytes).unwrap();
    recheck.complete_read(second, &bytes).unwrap();
    assert_eq!(recheck.enter_next(), Ok(None));
    let (proof, checked) = recheck.finish().ok().unwrap();
    assert_eq!(checked, proof.manifest());

    store.commit_next_with_wal_manifest(&mut disk, b"changed", manifest()).unwrap();
    let mut stale = AsyncSnapshotHeaderRecheck::new(
        store, proof, disk.sector_size(), disk.sector_count()).ok().unwrap();
    let request = stale.enter_next().unwrap().unwrap();
    disk.read_sector(request.lba, &mut bytes).unwrap();
    assert_eq!(stale.complete_read(request, &bytes),
        Err(AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Corrupt)));
    assert_eq!(stale.pending(), Some(request));
    assert_eq!(stale.release_unentered(request),
        Err(AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Corrupt)));
    assert_eq!(stale.complete_read(request, &bytes),
        Err(AsyncSnapshotCommitError::Store(SnapshotBlockStoreError::Corrupt)));
    assert!(stale.finish().is_err());
}
