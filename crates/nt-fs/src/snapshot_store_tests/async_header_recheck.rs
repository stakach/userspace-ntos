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

#[test]
fn unentered_header_refusal_returns_original_pair_without_disk_effect() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store.commit_next_with_wal_manifest(&mut disk, b"older", manifest()).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"newer", manifest()).unwrap();
    let proof = store.verify_paired_wal_snapshot(&mut disk).unwrap();
    let mut recheck = AsyncSnapshotHeaderRecheck::new(
        store, proof, disk.sector_size(), disk.sector_count()).ok().unwrap();
    let _request = recheck.enter_next().unwrap().unwrap();
    assert!(recheck.abort_no_effect().is_err());
    // Rebuild only to test the released request; the first cursor was consumed above.
    let proof = store.verify_paired_wal_snapshot(&mut disk).unwrap();
    let mut recheck = AsyncSnapshotHeaderRecheck::new(
        store, proof, disk.sector_size(), disk.sector_count()).ok().unwrap();
    let request = recheck.enter_next().unwrap().unwrap();
    recheck.release_unentered(request).unwrap();
    let proof = recheck.abort_no_effect().ok().unwrap();
    assert_eq!(proof.anchor(), manifest().anchor());
}

#[test]
fn unentered_checkpoint_recheck_abort_retains_dirty_publication_obligation() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store.commit_next_with_wal_manifest(&mut disk, b"older", manifest()).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"newer", manifest()).unwrap();
    let pair = store.verify_paired_wal_snapshot(&mut disk).unwrap();
    disk.events.clear();
    let publication = crate::SnapshotPublicationState::new();
    publication.mark_dirty();
    let capture = publication.begin_dirty_capture().unwrap().unwrap();
    let mut recheck = AsyncSnapshotHeaderRecheck::new(
        store, pair, disk.sector_size(), disk.sector_count()).ok().unwrap();
    let request = recheck.enter_next().unwrap().unwrap();
    recheck.release_unentered(request).unwrap();
    let pair = recheck.abort_no_effect().ok().unwrap();
    assert_eq!(pair.anchor(), manifest().anchor());
    assert!(!disk.events.iter().any(|event| matches!(event, Event::Write(_))),
        "the recheck refusal must not publish a snapshot slot");
    publication.abort_unwritten_checkpoint();
    drop(capture);
    assert!(publication.is_dirty(), "a later checkpoint must still capture the bytes");
    assert_eq!(publication.epochs(), (1, 0),
        "a refused read cannot satisfy the caller's publication target");
}

#[test]
fn repeated_unentered_header_busy_reuses_the_exact_owner_until_success() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store.commit_next_with_wal_manifest(&mut disk, b"older", manifest()).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"newer", manifest()).unwrap();
    let pair = store.verify_paired_wal_snapshot(&mut disk).unwrap();
    let mut recheck = AsyncSnapshotHeaderRecheck::new(
        store, pair, disk.sector_size(), disk.sector_count()).ok().unwrap();
    for _ in 0..3 {
        let request = recheck.enter_next().unwrap().unwrap();
        assert_eq!(request.lba, 0);
        recheck.release_unentered(request).unwrap();
        assert!(!recheck.is_done());
    }
    let mut bytes = [0; 512];
    for expected_lba in [0, 8] {
        let request = recheck.enter_next().unwrap().unwrap();
        assert_eq!(request.lba, expected_lba);
        disk.read_sector(request.lba, &mut bytes).unwrap();
        recheck.complete_read(request, &bytes).unwrap();
    }
    let (proof, checked) = recheck.finish().ok().unwrap();
    assert_eq!(checked, manifest());
    assert_eq!(proof.anchor(), manifest().anchor());
}
