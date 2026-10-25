use super::*;

fn baseline() -> WalSnapshotManifest {
    WalSnapshotManifest {
        incarnation: 77,
        base_serial: 0,
        high_water_serial: 0,
        high_water_end_lba: 0,
    }
}

fn fixture(payload: Vec<u8>) -> (CachedDisk, AsyncSnapshotCommit<Vec<u8>>) {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store
        .commit_next_with_wal_manifest(&mut disk, b"older", baseline())
        .unwrap();
    store
        .commit_next_with_wal_manifest(&mut disk, b"newer", baseline())
        .unwrap();
    disk.events.clear();
    let commit = AsyncSnapshotCommit::new(
        store,
        payload,
        baseline(),
        disk.sector_size(),
        disk.sector_count(),
    )
    .ok()
    .unwrap();
    (disk, commit)
}

fn perform(
    disk: &mut CachedDisk,
    commit: &mut AsyncSnapshotCommit<Vec<u8>>,
    request: AsyncSnapshotRequest,
) {
    match request.kind {
        AsyncSnapshotIoKind::Flush => {
            disk.flush().unwrap();
            commit.complete_effect(request, 0).unwrap();
        }
        AsyncSnapshotIoKind::Write => {
            disk.write_sectors(request.lba, commit.write_bytes(request).unwrap())
                .unwrap();
            commit.complete_effect(request, request.bytes).unwrap();
        }
        AsyncSnapshotIoKind::Read => {
            let mut bytes = alloc::vec![0; request.bytes];
            disk.read_sectors(request.lba, &mut bytes).unwrap();
            commit.complete_read(request, &bytes).unwrap();
        }
    }
}

fn rechecked_pair(store: SnapshotBlockStore, disk: &mut CachedDisk) -> RecheckedPairedWalSnapshot {
    let pair = store.verify_paired_wal_snapshot(disk).unwrap();
    let mut recheck = AsyncSnapshotHeaderRecheck::new(
        store, pair, disk.sector_size(), disk.sector_count(),
    ).ok().unwrap();
    while let Some(request) = recheck.enter_next().unwrap() {
        let mut bytes = alloc::vec![0; request.bytes];
        disk.read_sectors(request.lba, &mut bytes).unwrap();
        recheck.complete_read(request, &bytes).unwrap();
    }
    // The fixture completed exact reads under one exclusive synthetic reserve.
    unsafe { recheck.finish_proven() }.ok().unwrap()
}

#[test]
fn rechecked_pair_commit_skips_full_payload_scan_and_preserves_barriers() {
    let store = SnapshotBlockStore::new(0, 256);
    let mut disk = CachedDisk::with_sectors(256);
    let old = alloc::vec![0x31; 40 * 512];
    store.commit_next_with_wal_manifest(&mut disk, &old, baseline()).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, &old, baseline()).unwrap();
    let proof = rechecked_pair(store, &mut disk);
    let reads_before = disk.read_attempts;
    disk.events.clear();
    let mut commit = AsyncSnapshotCommit::new_from_rechecked_pair(
        alloc::vec![0xa5; 65 * 512], baseline(), proof,
    ).ok().unwrap();
    while let Some(request) = commit.enter_next().unwrap() {
        assert_ne!(request.kind, AsyncSnapshotIoKind::Read);
        perform(&mut disk, &mut commit, request);
    }
    assert_eq!(disk.read_attempts, reads_before);
    assert_eq!(disk.events.first(), Some(&Event::Flush));
    assert_eq!(disk.events.last(), Some(&Event::Flush));
    let (payload, generation, pair) = unsafe {
        commit.finish_with_payload_and_paired_proof()
    }.ok().unwrap();
    assert_eq!(generation, 3);
    assert_eq!(pair.anchor(), baseline().anchor());
    let reads_before_second = disk.read_attempts;
    let mut second = unsafe { AsyncSnapshotCommit::new_from_verified_pair(
        store, payload, baseline(), disk.sector_size(), disk.sector_count(), pair,
    ) }.ok().unwrap();
    while let Some(request) = second.enter_next().unwrap() {
        assert_ne!(request.kind, AsyncSnapshotIoKind::Read);
        perform(&mut disk, &mut second, request);
    }
    assert_eq!(disk.read_attempts, reads_before_second);
    let (generation, pair) = unsafe { second.finish_with_paired_proof() }.ok().unwrap();
    assert_eq!(generation, 4);
    assert_eq!(pair.anchor(), baseline().anchor());
    disk.power_cut();
    assert_eq!(store.read_latest(&mut disk).unwrap().unwrap().generation, 4);
}

#[test]
fn proof_checkpoint_refusal_returns_payload_and_exact_proof_before_effect() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store.commit_next_with_wal_manifest(&mut disk, b"older", baseline()).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"newer", baseline()).unwrap();
    let proof = rechecked_pair(store, &mut disk);
    let events = disk.events.clone();
    let payload = b"replacement".to_vec();
    let wrong = WalSnapshotManifest { incarnation: 78, ..baseline() };
    let (error, returned, proof) = match AsyncSnapshotCommit::new_from_rechecked_pair(
        payload.clone(), wrong, proof,
    ) {
        Ok(_) => panic!("changed anchor must refuse before physical effect"),
        Err(parts) => parts,
    };
    assert_eq!(error, SnapshotBlockStoreError::Corrupt);
    assert_eq!(returned, payload);
    assert_eq!(proof.anchor(), baseline().anchor());
    assert_eq!(disk.events, events);
}

#[test]
fn proof_checkpoint_uncertain_write_retains_ticket_and_previous_slot() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::new();
    store.commit_next_with_wal_manifest(&mut disk, b"older", baseline()).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"newer", baseline()).unwrap();
    let proof = rechecked_pair(store, &mut disk);
    let mut commit = AsyncSnapshotCommit::new_from_rechecked_pair(
        b"replacement".to_vec(), baseline(), proof,
    ).ok().unwrap();
    let barrier = commit.enter_next().unwrap().unwrap();
    assert_eq!(barrier.kind, AsyncSnapshotIoKind::Flush);
    perform(&mut disk, &mut commit, barrier);
    let write = commit.enter_next().unwrap().unwrap();
    assert_eq!(write.kind, AsyncSnapshotIoKind::Write);
    commit.lose(write).unwrap();
    assert_eq!(commit.pending(), Some(write));
    assert_eq!(commit.enter_next(), Err(AsyncSnapshotCommitError::Outstanding));
    assert_eq!(commit.release_unentered(write), Err(AsyncSnapshotCommitError::Outstanding));
    disk.power_cut();
    let selected = store.read_latest(&mut disk).unwrap().unwrap();
    assert_eq!(selected.generation, 2);
    assert_eq!(selected.payload, b"newer");
}

#[test]
fn async_commit_preserves_payload_header_barrier_order_and_recovery() {
    let (mut disk, mut commit) = fixture(alloc::vec![0xa5; 1300]);
    let mut kinds = Vec::new();
    while let Some(request) = commit.enter_next().unwrap() {
        if request.kind != AsyncSnapshotIoKind::Read {
            kinds.push(request.kind);
        }
        perform(&mut disk, &mut commit, request);
    }
    assert_eq!(
        kinds,
        [
            AsyncSnapshotIoKind::Flush,
            AsyncSnapshotIoKind::Write,
            AsyncSnapshotIoKind::Flush,
            AsyncSnapshotIoKind::Write,
            AsyncSnapshotIoKind::Flush,
        ]
    );
    assert_eq!(
        disk.events,
        [
            Event::Flush,
            Event::Write(1),
            Event::Write(2),
            Event::Write(3),
            Event::Flush,
            Event::Write(0),
            Event::Flush,
        ]
    );
    let generation = commit.finish().ok().unwrap();
    assert_eq!(generation, 3);
    disk.power_cut();
    let selected = SnapshotBlockStore::new(0, 16)
        .read_latest(&mut disk)
        .unwrap()
        .unwrap();
    assert_eq!(selected.generation, 3);
    assert_eq!(selected.payload, alloc::vec![0xa5; 1300]);
}

#[test]
fn native_checkpoint_mints_paired_proof_from_completed_io_without_postcommit_reads() {
    let (mut disk, mut commit) = fixture(alloc::vec![0xa5; 1300]);
    while let Some(request) = commit.enter_next().unwrap() {
        perform(&mut disk, &mut commit, request);
    }
    let reads = disk.read_attempts;
    // The fixture feeds the exact disk completion and flush for every request.
    let (generation, pair) = unsafe { commit.finish_with_paired_proof() }.ok().unwrap();
    assert_eq!(generation, 3);
    assert_eq!(disk.read_attempts, reads);
    assert_eq!(pair.anchor(), baseline().anchor());
    let reserve = crate::SnapshotReserve::new((), 91u64, SnapshotBlockStore::new(0, 16));
    let lease = reserve.try_acquire().unwrap();
    assert!(pair.matches_cached_fence(lease.store(), baseline().anchor()));
    assert!(!pair.matches_cached_fence(SnapshotBlockStore::new(1, 16), baseline().anchor()));
    assert!(!pair.matches_cached_fence(lease.store(), WalSnapshotAnchor {
        incarnation: 77, serial: 1, end_lba: 1,
    }));
    // A pending native owner retains this physical lease and excludes NtFlushKey.
    assert!(reserve.try_acquire().is_none());
    drop(lease);
    assert!(reserve.try_acquire().is_some());
    assert_eq!(SnapshotBlockStore::new(0, 16)
        .recheck_verified_paired_wal_snapshot(&mut disk, &pair), Ok(pair.manifest()));
}

#[test]
fn folded_first_pass_returns_the_same_owned_payload_for_second_pass() {
    let payload = alloc::vec![0x5c; 1300];
    let (mut disk, mut commit) = fixture(payload.clone());
    while let Some(request) = commit.enter_next().unwrap() {
        perform(&mut disk, &mut commit, request);
    }
    // Each synthetic completion above executes the exact backing operation and flush.
    let (returned, generation, pair) = unsafe {
        commit.finish_with_payload_and_paired_proof()
    }.ok().unwrap();
    assert_eq!(returned, payload);
    assert_eq!(generation, 3);
    assert_eq!(pair.anchor(), baseline().anchor());
}

#[test]
fn native_checkpoint_unentered_request_can_retry_with_new_exact_ticket() {
    let (mut disk, mut commit) = fixture(alloc::vec![0xa5; 1300]);
    let first = commit.enter_next().unwrap().unwrap();
    assert_eq!(first.kind, AsyncSnapshotIoKind::Flush);
    commit.release_unentered(first).unwrap();
    let second = commit.enter_next().unwrap().unwrap();
    assert_ne!(first.sequence, second.sequence);
    assert_eq!(commit.complete_effect(first, 0), Err(AsyncSnapshotCommitError::WrongTicket));
    perform(&mut disk, &mut commit, second);
    while let Some(request) = commit.enter_next().unwrap() {
        perform(&mut disk, &mut commit, request);
    }
    // The fixture completed every request against the same disk.
    assert_eq!(unsafe { commit.finish_with_paired_proof() }.ok().unwrap().0, 3);
}

#[test]
fn native_checkpoint_scans_and_writes_large_payloads_in_bounded_commands() {
    let store = SnapshotBlockStore::new(0, 256);
    let mut disk = CachedDisk::with_sectors(256);
    let old = alloc::vec![0x31; 40 * 512];
    store.commit_next_with_wal_manifest(&mut disk, &old, baseline()).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, &old, baseline()).unwrap();
    let replacement = alloc::vec![0xa5; 65 * 512];
    let mut commit = AsyncSnapshotCommit::new(
        store, replacement.clone(), baseline(), disk.sector_size(), disk.sector_count(),
    ).unwrap();
    let mut reads = Vec::new();
    let mut writes = Vec::new();
    while let Some(request) = commit.enter_next().unwrap() {
        match request.kind {
            AsyncSnapshotIoKind::Read => reads.push((request.lba, request.bytes / 512)),
            AsyncSnapshotIoKind::Write => writes.push((request.lba, request.bytes / 512)),
            AsyncSnapshotIoKind::Flush => {}
        }
        perform(&mut disk, &mut commit, request);
    }
    assert_eq!(reads, [(0, 1), (1, 32), (33, 8), (128, 1), (129, 32), (161, 8)]);
    assert_eq!(writes, [(1, 32), (33, 32), (65, 1), (0, 1)]);
    assert_eq!(commit.finish().ok().unwrap(), 3);
    disk.power_cut();
    let selected = store.read_latest(&mut disk).unwrap().unwrap();
    assert_eq!(selected.generation, 3);
    assert_eq!(selected.payload, replacement);
}

#[test]
fn interrupted_large_native_checkpoint_write_retains_owner_and_old_snapshot() {
    let store = SnapshotBlockStore::new(0, 256);
    let mut disk = CachedDisk::with_sectors(256);
    let old = alloc::vec![0x31; 40 * 512];
    store.commit_next_with_wal_manifest(&mut disk, &old, baseline()).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, &old, baseline()).unwrap();
    disk.events.clear();
    disk.fail_event = Some(16);
    let mut commit = AsyncSnapshotCommit::new(
        store, alloc::vec![0xa5; 65 * 512], baseline(), disk.sector_size(), disk.sector_count(),
    ).unwrap();
    loop {
        let request = commit.enter_next().unwrap().unwrap();
        if request.kind == AsyncSnapshotIoKind::Write {
            assert_eq!(request.bytes, 32 * 512);
            assert_eq!(disk.write_sectors(request.lba, commit.write_bytes(request).unwrap()),
                Err(SnapshotBlockStoreError::Io));
            commit.lose(request).unwrap();
            assert_eq!(commit.pending(), Some(request));
            assert_eq!(commit.enter_next(), Err(AsyncSnapshotCommitError::Outstanding));
            break;
        }
        perform(&mut disk, &mut commit, request);
    }
    disk.power_cut();
    let selected = store.read_latest(&mut disk).unwrap().unwrap();
    assert_eq!(selected.generation, 2);
    assert_eq!(selected.payload, old);
}

#[test]
fn every_async_read_write_and_flush_keeps_its_exact_ticket_until_completion() {
    for uncertain_step in 0..9 {
        let (mut disk, mut commit) = fixture(alloc::vec![0xa5; 1300]);
        for index in 0..9 {
            let request = commit.enter_next().unwrap().unwrap();
            if index == uncertain_step {
                commit.lose(request).unwrap();
                assert_eq!(commit.release_unentered(request),
                    Err(AsyncSnapshotCommitError::Outstanding));
                assert_eq!(
                    commit.enter_next(),
                    Err(AsyncSnapshotCommitError::Outstanding)
                );
                let mut wrong = request;
                wrong.sequence += 1;
                assert_eq!(
                    commit.complete_effect(wrong, wrong.bytes),
                    Err(AsyncSnapshotCommitError::WrongTicket)
                );
                assert_eq!(commit.pending(), Some(request));
            }
            perform(&mut disk, &mut commit, request);
            assert_eq!(
                commit.complete_effect(request, request.bytes),
                Err(AsyncSnapshotCommitError::WrongTicket)
            );
        }
        assert!(commit.enter_next().unwrap().is_none());
        assert_eq!(commit.finish().ok().unwrap(), 3);
    }
}

#[test]
fn async_commit_power_cuts_preserve_a_complete_wal_snapshot() {
    for partial_flush in [false, true] {
        for cut in 0..7 {
            let (mut disk, mut commit) = fixture(alloc::vec![0xa5; 1300]);
            disk.fail_event = Some(cut);
            disk.partial_flush = partial_flush;
            while let Some(request) = commit.enter_next().unwrap() {
                let result = match request.kind {
                    AsyncSnapshotIoKind::Read => {
                        let mut bytes = alloc::vec![0; request.bytes];
                        disk.read_sectors(request.lba, &mut bytes).unwrap();
                        commit.complete_read(request, &bytes).unwrap();
                        continue;
                    }
                    AsyncSnapshotIoKind::Write => {
                        disk.write_sectors(request.lba, commit.write_bytes(request).unwrap())
                    }
                    AsyncSnapshotIoKind::Flush => disk.flush(),
                };
                if result.is_err() {
                    commit.lose(request).unwrap();
                    assert_eq!(commit.pending(), Some(request));
                    assert_eq!(
                        commit.enter_next(),
                        Err(AsyncSnapshotCommitError::Outstanding)
                    );
                    break;
                }
                commit.complete_effect(request, request.bytes).unwrap();
            }
            disk.power_cut();
            let selected = SnapshotBlockStore::new(0, 16)
                .read_latest(&mut disk)
                .unwrap()
                .unwrap();
            assert!(selected.generation == 2 || selected.generation == 3);
            assert_eq!(
                selected.payload,
                if selected.generation == 2 {
                    b"newer".to_vec()
                } else {
                    alloc::vec![0xa5; 1300]
                }
            );
        }
    }
}
