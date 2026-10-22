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
