use super::*;

fn waiter(route: FileIoWaitRoute, tid: u64) -> SynchronousFileWaiter {
    let mut waiter = SynchronousFileWaiter::waiting(
        route,
        0x40,
        0x0012_019f,
        191,
        2,
        tid,
        tid + 100,
        FileIoMode::SynchronousAlertable,
        true,
        0,
        0x1002,
        0x2000,
        0x202,
    );
    waiter.reply_cap = tid + 200;
    waiter
}

fn hosted(file_id: u64) -> FileIoWaitRoute {
    FileIoWaitRoute::Hosted {
        file_id,
        device_id: 7,
        fs_context: 9,
    }
}

fn promote(
    table: &mut SynchronousFileWaitTable,
    waiter: SynchronousFileWaiter,
) -> SynchronousFileRetryIdentity {
    let slot = table.park(waiter).unwrap();
    table.promote_exact(slot, waiter.key(), waiter.tid).unwrap();
    table
        .retry_identity(slot, waiter.key(), waiter.tid)
        .unwrap()
}

fn acknowledge(table: &mut SynchronousFileWaitTable, identity: SynchronousFileRetryIdentity) {
    let mut attempt = table.begin_retry(identity).unwrap();
    table
        .record_retry(&mut attempt, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
}

#[test]
fn equal_numeric_ids_have_independent_fifo_and_exact_ownership() {
    let mut table = SynchronousFileWaitTable::new();
    let hosted_key = FileIoWaitKey::Hosted(10);
    let local_key = FileIoWaitKey::LocalOverlay(10);
    let local = waiter(FileIoWaitRoute::LocalOverlay { file_object: 10 }, 1);
    let first = table.park(local).unwrap();
    let peer = table.park(waiter(hosted(10), 2)).unwrap();
    let younger = table.park(waiter(local.route, 3)).unwrap();
    assert_eq!(table.oldest_waiting_for_file(local_key).unwrap().0, first);
    assert_eq!(table.oldest_waiting_for_file(hosted_key).unwrap().0, peer);
    assert!(table.take_exact(first, hosted_key, 1).is_none());
    assert!(table.wait_identity(first, hosted_key, 1).is_none());
    assert!(table.promote_exact(first, hosted_key, 1).is_none());
    table.promote_exact(first, local_key, 1).unwrap();
    assert!(table.retry_identity(first, hosted_key, 1).is_none());
    assert!(table.oldest_waiting_for_file(local_key).is_none());
    assert!(table.promote_exact(younger, local_key, 3).is_none());
    assert_eq!(table.oldest_waiting_for_file(hosted_key).unwrap().0, peer);
    table.promote_exact(peer, hosted_key, 2).unwrap();
    assert!(table.has_promoted_for_file(hosted_key));
    assert!(table.has_promoted_for_file(local_key));
}

#[test]
fn uncertain_local_reply_does_not_capture_hosted_numeric_peer() {
    let mut table = SynchronousFileWaitTable::new();
    let local = promote(
        &mut table,
        waiter(FileIoWaitRoute::LocalOverlay { file_object: 10 }, 1),
    );
    let mut attempt = table.begin_retry(local).unwrap();
    table
        .record_retry(&mut attempt, SynchronousFileRetryOutcome::Indeterminate(13))
        .unwrap();
    assert!(table.has_retry_delivery_for_file(FileIoWaitKey::LocalOverlay(10)));
    assert!(!table.has_retry_delivery_for_file(FileIoWaitKey::Hosted(10)));
    assert!(table
        .next_retry_for_file(FileIoWaitKey::LocalOverlay(10))
        .is_none());
    let peer = promote(&mut table, waiter(hosted(10), 2));
    assert_eq!(
        table.next_retry_for_file(FileIoWaitKey::Hosted(10)),
        Some(peer)
    );
    acknowledge(&mut table, peer);
    table.finish_retry(peer, Ok(())).unwrap();
    assert_eq!(
        table.adopt_promoted_fixture(2, 2, 102, 191).unwrap().route,
        hosted(10)
    );
    assert_eq!(table.retry_stats().indeterminate, 1);
}

#[test]
fn acknowledged_scan_visits_both_domains_even_with_equal_ids_or_retirement_failure() {
    let mut table = SynchronousFileWaitTable::new();
    let local = promote(
        &mut table,
        waiter(FileIoWaitRoute::LocalOverlay { file_object: 10 }, 1),
    );
    let hosted = promote(&mut table, waiter(hosted(10), 2));
    acknowledge(&mut table, local);
    acknowledge(&mut table, hosted);
    let first = table.next_acknowledged_retry_after(None).unwrap();
    let first_key = table.retry_delivery(first).unwrap().waiter.key();
    assert!(!table.finish_retry(first, Err(17)).unwrap());
    let second = table
        .next_acknowledged_retry_after(Some(first_key))
        .unwrap();
    let second_key = table.retry_delivery(second).unwrap().waiter.key();
    assert_ne!(first, second);
    assert_ne!(first_key, second_key);
    assert!(first_key < second_key);
    assert!(table
        .next_acknowledged_retry_after(Some(second_key))
        .is_none());
    assert_eq!(table.next_acknowledged_retry_after(None), Some(first));
}

#[test]
fn retry_preserves_captured_route_mode_access_independently_of_copied_input() {
    for route in [hosted(10), FileIoWaitRoute::LocalOverlay { file_object: 0 }] {
        for mode in [
            FileIoMode::SynchronousAlertable,
            FileIoMode::SynchronousNonAlertable,
        ] {
            let mut table = SynchronousFileWaitTable::new();
            let mut original = waiter(route, 1);
            original.mode = mode;
            let slot = table.park(original).unwrap();
            assert_eq!(
                table.alertable_waiting_for_thread(1).is_some(),
                original.is_alertable()
            );
            table.promote_exact(slot, original.key(), 1).unwrap();
            let identity = table.retry_identity(slot, original.key(), 1).unwrap();
            let attempt = table.begin_retry(identity).unwrap();
            assert_eq!(attempt.waiter().route, route);
            assert_eq!(attempt.waiter().mode, mode);
            assert_eq!(attempt.waiter().granted_access, original.granted_access);
            // Mechanism input is copied, but the table remains the immutable route owner.
            let mut copied = attempt.waiter();
            copied.mode = FileIoMode::Asynchronous;
            copied.granted_access = 0;
            copied.route = hosted(99);
            assert_ne!(copied, *table.retry_delivery(identity).unwrap().waiter);
            let mut attempt = attempt;
            table
                .record_retry(&mut attempt, SynchronousFileRetryOutcome::Acknowledged)
                .unwrap();
            table.finish_retry(identity, Ok(())).unwrap();
            let replay = table.adopt_promoted_fixture(2, 1, 101, 191).unwrap();
            assert_eq!(replay.route, route);
            assert_eq!(replay.mode, mode);
            assert_eq!(replay.granted_access, original.granted_access);
        }
    }
}

#[test]
fn admission_validates_domain_and_synchronous_mode_without_excluding_local_zero() {
    let mut table = SynchronousFileWaitTable::new();
    for route in [
        hosted(0),
        FileIoWaitRoute::Hosted {
            file_id: 10,
            device_id: 0,
            fs_context: 0,
        },
    ] {
        assert!(!route.is_valid());
        assert!(table.park(waiter(route, 1)).is_none());
    }
    let local = FileIoWaitRoute::LocalOverlay { file_object: 0 };
    assert!(local.is_valid());
    for route in [hosted(10), local] {
        let mut asynchronous = waiter(route, 1);
        asynchronous.mode = FileIoMode::Asynchronous;
        assert!(table.park(asynchronous).is_none());
        let mut cleanup_tid = waiter(route, 1);
        cleanup_tid.tid = u64::MAX;
        assert!(table.park(cleanup_tid).is_none());
    }
    assert!(table.is_empty());
    assert_eq!(table.park(waiter(local, 1)), Some(0));
    assert_eq!(
        table
            .oldest_waiting_for_file(FileIoWaitKey::LocalOverlay(0))
            .unwrap()
            .1
            .route,
        local
    );
}
