use super::*;

fn waiter(file: u64, tid: u64) -> SynchronousFileWaiter {
    let mut waiter = SynchronousFileWaiter::waiting(
        FileIoWaitRoute::Hosted {
            file_id: file,
            device_id: 7,
            fs_context: 9,
        },
        0x40,
        3,
        191,
        2,
        tid,
        tid + 100,
        FileIoMode::SynchronousAlertable,
        true,
        0x1000,
        0x1002,
        0x2000,
        0x202,
    );
    waiter.reply_cap = tid + 200;
    waiter.reply_mrs = core::array::from_fn(|index| 0xA000 + index as u64);
    waiter
}

fn promoted(
    table: &mut SynchronousFileWaitTable,
    file: u64,
    tid: u64,
) -> SynchronousFileRetryIdentity {
    let slot = table.park(waiter(file, tid)).unwrap();
    table
        .promote_exact(slot, FileIoWaitKey::Hosted(file), tid)
        .unwrap();
    table
        .retry_identity(slot, FileIoWaitKey::Hosted(file), tid)
        .unwrap()
}

fn acknowledged(table: &mut SynchronousFileWaitTable, identity: SynchronousFileRetryIdentity) {
    let mut attempt = table.begin_retry(identity).unwrap();
    table
        .record_retry(&mut attempt, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
}

fn assert_retained(table: &mut SynchronousFileWaitTable, identity: SynchronousFileRetryIdentity) {
    let original = *table.retry_delivery(identity).unwrap().waiter;
    assert!(table.has_retry_delivery_for_file(original.key()));
    assert!(table.has_retry_delivery_for_thread(original.tid));
    assert!(table.has_retry_delivery_for_pi(original.pi));
    assert!(table.has_waiter_for_pi(original.pi));
    assert!(!table.has_waiter_for_pi(original.pi + 1));
    assert!(!table.has_retry_delivery_for_file(FileIoWaitKey::Hosted(1010)));
    assert!(!table.has_retry_delivery_for_thread(original.tid + 1000));
    assert!(!table.has_retry_delivery_for_pi(original.pi + 1));
    assert!(table.has_retry_delivery_matching(|record| record.badge == original.badge));
    assert!(!table.has_retry_delivery_matching(|record| record.badge == original.badge + 1000));
    assert!(table
        .take_exact(identity.slot, original.key(), original.tid)
        .is_none());
    assert!(table
        .take_alertable_waiting_exact(identity.slot, original.key(), original.tid)
        .is_none());
    assert!(table.alertable_waiting_for_thread(original.tid).is_none());
    assert_eq!(
        table.take_thread_with(original.tid, |_| panic!("delivery cannot be discarded")),
        0
    );
    assert!(table
        .take_promoted(
            original.pi,
            original.tid,
            original.badge,
            original.service_number
        )
        .is_none());
    assert!(!table.reset());
    assert_eq!(*table.retry_delivery(identity).unwrap().waiter, original);
}

#[test]
fn retry_ack_and_local_retirement_preserve_exact_arguments_grant_and_reply() {
    let mut table = SynchronousFileWaitTable::new();
    let identity = promoted(&mut table, 10, 1);
    let original = *table.retry_delivery(identity).unwrap().waiter;
    assert_eq!(table.retry_stats().ready, 1);
    assert_eq!(
        table.next_retry_for_file(FileIoWaitKey::Hosted(10)),
        Some(identity)
    );
    assert_retained(&mut table, identity);
    assert!(table.finish_retry(identity, Ok(())).is_err());
    let mut attempt = table.begin_retry(identity).unwrap();
    assert_eq!(attempt.waiter(), original);
    assert_eq!(attempt.identity(), identity);
    assert_eq!(table.retry_stats().invoking, 1);
    assert_eq!(table.next_retry_for_file(FileIoWaitKey::Hosted(10)), None);
    assert_retained(&mut table, identity);
    table
        .record_retry(&mut attempt, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    assert_eq!(table.retry_stats().acknowledged, 1);
    assert_eq!(
        table.next_retry_for_file(FileIoWaitKey::Hosted(10)),
        Some(identity)
    );
    assert_retained(&mut table, identity);
    assert!(!table.finish_retry(identity, Err(13)).unwrap());
    assert_eq!(
        table.retry_delivery(identity).unwrap().phase,
        SynchronousFileRetryPhase::Acknowledged {
            local_error: Some(13)
        }
    );
    assert_retained(&mut table, identity);
    assert!(table.begin_retry(identity).is_err());
    assert!(table.finish_retry(identity, Ok(())).unwrap());
    assert_eq!(table.retry_stats().retired_grants, 1);
    assert!(!table.has_retry_delivery_for_thread(1));
    assert!(table.has_waiter_for_pi(2));
    assert_eq!(table.next_retry_for_file(FileIoWaitKey::Hosted(10)), None);
    assert!(table.finish_retry(identity, Ok(())).is_err());
    let consumed = table
        .take_promoted(
            original.pi,
            original.tid,
            original.badge,
            original.service_number,
        )
        .unwrap();
    assert_eq!(
        consumed,
        SynchronousFileWaiter {
            reply_cap: 0,
            ..original
        }
    );
    assert!(table.retry_delivery(identity).is_err());
    assert!(!table.has_waiter_for_pi(2));
}

#[test]
fn no_entry_retry_issues_fresh_ticket_and_rejects_old_or_mutated_ack() {
    let mut table = SynchronousFileWaitTable::new();
    let identity = promoted(&mut table, 10, 1);
    let mut rejected = table.begin_retry(identity).unwrap();
    table
        .record_retry(&mut rejected, SynchronousFileRetryOutcome::NotEntered(17))
        .unwrap();
    assert_eq!(
        table.retry_delivery(identity).unwrap().phase,
        SynchronousFileRetryPhase::Ready {
            last_error: Some(17)
        }
    );
    assert_retained(&mut table, identity);
    let mut retry = table.begin_retry(identity).unwrap();
    assert!(retry.attempt > rejected.attempt);
    assert!(table
        .record_retry(&mut rejected, SynchronousFileRetryOutcome::Acknowledged)
        .is_err());
    let mut stale = SynchronousFileRetryAttempt {
        consumed: false,
        ..rejected
    };
    assert!(table
        .record_retry(&mut stale, SynchronousFileRetryOutcome::Acknowledged)
        .is_err());
    retry.waiter.reply_cap += 1;
    assert!(table
        .record_retry(&mut retry, SynchronousFileRetryOutcome::Acknowledged)
        .is_err());
    retry.waiter.reply_cap -= 1;
    let mode = retry.waiter.mode;
    retry.waiter.mode = FileIoMode::SynchronousNonAlertable;
    assert!(table
        .record_retry(&mut retry, SynchronousFileRetryOutcome::Acknowledged)
        .is_err());
    retry.waiter.mode = mode;
    let route = retry.waiter.route;
    retry.waiter.route = FileIoWaitRoute::LocalOverlay { file_object: 10 };
    assert!(table
        .record_retry(&mut retry, SynchronousFileRetryOutcome::Acknowledged)
        .is_err());
    retry.waiter.route = route;
    retry.waiter.granted_access = 0;
    assert!(table
        .record_retry(&mut retry, SynchronousFileRetryOutcome::Acknowledged)
        .is_err());
    retry.waiter.granted_access = 3;
    table
        .record_retry(&mut retry, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    assert!(table
        .record_retry(&mut retry, SynchronousFileRetryOutcome::Acknowledged)
        .is_err());
}

#[test]
fn indeterminate_delivery_blocks_teardown_and_younger_file_waiter_not_other_files() {
    let mut table = SynchronousFileWaitTable::new();
    let identity = promoted(&mut table, 10, 1);
    let younger = table.park(waiter(10, 2)).unwrap();
    let mut attempt = table.begin_retry(identity).unwrap();
    table
        .record_retry(&mut attempt, SynchronousFileRetryOutcome::Indeterminate(29))
        .unwrap();
    assert_eq!(table.retry_stats().indeterminate, 1);
    assert_eq!(table.next_retry_for_file(FileIoWaitKey::Hosted(10)), None);
    assert_retained(&mut table, identity);
    assert!(table
        .promote_exact(younger, FileIoWaitKey::Hosted(10), 2)
        .is_none());
    assert!(table.begin_retry(identity).is_err());
    assert!(table.finish_retry(identity, Ok(())).is_err());
    let peer = promoted(&mut table, 20, 3);
    acknowledged(&mut table, peer);
    table.finish_retry(peer, Ok(())).unwrap();
    assert!(table.take_promoted(2, 3, 103, 191).is_some());
    assert_eq!(table.retry_stats().indeterminate, 1);
    assert_eq!(table.retry_stats().waiting, 1);
}

#[test]
fn dropped_ticket_retains_invoking_without_authorizing_another_reply() {
    let mut table = SynchronousFileWaitTable::new();
    let identity = promoted(&mut table, 10, 1);
    drop(table.begin_retry(identity).unwrap());
    assert_retained(&mut table, identity);
    assert!(table.begin_retry(identity).is_err());
    assert!(table.finish_retry(identity, Ok(())).is_err());
    assert_eq!(table.next_acknowledged_retry_after(None), None);
}

#[test]
fn foreign_tables_and_reused_slots_cannot_accept_old_identity_or_attempt() {
    let mut first = SynchronousFileWaitTable::new();
    let mut second = SynchronousFileWaitTable::new();
    let a = promoted(&mut first, 10, 1);
    let b = promoted(&mut second, 10, 1);
    assert_ne!(a, b);
    let mut attempt = first.begin_retry(a).unwrap();
    assert_eq!(
        second.record_retry(&mut attempt, SynchronousFileRetryOutcome::Acknowledged),
        Err(SynchronousFileRetryError::WrongIdentity)
    );
    assert!(second.begin_retry(a).is_err());
    assert!(second.finish_retry(a, Ok(())).is_err());
    first
        .record_retry(&mut attempt, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    first.finish_retry(a, Ok(())).unwrap();
    first.take_promoted(2, 1, 101, 191).unwrap();
    assert!(first.reset());
    let replacement = promoted(&mut first, 10, 1);
    assert_eq!(a.slot, replacement.slot);
    assert_ne!(a.sequence, replacement.sequence);
    assert!(first.begin_retry(a).is_err());
    assert!(first.finish_retry(a, Ok(())).is_err());
    assert!(first
        .record_retry(&mut attempt, SynchronousFileRetryOutcome::Acknowledged)
        .is_err());
    assert_eq!(
        first.next_retry_for_file(FileIoWaitKey::Hosted(10)),
        Some(replacement)
    );
}

#[test]
fn exhausted_attempt_or_admission_leaves_existing_owner_untouched() {
    let mut table = SynchronousFileWaitTable::new();
    let identity = promoted(&mut table, 10, 1);
    table.record_mut(identity.slot).unwrap().next_attempt = u64::MAX;
    assert!(matches!(
        table.begin_retry(identity),
        Err(SynchronousFileRetryError::Exhausted)
    ));
    assert_retained(&mut table, identity);
    assert_eq!(table.retry_stats().ready, 1);
    table.next_sequence = u64::MAX;
    assert!(table.park(waiter(20, 2)).is_none());
    assert_eq!(table.len(), 1);
}

#[test]
fn ordered_local_only_redrive_skips_failed_earlier_retirement_and_uncertain_rows() {
    let mut table = SynchronousFileWaitTable::new();
    let later = promoted(&mut table, 30, 1);
    let earlier = promoted(&mut table, 10, 2);
    let uncertain = promoted(&mut table, 20, 3);
    acknowledged(&mut table, later);
    acknowledged(&mut table, earlier);
    let mut attempt = table.begin_retry(uncertain).unwrap();
    table
        .record_retry(&mut attempt, SynchronousFileRetryOutcome::Indeterminate(9))
        .unwrap();
    assert_eq!(table.next_acknowledged_retry_after(None), Some(earlier));
    assert!(!table.finish_retry(earlier, Err(9)).unwrap());
    assert_eq!(
        table.next_acknowledged_retry_after(Some(FileIoWaitKey::Hosted(10))),
        Some(later)
    );
    assert_eq!(
        table.next_acknowledged_retry_after(Some(FileIoWaitKey::Hosted(30))),
        None
    );
    assert_eq!(table.next_acknowledged_retry_after(None), Some(earlier));
    table.finish_retry(later, Ok(())).unwrap();
    assert_eq!(
        table.next_acknowledged_retry_after(Some(FileIoWaitKey::Hosted(10))),
        None
    );
}

#[test]
fn scope_queries_cover_waiting_retired_grant_and_every_retained_delivery_phase() {
    let mut table = SynchronousFileWaitTable::new();
    let slot = table.park(waiter(10, 1)).unwrap();
    assert!(table.has_waiter_for_pi(2));
    assert!(!table.has_retry_delivery_for_pi(2));
    assert!(table
        .retry_identity(slot, FileIoWaitKey::Hosted(10), 1)
        .is_none());
    table
        .promote_exact(slot, FileIoWaitKey::Hosted(10), 1)
        .unwrap();
    let identity = table
        .retry_identity(slot, FileIoWaitKey::Hosted(10), 1)
        .unwrap();
    assert_retained(&mut table, identity);
    let mut attempt = table.begin_retry(identity).unwrap();
    assert_retained(&mut table, identity);
    table
        .record_retry(&mut attempt, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    assert_retained(&mut table, identity);
    table.finish_retry(identity, Ok(())).unwrap();
    assert_eq!(
        table.take_thread_with(1, |waiter| assert_eq!(waiter.reply_cap, 0)),
        1
    );
    assert!(!table.has_waiter_for_pi(2));
    assert!(table.reset());
}

#[test]
fn retired_unconsumed_grant_still_excludes_younger_file_promotion() {
    let mut table = SynchronousFileWaitTable::new();
    let identity = promoted(&mut table, 10, 1);
    let younger = table.park(waiter(10, 2)).unwrap();
    acknowledged(&mut table, identity);
    table.finish_retry(identity, Ok(())).unwrap();
    assert!(!table.has_retry_delivery_for_file(FileIoWaitKey::Hosted(10)));
    assert!(table.has_promoted_for_file(FileIoWaitKey::Hosted(10)));
    assert_eq!(
        table.oldest_waiting_for_file(FileIoWaitKey::Hosted(10)),
        None
    );
    assert_eq!(
        table.promote_exact(younger, FileIoWaitKey::Hosted(10), 2),
        None
    );
    table.take_promoted(2, 1, 101, 191).unwrap();
    assert!(!table.has_promoted_for_file(FileIoWaitKey::Hosted(10)));
    assert_eq!(
        table
            .oldest_waiting_for_file(FileIoWaitKey::Hosted(10))
            .unwrap()
            .0,
        younger
    );
    assert!(table
        .promote_exact(younger, FileIoWaitKey::Hosted(10), 2)
        .is_some());
}
