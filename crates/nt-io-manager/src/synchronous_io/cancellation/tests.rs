use super::*;

const FILE: u64 = 10;
const TID: u64 = 20;
const DEVICE: u64 = 7;
const ERROR: u32 = 0xc000_009a;
const KEY: FileIoWaitKey = FileIoWaitKey::Hosted(FILE);

fn waiter(tid: u64, cap: u64) -> SynchronousFileWaiter {
    let mut waiter = SynchronousFileWaiter::waiting(
        FileIoWaitRoute::Hosted {
            file_id: FILE,
            device_id: DEVICE,
            fs_context: 9,
        },
        1,
        3,
        191,
        2,
        tid,
        tid + 100,
        FileIoMode::SynchronousAlertable,
        true,
        0,
        0x1000,
        0x2000,
        0x202,
    );
    waiter.reply_cap = cap;
    waiter
}

fn cancel(
    table: &mut SynchronousFileWaitTable,
    slot: usize,
    tid: u64,
) -> SynchronousFileCancelIdentity {
    let identity = table.wait_identity(slot, KEY, tid).unwrap();
    table.request_cancellation(identity).unwrap()
}

fn complete(
    table: &mut SynchronousFileWaitTable,
    identity: SynchronousFileCancelIdentity,
    receipt: SynchronousFileCancelReceipt,
) {
    let mut attempt = table.begin_cancellation(identity).unwrap();
    table
        .record_cancellation(
            &mut attempt,
            SynchronousFileCancelOutcome::Completed(receipt),
        )
        .unwrap();
}

fn finish_hosted(
    table: &mut SynchronousFileWaitTable,
    identity: SynchronousFileCancelIdentity,
    cap: bool,
) {
    complete(
        table,
        identity,
        SynchronousFileCancelReceipt::HostedPolicy { waiters: 0 },
    );
    complete(table, identity, SynchronousFileCancelReceipt::Wake);
    complete(
        table,
        identity,
        SynchronousFileCancelReceipt::HostedReference(FileReferenceRelease {
            device_id: DEVICE,
            ..FileReferenceRelease::default()
        }),
    );
    if cap {
        complete(table, identity, SynchronousFileCancelReceipt::ReplyRevoked);
        complete(
            table,
            identity,
            SynchronousFileCancelReceipt::ReplyCapRetired,
        );
    }
    assert_eq!(
        table.cancellation(identity).unwrap().phase,
        SynchronousFileCancelPhase::Complete
    );
    table.finish_cancellation(identity).unwrap();
}

#[test]
fn reservations_are_cross_table_exact_and_reset_cannot_erase_them() {
    let mut first = SynchronousFileWaitTable::new();
    let mut second = SynchronousFileWaitTable::new();
    let a = first.reserve().unwrap();
    let b = second.reserve().unwrap();
    assert!(!second.cancel_reservation(a));
    assert!(second.park_reserved(a, waiter(TID, 40)).is_none());
    assert!(second.cancel_reserved(a, waiter(TID, 0)).is_none());
    assert!(!first.reset());
    assert!(first.cancel_reservation(a));
    let next = first.reserve().unwrap();
    assert_eq!(next.slot, a.slot);
    assert!(first.park_reserved(a, waiter(TID, 40)).is_none());
    assert!(first.park_reserved(next, waiter(TID, 40)).is_some());
    assert!(!first.cancel_reservation(next));
    assert!(second.cancel_reservation(b));
    assert!(second.reset());
}

#[test]
fn reverse_commit_preserves_fifo_publication_order_not_reservation_age() {
    let mut table = SynchronousFileWaitTable::new();
    let a = table.reserve().unwrap();
    let b = table.reserve().unwrap();
    let second = table.park_reserved(b, waiter(TID + 1, 41)).unwrap();
    table.park_reserved(a, waiter(TID, 40)).unwrap();
    assert_eq!(table.oldest_waiting_for_file(KEY).unwrap().0, second);
}

#[test]
fn failed_park_can_commit_rollback_after_nested_same_tid_publication() {
    let mut table = SynchronousFileWaitTable::new();
    let reservation = table.reserve().unwrap();
    let nested = table.park(waiter(TID, 41)).unwrap();
    let capacity = table.capacity();
    assert!(table.park_reserved(reservation, waiter(TID, 40)).is_none());
    let mut rollback = waiter(TID, 0);
    rollback.resume_sp = 0;
    rollback.handle = 0;
    rollback.badge = 0;
    let identity = table.cancel_reserved(reservation, rollback).unwrap();
    assert_eq!(table.capacity(), capacity);
    assert_eq!(table.len(), 2);
    assert_eq!(table.cancellation_ownership(KEY).waiting, 1);
    assert_eq!(table.oldest_waiting_for_file(KEY).unwrap().0, nested);
    finish_hosted(&mut table, identity, false);
    assert_eq!(table.len(), 1);
    assert_eq!(table.oldest_waiting_for_file(KEY).unwrap().0, nested);
}

#[test]
fn rollback_rejects_copied_published_owner_and_held_reply() {
    let mut table = SynchronousFileWaitTable::new();
    let slot = table.park(waiter(TID, 40)).unwrap();
    let mut copied = table.record(slot).unwrap().waiter;
    copied.reply_cap = 0;
    let reserved = table.reserve().unwrap();
    assert!(table.cancel_reserved(reserved, copied).is_none());
    assert!(table
        .cancel_reserved(reserved, waiter(TID + 1, 41))
        .is_none());
    assert!(table.cancel_reservation(reserved));
}

#[test]
fn cancellation_request_rejects_stale_slot_key_tid_and_foreign_table() {
    let mut first = SynchronousFileWaitTable::new();
    let slot = first.park(waiter(TID, 40)).unwrap();
    let identity = first.wait_identity(slot, KEY, TID).unwrap();
    let mut second = SynchronousFileWaitTable::new();
    second.park(waiter(TID, 40)).unwrap();
    assert_eq!(
        second.request_cancellation(identity),
        Err(SynchronousFileCancelError::WrongIdentity)
    );
    first.take_exact(slot, KEY, TID).unwrap();
    assert_eq!(first.park(waiter(TID, 40)), Some(slot));
    assert_eq!(
        first.request_cancellation(identity),
        Err(SynchronousFileCancelError::WrongIdentity)
    );
    assert!(!first.has_cancellation_for_thread(TID));
    assert!(!second.has_cancellation_for_thread(TID));
}

#[test]
fn cancellation_owns_all_effects_and_legacy_paths_cannot_extract_it() {
    let mut table = SynchronousFileWaitTable::new();
    let slot = table.park(waiter(TID, 40)).unwrap();
    let identity = cancel(&mut table, slot, TID);
    assert!(table.has_cancellation_for_thread(TID));
    assert!(table.has_cancellation_for_pi(2));
    assert!(table.has_waiter_for_pi(2));
    assert!(!table.has_retry_delivery_for_thread(TID));
    assert!(table.oldest_waiting_for_file(KEY).is_none());
    assert!(table.alertable_waiting_for_thread(TID).is_none());
    assert!(table.promote_exact(slot, KEY, TID).is_none());
    assert!(table.take_exact(slot, KEY, TID).is_none());
    assert_eq!(table.request_thread_cancellation(TID), 0);
    assert!(table.has_cancellation_for_thread(TID));
    assert!(!table.reset());
    finish_hosted(&mut table, identity, true);
    assert!(!table.has_cancellation_for_thread(TID));
    assert!(table.reset());
}

#[test]
fn definite_refusal_retries_only_its_effect_and_rejects_duplicate_ticket_receipts() {
    let mut table = SynchronousFileWaitTable::new();
    let slot = table.park(waiter(TID, 40)).unwrap();
    let identity = cancel(&mut table, slot, TID);
    let mut first = table.begin_cancellation(identity).unwrap();
    assert!(table.begin_cancellation(identity).is_err());
    table
        .record_cancellation(&mut first, SynchronousFileCancelOutcome::NotEntered(ERROR))
        .unwrap();
    let mut second = table.begin_cancellation(identity).unwrap();
    assert!(table
        .record_cancellation(
            &mut first,
            SynchronousFileCancelOutcome::Completed(SynchronousFileCancelReceipt::HostedPolicy {
                waiters: 0
            },)
        )
        .is_err());
    assert_eq!(second.effect(), SynchronousFileCancelEffect::Policy);
    table
        .record_cancellation(
            &mut second,
            SynchronousFileCancelOutcome::Completed(SynchronousFileCancelReceipt::HostedPolicy {
                waiters: 0,
            }),
        )
        .unwrap();
    assert_eq!(
        table.cancellation_ownership(KEY),
        SynchronousFileCancelOwnership::default()
    );
    let mut wake = table.begin_cancellation(identity).unwrap();
    assert_eq!(wake.effect(), SynchronousFileCancelEffect::Wake);
    table
        .record_cancellation(&mut wake, SynchronousFileCancelOutcome::NotEntered(ERROR))
        .unwrap();
    assert_eq!(
        table.begin_cancellation(identity).unwrap().effect(),
        SynchronousFileCancelEffect::Wake
    );
}

#[test]
fn mismatched_receipt_or_domain_cannot_settle_an_entered_effect() {
    let mut table = SynchronousFileWaitTable::new();
    let slot = table.park(waiter(TID, 40)).unwrap();
    let identity = cancel(&mut table, slot, TID);
    let mut attempt = table.begin_cancellation(identity).unwrap();
    for receipt in [
        SynchronousFileCancelReceipt::Wake,
        SynchronousFileCancelReceipt::LocalPolicy { waiters: 0 },
    ] {
        assert_eq!(
            table.record_cancellation(
                &mut attempt,
                SynchronousFileCancelOutcome::Completed(receipt)
            ),
            Err(SynchronousFileCancelError::WrongReceipt)
        );
    }
    table
        .record_cancellation(
            &mut attempt,
            SynchronousFileCancelOutcome::Completed(SynchronousFileCancelReceipt::HostedPolicy {
                waiters: 0,
            }),
        )
        .unwrap();
    complete(&mut table, identity, SynchronousFileCancelReceipt::Wake);
    let mut release = table.begin_cancellation(identity).unwrap();
    assert_eq!(
        table.record_cancellation(
            &mut release,
            SynchronousFileCancelOutcome::Completed(SynchronousFileCancelReceipt::HostedReference(
                FileReferenceRelease {
                    device_id: DEVICE + 1,
                    ..FileReferenceRelease::default()
                }
            ),)
        ),
        Err(SynchronousFileCancelError::WrongReceipt)
    );
}

#[test]
fn hosted_reference_receipt_retains_auxiliary_followup_before_cap_retirement() {
    let mut table = SynchronousFileWaitTable::new();
    let slot = table.park(waiter(TID, 40)).unwrap();
    let identity = cancel(&mut table, slot, TID);
    complete(
        &mut table,
        identity,
        SynchronousFileCancelReceipt::HostedPolicy { waiters: 0 },
    );
    complete(&mut table, identity, SynchronousFileCancelReceipt::Wake);
    let release = FileReferenceRelease {
        device_id: DEVICE,
        close_required: true,
        port_id: Some(9),
        cleanup_required: false,
    };
    complete(
        &mut table,
        identity,
        SynchronousFileCancelReceipt::HostedReference(release),
    );
    let mut followup = table.begin_cancellation(identity).unwrap();
    assert_eq!(
        followup.effect(),
        SynchronousFileCancelEffect::ReferenceFollowup
    );
    assert_eq!(followup.reference_release(), Some(release));
    table
        .record_cancellation(
            &mut followup,
            SynchronousFileCancelOutcome::NotEntered(ERROR),
        )
        .unwrap();
    assert_eq!(
        table.cancellation(identity).unwrap().reference_release,
        Some(release)
    );
    complete(
        &mut table,
        identity,
        SynchronousFileCancelReceipt::ReferenceFollowup,
    );
    complete(
        &mut table,
        identity,
        SynchronousFileCancelReceipt::ReplyRevoked,
    );
    assert_eq!(table.cancellation(identity).unwrap().waiter.reply_cap, 40);
    complete(
        &mut table,
        identity,
        SynchronousFileCancelReceipt::ReplyCapRetired,
    );
    assert_eq!(table.finish_cancellation(identity).unwrap().reply_cap, 0);
}

#[test]
fn local_zero_policy_receipt_consumes_reference_without_a_second_release() {
    let mut table = SynchronousFileWaitTable::new();
    let reservation = table.reserve().unwrap();
    let mut local = waiter(TID, 0);
    local.route = FileIoWaitRoute::LocalOverlay { file_object: 0 };
    let identity = table.cancel_reserved(reservation, local).unwrap();
    complete(
        &mut table,
        identity,
        SynchronousFileCancelReceipt::LocalPolicy { waiters: 0 },
    );
    complete(&mut table, identity, SynchronousFileCancelReceipt::Wake);
    assert_eq!(
        table.cancellation(identity).unwrap().phase,
        SynchronousFileCancelPhase::Complete
    );
    assert_eq!(
        table.cancellation(identity).unwrap().reference_release,
        None
    );
    assert_eq!(
        table.finish_cancellation(identity).unwrap().key(),
        FileIoWaitKey::LocalOverlay(0)
    );
}

#[test]
fn indeterminate_and_dropped_effects_are_never_reoffered_or_extracted() {
    for indeterminate in [false, true] {
        let mut table = SynchronousFileWaitTable::new();
        let slot = table.park(waiter(TID, 40)).unwrap();
        let identity = cancel(&mut table, slot, TID);
        let mut attempt = table.begin_cancellation(identity).unwrap();
        if indeterminate {
            table
                .record_cancellation(
                    &mut attempt,
                    SynchronousFileCancelOutcome::Indeterminate(ERROR),
                )
                .unwrap();
        }
        drop(attempt);
        assert!(table.next_cancellation_after(None).is_none());
        assert!(table.begin_cancellation(identity).is_err());
        assert!(table.finish_cancellation(identity).is_none());
        assert_eq!(table.cancellation_ownership(KEY).waiting, 1);
        assert!(!table.reset());
    }
}

#[test]
fn cancellation_defers_entered_retry_and_activates_only_after_definite_refusal() {
    let mut table = SynchronousFileWaitTable::new();
    let slot = table.park(waiter(TID, 40)).unwrap();
    table.promote_exact(slot, KEY, TID).unwrap();
    let retry = table.retry_identity(slot, KEY, TID).unwrap();
    let mut attempt = table.begin_retry(retry).unwrap();
    let cancel = cancel(&mut table, slot, TID);
    assert_eq!(
        table.cancellation(cancel).unwrap().phase,
        SynchronousFileCancelPhase::DeferredRetry
    );
    assert!(table.begin_cancellation(cancel).is_err());
    table
        .record_retry(&mut attempt, SynchronousFileRetryOutcome::NotEntered(ERROR))
        .unwrap();
    assert!(table.next_retry_for_file(KEY).is_none());
    assert!(table.begin_retry(retry).is_err());
    assert_eq!(table.cancellation_ownership(KEY).promoted, 1);
    finish_hosted(&mut table, cancel, true);
}

#[test]
fn accepted_retry_finishes_cap_retirement_before_deferred_grant_cancellation() {
    let mut table = SynchronousFileWaitTable::new();
    let slot = table.park(waiter(TID, 40)).unwrap();
    table.promote_exact(slot, KEY, TID).unwrap();
    let retry = table.retry_identity(slot, KEY, TID).unwrap();
    let mut attempt = table.begin_retry(retry).unwrap();
    let cancel = cancel(&mut table, slot, TID);
    table
        .record_retry(&mut attempt, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    assert_eq!(table.next_acknowledged_retry_after(None), Some(retry));
    assert!(table.begin_cancellation(cancel).is_err());
    assert!(!table.finish_retry(retry, Err(ERROR)).unwrap());
    assert!(table.begin_cancellation(cancel).is_err());
    assert!(table.finish_retry(retry, Ok(())).unwrap());
    assert!(table
        .adopt_promoted_fixture(2, TID, TID + 100, 191)
        .is_none());
    finish_hosted(&mut table, cancel, false);
}

#[test]
fn uncertain_retry_delivery_keeps_deferred_cancellation_and_grant_owned() {
    let mut table = SynchronousFileWaitTable::new();
    let slot = table.park(waiter(TID, 40)).unwrap();
    table.promote_exact(slot, KEY, TID).unwrap();
    let retry = table.retry_identity(slot, KEY, TID).unwrap();
    let mut attempt = table.begin_retry(retry).unwrap();
    let cancel = cancel(&mut table, slot, TID);
    table
        .record_retry(
            &mut attempt,
            SynchronousFileRetryOutcome::Indeterminate(ERROR),
        )
        .unwrap();
    assert!(table.begin_cancellation(cancel).is_err());
    assert!(table.has_retry_delivery_for_thread(TID));
    assert!(table.has_cancellation_for_thread(TID));
    assert_eq!(table.cancellation_ownership(KEY).promoted, 1);
    assert!(table.take_exact(slot, KEY, TID).is_none());
}

#[test]
fn tickets_are_exact_across_tables_and_reused_rows() {
    let mut first = SynchronousFileWaitTable::new();
    let mut second = SynchronousFileWaitTable::new();
    let slot = first.park(waiter(TID, 40)).unwrap();
    let other = second.park(waiter(TID, 40)).unwrap();
    let id = cancel(&mut first, slot, TID);
    let other_id = cancel(&mut second, other, TID);
    let mut ticket = first.begin_cancellation(id).unwrap();
    assert_eq!(
        second.record_cancellation(&mut ticket, SynchronousFileCancelOutcome::NotEntered(ERROR)),
        Err(SynchronousFileCancelError::WrongIdentity)
    );
    first
        .record_cancellation(&mut ticket, SynchronousFileCancelOutcome::NotEntered(ERROR))
        .unwrap();
    finish_hosted(&mut first, id, true);
    assert_eq!(first.park(waiter(TID, 40)), Some(slot));
    cancel(&mut first, slot, TID);
    assert_eq!(
        first.record_cancellation(&mut ticket, SynchronousFileCancelOutcome::NotEntered(ERROR)),
        Err(SynchronousFileCancelError::WrongIdentity)
    );
    finish_hosted(&mut second, other_id, true);
}

#[test]
fn preflight_preserves_publication_budget_and_exhaustion_keeps_owned_work() {
    let mut table = SynchronousFileWaitTable::new();
    table.next_queue_order = u64::MAX - 2;
    let first = table.reserve().unwrap();
    let second = table.reserve().unwrap();
    assert!(table.reserve().is_none());
    let slot = table.park_reserved(second, waiter(TID + 1, 41)).unwrap();
    table.park_reserved(first, waiter(TID, 40)).unwrap();
    let id = cancel(&mut table, slot, TID + 1);
    table.record_mut(slot).unwrap().next_attempt = u64::MAX;
    assert_eq!(
        table.begin_cancellation(id).unwrap_err(),
        SynchronousFileCancelError::Exhausted
    );
    assert!(table.finish_cancellation(id).is_none());
    assert!(!table.reset());
}

#[test]
fn cancelled_ready_retry_keeps_cap_ownership_without_pinning_runtime() {
    let mut table = SynchronousFileWaitTable::new();
    let slot = table.park(waiter(TID, 50)).unwrap();
    assert!(!table.has_runtime_dependency_for_thread(TID));
    table.promote_exact(slot, KEY, TID).unwrap();
    assert!(table.has_runtime_dependency_for_thread(TID));
    assert!(table.has_runtime_dependency_for_pi(2));
    let id = cancel(&mut table, slot, TID);
    assert!(
        table.has_retry_delivery_for_thread(TID),
        "historical Ready remains diagnostic"
    );
    assert!(!table.has_runtime_dependency_for_thread(TID));
    assert!(!table.has_runtime_dependency_for_pi(2));
    complete(
        &mut table,
        id,
        SynchronousFileCancelReceipt::HostedPolicy { waiters: 0 },
    );
    complete(&mut table, id, SynchronousFileCancelReceipt::Wake);
    complete(
        &mut table,
        id,
        SynchronousFileCancelReceipt::HostedReference(FileReferenceRelease {
            device_id: DEVICE,
            ..FileReferenceRelease::default()
        }),
    );
    let mut revoke = table.begin_cancellation(id).unwrap();
    assert_eq!(revoke.effect(), SynchronousFileCancelEffect::RevokeReply);
    assert!(!table.has_runtime_dependency_for_thread(TID));
    table
        .record_cancellation(&mut revoke, SynchronousFileCancelOutcome::NotEntered(ERROR))
        .unwrap();
    assert!(!table.has_runtime_dependency_for_thread(TID));
    complete(&mut table, id, SynchronousFileCancelReceipt::ReplyRevoked);
    let mut retype = table.begin_cancellation(id).unwrap();
    assert_eq!(retype.effect(), SynchronousFileCancelEffect::RetireReplyCap);
    table
        .record_cancellation(
            &mut retype,
            SynchronousFileCancelOutcome::Indeterminate(ERROR),
        )
        .unwrap();
    assert!(!table.has_runtime_dependency_for_thread(TID));
    assert!(table.has_cancellation_for_thread(TID));
    assert!(table.has_waiter_for_pi(2));
}

#[test]
fn deferred_retry_depends_on_runtime_until_exact_delivery_outcome_and_retirement() {
    for outcome in [
        SynchronousFileRetryOutcome::NotEntered(ERROR),
        SynchronousFileRetryOutcome::Indeterminate(ERROR),
        SynchronousFileRetryOutcome::Acknowledged,
    ] {
        let mut table = SynchronousFileWaitTable::new();
        let slot = table.park(waiter(TID, 50)).unwrap();
        table.promote_exact(slot, KEY, TID).unwrap();
        let retry_id = table.retry_identity(slot, KEY, TID).unwrap();
        let mut retry = table.begin_retry(retry_id).unwrap();
        cancel(&mut table, slot, TID);
        assert!(table.has_runtime_dependency_for_thread(TID));
        table.record_retry(&mut retry, outcome).unwrap();
        match outcome {
            SynchronousFileRetryOutcome::NotEntered(_) => {
                assert!(!table.has_runtime_dependency_for_thread(TID))
            }
            SynchronousFileRetryOutcome::Indeterminate(_) => {
                assert!(table.has_runtime_dependency_for_thread(TID))
            }
            SynchronousFileRetryOutcome::Acknowledged => {
                assert!(table.has_runtime_dependency_for_thread(TID));
                assert!(!table.finish_retry(retry_id, Err(ERROR)).unwrap());
                assert!(table.has_runtime_dependency_for_thread(TID));
                assert!(table.finish_retry(retry_id, Ok(())).unwrap());
                assert!(!table.has_runtime_dependency_for_thread(TID));
            }
        }
    }
}

#[test]
fn ingress_keeps_runtime_dependency_after_retry_cap_retirement() {
    let mut table = SynchronousFileWaitTable::new();
    let slot = table.park(waiter(TID, 50)).unwrap();
    table.promote_exact(slot, KEY, TID).unwrap();
    let retry_id = table.retry_identity(slot, KEY, TID).unwrap();
    let mut retry = table.begin_retry(retry_id).unwrap();
    table
        .record_retry(&mut retry, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    table.finish_retry(retry_id, Ok(())).unwrap();
    assert!(!table.has_runtime_dependency_for_thread(TID));
    let mut ingress = table
        .begin_ingress(2, TID, TID + 100, 191)
        .unwrap()
        .unwrap();
    assert!(table.has_runtime_dependency_for_thread(TID));
    let id = cancel(&mut table, slot, TID);
    assert!(table.has_runtime_dependency_for_thread(TID));
    assert_eq!(table.reject_ingress(&mut ingress, ERROR).unwrap(), id);
    assert!(!table.has_runtime_dependency_for_thread(TID));
}

#[test]
fn runtime_dependency_matching_respects_preserved_thread_and_process() {
    let mut table = SynchronousFileWaitTable::new();
    let first = table.park(waiter(TID, 50)).unwrap();
    table.promote_exact(first, KEY, TID).unwrap();
    let mut peer = waiter(TID + 1, 51);
    peer.route = FileIoWaitRoute::Hosted {
        file_id: FILE + 1,
        device_id: DEVICE,
        fs_context: 0,
    };
    peer.pi = 3;
    let second = table.park(peer).unwrap();
    table.promote_exact(second, peer.key(), peer.tid).unwrap();
    assert!(!table.has_runtime_dependency_matching(|waiter| waiter.pi == 2 && waiter.tid != TID));
    assert!(table.has_runtime_dependency_matching(|waiter| waiter.pi == 3 && waiter.tid != TID));
    cancel(&mut table, first, TID);
    assert!(!table.has_runtime_dependency_for_pi(2));
    assert!(table.has_runtime_dependency_for_pi(3));
}
