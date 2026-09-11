use super::*;
use SynchronousFileCancelDisposition as Disposition;
use SynchronousFileCancelEffect as Effect;
use SynchronousFileCancelOutcome as Outcome;
use SynchronousFileCancelPhase as Phase;
use SynchronousFileCancelReceipt as Receipt;

const KEY: FileIoWaitKey = FileIoWaitKey::Hosted(10);
const ERROR: u32 = 0xc000_009a;

fn waiter() -> SynchronousFileWaiter {
    let mut waiter = SynchronousFileWaiter::waiting(
        FileIoWaitRoute::Hosted {
            file_id: 10,
            device_id: 7,
            fs_context: 9,
        },
        1,
        3,
        191,
        2,
        20,
        120,
        FileIoMode::SynchronousAlertable,
        true,
        0,
        0x1000,
        0x2000,
        0x202,
    );
    waiter.reply_cap = 50;
    waiter
}

fn parked() -> (SynchronousFileWaitTable, SynchronousFileWaitIdentity) {
    let mut table = SynchronousFileWaitTable::new();
    let slot = table.park(waiter()).unwrap();
    let id = table.wait_identity(slot, KEY, 20).unwrap();
    (table, id)
}

fn interrupted() -> (SynchronousFileWaitTable, SynchronousFileCancelIdentity) {
    let (mut table, id) = parked();
    table.request_user_apc_interruption(id).unwrap();
    (table, id)
}

fn complete(
    table: &mut SynchronousFileWaitTable,
    id: SynchronousFileCancelIdentity,
    receipt: Receipt,
) {
    let mut attempt = table.begin_cancellation(id).unwrap();
    table
        .record_cancellation(&mut attempt, Outcome::Completed(receipt))
        .unwrap();
}

fn ready_stage(table: &mut SynchronousFileWaitTable, id: SynchronousFileCancelIdentity) {
    complete(table, id, Receipt::HostedPolicy { waiters: 0 });
    complete(table, id, Receipt::Wake);
    complete(
        table,
        id,
        Receipt::HostedReference(FileReferenceRelease {
            device_id: 7,
            ..FileReferenceRelease::default()
        }),
    );
    assert_eq!(
        table.cancellation(id).unwrap().phase,
        Phase::Ready {
            effect: Effect::StageUserApc,
            last_error: None
        }
    );
}

#[test]
fn apc_claim_is_exact_single_and_excludes_fifo_retry_and_extraction() {
    let (mut table, id) = interrupted();
    assert!(table.has_user_apc_interruption_for_thread(20));
    assert!(table.has_runtime_dependency_for_thread(20));
    assert!(table.has_runtime_dependency_for_pi(2));
    assert!(table.alertable_waiting_for_thread(20).is_none());
    assert!(table.oldest_waiting_for_file(KEY).is_none());
    assert!(table.take_exact(id.slot(), KEY, 20).is_none());
    assert!(table.promote_exact(id.slot(), KEY, 20).is_none());
    assert_eq!(
        table.request_user_apc_interruption(id),
        Err(SynchronousFileCancelError::InvalidPhase)
    );
    let (mut other, _) = parked();
    assert_eq!(
        other.request_user_apc_interruption(id),
        Err(SynchronousFileCancelError::WrongIdentity)
    );
    assert!(!table.reset());
    assert_eq!(table.cancellation_ownership(KEY).waiting, 1);
}

#[test]
fn nonalertable_promoted_and_stale_rows_cannot_be_claimed_for_apc() {
    let (mut table, id) = parked();
    table.promote_exact(id.slot(), KEY, 20).unwrap();
    assert_eq!(
        table.request_user_apc_interruption(id),
        Err(SynchronousFileCancelError::InvalidPhase)
    );
    let mut table = SynchronousFileWaitTable::new();
    let mut request = waiter();
    request.mode = FileIoMode::SynchronousNonAlertable;
    let slot = table.park(request).unwrap();
    let old = table.wait_identity(slot, KEY, 20).unwrap();
    assert_eq!(
        table.request_user_apc_interruption(old),
        Err(SynchronousFileCancelError::InvalidPhase)
    );
    table.take_exact(slot, KEY, 20).unwrap();
    assert_eq!(table.park(waiter()), Some(slot));
    assert_eq!(
        table.request_user_apc_interruption(old),
        Err(SynchronousFileCancelError::WrongIdentity)
    );
}

#[test]
fn staging_sending_and_cap_retirement_have_independent_receipts() {
    let (mut table, id) = interrupted();
    ready_stage(&mut table, id);
    let mut stage = table.begin_cancellation(id).unwrap();
    assert_eq!(stage.identity(), id);
    assert_eq!(stage.disposition(), Disposition::UserApc);
    assert!(!stage.teardown_requested());
    assert_eq!(
        table.record_cancellation(&mut stage, Outcome::Completed(Receipt::UserApcReplySent)),
        Err(SynchronousFileCancelError::WrongReceipt)
    );
    table
        .record_cancellation(&mut stage, Outcome::NotEntered(ERROR))
        .unwrap();
    let mut stage = table.begin_cancellation(id).unwrap();
    table
        .record_cancellation(&mut stage, Outcome::Completed(Receipt::UserApcStaged))
        .unwrap();
    assert!(table
        .record_cancellation(&mut stage, Outcome::Completed(Receipt::UserApcStaged))
        .is_err());
    let mut send = table.begin_cancellation(id).unwrap();
    assert_eq!(send.effect(), Effect::SendUserApc);
    table
        .record_cancellation(&mut send, Outcome::NotEntered(ERROR))
        .unwrap();
    let mut send = table.begin_cancellation(id).unwrap();
    assert_eq!(send.effect(), Effect::SendUserApc);
    table
        .record_cancellation(&mut send, Outcome::Completed(Receipt::UserApcReplySent))
        .unwrap();
    let mut retire = table.begin_cancellation(id).unwrap();
    assert_eq!(retire.effect(), Effect::RetireApcReplyCap);
    table
        .record_cancellation(&mut retire, Outcome::NotEntered(ERROR))
        .unwrap();
    assert!(table.has_runtime_dependency_for_thread(20));
    complete(&mut table, id, Receipt::UserApcReplyCapRetired);
    assert_eq!(table.cancellation(id).unwrap().waiter.reply_cap, 0);
    assert!(table.has_runtime_dependency_for_thread(20));
    table.finish_cancellation(id).unwrap();
    assert!(!table.has_runtime_dependency_for_thread(20));
    assert!(!table.has_user_apc_interruption_for_thread(20));
}

#[test]
fn teardown_ready_stage_or_send_keeps_policy_receipts_and_never_stages_or_sends_again() {
    for staged in [false, true] {
        let (mut table, id) = interrupted();
        ready_stage(&mut table, id);
        if staged {
            complete(&mut table, id, Receipt::UserApcStaged);
        }
        let reference = table.cancellation(id).unwrap().reference_release;
        assert_eq!(table.request_thread_cancellation(20), 1);
        assert_eq!(table.request_thread_cancellation(20), 0);
        let view = table.cancellation(id).unwrap();
        assert_eq!(view.disposition, Disposition::Teardown);
        assert!(view.teardown_requested);
        assert_eq!(view.reference_release, reference);
        assert_eq!(view.policy_waiters, Some(0));
        assert_eq!(
            view.phase,
            Phase::Ready {
                effect: Effect::RevokeReply,
                last_error: None
            }
        );
        assert!(!table.has_runtime_dependency_for_thread(20));
        complete(&mut table, id, Receipt::ReplyRevoked);
        complete(&mut table, id, Receipt::ReplyCapRetired);
        table.finish_cancellation(id).unwrap();
    }
}

#[test]
fn teardown_before_stage_does_not_discard_inflight_policy_receipt() {
    let (mut table, id) = interrupted();
    let mut policy = table.begin_cancellation(id).unwrap();
    table.request_cancellation(id).unwrap();
    assert!(!table.has_runtime_dependency_for_thread(20));
    table
        .record_cancellation(
            &mut policy,
            Outcome::Completed(Receipt::HostedPolicy { waiters: 0 }),
        )
        .unwrap();
    complete(&mut table, id, Receipt::Wake);
    complete(
        &mut table,
        id,
        Receipt::HostedReference(FileReferenceRelease {
            device_id: 7,
            ..FileReferenceRelease::default()
        }),
    );
    assert_eq!(
        table.begin_cancellation(id).unwrap().effect(),
        Effect::RevokeReply
    );
}

#[test]
fn entered_stage_teardown_waits_for_definite_receipt_and_does_not_send() {
    for staged in [false, true] {
        let (mut table, id) = interrupted();
        ready_stage(&mut table, id);
        let mut stage = table.begin_cancellation(id).unwrap();
        table.request_cancellation(id).unwrap();
        assert!(table.has_runtime_dependency_for_thread(20));
        assert!(table.begin_cancellation(id).is_err());
        table
            .record_cancellation(
                &mut stage,
                if staged {
                    Outcome::Completed(Receipt::UserApcStaged)
                } else {
                    Outcome::NotEntered(ERROR)
                },
            )
            .unwrap();
        assert_eq!(
            table.cancellation(id).unwrap().disposition,
            Disposition::Teardown
        );
        assert!(!table.has_runtime_dependency_for_thread(20));
        assert_eq!(
            table.begin_cancellation(id).unwrap().effect(),
            Effect::RevokeReply
        );
    }
}

#[test]
fn entered_send_teardown_distinguishes_refusal_from_accepted_reply() {
    for sent in [false, true] {
        let (mut table, id) = interrupted();
        ready_stage(&mut table, id);
        complete(&mut table, id, Receipt::UserApcStaged);
        let mut send = table.begin_cancellation(id).unwrap();
        table.request_cancellation(id).unwrap();
        assert!(table.has_runtime_dependency_for_thread(20));
        table
            .record_cancellation(
                &mut send,
                if sent {
                    Outcome::Completed(Receipt::UserApcReplySent)
                } else {
                    Outcome::NotEntered(ERROR)
                },
            )
            .unwrap();
        assert_eq!(table.has_runtime_dependency_for_thread(20), sent);
        let mut next = table.begin_cancellation(id).unwrap();
        assert_eq!(
            next.effect(),
            if sent {
                Effect::RetireApcReplyCap
            } else {
                Effect::RevokeReply
            }
        );
        if sent {
            table
                .record_cancellation(&mut next, Outcome::NotEntered(ERROR))
                .unwrap();
            table.request_cancellation(id).unwrap();
            assert_eq!(
                table.begin_cancellation(id).unwrap().effect(),
                Effect::RetireApcReplyCap
            );
        }
    }
}

#[test]
fn uncertain_or_dropped_stage_and_send_quarantine_owner_and_runtime() {
    for send in [false, true] {
        for indeterminate in [false, true] {
            let (mut table, id) = interrupted();
            ready_stage(&mut table, id);
            if send {
                complete(&mut table, id, Receipt::UserApcStaged);
            }
            let mut attempt = table.begin_cancellation(id).unwrap();
            if indeterminate {
                table
                    .record_cancellation(&mut attempt, Outcome::Indeterminate(ERROR))
                    .unwrap();
            }
            drop(attempt);
            table.request_cancellation(id).unwrap();
            assert!(table.has_runtime_dependency_for_thread(20));
            assert!(table.has_user_apc_interruption_for_thread(20));
            assert!(table.next_cancellation_after(None).is_none());
            assert!(table.begin_cancellation(id).is_err());
            assert!(table.finish_cancellation(id).is_none());
            assert!(!table.reset());
        }
    }
}

#[test]
fn local_apc_interruption_consumes_reference_atomically_before_staging() {
    let mut table = SynchronousFileWaitTable::new();
    let mut request = waiter();
    request.route = FileIoWaitRoute::LocalOverlay { file_object: 0 };
    let slot = table.park(request).unwrap();
    let id = table.wait_identity(slot, request.key(), 20).unwrap();
    table.request_user_apc_interruption(id).unwrap();
    complete(&mut table, id, Receipt::LocalPolicy { waiters: 0 });
    complete(&mut table, id, Receipt::Wake);
    assert_eq!(
        table.begin_cancellation(id).unwrap().effect(),
        Effect::StageUserApc
    );
    assert_eq!(table.cancellation(id).unwrap().reference_release, None);
}
