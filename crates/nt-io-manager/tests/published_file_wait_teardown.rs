//! Published waiter teardown composed with real File policy and exact retained cancellation.
//! Reply deletion, retyping, and sends are controlled fixture effects, not microkernel proof.

use nt_io_completion::{FileCompletionTable, FileIoAcquireResult, FileIoMode};
use nt_io_manager::*;

const FILE: u64 = 17;
const DEVICE: u64 = 7;
const ACTIVE: u64 = 20;
const WAITER: u64 = 21;
const CAP: u64 = 47;
const REFUSED: u32 = 13;
const MODE: FileIoMode = FileIoMode::SynchronousNonAlertable;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplyObject {
    Bound,
    Empty,
    Unbound,
}

struct SavedReply {
    object: ReplyObject,
    reusable: bool,
    deletions: usize,
    retypes: usize,
    replies: usize,
}

impl SavedReply {
    fn new() -> Self {
        Self {
            object: ReplyObject::Bound,
            reusable: false,
            deletions: 0,
            retypes: 0,
            replies: 0,
        }
    }

    fn delete(&mut self, accepted: bool) -> SynchronousFileCancelOutcome {
        assert_eq!(self.object, ReplyObject::Bound);
        assert!(!self.reusable);
        if !accepted {
            return SynchronousFileCancelOutcome::NotEntered(REFUSED);
        }
        self.object = ReplyObject::Empty;
        self.deletions += 1;
        SynchronousFileCancelOutcome::Completed(SynchronousFileCancelReceipt::ReplyRevoked)
    }

    fn retype(&mut self, accepted: bool) -> SynchronousFileCancelOutcome {
        assert_eq!(self.object, ReplyObject::Empty);
        assert!(!self.reusable);
        if !accepted {
            return SynchronousFileCancelOutcome::NotEntered(REFUSED);
        }
        self.object = ReplyObject::Unbound;
        self.retypes += 1;
        SynchronousFileCancelOutcome::Completed(SynchronousFileCancelReceipt::ReplyCapRetired)
    }
}

struct Fixture {
    files: FileCompletionTable<1>,
    table: SynchronousFileWaitTable,
    identity: SynchronousFileWaitIdentity,
    slot: usize,
    promoted: bool,
    reply: SavedReply,
}

impl Fixture {
    fn new(promoted: bool) -> Self {
        let mut files = FileCompletionTable::new();
        files.insert_file_with_mode(FILE, DEVICE, MODE).unwrap();
        assert_eq!(
            files.acquire_file_io(FILE, ACTIVE),
            Ok(FileIoAcquireResult::Acquired)
        );
        let mut table = SynchronousFileWaitTable::new();
        let reservation = table.reserve().unwrap();
        assert_eq!(
            files.acquire_file_io(FILE, WAITER),
            Ok(FileIoAcquireResult::Contended { alertable: false })
        );
        let mut waiter = SynchronousFileWaiter::waiting(
            FileIoWaitRoute::Hosted {
                file_id: FILE,
                device_id: DEVICE,
                fs_context: 9,
            },
            0x40,
            1,
            191,
            2,
            WAITER,
            WAITER + 100,
            MODE,
            true,
            0,
            0x1002,
            0x2000,
            0x202,
        );
        waiter.reply_cap = CAP;
        let slot = table.park_reserved(reservation, waiter).unwrap();
        let identity = table
            .wait_identity(slot, FileIoWaitKey::Hosted(FILE), WAITER)
            .unwrap();
        if promoted {
            files.release_io(FILE, ACTIVE).unwrap();
            files.release_file(FILE).unwrap();
            files.promote_io_waiter(FILE, WAITER).unwrap();
            table
                .promote_exact(slot, FileIoWaitKey::Hosted(FILE), WAITER)
                .unwrap();
        }
        Self {
            files,
            table,
            identity,
            slot,
            promoted,
            reply: SavedReply::new(),
        }
    }

    fn cancel_policy_and_reference(&mut self) {
        use SynchronousFileCancelEffect as Effect;
        use SynchronousFileCancelReceipt as Receipt;
        let mut policy = self.table.begin_cancellation(self.identity).unwrap();
        assert_eq!(policy.effect(), Effect::Policy);
        let waiters = if self.promoted {
            self.files.cancel_promoted_io(FILE, WAITER).unwrap().waiters
        } else {
            self.files.cancel_io_waiter(FILE).unwrap()
        };
        assert_eq!(waiters, 0);
        self.table
            .record_cancellation(
                &mut policy,
                SynchronousFileCancelOutcome::Completed(Receipt::HostedPolicy { waiters }),
            )
            .unwrap();
        let mut wake = self.table.begin_cancellation(self.identity).unwrap();
        assert_eq!(wake.effect(), Effect::Wake);
        self.table
            .record_cancellation(
                &mut wake,
                SynchronousFileCancelOutcome::Completed(Receipt::Wake),
            )
            .unwrap();
        let mut reference = self.table.begin_cancellation(self.identity).unwrap();
        assert_eq!(reference.effect(), Effect::HostedReference);
        let release = self.files.release_file(FILE).unwrap();
        assert!(!release.close_required);
        self.table
            .record_cancellation(
                &mut reference,
                SynchronousFileCancelOutcome::Completed(Receipt::HostedReference(release)),
            )
            .unwrap();
    }

    fn cap_effect(&mut self, effect: SynchronousFileCancelEffect, accepted: bool) {
        let mut attempt = self.table.begin_cancellation(self.identity).unwrap();
        assert_eq!(attempt.effect(), effect);
        assert_eq!(attempt.waiter().reply_cap, CAP);
        assert!(self.table.begin_cancellation(self.identity).is_err());
        let outcome = match effect {
            SynchronousFileCancelEffect::RevokeReply => self.reply.delete(accepted),
            SynchronousFileCancelEffect::RetireReplyCap => self.reply.retype(accepted),
            _ => panic!("not a capability effect"),
        };
        self.table
            .record_cancellation(&mut attempt, outcome)
            .unwrap();
        if effect == SynchronousFileCancelEffect::RetireReplyCap && accepted {
            // The fixture pool releases the reservation only after successful retype is recorded.
            self.reply.reusable = true;
        }
    }

    fn close(mut self) {
        if !self.promoted {
            self.files.release_io(FILE, ACTIVE).unwrap();
            self.files.release_file(FILE).unwrap();
        }
        assert!(self.files.release_handle(FILE).unwrap().cleanup_required);
        assert_eq!(
            self.files.begin_cleanup(FILE),
            Ok(FileIoAcquireResult::Acquired)
        );
        self.files.mark_cleanup_lifecycle_started(FILE).unwrap();
        self.files.release_cleanup_io(FILE).unwrap();
        assert!(
            self.files
                .release_cleanup_reference(FILE)
                .unwrap()
                .close_required
        );
        assert!(self.table.is_empty());
    }
}

#[test]
fn waiting_and_promoted_teardown_retry_delete_and_retype_as_separate_effects() {
    use SynchronousFileCancelEffect as Effect;
    for promoted in [false, true] {
        let mut fixture = Fixture::new(promoted);
        fixture
            .table
            .request_cancellation(fixture.identity)
            .unwrap();
        fixture.cancel_policy_and_reference();
        let release = fixture
            .table
            .cancellation(fixture.identity)
            .unwrap()
            .reference_release;
        fixture.cap_effect(Effect::RevokeReply, false);
        assert_eq!(fixture.reply.object, ReplyObject::Bound);
        assert_eq!(fixture.reply.deletions, 0);
        assert!(!fixture.reply.reusable);
        assert!(fixture
            .table
            .finish_cancellation(fixture.identity)
            .is_none());
        fixture.cap_effect(Effect::RevokeReply, true);
        assert_eq!(fixture.reply.object, ReplyObject::Empty);
        assert_eq!(fixture.reply.deletions, 1);
        assert!(!fixture.reply.reusable);
        fixture.cap_effect(Effect::RetireReplyCap, false);
        assert_eq!(fixture.reply.object, ReplyObject::Empty);
        assert_eq!(fixture.reply.deletions, 1);
        assert_eq!(fixture.reply.retypes, 0);
        assert!(!fixture.reply.reusable);
        assert_eq!(
            fixture
                .table
                .cancellation(fixture.identity)
                .unwrap()
                .reference_release,
            release
        );
        fixture.cap_effect(Effect::RetireReplyCap, true);
        assert_eq!(fixture.reply.object, ReplyObject::Unbound);
        assert!(fixture.reply.reusable);
        assert_eq!(
            (
                fixture.reply.deletions,
                fixture.reply.retypes,
                fixture.reply.replies
            ),
            (1, 1, 0)
        );
        fixture.table.finish_cancellation(fixture.identity).unwrap();
        fixture.close();
    }
}

#[test]
fn an_acknowledged_retry_must_retire_its_cap_before_deferred_cancellation_takes_over() {
    let mut fixture = Fixture::new(true);
    let retry_id = fixture
        .table
        .retry_identity(fixture.slot, FileIoWaitKey::Hosted(FILE), WAITER)
        .unwrap();
    let mut retry = fixture.table.begin_retry(retry_id).unwrap();
    fixture
        .table
        .request_cancellation(fixture.identity)
        .unwrap();
    assert_eq!(
        fixture.table.cancellation(fixture.identity).unwrap().phase,
        SynchronousFileCancelPhase::DeferredRetry
    );
    assert!(fixture.table.begin_cancellation(fixture.identity).is_err());
    assert_eq!(fixture.files.io_grant_owner(FILE), Ok(Some(WAITER)));
    // This send is acknowledged, so deletion would target an already-consumed reply binding.
    fixture.reply.object = ReplyObject::Unbound;
    fixture.reply.replies += 1;
    fixture
        .table
        .record_retry(&mut retry, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    assert!(!fixture.table.finish_retry(retry_id, Err(REFUSED)).unwrap());
    assert!(!fixture.reply.reusable);
    assert!(fixture.table.begin_cancellation(fixture.identity).is_err());
    assert_eq!(fixture.files.io_grant_owner(FILE), Ok(Some(WAITER)));
    assert!(fixture.table.finish_retry(retry_id, Ok(())).unwrap());
    fixture.reply.reusable = true;
    assert_eq!(
        fixture
            .table
            .cancellation(fixture.identity)
            .unwrap()
            .waiter
            .reply_cap,
        0
    );
    fixture.cancel_policy_and_reference();
    assert_eq!(
        fixture.table.cancellation(fixture.identity).unwrap().phase,
        SynchronousFileCancelPhase::Complete
    );
    fixture.table.finish_cancellation(fixture.identity).unwrap();
    assert_eq!(
        (
            fixture.reply.deletions,
            fixture.reply.retypes,
            fixture.reply.replies
        ),
        (0, 0, 1)
    );
    fixture.close();
}

#[test]
fn rejected_retry_releases_its_claim_to_cancellation_but_uncertain_or_dropped_sends_do_not() {
    for outcome in [
        Some(SynchronousFileRetryOutcome::NotEntered(REFUSED)),
        Some(SynchronousFileRetryOutcome::Indeterminate(REFUSED)),
        None,
    ] {
        let mut fixture = Fixture::new(true);
        let retry_id = fixture
            .table
            .retry_identity(fixture.slot, FileIoWaitKey::Hosted(FILE), WAITER)
            .unwrap();
        let mut retry = fixture.table.begin_retry(retry_id).unwrap();
        fixture
            .table
            .request_cancellation(fixture.identity)
            .unwrap();
        if let Some(outcome) = outcome {
            fixture.table.record_retry(&mut retry, outcome).unwrap();
        }
        drop(retry);
        if matches!(outcome, Some(SynchronousFileRetryOutcome::NotEntered(_))) {
            fixture.cancel_policy_and_reference();
            fixture.cap_effect(SynchronousFileCancelEffect::RevokeReply, true);
            fixture.cap_effect(SynchronousFileCancelEffect::RetireReplyCap, true);
            fixture.table.finish_cancellation(fixture.identity).unwrap();
            fixture.close();
        } else {
            assert!(fixture.table.begin_cancellation(fixture.identity).is_err());
            assert!(fixture
                .table
                .next_retry_for_file(FileIoWaitKey::Hosted(FILE))
                .is_none());
            assert!(fixture
                .table
                .finish_cancellation(fixture.identity)
                .is_none());
            assert_eq!(fixture.files.io_grant_owner(FILE), Ok(Some(WAITER)));
            assert_eq!(fixture.reply.object, ReplyObject::Bound);
            assert!(!fixture.reply.reusable);
            assert_eq!(
                (
                    fixture.reply.deletions,
                    fixture.reply.retypes,
                    fixture.reply.replies
                ),
                (0, 0, 0)
            );
            assert!(fixture.files.release_handle(FILE).unwrap().cleanup_required);
            assert_eq!(
                fixture.files.begin_cleanup(FILE),
                Ok(FileIoAcquireResult::Contended { alertable: false })
            );
            assert_eq!(fixture.files.promote_cleanup_if_ready(FILE), Ok(false));
        }
    }
}
