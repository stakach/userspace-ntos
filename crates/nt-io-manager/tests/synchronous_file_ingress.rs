//! Promoted retry ingress composed with real hosted File acquisition and reference policy.
//! Copy-in, IPC, and provider followup results are explicit fixtures, not native execution proof.

use nt_io_completion::{FileCompletionTable, FileIoAcquireResult, FileIoMode};
use nt_io_manager::*;

const FILE: u64 = 17;
const DEVICE: u64 = 7;
const FIRST: u64 = 20;
const SECOND: u64 = 21;
const THIRD: u64 = 22;
const PI: u32 = 2;
const SSN: u32 = 191;
const MODE: FileIoMode = FileIoMode::SynchronousNonAlertable;
const REFUSED: u32 = 0xc000_0001;
const COPYIN_FAULT: u32 = 0xc000_0005;

fn waiter(tid: u64) -> SynchronousFileWaiter {
    let mut waiter = SynchronousFileWaiter::waiting(
        FileIoWaitRoute::Hosted {
            file_id: FILE,
            device_id: DEVICE,
            fs_context: 9,
        },
        0x40,
        3,
        SSN,
        PI,
        tid,
        tid + 100,
        MODE,
        true,
        0,
        0x1002,
        0x2000,
        0x202,
    );
    waiter.reply_cap = tid + 200;
    waiter
}

fn empty_file() -> FileCompletionTable<1> {
    let mut files = FileCompletionTable::new();
    files.insert_file_with_mode(FILE, DEVICE, MODE).unwrap();
    files
}

fn close_empty_file(files: &mut FileCompletionTable<1>) {
    assert!(files.release_handle(FILE).unwrap().cleanup_required);
    assert_eq!(files.begin_cleanup(FILE), Ok(FileIoAcquireResult::Acquired));
    files.mark_cleanup_lifecycle_started(FILE).unwrap();
    files.release_cleanup_io(FILE).unwrap();
    assert!(
        files
            .release_cleanup_reference(FILE)
            .unwrap()
            .close_required
    );
    assert!(files.io_mode(FILE).is_err());
}

fn queue(
    files: &mut FileCompletionTable<1>,
    table: &mut SynchronousFileWaitTable,
    tid: u64,
) -> usize {
    let reservation = table.reserve().unwrap();
    assert_eq!(
        files.acquire_file_io(FILE, tid),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    table.park_reserved(reservation, waiter(tid)).unwrap()
}

fn promoted() -> (FileCompletionTable<1>, SynchronousFileWaitTable, usize) {
    let mut files = empty_file();
    assert_eq!(
        files.acquire_file_io(FILE, FIRST),
        Ok(FileIoAcquireResult::Acquired)
    );
    let mut table = SynchronousFileWaitTable::new();
    let slot = queue(&mut files, &mut table, SECOND);
    files.release_io(FILE, FIRST).unwrap();
    assert!(!files.release_file(FILE).unwrap().close_required);
    files.promote_io_waiter(FILE, SECOND).unwrap();
    table
        .promote_exact(slot, FileIoWaitKey::Hosted(FILE), SECOND)
        .unwrap();
    let identity = table
        .retry_identity(slot, FileIoWaitKey::Hosted(FILE), SECOND)
        .unwrap();
    let mut retry = table.begin_retry(identity).unwrap();
    table
        .record_retry(&mut retry, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    assert!(table.finish_retry(identity, Ok(())).unwrap());
    assert_eq!(files.io_grant_owner(FILE), Ok(Some(SECOND)));
    (files, table, slot)
}

fn apply(
    table: &mut SynchronousFileWaitTable,
    identity: SynchronousFileCancelIdentity,
    effect: SynchronousFileCancelEffect,
    source: impl FnOnce(&mut SynchronousFileWaitTable) -> SynchronousFileCancelReceipt,
) -> SynchronousFileCancelReceipt {
    let mut attempt = table.begin_cancellation(identity).unwrap();
    assert_eq!(attempt.effect(), effect);
    assert!(table.begin_cancellation(identity).is_err());
    let receipt = source(table);
    table
        .record_cancellation(
            &mut attempt,
            SynchronousFileCancelOutcome::Completed(receipt),
        )
        .unwrap();
    receipt
}

fn cancel_policy(
    files: &mut FileCompletionTable<1>,
    table: &mut SynchronousFileWaitTable,
    identity: SynchronousFileCancelIdentity,
) {
    apply(table, identity, SynchronousFileCancelEffect::Policy, |_| {
        SynchronousFileCancelReceipt::HostedPolicy {
            waiters: files.cancel_promoted_io(FILE, SECOND).unwrap().waiters,
        }
    });
}

#[test]
fn fresh_acquisition_failures_leave_no_reference_or_waiter_to_leak() {
    let mut files = empty_file();
    for tid in [0, u64::MAX] {
        assert!(files.acquire_file_io(FILE, tid).is_err());
        assert_eq!(files.io_lock_owner(FILE), Ok(None));
        assert_eq!(files.io_waiter_count(FILE), Ok(0));
    }
    assert!(files.acquire_file_io(FILE + 1, FIRST).is_err());
    assert_eq!(
        files.acquire_file_io(FILE, FIRST),
        Ok(FileIoAcquireResult::Acquired)
    );
    assert_eq!(
        files.acquire_file_io(FILE, SECOND),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    assert_eq!(files.cancel_io_waiter(FILE), Ok(0));
    assert!(!files.release_file(FILE).unwrap().close_required);
    files.release_io(FILE, FIRST).unwrap();
    assert!(!files.release_file(FILE).unwrap().close_required);
    // Exactly the two admitted references were released. Any refused-acquisition leak prevents
    // this final close from retiring the File identity.
    close_empty_file(&mut files);
}

#[test]
fn promoted_copyin_rejection_retains_the_original_grant_for_capless_cancellation() {
    use SynchronousFileCancelEffect as Effect;
    use SynchronousFileCancelReceipt as Receipt;
    let (mut files, mut table, _) = promoted();
    let mut ingress = table
        .begin_ingress(PI, SECOND, SECOND + 100, SSN)
        .unwrap()
        .unwrap();
    assert_eq!(ingress.waiter().reply_cap, 0);
    assert_eq!(ingress.waiter().route, waiter(SECOND).route);
    let identity = table.reject_ingress(&mut ingress, COPYIN_FAULT).unwrap();
    assert_eq!(files.io_grant_owner(FILE), Ok(Some(SECOND)));
    assert_eq!(files.io_waiter_count(FILE), Ok(0));
    assert_eq!(table.cancellation(identity).unwrap().waiter.reply_cap, 0);
    assert!(table.reject_ingress(&mut ingress, COPYIN_FAULT).is_err());
    cancel_policy(&mut files, &mut table, identity);
    apply(&mut table, identity, Effect::Wake, |_| Receipt::Wake);
    apply(&mut table, identity, Effect::HostedReference, |_| {
        Receipt::HostedReference(files.release_file(FILE).unwrap())
    });
    assert_eq!(
        table.cancellation(identity).unwrap().phase,
        SynchronousFileCancelPhase::Complete
    );
    assert_eq!(table.finish_cancellation(identity).unwrap().reply_cap, 0);
    assert!(table.is_empty());
    close_empty_file(&mut files);
}

#[test]
fn grant_adoption_is_exact_and_does_not_retain_or_count_a_second_operation() {
    let (mut files, mut table, _) = promoted();
    assert!(files.acquire_file_io(FILE, SECOND).is_err());
    assert_eq!(files.io_grant_owner(FILE), Ok(Some(SECOND)));
    let mut ingress = table
        .begin_ingress(PI, SECOND, SECOND + 100, SSN)
        .unwrap()
        .unwrap();
    let mut adoption = table.begin_adoption(&mut ingress).unwrap();
    assert!(table.begin_adoption(&mut ingress).is_err());
    let result = files.adopt_io_grant(FILE, SECOND);
    assert_eq!(result, Ok(()));
    let owner = table
        .record_adoption(&mut adoption, result)
        .unwrap()
        .unwrap();
    assert_eq!(owner.waiter().route, waiter(SECOND).route);
    assert!(!owner.cancellation_requested());
    assert!(table.record_adoption(&mut adoption, Ok(())).is_err());
    assert!(files.adopt_io_grant(FILE, SECOND).is_err());
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(SECOND)));
    assert_eq!(files.io_grant_owner(FILE), Ok(None));
    assert_eq!(files.io_waiter_count(FILE), Ok(0));
    assert!(table.is_empty());
    files.release_io(FILE, SECOND).unwrap();
    assert!(!files.release_file(FILE).unwrap().close_required);
    close_empty_file(&mut files);
}

#[test]
fn a_cancelled_ingress_retires_independently_of_the_next_waiters_uncertain_retry() {
    use SynchronousFileCancelEffect as Effect;
    use SynchronousFileCancelReceipt as Receipt;
    let (mut files, mut table, _) = promoted();
    let third_slot = queue(&mut files, &mut table, THIRD);
    let mut ingress = table
        .begin_ingress(PI, SECOND, SECOND + 100, SSN)
        .unwrap()
        .unwrap();
    let identity = table.reject_ingress(&mut ingress, COPYIN_FAULT).unwrap();
    cancel_policy(&mut files, &mut table, identity);
    apply(&mut table, identity, Effect::Wake, |table| {
        assert_eq!(files.promote_io_waiter(FILE, THIRD), Ok(0));
        table
            .promote_exact(third_slot, FileIoWaitKey::Hosted(FILE), THIRD)
            .unwrap();
        let retry = table
            .retry_identity(third_slot, FileIoWaitKey::Hosted(FILE), THIRD)
            .unwrap();
        let mut attempt = table.begin_retry(retry).unwrap();
        table
            .record_retry(&mut attempt, SynchronousFileRetryOutcome::Indeterminate(13))
            .unwrap();
        // Wake transferred ownership to THIRD's own retry record. Its uncertain delivery is not
        // an uncertain SECOND cancellation and must not replay SECOND's committed policy.
        Receipt::Wake
    });
    apply(&mut table, identity, Effect::HostedReference, |_| {
        Receipt::HostedReference(files.release_file(FILE).unwrap())
    });
    table.finish_cancellation(identity).unwrap();
    assert_eq!(table.len(), 1);
    assert!(table
        .next_retry_for_file(FileIoWaitKey::Hosted(FILE))
        .is_none());
    assert_eq!(files.io_grant_owner(FILE), Ok(Some(THIRD)));
    assert_eq!(files.io_waiter_count(FILE), Ok(0));
    assert!(files.release_handle(FILE).unwrap().cleanup_required);
    assert_eq!(
        files.begin_cleanup(FILE),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(false));
    assert!(files.release_io(FILE, THIRD).is_err());
}

#[test]
fn close_followup_retries_use_the_reference_receipt_after_the_file_row_is_gone() {
    use SynchronousFileCancelEffect as Effect;
    use SynchronousFileCancelReceipt as Receipt;
    let (mut files, mut table, _) = promoted();
    assert!(files.release_handle(FILE).unwrap().cleanup_required);
    assert_eq!(
        files.begin_cleanup(FILE),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    let mut ingress = table
        .begin_ingress(PI, SECOND, SECOND + 100, SSN)
        .unwrap()
        .unwrap();
    let identity = table.reject_ingress(&mut ingress, COPYIN_FAULT).unwrap();
    cancel_policy(&mut files, &mut table, identity);
    apply(&mut table, identity, Effect::Wake, |_| {
        assert!(files.promote_cleanup_if_ready(FILE).unwrap());
        files.mark_cleanup_lifecycle_started(FILE).unwrap();
        files.release_cleanup_io(FILE).unwrap();
        assert!(
            !files
                .release_cleanup_reference(FILE)
                .unwrap()
                .close_required
        );
        Receipt::Wake
    });
    let Receipt::HostedReference(release) =
        apply(&mut table, identity, Effect::HostedReference, |_| {
            Receipt::HostedReference(files.release_file(FILE).unwrap())
        })
    else {
        unreachable!()
    };
    assert!(release.close_required);
    assert_eq!(release.device_id, DEVICE);
    // Synchronous Files cannot associate an IOCP; close is the real followup for this mode.
    assert_eq!(release.port_id, None);
    assert!(files.io_mode(FILE).is_err());
    let mut attempt = table.begin_cancellation(identity).unwrap();
    assert_eq!(attempt.effect(), Effect::ReferenceFollowup);
    assert_eq!(attempt.reference_release(), Some(release));
    table
        .record_cancellation(
            &mut attempt,
            SynchronousFileCancelOutcome::NotEntered(REFUSED),
        )
        .unwrap();
    assert!(table.finish_cancellation(identity).is_none());
    assert_eq!(
        table.cancellation(identity).unwrap().reference_release,
        Some(release)
    );
    apply(&mut table, identity, Effect::ReferenceFollowup, |table| {
        assert_eq!(
            table.cancellation(identity).unwrap().reference_release,
            Some(release)
        );
        // The provider CLOSE is acknowledged by this fixture; no deleted File lookup is used.
        Receipt::ReferenceFollowup
    });
    assert_eq!(table.finish_cancellation(identity).unwrap().reply_cap, 0);
    assert!(table.is_empty());
}
