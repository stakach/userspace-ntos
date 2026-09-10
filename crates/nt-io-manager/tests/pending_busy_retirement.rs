//! Real File Busy/reference policy composed with retained terminal delivery and FIFO ownership.
//! The fixture supplies release, wake, reply, and ACK outcomes; this is not native IPC proof.

use nt_io_completion::{FileCompletionTable, FileIoAcquireResult, FileIoMode};
use nt_io_manager::*;

const FILE: u64 = 10;
const DEVICE: u64 = 7;
const IRP: u64 = 91;
const FIRST: u64 = 20;
const SECOND: u64 = 21;
const PI: u32 = 2;
const SERVICE: u32 = 191;
const MODE: FileIoMode = FileIoMode::SynchronousNonAlertable;
const REFUSED: u32 = 0xc000_0001;

fn fixture() -> (FileCompletionTable<1>, PendingFileIoTable, usize) {
    let mut files = FileCompletionTable::new();
    files.insert_file_with_mode(FILE, DEVICE, MODE).unwrap();
    files.retain_file(FILE).unwrap();
    assert_eq!(
        files.begin_io(FILE, FIRST),
        Ok(FileIoAcquireResult::Acquired)
    );
    files.set_signaled(FILE, false).unwrap();
    let mut pending = PendingFileIoTable::new();
    let slot = pending
        .park(PendingFileIo {
            file_id: FILE,
            irp_id: IRP,
            major: 3,
            pi: PI,
            tid: FIRST,
            busy: Some(PendingFileBusy::new(FileIoBusyOwner {
                key: FileIoWaitKey::Hosted(FILE),
                tid: FIRST,
                mode: MODE,
            })),
            iosb_va: 0x1000,
            signal_file: true,
            event_obj_idx: u64::MAX,
            reply_cap: 47,
            reply_required: true,
            ..PendingFileIo::default()
        })
        .unwrap();
    (files, pending, slot)
}

fn terminal_surfaces(
    files: &mut FileCompletionTable<1>,
    pending: &mut PendingFileIoTable,
    slot: usize,
) {
    pending
        .mark_delivery_exact(slot, IRP, IO_DELIVERY_IOSB_PUBLISHED)
        .unwrap();
    files.set_signaled(FILE, true).unwrap();
    pending
        .mark_delivery_exact(slot, IRP, IO_DELIVERY_FILE_PUBLISHED)
        .unwrap();
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(FIRST)));
}

fn queue_second(files: &mut FileCompletionTable<1>) -> SynchronousFileWaitTable {
    files.retain_file(FILE).unwrap();
    assert_eq!(
        files.begin_io(FILE, SECOND),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    let mut waiters = SynchronousFileWaitTable::new();
    let mut waiter = SynchronousFileWaiter::waiting(
        FileIoWaitRoute::Hosted {
            file_id: FILE,
            device_id: DEVICE,
            fs_context: 9,
        },
        0x40,
        3,
        SERVICE,
        PI,
        SECOND,
        SECOND + 100,
        MODE,
        true,
        0,
        0x1002,
        0x2000,
        0x202,
    );
    waiter.reply_cap = SECOND + 200;
    waiters.park(waiter).unwrap();
    waiters
}

fn close_last_handle(files: &mut FileCompletionTable<1>) {
    assert!(files.release_handle(FILE).unwrap().cleanup_required);
    assert_eq!(
        files.begin_cleanup(FILE),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(false));
}

fn cleanup_retains_delivery_reference(files: &mut FileCompletionTable<1>) {
    assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(true));
    assert_eq!(files.mark_cleanup_lifecycle_started(FILE), Ok(true));
    assert!(files.release_cleanup_reference(FILE).is_err());
    files.release_cleanup_io(FILE).unwrap();
    assert!(
        !files
            .release_cleanup_reference(FILE)
            .unwrap()
            .close_required
    );
    assert_eq!(files.io_mode(FILE), Ok(MODE));
}

fn reply_with_refusal(pending: &mut PendingFileIoTable, slot: usize) {
    let cap = pending.claim_reply_cap_exact(slot, IRP).unwrap().unwrap();
    // The send explicitly did not enter. Restore only that exact claimed capability.
    pending.restore_reply_cap_exact(slot, IRP, cap).unwrap();
    assert!(pending.finish_exact(slot, IRP).is_none());
    assert_eq!(pending.claim_reply_cap_exact(slot, IRP), Some(Some(cap)));
    pending.mark_reply_published_exact(slot, IRP).unwrap();
}

fn record_backend_ack(
    pending: &mut PendingFileIoTable,
    slot: usize,
    result: Result<(), u32>,
) -> bool {
    result.is_ok() && pending.mark_backend_acked_exact(slot, IRP).is_some()
}

#[test]
fn refused_release_keeps_busy_and_reference_until_one_checked_release_commits() {
    let (mut files, mut pending, slot) = fixture();
    terminal_surfaces(&mut files, &mut pending, slot);
    close_last_handle(&mut files);
    let mut attempt = pending.begin_busy_release_exact(slot, IRP).unwrap();
    assert!(pending.begin_busy_release_exact(slot, IRP).is_err());
    // A real wrong-owner refusal is side-effect-free, so a fresh exact attempt is permitted.
    let refused = files
        .release_io(FILE, SECOND)
        .map(|release| release.waiters);
    assert!(refused.is_err());
    pending.record_busy_release(&mut attempt, refused).unwrap();
    assert!(pending.get(slot).unwrap().busy.unwrap().release_pending());
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(FIRST)));
    assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(false));
    assert!(pending.claim_reply_cap_exact(slot, IRP).is_none());
    assert!(pending.mark_backend_acked_exact(slot, IRP).is_none());
    assert!(pending.finish_exact(slot, IRP).is_none());

    let mut attempt = pending.begin_busy_release_exact(slot, IRP).unwrap();
    let released = files.release_io(FILE, FIRST).map(|release| release.waiters);
    pending.record_busy_release(&mut attempt, released).unwrap();
    assert!(pending.record_busy_release(&mut attempt, Ok(0)).is_err());
    assert!(pending.begin_busy_release_exact(slot, IRP).is_err());
    assert_eq!(files.io_lock_owner(FILE), Ok(None));
    let mut wake = pending.begin_busy_wake_exact(slot, IRP).unwrap();
    pending.record_busy_wake(&mut wake, Ok(())).unwrap();
    cleanup_retains_delivery_reference(&mut files);
    reply_with_refusal(&mut pending, slot);
    assert!(pending.completion_surfaces_settled_exact(slot, IRP));
    // The first backend ACK was refused; without recording acceptance the owner stays live.
    assert!(!record_backend_ack(&mut pending, slot, Err(REFUSED)));
    assert!(pending.finish_exact(slot, IRP).is_none());
    assert!(pending.begin_busy_release_exact(slot, IRP).is_err());
    assert!(record_backend_ack(&mut pending, slot, Ok(())));
    assert_eq!(pending.finish_exact(slot, IRP).unwrap().file_id, FILE);
    assert!(files.release_file(FILE).unwrap().close_required);
    assert!(files.io_mode(FILE).is_err());
}

#[test]
fn wake_retry_preserves_fifo_grant_without_releasing_busy_twice() {
    let (mut files, mut pending, slot) = fixture();
    let mut waiters = queue_second(&mut files);
    terminal_surfaces(&mut files, &mut pending, slot);
    close_last_handle(&mut files);
    let mut release = pending.begin_busy_release_exact(slot, IRP).unwrap();
    let result = files
        .release_io(FILE, FIRST)
        .map(|released| released.waiters);
    assert_eq!(result, Ok(1));
    pending.record_busy_release(&mut release, result).unwrap();

    let mut wake = pending.begin_busy_wake_exact(slot, IRP).unwrap();
    assert!(pending.begin_busy_wake_exact(slot, IRP).is_err());
    let (wait_slot, waiter) = waiters
        .oldest_waiting_for_file(FileIoWaitKey::Hosted(FILE))
        .unwrap();
    assert_eq!(waiter.tid, SECOND);
    files.promote_io_waiter(FILE, SECOND).unwrap();
    waiters
        .promote_exact(wait_slot, FileIoWaitKey::Hosted(FILE), SECOND)
        .unwrap();
    let identity = waiters
        .retry_identity(wait_slot, FileIoWaitKey::Hosted(FILE), SECOND)
        .unwrap();
    let mut retry = waiters.begin_retry(identity).unwrap();
    waiters
        .record_retry(&mut retry, SynchronousFileRetryOutcome::NotEntered(13))
        .unwrap();
    pending.record_busy_wake(&mut wake, Err(REFUSED)).unwrap();
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(SECOND)));
    assert_eq!(files.io_waiter_count(FILE), Ok(0));
    assert!(pending.begin_busy_release_exact(slot, IRP).is_err());
    assert!(pending.claim_reply_cap_exact(slot, IRP).is_none());
    assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(false));

    let mut wake = pending.begin_busy_wake_exact(slot, IRP).unwrap();
    assert!(waiters
        .oldest_waiting_for_file(FileIoWaitKey::Hosted(FILE))
        .is_none());
    let mut retry = waiters.begin_retry(identity).unwrap();
    waiters
        .record_retry(&mut retry, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    assert!(waiters.finish_retry(identity, Ok(())).unwrap());
    waiters
        .take_promoted(PI, SECOND, SECOND + 100, SERVICE)
        .unwrap();
    assert_eq!(
        files.begin_io(FILE, SECOND),
        Ok(FileIoAcquireResult::Acquired)
    );
    pending.record_busy_wake(&mut wake, Ok(())).unwrap();
    assert!(pending.get(slot).unwrap().busy.unwrap().is_settled());
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(SECOND)));
    // FIRST's settled record cannot unlock the newly adopted SECOND operation.
    assert!(pending.begin_busy_release_exact(slot, IRP).is_err());
    reply_with_refusal(&mut pending, slot);
    pending.mark_backend_acked_exact(slot, IRP).unwrap();
    pending.finish_exact(slot, IRP).unwrap();
    assert!(!files.release_file(FILE).unwrap().close_required);
    assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(false));
    files.release_io(FILE, SECOND).unwrap();
    assert!(!files.release_file(FILE).unwrap().close_required);
    assert!(files.promote_cleanup_if_ready(FILE).unwrap());
    files.mark_cleanup_lifecycle_started(FILE).unwrap();
    files.release_cleanup_io(FILE).unwrap();
    assert!(
        files
            .release_cleanup_reference(FILE)
            .unwrap()
            .close_required
    );
    assert!(waiters.is_empty());
}

#[test]
fn newer_busy_owner_takes_wake_responsibility_from_an_older_completion() {
    const THIRD: u64 = SECOND + 1;
    let (mut files, mut pending, slot) = fixture();
    terminal_surfaces(&mut files, &mut pending, slot);
    let mut release = pending.begin_busy_release_exact(slot, IRP).unwrap();
    let result = files
        .release_io(FILE, FIRST)
        .map(|released| released.waiters);
    assert_eq!(result, Ok(0));
    pending.record_busy_release(&mut release, result).unwrap();

    files.retain_file(FILE).unwrap();
    assert_eq!(
        files.begin_io(FILE, SECOND),
        Ok(FileIoAcquireResult::Acquired)
    );
    files.set_signaled(FILE, false).unwrap();
    files.retain_file(FILE).unwrap();
    assert_eq!(
        files.begin_io(FILE, THIRD),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    let mut waiters = SynchronousFileWaitTable::new();
    let mut waiter = SynchronousFileWaiter::waiting(
        FileIoWaitRoute::Hosted {
            file_id: FILE,
            device_id: DEVICE,
            fs_context: 9,
        },
        0x40,
        3,
        SERVICE,
        PI,
        THIRD,
        THIRD + 100,
        MODE,
        true,
        0,
        0x1002,
        0x2000,
        0x202,
    );
    waiter.reply_cap = THIRD + 200;
    waiters.park(waiter).unwrap();

    let mut wake = pending.begin_busy_wake_exact(slot, IRP).unwrap();
    assert_eq!(wake.waiters(), 0);
    // This fixture makes the wake decision from current policy, not FIRST's stale waiter count.
    // An adopted owner without an outstanding grant owns the next release/promotion pass.
    let owner = files.io_lock_owner(FILE).unwrap();
    let grant = files.io_grant_owner(FILE).unwrap();
    assert_eq!(owner, Some(SECOND));
    assert_eq!(grant, None);
    let superseded = owner.is_some() && grant.is_none();
    assert!(superseded);
    if superseded {
        pending.record_busy_wake(&mut wake, Ok(())).unwrap();
    }
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(SECOND)));
    assert_eq!(files.io_waiter_count(FILE), Ok(1));
    assert_eq!(files.is_signaled(FILE), Ok(false));
    assert_eq!(
        waiters
            .oldest_waiting_for_file(FileIoWaitKey::Hosted(FILE))
            .unwrap()
            .1
            .tid,
        THIRD
    );
    assert!(pending.begin_busy_release_exact(slot, IRP).is_err());
    reply_with_refusal(&mut pending, slot);
    assert!(record_backend_ack(&mut pending, slot, Ok(())));
    pending.finish_exact(slot, IRP).unwrap();
    assert!(!files.release_file(FILE).unwrap().close_required);
    assert!(pending.is_empty());
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(SECOND)));

    close_last_handle(&mut files);
    assert_eq!(files.release_io(FILE, SECOND).unwrap().waiters, 1);
    assert!(!files.release_file(FILE).unwrap().close_required);
    let (wait_slot, waiter) = waiters
        .oldest_waiting_for_file(FileIoWaitKey::Hosted(FILE))
        .unwrap();
    assert_eq!(waiter.tid, THIRD);
    files.promote_io_waiter(FILE, THIRD).unwrap();
    waiters
        .promote_exact(wait_slot, FileIoWaitKey::Hosted(FILE), THIRD)
        .unwrap();
    let identity = waiters
        .retry_identity(wait_slot, FileIoWaitKey::Hosted(FILE), THIRD)
        .unwrap();
    let mut retry = waiters.begin_retry(identity).unwrap();
    waiters
        .record_retry(&mut retry, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    assert!(waiters.finish_retry(identity, Ok(())).unwrap());
    waiters
        .take_promoted(PI, THIRD, THIRD + 100, SERVICE)
        .unwrap();
    assert_eq!(
        files.begin_io(FILE, THIRD),
        Ok(FileIoAcquireResult::Acquired)
    );
    assert_eq!(files.release_io(FILE, THIRD).unwrap().waiters, 0);
    assert!(!files.release_file(FILE).unwrap().close_required);
    assert!(files.promote_cleanup_if_ready(FILE).unwrap());
    files.mark_cleanup_lifecycle_started(FILE).unwrap();
    files.release_cleanup_io(FILE).unwrap();
    assert!(
        files
            .release_cleanup_reference(FILE)
            .unwrap()
            .close_required
    );
    assert!(waiters.is_empty());
}

#[test]
fn abandonment_during_entered_wake_cannot_retire_or_replay_its_owner() {
    let (mut files, mut pending, slot) = fixture();
    terminal_surfaces(&mut files, &mut pending, slot);
    close_last_handle(&mut files);
    let mut release = pending.begin_busy_release_exact(slot, IRP).unwrap();
    let result = files
        .release_io(FILE, FIRST)
        .map(|released| released.waiters);
    pending.record_busy_release(&mut release, result).unwrap();
    let wake = pending.begin_busy_wake_exact(slot, IRP).unwrap();
    let mut abandoned = Vec::new();
    assert_eq!(
        pending.abandon_thread_transfers_with(FIRST, |owner| abandoned.push(owner)),
        1
    );
    assert_eq!(abandoned[0].reply_cap, 47);
    assert!(pending.get(slot).unwrap().consumer_abandoned);
    // Losing an entered ticket says nothing about its effects. Never infer permission to retry.
    drop(wake);
    assert!(pending.begin_busy_wake_exact(slot, IRP).is_err());
    assert!(pending.begin_busy_release_exact(slot, IRP).is_err());
    assert_eq!(
        pending.take_thread_with(FIRST, |_| panic!("Busy owner must stay retained")),
        0
    );
    assert!(!pending.completion_surfaces_settled_exact(slot, IRP));
    assert!(pending.mark_backend_acked_exact(slot, IRP).is_none());
    assert!(pending.finish_exact(slot, IRP).is_none());
    cleanup_retains_delivery_reference(&mut files);
    assert_eq!(files.io_mode(FILE), Ok(MODE));
}

#[test]
fn abandoned_release_ticket_keeps_final_handle_cleanup_behind_the_live_operation() {
    let (mut files, mut pending, slot) = fixture();
    terminal_surfaces(&mut files, &mut pending, slot);
    close_last_handle(&mut files);
    let release = pending.begin_busy_release_exact(slot, IRP).unwrap();
    drop(release);
    assert_eq!(pending.abandon_thread_transfers_with(FIRST, |_| {}), 1);
    assert!(pending.begin_busy_release_exact(slot, IRP).is_err());
    assert!(pending.begin_busy_wake_exact(slot, IRP).is_err());
    assert!(pending.finish_exact(slot, IRP).is_none());
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(FIRST)));
    assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(false));
    assert!(files.release_cleanup_reference(FILE).is_err());
    assert_eq!(files.io_mode(FILE), Ok(MODE));
}
