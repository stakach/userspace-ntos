//! Hosted policy ownership composed with the actual FIFO and retained retry protocol.
//! Reply outcomes are supplied by the fixture; no native IPC is executed here.

use nt_io_completion::{FileCompletionTable, FileIoAcquireResult, FileIoMode};
use nt_io_manager::{
    SynchronousFileRetryIdentity, SynchronousFileRetryOutcome, SynchronousFileWaitTable,
    SynchronousFileWaiter,
};

const FILE: u64 = 10;
const DEVICE: u64 = 7;
const PI: u32 = 2;
const SERVICE: u32 = 191;

fn park(waiters: &mut SynchronousFileWaitTable, tid: u64) {
    let mut waiter = SynchronousFileWaiter::waiting(
        FILE,
        DEVICE,
        9,
        0x40,
        3,
        SERVICE,
        PI,
        tid,
        tid + 100,
        false,
        true,
        0,
        0x1002,
        0x2000,
        0x202,
    );
    waiter.reply_cap = tid + 200;
    waiter.reply_mrs = core::array::from_fn(|index| 0xa000 + index as u64);
    waiters.park(waiter).unwrap();
}

fn promote(
    files: &mut FileCompletionTable<2>,
    waiters: &mut SynchronousFileWaitTable,
    expected_tid: u64,
) -> SynchronousFileRetryIdentity {
    let (slot, waiter) = waiters.oldest_waiting_for_file(FILE).unwrap();
    assert_eq!(waiter.tid, expected_tid);
    files.promote_io_waiter(FILE, waiter.tid).unwrap();
    waiters.promote_exact(slot, FILE, waiter.tid).unwrap();
    waiters.retry_identity(slot, FILE, waiter.tid).unwrap()
}

fn acknowledge_and_adopt(
    files: &mut FileCompletionTable<2>,
    waiters: &mut SynchronousFileWaitTable,
    identity: SynchronousFileRetryIdentity,
    tid: u64,
) {
    let original = *waiters.retry_delivery(identity).unwrap().waiter;
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(tid)));
    assert!(files.release_io(FILE, tid).is_err());
    let mut attempt = waiters.begin_retry(identity).unwrap();
    waiters
        .record_retry(&mut attempt, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    assert!(!waiters.finish_retry(identity, Err(0xc000_0001)).unwrap());
    assert!(waiters.take_promoted(PI, tid, tid + 100, SERVICE).is_none());
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(tid)));
    assert!(waiters.finish_retry(identity, Ok(())).unwrap());
    assert!(waiters
        .take_promoted(PI, tid, tid + 100, SERVICE + 1)
        .is_none());
    let consumed = waiters.take_promoted(PI, tid, tid + 100, SERVICE).unwrap();
    assert_eq!(consumed.file_id, original.file_id);
    assert_eq!(consumed.reply_mrs, original.reply_mrs);
    assert_eq!(consumed.reply_cap, 0);
    // The promoted request already owns its File reference; no second retain occurs here.
    assert_eq!(files.begin_io(FILE, tid), Ok(FileIoAcquireResult::Acquired));
}

#[test]
fn fifo_grants_survive_retry_retirement_and_precede_last_handle_cleanup() {
    let mut files = FileCompletionTable::<2>::new();
    files
        .insert_file_with_mode(FILE, DEVICE, FileIoMode::SynchronousNonAlertable)
        .unwrap();
    let mut waiters = SynchronousFileWaitTable::new();
    files.retain_file(FILE).unwrap();
    assert_eq!(files.begin_io(FILE, 10), Ok(FileIoAcquireResult::Acquired));
    files.retain_file(FILE).unwrap();
    assert_eq!(
        files.begin_io(FILE, 20),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    park(&mut waiters, 20);
    assert_eq!(files.release_io(FILE, 10).unwrap().waiters, 1);
    assert!(!files.release_file(FILE).unwrap().close_required);

    // Even in the release/promotion interval a new arrival must join the existing FIFO.
    files.retain_file(FILE).unwrap();
    assert_eq!(
        files.begin_io(FILE, 30),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    park(&mut waiters, 30);
    assert!(files.release_handle(FILE).unwrap().cleanup_required);
    assert_eq!(
        files.begin_cleanup(FILE),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    assert!(files.begin_io(FILE, 40).is_err());
    assert_eq!(files.io_waiter_count(FILE), Ok(2));

    for tid in [20, 30] {
        assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(false));
        let identity = promote(&mut files, &mut waiters, tid);
        let mut rejected = waiters.begin_retry(identity).unwrap();
        waiters
            .record_retry(&mut rejected, SynchronousFileRetryOutcome::NotEntered(13))
            .unwrap();
        assert_eq!(files.io_lock_owner(FILE), Ok(Some(tid)));
        assert!(waiters.oldest_waiting_for_file(FILE).is_none());
        acknowledge_and_adopt(&mut files, &mut waiters, identity, tid);
        assert_eq!(
            files.release_io(FILE, tid).unwrap().waiters,
            u32::from(tid == 20)
        );
        assert!(!files.release_file(FILE).unwrap().close_required);
    }
    assert!(waiters.is_empty());
    assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(true));
    assert_eq!(files.mark_cleanup_lifecycle_started(FILE), Ok(true));
    assert!(files.release_cleanup_reference(FILE).is_err());
    assert_eq!(files.release_cleanup_io(FILE).unwrap().waiters, 0);
    assert!(
        files
            .release_cleanup_reference(FILE)
            .unwrap()
            .close_required
    );
    assert!(files.io_mode(FILE).is_err());
}

#[test]
fn uncertain_retry_keeps_busy_and_cleanup_blocked_without_blocking_another_file() {
    let mut files = FileCompletionTable::<2>::new();
    for file in [FILE, FILE + 1] {
        files
            .insert_file_with_mode(file, DEVICE, FileIoMode::SynchronousNonAlertable)
            .unwrap();
    }
    let mut waiters = SynchronousFileWaitTable::new();
    for tid in [10, 20, 30] {
        files.retain_file(FILE).unwrap();
        let acquired = files.begin_io(FILE, tid).unwrap();
        if tid == 10 {
            assert_eq!(acquired, FileIoAcquireResult::Acquired);
        } else {
            assert_eq!(
                acquired,
                FileIoAcquireResult::Contended { alertable: false }
            );
            park(&mut waiters, tid);
        }
    }
    files.release_io(FILE, 10).unwrap();
    files.release_file(FILE).unwrap();
    let identity = promote(&mut files, &mut waiters, 20);
    let mut attempt = waiters.begin_retry(identity).unwrap();
    waiters
        .record_retry(&mut attempt, SynchronousFileRetryOutcome::Indeterminate(13))
        .unwrap();
    assert!(files.release_handle(FILE).unwrap().cleanup_required);
    assert_eq!(
        files.begin_cleanup(FILE),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    assert_eq!(waiters.next_retry_for_file(FILE), None);
    assert!(waiters.oldest_waiting_for_file(FILE).is_none());
    assert!(waiters.take_promoted(PI, 20, 120, SERVICE).is_none());
    assert_eq!(
        waiters.take_thread_with(20, |_| panic!("uncertain reply is still owned")),
        0
    );
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(20)));
    assert_eq!(files.io_waiter_count(FILE), Ok(1));
    assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(false));
    assert!(files.release_io(FILE, 20).is_err());

    files.retain_file(FILE + 1).unwrap();
    assert_eq!(
        files.begin_io(FILE + 1, 40),
        Ok(FileIoAcquireResult::Acquired)
    );
    files.release_io(FILE + 1, 40).unwrap();
    files.release_file(FILE + 1).unwrap();
    assert!(files.release_handle(FILE + 1).unwrap().cleanup_required);
    assert_eq!(
        files.begin_cleanup(FILE + 1),
        Ok(FileIoAcquireResult::Acquired)
    );
    files.mark_cleanup_lifecycle_started(FILE + 1).unwrap();
    files.release_cleanup_io(FILE + 1).unwrap();
    assert!(
        files
            .release_cleanup_reference(FILE + 1)
            .unwrap()
            .close_required
    );
    // The first File deliberately remains retained; uncertain delivery is not cancellation.
    assert_eq!(waiters.retry_stats().indeterminate, 1);
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(20)));
}
