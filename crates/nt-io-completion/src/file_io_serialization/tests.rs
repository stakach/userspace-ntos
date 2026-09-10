use super::*;

const SYNC: FileIoMode = FileIoMode::SynchronousNonAlertable;
const ALERTABLE: FileIoMode = FileIoMode::SynchronousAlertable;
const ASYNC: FileIoMode = FileIoMode::Asynchronous;

#[test]
fn empty_state_and_async_bypass_are_independent_of_file_signaling() {
    let mut busy = FileIoSerialization::new();
    assert_eq!(busy, FileIoSerialization::default());
    assert_eq!(busy.io_lock_owner(), None);
    assert_eq!(busy.io_waiter_count(), 0);
    assert!(!busy.has_live_io());
    assert!(!busy.cleanup_waiting());
    assert!(!busy.is_cleanup_owner());
    for tid in [1, 2] {
        assert_eq!(
            busy.begin_io(ASYNC, tid, false),
            Ok(FileIoAcquireResult::Bypassed)
        );
    }
    assert_eq!(busy.begin_cleanup(ASYNC), Ok(FileIoAcquireResult::Bypassed));
    assert_eq!(busy, FileIoSerialization::new());
    assert_eq!(busy.begin_io(ASYNC, 1, true), Err(STATUS_INVALID_HANDLE));
    assert_eq!(busy, FileIoSerialization::new());
}

#[test]
fn invalid_ordinary_owners_never_mutate_idle_or_cleanup_state() {
    let mut busy = FileIoSerialization::new();
    for cleanup in [false, true] {
        if cleanup {
            busy.begin_cleanup(SYNC).unwrap();
        }
        for tid in [0, u64::MAX] {
            let before = busy;
            for mode in [ASYNC, SYNC, ALERTABLE] {
                assert_eq!(
                    busy.begin_io(mode, tid, false),
                    Err(STATUS_INVALID_PARAMETER)
                );
                assert_eq!(
                    busy.promote_io_waiter(mode, tid),
                    Err(STATUS_INVALID_PARAMETER)
                );
                assert_eq!(busy.release_io(mode, tid), Err(STATUS_INVALID_PARAMETER));
            }
            assert_eq!(busy.cancel_promoted_io(tid), Err(STATUS_INVALID_PARAMETER));
            assert_eq!(busy, before);
        }
    }
}

#[test]
fn same_thread_reentry_contends_but_promoted_grant_is_consumed_once() {
    let mut busy = FileIoSerialization::new();
    assert_eq!(
        busy.begin_io(ALERTABLE, 1, false),
        Ok(FileIoAcquireResult::Acquired)
    );
    assert_eq!(
        busy.begin_io(ALERTABLE, 1, false),
        Ok(FileIoAcquireResult::Contended { alertable: true })
    );
    assert_eq!(busy.cancel_io_waiter(), Ok(0));
    busy.begin_io(ALERTABLE, 2, false).unwrap();
    assert_eq!(
        busy.release_io(ALERTABLE, 1),
        Ok(FileIoRelease { waiters: 1 })
    );
    assert_eq!(busy.promote_io_waiter(ALERTABLE, 2), Ok(0));
    assert_eq!(busy.io_lock_owner(), Some(2));
    assert_eq!(busy.release_io(ALERTABLE, 2), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(
        busy.begin_io(ALERTABLE, 2, false),
        Ok(FileIoAcquireResult::Acquired)
    );
    assert_eq!(
        busy.begin_io(ALERTABLE, 2, false),
        Ok(FileIoAcquireResult::Contended { alertable: true })
    );
    assert_eq!(busy.cancel_promoted_io(2), Err(STATUS_INVALID_PARAMETER));
    busy.cancel_io_waiter().unwrap();
    busy.release_io(ALERTABLE, 2).unwrap();
    assert_eq!(busy.release_io(ALERTABLE, 2), Err(STATUS_INVALID_PARAMETER));
    assert!(!busy.has_live_io());
}

#[test]
fn new_arrival_cannot_barge_between_release_and_fifo_promotion() {
    let mut busy = FileIoSerialization::new();
    busy.begin_io(SYNC, 1, false).unwrap();
    busy.begin_io(SYNC, 2, false).unwrap();
    busy.release_io(SYNC, 1).unwrap();
    assert_eq!(busy.io_lock_owner(), None);
    assert_eq!(
        busy.begin_io(SYNC, 3, false),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    assert_eq!(busy.io_lock_owner(), None);
    assert_eq!(busy.io_waiter_count(), 2);
    assert_eq!(busy.promote_io_waiter(SYNC, 2), Ok(1));
    busy.begin_io(SYNC, 2, false).unwrap();
    busy.release_io(SYNC, 2).unwrap();
    assert_eq!(busy.promote_io_waiter(SYNC, 3), Ok(0));
    busy.begin_io(SYNC, 3, false).unwrap();
    busy.release_io(SYNC, 3).unwrap();
    assert!(!busy.has_live_io());
}

#[test]
fn waiter_overflow_and_wrong_transition_leave_the_original_state_intact() {
    let mut busy = FileIoSerialization {
        owner_tid: 1,
        waiters: u32::MAX,
        ..FileIoSerialization::new()
    };
    let before = busy;
    assert_eq!(
        busy.begin_io(SYNC, 2, false),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(busy.release_io(SYNC, 2), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(
        busy.promote_io_waiter(SYNC, 2),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(busy.release_cleanup_io(), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(busy.cancel_promoted_io(1), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(busy, before);
    busy.owner_tid = 0;
    let released = busy;
    assert_eq!(
        busy.begin_io(SYNC, 2, false),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(busy, released);
}

#[test]
fn cleanup_follows_every_preexisting_waiter_and_allows_only_the_exact_grant() {
    let mut busy = FileIoSerialization::new();
    busy.begin_io(SYNC, 1, false).unwrap();
    busy.begin_io(SYNC, 2, false).unwrap();
    assert_eq!(
        busy.begin_cleanup(SYNC),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    assert!(busy.cleanup_waiting());
    assert_eq!(busy.begin_cleanup(SYNC), Err(STATUS_INVALID_PARAMETER));
    let before = busy;
    assert_eq!(busy.begin_io(SYNC, 3, true), Err(STATUS_INVALID_HANDLE));
    assert_eq!(
        busy.promote_cleanup_if_ready(SYNC, false),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        busy.promote_cleanup_if_ready(ASYNC, true),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(busy, before);
    busy.release_io(SYNC, 1).unwrap();
    assert_eq!(busy.promote_cleanup_if_ready(SYNC, true), Ok(false));
    busy.promote_io_waiter(SYNC, 2).unwrap();
    assert_eq!(busy.begin_io(SYNC, 3, true), Err(STATUS_INVALID_HANDLE));
    assert_eq!(
        busy.begin_io(SYNC, 2, true),
        Ok(FileIoAcquireResult::Acquired)
    );
    assert_eq!(busy.begin_io(SYNC, 2, true), Err(STATUS_INVALID_HANDLE));
    busy.release_io(SYNC, 2).unwrap();
    assert_eq!(busy.promote_cleanup_if_ready(SYNC, true), Ok(true));
    assert!(busy.is_cleanup_owner());
    assert_eq!(busy.io_lock_owner(), Some(u64::MAX));
    assert!(!busy.cleanup_waiting());
    assert_eq!(busy.promote_cleanup_if_ready(SYNC, true), Ok(false));
    assert_eq!(busy.release_cleanup_io(), Ok(FileIoRelease { waiters: 0 }));
    assert_eq!(busy.release_cleanup_io(), Err(STATUS_INVALID_PARAMETER));
    assert!(!busy.has_live_io());
}

#[test]
fn cancelling_an_unconsumed_grant_keeps_cleanup_and_other_waiters_owned() {
    let mut busy = FileIoSerialization::new();
    busy.begin_io(SYNC, 1, false).unwrap();
    busy.begin_io(SYNC, 2, false).unwrap();
    busy.begin_io(SYNC, 3, false).unwrap();
    busy.begin_cleanup(SYNC).unwrap();
    busy.release_io(SYNC, 1).unwrap();
    busy.promote_io_waiter(SYNC, 2).unwrap();
    let before = busy;
    assert_eq!(busy.cancel_promoted_io(3), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(busy, before);
    assert_eq!(busy.cancel_promoted_io(2), Ok(FileIoRelease { waiters: 1 }));
    assert_eq!(busy.cancel_promoted_io(2), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(busy.promote_cleanup_if_ready(SYNC, true), Ok(false));
    assert_eq!(busy.cancel_io_waiter(), Ok(0));
    assert_eq!(busy.cancel_io_waiter(), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(busy.promote_cleanup_if_ready(SYNC, true), Ok(true));
}

#[test]
fn hosted_adapter_preserves_reference_checks_signal_state_and_error_ordering() {
    let mut files = crate::FileCompletionTable::<1>::new();
    assert_eq!(files.begin_io(1, 0), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(files.begin_io(1, 2), Err(STATUS_INVALID_HANDLE));
    assert_eq!(files.release_io(1, 0), Err(STATUS_INVALID_HANDLE));
    files.insert_file_with_mode(1, 2, SYNC).unwrap();
    assert_eq!(files.begin_cleanup(1), Err(STATUS_INVALID_PARAMETER));
    for signaled in [false, true] {
        files.set_signaled(1, signaled).unwrap();
        files.begin_io(1, 10).unwrap();
        assert_eq!(files.is_signaled(1), Ok(signaled));
        files.release_io(1, 10).unwrap();
        assert_eq!(files.is_signaled(1), Ok(signaled));
    }
    assert!(files.release_handle(1).unwrap().cleanup_required);
    files.begin_cleanup(1).unwrap();
    assert_eq!(
        files.release_cleanup_reference(1),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(files.io_lock_owner(1), Ok(Some(u64::MAX)));
    files.mark_cleanup_lifecycle_started(1).unwrap();
    files.release_cleanup_io(1).unwrap();
    assert!(files.release_cleanup_reference(1).unwrap().close_required);
}

#[test]
fn hosted_adapter_rejects_idle_owner_holes_and_preserves_waiter_priority() {
    let mut files = crate::FileCompletionTable::<1>::new();
    files.insert_file_with_mode(1, 2, SYNC).unwrap();
    for tid in [0, u64::MAX] {
        assert_eq!(files.begin_io(1, tid), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(files.release_io(1, tid), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(
            files.cancel_promoted_io(1, tid),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            files.promote_io_waiter(1, tid),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(files.io_lock_owner(1), Ok(None));
        assert_eq!(files.io_waiter_count(1), Ok(0));
    }
    files.begin_io(1, 10).unwrap();
    files.begin_io(1, 20).unwrap();
    files.release_io(1, 10).unwrap();
    assert_eq!(
        files.begin_io(1, 30),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    assert_eq!(files.io_lock_owner(1), Ok(None));
    assert_eq!(files.promote_io_waiter(1, 20), Ok(1));
    files.begin_io(1, 20).unwrap();
    files.release_io(1, 20).unwrap();
    files.promote_io_waiter(1, 30).unwrap();
    files.begin_io(1, 30).unwrap();
    files.release_io(1, 30).unwrap();
}
