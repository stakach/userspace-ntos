use super::*;
use crate::{FileCompletionBinding, FileIoAcquireResult, STATUS_INSUFFICIENT_RESOURCES};
use core::cell::Cell;

const ALERT: FileIoMode = FileIoMode::SynchronousAlertable;
const NONALERT: FileIoMode = FileIoMode::SynchronousNonAlertable;
const ASYNC: FileIoMode = FileIoMode::Asynchronous;

fn owned(mode: FileIoMode) -> FileCompletionTable<1> {
    let mut files = FileCompletionTable::new();
    files.insert_file_with_mode(10, 77, mode).unwrap();
    assert_eq!(
        files.acquire_file_io(10, 1),
        Ok(if mode.is_synchronous() {
            FileIoAcquireResult::Acquired
        } else {
            FileIoAcquireResult::Bypassed
        })
    );
    files
}

#[test]
fn alertability_updates_change_only_mode_with_no_spare_table_capacity() {
    for (before_mode, next_mode) in [(ALERT, NONALERT), (NONALERT, ALERT)] {
        let mut files = owned(before_mode);
        assert_eq!(
            files.acquire_file_io(10, 2),
            Ok(FileIoAcquireResult::Contended {
                alertable: before_mode.is_alertable(),
            })
        );
        let entry = files.entry_mut(10).unwrap();
        entry.signaled = false;
        entry.notification_modes = crate::FILE_SKIP_SET_EVENT_ON_HANDLE;
        let mut expected = *entry;
        let calls = Cell::new(0);
        let canonical = Cell::new(before_mode);
        assert_eq!(
            files.update_io_mode_with(10, 77, 1, before_mode, next_mode, || {
                calls.set(calls.get() + 1);
                canonical.set(next_mode);
                Ok(())
            }),
            Ok(())
        );
        expected.io_mode = next_mode;
        assert_eq!(files.entries, [expected]);
        assert_eq!(canonical.get(), next_mode);
        assert_eq!(calls.get(), 1);
    }
}

#[test]
fn mode_preflight_refuses_identity_owner_and_synchronicity_before_body_effects() {
    for (file, device, tid, expected_mode, next, status) in [
        (0, 77, 1, ALERT, NONALERT, STATUS_INVALID_HANDLE),
        (11, 77, 1, ALERT, NONALERT, STATUS_INVALID_HANDLE),
        (10, 0, 1, ALERT, NONALERT, STATUS_INVALID_HANDLE),
        (10, 78, 1, ALERT, NONALERT, STATUS_INVALID_HANDLE),
        (10, 77, 0, ALERT, NONALERT, STATUS_INVALID_PARAMETER),
        (10, 77, u64::MAX, ALERT, NONALERT, STATUS_INVALID_PARAMETER),
        (10, 77, 2, ALERT, NONALERT, STATUS_INVALID_PARAMETER),
        (10, 77, 1, NONALERT, NONALERT, STATUS_INVALID_PARAMETER),
        (10, 77, 1, ALERT, ASYNC, STATUS_INVALID_PARAMETER),
    ] {
        let mut files = owned(ALERT);
        let before = files.entries;
        assert_eq!(
            files.update_io_mode_with(file, device, tid, expected_mode, next, || {
                panic!("refused mode update must not invoke canonical mutation")
            }),
            Err(status)
        );
        assert_eq!(files.entries, before);
    }
}

#[test]
fn unacquired_and_promoted_busy_are_not_mode_update_owners() {
    let mut files = FileCompletionTable::<1>::new();
    files
        .reserve_file_handle_publication_with_mode(10, 77, ALERT)
        .unwrap();
    let reserved = files.entries;
    assert_eq!(
        files.update_io_mode_with(10, 77, 1, ALERT, NONALERT, || panic!("reserved File")),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(files.entries, reserved);
    files.commit_reserved_file_handle(10).unwrap();
    let idle = files.entries;
    assert_eq!(
        files.update_io_mode_with(10, 77, 1, ALERT, NONALERT, || panic!("unacquired Busy")),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(files.entries, idle);
    files.acquire_file_io(10, 1).unwrap();
    files.acquire_file_io(10, 2).unwrap();
    files.release_io(10, 1).unwrap();
    files.promote_io_waiter(10, 2).unwrap();
    let promoted = files.entries;
    assert_eq!(
        files.update_io_mode_with(10, 77, 2, ALERT, NONALERT, || panic!("unadopted grant")),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(files.entries, promoted);
    files.adopt_io_grant(10, 2).unwrap();
    assert_eq!(
        files.update_io_mode_with(10, 77, 2, ALERT, NONALERT, || Ok(())),
        Ok(())
    );
}

#[test]
fn failed_canonical_update_keeps_complete_policy_state_unchanged() {
    let mut files = owned(ALERT);
    files.acquire_file_io(10, 2).unwrap();
    let before = files.entries;
    let calls = Cell::new(0);
    assert_eq!(
        files.update_io_mode_with(10, 77, 1, ALERT, NONALERT, || {
            calls.set(calls.get() + 1);
            Err(STATUS_INSUFFICIENT_RESOURCES)
        }),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(files.entries, before);
}

#[test]
fn captured_wait_policy_survives_mode_change_while_new_admissions_use_live_mode() {
    for (old, next) in [(ALERT, NONALERT), (NONALERT, ALERT)] {
        let mut files = owned(old);
        let captured = files.io_mode(10).unwrap();
        assert_eq!(
            files.acquire_file_io_with_mode(10, 2, captured),
            Ok(FileIoAcquireResult::Contended {
                alertable: captured.is_alertable(),
            })
        );
        files
            .update_io_mode_with(10, 77, 1, old, next, || Ok(()))
            .unwrap();
        assert_eq!(
            files.acquire_file_io_with_mode(10, 3, captured),
            Ok(FileIoAcquireResult::Contended {
                alertable: old.is_alertable(),
            })
        );
        assert_eq!(
            files.acquire_file_io(10, 4),
            Ok(FileIoAcquireResult::Contended {
                alertable: next.is_alertable(),
            })
        );
        assert_eq!(captured.is_alertable(), old.is_alertable());
        assert_eq!(files.io_waiter_count(10), Ok(3));
        assert_eq!(files.release_io(10, 1).unwrap().waiters, 3);
        files.promote_io_waiter(10, 2).unwrap();
        files.adopt_io_grant(10, 2).unwrap();
        assert_eq!(files.release_io(10, 2).unwrap().waiters, 2);
    }
}

#[test]
fn retained_mode_update_preserves_last_handle_cleanup_ownership() {
    let mut files = owned(ALERT);
    assert!(files.release_handle(10).unwrap().cleanup_required);
    assert_eq!(
        files.begin_cleanup(10),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    let mut expected = files.entries;
    files
        .update_io_mode_with(10, 77, 1, ALERT, NONALERT, || Ok(()))
        .unwrap();
    expected[0].io_mode = NONALERT;
    assert_eq!(files.entries, expected);
    files.release_io(10, 1).unwrap();
    files.release_file(10).unwrap();
    assert_eq!(files.promote_cleanup_if_ready(10), Ok(true));
    files.mark_cleanup_lifecycle_started(10).unwrap();
    files.release_cleanup_io(10).unwrap();
    files.release_cleanup_reference(10).unwrap();
    assert_eq!(files.io_mode(10), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn asynchronous_mode_updates_need_no_busy_but_cannot_change_synchronicity() {
    let mut files = owned(ASYNC);
    files
        .associate(
            10,
            FileCompletionBinding {
                port_id: 4,
                key_context: 9,
            },
        )
        .unwrap();
    let before = files.entries;
    files
        .update_io_mode_with(10, 77, 1, ASYNC, ASYNC, || Ok(()))
        .unwrap();
    assert_eq!(files.entries, before);
    for next in [ALERT, NONALERT] {
        assert_eq!(
            files.update_io_mode_with(10, 77, 1, ASYNC, next, || panic!("asynchronous conversion")),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(files.entries, before);
    }
    assert!(files.release_handle(10).unwrap().cleanup_required);
    files.begin_cleanup(10).unwrap();
    let retained = files.entries;
    files
        .update_io_mode_with(10, 77, 1, ASYNC, ASYNC, || Ok(()))
        .unwrap();
    assert_eq!(files.entries, retained);
}

#[test]
fn captured_admission_mismatch_or_exhaustion_leaves_references_and_busy_unchanged() {
    for (live, captured) in [
        (ASYNC, ALERT),
        (ASYNC, NONALERT),
        (ALERT, ASYNC),
        (NONALERT, ASYNC),
    ] {
        let mut files = owned(live);
        let before = files.entries;
        assert_eq!(
            files.acquire_file_io_with_mode(10, 2, captured),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(files.entries, before);
    }
    let mut files = owned(ALERT);
    files.entry_mut(10).unwrap().references = u32::MAX;
    let before = files.entries;
    assert_eq!(
        files.acquire_file_io_with_mode(10, 2, NONALERT),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(files.entries, before);
}
