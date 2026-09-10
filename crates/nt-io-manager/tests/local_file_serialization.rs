//! Shared Busy transitions composed with real local file references and mutations. The fixture
//! drives admission/promotion explicitly; native local serialization is not claimed here.

use nt_fs::*;
use nt_io_completion::{FileIoAcquireResult, FileIoMode, FileIoSerialization};

const MODE: FileIoMode = FileIoMode::SynchronousNonAlertable;
const FIRST: u64 = 121;
const SECOND: u64 = 122;
const THIRD: u64 = 123;

fn file() -> (FileSystem, u64) {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(r"\??\C:\serialized", b"abcdef"));
    let opened = fs.zw_create_file(
        r"\??\C:\serialized",
        FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    );
    assert_eq!(opened.status, STATUS_SUCCESS);
    (fs, opened.handle)
}

fn position_effect(
    fs: &mut FileSystem,
    handle: u64,
    busy: &FileIoSerialization,
    tid: u64,
    position: u64,
    effects: &mut Vec<u64>,
) {
    assert_eq!(busy.io_lock_owner(), Some(tid));
    assert_eq!(
        fs.zw_set_information_file(handle, FILE_POSITION_INFORMATION, &position.to_le_bytes()),
        STATUS_SUCCESS
    );
    effects.push(tid);
}

#[test]
fn contention_preserves_file_state_and_event_does_not_release_busy() {
    let (mut fs, handle) = file();
    let mut busy = FileIoSerialization::new();
    let mut effects = Vec::new();

    fs.zw_retain_io_reference(handle).unwrap();
    assert_eq!(
        busy.begin_io(MODE, FIRST, false),
        Ok(FileIoAcquireResult::Acquired)
    );
    fs.zw_set_file_signaled(handle, false).unwrap();
    position_effect(&mut fs, handle, &busy, FIRST, 11, &mut effects);

    // Retain only before contention. A waiter must not reset the active request's event.
    fs.zw_set_file_signaled(handle, true).unwrap();
    fs.zw_retain_io_reference(handle).unwrap();
    assert_eq!(
        busy.begin_io(MODE, SECOND, false),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    assert_eq!(fs.zw_is_file_signaled(handle), Ok(true));
    assert_eq!(busy.io_lock_owner(), Some(FIRST));
    assert_eq!(fs.current_offset(handle), Some(11));
    assert_eq!(effects, [FIRST]);

    // Releasing Busy does not change the event. Promotion reserves Busy before wakeup.
    assert_eq!(busy.release_io(MODE, FIRST).unwrap().waiters, 1);
    fs.zw_release_io_reference(handle).unwrap();
    assert_eq!(fs.zw_is_file_signaled(handle), Ok(true));
    assert_eq!(busy.promote_io_waiter(MODE, SECOND), Ok(0));
    fs.zw_retain_io_reference(handle).unwrap();
    assert_eq!(
        busy.begin_io(MODE, THIRD, false),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    assert_eq!(busy.io_lock_owner(), Some(SECOND));
    assert_eq!(fs.current_offset(handle), Some(11));
    assert_eq!(
        busy.begin_io(MODE, SECOND, false),
        Ok(FileIoAcquireResult::Acquired)
    );
    // The promoted operation adopts its existing reference; there is no second begin/retain.
    fs.zw_set_file_signaled(handle, false).unwrap();
    position_effect(&mut fs, handle, &busy, SECOND, 22, &mut effects);
    assert_eq!(busy.cancel_io_waiter(), Ok(0));
    fs.zw_release_io_reference(handle).unwrap();
    assert_eq!(busy.release_io(MODE, SECOND).unwrap().waiters, 0);
    fs.zw_release_io_reference(handle).unwrap();
    assert!(!busy.has_live_io());
    assert_eq!(fs.zw_is_file_signaled(handle), Ok(false));
    assert_eq!(fs.current_offset(handle), Some(22));
    assert_eq!(effects, [FIRST, SECOND]);
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert_eq!(
        fs.query_file_object_information(handle),
        Err(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn promoted_operation_adopts_its_reference_after_the_final_handle_is_closed() {
    let (mut fs, handle) = file();
    let mut busy = FileIoSerialization::new();
    let mut effects = Vec::new();
    fs.zw_retain_io_reference(handle).unwrap();
    assert_eq!(
        busy.begin_io(MODE, FIRST, false),
        Ok(FileIoAcquireResult::Acquired)
    );
    fs.zw_set_file_signaled(handle, false).unwrap();
    fs.zw_retain_io_reference(handle).unwrap();
    assert_eq!(
        busy.begin_io(MODE, SECOND, false),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );

    // This fixture keeps Busy outside nt-fs, so canonical Busy is idle and close cleans up now.
    // Retained-object adoption here does not prove canonical or native cleanup ordering.
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert_eq!(
        fs.zw_retain_io_reference(handle),
        Err(STATUS_INVALID_HANDLE)
    );
    assert!(fs.query_file_object_information(handle).is_ok());
    assert_eq!(busy.begin_io(MODE, THIRD, true), Err(STATUS_INVALID_HANDLE));
    assert_eq!(busy.io_waiter_count(), 1);
    assert_eq!(busy.release_io(MODE, FIRST).unwrap().waiters, 1);
    assert_eq!(busy.promote_io_waiter(MODE, SECOND), Ok(0));
    fs.zw_release_io_reference(handle).unwrap();
    assert_eq!(
        busy.begin_io(MODE, SECOND, true),
        Ok(FileIoAcquireResult::Acquired)
    );
    fs.zw_set_file_signaled(handle, false).unwrap();
    position_effect(&mut fs, handle, &busy, SECOND, 37, &mut effects);
    assert_eq!(fs.current_offset(handle), Some(37));
    assert_eq!(effects, [SECOND]);
    busy.release_io(MODE, SECOND).unwrap();
    assert!(fs.query_file_object_information(handle).is_ok());
    fs.zw_release_io_reference(handle).unwrap();
    assert_eq!(
        fs.query_file_object_information(handle),
        Err(STATUS_INVALID_HANDLE)
    );
    assert!(!busy.has_live_io());
}

#[test]
fn cleanup_core_orders_behind_every_preexisting_ordinary_waiter() {
    // This drives only the extracted core with a fixture-owned cleanup reference. The canonical
    // filesystem embedding and its cleanup side effects are covered by local_file_cleanup.rs.
    for mode in [
        FileIoMode::SynchronousAlertable,
        FileIoMode::SynchronousNonAlertable,
    ] {
        let mut busy = FileIoSerialization::new();
        assert_eq!(
            busy.begin_io(mode, FIRST, false),
            Ok(FileIoAcquireResult::Acquired)
        );
        for tid in [SECOND, THIRD] {
            assert_eq!(
                busy.begin_io(mode, tid, false),
                Ok(FileIoAcquireResult::Contended {
                    alertable: mode.is_alertable()
                })
            );
        }
        assert_eq!(
            busy.begin_cleanup(mode),
            Ok(FileIoAcquireResult::Contended { alertable: false })
        );
        assert!(busy.cleanup_waiting());
        assert_eq!(busy.promote_cleanup_if_ready(mode, true), Ok(false));
        assert_eq!(busy.release_io(mode, FIRST).unwrap().waiters, 2);
        assert_eq!(busy.promote_cleanup_if_ready(mode, true), Ok(false));
        let mut completed = vec![FIRST];
        // FIFO selection belongs to the embedding wait queue, not the counter-only core.
        for (tid, remaining) in [(SECOND, 1), (THIRD, 0)] {
            assert_eq!(busy.promote_io_waiter(mode, tid), Ok(remaining));
            assert_eq!(busy.promote_cleanup_if_ready(mode, true), Ok(false));
            assert_eq!(
                busy.begin_io(mode, tid, true),
                Ok(FileIoAcquireResult::Acquired)
            );
            assert!(!busy.is_cleanup_owner());
            completed.push(tid);
            assert_eq!(busy.release_io(mode, tid).unwrap().waiters, remaining);
        }
        assert_eq!(completed, [FIRST, SECOND, THIRD]);
        assert_eq!(busy.promote_cleanup_if_ready(mode, true), Ok(true));
        assert!(busy.is_cleanup_owner());
        assert!(!busy.cleanup_waiting());
        assert!(busy.begin_io(mode, 124, true).is_err());
        assert_eq!(busy.release_cleanup_io().unwrap().waiters, 0);
        assert!(!busy.has_live_io());
    }
}

#[test]
fn cancelled_waiter_and_abandoned_promoted_grant_release_only_their_existing_references() {
    let (mut fs, handle) = file();
    let mut busy = FileIoSerialization::new();
    let mut effects = Vec::new();
    fs.zw_retain_io_reference(handle).unwrap();
    assert_eq!(
        busy.begin_io(MODE, FIRST, false),
        Ok(FileIoAcquireResult::Acquired)
    );
    fs.zw_set_file_signaled(handle, false).unwrap();
    position_effect(&mut fs, handle, &busy, FIRST, 8, &mut effects);
    for tid in [SECOND, THIRD] {
        fs.zw_retain_io_reference(handle).unwrap();
        assert_eq!(
            busy.begin_io(MODE, tid, false),
            Ok(FileIoAcquireResult::Contended { alertable: false })
        );
    }
    // Definitive queue cancellation removes SECOND's count and its pre-admitted reference.
    assert_eq!(busy.cancel_io_waiter(), Ok(1));
    fs.zw_release_io_reference(handle).unwrap();
    fs.zw_set_file_signaled(handle, true).unwrap();
    assert_eq!(busy.release_io(MODE, FIRST).unwrap().waiters, 1);
    fs.zw_release_io_reference(handle).unwrap();
    assert_eq!(busy.promote_io_waiter(MODE, THIRD), Ok(0));
    let promoted = busy;
    assert!(busy.cancel_promoted_io(SECOND).is_err());
    assert_eq!(busy, promoted);
    assert!(busy.release_io(MODE, THIRD).is_err());
    assert_eq!(busy, promoted);
    // The thread died before adopting the grant. No operation or event reset happened.
    assert_eq!(busy.cancel_promoted_io(THIRD).unwrap().waiters, 0);
    fs.zw_release_io_reference(handle).unwrap();
    assert_eq!(fs.zw_is_file_signaled(handle), Ok(true));
    assert_eq!(fs.current_offset(handle), Some(8));
    assert_eq!(effects, [FIRST]);
    assert!(!busy.has_live_io());
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert_eq!(
        fs.query_file_object_information(handle),
        Err(STATUS_INVALID_HANDLE)
    );
}
