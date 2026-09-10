use super::*;

const PATH: &str = r"\??\C:\serialized.txt";
const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

fn open(options: u32) -> (FileSystem, u64) {
    let mut fs = FileSystem::new(MemFs::new());
    let created = fs.zw_create_file(
        PATH,
        FILE_READ_DATA | FILE_WRITE_DATA | DELETE | SYNCHRONIZE,
        0,
        SHARE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | options,
    );
    assert_eq!(created.status, STATUS_SUCCESS);
    (fs, created.handle)
}

#[test]
fn acquired_and_waiting_references_do_not_change_signal_and_cannot_be_released() {
    let (mut fs, handle) = open(FILE_SYNCHRONOUS_IO_NONALERT);
    assert_eq!(handle, 0);
    fs.zw_set_file_signaled(handle, true).unwrap();
    assert_eq!(
        fs.zw_acquire_file_io(handle, 1),
        Ok(FileIoAcquireResult::Acquired)
    );
    assert_eq!(
        fs.zw_acquire_file_io(handle, 2),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    let before = fs.zw_file_io_state(handle).unwrap();
    assert_eq!(before.references, 3);
    assert!(before.signaled);
    assert_eq!(fs.zw_begin_file_io(handle), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(
        fs.zw_release_io_reference(handle),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(fs.zw_file_io_state(handle), Ok(before));
    assert_eq!(fs.zw_cancel_file_io_waiter(handle), Ok(0));
    fs.zw_release_file_io(handle, 1).unwrap();
    fs.zw_release_io_reference(handle).unwrap();
    assert_eq!(fs.zw_file_io_state(handle).unwrap().references, 1);
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
}

#[test]
fn exact_grant_adoption_never_retains_twice_or_acquires_idle() {
    let (mut fs, handle) = open(FILE_SYNCHRONOUS_IO_NONALERT);
    assert_eq!(
        fs.zw_adopt_file_io(handle, 1),
        Err(STATUS_INVALID_PARAMETER)
    );
    fs.zw_acquire_file_io(handle, 1).unwrap();
    fs.zw_acquire_file_io(handle, 2).unwrap();
    fs.zw_release_file_io(handle, 1).unwrap();
    fs.zw_release_io_reference(handle).unwrap();
    fs.zw_promote_file_io_waiter(handle, 2).unwrap();
    let before = fs.zw_file_io_state(handle).unwrap();
    assert_eq!(
        fs.zw_acquire_file_io(handle, 2),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        fs.zw_adopt_file_io(handle, 3),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(fs.zw_file_io_state(handle), Ok(before));
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert_eq!(fs.zw_adopt_file_io(handle, 2), Ok(()));
    assert_eq!(
        fs.zw_file_io_state(handle).unwrap().references,
        before.references
    );
    assert_eq!(
        fs.zw_adopt_file_io(handle, 2),
        Err(STATUS_INVALID_PARAMETER)
    );
    fs.zw_release_file_io(handle, 2).unwrap();
    fs.zw_release_io_reference(handle).unwrap();
    assert_eq!(fs.zw_file_io_state(handle), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn admission_failures_do_not_mutate_reference_or_busy_state() {
    let (mut fs, handle) = open(FILE_SYNCHRONOUS_IO_ALERT);
    for tid in [0, u64::MAX] {
        let before = fs.zw_file_io_state(handle).unwrap();
        assert_eq!(
            fs.zw_acquire_file_io(handle, tid),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(fs.zw_file_io_state(handle), Ok(before));
    }
    assert_eq!(
        fs.zw_acquire_file_io(INVALID_HANDLE, 1),
        Err(STATUS_INVALID_HANDLE)
    );
    fs.obj_mut(handle).unwrap().references = u32::MAX;
    let before = fs.zw_file_io_state(handle).unwrap();
    assert_eq!(fs.zw_acquire_file_io(handle, 1), Err(STATUS_QUOTA_EXCEEDED));
    assert_eq!(fs.zw_file_io_state(handle), Ok(before));
    fs.obj_mut(handle).unwrap().references = 0;
    assert_eq!(fs.zw_acquire_file_io(handle, 1), Err(STATUS_DATA_ERROR));
    assert_eq!(fs.obj(handle).unwrap().serialization.io_lock_owner(), None);
}

#[test]
fn only_final_duplicate_close_transfers_cleanup_and_async_io_does_not_block_it() {
    for options in [0, FILE_SYNCHRONOUS_IO_NONALERT] {
        let (mut fs, handle) = open(options);
        assert_eq!(fs.zw_retain(handle), STATUS_SUCCESS);
        fs.zw_retain_io_reference(handle).unwrap();
        assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
        assert_eq!(fs.zw_file_io_state(handle).unwrap().handle_references, 1);
        assert_eq!(fs.pending_file_cleanup_from(0), None);
        assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
        let state = fs.zw_file_io_state(handle).unwrap();
        assert_eq!(state.references, 1);
        assert_eq!(state.handle_references, 0);
        assert!(!state.cleanup_pending);
        assert_eq!(fs.pending_file_cleanup_count, 0);
        assert_eq!(fs.zw_release_io_reference(handle), Ok(()));
    }
}

#[test]
fn cleanup_preparation_failure_is_retained_without_replaying_close_or_release() {
    let (mut fs, handle) = open(FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE);
    fs.zw_acquire_file_io(handle, 1).unwrap();
    let object = fs.obj(handle).unwrap();
    let (node, entry) = (object.node_id, object.entry_id);
    let (parent, index, _) = fs.volume.entry_location(entry).unwrap();
    fs.volume.node_mut(parent).unwrap().children[index].node_id = 0;
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert_eq!(fs.pending_file_cleanup_from(0), Some((0, handle)));
    assert_eq!(
        fs.zw_release_file_io(handle, 1),
        Ok(FileIoRelease { waiters: 0 })
    );
    let failed = fs.zw_file_io_state(handle).unwrap();
    assert!(failed.cleanup_pending);
    assert_eq!(failed.cleanup_error, Some(STATUS_DATA_ERROR));
    assert_eq!(failed.references, 2);
    assert_eq!(fs.zw_close(handle), STATUS_INVALID_HANDLE);
    assert_eq!(fs.zw_release_io_reference(handle), Ok(()));
    assert_eq!(fs.zw_file_io_state(handle).unwrap().references, 1);
    assert_eq!(
        fs.zw_release_io_reference(handle),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(fs.zw_redrive_file_cleanup(handle), Err(STATUS_DATA_ERROR));
    assert_eq!(
        fs.take_file_cleanup_effects(),
        FileCleanupEffects::default()
    );
    fs.volume.node_mut(parent).unwrap().children[index].node_id = node;
    assert_eq!(fs.zw_redrive_file_cleanup(handle), Ok(true));
    assert_eq!(fs.pending_file_cleanup_from(0), None);
    assert_eq!(fs.pending_file_cleanup_count, 0);
    assert_eq!(fs.zw_file_io_state(handle), Err(STATUS_INVALID_HANDLE));
    assert!(fs.take_file_cleanup_effects().namespace_changed);
    assert_eq!(
        fs.take_file_cleanup_effects(),
        FileCleanupEffects::default()
    );
}

#[test]
fn absent_exact_entry_does_not_delete_a_replacement_or_leak_cleanup() {
    let (mut fs, handle) = open(FILE_DELETE_ON_CLOSE);
    fs.zw_retain_io_reference(handle).unwrap();
    let entry = fs.obj(handle).unwrap().entry_id;
    fs.volume.unlink_entry(entry).unwrap();
    assert!(fs.provision_file(PATH, b"replacement"));
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert_eq!(
        fs.file_bytes_owned(PATH).as_deref(),
        Some(&b"replacement"[..])
    );
    assert!(!fs.zw_file_io_state(handle).unwrap().cleanup_pending);
    assert_eq!(fs.pending_file_cleanup_count, 0);
    assert_eq!(
        fs.take_file_cleanup_effects(),
        FileCleanupEffects::default()
    );
    fs.zw_release_io_reference(handle).unwrap();
}

#[test]
fn cleanup_enumeration_and_effects_survive_row_retirement_and_reuse() {
    let (mut fs, first) = open(FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE);
    let second = fs.zw_create_file(
        r"\??\C:\second.txt",
        FILE_READ_DATA | DELETE | SYNCHRONIZE,
        0,
        SHARE,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
    );
    assert_eq!(second.status, STATUS_SUCCESS);
    for handle in [first, second.handle] {
        fs.zw_acquire_file_io(handle, 1).unwrap();
        assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    }
    assert_eq!(fs.pending_file_cleanup_count, 2);
    let (index, _) = fs.pending_file_cleanup_from(0).unwrap();
    assert_eq!(
        fs.pending_file_cleanup_from(index + 1),
        Some((second.handle as usize, second.handle))
    );
    assert_eq!(
        fs.pending_file_cleanup_from(second.handle as usize + 1),
        None
    );
    for handle in [first, second.handle] {
        fs.zw_release_file_io(handle, 1).unwrap();
        assert!(fs.query_file_object_information(handle).is_ok());
        assert!(fs.file_cleanup_effects.namespace_changed);
        fs.zw_release_io_reference(handle).unwrap();
    }
    assert_eq!(fs.pending_file_cleanup_count, 0);
    assert_eq!(fs.pending_file_cleanup_from(0), None);
    assert!(fs.take_file_cleanup_effects().namespace_changed);
    assert_eq!(
        fs.take_file_cleanup_effects(),
        FileCleanupEffects::default()
    );
    let replacement = fs.zw_create_file(
        PATH,
        FILE_READ_DATA,
        0,
        SHARE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(replacement.status, STATUS_SUCCESS);
    assert_eq!(replacement.handle, first);
    assert_eq!(fs.pending_file_cleanup_from(0), None);
}

#[test]
fn pending_cleanup_count_overflow_rejects_before_consuming_the_handle() {
    let (mut fs, handle) = open(FILE_SYNCHRONOUS_IO_NONALERT);
    fs.pending_file_cleanup_count = usize::MAX;
    let before = fs.zw_file_io_state(handle).unwrap();
    assert_eq!(fs.zw_close(handle), STATUS_QUOTA_EXCEEDED);
    assert_eq!(fs.zw_file_io_state(handle), Ok(before));
}

#[test]
fn notification_cleanup_effect_is_sticky_until_taken_even_after_acknowledgement() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\watched"));
    let opened = fs.zw_create_file(
        r"\??\C:\watched",
        FILE_READ_DATA | SYNCHRONIZE,
        0,
        SHARE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    );
    assert_eq!(opened.status, STATUS_SUCCESS);
    let handle = opened.handle;
    fs.zw_retain_io_reference(handle).unwrap();
    let id = fs
        .zw_notify_change_directory_file(
            handle,
            crate::FILE_NOTIFY_CHANGE_FILE_NAME,
            false,
            128,
            77,
        )
        .unwrap();
    fs.zw_acquire_file_io(handle, 1).unwrap();
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert_eq!(
        fs.take_file_cleanup_effects(),
        FileCleanupEffects::default()
    );
    fs.zw_release_file_io(handle, 1).unwrap();
    let completion = fs.pop_directory_notify_completion().unwrap();
    assert_eq!(completion.id, id);
    assert_eq!(completion.status, crate::STATUS_NOTIFY_CLEANUP);
    fs.zw_release_io_reference(handle).unwrap();
    fs.zw_release_io_reference(handle).unwrap();
    assert_eq!(fs.pending_file_cleanup_from(0), None);
    assert_eq!(
        fs.take_file_cleanup_effects(),
        FileCleanupEffects {
            namespace_changed: false,
            notifications_completed: true,
        }
    );
    assert_eq!(
        fs.take_file_cleanup_effects(),
        FileCleanupEffects::default()
    );
}
