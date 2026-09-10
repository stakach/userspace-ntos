//! Canonical local File ownership with real namespace, share, and notification effects.
//! The fixture selects waiter order explicitly; this is not native syscall or boot proof.

use nt_fs::*;
use nt_io_completion::FileIoAcquireResult;

const FIRST: u64 = 171;
const SECOND: u64 = 172;
const THIRD: u64 = 173;
const SOURCE: &str = r"\??\C:\cleanup-source";
const TARGET: &str = r"\??\C:\cleanup-current";

fn file() -> (FileSystem, u64) {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(SOURCE, b"payload"));
    let opened = fs.zw_create_file(
        SOURCE,
        FILE_READ_DATA | FILE_WRITE_DATA | DELETE | SYNCHRONIZE,
        0,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    );
    assert_eq!(opened.status, STATUS_SUCCESS);
    (fs, opened.handle)
}

fn acquire_pair(fs: &mut FileSystem, handle: u64) {
    assert_eq!(
        fs.zw_acquire_file_io(handle, FIRST),
        Ok(FileIoAcquireResult::Acquired)
    );
    fs.zw_set_file_signaled(handle, false).unwrap();
    fs.zw_set_file_signaled(handle, true).unwrap();
    assert_eq!(
        fs.zw_acquire_file_io(handle, SECOND),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    // Admission retains only: waiting cannot reset the active operation's File event.
    let state = fs.zw_file_io_state(handle).unwrap();
    assert_eq!(state.owner_tid, Some(FIRST));
    assert_eq!(state.waiters, 1);
    assert!(state.signaled);
}

fn close_with_pair(fs: &mut FileSystem, handle: u64) {
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    let state = fs.zw_file_io_state(handle).unwrap();
    assert_eq!(state.handle_references, 0);
    assert!(state.cleanup_pending);
    assert_eq!(state.cleanup_error, None);
    assert_eq!(fs.zw_redrive_file_cleanup(handle), Ok(false));
    assert_eq!(
        fs.zw_acquire_file_io(handle, THIRD),
        Err(STATUS_INVALID_HANDLE)
    );
}

fn promote_second(fs: &mut FileSystem, handle: u64) {
    assert_eq!(fs.zw_release_file_io(handle, FIRST).unwrap().waiters, 1);
    assert!(fs.zw_file_io_state(handle).unwrap().cleanup_pending);
    assert_eq!(fs.zw_redrive_file_cleanup(handle), Ok(false));
    assert_eq!(fs.zw_promote_file_io_waiter(handle, SECOND), Ok(0));
    fs.zw_release_io_reference(handle).unwrap();
    let references = fs.zw_file_io_state(handle).unwrap().references;
    fs.zw_adopt_file_io(handle, SECOND).unwrap();
    assert_eq!(fs.zw_file_io_state(handle).unwrap().references, references);
    fs.zw_set_file_signaled(handle, false).unwrap();
}

fn gone(fs: &FileSystem, handle: u64) {
    assert_eq!(
        fs.query_file_object_information(handle),
        Err(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn queued_rename_and_disposition_after_close_determine_current_cleanup_effects() {
    for delete_at_cleanup in [false, true] {
        let (mut fs, handle) = file();
        let original_nodes = fs.node_count();
        acquire_pair(&mut fs, handle);
        assert_eq!(
            fs.zw_set_information_file(
                handle,
                FILE_DISPOSITION_INFORMATION,
                &[u8::from(!delete_at_cleanup)],
            ),
            STATUS_SUCCESS
        );
        close_with_pair(&mut fs, handle);
        assert_eq!(
            fs.file_bytes_owned(SOURCE).as_deref(),
            Some(&b"payload"[..])
        );
        promote_second(&mut fs, handle);

        assert_eq!(
            fs.zw_set_information_file(
                handle,
                FILE_DISPOSITION_INFORMATION,
                &[u8::from(delete_at_cleanup)],
            ),
            STATUS_SUCCESS
        );
        let name: Vec<u8> = "cleanup-current"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            fs.zw_rename_file(handle, FileRenameRoot::SourceParent, &name, false),
            STATUS_SUCCESS
        );
        assert_eq!(fs.file_len(SOURCE), None);
        assert_eq!(fs.file_len(TARGET), Some(7));
        assert!(fs.zw_file_io_state(handle).unwrap().cleanup_pending);

        fs.zw_release_file_io(handle, SECOND).unwrap();
        let state = fs.zw_file_io_state(handle).unwrap();
        assert!(!state.cleanup_pending);
        assert_eq!(state.owner_tid, None);
        assert_eq!(state.cleanup_error, None);
        assert_eq!(fs.zw_redrive_file_cleanup(handle), Ok(false));
        assert_eq!(fs.file_len(TARGET), (!delete_at_cleanup).then_some(7));
        assert!(fs.query_file_object_information(handle).is_ok());
        assert_eq!(fs.node_count(), original_nodes);
        fs.zw_release_io_reference(handle).unwrap();
        gone(&fs, handle);
        assert_eq!(
            fs.node_count(),
            original_nodes - usize::from(delete_at_cleanup)
        );
    }
}

#[test]
fn cleanup_releases_share_claim_before_the_last_completion_reference() {
    let (mut fs, handle) = file();
    acquire_pair(&mut fs, handle);
    close_with_pair(&mut fs, handle);
    let open_reader = |fs: &mut FileSystem| {
        fs.zw_create_file(
            SOURCE,
            FILE_READ_DATA,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
        )
    };
    assert_eq!(open_reader(&mut fs).status, STATUS_SHARING_VIOLATION);
    promote_second(&mut fs, handle);
    assert_eq!(open_reader(&mut fs).status, STATUS_SHARING_VIOLATION);
    fs.zw_release_file_io(handle, SECOND).unwrap();
    assert!(!fs.zw_file_io_state(handle).unwrap().cleanup_pending);
    let reader = open_reader(&mut fs);
    assert_eq!(reader.status, STATUS_SUCCESS);
    assert_ne!(reader.handle, handle);
    assert!(fs.query_file_object_information(handle).is_ok());
    assert_eq!(fs.zw_close(reader.handle), STATUS_SUCCESS);
    fs.zw_release_io_reference(handle).unwrap();
    gone(&fs, handle);
    assert_eq!(fs.file_len(SOURCE), Some(7));
}

#[test]
fn notify_reference_does_not_block_cleanup_but_admitted_directory_work_does() {
    const NOTIFY_TID: u64 = 174;
    const CONTEXT: u64 = 0xabc;
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(r"\??\C:\watched\child", b"child"));
    let dir = fs.zw_create_file(
        r"\??\C:\watched",
        FILE_READ_DATA | SYNCHRONIZE,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    );
    assert_eq!(dir.status, STATUS_SUCCESS);
    let handle = dir.handle;
    assert_eq!(
        fs.zw_acquire_file_io(handle, NOTIFY_TID),
        Ok(FileIoAcquireResult::Acquired)
    );
    let notify = fs
        .zw_notify_change_directory_file(handle, FILE_NOTIFY_CHANGE_FILE_NAME, false, 256, CONTEXT)
        .unwrap();
    // Notify relinquishes Busy after registration but owns its original I/O reference.
    fs.zw_release_file_io(handle, NOTIFY_TID).unwrap();
    acquire_pair(&mut fs, handle);
    close_with_pair(&mut fs, handle);
    assert!(fs.pop_directory_notify_completion().is_none());
    promote_second(&mut fs, handle);
    assert!(fs.pop_directory_notify_completion().is_none());
    fs.zw_release_file_io(handle, SECOND).unwrap();
    assert!(!fs.zw_file_io_state(handle).unwrap().cleanup_pending);
    let completion = fs.pop_directory_notify_completion().unwrap();
    assert_eq!(completion.id, notify);
    assert_eq!(completion.context, CONTEXT);
    assert_eq!(completion.status, STATUS_NOTIFY_CLEANUP);
    assert_eq!(completion.information, 0);
    assert!(completion.bytes.is_empty());
    assert!(fs.pop_directory_notify_completion().is_none());
    fs.zw_release_io_reference(handle).unwrap();
    assert!(fs.query_file_object_information(handle).is_ok());
    fs.zw_release_io_reference(handle).unwrap();
    gone(&fs, handle);
    assert_eq!(fs.file_len(r"\??\C:\watched\child"), Some(5));
}

#[test]
fn cancelled_waiter_and_abandoned_grant_allow_exact_final_cleanup_and_retirement() {
    let (mut fs, handle) = file();
    let nodes = fs.node_count();
    acquire_pair(&mut fs, handle);
    assert_eq!(
        fs.zw_acquire_file_io(handle, THIRD),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    assert_eq!(
        fs.zw_set_information_file(handle, FILE_DISPOSITION_INFORMATION, &[1]),
        STATUS_SUCCESS
    );
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    let references = fs.zw_file_io_state(handle).unwrap().references;
    assert_eq!(fs.zw_cancel_file_io_waiter(handle), Ok(1));
    assert_eq!(
        fs.zw_file_io_state(handle).unwrap().references,
        references - 1
    );
    assert_eq!(fs.file_len(SOURCE), Some(7));
    assert_eq!(fs.zw_release_file_io(handle, FIRST).unwrap().waiters, 1);
    fs.zw_release_io_reference(handle).unwrap();
    assert_eq!(fs.zw_promote_file_io_waiter(handle, THIRD), Ok(0));
    let references = fs.zw_file_io_state(handle).unwrap().references;
    assert!(fs.zw_cancel_promoted_file_io(handle, SECOND).is_err());
    let state = fs.zw_file_io_state(handle).unwrap();
    assert_eq!(state.references, references);
    assert_eq!(state.owner_tid, Some(THIRD));
    assert!(state.cleanup_pending);
    // Cancelling the promoted grant consumes its existing reference, without adoption.
    assert_eq!(
        fs.zw_cancel_promoted_file_io(handle, THIRD)
            .unwrap()
            .waiters,
        0
    );
    gone(&fs, handle);
    assert_eq!(fs.file_len(SOURCE), None);
    assert_eq!(fs.node_count(), nodes - 1);
}
