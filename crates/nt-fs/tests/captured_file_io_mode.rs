use nt_fs::*;
use nt_io_completion::{FileIoAcquireResult, FileIoMode};

#[test]
fn counted_local_fifo_keeps_admitted_alertability_when_live_file_mode_changes() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(r"\??\C:\captured-mode", b"data"));
    let opened = fs.zw_create_file(r"\??\C:\captured-mode",
        FILE_READ_DATA | SYNCHRONIZE, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    assert_eq!(opened.status, STATUS_SUCCESS);
    let file = opened.handle;
    assert_eq!(fs.zw_acquire_file_io(file, 10), Ok(FileIoAcquireResult::Acquired));
    // The admitted mode SET changes the body while a later request already captured its policy.
    assert_eq!(fs.zw_set_information_file(file, FILE_MODE_INFORMATION,
        &FILE_SYNCHRONOUS_IO_ALERT.to_le_bytes()), STATUS_SUCCESS);
    assert_eq!(fs.zw_acquire_file_io_with_mode(file, 11, FileIoMode::SynchronousNonAlertable),
        Ok(FileIoAcquireResult::Contended { alertable: false }));
    let before = fs.zw_file_io_state(file).unwrap();
    assert_eq!(fs.zw_acquire_file_io_with_mode(file, 12, FileIoMode::Asynchronous),
        Err(STATUS_INVALID_PARAMETER));
    assert_eq!(fs.zw_file_io_state(file).unwrap(), before);
    fs.zw_release_file_io(file, 10).unwrap();
    fs.zw_release_io_reference(file).unwrap();
    fs.zw_promote_file_io_waiter(file, 11).unwrap();
    fs.zw_adopt_file_io(file, 11).unwrap();
    fs.zw_release_file_io(file, 11).unwrap();
    fs.zw_release_io_reference(file).unwrap();
    assert_eq!(fs.zw_file_io_state(file).unwrap().references, 1);
    assert_eq!(fs.zw_close(file), STATUS_SUCCESS);
}
