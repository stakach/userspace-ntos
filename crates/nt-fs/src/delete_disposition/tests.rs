use super::*;

const PATH: &str = r"\??\C:\Dir\Scratch.tmp";
const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const ACCESS: u32 = FILE_READ_DATA | FILE_WRITE_DATA | DELETE | SYNCHRONIZE;

fn volume() -> FileSystem {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.initialize_timestamps(100));
    assert!(fs.provision_directory(r"\??\C:\Dir"));
    fs
}

fn open(fs: &mut FileSystem, disposition: u32, attributes: u32, options: u32) -> CreateResult {
    fs.zw_create_file(
        PATH,
        ACCESS,
        attributes,
        SHARE,
        disposition,
        options | FILE_NON_DIRECTORY_FILE,
    )
}

fn opened(fs: &mut FileSystem, disposition: u32, options: u32) -> u64 {
    let result = open(fs, disposition, 0, options);
    assert_eq!(result.status, STATUS_SUCCESS);
    result.handle
}

fn set_disposition(fs: &mut FileSystem, handle: u64, delete: bool) -> u32 {
    fs.zw_set_information_file(handle, FILE_DISPOSITION_INFORMATION, &[delete as u8])
}

fn delete_pending(fs: &FileSystem, handle: u64) -> bool {
    fs.query_file_object_information(handle)
        .unwrap()
        .metadata
        .delete_pending
}

#[test]
fn a_pending_delete_takes_effect_when_the_last_handle_closes() {
    let mut fs = volume();
    let first = opened(&mut fs, FILE_CREATE, 0);
    let second = opened(&mut fs, FILE_OPEN, 0);
    assert_eq!(set_disposition(&mut fs, first, true), STATUS_SUCCESS);
    // DeletePending belongs to the file, not to the handle that set it.
    assert!(delete_pending(&fs, first));
    assert!(delete_pending(&fs, second));

    assert_eq!(fs.zw_close(first), STATUS_SUCCESS);
    assert!(fs.query_metadata(PATH).is_some());
    assert!(delete_pending(&fs, second));

    assert_eq!(fs.zw_close(second), STATUS_SUCCESS);
    assert!(fs.query_metadata(PATH).is_none());
}

#[test]
fn a_file_with_a_pending_delete_cannot_be_opened_again() {
    let mut fs = volume();
    let first = opened(&mut fs, FILE_CREATE, 0);
    assert_eq!(set_disposition(&mut fs, first, true), STATUS_SUCCESS);
    for disposition in [FILE_OPEN, FILE_OPEN_IF, FILE_OVERWRITE_IF, FILE_SUPERSEDE] {
        let again = open(&mut fs, disposition, 0, 0);
        assert_eq!(again.status, STATUS_DELETE_PENDING, "disposition {disposition}");
        assert_eq!(again.handle, INVALID_HANDLE);
    }
    assert_eq!(fs.zw_close(first), STATUS_SUCCESS);
    assert!(fs.query_metadata(PATH).is_none());
    // The name is free once the delete has happened.
    let recreated = opened(&mut fs, FILE_CREATE, 0);
    assert!(!delete_pending(&fs, recreated));
}

#[test]
fn any_handle_clears_a_pending_delete() {
    let mut fs = volume();
    let first = opened(&mut fs, FILE_CREATE, 0);
    let second = opened(&mut fs, FILE_OPEN, 0);
    assert_eq!(set_disposition(&mut fs, first, true), STATUS_SUCCESS);
    assert_eq!(set_disposition(&mut fs, second, false), STATUS_SUCCESS);
    assert!(!delete_pending(&fs, first));
    assert!(!delete_pending(&fs, second));
    assert_eq!(fs.zw_close(first), STATUS_SUCCESS);
    assert_eq!(fs.zw_close(second), STATUS_SUCCESS);
    assert!(fs.query_metadata(PATH).is_some());
}

#[test]
fn delete_on_close_marks_the_file_when_its_own_handle_closes() {
    let mut fs = volume();
    let first = opened(&mut fs, FILE_CREATE, FILE_DELETE_ON_CLOSE);
    // Until that handle closes the file is an ordinary open file.
    assert!(!delete_pending(&fs, first));
    let second = opened(&mut fs, FILE_OPEN, 0);
    assert!(!delete_pending(&fs, second));

    assert_eq!(fs.zw_close(first), STATUS_SUCCESS);
    assert!(fs.query_metadata(PATH).is_some());
    assert!(delete_pending(&fs, second));
    assert_eq!(open(&mut fs, FILE_OPEN, 0, 0).status, STATUS_DELETE_PENDING);

    assert_eq!(fs.zw_close(second), STATUS_SUCCESS);
    assert!(fs.query_metadata(PATH).is_none());
}

#[test]
fn a_duplicated_handle_keeps_the_file_until_it_closes_too() {
    let mut fs = volume();
    let handle = opened(&mut fs, FILE_CREATE, 0);
    assert_eq!(fs.zw_retain(handle), STATUS_SUCCESS);
    assert_eq!(set_disposition(&mut fs, handle, true), STATUS_SUCCESS);
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert!(fs.query_metadata(PATH).is_some());
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert!(fs.query_metadata(PATH).is_none());
}

#[test]
fn a_read_only_file_cannot_be_opened_or_created_delete_on_close() {
    let mut fs = volume();
    let created = open(&mut fs, FILE_CREATE, FILE_ATTRIBUTE_READONLY, FILE_DELETE_ON_CLOSE);
    assert_eq!(created.status, STATUS_CANNOT_DELETE);
    assert!(fs.query_metadata(PATH).is_none());

    let created = open(&mut fs, FILE_CREATE, FILE_ATTRIBUTE_READONLY, 0);
    assert_eq!(created.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_close(created.handle), STATUS_SUCCESS);
    assert_eq!(
        open(&mut fs, FILE_OPEN, 0, FILE_DELETE_ON_CLOSE).status,
        STATUS_CANNOT_DELETE
    );
    let plain = opened(&mut fs, FILE_OPEN, 0);
    assert_eq!(set_disposition(&mut fs, plain, true), STATUS_CANNOT_DELETE);
    assert!(!delete_pending(&fs, plain));
    assert_eq!(fs.zw_close(plain), STATUS_SUCCESS);
    assert!(fs.query_metadata(PATH).is_some());
}

#[test]
fn a_delete_pending_directory_admits_no_new_entry() {
    let mut fs = volume();
    let directory = fs.zw_create_file(
        r"\??\C:\Dir\Sub",
        ACCESS,
        0,
        SHARE,
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(directory.status, STATUS_SUCCESS);
    assert_eq!(set_disposition(&mut fs, directory.handle, true), STATUS_SUCCESS);
    // A delete-pending directory admits no new entries.
    let child = fs.zw_create_file(
        r"\??\C:\Dir\Sub\child.txt",
        ACCESS,
        0,
        SHARE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(child.status, STATUS_DELETE_PENDING);
    assert_eq!(fs.zw_close(directory.handle), STATUS_SUCCESS);
    assert!(fs.query_metadata(r"\??\C:\Dir\Sub").is_none());
}

#[test]
fn a_delete_on_close_directory_that_gained_an_entry_is_kept() {
    let mut fs = volume();
    let directory = fs.zw_create_file(
        r"\??\C:\Dir\Sub",
        ACCESS,
        0,
        SHARE,
        FILE_CREATE,
        FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
    );
    assert_eq!(directory.status, STATUS_SUCCESS);
    assert!(fs.provision_file(r"\??\C:\Dir\Sub\child.txt", b"child"));
    assert_eq!(fs.zw_close(directory.handle), STATUS_SUCCESS);
    assert_eq!(fs.zw_file_io_state(directory.handle).err(), Some(STATUS_INVALID_HANDLE));
    assert!(fs.query_metadata(r"\??\C:\Dir\Sub\child.txt").is_some());
}
