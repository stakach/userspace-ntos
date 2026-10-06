use super::*;

const PATH: &str = r"\??\C:\io.txt";

fn open(options: u32) -> (FileSystem, u64) {
    let mut fs = FileSystem::new(MemFs::new());
    let result = fs.zw_create_file(
        PATH,
        FILE_READ_DATA | FILE_WRITE_DATA | DELETE | SYNCHRONIZE,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_CREATE,
        options,
    );
    assert_eq!(result.status, STATUS_SUCCESS);
    (fs, result.handle)
}

fn state(fs: &FileSystem, handle: u64) -> (u32, u32, bool) {
    let object = fs.obj(handle).unwrap();
    (object.references, object.handle_references, object.signaled)
}

#[test]
fn zero_id_begins_from_either_signal_state() {
    for signaled in [false, true] {
        let (mut fs, handle) = open(FILE_NON_DIRECTORY_FILE);
        assert_eq!(handle, 0);
        fs.zw_set_file_signaled(handle, signaled).unwrap();
        assert_eq!(fs.zw_begin_file_io(handle), Ok(()));
        assert_eq!(state(&fs, handle), (2, 1, false));
        fs.zw_release_io_reference(handle).unwrap();
        assert_eq!(state(&fs, handle), (1, 1, false));
    }
}

#[test]
fn duplicate_handles_and_multiple_operations_keep_distinct_reference_counts() {
    let (mut fs, handle) = open(FILE_NON_DIRECTORY_FILE);
    assert_eq!(fs.zw_retain(handle), STATUS_SUCCESS);
    fs.zw_begin_file_io(handle).unwrap();
    fs.zw_begin_file_io(handle).unwrap();
    assert_eq!(state(&fs, handle), (4, 2, false));
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    fs.zw_release_io_reference(handle).unwrap();
    assert_eq!(state(&fs, handle), (2, 1, false));
    fs.zw_release_io_reference(handle).unwrap();
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert!(fs.obj(handle).is_none());
}

#[test]
fn quota_failure_preserves_both_counters_and_signal() {
    for signaled in [false, true] {
        let (mut fs, handle) = open(FILE_NON_DIRECTORY_FILE);
        fs.obj_mut(handle).unwrap().references = u32::MAX;
        fs.zw_set_file_signaled(handle, signaled).unwrap();
        let before = state(&fs, handle);
        assert_eq!(fs.zw_begin_file_io(handle), Err(STATUS_QUOTA_EXCEEDED));
        assert_eq!(state(&fs, handle), before);
    }
}

#[test]
fn missing_and_released_objects_cannot_begin() {
    let (mut fs, handle) = open(FILE_NON_DIRECTORY_FILE);
    let before = state(&fs, handle);
    for invalid in [handle + 1, INVALID_HANDLE, u64::MAX] {
        assert_eq!(fs.zw_begin_file_io(invalid), Err(STATUS_INVALID_HANDLE));
        assert_eq!(state(&fs, handle), before);
    }
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert_eq!(fs.zw_begin_file_io(handle), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn admitted_body_reference_can_begin_after_last_handle_closes() {
    let (mut fs, handle) = open(FILE_NON_DIRECTORY_FILE);
    fs.zw_retain_io_reference(handle).unwrap();
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    fs.zw_set_file_signaled(handle, true).unwrap();
    assert_eq!(state(&fs, handle), (1, 0, true));

    assert_eq!(fs.zw_begin_file_io(handle), Err(STATUS_INVALID_HANDLE));
    assert_eq!(state(&fs, handle), (1, 0, true));
    assert_eq!(fs.zw_begin_referenced_file_io(handle), Ok(()));
    assert_eq!(state(&fs, handle), (2, 0, false));

    fs.zw_release_io_reference(handle).unwrap();
    assert_eq!(state(&fs, handle), (1, 0, false));
    fs.zw_release_io_reference(handle).unwrap();
    assert!(fs.obj(handle).is_none());
    assert_eq!(fs.zw_begin_referenced_file_io(handle), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn referenced_begin_requires_an_independent_body_pin() {
    let (mut fs, handle) = open(FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    let before = state(&fs, handle);
    assert_eq!(fs.zw_begin_referenced_file_io(handle), Err(STATUS_INVALID_HANDLE));
    assert_eq!(state(&fs, handle), before);

    fs.zw_acquire_file_io(handle, 7).unwrap();
    let before = state(&fs, handle);
    assert_eq!(fs.zw_begin_referenced_file_io(handle), Err(STATUS_INVALID_HANDLE));
    assert_eq!(state(&fs, handle), before);
    fs.zw_acquire_file_io(handle, 8).unwrap();
    let before = state(&fs, handle);
    assert_eq!(fs.zw_begin_referenced_file_io(handle), Err(STATUS_INVALID_HANDLE));
    assert_eq!(state(&fs, handle), before);
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    let before = state(&fs, handle);
    assert_eq!(fs.zw_begin_referenced_file_io(handle), Err(STATUS_INVALID_HANDLE));
    assert_eq!(state(&fs, handle), before);
}

#[test]
fn retained_cleanup_only_is_not_admitted_body_authority() {
    let (mut fs, handle) = open(
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
    );
    fs.zw_acquire_file_io(handle, 7).unwrap();
    let object = fs.obj(handle).unwrap();
    let (node, entry) = (object.node_id, object.entry_id);
    let (parent, index, _) = fs.volume.entry_location(entry).unwrap();
    fs.volume.node_mut(parent).unwrap().children[index].node_id = 0;
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    fs.zw_release_file_io(handle, 7).unwrap();
    fs.zw_release_io_reference(handle).unwrap();
    let before = state(&fs, handle);
    assert_eq!(before.0, 1);
    assert_eq!(before.1, 0);
    assert!(fs.zw_file_io_state(handle).unwrap().cleanup_pending);
    assert_eq!(fs.zw_begin_referenced_file_io(handle), Err(STATUS_INVALID_HANDLE));
    assert_eq!(state(&fs, handle), before);
    fs.volume.node_mut(parent).unwrap().children[index].node_id = node;
    assert_eq!(fs.zw_redrive_file_cleanup(handle), Ok(true));
    assert!(fs.obj(handle).is_none());
}

#[test]
fn io_only_object_cannot_begin_and_remains_owned_until_release() {
    for signaled in [false, true] {
        let (mut fs, handle) = open(FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE);
        let node = fs.obj(handle).unwrap().node_id;
        fs.zw_begin_file_io(handle).unwrap();
        assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
        fs.zw_set_file_signaled(handle, signaled).unwrap();
        let before = state(&fs, handle);
        assert_eq!(before, (1, 0, signaled));
        assert_eq!(fs.zw_begin_file_io(handle), Err(STATUS_INVALID_HANDLE));
        assert_eq!(state(&fs, handle), before);
        assert!(fs.query_file_object_information(handle).is_ok());
        fs.zw_release_io_reference(handle).unwrap();
        assert!(fs.obj(handle).is_none());
        assert!(fs.volume.node(node).is_none());
        assert!(fs.query_metadata(PATH).is_none());
    }
}

#[test]
fn directory_object_can_begin_and_complete_its_reference_lifetime() {
    let (mut fs, handle) = open(FILE_DIRECTORY_FILE);
    fs.zw_set_file_signaled(handle, true).unwrap();
    fs.zw_begin_file_io(handle).unwrap();
    assert_eq!(state(&fs, handle), (2, 1, false));
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert!(
        fs.query_file_object_information(handle)
            .unwrap()
            .metadata
            .is_directory
    );
    fs.zw_release_io_reference(handle).unwrap();
    assert!(fs.obj(handle).is_none());
}

#[test]
fn malformed_reference_counts_fail_without_mutation() {
    for references in [0, 1] {
        let (mut fs, handle) = open(FILE_NON_DIRECTORY_FILE);
        let object = fs.obj_mut(handle).unwrap();
        object.references = references;
        object.handle_references = 2;
        object.signaled = true;
        let before = state(&fs, handle);
        assert_eq!(fs.zw_begin_file_io(handle), Err(STATUS_DATA_ERROR));
        assert_eq!(state(&fs, handle), before);
    }
}

#[test]
fn missing_backing_node_fails_without_mutation() {
    let (mut fs, handle) = open(FILE_NON_DIRECTORY_FILE);
    fs.zw_set_file_signaled(handle, true).unwrap();
    let node = fs.obj(handle).unwrap().node_id;
    fs.volume.nodes[node as usize] = None;
    let before = state(&fs, handle);
    assert_eq!(fs.zw_begin_file_io(handle), Err(STATUS_DATA_ERROR));
    assert_eq!(state(&fs, handle), before);
}
