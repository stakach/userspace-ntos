use super::*;

const PATH: &str = r"\??\C:\Dir\Source.txt";
const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const ACCESS: u32 = FILE_READ_DATA | FILE_WRITE_DATA | DELETE | 0x0010_0000;

fn open_file(options: u32) -> (FileSystem, u64) {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.initialize_timestamps(100));
    assert!(fs.provision_directory(r"\??\C:\Dir"));
    let opened = fs.zw_create_file(
        PATH,
        ACCESS,
        0,
        SHARE,
        FILE_CREATE,
        options | FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(opened.status, STATUS_SUCCESS);
    (fs, opened.handle)
}

fn wide_bytes(name: &str) -> Vec<u8> {
    name.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn live_snapshot_preserves_metadata_position_and_mode_for_open_id_zero() {
    let options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH;
    let (mut fs, handle) = open_file(options);
    assert_eq!(handle, 0);
    assert_eq!(
        fs.zw_write_file(handle, None, b"contents"),
        (STATUS_SUCCESS, 8)
    );
    assert_eq!(
        fs.zw_set_information_file(handle, FILE_POSITION_INFORMATION, &3u64.to_le_bytes()),
        STATUS_SUCCESS
    );
    let before = fs.query_file_object_information(handle).unwrap();
    assert_eq!(before.metadata, fs.zw_query_metadata(handle).unwrap());
    assert_eq!(before.metadata.end_of_file, 8);
    assert_ne!(before.metadata.file_id, handle);
    assert_eq!(before.current_offset, 3);
    assert_eq!(
        before.mode,
        crate::file_mode_from_create_options(options | FILE_NON_DIRECTORY_FILE)
    );
    assert_eq!(fs.query_file_object_information(handle), Ok(before));
    assert_eq!(fs.query_opened_name(handle).unwrap(), r"\Dir\Source.txt");
    assert_eq!(fs.query_short_name(handle), Ok(FileShortName::EMPTY));
}

#[test]
fn missing_and_released_open_objects_return_invalid_handle() {
    let (mut fs, handle) = open_file(0);
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    for invalid in [handle, handle + 1, INVALID_HANDLE, u64::MAX] {
        assert_eq!(
            fs.query_file_object_information(invalid),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(fs.query_opened_name(invalid), Err(STATUS_INVALID_HANDLE));
        assert_eq!(fs.query_short_name(invalid), Err(STATUS_INVALID_HANDLE));
    }
}

#[test]
fn corrupt_extent_backing_is_not_reported_as_an_invalid_open() {
    let (mut fs, handle) = open_file(0);
    let node = fs.obj(handle).unwrap().node_id;
    let blob = fs.volume.blobs.len();
    fs.volume.blobs.push(b"data".to_vec());
    for extents in [
        alloc::vec![FileExtent {
            blob: blob + 1,
            offset: 0,
            len: 1
        }],
        alloc::vec![FileExtent {
            blob,
            offset: 3,
            len: 2
        }],
        alloc::vec![FileExtent {
            blob,
            offset: usize::MAX,
            len: 1
        }],
        alloc::vec![
            FileExtent {
                blob: ZERO_EXTENT_BLOB,
                offset: 0,
                len: usize::MAX
            },
            FileExtent {
                blob: ZERO_EXTENT_BLOB,
                offset: 0,
                len: 1
            },
        ],
    ] {
        fs.volume.node_mut(node).unwrap().data = FileData::Extents(extents);
        assert_eq!(
            fs.query_file_object_information(handle),
            Err(STATUS_DATA_ERROR)
        );
    }
    assert!(fs.obj(handle).is_some());
}

#[test]
fn a_live_object_with_a_missing_node_is_storage_corruption() {
    let (mut fs, handle) = open_file(0);
    let node = fs.obj(handle).unwrap().node_id;
    fs.volume.nodes[node as usize] = None;
    assert_eq!(
        fs.query_file_object_information(handle),
        Err(STATUS_DATA_ERROR)
    );
    assert_eq!(fs.query_opened_name(handle), Err(STATUS_DATA_ERROR));
    assert_eq!(fs.query_short_name(handle), Err(STATUS_DATA_ERROR));
}

#[test]
fn hardlinks_share_node_metadata_but_open_instances_keep_their_position() {
    let (mut fs, source) = open_file(0);
    assert_eq!(fs.zw_write_file(source, None, b"data"), (STATUS_SUCCESS, 4));
    assert_eq!(
        fs.zw_link_file(
            source,
            FileRenameRoot::SourceParent,
            &wide_bytes("Alias.txt"),
            false
        ),
        STATUS_SUCCESS
    );
    let alias = fs.zw_create_file(
        r"\??\C:\Dir\Alias.txt",
        ACCESS,
        0,
        SHARE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(alias.status, STATUS_SUCCESS);
    assert_ne!(alias.handle, source);
    assert_eq!(fs.zw_retain(source), STATUS_SUCCESS);
    let source_info = fs.query_file_object_information(source).unwrap();
    let alias_info = fs.query_file_object_information(alias.handle).unwrap();
    assert_eq!(source_info.metadata.file_id, alias_info.metadata.file_id);
    assert_eq!(source_info.metadata.number_of_links, 2);
    assert_eq!(source_info.current_offset, 4);
    assert_eq!(alias_info.current_offset, 0);
    assert_eq!(
        fs.query_opened_name(alias.handle).unwrap(),
        r"\Dir\Alias.txt"
    );
    assert_eq!(fs.zw_close(source), STATUS_SUCCESS);
    assert_eq!(fs.query_file_object_information(source), Ok(source_info));
    assert_eq!(fs.zw_close(source), STATUS_SUCCESS);
    assert_eq!(
        fs.query_file_object_information(source),
        Err(STATUS_INVALID_HANDLE)
    );
    assert!(fs.query_file_object_information(alias.handle).is_ok());
}

#[test]
fn cleanup_keeps_io_referenced_metadata_and_names_until_final_release() {
    let (mut fs, handle) = open_file(FILE_DELETE_ON_CLOSE);
    assert_eq!(fs.zw_write_file(handle, None, b"data"), (STATUS_SUCCESS, 4));
    let short =
        FileShortName::from_units(&"SOURCE~1.TXT".encode_utf16().collect::<Vec<_>>()).unwrap();
    let entry = fs.obj(handle).unwrap().entry_id;
    assert_eq!(fs.volume.set_entry_short_name(entry, short), STATUS_SUCCESS);
    assert_eq!(fs.query_short_name(handle), Ok(short));
    fs.zw_retain_io_reference(handle).unwrap();
    let before = fs.query_file_object_information(handle).unwrap();
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert!(fs.query_metadata(PATH).is_none());
    let retained = fs.query_file_object_information(handle).unwrap();
    assert_eq!(retained.metadata.file_id, before.metadata.file_id);
    assert_eq!(retained.metadata.number_of_links, 0);
    assert!(retained.metadata.delete_pending);
    assert_eq!(retained.current_offset, before.current_offset);
    assert_eq!(fs.query_opened_name(handle).unwrap(), r"\Dir\Source.txt");
    assert_eq!(fs.query_short_name(handle), Ok(FileShortName::EMPTY));
    fs.zw_release_io_reference(handle).unwrap();
    assert_eq!(
        fs.query_file_object_information(handle),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(fs.query_opened_name(handle), Err(STATUS_INVALID_HANDLE));
    assert_eq!(fs.query_short_name(handle), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn renamed_then_unlinked_entry_retains_its_name_with_another_hardlink() {
    let (mut fs, handle) = open_file(FILE_DELETE_ON_CLOSE);
    assert_eq!(
        fs.zw_link_file(
            handle,
            FileRenameRoot::SourceParent,
            &wide_bytes("Alias.txt"),
            false
        ),
        STATUS_SUCCESS
    );
    assert_eq!(
        fs.zw_rename_file(
            handle,
            FileRenameRoot::SourceParent,
            &wide_bytes("Renamed.txt"),
            false
        ),
        STATUS_SUCCESS
    );
    assert_eq!(fs.query_opened_name(handle).unwrap(), r"\Dir\Renamed.txt");
    fs.zw_retain_io_reference(handle).unwrap();
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    let retained = fs.query_file_object_information(handle).unwrap();
    assert_eq!(retained.metadata.number_of_links, 1);
    assert_eq!(fs.query_opened_name(handle).unwrap(), r"\Dir\Renamed.txt");
    assert_eq!(fs.query_short_name(handle), Ok(FileShortName::EMPTY));
    assert!(fs.query_metadata(r"\??\C:\Dir\Alias.txt").is_some());
}

#[test]
fn present_entry_pointing_at_a_different_node_is_corruption() {
    let (mut fs, handle) = open_file(0);
    let entry = fs.obj(handle).unwrap().entry_id;
    let (parent, index, _) = fs.volume.entry_location(entry).unwrap();
    fs.volume.node_mut(parent).unwrap().children[index].node_id = 0;
    assert_eq!(fs.query_opened_name(handle), Err(STATUS_DATA_ERROR));
    assert_eq!(fs.query_short_name(handle), Err(STATUS_DATA_ERROR));
}

#[test]
fn corrupt_parent_chain_returns_an_error_instead_of_shortening_the_name() {
    let (mut fs, handle) = open_file(0);
    let entry = fs.obj(handle).unwrap().entry_id;
    let (parent, _, _) = fs.volume.entry_location(entry).unwrap();
    fs.volume.node_mut(parent).unwrap().parent = parent;
    assert_eq!(fs.query_opened_name(handle), Err(STATUS_DATA_ERROR));
    fs.volume.node_mut(parent).unwrap().is_dir = false;
    assert_eq!(fs.query_opened_name(handle), Err(STATUS_DATA_ERROR));
    assert_eq!(fs.query_short_name(handle), Err(STATUS_DATA_ERROR));
}

#[test]
fn root_directory_has_checked_metadata_and_no_alternate_name() {
    let mut fs = FileSystem::new(MemFs::new());
    let root = fs.zw_create_file(
        r"\??\C:\",
        FILE_READ_DATA,
        0,
        SHARE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(root.status, STATUS_SUCCESS);
    assert!(
        fs.query_file_object_information(root.handle)
            .unwrap()
            .metadata
            .is_directory
    );
    assert_eq!(fs.query_opened_name(root.handle).unwrap(), "\\");
    assert_eq!(fs.query_short_name(root.handle), Ok(FileShortName::EMPTY));
}
