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

/// What the mounted volume answers for a File it created, extended and renamed in the writable
/// layer: every query class `CopyFileW`, `DeleteFileW`, `GetFileInformationByHandle` and the
/// shell read must describe the File as it now is.
#[test]
fn query_classes_describe_a_file_created_extended_and_renamed() {
    let (mut fs, handle) = open_file(0);
    assert_eq!(fs.zw_write_file(handle, None, b"0123456789"), (STATUS_SUCCESS, 10));
    assert_eq!(
        fs.zw_set_information_file(handle, FILE_END_OF_FILE_INFORMATION, &5000u64.to_le_bytes()),
        STATUS_SUCCESS
    );
    fs.set_current_time_100ns(700);
    assert_eq!(
        fs.zw_rename_file(
            handle,
            FileRenameRoot::VolumeRoot,
            &wide_bytes(r"\Dir\Renamed.dat"),
            false,
        ),
        STATUS_SUCCESS
    );
    let info = fs.query_file_object_information(handle).unwrap();
    let name: Vec<u16> = fs.query_opened_name(handle).unwrap().encode_utf16().collect();
    assert_eq!(String::from_utf16(&name).unwrap(), r"\Dir\Renamed.dat");
    let mut query = info.metadata.query_metadata();
    query.current_byte_offset = info.current_offset;
    let u32_at = |bytes: &[u8], at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let u64_at = |bytes: &[u8], at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());

    let mut basic = [0u8; 40];
    assert_eq!(crate::encode_query_information(FILE_BASIC_INFORMATION, query, &mut basic), Ok(40));
    assert_eq!(u64_at(&basic, 0), 100, "creation time is the create's");
    assert!(u64_at(&basic, 16) >= 100, "last write time is set");
    assert_eq!(u32_at(&basic, 32), FILE_ATTRIBUTE_ARCHIVE);

    let mut standard = [0u8; 24];
    assert_eq!(
        crate::encode_query_information(crate::FILE_STANDARD_INFORMATION, query, &mut standard),
        Ok(24)
    );
    let allocation = u64_at(&standard, 0);
    assert!(allocation >= 5000);
    assert_eq!(u64_at(&standard, 8), 5000);
    assert_eq!(u32_at(&standard, 16), 1, "one link");
    assert_eq!(&standard[20..22], &[0, 0], "neither delete-pending nor a directory");

    let mut network = [0u8; 56];
    assert_eq!(
        crate::encode_query_information(crate::FILE_NETWORK_OPEN_INFORMATION, query, &mut network),
        Ok(56)
    );
    assert_eq!(&network[..32], &basic[..32]);
    assert_eq!(u64_at(&network, 32), allocation);
    assert_eq!(u64_at(&network, 40), 5000);
    assert_eq!(u32_at(&network, 48), FILE_ATTRIBUTE_ARCHIVE);

    let mut tag = [0u8; 8];
    assert_eq!(
        crate::encode_query_information(crate::FILE_ATTRIBUTE_TAG_INFORMATION, query, &mut tag),
        Ok(8)
    );
    assert_eq!((u32_at(&tag, 0), u32_at(&tag, 4)), (FILE_ATTRIBUTE_ARCHIVE, 0));

    let mut internal = [0u8; 8];
    assert_eq!(
        crate::encode_query_information(crate::FILE_INTERNAL_INFORMATION, query, &mut internal),
        Ok(8)
    );
    assert_eq!(u64::from_le_bytes(internal), info.metadata.file_id);
    assert_ne!(info.metadata.file_id, 0);

    let mut named = [0u8; 4 + 64];
    let result =
        crate::encode_named_query_information(crate::FILE_NAME_INFORMATION, query, &name, &mut named)
            .unwrap();
    assert_eq!(result.status, STATUS_SUCCESS);
    assert_eq!(result.information, 4 + name.len() * 2);
    assert_eq!(u32_at(&named, 0) as usize, name.len() * 2);
    assert_eq!(&named[4..4 + name.len() * 2], &wide_bytes(r"\Dir\Renamed.dat")[..]);

    let mut all = [0u8; 100 + 64];
    let result =
        crate::encode_named_query_information(crate::FILE_ALL_INFORMATION, query, &name, &mut all).unwrap();
    assert_eq!(result.status, STATUS_SUCCESS);
    assert_eq!(result.information, 100 + name.len() * 2);
    assert_eq!(&all[..36], &basic[..36]);
    assert_eq!(&all[40..64], &standard[..]);
    assert_eq!(&all[64..72], &internal[..]);
    assert_eq!(u32_at(&all, 96) as usize, name.len() * 2);
    assert_eq!(&all[100..100 + name.len() * 2], &wide_bytes(r"\Dir\Renamed.dat")[..]);
}
