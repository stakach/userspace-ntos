use super::*;

const ACCESS: u32 = FILE_READ_DATA | FILE_WRITE_DATA;
const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

#[derive(Clone, Copy, Debug)]
enum Api {
    Absolute,
    Relative,
    Directory,
}

const APIS: [Api; 3] = [Api::Absolute, Api::Relative, Api::Directory];

fn fixture() -> (FileSystem, u64) {
    let mut fs = FileSystem::new(MemFs::new());
    fs.set_current_time_100ns(1234);
    let parent = fs.zw_create_file_relative(
        b"Parent",
        ACCESS,
        0,
        SHARE,
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(parent.status, STATUS_SUCCESS);
    (fs, parent.handle)
}

fn create(
    fs: &mut FileSystem,
    parent: u64,
    api: Api,
    disposition: u32,
    options: u32,
) -> CreateResult {
    match api {
        Api::Absolute => fs.zw_create_file(
            r"\??\C:\Parent\Target.dat",
            ACCESS,
            FILE_ATTRIBUTE_HIDDEN,
            SHARE,
            disposition,
            options,
        ),
        Api::Relative => fs.zw_create_file_relative(
            b"parent\\Target.dat",
            ACCESS,
            FILE_ATTRIBUTE_HIDDEN,
            SHARE,
            disposition,
            options,
        ),
        Api::Directory => fs.zw_create_file_relative_to_directory(
            parent,
            b"Target.dat",
            ACCESS,
            FILE_ATTRIBUTE_HIDDEN,
            SHARE,
            disposition,
            options,
        ),
    }
}

fn identities(fs: &FileSystem) -> (u64, u64, usize, usize) {
    (
        fs.volume.next_file_id,
        fs.volume.next_entry_id,
        fs.volume.nodes.len(),
        fs.handles.len(),
    )
}

fn watch(fs: &mut FileSystem, parent: u64) -> crate::DirectoryNotifyId {
    fs.zw_notify_change_directory_file(
        parent,
        crate::FILE_NOTIFY_CHANGE_FILE_NAME
            | crate::FILE_NOTIFY_CHANGE_DIR_NAME
            | crate::FILE_NOTIFY_CHANGE_SIZE
            | crate::FILE_NOTIFY_CHANGE_LAST_WRITE,
        false,
        1024,
        45,
    )
    .unwrap()
}

fn assert_failure(result: CreateResult) {
    assert_eq!(result.status, STATUS_INSUFFICIENT_RESOURCES);
    assert_eq!(result.handle, INVALID_HANDLE);
    assert_eq!(result.information, 0);
}

#[test]
fn new_file_allocation_errors_preserve_namespace_identities_handles_and_notifications() {
    for api in APIS {
        for disposition in [FILE_CREATE, FILE_OPEN_IF, FILE_OVERWRITE_IF, FILE_SUPERSEDE] {
            for stage in 0..7 {
                let (mut fs, parent) = fixture();
                let before = identities(&fs);
                let notification = watch(&mut fs, parent);
                fs.create_fail_at = Some(stage);
                assert_failure(create(
                    &mut fs,
                    parent,
                    api,
                    disposition,
                    FILE_NON_DIRECTORY_FILE,
                ));
                assert_eq!(identities(&fs), before, "{api:?}, {disposition}, {stage}");
                assert!(fs.volume.lookup(r"\Parent\Target.dat").is_none());
                assert_eq!(
                    fs.volume
                        .node(fs.obj(parent).unwrap().node_id)
                        .unwrap()
                        .children
                        .len(),
                    0
                );
                assert_eq!(fs.notifications.pending_len(), 1);
                assert!(fs.directory_notify_completion(notification).is_none());
                assert!(fs.pop_directory_notify_completion().is_none());

                let retry = create(&mut fs, parent, api, disposition, FILE_NON_DIRECTORY_FILE);
                assert_eq!(
                    (retry.status, retry.information),
                    (STATUS_SUCCESS, FILE_CREATED)
                );
                let object = fs.obj(retry.handle).unwrap();
                assert_eq!(object.entry_id, before.1);
                assert_eq!(fs.volume.node(object.node_id).unwrap().file_id, before.0);
                assert_eq!(
                    fs.zw_query_opened_name(retry.handle).as_deref(),
                    Some(r"\Parent\Target.dat")
                );
                assert!(fs.directory_notify_completion(notification).is_some());
            }
        }
    }
}

#[test]
fn existing_file_allocation_errors_never_truncate_or_publish_an_open() {
    for api in APIS {
        for disposition in [
            FILE_OPEN,
            FILE_OPEN_IF,
            FILE_OVERWRITE,
            FILE_OVERWRITE_IF,
            FILE_SUPERSEDE,
        ] {
            for stage in 0..2 {
                let (mut fs, parent) = fixture();
                let original = create(&mut fs, parent, api, FILE_CREATE, FILE_NON_DIRECTORY_FILE);
                assert_eq!(original.status, STATUS_SUCCESS);
                let bytes = b"retained data across failed open publication";
                assert_eq!(
                    fs.zw_write_file(original.handle, Some(0), bytes),
                    (STATUS_SUCCESS, bytes.len())
                );
                let node = fs.obj(original.handle).unwrap().node_id;
                assert_eq!(fs.volume.set_allocation_size(node, 8192), STATUS_SUCCESS);
                assert_eq!(
                    fs.volume.set_valid_data_length(node, bytes.len() as u64),
                    STATUS_SUCCESS
                );
                let metadata = fs.volume.metadata(node, false).unwrap();
                let before = identities(&fs);
                let entry = fs.obj(original.handle).unwrap().entry_id;
                let notification = watch(&mut fs, parent);
                fs.set_current_time_100ns(9999);
                fs.create_fail_at = Some(stage);
                assert_failure(create(
                    &mut fs,
                    parent,
                    api,
                    disposition,
                    FILE_NON_DIRECTORY_FILE,
                ));
                assert_eq!(identities(&fs), before, "{api:?}, {disposition}, {stage}");
                assert_eq!(fs.volume.metadata(node, false), Some(metadata));
                assert_eq!(fs.volume.read_at(node, 0, 1024), bytes);
                assert_eq!(fs.obj(original.handle).unwrap().entry_id, entry);
                assert_eq!(fs.notifications.pending_len(), 1);
                assert!(fs.directory_notify_completion(notification).is_none());
                assert!(fs.pop_directory_notify_completion().is_none());

                let retry = create(&mut fs, parent, api, disposition, FILE_NON_DIRECTORY_FILE);
                assert_eq!(retry.status, STATUS_SUCCESS);
                assert_eq!(fs.obj(retry.handle).unwrap().entry_id, entry);
                assert_eq!(fs.obj(retry.handle).unwrap().node_id, node);
                let truncates = matches!(
                    disposition,
                    FILE_OVERWRITE | FILE_OVERWRITE_IF | FILE_SUPERSEDE
                );
                assert_eq!(
                    fs.volume.size(node),
                    if truncates { 0 } else { bytes.len() as u64 }
                );
                assert_eq!(
                    fs.directory_notify_completion(notification).is_some(),
                    truncates
                );
            }
        }
    }
}

#[test]
fn directory_creation_allocation_errors_leave_no_child() {
    for api in APIS {
        for stage in 0..7 {
            let (mut fs, parent) = fixture();
            let before = identities(&fs);
            let notification = watch(&mut fs, parent);
            fs.create_fail_at = Some(stage);
            assert_failure(create(
                &mut fs,
                parent,
                api,
                FILE_CREATE,
                FILE_DIRECTORY_FILE,
            ));
            assert_eq!(identities(&fs), before);
            assert!(fs.volume.lookup(r"\Parent\Target.dat").is_none());
            assert!(fs.directory_notify_completion(notification).is_none());
            let retry = create(&mut fs, parent, api, FILE_CREATE, FILE_DIRECTORY_FILE);
            assert_eq!(retry.status, STATUS_SUCCESS);
            let metadata = fs
                .volume
                .metadata(fs.obj(retry.handle).unwrap().node_id, false)
                .unwrap();
            assert!(metadata.is_directory);
            assert_eq!(
                metadata.attributes,
                FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN
            );
        }
    }
}

#[test]
fn exhausted_file_or_entry_identity_does_not_publish_partial_creation() {
    for api in APIS {
        for file_identity in [false, true] {
            let (mut fs, parent) = fixture();
            if file_identity {
                fs.volume.next_file_id = u64::MAX;
            } else {
                fs.volume.next_entry_id = u64::MAX;
            }
            let before = identities(&fs);
            let notification = watch(&mut fs, parent);
            assert_failure(create(
                &mut fs,
                parent,
                api,
                FILE_CREATE,
                FILE_NON_DIRECTORY_FILE,
            ));
            assert_eq!(identities(&fs), before);
            assert!(fs.volume.lookup(r"\Parent\Target.dat").is_none());
            assert_eq!(fs.notifications.pending_len(), 1);
            assert!(fs.directory_notify_completion(notification).is_none());
            if file_identity {
                fs.volume.next_file_id -= 1;
            } else {
                fs.volume.next_entry_id -= 1;
            }
            let retry = create(&mut fs, parent, api, FILE_CREATE, FILE_NON_DIRECTORY_FILE);
            assert_eq!(retry.status, STATUS_SUCCESS);
        }
    }
}

#[test]
fn create_reuses_an_empty_handle_without_requiring_growth() {
    let (mut fs, parent) = fixture();
    let original = create(
        &mut fs,
        parent,
        Api::Relative,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(original.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_close(original.handle), STATUS_SUCCESS);
    let slots = fs.handles.len();
    fs.create_fail_at = Some(1);
    let reopened = create(
        &mut fs,
        parent,
        Api::Relative,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(reopened.status, STATUS_SUCCESS);
    assert_eq!(reopened.handle, original.handle);
    assert_eq!(fs.handles.len(), slots);
    assert_eq!(fs.zw_close(reopened.handle), STATUS_SUCCESS);
    fs.create_fail_at = Some(6);
    let new_file =
        fs.zw_create_file_relative(b"Parent\\Other.dat", ACCESS, 0, SHARE, FILE_CREATE, 0);
    assert_eq!(new_file.status, STATUS_SUCCESS);
    assert_eq!(new_file.handle, original.handle);
    assert_eq!(fs.handles.len(), slots);
}

#[test]
fn canonical_open_names_preserve_directory_aliases_and_selected_hard_links() {
    let (mut fs, parent) = fixture();
    let parent_entry = fs.obj(parent).unwrap().entry_id;
    let short: Vec<u16> = "PARENT~1".encode_utf16().collect();
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&((short.len() * 2) as u32).to_le_bytes());
    for unit in short {
        encoded.extend_from_slice(&unit.to_le_bytes());
    }
    let short = parse_short_name_information(&encoded).unwrap();
    assert_eq!(
        fs.volume.set_entry_short_name(parent_entry, short),
        STATUS_SUCCESS
    );
    let original =
        fs.zw_create_file_relative(b"parent~1\\LongName.dat", ACCESS, 0, SHARE, FILE_CREATE, 0);
    assert_eq!(original.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_query_opened_name(original.handle).as_deref(),
        Some(r"\Parent\LongName.dat")
    );
    let node = fs.obj(original.handle).unwrap().node_id;
    let parent_node = fs.obj(parent).unwrap().node_id;
    let alias_entry = fs
        .volume
        .insert_entry(parent_node, "LinkedName.dat", node)
        .unwrap();
    let alias =
        fs.zw_create_file_relative(b"PARENT~1\\LINKEDNAME.DAT", ACCESS, 0, SHARE, FILE_OPEN, 0);
    assert_eq!(alias.status, STATUS_SUCCESS);
    assert_eq!(fs.obj(alias.handle).unwrap().entry_id, alias_entry);
    assert_eq!(fs.obj(alias.handle).unwrap().node_id, node);
    assert_eq!(
        fs.zw_query_opened_name(alias.handle).as_deref(),
        Some(r"\Parent\LinkedName.dat")
    );
    let root = fs.zw_create_file_relative(b"", ACCESS, 0, SHARE, FILE_OPEN, FILE_DIRECTORY_FILE);
    assert_eq!(root.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_query_opened_name(root.handle).as_deref(), Some(r"\"));
    let root_child = fs.zw_create_file_relative_to_directory(
        root.handle,
        b"RootChild",
        ACCESS,
        0,
        SHARE,
        FILE_CREATE,
        0,
    );
    assert_eq!(root_child.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_query_opened_name(root_child.handle).as_deref(),
        Some(r"\RootChild")
    );
}
