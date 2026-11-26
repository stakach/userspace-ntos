use super::*;
use alloc::vec::Vec;

// These tests specify the pre-effect contract for a mounted snapshot slot. The limit is the
// store's payload capacity and therefore includes the serialized MemFs snapshot header.
const SNAPSHOT_CAPACITY_DISK_FULL: u32 = 0xC000_007F;

fn capacity_utf16(name: &str) -> Vec<u8> {
    name.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn snapshot_capacity_refuses_create_before_publishing_a_name_or_handle() {
    let mut fs = FileSystem::new(MemFs::new());
    let before = fs.export_volume_snapshot().unwrap();
    fs.set_snapshot_payload_capacity(before.len()).unwrap();

    let created = fs.zw_create_file(r"\??\C:\new.txt", FILE_READ_DATA | FILE_WRITE_DATA,
        0, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE);
    assert_eq!(created.status, SNAPSHOT_CAPACITY_DISK_FULL);
    assert_eq!(created.handle, INVALID_HANDLE);
    assert_eq!(created.information, 0);
    assert!(fs.query_metadata(r"\??\C:\new.txt").is_none());
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
}

#[test]
fn snapshot_capacity_refuses_write_growth_before_changing_bytes_or_file_offset() {
    let mut fs = FileSystem::new(MemFs::new());
    let opened = fs.zw_create_file(r"\??\C:\data.txt", FILE_READ_DATA | FILE_WRITE_DATA,
        0, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE);
    assert_eq!(opened.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_write_file(opened.handle, None, b"abc"), (STATUS_SUCCESS, 3));
    let before = fs.export_volume_snapshot().unwrap();
    let offset = fs.current_offset(opened.handle);
    fs.set_snapshot_payload_capacity(before.len()).unwrap();

    assert_eq!(fs.zw_write_file(opened.handle, None, b"d"),
        (SNAPSHOT_CAPACITY_DISK_FULL, 0));
    assert_eq!(fs.current_offset(opened.handle), offset);
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
    assert_eq!(fs.zw_read_file(opened.handle, Some(0), 8),
        (STATUS_SUCCESS, b"abc".to_vec()));

    // A same-size overwrite still fits: the quota concerns serialized growth.
    assert_eq!(fs.zw_write_file(opened.handle, Some(0), b"xyz"), (STATUS_SUCCESS, 3));
    assert_eq!(fs.export_volume_snapshot().unwrap().len(), before.len());
}

#[test]
fn snapshot_capacity_released_by_truncate_admits_a_later_write() {
    let mut fs = FileSystem::new(MemFs::new());
    let large = fs.zw_create_file(r"\??\C:\large.txt", FILE_WRITE_DATA,
        0, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE);
    let target = fs.zw_create_file(r"\??\C:\target.txt", FILE_WRITE_DATA,
        0, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE);
    assert_eq!((large.status, target.status), (STATUS_SUCCESS, STATUS_SUCCESS));
    assert_eq!(fs.zw_write_file(large.handle, None, b"twelve bytes"), (STATUS_SUCCESS, 12));
    let capacity = fs.export_volume_snapshot().unwrap().len();
    fs.set_snapshot_payload_capacity(capacity).unwrap();

    assert_eq!(fs.zw_write_file(target.handle, None, b"new"),
        (SNAPSHOT_CAPACITY_DISK_FULL, 0));
    assert_eq!(fs.zw_set_information_file(large.handle, FILE_END_OF_FILE_INFORMATION,
        &0u64.to_le_bytes()), STATUS_SUCCESS);
    assert_eq!(fs.zw_write_file(target.handle, None, b"new"), (STATUS_SUCCESS, 3));
    assert!(fs.export_volume_snapshot().unwrap().len() <= capacity);
}

#[test]
fn snapshot_capacity_released_by_delete_admits_a_new_name() {
    let mut fs = FileSystem::new(MemFs::new());
    let doomed = fs.zw_create_file(r"\??\C:\doomed.txt", FILE_WRITE_DATA,
        0, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE);
    assert_eq!(doomed.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_write_file(doomed.handle, None, b"payload"), (STATUS_SUCCESS, 7));
    let capacity = fs.export_volume_snapshot().unwrap().len();
    fs.set_snapshot_payload_capacity(capacity).unwrap();

    let refused = fs.zw_create_file(r"\??\C:\replacement.txt", FILE_WRITE_DATA,
        0, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE);
    assert_eq!(refused.status, SNAPSHOT_CAPACITY_DISK_FULL);
    assert_eq!(refused.handle, INVALID_HANDLE);
    assert_eq!(fs.zw_set_information_file(doomed.handle, FILE_DISPOSITION_INFORMATION, &[1]),
        STATUS_SUCCESS);
    assert_eq!(fs.zw_close(doomed.handle), STATUS_SUCCESS);
    assert!(fs.query_metadata(r"\??\C:\doomed.txt").is_none());

    let retried = fs.zw_create_file(r"\??\C:\replacement.txt", FILE_WRITE_DATA,
        0, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE);
    assert_eq!(retried.status, STATUS_SUCCESS);
    assert!(fs.export_volume_snapshot().unwrap().len() <= capacity);
}

#[test]
fn snapshot_capacity_refuses_sparse_extent_split_at_unchanged_eof() {
    let mut fs = FileSystem::new(MemFs::new());
    let opened = fs.zw_create_file(r"\??\C:\sparse.bin", FILE_READ_DATA | FILE_WRITE_DATA,
        0, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE);
    assert_eq!(opened.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_set_information_file(opened.handle, FILE_END_OF_FILE_INFORMATION,
        &4096u64.to_le_bytes()), STATUS_SUCCESS);
    let before = fs.export_volume_snapshot().unwrap();
    fs.set_snapshot_payload_capacity(before.len()).unwrap();

    // Replacing one zero byte creates two zero extents and one data extent. EOF is unchanged,
    // but the encoded snapshot grows by extent headers and the written byte.
    assert_eq!(fs.zw_write_file(opened.handle, Some(1), b"x"),
        (SNAPSHOT_CAPACITY_DISK_FULL, 0));
    assert_eq!(fs.zw_query_standard_information(opened.handle).unwrap().end_of_file, 4096);
    assert_eq!(fs.zw_read_file(opened.handle, Some(0), 3),
        (STATUS_SUCCESS, alloc::vec![0, 0, 0]));
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
}

#[test]
fn snapshot_capacity_refuses_directory_rename_that_grows_descendant_paths() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\a"));
    assert!(fs.provision_file(r"\??\C:\a\child.txt", b"data"));
    let directory = fs.zw_create_file(r"\??\C:\a", DELETE | SYNCHRONIZE,
        0, 0, FILE_OPEN, FILE_DIRECTORY_FILE);
    assert_eq!(directory.status, STATUS_SUCCESS);
    let before = fs.export_volume_snapshot().unwrap();
    fs.set_snapshot_payload_capacity(before.len()).unwrap();

    assert_eq!(fs.zw_rename_file(directory.handle, FileRenameRoot::VolumeRoot,
        &capacity_utf16(r"\longer"), false), SNAPSHOT_CAPACITY_DISK_FULL);
    assert!(fs.query_metadata(r"\??\C:\longer").is_none());
    assert_eq!(fs.file_bytes(r"\??\C:\a\child.txt"), Some(&b"data"[..]));
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
}

#[test]
fn snapshot_capacity_charges_hard_link_record_without_copying_file_data() {
    let mut fs = FileSystem::new(MemFs::new());
    let payload = alloc::vec![b'x'; 512];
    let opened = fs.zw_create_file(r"\??\C:\a.bin", FILE_READ_DATA | FILE_WRITE_DATA,
        0, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE);
    assert_eq!(opened.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_write_file(opened.handle, Some(0), &payload),
        (STATUS_SUCCESS, payload.len()));
    let before = fs.export_volume_snapshot().unwrap();

    // Derive the precise one-link budget from the same serializer, avoiding a duplicate format
    // formula in this test. A hard link adds a path record, not a second copy of the data.
    let mut reference = FileSystem::from_volume_snapshot(&before).unwrap();
    let reference_open = reference.zw_create_file(r"\??\C:\a.bin", FILE_READ_DATA,
        0, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE);
    assert_eq!(reference_open.status, STATUS_SUCCESS);
    assert_eq!(reference.zw_link_file(reference_open.handle, FileRenameRoot::VolumeRoot,
        &capacity_utf16(r"\b.bin"), false), STATUS_SUCCESS);
    let one_link_capacity = reference.export_volume_snapshot().unwrap().len();
    assert!(one_link_capacity > before.len());
    assert!(one_link_capacity - before.len() < payload.len());
    fs.set_snapshot_payload_capacity(one_link_capacity).unwrap();

    assert_eq!(fs.zw_link_file(opened.handle, FileRenameRoot::VolumeRoot,
        &capacity_utf16(r"\b.bin"), false), STATUS_SUCCESS);
    assert_eq!(fs.export_volume_snapshot().unwrap().len(), one_link_capacity);
    assert_eq!(fs.zw_link_file(opened.handle, FileRenameRoot::VolumeRoot,
        &capacity_utf16(r"\c.bin"), false), SNAPSHOT_CAPACITY_DISK_FULL);
    assert!(fs.query_metadata(r"\??\C:\c.bin").is_none());
    assert_eq!(fs.file_bytes(r"\??\C:\b.bin"), Some(payload.as_slice()));
    assert_eq!(fs.export_volume_snapshot().unwrap().len(), one_link_capacity);
}

#[test]
fn snapshot_capacity_refuses_overlay_copy_up_before_parent_or_file_is_published() {
    let mut fs = FileSystem::new(MemFs::new());
    let source = FileMetadata {
        end_of_file: 3,
        valid_data_length: 3,
        attributes: FILE_ATTRIBUTE_ARCHIVE,
        number_of_links: 1,
        ..FileMetadata::default()
    };
    let before = fs.export_volume_snapshot().unwrap();
    fs.set_snapshot_payload_capacity(before.len()).unwrap();

    let refused = fs.create_prepared_overlay_relative(
        b"windows\\system32\\state.dat", Some(b"windows\\system32"),
        Some((source, b"fat".to_vec())), FILE_READ_DATA, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(refused.status, SNAPSHOT_CAPACITY_DISK_FULL);
    assert_eq!(refused.handle, INVALID_HANDLE);
    assert_eq!(fs.query_metadata_relative(b"windows\\system32"), None);
    assert_eq!(fs.file_bytes_relative(b"windows\\system32\\state.dat"), None);
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
}

#[test]
fn snapshot_capacity_refuses_absent_hive_log_before_create_or_append() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\Windows\System32\Config"));
    let path = r"\??\C:\Windows\System32\Config\SOFTWARE.LOG";
    let before = fs.export_volume_snapshot().unwrap();
    fs.set_snapshot_payload_capacity(before.len()).unwrap();

    assert_eq!(fs.append_file_by_path(path, b"journal"), (SNAPSHOT_CAPACITY_DISK_FULL, 0));
    assert!(fs.query_metadata(path).is_none());
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
}

#[test]
fn snapshot_capacity_refuses_existing_hive_log_append_without_changing_bytes() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\Windows\System32\Config"));
    let path = r"\??\C:\Windows\System32\Config\SOFTWARE.LOG";
    assert_eq!(fs.append_file_by_path(path, b"old"), (STATUS_SUCCESS, 3));
    let before = fs.export_volume_snapshot().unwrap();
    fs.set_snapshot_payload_capacity(before.len()).unwrap();

    assert_eq!(fs.append_file_by_path(path, b"new"), (SNAPSHOT_CAPACITY_DISK_FULL, 0));
    assert_eq!(fs.file_bytes(path), Some(&b"old"[..]));
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
}

#[test]
fn snapshot_capacity_reserved_create_then_exact_wal_replay_consumes_one_charge() {
    let path = r"\??\C:\SOFTWARE.LOG";
    let record = b"HLR1 reserved mutation";
    let mut reference = FileSystem::new(MemFs::new());
    let created = reference.zw_create_file(path, FILE_READ_DATA | FILE_WRITE_DATA,
        0, 0, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE);
    assert_eq!(created.status, STATUS_SUCCESS);
    assert_eq!(reference.append_file_by_path(path, record), (STATUS_SUCCESS, record.len()));
    let capacity = reference.export_volume_snapshot().unwrap().len();

    let mut fs = FileSystem::new(MemFs::new());
    fs.set_snapshot_payload_capacity(capacity).unwrap();
    let mut token = fs.reserve_snapshot_append_by_path(path, record.len()).unwrap();
    let created = fs.zw_create_file_reserved(&mut token, path, FILE_READ_DATA | FILE_WRITE_DATA,
        0, 0, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE);
    assert_eq!(created.status, STATUS_SUCCESS);
    let file_id = fs.existing_file_id(path).unwrap();
    assert_eq!(fs.zw_create_file(r"\??\C:\other", FILE_WRITE_DATA, 0, 0,
        FILE_CREATE, FILE_NON_DIRECTORY_FILE).status, SNAPSHOT_CAPACITY_DISK_FULL);
    let payload = HiveLogWalPayload { file_id, expected_log_len: 0, path, record };
    assert!(matches!(fs.replay_hive_log_wal_payload_reserved(token, payload),
        Ok(HiveLogWalReplay::Appended)));
    assert_eq!(fs.file_bytes_owned(path).unwrap(), record);
    assert_eq!(fs.export_volume_snapshot().unwrap().len(), capacity);
}

#[test]
fn snapshot_capacity_future_replacement_updates_atomically_and_consumes_at_peak() {
    let path = r"\??\C:\SYSTEM";
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(path, b"old"));
    assert!(fs.provision_file(r"\??\C:\SYSTEM.LOG", b"old journal"));
    let opened = fs.zw_create_file(path, FILE_READ_DATA | FILE_WRITE_DATA,
        0, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE);
    assert_eq!(opened.status, STATUS_SUCCESS);
    let before = fs.export_volume_snapshot().unwrap();
    fs.set_snapshot_payload_capacity(before.len() + 3).unwrap();
    let token = fs.reserve_snapshot_replacement_by_path(path, 5).unwrap();
    let token = fs.update_snapshot_replacement_projection(token, 6).unwrap();
    let (_, token) = fs.update_snapshot_replacement_projection(token, 7).err().unwrap();
    let (_, token, data) = fs.replace_file_data_owned_reserved(token, opened.handle,
        b"wrong".to_vec()).err().unwrap();
    assert_eq!(data, b"wrong");
    assert_eq!(fs.file_bytes_owned(path).unwrap(), b"old");
    fs.replace_file_data_owned_reserved(token, opened.handle, b"newest".to_vec())
        .map_err(|(status, _, _)| status).unwrap();
    assert_eq!(fs.file_bytes_owned(path).unwrap(), b"newest");
    assert_eq!(fs.export_volume_snapshot().unwrap().len(), before.len() + 3);
}

#[test]
fn snapshot_capacity_checked_provision_refuses_entire_missing_tree() {
    let mut fs = FileSystem::new(MemFs::new());
    let before = fs.export_volume_snapshot().unwrap();
    fs.set_snapshot_payload_capacity(before.len()).unwrap();

    assert_eq!(fs.provision_file_relative_checked(b"windows\\system32\\config\\SYSTEM",
        b"hive"), Err(SNAPSHOT_CAPACITY_DISK_FULL));
    assert_eq!(fs.query_metadata_relative(b"windows"), None);
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
    assert_eq!(fs.provision_directory_relative_checked(b"windows\\system32"),
        Err(SNAPSHOT_CAPACITY_DISK_FULL));
    assert_eq!(fs.query_metadata_relative(b"windows"), None);
}

#[test]
fn snapshot_capacity_replay_rejects_unreserved_growth_without_changing_log() {
    let path = r"\??\C:\SOFTWARE.LOG";
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(path, b"base"));
    let id = fs.existing_file_id(path).unwrap();
    let before = fs.export_volume_snapshot().unwrap();
    fs.set_snapshot_payload_capacity(before.len()).unwrap();

    let record = HiveLogWalPayload {
        file_id: id, expected_log_len: 4, path, record: b"HLR1 mutation",
    };
    assert_eq!(fs.replay_hive_log_wal_payload(record),
        Err(HiveLogWalReplayError::Capacity));
    assert_eq!(fs.file_bytes_owned(path).unwrap(), b"base");
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
}

#[test]
fn snapshot_future_replacement_fences_ordinary_mutations_until_consumed_or_cancelled() {
    let path = r"\??\C:\SYSTEM";
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(path, b"old"));
    let before = fs.export_volume_snapshot().unwrap();
    fs.set_snapshot_payload_capacity(before.len() + 1).unwrap();
    let token = fs.reserve_snapshot_replacement_by_path(path, 4).unwrap();
    let opened = fs.zw_create_file(path, FILE_WRITE_DATA | DELETE | SYNCHRONIZE,
        0, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE);
    assert_eq!(opened.status, STATUS_SUCCESS);

    assert_eq!(fs.zw_write_file(opened.handle, Some(0), b"x"), (STATUS_ACCESS_DENIED, 0));
    assert_eq!(fs.zw_set_information_file(opened.handle, FILE_END_OF_FILE_INFORMATION,
        &0u64.to_le_bytes()), STATUS_ACCESS_DENIED);
    assert_eq!(fs.zw_set_information_file(opened.handle, FILE_DISPOSITION_INFORMATION,
        &[1]), STATUS_ACCESS_DENIED);
    assert_eq!(fs.zw_rename_file(opened.handle, FileRenameRoot::VolumeRoot,
        &capacity_utf16(r"\moved"), false), STATUS_ACCESS_DENIED);
    assert_eq!(fs.zw_link_file(opened.handle, FileRenameRoot::VolumeRoot,
        &capacity_utf16(r"\alias"), false), STATUS_ACCESS_DENIED);
    assert_eq!(fs.provision_file_checked(path, b"x"), Err(STATUS_ACCESS_DENIED));
    assert_eq!(fs.zw_close(opened.handle), STATUS_SUCCESS);
    assert_eq!(fs.zw_create_file(path, FILE_WRITE_DATA, 0, 0,
        FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE).status, STATUS_ACCESS_DENIED);
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);

    fs.cancel_snapshot_reservation(token).map_err(|(status, _)| status).unwrap();
    assert_eq!(fs.zw_create_file(path, FILE_WRITE_DATA, 0, 0,
        FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE).status, STATUS_SUCCESS);
}

#[test]
fn snapshot_capacity_reconciles_private_boot_replay_once_before_publication() {
    let parent = r"\??\C:\Config";
    let path = r"\??\C:\Config\new";
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(parent));
    let parent_file_id = fs.query_metadata(parent).unwrap().file_id;
    let before = fs.export_volume_snapshot().unwrap();
    fs.set_snapshot_payload_capacity(before.len() + 1024).unwrap();
    let mut cursor = crate::FileDeltaReplayCursor::new();
    let record = crate::FileCreateWalPayload {
        sequence: 1, file_id: parent_file_id + 1, parent_file_id, path,
        attributes: FILE_ATTRIBUTE_NORMAL, is_directory: false, times: [0; 4],
    };
    assert_eq!(fs.replay_file_create_wal_payload(&mut cursor, record), Ok(()));
    // An unpublished replay has a changed tree. Capture must fail closed until the one-time
    // reconciliation validates the actual image and refreshes the mounted length ledger.
    assert_eq!(fs.export_volume_snapshot(), Err(MemFsSnapshotError::InvalidRecord));
    let actual = fs.reconcile_unpublished_replay_snapshot().unwrap();
    assert!(actual > before.len());
    assert_eq!(fs.snapshot_payload_encoded_len(), Ok(actual));
    assert_eq!(fs.export_volume_snapshot().unwrap().len(), actual);
}
