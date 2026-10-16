use super::*;

const LOG: &str = r"\??\C:\Config\SOFTWARE.LOG";

fn fixture() -> (FileSystem, u64) {
    let mut volume = MemFs::new();
    let config = volume.create_child(0, "Config", true);
    volume.create_child(config, "SOFTWARE.LOG", false);
    let fs = FileSystem::new(volume);
    let file_id = fs.existing_file_id(LOG).unwrap();
    (fs, file_id)
}

fn utf16(name: &str) -> Vec<u8> {
    name.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn protected_log_refuses_generic_content_changes_but_allows_exact_wal_replay() {
    let (mut fs, file_id) = fixture();
    fs.protect_wal_log(LOG, file_id).unwrap();
    let opened = fs.zw_create_file(
        LOG, FILE_WRITE_DATA | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(opened.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_write_file(opened.handle, None, b"wrong"), (STATUS_ACCESS_DENIED, 0));
    assert_eq!(fs.zw_append_file(opened.handle, b"wrong"), (STATUS_ACCESS_DENIED, 0));
    assert_eq!(fs.append_file_by_path(LOG, b"wrong"), (STATUS_ACCESS_DENIED, 0));
    assert_eq!(fs.replace_file_data_owned(opened.handle, b"wrong".to_vec()), STATUS_ACCESS_DENIED);
    assert_eq!(
        fs.zw_set_information_file(opened.handle, FILE_END_OF_FILE_INFORMATION, &0u64.to_le_bytes()),
        STATUS_ACCESS_DENIED,
    );
    assert_eq!(
        fs.zw_set_information_file(opened.handle, FILE_DISPOSITION_INFORMATION, &[1]),
        STATUS_ACCESS_DENIED,
    );
    assert_eq!(fs.zw_close(opened.handle), STATUS_SUCCESS);
    assert_eq!(
        fs.zw_create_file(LOG, FILE_WRITE_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0,
            FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE).status,
        STATUS_ACCESS_DENIED,
    );
    let payload = HiveLogWalPayload {
        file_id, expected_log_len: 0, path: LOG, record: b"durable",
    };
    assert_eq!(fs.replay_hive_log_wal_payload(payload), Ok(HiveLogWalReplay::Appended));
    assert_eq!(fs.replay_hive_log_wal_payload(payload), Ok(HiveLogWalReplay::AlreadyPresent));
    assert_eq!(fs.try_file_bytes_owned(LOG).unwrap(), Some(b"durable".to_vec()));
    fs.release_wal_log_protection_after_fold();
    let reopened = fs.zw_create_file(LOG, FILE_WRITE_DATA | SYNCHRONIZE, 0, 0,
        FILE_OPEN, FILE_NON_DIRECTORY_FILE);
    assert_eq!(reopened.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_append_file(reopened.handle, b"next"), (STATUS_SUCCESS, 4));
}

#[test]
fn protected_log_refuses_name_changes_and_parent_rename() {
    let (mut fs, file_id) = fixture();
    let other = fs.zw_create_file(
        r"\??\C:\Config\other.txt", FILE_WRITE_DATA | SYNCHRONIZE, 0, 0,
        FILE_CREATE, FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(other.status, STATUS_SUCCESS);
    let log = fs.zw_create_file(LOG, FILE_WRITE_DATA | SYNCHRONIZE, 0, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE);
    assert_eq!(log.status, STATUS_SUCCESS);
    let directory = fs.zw_create_file(
        r"\??\C:\Config", FILE_READ_DATA | SYNCHRONIZE, 0, 0, FILE_OPEN, FILE_DIRECTORY_FILE,
    );
    assert_eq!(directory.status, STATUS_SUCCESS);
    fs.protect_wal_log(LOG, file_id).unwrap();
    assert_eq!(
        fs.zw_rename_file(log.handle, FileRenameRoot::SourceParent, &utf16("moved.LOG"), false),
        STATUS_ACCESS_DENIED,
    );
    assert_eq!(
        fs.zw_rename_file(other.handle, FileRenameRoot::SourceParent, &utf16("SOFTWARE.LOG"), true),
        STATUS_ACCESS_DENIED,
    );
    assert_eq!(
        fs.zw_link_file(other.handle, FileRenameRoot::SourceParent, &utf16("SOFTWARE.LOG"), true),
        STATUS_ACCESS_DENIED,
    );
    assert_eq!(
        fs.zw_rename_file(directory.handle, FileRenameRoot::VolumeRoot, &utf16("Moved"), false),
        STATUS_ACCESS_DENIED,
    );
    assert_eq!(fs.existing_file_id(LOG), Some(file_id));
}

#[test]
fn protect_rejects_an_existing_delete_pending_owner() {
    let (mut fs, file_id) = fixture();
    let opened = fs.zw_create_file(LOG, 0x0001_0000 | SYNCHRONIZE, 0, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE);
    assert_eq!(opened.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_set_information_file(opened.handle, FILE_DISPOSITION_INFORMATION, &[1]),
        STATUS_SUCCESS,
    );
    assert_eq!(fs.protect_wal_log(LOG, file_id), Err(STATUS_ACCESS_DENIED));
}
