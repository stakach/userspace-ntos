use super::*;

const LOG_PATH: &str = r"\??\C:\SOFTWARE.LOG";
const DISK_FULL: u32 = 0xC000_007F;

#[test]
fn absent_hive_log_create_refuses_full_snapshot_before_name_or_file_id() {
    let mut fs = FileSystem::new(MemFs::new());
    let before = fs.export_volume_snapshot().unwrap();
    fs.set_snapshot_payload_capacity(before.len()).unwrap();

    let opened = fs.zw_create_file(LOG_PATH, FILE_WRITE_DATA | SYNCHRONIZE, 0, 0,
        FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE);
    assert_eq!(opened.status, DISK_FULL);
    assert_eq!(opened.handle, INVALID_HANDLE);
    assert_eq!(fs.existing_file_id(LOG_PATH), None);
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
}

#[test]
fn existing_hive_log_replay_refuses_unreserved_growth_before_append() {
    let mut fs = FileSystem::new(MemFs::new());
    let opened = fs.zw_create_file(LOG_PATH, FILE_WRITE_DATA | SYNCHRONIZE, 0, 0,
        FILE_CREATE, FILE_NON_DIRECTORY_FILE);
    assert_eq!(opened.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_write_file(opened.handle, None, b"base"), (STATUS_SUCCESS, 4));
    let file_id = fs.existing_file_id(LOG_PATH).unwrap();
    let before = fs.export_volume_snapshot().unwrap();
    let offset = fs.current_offset(opened.handle);
    fs.set_snapshot_payload_capacity(before.len()).unwrap();

    let record = HiveLogWalPayload { file_id, expected_log_len: 4,
        path: LOG_PATH, record: b"HLR1 next" };
    assert!(fs.replay_hive_log_wal_payload(record).is_err(),
        "a committed record needs capacity reserved before WAL publication");
    assert_eq!(fs.existing_file_id(LOG_PATH), Some(file_id));
    assert_eq!(fs.file_bytes_owned(LOG_PATH).unwrap(), b"base");
    assert_eq!(fs.current_offset(opened.handle), offset);
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
}
