use super::*;
use crate::{
    decode_file_create_wal_payload, decode_file_delta_wal_payload,
    encode_file_create_wal_payload, encode_file_delta_wal_payload, FileCreateWalPayload,
    FileDeltaRecord, FileRenameRoot, FileRenameWalPayload, FileShortName, MemFs,
};

const CONFIG: &str = r"\??\C:\ReactOS\System32\Config";
const SYSTEM: &str = r"\??\C:\ReactOS\System32\Config\SYSTEM";
const SYSTEM_LOG: &str = r"\??\C:\ReactOS\System32\Config\SYSTEM.LOG";
const SOFTWARE: &str = r"\??\C:\ReactOS\System32\Config\SOFTWARE";
const SOFTWARE_LOG: &str = r"\??\C:\ReactOS\System32\Config\SOFTWARE.LOG";

fn snapshot() -> FileSystem {
    let mut fs = FileSystem::new(MemFs::new());
    for (path, bytes) in [
        (SYSTEM, b"system primary".as_slice()),
        (SYSTEM_LOG, b"system log".as_slice()),
        (SOFTWARE, b"software primary".as_slice()),
        (SOFTWARE_LOG, b"software log".as_slice()),
    ] {
        assert!(fs.provision_file(path, bytes));
    }
    fs
}

#[test]
fn boot_replay_rejects_a_hive_append_to_the_pre_read_system_log() {
    let mut fs = snapshot();
    let before = fs.file_bytes_owned(SYSTEM_LOG).unwrap();
    let payload = HiveLogWalPayload {
        file_id: fs.existing_file_id(SYSTEM_LOG).unwrap(),
        expected_log_len: before.len() as u64,
        path: SYSTEM_LOG,
        record: b"HLR1 system mutation",
    };
    let mut replay = BootSystemPreRead::new(&fs, SYSTEM, SYSTEM_LOG);
    assert_eq!(
        replay.replay_hive_log(&mut fs, payload),
        Err(HiveLogWalReplayError::ProtectedTarget),
    );
    assert_eq!(fs.file_bytes_owned(SYSTEM_LOG), Some(before));
}

#[test]
fn boot_replay_keeps_a_different_hive_log_append_valid() {
    let mut fs = snapshot();
    let system_before = fs.file_bytes_owned(SYSTEM_LOG).unwrap();
    let payload = HiveLogWalPayload {
        file_id: fs.existing_file_id(SOFTWARE_LOG).unwrap(),
        expected_log_len: b"software log".len() as u64,
        path: SOFTWARE_LOG,
        record: b"HLR1 software mutation",
    };
    let mut replay = BootSystemPreRead::new(&fs, SYSTEM, SYSTEM_LOG);
    assert_eq!(
        replay.replay_hive_log(&mut fs, payload),
        Ok(HiveLogWalReplay::Appended),
    );
    assert_eq!(fs.file_bytes_owned(SYSTEM_LOG), Some(system_before));
    assert_eq!(
        fs.file_bytes_owned(SOFTWARE_LOG),
        Some(b"software logHLR1 software mutation".to_vec()),
    );
}

#[test]
fn boot_replay_still_refuses_file_deltas_to_either_pre_read_image() {
    let mut fs = snapshot();
    let mut replay = BootSystemPreRead::new(&fs, SYSTEM, SYSTEM_LOG);
    for path in [SYSTEM, SYSTEM_LOG] {
        let before = fs.file_bytes_owned(path).unwrap();
        let encoded = encode_file_delta_wal_payload(FileDeltaRecord {
            sequence: 1,
            file_id: fs.existing_file_id(path).unwrap(),
            path,
            end_of_file: 0,
            extents: &[],
        }).unwrap();
        let payload = decode_file_delta_wal_payload(&encoded).unwrap();
        assert_eq!(
            replay.replay_file_delta(&mut fs, payload),
            Err(FileDeltaWalReplayError::ProtectedTarget),
        );
        assert_eq!(fs.file_bytes_owned(path), Some(before));
    }
}

#[test]
fn boot_replay_refuses_pre_read_file_creation_without_consuming_the_volume_cursor() {
    let mut fs = snapshot();
    let mut replay = BootSystemPreRead::new(&fs, SYSTEM, SYSTEM_LOG);
    let parent_file_id = fs.query_metadata(CONFIG).unwrap().file_id;
    for path in [SYSTEM, SYSTEM_LOG] {
        let metadata = fs.query_metadata(path).unwrap();
        let bytes_before = fs.file_bytes_owned(path).unwrap();
        let encoded = encode_file_create_wal_payload(FileCreateWalPayload {
            sequence: 1,
            file_id: metadata.file_id,
            parent_file_id,
            path,
            attributes: metadata.attributes,
            is_directory: false,
            times: [
                metadata.creation_time,
                metadata.last_access_time,
                metadata.last_write_time,
                metadata.change_time,
            ],
        }).unwrap();
        let payload = decode_file_create_wal_payload(&encoded).unwrap();
        assert_eq!(
            replay.replay_file_create(&mut fs, payload),
            Err(FileDeltaWalReplayError::ProtectedTarget),
        );
        assert_eq!(replay.file_delta_cursor.last_applied(), None);
        assert_eq!(fs.file_bytes_owned(path), Some(bytes_before));
    }
    // A different first record must still be able to take sequence one.
    let encoded = encode_file_delta_wal_payload(FileDeltaRecord {
        sequence: 1,
        file_id: fs.existing_file_id(SOFTWARE).unwrap(),
        path: SOFTWARE,
        end_of_file: 0,
        extents: &[],
    }).unwrap();
    assert_eq!(
        replay.replay_file_delta(&mut fs, decode_file_delta_wal_payload(&encoded).unwrap()),
        Ok(()),
    );
    assert_eq!(replay.file_delta_cursor.last_applied(), Some(1));
}

#[test]
fn boot_rename_refuses_pre_read_identity_alias_and_target_path_without_advancing() {
    const ALIAS: &str = r"\??\C:\ReactOS\System32\Config\SYSTEM_ALIAS";
    let mut fs = snapshot();
    let opened = fs.zw_create_file(
        SYSTEM, crate::DELETE | crate::SYNCHRONIZE, 0,
        crate::FILE_SHARE_READ | crate::FILE_SHARE_WRITE | crate::FILE_SHARE_DELETE,
        crate::FILE_OPEN, crate::FILE_OPEN_FOR_BACKUP_INTENT,
    );
    assert_eq!(opened.status, crate::STATUS_SUCCESS);
    let link: alloc::vec::Vec<u8> = r"\ReactOS\System32\Config\SYSTEM_ALIAS"
        .encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(fs.zw_link_file(opened.handle, FileRenameRoot::VolumeRoot, &link, false),
        crate::STATUS_SUCCESS);
    assert_eq!(fs.zw_close(opened.handle), crate::STATUS_SUCCESS);
    let config_id = fs.query_metadata(CONFIG).unwrap().file_id;
    let system_id = fs.existing_file_id(SYSTEM).unwrap();
    let software_id = fs.existing_file_id(SOFTWARE).unwrap();
    let before = fs.export_volume_snapshot().unwrap();
    let mut replay = BootSystemPreRead::new(&fs, SYSTEM, SYSTEM_LOG);
    let alias_source = FileRenameWalPayload {
        sequence: 1,
        source_file_id: system_id,
        source_parent_file_id: config_id,
        target_parent_file_id: config_id,
        replaced_file_id: software_id,
        source_path: ALIAS,
        target_path: SOFTWARE,
        moved_short_name: FileShortName::EMPTY,
        change_time: fs.query_metadata(SYSTEM).unwrap().change_time + 1,
    };
    assert_eq!(replay.replay_file_rename(&mut fs, alias_source),
        Err(FileDeltaWalReplayError::ProtectedTarget));
    let protected_target = FileRenameWalPayload {
        source_file_id: software_id,
        replaced_file_id: 0, // even a forged ID cannot bypass the protected name
        source_path: SOFTWARE,
        target_path: SYSTEM,
        ..alias_source
    };
    assert_eq!(replay.replay_file_rename(&mut fs, protected_target),
        Err(FileDeltaWalReplayError::ProtectedTarget));
    assert_eq!(replay.file_delta_cursor.last_applied(), None);
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
}

#[test]
fn boot_rename_refuses_directory_containing_pre_read_system() {
    let mut fs = snapshot();
    let parent = r"\??\C:\ReactOS\System32";
    let target = r"\??\C:\ReactOS\System32\ConfigMoved";
    let before = fs.export_volume_snapshot().unwrap();
    let mut replay = BootSystemPreRead::new(&fs, SYSTEM, SYSTEM_LOG);
    let config = fs.query_metadata(CONFIG).unwrap();
    let parent_id = fs.query_metadata(parent).unwrap().file_id;
    let record = FileRenameWalPayload {
        sequence: 1,
        source_file_id: config.file_id,
        source_parent_file_id: parent_id,
        target_parent_file_id: parent_id,
        replaced_file_id: 0,
        source_path: CONFIG,
        target_path: target,
        moved_short_name: FileShortName::EMPTY,
        change_time: config.change_time + 1,
    };
    assert_eq!(replay.replay_file_rename(&mut fs, record),
        Err(FileDeltaWalReplayError::ProtectedTarget));
    assert_eq!(replay.file_delta_cursor.last_applied(), None);
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
    assert_eq!(fs.file_bytes_owned(SYSTEM), Some(b"system primary".to_vec()));
}

#[test]
fn boot_rename_refuses_directory_containing_a_pre_read_hard_link() {
    const ALIAS_DIR: &str = r"\??\C:\ReactOS\System32\AliasDir";
    let mut fs = snapshot();
    assert!(fs.provision_directory(ALIAS_DIR));
    let opened = fs.zw_create_file(
        SYSTEM, crate::DELETE | crate::SYNCHRONIZE, 0,
        crate::FILE_SHARE_READ | crate::FILE_SHARE_WRITE | crate::FILE_SHARE_DELETE,
        crate::FILE_OPEN, crate::FILE_OPEN_FOR_BACKUP_INTENT,
    );
    assert_eq!(opened.status, crate::STATUS_SUCCESS);
    let link: alloc::vec::Vec<u8> = r"\ReactOS\System32\AliasDir\SYSTEM_LINK"
        .encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(fs.zw_link_file(opened.handle, FileRenameRoot::VolumeRoot, &link, false),
        crate::STATUS_SUCCESS);
    assert_eq!(fs.zw_close(opened.handle), crate::STATUS_SUCCESS);
    let before = fs.export_volume_snapshot().unwrap();
    let parent_id = fs.query_metadata(r"\??\C:\ReactOS\System32").unwrap().file_id;
    let alias_dir = fs.query_metadata(ALIAS_DIR).unwrap();
    let mut replay = BootSystemPreRead::new(&fs, SYSTEM, SYSTEM_LOG);
    let record = FileRenameWalPayload {
        sequence: 1,
        source_file_id: alias_dir.file_id,
        source_parent_file_id: parent_id,
        target_parent_file_id: parent_id,
        replaced_file_id: 0,
        source_path: ALIAS_DIR,
        target_path: r"\??\C:\ReactOS\System32\AliasDirMoved",
        moved_short_name: FileShortName::EMPTY,
        change_time: alias_dir.change_time + 1,
    };
    assert_eq!(replay.replay_file_rename(&mut fs, record),
        Err(FileDeltaWalReplayError::ProtectedTarget));
    assert_eq!(replay.file_delta_cursor.last_applied(), None);
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
}

#[test]
fn rename_replay_refuses_exact_protected_wal_log_target() {
    let mut fs = snapshot();
    let log_id = fs.existing_file_id(SOFTWARE_LOG).unwrap();
    fs.protect_wal_log(SOFTWARE_LOG, log_id).unwrap();
    let config_id = fs.query_metadata(CONFIG).unwrap().file_id;
    let record = FileRenameWalPayload {
        sequence: 1,
        source_file_id: fs.existing_file_id(SOFTWARE).unwrap(),
        source_parent_file_id: config_id,
        target_parent_file_id: config_id,
        replaced_file_id: log_id,
        source_path: SOFTWARE,
        target_path: SOFTWARE_LOG,
        moved_short_name: FileShortName::EMPTY,
        change_time: fs.query_metadata(SOFTWARE).unwrap().change_time + 1,
    };
    let before = fs.export_volume_snapshot().unwrap();
    let mut cursor = crate::VolumeWalReplayCursor::new();
    assert_eq!(fs.replay_file_rename_wal_payload(&mut cursor, record),
        Err(FileDeltaWalReplayError::ProtectedTarget));
    assert_eq!(cursor.last_applied(), None);
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
}
