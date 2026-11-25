use super::*;
use crate::{
    decode_file_create_wal_payload, decode_file_delta_wal_payload,
    encode_file_create_wal_payload, encode_file_delta_wal_payload, FileCreateWalPayload,
    FileDeltaRecord, MemFs,
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
