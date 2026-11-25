use super::*;
use crate::{
    decode_file_delta_wal_payload, encode_file_delta_wal_payload, FileDeltaRecord, MemFs,
};

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
