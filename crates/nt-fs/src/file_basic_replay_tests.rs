use crate::snapshot_test_device::CachedDisk;
use crate::{
    decode_volume_wal_payload, encode_file_basic_wal_payload, BootSystemPreRead,
    FileBasicWalPayload, FileDeltaWalReplayError, FileMetadata, FileSystem, MemFs,
    RegistryWal, RegistryWalState, VolumeWalPayload, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_BASIC_INFORMATION,
    FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_SHARE_READ, FILE_WRITE_DATA, STATUS_SUCCESS,
};
use crate::volume_wal_sequence::VolumeWalReplayCursor;

const FILE: &str = r"\??\C:\ReactOS\System32\Config\SOFTWARE";
const OTHER: &str = r"\??\C:\ReactOS\System32\Config\OTHER";
const DIRECTORY: &str = r"\??\C:\ReactOS\System32\Config";
const SYSTEM: &str = r"\??\C:\ReactOS\System32\Config\SYSTEM";
const SYSTEM_LOG: &str = r"\??\C:\ReactOS\System32\Config\SYSTEM.LOG";
const INCARNATION: u64 = 77;

fn state<'a>(sequence: u64, path: &'a str, metadata: FileMetadata) -> FileBasicWalPayload<'a> {
    FileBasicWalPayload {
        sequence, file_id: metadata.file_id, path, attributes: metadata.attributes,
        times: [metadata.creation_time, metadata.last_access_time,
            metadata.last_write_time, metadata.change_time],
    }
}

fn set_basic(fs: &mut FileSystem, times: [u64; 4], attributes: u32) -> FileMetadata {
    let opened = fs.zw_create_file(
        FILE, FILE_WRITE_DATA, 0, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(opened.status, STATUS_SUCCESS);
    let mut basic = [0u8; 40];
    for (index, time) in times.into_iter().enumerate() {
        basic[index * 8..index * 8 + 8].copy_from_slice(&time.to_le_bytes());
    }
    basic[32..36].copy_from_slice(&attributes.to_le_bytes());
    assert_eq!(fs.zw_set_information_file(opened.handle, FILE_BASIC_INFORMATION, &basic),
        STATUS_SUCCESS);
    assert_eq!(fs.zw_close(opened.handle), STATUS_SUCCESS);
    fs.query_metadata(FILE).unwrap()
}

fn append(wal: &mut RegistryWal<CachedDisk>, payload: &[u8]) {
    wal.begin(payload.to_vec()).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
}

fn recover_after_power_cut(mut disk: CachedDisk) -> RegistryWal<CachedDisk> {
    disk.power_cut();
    let mut wal = RegistryWal::recover(disk, INCARNATION).unwrap();
    if wal.state() == RegistryWalState::RecoveredUncommitted {
        wal.clear_recovered_tail().unwrap();
    }
    wal
}

#[test]
fn resolved_basic_info_recovers_from_each_selected_snapshot_base() {
    let mut live = FileSystem::new(MemFs::new());
    assert!(live.initialize_timestamps(100));
    assert!(live.provision_file(FILE, b"unchanged hive bytes"));
    let file_id = live.existing_file_id(FILE).unwrap();
    let initial = live.query_metadata(FILE).unwrap();
    let before = live.export_volume_snapshot().unwrap();
    let first = set_basic(&mut live, [11, 12, 13, 14],
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY);
    let after_first = live.export_volume_snapshot().unwrap();
    let second = set_basic(&mut live, [21, 22, 23, 24], FILE_ATTRIBUTE_HIDDEN);
    let after_second = live.export_volume_snapshot().unwrap();
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(64), INCARNATION).unwrap();
    append(&mut wal, &encode_file_basic_wal_payload(state(1, FILE, first)).unwrap());
    append(&mut wal, &encode_file_basic_wal_payload(state(2, FILE, second)).unwrap());
    let wal = recover_after_power_cut(wal.into_device().unwrap());
    assert_eq!(wal.records().len(), 2);

    for (snapshot, selected_base_serial) in [
        (&before, 0usize), (&after_first, 1), (&after_second, 2),
    ] {
        let mut restored = FileSystem::from_volume_snapshot(snapshot).unwrap();
        let mut pre_read = BootSystemPreRead::new(&restored, SYSTEM, SYSTEM_LOG);
        for record in &wal.records()[selected_base_serial..] {
            let VolumeWalPayload::FileBasic(payload) =
                decode_volume_wal_payload(&record.payload).unwrap()
            else {
                panic!("basic-info WAL record must retain its typed route");
            };
            assert_eq!(pre_read.replay_file_basic(&mut restored, payload), Ok(()));
        }
        assert_eq!(restored.query_metadata(FILE), Some(second));
        assert_eq!(restored.existing_file_id(FILE), Some(file_id));
        assert_eq!(restored.file_bytes_owned(FILE), Some(b"unchanged hive bytes".to_vec()));
    }

    let record = encode_file_basic_wal_payload(state(1, FILE, first)).unwrap();
    let mut uncommitted = RegistryWal::recover(CachedDisk::with_sectors(64), INCARNATION).unwrap();
    uncommitted.begin(record).unwrap();
    uncommitted.prepare().unwrap();
    assert!(recover_after_power_cut(uncommitted.into_device_for_test()).records().is_empty());
    assert_eq!(FileSystem::from_volume_snapshot(&before).unwrap().query_metadata(FILE), Some(initial));
}

#[test]
fn basic_info_replay_refuses_foreign_protected_and_gapped_records_without_consuming_order() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(FILE, b"content"));
    assert!(fs.provision_file(OTHER, b"other"));
    let before = fs.export_volume_snapshot().unwrap();
    let metadata = fs.query_metadata(FILE).unwrap();
    let record = FileBasicWalPayload {
        sequence: 1, file_id: metadata.file_id, path: FILE,
        attributes: FILE_ATTRIBUTE_HIDDEN, times: [11, 12, 13, 14],
    };
    let mut cursor = VolumeWalReplayCursor::new();
    for foreign in [
        FileBasicWalPayload { file_id: metadata.file_id + 100, ..record },
        FileBasicWalPayload { path: OTHER, ..record },
        FileBasicWalPayload { attributes: FILE_ATTRIBUTE_DIRECTORY, ..record },
    ] {
        assert_eq!(fs.replay_file_basic_wal_payload(&mut cursor, foreign),
            Err(FileDeltaWalReplayError::ForeignIdentity));
        assert_eq!(cursor.last_applied(), None);
        assert_eq!(fs.export_volume_snapshot().unwrap(), before);
    }
    let mut pre_read = BootSystemPreRead::new(&fs, FILE, SYSTEM_LOG);
    assert_eq!(pre_read.replay_file_basic(&mut fs, record),
        Err(FileDeltaWalReplayError::ProtectedTarget));
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
    let other = FileBasicWalPayload {
        sequence: 1, file_id: fs.existing_file_id(OTHER).unwrap(), path: OTHER,
        attributes: FILE_ATTRIBUTE_READONLY, times: [21, 22, 23, 24],
    };
    assert_eq!(pre_read.replay_file_basic(&mut fs, other), Ok(()));
    assert_eq!(fs.query_metadata(OTHER).unwrap().attributes, FILE_ATTRIBUTE_READONLY);

    assert_eq!(fs.replay_file_basic_wal_payload(&mut cursor, record), Ok(()));
    let applied = fs.export_volume_snapshot().unwrap();
    assert_eq!(fs.replay_file_basic_wal_payload(
        &mut cursor, FileBasicWalPayload { sequence: 3, ..record }),
        Err(FileDeltaWalReplayError::OutOfOrder));
    assert_eq!(cursor.last_applied(), Some(1));
    assert_eq!(fs.export_volume_snapshot().unwrap(), applied);
    assert_eq!(fs.replay_file_basic_wal_payload(
        &mut cursor, FileBasicWalPayload {
            sequence: 2, attributes: FILE_ATTRIBUTE_NORMAL,
            times: [31, 32, 33, 34], ..record
        }),
        Ok(()));
    assert_eq!(cursor.last_applied(), Some(2));
    assert_eq!(fs.query_metadata(FILE).unwrap().change_time, 34);
    assert_eq!(fs.query_metadata(FILE).unwrap().attributes, FILE_ATTRIBUTE_NORMAL);
}

#[test]
fn basic_info_replay_updates_directory_metadata_without_creating_an_entry() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(DIRECTORY));
    let id = fs.query_metadata(DIRECTORY).unwrap().file_id;
    let mut cursor = VolumeWalReplayCursor::new();
    assert_eq!(fs.replay_file_basic_wal_payload(&mut cursor, FileBasicWalPayload {
        sequence: 1, file_id: id, path: DIRECTORY,
        attributes: FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN,
        times: [11, 12, 13, 14],
    }), Ok(()));
    let metadata = fs.query_metadata(DIRECTORY).unwrap();
    assert_eq!((metadata.file_id, metadata.attributes, metadata.creation_time,
        metadata.last_access_time, metadata.last_write_time, metadata.change_time),
        (id, FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN, 11, 12, 13, 14));
}
