use alloc::vec;
use alloc::vec::Vec;

use crate::file_delta_wal_payload::{
    changed_file_delta_extents, decode_file_delta_wal_payload, encode_file_delta_wal_payload,
    FileDeltaExtent, FileDeltaRecord, FileDeltaReplayCursor, FileDeltaWalReplayError,
};
use crate::snapshot_test_device::CachedDisk;
use crate::{
    decode_volume_wal_payload, encode_file_create_wal_payload, encode_file_rename_wal_payload,
    encode_hive_log_wal_payload, BootSystemPreRead, FileCreateWalPayload, FileRenameWalPayload,
    FileSystem, HiveLogWalPayload, MemFs,
    RegistryWal, RegistryWalError, RegistryWalState, VolumeWalPayload,
};

const FILE: &str = r"\??\C:\ReactOS\System32\Config\SOFTWARE";
const DIRECTORY: &str = r"\??\C:\ReactOS\System32\Config";
const LOG: &str = r"\??\C:\ReactOS\System32\Config\SOFTWARE.LOG";
const CREATED_DIRECTORY: &str = r"\??\C:\ReactOS\System32\Config\NewDirectory";
const CREATED_CHILD: &str = r"\??\C:\ReactOS\System32\Config\NewDirectory\Child";

fn volume_with(bytes: &[u8]) -> FileSystem {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(FILE, bytes));
    fs
}

fn contents(fs: &FileSystem) -> Vec<u8> {
    fs.file_bytes_owned(FILE).unwrap()
}

fn restored_copy(fs: &FileSystem) -> FileSystem {
    FileSystem::from_volume_snapshot(&fs.export_volume_snapshot().unwrap()).unwrap()
}

fn creation_record<'a>(
    fs: &FileSystem,
    sequence: u64,
    path: &'a str,
    parent: &str,
) -> FileCreateWalPayload<'a> {
    let metadata = fs.query_metadata(path).unwrap();
    FileCreateWalPayload {
        sequence,
        file_id: metadata.file_id,
        parent_file_id: fs.query_metadata(parent).unwrap().file_id,
        path,
        attributes: metadata.attributes,
        is_directory: metadata.is_directory,
        times: [
            metadata.creation_time,
            metadata.last_access_time,
            metadata.last_write_time,
            metadata.change_time,
        ],
    }
}

fn encoded(fs: &FileSystem, sequence: u64, end_of_file: u64, extents: &[FileDeltaExtent<'_>]) -> Vec<u8> {
    encode_file_delta_wal_payload(FileDeltaRecord {
        sequence,
        file_id: fs.existing_file_id(FILE).unwrap(),
        path: FILE,
        end_of_file,
        extents,
    }).unwrap()
}

/// The record a producer would log to move the file from `old` to `new`.
fn transition(fs: &FileSystem, sequence: u64, old: &[u8], new: &[u8]) -> Vec<u8> {
    let extents = changed_file_delta_extents(old, new).unwrap();
    encoded(fs, sequence, new.len() as u64, &extents)
}

fn replay(
    fs: &mut FileSystem,
    cursor: &mut FileDeltaReplayCursor,
    record: &[u8],
) -> Result<(), FileDeltaWalReplayError> {
    fs.replay_file_delta_wal_payload(cursor, decode_file_delta_wal_payload(record).unwrap())
}

#[test]
fn replay_overwrites_extends_and_truncates_to_the_recorded_length() {
    let mut fs = volume_with(b"0123456789");
    let mut cursor = FileDeltaReplayCursor::new();

    let overwrite = encoded(&fs, 1, 10, &[FileDeltaExtent { offset: 2, bytes: b"AB" }]);
    assert_eq!(replay(&mut fs, &mut cursor, &overwrite), Ok(()));
    assert_eq!(contents(&fs), b"01AB456789");

    // A write beyond the old end zero-fills the gap and the unwritten tail.
    let extend = encoded(&fs, 2, 20, &[FileDeltaExtent { offset: 14, bytes: b"XY" }]);
    assert_eq!(replay(&mut fs, &mut cursor, &extend), Ok(()));
    assert_eq!(contents(&fs), b"01AB456789\0\0\0\0XY\0\0\0\0");

    let truncate = encoded(&fs, 3, 3, &[]);
    assert_eq!(replay(&mut fs, &mut cursor, &truncate), Ok(()));
    assert_eq!(contents(&fs), b"01A");
    assert_eq!(fs.file_len(FILE), Some(3));
    assert_eq!(cursor.last_applied(), Some(3));
}

#[test]
fn replayed_volume_survives_a_snapshot_round_trip() {
    let mut fs = volume_with(&[7u8; 2048]);
    let mut cursor = FileDeltaReplayCursor::new();
    let record = encoded(&fs, 1, 3000, &[FileDeltaExtent { offset: 1024, bytes: &[9u8; 600] }]);
    assert_eq!(replay(&mut fs, &mut cursor, &record), Ok(()));

    let mut expected = vec![7u8; 2048];
    expected[1024..1624].fill(9);
    expected.resize(3000, 0);
    assert_eq!(contents(&fs), expected);
    assert_eq!(contents(&restored_copy(&fs)), expected);
}

/// A committed creation must precede its content delta when the selected snapshot predates both.
#[test]
fn committed_delta_recovers_a_new_file_and_its_metadata_from_an_older_snapshot() {
    let mut live = FileSystem::new(MemFs::new());
    assert!(live.provision_directory(DIRECTORY));
    let base = live.export_volume_snapshot().unwrap();
    let created = live.zw_create_file(
        FILE, crate::FILE_WRITE_DATA, crate::FILE_ATTRIBUTE_HIDDEN, 0,
        crate::FILE_CREATE, crate::FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(created.status, crate::STATUS_SUCCESS);
    let created_metadata = live.query_metadata(FILE).unwrap();
    assert_eq!(live.zw_write_file(created.handle, None, b"new hive"), (crate::STATUS_SUCCESS, 8));
    assert_eq!(live.zw_close(created.handle), crate::STATUS_SUCCESS);
    let written_metadata = live.query_metadata(FILE).unwrap();
    let contents = live.file_bytes_owned(FILE).unwrap();
    let extents = changed_file_delta_extents(&[], &contents).unwrap();
    let creation = encode_file_create_wal_payload(FileCreateWalPayload {
        sequence: 1,
        file_id: created_metadata.file_id,
        parent_file_id: live.query_metadata(DIRECTORY).unwrap().file_id,
        path: FILE,
        attributes: created_metadata.attributes,
        is_directory: false,
        times: [created_metadata.creation_time, created_metadata.last_access_time,
            created_metadata.last_write_time, created_metadata.change_time],
    }).unwrap();
    let encoded = encode_file_delta_wal_payload(FileDeltaRecord {
        sequence: 2,
        file_id: written_metadata.file_id,
        path: FILE,
        end_of_file: contents.len() as u64,
        extents: &extents,
    }).unwrap();
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(64), INCARNATION).unwrap();
    append(&mut wal, &creation);
    append(&mut wal, &encoded);
    let wal = recover_after_power_cut(wal.into_device().unwrap());

    let mut restored = FileSystem::from_volume_snapshot(&base).unwrap();
    assert_eq!(
        restored.query_metadata(DIRECTORY).unwrap().file_id,
        live.query_metadata(DIRECTORY).unwrap().file_id,
    );
    let mut replay = BootSystemPreRead::new(
        &restored,
        r"\??\C:\ReactOS\System32\Config\SYSTEM",
        r"\??\C:\ReactOS\System32\Config\SYSTEM.LOG",
    );
    assert_eq!(wal.records().len(), 2);
    for record in wal.records() {
        match decode_volume_wal_payload(&record.payload).unwrap() {
            VolumeWalPayload::FileCreate(payload) => {
                assert_eq!(replay.replay_file_create(&mut restored, payload), Ok(()));
            }
            VolumeWalPayload::FileDelta(payload) => {
                assert_eq!(replay.replay_file_delta(&mut restored, payload), Ok(()));
            }
            other => panic!("committed payload routed as {other:?}"),
        }
    }
    assert_eq!(restored.file_bytes_owned(FILE), Some(contents));
    let recovered_metadata = restored.query_metadata(FILE).unwrap();
    assert_eq!(recovered_metadata.file_id, created_metadata.file_id);
    assert_eq!(recovered_metadata.attributes, created_metadata.attributes);
    assert_eq!(recovered_metadata.is_directory, created_metadata.is_directory);
    assert_eq!(recovered_metadata.creation_time, created_metadata.creation_time);
    assert_eq!(recovered_metadata.end_of_file, written_metadata.end_of_file);
    assert_eq!(recovered_metadata.valid_data_length, written_metadata.valid_data_length);
    assert_eq!(recovered_metadata.allocation_size, written_metadata.allocation_size);
    // FileDelta records contain bytes and EOF, not the final write/change timestamps.
    let sibling = r"\??\C:\ReactOS\System32\Config\NEXT";
    assert!(live.provision_file(sibling, b""));
    assert!(restored.provision_file(sibling, b""));
    assert_eq!(restored.existing_file_id(sibling), live.existing_file_id(sibling));
}

#[test]
fn create_then_delta_replays_from_both_intermediate_snapshot_positions() {
    let mut live = FileSystem::new(MemFs::new());
    assert!(live.provision_directory(DIRECTORY));
    let opened = live.zw_create_file(
        FILE, crate::FILE_WRITE_DATA, crate::FILE_ATTRIBUTE_HIDDEN, 0,
        crate::FILE_CREATE, crate::FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(opened.status, crate::STATUS_SUCCESS);
    let creation = encode_file_create_wal_payload(creation_record(&live, 1, FILE, DIRECTORY)).unwrap();
    let after_create = live.export_volume_snapshot().unwrap();
    assert_eq!(live.zw_write_file(opened.handle, None, b"later bytes"), (crate::STATUS_SUCCESS, 11));
    assert_eq!(live.zw_close(opened.handle), crate::STATUS_SUCCESS);
    let bytes = live.file_bytes_owned(FILE).unwrap();
    let extents = changed_file_delta_extents(&[], &bytes).unwrap();
    let delta = encode_file_delta_wal_payload(FileDeltaRecord {
        sequence: 2, file_id: live.existing_file_id(FILE).unwrap(), path: FILE,
        end_of_file: bytes.len() as u64, extents: &extents,
    }).unwrap();
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(64), INCARNATION).unwrap();
    append(&mut wal, &creation);
    append(&mut wal, &delta);
    let wal = recover_after_power_cut(wal.into_device().unwrap());
    assert_eq!(wal.records().len(), 2);

    // A later snapshot can already include the creation. Replay must not allocate another ID
    // whether it sees only the remaining suffix or the full anchored WAL.
    let sibling = r"\??\C:\ReactOS\System32\Config\After";
    assert!(live.provision_file(sibling, b""));
    for suffix_start in [0, 1] {
        let mut restored = FileSystem::from_volume_snapshot(&after_create).unwrap();
        let mut replay = BootSystemPreRead::new(
            &restored,
            r"\??\C:\ReactOS\System32\Config\SYSTEM",
            r"\??\C:\ReactOS\System32\Config\SYSTEM.LOG",
        );
        for record in &wal.records()[suffix_start..] {
            match decode_volume_wal_payload(&record.payload).unwrap() {
                VolumeWalPayload::FileCreate(payload) => {
                    assert_eq!(replay.replay_file_create(&mut restored, payload), Ok(()));
                }
                VolumeWalPayload::FileDelta(payload) => {
                    assert_eq!(replay.replay_file_delta(&mut restored, payload), Ok(()));
                }
                other => panic!("committed payload routed as {other:?}"),
            }
        }
        assert_eq!(restored.file_bytes_owned(FILE), Some(bytes.clone()));
        assert_eq!(restored.query_metadata(FILE).unwrap().file_id, live.query_metadata(FILE).unwrap().file_id);
        assert!(restored.provision_file(sibling, b""));
        assert_eq!(restored.existing_file_id(sibling), live.existing_file_id(sibling));
    }
}

/// LiberNT's SaveDefaultUserHive retries RegSaveKeyExW after replacing an existing .bak with
/// MoveFileExW. A content-only or create-only WAL cannot reconstruct that namespace mutation.
#[test]
fn installer_backup_rename_requires_a_committed_namespace_record() {
    const PROFILE: &str = r"\??\C:\Users\Default";
    const SOURCE: &str = r"\??\C:\Users\Default\ntuser.dat";
    const BACKUP: &str = r"\??\C:\Users\Default\ntuser.bak";
    const SIBLING: &str = r"\??\C:\Users\Default\next.dat";

    let mut live = FileSystem::new(MemFs::new());
    assert!(live.provision_file(SOURCE, b"old default hive"));
    assert!(live.provision_file(BACKUP, b"superseded backup"));
    let opened = live.zw_create_file(
        SOURCE,
        crate::DELETE | crate::SYNCHRONIZE,
        0,
        crate::FILE_SHARE_READ | crate::FILE_SHARE_WRITE | crate::FILE_SHARE_DELETE,
        crate::FILE_OPEN,
        crate::FILE_OPEN_FOR_BACKUP_INTENT,
    );
    assert_eq!(opened.status, crate::STATUS_SUCCESS);
    let old_source = live.query_metadata(SOURCE).unwrap();
    let old_backup = live.query_metadata(BACKUP).unwrap();
    // The selected snapshot can predate a short-name update carried by this rename record.
    let before_rename = live.export_volume_snapshot().unwrap();
    let short: Vec<u16> = "NTUSER~1.DAT".encode_utf16().collect();
    let mut short_information = vec![0u8; 4 + short.len() * 2];
    short_information[..4].copy_from_slice(&((short.len() * 2) as u32).to_le_bytes());
    for (index, unit) in short.iter().copied().enumerate() {
        short_information[4 + index * 2..6 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    assert_eq!(live.zw_set_information_file(
        opened.handle, crate::FILE_SHORT_NAME_INFORMATION, &short_information,
    ), crate::STATUS_SUCCESS);
    let mut target = Vec::new();
    for unit in r"\Users\Default\ntuser.bak".encode_utf16() {
        target.extend_from_slice(&unit.to_le_bytes());
    }
    assert_eq!(
        live.zw_rename_file(opened.handle, crate::FileRenameRoot::VolumeRoot, &target, true),
        crate::STATUS_SUCCESS,
    );
    let moved_short_name = live.zw_query_short_name(opened.handle).unwrap();
    assert_eq!(live.zw_close(opened.handle), crate::STATUS_SUCCESS);
    let moved = live.query_metadata(BACKUP).unwrap();
    assert_eq!(moved.file_id, old_source.file_id);
    assert_ne!(moved.file_id, old_backup.file_id);
    assert_eq!(live.file_bytes_owned(SOURCE), None);
    let after_rename = live.export_volume_snapshot().unwrap();
    let rename = encode_file_rename_wal_payload(FileRenameWalPayload {
        sequence: 1,
        source_file_id: old_source.file_id,
        source_parent_file_id: live.query_metadata(PROFILE).unwrap().file_id,
        target_parent_file_id: live.query_metadata(PROFILE).unwrap().file_id,
        replaced_file_id: old_backup.file_id,
        source_path: SOURCE,
        target_path: BACKUP,
        moved_short_name,
        change_time: moved.change_time,
    }).unwrap();

    let new_source = live.zw_create_file(
        SOURCE, crate::FILE_WRITE_DATA, crate::FILE_ATTRIBUTE_HIDDEN, 0,
        crate::FILE_CREATE, crate::FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(new_source.status, crate::STATUS_SUCCESS);
    let creation = encode_file_create_wal_payload(creation_record(&live, 2, SOURCE, PROFILE)).unwrap();
    let after_create = live.export_volume_snapshot().unwrap();
    assert_eq!(live.zw_write_file(new_source.handle, None, b"new default hive"), (crate::STATUS_SUCCESS, 16));
    assert_eq!(live.zw_close(new_source.handle), crate::STATUS_SUCCESS);
    let after_write = live.export_volume_snapshot().unwrap();
    let new_metadata = live.query_metadata(SOURCE).unwrap();
    let new_bytes = live.file_bytes_owned(SOURCE).unwrap();
    let extents = changed_file_delta_extents(&[], &new_bytes).unwrap();
    let data = encode_file_delta_wal_payload(FileDeltaRecord {
        sequence: 3, file_id: new_metadata.file_id, path: SOURCE,
        end_of_file: new_bytes.len() as u64, extents: &extents,
    }).unwrap();
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(64), INCARNATION).unwrap();
    append(&mut wal, &rename);
    append(&mut wal, &creation);
    append(&mut wal, &data);
    let wal = recover_after_power_cut(wal.into_device().unwrap());
    assert_eq!(wal.records().len(), 3);

    assert!(live.provision_file(SIBLING, b""));
    for (snapshot, suffix_start) in [
        (&before_rename, 0usize),
        (&after_rename, 1),
        (&after_create, 2),
        (&after_write, 3),
    ] {
        // An anchored WAL can include records already folded into a later snapshot.
        for start in [suffix_start, 0] {
            let mut restored = FileSystem::from_volume_snapshot(snapshot).unwrap();
            let mut replay = BootSystemPreRead::new(
                &restored,
                r"\??\C:\ReactOS\System32\Config\SYSTEM",
                r"\??\C:\ReactOS\System32\Config\SYSTEM.LOG",
            );
            for record in &wal.records()[start..] {
                match decode_volume_wal_payload(&record.payload).unwrap() {
                    VolumeWalPayload::FileRename(payload) => {
                        assert_eq!(replay.replay_file_rename(&mut restored, payload), Ok(()));
                    }
                    VolumeWalPayload::FileCreate(payload) => {
                        assert_eq!(replay.replay_file_create(&mut restored, payload), Ok(()));
                    }
                    VolumeWalPayload::FileDelta(payload) => {
                        assert_eq!(replay.replay_file_delta(&mut restored, payload), Ok(()));
                    }
                    other => panic!("committed payload routed as {other:?}"),
                }
            }
            assert_eq!(restored.file_bytes_owned(BACKUP), Some(b"old default hive".to_vec()));
            assert_eq!(restored.query_metadata(BACKUP), Some(moved));
            let backed = restored.zw_create_file(
                BACKUP, crate::FILE_READ_DATA, 0,
                crate::FILE_SHARE_READ | crate::FILE_SHARE_WRITE | crate::FILE_SHARE_DELETE,
                crate::FILE_OPEN, crate::FILE_NON_DIRECTORY_FILE,
            );
            assert_eq!(backed.status, crate::STATUS_SUCCESS);
            assert_eq!(restored.zw_query_short_name(backed.handle), Some(moved_short_name));
            assert_eq!(restored.zw_close(backed.handle), crate::STATUS_SUCCESS);
            assert_eq!(restored.file_bytes_owned(SOURCE), Some(new_bytes.clone()));
            assert_eq!(restored.query_metadata(SOURCE).unwrap().file_id, new_metadata.file_id);
            assert!(restored.provision_file(SIBLING, b""));
            assert_eq!(restored.existing_file_id(SIBLING), live.existing_file_id(SIBLING));
        }
    }
}

#[test]
fn two_renames_replay_only_the_suffix_after_the_selected_snapshot_base() {
    const PARENT: &str = r"\??\C:\Users\Default";
    const A: &str = r"\??\C:\Users\Default\a.dat";
    const B: &str = r"\??\C:\Users\Default\b.dat";
    const C: &str = r"\??\C:\Users\Default\c.dat";
    let mut live = FileSystem::new(MemFs::new());
    for (path, bytes) in [(A, b"source".as_slice()), (B, b"old b".as_slice()),
        (C, b"old c".as_slice())]
    {
        assert!(live.provision_file(path, bytes));
    }
    let parent_id = live.query_metadata(PARENT).unwrap().file_id;
    let source_id = live.existing_file_id(A).unwrap();
    let replaced_b = live.existing_file_id(B).unwrap();
    let replaced_c = live.existing_file_id(C).unwrap();
    let snapshots = [live.export_volume_snapshot().unwrap()];
    let opened = live.zw_create_file(
        A, crate::DELETE | crate::SYNCHRONIZE, 0,
        crate::FILE_SHARE_READ | crate::FILE_SHARE_WRITE | crate::FILE_SHARE_DELETE,
        crate::FILE_OPEN, crate::FILE_OPEN_FOR_BACKUP_INTENT,
    );
    assert_eq!(opened.status, crate::STATUS_SUCCESS);
    let target_bytes = |path: &str| -> Vec<u8> {
        path.encode_utf16().flat_map(u16::to_le_bytes).collect()
    };
    assert_eq!(live.zw_rename_file(
        opened.handle, crate::FileRenameRoot::VolumeRoot,
        &target_bytes(r"\Users\Default\b.dat"), true,
    ), crate::STATUS_SUCCESS);
    let after_b = live.export_volume_snapshot().unwrap();
    let first = encode_file_rename_wal_payload(FileRenameWalPayload {
        sequence: 1,
        source_file_id: source_id,
        source_parent_file_id: parent_id,
        target_parent_file_id: parent_id,
        replaced_file_id: replaced_b,
        source_path: A,
        target_path: B,
        moved_short_name: crate::FileShortName::EMPTY,
        change_time: live.query_metadata(B).unwrap().change_time,
    }).unwrap();
    assert_eq!(live.zw_rename_file(
        opened.handle, crate::FileRenameRoot::VolumeRoot,
        &target_bytes(r"\Users\Default\c.dat"), true,
    ), crate::STATUS_SUCCESS);
    assert_eq!(live.zw_close(opened.handle), crate::STATUS_SUCCESS);
    let after_c = live.export_volume_snapshot().unwrap();
    let second = encode_file_rename_wal_payload(FileRenameWalPayload {
        sequence: 2,
        source_file_id: source_id,
        source_parent_file_id: parent_id,
        target_parent_file_id: parent_id,
        replaced_file_id: replaced_c,
        source_path: B,
        target_path: C,
        moved_short_name: crate::FileShortName::EMPTY,
        change_time: live.query_metadata(C).unwrap().change_time,
    }).unwrap();
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(64), INCARNATION).unwrap();
    append(&mut wal, &first);
    append(&mut wal, &second);
    let wal = recover_after_power_cut(wal.into_device().unwrap());
    assert_eq!(wal.records().len(), 2);

    // The authenticated snapshot header supplies base_serial; native recovery slices the
    // physical WAL at that serial. It never replays A→B over the snapshot already holding C.
    for (snapshot, base_serial) in [
        (&snapshots[0], 0usize), (&after_b, 1), (&after_c, 2),
    ] {
        let mut restored = FileSystem::from_volume_snapshot(snapshot).unwrap();
        let mut replay = BootSystemPreRead::new(
            &restored,
            r"\??\C:\ReactOS\System32\Config\SYSTEM",
            r"\??\C:\ReactOS\System32\Config\SYSTEM.LOG",
        );
        for record in &wal.records()[base_serial..] {
            let VolumeWalPayload::FileRename(payload) =
                decode_volume_wal_payload(&record.payload).unwrap()
            else {
                panic!("rename chain must retain typed WAL order");
            };
            assert_eq!(replay.replay_file_rename(&mut restored, payload), Ok(()));
        }
        assert_eq!(restored.existing_file_id(A), None);
        assert_eq!(restored.existing_file_id(B), None);
        assert_eq!(restored.existing_file_id(C), Some(source_id));
        assert_eq!(restored.file_bytes_owned(C), Some(b"source".to_vec()));
    }
}

#[test]
fn rename_replay_refuses_foreign_identity_and_sequence_gap_without_advancing() {
    const SOURCE: &str = r"\??\C:\Users\Default\ntuser.dat";
    const BACKUP: &str = r"\??\C:\Users\Default\ntuser.bak";
    const PARENT: &str = r"\??\C:\Users\Default";
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(SOURCE, b"old source"));
    assert!(fs.provision_file(BACKUP, b"old backup"));
    let before = fs.export_volume_snapshot().unwrap();
    let source_id = fs.existing_file_id(SOURCE).unwrap();
    let backup_id = fs.existing_file_id(BACKUP).unwrap();
    let parent_id = fs.query_metadata(PARENT).unwrap().file_id;
    let record = FileRenameWalPayload {
        sequence: 1,
        source_file_id: source_id,
        source_parent_file_id: parent_id,
        target_parent_file_id: parent_id,
        replaced_file_id: backup_id,
        source_path: SOURCE,
        target_path: BACKUP,
        moved_short_name: crate::FileShortName::EMPTY,
        change_time: fs.query_metadata(BACKUP).unwrap().change_time + 1,
    };
    let mut cursor = FileDeltaReplayCursor::new();
    for foreign in [
        FileRenameWalPayload { source_file_id: source_id + 100, ..record },
        FileRenameWalPayload { source_parent_file_id: parent_id + 100, ..record },
        FileRenameWalPayload { target_parent_file_id: parent_id + 100, ..record },
        FileRenameWalPayload { replaced_file_id: backup_id + 100, ..record },
    ] {
        assert_eq!(fs.replay_file_rename_wal_payload(&mut cursor, foreign),
            Err(FileDeltaWalReplayError::ForeignIdentity));
        assert_eq!(cursor.last_applied(), None);
        assert_eq!(fs.export_volume_snapshot().unwrap(), before);
    }
    assert_eq!(fs.replay_file_rename_wal_payload(&mut cursor, record), Ok(()));
    let moved = fs.export_volume_snapshot().unwrap();
    assert_eq!(fs.existing_file_id(BACKUP), Some(source_id));
    assert_eq!(fs.replay_file_rename_wal_payload(
        &mut cursor, FileRenameWalPayload { sequence: 3, ..record }),
        Err(FileDeltaWalReplayError::OutOfOrder));
    assert_eq!(cursor.last_applied(), Some(1));
    assert_eq!(fs.export_volume_snapshot().unwrap(), moved);
    assert_eq!(fs.replay_file_rename_wal_payload(
        &mut cursor, FileRenameWalPayload { sequence: 2, ..record }), Ok(()));
    assert_eq!(cursor.last_applied(), Some(2));
    assert_eq!(fs.export_volume_snapshot().unwrap(), moved);
}

#[test]
fn uncommitted_rename_is_not_recovered_after_power_cut() {
    const SOURCE: &str = r"\??\C:\Users\Default\ntuser.dat";
    const BACKUP: &str = r"\??\C:\Users\Default\ntuser.bak";
    const PARENT: &str = r"\??\C:\Users\Default";
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(SOURCE, b"old source"));
    assert!(fs.provision_file(BACKUP, b"old backup"));
    let parent = fs.query_metadata(PARENT).unwrap().file_id;
    let record = encode_file_rename_wal_payload(FileRenameWalPayload {
        sequence: 1,
        source_file_id: fs.existing_file_id(SOURCE).unwrap(),
        source_parent_file_id: parent,
        target_parent_file_id: parent,
        replaced_file_id: fs.existing_file_id(BACKUP).unwrap(),
        source_path: SOURCE,
        target_path: BACKUP,
        moved_short_name: crate::FileShortName::EMPTY,
        change_time: fs.query_metadata(BACKUP).unwrap().change_time + 1,
    }).unwrap();
    let before = fs.export_volume_snapshot().unwrap();
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(64), INCARNATION).unwrap();
    wal.begin(record).unwrap();
    wal.prepare().unwrap();
    let recovered = recover_after_power_cut(wal.into_device_for_test());
    assert!(recovered.records().is_empty());
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
}

#[test]
fn directory_creation_must_replay_before_its_child_creation() {
    let mut live = FileSystem::new(MemFs::new());
    assert!(live.provision_directory(DIRECTORY));
    let base = live.export_volume_snapshot().unwrap();
    let directory = live.zw_create_file(
        CREATED_DIRECTORY, crate::FILE_READ_DATA, crate::FILE_ATTRIBUTE_DIRECTORY, 0,
        crate::FILE_CREATE, crate::FILE_DIRECTORY_FILE,
    );
    assert_eq!(directory.status, crate::STATUS_SUCCESS);
    assert_eq!(live.zw_close(directory.handle), crate::STATUS_SUCCESS);
    let child = live.zw_create_file(
        CREATED_CHILD, crate::FILE_WRITE_DATA, crate::FILE_ATTRIBUTE_HIDDEN, 0,
        crate::FILE_CREATE, crate::FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(child.status, crate::STATUS_SUCCESS);
    assert_eq!(live.zw_close(child.handle), crate::STATUS_SUCCESS);
    let directory_record = encode_file_create_wal_payload(
        creation_record(&live, 1, CREATED_DIRECTORY, DIRECTORY),
    ).unwrap();
    let child_record = encode_file_create_wal_payload(
        creation_record(&live, 2, CREATED_CHILD, CREATED_DIRECTORY),
    ).unwrap();
    let directory_payload = crate::decode_file_create_wal_payload(&directory_record).unwrap();
    let child_payload = crate::decode_file_create_wal_payload(&child_record).unwrap();
    let mut restored = FileSystem::from_volume_snapshot(&base).unwrap();
    let mut replay = BootSystemPreRead::new(
        &restored,
        r"\??\C:\ReactOS\System32\Config\SYSTEM",
        r"\??\C:\ReactOS\System32\Config\SYSTEM.LOG",
    );
    assert_eq!(
        replay.replay_file_create(&mut restored, child_payload),
        Err(FileDeltaWalReplayError::MissingFile),
    );
    assert_eq!(restored.query_metadata(CREATED_CHILD), None);
    assert_eq!(replay.replay_file_create(&mut restored, directory_payload), Ok(()));
    assert_eq!(replay.replay_file_create(&mut restored, child_payload), Ok(()));
    for path in [CREATED_DIRECTORY, CREATED_CHILD] {
        let expected = live.query_metadata(path).unwrap();
        let actual = restored.query_metadata(path).unwrap();
        assert_eq!(actual.file_id, expected.file_id);
        assert_eq!(actual.attributes, expected.attributes);
        assert_eq!(actual.is_directory, expected.is_directory);
    }
    let sibling = r"\??\C:\ReactOS\System32\Config\Next";
    assert!(live.provision_file(sibling, b""));
    assert!(restored.provision_file(sibling, b""));
    assert_eq!(restored.existing_file_id(sibling), live.existing_file_id(sibling));
}

#[test]
fn create_replay_rejects_foreign_parent_identity_and_sequence_gaps() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(DIRECTORY));
    let parent_file_id = fs.query_metadata(DIRECTORY).unwrap().file_id;
    let record = FileCreateWalPayload {
        sequence: 4, file_id: parent_file_id + 1, parent_file_id, path: FILE,
        attributes: crate::FILE_ATTRIBUTE_HIDDEN, is_directory: false, times: [11, 12, 13, 14],
    };
    let mut cursor = FileDeltaReplayCursor::new();
    let foreign = FileCreateWalPayload { parent_file_id: parent_file_id + 1, ..record };
    assert_eq!(
        fs.replay_file_create_wal_payload(&mut cursor, foreign),
        Err(FileDeltaWalReplayError::ForeignIdentity),
    );
    assert_eq!(fs.existing_file_id(FILE), None);
    assert_eq!(cursor.last_applied(), None);
    let gap = FileCreateWalPayload { file_id: record.file_id + 1, ..record };
    assert_eq!(
        fs.replay_file_create_wal_payload(&mut cursor, gap),
        Err(FileDeltaWalReplayError::ForeignIdentity),
    );
    assert_eq!(fs.existing_file_id(FILE), None);
    assert_eq!(cursor.last_applied(), None);
    assert_eq!(fs.replay_file_create_wal_payload(&mut cursor, record), Ok(()));
    assert_eq!(fs.existing_file_id(FILE), Some(record.file_id));
    assert_eq!(fs.query_metadata(FILE).unwrap().attributes, crate::FILE_ATTRIBUTE_HIDDEN);
    let metadata = fs.query_metadata(FILE);
    assert_eq!(
        fs.replay_file_create_wal_payload(&mut cursor, FileCreateWalPayload { sequence: 6, ..record }),
        Err(FileDeltaWalReplayError::OutOfOrder),
    );
    assert_eq!(
        fs.replay_file_create_wal_payload(&mut cursor, record),
        Err(FileDeltaWalReplayError::OutOfOrder),
    );
    assert_eq!(fs.query_metadata(FILE), metadata);
    assert_eq!(cursor.last_applied(), Some(4));
}

#[test]
fn create_replay_allows_a_sibling_of_a_protected_log_but_refuses_the_log_itself() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(DIRECTORY));
    assert!(fs.provision_file(LOG, b"anchored log"));
    let parent_file_id = fs.query_metadata(DIRECTORY).unwrap().file_id;
    let log_file_id = fs.existing_file_id(LOG).unwrap();
    fs.protect_wal_log(LOG, log_file_id).unwrap();
    let mut cursor = FileDeltaReplayCursor::new();
    let sibling = FileCreateWalPayload {
        sequence: 1, file_id: log_file_id + 1, parent_file_id, path: FILE,
        attributes: crate::FILE_ATTRIBUTE_HIDDEN, is_directory: false, times: [0; 4],
    };
    assert_eq!(fs.replay_file_create_wal_payload(&mut cursor, sibling), Ok(()));
    assert_eq!(fs.existing_file_id(FILE), Some(sibling.file_id));
    let protected = FileCreateWalPayload {
        sequence: 2, file_id: log_file_id, parent_file_id, path: LOG,
        attributes: fs.query_metadata(LOG).unwrap().attributes,
        is_directory: false, times: [0; 4],
    };
    assert_eq!(
        fs.replay_file_create_wal_payload(&mut cursor, protected),
        Err(FileDeltaWalReplayError::ProtectedTarget),
    );
    assert_eq!(fs.file_bytes_owned(LOG), Some(b"anchored log".to_vec()));
    assert_eq!(cursor.last_applied(), Some(1));
}

#[test]
fn uncommitted_create_record_does_not_materialize_a_name_after_power_cut() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(DIRECTORY));
    let record = encode_file_create_wal_payload(FileCreateWalPayload {
        sequence: 1,
        file_id: fs.query_metadata(DIRECTORY).unwrap().file_id + 1,
        parent_file_id: fs.query_metadata(DIRECTORY).unwrap().file_id,
        path: FILE,
        attributes: crate::FILE_ATTRIBUTE_HIDDEN,
        is_directory: false,
        times: [0; 4],
    }).unwrap();
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(64), INCARNATION).unwrap();
    wal.begin(record).unwrap();
    wal.prepare().unwrap();
    let wal = recover_after_power_cut(wal.into_device_for_test());
    assert!(wal.records().is_empty());
    assert_eq!(fs.existing_file_id(FILE), None);
}

#[test]
fn replay_refuses_a_missing_foreign_directory_or_protected_target_without_change() {
    let mut cursor = FileDeltaReplayCursor::new();

    let source = volume_with(b"base");
    let record = encoded(&source, 1, 4, &[FileDeltaExtent { offset: 0, bytes: b"X" }]);
    let mut missing = FileSystem::new(MemFs::new());
    assert_eq!(replay(&mut missing, &mut cursor, &record), Err(FileDeltaWalReplayError::MissingFile));

    let mut fs = volume_with(b"base");
    let foreign = encode_file_delta_wal_payload(FileDeltaRecord {
        sequence: 1,
        file_id: fs.existing_file_id(FILE).unwrap() + 1,
        path: FILE,
        end_of_file: 1,
        extents: &[],
    }).unwrap();
    assert_eq!(replay(&mut fs, &mut cursor, &foreign), Err(FileDeltaWalReplayError::ForeignIdentity));

    let directory = encode_file_delta_wal_payload(FileDeltaRecord {
        sequence: 1, file_id: 1, path: DIRECTORY, end_of_file: 0, extents: &[],
    }).unwrap();
    assert_eq!(replay(&mut fs, &mut cursor, &directory), Err(FileDeltaWalReplayError::MissingFile));

    assert!(fs.provision_file(LOG, b"HLR1 log"));
    let log_id = fs.existing_file_id(LOG).unwrap();
    fs.protect_wal_log(LOG, log_id).unwrap();
    let protected = encode_file_delta_wal_payload(FileDeltaRecord {
        sequence: 1, file_id: log_id, path: LOG, end_of_file: 0, extents: &[],
    }).unwrap();
    assert_eq!(replay(&mut fs, &mut cursor, &protected), Err(FileDeltaWalReplayError::ProtectedTarget));

    assert_eq!(contents(&fs), b"base");
    assert_eq!(fs.file_bytes_owned(LOG).unwrap(), b"HLR1 log");
    assert_eq!(cursor.last_applied(), None);
}

#[test]
fn replay_refuses_a_gap_duplicate_or_reordered_delta_without_change() {
    let mut fs = volume_with(b"....");
    let write = |fs: &FileSystem, sequence, byte: &[u8]| {
        encoded(fs, sequence, 4, &[FileDeltaExtent { offset: 0, bytes: byte }])
    };
    let (first, second, third) = (write(&fs, 5, b"1"), write(&fs, 6, b"2"), write(&fs, 7, b"3"));
    let mut cursor = FileDeltaReplayCursor::new();

    // A replayed suffix may begin after records already folded into the snapshot.
    assert_eq!(replay(&mut fs, &mut cursor, &first), Ok(()));
    assert_eq!(replay(&mut fs, &mut cursor, &third), Err(FileDeltaWalReplayError::OutOfOrder));
    assert_eq!(replay(&mut fs, &mut cursor, &first), Err(FileDeltaWalReplayError::OutOfOrder));
    assert_eq!(contents(&fs), b"1...");
    assert_eq!(cursor.last_applied(), Some(5));

    assert_eq!(replay(&mut fs, &mut cursor, &second), Ok(()));
    assert_eq!(replay(&mut fs, &mut cursor, &first), Err(FileDeltaWalReplayError::OutOfOrder));
    assert_eq!(replay(&mut fs, &mut cursor, &third), Ok(()));
    assert_eq!(contents(&fs), b"3...");
    assert_eq!(cursor.last_applied(), Some(7));
}

#[test]
fn a_refused_record_does_not_advance_the_cursor() {
    let mut fs = volume_with(b"base");
    let mut cursor = FileDeltaReplayCursor::new();
    let foreign = encode_file_delta_wal_payload(FileDeltaRecord {
        sequence: 1, file_id: fs.existing_file_id(FILE).unwrap() + 1, path: FILE,
        end_of_file: 0, extents: &[],
    }).unwrap();
    assert_eq!(replay(&mut fs, &mut cursor, &foreign), Err(FileDeltaWalReplayError::ForeignIdentity));
    let valid = encoded(&fs, 1, 2, &[]);
    assert_eq!(replay(&mut fs, &mut cursor, &valid), Ok(()));
    assert_eq!(contents(&fs), b"ba");
}

/// A one-slot checkpoint can publish a newer image without advancing the header's base serial,
/// so boot replays records the snapshot already holds. Truncation followed by regrowth is the
/// case where stale bytes would survive if a record only described its own writes.
#[test]
fn replaying_the_whole_suffix_over_any_later_snapshot_gives_the_final_state() {
    let states: [Vec<u8>; 5] = [
        vec![0xAA; 2048],
        vec![0xAA; 512],                                   // truncate
        [vec![0xAA; 512], vec![0; 1536]].concat(),         // regrow with zeroes
        [vec![0xAA; 512], vec![0; 1024], vec![0xBB; 512]].concat(), // write the last block
        [vec![0xCC; 512], vec![0; 1024], vec![0xBB; 100]].concat(), // rewrite head, shrink tail
    ];
    let mut live = volume_with(&states[0]);
    let mut cursor = FileDeltaReplayCursor::new();
    let mut records = Vec::new();
    let mut snapshots = vec![live.export_volume_snapshot().unwrap()];
    for (index, pair) in states.windows(2).enumerate() {
        let record = transition(&live, index as u64 + 1, &pair[0], &pair[1]);
        assert_eq!(replay(&mut live, &mut cursor, &record), Ok(()));
        assert_eq!(contents(&live), pair[1], "state {}", index + 1);
        records.push(record);
        snapshots.push(live.export_volume_snapshot().unwrap());
    }
    for (captured_after, snapshot) in snapshots.iter().enumerate() {
        let mut restored = FileSystem::from_volume_snapshot(snapshot).unwrap();
        let mut cursor = FileDeltaReplayCursor::new();
        for record in &records {
            assert_eq!(replay(&mut restored, &mut cursor, record), Ok(()));
        }
        assert_eq!(contents(&restored), states[4], "snapshot after record {captured_after}");
    }
}

/// The same convergence over a longer generated history of overwrites, growth and truncation.
#[test]
fn generated_histories_converge_from_every_intermediate_snapshot() {
    let mut seed = 0x381_u64;
    let mut next = move |bound: usize| {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((seed >> 33) as usize) % bound
    };
    let mut state: Vec<u8> = (0..3000).map(|index| (index % 251) as u8 + 1).collect();
    let mut live = volume_with(&state);
    let mut cursor = FileDeltaReplayCursor::new();
    let mut records = Vec::new();
    let mut snapshots = vec![live.export_volume_snapshot().unwrap()];
    for step in 0..40u64 {
        let old = state.clone();
        match next(4) {
            0 => state.truncate(next(old.len() + 1)),
            1 => state.resize(old.len() + next(2000), 0),
            _ => {
                let offset = next(old.len() + 1500);
                let len = 1 + next(900);
                if state.len() < offset + len {
                    state.resize(offset + len, 0);
                }
                let fill = (step as u8).wrapping_mul(7) | 1;
                state[offset..offset + len].fill(fill);
            }
        }
        let record = transition(&live, step + 1, &old, &state);
        assert_eq!(replay(&mut live, &mut cursor, &record), Ok(()));
        assert_eq!(contents(&live), state, "step {step}");
        records.push(record);
        snapshots.push(live.export_volume_snapshot().unwrap());
    }
    for (captured_after, snapshot) in snapshots.iter().enumerate() {
        let mut restored = FileSystem::from_volume_snapshot(snapshot).unwrap();
        let mut cursor = FileDeltaReplayCursor::new();
        for record in &records {
            assert_eq!(replay(&mut restored, &mut cursor, record), Ok(()));
        }
        assert_eq!(contents(&restored), state, "snapshot after record {captured_after}");
    }
}

// ---- Composition with the physical sector WAL ---------------------------------------------

const INCARNATION: u64 = 77;

fn append(wal: &mut RegistryWal<CachedDisk>, payload: &[u8]) {
    wal.begin(payload.to_vec()).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
}

/// A recovered file delta must pass the production payload router before its
/// already tested file replay is allowed to touch the unpublished volume.
fn replay_recovered(wal: &RegistryWal<CachedDisk>, fs: &mut FileSystem) -> Result<(), FileDeltaWalReplayError> {
    let mut cursor = FileDeltaReplayCursor::new();
    for record in wal.records() {
        match decode_volume_wal_payload(&record.payload).expect("committed WAL kind must route") {
            VolumeWalPayload::HiveLog(payload) => {
                fs.replay_hive_log_wal_payload(payload).unwrap();
            }
            VolumeWalPayload::System(_) => {}
            VolumeWalPayload::FileDelta(payload) => {
                fs.replay_file_delta_wal_payload(&mut cursor, payload)?;
            }
            VolumeWalPayload::FileCreate(payload) => {
                fs.replay_file_create_wal_payload(&mut cursor, payload)?;
            }
            VolumeWalPayload::FileRename(payload) => {
                fs.replay_file_rename_wal_payload(&mut cursor, payload)?;
            }
        }
    }
    Ok(())
}

struct History {
    base: FileSystem,
    payloads: Vec<Vec<u8>>,
    states: Vec<Vec<u8>>,
}

/// Three file deltas with a hive-log append between the first two.
fn history() -> History {
    let s0 = vec![0x10u8; 1536];
    let mut s1 = s0.clone();
    s1[600..700].fill(0x21);
    let mut s2 = s1.clone();
    s2.resize(2600, 0);
    s2[2500..].fill(0x32);
    let mut s3 = s2.clone();
    s3.truncate(1100);
    s3[0] = 0x43;

    let mut base = volume_with(&s0);
    assert!(base.provision_file(LOG, b"base"));
    let hive_log = encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: base.existing_file_id(LOG).unwrap(),
        expected_log_len: 4,
        path: LOG,
        record: b"HLR1 interleaved",
    }).unwrap();
    let payloads = vec![
        transition(&base, 1, &s0, &s1),
        hive_log,
        transition(&base, 2, &s1, &s2),
        transition(&base, 3, &s2, &s3),
    ];
    History { base, payloads, states: vec![s0, s1, s2, s3] }
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
fn committed_deltas_recover_through_the_sector_wal_in_order() {
    let history = history();
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(64), INCARNATION).unwrap();
    for payload in &history.payloads {
        append(&mut wal, payload);
    }
    let wal = recover_after_power_cut(wal.into_device().unwrap());
    assert_eq!(wal.records().len(), 4);

    let mut restored = restored_copy(&history.base);
    assert_eq!(replay_recovered(&wal, &mut restored), Ok(()));
    assert_eq!(contents(&restored), history.states[3]);
    assert_eq!(restored.file_bytes_owned(LOG).unwrap(), b"baseHLR1 interleaved");
}

#[test]
fn a_delta_without_its_commit_marker_is_not_replayed() {
    let history = history();
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(64), INCARNATION).unwrap();
    for payload in &history.payloads[..3] {
        append(&mut wal, payload);
    }
    wal.begin(history.payloads[3].clone()).unwrap();
    wal.prepare().unwrap();
    let wal = recover_after_power_cut(wal.into_device_for_test());
    assert_eq!(wal.records().len(), 3);

    let mut restored = restored_copy(&history.base);
    assert_eq!(replay_recovered(&wal, &mut restored), Ok(()));
    assert_eq!(contents(&restored), history.states[2]);
}

#[test]
fn a_torn_delta_frame_is_not_replayed() {
    let history = history();
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(64), INCARNATION).unwrap();
    for payload in &history.payloads[..3] {
        append(&mut wal, payload);
    }
    // Fail the second payload sector: the header and first sector were written but never
    // reached a barrier, and the remaining sectors were never written at all.
    let events = wal.device_mut_for_test().events.len();
    wal.device_mut_for_test().fail_event = Some(events + 2);
    wal.begin(history.payloads[3].clone()).unwrap();
    assert!(matches!(wal.prepare(), Err(RegistryWalError::Storage(_))));
    assert_eq!(wal.state(), RegistryWalState::Uncertain);
    let wal = recover_after_power_cut(wal.into_device_for_test());
    assert_eq!(wal.records().len(), 3);

    let mut restored = restored_copy(&history.base);
    assert_eq!(replay_recovered(&wal, &mut restored), Ok(()));
    assert_eq!(contents(&restored), history.states[2]);
}

#[test]
fn a_corrupt_committed_delta_fails_recovery_before_any_replay() {
    let history = history();
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(64), INCARNATION).unwrap();
    for payload in &history.payloads {
        append(&mut wal, payload);
    }
    let mut disk = wal.into_device().unwrap();
    // Frame 1 is a header, its payload sectors and a marker; corrupt its first payload sector.
    disk.corrupt(1);
    assert_eq!(RegistryWal::recover(disk, INCARNATION).err(), Some(RegistryWalError::Corrupt));
}

#[test]
fn a_delta_missing_from_the_recovered_order_stops_replay_at_the_gap() {
    let history = history();
    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(64), INCARNATION).unwrap();
    // The producer logged deltas 1 and 3 but lost delta 2 (for example an aborted prepare
    // whose in-memory change was kept).
    append(&mut wal, &history.payloads[0]);
    append(&mut wal, &history.payloads[3]);
    let wal = recover_after_power_cut(wal.into_device().unwrap());

    let mut restored = restored_copy(&history.base);
    assert_eq!(replay_recovered(&wal, &mut restored), Err(FileDeltaWalReplayError::OutOfOrder));
    assert_eq!(contents(&restored), history.states[1]);
}
