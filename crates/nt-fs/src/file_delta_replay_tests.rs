use alloc::vec;
use alloc::vec::Vec;

use crate::file_delta_wal_payload::{
    changed_file_delta_extents, decode_file_delta_wal_payload, encode_file_delta_wal_payload,
    FileDeltaExtent, FileDeltaRecord, FileDeltaReplayCursor, FileDeltaWalReplayError,
};
use crate::snapshot_test_device::CachedDisk;
use crate::{
    decode_volume_wal_payload, encode_hive_log_wal_payload, FileSystem, HiveLogWalPayload, MemFs,
    RegistryWal, RegistryWalError, RegistryWalState, VolumeWalPayload,
};

const FILE: &str = r"\??\C:\ReactOS\System32\Config\SOFTWARE";
const DIRECTORY: &str = r"\??\C:\ReactOS\System32\Config";
const LOG: &str = r"\??\C:\ReactOS\System32\Config\SOFTWARE.LOG";

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

/// Route a recovered WAL the way boot will: existing kinds first, file deltas by their codec.
fn replay_recovered(wal: &RegistryWal<CachedDisk>, fs: &mut FileSystem) -> Result<(), FileDeltaWalReplayError> {
    let mut cursor = FileDeltaReplayCursor::new();
    for record in wal.records() {
        match decode_volume_wal_payload(&record.payload) {
            Ok(VolumeWalPayload::HiveLog(payload)) => {
                fs.replay_hive_log_wal_payload(payload).unwrap();
            }
            Ok(VolumeWalPayload::System(_)) => {}
            Err(_) => {
                let payload = decode_file_delta_wal_payload(&record.payload).unwrap();
                fs.replay_file_delta_wal_payload(&mut cursor, payload)?;
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
