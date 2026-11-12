use super::*;
use crate::{decode_volume_wal_payload, VolumeWalPayloadError};
use alloc::vec;
use alloc::vec::Vec;

const PATH: &str = r"\??\C:\ReactOS\System32\Config\SOFTWARE";

fn record<'a>(extents: &'a [FileDeltaExtent<'a>], end_of_file: u64) -> FileDeltaRecord<'a> {
    FileDeltaRecord { sequence: 7, file_id: 42, path: PATH, end_of_file, extents }
}

fn two_extents() -> [FileDeltaExtent<'static>; 2] {
    [
        FileDeltaExtent { offset: 512, bytes: b"first run" },
        FileDeltaExtent { offset: 4096, bytes: b"second" },
    ]
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn round_trips_identity_length_and_every_extent() {
    let extents = two_extents();
    let bytes = encode_file_delta_wal_payload(record(&extents, 8192)).unwrap();
    assert_eq!(&bytes[..8], b"NTFDLT01");

    let decoded = decode_file_delta_wal_payload(&bytes).unwrap();
    assert_eq!(decoded.sequence(), 7);
    assert_eq!(decoded.file_id(), 42);
    assert_eq!(decoded.end_of_file(), 8192);
    assert_eq!(decoded.path(), PATH);
    assert_eq!(decoded.extents().collect::<Vec<_>>(), extents);
}

#[test]
fn a_pure_length_change_has_no_extents() {
    let bytes = encode_file_delta_wal_payload(record(&[], 100)).unwrap();
    let decoded = decode_file_delta_wal_payload(&bytes).unwrap();
    assert_eq!(decoded.end_of_file(), 100);
    assert_eq!(decoded.extents().count(), 0);
}

#[test]
fn layout_is_stable() {
    let extents = [FileDeltaExtent { offset: 3, bytes: b"xy" }];
    let bytes = encode_file_delta_wal_payload(FileDeltaRecord {
        sequence: 1, file_id: 2, path: r"\a", end_of_file: 9, extents: &extents,
    }).unwrap();
    let mut expected = Vec::new();
    expected.extend_from_slice(b"NTFDLT01");
    expected.extend_from_slice(&1u64.to_le_bytes());
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(&9u64.to_le_bytes());
    expected.extend_from_slice(&2u32.to_le_bytes()); // path length
    expected.extend_from_slice(&1u32.to_le_bytes()); // run count
    expected.extend_from_slice(&2u32.to_le_bytes()); // data length
    expected.extend_from_slice(&0u32.to_le_bytes()); // reserved
    expected.extend_from_slice(br"\a");
    expected.extend_from_slice(&3u64.to_le_bytes());
    expected.extend_from_slice(&2u32.to_le_bytes());
    expected.extend_from_slice(b"xy");
    assert_eq!(bytes, expected);
}

#[test]
fn encoder_refuses_records_replay_could_not_apply_exactly() {
    let extents = two_extents();
    let valid = record(&extents, 8192);
    let refuse = |record| encode_file_delta_wal_payload(record).unwrap_err();

    assert_eq!(refuse(FileDeltaRecord { sequence: 0, ..valid }), FileDeltaWalPayloadError::InvalidSequence);
    assert_eq!(refuse(FileDeltaRecord { file_id: 0, ..valid }), FileDeltaWalPayloadError::InvalidIdentity);
    assert_eq!(refuse(FileDeltaRecord { path: "relative", ..valid }), FileDeltaWalPayloadError::InvalidPath);
    assert_eq!(refuse(FileDeltaRecord { path: "\\nul\0", ..valid }), FileDeltaWalPayloadError::InvalidPath);
    assert_eq!(refuse(FileDeltaRecord { end_of_file: i64::MAX as u64 + 1, ..valid }),
        FileDeltaWalPayloadError::InvalidLength);
    // The second extent ends at 4102.
    assert_eq!(refuse(FileDeltaRecord { end_of_file: 4101, ..valid }), FileDeltaWalPayloadError::InvalidExtent);
    assert!(encode_file_delta_wal_payload(FileDeltaRecord { end_of_file: 4102, ..valid }).is_ok());

    let empty = [FileDeltaExtent { offset: 0, bytes: b"" }];
    assert_eq!(refuse(record(&empty, 8)), FileDeltaWalPayloadError::InvalidExtent);
    let descending = [extents[1], extents[0]];
    assert_eq!(refuse(record(&descending, 8192)), FileDeltaWalPayloadError::InvalidExtent);
    let overlapping = [
        FileDeltaExtent { offset: 0, bytes: b"abcd" },
        FileDeltaExtent { offset: 3, bytes: b"z" },
    ];
    assert_eq!(refuse(record(&overlapping, 8192)), FileDeltaWalPayloadError::InvalidExtent);
    let adjacent = [
        FileDeltaExtent { offset: 0, bytes: b"abcd" },
        FileDeltaExtent { offset: 4, bytes: b"z" },
    ];
    assert!(encode_file_delta_wal_payload(record(&adjacent, 8192)).is_ok());
}

#[test]
fn decoder_rejects_every_truncation_and_any_trailing_byte() {
    let extents = two_extents();
    let bytes = encode_file_delta_wal_payload(record(&extents, 8192)).unwrap();
    assert_eq!(decode_file_delta_wal_payload(&bytes[..4]), Err(FileDeltaWalPayloadError::UnknownKind));
    for end in 8..bytes.len() {
        assert_eq!(decode_file_delta_wal_payload(&bytes[..end]),
            Err(FileDeltaWalPayloadError::InvalidLength), "prefix {end}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(decode_file_delta_wal_payload(&extra), Err(FileDeltaWalPayloadError::InvalidLength));
}

#[test]
fn decoder_rejects_altered_header_fields() {
    let extents = two_extents();
    let valid = encode_file_delta_wal_payload(record(&extents, 8192)).unwrap();
    let altered = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut bytes = valid.clone();
        edit(&mut bytes);
        decode_file_delta_wal_payload(&bytes).unwrap_err()
    };
    let runs = 48 + PATH.len();

    assert_eq!(decode_file_delta_wal_payload(b""), Err(FileDeltaWalPayloadError::UnknownKind));
    assert_eq!(altered(&|b| b[7] = b'2'), FileDeltaWalPayloadError::UnknownKind);
    assert_eq!(altered(&|b| put_u64(b, 8, 0)), FileDeltaWalPayloadError::InvalidSequence);
    assert_eq!(altered(&|b| put_u64(b, 16, 0)), FileDeltaWalPayloadError::InvalidIdentity);
    assert_eq!(altered(&|b| put_u64(b, 24, u64::MAX)), FileDeltaWalPayloadError::InvalidLength);
    assert_eq!(altered(&|b| put_u32(b, 32, u32::MAX)), FileDeltaWalPayloadError::InvalidLength);
    assert_eq!(altered(&|b| put_u32(b, 36, 3)), FileDeltaWalPayloadError::InvalidLength);
    assert_eq!(altered(&|b| put_u32(b, 40, 14)), FileDeltaWalPayloadError::InvalidLength);
    assert_eq!(altered(&|b| put_u32(b, 44, 1)), FileDeltaWalPayloadError::UnknownKind);
    assert_eq!(altered(&|b| b[48] = b'x'), FileDeltaWalPayloadError::InvalidPath);
    assert_eq!(altered(&|b| b[49] = 0xff), FileDeltaWalPayloadError::InvalidPath);
    // Run table: first run moved past the second, a zero-length run, and a run past EOF.
    assert_eq!(altered(&|b| put_u64(b, runs, 4096)), FileDeltaWalPayloadError::InvalidExtent);
    assert_eq!(altered(&|b| { put_u32(b, runs + 8, 0); put_u32(b, runs + 20, 15); }),
        FileDeltaWalPayloadError::InvalidExtent);
    assert_eq!(altered(&|b| put_u64(b, runs + 12, 8190)), FileDeltaWalPayloadError::InvalidExtent);
    // Run lengths that no longer add up to the recorded data length.
    assert_eq!(altered(&|b| put_u32(b, runs + 8, 8)), FileDeltaWalPayloadError::InvalidExtent);
}

/// Dormancy contract for this increment: the live boot router still refuses the new kind,
/// so no existing volume can be handed a file delta before replay is integrated.
#[test]
fn live_volume_wal_router_does_not_route_file_deltas_yet() {
    let bytes = encode_file_delta_wal_payload(record(&[], 0)).unwrap();
    assert_eq!(decode_volume_wal_payload(&bytes), Err(VolumeWalPayloadError::UnknownKind));
}

#[test]
fn diff_reports_only_changed_blocks_and_joins_neighbours() {
    let old = vec![0x11u8; 8 * 512];
    let mut new = old.clone();
    new[512 + 7] = 0x22; // block 1
    new[2 * 512] = 0x33; // block 2, adjacent
    new[6 * 512 + 511] = 0x44; // block 6
    let extents = changed_file_delta_extents(&old, &new).unwrap();
    assert_eq!(extents, [
        FileDeltaExtent { offset: 512, bytes: &new[512..3 * 512] },
        FileDeltaExtent { offset: 6 * 512, bytes: &new[6 * 512..7 * 512] },
    ]);
    assert!(changed_file_delta_extents(&old, &old).unwrap().is_empty());
}

#[test]
fn diff_leaves_truncation_and_zero_growth_to_the_recorded_length() {
    let old = vec![0x11u8; 1000];
    // Shrinking keeps a common prefix: nothing to write.
    assert!(changed_file_delta_extents(&old, &old[..700]).unwrap().is_empty());

    // Growth by zeroes is implied by the new length, including the tail of the last old block.
    let mut grown = old.clone();
    grown.resize(3000, 0);
    assert!(changed_file_delta_extents(&old, &grown).unwrap().is_empty());

    // A non-zero byte beyond the old end is a change, clipped to the new length.
    grown[2999] = 9;
    assert_eq!(changed_file_delta_extents(&old, &grown).unwrap(),
        [FileDeltaExtent { offset: 2560, bytes: &grown[2560..3000] }]);

    // Bytes after the old end inside its last block count as a change when they are non-zero.
    let mut tail = old.clone();
    tail.resize(1024, 0);
    tail[1001] = 5;
    assert_eq!(changed_file_delta_extents(&old, &tail).unwrap(),
        [FileDeltaExtent { offset: 512, bytes: &tail[512..1024] }]);
}

#[test]
fn diff_output_is_always_encodable() {
    let old = vec![1u8; 1500];
    let mut new = vec![1u8; 2600];
    new[0] = 2;
    new[1499] = 3;
    new[2599] = 4;
    let extents = changed_file_delta_extents(&old, &new).unwrap();
    let bytes = encode_file_delta_wal_payload(record(&extents, new.len() as u64)).unwrap();
    let decoded = decode_file_delta_wal_payload(&bytes).unwrap();
    assert_eq!(decoded.extents().collect::<Vec<_>>(), extents);
}
