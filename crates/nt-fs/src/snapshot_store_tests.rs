use super::*;
use crate::snapshot_test_device::{CachedDisk, Event};

#[path = "snapshot_store_tests/batched_reads.rs"]
mod batched_reads;

#[path = "snapshot_store_tests/batched_writes.rs"]
mod batched_writes;

fn two_generations() -> (SnapshotBlockStore, CachedDisk) {
    let store = SnapshotBlockStore::new(0, 16);
    let mut dev = CachedDisk::new();
    assert_eq!(store.commit_next(&mut dev, b"first"), Ok(1));
    assert_eq!(store.commit_next(&mut dev, b"second"), Ok(2));
    dev.events.clear();
    (store, dev)
}

#[test]
fn commit_orders_three_barriers_and_survives_power_loss() {
    let (store, mut dev) = two_generations();
    assert_eq!(store.commit_next(&mut dev, b"third"), Ok(3));
    assert_eq!(
        dev.events,
        [
            Event::Flush,
            Event::Write(1),
            Event::Flush,
            Event::Write(0),
            Event::Flush
        ]
    );
    dev.power_cut();
    let snapshot = store.read_latest(&mut dev).unwrap().unwrap();
    assert_eq!(snapshot.generation, 3);
    assert_eq!(snapshot.payload, b"third");
}

#[test]
fn every_write_and_barrier_failure_preserves_a_complete_snapshot() {
    let payload = alloc::vec![0xa5; 1300];
    for partial_flush in [false, true] {
        for fail_event in 0..7 {
            let (store, mut dev) = two_generations();
            dev.fail_event = Some(fail_event);
            dev.partial_flush = partial_flush;
            assert_eq!(
                store.commit_next(&mut dev, &payload),
                Err(SnapshotBlockStoreError::Io)
            );
            if fail_event <= 4 {
                assert!(
                    !dev.events.contains(&Event::Write(0)),
                    "payload failure must not publish a header"
                );
            }
            dev.power_cut();
            let snapshot = store.read_latest(&mut dev).unwrap().unwrap();
            assert!(snapshot.generation == 2 || snapshot.generation == 3);
            assert_eq!(
                snapshot.payload,
                if snapshot.generation == 2 {
                    b"second".to_vec()
                } else {
                    payload.clone()
                }
            );
        }
    }
}

#[test]
fn retry_stabilizes_uncertain_header_before_reusing_previous_slot() {
    let (store, mut dev) = two_generations();
    dev.fail_event = Some(4);
    assert_eq!(
        store.commit_next(&mut dev, b"third"),
        Err(SnapshotBlockStoreError::Io)
    );
    assert_eq!(
        store.read_latest(&mut dev).unwrap().unwrap().generation,
        3,
        "new header is only cached"
    );
    dev.events.clear();
    dev.fail_event = Some(0);
    assert_eq!(
        store.commit_next(&mut dev, b"fourth"),
        Err(SnapshotBlockStoreError::Io)
    );
    assert_eq!(dev.events, [Event::Flush]);
    dev.fail_event = None;
    assert_eq!(store.commit_next(&mut dev, b"fourth"), Ok(4));
    dev.power_cut();
    assert_eq!(
        store.read_latest(&mut dev).unwrap().unwrap().payload,
        b"fourth"
    );
}

#[test]
fn corrupt_latest_payload_does_not_make_previous_valid_slot_reusable() {
    let (store, mut dev) = two_generations();
    dev.corrupt(9);
    dev.fail_event = Some(2); // Fail payload barrier after writing the corrupt slot.
    assert_eq!(
        store.commit_next(&mut dev, b"replacement"),
        Err(SnapshotBlockStoreError::Io)
    );
    assert_eq!(dev.events, [Event::Flush, Event::Write(9), Event::Flush]);
    dev.power_cut();
    assert_eq!(
        store.read_latest(&mut dev).unwrap().unwrap().payload,
        b"first"
    );
    assert_eq!(store.commit_next(&mut dev, b"replacement"), Ok(2));
}

#[test]
fn ambiguous_header_or_payload_io_prevents_slot_reuse() {
    for lba in [0, 8, 9] {
        let (store, mut dev) = two_generations();
        dev.fail_read = Some(lba);
        assert_eq!(
            store.commit_next(&mut dev, b"third"),
            Err(SnapshotBlockStoreError::Io)
        );
        assert_eq!(dev.events, [Event::Flush]);
    }
}

#[test]
fn corrupt_only_snapshot_is_not_silently_reinitialized() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut dev = CachedDisk::new();
    store.commit_next(&mut dev, b"first").unwrap();
    dev.corrupt(1);
    dev.events.clear();
    assert_eq!(
        store.commit_next(&mut dev, b"replacement"),
        Err(SnapshotBlockStoreError::Corrupt)
    );
    assert_eq!(dev.events, [Event::Flush]);
}

#[test]
fn generation_exhaustion_cannot_report_invisible_success() {
    let (store, mut dev) = two_generations();
    let header = SlotHeader {
        slot: 1,
        generation: u64::MAX,
        payload_len: 6,
        payload_crc: crc32c(b"second"),
        payload_sectors: 1,
    };
    encode_header(&mut dev.cache[8 * 512..9 * 512], header);
    dev.stable.copy_from_slice(&dev.cache);
    assert_eq!(
        store.commit_next(&mut dev, b"third"),
        Err(SnapshotBlockStoreError::OutOfSpace)
    );
    assert_eq!(dev.events, [Event::Flush]);
}

#[test]
fn streaming_crc_mismatch_never_publishes_a_header() {
    let (store, mut dev) = two_generations();
    assert_eq!(
        store.commit_next_streaming(&mut dev, 3, crc32c(b"bad"), |writer| writer
            .write_all(b"new")),
        Err(SnapshotBlockStoreError::Corrupt)
    );
    assert_eq!(dev.events, [Event::Flush, Event::Write(1)]);
    dev.power_cut();
    assert_eq!(
        store.read_latest(&mut dev).unwrap().unwrap().payload,
        b"second"
    );
}

#[test]
fn combined_crc_rejects_changed_truncated_and_extended_streams_before_publication() {
    use nt_config_store::codec::crc32c_combine;

    let header = b"captured snapshot header";
    let payload = alloc::vec![0x5a; 1300];
    let total_len = header.len() + payload.len();
    let expected_crc = crc32c_combine(crc32c(header), crc32c(&payload), payload.len() as u64);
    for drift in 0..3 {
        let (store, mut dev) = two_generations();
        let mut actual_payload = payload.clone();
        if drift == 0 {
            actual_payload[777] ^= 1;
        } else if drift == 1 {
            actual_payload.pop();
        }
        assert_eq!(
            store.commit_next_streaming(&mut dev, total_len, expected_crc, |writer| {
                writer.write_all(header)?;
                writer.write_all(&actual_payload)?;
                if drift == 2 {
                    // Even an encoder ignoring the overrun cannot publish a header.
                    assert_eq!(
                        writer.write_all(&[0]),
                        Err(SnapshotBlockStoreError::Corrupt)
                    );
                }
                Ok(())
            }),
            Err(SnapshotBlockStoreError::Corrupt)
        );
        assert_eq!(dev.events.first(), Some(&Event::Flush));
        assert!(!dev.events.contains(&Event::Write(0)));
        assert_eq!(
            dev.events
                .iter()
                .filter(|event| **event == Event::Flush)
                .count(),
            1
        );
        dev.power_cut();
        let previous = store.read_latest(&mut dev).unwrap().unwrap();
        assert_eq!(previous.generation, 2);
        assert_eq!(previous.payload, b"second");

        dev.events.clear();
        assert_eq!(
            store.commit_next_streaming(&mut dev, total_len, expected_crc, |writer| {
                writer.write_all(header)?;
                writer.write_all(&payload)
            }),
            Ok(3)
        );
        assert_eq!(
            dev.events,
            [
                Event::Flush,
                Event::Write(1),
                Event::Write(2),
                Event::Write(3),
                Event::Flush,
                Event::Write(0),
                Event::Flush
            ]
        );
        dev.power_cut();
        let committed = store.read_latest(&mut dev).unwrap().unwrap();
        assert_eq!(committed.generation, 3);
        assert_eq!(&committed.payload[..header.len()], header);
        assert_eq!(&committed.payload[header.len()..], payload);
    }
}

#[test]
fn empty_payload_still_persists_its_commit_header() {
    let (store, mut dev) = two_generations();
    assert_eq!(store.commit_next(&mut dev, b""), Ok(3));
    assert_eq!(
        dev.events,
        [Event::Flush, Event::Flush, Event::Write(0), Event::Flush]
    );
    dev.power_cut();
    assert!(store
        .read_latest(&mut dev)
        .unwrap()
        .unwrap()
        .payload
        .is_empty());
}
