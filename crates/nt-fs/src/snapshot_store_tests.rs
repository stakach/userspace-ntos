use super::*;
use crate::snapshot_test_device::{CachedDisk, Event};

#[path = "snapshot_store_tests/batched_reads.rs"]
mod batched_reads;

#[path = "snapshot_store_tests/batched_writes.rs"]
mod batched_writes;

#[path = "snapshot_store_tests/wide_batches.rs"]
mod wide_batches;

#[path = "snapshot_store_tests/wal_manifest.rs"]
mod wal_manifest;

#[path = "snapshot_store_tests/wal_epoch_rollover.rs"]
mod wal_epoch_rollover;

#[path = "snapshot_store_tests/async_commit.rs"]
mod async_commit;

#[path = "snapshot_store_tests/async_header_recheck.rs"]
mod async_header_recheck;

#[path = "snapshot_store_tests/async_wal_anchor.rs"]
mod async_wal_anchor;

#[path = "snapshot_store_tests/hive_wal_publication.rs"]
mod hive_wal_publication;

#[path = "snapshot_store_tests/large_slot_powercuts.rs"]
mod large_slot_powercuts;

fn two_generations() -> (SnapshotBlockStore, CachedDisk) {
    let store = SnapshotBlockStore::new(0, 16);
    let mut dev = CachedDisk::new();
    assert_eq!(store.commit_next(&mut dev, b"first"), Ok(1));
    assert_eq!(store.commit_next(&mut dev, b"second"), Ok(2));
    dev.events.clear();
    (store, dev)
}

/// The migration changes slot spacing, not header encoding or payload contents. Keep only
/// written sectors while retaining the real LBA geometry of the installed reserve.
struct SparseMigrationDisk {
    sectors: u64,
    written: alloc::collections::BTreeMap<u64, [u8; 512]>,
}

impl SparseMigrationDisk {
    fn new(sectors: u64) -> Self {
        Self { sectors, written: alloc::collections::BTreeMap::new() }
    }

    fn copy_slot_start_from(
        &mut self,
        source: &Self,
        source_start: u64,
        target_start: u64,
        slot_sectors: u64,
    ) {
        for (&lba, sector) in source.written.range(source_start..source_start + slot_sectors) {
            self.write_sector(target_start + (lba - source_start), sector).unwrap();
        }
    }
}

impl SnapshotBlockDevice for SparseMigrationDisk {
    fn sector_size(&self) -> usize { 512 }
    fn sector_count(&self) -> u64 { self.sectors }

    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        if lba >= self.sectors || out.len() != 512 {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        out.copy_from_slice(self.written.get(&lba).unwrap_or(&[0; 512]));
        Ok(())
    }

    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        if lba >= self.sectors || data.len() != 512 {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        let mut sector = [0; 512];
        sector.copy_from_slice(data);
        self.written.insert(lba, sector);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), SnapshotBlockStoreError> { Ok(()) }
}

#[test]
fn relocated_eight_mib_slots_keep_latest_generation_and_wal_proof() {
    use crate::{OwnedBoundedBlockRange, RegistryWal};

    const MIB_SECTORS: u64 = 1024 * 1024 / 512;
    const WAL_SECTORS: u64 = 16 * MIB_SECTORS;
    const OLD_SLOT_SECTORS: u64 = 8 * MIB_SECTORS;
    const NEW_SLOT_SECTORS: u64 = 32 * MIB_SECTORS;
    const INCARNATION: u64 = 77;

    let old_store = SnapshotBlockStore::new(0, 2 * OLD_SLOT_SECTORS);
    let new_store = SnapshotBlockStore::new(WAL_SECTORS, 2 * NEW_SLOT_SECTORS);
    let mut old = SparseMigrationDisk::new(2 * OLD_SLOT_SECTORS);
    let baseline = WalSnapshotManifest {
        incarnation: INCARNATION,
        base_serial: 0,
        high_water_serial: 0,
        high_water_end_lba: 0,
    };
    assert_eq!(old_store.commit_next_with_wal_manifest(&mut old, b"older", baseline), Ok(1));
    assert_eq!(old_store.commit_next_with_wal_manifest(&mut old, b"latest", baseline), Ok(2));

    let new = SparseMigrationDisk::new(WAL_SECTORS + 2 * NEW_SLOT_SECTORS);
    let range = OwnedBoundedBlockRange::new(new, 0, WAL_SECTORS).ok().unwrap();
    let mut wal = RegistryWal::recover(range, INCARNATION).unwrap();
    wal.begin(b"committed-before-slot-migration".to_vec()).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let (incarnation, serial, end_lba) = wal.verified_prefix().unwrap();
    let anchor = WalSnapshotAnchor { incarnation, serial, end_lba };
    assert_eq!(serial, 1);
    let mut new = wal.into_device().ok().unwrap().into_device();

    let mut update = WalSnapshotAnchorUpdate::admit(old_store, old, anchor).ok().unwrap();
    update.advance().unwrap();
    old = update.into_device().unwrap();
    assert_eq!(old_store.verify_paired_wal_snapshot(&mut old).unwrap().anchor(), anchor);

    // Copy each complete old 8 MiB slot into the beginning of its new 32 MiB slot.
    // Unwritten sparse sectors represent the copied zero-filled remainder.
    for slot in 0..2 {
        new.copy_slot_start_from(
            &old,
            slot * OLD_SLOT_SECTORS,
            WAL_SECTORS + slot * NEW_SLOT_SECTORS,
            OLD_SLOT_SECTORS,
        );
    }
    assert!(!new.written.contains_key(&(WAL_SECTORS + OLD_SLOT_SECTORS)),
        "the old second-slot header must not remain at its former spacing");
    assert!(new.written.contains_key(&(WAL_SECTORS + NEW_SLOT_SECTORS)));

    let recovered = new_store.read_latest_wal(&mut new).unwrap().unwrap();
    assert_eq!(recovered.snapshot.generation, 2);
    assert_eq!(recovered.snapshot.payload, b"latest");
    assert_eq!(recovered.selected_base_serial, 0);
    assert_eq!(recovered.anchor, anchor);

    let proof = new_store.verify_paired_wal_snapshot(&mut new).unwrap();
    assert_eq!(proof.manifest().high_water_serial, 1);
    assert_eq!(proof.anchor(), anchor);
    assert!(proof.matches_cached_fence(new_store, anchor));
    assert!(!proof.matches_cached_fence(old_store, anchor));
    assert_eq!(new_store.recheck_verified_paired_wal_snapshot(&mut new, &proof),
        Ok(proof.manifest()));

    let range = OwnedBoundedBlockRange::new(new, 0, WAL_SECTORS).ok().unwrap();
    let wal = RegistryWal::recover(range, INCARNATION).unwrap();
    assert_eq!(recovered.verify_recovered_wal(&wal), Ok(()));
}

#[test]
fn async_epoch_rollover_admits_disjoint_wal_before_nonzero_snapshot_store() {
    use crate::{AsyncWalEpochRollover, OwnedBoundedBlockRange, RegistryWal};

    const MIB_SECTORS: u64 = 1024 * 1024 / 512;
    const WAL_SECTORS: u64 = 16 * MIB_SECTORS;
    const SNAPSHOT_SLOT_SECTORS: u64 = 32 * MIB_SECTORS;
    let store = SnapshotBlockStore::new(WAL_SECTORS, 2 * SNAPSHOT_SLOT_SECTORS);
    let store_end = WAL_SECTORS + 2 * SNAPSHOT_SLOT_SECTORS;
    assert!(!store.contains_sector_range(WAL_SECTORS - 1, 1));
    assert!(!store.contains_sector_range(WAL_SECTORS, 0));
    assert!(store.contains_sector_range(WAL_SECTORS, 1));
    assert!(store.contains_sector_range(store_end - 1, 1));
    assert!(!store.contains_sector_range(store_end - 1, 2));
    let mut disk = SparseMigrationDisk::new(WAL_SECTORS + 2 * SNAPSHOT_SLOT_SECTORS);
    let empty = WalSnapshotManifest {
        incarnation: 77, base_serial: 0,
        high_water_serial: 0, high_water_end_lba: 0,
    };
    store.commit_next_with_wal_manifest(&mut disk, b"old", empty).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"old", empty).unwrap();

    let range = OwnedBoundedBlockRange::new(disk, 0, WAL_SECTORS).ok().unwrap();
    let mut wal = RegistryWal::recover(range, 77).unwrap();
    wal.begin(b"durable-before-fold".to_vec()).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let (incarnation, serial, end_lba) = wal.verified_prefix().unwrap();
    assert_eq!(serial, 1);
    let anchor = WalSnapshotAnchor { incarnation, serial, end_lba };
    let disk = wal.into_device().ok().unwrap().into_device();
    let mut update = WalSnapshotAnchorUpdate::admit(store, disk, anchor).ok().unwrap();
    update.advance().unwrap();
    let mut disk = update.into_device().unwrap();

    let folded = WalSnapshotManifest {
        incarnation, base_serial: serial,
        high_water_serial: serial, high_water_end_lba: end_lba,
    };
    store.commit_next_with_wal_manifest(&mut disk, b"folded", folded).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"folded", folded).unwrap();
    let pair = store.verify_paired_wal_snapshot(&mut disk).unwrap();
    assert_eq!(pair.manifest(), folded, "the proof must cover both real folded payloads");

    let (error, pair) = AsyncWalEpochRollover::admit(
        store, pair, WAL_SECTORS, 1, 88, disk.sector_size(), disk.sector_count(),
    ).err().expect("overlapping WAL and snapshot ranges must be rejected");
    assert_eq!(error, SnapshotBlockStoreError::Corrupt);
    let (error, pair) = AsyncWalEpochRollover::admit(
        store, pair, u64::MAX, 2, 88, disk.sector_size(), disk.sector_count(),
    ).err().expect("overflowing WAL range must be rejected");
    assert_eq!(error, SnapshotBlockStoreError::Corrupt);

    let mut rollover = AsyncWalEpochRollover::admit(
        store, pair, 0, WAL_SECTORS, 88, disk.sector_size(), disk.sector_count(),
    ).ok().expect("a disjoint WAL before the snapshots must be admissible");
    let first = rollover.enter_next().unwrap().unwrap();
    assert_eq!(first.lba, WAL_SECTORS, "reset starts at the first snapshot header");
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
        wal: None,
        resetting: false,
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
