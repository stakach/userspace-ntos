use super::*;
use crate::{OwnedBoundedBlockRange, RegistryWal};

const MIB_SECTORS: u64 = 1024 * 1024 / 512;
const WAL_START: u64 = 16 * MIB_SECTORS;
const WAL_SECTORS: u64 = 16 * MIB_SECTORS;
const SNAPSHOT_START: u64 = 32 * MIB_SECTORS;
const SLOT_SECTORS: u64 = 32 * MIB_SECTORS;
const INCARNATION: u64 = 77;

fn recovered_disk(
    store: SnapshotBlockStore,
    mut disk: CachedDisk,
    expected_generation: u64,
    expected_payload: &[u8],
    expected_base_serial: u64,
    expected_anchor: WalSnapshotAnchor,
) -> CachedDisk {
    let selected = store.read_latest_wal(&mut disk).unwrap().unwrap();
    assert_eq!(selected.snapshot.generation, expected_generation);
    assert_eq!(selected.snapshot.payload, expected_payload);
    assert_eq!(selected.selected_base_serial, expected_base_serial);
    assert_eq!(selected.anchor, expected_anchor);

    let range = OwnedBoundedBlockRange::new(disk, WAL_START, WAL_SECTORS).ok().unwrap();
    let wal = RegistryWal::recover(range, INCARNATION).unwrap();
    assert_eq!(selected.verify_recovered_wal(&wal), Ok(()));
    assert_eq!(wal.records().len(), 1);
    assert_eq!(wal.records()[0].payload, b"committed-before-fold");
    wal.into_device().ok().unwrap().into_device()
}

/// A relocated 32 MiB slot must publish an image too large for the former 8 MiB slot without
/// losing its disjoint SYSTEM WAL floor at either header boundary. A failed final flush can
/// persist the new header, so recovery must use the disk rather than the API's error alone.
#[test]
fn relocated_large_fold_recovers_at_each_header_power_cut() {
    let store = SnapshotBlockStore::new(SNAPSHOT_START, 2 * SLOT_SECTORS);
    let old_store = SnapshotBlockStore::new(0, 16 * MIB_SECTORS);
    let mut disk = CachedDisk::with_sectors((SNAPSHOT_START + 2 * SLOT_SECTORS) as usize);
    let large = alloc::vec![0xa5; 8 * 1024 * 1024 + 4096];
    assert!(large.len() > old_store.payload_capacity(&disk).unwrap());
    assert!(large.len() < store.payload_capacity(&disk).unwrap());

    let baseline = WalSnapshotManifest {
        incarnation: INCARNATION,
        base_serial: 0,
        high_water_serial: 0,
        high_water_end_lba: 0,
    };
    assert_eq!(store.commit_next_with_wal_manifest(&mut disk, b"base", baseline), Ok(1));
    assert_eq!(store.commit_next_with_wal_manifest(&mut disk, b"base", baseline), Ok(2));

    let range = OwnedBoundedBlockRange::new(disk, WAL_START, WAL_SECTORS).ok().unwrap();
    let mut wal = RegistryWal::recover(range, INCARNATION).unwrap();
    wal.begin(b"committed-before-fold".to_vec()).unwrap();
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
        incarnation,
        base_serial: serial,
        high_water_serial: serial,
        high_water_end_lba: end_lba,
    };
    assert_eq!(store.current_wal_checkpoint_manifest(&mut disk).unwrap().base_serial, 0);

    // The synchronous adapter emits one preflush, one write per payload sector, then the
    // payload flush before the target header. Stop before that first header takes effect.
    let header_event = large.len().div_ceil(512) + 2;
    disk.events.clear();
    disk.fail_event = Some(header_event);
    assert_eq!(store.commit_next_with_wal_manifest(&mut disk, &large, folded),
        Err(SnapshotBlockStoreError::Io));
    assert_eq!(disk.events.last(), Some(&Event::Write(SNAPSHOT_START)));
    disk.power_cut();
    disk = recovered_disk(store, disk, 2, b"base", 0, anchor);

    // The first header may reach stable media even if its final flush reports failure.
    disk.events.clear();
    disk.fail_event = Some(header_event + 1);
    disk.partial_flush = true;
    assert_eq!(store.commit_next_with_wal_manifest(&mut disk, &large, folded),
        Err(SnapshotBlockStoreError::Io));
    assert_eq!(disk.events.last(), Some(&Event::Flush));
    disk.power_cut();
    disk = recovered_disk(store, disk, 3, &large, serial, anchor);

    // Replacing the second slot has the same two crash cuts. The first large slot stays
    // authoritative even if the old companion's payload is torn before its header changes.
    disk.events.clear();
    disk.partial_flush = false;
    disk.fail_event = Some(header_event);
    assert_eq!(store.commit_next_with_wal_manifest(&mut disk, &large, folded),
        Err(SnapshotBlockStoreError::Io));
    assert_eq!(disk.events.last(), Some(&Event::Write(SNAPSHOT_START + SLOT_SECTORS)));
    disk.power_cut();
    disk = recovered_disk(store, disk, 3, &large, serial, anchor);

    disk.events.clear();
    disk.fail_event = Some(header_event + 1);
    disk.partial_flush = true;
    assert_eq!(store.commit_next_with_wal_manifest(&mut disk, &large, folded),
        Err(SnapshotBlockStoreError::Io));
    disk.power_cut();
    let mut disk = recovered_disk(store, disk, 4, &large, serial, anchor);
    let pair = store.verify_paired_wal_snapshot(&mut disk).unwrap();
    assert_eq!(pair.manifest(), folded);
    assert_eq!(pair.anchor(), anchor);
}
