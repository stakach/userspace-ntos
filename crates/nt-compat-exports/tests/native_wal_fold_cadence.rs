//! Background compaction may wait while the already-anchored WAL remains durable.

#[path = "../../../components/ntos-executive/src/wal_fold_cadence.rs"]
mod wal_fold_cadence;

use wal_fold_cadence::{background_fold_due, next_background_fold_deadline, MAX_DIRTY_AGE_100NS};

#[test]
fn small_durable_wal_records_coalesce_from_the_first_dirty_observation() {
    let first_dirty = 10 * 10_000_000;
    let capacity = 4096;
    assert_eq!(
        next_background_fold_deadline(Some(first_dirty)),
        Some(first_dirty + MAX_DIRTY_AGE_100NS)
    );
    for now in [first_dirty, first_dirty + 5 * 10_000_000, first_dirty + 30 * 10_000_000] {
        assert!(!background_fold_due(first_dirty, now, 64, capacity));
    }
    assert!(background_fold_due(
        first_dirty,
        first_dirty + MAX_DIRTY_AGE_100NS,
        64,
        capacity,
    ));
}

#[test]
fn wal_capacity_pressure_overrides_the_background_age() {
    let first_dirty = 10 * 10_000_000;
    let now = first_dirty + 10_000_000;
    assert!(!background_fold_due(first_dirty, now, 3071, 4096));
    assert!(background_fold_due(first_dirty, now, 3072, 4096));
    assert_eq!(next_background_fold_deadline(None), None);
}

#[test]
fn live_system_wal_fold_uses_durable_dirty_age_and_capacity_pressure() {
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let owner = include_str!("../../../components/ntos-executive/src/writable_fs/snapshot_storage.rs");
    let fold = include_str!("../../../components/ntos-executive/src/writable_fs/system_wal_fold.rs");
    assert!(service.contains("wal_fold_cadence::next_background_fold_deadline"));
    assert!(service.contains("wal_fold_cadence::background_fold_due"));
    assert!(!service.contains("SYSTEM_WAL_FOLD_INTERVAL_100NS"));
    assert!(owner.contains("note_durable_system_wal_mutation"));
    assert!(fold.contains("note_system_wal_fold_complete"));
}
