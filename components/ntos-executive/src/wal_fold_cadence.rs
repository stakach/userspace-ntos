//! Background compaction policy for an already durable, replayable registry WAL.

pub(crate) const MAX_DIRTY_AGE_100NS: u64 = 60 * 10_000_000;

pub(crate) fn next_background_fold_deadline(first_dirty: Option<u64>) -> Option<u64> {
    first_dirty.map(|at| at.saturating_add(MAX_DIRTY_AGE_100NS))
}

pub(crate) fn background_fold_due(
    first_dirty: u64,
    now: u64,
    used_sectors: u64,
    capacity_sectors: u64,
) -> bool {
    let pressure = capacity_sectors >= 4
        && used_sectors >= capacity_sectors.saturating_sub(capacity_sectors / 4);
    pressure || now.saturating_sub(first_dirty) >= MAX_DIRTY_AGE_100NS
}
