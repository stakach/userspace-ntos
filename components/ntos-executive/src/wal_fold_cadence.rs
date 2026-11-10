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

/// Read the clock only for an existing durable WAL epoch, and return the same
/// observation to the caller so a failed fold can schedule its retry from it.
pub(crate) fn background_fold_due_time_if_owned(
    first_dirty: Option<u64>,
    used_sectors: u64,
    capacity_sectors: u64,
    now: impl FnOnce() -> u64,
) -> Option<u64> {
    let first_dirty = first_dirty?;
    let now = now();
    background_fold_due(first_dirty, now, used_sectors, capacity_sectors).then_some(now)
}
