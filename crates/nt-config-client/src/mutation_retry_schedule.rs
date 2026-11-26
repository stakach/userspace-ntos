//! Value-only selection of retained registry mutations by their own retry deadlines.

use core::sync::atomic::{AtomicU64, Ordering};

/// A hint from one authenticated native hive terminal. It authorizes no journal poll,
/// publication, or Reply; the retained row must still revalidate its exact journal.
pub struct MutableHiveCompletionHint { journal: AtomicU64 }

impl MutableHiveCompletionHint {
    pub const fn new() -> Self { Self { journal: AtomicU64::new(0) } }

    pub fn publish(&self, journal: u64) -> bool {
        journal != 0 && self.journal.compare_exchange(0, journal,
            Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    pub fn current(&self) -> Option<u64> {
        let journal = self.journal.load(Ordering::Acquire);
        (journal != 0).then_some(journal)
    }

    pub fn clear_exact(&self, journal: u64) -> bool {
        journal != 0 && self.journal.compare_exchange(journal, 0,
            Ordering::AcqRel, Ordering::Acquire).is_ok()
    }
}

impl Default for MutableHiveCompletionHint {
    fn default() -> Self { Self::new() }
}

/// A timed pass retains the existing all-row scan. An exact physical hive terminal may
/// advance only the row that still owns its journal; neither mode claims that row or its Reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutableHivePass { Timed, ExactJournal(u64) }

impl MutableHivePass {
    pub fn row_due(self, journal_id: Option<u64>, polling_journal: bool) -> bool {
        match self {
            Self::Timed => true,
            Self::ExactJournal(id) => polling_journal && journal_id == Some(id),
        }
    }

    pub fn is_timed(self) -> bool { matches!(self, Self::Timed) }
}

pub fn mutable_hive_pass(
    pending: u64, now: u64, deadline: u64, completed_journal: Option<u64>,
) -> Option<MutableHivePass> {
    if pending == 0 { return None; }
    if now >= deadline { return Some(MutableHivePass::Timed); }
    completed_journal.filter(|id| *id != 0).map(MutableHivePass::ExactJournal)
}

pub fn mutable_hive_deadline(
    pending: u64, notification_waiting: u64, notification_ready: bool,
    deadline: u64, completed_journal: Option<u64>, active: bool, now: u64,
) -> Option<u64> {
    if pending == 0 { return None; }
    if !active && completed_journal.is_some_and(|id| id != 0) { return Some(now); }
    (pending > notification_waiting || notification_ready).then_some(deadline)
}

/// Select the first eligible row at or after the round-robin cursor. `None` excludes an absent
/// row or one whose caller kind cannot run at this boundary; no owner is claimed here.
pub fn select_ready_index(
    count: usize,
    start: usize,
    now: u64,
    mut retry_at: impl FnMut(usize) -> Option<u64>,
) -> Option<usize> {
    if count == 0 { return None; }
    let start = start % count;
    (0..count).map(|step| (start + step) % count)
        .find(|&index| retry_at(index).is_some_and(|deadline| deadline <= now))
}

/// Earliest retained wake across all rows, including caller kinds unavailable to a nested drive.
pub fn earliest_retry_deadline(
    count: usize,
    mut retry_at: impl FnMut(usize) -> Option<u64>,
) -> Option<u64> {
    (0..count).filter_map(|index| retry_at(index)).min()
}

/// The row whose storage admission retained native header recheck `settled`.
///
/// A refused admission waits for that recheck to reach a terminal state, not for its retry
/// delay: the caller makes the returned row ready at once, and the delay stays as the bound for
/// a wake that never arrives. Zero names no recheck, and only an exact match is returned, so an
/// unrelated settlement leaves every row on its own deadline.
pub fn header_recheck_waiter(
    count: usize,
    settled: u64,
    mut recheck_id: impl FnMut(usize) -> Option<u64>,
) -> Option<usize> {
    if settled == 0 { return None; }
    (0..count).find(|&index| recheck_id(index) == Some(settled))
}

/// Ready every row that BEGIN refused because another mutation held the writer lease.
///
/// A mutation that completes has released that lease, which is what those rows wait for.
/// `ready` receives each such row; the count is returned. The retry delay stays as the bound
/// for a lease held outside this table. Rows waiting for anything else are left alone.
pub fn ready_writer_waiters(
    count: usize,
    mut waits_for_writer: impl FnMut(usize) -> bool,
    mut ready: impl FnMut(usize),
) -> usize {
    let mut woken = 0;
    for index in 0..count {
        if waits_for_writer(index) {
            ready(index);
            woken += 1;
        }
    }
    woken
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const RETRY_DELAY: u64 = 10_000_000;

    #[test]
    fn current_mutable_hive_pass_keeps_the_shared_deadline_and_row_order() {
        assert_eq!(mutable_hive_deadline(2, 0, false, 150, None, false, 100), Some(150));
        assert_eq!(mutable_hive_deadline(1, 1, false, 150, None, false, 100), None);
        assert_eq!(mutable_hive_deadline(1, 1, true, 150, None, false, 100), Some(150));
        assert!(mutable_hive_pass(2, 149, 150, None).is_none());
        let pass = mutable_hive_pass(2, 150, 150, None).unwrap();
        assert_eq!((0..3).filter(|_| pass.row_due(None, false)).collect::<Vec<_>>(),
            alloc::vec![0, 1, 2]);
        assert!(mutable_hive_pass(0, 150, 150, None).is_none());
    }

    #[test]
    fn exact_hive_terminal_must_not_advance_an_unrelated_poll_row() {
        // A's authenticated physical terminal can make A ready before the 10 ms fallback.
        // Under the current shared NEXT gate, setting it to `now` also selects B, which
        // remains in Begin while the singleton journal belongs to A.
        let now = 100;
        let journal_ids = [Some(7), None];
        let authenticated_terminal = 7;
        let fallback = 100_100;
        assert!(mutable_hive_pass(2, now, fallback, None).is_none());
        let pass = mutable_hive_pass(2, now, fallback, Some(authenticated_terminal)).unwrap();
        let selected: Vec<_> = (0..journal_ids.len())
            .filter(|&index| pass.row_due(journal_ids[index], index == 0)).collect();
        let expected: Vec<_> = journal_ids.iter().enumerate()
            .filter_map(|(index, journal)| (*journal == Some(authenticated_terminal))
            .then_some(index)).collect();
        assert_eq!(selected, expected,
            "an exact completion wake may select only the row that owns its journal");
        assert_eq!(mutable_hive_deadline(2, 0, false, fallback,
            Some(authenticated_terminal), false, now), Some(now));
        assert!(!mutable_hive_pass(2, now, fallback, Some(9)).unwrap()
            .row_due(journal_ids[0], true));
    }

    #[test]
    fn exact_completion_hint_is_one_shot_and_stale_rows_cannot_spin_the_timer() {
        let hint = MutableHiveCompletionHint::new();
        assert!(!hint.publish(0));
        assert!(hint.publish(7));
        assert!(!hint.publish(9), "a second journal cannot replace an unconsumed hint");
        assert_eq!(hint.current(), Some(7));
        assert!(!hint.clear_exact(9));
        assert_eq!(mutable_hive_deadline(1, 0, false, 500, hint.current(), false, 100), Some(100));
        assert!(!mutable_hive_pass(1, 100, 500, hint.current()).unwrap()
            .row_due(Some(9), true),
            "a newer singleton journal keeps its timed fallback if an old hint wins the slot");
        assert_eq!(mutable_hive_deadline(0, 0, false, 500, hint.current(), false, 100), None,
            "a retired row cannot arm an immediate timer even with a stale hint");
        assert_eq!(mutable_hive_deadline(1, 0, false, 500, hint.current(), true, 100), Some(500),
            "an active row must finish before its retained hint can arm an immediate timer");
        let pass = mutable_hive_pass(1, 100, 500, hint.current()).unwrap();
        assert!(!pass.row_due(Some(9), true), "a reused row cannot claim a stale hint");
        assert!(hint.clear_exact(7));
        assert_eq!(hint.current(), None);
        assert_eq!(mutable_hive_deadline(1, 0, false, 500, hint.current(), false, 100), Some(500));
        assert!(hint.publish(9));
        assert!(hint.clear_exact(9));
        assert!(!hint.clear_exact(9), "duplicate retirement cannot consume a new hint");
    }

    #[test]
    fn settled_header_recheck_readies_its_refused_admission_before_the_retry_delay() {
        // Row 0 was refused at t=100 while header recheck 7 ran; row 1 waits on a timed retry.
        let rechecks = [Some(7), None];
        let mut deadlines = [Some(100 + RETRY_DELAY), Some(150 + RETRY_DELAY)];
        assert_eq!(select_ready_index(2, 0, 120, |index| deadlines[index]), None);

        let woken = header_recheck_waiter(2, 7, |index| rechecks[index]);
        assert_eq!(woken, Some(0), "the recheck terminal is the event the admission waits for");
        deadlines[woken.unwrap()] = Some(120);
        assert_eq!(select_ready_index(2, 1, 120, |index| deadlines[index]), Some(0));
        assert_eq!(earliest_retry_deadline(2, |index| deadlines[index]), Some(120));
        assert_eq!(deadlines[1], Some(150 + RETRY_DELAY), "an unrelated row keeps its deadline");
    }

    #[test]
    fn released_writer_lease_readies_its_waiter_ahead_of_the_next_mutation() {
        // Slot 0 just completed and its caller already submitted the next mutation there.
        // Slot 1 was refused by BEGIN while slot 0 held the lease; slot 2 is on a timed retry.
        let waits_for_writer = [false, true, false];
        let mut deadlines = [Some(0), Some(100 + RETRY_DELAY), Some(100 + RETRY_DELAY)];
        let woken = ready_writer_waiters(3, |index| waits_for_writer[index],
            |index| deadlines[index] = Some(130));
        assert_eq!(woken, 1);
        assert_eq!(deadlines, [Some(0), Some(130), Some(100 + RETRY_DELAY)]);
        // The cursor follows the completed slot, so the waiter runs before slot 0's new row.
        assert_eq!(select_ready_index(3, 1, 130, |index| deadlines[index]), Some(1),
            "the row that waited for the lease must not lose it again to the same caller");
    }

    #[test]
    fn no_writer_waiter_means_no_wake() {
        let mut readied = 0;
        assert_eq!(ready_writer_waiters(3, |_| false, |_| readied += 1), 0);
        assert_eq!(ready_writer_waiters(0, |_| true, |_| readied += 1), 0);
        assert_eq!(readied, 0);
    }

    #[test]
    fn an_unrelated_or_absent_recheck_wakes_no_row() {
        let rechecks = [Some(7), None, Some(9)];
        assert_eq!(header_recheck_waiter(3, 8, |index| rechecks[index]), None);
        assert_eq!(header_recheck_waiter(3, 0, |index| rechecks[index]), None,
            "zero is not a recheck identity");
        assert_eq!(header_recheck_waiter(3, 0, |_| Some(0)), None);
        assert_eq!(header_recheck_waiter(0, 7, |_| Some(7)), None);
        assert_eq!(header_recheck_waiter(3, 9, |index| rechecks[index]), Some(2));
    }

    #[test]
    fn busy_row_does_not_delay_an_independent_ready_row() {
        let deadlines = [Some(100), Some(0)];
        assert_eq!(select_ready_index(2, 0, 50, |index| deadlines[index]), Some(1));
        assert_eq!(earliest_retry_deadline(2, |index| deadlines[index]), Some(0));
        assert_eq!(select_ready_index(2, 0, 100, |index| deadlines[index]), Some(0));
    }

    #[test]
    fn nested_provider_selection_excludes_hosted_rows_without_hiding_their_wake() {
        let deadlines = [Some(0), Some(80), Some(40)];
        assert_eq!(select_ready_index(3, 0, 50, |index| {
            (index != 0).then_some(deadlines[index]).flatten()
        }), Some(2));
        assert_eq!(select_ready_index(3, 0, 50, |index| {
            (index == 1).then_some(deadlines[index]).flatten()
        }), None);
        assert_eq!(earliest_retry_deadline(3, |index| deadlines[index]), Some(0));
    }

    #[test]
    fn exact_wal_settlement_makes_only_its_row_ready() {
        let mut deadlines = [Some(100), Some(150)];
        assert_eq!(earliest_retry_deadline(2, |index| deadlines[index]), Some(100));
        deadlines[1] = Some(40);
        assert_eq!(select_ready_index(2, 1, 40, |index| deadlines[index]), Some(1));
        assert_eq!(earliest_retry_deadline(2, |index| deadlines[index]), Some(40));
    }
}
