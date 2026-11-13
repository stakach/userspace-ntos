//! Value-only selection of retained registry mutations by their own retry deadlines.

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

#[cfg(test)]
mod tests {
    use super::*;

    const RETRY_DELAY: u64 = 10_000_000;

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
