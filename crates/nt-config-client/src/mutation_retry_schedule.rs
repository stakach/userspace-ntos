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

#[cfg(test)]
mod tests {
    use super::*;

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
