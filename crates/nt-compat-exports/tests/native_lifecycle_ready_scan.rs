//! Exercise the native retained-owner readiness pass used by nested pump gates (#348).
#[path = "../../../components/ntos-executive/src/lifecycle_ready_scan.rs"]
mod ready_scan;

use ready_scan::{first_ready, PassClock};
use std::cell::Cell;

/// Rows as (retry_after, ready); the pass returns the first ready, undeferred slot.
fn pass(rows: &[(u64, bool)], now: u64, reads: &Cell<usize>, evaluated: &Cell<usize>) -> Option<usize> {
    let mut clock = PassClock::new(|| { reads.set(reads.get() + 1); now });
    first_ready(rows.len(), &mut clock, |slot, clock| {
        evaluated.set(evaluated.get() + 1);
        !clock.deferred(rows[slot].0) && rows[slot].1
    })
}

#[test]
fn one_pass_evaluates_each_row_once_and_samples_the_clock_at_most_once() {
    // 500 deferred rows ahead of one ready row: a lookup-per-row scan would search the table
    // for every row (O(n^2)) and read the clock for each deferred row.
    let mut rows = vec![(1_000, true); 500];
    rows.push((0, true));
    let (reads, evaluated) = (Cell::new(0), Cell::new(0));
    assert_eq!(pass(&rows, 10, &reads, &evaluated), Some(500));
    assert_eq!(evaluated.get(), 501);
    assert_eq!(reads.get(), 1);

    // An expired deadline is ready; rows without deadlines never read the clock.
    let (reads, evaluated) = (Cell::new(0), Cell::new(0));
    assert_eq!(pass(&[(0, false), (5, true)], 10, &reads, &evaluated), Some(1));
    assert_eq!((reads.get(), evaluated.get()), (1, 2));
    let (reads, evaluated) = (Cell::new(0), Cell::new(0));
    assert_eq!(pass(&[(0, false), (0, false)], 10, &reads, &evaluated), None);
    assert_eq!((reads.get(), evaluated.get()), (0, 2));
    // The pass stops at the first ready row.
    let (reads, evaluated) = (Cell::new(0), Cell::new(0));
    assert_eq!(pass(&[(0, true), (99, true)], 10, &reads, &evaluated), Some(0));
    assert_eq!((reads.get(), evaluated.get()), (0, 1));
}
