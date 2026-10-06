use super::*;

#[test]
fn categories_have_independent_attempt_sector_time_and_failure_totals() {
    let census = CommandCensus::new();
    census.record(IoOperation::Read, 10, 18, 3, false);
    census.record(IoOperation::Write, 20, 31, 7, true);
    census.record(IoOperation::Barrier, 32, 45, 0, false);
    assert_eq!(
        census.snapshot(IoOperation::Read),
        IoSnapshot {
            commands: 1,
            sectors: 3,
            ticks: 8,
            failures: 0
        }
    );
    assert_eq!(
        census.snapshot(IoOperation::Write),
        IoSnapshot {
            commands: 1,
            sectors: 7,
            ticks: 11,
            failures: 1
        }
    );
    assert_eq!(
        census.snapshot(IoOperation::Barrier),
        IoSnapshot {
            commands: 1,
            sectors: 0,
            ticks: 13,
            failures: 0
        }
    );
}

#[test]
fn failed_attempts_still_count_requested_sectors_and_elapsed_ticks() {
    let census = CommandCensus::new();
    census.record(IoOperation::Read, 5, 15, 12, true);
    census.record(IoOperation::Read, 20, 24, 2, false);
    census.record(IoOperation::Read, 30, 37, 5, true);
    assert_eq!(
        census.snapshot(IoOperation::Read),
        IoSnapshot {
            commands: 3,
            sectors: 19,
            ticks: 21,
            failures: 2
        }
    );
    assert_eq!(census.snapshot(IoOperation::Write), IoSnapshot::default());
    assert_eq!(census.snapshot(IoOperation::Barrier), IoSnapshot::default());
}

#[test]
fn non_data_barrier_attempt_and_failure_are_visible_with_zero_sectors() {
    let census = CommandCensus::new();
    census.record(IoOperation::Barrier, 100, 100, 0, true);
    census.record(IoOperation::Barrier, 101, 103, 0, false);
    assert_eq!(
        census.snapshot(IoOperation::Barrier),
        IoSnapshot {
            commands: 2,
            sectors: 0,
            ticks: 2,
            failures: 1
        }
    );
}

#[test]
fn timestamp_and_total_overflow_use_wrapping_arithmetic() {
    let census = CommandCensus::new();
    census.record(IoOperation::Write, u64::MAX - 2, 4, u64::MAX, false);
    census.record(IoOperation::Write, 0, u64::MAX, 2, true);
    assert_eq!(
        census.snapshot(IoOperation::Write),
        IoSnapshot {
            commands: 2,
            sectors: 1,
            ticks: 6,
            failures: 1
        }
    );
}

#[test]
fn const_initialization_starts_all_categories_empty() {
    const CENSUS: CommandCensus = CommandCensus::new();
    let census = CENSUS;
    for operation in [IoOperation::Read, IoOperation::Write, IoOperation::Barrier] {
        assert_eq!(census.snapshot(operation), IoSnapshot::default());
    }
}
