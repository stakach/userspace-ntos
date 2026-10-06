use super::*;

#[test]
fn command_window_zero_interval_has_zero_deltas() {
    let census = CommandCensus::new();
    let window = CommandWindow::start(&census, Some(50));
    let result = window.finish(Some(50));
    assert_eq!(result.read, IoSnapshot::default());
    assert_eq!(result.write, IoSnapshot::default());
    assert_eq!(result.barrier, IoSnapshot::default());
    assert_eq!(result.elapsed_100ns, Some(0));
}

#[test]
fn command_window_samples_interleaved_operations_inclusively() {
    let census = CommandCensus::new();
    census.record(IoOperation::Read, 0, 9, 20, false);
    let window = CommandWindow::start(&census, Some(100));
    census.record(IoOperation::Read, 20, 23, 2, false);
    census.record(IoOperation::Write, 40, 47, 8, true);
    census.record(IoOperation::Barrier, 50, 51, 0, false);
    census.record(IoOperation::Read, 30, 35, 4, true);
    let result = window.finish(Some(117));
    assert_eq!(
        result.read,
        IoSnapshot {
            commands: 2,
            sectors: 6,
            ticks: 8,
            failures: 1
        }
    );
    assert_eq!(
        result.write,
        IoSnapshot {
            commands: 1,
            sectors: 8,
            ticks: 7,
            failures: 1
        }
    );
    assert_eq!(
        result.barrier,
        IoSnapshot {
            commands: 1,
            sectors: 0,
            ticks: 1,
            failures: 0
        }
    );
    assert_eq!(result.elapsed_100ns, Some(17));
    assert_eq!(census.snapshot(IoOperation::Read).commands, 3);
}

#[test]
fn command_window_wrapping_totals_preserve_all_four_deltas() {
    let census = CommandCensus::new();
    for operation in [IoOperation::Read, IoOperation::Write, IoOperation::Barrier] {
        let counters = census.counters(operation);
        counters.commands.store(u64::MAX, Ordering::Relaxed);
        counters.sectors.store(u64::MAX - 1, Ordering::Relaxed);
        counters.ticks.store(u64::MAX - 2, Ordering::Relaxed);
        counters.failures.store(u64::MAX, Ordering::Relaxed);
    }
    let window = CommandWindow::start(&census, Some(1));
    for operation in [IoOperation::Read, IoOperation::Write, IoOperation::Barrier] {
        census.record(operation, u64::MAX - 1, 3, 4, true);
    }
    let result = window.finish(Some(2));
    let expected = IoSnapshot {
        commands: 1,
        sectors: 4,
        ticks: 5,
        failures: 1,
    };
    assert_eq!(result.read, expected);
    assert_eq!(result.write, expected);
    assert_eq!(result.barrier, expected);
}

#[test]
fn command_window_missing_or_backwards_clock_has_no_elapsed_value() {
    let census = CommandCensus::new();
    for (start, end) in [
        (None, None),
        (None, Some(10)),
        (Some(10), None),
        (Some(10), Some(9)),
        (Some(u64::MAX), Some(0)),
    ] {
        assert_eq!(
            CommandWindow::start(&census, start)
                .finish(end)
                .elapsed_100ns,
            None
        );
    }
}

#[test]
fn command_window_ticks_are_not_converted_to_elapsed_units() {
    let census = CommandCensus::new();
    let window = CommandWindow::start(&census, Some(100));
    census.record(IoOperation::Write, 10, 900_010, 1, false);
    let result = window.finish(Some(101));
    assert_eq!(result.write.ticks, 900_000);
    assert_eq!(result.elapsed_100ns, Some(1));
}

#[test]
fn command_window_remains_bound_to_its_original_census() {
    let first = CommandCensus::new();
    let second = CommandCensus::new();
    let first_window = CommandWindow::start(&first, None);
    let second_window = CommandWindow::start(&second, None);
    second.record(IoOperation::Read, 0, 10, 3, true);
    first.record(IoOperation::Write, 0, 5, 2, false);
    let a = first_window.finish(None);
    let b = second_window.finish(None);
    assert_eq!(a.read, IoSnapshot::default());
    assert_eq!(a.write.commands, 1);
    assert_eq!(b.read.commands, 1);
    assert_eq!(b.write, IoSnapshot::default());
}
