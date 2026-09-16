use super::*;
use alloc::vec;

#[test]
fn programming_writes_mode_then_low_and_high_bytes() {
    let shot = PitOneShot {
        reload: 0x1234,
        ticks: 0x1234,
        wake_deadline_100ns: 100,
        chunked: false,
    };
    let mut writes = Vec::new();
    shot.program(|port, value| {
        writes.push((port, value));
        Ok::<_, ()>(())
    })
    .unwrap();
    assert_eq!(writes, vec![(0x43, 0x30), (0x40, 0x34), (0x40, 0x12)]);
}

#[test]
fn programming_failure_stops_at_each_failed_write() {
    let shot = pit_oneshot_for_deadline(0, 100, 0);
    for failure in 0..3 {
        let mut calls = 0;
        let result = shot.program(|_, _| {
            let index = calls;
            calls += 1;
            if index == failure {
                Err(failure)
            } else {
                Ok(())
            }
        });
        assert_eq!(result, Err(failure));
        assert_eq!(calls, failure + 1);
    }
}

#[test]
fn maximum_interval_programs_zero_reload_without_truncating_the_wait() {
    let shot = pit_oneshot_for_deadline(0, 10_000_000, 0);
    assert!(shot.chunked);
    let mut writes = Vec::new();
    shot.program(|port, value| {
        writes.push((port, value));
        Ok::<_, ()>(())
    })
    .unwrap();
    assert_eq!(writes, vec![(0x43, 0x30), (0x40, 0), (0x40, 0)]);
    assert!(shot.wake_deadline_100ns < 10_000_000);
}

#[test]
fn deferred_notification_after_rearm_does_not_expire_the_new_deadline() {
    let mut clock = FakeClock::new();
    let mut timers = TimerQueue::new();
    timers.set(1, -100, 0, Some(11), &clock);
    let old_shot = pit_oneshot_for_deadline(0, 100, 0);
    clock.advance_100ns(old_shot.wake_deadline_100ns);
    // The old notification is pending, but the timer is reset before it is drained.
    assert!(timers.set(1, -10_000, 0, Some(12), &clock));
    let deadline = clock.snapshot().monotonic_100ns + 10_000;
    let new_shot = pit_oneshot_for_deadline(clock.snapshot().monotonic_100ns, deadline, 0);
    new_shot.program(|_, _| Ok::<_, ()>(())).unwrap();
    for _ in 0..3 {
        assert!(timers.run_due(&clock).is_empty());
        assert!(!timers.read_state(1));
    }
    clock.advance_100ns(9_999);
    assert!(timers.run_due(&clock).is_empty());
    clock.advance_100ns(1);
    assert_eq!(timers.run_due(&clock), vec![12]);
    assert!(timers.run_due(&clock).is_empty());
}

#[test]
fn cancelled_notification_and_chunk_wakes_do_not_advance_time() {
    let mut clock = FakeClock::new();
    let mut timers = TimerQueue::new();
    timers.set(1, -10, 0, Some(11), &clock);
    timers.set(2, -10_000_000, 0, Some(22), &clock);
    assert!(timers.cancel(1));
    let chunk = pit_oneshot_for_deadline(0, 10_000_000, 0);
    assert!(chunk.chunked);
    assert!(timers.run_due(&clock).is_empty());
    clock.advance_100ns(chunk.wake_deadline_100ns);
    assert!(timers.run_due(&clock).is_empty());
    let next_chunk = pit_oneshot_for_deadline(clock.snapshot().monotonic_100ns, 10_000_000, 0);
    next_chunk.program(|_, _| Ok::<_, ()>(())).unwrap();
    assert!(timers.run_due(&clock).is_empty());
    clock.advance_100ns(10_000_000 - clock.snapshot().monotonic_100ns);
    assert_eq!(timers.run_due(&clock), vec![22]);
    assert!(!timers.read_state(1));
}
