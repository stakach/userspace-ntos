use super::*;
use crate::{HostedDpcOwner, HostedDpcQueueResult, HostedDpcTable};

#[test]
fn finite_wait_requires_programming_not_merely_an_available_owner() {
    for (outcome, available, programmed) in [
        (TimerRearmOutcome::Unavailable, false, false),
        (TimerRearmOutcome::Idle, true, false),
        (TimerRearmOutcome::Programmed, true, true),
        (TimerRearmOutcome::Failed, false, false),
    ] {
        assert_eq!(outcome.owner_available(), available);
        assert_eq!(outcome.deadline_programmed(), programmed);
    }
}
use alloc::vec;

#[test]
fn receive_preflight_checks_every_owner_state_before_rearm_effects() {
    for registered in [false, true] {
        for active in [false, true] {
            for delivery_running in [false, true] {
                for continuation_running in [false, true] {
                    let state = TimerReceiveState {
                        registered,
                        active,
                        delivery_running,
                        continuation_running,
                    };
                    let expected = if !registered {
                        Err(TimerReceiveError::UnregisteredOwner)
                    } else if !active {
                        Err(TimerReceiveError::UnavailableOwner)
                    } else if delivery_running {
                        Err(TimerReceiveError::ActiveDelivery)
                    } else if continuation_running {
                        Err(TimerReceiveError::ActiveContinuation)
                    } else {
                        Ok(())
                    };
                    let mut effects = 0;
                    assert_eq!(
                        state.prepare(|| {
                            effects += 1;
                            Some(TimerRearmOutcome::Programmed)
                        }),
                        expected,
                    );
                    assert_eq!(effects, usize::from(expected.is_ok()));
                }
            }
        }
    }
}

#[test]
fn receive_accepts_only_successful_or_unnecessary_rearm() {
    for (outcome, expected) in [
        (None, Ok(())),
        (Some(TimerRearmOutcome::Idle), Ok(())),
        (Some(TimerRearmOutcome::Programmed), Ok(())),
        (
            Some(TimerRearmOutcome::Unavailable),
            Err(TimerReceiveError::Rearm(TimerRearmOutcome::Unavailable)),
        ),
        (
            Some(TimerRearmOutcome::Failed),
            Err(TimerReceiveError::Rearm(TimerRearmOutcome::Failed)),
        ),
    ] {
        let mut effects = 0;
        let state = TimerReceiveState {
            registered: true,
            active: true,
            delivery_running: false,
            continuation_running: false,
        };
        assert_eq!(
            state.prepare(|| {
                effects += 1;
                outcome
            }),
            expected,
        );
        assert_eq!(effects, 1);
    }
}

#[test]
fn receive_preparation_never_acknowledges_retained_continuation_demand() {
    use nt_component_suspension::{ResumeDemand, ResumeWake};

    let mut wake = ResumeWake::new(10, 80).unwrap();
    wake.reconcile_demand(ResumeDemand::Pending, 100);
    let mut pass = wake.begin_pass(100).unwrap().unwrap();
    wake.finish_pass(&mut pass, 100, true, false).unwrap();
    assert_eq!(wake.next_deadline(), Some(110));

    let mut effects = 0;
    for outcome in [TimerRearmOutcome::Failed, TimerRearmOutcome::Programmed] {
        let state = TimerReceiveState {
            registered: true,
            active: true,
            delivery_running: false,
            continuation_running: wake.is_running(),
        };
        let result = state.prepare(|| {
            effects += 1;
            assert_eq!(wake.next_deadline(), Some(110));
            Some(outcome)
        });
        assert_eq!(result.is_ok(), outcome == TimerRearmOutcome::Programmed);
        assert_eq!(wake.next_deadline(), Some(110));
        assert!(!wake.is_running());
    }
    assert_eq!(effects, 2);

    let mut pass = wake.begin_pass(110).unwrap().unwrap();
    let state = TimerReceiveState {
        registered: true,
        active: true,
        delivery_running: false,
        continuation_running: wake.is_running(),
    };
    assert_eq!(
        state.prepare(|| {
            effects += 1;
            Some(TimerRearmOutcome::Programmed)
        }),
        Err(TimerReceiveError::ActiveContinuation),
    );
    assert_eq!(effects, 2);
    assert!(wake.is_running());
    assert_eq!(wake.next_deadline(), None);

    // Only the exact outer pass may acknowledge work; receive preparation preserves backoff.
    wake.finish_pass(&mut pass, 110, true, false).unwrap();
    assert_eq!(wake.next_deadline(), Some(130));
}

#[test]
fn expired_timer_dpc_survives_until_a_separate_scheduler_claim() {
    let mut clock = FakeClock::new();
    let mut timers = TimerQueue::new();
    let mut dpcs = HostedDpcTable::new();
    let owner = HostedDpcOwner::new(1, 2, 3).unwrap();
    let other = HostedDpcOwner::new(4, 5, 6).unwrap();
    let identity = dpcs.register(owner, 11, 100, 200).unwrap();
    timers.set(1, -100, 0, Some(11), &clock);
    clock.advance_100ns(100);
    for expiry in timers.run_due_expirations(&clock) {
        assert_eq!(expiry.dpc_ptr, Some(identity.dpc_token));
        assert_eq!(
            dpcs.queue(identity, 0, 0),
            Ok(HostedDpcQueueResult::Queued(identity))
        );
    }
    assert!(timers.read_state(1));
    assert!(timers.run_due_expirations(&clock).is_empty());
    assert!(dpcs.has_queued());
    assert!(!dpcs.snapshot(identity).unwrap().in_flight);
    assert_eq!(dpcs.begin_next(other), Ok(None));
    assert!(dpcs.has_queued());
    let activation = dpcs.begin_next(owner).unwrap().unwrap();
    assert_eq!(activation.identity, identity);
    assert!(!dpcs.has_queued());
    dpcs.complete(activation).unwrap();
    assert_eq!(dpcs.begin_next(owner), Ok(None));
}

#[test]
fn periodic_expirations_coalesce_before_dispatch_and_requeue_after_claim() {
    let mut clock = FakeClock::new();
    let mut timers = TimerQueue::new();
    let mut dpcs = HostedDpcTable::new();
    let owner = HostedDpcOwner::new(1, 2, 3).unwrap();
    let identity = dpcs.register(owner, 11, 100, 200).unwrap();
    timers.set(1, -100, 1, Some(11), &clock);
    for (delta, expected) in [
        (100, HostedDpcQueueResult::Queued(identity)),
        (10_000, HostedDpcQueueResult::AlreadyQueued(identity)),
    ] {
        clock.advance_100ns(delta);
        let expired = timers.run_due_expirations(&clock);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].dpc_ptr, Some(identity.dpc_token));
        assert_eq!(dpcs.queue(identity, 0, 0), Ok(expected));
    }
    assert_eq!(dpcs.queued_count(owner), 1);
    let first = dpcs.begin_next(owner).unwrap().unwrap();
    clock.advance_100ns(10_000);
    assert_eq!(timers.run_due_expirations(&clock).len(), 1);
    assert_eq!(
        dpcs.queue(identity, 0, 0),
        Ok(HostedDpcQueueResult::Queued(identity))
    );
    assert!(dpcs.has_queued());
    assert_eq!(dpcs.begin_next(owner), Ok(None));
    dpcs.complete(first).unwrap();
    let second = dpcs.begin_next(owner).unwrap().unwrap();
    assert_ne!(first.sequence, second.sequence);
    dpcs.complete(second).unwrap();
    assert!(!dpcs.has_queued());
}

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
