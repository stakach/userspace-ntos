use super::*;
use nt_delay_execution::{Deadline, Waiter};
use nt_provider_wait::{ProviderDomainIdentity, ProviderTimerKind};

fn now(monotonic_100ns: u64, system_time_100ns: u64) -> TimeSnapshot {
    TimeSnapshot {
        monotonic_100ns,
        system_time_100ns,
        clock_generation: 0,
    }
}

fn queue(deadline: Deadline) -> Queue {
    let mut queue = Queue::new();
    queue
        .insert(Waiter {
            deadline,
            sequence: 0,
            reply_cap: 17,
            thread_id: 23,
            badge: 29,
        })
        .unwrap();
    queue
}

fn timers(interval: i64) -> ProviderTimerTable {
    let mut timers = ProviderTimerTable::new(ProviderDomainIdentity {
        domain: 7,
        generation: 3,
    })
    .unwrap();
    timers
        .publish(51, ProviderTimerKind::Synchronization)
        .unwrap();
    timers.set_local(51, interval, 0, now(10, 1_000)).unwrap();
    timers
}

#[test]
fn collection_preserves_due_records_across_dispatcher_handoff() {
    let mut queue = queue(Deadline::from_nt_timeout(Some(-50), now(10, 1_000)));
    let mut dispatcher = crate::dispatcher_state::DispatcherState::new(1, 1);
    dispatcher.provider_timers = Some(timers(-100));
    let expected = DispatcherDeadlines {
        delay: Some(60),
        provider_timer: Some(110),
    };
    for _ in 0..2 {
        assert_eq!(
            DispatcherDeadlines::collect(
                &queue,
                dispatcher.provider_timers.as_ref(),
                now(10, 1_000)
            ),
            expected
        );
    }
    let moved = dispatcher;
    let mut timers = moved.provider_timers.unwrap();
    assert_eq!(
        DispatcherDeadlines::collect(&queue, Some(&timers), now(110, 1_100)),
        expected
    );
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.pop_due(now(110, 1_100)).unwrap().reply_cap, 17);
    assert!(queue.pop_due(now(110, 1_100)).is_none());
    assert!(timers.expire_next_due(now(110, 1_100)).is_some());
    assert!(timers.expire_next_due(now(110, 1_100)).is_none());
}

#[test]
fn absolute_targets_share_the_supplied_clock_snapshot() {
    let queue = queue(Deadline::from_nt_timeout(Some(2_000), now(10, 1_000)));
    let timers = timers(3_000);
    assert_eq!(
        DispatcherDeadlines::collect(&queue, Some(&timers), now(10, 1_000)),
        DispatcherDeadlines {
            delay: Some(1_010),
            provider_timer: Some(2_010)
        }
    );
    assert_eq!(
        DispatcherDeadlines::collect(&queue, Some(&timers), now(20, 4_000)),
        DispatcherDeadlines {
            delay: Some(20),
            provider_timer: Some(20)
        }
    );
    assert_eq!(
        DispatcherDeadlines::collect(&queue, Some(&timers), now(30, 500)),
        DispatcherDeadlines {
            delay: Some(1_530),
            provider_timer: Some(2_530)
        }
    );
    assert_eq!(queue.len(), 1);
}

#[test]
fn a_timer_pass_keeps_its_snapshot_when_the_system_clock_changes_between_sources() {
    for (initial, changed, due) in [(1_000, 4_000, false), (4_000, 1_000, true)] {
        let mut clock = nt_time::AdjustableClock::new(10, initial);
        let sampled = clock.snapshot(10);
        let mut queue = queue(Deadline::from_nt_timeout(Some(2_000), sampled));
        let mut timers = timers(2_000);
        let collected = DispatcherDeadlines::collect(&queue, Some(&timers), sampled);
        let delay = queue.pop_due(sampled);

        // A nested service adjusts system time after one source has already been scanned.
        clock.set_system_time(20, changed).unwrap();
        let expiry = timers.expire_next_due(sampled);
        assert_eq!(delay.is_some(), due);
        assert_eq!(expiry.is_some(), due);
        assert_eq!(collected.delay.is_some_and(|target| target <= 10), due);
        assert_eq!(
            collected.provider_timer.is_some_and(|target| target <= 10),
            due
        );

        let fresh = clock.snapshot(20);
        assert_ne!(fresh.clock_generation, sampled.clock_generation);
        if !due {
            assert!(queue.pop_due(fresh).is_some());
            assert!(timers.expire_next_due(fresh).is_some());
        }
        assert!(queue.pop_due(fresh).is_none());
        assert!(timers.expire_next_due(fresh).is_none());
    }
}

#[test]
fn infinite_wait_and_absent_or_cancelled_timer_have_no_target() {
    let queue = queue(Deadline::Infinite);
    let expected = DispatcherDeadlines {
        delay: None,
        provider_timer: None,
    };
    assert_eq!(
        DispatcherDeadlines::collect(&queue, None, now(10, 1_000)),
        expected
    );
    let mut timers = timers(-100);
    timers.cancel_local(51).unwrap();
    assert_eq!(
        DispatcherDeadlines::collect(&queue, Some(&timers), now(10, 1_000)),
        expected
    );
    assert_eq!(queue.len(), 1);
}
