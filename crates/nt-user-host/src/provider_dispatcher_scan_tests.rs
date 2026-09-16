use super::*;

#[test]
fn delivery_deferred_during_hosted_work_gets_a_provider_scan_before_receive() {
    use core::sync::atomic::{AtomicU64, Ordering};
    use nt_time::{DeferredTimerProgress, TimerDeliveryGate};

    let (mut state, object, timer) = timed_state();
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    {
        let mut objects = backend(
            &mut state,
            Some(ProviderDispatcherAccess::hosted(owner(), 42).unwrap()),
        );
        arbiter
            .admit(
                &mut objects,
                &wait(&[object, timer.wait_object()]),
                owner(),
                1,
                now(),
            )
            .unwrap();
    }
    let gate = TimerDeliveryGate::new();
    let pending = AtomicU64::new(1);
    let mut progress = DeferredTimerProgress::new();
    let outer = gate.try_enter().unwrap();
    let sampled = pending.load(Ordering::Relaxed);
    // Hosted IPC receives another tick. The nested ACK path cannot borrow dispatcher state.
    pending.fetch_add(1, Ordering::Relaxed);
    assert!(gate.try_enter().is_none());
    {
        let mut objects = backend(&mut state, None);
        assert_eq!(
            objects.scan_timed(&mut arbiter, now(), |_| Ok::<_, ()>(())),
            Ok(ProviderTimedScan::default())
        );
    }
    progress.record_scan(sampled);
    drop(outer);
    assert!(progress.needs_scan(pending.load(Ordering::Relaxed)));

    // The pre-receive pass services providers too, without requiring another hardware tick.
    let _next = gate.try_enter().unwrap();
    let sampled = pending.load(Ordering::Relaxed);
    let due = TimeSnapshot {
        monotonic_100ns: 110,
        ..now()
    };
    let mut completions = 0;
    {
        let mut objects = backend(&mut state, None);
        assert_eq!(
            objects.scan_timed(&mut arbiter, due, |_| {
                completions += 1;
                Ok::<_, ()>(())
            }),
            Ok(ProviderTimedScan {
                timeouts: 0,
                expired_timers: 1,
                ready: 1
            })
        );
        assert_eq!(objects.event_objects.live_lease_count(), 0);
    }
    progress.record_scan(sampled);
    assert_eq!(completions, 1);
    assert!(arbiter.is_empty());
    assert_eq!(pending.load(Ordering::Relaxed), 2);
    assert!(!progress.needs_scan(pending.load(Ordering::Relaxed)));
}

fn timed_state() -> (
    DispatcherState,
    ProviderWaitObject,
    nt_provider_wait::ProviderTimerId,
) {
    let mut state = DispatcherState::new(1, 2);
    let (_, object) = event(&mut state);
    let mut timers = ProviderTimerTable::new(PROVIDER).unwrap();
    let timer = timers
        .publish(301, ProviderTimerKind::Synchronization)
        .unwrap();
    timers.set_local(301, -100, 0, now()).unwrap();
    state.provider_timers = Some(timers);
    (state, object, timer)
}

#[test]
fn scan_keeps_timeout_before_timer_expiry_without_consuming_signals() {
    let (mut state, object, timer) = timed_state();
    let mut request = wait(&[object, timer.wait_object()]);
    request.header.timeout_kind = ProviderWaitTimeoutKind::Relative as u32;
    request.header.timeout_100ns = -100;
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    let mut objects = backend(
        &mut state,
        Some(ProviderDispatcherAccess::hosted(owner(), 42).unwrap()),
    );
    arbiter
        .admit(&mut objects, &request, owner(), 1, now())
        .unwrap();
    objects.access = None;
    let due = TimeSnapshot {
        monotonic_100ns: 110,
        ..now()
    };
    let mut statuses = alloc::vec::Vec::new();
    let scanned = objects
        .scan_timed(&mut arbiter, due, |completion| {
            statuses.push(completion.status);
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(
        scanned,
        ProviderTimedScan {
            timeouts: 1,
            expired_timers: 1,
            ready: 0
        }
    );
    assert_eq!(statuses.as_slice(), &[0x102]);
    assert!(objects.events.read_state(101));
    assert_eq!(objects.timers.as_ref().unwrap().read_state(timer), Ok(true));
    assert!(arbiter.is_empty());
    assert_eq!(objects.event_objects.live_lease_count(), 0);
}

#[test]
fn refused_ready_publication_retries_without_another_timer_expiration() {
    let (mut state, object, timer) = timed_state();
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    {
        let mut objects = backend(
            &mut state,
            Some(ProviderDispatcherAccess::hosted(owner(), 42).unwrap()),
        );
        arbiter
            .admit(
                &mut objects,
                &wait(&[object, timer.wait_object()]),
                owner(),
                1,
                now(),
            )
            .unwrap();
    }
    let mut runtime = state;
    let mut objects = backend(&mut runtime, None);
    let due = TimeSnapshot {
        monotonic_100ns: 110,
        ..now()
    };
    assert_eq!(
        objects.scan_timed(&mut arbiter, due, |_| Err::<(), _>(7)),
        Err((
            ProviderTimedScan {
                timeouts: 0,
                expired_timers: 1,
                ready: 0
            },
            7
        ))
    );
    assert!(objects.events.read_state(101));
    assert_eq!(objects.timers.as_ref().unwrap().read_state(timer), Ok(true));
    assert_eq!(objects.event_objects.live_lease_count(), 1);
    assert_eq!(
        objects.scan_timed(&mut arbiter, due, |_| Ok::<_, ()>(())),
        Ok(ProviderTimedScan {
            timeouts: 0,
            expired_timers: 0,
            ready: 1
        })
    );
    assert!(!objects.events.read_state(101));
    assert_eq!(
        objects.timers.as_ref().unwrap().read_state(timer),
        Ok(false)
    );
    assert_eq!(objects.event_objects.live_lease_count(), 0);
    assert!(arbiter.is_empty());
}

#[test]
fn no_due_work_does_not_publish_or_grant_admission() {
    let (mut state, object, _) = timed_state();
    let mut objects = backend(&mut state, None);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    assert_eq!(
        objects.scan_timed(&mut arbiter, now(), |_| -> Result<(), ()> {
            panic!("no completion is ready")
        }),
        Ok(ProviderTimedScan::default())
    );
    assert_eq!(
        objects.acquire_dispatcher_wait(owner(), object),
        Err(INVALID_PARAMETER)
    );
}
