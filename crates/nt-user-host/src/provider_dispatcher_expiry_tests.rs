use super::*;

#[test]
fn absent_timer_table_does_not_change_event_or_grant_admission() {
    let mut state = DispatcherState::new(1, 1);
    let (id, object) = event(&mut state);
    let before = state.event_objects.snapshot(id).unwrap();
    let mut objects = backend(&mut state, None);
    assert_eq!(objects.expire_timers(now()), 0);
    assert!(objects.events.read_state(101));
    assert_eq!(objects.event_objects.snapshot(id), Ok(before));
    assert_eq!(
        objects.acquire_dispatcher_wait(owner(), object),
        Err(INVALID_PARAMETER)
    );
}

#[test]
fn moved_wait_keeps_leases_and_signal_when_publication_is_refused() {
    let mut state = DispatcherState::new(1, 2);
    let (_, object) = event(&mut state);
    let mut timers = ProviderTimerTable::new(PROVIDER).unwrap();
    let timer = timers
        .publish(301, ProviderTimerKind::Synchronization)
        .unwrap();
    timers.set_local(301, -100, 0, now()).unwrap();
    state.provider_timers = Some(timers);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    {
        let mut objects = backend(
            &mut state,
            Some(ProviderDispatcherAccess::hosted(owner(), 42).unwrap()),
        );
        assert_eq!(
            arbiter.admit(
                &mut objects,
                &wait(&[object, timer.wait_object()]),
                owner(),
                1,
                now()
            ),
            Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 23 })
        );
    }
    let mut moved = state;
    let mut objects = backend(&mut moved, None);
    let before_due = TimeSnapshot {
        monotonic_100ns: 109,
        ..now()
    };
    let due = TimeSnapshot {
        monotonic_100ns: 110,
        ..now()
    };
    assert_eq!(objects.expire_timers(before_due), 0);
    assert!(arbiter.pop_ready(&mut objects).is_none());
    assert_eq!(objects.expire_timers(due), 1);
    assert_eq!(
        arbiter.pop_ready_with(&mut objects, |_| Err::<(), _>(37)),
        Err(37)
    );
    assert!(objects.events.read_state(101));
    assert_eq!(objects.timers.as_ref().unwrap().read_state(timer), Ok(true));
    assert_eq!(objects.event_objects.live_lease_count(), 1);
    assert_eq!(objects.expire_timers(due), 0);
    assert_eq!(arbiter.pop_ready(&mut objects).unwrap().status, 0);
    assert!(!objects.events.read_state(101));
    assert_eq!(
        objects.timers.as_ref().unwrap().read_state(timer),
        Ok(false)
    );
    assert_eq!(objects.event_objects.live_lease_count(), 0);
    assert!(objects
        .timers
        .as_mut()
        .unwrap()
        .request_retire_local(301)
        .unwrap()
        .is_some());
}

#[test]
fn clock_limit_expires_each_periodic_timer_once_per_pass_without_starving_others() {
    let mut state = DispatcherState::new(1, 1);
    let mut timers = ProviderTimerTable::new(PROVIDER).unwrap();
    let first = timers
        .publish(301, ProviderTimerKind::Synchronization)
        .unwrap();
    let second = timers
        .publish(302, ProviderTimerKind::Notification)
        .unwrap();
    let third = timers
        .publish(303, ProviderTimerKind::Notification)
        .unwrap();
    timers.set_local(301, -1, 1, now()).unwrap();
    timers.set_local(302, -1, 2, now()).unwrap();
    timers.set_local(303, -1, 0, now()).unwrap();
    state.provider_timers = Some(timers);
    let mut objects = backend(&mut state, None);
    let limit = TimeSnapshot {
        monotonic_100ns: u64::MAX,
        system_time_100ns: u64::MAX,
        clock_generation: 0,
    };
    assert_eq!(objects.expire_timers(limit), 3);
    for id in [first, second, third] {
        assert_eq!(objects.timers.as_ref().unwrap().read_state(id), Ok(true));
    }
    // Periodic deadlines retain existing saturation semantics, but no scan spins forever.
    assert_eq!(objects.expire_timers(limit), 2);
}
