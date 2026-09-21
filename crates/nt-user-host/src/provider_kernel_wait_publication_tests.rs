use super::*;

fn publish(
    f: &mut Fixture,
    state: &mut DispatcherState,
    arbiter: &mut ProviderDispatcherWaitArbiter<ProviderDispatcherLease>,
    caller: KernelProviderCaller,
    work: KernelProviderWaitWork,
    sequence: u64,
    sampled_at: TimeSnapshot,
) -> Result<
    (Admission, Option<KernelProviderWaitCapture>),
    (
        KernelProviderWaitAdmissionError<u32>,
        KernelProviderWaitCapture,
    ),
> {
    let capture = match work {
        KernelProviderWaitWork::Initial(capture) => capture,
        KernelProviderWaitWork::Repark { next, .. } => next,
    };
    f.activations.publish_wait_work(
        caller,
        &f.pm,
        &f.catalog,
        &mut f.lanes,
        arbiter,
        &mut backend(state, Some(caller.owner())),
        work,
        sequence,
        sampled_at,
        capture,
        |status| status,
    )
}

#[test]
fn discovered_initial_work_publishes_ready_parked_and_expired_waits() {
    for (signaled, current) in [(false, 10), (true, 10), (false, 100_010)] {
        let (mut f, mut state) = fixture(signaled);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let (caller, work) = next_work(&mut f).unwrap();
        let result = publish(
            &mut f,
            &mut state,
            &mut arbiter,
            caller,
            work.unwrap(),
            1,
            TimeSnapshot {
                monotonic_100ns: current,
                ..now()
            },
        )
        .unwrap();
        let expected = if signaled {
            Admission::Satisfied {
                wait_id: 71,
                status: 0,
            }
        } else if current == 10 {
            Admission::Parked { wait_id: 71 }
        } else {
            Admission::TimedOut { wait_id: 71 }
        };
        assert_eq!(result, (expected, None));
        assert_eq!(f.state().captured_wait(), Some(f.capture));
        assert_eq!(f.capture.observed_at(), now());
        assert_eq!(references(&f.pm, caller.thread()), (1, 1));
        assert_eq!(next_work(&mut f), None);
        assert_eq!(
            state.event_objects.live_lease_count(),
            usize::from(!signaled && current == 10)
        );
    }
}

#[test]
fn stale_discovery_is_revalidated_without_consuming_an_event() {
    let (mut f, mut state) = fixture(true);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    let (caller, work) = next_work(&mut f).unwrap();
    f.catalog.retire(f.provider, 0).unwrap();
    let error = publish(
        &mut f,
        &mut state,
        &mut arbiter,
        caller,
        work.unwrap(),
        1,
        now(),
    )
    .unwrap_err();
    assert_eq!(
        error,
        (
            KernelProviderWaitAdmissionError::Authority(STATUS_INVALID_HANDLE),
            f.capture
        )
    );
    assert!(state.events.read_state(101));
    assert_eq!(state.event_objects.live_lease_count(), 0);
    assert_eq!(f.state().captured_wait(), Some(f.capture));
    assert_eq!(f.lanes.suspension_count(caller.dispatch.lane()), Ok(0));
}

#[test]
fn mislabeled_repark_retains_both_captures_until_exact_replacement() {
    let (mut f, mut state) = fixture(true);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
    let previous = f.capture;
    let next = next_capture(&mut f, 72);
    let frame = f.lanes.top(f.caller.dispatch.lane()).unwrap().cloned();
    state.events.set_existing(101).unwrap();
    let caller = f.caller;
    for bad in [
        KernelProviderWaitWork::Initial(next),
        KernelProviderWaitWork::Repark {
            previous: next,
            next,
        },
    ] {
        let error = publish(&mut f, &mut state, &mut arbiter, caller, bad, 2, now()).unwrap_err();
        assert_eq!(error.1, next);
        assert_eq!(f.state().active_resume(), Some(previous));
        assert_eq!(f.state().captured_wait(), Some(next));
        assert_eq!(f.lanes.top(caller.dispatch.lane()).unwrap().cloned(), frame);
        assert_eq!(state.event_objects.live_lease_count(), 0);
        assert!(state.events.read_state(101));
    }
    let (_, work) = next_work(&mut f).unwrap();
    assert_eq!(
        publish(
            &mut f,
            &mut state,
            &mut arbiter,
            caller,
            work.unwrap(),
            2,
            now()
        ),
        Ok((
            Admission::Satisfied {
                wait_id: 72,
                status: 0
            },
            Some(previous)
        ))
    );
    assert_eq!(f.lanes.suspension_count(caller.dispatch.lane()), Ok(1));
    assert!(!state.events.read_state(101));
}

#[test]
fn rejected_discovery_does_not_block_later_work_or_restart_the_pass() {
    let (mut f, mut state) = fixture(true);
    f.lanes
        .suspend_running(
            f.caller.dispatch.lane(),
            f.caller.current_binding(&f.lanes).unwrap().reply_object,
            99,
        )
        .unwrap();
    let object = f.capture.request().objects[0];
    let second = append_waiting_activation_with(&mut f, |request| request.objects[0] = object);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    let mut cursor = f.activations.wait_work_cursor();
    let mut visited = 0;
    let mut sequence = 0;
    while let Some((caller, work)) =
        f.activations
            .next_wait_work(&mut cursor, &f.pm, &f.catalog, &f.lanes)
    {
        if visited == 0 {
            assert_eq!(work, Err(STATUS_INVALID_HANDLE));
            assert!(state.events.read_state(101));
        } else {
            sequence += 1;
            let result = publish(
                &mut f,
                &mut state,
                &mut arbiter,
                caller,
                work.unwrap(),
                sequence,
                now(),
            );
            assert_eq!(caller, second.caller());
            assert_eq!(
                result,
                Ok((
                    Admission::Satisfied {
                        wait_id: 81,
                        status: 0
                    },
                    None
                ))
            );
        }
        visited += 1;
    }
    assert_eq!(visited, 2);
    assert_eq!(sequence, 1);
    assert_eq!(f.state().captured_wait(), Some(f.capture));
    assert_eq!(f.lanes.suspension_count(f.caller.dispatch.lane()), Ok(0));
    assert_eq!(state.event_objects.live_lease_count(), 0);
    assert!(!state.events.read_state(101));
    assert_eq!(
        next_work(&mut f),
        Some((f.caller, Err(STATUS_INVALID_HANDLE)))
    );
}

#[test]
fn publication_uses_the_supplied_snapshot_not_a_later_clock_adjustment() {
    for changed_system_time in [50, 5_000] {
        let (mut f, mut state) = fixture(true);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
        let previous = f.capture;
        let next = next_capture_with(&mut f, 72, |request| {
            request.header.timeout_kind = ProviderWaitTimeoutKind::Absolute as u32;
            request.header.timeout_100ns = 500;
        });
        let mut clock = nt_time::AdjustableClock::new(10, 100);
        let sampled = clock.snapshot(10);
        clock.set_system_time(20, changed_system_time).unwrap();
        let (caller, work) = next_work(&mut f).unwrap();
        assert_eq!(
            publish(
                &mut f,
                &mut state,
                &mut arbiter,
                caller,
                work.unwrap(),
                2,
                sampled
            ),
            Ok((Admission::Parked { wait_id: 72 }, Some(previous)))
        );
        assert_eq!(arbiter.next_deadline(sampled), Some(410));
        assert_ne!(arbiter.next_deadline(clock.snapshot(20)), Some(410));
        assert_eq!(f.state().captured_wait(), Some(next));
        assert_eq!(next.observed_at(), now());
        assert_eq!(state.event_objects.live_lease_count(), 1);
    }
}
