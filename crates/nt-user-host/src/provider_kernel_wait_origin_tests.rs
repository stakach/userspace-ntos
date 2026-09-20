use super::*;

fn at(monotonic_100ns: u64) -> TimeSnapshot {
    TimeSnapshot {
        monotonic_100ns,
        ..now()
    }
}

#[test]
fn deferred_initial_publication_uses_observed_origin_and_current_expiry() {
    for current in [50_000, 100_010] {
        let (mut f, mut state) = fixture(false);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        assert_eq!(f.capture.observed_at(), now());
        let result = f
            .activations
            .publish_wait_work(
                f.caller,
                &f.pm,
                &f.catalog,
                &mut f.lanes,
                &mut arbiter,
                &mut backend(&mut state, Some(f.caller.owner())),
                KernelProviderWaitWork::Initial(f.capture),
                1,
                at(current),
                f.capture,
                |status| status,
            )
            .unwrap();
        assert_eq!(result.1, None);
        let result = result.0;
        if current < 100_010 {
            assert_eq!(result, Admission::Parked { wait_id: 71 });
            assert_eq!(arbiter.next_deadline(at(current)), Some(100_010));
            assert_eq!(state.event_objects.live_lease_count(), 1);
        } else {
            assert_eq!(result, Admission::TimedOut { wait_id: 71 });
            assert!(arbiter.is_empty());
            assert_eq!(state.event_objects.live_lease_count(), 0);
            assert_eq!(
                f.resume().unwrap().selection().completion,
                nt_provider_wait::STATUS_TIMEOUT
            );
        }
        assert_eq!(f.capture.observed_at(), now());
        assert!(!state.events.read_state(101));
    }
}

#[test]
fn rejected_publication_retry_cannot_refresh_captured_origin() {
    let (mut f, mut state) = fixture(false);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    // A zero admission sequence rejects publication without losing the stopped request.
    assert!(admit(&mut f, &mut state, &mut arbiter, 0).is_err());
    assert_eq!(f.state().captured_wait(), Some(f.capture));
    assert_eq!(state.event_objects.live_lease_count(), 0);
    let result = f
        .activations
        .publish_wait_work(
            f.caller,
            &f.pm,
            &f.catalog,
            &mut f.lanes,
            &mut arbiter,
            &mut backend(&mut state, Some(f.caller.owner())),
            KernelProviderWaitWork::Initial(f.capture),
            1,
            at(200_000),
            f.capture,
            |status| status,
        )
        .unwrap();
    assert_eq!(result, (Admission::TimedOut { wait_id: 71 }, None));
    assert_eq!(f.capture.observed_at(), now());
    assert_eq!(state.event_objects.live_lease_count(), 0);
}

#[test]
fn repeated_wait_gets_new_origin_but_deferred_repark_does_not() {
    for current in [100_025, 100_060] {
        let (mut f, mut state) = fixture(true);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
        let previous = f.capture;
        let origin = at(100_010);
        let next = next_capture_at(&mut f, 72, origin, |request| {
            request.header.timeout_100ns = -50;
        });
        assert_eq!(previous.observed_at(), now());
        assert_eq!(next.observed_at(), origin);
        let (result, retired) = f
            .activations
            .publish_wait_work(
                f.caller,
                &f.pm,
                &f.catalog,
                &mut f.lanes,
                &mut arbiter,
                &mut backend(&mut state, Some(f.caller.owner())),
                KernelProviderWaitWork::Repark { previous, next },
                2,
                at(current),
                next,
                |status| status,
            )
            .unwrap();
        assert_eq!(retired, Some(previous));
        assert_eq!(f.state().captured_wait(), Some(next));
        assert_eq!(f.lanes.suspension_count(f.caller.dispatch.lane()), Ok(1));
        if current < 100_060 {
            assert_eq!(result, Admission::Parked { wait_id: 72 });
            assert_eq!(arbiter.next_deadline(at(current)), Some(100_060));
        } else {
            assert_eq!(result, Admission::TimedOut { wait_id: 72 });
            assert_eq!(state.event_objects.live_lease_count(), 0);
            f.capture = next;
            assert_eq!(
                f.resume().unwrap().selection().completion,
                nt_provider_wait::STATUS_TIMEOUT
            );
        }
        assert!(!state.events.read_state(101));
    }
}
