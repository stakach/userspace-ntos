use super::*;

fn validate_unchanged(f: &mut Fixture) -> Result<(), KernelProviderResumeError> {
    let lane = f.caller.dispatch.lane();
    let frame = f.lanes.top(lane).unwrap().cloned();
    let phase = f.lanes.phase(lane);
    let dispatch = f.lanes.active_dispatch_identity(lane);
    let observation = f
        .state()
        .progress()
        .provider_wait_observation(f.caller.current_binding(&f.lanes).unwrap().reply_object);
    let capture = f.state().captured_wait();
    let active = f.state().active_resume();
    let bank = &*f.activations.recipient(f.caller).unwrap().bank as *const u64;
    let result = f
        .activations
        .validate_wait_resume(f.caller, &f.pm, &f.catalog, &f.lanes, f.capture);
    assert_eq!(f.lanes.top(lane).unwrap().cloned(), frame);
    assert_eq!(f.lanes.phase(lane), phase);
    assert_eq!(f.lanes.active_dispatch_identity(lane), dispatch);
    assert_eq!(
        f.state()
            .progress()
            .provider_wait_observation(f.caller.current_binding(&f.lanes).unwrap().reply_object),
        observation
    );
    assert_eq!(f.state().captured_wait(), capture);
    assert_eq!(f.state().active_resume(), active);
    assert_eq!(
        &*f.activations.recipient(f.caller).unwrap().bank as *const u64,
        bank
    );
    result
}

#[test]
fn repeated_eligibility_leaves_selected_and_cancelled_waits_unclaimed() {
    for cancelled in [false, true] {
        let mut f = Fixture::new();
        if cancelled {
            f.lanes.cancel(f.capture.key(), -1).unwrap();
        } else {
            f.lanes.select(f.capture.key(), 258).unwrap();
        }
        for _ in 0..3 {
            assert_eq!(validate_unchanged(&mut f), Ok(()));
        }
        let ticket = f.resume().unwrap();
        assert_eq!(ticket.selection().cancelled, cancelled);
        assert_eq!(
            validate_unchanged(&mut f),
            Err(KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE))
        );
    }
}

#[test]
fn eligibility_rejects_waiting_and_exited_caller_before_entry() {
    let mut f = Fixture::new();
    assert_eq!(
        validate_unchanged(&mut f),
        Err(KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE))
    );
    f.lanes.select(f.capture.key(), 258).unwrap();
    assert_eq!(validate_unchanged(&mut f), Ok(()));
    f.pm.terminate_thread(f.caller.thread().thread_id(), 0)
        .unwrap();
    let error = validate_unchanged(&mut f).unwrap_err();
    assert!(matches!(error, KernelProviderResumeError::Authority(_)));
    assert_eq!(f.resume().unwrap_err(), error);
}

#[test]
fn eligibility_authenticates_both_typed_frame_and_retained_pump_epoch() {
    let mut f = Fixture::new();
    let first = f.capture;
    f.lanes.select(first.key(), 258).unwrap();
    f.repark(72, 2);
    let current = f.repark(71, 3);
    assert_eq!(first.key(), current.key());
    assert_eq!(first.request(), current.request());
    assert_ne!(first.observation(), current.observation());
    f.capture = first;
    assert_eq!(
        validate_unchanged(&mut f),
        Err(KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE))
    );
    let lane = f.caller.dispatch.lane();
    f.lanes
        .frame_mut(lane, current.key())
        .unwrap()
        .unwrap()
        .continuation = first;
    assert_eq!(
        validate_unchanged(&mut f),
        Err(KernelProviderResumeError::Pump(PumpProgressError::NotReady))
    );
    f.capture = current;
    f.lanes
        .frame_mut(lane, current.key())
        .unwrap()
        .unwrap()
        .continuation = current;
    assert_eq!(validate_unchanged(&mut f), Ok(()));
    drop(f.resume().unwrap());
}

#[test]
fn eligibility_is_not_permission_to_override_a_busy_physical_component() {
    let mut f = Fixture::new();
    f.lanes.select(f.capture.key(), 258).unwrap();
    let other = f.lanes.allocate(binding(2)).unwrap();
    f.lanes
        .begin_dispatch(other, binding(2).reply_object)
        .unwrap();
    assert_eq!(validate_unchanged(&mut f), Ok(()));
    assert_eq!(
        f.assert_refused_unchanged(),
        KernelProviderResumeError::Lane(LaneError::Busy)
    );
    f.lanes
        .finish_dispatch(other, binding(2).reply_object)
        .unwrap();
    assert_eq!(validate_unchanged(&mut f), Ok(()));
    drop(f.resume().unwrap());
}
