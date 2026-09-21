use super::*;
use crate::provider_kernel_pump::KernelProviderPumpAttempt;

fn validate(
    f: &mut Fixture,
    capture: KernelProviderWaitCapture,
    attempt: &KernelProviderPumpAttempt,
) -> Result<(), u32> {
    f.activations
        .validate_wait_execution(f.caller, &f.pm, &f.catalog, &f.lanes, capture, attempt)
}

fn assert_refused_unchanged(
    f: &mut Fixture,
    capture: KernelProviderWaitCapture,
    attempt: &KernelProviderPumpAttempt,
) {
    let lane = f.caller.dispatch.lane();
    let phase = f.lanes.phase(lane).unwrap();
    let frame = f.lanes.top(lane).unwrap().cloned();
    let dispatch = f.lanes.active_dispatch_identity(lane).unwrap();
    let disposition = f.state().progress().disposition();
    let retained = f.state().captured_wait();
    let active_resume = f.state().active_resume();
    let bank = &*f.activations.recipient(f.caller).unwrap().bank as *const u64;
    assert!(validate(f, capture, attempt).is_err());
    assert_eq!(f.lanes.phase(lane).unwrap(), phase);
    assert_eq!(f.lanes.top(lane).unwrap().cloned(), frame);
    assert_eq!(f.lanes.active_dispatch_identity(lane).unwrap(), dispatch);
    assert_eq!(f.state().progress().disposition(), disposition);
    assert_eq!(f.state().captured_wait(), retained);
    assert_eq!(f.state().active_resume(), active_resume);
    assert_eq!(
        &*f.activations.recipient(f.caller).unwrap().bank as *const u64,
        bank
    );
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    assert!(f.activations.completion(f.caller).is_err());
}

#[test]
fn selected_and_cancelled_claims_validate_until_the_exact_entry_is_observed() {
    for cancelled in [false, true] {
        let mut f = Fixture::new();
        if cancelled {
            f.lanes.cancel(f.capture.key(), -1).unwrap();
        } else {
            f.lanes.select(f.capture.key(), 258).unwrap();
        }
        let (capture, mut attempt, _) = f.resume().unwrap().into_parts();
        assert_eq!(validate(&mut f, capture, &attempt), Ok(()));
        assert_eq!(validate(&mut f, capture, &attempt), Ok(()));
        let reply = f.caller.current_binding(&f.lanes).unwrap().reply_object;
        f.activations
            .recipient_mut(f.caller)
            .unwrap()
            .state
            .observe(&mut attempt, facts(reply, true), Some(7))
            .unwrap();
        assert_refused_unchanged(&mut f, capture, &attempt);
        assert_eq!(
            f.state().progress().disposition(),
            Some(KernelProviderPumpDisposition::Returned(7))
        );
    }
}

#[test]
fn irq_yield_requires_fresh_receive_entry_without_reopening_the_wait_claim() {
    let mut f = Fixture::new();
    f.lanes.select(f.capture.key(), 258).unwrap();
    let (capture, mut resumed, _) = f.resume().unwrap().into_parts();
    let reply = f.caller.current_binding(&f.lanes).unwrap().reply_object;
    let mut yielded = facts(reply, false);
    yielded.provider_wait_suspended = false;
    yielded.scheduler_yielded = true;
    f.activations
        .recipient_mut(f.caller)
        .unwrap()
        .state
        .observe(&mut resumed, yielded, None)
        .unwrap();
    assert_refused_unchanged(&mut f, capture, &resumed);
    let mut receive = f
        .activations
        .recipient_mut(f.caller)
        .unwrap()
        .state
        .begin_receive_after_yield()
        .unwrap();
    assert_refused_unchanged(&mut f, capture, &resumed);
    assert_eq!(validate(&mut f, capture, &receive), Ok(()));
    assert!(f.resume().is_err());
    assert_eq!(validate(&mut f, capture, &receive), Ok(()));
    f.activations
        .recipient_mut(f.caller)
        .unwrap()
        .state
        .observe(&mut receive, facts(reply, true), Some(0))
        .unwrap();
    assert_refused_unchanged(&mut f, capture, &receive);
}

#[test]
fn a_foreign_unconsumed_attempt_with_the_same_reply_number_is_not_execution() {
    let mut f = Fixture::new();
    let mut foreign = Fixture::new();
    assert_eq!(
        f.caller.current_binding(&f.lanes).unwrap().reply_object,
        foreign
            .caller
            .current_binding(&foreign.lanes)
            .unwrap()
            .reply_object
    );
    f.lanes.select(f.capture.key(), 258).unwrap();
    foreign.lanes.select(foreign.capture.key(), 258).unwrap();
    let (capture, attempt, _) = f.resume().unwrap().into_parts();
    let (_, foreign_attempt, _) = foreign.resume().unwrap().into_parts();
    assert_refused_unchanged(&mut f, capture, &foreign_attempt);
    assert_eq!(validate(&mut f, capture, &attempt), Ok(()));
}

#[test]
fn altered_frame_capture_owner_and_phase_refuse_without_consuming_entry() {
    let mut f = Fixture::new();
    f.lanes.select(f.capture.key(), 258).unwrap();
    let (capture, attempt, _) = f.resume().unwrap().into_parts();
    let lane = f.caller.dispatch.lane();
    let original = f.lanes.top(lane).unwrap().unwrap().clone();
    let foreign_capture = Fixture::new().capture;
    f.lanes
        .frame_mut(lane, capture.key())
        .unwrap()
        .unwrap()
        .continuation = foreign_capture;
    assert_refused_unchanged(&mut f, capture, &attempt);
    *f.lanes.frame_mut(lane, capture.key()).unwrap().unwrap() = original.clone();
    f.lanes
        .frame_mut(lane, capture.key())
        .unwrap()
        .unwrap()
        .owner
        .provider_generation += 1;
    assert_refused_unchanged(&mut f, capture, &attempt);
    *f.lanes.frame_mut(lane, capture.key()).unwrap().unwrap() = original.clone();
    f.lanes
        .frame_mut(lane, capture.key())
        .unwrap()
        .unwrap()
        .phase = SuspensionPhase::Waiting;
    assert_refused_unchanged(&mut f, capture, &attempt);
    *f.lanes.frame_mut(lane, capture.key()).unwrap().unwrap() = original;
    assert_eq!(validate(&mut f, capture, &attempt), Ok(()));
}

#[test]
fn foreign_canonical_authorities_and_wrong_caller_refuse_the_claimed_entry() {
    let mut f = Fixture::new();
    f.lanes.select(f.capture.key(), 258).unwrap();
    let (capture, attempt, _) = f.resume().unwrap().into_parts();
    let mut foreign_pm = bootstrap().into_parts().pm;
    requestor(&mut foreign_pm, 0x3000);
    let mut foreign_catalog = ProviderDomainCatalog::new();
    assert_eq!(foreign_catalog.register().unwrap(), f.provider);
    for (pm, catalog) in [(&foreign_pm, &f.catalog), (&f.pm, &foreign_catalog)] {
        assert!(f
            .activations
            .validate_wait_execution(f.caller, pm, catalog, &f.lanes, capture, &attempt,)
            .is_err());
    }
    let mut wrong = f.caller;
    wrong.receive_endpoint += 1;
    assert!(f
        .activations
        .validate_wait_execution(wrong, &f.pm, &f.catalog, &f.lanes, capture, &attempt,)
        .is_err());
    assert_eq!(validate(&mut f, capture, &attempt), Ok(()));
}

#[test]
fn provider_retirement_and_requestor_exit_revoke_execution_after_claim() {
    for retire_provider in [false, true] {
        let mut f = Fixture::new();
        f.lanes.select(f.capture.key(), 258).unwrap();
        let (capture, attempt, _) = f.resume().unwrap().into_parts();
        assert_eq!(validate(&mut f, capture, &attempt), Ok(()));
        if retire_provider {
            f.catalog.retire(f.provider, 0).unwrap();
        } else {
            f.pm.terminate_thread(f.caller.thread().thread_id(), 0)
                .unwrap();
        }
        assert_refused_unchanged(&mut f, capture, &attempt);
    }
}

#[test]
fn recycled_wait_id_does_not_authorize_the_old_capture_epoch() {
    let mut f = Fixture::new();
    let original = f.capture;
    f.lanes.select(original.key(), 258).unwrap();
    f.repark(72, 2);
    let current = f.repark(71, 3);
    assert_eq!(original.key(), current.key());
    assert_eq!(original.request(), current.request());
    assert_ne!(original, current);
    let (_, attempt, _) = f.resume().unwrap().into_parts();
    assert_refused_unchanged(&mut f, original, &attempt);
    assert_eq!(validate(&mut f, current, &attempt), Ok(()));
}

#[test]
fn paired_stale_frame_and_capture_cannot_replace_the_claimed_origin_across_irq_yield() {
    for after_yield in [false, true] {
        let mut f = Fixture::new();
        let original = f.capture;
        f.lanes.select(original.key(), 258).unwrap();
        f.repark(72, 2);
        let current = f.repark(71, 3);
        assert_eq!(original.key(), current.key());
        assert_eq!(original.request(), current.request());
        assert_ne!(original, current);
        let (_, mut attempt, _) = f.resume().unwrap().into_parts();
        if after_yield {
            let mut yielded = facts(
                f.caller.current_binding(&f.lanes).unwrap().reply_object,
                false,
            );
            yielded.provider_wait_suspended = false;
            yielded.scheduler_yielded = true;
            let state = &mut f.activations.recipient_mut(f.caller).unwrap().state;
            state.observe(&mut attempt, yielded, None).unwrap();
            attempt = state.begin_receive_after_yield().unwrap();
        }
        assert_eq!(f.state().active_resume(), Some(current));
        assert_eq!(validate(&mut f, current, &attempt), Ok(()));
        let lane = f.caller.dispatch.lane();
        f.lanes
            .frame_mut(lane, current.key())
            .unwrap()
            .unwrap()
            .continuation = original;
        assert_refused_unchanged(&mut f, original, &attempt);
        assert_eq!(f.state().active_resume(), Some(current));
        f.lanes
            .frame_mut(lane, current.key())
            .unwrap()
            .unwrap()
            .continuation = current;
        assert_eq!(validate(&mut f, current, &attempt), Ok(()));
    }
}
