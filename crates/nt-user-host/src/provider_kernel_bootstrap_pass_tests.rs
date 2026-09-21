use super::*;
use nt_component_suspension::{ResumeDemand, ResumePass, ResumeWake};

fn next_in_pass(f: &mut Fixture, pass: &mut ResumePass) -> Option<KernelProviderWaitCapture> {
    let candidate = f.lanes.next_resumable_in_pass(pass, |frame| {
        f.activations
            .validate_wait_resume(
                frame.continuation.caller(),
                &f.pm,
                &f.catalog,
                &f.lanes,
                frame.continuation,
            )
            .is_ok()
    })?;
    Some(f.lanes.top(candidate.lane).unwrap().unwrap().continuation)
}

#[test]
fn ready_repark_waits_for_next_bounded_pass_before_exact_terminal_ack() {
    let (mut f, mut state) = fixture(true);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    let bank = &*f.activations.recipient(f.caller).unwrap().bank as *const u64;
    let mut wake = ResumeWake::new(10, 40).unwrap();
    wake.reconcile_demand(ResumeDemand::Pending, 100);
    let mut wake_pass = wake.begin_pass(100).unwrap().unwrap();
    assert!(matches!(
        admit(&mut f, &mut state, &mut arbiter, 1),
        Ok(Admission::Satisfied { .. })
    ));
    let mut pass = f.lanes.resume_pass();
    assert_eq!(next_in_pass(&mut f, &mut pass), Some(f.capture));

    let next = next_capture(&mut f, 72);
    assert!(f.lanes.execution_busy());
    assert_eq!(state.events.set_existing(101), Some(false));
    assert!(matches!(
        repark(&mut f, &mut state, &mut arbiter, next, 2),
        Ok((Admission::Satisfied { .. }, _))
    ));
    f.capture = next;
    assert!(!f.lanes.execution_busy());
    assert!(f.lanes.next_resumable().is_some());
    assert_eq!(next_in_pass(&mut f, &mut pass), None);
    assert_eq!(f.state().captured_wait(), Some(next));
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    assert_eq!(
        &*f.activations.recipient(f.caller).unwrap().bank as *const u64,
        bank
    );
    wake.finish_pass(&mut wake_pass, 100, true, true).unwrap();
    assert_eq!(wake.next_deadline(), Some(110));
    assert!(wake.begin_pass(109).unwrap().is_none());

    let mut wake_pass = wake.begin_pass(110).unwrap().unwrap();
    let mut pass = f.lanes.resume_pass();
    assert_eq!(next_in_pass(&mut f, &mut pass), Some(next));
    let (_, mut attempt, _) = f.resume().unwrap().into_parts();
    let reply = f.caller.current_binding(&f.lanes).unwrap().reply_object;
    f.activations
        .recipient_mut(f.caller)
        .unwrap()
        .state
        .observe(&mut attempt, facts(reply, true), Some(7))
        .unwrap();
    let terminal = f
        .activations
        .retain_terminal_completion(
            f.caller,
            &f.pm,
            &f.catalog,
            &mut f.lanes,
            next.key(),
            456,
            7,
        )
        .unwrap();
    assert!(f.activations.completion(f.caller).is_err());
    assert_eq!(next_in_pass(&mut f, &mut pass), None);
    let mut delivery = f
        .lanes
        .begin_terminal_stage(terminal, reply, TerminalStage::LocalDelivery)
        .unwrap();
    f.activations
        .with_terminal_recipient(
            f.caller,
            &f.pm,
            &mut f.lanes,
            terminal,
            &delivery,
            |recipient, payload, status| {
                assert_eq!(*payload, 456);
                assert_eq!(status, 7);
                recipient.state.deliver_terminal_return(terminal, status)
            },
        )
        .unwrap()
        .unwrap();
    assert!(f.state().delivered_terminal_return(terminal, 7));
    f.lanes
        .record_terminal_stage(&mut delivery, reply, TerminalStageOutcome::Acknowledged)
        .unwrap();
    let (receipt, retired) = f
        .activations
        .finish_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(retired.payload, 456);
    assert_eq!(receipt, f.activations.completion(f.caller).unwrap());
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    let wrong = KernelProviderCompletionReceipt {
        status: 8,
        ..receipt
    };
    assert!(f
        .activations
        .acknowledge_completion_with_recipient(wrong, &mut f.pm)
        .is_err());
    assert_eq!(receipt, f.activations.completion(f.caller).unwrap());
    let (status, recipient) = f
        .activations
        .acknowledge_completion_with_recipient(receipt, &mut f.pm)
        .unwrap();
    assert_eq!(status, 7);
    assert_eq!(&*recipient.bank as *const u64, bank);
    assert_eq!(references(&f.pm, f.caller.thread()), (0, 0));
    assert!(!f.activations.has_ready_completion());
    assert_eq!(state.event_objects.live_lease_count(), 0);
    wake.finish_pass(&mut wake_pass, 110, false, true).unwrap();
    assert_eq!(wake.next_deadline(), None);
}

#[test]
fn candidate_claim_refusal_is_not_retried_inside_same_pass() {
    let (mut f, mut state) = fixture(true);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
    let mut pass = f.lanes.resume_pass();
    let capture = next_in_pass(&mut f, &mut pass).unwrap();
    let mut wrong = f.caller;
    wrong.receive_endpoint += 1;
    assert!(f
        .activations
        .begin_wait_resume(wrong, &f.pm, &f.catalog, &mut f.lanes, capture)
        .is_err());
    assert_eq!(next_in_pass(&mut f, &mut pass), None);
    assert_eq!(f.state().captured_wait(), Some(capture));
    assert!(!f.lanes.execution_busy());
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    let mut next_pass = f.lanes.resume_pass();
    assert_eq!(next_in_pass(&mut f, &mut next_pass), Some(capture));
    assert!(f.resume().is_ok());
}

#[test]
fn stopped_wait_publication_releases_running_before_future_pacing_deadline() {
    for repeated in [false, true] {
        for signaled in [false, true] {
            let (mut f, mut state) = fixture(repeated || signaled);
            let mut arbiter = ProviderDispatcherWaitArbiter::new();
            let work = if repeated {
                admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
                let previous = f.capture;
                let next = next_capture(&mut f, 72);
                if signaled {
                    assert_eq!(state.events.set_existing(101), Some(false));
                }
                KernelProviderWaitWork::Repark { previous, next }
            } else {
                KernelProviderWaitWork::Initial(f.capture)
            };
            let capture = match work {
                KernelProviderWaitWork::Initial(capture) => capture,
                KernelProviderWaitWork::Repark { next, .. } => next,
            };
            let mut wake = ResumeWake::new(10, 40).unwrap();
            wake.reconcile_demand(ResumeDemand::Pending, 100);
            let mut previous_pass = wake.begin_pass(100).unwrap().unwrap();
            wake.finish_pass(&mut previous_pass, 100, true, true)
                .unwrap();
            assert_eq!(wake.next_deadline(), Some(110));
            assert!(wake.begin_pass(105).unwrap().is_none());
            assert!(f.lanes.execution_busy());

            // Publication is memory-only and precedes the pacing gate. Deferring it would
            // strand Running ownership and prevent the outer scheduler from receiving.
            let publication_time = TimeSnapshot {
                monotonic_100ns: 105,
                ..now()
            };
            let (admission, _) = f
                .activations
                .publish_wait_work(
                    f.caller,
                    &f.pm,
                    &f.catalog,
                    &mut f.lanes,
                    &mut arbiter,
                    &mut backend(&mut state, Some(f.caller.owner())),
                    work,
                    2,
                    publication_time,
                    capture,
                    |status| status,
                )
                .unwrap();
            f.capture = capture;
            assert!(!f.lanes.execution_busy());
            assert_eq!(f.state().captured_wait(), Some(capture));
            assert_eq!(wake.next_deadline(), Some(110));
            assert!(wake.begin_pass(109).unwrap().is_none());
            if signaled {
                assert!(matches!(admission, Admission::Satisfied { .. }));
                assert!(f.lanes.next_resumable().is_some());
                wake.reconcile_demand(ResumeDemand::Pending, 109);
                assert_eq!(wake.next_deadline(), Some(110));
                let mut pass = wake.begin_pass(110).unwrap().unwrap();
                let _execution = f.resume().unwrap();
                assert!(f.lanes.execution_busy());
                wake.finish_pass(&mut pass, 110, true, true).unwrap();
            } else {
                assert!(matches!(admission, Admission::Parked { .. }));
                assert!(f.lanes.next_resumable().is_none());
                // The NT timeout is based on captured time 10, not publication time 105.
                assert_eq!(capture.observed_at(), now());
                assert_eq!(arbiter.next_deadline(publication_time), Some(100_010));
                assert_eq!(state.event_objects.live_lease_count(), 1);
            }
        }
    }
}
