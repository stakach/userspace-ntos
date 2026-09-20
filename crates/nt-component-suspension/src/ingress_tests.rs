use super::*;

type Lanes = ComponentSuspensionLanes<u64, u32, ()>;

fn receive<M>(lanes: &Lanes, ingress: &mut ComponentIngress<M>, message: M) {
    let mut attempt = lanes.begin_ingress_receive(ingress).unwrap();
    assert!(ingress
        .observe_receive(&mut attempt, IngressObservation::Call(message))
        .is_ok());
}

#[test]
fn invalid_bindings_are_rejected() {
    for (endpoint, reply) in [(0, 1), (1, 0), (1, 1)] {
        assert!(matches!(
            ComponentIngress::<()>::new(endpoint, reply),
            Err(IngressError::InvalidBinding)
        ));
    }
}

#[test]
fn canonical_lane_reply_is_excluded_when_idle_running_or_suspended() {
    let mut lanes = Lanes::new(1, 1);
    let lane = lanes
        .allocate(LaneBinding {
            executor_id: 10,
            receive_endpoint: 20,
            reply_object: 30,
        })
        .unwrap();
    let mut aliased = ComponentIngress::<()>::new(40, 30).unwrap();
    assert_eq!(
        lanes.begin_ingress_receive(&mut aliased).unwrap_err(),
        IngressError::ReplyInUse
    );
    lanes.begin_dispatch(lane, 30).unwrap();
    let mut separate = ComponentIngress::<()>::new(40, 50).unwrap();
    for ingress in [&mut aliased, &mut separate] {
        assert_eq!(
            lanes.begin_ingress_receive(ingress).unwrap_err(),
            IngressError::ExecutionBusy
        );
        assert_eq!(ingress.phase, Phase::Ready);
    }
    lanes.suspend_running(lane, 30, 1).unwrap();
    assert_eq!(
        lanes.begin_ingress_receive(&mut aliased).unwrap_err(),
        IngressError::ReplyInUse
    );
    assert!(lanes.begin_ingress_receive(&mut separate).is_ok());
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
}

#[test]
fn dropped_receive_and_wrong_owner_never_reopen_receive() {
    let lanes = Lanes::new(0, 1);
    let mut first = ComponentIngress::<u64>::new(10, 20).unwrap();
    let mut second = ComponentIngress::<u64>::new(30, 40).unwrap();
    let mut first_attempt = lanes.begin_ingress_receive(&mut first).unwrap();
    let second_attempt = lanes.begin_ingress_receive(&mut second).unwrap();
    let error = second
        .observe_receive(&mut first_attempt, IngressObservation::Call(123))
        .err()
        .unwrap();
    assert!(matches!(
        error,
        (IngressError::WrongAttempt, IngressObservation::Call(123))
    ));
    assert!(first
        .observe_receive(&mut first_attempt, IngressObservation::NoCall)
        .is_ok());
    drop(second_attempt);
    assert_eq!(
        lanes.begin_ingress_receive(&mut second).unwrap_err(),
        IngressError::NotReady
    );
    assert!(matches!(second.phase, Phase::Receiving(_)));
    assert!(second.message().is_none());
}

#[test]
fn no_call_releases_receive_but_zero_word_call_requires_reply_acknowledgement() {
    let lanes = Lanes::new(0, 1);
    let mut ingress = ComponentIngress::new(10, 20).unwrap();
    let mut empty = lanes.begin_ingress_receive(&mut ingress).unwrap();
    assert!(ingress
        .observe_receive(&mut empty, IngressObservation::NoCall)
        .is_ok());
    assert!(ingress
        .observe_receive(&mut empty, IngressObservation::NoCall)
        .is_err());
    receive(&lanes, &mut ingress, (0u64, [0u64; 0]));
    assert_eq!(ingress.message(), Some(&(0, [])));
    assert_eq!(
        lanes.begin_ingress_receive(&mut ingress).unwrap_err(),
        IngressError::NotReady
    );
    let mut reply = ingress.begin_reply().unwrap();
    assert_eq!(
        ingress.observe_reply(&mut reply, IngressReplyObservation::Acknowledged),
        Ok(Some((0, [])))
    );
    assert_eq!(
        ingress.observe_reply(&mut reply, IngressReplyObservation::Acknowledged),
        Err(IngressError::WrongAttempt)
    );
    assert!(ingress.message().is_none());
    assert!(lanes.begin_ingress_receive(&mut ingress).is_ok());
}

#[test]
fn no_effects_retains_the_exact_nonclone_payload_for_a_fresh_reply_attempt() {
    #[derive(Debug, PartialEq)]
    struct Payload(alloc::boxed::Box<u64>);
    let lanes = Lanes::new(0, 1);
    let mut ingress = ComponentIngress::new(10, 20).unwrap();
    let payload = Payload(alloc::boxed::Box::new(123));
    let address = &*payload.0 as *const u64;
    receive(&lanes, &mut ingress, payload);
    let mut first = ingress.begin_reply().unwrap();
    assert_eq!(
        ingress.observe_reply(&mut first, IngressReplyObservation::NoEffects),
        Ok(None)
    );
    assert_eq!(&*ingress.message().unwrap().0 as *const u64, address);
    assert_eq!(
        lanes.begin_ingress_receive(&mut ingress).unwrap_err(),
        IngressError::NotReady
    );
    let mut retry = ingress.begin_reply().unwrap();
    assert_eq!(
        ingress.observe_reply(&mut first, IngressReplyObservation::Acknowledged),
        Err(IngressError::WrongAttempt)
    );
    let released = ingress
        .observe_reply(&mut retry, IngressReplyObservation::Acknowledged)
        .unwrap()
        .unwrap();
    assert_eq!(&*released.0 as *const u64, address);
}

#[test]
fn indeterminate_reply_retains_exact_ticket_until_later_evidence() {
    let lanes = Lanes::new(0, 1);
    let mut first = ComponentIngress::new(10, 20).unwrap();
    let mut second = ComponentIngress::new(30, 40).unwrap();
    receive(&lanes, &mut first, 123);
    receive(&lanes, &mut second, 456);
    let mut attempt = first.begin_reply().unwrap();
    let mut other = second.begin_reply().unwrap();
    for _ in 0..2 {
        assert_eq!(
            first.observe_reply(&mut attempt, IngressReplyObservation::Indeterminate),
            Ok(None)
        );
        assert_eq!(first.message(), Some(&123));
        assert_eq!(first.begin_reply().unwrap_err(), IngressError::NotReady);
        assert_eq!(
            lanes.begin_ingress_receive(&mut first).unwrap_err(),
            IngressError::NotReady
        );
    }
    assert_eq!(
        first.observe_reply(&mut other, IngressReplyObservation::Acknowledged),
        Err(IngressError::WrongAttempt)
    );
    assert_eq!(
        first.observe_reply(&mut attempt, IngressReplyObservation::Acknowledged),
        Ok(Some(123))
    );
    drop(other);
    assert_eq!(second.begin_reply().unwrap_err(), IngressError::NotReady);
    assert_eq!(second.message(), Some(&456));
}

#[test]
fn exhausted_identities_fail_before_receive_or_reply_state_changes() {
    let lanes = Lanes::new(0, 1);
    for value in [0, u64::MAX] {
        let counter = AtomicU64::new(value);
        let mut ingress = ComponentIngress::new(10, 20).unwrap();
        assert_eq!(
            ingress.begin_receive(&counter).unwrap_err(),
            IngressError::IdentityExhausted
        );
        assert_eq!(ingress.phase, Phase::Ready);
        assert_eq!(counter.load(Ordering::Relaxed), value);
        receive(&lanes, &mut ingress, 123);
        assert_eq!(
            ingress.begin_reply_with_counter(&counter).unwrap_err(),
            IngressError::IdentityExhausted
        );
        assert_eq!(ingress.phase, Phase::Held);
        assert_eq!(ingress.message(), Some(&123));
        assert_eq!(counter.load(Ordering::Relaxed), value);
    }
}

fn ingress_in_phase(lanes: &Lanes, reply: u64, phase: usize) -> ComponentIngress<u64> {
    let mut ingress = ComponentIngress::new(10, reply).unwrap();
    if phase == 1 {
        let _attempt = lanes.begin_ingress_receive(&mut ingress).unwrap();
    } else if phase >= 2 {
        receive(lanes, &mut ingress, reply + 100);
        if phase >= 3 {
            let mut attempt = ingress.begin_reply().unwrap();
            if phase == 4 {
                assert_eq!(
                    ingress.observe_reply(&mut attempt, IngressReplyObservation::Indeterminate),
                    Ok(None)
                );
            }
        }
    }
    ingress
}

#[test]
fn handoff_rejects_every_nonheld_current_or_nonready_replacement_without_changes() {
    let lanes = Lanes::new(0, 1);
    for current_phase in 0..5 {
        for replacement_phase in 0..5 {
            if current_phase == 2 && replacement_phase == 0 {
                continue;
            }
            let mut current = ingress_in_phase(&lanes, 20, current_phase);
            let replacement = ingress_in_phase(&lanes, 30, replacement_phase);
            let before_current = (current.phase, current.message);
            let before_replacement = (replacement.phase, replacement.message);
            let (error, replacement) = lanes
                .handoff_ingress_call(&mut current, replacement)
                .err()
                .unwrap();
            assert_eq!(error, IngressError::NotReady);
            assert_eq!((current.phase, current.message), before_current);
            assert_eq!((replacement.phase, replacement.message), before_replacement);
            assert_eq!((current.endpoint(), current.reply()), (10, 20));
            assert_eq!((replacement.endpoint(), replacement.reply()), (10, 30));
        }
    }
}

#[test]
fn handoff_rejects_different_endpoint_or_same_reply_and_retains_both_owners() {
    let lanes = Lanes::new(0, 1);
    for (endpoint, reply) in [(11, 30), (10, 20)] {
        let mut current = ingress_in_phase(&lanes, 20, 2);
        let replacement = ComponentIngress::new(endpoint, reply).unwrap();
        let (error, replacement) = lanes
            .handoff_ingress_call(&mut current, replacement)
            .err()
            .unwrap();
        assert_eq!(error, IngressError::InvalidBinding);
        assert_eq!(current.phase, Phase::Held);
        assert_eq!(current.message(), Some(&120));
        assert_eq!(replacement.phase, Phase::Ready);
        assert!(replacement.message().is_none());
        assert_eq!(
            (replacement.endpoint(), replacement.reply()),
            (endpoint, reply)
        );
        let mut attempt = current.begin_reply().unwrap();
        assert_eq!(
            current.observe_reply(&mut attempt, IngressReplyObservation::Acknowledged),
            Ok(Some(120))
        );
    }
}

#[test]
fn handoff_checks_both_canonical_replies_and_physical_execution_before_moving() {
    for bound_reply in [20, 30, 40] {
        for lane_phase in 0..3 {
            let mut lanes = Lanes::new(1, 1);
            let mut current = ingress_in_phase(&lanes, 20, 2);
            let replacement = ComponentIngress::new(10, 30).unwrap();
            let lane = lanes
                .allocate(LaneBinding {
                    executor_id: 50,
                    receive_endpoint: 60,
                    reply_object: bound_reply,
                })
                .unwrap();
            if lane_phase > 0 {
                lanes.begin_dispatch(lane, bound_reply).unwrap();
                if lane_phase == 2 {
                    lanes.suspend_running(lane, bound_reply, 1).unwrap();
                }
            }
            let result = lanes.handoff_ingress_call(&mut current, replacement);
            if bound_reply == 40 && lane_phase != 1 {
                let retained = result.ok().unwrap();
                assert_eq!(retained.message(), Some(&120));
                assert_eq!(current.reply(), 30);
            } else {
                let (error, replacement) = result.err().unwrap();
                assert_eq!(
                    error,
                    if lane_phase == 1 {
                        IngressError::ExecutionBusy
                    } else {
                        IngressError::ReplyInUse
                    }
                );
                assert_eq!(current.phase, Phase::Held);
                assert_eq!(current.message(), Some(&120));
                assert_eq!(current.reply(), 20);
                assert_eq!(replacement.phase, Phase::Ready);
                assert_eq!(replacement.reply(), 30);
                assert!(replacement.message().is_none());
            }
            assert_eq!(
                lanes.phase(lane),
                Ok(match lane_phase {
                    0 => LanePhase::Idle,
                    1 => LanePhase::Running,
                    _ => LanePhase::Suspended,
                })
            );
        }
    }
}

#[test]
fn handoff_retains_nonclone_payload_while_replacement_receives_and_replies_independently() {
    #[derive(Debug, PartialEq)]
    struct Payload(alloc::boxed::Box<u64>);
    let lanes = Lanes::new(0, 1);
    let mut current = ComponentIngress::new(10, 20).unwrap();
    let payload = Payload(alloc::boxed::Box::new(123));
    let address = &*payload.0 as *const u64;
    let mut old_receive = lanes.begin_ingress_receive(&mut current).unwrap();
    assert!(current
        .observe_receive(&mut old_receive, IngressObservation::Call(payload))
        .is_ok());
    let replacement = ComponentIngress::new(10, 30).unwrap();
    let mut retained = lanes
        .handoff_ingress_call(&mut current, replacement)
        .ok()
        .unwrap();
    assert_eq!(retained.phase, Phase::Held);
    assert_eq!(retained.reply(), 20);
    assert_eq!(&*retained.message().unwrap().0 as *const u64, address);
    assert_eq!(current.phase, Phase::Ready);
    assert!(current.message().is_none());
    let mut new_receive = lanes.begin_ingress_receive(&mut current).unwrap();
    assert!(matches!(
        current.observe_receive(&mut old_receive, IngressObservation::NoCall),
        Err((IngressError::WrongAttempt, IngressObservation::NoCall))
    ));
    assert!(matches!(
        retained.observe_receive(&mut new_receive, IngressObservation::NoCall),
        Err((IngressError::WrongAttempt, IngressObservation::NoCall))
    ));
    let mut old_reply = retained.begin_reply().unwrap();
    assert_eq!(
        retained.observe_reply(&mut old_reply, IngressReplyObservation::Indeterminate),
        Ok(None)
    );
    assert!(current
        .observe_receive(
            &mut new_receive,
            IngressObservation::Call(Payload(alloc::boxed::Box::new(456)))
        )
        .is_ok());
    let mut new_reply = current.begin_reply().unwrap();
    assert_eq!(
        current.observe_reply(&mut old_reply, IngressReplyObservation::Acknowledged),
        Err(IngressError::WrongAttempt)
    );
    assert_eq!(
        retained.observe_reply(&mut new_reply, IngressReplyObservation::Acknowledged),
        Err(IngressError::WrongAttempt)
    );
    assert_eq!(
        current.observe_reply(&mut new_reply, IngressReplyObservation::Acknowledged),
        Ok(Some(Payload(alloc::boxed::Box::new(456))))
    );
    assert_eq!(&*retained.message().unwrap().0 as *const u64, address);
    assert_eq!(retained.begin_reply().unwrap_err(), IngressError::NotReady);
    let _next_receive = lanes.begin_ingress_receive(&mut current).unwrap();
    let released = retained
        .observe_reply(&mut old_reply, IngressReplyObservation::Acknowledged)
        .unwrap()
        .unwrap();
    assert_eq!(&*released.0 as *const u64, address);
    assert_eq!(retained.phase, Phase::Ready);
    assert!(retained.message().is_none());
    assert!(lanes.begin_ingress_receive(&mut retained).is_ok());
}

// Native fan-in must still prove capability provenance and retain returned owners while routing.
