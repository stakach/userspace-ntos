use super::*;

fn retained_local(lanes: &mut Lanes, id: u64) -> TerminalIdentity {
    let (lane, key) = running(lanes, id);
    lanes
        .retain_local_terminal_running(lane, binding(id).reply_object, key, owner(id), id * 1000)
        .unwrap()
}

#[test]
fn local_delivery_acknowledges_without_hosted_stages_and_retires_exact_frame() {
    let mut lanes = Lanes::new(1, 2);
    let identity = retained_local(&mut lanes, 1);
    let reply = binding(1).reply_object;
    let dispatch = lanes.active_dispatch_identity(identity.lane()).unwrap();
    assert_eq!(
        lanes.terminal(identity, reply).unwrap().phase,
        TerminalPhase::Ready {
            stage: TerminalStage::LocalDelivery,
            last_error: None,
        }
    );
    for stage in [
        TerminalStage::Output,
        TerminalStage::Context,
        TerminalStage::Publication,
        TerminalStage::Reply,
    ] {
        assert!(lanes.begin_terminal_stage(identity, reply, stage).is_err());
    }
    assert!(lanes.finish_terminal(identity, reply, Ok(())).is_err());
    let mut attempt = lanes
        .begin_terminal_stage(identity, reply, TerminalStage::LocalDelivery)
        .unwrap();
    assert_eq!(attempt.identity(), identity);
    assert_eq!(attempt.stage(), TerminalStage::LocalDelivery);
    assert!(lanes
        .record_terminal_stage_with_payload(&mut attempt, reply, 99)
        .is_err());
    assert_eq!(*lanes.terminal(identity, reply).unwrap().payload, 1000);
    lanes
        .with_terminal_payload(&attempt, reply, |payload| *payload = 0xc0000001)
        .unwrap();
    lanes
        .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
        .unwrap();
    assert_eq!(
        lanes.terminal(identity, reply).unwrap().phase,
        TerminalPhase::Acknowledged { local_error: None }
    );
    assert_eq!(
        lanes.active_dispatch_identity(identity.lane()).unwrap(),
        dispatch
    );
    assert!(lanes
        .finish_terminal(identity, reply, Err(77))
        .unwrap()
        .is_none());
    assert_eq!(
        lanes.terminal(identity, reply).unwrap().phase,
        TerminalPhase::Acknowledged {
            local_error: Some(77)
        }
    );
    assert!(lanes
        .begin_terminal_stage(identity, reply, TerminalStage::LocalDelivery)
        .is_err());
    assert!(lanes
        .with_terminal_payload(&attempt, reply, |_| panic!("consumed ticket"))
        .is_err());
    let retired = lanes
        .finish_terminal(identity, reply, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(retired.suspension.key, identity.key());
    assert_eq!(retired.suspension.owner, owner(1));
    assert_eq!(retired.suspension.continuation, 100);
    assert_eq!(retired.suspension.completion, 42);
    assert_eq!(retired.payload, 0xc0000001);
    assert_eq!(lanes.phase(identity.lane()), Ok(LanePhase::Idle));
    assert!(lanes.finish_terminal(identity, reply, Ok(())).is_err());
}

#[test]
fn local_delivery_no_effects_retries_only_with_new_exact_ticket() {
    let mut lanes = Lanes::new(1, 2);
    let identity = retained_local(&mut lanes, 1);
    let reply = binding(1).reply_object;
    let mut first = lanes
        .begin_terminal_stage(identity, reply, TerminalStage::LocalDelivery)
        .unwrap();
    lanes
        .record_terminal_stage(&mut first, reply, TerminalStageOutcome::NoEffects(55))
        .unwrap();
    assert_eq!(
        lanes.terminal(identity, reply).unwrap().phase,
        TerminalPhase::Ready {
            stage: TerminalStage::LocalDelivery,
            last_error: Some(55),
        }
    );
    let mut retry = lanes
        .begin_terminal_stage(identity, reply, TerminalStage::LocalDelivery)
        .unwrap();
    assert!(retry.attempt > first.attempt);
    assert!(lanes
        .with_terminal_payload(&first, reply, |_| panic!("old attempt"))
        .is_err());
    assert!(lanes
        .record_terminal_stage(&mut first, reply, TerminalStageOutcome::Acknowledged)
        .is_err());
    lanes
        .record_terminal_stage(&mut retry, reply, TerminalStageOutcome::Acknowledged)
        .unwrap();
    assert!(matches!(
        lanes.terminal(identity, reply).unwrap().phase,
        TerminalPhase::Acknowledged { .. }
    ));
}

#[test]
fn local_delivery_uncertainty_and_dropped_attempt_never_replay() {
    for uncertain in [false, true] {
        let mut lanes = Lanes::new(1, 2);
        let identity = retained_local(&mut lanes, 1);
        let reply = binding(1).reply_object;
        let mut attempt = lanes
            .begin_terminal_stage(identity, reply, TerminalStage::LocalDelivery)
            .unwrap();
        if uncertain {
            lanes
                .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Indeterminate(91))
                .unwrap();
        }
        drop(attempt);
        assert_eq!(lanes.next_terminal(), None);
        assert!(lanes.has_terminal_in_scope(scope()));
        assert_eq!(lanes.suspension_count(identity.lane()), Ok(1));
        assert!(lanes
            .begin_terminal_stage(identity, reply, TerminalStage::LocalDelivery)
            .is_err());
        assert!(lanes.finish_terminal(identity, reply, Ok(())).is_err());
        assert!(lanes.release(identity.lane(), reply).is_err());
        assert_eq!(*lanes.terminal(identity, reply).unwrap().payload, 1000);
    }
}

#[test]
fn local_delivery_cannot_replace_hosted_protocol() {
    let mut lanes = Lanes::new(1, 2);
    let identity = retained(&mut lanes, 1);
    let reply = binding(1).reply_object;
    assert!(lanes
        .begin_terminal_stage(identity, reply, TerminalStage::LocalDelivery)
        .is_err());
    ack(&mut lanes, identity, TerminalStage::Output);
    assert_eq!(
        lanes.terminal(identity, reply).unwrap().phase,
        TerminalPhase::Ready {
            stage: TerminalStage::Context,
            last_error: None
        }
    );
    assert!(lanes.finish_terminal(identity, reply, Ok(())).is_err());
}

#[test]
fn local_delivery_respects_busy_fence_and_foreign_ticket_rejection() {
    let mut lanes = Lanes::new(2, 2);
    let identity = retained_local(&mut lanes, 1);
    let reply = binding(1).reply_object;
    let peer = lanes.allocate(binding(2)).unwrap();
    lanes.begin_dispatch(peer, binding(2).reply_object).unwrap();
    assert!(matches!(
        lanes.begin_terminal_stage(identity, reply, TerminalStage::LocalDelivery),
        Err(LaneError::Busy)
    ));
    lanes
        .finish_dispatch(peer, binding(2).reply_object)
        .unwrap();
    let mut other = Lanes::new(1, 2);
    let other_identity = retained_local(&mut other, 1);
    let mut attempt = lanes
        .begin_terminal_stage(identity, reply, TerminalStage::LocalDelivery)
        .unwrap();
    assert_eq!(
        lanes.begin_dispatch(peer, binding(2).reply_object),
        Err(LaneError::Busy)
    );
    assert!(other
        .with_terminal_payload(&attempt, reply, |_| panic!("foreign ticket"))
        .is_err());
    assert!(other
        .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
        .is_err());
    assert!(lanes
        .record_terminal_stage(&mut attempt, reply + 1, TerminalStageOutcome::Acknowledged)
        .is_err());
    lanes
        .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
        .unwrap();
    assert_eq!(
        other.terminal(other_identity, reply).unwrap().phase,
        TerminalPhase::Ready {
            stage: TerminalStage::LocalDelivery,
            last_error: None
        }
    );
}
