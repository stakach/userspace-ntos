use super::*;

#[path = "handoff_tests.rs"]
mod handoff_tests;

type Lanes = ComponentSuspensionLanes<u64, u32, u64>;

fn owner(id: u64) -> SuspensionOwner {
    SuspensionOwner {
        provider_domain: 1,
        provider_generation: 2,
        client_pi: 3,
        client_generation: 4,
        client_tid: 5,
        client_badge: 6,
        dispatch_id: id,
    }
}

fn scope() -> SuspensionScope {
    SuspensionScope::Thread {
        domain: 1,
        provider_generation: 2,
        client_pi: 3,
        client_generation: 4,
        client_tid: 5,
        client_badge: 6,
    }
}

fn binding(id: u64) -> LaneBinding {
    LaneBinding {
        executor_id: id * 10 + 1,
        receive_endpoint: id * 10 + 2,
        reply_object: id * 10 + 3,
    }
}

fn running(lanes: &mut Lanes, id: u64) -> (LaneHandle, SuspensionKey) {
    let bind = binding(id);
    let lane = lanes.allocate(bind).unwrap();
    let key = SuspensionKey::provider_wait(id);
    lanes.begin_dispatch(lane, bind.reply_object).unwrap();
    lanes
        .admit_running(lane, bind.reply_object, key, id, owner(id), id * 100)
        .unwrap();
    lanes.select(key, 42).unwrap();
    lanes.begin_resume(lane, bind.reply_object, key).unwrap();
    (lane, key)
}

fn retained(lanes: &mut Lanes, id: u64) -> TerminalIdentity {
    let (lane, key) = running(lanes, id);
    lanes
        .retain_terminal_running(lane, binding(id).reply_object, key, owner(id), id * 1000)
        .unwrap()
}

fn ack(lanes: &mut Lanes, identity: TerminalIdentity, stage: TerminalStage) {
    let reply = identity.binding.reply_object;
    let mut attempt = lanes.begin_terminal_stage(identity, reply, stage).unwrap();
    lanes
        .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
        .unwrap();
}

fn ack_all(lanes: &mut Lanes, identity: TerminalIdentity) {
    for stage in [
        TerminalStage::Output,
        TerminalStage::Context,
        TerminalStage::Publication,
        TerminalStage::Reply,
    ] {
        ack(lanes, identity, stage);
    }
}

#[test]
fn provider_and_terminal_entry_share_the_execution_fence() {
    let mut lanes = Lanes::new(2, 4);
    let identity = retained(&mut lanes, 1);
    let reply = binding(1).reply_object;
    let peer = lanes.allocate(binding(2)).unwrap();
    let peer_reply = binding(2).reply_object;
    let before = lanes.terminal(identity, reply).unwrap().phase;
    lanes.begin_dispatch(peer, peer_reply).unwrap();
    assert_eq!(
        lanes.next_terminal_if(|_, _| panic!("running provider excludes terminal selection")),
        None
    );
    assert!(matches!(
        lanes.begin_terminal_stage(identity, reply, TerminalStage::Output),
        Err(LaneError::Busy)
    ));
    assert_eq!(lanes.terminal(identity, reply).unwrap().phase, before);
    lanes.finish_dispatch(peer, peer_reply).unwrap();
    let mut attempt = lanes
        .begin_terminal_stage(identity, reply, TerminalStage::Output)
        .unwrap();
    assert_eq!(lanes.begin_dispatch(peer, peer_reply), Err(LaneError::Busy));
    lanes
        .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
        .unwrap();
    assert_eq!(lanes.next_terminal(), Some(identity));
    ack(&mut lanes, identity, TerminalStage::Context);
}

#[test]
fn output_context_reply_and_local_retirement_retain_exact_original_frame() {
    let mut lanes = Lanes::new(2, 4);
    let identity = retained(&mut lanes, 1);
    let reply = binding(1).reply_object;
    let dispatch = lanes
        .active_dispatch_identity(identity.lane())
        .unwrap()
        .unwrap();
    assert_eq!(lanes.phase(identity.lane()), Ok(LanePhase::Terminal));
    assert_eq!(lanes.running(), None);
    assert_eq!(lanes.suspension_count(identity.lane()), Ok(1));
    assert_eq!(lanes.next_terminal(), Some(identity));
    assert_eq!(lanes.frames().count(), 1);
    assert!(lanes.contains_scope(scope()));
    assert!(lanes.has_terminal_in_scope(scope()));
    assert_eq!(lanes.next_cancellable_in_scope(scope()), None);
    assert!(lanes.finish_terminal(identity, reply, Ok(())).is_err());
    assert!(lanes
        .begin_terminal_stage(identity, reply, TerminalStage::Context)
        .is_err());

    let mut output = lanes
        .begin_terminal_stage(identity, reply, TerminalStage::Output)
        .unwrap();
    assert_eq!(lanes.next_terminal(), None);
    lanes
        .record_terminal_stage_with_payload(&mut output, reply, 0xc0000001)
        .unwrap();
    assert_eq!(
        *lanes.terminal(identity, reply).unwrap().payload,
        0xc0000001
    );
    assert!(lanes
        .record_terminal_stage(&mut output, reply, TerminalStageOutcome::Acknowledged)
        .is_err());
    ack(&mut lanes, identity, TerminalStage::Context);
    ack(&mut lanes, identity, TerminalStage::Publication);
    ack(&mut lanes, identity, TerminalStage::Reply);
    assert!(lanes.is_dispatch_identity_active(dispatch));
    assert_eq!(lanes.next_terminal(), Some(identity));
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
    assert!(lanes.contains_scope(scope()));
    for stage in [
        TerminalStage::Output,
        TerminalStage::Context,
        TerminalStage::Publication,
        TerminalStage::Reply,
    ] {
        assert!(lanes.begin_terminal_stage(identity, reply, stage).is_err());
    }
    let retired = lanes
        .finish_terminal(identity, reply, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(retired.suspension.key, identity.key());
    assert_eq!(retired.suspension.owner, owner(1));
    assert_eq!(retired.suspension.continuation, 100);
    assert_eq!(retired.suspension.completion, 42);
    assert!(!retired.suspension.cancelled);
    assert_eq!(retired.payload, 0xc0000001);
    assert_eq!(lanes.phase(identity.lane()), Ok(LanePhase::Idle));
    assert!(!lanes.is_dispatch_identity_active(dispatch));
    assert!(!lanes.contains_scope(scope()));
    assert!(!lanes.has_terminal_in_scope(scope()));
    assert_eq!(lanes.frames().count(), 0);
    assert!(lanes.finish_terminal(identity, reply, Ok(())).is_err());
}

#[test]
fn exact_identity_binding_scope_and_other_coordinator_reject_without_effects() {
    let mut lanes = Lanes::new(2, 3);
    let identity = retained(&mut lanes, 1);
    let reply = binding(1).reply_object;
    assert!(lanes.terminal(identity, reply + 1).is_err());
    let mut wrong_owner = identity;
    wrong_owner.owner.client_generation += 1;
    let mut wrong_provider = identity;
    wrong_provider.owner.provider_generation += 1;
    let mut wrong_key = identity;
    wrong_key.key = SuspensionKey::lpc_request(1);
    let mut wrong_binding = identity;
    wrong_binding.binding.executor_id += 1;
    let mut wrong_epoch = identity;
    wrong_epoch.resume_epoch += 1;
    for stale in [
        wrong_owner,
        wrong_provider,
        wrong_key,
        wrong_binding,
        wrong_epoch,
    ] {
        assert!(lanes.terminal(stale, reply).is_err());
        assert!(lanes
            .begin_terminal_stage(stale, reply, TerminalStage::Output)
            .is_err());
    }
    let mut other = Lanes::new(2, 3);
    let other_identity = retained(&mut other, 1);
    assert_ne!(identity, other_identity);
    let mut attempt = lanes
        .begin_terminal_stage(identity, reply, TerminalStage::Output)
        .unwrap();
    assert!(other
        .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
        .is_err());
    assert!(!attempt.consumed);
    lanes
        .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
        .unwrap();
    assert_eq!(
        other.terminal(other_identity, reply).unwrap().phase,
        TerminalPhase::Ready {
            stage: TerminalStage::Output,
            last_error: None
        }
    );
    let wrong_scope = SuspensionScope::Thread {
        domain: 1,
        provider_generation: 2,
        client_pi: 3,
        client_generation: 9,
        client_tid: 5,
        client_badge: 6,
    };
    assert!(!lanes.has_terminal_in_scope(wrong_scope));
}

#[test]
fn no_effects_retries_only_current_stage_with_new_ticket() {
    let mut lanes = Lanes::new(1, 2);
    let identity = retained(&mut lanes, 1);
    let reply = binding(1).reply_object;
    for stage in [
        TerminalStage::Output,
        TerminalStage::Context,
        TerminalStage::Publication,
        TerminalStage::Reply,
    ] {
        let mut rejected = lanes.begin_terminal_stage(identity, reply, stage).unwrap();
        let previous_attempt = rejected.attempt;
        lanes
            .record_terminal_stage(&mut rejected, reply, TerminalStageOutcome::NoEffects(55))
            .unwrap();
        assert_eq!(
            lanes.terminal(identity, reply).unwrap().phase,
            TerminalPhase::Ready {
                stage,
                last_error: Some(55)
            }
        );
        assert!(lanes.finish_terminal(identity, reply, Ok(())).is_err());
        let mut retry = lanes.begin_terminal_stage(identity, reply, stage).unwrap();
        assert!(retry.attempt > previous_attempt);
        assert!(lanes
            .record_terminal_stage(&mut rejected, reply, TerminalStageOutcome::Acknowledged)
            .is_err());
        lanes
            .record_terminal_stage(&mut retry, reply, TerminalStageOutcome::Acknowledged)
            .unwrap();
    }
    lanes
        .finish_terminal(identity, reply, Ok(()))
        .unwrap()
        .unwrap();
}

#[test]
fn indeterminate_stage_retains_authority_and_never_replays() {
    for uncertain_stage in [
        TerminalStage::Output,
        TerminalStage::Context,
        TerminalStage::Publication,
        TerminalStage::Reply,
    ] {
        let mut lanes = Lanes::new(1, 2);
        let identity = retained(&mut lanes, 1);
        let reply = binding(1).reply_object;
        for stage in [
            TerminalStage::Output,
            TerminalStage::Context,
            TerminalStage::Publication,
            TerminalStage::Reply,
        ] {
            if stage == uncertain_stage {
                break;
            }
            ack(&mut lanes, identity, stage);
        }
        let mut attempt = lanes
            .begin_terminal_stage(identity, reply, uncertain_stage)
            .unwrap();
        lanes
            .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Indeterminate(91))
            .unwrap();
        assert_eq!(
            lanes.terminal(identity, reply).unwrap().phase,
            TerminalPhase::Indeterminate {
                stage: uncertain_stage,
                status: 91
            }
        );
        assert_eq!(lanes.next_terminal(), None);
        assert_eq!(lanes.terminal_identities().count(), 1);
        assert!(lanes.has_terminal_in_scope(scope()));
        assert!(lanes.contains_scope(scope()));
        assert!(lanes.finish_terminal(identity, reply, Ok(())).is_err());
        assert!(lanes
            .begin_terminal_stage(identity, reply, uncertain_stage)
            .is_err());
        assert!(lanes
            .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
            .is_err());
        assert_eq!(*lanes.terminal(identity, reply).unwrap().payload, 1000);
    }
}

#[test]
fn dropped_inflight_ticket_does_not_reauthorize_stage_or_retirement() {
    let mut lanes = Lanes::new(1, 2);
    let identity = retained(&mut lanes, 1);
    let reply = binding(1).reply_object;
    let attempt = lanes
        .begin_terminal_stage(identity, reply, TerminalStage::Output)
        .unwrap();
    drop(attempt);
    assert_eq!(lanes.next_terminal(), None);
    assert!(lanes
        .begin_terminal_stage(identity, reply, TerminalStage::Output)
        .is_err());
    assert!(lanes.finish_terminal(identity, reply, Ok(())).is_err());
    assert!(lanes.release(identity.lane(), reply).is_err());
    assert!(lanes.has_terminal_in_scope(scope()));
}

#[test]
fn terminal_lane_blocks_mutation_but_other_lanes_can_run_and_retire() {
    let mut lanes = Lanes::new(3, 4);
    let identity = retained(&mut lanes, 1);
    let lane = identity.lane();
    let reply = binding(1).reply_object;
    assert!(lanes.begin_dispatch(lane, reply).is_err());
    assert!(lanes.begin_resume(lane, reply, identity.key()).is_err());
    assert!(lanes.finish_dispatch(lane, reply).is_err());
    assert!(lanes
        .retain_terminal_running(lane, reply, identity.key(), owner(1), 5)
        .is_err());
    assert!(lanes
        .admit_running(
            lane,
            reply,
            SuspensionKey::lpc_request(50),
            50,
            owner(50),
            50
        )
        .is_err());
    assert!(lanes
        .rearm_running(
            lane,
            reply,
            identity.key(),
            SuspensionKey::lpc_request(50),
            50,
            owner(1),
            50
        )
        .is_err());
    assert!(lanes.frame_mut(lane, identity.key()).is_err());
    assert!(lanes.select(identity.key(), 1).is_err());
    assert!(lanes.cancel(identity.key(), 1).is_err());
    assert!(lanes
        .rollback_admission(lane, reply, identity.key())
        .is_err());
    assert!(lanes.resume_external(lane, reply, 77).is_err());
    assert!(lanes.release(lane, reply).is_err());
    assert_eq!(lanes.next_resumable(), None);
    assert_eq!(lanes.next_idle(), None);

    let other_identity = retained(&mut lanes, 2);
    assert_eq!(lanes.next_terminal(), Some(identity));
    let mut held = lanes
        .begin_terminal_stage(identity, reply, TerminalStage::Output)
        .unwrap();
    assert_eq!(lanes.next_terminal(), None);
    lanes.record_terminal_stage(&mut held, reply, TerminalStageOutcome::Indeterminate(1)).unwrap();
    assert_eq!(lanes.next_terminal(), Some(other_identity));
    ack_all(&mut lanes, other_identity);
    lanes
        .finish_terminal(other_identity, binding(2).reply_object, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(lanes.next_idle().unwrap().0, other_identity.lane());
    assert_eq!(lanes.terminal_identities().count(), 1);
    assert!(lanes.terminal(identity, reply).is_ok());
}

#[test]
fn terminal_retirement_restores_external_ownership_without_idle_window() {
    let mut lanes = Lanes::new(1, 3);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    lanes.suspend_running(lane, reply, 88).unwrap();
    lanes.resume_external(lane, reply, 88).unwrap();
    let key = SuspensionKey::provider_wait(1);
    lanes
        .admit_running(lane, reply, key, 1, owner(1), 100)
        .unwrap();
    lanes.cancel(key, 99).unwrap();
    lanes.begin_resume(lane, reply, key).unwrap();
    let identity = lanes
        .retain_terminal_running(lane, reply, key, owner(1), 1000)
        .unwrap();
    assert_eq!(lanes.external_top(lane), Ok(Some(88)));
    assert!(lanes.resume_external(lane, reply, 88).is_err());
    ack_all(&mut lanes, identity);
    let retired = lanes
        .finish_terminal(identity, reply, Ok(()))
        .unwrap()
        .unwrap();
    assert!(retired.suspension.cancelled);
    assert_eq!(retired.suspension.completion, 99);
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    assert!(lanes.is_dispatch_identity_active(dispatch));
    lanes.resume_external(lane, reply, 88).unwrap();
    lanes.complete_external(lane, reply, 88).unwrap();
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
}

#[test]
fn terminal_blocks_buried_owners_from_scope_teardown_and_mutation() {
    let mut lanes = Lanes::new(1, 3);
    let (lane, parent_key) = running(&mut lanes, 1);
    let reply = binding(1).reply_object;
    let child_key = SuspensionKey::lpc_request(2);
    let child_owner = SuspensionOwner {
        client_tid: 77,
        client_badge: 88,
        ..owner(2)
    };
    lanes
        .admit_running(lane, reply, child_key, 2, child_owner, 200)
        .unwrap();
    lanes.select(child_key, 43).unwrap();
    lanes.begin_resume(lane, reply, child_key).unwrap();
    let identity = lanes
        .retain_terminal_running(lane, reply, child_key, child_owner, 2000)
        .unwrap();
    assert!(!scope().matches(identity.owner()));
    assert!(lanes.has_terminal_in_scope(scope()));
    assert!(lanes.contains_scope(scope()));
    assert_eq!(lanes.frames().count(), 2);
    assert!(lanes.frame_mut(lane, parent_key).is_err());
    assert!(lanes.select(parent_key, 1).is_err());
    assert!(lanes.cancel(parent_key, 1).is_err());
    ack_all(&mut lanes, identity);
    lanes
        .finish_terminal(identity, reply, Ok(()))
        .unwrap()
        .unwrap();
    assert!(!lanes.has_terminal_in_scope(scope()));
    assert!(lanes.contains_scope(scope()));
    assert_eq!(lanes.frames().count(), 1);
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
}

#[test]
fn stale_terminal_identity_cannot_access_reused_lane_or_dispatch() {
    let mut lanes = Lanes::new(1, 3);
    let first = retained(&mut lanes, 1);
    let reply = binding(1).reply_object;
    ack_all(&mut lanes, first);
    lanes
        .finish_terminal(first, reply, Ok(()))
        .unwrap()
        .unwrap();
    lanes.release(first.lane(), reply).unwrap();
    let second = retained(&mut lanes, 1);
    assert_eq!(first.lane().index, second.lane().index);
    assert_ne!(first.lane().generation, second.lane().generation);
    assert!(matches!(
        lanes.terminal(first, reply),
        Err(LaneError::StaleGeneration)
    ));
    assert!(lanes
        .begin_terminal_stage(first, reply, TerminalStage::Output)
        .is_err());
    assert!(lanes.finish_terminal(first, reply, Ok(())).is_err());
    assert_eq!(lanes.next_terminal(), Some(second));
}

#[test]
fn output_payload_update_is_atomic_and_forbidden_for_later_stages() {
    let mut lanes = Lanes::new(1, 2);
    let identity = retained(&mut lanes, 1);
    let reply = binding(1).reply_object;
    let mut output = lanes
        .begin_terminal_stage(identity, reply, TerminalStage::Output)
        .unwrap();
    assert!(lanes
        .record_terminal_stage_with_payload(&mut output, reply + 1, 77)
        .is_err());
    assert_eq!(*lanes.terminal(identity, reply).unwrap().payload, 1000);
    assert!(!output.consumed);
    lanes
        .record_terminal_stage_with_payload(&mut output, reply, 88)
        .unwrap();
    let mut context = lanes
        .begin_terminal_stage(identity, reply, TerminalStage::Context)
        .unwrap();
    assert!(lanes
        .record_terminal_stage_with_payload(&mut context, reply, 99)
        .is_err());
    assert_eq!(*lanes.terminal(identity, reply).unwrap().payload, 88);
    assert!(!context.consumed);
    lanes
        .record_terminal_stage(&mut context, reply, TerminalStageOutcome::Acknowledged)
        .unwrap();
}

#[test]
fn epoch_and_attempt_exhaustion_refuse_before_mechanism_entry() {
    let mut lanes = Lanes::new(1, 3);
    let (lane, key) = running(&mut lanes, 1);
    let reply = binding(1).reply_object;
    let next = SuspensionKey::lpc_request(2);
    lanes
        .rearm_running(lane, reply, key, next, 2, owner(1), 200)
        .unwrap();
    lanes.select(next, 5).unwrap();
    lanes.lane_mut(lane).unwrap().resume_epoch = u64::MAX;
    assert_eq!(
        lanes.begin_resume(lane, reply, next),
        Err(LaneError::NoCapacity)
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    assert_eq!(lanes.running(), None);
    assert!(matches!(
        lanes.frame(lane, next).unwrap().unwrap().phase,
        SuspensionPhase::Selected { completion: 5 }
    ));
    lanes.lane_mut(lane).unwrap().resume_epoch = u64::MAX - 1;
    lanes.begin_resume(lane, reply, next).unwrap();
    let identity = lanes
        .retain_terminal_running(lane, reply, next, owner(1), 1)
        .unwrap();
    assert_eq!(identity.resume_epoch, u64::MAX);
    lanes
        .lane_mut(lane)
        .unwrap()
        .terminal
        .as_mut()
        .unwrap()
        .next_attempt = u64::MAX;
    assert!(matches!(
        lanes.begin_terminal_stage(identity, reply, TerminalStage::Output),
        Err(LaneError::NoCapacity)
    ));
    assert_eq!(
        lanes.terminal(identity, reply).unwrap().phase,
        TerminalPhase::Ready {
            stage: TerminalStage::Output,
            last_error: None
        }
    );
    assert!(lanes.has_terminal_in_scope(scope()));
}

#[test]
fn filtered_selection_advances_past_failed_local_retirement_without_losing_it() {
    let mut lanes = Lanes::new(3, 2);
    let first = retained(&mut lanes, 1);
    let second = retained(&mut lanes, 2);
    let third = retained(&mut lanes, 3);
    ack_all(&mut lanes, first);
    assert!(lanes
        .finish_terminal(first, binding(1).reply_object, Err(7))
        .unwrap()
        .is_none());
    assert_eq!(lanes.next_terminal(), Some(first));
    let cursor = (1, first.lane().index);
    assert_eq!(
        lanes.next_terminal_if(|identity, view| {
            (view.frame.admission_sequence, identity.lane().index) > cursor
        }),
        Some(second)
    );
    ack_all(&mut lanes, second);
    lanes
        .finish_terminal(second, binding(2).reply_object, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(
        lanes.next_terminal_if(|identity, view| {
            (view.frame.admission_sequence, identity.lane().index) > cursor
        }),
        Some(third)
    );
    assert_eq!(
        lanes
            .terminal(first, binding(1).reply_object)
            .unwrap()
            .phase,
        TerminalPhase::Acknowledged {
            local_error: Some(7)
        }
    );
    assert_eq!(lanes.next_terminal(), Some(first));
    assert_eq!(lanes.terminal_identities().count(), 2);
}
