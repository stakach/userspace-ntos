use super::*;

const STAGES: [TerminalStage; 4] = [
    TerminalStage::Output,
    TerminalStage::Context,
    TerminalStage::Publication,
    TerminalStage::Reply,
];

fn transfer(lanes: &mut Lanes, id: u64, token: u64) -> TerminalIdentity {
    let (lane, key) = running(lanes, id);
    lanes.retain_external_terminal_running(
        lane, binding(id).reply_object, key, owner(id), token, id * 1000,
    ).unwrap()
}

#[test]
fn preentry_capacity_failure_preserves_selected_source_and_epoch() {
    let mut lanes = Lanes::new(1, 2);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    let key = SuspensionKey::provider_wait(1);
    lanes.begin_dispatch(lane, reply).unwrap();
    lanes.admit_running(lane, reply, key, 1, owner(1), 100).unwrap();
    lanes.select(key, 42).unwrap();
    assert_eq!(lanes.begin_resume_with_capacity(lane, reply, key, |_| {
        Err(LaneError::NoCapacity)
    }), Err(LaneError::NoCapacity));
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    assert_eq!(lanes.running(), None);
    assert_eq!(lanes.lane(lane).unwrap().resume_epoch, 0);
    assert_eq!(lanes.external_depth(lane), Ok(0));
    assert!(matches!(lanes.frame(lane, key).unwrap().unwrap().phase,
        SuspensionPhase::Selected { completion: 42 }));
    assert_eq!(lanes.next_resumable().unwrap().suspension.key, key);
    lanes.begin_resume(lane, reply, key).unwrap();
    assert!(lanes.lane(lane).unwrap().external_tokens.capacity() >= 1);
}

#[test]
fn preentry_depth_refusal_does_not_reserve_or_consume_selected_source() {
    let mut lanes = Lanes::new(1, 1);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    let key = SuspensionKey::provider_wait(1);
    lanes.begin_dispatch(lane, reply).unwrap();
    lanes.suspend_running(lane, reply, 77).unwrap();
    lanes.resume_external(lane, reply, 77).unwrap();
    lanes.admit_running(lane, reply, key, 1, owner(1), 100).unwrap();
    lanes.select(key, 42).unwrap();
    assert_eq!(lanes.begin_resume_with_capacity(lane, reply, key,
        |_| panic!("depth refusal must precede allocation")),
        Err(LaneError::Suspension(SuspensionError::Overflow)));
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    assert_eq!(lanes.lane(lane).unwrap().resume_epoch, 0);
    assert_eq!(lanes.external_top(lane), Ok(Some(77)));
    assert!(matches!(lanes.frame(lane, key).unwrap().unwrap().phase,
        SuspensionPhase::Selected { completion: 42 }));
}

#[test]
fn handoff_requires_every_ack_and_successful_local_retirement_without_allocation() {
    let mut lanes = Lanes::new(1, 2);
    let identity = transfer(&mut lanes, 1, 77);
    let lane = identity.lane();
    let reply = identity.binding.reply_object;
    let vector = &lanes.lane(lane).unwrap().external_tokens;
    let reserved = (vector.as_ptr(), vector.capacity());
    assert_eq!(identity.external_token(), Some(77));
    for stage in STAGES {
        assert_eq!(lanes.external_top(lane), Ok(None));
        assert_eq!(lanes.can_resume_external(lane, reply, 77), Ok(false));
        assert!(lanes.resume_external(lane, reply, 77).is_err());
        assert!(lanes.finish_terminal(identity, reply, Ok(())).is_err());
        assert_eq!(lanes.suspension_count(lane), Ok(1));
        assert!(matches!(lanes.frame(lane, identity.key()).unwrap().unwrap().phase,
            SuspensionPhase::Resuming { .. }));
        let mut failed = lanes.begin_terminal_stage(identity, reply, stage).unwrap();
        lanes.record_terminal_stage(&mut failed, reply, TerminalStageOutcome::NoEffects(12)).unwrap();
        assert_eq!(lanes.external_top(lane), Ok(None));
        ack(&mut lanes, identity, stage);
    }
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Terminal));
    assert_eq!(lanes.can_resume_external(lane, reply, 77), Ok(false));
    assert!(lanes.finish_terminal(identity, reply, Err(19)).unwrap().is_none());
    assert_eq!(lanes.suspension_count(lane), Ok(1));
    assert_eq!(lanes.external_depth(lane), Ok(0));
    let retired = lanes.finish_terminal(identity, reply, Ok(())).unwrap().unwrap();
    assert_eq!(retired.suspension.continuation, 100);
    assert_eq!(retired.payload, 1000);
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    assert_eq!(lanes.suspension_count(lane), Ok(0));
    assert_eq!(lanes.external_top(lane), Ok(Some(77)));
    let vector = &lanes.lane(lane).unwrap().external_tokens;
    assert_eq!((vector.as_ptr(), vector.capacity()), reserved);
    assert!(lanes.finish_terminal(identity, reply, Ok(())).is_err());
    assert_eq!(lanes.can_resume_external(lane, reply, 78), Ok(false));
    assert!(lanes.can_resume_external(lane, reply + 1, 77).is_err());
    assert_eq!(lanes.can_resume_external(lane, reply, 77), Ok(true));
    lanes.resume_external(lane, reply, 77).unwrap();
    lanes.complete_external(lane, reply, 77).unwrap();
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
}

#[test]
fn rejected_handoff_returns_owned_payload_without_mutating_running_source() {
    let mut lanes = Lanes::new(1, 3);
    let (lane, key) = running(&mut lanes, 1);
    let reply = binding(1).reply_object;
    for (bad_reply, bad_key, bad_owner, token) in [
        (reply, key, owner(1), 0),
        (reply + 1, key, owner(1), 77),
        (reply, SuspensionKey::provider_wait(2), owner(1), 77),
        (reply, key, owner(2), 77),
    ] {
        let (_, payload) = lanes.retain_external_terminal_running(
            lane, bad_reply, bad_key, bad_owner, token, 123,
        ).unwrap_err();
        assert_eq!(payload, 123);
        assert_eq!(lanes.phase(lane), Ok(LanePhase::Running));
        assert_eq!(lanes.running(), Some(lane));
        assert_eq!(lanes.suspension_count(lane), Ok(1));
    }
    lanes.suspend_running(lane, reply, 77).unwrap();
    lanes.resume_external(lane, reply, 77).unwrap();
    assert_eq!(lanes.retain_external_terminal_running(lane, reply, key, owner(1), 77, 123),
        Err((LaneError::InvalidIdentity, 123)));
    assert_eq!(lanes.external_top(lane), Ok(Some(77)));
    let identity = lanes.retain_external_terminal_running(lane, reply, key, owner(1), 88, 123).unwrap();
    let mut forged = identity;
    forged.external_token = Some(89);
    assert!(lanes.terminal(forged, reply).is_err());
    assert!(lanes.begin_terminal_stage(forged, reply, TerminalStage::Output).is_err());
    assert!(lanes.finish_terminal(forged, reply, Ok(())).is_err());
    assert_eq!(lanes.terminal_record(identity, reply).unwrap().identity.external_token(), Some(88));
}

#[test]
fn indeterminate_transfer_retains_source_and_token_while_other_lanes_progress() {
    for uncertain in STAGES {
        let mut lanes = Lanes::new(2, 2);
        let identity = transfer(&mut lanes, 1, 77);
        let reply = binding(1).reply_object;
        for stage in STAGES {
            if stage == uncertain { break; }
            ack(&mut lanes, identity, stage);
        }
        let mut attempt = lanes.begin_terminal_stage(identity, reply, uncertain).unwrap();
        lanes.record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Indeterminate(31)).unwrap();
        assert!(!lanes.execution_busy());
        assert!(lanes.has_terminal_in_scope(scope()));
        assert!(lanes.cancel(identity.key(), 31).is_err());
        assert_eq!(lanes.external_top(identity.lane()), Ok(None));
        assert_eq!(lanes.terminal_record(identity, reply).unwrap().identity.external_token(), Some(77));
        assert_eq!(lanes.suspension_count(identity.lane()), Ok(1));
        assert!(!lanes.can_resume_external(identity.lane(), reply, 77).unwrap());
        assert!(lanes.finish_terminal(identity, reply, Ok(())).is_err());
        let peer = retained(&mut lanes, 2);
        ack_all(&mut lanes, peer);
        lanes.finish_terminal(peer, binding(2).reply_object, Ok(())).unwrap().unwrap();
        assert_eq!(lanes.phase(peer.lane()), Ok(LanePhase::Idle));
        assert_eq!(lanes.phase(identity.lane()), Ok(LanePhase::Terminal));
    }
}

#[test]
fn invoking_stage_fences_all_execution_entry_and_selection_until_exact_ack() {
    let mut lanes = Lanes::new(4, 3);
    let first = transfer(&mut lanes, 1, 77);
    let second = retained(&mut lanes, 2);
    let peer = lanes.allocate(binding(3)).unwrap();
    let peer_reply = binding(3).reply_object;
    lanes.begin_dispatch(peer, peer_reply).unwrap();
    lanes.suspend_running(peer, peer_reply, 88).unwrap();
    lanes.resume_external(peer, peer_reply, 88).unwrap();
    let key = SuspensionKey::provider_wait(3);
    lanes.admit_running(peer, peer_reply, key, 3, owner(3), 300).unwrap();
    lanes.select(key, 42).unwrap();
    let idle = lanes.allocate(binding(4)).unwrap();
    let reply = binding(1).reply_object;
    let mut attempt = lanes.begin_terminal_stage(first, reply, TerminalStage::Output).unwrap();
    assert!(lanes.execution_busy());
    assert_eq!(lanes.begin_dispatch(idle, binding(4).reply_object), Err(LaneError::Busy));
    assert_eq!(lanes.resume_external(peer, peer_reply, 88), Err(LaneError::Busy));
    assert_eq!(lanes.can_resume_external(peer, peer_reply, 88), Ok(false));
    assert_eq!(lanes.begin_resume(peer, peer_reply, key), Err(LaneError::Busy));
    assert_eq!(lanes.rollback_admission(peer, peer_reply, key), Err(LaneError::Busy));
    assert_eq!(lanes.next_resumable_if(|_| panic!("fenced selection")), None);
    assert_eq!(lanes.next_terminal_if(|_, _| panic!("fenced selection")), None);
    assert_eq!(lanes.next_idle(), None);
    assert!(!lanes.needs_idle_lane());
    assert!(matches!(lanes.begin_terminal_stage(second, binding(2).reply_object, TerminalStage::Output),
        Err(LaneError::Busy)));
    assert!(lanes.record_terminal_stage(&mut attempt, reply + 1, TerminalStageOutcome::Acknowledged).is_err());
    assert!(lanes.execution_busy());
    lanes.record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged).unwrap();
    assert!(!lanes.execution_busy());
    assert!(lanes.next_resumable().is_some());
    assert!(lanes.next_terminal().is_some());
    assert_eq!(lanes.can_resume_external(peer, peer_reply, 88), Ok(true));
    lanes.begin_dispatch(idle, binding(4).reply_object).unwrap();
}

#[test]
fn payload_access_requires_exact_live_unconsumed_attempt() {
    let mut lanes = Lanes::new(1, 2);
    let identity = transfer(&mut lanes, 1, 77);
    let reply = binding(1).reply_object;
    let mut attempt = lanes.begin_terminal_stage(identity, reply, TerminalStage::Output).unwrap();
    assert_eq!(lanes.with_terminal_payload(&attempt, reply, |payload| {
        let previous = *payload;
        *payload = 2000;
        previous
    }), Ok(1000));
    assert!(lanes.with_terminal_payload(&attempt, reply + 1, |_| panic!("wrong reply")).is_err());
    let mut foreign_lanes = Lanes::new(1, 2);
    let foreign_identity = transfer(&mut foreign_lanes, 1, 77);
    let foreign = foreign_lanes.begin_terminal_stage(foreign_identity, reply, TerminalStage::Output).unwrap();
    assert!(lanes.with_terminal_payload(&foreign, reply, |_| panic!("foreign attempt")).is_err());
    lanes.record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::NoEffects(7)).unwrap();
    assert!(lanes.with_terminal_payload(&attempt, reply, |_| panic!("consumed attempt")).is_err());
    let mut retry = lanes.begin_terminal_stage(identity, reply, TerminalStage::Output).unwrap();
    let stale = TerminalAttempt { consumed: false, ..attempt };
    assert!(lanes.with_terminal_payload(&stale, reply, |_| panic!("stale ticket")).is_err());
    assert_eq!(lanes.with_terminal_payload(&retry, reply, |payload| *payload), Ok(2000));
    lanes.record_terminal_stage(&mut retry, reply, TerminalStageOutcome::Acknowledged).unwrap();
    assert!(lanes.with_terminal_payload(&retry, reply, |_| panic!("acknowledged ticket")).is_err());
}

#[test]
fn noncopy_payload_survives_rejection_and_local_take_across_mechanism_entry() {
    use alloc::boxed::Box;
    let mut lanes = ComponentSuspensionLanes::<u64, u32, Option<Box<u64>>>::new(1, 2);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    let key = SuspensionKey::provider_wait(1);
    lanes.begin_dispatch(lane, reply).unwrap();
    lanes.admit_running(lane, reply, key, 1, owner(1), 100).unwrap();
    lanes.select(key, 42).unwrap();
    lanes.begin_resume(lane, reply, key).unwrap();
    let payload = Some(Box::new(99));
    let original = &**payload.as_ref().unwrap() as *const u64;
    let (error, payload) = lanes.retain_external_terminal_running(
        lane, reply, key, owner(1), 0, payload,
    ).unwrap_err();
    assert_eq!(error, LaneError::InvalidIdentity);
    assert_eq!(&**payload.as_ref().unwrap() as *const u64, original);
    let identity = lanes.retain_external_terminal_running(
        lane, reply, key, owner(1), 77, payload,
    ).unwrap();
    let mut attempt = lanes.begin_terminal_stage(identity, reply, TerminalStage::Output).unwrap();
    let mut local = lanes.with_terminal_payload(&attempt, reply, Option::take).unwrap().unwrap();
    assert!(lanes.terminal(identity, reply).unwrap().payload.is_none());
    assert!(lanes.execution_busy());
    assert!(lanes.has_terminal_in_scope(scope()));
    *local = 100;
    lanes.with_terminal_payload(&attempt, reply, |payload| *payload = Some(local)).unwrap();
    lanes.record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged).unwrap();
    let payload = lanes.terminal(identity, reply).unwrap().payload.as_ref().unwrap();
    assert_eq!(&**payload as *const u64, original);
    assert_eq!(**payload, 100);
}

#[test]
fn interleaved_handoffs_keep_owned_bytes_after_shared_input_reuse() {
    let mut lanes = ComponentSuspensionLanes::<u64, u32, alloc::vec::Vec<u8>>::new(2, 2);
    let mut shared = [0u8; 64];
    let mut identities = alloc::vec::Vec::new();
    for id in 1..=2 {
        let lane = lanes.allocate(binding(id)).unwrap();
        let reply = binding(id).reply_object;
        let key = SuspensionKey::provider_wait(id);
        lanes.begin_dispatch(lane, reply).unwrap();
        lanes.admit_running(lane, reply, key, id, owner(id), id * 100).unwrap();
        lanes.select(key, 42).unwrap();
        lanes.begin_resume(lane, reply, key).unwrap();
        shared.fill(id as u8);
        identities.push(lanes.retain_external_terminal_running(
            lane, reply, key, owner(id), id + 70, shared.to_vec(),
        ).unwrap());
    }
    shared.fill(0xff);
    for (index, identity) in identities.into_iter().enumerate().rev() {
        let reply = identity.binding.reply_object;
        for stage in STAGES {
            let mut attempt = lanes.begin_terminal_stage(identity, reply, stage).unwrap();
            lanes.with_terminal_payload(&attempt, reply, |bytes| {
                assert_eq!(bytes.as_slice(), &[index as u8 + 1; 64]);
            }).unwrap();
            assert_eq!(lanes.can_resume_external(identity.lane(), reply, index as u64 + 71), Ok(false));
            lanes.record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged).unwrap();
        }
        let retired = lanes.finish_terminal(identity, reply, Ok(())).unwrap().unwrap();
        assert_eq!(retired.payload.as_slice(), &[index as u8 + 1; 64]);
    }
}
