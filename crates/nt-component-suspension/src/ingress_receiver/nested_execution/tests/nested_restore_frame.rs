use super::*;

#[test]
fn nested_restore_frame_keeps_the_continuation_until_exact_restoration() {
    use crate::{NestedRestoreFrame, NestedRestoreFrameError as Error, NestedRestoreKey,
        NestedRestorePhase as Phase};
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let scope = f.receiver.suspend_for_nested_execution(
        route, dispatch, &mut f.lanes, &f.peers, bound,
    ).unwrap();
    let parent_reply = f.lanes.binding(dispatch.lane()).unwrap().reply_object;
    let owner = receive_owner(dispatch);
    let key = NestedRestoreKey::new(scope.identity(), parent_reply, 501, owner).unwrap();
    let wrong_reply = NestedRestoreKey::new(scope.identity(), parent_reply + 1, 501, owner).unwrap();
    let wrong_root_reply = NestedRestoreKey::new(scope.identity(), parent_reply, 502, owner).unwrap();
    let wrong_owner = NestedRestoreKey::new(scope.identity(), parent_reply, 501,
        crate::SuspensionOwner { dispatch_id: owner.dispatch_id + 1, ..owner }).unwrap();
    let mut other = Fixture::new();
    let (other_route, other_dispatch) = other.parent(2);
    let other_scope = other.receiver.suspend_for_nested_execution(
        other_route, other_dispatch, &mut other.lanes, &other.peers, bound,
    ).unwrap();
    let wrong_scope = NestedRestoreKey::new(other_scope.identity(), parent_reply, 501, owner).unwrap();

    let mut frame = NestedRestoreFrame::prepare(key, 0xBEEF_u64);
    assert_eq!(frame.transfer_result_no_effects(key, Ok::<_, u64>), Err(Error::InvalidPhase));
    assert_eq!(frame.retain(wrong_scope), Err(Error::InvalidIdentity));
    assert_eq!(frame.retain(wrong_reply), Err(Error::InvalidIdentity));
    assert_eq!(frame.retain(wrong_root_reply), Err(Error::InvalidIdentity));
    assert_eq!(frame.retain(wrong_owner), Err(Error::InvalidIdentity));
    assert_eq!(frame.phase(), Phase::Prepared);
    frame.retain(key).unwrap();
    assert_eq!(frame.transfer_result_no_effects(key, Ok::<_, u64>), Err(Error::InvalidPhase));
    frame.begin_retry(key).unwrap();
    assert_eq!(frame.transfer_result_no_effects(key, Ok::<_, u64>), Err(Error::InvalidPhase));
    frame.refuse_retry_no_effects(key).unwrap();
    assert_eq!(frame.phase(), Phase::Retained);
    frame.begin_retry(key).unwrap();
    frame.acknowledge_restored(key).unwrap();
    assert_eq!(frame.transfer_result_no_effects(key, Ok::<_, u64>), Err(Error::InvalidPhase));
    frame.begin_receive(key).unwrap();
    assert_eq!(frame.begin_receive(key), Err(Error::InvalidPhase));
    frame.refuse_receive_no_effects(key).unwrap();
    frame.begin_receive(key).unwrap();
    assert_eq!(frame.record_receive_result(wrong_owner, 0xFACE),
        Err((Error::InvalidIdentity, 0xFACE)));
    assert_eq!(frame.record_receive_result(key, 0xFACE), Ok(0xBEEF));
    assert_eq!(frame.phase(), Phase::ResultRetained);
    assert_eq!(frame.transfer_result_no_effects(wrong_owner, Ok::<_, u64>),
        Err(Error::InvalidIdentity));
    assert_eq!(frame.transfer_result_no_effects(key, Err::<u64, _>),
        Err(Error::RefusedNoEffects));
    assert_eq!(frame.phase(), Phase::ResultRetained);
    assert_eq!(frame.transfer_result_no_effects(wrong_scope, Ok::<_, u64>),
        Err(Error::InvalidIdentity));
    assert_eq!(frame.transfer_result_no_effects(key, Ok::<_, u64>), Ok(0xFACE));
    assert_eq!(frame.transfer_result_no_effects(key, Ok::<_, u64>),
        Err(Error::InvalidPhase));
    assert_eq!(frame.phase(), Phase::Consumed);
}
#[test]
fn uncertain_nested_restore_never_retries_or_yields_a_completion() {
    use crate::{NestedRestoreFrame, NestedRestoreFrameError as Error, NestedRestoreKey,
        NestedRestorePhase as Phase};
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let scope = f.receiver.suspend_for_nested_execution(
        route, dispatch, &mut f.lanes, &f.peers, bound,
    ).unwrap();
    let reply = f.lanes.binding(dispatch.lane()).unwrap().reply_object;
    let key = NestedRestoreKey::new(scope.identity(), reply, 501, receive_owner(dispatch)).unwrap();
    let mut frame = NestedRestoreFrame::prepare(key, 0xCAFE_u64);
    frame.retain(key).unwrap();
    frame.begin_retry(key).unwrap();
    frame.quarantine(key).unwrap();
    assert_eq!(frame.phase(), Phase::Quarantined);
    assert_eq!(frame.begin_retry(key), Err(Error::InvalidPhase));
    assert_eq!(frame.refuse_retry_no_effects(key), Err(Error::InvalidPhase));
    assert_eq!(frame.acknowledge_restored(key), Err(Error::InvalidPhase));
    assert_eq!(frame.transfer_result_no_effects(key, Ok::<_, u64>), Err(Error::InvalidPhase));
}

#[test]
fn uncertain_receive_setup_quarantines_the_restored_parent_and_keeps_its_snapshot() {
    use crate::{NestedRestoreFrame, NestedRestoreFrameError as Error, NestedRestoreKey,
        NestedRestorePhase as Phase};
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let scope = f.receiver.suspend_for_nested_execution(
        route, dispatch, &mut f.lanes, &f.peers, bound,
    ).unwrap();
    let reply = f.lanes.binding(dispatch.lane()).unwrap().reply_object;
    let key = NestedRestoreKey::new(scope.identity(), reply, 501, receive_owner(dispatch)).unwrap();
    let mut frame = NestedRestoreFrame::prepare(key, 0xABCD_u64);
    frame.retain(key).unwrap();
    frame.begin_retry(key).unwrap();
    frame.acknowledge_restored(key).unwrap();
    frame.begin_receive(key).unwrap();
    frame.quarantine_receive(key).unwrap();
    assert_eq!(frame.phase(), Phase::Quarantined);
    assert_eq!(frame.continuation_ref(key), Ok(&0xABCD));
    assert_eq!(frame.begin_receive(key), Err(Error::InvalidPhase));
    assert_eq!(frame.refuse_receive_no_effects(key), Err(Error::InvalidPhase));
    assert_eq!(frame.transfer_result_no_effects(key, Ok::<_, u64>),
        Err(Error::InvalidPhase));
}

#[test]
fn restored_nested_terminal_admission_is_exact_and_returns_both_values_on_refusal() {
    use crate::{NestedRestoreKey, SuspensionKey, SuspensionPhase, TerminalStage,
        TerminalStageOutcome};
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let reply = f.lanes.binding(dispatch.lane()).unwrap().reply_object;
    let owner = receive_owner(dispatch);
    let mut scope = f.receiver.suspend_for_nested_execution(
        route, dispatch, &mut f.lanes, &f.peers, bound,
    ).unwrap();
    let identity = scope.identity();
    let key = NestedRestoreKey::new(identity, reply, 501, owner).unwrap();
    let stale = NestedRestoreKey::new(identity, reply + 1, 501, owner).unwrap();
    assert!(matches!(f.lanes.retain_nested_restored_terminal_owned(key, 1, 123, ()),
        Err((_, 123, ()))));
    f.receiver.resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound).unwrap();
    assert!(matches!(f.lanes.retain_nested_restored_terminal_owned(stale, 1, 123, ()),
        Err((_, 123, ()))));
    assert_eq!(f.lanes.suspension_count(dispatch.lane()), Ok(0));
    let terminal = f.lanes.retain_nested_restored_terminal_owned(key, 1, 123, ()).unwrap();
    assert_eq!(terminal.key(), SuspensionKey::nested_restore(identity.sequence()));
    assert!(matches!(f.lanes.frame(dispatch.lane(), terminal.key()).unwrap().unwrap().phase,
        SuspensionPhase::NestedTerminal));
    assert!(f.lanes.finish_shared_nested_restore_terminal(route, dispatch, terminal, reply,
        Ok(())).is_err());
    for stage in [TerminalStage::Output, TerminalStage::Context,
        TerminalStage::Publication, TerminalStage::Reply] {
        let mut attempt = f.lanes.begin_terminal_stage(terminal, reply, stage).unwrap();
        f.lanes.record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
            .unwrap();
    }
    let retired = f.lanes.finish_shared_nested_restore_terminal(
        route, dispatch, terminal, reply, Ok(())).unwrap().unwrap();
    assert_eq!(retired.continuation, 123);
    assert_eq!(retired.payload, ());
    assert_eq!(f.lanes.active_dispatch_identity(dispatch.lane()), Ok(Some(dispatch)));
    assert_eq!(f.lanes.suspension_count(dispatch.lane()), Ok(0));
}

#[test]
fn restored_nested_continuation_moves_to_a_real_wait_only_after_admission() {
    use crate::{NestedRestoreFrame, NestedRestoreFrameError as Error, NestedRestoreKey,
        NestedRestorePhase as Phase, SuspensionKey};
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let reply = f.lanes.binding(dispatch.lane()).unwrap().reply_object;
    let owner = receive_owner(dispatch);
    let mut scope = f.receiver.suspend_for_nested_execution(
        route, dispatch, &mut f.lanes, &f.peers, bound,
    ).unwrap();
    let key = NestedRestoreKey::new(scope.identity(), reply, 501, owner).unwrap();
    let mut frame = NestedRestoreFrame::prepare(key, 123_u64);
    frame.retain(key).unwrap();
    frame.begin_retry(key).unwrap();
    f.receiver.resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound).unwrap();
    frame.acknowledge_restored(key).unwrap();
    frame.begin_receive(key).unwrap();
    assert_eq!(frame.record_receive_result(key, 123), Ok(123));
    let wait = SuspensionKey::provider_wait(77);
    assert_eq!(frame.transfer_result_no_effects(key, |continuation| {
        f.lanes.admit_running_owned(dispatch.lane(), reply + 1, wait, 1, owner, continuation)
            .map_err(|(_, continuation)| continuation)
    }), Err(Error::RefusedNoEffects));
    assert_eq!(frame.phase(), Phase::ResultRetained);
    assert_eq!(f.lanes.suspension_count(dispatch.lane()), Ok(0));
    frame.transfer_result_no_effects(key, |continuation| {
        f.lanes.admit_running_owned(dispatch.lane(), reply, wait, 1, owner, continuation)
            .map_err(|(_, continuation)| continuation)
    }).unwrap();
    assert_eq!(frame.phase(), Phase::Consumed);
    assert_eq!(f.lanes.frame(dispatch.lane(), wait).unwrap().unwrap().continuation, 123);
    assert_eq!(frame.transfer_result_no_effects(key, Ok::<_, u64>), Err(Error::InvalidPhase));
}
