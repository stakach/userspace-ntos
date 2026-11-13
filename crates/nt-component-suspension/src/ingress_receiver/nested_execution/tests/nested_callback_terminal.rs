use super::*;

fn acknowledge_callback_terminal(
    lanes: &mut Lanes,
    identity: crate::TerminalIdentity,
    reply: u64,
) {
    use crate::{TerminalStage, TerminalStageOutcome};
    for stage in [TerminalStage::Output, TerminalStage::Context,
        TerminalStage::Publication, TerminalStage::Reply]
    {
        let mut attempt = lanes.begin_terminal_stage(identity, reply, stage).unwrap();
        lanes.record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
            .unwrap();
    }
}

#[test]
fn nested_callback_terminal_pushes_new_token_above_exact_outer_callback_after_ack() {
    use crate::NestedRestoreKey;
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let lane = dispatch.lane();
    let reply = f.lanes.binding(lane).unwrap().reply_object;
    let owner = receive_owner(dispatch);
    let outer = 77;
    let new_callback = 88;
    f.lanes.suspend_running(lane, reply, outer).unwrap();
    f.lanes.resume_external(lane, reply, outer).unwrap();
    let mut scope = f.receiver.suspend_for_nested_execution(
        route, dispatch, &mut f.lanes, &f.peers, bound,
    ).unwrap();
    let key = NestedRestoreKey::new(scope.identity(), reply, 501, owner).unwrap();
    f.receiver.resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound).unwrap();

    // Every refusal returns both offered values and leaves the active outer token untouched.
    for (observed_outer, offered_new) in [
        (None, new_callback),
        (Some(outer + 1), new_callback),
        (Some(outer), outer),
        (Some(outer), 0),
    ] {
        assert!(matches!(f.lanes.retain_nested_restored_callback_terminal_owned(
            key, observed_outer, offered_new, 1, 123, (),
        ), Err((_, 123, ()))));
        assert_eq!(f.lanes.external_top(lane), Ok(Some(outer)));
        assert_eq!(f.lanes.external_depth(lane), Ok(1));
        assert_eq!(f.lanes.suspension_count(lane), Ok(0));
    }

    let terminal = f.lanes.retain_nested_restored_callback_terminal_owned(
        key, Some(outer), new_callback, 1, 123, (),
    ).unwrap();
    assert_eq!(terminal.external_token(), Some(new_callback));
    assert_eq!(f.lanes.external_top(lane), Ok(Some(outer)));
    assert!(f.lanes.finish_shared_nested_restore_terminal(
        route, dispatch, terminal, reply, Ok(()),
    ).is_err());
    acknowledge_callback_terminal(&mut f.lanes, terminal, reply);
    // A lost capacity reservation after ACK must leave the terminal and frame intact.
    f.lanes.lane_mut(lane).unwrap().external_tokens.shrink_to_fit();
    assert!(matches!(f.lanes.finish_shared_nested_restore_terminal(
        route, dispatch, terminal, reply, Ok(()),
    ), Err(crate::LaneError::NoCapacity)));
    assert_eq!(f.lanes.terminal(terminal, reply).unwrap().phase,
        crate::TerminalPhase::Acknowledged { local_error: None });
    f.lanes.lane_mut(lane).unwrap().external_tokens.try_reserve(1).unwrap();
    let retired = f.lanes.finish_shared_nested_restore_terminal(
        route, dispatch, terminal, reply, Ok(()),
    ).unwrap().unwrap();
    assert_eq!((retired.continuation, retired.payload), (123, ()));
    assert_eq!(f.lanes.external_depth(lane), Ok(2));
    assert_eq!(f.lanes.external_top(lane), Ok(Some(new_callback)));
    f.lanes.repark_external(lane, reply, new_callback).unwrap();
    f.lanes.resume_external(lane, reply, new_callback).unwrap();
    f.lanes.retire_external_running(lane, reply, new_callback).unwrap();
    assert_eq!(f.lanes.external_top(lane), Ok(Some(outer)));
}

#[test]
fn nested_callback_terminal_without_outer_token_reparks_only_new_callback() {
    use crate::NestedRestoreKey;
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let lane = dispatch.lane();
    let reply = f.lanes.binding(lane).unwrap().reply_object;
    let owner = receive_owner(dispatch);
    let mut scope = f.receiver.suspend_for_nested_execution(
        route, dispatch, &mut f.lanes, &f.peers, bound,
    ).unwrap();
    let key = NestedRestoreKey::new(scope.identity(), reply, 501, owner).unwrap();
    f.receiver.resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound).unwrap();

    assert!(matches!(f.lanes.retain_nested_restored_callback_terminal_owned(
        key, Some(77), 88, 1, 123, (),
    ), Err((_, 123, ()))));
    let terminal = f.lanes.retain_nested_restored_callback_terminal_owned(
        key, None, 88, 1, 123, (),
    ).unwrap();
    assert_eq!(terminal.external_token(), Some(88));
    acknowledge_callback_terminal(&mut f.lanes, terminal, reply);
    let retired = f.lanes.finish_shared_nested_restore_terminal(
        route, dispatch, terminal, reply, Ok(()),
    ).unwrap().unwrap();
    assert_eq!((retired.continuation, retired.payload), (123, ()));
    assert_eq!(f.lanes.external_depth(lane), Ok(1));
    assert_eq!(f.lanes.external_top(lane), Ok(Some(88)));
    f.lanes.repark_external(lane, reply, 88).unwrap();
    assert_eq!(f.lanes.phase(lane), Ok(LanePhase::Suspended));
}
