use super::*;
use crate::{IngressReceiveDisposition, IpcBufferSnapshot, ReceivedMessage};

type Lanes = ComponentSuspensionLanes<u64, u32, u64>;

fn bound(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::BoundToTarget)
}

fn message(route: peer_registry::PeerRoute, label: u64) -> ReceivedMessage {
    ReceivedMessage::new(
        route.badge(),
        label << 12,
        [0; 4],
        IpcBufferSnapshot::capture(|_| 0),
    )
}

fn setup(
    external: bool,
) -> (
    Lanes,
    peer_registry::PeerRegistry,
    peer_registry::PeerRoute,
    LaneDispatchIdentity,
    TerminalIdentity,
    IngressReceiver<ReceivedMessage>,
) {
    let mut lanes = Lanes::new(2, 4);
    let mut peers = peer_registry::PeerRegistry::new(20, 2);
    let (lane, mut registration) = lanes
        .allocate_shared_staged(
            &mut peers,
            1,
            2,
            LaneBinding {
                executor_id: 10,
                receive_endpoint: 20,
                reply_object: 30,
            },
        )
        .unwrap();
    let route = peers.publish_lane(&mut registration, 1, 2, &lanes).unwrap();
    lanes
        .begin_startup(lane, 30, |_, _| Ok::<_, u8>(ReplyBindingObservation::Free))
        .unwrap();
    lanes.complete_startup(lane, 30, bound).unwrap();
    let mut receiver = IngressReceiver::new(20, 40, 2).unwrap();
    receiver.begin_receive(&lanes).unwrap();
    receiver.capture(message(route, 55)).ok().unwrap();
    receiver
        .resolve(IngressReceiveDisposition::Call)
        .ok()
        .unwrap();
    receiver
        .retain(
            &lanes,
            ComponentIngress::new(20, 41).unwrap(),
            &mut peers,
            route.badge(),
            bound,
        )
        .ok()
        .unwrap();
    let mut pool = IngressReplyPool::new(20, 1).unwrap();
    let dispatch = pool
        .admit(
            &mut receiver,
            route,
            &mut lanes,
            &peers,
            1,
            2,
            |_, reply| {
                Ok::<_, u8>(if reply == 30 {
                    ReplyBindingObservation::Free
                } else {
                    ReplyBindingObservation::BoundToTarget
                })
            },
        )
        .unwrap();
    receiver
        .reply_stored(route, dispatch, &lanes, bound, |_| {
            IngressReplyObservation::Acknowledged
        })
        .unwrap();
    receiver
        .begin_receive_for_owner(&lanes, IngressExecutionOwner::Dispatch(dispatch))
        .unwrap();
    receiver.capture(message(route, 55)).ok().unwrap();
    receiver
        .resolve(IngressReceiveDisposition::Call)
        .ok()
        .unwrap();
    receiver
        .retain(
            &lanes,
            ComponentIngress::new(20, 42).unwrap(),
            &mut peers,
            route.badge(),
            bound,
        )
        .ok()
        .unwrap();
    let key = SuspensionKey::provider_wait(9);
    let owner = SuspensionOwner {
        provider_domain: 1,
        provider_generation: 2,
        caller: SuspensionCaller::Kernel { lane },
        dispatch_id: dispatch.epoch(),
    };
    lanes.admit_running(lane, 40, key, 1, owner, 123).unwrap();
    lanes.select(key, 456).unwrap();
    lanes.begin_resume(lane, 40, key).unwrap();
    let terminal = if external {
        lanes
            .retain_external_terminal_running(lane, 40, key, owner, 77, 789)
            .unwrap()
    } else {
        lanes
            .retain_terminal_running(lane, 40, key, owner, 789)
            .unwrap()
    };
    (lanes, peers, route, dispatch, terminal, receiver)
}

fn ack_all(lanes: &mut Lanes, terminal: TerminalIdentity) {
    for stage in [
        TerminalStage::Output,
        TerminalStage::Context,
        TerminalStage::Publication,
        TerminalStage::Reply,
    ] {
        let mut attempt = lanes.begin_terminal_stage(terminal, 40, stage).unwrap();
        lanes
            .record_terminal_stage(&mut attempt, 40, TerminalStageOutcome::Acknowledged)
            .unwrap();
    }
}

#[test]
fn semantic_retirement_preserves_epoch_until_authenticated_receiver_completion() {
    let (mut lanes, mut peers, route, dispatch, terminal, mut receiver) = setup(false);
    ack_all(&mut lanes, terminal);
    let retired = lanes
        .finish_shared_terminal(route, dispatch, terminal, 40, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(retired.payload, 789);
    assert_eq!(retired.suspension.continuation, 123);
    assert_eq!(retired.suspension.completion, 456);
    assert_eq!(lanes.phase(dispatch.lane()), Ok(LanePhase::Running));
    assert_eq!(lanes.running(), Some(dispatch.lane()));
    assert_eq!(
        lanes.active_dispatch_identity(dispatch.lane()),
        Ok(Some(dispatch))
    );
    assert_eq!(lanes.suspension_count(dispatch.lane()), Ok(0));
    assert_eq!(peers.state(route).unwrap().1, 2);
    assert!(lanes
        .finish_shared_terminal(route, dispatch, terminal, 40, Ok(()))
        .is_err());
    assert!(receiver
        .complete_from_message(
            route,
            dispatch,
            41,
            56,
            &mut lanes,
            &mut peers,
            |_, _| -> Result<_, u8> { panic!("wrong completion label") }
        )
        .is_err());
    assert_eq!(
        lanes.active_dispatch_identity(dispatch.lane()),
        Ok(Some(dispatch))
    );
    receiver
        .complete_from_message(
            route,
            dispatch,
            41,
            55,
            &mut lanes,
            &mut peers,
            |tcb, reply| {
                assert_eq!(tcb, 10);
                Ok::<_, u8>(if reply == 40 {
                    ReplyBindingObservation::Free
                } else {
                    ReplyBindingObservation::BoundToTarget
                })
            },
        )
        .unwrap();
    assert_eq!(lanes.phase(dispatch.lane()), Ok(LanePhase::Idle));
    assert_eq!(lanes.running(), None);
    assert_eq!(lanes.active_dispatch_identity(dispatch.lane()), Ok(None));
    assert_eq!(peers.state(route).unwrap().1, 1);
}

#[test]
fn stale_route_dispatch_and_reply_do_not_retire_terminal() {
    let (mut lanes, _, route, dispatch, terminal, _) = setup(false);
    let (_, _, foreign_route, foreign_dispatch, _, _) = setup(false);
    ack_all(&mut lanes, terminal);
    for (route, dispatch, reply) in [
        (foreign_route, dispatch, 40),
        (route, foreign_dispatch, 40),
        (route, dispatch, 41),
    ] {
        assert!(lanes
            .finish_shared_terminal(route, dispatch, terminal, reply, Ok(()))
            .is_err());
        assert_eq!(lanes.phase(terminal.lane()), Ok(LanePhase::Terminal));
        assert_eq!(lanes.running(), None);
        assert!(matches!(
            lanes.terminal(terminal, 40).unwrap().phase,
            TerminalPhase::Acknowledged { .. }
        ));
    }
}

#[test]
fn unacknowledged_entered_and_indeterminate_stages_cannot_retire() {
    let (mut lanes, _, route, dispatch, terminal, _) = setup(false);
    assert!(lanes
        .finish_shared_terminal(route, dispatch, terminal, 40, Ok(()))
        .is_err());
    let mut attempt = lanes
        .begin_terminal_stage(terminal, 40, TerminalStage::Output)
        .unwrap();
    assert!(lanes
        .finish_shared_terminal(route, dispatch, terminal, 40, Ok(()))
        .is_err());
    lanes
        .record_terminal_stage(&mut attempt, 40, TerminalStageOutcome::Indeterminate(9))
        .unwrap();
    assert!(lanes
        .finish_shared_terminal(route, dispatch, terminal, 40, Ok(()))
        .is_err());
    assert!(lanes
        .begin_terminal_stage(terminal, 40, TerminalStage::Output)
        .is_err());
    assert_eq!(lanes.phase(dispatch.lane()), Ok(LanePhase::Terminal));
    assert_eq!(lanes.suspension_count(dispatch.lane()), Ok(1));
    assert_eq!(
        lanes.active_dispatch_identity(dispatch.lane()),
        Ok(Some(dispatch))
    );
}

#[test]
fn local_failure_retains_ack_and_allows_only_local_retry() {
    let (mut lanes, _, route, dispatch, terminal, _) = setup(false);
    ack_all(&mut lanes, terminal);
    assert!(lanes
        .finish_shared_terminal(route, dispatch, terminal, 40, Err(5))
        .unwrap()
        .is_none());
    assert_eq!(
        lanes.terminal(terminal, 40).unwrap().phase,
        TerminalPhase::Acknowledged {
            local_error: Some(5)
        }
    );
    assert_eq!(lanes.running(), None);
    assert_eq!(lanes.suspension_count(dispatch.lane()), Ok(1));
    assert!(lanes
        .finish_shared_terminal(route, dispatch, terminal, 40, Ok(()))
        .unwrap()
        .is_some());
    assert_eq!(lanes.running(), Some(dispatch.lane()));
}

#[test]
fn unrelated_running_lane_prevents_execution_fence_theft() {
    let (mut lanes, _, route, dispatch, terminal, _) = setup(false);
    ack_all(&mut lanes, terminal);
    let other = lanes
        .allocate(LaneBinding {
            executor_id: 70,
            receive_endpoint: 80,
            reply_object: 90,
        })
        .unwrap();
    lanes.begin_dispatch(other, 90).unwrap();
    assert!(matches!(
        lanes.finish_shared_terminal(route, dispatch, terminal, 40, Ok(())),
        Err(LaneError::Busy)
    ));
    assert_eq!(lanes.running(), Some(other));
    assert_eq!(lanes.phase(dispatch.lane()), Ok(LanePhase::Terminal));
    lanes.finish_dispatch(other, 90).unwrap();
    assert!(lanes
        .finish_shared_terminal(route, dispatch, terminal, 40, Ok(()))
        .unwrap()
        .is_some());
}

#[test]
fn external_transfer_token_uses_existing_running_retirement() {
    let (mut lanes, mut peers, route, dispatch, terminal, mut receiver) = setup(true);
    ack_all(&mut lanes, terminal);
    lanes
        .finish_shared_terminal(route, dispatch, terminal, 40, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(lanes.external_top(dispatch.lane()), Ok(Some(77)));
    assert_eq!(lanes.running(), Some(dispatch.lane()));
    assert!(receiver
        .complete_from_message(
            route,
            dispatch,
            41,
            55,
            &mut lanes,
            &mut peers,
            |_, reply| Ok::<_, u8>(if reply == 40 {
                ReplyBindingObservation::Free
            } else {
                ReplyBindingObservation::BoundToTarget
            })
        )
        .is_err());
    lanes
        .retire_external_running(dispatch.lane(), 40, 77)
        .unwrap();
    receiver
        .complete_from_message(
            route,
            dispatch,
            41,
            55,
            &mut lanes,
            &mut peers,
            |_, reply| {
                Ok::<_, u8>(if reply == 40 {
                    ReplyBindingObservation::Free
                } else {
                    ReplyBindingObservation::BoundToTarget
                })
            },
        )
        .unwrap();
    assert_eq!(lanes.phase(dispatch.lane()), Ok(LanePhase::Idle));
}

#[test]
fn existing_finish_terminal_keeps_original_idle_behavior() {
    let (mut lanes, _, _, dispatch, terminal, _) = setup(false);
    ack_all(&mut lanes, terminal);
    lanes
        .finish_terminal(terminal, 40, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(lanes.phase(dispatch.lane()), Ok(LanePhase::Idle));
    assert_eq!(lanes.active_dispatch_identity(dispatch.lane()), Ok(None));
    assert_eq!(lanes.running(), None);
}
