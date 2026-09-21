use super::*;
use crate::{IpcBufferSnapshot, LaneBinding};

type Lanes = ComponentSuspensionLanes<(), (), ()>;

fn proof(_: u64, reply: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(if reply == 30 {
        ReplyBindingObservation::Free
    } else {
        ReplyBindingObservation::BoundToTarget
    })
}
fn no_query(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    panic!("preflight refusal")
}

fn fixture(
    info: u64,
    wrong_badge: bool,
) -> (
    Lanes,
    PeerRegistry,
    PeerRoute,
    LaneDispatchIdentity,
    IngressReceiver<ReceivedMessage>,
) {
    let mut lanes = Lanes::new(1, 2);
    let mut peers = PeerRegistry::new(20, 1);
    let (_, mut registration) = lanes
        .allocate_shared_staged(
            &mut peers,
            1,
            1,
            LaneBinding {
                executor_id: 10,
                receive_endpoint: 20,
                reply_object: 30,
            },
        )
        .unwrap();
    let route = peers.publish_lane(&mut registration, 1, 1, &lanes).unwrap();
    let dispatch = lanes
        .begin_bootstrap_dispatch(route, &peers, proof)
        .unwrap();
    let mut receiver = IngressReceiver::new(20, 40, 1).unwrap();
    receiver
        .begin_receive_for_owner(&lanes, IngressExecutionOwner::Dispatch(dispatch))
        .unwrap();
    receiver
        .capture(ReceivedMessage::new(
            if wrong_badge { 0 } else { route.badge() },
            info,
            [0; 4],
            IpcBufferSnapshot::capture(|_| 0),
        ))
        .ok()
        .unwrap();
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
            proof,
        )
        .ok()
        .unwrap();
    (lanes, peers, route, dispatch, receiver)
}

#[test]
fn first_completion_ends_bootstrap_without_reply_or_synthetic_ack() {
    let (mut lanes, peers, route, dispatch, mut receiver) = fixture(7 << 12, false);
    receiver
        .complete_bootstrap_from_message(route, dispatch, 40, 7, &mut lanes, &peers, proof)
        .unwrap();
    assert_eq!(lanes.phase(dispatch.lane()), Ok(LanePhase::Idle));
    assert_eq!(lanes.active_dispatch_identity(dispatch.lane()), Ok(None));
    assert_eq!(lanes.running(), None);
    assert_eq!(lanes.binding(dispatch.lane()).unwrap().reply_object, 30);
    assert!(receiver.store.stored_reply(route, 40).unwrap().is_held());
    assert_eq!(peers.state(route).unwrap().1, 1);
    assert!(receiver
        .complete_bootstrap_from_message(route, dispatch, 40, 7, &mut lanes, &peers, no_query)
        .is_err());
}

#[test]
fn bad_protocol_refuses_before_queries_and_preserves_marker() {
    for (info, wrong_badge, label) in [
        (7 << 12 | 1, false, 7),
        (8 << 12, false, 7),
        (7 << 12, true, 7),
        (0, false, 0),
        (7 << 12, false, u64::MAX),
    ] {
        let (mut lanes, peers, route, dispatch, mut receiver) = fixture(info, wrong_badge);
        assert_eq!(
            receiver.complete_bootstrap_from_message(
                route, dispatch, 40, label, &mut lanes, &peers, no_query
            ),
            Err(StoredCompletionError::InvalidCompletionMessage)
        );
        assert_eq!(lanes.running(), Some(dispatch.lane()));
        assert_eq!(
            lanes.lane(dispatch.lane()).unwrap().bootstrap_dispatch,
            Some((dispatch, 30))
        );
    }
}

#[test]
fn every_query_refusal_preserves_epoch_and_held_completion() {
    for failed_reply in [30, 40] {
        for error in [false, true] {
            let (mut lanes, peers, route, dispatch, mut receiver) = fixture(7 << 12, false);
            let result = receiver.complete_bootstrap_from_message(
                route,
                dispatch,
                40,
                7,
                &mut lanes,
                &peers,
                |tcb, reply| {
                    if reply == failed_reply {
                        if error {
                            Err(3)
                        } else {
                            Ok(ReplyBindingObservation::BoundElsewhere)
                        }
                    } else {
                        proof(tcb, reply)
                    }
                },
            );
            assert!(result.is_err());
            assert_eq!(lanes.running(), Some(dispatch.lane()));
            assert!(receiver.store.stored_reply(route, 40).unwrap().is_held());
            receiver
                .complete_bootstrap_from_message(route, dispatch, 40, 7, &mut lanes, &peers, proof)
                .unwrap();
        }
    }
}

#[test]
fn missing_bootstrap_marker_or_semantic_owner_cannot_finish() {
    let (mut lanes, peers, route, dispatch, mut receiver) = fixture(7 << 12, false);
    lanes.lane_mut(dispatch.lane()).unwrap().bootstrap_dispatch = None;
    assert_eq!(
        receiver
            .complete_bootstrap_from_message(route, dispatch, 40, 7, &mut lanes, &peers, no_query),
        Err(StoredCompletionError::WrongOwner)
    );
    lanes.lane_mut(dispatch.lane()).unwrap().bootstrap_dispatch = Some((dispatch, 30));
    lanes.suspend_running(dispatch.lane(), 30, 9).unwrap();
    lanes.resume_external(dispatch.lane(), 30, 9).unwrap();
    assert_eq!(
        receiver
            .complete_bootstrap_from_message(route, dispatch, 40, 7, &mut lanes, &peers, no_query),
        Err(StoredCompletionError::WrongOwner)
    );
    lanes
        .retire_external_running(dispatch.lane(), 30, 9)
        .unwrap();
    receiver
        .complete_bootstrap_from_message(route, dispatch, 40, 7, &mut lanes, &peers, proof)
        .unwrap();
}

#[test]
fn adoption_consumes_bootstrap_authority() {
    let (mut lanes, peers, route, dispatch, mut receiver) = fixture(7 << 12, false);
    let mut displaced = None;
    receiver
        .adopt_bootstrap_call(
            route,
            dispatch,
            40,
            &mut lanes,
            &peers,
            &mut displaced,
            proof,
        )
        .unwrap();
    assert_eq!(
        lanes.lane(dispatch.lane()).unwrap().bootstrap_dispatch,
        None
    );
    assert_eq!(
        receiver
            .complete_bootstrap_from_message(route, dispatch, 40, 7, &mut lanes, &peers, no_query),
        Err(StoredCompletionError::WrongOwner)
    );
}
