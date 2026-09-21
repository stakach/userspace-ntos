use super::*;
use crate::{IngressReplyObservation, LaneBinding, LaneDispatchIdentity, LanePhase};

type Lanes = ComponentSuspensionLanes<(), (), ()>;
fn bound(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::BoundToTarget)
}
fn no_query(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    panic!("invalid parked owner")
}
fn no_invoke(_: u64) -> IngressReplyObservation {
    panic!("Reply must not execute")
}

fn fixture() -> (
    Lanes,
    PeerRegistry,
    PeerRoute,
    LaneDispatchIdentity,
    crate::LaneHandle,
    IngressReceiver<u64>,
    Option<ComponentIngress<u64>>,
) {
    let mut lanes = Lanes::new(2, 2);
    let mut peers = PeerRegistry::new(20, 2);
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
        .begin_bootstrap_dispatch(route, &peers, |_, _| {
            Ok::<_, u8>(ReplyBindingObservation::Free)
        })
        .unwrap();
    let mut receiver = IngressReceiver::new(20, 40, 2).unwrap();
    receiver
        .begin_receive_for_owner(&lanes, IngressExecutionOwner::Dispatch(dispatch))
        .unwrap();
    receiver.capture(123).ok().unwrap();
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
    let mut pending = None;
    receiver
        .adopt_bootstrap_call(
            route,
            dispatch,
            40,
            &mut lanes,
            &peers,
            &mut pending,
            |_, reply| {
                Ok::<_, u8>(if reply == 30 {
                    ReplyBindingObservation::Free
                } else {
                    ReplyBindingObservation::BoundToTarget
                })
            },
        )
        .unwrap();
    lanes.suspend_running(dispatch.lane(), 40, 77).unwrap();
    let other = lanes
        .allocate(LaneBinding {
            executor_id: 50,
            receive_endpoint: 60,
            reply_object: 70,
        })
        .unwrap();
    lanes.begin_dispatch(other, 70).unwrap();
    (lanes, peers, route, dispatch, other, receiver, pending)
}

#[test]
fn parked_reply_ack_preserves_other_running_lane_and_wait_epoch() {
    let (mut lanes, peers, route, dispatch, other, mut receiver, _pending) = fixture();
    assert_eq!(
        receiver.reply_parked_stored(route, dispatch, 77, &lanes, &peers, bound, |reply| {
            assert_eq!(reply, 40);
            IngressReplyObservation::Acknowledged
        }),
        Ok(IngressReplyObservation::Acknowledged)
    );
    assert_eq!(lanes.running(), Some(other));
    assert_eq!(lanes.phase(dispatch.lane()), Ok(LanePhase::Suspended));
    assert_eq!(
        lanes.active_dispatch_identity(dispatch.lane()),
        Ok(Some(dispatch))
    );
    assert_eq!(lanes.external_top(dispatch.lane()), Ok(Some(77)));
    assert!(receiver
        .store
        .stored_dispatch_mut(route, dispatch)
        .unwrap()
        .is_acknowledged());
    assert!(lanes.resume_external(dispatch.lane(), 40, 77).is_err());
    lanes.finish_dispatch(other, 70).unwrap();
    lanes.resume_external(dispatch.lane(), 40, 77).unwrap();
    assert_eq!(lanes.running(), Some(dispatch.lane()));
}

#[test]
fn wrong_token_dispatch_registry_and_route_refuse_before_native_effects() {
    let (mut lanes, mut peers, route, dispatch, other, mut receiver, _pending) = fixture();
    for token in [0, 78] {
        assert!(receiver
            .reply_parked_stored(route, dispatch, token, &lanes, &peers, no_query, no_invoke)
            .is_err());
    }
    let stale = LaneDispatchIdentity {
        lane: dispatch.lane(),
        epoch: dispatch.epoch() + 1,
    };
    assert!(receiver
        .reply_parked_stored(route, stale, 77, &lanes, &peers, no_query, no_invoke)
        .is_err());
    let foreign = PeerRegistry::new(20, 2);
    assert!(receiver
        .reply_parked_stored(route, dispatch, 77, &lanes, &foreign, no_query, no_invoke)
        .is_err());
    peers.begin_retirement(route).unwrap();
    assert!(receiver
        .reply_parked_stored(route, dispatch, 77, &lanes, &peers, no_query, no_invoke)
        .is_err());
    assert_eq!(lanes.running(), Some(other));
    lanes.finish_dispatch(other, 70).unwrap();
}

#[test]
fn uncertain_reply_is_retained_and_never_replayed() {
    let (lanes, peers, route, dispatch, other, mut receiver, _pending) = fixture();
    assert_eq!(
        receiver.reply_parked_stored(route, dispatch, 77, &lanes, &peers, bound, |_| {
            IngressReplyObservation::Indeterminate
        }),
        Ok(IngressReplyObservation::Indeterminate)
    );
    assert!(receiver
        .reply_parked_stored(route, dispatch, 77, &lanes, &peers, bound, no_invoke)
        .is_err());
    assert_eq!(lanes.running(), Some(other));
    assert_eq!(lanes.external_top(dispatch.lane()), Ok(Some(77)));
    assert_eq!(peers.state(route).unwrap().1, 1);
}

#[test]
fn query_failure_and_nonbound_do_not_acknowledge_or_invoke() {
    let (lanes, peers, route, dispatch, other, mut receiver, _pending) = fixture();
    assert!(receiver
        .reply_parked_stored(
            route,
            dispatch,
            77,
            &lanes,
            &peers,
            |_, _| Err(9u8),
            no_invoke
        )
        .is_err());
    assert!(receiver
        .reply_parked_stored(
            route,
            dispatch,
            77,
            &lanes,
            &peers,
            |_, _| Ok::<_, u8>(ReplyBindingObservation::Free),
            no_invoke
        )
        .is_err());
    assert!(!receiver
        .store
        .stored_dispatch_mut(route, dispatch)
        .unwrap()
        .is_acknowledged());
    assert_eq!(lanes.running(), Some(other));
    assert_eq!(
        receiver.reply_parked_stored(route, dispatch, 77, &lanes, &peers, bound, |_| {
            IngressReplyObservation::Acknowledged
        }),
        Ok(IngressReplyObservation::Acknowledged)
    );
}
