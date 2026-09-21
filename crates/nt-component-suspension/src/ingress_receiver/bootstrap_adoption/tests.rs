use super::*;
use crate::{LaneBinding, LanePhase};

type Lanes = ComponentSuspensionLanes<u64, u32, ()>;

fn bound(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::BoundToTarget)
}

fn proof(tcb: u64, reply: u64) -> Result<ReplyBindingObservation, u8> {
    assert_eq!(tcb, 10);
    Ok(match reply {
        30 => ReplyBindingObservation::Free,
        40 => ReplyBindingObservation::BoundToTarget,
        _ => panic!("unexpected Reply"),
    })
}

fn no_query(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    panic!("refused bootstrap must not query")
}

fn setup() -> (
    Lanes,
    PeerRegistry,
    PeerRoute,
    crate::LaneDispatchIdentity,
    IngressReceiver<u64>,
) {
    let mut lanes = Lanes::new(2, 4);
    let mut peers = PeerRegistry::new(20, 2);
    let (_lane, mut registration) = lanes
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
    let dispatch = lanes
        .begin_bootstrap_dispatch(route, &peers, |_, _| {
            Ok::<_, u8>(ReplyBindingObservation::Free)
        })
        .unwrap();
    let mut receiver = IngressReceiver::new(20, 40, 1).unwrap();
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
    (lanes, peers, route, dispatch, receiver)
}

fn unchanged(
    lanes: &Lanes,
    peers: &PeerRegistry,
    route: PeerRoute,
    dispatch: crate::LaneDispatchIdentity,
    receiver: &IngressReceiver<u64>,
) {
    assert_eq!(lanes.phase(dispatch.lane()), Ok(LanePhase::Running));
    assert_eq!(lanes.running(), Some(dispatch.lane()));
    assert_eq!(
        lanes.active_dispatch_identity(dispatch.lane()),
        Ok(Some(dispatch))
    );
    assert_eq!(lanes.binding(dispatch.lane()).unwrap().reply_object, 30);
    assert_eq!(
        receiver.store.stored_reply(route, 40).unwrap().admitted,
        None
    );
    assert_eq!(
        *receiver.store.stored_reply(route, 40).unwrap().message(),
        123
    );
    assert_eq!(receiver.available(), 0);
    assert_eq!(peers.state(route).unwrap().1, 1);
}

#[test]
fn first_call_adopts_existing_epoch_even_when_retained_store_is_full() {
    let (mut lanes, peers, route, dispatch, mut receiver) = setup();
    let mut pending = None;
    let mut queries = alloc::vec::Vec::new();
    assert_eq!(
        receiver.adopt_bootstrap_call(
            route,
            dispatch,
            40,
            &mut lanes,
            &peers,
            &mut pending,
            |tcb, reply| {
                queries.push((tcb, reply));
                proof(tcb, reply)
            }
        ),
        Ok(())
    );
    assert_eq!(queries, [(10, 30), (10, 40)]);
    assert_eq!(
        lanes.active_dispatch_identity(dispatch.lane()),
        Ok(Some(dispatch))
    );
    assert_eq!(lanes.running(), Some(dispatch.lane()));
    assert_eq!(lanes.binding(dispatch.lane()).unwrap().reply_object, 40);
    assert_eq!(
        receiver.store.stored_reply(route, 40).unwrap().admitted,
        Some(dispatch)
    );
    assert_eq!(pending.as_ref().unwrap().reply(), 30);
    assert_eq!(receiver.available(), 0);
    assert_eq!(peers.state(route).unwrap().1, 1);
    let mut pool = crate::IngressReplyPool::new(20, 1).unwrap();
    pool.insert_pending(&mut pending, &receiver, &lanes, |_| {
        Ok::<_, u8>(ReplyBindingObservation::Free)
    })
    .unwrap();
    assert!(pending.is_none());
    assert_eq!(
        receiver.adopt_bootstrap_call(
            route,
            dispatch,
            40,
            &mut lanes,
            &peers,
            &mut pending,
            no_query
        ),
        Err(BootstrapAdoptionError::AlreadyAdmitted)
    );
    receiver
        .reply_stored(route, dispatch, &lanes, bound, |_| {
            crate::IngressReplyObservation::Acknowledged
        })
        .unwrap();
}

#[test]
fn failed_queries_leave_canonical_and_retained_ownership_unchanged() {
    for (failed, result, expected) in [
        (30, Err(7), BootstrapAdoptionError::Query(7)),
        (40, Err(8), BootstrapAdoptionError::Query(8)),
        (
            30,
            Ok(ReplyBindingObservation::BoundToTarget),
            BootstrapAdoptionError::OldReplyNotFree,
        ),
        (
            40,
            Ok(ReplyBindingObservation::Free),
            BootstrapAdoptionError::IncomingNotBound,
        ),
    ] {
        let (mut lanes, peers, route, dispatch, mut receiver) = setup();
        let mut pending = None;
        assert_eq!(
            receiver.adopt_bootstrap_call(
                route,
                dispatch,
                40,
                &mut lanes,
                &peers,
                &mut pending,
                |tcb, reply| if reply == failed {
                    result
                } else {
                    proof(tcb, reply)
                }
            ),
            Err(expected)
        );
        assert!(pending.is_none());
        unchanged(&lanes, &peers, route, dispatch, &receiver);
    }
}

#[test]
fn occupied_pending_slot_refuses_without_losing_either_owner() {
    let (mut lanes, peers, route, dispatch, mut receiver) = setup();
    let mut pending = Some(ComponentIngress::new(20, 90).unwrap());
    assert_eq!(
        receiver.adopt_bootstrap_call(
            route,
            dispatch,
            40,
            &mut lanes,
            &peers,
            &mut pending,
            no_query
        ),
        Err(BootstrapAdoptionError::PendingReply)
    );
    assert_eq!(pending.as_ref().unwrap().reply(), 90);
    unchanged(&lanes, &peers, route, dispatch, &receiver);
}

#[test]
fn foreign_route_epoch_registry_and_nonrunning_owner_are_refused() {
    let (mut lanes, peers, route, dispatch, mut receiver) = setup();
    let (_, foreign, foreign_route, foreign_dispatch, _) = setup();
    let mut pending = None;
    assert_eq!(
        receiver.adopt_bootstrap_call(
            foreign_route,
            dispatch,
            40,
            &mut lanes,
            &peers,
            &mut pending,
            no_query
        ),
        Err(BootstrapAdoptionError::WrongOwner)
    );
    assert_eq!(
        receiver.adopt_bootstrap_call(
            route,
            foreign_dispatch,
            40,
            &mut lanes,
            &peers,
            &mut pending,
            no_query
        ),
        Err(BootstrapAdoptionError::WrongOwner)
    );
    assert_eq!(
        receiver.adopt_bootstrap_call(
            route,
            dispatch,
            40,
            &mut lanes,
            &foreign,
            &mut pending,
            no_query
        ),
        Err(BootstrapAdoptionError::WrongOwner)
    );
    unchanged(&lanes, &peers, route, dispatch, &receiver);
    lanes.suspend_running(dispatch.lane(), 30, 77).unwrap();
    assert_eq!(
        receiver.adopt_bootstrap_call(
            route,
            dispatch,
            40,
            &mut lanes,
            &peers,
            &mut pending,
            no_query
        ),
        Err(BootstrapAdoptionError::WrongOwner)
    );
    assert!(pending.is_none());
}

#[test]
fn checked_out_or_uncertain_incoming_call_cannot_be_adopted() {
    let (mut lanes, peers, route, dispatch, mut receiver) = setup();
    let checkout = receiver.checkout(route).unwrap();
    let mut pending = None;
    assert_eq!(
        receiver.adopt_bootstrap_call(
            route,
            dispatch,
            40,
            &mut lanes,
            &peers,
            &mut pending,
            no_query
        ),
        Err(BootstrapAdoptionError::AlreadyAdmitted)
    );
    receiver.restore(checkout).ok().unwrap();
    receiver
        .store
        .stored_reply_mut(route, 40)
        .unwrap()
        .reply_owned(|_| crate::IngressReplyObservation::Indeterminate)
        .unwrap();
    assert_eq!(
        receiver.adopt_bootstrap_call(
            route,
            dispatch,
            40,
            &mut lanes,
            &peers,
            &mut pending,
            no_query
        ),
        Err(BootstrapAdoptionError::NotHeld)
    );
    unchanged(&lanes, &peers, route, dispatch, &receiver);
}

#[test]
fn first_call_handoff_preserves_resumed_semantic_owners() {
    let (mut lanes, peers, route, dispatch, mut receiver) = setup();
    let lane = dispatch.lane();
    let key = crate::SuspensionKey::provider_wait(9);
    let owner = crate::SuspensionOwner {
        provider_domain: 1,
        provider_generation: 2,
        dispatch_id: dispatch.epoch(),
        caller: crate::SuspensionCaller::Kernel { lane },
    };
    lanes.admit_running(lane, 30, key, 1, owner, 99).unwrap();
    lanes.select(key, 5).unwrap();
    lanes.begin_resume(lane, 30, key).unwrap();
    lanes.suspend_running(lane, 30, 77).unwrap();
    lanes.resume_external(lane, 30, 77).unwrap();
    let frame = lanes.frame(lane, key).unwrap().unwrap().clone();
    let mut pending = None;
    receiver
        .adopt_bootstrap_call(route, dispatch, 40, &mut lanes, &peers, &mut pending, proof)
        .unwrap();
    assert_eq!(lanes.frame(lane, key).unwrap().unwrap(), &frame);
    assert_eq!(lanes.external_top(lane), Ok(Some(77)));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));
}
