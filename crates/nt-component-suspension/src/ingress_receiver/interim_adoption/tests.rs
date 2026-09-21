use super::*;
use crate::{
    IngressReplyObservation, LaneBinding, LanePhase, SuspensionCaller, SuspensionKey,
    SuspensionOwner,
};

type Lanes = ComponentSuspensionLanes<u64, u32, ()>;

fn bound(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::BoundToTarget)
}

fn proof(tcb: u64, reply: u64) -> Result<ReplyBindingObservation, u8> {
    assert_eq!(tcb, 10);
    Ok(match reply {
        40 => ReplyBindingObservation::Free,
        41 => ReplyBindingObservation::BoundToTarget,
        _ => panic!("unexpected pair"),
    })
}

fn no_query(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    panic!("preflight must reject before querying")
}

fn setup(
    ack: bool,
) -> (
    Lanes,
    PeerRegistry,
    PeerRoute,
    crate::LaneDispatchIdentity,
    IngressReceiver<u64>,
) {
    let mut lanes = Lanes::new(2, 4);
    let mut peers = PeerRegistry::new(20, 2);
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
    let mut receiver = IngressReceiver::new(20, 40, 3).unwrap();
    receiver.begin_receive(&lanes).unwrap();
    receiver.capture(100).ok().unwrap();
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
    let mut pool = crate::IngressReplyPool::new(20, 1).unwrap();
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
    if ack {
        receiver
            .reply_stored(route, dispatch, &lanes, bound, |_| {
                IngressReplyObservation::Acknowledged
            })
            .unwrap();
    }
    receiver
        .begin_receive_for_owner(&lanes, IngressExecutionOwner::Dispatch(dispatch))
        .unwrap();
    receiver.capture(200).ok().unwrap();
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
    (lanes, peers, route, dispatch, receiver)
}

fn unchanged(
    lanes: &Lanes,
    peers: &PeerRegistry,
    route: PeerRoute,
    dispatch: crate::LaneDispatchIdentity,
    receiver: &IngressReceiver<u64>,
) {
    assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Running));
    assert_eq!(lanes.running(), Some(route.identity().lane));
    assert_eq!(
        lanes.active_dispatch_identity(route.identity().lane),
        Ok(Some(dispatch))
    );
    assert_eq!(
        lanes.binding(route.identity().lane).unwrap().reply_object,
        40
    );
    assert_eq!(
        receiver.store.stored_reply(route, 40).unwrap().admitted,
        Some(dispatch)
    );
    assert_eq!(
        receiver.store.stored_reply(route, 41).unwrap().admitted,
        None
    );
    assert_eq!(peers.state(route).unwrap().1, 2);
    assert_eq!(receiver.available(), 1);
}

#[test]
fn adoption_keeps_epoch_and_publishes_displaced_reply_before_pool_query() {
    let (mut lanes, mut peers, route, dispatch, mut receiver) = setup(true);
    let mut pending = None;
    let mut queries = alloc::vec::Vec::new();
    assert_eq!(
        receiver.adopt_interim_call(
            route,
            dispatch,
            41,
            &mut lanes,
            &mut peers,
            &mut pending,
            |tcb, reply| {
                queries.push((tcb, reply));
                proof(tcb, reply)
            }
        ),
        Ok(100)
    );
    assert_eq!(queries, [(10, 40), (10, 41)]);
    assert_eq!(
        lanes.active_dispatch_identity(route.identity().lane),
        Ok(Some(dispatch))
    );
    assert_eq!(
        lanes.binding(route.identity().lane).unwrap().reply_object,
        41
    );
    assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Running));
    assert_eq!(lanes.running(), Some(route.identity().lane));
    assert_eq!(
        receiver.store.stored_reply(route, 41).unwrap().admitted,
        Some(dispatch)
    );
    assert_eq!(
        *receiver.store.stored_reply(route, 41).unwrap().message(),
        200
    );
    assert!(receiver.store.stored_reply(route, 40).is_err());
    assert_eq!(peers.state(route).unwrap().1, 1);
    assert_eq!(receiver.available(), 2);
    assert_eq!(pending.as_ref().unwrap().reply(), 40);
    let mut pool = crate::IngressReplyPool::new(20, 1).unwrap();
    assert_eq!(
        pool.insert_pending(&mut pending, &receiver, &lanes, |_| Err(7u8)),
        Err(crate::ReplyPoolError::Query(7))
    );
    assert_eq!(pending.as_ref().unwrap().reply(), 40);
    pool.insert_pending(&mut pending, &receiver, &lanes, |_| {
        Ok::<_, u8>(ReplyBindingObservation::Free)
    })
    .unwrap();
    assert!(pending.is_none());
    receiver
        .reply_stored(
            route,
            dispatch,
            &lanes,
            |tcb, reply| {
                assert_eq!((tcb, reply), (10, 41));
                bound(tcb, reply)
            },
            |_| IngressReplyObservation::Acknowledged,
        )
        .unwrap();
}

#[test]
fn each_query_refusal_preserves_both_calls_and_epoch() {
    for (failed, result, expected) in [
        (40, Err(5), InterimAdoptionError::Query(5)),
        (41, Err(6), InterimAdoptionError::Query(6)),
        (
            40,
            Ok(ReplyBindingObservation::BoundToTarget),
            InterimAdoptionError::OldReplyNotFree,
        ),
        (
            41,
            Ok(ReplyBindingObservation::Free),
            InterimAdoptionError::IncomingNotBound,
        ),
    ] {
        let (mut lanes, mut peers, route, dispatch, mut receiver) = setup(true);
        let mut pending = None;
        assert_eq!(
            receiver.adopt_interim_call(
                route,
                dispatch,
                41,
                &mut lanes,
                &mut peers,
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
fn occupied_pending_unacknowledged_old_and_aliased_incoming_refuse() {
    let (mut lanes, mut peers, route, dispatch, mut receiver) = setup(false);
    let mut pending = Some(ComponentIngress::new(20, 90).unwrap());
    assert_eq!(
        receiver.adopt_interim_call(
            route,
            dispatch,
            41,
            &mut lanes,
            &mut peers,
            &mut pending,
            no_query
        ),
        Err(InterimAdoptionError::PendingReply)
    );
    assert_eq!(pending.take().unwrap().reply(), 90);
    assert_eq!(
        receiver.adopt_interim_call(
            route,
            dispatch,
            41,
            &mut lanes,
            &mut peers,
            &mut pending,
            no_query
        ),
        Err(InterimAdoptionError::NotAcknowledged)
    );
    unchanged(&lanes, &peers, route, dispatch, &receiver);
    assert_eq!(
        receiver.adopt_interim_call(
            route,
            dispatch,
            40,
            &mut lanes,
            &mut peers,
            &mut pending,
            no_query
        ),
        Err(InterimAdoptionError::ReplyInUse)
    );
}

#[test]
fn wrong_epoch_foreign_registry_and_nonrunning_phase_refuse() {
    let (mut lanes, mut peers, route, dispatch, mut receiver) = setup(true);
    let (_, mut foreign, _, foreign_dispatch, _) = setup(true);
    let mut pending = None;
    assert_eq!(
        receiver.adopt_interim_call(
            route,
            foreign_dispatch,
            41,
            &mut lanes,
            &mut peers,
            &mut pending,
            no_query
        ),
        Err(InterimAdoptionError::WrongOwner)
    );
    assert_eq!(
        receiver.adopt_interim_call(
            route,
            dispatch,
            41,
            &mut lanes,
            &mut foreign,
            &mut pending,
            no_query
        ),
        Err(InterimAdoptionError::WrongOwner)
    );
    unchanged(&lanes, &peers, route, dispatch, &receiver);
    lanes
        .suspend_running(route.identity().lane, 40, 77)
        .unwrap();
    assert_eq!(
        receiver.adopt_interim_call(
            route,
            dispatch,
            41,
            &mut lanes,
            &mut peers,
            &mut pending,
            no_query
        ),
        Err(InterimAdoptionError::WrongOwner)
    );
    assert_eq!(lanes.external_top(route.identity().lane), Ok(Some(77)));
}

#[test]
fn resumed_external_callback_keeps_exact_token_through_handoff() {
    let (mut lanes, mut peers, route, dispatch, mut receiver) = setup(true);
    let lane = route.identity().lane;
    lanes.suspend_running(lane, 40, 77).unwrap();
    lanes.resume_external(lane, 40, 77).unwrap();
    let mut pending = None;
    assert_eq!(
        receiver.adopt_interim_call(
            route,
            dispatch,
            41,
            &mut lanes,
            &mut peers,
            &mut pending,
            proof
        ),
        Ok(100)
    );
    assert_eq!(lanes.external_top(lane), Ok(Some(77)));
    assert_eq!(lanes.external_depth(lane), Ok(1));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));
    lanes.repark_external(lane, 41, 77).unwrap();
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
}

#[test]
fn resuming_suspension_preserves_frame_continuation_and_completion() {
    let (mut lanes, mut peers, route, dispatch, mut receiver) = setup(true);
    let lane = route.identity().lane;
    let key = SuspensionKey::provider_wait(99);
    let owner = SuspensionOwner {
        provider_domain: 1,
        provider_generation: 2,
        caller: SuspensionCaller::Kernel { lane },
        dispatch_id: dispatch.epoch(),
    };
    lanes.admit_running(lane, 40, key, 9, owner, 1234).unwrap();
    lanes.select(key, 55).unwrap();
    lanes.begin_resume(lane, 40, key).unwrap();
    let before = lanes.frame(lane, key).unwrap().unwrap().clone();
    let resume_epoch = lanes.lane(lane).unwrap().resume_epoch;
    let mut pending = None;
    assert_eq!(
        receiver.adopt_interim_call(
            route,
            dispatch,
            41,
            &mut lanes,
            &mut peers,
            &mut pending,
            proof
        ),
        Ok(100)
    );
    assert_eq!(lanes.frame(lane, key).unwrap().unwrap(), &before);
    assert_eq!(lanes.lane(lane).unwrap().resume_epoch, resume_epoch);
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));
    assert_eq!(lanes.suspension_count(lane), Ok(1));
}

#[test]
fn entered_terminal_preserves_exact_reply_authority() {
    let (mut lanes, mut peers, route, dispatch, mut receiver) = setup(true);
    let lane = route.identity().lane;
    let key = SuspensionKey::provider_wait(99);
    let owner = SuspensionOwner {
        provider_domain: 1,
        provider_generation: 2,
        caller: SuspensionCaller::Kernel { lane },
        dispatch_id: dispatch.epoch(),
    };
    lanes.admit_running(lane, 40, key, 9, owner, 1234).unwrap();
    lanes.select(key, 55).unwrap();
    lanes.begin_resume(lane, 40, key).unwrap();
    let terminal = lanes
        .retain_terminal_running(lane, 40, key, owner, ())
        .unwrap();
    let mut pending = None;
    assert!(receiver
        .adopt_interim_call(
            route,
            dispatch,
            41,
            &mut lanes,
            &mut peers,
            &mut pending,
            no_query
        )
        .is_err());
    assert!(pending.is_none());
    assert_eq!(lanes.binding(lane).unwrap().reply_object, 40);
    assert_eq!(
        receiver.store.stored_reply(route, 40).unwrap().admitted,
        Some(dispatch)
    );
    assert_eq!(
        receiver.store.stored_reply(route, 41).unwrap().admitted,
        None
    );
    assert_eq!(peers.state(route).unwrap().1, 2);
    lanes
        .begin_terminal_stage(terminal, 40, crate::TerminalStage::Output)
        .unwrap();
}

#[test]
fn nonheld_incoming_is_not_adopted() {
    let (mut lanes, mut peers, route, dispatch, mut receiver) = setup(true);
    receiver
        .store
        .stored_reply_mut(route, 41)
        .unwrap()
        .reply_owned(|_| IngressReplyObservation::Indeterminate)
        .unwrap();
    let mut pending = None;
    assert_eq!(
        receiver.adopt_interim_call(
            route,
            dispatch,
            41,
            &mut lanes,
            &mut peers,
            &mut pending,
            no_query
        ),
        Err(InterimAdoptionError::NotHeld)
    );
    assert!(pending.is_none());
    unchanged(&lanes, &peers, route, dispatch, &receiver);
}
