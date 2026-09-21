use super::*;
use crate::{IpcBufferSnapshot, LaneBinding, ReceivedMessage};

type Lanes = ComponentSuspensionLanes<(), (), ()>;

fn message(badge: u64, info: u64) -> ReceivedMessage {
    ReceivedMessage::new(
        badge,
        info,
        [91; 4],
        IpcBufferSnapshot::capture(|i| i as u64),
    )
}

fn setup(
    info: u64,
    wrong_badge: bool,
) -> (
    Lanes,
    PeerRegistry,
    PeerRoute,
    crate::LaneDispatchIdentity,
    IngressReceiver<ReceivedMessage>,
) {
    let mut lanes = Lanes::new(1, 2);
    let mut peers = PeerRegistry::new(20, 1);
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
    lanes
        .complete_startup(lane, 30, |_, _| {
            Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)
        })
        .unwrap();
    let mut owner = IngressReceiver::new(20, 40, 2).unwrap();
    owner.begin_receive(&lanes).unwrap();
    owner
        .capture(message(route.badge(), 123 << 12))
        .ok()
        .unwrap();
    owner.resolve(IngressReceiveDisposition::Call).ok().unwrap();
    owner
        .retain(
            &lanes,
            ComponentIngress::new(20, 41).unwrap(),
            &mut peers,
            route.badge(),
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
        )
        .ok()
        .unwrap();
    let mut pool = crate::IngressReplyPool::new(20, 1).unwrap();
    let dispatch = pool
        .admit(&mut owner, route, &mut lanes, &peers, 1, 2, |_, reply| {
            Ok::<_, u8>(if reply == 30 {
                ReplyBindingObservation::Free
            } else {
                ReplyBindingObservation::BoundToTarget
            })
        })
        .unwrap();
    owner
        .reply_stored(
            route,
            dispatch,
            &lanes,
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
            |_| crate::IngressReplyObservation::Acknowledged,
        )
        .unwrap();
    owner
        .begin_receive_for_owner(&lanes, IngressExecutionOwner::Dispatch(dispatch))
        .unwrap();
    owner
        .capture(message(if wrong_badge { 0 } else { route.badge() }, info))
        .ok()
        .unwrap();
    owner.resolve(IngressReceiveDisposition::Call).ok().unwrap();
    owner
        .retain(
            &lanes,
            ComponentIngress::new(20, 42).unwrap(),
            &mut peers,
            route.badge(),
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
        )
        .ok()
        .unwrap();
    (lanes, peers, route, dispatch, owner)
}

#[test]
fn exact_completion_proof_preserves_new_call() {
    let (mut lanes, mut peers, route, dispatch, mut owner) = setup(55 << 12, false);
    let mut queries = alloc::vec::Vec::new();
    let old = owner
        .complete_from_message(
            route,
            dispatch,
            41,
            55,
            &mut lanes,
            &mut peers,
            |tcb, reply| {
                queries.push((tcb, reply));
                Ok::<_, u8>(if reply == 41 {
                    ReplyBindingObservation::BoundToTarget
                } else {
                    ReplyBindingObservation::Free
                })
            },
        )
        .ok()
        .unwrap();
    assert_eq!(queries, [(10, 41), (10, 40)]);
    assert_eq!(old.info(), 123 << 12);
    assert_eq!(owner.available(), 1);
    assert_eq!(peers.state(route).unwrap().1, 1);
    let new = owner.checkout(route).unwrap();
    assert_eq!(new.call().reply(), 41);
    assert_eq!(new.call().message().info(), 55 << 12);
    assert!(new.call().is_held());
}

#[test]
fn malformed_completion_and_labels_refuse_before_query() {
    for (info, wrong_badge, label) in [
        (55 << 12 | 5, false, 55),
        (55 << 12 | 0x80, false, 55),
        (56 << 12, false, 55),
        (55 << 12, true, 55),
        (0, false, 0),
        (55 << 12, false, u64::MAX),
    ] {
        let (mut lanes, mut peers, route, dispatch, mut owner) = setup(info, wrong_badge);
        assert_eq!(
            owner
                .complete_from_message(
                    route,
                    dispatch,
                    41,
                    label,
                    &mut lanes,
                    &mut peers,
                    |_, _| -> Result<ReplyBindingObservation, u8> {
                        panic!("malformed completion")
                    }
                )
                .err(),
            Some(StoredCompletionError::InvalidCompletionMessage)
        );
        assert_eq!(owner.available(), 0);
        assert_eq!(
            lanes.active_dispatch_identity(dispatch.lane),
            Ok(Some(dispatch))
        );
    }
}

#[test]
fn either_binding_failure_preserves_both_calls() {
    for fail in [40, 41] {
        let (mut lanes, mut peers, route, dispatch, mut owner) = setup(55 << 12, false);
        assert_eq!(
            owner
                .complete_from_message(
                    route,
                    dispatch,
                    41,
                    55,
                    &mut lanes,
                    &mut peers,
                    |_, reply| {
                        if reply == fail {
                            Err(7u8)
                        } else {
                            Ok(ReplyBindingObservation::BoundToTarget)
                        }
                    }
                )
                .err(),
            Some(StoredCompletionError::Query(7))
        );
        assert_eq!(owner.available(), 0);
        assert_eq!(peers.state(route).unwrap().1, 2);
        assert_eq!(
            lanes.active_dispatch_identity(dispatch.lane),
            Ok(Some(dispatch))
        );
        assert!(owner.excludes_reply(40) && owner.excludes_reply(41));
    }
}

#[test]
fn unbound_completion_never_queries_old_reply_or_ends_dispatch() {
    let (mut lanes, mut peers, route, dispatch, mut owner) = setup(55 << 12, false);
    assert_eq!(
        owner
            .complete_from_message(
                route,
                dispatch,
                41,
                55,
                &mut lanes,
                &mut peers,
                |_, reply| {
                    assert_eq!(reply, 41);
                    Ok::<_, u8>(ReplyBindingObservation::Free)
                }
            )
            .err(),
        Some(StoredCompletionError::CompletionNotBound)
    );
    assert_eq!(owner.available(), 0);
    assert_eq!(
        lanes.active_dispatch_identity(dispatch.lane),
        Ok(Some(dispatch))
    );
}
