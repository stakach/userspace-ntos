use super::*;
use crate::{IngressReceiveDisposition, IngressReplyObservation, LaneBinding};

type Lanes = ComponentSuspensionLanes<(), (), ()>;

fn setup() -> (
    Lanes,
    PeerRegistry,
    crate::peer_registry::PeerRoute,
    IngressReceiver<u64>,
    IngressReplyPool<u64>,
) {
    let mut lanes = Lanes::new(2, 2);
    let lane = lanes
        .allocate(LaneBinding {
            executor_id: 10,
            receive_endpoint: 20,
            reply_object: 30,
        })
        .unwrap();
    let mut peers = PeerRegistry::new(20, 1);
    let mut registration = peers.stage_lane(1, 2, &lanes, lane).unwrap();
    let route = peers.publish_lane(&mut registration, 1, 2, &lanes).unwrap();
    (
        lanes,
        peers,
        route,
        IngressReceiver::new(20, 40, 2).unwrap(),
        IngressReplyPool::new(20, 1).unwrap(),
    )
}

fn free(_: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::Free)
}
fn bound(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::BoundToTarget)
}

fn call(owner: &mut IngressReceiver<u64>, lanes: &Lanes) {
    owner.begin_receive(lanes).unwrap();
    owner.capture(123).unwrap();
    owner.resolve(IngressReceiveDisposition::Call).unwrap();
}

#[test]
fn insert_rejects_wrong_endpoint_and_aliases_without_query() {
    let (lanes, _, _, owner, mut pool) = setup();
    for (endpoint, reply) in [(21, 41), (20, 40), (20, 30)] {
        let (_, returned) = pool
            .insert(
                ComponentIngress::new(endpoint, reply).unwrap(),
                &owner,
                &lanes,
                |_| -> Result<ReplyBindingObservation, u8> { panic!("invalid alias") },
            )
            .err()
            .unwrap();
        assert_eq!(returned.reply(), reply);
        assert!(pool.is_empty());
    }
    pool.insert(ComponentIngress::new(20, 41).unwrap(), &owner, &lanes, free)
        .ok()
        .unwrap();
    assert!(pool.excludes_reply(41));
    assert!(pool
        .insert(ComponentIngress::new(20, 42).unwrap(), &owner, &lanes, free)
        .is_err());
    assert_eq!(pool.len(), 1);
}

#[test]
fn held_and_uncertain_replies_are_never_pooled() {
    let (lanes, _, _, owner, mut pool) = setup();
    let mut held = ComponentIngress::new(20, 41).unwrap();
    let mut receive = lanes.begin_ingress_receive(&mut held).unwrap();
    held.observe_receive(&mut receive, crate::IngressObservation::Call(123))
        .unwrap();
    let (_, held) = pool.insert(held, &owner, &lanes, free).err().unwrap();
    assert_eq!(held.message(), Some(&123));
    for observation in [
        ReplyBindingObservation::Offered,
        ReplyBindingObservation::BoundToTarget,
        ReplyBindingObservation::BoundElsewhere,
    ] {
        let (_, returned) = pool
            .insert(
                ComponentIngress::new(20, 42).unwrap(),
                &owner,
                &lanes,
                |_| Ok::<_, u8>(observation),
            )
            .err()
            .unwrap();
        assert_eq!(returned.reply(), 42);
        assert!(pool.is_empty());
    }
}

#[test]
fn failed_handoff_restores_replacement_and_success_transfers_once() {
    let (lanes, mut peers, route, mut owner, mut pool) = setup();
    pool.insert(ComponentIngress::new(20, 41).unwrap(), &owner, &lanes, free)
        .ok()
        .unwrap();
    call(&mut owner, &lanes);
    assert!(pool
        .retain(
            &mut owner,
            &lanes,
            &mut peers,
            route.badge(),
            free,
            |_, _| Err(7u8)
        )
        .is_err());
    assert_eq!(pool.len(), 1);
    assert!(pool.excludes_reply(41));
    assert_eq!(owner.reply(), 40);
    assert_eq!(owner.message(), Some(&123));
    assert_eq!(peers.state(route).unwrap().1, 0);
    pool.retain(&mut owner, &lanes, &mut peers, route.badge(), free, bound)
        .unwrap();
    assert!(pool.is_empty());
    assert_eq!(owner.reply(), 41);
    assert_eq!(*owner.checkout(route).unwrap().call().message(), 123);
    assert!(pool
        .retain(&mut owner, &lanes, &mut peers, route.badge(), free, bound)
        .is_err());
}

#[test]
fn checkout_revalidates_free_state_and_new_canonical_alias() {
    let (mut lanes, mut peers, route, mut owner, mut pool) = setup();
    pool.insert(ComponentIngress::new(20, 41).unwrap(), &owner, &lanes, free)
        .ok()
        .unwrap();
    call(&mut owner, &lanes);
    assert!(pool
        .retain(
            &mut owner,
            &lanes,
            &mut peers,
            route.badge(),
            |_| Err(8u8),
            bound
        )
        .is_err());
    assert_eq!(pool.len(), 1);
    lanes
        .allocate(LaneBinding {
            executor_id: 11,
            receive_endpoint: 21,
            reply_object: 41,
        })
        .unwrap();
    assert!(pool
        .retain(
            &mut owner,
            &lanes,
            &mut peers,
            route.badge(),
            |_| -> Result<ReplyBindingObservation, u8> { panic!("canonical alias") },
            bound
        )
        .is_err());
    assert_eq!(pool.len(), 1);
    assert_eq!(owner.message(), Some(&123));
}

#[test]
fn acknowledged_reply_is_not_recycled_while_still_canonical() {
    let (mut lanes, mut peers, route, mut owner, mut pool) = setup();
    pool.insert(ComponentIngress::new(20, 41).unwrap(), &owner, &lanes, free)
        .ok()
        .unwrap();
    call(&mut owner, &lanes);
    pool.retain(&mut owner, &lanes, &mut peers, route.badge(), free, bound)
        .unwrap();
    let mut checkout = owner.checkout(route).unwrap();
    let displaced = checkout
        .begin_dispatch(&mut lanes, &peers, 1, 2, |_, reply| {
            Ok::<_, u8>(if reply == 30 {
                ReplyBindingObservation::Free
            } else {
                ReplyBindingObservation::BoundToTarget
            })
        })
        .unwrap();
    assert_eq!(displaced.displaced_reply, 30);
    let mut reply = checkout.begin_reply().unwrap();
    checkout
        .observe_reply(&mut reply, IngressReplyObservation::Acknowledged)
        .unwrap();
    checkout.finish_dispatch(&mut lanes).unwrap();
    let (acknowledged, _) = owner.finish_checkout(checkout, &mut peers).ok().unwrap();
    let (_, returned) = pool
        .insert(
            acknowledged,
            &owner,
            &lanes,
            |_| -> Result<ReplyBindingObservation, u8> { panic!("canonical acknowledged Reply") },
        )
        .err()
        .unwrap();
    assert_eq!(returned.reply(), 40);
    assert!(pool.is_empty());
}
