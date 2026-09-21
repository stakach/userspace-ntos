use super::*;
use crate::{IngressReplyObservation, LaneBinding};

type Lanes = ComponentSuspensionLanes<(), (), ()>;

fn setup() -> (Lanes, PeerRegistry, PeerRoute, IngressReceiver<u64>) {
    let mut lanes = Lanes::new(1, 2);
    let lane = lanes
        .allocate(LaneBinding {
            executor_id: 10,
            receive_endpoint: 20,
            reply_object: 30,
        })
        .unwrap();
    let mut peers = PeerRegistry::new(20, 1);
    let mut ticket = peers.stage_lane(1, 2, &lanes, lane).unwrap();
    let route = peers.publish_lane(&mut ticket, 1, 2, &lanes).unwrap();
    (
        lanes,
        peers,
        route,
        IngressReceiver::new(20, 40, 1).unwrap(),
    )
}

fn capture_call(owner: &mut IngressReceiver<u64>, lanes: &Lanes, payload: u64) {
    owner.begin_receive(lanes).unwrap();
    owner.capture(payload).unwrap();
    assert_eq!(
        owner.resolve(IngressReceiveDisposition::Call).unwrap(),
        None
    );
}

#[test]
fn sealed_owner_preserves_unresolved_receive_and_returns_noncall_snapshot() {
    let (lanes, _, _, mut owner) = setup();
    assert!(owner.excludes_reply(40));
    assert_eq!(owner.capture(9).err().unwrap().1, 9);
    owner.begin_receive(&lanes).unwrap();
    assert_eq!(owner.phase(), Some(ReservedReceivePhase::Receiving));
    assert_eq!(owner.available(), 0);
    owner.capture(123).unwrap();
    assert!(owner.begin_receive(&lanes).is_err());
    assert_eq!(owner.capture(456).err().unwrap().1, 456);
    assert_eq!(owner.message(), Some(&123));
    assert_eq!(
        owner.resolve(IngressReceiveDisposition::NoCall).unwrap(),
        Some(123)
    );
    assert_eq!(owner.phase(), None);
    assert_eq!(owner.available(), 1);
    assert!(owner.excludes_reply(40));
    assert!(owner.message().is_none());
    owner.begin_receive(&lanes).unwrap();
}

#[test]
fn failed_authentication_preserves_owner_until_successful_handoff() {
    let (lanes, mut peers, route, mut owner) = setup();
    capture_call(&mut owner, &lanes, 123);
    let (_, replacement) = owner
        .retain(
            &lanes,
            ComponentIngress::new(20, 41).unwrap(),
            &mut peers,
            route.badge(),
            |_, _| Err(9u8),
        )
        .err()
        .unwrap();
    assert_eq!(owner.phase(), Some(ReservedReceivePhase::Held));
    assert_eq!(owner.message(), Some(&123));
    assert_eq!(owner.available(), 0);
    assert!(owner.begin_receive(&lanes).is_err());
    assert!(owner.resolve(IngressReceiveDisposition::NoCall).is_err());
    owner
        .retain(&lanes, replacement, &mut peers, route.badge(), |_, _| {
            Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)
        })
        .ok()
        .unwrap();
    assert_eq!(owner.phase(), None);
    assert_eq!(owner.reply(), 41);
    assert!(owner.excludes_reply(40));
    assert!(owner.excludes_reply(41));
    assert_eq!(owner.message(), None);
    assert_eq!(*owner.checkout(route).unwrap().call().message(), 123);
}

#[test]
fn checked_out_work_blocks_receive_until_ack_and_registry_release() {
    let (lanes, mut peers, route, mut owner) = setup();
    capture_call(&mut owner, &lanes, 123);
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
    let checkout = owner.checkout(route).unwrap();
    assert!(owner.begin_receive(&lanes).is_err());
    assert_eq!(owner.phase(), None);
    let (_, checkout) = owner.finish_checkout(checkout, &mut peers).err().unwrap();
    owner.restore(checkout).ok().unwrap();
    let mut checkout = owner.checkout(route).unwrap();
    let mut reply = checkout.begin_reply().unwrap();
    checkout
        .observe_reply(&mut reply, IngressReplyObservation::Acknowledged)
        .unwrap();
    let (free, payload) = owner.finish_checkout(checkout, &mut peers).ok().unwrap();
    assert_eq!((free.reply(), payload), (40, 123));
    assert!(!owner.excludes_reply(40));
    assert!(owner.excludes_reply(41));
    assert_eq!(owner.available(), 1);
    owner.begin_receive(&lanes).unwrap();
}

#[test]
fn invalid_construction_and_canonical_conflict_do_not_claim_receive() {
    assert!(IngressReceiver::<u64>::new(0, 40, 1).is_err());
    assert!(IngressReceiver::<u64>::new(20, 20, 1).is_err());
    assert!(IngressReceiver::<u64>::new(20, 40, 0).is_err());
    let (lanes, _, _, _) = setup();
    let mut owner = IngressReceiver::<u64>::new(20, 30, 1).unwrap();
    assert!(owner.begin_receive(&lanes).is_err());
    assert_eq!(owner.available(), 1);
    assert_eq!(owner.phase(), None);
    assert!(owner.excludes_reply(30));
}
