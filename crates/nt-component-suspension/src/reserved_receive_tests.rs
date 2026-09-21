use super::*;
use crate::{IngressReplyObservation, LaneBinding};

type Lanes = ComponentSuspensionLanes<(), (), ()>;

fn setup() -> (
    Lanes,
    PeerRegistry,
    crate::peer_registry::PeerRoute,
    ComponentIngress<u64>,
    RetainedWork<u64>,
) {
    let mut lanes = Lanes::new(1, 2);
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
        ComponentIngress::new(20, 40).unwrap(),
        RetainedWork::new(20, 2).unwrap(),
    )
}

#[test]
fn no_call_returns_snapshot_and_releases_only_its_reservation() {
    let (lanes, _, _, mut ingress, mut store) = setup();
    let _other = store.reserve(41).unwrap();
    let mut receive = store.begin_receive(&lanes, &mut ingress).unwrap();
    assert_eq!(store.available(), 0);
    assert!(store.excludes_reply(40));
    receive.capture(&store, &mut ingress, 987).unwrap();
    assert_eq!(
        receive
            .resolve(&mut store, &mut ingress, IngressReceiveDisposition::NoCall)
            .unwrap(),
        Some(987)
    );
    assert_eq!(store.available(), 1);
    assert!(store.excludes_reply(41));
    assert!(!store.excludes_reply(40));
    assert!(receive
        .resolve(&mut store, &mut ingress, IngressReceiveDisposition::NoCall)
        .is_err());
    assert!(store.begin_receive(&lanes, &mut ingress).is_ok());
}

#[test]
fn receive_admission_failure_rolls_back_without_changing_ingress() {
    let (lanes, _, _, mut ingress, mut store) = setup();
    let mut canonical = ComponentIngress::<u64>::new(20, 30).unwrap();
    assert!(store.begin_receive(&lanes, &mut canonical).is_err());
    assert_eq!(store.available(), 2);
    assert!(!store.excludes_reply(30));
    let _first = store.reserve(41).unwrap();
    let _second = store.reserve(42).unwrap();
    assert!(store.begin_receive(&lanes, &mut ingress).is_err());
    // Capacity refusal occurs before the native receive owner is entered.
    assert!(lanes.begin_ingress_receive(&mut ingress).is_ok());
}

#[test]
fn wrong_store_and_ingress_preserve_capture_and_reservation() {
    let (lanes, _, _, mut ingress, mut store) = setup();
    let mut receive = store.begin_receive(&lanes, &mut ingress).unwrap();
    let mut foreign = RetainedWork::new(20, 2).unwrap();
    let mut other = ComponentIngress::new(20, 41).unwrap();
    assert_eq!(
        receive
            .capture(&foreign, &mut ingress, 111)
            .err()
            .unwrap()
            .1,
        111
    );
    assert_eq!(
        receive.capture(&store, &mut other, 112).err().unwrap().1,
        112
    );
    receive.capture(&store, &mut ingress, 113).unwrap();
    assert!(receive
        .resolve(
            &mut foreign,
            &mut ingress,
            IngressReceiveDisposition::NoCall
        )
        .is_err());
    assert_eq!(ingress.message(), Some(&113));
    assert!(store.excludes_reply(40));
    assert_eq!(
        receive
            .resolve(&mut store, &mut ingress, IngressReceiveDisposition::NoCall)
            .unwrap(),
        Some(113)
    );
}

#[test]
fn unresolved_drop_keeps_snapshot_and_capacity_charged() {
    let (lanes, _, _, mut ingress, mut store) = setup();
    let mut receive = store.begin_receive(&lanes, &mut ingress).unwrap();
    receive.capture(&store, &mut ingress, 123).unwrap();
    drop(receive);
    assert_eq!(ingress.message(), Some(&123));
    assert_eq!(store.available(), 1);
    assert!(store.excludes_reply(40));
    assert!(store.begin_receive(&lanes, &mut ingress).is_err());
}

#[test]
fn retained_call_is_committed_before_replacement_can_receive() {
    let (lanes, mut peers, route, mut ingress, mut store) = setup();
    let mut receive = store.begin_receive(&lanes, &mut ingress).unwrap();
    receive.capture(&store, &mut ingress, 123).unwrap();
    assert_eq!(
        receive
            .resolve(&mut store, &mut ingress, IngressReceiveDisposition::Call)
            .unwrap(),
        None
    );
    receive
        .retain(
            &mut store,
            &lanes,
            &mut ingress,
            ComponentIngress::new(20, 41).unwrap(),
            &mut peers,
            route.badge(),
            |executor, reply| {
                assert_eq!((executor, reply), (10, 40));
                Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)
            },
        )
        .ok()
        .unwrap();
    assert_eq!(ingress.reply(), 41);
    assert_eq!(store.available(), 1);
    let mut checkout = store.checkout(route).unwrap();
    assert_eq!(*checkout.call().message(), 123);
    let _nested = store.begin_receive(&lanes, &mut ingress).unwrap();
    assert_eq!(store.available(), 0);
    let mut reply = checkout.begin_reply().unwrap();
    checkout
        .observe_reply(&mut reply, IngressReplyObservation::Acknowledged)
        .unwrap();
    let (_, message) = store.finish_checkout(checkout, &mut peers).ok().unwrap();
    assert_eq!(message, 123);
    assert_eq!(store.available(), 1);
    assert!(store.excludes_reply(41));
}

#[test]
fn query_and_replacement_alias_failures_keep_original_call_for_retry() {
    let (lanes, mut peers, route, mut ingress, mut store) = setup();
    let mut receive = store.begin_receive(&lanes, &mut ingress).unwrap();
    receive.capture(&store, &mut ingress, 123).unwrap();
    receive
        .resolve(&mut store, &mut ingress, IngressReceiveDisposition::Call)
        .unwrap();
    let mut other = store.reserve(41).unwrap();
    let (_, replacement) = receive
        .retain(
            &mut store,
            &lanes,
            &mut ingress,
            ComponentIngress::new(20, 41).unwrap(),
            &mut peers,
            route.badge(),
            |_, _| -> Result<ReplyBindingObservation, u8> { panic!("reserved replacement") },
        )
        .err()
        .unwrap();
    store.release_reservation(&mut other).unwrap();
    let (_, replacement) = receive
        .retain(
            &mut store,
            &lanes,
            &mut ingress,
            replacement,
            &mut peers,
            route.badge(),
            |_, _| Err(9u8),
        )
        .err()
        .unwrap();
    assert_eq!(ingress.reply(), 40);
    assert_eq!(ingress.message(), Some(&123));
    assert!(store.excludes_reply(40));
    assert_eq!(peers.state(route).unwrap().1, 0);
    receive
        .retain(
            &mut store,
            &lanes,
            &mut ingress,
            replacement,
            &mut peers,
            route.badge(),
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
        )
        .ok()
        .unwrap();
    assert_eq!(peers.state(route).unwrap().1, 1);
    assert_eq!(*store.checkout(route).unwrap().call().message(), 123);
}

#[test]
fn old_reservation_cannot_retain_a_later_call_on_the_same_ingress() {
    let (lanes, mut peers, route, mut ingress, mut store) = setup();
    let mut original = store.begin_receive(&lanes, &mut ingress).unwrap();
    original.capture(&store, &mut ingress, 123).unwrap();
    original
        .resolve(&mut store, &mut ingress, IngressReceiveDisposition::Call)
        .unwrap();
    let mut reply = ingress.begin_reply().unwrap();
    assert_eq!(
        ingress
            .observe_reply(&mut reply, IngressReplyObservation::Acknowledged)
            .unwrap(),
        Some(123)
    );
    let mut later = lanes.begin_ingress_receive(&mut ingress).unwrap();
    ingress
        .observe_receive(&mut later, crate::IngressObservation::Call(456))
        .unwrap();
    let (_, replacement) = original
        .retain(
            &mut store,
            &lanes,
            &mut ingress,
            ComponentIngress::new(20, 41).unwrap(),
            &mut peers,
            route.badge(),
            |_, _| -> Result<ReplyBindingObservation, u8> {
                panic!("different receive must not query")
            },
        )
        .err()
        .unwrap();
    assert_eq!(replacement.reply(), 41);
    assert_eq!(ingress.message(), Some(&456));
    assert_eq!(peers.state(route).unwrap().1, 0);
    assert!(store.excludes_reply(40));
    assert_eq!(store.available(), 1);
}
