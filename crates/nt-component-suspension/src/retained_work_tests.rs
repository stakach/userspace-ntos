use super::*;
use crate::{
    ComponentSuspensionLanes, IngressObservation, IngressReplyObservation, LaneBinding,
    ReplyBindingObservation,
};

type Lanes = ComponentSuspensionLanes<(), (), ()>;

#[test]
fn exact_dispatch_and_reply_selection_skip_an_earlier_call_for_same_peer() {
    let (mut lanes, mut peers, route, mut old) = call(40);
    let mut ingress = ComponentIngress::new(20, 42).unwrap();
    let mut receive = lanes.begin_ingress_receive(&mut ingress).unwrap();
    assert!(ingress
        .observe_receive(&mut receive, IngressObservation::Call(456))
        .is_ok());
    let next = lanes
        .retain_peer_ingress(
            &mut ingress,
            ComponentIngress::new(20, 43).unwrap(),
            &mut peers,
            route.badge(),
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
        )
        .ok()
        .unwrap();
    let receipt = lanes
        .begin_retained_dispatch(&peers, &mut old, 1, 2, |_, reply| {
            Ok::<_, u8>(if reply == 30 {
                ReplyBindingObservation::Free
            } else {
                ReplyBindingObservation::BoundToTarget
            })
        })
        .unwrap();
    let mut store = RetainedWork::new(20, 2).unwrap();
    let slot = store.reserve(42).unwrap();
    assert!(store.commit(slot, next).is_ok());
    let slot = store.reserve(40).unwrap();
    assert!(store.commit(slot, old).is_ok());
    let selected = store.stored_dispatch_mut(route, receipt.dispatch).unwrap();
    assert_eq!(selected.reply(), 40);
    assert_eq!(*selected.message(), 140);
    let checkout = store.checkout_reply(route, 40).unwrap();
    assert_eq!(checkout.call().reply(), 40);
    let next = store.checkout(route).unwrap();
    assert_eq!(next.call().reply(), 42);
    assert_eq!(*next.call().message(), 456);
}

fn call(reply: u64) -> (Lanes, PeerRegistry, PeerRoute, RetainedIngress<u64>) {
    call_for(reply, 1, 10)
}

fn call_for(
    reply: u64,
    domain: u64,
    executor: u64,
) -> (Lanes, PeerRegistry, PeerRoute, RetainedIngress<u64>) {
    let mut lanes = Lanes::new(1, 2);
    let lane = lanes
        .allocate(LaneBinding {
            executor_id: executor,
            receive_endpoint: 20,
            reply_object: 29 + domain,
        })
        .unwrap();
    let mut peers = PeerRegistry::new(20, 1);
    let mut registration = peers.stage_lane(domain, 2, &lanes, lane).unwrap();
    let route = peers
        .publish_lane(&mut registration, domain, 2, &lanes)
        .unwrap();
    let mut ingress = ComponentIngress::new(20, reply).unwrap();
    let mut receive = lanes.begin_ingress_receive(&mut ingress).unwrap();
    assert!(ingress
        .observe_receive(&mut receive, IngressObservation::Call(reply + 100))
        .is_ok());
    let call = lanes
        .retain_peer_ingress(
            &mut ingress,
            ComponentIngress::new(20, reply + 1).unwrap(),
            &mut peers,
            route.badge(),
            |_, _| Ok::<_, ()>(ReplyBindingObservation::BoundToTarget),
        )
        .ok()
        .unwrap();
    (lanes, peers, route, call)
}

fn ack(call: &mut RetainedWorkCheckout<u64>) {
    let mut reply = call.begin_reply().unwrap();
    call.observe_reply(&mut reply, IngressReplyObservation::Acknowledged)
        .unwrap();
}

#[test]
fn reservation_is_bounded_and_excludes_reply_before_receive() {
    assert!(RetainedWork::<u64>::new(0, 1).is_err());
    assert!(RetainedWork::<u64>::new(20, 0).is_err());
    assert_eq!(
        RetainedWork::<u64>::new(20, usize::MAX).err(),
        Some(RetainedWorkError::NoCapacity)
    );
    let mut store = RetainedWork::<u64>::new(20, 1).unwrap();
    assert_eq!(
        store.reserve(0).err(),
        Some(RetainedWorkError::InvalidReply)
    );
    assert_eq!(
        store.reserve(20).err(),
        Some(RetainedWorkError::InvalidReply)
    );
    let mut reservation = store.reserve(40).unwrap();
    assert_eq!(store.available(), 0);
    assert!(store.excludes_reply(40));
    assert_eq!(store.reserve(40).err(), Some(RetainedWorkError::ReplyInUse));
    assert_eq!(store.reserve(41).err(), Some(RetainedWorkError::NoCapacity));
    store.release_reservation(&mut reservation).unwrap();
    assert_eq!(store.available(), 1);
    assert!(!store.excludes_reply(40));
    assert_eq!(
        store.release_reservation(&mut reservation),
        Err(RetainedWorkError::WrongOwner)
    );
}

#[test]
fn reservation_ids_do_not_cross_stores_or_wrap() {
    let mut a = RetainedWork::<u64>::new(20, 1).unwrap();
    let mut b = RetainedWork::<u64>::new(20, 1).unwrap();
    let mut ticket = a.reserve(40).unwrap();
    let own = b.reserve(40).unwrap();
    assert_ne!(ticket.identity, own.identity);
    assert_eq!(
        b.release_reservation(&mut ticket),
        Err(RetainedWorkError::WrongOwner)
    );
    a.release_reservation(&mut ticket).unwrap();
    for value in [0, u64::MAX] {
        assert_eq!(
            a.reserve_with_counter(40, &AtomicU64::new(value)).err(),
            Some(RetainedWorkError::IdentityExhausted)
        );
        assert_eq!(a.available(), 1);
    }
    let later = a.reserve(40).unwrap();
    assert_ne!(later.identity, own.identity);
}

#[test]
fn commit_errors_preserve_call_and_reservation() {
    let (_, _, _, retained) = call(40);
    let mut a = RetainedWork::new(20, 1).unwrap();
    let mut b = RetainedWork::new(20, 1).unwrap();
    let ticket = a.reserve(40).unwrap();
    let (error, ticket, retained) = b.commit(ticket, retained).err().unwrap();
    assert_eq!(error, RetainedWorkError::WrongOwner);
    assert_eq!(*retained.message(), 140);
    assert!(a.commit(ticket, retained).is_ok());
    let (_, _, _, retained) = call(44);
    let ticket = b.reserve(42).unwrap();
    let (error, mut ticket, retained) = b.commit(ticket, retained).err().unwrap();
    assert_eq!(error, RetainedWorkError::InvalidReply);
    assert_eq!(retained.reply(), 44);
    b.release_reservation(&mut ticket).unwrap();
    let mut wrong = RetainedWork::new(21, 1).unwrap();
    let ticket = wrong.reserve(44).unwrap();
    let (error, _, retained) = wrong.commit(ticket, retained).err().unwrap();
    assert_eq!(error, RetainedWorkError::WrongEndpoint);
    assert_eq!(retained.reply(), 44);
    assert!(wrong.excludes_reply(44));
}

#[test]
fn checkout_keeps_capacity_reply_and_exact_route_until_restored() {
    let (_, _, route, retained) = call(40);
    let (_, _, foreign, _) = call(44);
    let mut store = RetainedWork::new(20, 1).unwrap();
    let ticket = store.reserve(40).unwrap();
    assert!(store.commit(ticket, retained).is_ok());
    assert_eq!(
        store.checkout(foreign).err().map(|e| e),
        Some(RetainedWorkError::NotFound)
    );
    let checkout = store.checkout(route).unwrap();
    assert_eq!(*checkout.call().message(), 140);
    assert!(store.excludes_reply(40));
    assert_eq!(store.available(), 0);
    assert_eq!(
        store.checkout(route).err(),
        Some(RetainedWorkError::NotFound)
    );
    let mut foreign_store = RetainedWork::new(20, 1).unwrap();
    let (error, checkout) = foreign_store.restore(checkout).err().unwrap();
    assert_eq!(error, RetainedWorkError::WrongOwner);
    assert!(store.restore(checkout).is_ok());
    assert_eq!(*store.checkout(route).unwrap().call().message(), 140);
    assert_eq!(store.available(), 0);
}

#[test]
fn acknowledgement_and_registry_release_are_required_before_vacancy() {
    let (_, mut peers, route, retained) = call(40);
    let mut store = RetainedWork::new(20, 1).unwrap();
    let ticket = store.reserve(40).unwrap();
    assert!(store.commit(ticket, retained).is_ok());
    let checkout = store.checkout(route).unwrap();
    let (error, mut checkout) = store.finish_checkout(checkout, &mut peers).err().unwrap();
    assert_eq!(
        error,
        RetainedWorkFinishError::Call(RetainedIngressError::NotAcknowledged)
    );
    let mut attempt = checkout.begin_reply().unwrap();
    checkout
        .observe_reply(&mut attempt, IngressReplyObservation::Indeterminate)
        .unwrap();
    assert!(store.restore(checkout).is_ok());
    let mut checkout = store.checkout(route).unwrap();
    checkout
        .observe_reply(&mut attempt, IngressReplyObservation::Acknowledged)
        .unwrap();
    let mut foreign = PeerRegistry::new(20, 1);
    let (_, checkout) = store.finish_checkout(checkout, &mut foreign).err().unwrap();
    assert_eq!(store.available(), 0);
    assert!(store.excludes_reply(40));
    let (_, payload) = store.finish_checkout(checkout, &mut peers).ok().unwrap();
    assert_eq!(payload, 140);
    assert_eq!(store.available(), 1);
    assert!(!store.excludes_reply(40));
}

#[test]
fn admitted_dispatch_prevents_checkout_finish_until_exact_completion() {
    let (mut lanes, mut peers, route, retained) = call(40);
    let mut store = RetainedWork::new(20, 1).unwrap();
    let ticket = store.reserve(40).unwrap();
    assert!(store.commit(ticket, retained).is_ok());
    let mut checkout = store.checkout(route).unwrap();
    checkout
        .begin_dispatch(&mut lanes, &peers, 1, 2, |_, reply| {
            Ok::<_, ()>(if reply == 30 {
                ReplyBindingObservation::Free
            } else {
                ReplyBindingObservation::BoundToTarget
            })
        })
        .unwrap();
    ack(&mut checkout);
    let (error, mut checkout) = store.finish_checkout(checkout, &mut peers).err().unwrap();
    assert_eq!(
        error,
        RetainedWorkFinishError::Call(RetainedIngressError::DispatchActive)
    );
    checkout.finish_dispatch(&mut lanes).unwrap();
    assert!(store.finish_checkout(checkout, &mut peers).is_ok());
    assert_eq!(store.available(), 1);
}

#[test]
fn multiple_peers_complete_out_of_order_without_releasing_other_slots() {
    let (_, mut peers_a, route_a, call_a) = call(40);
    let (_, mut peers_b, route_b, call_b) = call_for(44, 2, 11);
    let mut store = RetainedWork::new(20, 2).unwrap();
    let backing = store.slots.as_ptr();
    let capacity = store.slots.capacity();
    for call in [call_a, call_b] {
        let ticket = store.reserve(call.reply()).unwrap();
        assert!(store.commit(ticket, call).is_ok());
    }
    for (route, peers, expected) in [(route_b, &mut peers_b, 144), (route_a, &mut peers_a, 140)] {
        let mut checkout = store.checkout(route).unwrap();
        ack(&mut checkout);
        assert_eq!(
            store.finish_checkout(checkout, peers).ok().unwrap().1,
            expected
        );
    }
    assert_eq!(store.available(), 2);
    assert_eq!(store.slots.as_ptr(), backing);
    assert_eq!(store.slots.capacity(), capacity);
}

#[test]
fn dropped_reservation_and_checkout_never_release_capacity_or_reply() {
    let mut store = RetainedWork::<u64>::new(20, 2).unwrap();
    drop(store.reserve(42).unwrap());
    assert!(store.excludes_reply(42));
    let (_, peers, route, retained) = call(40);
    let ticket = store.reserve(40).unwrap();
    assert!(store.commit(ticket, retained).is_ok());
    drop(store.checkout(route).unwrap());
    assert!(store.excludes_reply(40));
    assert_eq!(store.available(), 0);
    assert_eq!(peers.state(route).unwrap().1, 1);
}

#[test]
fn foreign_same_slot_finish_and_stale_reservation_cannot_release_owners() {
    let (_, mut peers, route, retained) = call(40);
    let mut a = RetainedWork::new(20, 1).unwrap();
    let mut b = RetainedWork::new(20, 1).unwrap();
    let mut old = a.reserve(40).unwrap();
    a.release_reservation(&mut old).unwrap();
    let ticket = a.reserve(40).unwrap();
    assert_eq!(
        a.release_reservation(&mut old),
        Err(RetainedWorkError::WrongOwner)
    );
    assert!(a.commit(ticket, retained).is_ok());
    let mut checkout = a.checkout(route).unwrap();
    ack(&mut checkout);
    let _foreign_ticket = b.reserve(40).unwrap();
    let (error, checkout) = b.finish_checkout(checkout, &mut peers).err().unwrap();
    assert_eq!(
        error,
        RetainedWorkFinishError::Store(RetainedWorkError::WrongOwner)
    );
    assert_eq!(peers.state(route).unwrap().1, 1);
    assert_eq!(a.available(), 0);
    assert_eq!(b.available(), 0);
    assert!(a.finish_checkout(checkout, &mut peers).is_ok());
}

#[test]
fn nested_arrival_cannot_steal_checked_out_restore_capacity() {
    let (mut lanes, mut peers_a, route_a, call_a) = call(40);
    let (_, mut peers_b, route_b, call_b) = call_for(44, 2, 11);
    let mut store = RetainedWork::new(20, 2).unwrap();
    let backing = store.slots.as_ptr();
    let ticket = store.reserve(40).unwrap();
    assert!(store.commit(ticket, call_a).is_ok());
    let mut first = store.checkout(route_a).unwrap();
    let nested = store.reserve(44).unwrap();
    assert!(store.commit(nested, call_b).is_ok());
    assert_eq!(store.reserve(48).err(), Some(RetainedWorkError::NoCapacity));
    assert_eq!(
        first.begin_dispatch(&mut lanes, &peers_a, 1, 2, |_, _| Err(9u8)),
        Err(crate::RetainedDispatchError::Query(9)),
    );
    assert!(store.restore(first).is_ok());
    assert_eq!(store.available(), 0);
    assert!(store.excludes_reply(40));
    assert!(store.excludes_reply(44));
    let mut first = store.checkout(route_a).unwrap();
    ack(&mut first);
    assert_eq!(
        store.finish_checkout(first, &mut peers_a).ok().unwrap().1,
        140
    );
    assert!(store.excludes_reply(44));
    let mut second = store.checkout(route_b).unwrap();
    ack(&mut second);
    assert_eq!(
        store.finish_checkout(second, &mut peers_b).ok().unwrap().1,
        144
    );
    assert_eq!(store.available(), 2);
    assert_eq!(store.slots.as_ptr(), backing);
}
