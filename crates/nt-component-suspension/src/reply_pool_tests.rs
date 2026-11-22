use super::*;
use crate::{IngressExecutionOwner, IngressReceiveDisposition, IngressReplyObservation, LaneBinding};

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

fn setup_shared() -> (
    Lanes,
    PeerRegistry,
    crate::peer_registry::PeerRoute,
    IngressReceiver<u64>,
    IngressReplyPool<u64>,
) {
    let mut lanes = Lanes::new(2, 2);
    let mut peers = PeerRegistry::new(20, 2);
    let (lane, mut registration) = lanes.allocate_shared_staged(
        &mut peers, 1, 2, LaneBinding {
            executor_id: 10,
            receive_endpoint: 20,
            reply_object: 30,
        },
    ).unwrap();
    let route = peers.publish_lane(&mut registration, 1, 2, &lanes).unwrap();
    lanes.begin_startup(lane, 30, |_, _| Ok::<_, u8>(ReplyBindingObservation::Free)).unwrap();
    lanes.complete_startup(lane, 30, |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)).unwrap();
    (
        lanes, peers, route,
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
fn admission_keeps_call_stored_and_recycles_only_displaced_reply() {
    let (mut lanes, mut peers, route, mut owner, mut pool) = setup();
    pool.insert(ComponentIngress::new(20, 41).unwrap(), &owner, &lanes, free)
        .ok()
        .unwrap();
    call(&mut owner, &lanes);
    pool.retain(&mut owner, &lanes, &mut peers, route.badge(), free, bound)
        .unwrap();
    let available = owner.available();
    let dispatch = pool
        .admit(&mut owner, route, &mut lanes, &peers, 1, 2, |tcb, reply| {
            assert_eq!(tcb, 10);
            Ok::<_, u8>(if reply == 30 {
                ReplyBindingObservation::Free
            } else {
                assert_eq!(reply, 40);
                ReplyBindingObservation::BoundToTarget
            })
        })
        .unwrap();
    assert_eq!(owner.available(), available);
    assert!(owner.excludes_reply(40));
    assert!(pool.excludes_reply(30));
    assert!(!pool.excludes_reply(40));
    assert_eq!(
        lanes.binding(route.identity().lane).unwrap().reply_object,
        40
    );
    assert_eq!(
        lanes.active_dispatch_identity(dispatch.lane),
        Ok(Some(dispatch))
    );
    let mut checkout = owner.checkout(route).unwrap();
    assert_eq!(*checkout.call().message(), 123);
    let mut attempt = checkout.begin_reply().unwrap();
    checkout
        .observe_reply(&mut attempt, IngressReplyObservation::Acknowledged)
        .unwrap();
    let (_, mut checkout) = owner.finish_checkout(checkout, &mut peers).err().unwrap();
    checkout.finish_dispatch(&mut lanes).unwrap();
    let (ready, message) = owner.finish_checkout(checkout, &mut peers).ok().unwrap();
    assert_eq!(message, 123);
    // ACK does not displace the canonical Reply, even after the execution epoch ends.
    let (_, ready) = pool.insert(ready, &owner, &lanes, free).err().unwrap();
    assert_eq!(ready.reply(), 40);
    assert_eq!(peers.state(route).unwrap().1, 0);
}

#[test]
fn same_lane_is_not_ready_for_a_second_dispatch_while_first_reply_is_owned() {
    let (mut lanes, mut peers, route, mut owner, _) = setup();
    let mut pool = IngressReplyPool::new(20, 2).unwrap();
    pool.insert(ComponentIngress::new(20, 41).unwrap(), &owner, &lanes, free)
        .ok().unwrap();
    call(&mut owner, &lanes);
    pool.retain(&mut owner, &lanes, &mut peers, route.badge(), free, bound)
        .unwrap();
    assert!(pool.ready_for_admission(&owner, route, &lanes));
    let first = pool.admit(&mut owner, route, &mut lanes, &peers, 1, 2, |_, reply| {
        Ok::<_, u8>(if reply == 30 {
            ReplyBindingObservation::Free
        } else {
            ReplyBindingObservation::BoundToTarget
        })
    }).unwrap();
    assert!(!pool.ready_for_admission(&owner, route, &lanes));
    assert_eq!(lanes.active_dispatch_identity(first.lane), Ok(Some(first)));
    assert!(owner.excludes_reply(40));
    assert!(pool.excludes_reply(30));
}

#[test]
fn independent_worker_admits_while_primary_call_remains_occupied() {
    let mut lanes = Lanes::new(2, 2);
    let mut peers = PeerRegistry::new(20, 2);
    let (primary_lane, mut primary_registration) = lanes.allocate_shared_staged(&mut peers, 1, 2, LaneBinding {
        executor_id: 10,
        receive_endpoint: 20,
        reply_object: 30,
    }).unwrap();
    let (worker_lane, mut registration) = lanes.allocate_shared_staged(&mut peers, 1, 2, LaneBinding {
        executor_id: 11,
        receive_endpoint: 20,
        reply_object: 31,
    }).unwrap();
    let primary = peers.publish_lane(&mut primary_registration, 1, 2, &lanes).unwrap();
    let worker = peers.publish_lane(&mut registration, 1, 2, &lanes).unwrap();
    for (lane, reply) in [(primary_lane, 30), (worker_lane, 31)] {
        lanes.begin_startup(lane, reply,
            |_, _| Ok::<_, u8>(ReplyBindingObservation::Free)).unwrap();
        lanes.complete_startup(lane, reply,
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)).unwrap();
    }
    let mut receiver = IngressReceiver::new(20, 40, 3).unwrap();
    let mut pool = IngressReplyPool::new(20, 3).unwrap();
    for reply in [41, 42, 43] {
        pool.insert(ComponentIngress::new(20, reply).unwrap(), &receiver, &lanes, free)
            .ok().unwrap();
    }
    call(&mut receiver, &lanes);
    pool.retain(&mut receiver, &lanes, &mut peers, primary.badge(), free, bound)
        .unwrap();
    let primary_dispatch = pool.admit(&mut receiver, primary, &mut lanes, &peers, 1, 2,
        |_, reply| Ok::<_, u8>(if reply == 30 {
            ReplyBindingObservation::Free
        } else {
            ReplyBindingObservation::BoundToTarget
        }),
    ).unwrap();
    assert!(!pool.ready_for_admission(&receiver, primary, &lanes));

    receiver.begin_receive_for_owner(&lanes,
        crate::IngressExecutionOwner::Dispatch(primary_dispatch)).unwrap();
    receiver.capture(456).unwrap();
    receiver.resolve(IngressReceiveDisposition::Call).unwrap();
    pool.retain(&mut receiver, &lanes, &mut peers, worker.badge(), free, bound)
        .unwrap();
    assert_eq!(receiver.next_unadmitted(worker).map(|(_, message)| *message), Some(456));
    assert!(pool.ready_for_admission(&receiver, worker, &lanes));
    assert!(!pool.ready_for_admission(&receiver, primary, &lanes));
}

#[test]
fn completed_lane_reuses_its_physical_reply_after_next_call_is_retained() {
    let (mut lanes, mut peers, route, mut owner, _) = setup();
    let mut pool = IngressReplyPool::new(20, 2).unwrap();
    pool.insert(ComponentIngress::new(20, 41).unwrap(), &owner, &lanes, free)
        .ok().unwrap();
    call(&mut owner, &lanes);
    pool.retain(&mut owner, &lanes, &mut peers, route.badge(), free, bound)
        .unwrap();
    assert_eq!(owner.retained_reply_owner(40).unwrap().kind, crate::RetainedReplyKind::Stored);
    pool.admit(&mut owner, route, &mut lanes, &peers, 1, 2, |_, reply| {
        Ok::<_, u8>(if reply == 30 {
            ReplyBindingObservation::Free
        } else {
            ReplyBindingObservation::BoundToTarget
        })
    }).unwrap();
    assert!(owner.retained_reply_owner(40).unwrap().admitted);

    let mut checkout = owner.checkout(route).unwrap();
    let mut attempt = checkout.begin_reply().unwrap();
    checkout.observe_reply(&mut attempt, IngressReplyObservation::Acknowledged)
        .unwrap();
    let (_, mut checkout) = owner.finish_checkout(checkout, &mut peers).err().unwrap();
    checkout.finish_dispatch(&mut lanes).unwrap();
    let (ready, _) = owner.finish_checkout(checkout, &mut peers).ok().unwrap();
    drop(ready); // The canonical lane, now bound to Reply 40, owns this capability.
    assert!(owner.retained_reply_owner(40).is_none());

    assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Idle));
    assert_eq!(lanes.binding(route.identity().lane).unwrap().reply_object, 40);
    call(&mut owner, &lanes);
    pool.retain(&mut owner, &lanes, &mut peers, route.badge(), free, bound)
        .unwrap();
    assert_eq!(pool.len(), 0);
    assert!(!owner.excludes_reply(40));
    assert!(!pool.excludes_reply(40));
    assert!(owner.next_unadmitted(route).is_some());
    assert!(pool.ready_for_admission(&owner, route, &lanes));
}

#[test]
fn idle_lane_with_receiver_owned_reply_is_not_admissible() {
    let mut lanes = Lanes::new(1, 2);
    let lane = lanes.allocate(LaneBinding {
        executor_id: 10,
        receive_endpoint: 20,
        reply_object: 40,
    }).unwrap();
    let mut peers = PeerRegistry::new(20, 1);
    let mut registration = peers.stage_lane(1, 2, &lanes, lane).unwrap();
    let route = peers.publish_lane(&mut registration, 1, 2, &lanes).unwrap();
    let receiver = IngressReceiver::<u64>::new(20, 40, 2).unwrap();
    let pool = IngressReplyPool::<u64>::new(20, 2).unwrap();

    assert!(receiver.excludes_reply(40));
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
    assert!(!pool.ready_for_admission(&receiver, route, &lanes));
}

#[test]
fn admission_query_failure_preserves_stored_call_and_all_ownership() {
    for fail_reply in [30, 40] {
        let (mut lanes, mut peers, route, mut owner, mut pool) = setup();
        pool.insert(ComponentIngress::new(20, 41).unwrap(), &owner, &lanes, free)
            .ok()
            .unwrap();
        call(&mut owner, &lanes);
        pool.retain(&mut owner, &lanes, &mut peers, route.badge(), free, bound)
            .unwrap();
        assert_eq!(
            pool.admit(&mut owner, route, &mut lanes, &peers, 1, 2, |_, reply| {
                if reply == fail_reply {
                    Err(7u8)
                } else {
                    Ok(ReplyBindingObservation::Free)
                }
            }),
            Err(ReplyAdmissionError::Dispatch(RetainedDispatchError::Query(
                7
            )))
        );
        assert!(pool.is_empty());
        assert_eq!(
            lanes.binding(route.identity().lane).unwrap().reply_object,
            30
        );
        assert_eq!(lanes.running(), None);
        assert_eq!(peers.state(route).unwrap().1, 1);
        assert!(owner.excludes_reply(40));
        let checkout = owner.checkout(route).unwrap();
        assert_eq!(*checkout.call().message(), 123);
        assert!(owner.restore(checkout).is_ok());
    }
}

#[test]
fn admission_full_pool_refuses_before_queries_or_checkout() {
    let (mut lanes, mut peers, route, mut owner, mut pool) = setup();
    pool.insert(ComponentIngress::new(20, 41).unwrap(), &owner, &lanes, free)
        .ok()
        .unwrap();
    call(&mut owner, &lanes);
    pool.retain(&mut owner, &lanes, &mut peers, route.badge(), free, bound)
        .unwrap();
    pool.insert(ComponentIngress::new(20, 42).unwrap(), &owner, &lanes, free)
        .ok()
        .unwrap();
    assert_eq!(
        pool.admit(
            &mut owner,
            route,
            &mut lanes,
            &peers,
            1,
            2,
            |_, _| -> Result<ReplyBindingObservation, u8> { panic!("full pool must not query") }
        ),
        Err(ReplyAdmissionError::Pool(ReplyPoolError::NoCapacity))
    );
    assert_eq!(lanes.running(), None);
    assert!(pool.excludes_reply(42));
    assert_eq!(*owner.checkout(route).unwrap().call().message(), 123);
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
fn held_query_refusal_retries_only_with_the_original_execution_and_reply_owners() {
    use crate::ReservedReceivePhase;

    let (mut lanes, mut peers, route, mut owner, mut pool) = setup_shared();
    pool.insert(ComponentIngress::new(20, 41).unwrap(), &owner, &lanes, free)
        .ok().unwrap();
    lanes.begin_dispatch(route.identity().lane, 30).unwrap();
    let dispatch = lanes.active_dispatch_identity(route.identity().lane).unwrap().unwrap();
    let execution = IngressExecutionOwner::Dispatch(dispatch);
    owner.begin_receive_for_owner(&lanes, execution).unwrap();
    owner.capture(123).unwrap();
    owner.resolve(IngressReceiveDisposition::Call).unwrap();

    let refusal = pool.retain(
        &mut owner, &lanes, &mut peers, route.badge(), free,
        |_, _| Err(7u8),
    ).unwrap_err();
    assert_eq!(owner.phase(), Some(ReservedReceivePhase::Held));
    assert_eq!(owner.message(), Some(&123));
    assert_eq!(owner.reply(), 40);
    assert!(pool.excludes_reply(41));
    assert_eq!(peers.state(route).unwrap().1, 0);

    // This is only eligibility for another read-only query, not physical binding authority.
    // A copied numeric Reply, foreign route, new epoch, or endpoint must not grant eligibility.
    assert!(pool.held_query_retry_eligible(&owner, &lanes, execution, route, 40, 41, &refusal));
    let (_, mut foreign_registration) = lanes.allocate_shared_staged(
        &mut peers, 9, 10, LaneBinding {
            executor_id: 11,
            receive_endpoint: 20,
            reply_object: 31,
        },
    ).unwrap();
    let foreign_route = peers.publish_lane(&mut foreign_registration, 9, 10, &lanes).unwrap();
    assert!(!pool.held_query_retry_eligible(
        &owner, &lanes, execution, foreign_route, 40, 41, &refusal,
    ));
    assert!(!pool.held_query_retry_eligible(
        &owner, &lanes, IngressExecutionOwner::Idle, route, 40, 41, &refusal,
    ));
    assert!(!pool.held_query_retry_eligible(&owner, &lanes, execution, route, 41, 41, &refusal));
    assert!(!pool.held_query_retry_eligible(&owner, &lanes, execution, route, 40, 42, &refusal));
    let mut foreign_endpoint = IngressReceiver::<u64>::new(21, 40, 2).unwrap();
    foreign_endpoint.begin_receive_for_owner(&lanes, execution).unwrap();
    foreign_endpoint.capture(123).unwrap();
    foreign_endpoint.resolve(IngressReceiveDisposition::Call).unwrap();
    assert_eq!(foreign_endpoint.phase(), Some(ReservedReceivePhase::Held));
    assert!(!pool.held_query_retry_eligible(
        &foreign_endpoint, &lanes, execution, route, 40, 41, &refusal,
    ));

    pool.retain(&mut owner, &lanes, &mut peers, route.badge(), free, bound).unwrap();
    assert_eq!(owner.phase(), None);
    assert_eq!(owner.reply(), 41);
    assert!(!pool.held_query_retry_eligible(&owner, &lanes, execution, route, 40, 41, &refusal));
    assert_eq!(*owner.checkout(route).unwrap().call().message(), 123);
}

#[test]
fn held_binding_mismatch_does_not_authorize_query_retry() {
    let (mut lanes, mut peers, route, mut owner, mut pool) = setup_shared();
    pool.insert(ComponentIngress::new(20, 41).unwrap(), &owner, &lanes, free)
        .ok().unwrap();
    lanes.begin_dispatch(route.identity().lane, 30).unwrap();
    let dispatch = lanes.active_dispatch_identity(route.identity().lane).unwrap().unwrap();
    let execution = IngressExecutionOwner::Dispatch(dispatch);
    owner.begin_receive_for_owner(&lanes, execution).unwrap();
    owner.capture(123).unwrap();
    owner.resolve(IngressReceiveDisposition::Call).unwrap();

    let refusal = pool.retain(
        &mut owner, &lanes, &mut peers, route.badge(), free,
        |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundElsewhere),
    ).unwrap_err();
    assert!(!pool.held_query_retry_eligible(&owner, &lanes, execution, route, 40, 41, &refusal));
    assert_eq!(owner.message(), Some(&123));
    assert_eq!(owner.reply(), 40);
    assert!(pool.excludes_reply(41));
    assert_eq!(peers.state(route).unwrap().1, 0);
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

/// A provider calling back into a dependent asks for the dependent's retained Call. Every way
/// that request can be refused must stay distinguishable to the adapter that reports it.
#[test]
fn nested_dependent_admission_refusals_name_their_invariant() {
    use crate::{AdmissionRefusal, LaneError, RetainedDispatchError, RetainedWorkError};
    let (mut lanes, mut peers, provider, mut owner, _) = setup_shared();
    let (dependent_lane, mut registration) = lanes.allocate_shared_staged(
        &mut peers, 1, 2, LaneBinding { executor_id: 11, receive_endpoint: 20, reply_object: 31 },
    ).unwrap();
    let dependent = peers.publish_lane(&mut registration, 1, 2, &lanes).unwrap();
    lanes.begin_startup(dependent_lane, 31, |_, _| Ok::<_, u8>(ReplyBindingObservation::Free)).unwrap();
    lanes.complete_startup(dependent_lane, 31,
        |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)).unwrap();
    let mut pool = IngressReplyPool::new(20, 3).unwrap();
    for reply in [41, 42] {
        pool.insert(ComponentIngress::new(20, reply).unwrap(), &owner, &lanes, free).ok().unwrap();
    }
    let observe = |old: u64| move |_: u64, reply: u64| Ok::<_, u8>(if reply == old {
        ReplyBindingObservation::Free
    } else {
        ReplyBindingObservation::BoundToTarget
    });

    // The dependent has not parked a Call on the shared endpoint.
    let refused = pool.admit(&mut owner, dependent, &mut lanes, &peers, 1, 2, observe(31))
        .unwrap_err();
    assert_eq!(refused, ReplyAdmissionError::Store(RetainedWorkError::NotFound));
    assert_eq!(refused.refusal(), AdmissionRefusal::NoRetainedCall);

    call(&mut owner, &lanes);
    pool.retain(&mut owner, &lanes, &mut peers, provider.badge(), free, bound).unwrap();
    let provider_dispatch = pool.admit(&mut owner, provider, &mut lanes, &peers, 1, 2, observe(30))
        .unwrap();
    owner.begin_receive_for_owner(&lanes, IngressExecutionOwner::Dispatch(provider_dispatch))
        .unwrap();

    // The shared receive is still reserved for the running provider.
    let refused = pool.admit(&mut owner, dependent, &mut lanes, &peers, 1, 2, observe(31))
        .unwrap_err();
    assert_eq!(refused.refusal(), AdmissionRefusal::ReceiveInProgress);

    owner.capture(456).unwrap();
    owner.resolve(IngressReceiveDisposition::Call).unwrap();
    pool.retain(&mut owner, &lanes, &mut peers, dependent.badge(), free, bound).unwrap();

    // The provider was not parked, so the single execution token is still its own.
    let refused = pool.admit(&mut owner, dependent, &mut lanes, &peers, 1, 2, observe(31))
        .unwrap_err();
    assert_eq!(refused, ReplyAdmissionError::Dispatch(RetainedDispatchError::Lane(LaneError::Busy)));
    assert_eq!(refused.refusal(), AdmissionRefusal::ExecutionBusy);
    // A refusal leaves the dependent's Call retained and its canonical Reply in place.
    assert_eq!(owner.next_unadmitted(dependent).map(|(_, message)| *message), Some(456));
    assert_eq!(lanes.binding(dependent_lane).unwrap().reply_object, 31);
    assert_eq!(lanes.active_dispatch_identity(dependent_lane), Ok(None));

    for (error, class, name) in [
        (ReplyAdmissionError::<u8>::Pool(ReplyPoolError::NoCapacity),
            AdmissionRefusal::ReplacementPoolFull, "replacement-pool-full"),
        (ReplyAdmissionError::Pool(ReplyPoolError::ReplyInUse),
            AdmissionRefusal::ReplyAliased, "reply-aliased"),
        (ReplyAdmissionError::Dispatch(RetainedDispatchError::Lane(LaneError::InvalidPhase)),
            AdmissionRefusal::LaneNotIdle, "lane-not-idle"),
        (ReplyAdmissionError::Dispatch(RetainedDispatchError::OldReplyNotFree),
            AdmissionRefusal::CanonicalReplyNotFree, "canonical-reply-not-free"),
        (ReplyAdmissionError::Dispatch(RetainedDispatchError::BindingMismatch),
            AdmissionRefusal::CallNotBoundToExecutor, "call-not-bound-to-executor"),
        (ReplyAdmissionError::Dispatch(RetainedDispatchError::Query(7)),
            AdmissionRefusal::BindingQueryFailed, "binding-query-failed"),
    ] {
        assert_eq!(error.refusal(), class);
        assert_eq!(class.name(), name);
    }
}

/// #427: condrv's primary dispatch waits (KeWaitForSingleObject) for conhost's GET_NEXT_REQUEST,
/// a second IRP to the same driver. A primary parked in its wait releases the execution token,
/// so the instance's worker lane admits that IRP while the primary stays unready.
#[test]
fn worker_admits_a_dispatch_while_the_primary_dispatch_is_parked_in_a_wait() {
    let mut lanes = Lanes::new(2, 2);
    let mut peers = PeerRegistry::new(20, 2);
    let (primary_lane, mut primary_registration) = lanes.allocate_shared_staged(&mut peers, 1, 2, LaneBinding {
        executor_id: 10,
        receive_endpoint: 20,
        reply_object: 30,
    }).unwrap();
    let (worker_lane, mut registration) = lanes.allocate_shared_staged(&mut peers, 1, 2, LaneBinding {
        executor_id: 11,
        receive_endpoint: 20,
        reply_object: 31,
    }).unwrap();
    let primary = peers.publish_lane(&mut primary_registration, 1, 2, &lanes).unwrap();
    let worker = peers.publish_lane(&mut registration, 1, 2, &lanes).unwrap();
    for (lane, reply) in [(primary_lane, 30), (worker_lane, 31)] {
        lanes.begin_startup(lane, reply,
            |_, _| Ok::<_, u8>(ReplyBindingObservation::Free)).unwrap();
        lanes.complete_startup(lane, reply,
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)).unwrap();
    }
    let mut receiver = IngressReceiver::new(20, 40, 3).unwrap();
    let mut pool = IngressReplyPool::new(20, 3).unwrap();
    for reply in [41, 42, 43] {
        pool.insert(ComponentIngress::new(20, reply).unwrap(), &receiver, &lanes, free)
            .ok().unwrap();
    }
    let rebind = |_: u64, reply: u64| Ok::<_, u8>(if reply == 30 || reply == 31 {
        ReplyBindingObservation::Free
    } else {
        ReplyBindingObservation::BoundToTarget
    });
    call(&mut receiver, &lanes);
    pool.retain(&mut receiver, &lanes, &mut peers, primary.badge(), free, bound).unwrap();
    let primary_dispatch = pool.admit(&mut receiver, primary, &mut lanes, &peers, 1, 2, rebind)
        .unwrap();
    let primary_reply = lanes.binding(primary_dispatch.lane).unwrap().reply_object;
    // The primary dispatch parks in its provider wait.
    lanes.suspend_running(primary_dispatch.lane, primary_reply, 77).unwrap();
    assert!(!lanes.execution_busy());

    // Nothing runs while the primary waits, so the next Call is received with no owner (#420's
    // root event boundary), not on behalf of the parked dispatch.
    call(&mut receiver, &lanes);
    pool.retain(&mut receiver, &lanes, &mut peers, worker.badge(), free, bound).unwrap();
    assert!(!pool.ready_for_admission(&receiver, primary, &lanes));
    assert!(pool.ready_for_admission(&receiver, worker, &lanes));
    let worker_dispatch = pool.admit(&mut receiver, worker, &mut lanes, &peers, 1, 2, rebind)
        .unwrap();
    assert_ne!(worker_dispatch.lane, primary_dispatch.lane);
    assert_eq!(lanes.active_dispatch_identity(primary_dispatch.lane), Ok(Some(primary_dispatch)));
}

/// condrv's two lanes after cmd's request parked the primary in its KeWait (#427): the primary
/// dispatch is suspended, and the next Call is retained for the worker route.
fn condrv_with_parked_primary() -> (Lanes, IngressReceiver<u64>, IngressReplyPool<u64>, PeerRoute, PeerRoute) {
    let mut lanes = Lanes::new(2, 2);
    let mut peers = PeerRegistry::new(20, 2);
    let (primary_lane, mut primary_registration) = lanes.allocate_shared_staged(&mut peers, 1, 2,
        LaneBinding { executor_id: 10, receive_endpoint: 20, reply_object: 30 }).unwrap();
    let (worker_lane, mut worker_registration) = lanes.allocate_shared_staged(&mut peers, 1, 2,
        LaneBinding { executor_id: 11, receive_endpoint: 20, reply_object: 31 }).unwrap();
    let primary = peers.publish_lane(&mut primary_registration, 1, 2, &lanes).unwrap();
    let worker = peers.publish_lane(&mut worker_registration, 1, 2, &lanes).unwrap();
    for (lane, reply) in [(primary_lane, 30), (worker_lane, 31)] {
        lanes.begin_startup(lane, reply, |_, _| Ok::<_, u8>(ReplyBindingObservation::Free)).unwrap();
        lanes.complete_startup(lane, reply,
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)).unwrap();
    }
    let mut receiver = IngressReceiver::new(20, 40, 3).unwrap();
    let mut pool = IngressReplyPool::new(20, 3).unwrap();
    for reply in [41, 42, 43] {
        pool.insert(ComponentIngress::new(20, reply).unwrap(), &receiver, &lanes, free).ok().unwrap();
    }
    let rebind = |_: u64, reply: u64| Ok::<_, u8>(if reply == 30 || reply == 31 {
        ReplyBindingObservation::Free
    } else {
        ReplyBindingObservation::BoundToTarget
    });
    call(&mut receiver, &lanes);
    pool.retain(&mut receiver, &lanes, &mut peers, primary.badge(), free, bound).unwrap();
    let parked = pool.admit(&mut receiver, primary, &mut lanes, &peers, 1, 2, rebind).unwrap();
    let parked_reply = lanes.binding(parked.lane).unwrap().reply_object;
    lanes.suspend_running(parked.lane, parked_reply, 77).unwrap();
    call(&mut receiver, &lanes);
    pool.retain(&mut receiver, &lanes, &mut peers, worker.badge(), free, bound).unwrap();
    (lanes, receiver, pool, primary, worker)
}

/// Boot 44969720271: dxgkrnl's PsCreateSystemThread thread waited for the whole boot, and a
/// waiter row alone made its primary count as "waiting". A system-thread or DPC wait is not a
/// parked dispatch: the primary is idle, and its IRPs stay on it.
#[test]
fn a_system_thread_waiter_never_makes_an_idle_primary_parked() {
    let mut lanes = Lanes::new(2, 2);
    let mut peers = PeerRegistry::new(20, 2);
    let (primary, _) = lanes.allocate_shared_staged(&mut peers, 1, 2,
        LaneBinding { executor_id: 10, receive_endpoint: 20, reply_object: 30 }).unwrap();
    lanes.begin_startup(primary, 30, |_, _| Ok::<_, u8>(ReplyBindingObservation::Free)).unwrap();
    lanes.complete_startup(primary, 30,
        |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)).unwrap();
    // The system thread's wait carries no dispatch of the primary.
    assert!(!crate::primary_dispatch_parked(&lanes, primary, None));
}

/// condrv: cmd's request is the primary's current dispatch, parked in its own KeWait. That
/// primary diverts the next IRP, whatever its major, to the idle worker.
#[test]
fn a_primary_parked_in_its_own_dispatch_diverts_any_major_to_the_worker() {
    let (lanes, receiver, pool, primary, worker) = condrv_with_parked_primary();
    let parked = lanes.active_dispatch_identity(primary.identity().lane).unwrap();
    assert!(parked.is_some());
    assert!(crate::primary_dispatch_parked(&lanes, primary.identity().lane, parked));
    // Another dispatch's parked wait is not this primary's.
    let mut other = parked.unwrap();
    other = LaneDispatchIdentity { epoch: other.epoch + 1, ..other };
    assert!(!crate::primary_dispatch_parked(&lanes, primary.identity().lane, Some(other)));
    let lane = nt_hosted_runtime::select_ordinary_irp_lane(
        pool.ready_for_admission(&receiver, primary, &lanes),
        crate::primary_dispatch_parked(&lanes, primary.identity().lane, parked),
        pool.ready_for_admission(&receiver, worker, &lanes),
    );
    assert_eq!(lane, nt_hosted_runtime::OrdinaryIrpLane::Worker);
    assert!(nt_hosted_runtime::worker_lane_dispatches_major(0x1b), "IRP_MJ_PNP is not excluded");
}
