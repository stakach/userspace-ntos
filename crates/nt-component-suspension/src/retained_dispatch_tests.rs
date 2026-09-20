use super::*;
use crate::peer_registry::{PeerPhase, PeerRoute};
use crate::{
    ComponentIngress, IngressError, IngressObservation, IngressReplyObservation, LaneBinding,
    RetainedIngressError,
};

type Lanes = ComponentSuspensionLanes<(), (), ()>;

fn setup() -> (Lanes, PeerRegistry, PeerRoute, RetainedIngress<u64>) {
    let mut lanes = Lanes::new(2, 4);
    let lane = lanes
        .allocate(LaneBinding {
            executor_id: 10,
            receive_endpoint: 20,
            reply_object: 30,
        })
        .unwrap();
    let mut peers = PeerRegistry::new(20, 2);
    let mut registration = peers.stage_lane(1, 2, &lanes, lane).unwrap();
    let route = peers.publish_lane(&mut registration, 1, 2, &lanes).unwrap();
    let mut ingress = ComponentIngress::new(20, 40).unwrap();
    let mut receive = lanes.begin_ingress_receive(&mut ingress).unwrap();
    assert!(ingress
        .observe_receive(&mut receive, IngressObservation::Call(123))
        .is_ok());
    let retained = lanes
        .retain_peer_ingress(
            &mut ingress,
            ComponentIngress::new(20, 41).unwrap(),
            &mut peers,
            route.badge(),
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
        )
        .ok()
        .unwrap();
    (lanes, peers, route, retained)
}

fn proof(executor: u64, reply: u64) -> Result<ReplyBindingObservation, u8> {
    assert_eq!(executor, 10);
    Ok(match reply {
        30 => ReplyBindingObservation::Free,
        40 => ReplyBindingObservation::BoundToTarget,
        _ => panic!("unexpected Reply query"),
    })
}

fn unchanged(
    lanes: &Lanes,
    peers: &PeerRegistry,
    route: PeerRoute,
    retained: &RetainedIngress<u64>,
) {
    let lane = route.identity().lane;
    assert_eq!(lanes.binding(lane).unwrap().reply_object, 30);
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(None));
    assert_eq!(retained.reply(), 40);
    assert_eq!(*retained.message(), 123);
    assert_eq!(retained.admitted, None);
    assert_eq!(peers.state(route).unwrap().1, 1);
}

fn ack(retained: &mut RetainedIngress<u64>) {
    let mut attempt = retained.begin_reply().unwrap();
    retained
        .observe_reply(&mut attempt, IngressReplyObservation::Acknowledged)
        .unwrap();
}

#[test]
fn adoption_rotates_reply_with_fresh_epoch_and_retains_canonical_exclusion_after_ack() {
    let (mut lanes, mut peers, route, mut retained) = setup();
    let mut queries = alloc::vec::Vec::new();
    let admitted = lanes
        .begin_retained_dispatch(&peers, &mut retained, 1, 2, |executor, reply| {
            queries.push((executor, reply));
            proof(executor, reply)
        })
        .unwrap();
    assert_eq!(queries, [(10, 30), (10, 40)]);
    assert_eq!(admitted.lane, route.identity().lane);
    assert_eq!(admitted.displaced_reply, 30);
    assert_ne!(admitted.dispatch.epoch, 0);
    assert_eq!(
        lanes.active_dispatch_identity(admitted.lane),
        Ok(Some(admitted.dispatch))
    );
    assert_eq!(lanes.binding(admitted.lane).unwrap().reply_object, 40);
    assert_eq!(peers.state(route), Ok((PeerPhase::Active, 1)));
    assert_eq!(
        lanes.finish_dispatch(admitted.lane, 30),
        Err(LaneError::WrongBinding)
    );
    ack(&mut retained);
    let (error, mut retained) = retained.finish(&mut peers).err().unwrap();
    assert_eq!(error, RetainedIngressError::DispatchActive);
    assert_eq!(peers.state(route), Ok((PeerPhase::Active, 1)));
    lanes.finish_retained_dispatch(&mut retained).unwrap();
    let (mut ready, payload) = retained.finish(&mut peers).ok().unwrap();
    assert_eq!(payload, 123);
    assert_eq!(peers.state(route), Ok((PeerPhase::Active, 0)));
    assert_eq!(
        lanes.begin_ingress_receive(&mut ready).unwrap_err(),
        IngressError::ReplyInUse
    );
    let mut displaced = ComponentIngress::<u64>::new(20, admitted.displaced_reply).unwrap();
    let mut receive = lanes.begin_ingress_receive(&mut displaced).unwrap();
    assert!(displaced
        .observe_receive(&mut receive, IngressObservation::Call(456))
        .is_ok());
    let mut second = lanes
        .retain_peer_ingress(
            &mut displaced,
            ComponentIngress::new(20, 42).unwrap(),
            &mut peers,
            route.badge(),
            |_, reply| {
                assert_eq!(reply, 30);
                Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)
            },
        )
        .ok()
        .unwrap();
    let next = lanes
        .begin_retained_dispatch(&peers, &mut second, 1, 2, |executor, reply| {
            assert_eq!(executor, 10);
            Ok::<_, u8>(match reply {
                40 => ReplyBindingObservation::Free,
                30 => ReplyBindingObservation::BoundToTarget,
                _ => panic!("unexpected rotated Reply"),
            })
        })
        .unwrap();
    assert_eq!(next.displaced_reply, 40);
    assert_ne!(next.dispatch, admitted.dispatch);
    assert_eq!(lanes.binding(next.lane).unwrap().reply_object, 30);
    lanes.finish_retained_dispatch(&mut second).unwrap();
    assert!(lanes.begin_ingress_receive(&mut ready).is_ok());
    ack(&mut second);
    let (mut second_ready, payload) = second.finish(&mut peers).ok().unwrap();
    assert_eq!(payload, 456);
    assert_eq!(
        lanes.begin_ingress_receive(&mut second_ready).unwrap_err(),
        IngressError::ReplyInUse
    );
}

#[test]
fn rejected_old_reply_states_preserve_all_ownership_and_skip_incoming_query() {
    for observation in [
        ReplyBindingObservation::Offered,
        ReplyBindingObservation::BoundToTarget,
        ReplyBindingObservation::BoundElsewhere,
    ] {
        let (mut lanes, peers, route, mut retained) = setup();
        let mut count = 0;
        assert_eq!(
            lanes.begin_retained_dispatch(&peers, &mut retained, 1, 2, |executor, reply| {
                assert_eq!((executor, reply), (10, 30));
                count += 1;
                Ok::<_, u8>(observation)
            }),
            Err(RetainedDispatchError::OldReplyNotFree)
        );
        assert_eq!(count, 1);
        unchanged(&lanes, &peers, route, &retained);
    }
}

#[test]
fn incoming_binding_mismatch_and_each_query_error_preserve_all_ownership() {
    for observation in [
        ReplyBindingObservation::Free,
        ReplyBindingObservation::Offered,
        ReplyBindingObservation::BoundElsewhere,
    ] {
        let (mut lanes, peers, route, mut retained) = setup();
        assert_eq!(
            lanes.begin_retained_dispatch(&peers, &mut retained, 1, 2, |_, reply| {
                Ok::<_, u8>(if reply == 30 {
                    ReplyBindingObservation::Free
                } else {
                    observation
                })
            }),
            Err(RetainedDispatchError::BindingMismatch)
        );
        unchanged(&lanes, &peers, route, &retained);
    }
    for failing_reply in [30, 40] {
        let (mut lanes, peers, route, mut retained) = setup();
        assert_eq!(
            lanes.begin_retained_dispatch(&peers, &mut retained, 1, 2, |executor, reply| {
                if reply == failing_reply {
                    Err(9)
                } else {
                    proof(executor, reply)
                }
            }),
            Err(RetainedDispatchError::Query(9))
        );
        unchanged(&lanes, &peers, route, &retained);
    }
}

#[test]
fn epoch_exhaustion_does_not_swap_reply_or_mark_retention_admitted() {
    for value in [0, u64::MAX] {
        let (mut lanes, peers, route, mut retained) = setup();
        let counter = core::sync::atomic::AtomicU64::new(value);
        assert_eq!(
            lanes.begin_retained_dispatch_with_counter(
                &peers,
                &mut retained,
                1,
                2,
                proof,
                &counter,
            ),
            Err(RetainedDispatchError::Lane(LaneError::NoCapacity))
        );
        unchanged(&lanes, &peers, route, &retained);
        assert_eq!(
            lanes.finish_retained_dispatch(&mut retained),
            Err(RetainedDispatchError::NotAdmitted)
        );
    }
}

#[test]
fn wrong_domain_and_retiring_or_foreign_registry_never_query() {
    let (mut lanes, mut peers, route, mut retained) = setup();
    for (domain, generation) in [(0, 2), (1, 0), (2, 2), (1, 3)] {
        assert!(lanes
            .begin_retained_dispatch(
                &peers,
                &mut retained,
                domain,
                generation,
                |_, _| -> Result<_, u8> { panic!("wrong domain queried") }
            )
            .is_err());
        unchanged(&lanes, &peers, route, &retained);
    }
    let foreign = PeerRegistry::new(20, 2);
    assert!(lanes
        .begin_retained_dispatch(&foreign, &mut retained, 1, 2, |_, _| -> Result<_, u8> {
            panic!("foreign registry queried")
        })
        .is_err());
    peers.begin_retirement(route).unwrap();
    assert!(lanes
        .begin_retained_dispatch(&peers, &mut retained, 1, 2, |_, _| -> Result<_, u8> {
            panic!("retiring peer queried")
        })
        .is_err());
    unchanged(&lanes, &peers, route, &retained);
}

#[test]
fn stale_lane_and_incoming_aliases_never_query_or_change_owner() {
    let (mut lanes, peers, route, mut retained) = setup();
    let binding = lanes.release(route.identity().lane, 30).unwrap();
    let replacement = lanes.allocate(binding).unwrap();
    assert_ne!(replacement, route.identity().lane);
    assert!(lanes
        .begin_retained_dispatch(&peers, &mut retained, 1, 2, |_, _| -> Result<_, u8> {
            panic!("stale lane queried")
        })
        .is_err());
    assert_eq!(lanes.binding(replacement), Ok(binding));
    assert_eq!(*retained.message(), 123);
    for alias_self in [false, true] {
        let (mut lanes, peers, route, mut retained) = setup();
        if alias_self {
            lanes
                .lane_mut(route.identity().lane)
                .unwrap()
                .binding
                .reply_object = 40;
        } else {
            lanes
                .allocate(LaneBinding {
                    executor_id: 11,
                    receive_endpoint: 21,
                    reply_object: 40,
                })
                .unwrap();
        }
        assert_eq!(
            lanes.begin_retained_dispatch(&peers, &mut retained, 1, 2, |_, _| -> Result<_, u8> {
                panic!("aliased Reply queried")
            }),
            Err(RetainedDispatchError::ReplyInUse)
        );
        assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Idle));
        assert_eq!(peers.state(route), Ok((PeerPhase::Active, 1)));
    }
}

#[test]
fn reply_in_progress_indeterminate_and_acknowledged_are_not_held_calls() {
    for observation in [
        None,
        Some(IngressReplyObservation::Indeterminate),
        Some(IngressReplyObservation::Acknowledged),
    ] {
        let (mut lanes, peers, route, mut retained) = setup();
        let mut attempt = retained.begin_reply().unwrap();
        if let Some(observation) = observation {
            retained.observe_reply(&mut attempt, observation).unwrap();
        }
        assert_eq!(
            lanes.begin_retained_dispatch(&peers, &mut retained, 1, 2, |_, _| -> Result<_, u8> {
                panic!("unheld Call queried")
            }),
            Err(RetainedDispatchError::NotHeld)
        );
        unchanged(&lanes, &peers, route, &retained);
    }
    let (mut lanes, peers, _, mut retained) = setup();
    let mut attempt = retained.begin_reply().unwrap();
    retained
        .observe_reply(&mut attempt, IngressReplyObservation::NoEffects)
        .unwrap();
    assert!(lanes
        .begin_retained_dispatch(&peers, &mut retained, 1, 2, proof)
        .is_ok());
}

#[test]
fn busy_physical_domain_and_suspended_lane_cannot_adopt() {
    for suspend in [false, true] {
        let (mut lanes, peers, route, mut retained) = setup();
        let lane = route.identity().lane;
        lanes.begin_dispatch(lane, 30).unwrap();
        if suspend {
            lanes.suspend_running(lane, 30, 7).unwrap();
        }
        let before = lanes.active_dispatch_identity(lane).unwrap();
        assert!(lanes
            .begin_retained_dispatch(&peers, &mut retained, 1, 2, |_, _| -> Result<_, u8> {
                panic!("busy lane queried")
            })
            .is_err());
        assert_eq!(lanes.active_dispatch_identity(lane), Ok(before));
        assert_eq!(lanes.binding(lane).unwrap().reply_object, 30);
        assert_eq!(*retained.message(), 123);
    }
}

#[test]
fn suspended_or_changed_dispatch_cannot_clear_retained_admission() {
    let (mut lanes, mut peers, route, mut retained) = setup();
    let admission = lanes
        .begin_retained_dispatch(&peers, &mut retained, 1, 2, proof)
        .unwrap();
    lanes.suspend_running(admission.lane, 40, 7).unwrap();
    ack(&mut retained);
    assert!(lanes.finish_retained_dispatch(&mut retained).is_err());
    let (error, mut retained) = retained.finish(&mut peers).err().unwrap();
    assert_eq!(error, RetainedIngressError::DispatchActive);
    lanes.resume_external(admission.lane, 40, 7).unwrap();
    lanes.complete_external(admission.lane, 40, 7).unwrap();
    lanes.begin_dispatch(admission.lane, 40).unwrap();
    assert_ne!(
        lanes.active_dispatch_identity(admission.lane),
        Ok(Some(admission.dispatch))
    );
    assert_eq!(
        lanes.finish_retained_dispatch(&mut retained),
        Err(RetainedDispatchError::DispatchMismatch)
    );
    let (error, retained) = retained.finish(&mut peers).err().unwrap();
    assert_eq!(error, RetainedIngressError::DispatchActive);
    assert_eq!(*retained.message(), 123);
    assert_eq!(peers.state(route), Ok((PeerPhase::Active, 1)));
}

#[test]
fn resumed_external_continuation_retires_before_exact_dispatch_completion() {
    let (mut lanes, mut peers, route, mut retained) = setup();
    let admission = lanes
        .begin_retained_dispatch(&peers, &mut retained, 1, 2, proof)
        .unwrap();
    lanes.suspend_running(admission.lane, 40, 7).unwrap();
    assert!(lanes.finish_retained_dispatch(&mut retained).is_err());
    lanes.resume_external(admission.lane, 40, 7).unwrap();
    assert!(lanes.finish_retained_dispatch(&mut retained).is_err());
    assert_eq!(retained.admitted, Some(admission.dispatch));
    lanes
        .retire_external_running(admission.lane, 40, 7)
        .unwrap();
    assert_eq!(
        lanes.active_dispatch_identity(admission.lane),
        Ok(Some(admission.dispatch))
    );
    lanes.finish_retained_dispatch(&mut retained).unwrap();
    assert_eq!(retained.admitted, None);
    assert_eq!(lanes.phase(admission.lane), Ok(LanePhase::Idle));
    assert_eq!(peers.state(route), Ok((PeerPhase::Active, 1)));
    ack(&mut retained);
    assert_eq!(retained.finish(&mut peers).ok().unwrap().1, 123);
    assert_eq!(peers.state(route), Ok((PeerPhase::Active, 0)));
}
