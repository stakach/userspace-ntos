use super::*;
use crate::{LaneBinding, LanePhase};

type Lanes = ComponentSuspensionLanes<(), (), ()>;

fn setup() -> (Lanes, PeerRegistry, PeerRoute, IngressReceiver<u64>) {
    let mut lanes = Lanes::new(1, 2);
    let mut peers = PeerRegistry::new(20, 1);
    let (_, mut ticket) = lanes
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
    let route = peers.publish_lane(&mut ticket, 1, 2, &lanes).unwrap();
    (
        lanes,
        peers,
        route,
        IngressReceiver::new(20, 40, 1).unwrap(),
    )
}

fn start(lanes: &mut Lanes, route: PeerRoute) {
    lanes
        .begin_startup(route.identity().lane, 30, |_, _| {
            Ok::<_, u8>(ReplyBindingObservation::Free)
        })
        .unwrap();
}

#[test]
fn startup_receive_retains_call_without_creating_dispatch_or_releasing_fence() {
    let (mut lanes, mut peers, route, mut owner) = setup();
    start(&mut lanes, route);
    owner
        .begin_receive_for_owner(&lanes, IngressExecutionOwner::Startup(route))
        .unwrap();
    owner.capture(123).unwrap();
    owner.resolve(IngressReceiveDisposition::Call).unwrap();
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
    assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Starting));
    assert_eq!(lanes.running(), Some(route.identity().lane));
    assert_eq!(
        lanes.active_dispatch_identity(route.identity().lane),
        Err(crate::LaneError::InvalidPhase)
    );
    assert_eq!(peers.state(route).unwrap().1, 1);
    assert_eq!(*owner.checkout(route).unwrap().call().message(), 123);
}

#[test]
fn startup_receive_rejects_staged_foreign_and_completed_owners() {
    let (mut lanes, _, route, mut owner) = setup();
    assert!(owner
        .begin_receive_for_owner(&lanes, IngressExecutionOwner::Startup(route))
        .is_err());
    assert_eq!(owner.available(), 1);
    start(&mut lanes, route);
    let (mut foreign, _, other, _) = setup();
    start(&mut foreign, other);
    assert_eq!(other.identity().lane, route.identity().lane);
    assert!(owner
        .begin_receive_for_owner(&foreign, IngressExecutionOwner::Startup(route))
        .is_err());
    assert_eq!(owner.available(), 1);
    lanes
        .complete_startup(route.identity().lane, 30, |_, _| {
            Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)
        })
        .unwrap();
    assert!(owner
        .begin_receive_for_owner(&lanes, IngressExecutionOwner::Startup(route))
        .is_err());
    assert_eq!(owner.available(), 1);
}

#[test]
fn startup_transition_after_receive_preserves_held_call_on_handoff_refusal() {
    let (mut lanes, mut peers, route, mut owner) = setup();
    start(&mut lanes, route);
    owner
        .begin_receive_for_owner(&lanes, IngressExecutionOwner::Startup(route))
        .unwrap();
    owner.capture(123).unwrap();
    owner.resolve(IngressReceiveDisposition::Call).unwrap();
    lanes
        .complete_startup(route.identity().lane, 30, |_, _| {
            Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)
        })
        .unwrap();
    assert!(owner
        .retain(
            &lanes,
            ComponentIngress::new(20, 41).unwrap(),
            &mut peers,
            route.badge(),
            |_, _| -> Result<ReplyBindingObservation, u8> { panic!("stale startup owner") }
        )
        .is_err());
    assert_eq!(owner.message(), Some(&123));
    assert_eq!(owner.phase(), Some(ReservedReceivePhase::Held));
    assert_eq!(owner.available(), 0);
    assert_eq!(peers.state(route).unwrap().1, 0);
}
