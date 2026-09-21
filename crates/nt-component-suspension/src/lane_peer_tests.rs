use super::*;
use crate::peer_registry::PeerPhase;
use crate::{LaneBinding, LanePhase};

type Lanes = ComponentSuspensionLanes<(), (), ()>;

fn second_binding() -> LaneBinding {
    LaneBinding {
        executor_id: 44,
        reply_object: 66,
        ..binding()
    }
}

#[test]
fn shared_allocation_stages_distinct_authenticated_peers_without_execution() {
    let mut lanes = Lanes::new(2, 4);
    let mut peers = PeerRegistry::new(22, 2);
    let (first, mut a) = lanes
        .allocate_shared_staged(&mut peers, 7, 8, binding())
        .unwrap();
    let (second, mut b) = lanes
        .allocate_shared_staged(&mut peers, 7, 8, second_binding())
        .unwrap();
    assert_ne!(a.route().unwrap().badge(), b.route().unwrap().badge());
    for (lane, reply) in [(first, 33), (second, 66)] {
        assert_eq!(lanes.phase(lane), Ok(LanePhase::Staged));
        assert_eq!(
            lanes.begin_dispatch(lane, reply),
            Err(LaneError::InvalidPhase)
        );
    }
    let ar = peers.publish_lane(&mut a, 7, 8, &lanes).unwrap();
    let br = peers.publish_lane(&mut b, 7, 8, &lanes).unwrap();
    assert_eq!(peers.resolve_lane(ar.badge(), 7, 8, &lanes), Ok(ar));
    assert_eq!(peers.resolve_lane(br.badge(), 7, 8, &lanes), Ok(br));
    assert_eq!(lanes.running(), None);
}

#[test]
fn shared_endpoint_preserves_distinct_provider_domains_and_generations() {
    for (domain, generation) in [(9, 8), (7, 9), (9, 10)] {
        let mut lanes = Lanes::new(2, 4);
        let mut peers = PeerRegistry::new(22, 2);
        let (first, mut a) = lanes
            .allocate_shared_staged(&mut peers, 7, 8, binding())
            .unwrap();
        let ar = peers.publish_lane(&mut a, 7, 8, &lanes).unwrap();
        let (second, mut b) = lanes
            .allocate_shared_staged(&mut peers, domain, generation, second_binding())
            .unwrap();
        assert_eq!(
            peers.publish_lane(&mut b, 7, 8, &lanes),
            Err(PeerLaneError::Peer(PeerError::WrongOwner))
        );
        let br = peers
            .publish_lane(&mut b, domain, generation, &lanes)
            .unwrap();
        assert_ne!(ar.badge(), br.badge());
        assert_eq!(peers.resolve_lane(ar.badge(), 7, 8, &lanes), Ok(ar));
        assert_eq!(
            peers.resolve_lane(br.badge(), domain, generation, &lanes),
            Ok(br)
        );
        assert_eq!(
            peers.resolve_lane(ar.badge(), domain, generation, &lanes),
            Err(PeerLaneError::Peer(PeerError::WrongOwner))
        );
        assert_eq!(
            peers.resolve_lane(br.badge(), 7, 8, &lanes),
            Err(PeerLaneError::Peer(PeerError::WrongOwner))
        );
        assert_eq!(lanes.phase(first), Ok(LanePhase::Staged));
        assert_eq!(lanes.phase(second), Ok(LanePhase::Staged));
        assert_eq!(lanes.running(), None);
    }
}

#[test]
fn unpublished_peers_from_different_domains_can_share_ingress() {
    let mut lanes = Lanes::new(2, 4);
    let mut peers = PeerRegistry::new(22, 2);
    let (_, mut a) = lanes
        .allocate_shared_staged(&mut peers, 7, 8, binding())
        .unwrap();
    let (_, mut b) = lanes
        .allocate_shared_staged(&mut peers, 9, 10, second_binding())
        .unwrap();
    let ar = a.route().unwrap();
    let br = b.route().unwrap();
    assert_eq!(peers.state(ar), Ok((PeerPhase::Staged, 0)));
    assert_eq!(peers.state(br), Ok((PeerPhase::Staged, 0)));
    assert_eq!(peers.resolve(ar.badge()), None);
    assert_eq!(peers.resolve(br.badge()), None);
    assert_eq!(peers.publish_lane(&mut b, 9, 10, &lanes), Ok(br));
    assert_eq!(peers.publish_lane(&mut a, 7, 8, &lanes), Ok(ar));
    assert_eq!(lanes.running(), None);
}

#[test]
fn private_and_shared_endpoint_ownership_cannot_mix() {
    let (mut private, _, mut peers) = setup();
    assert_eq!(
        private
            .allocate_shared_staged(&mut peers, 9, 10, second_binding())
            .unwrap_err(),
        PeerLaneError::Lane(LaneError::DuplicateBinding)
    );
    let mut shared = Lanes::new(2, 4);
    let _ticket = shared
        .allocate_shared_staged(&mut peers, 7, 8, binding())
        .unwrap();
    assert_eq!(
        shared.allocate(second_binding()),
        Err(LaneError::DuplicateBinding)
    );
    assert_eq!(
        shared.allocate_staged(second_binding()),
        Err(LaneError::DuplicateBinding)
    );
    assert_eq!(private.len(), 1);
    assert_eq!(shared.len(), 1);
}

#[test]
fn shared_allocation_rejects_foreign_registry_zero_identity_and_retired_identity() {
    let mut lanes = Lanes::new(2, 4);
    let mut peers = PeerRegistry::new(22, 2);
    let (_, mut ticket) = lanes
        .allocate_shared_staged(&mut peers, 7, 8, binding())
        .unwrap();
    let mut foreign = PeerRegistry::new(22, 2);
    assert_eq!(
        lanes
            .allocate_shared_staged(&mut foreign, 7, 8, second_binding())
            .unwrap_err(),
        PeerLaneError::Peer(PeerError::WrongOwner)
    );
    for (domain, generation) in [(0, 8), (7, 0)] {
        assert_eq!(
            lanes
                .allocate_shared_staged(&mut peers, domain, generation, second_binding())
                .unwrap_err(),
            PeerLaneError::Peer(PeerError::WrongOwner)
        );
    }
    let route = peers.publish_lane(&mut ticket, 7, 8, &lanes).unwrap();
    peers.begin_retirement(route).unwrap();
    assert_eq!(
        lanes
            .allocate_shared_staged(&mut peers, 9, 10, second_binding())
            .unwrap_err(),
        PeerLaneError::Peer(PeerError::WrongPhase)
    );
    peers.finish_retirement(route).unwrap();
    assert_eq!(
        lanes
            .allocate_shared_staged(&mut peers, 9, 10, second_binding())
            .unwrap_err(),
        PeerLaneError::Peer(PeerError::WrongOwner)
    );
    assert_eq!(lanes.len(), 1);
}

#[test]
fn shared_peer_capacity_failure_rolls_back_only_unpublished_lane() {
    let mut lanes = Lanes::new(2, 4);
    let mut full = PeerRegistry::new(22, 0);
    assert_eq!(
        lanes
            .allocate_shared_staged(&mut full, 7, 8, binding())
            .unwrap_err(),
        PeerLaneError::Peer(PeerError::NoCapacity)
    );
    assert!(lanes.is_empty());
    let mut peers = PeerRegistry::new(22, 1);
    let (first, ticket) = lanes
        .allocate_shared_staged(&mut peers, 7, 8, binding())
        .unwrap();
    assert_eq!(first.generation, 2);
    assert_eq!(
        lanes
            .allocate_shared_staged(&mut peers, 7, 8, second_binding())
            .unwrap_err(),
        PeerLaneError::Peer(PeerError::NoCapacity)
    );
    assert_eq!(lanes.len(), 1);
    assert_eq!(
        peers.state(ticket.route().unwrap()),
        Ok((PeerPhase::Staged, 0))
    );
}

#[test]
fn shared_allocation_preserves_executor_reply_and_lane_capacity_checks() {
    let mut lanes = Lanes::new(1, 4);
    let mut peers = PeerRegistry::new(22, 3);
    let _ticket = lanes
        .allocate_shared_staged(&mut peers, 7, 8, binding())
        .unwrap();
    for duplicate in [
        LaneBinding {
            executor_id: 11,
            ..second_binding()
        },
        LaneBinding {
            reply_object: 33,
            ..second_binding()
        },
    ] {
        assert_eq!(
            lanes
                .allocate_shared_staged(&mut peers, 9, 10, duplicate)
                .unwrap_err(),
            PeerLaneError::Lane(LaneError::DuplicateBinding)
        );
    }
    assert_eq!(
        lanes
            .allocate_shared_staged(&mut peers, 7, 8, second_binding())
            .unwrap_err(),
        PeerLaneError::Lane(LaneError::NoCapacity)
    );
    assert_eq!(lanes.len(), 1);
}

fn binding() -> LaneBinding {
    LaneBinding {
        executor_id: 11,
        receive_endpoint: 22,
        reply_object: 33,
    }
}

fn setup() -> (Lanes, LaneHandle, PeerRegistry) {
    let mut lanes = Lanes::new(2, 4);
    let lane = lanes.allocate(binding()).unwrap();
    (lanes, lane, PeerRegistry::new(22, 1))
}

fn publish(peers: &mut PeerRegistry, lanes: &Lanes, lane: LaneHandle) -> PeerRoute {
    let mut registration = peers.stage_lane(7, 8, lanes, lane).unwrap();
    peers.publish_lane(&mut registration, 7, 8, lanes).unwrap()
}

fn assert_idle(lanes: &Lanes, lane: LaneHandle) {
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(None));
    assert_eq!(lanes.running(), None);
}

#[test]
fn staging_derives_executor_and_rejects_wrong_endpoint_without_reserving_capacity() {
    let (lanes, lane, mut peers) = setup();
    let mut other = Lanes::new(1, 4);
    let wrong = other
        .allocate(LaneBinding {
            receive_endpoint: 23,
            ..binding()
        })
        .unwrap();
    assert_eq!(
        peers.stage_lane(7, 8, &other, wrong).unwrap_err(),
        PeerLaneError::Peer(PeerError::WrongOwner)
    );
    let registration = peers.stage_lane(7, 8, &lanes, lane).unwrap();
    let route = registration.route().unwrap();
    assert_eq!(route.endpoint(), 22);
    assert_eq!(
        route.identity(),
        PeerIdentity {
            domain: 7,
            domain_generation: 8,
            executor: 11,
            lane,
        }
    );
    assert_eq!(peers.state(route), Ok((PeerPhase::Staged, 0)));
    assert_eq!(peers.resolve(route.badge()), None);
}

#[test]
fn stale_generation_publication_preserves_registration_for_abort() {
    let (mut lanes, lane, mut peers) = setup();
    let mut registration = peers.stage_lane(7, 8, &lanes, lane).unwrap();
    let route = registration.route().unwrap();
    lanes.release(lane, 33).unwrap();
    let replacement = lanes.allocate(binding()).unwrap();
    assert_eq!(replacement.index, lane.index);
    assert_ne!(replacement.generation, lane.generation);
    assert_eq!(
        peers.publish_lane(&mut registration, 7, 8, &lanes),
        Err(PeerLaneError::Lane(LaneError::StaleGeneration))
    );
    assert_eq!(registration.route(), Some(route));
    assert_eq!(peers.state(route), Ok((PeerPhase::Staged, 0)));
    peers.abort(&mut registration).unwrap();
    assert_eq!(registration.route(), None);
    assert_eq!(peers.state(route), Err(PeerError::WrongOwner));
    assert_idle(&lanes, replacement);
}

#[test]
fn publication_and_resolution_require_exact_nonzero_physical_domain() {
    let (lanes, lane, mut peers) = setup();
    let mut registration = peers.stage_lane(7, 8, &lanes, lane).unwrap();
    let route = registration.route().unwrap();
    for (domain, generation) in [(0, 8), (7, 0), (9, 8), (7, 9)] {
        assert_eq!(
            peers.publish_lane(&mut registration, domain, generation, &lanes),
            Err(PeerLaneError::Peer(PeerError::WrongOwner))
        );
        assert_eq!(registration.route(), Some(route));
        assert_eq!(peers.state(route), Ok((PeerPhase::Staged, 0)));
    }
    peers.publish_lane(&mut registration, 7, 8, &lanes).unwrap();
    for (domain, generation) in [(0, 8), (7, 0), (9, 8), (7, 9)] {
        assert_eq!(
            peers.resolve_lane(route.badge(), domain, generation, &lanes),
            Err(PeerLaneError::Peer(PeerError::WrongOwner))
        );
        assert_eq!(peers.state(route), Ok((PeerPhase::Active, 0)));
    }
    assert_eq!(peers.resolve_lane(route.badge(), 7, 8, &lanes), Ok(route));
}

#[test]
fn equal_handles_with_changed_executor_or_endpoint_cannot_publish_or_resolve() {
    for changed in [
        LaneBinding {
            executor_id: 12,
            ..binding()
        },
        LaneBinding {
            receive_endpoint: 23,
            ..binding()
        },
    ] {
        let (lanes, lane, mut peers) = setup();
        let mut registration = peers.stage_lane(7, 8, &lanes, lane).unwrap();
        let route = registration.route().unwrap();
        let mut replacement = Lanes::new(2, 4);
        assert_eq!(replacement.allocate(changed).unwrap(), lane);
        assert_eq!(
            peers.publish_lane(&mut registration, 7, 8, &replacement),
            Err(PeerLaneError::Peer(PeerError::WrongOwner))
        );
        assert_eq!(registration.route(), Some(route));
        peers.publish_lane(&mut registration, 7, 8, &lanes).unwrap();
        assert_eq!(
            peers.resolve_lane(route.badge(), 7, 8, &replacement),
            Err(PeerLaneError::Peer(PeerError::WrongOwner))
        );
        assert_idle(&replacement, lane);
    }
}

#[test]
fn identical_replacement_table_requires_a_new_physical_domain_generation() {
    let (lanes, lane, mut peers) = setup();
    let route = publish(&mut peers, &lanes, lane);
    let mut replacement = Lanes::new(2, 4);
    assert_eq!(replacement.allocate(binding()).unwrap(), lane);
    // The domain owner must advance its generation when replacing the entire lane table.
    assert_eq!(
        peers.resolve_lane(route.badge(), 7, 9, &replacement),
        Err(PeerLaneError::Peer(PeerError::WrongOwner))
    );
    assert_idle(&replacement, lane);
}

#[test]
fn active_route_cannot_resolve_a_released_or_reallocated_lane() {
    let (mut lanes, lane, mut peers) = setup();
    let route = publish(&mut peers, &lanes, lane);
    let ticket = peers.retain(route).unwrap();
    lanes.release(lane, 33).unwrap();
    assert_eq!(
        peers.resolve_lane(route.badge(), 7, 8, &lanes),
        Err(PeerLaneError::Lane(LaneError::NotFound))
    );
    let replacement = lanes.allocate(binding()).unwrap();
    assert_eq!(
        lanes.begin_peer_dispatch(&peers, &ticket, 7, 8, 33),
        Err(PeerLaneError::Lane(LaneError::StaleGeneration))
    );
    assert_eq!(peers.state(route), Ok((PeerPhase::Active, 1)));
    assert_idle(&lanes, replacement);
}

#[test]
fn retiring_peer_is_excluded_from_resolution_and_dispatch() {
    let (mut lanes, lane, mut peers) = setup();
    let route = publish(&mut peers, &lanes, lane);
    let ticket = peers.retain(route).unwrap();
    peers.begin_retirement(route).unwrap();
    assert_eq!(
        peers.resolve_lane(route.badge(), 7, 8, &lanes),
        Err(PeerLaneError::Peer(PeerError::WrongOwner))
    );
    assert_eq!(
        lanes.begin_peer_dispatch(&peers, &ticket, 7, 8, 33),
        Err(PeerLaneError::Peer(PeerError::WrongOwner))
    );
    assert_eq!(peers.state(route), Ok((PeerPhase::Retiring, 1)));
    assert_idle(&lanes, lane);
}

#[test]
fn admitted_dispatch_returns_exact_lane_and_fresh_epoch() {
    let (mut lanes, lane, mut peers) = setup();
    let route = publish(&mut peers, &lanes, lane);
    let ticket = peers.retain(route).unwrap();
    assert_eq!(
        lanes.begin_peer_dispatch(&peers, &ticket, 7, 8, 33),
        Ok(lane)
    );
    let first = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    assert_ne!(first.epoch(), 0);
    assert_eq!(lanes.running(), Some(lane));
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Running));
    lanes.finish_dispatch(lane, 33).unwrap();
    assert_idle(&lanes, lane);
    lanes
        .begin_peer_dispatch(&peers, &ticket, 7, 8, 33)
        .unwrap();
    let second = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    assert_ne!(first, second);
    lanes.finish_dispatch(lane, 33).unwrap();
}

#[test]
fn wrong_reply_or_peer_identity_never_transitions_the_lane() {
    let (mut lanes, lane, mut peers) = setup();
    let route = publish(&mut peers, &lanes, lane);
    let ticket = peers.retain(route).unwrap();
    for reply in [0, 34] {
        assert_eq!(
            lanes.begin_peer_dispatch(&peers, &ticket, 7, 8, reply),
            Err(PeerLaneError::Lane(LaneError::WrongBinding))
        );
        assert_idle(&lanes, lane);
    }
    for (domain, generation) in [(0, 8), (7, 0), (9, 8), (7, 9)] {
        assert_eq!(
            lanes.begin_peer_dispatch(&peers, &ticket, domain, generation, 33),
            Err(PeerLaneError::Peer(PeerError::WrongOwner))
        );
        assert_idle(&lanes, lane);
    }
}

#[test]
fn another_running_lane_prevents_peer_dispatch_without_changing_either_owner() {
    let (mut lanes, lane, mut peers) = setup();
    let route = publish(&mut peers, &lanes, lane);
    let ticket = peers.retain(route).unwrap();
    let other = lanes
        .allocate(LaneBinding {
            executor_id: 44,
            receive_endpoint: 55,
            reply_object: 66,
        })
        .unwrap();
    lanes.begin_dispatch(other, 66).unwrap();
    let dispatch = lanes.active_dispatch_identity(other).unwrap();
    assert_eq!(
        lanes.begin_peer_dispatch(&peers, &ticket, 7, 8, 33),
        Err(PeerLaneError::Lane(LaneError::Busy))
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(None));
    assert_eq!(lanes.running(), Some(other));
    assert_eq!(lanes.active_dispatch_identity(other), Ok(dispatch));
    lanes.finish_dispatch(other, 66).unwrap();
}

#[test]
fn peer_registration_does_not_relax_duplicate_endpoint_rejection() {
    let (mut lanes, lane, mut peers) = setup();
    let route = publish(&mut peers, &lanes, lane);
    assert_eq!(
        lanes.allocate(LaneBinding {
            executor_id: 44,
            receive_endpoint: 22,
            reply_object: 66,
        }),
        Err(LaneError::DuplicateBinding)
    );
    assert_eq!(lanes.len(), 1);
    assert_eq!(peers.resolve_lane(route.badge(), 7, 8, &lanes), Ok(route));
    assert_idle(&lanes, lane);
}

#[test]
fn consumed_or_wrong_registry_retention_cannot_admit_dispatch() {
    let (mut lanes, lane, mut peers) = setup();
    let route = publish(&mut peers, &lanes, lane);
    let mut ticket = peers.retain(route).unwrap();
    let mut other = PeerRegistry::new(22, 1);
    let other_route = publish(&mut other, &lanes, lane);
    assert_eq!(
        lanes.begin_peer_dispatch(&other, &ticket, 7, 8, 33),
        Err(PeerLaneError::Peer(PeerError::WrongOwner))
    );
    assert_eq!(ticket.route(), Some(route));
    assert_eq!(peers.state(route), Ok((PeerPhase::Active, 1)));
    assert_eq!(other.state(other_route), Ok((PeerPhase::Active, 0)));
    assert_idle(&lanes, lane);
    peers.release(&mut ticket).unwrap();
    assert_eq!(
        lanes.begin_peer_dispatch(&peers, &ticket, 7, 8, 33),
        Err(PeerLaneError::Peer(PeerError::WrongOwner))
    );
    assert_eq!(ticket.route(), None);
    assert_eq!(peers.state(route), Ok((PeerPhase::Active, 0)));
    assert_idle(&lanes, lane);
}

#[test]
fn suspended_lane_remains_resolvable_but_cannot_accept_a_new_dispatch() {
    let (mut lanes, lane, mut peers) = setup();
    let route = publish(&mut peers, &lanes, lane);
    let ticket = peers.retain(route).unwrap();
    lanes
        .begin_peer_dispatch(&peers, &ticket, 7, 8, 33)
        .unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap();
    lanes.suspend_running(lane, 33, 99).unwrap();
    assert_eq!(peers.resolve_lane(route.badge(), 7, 8, &lanes), Ok(route));
    assert_eq!(
        lanes.begin_peer_dispatch(&peers, &ticket, 7, 8, 33),
        Err(PeerLaneError::Lane(LaneError::InvalidPhase))
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(dispatch));
    assert_eq!(lanes.running(), None);
    assert_eq!(ticket.route(), Some(route));
    assert_eq!(peers.state(route), Ok((PeerPhase::Active, 1)));
}
