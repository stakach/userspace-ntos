use super::*;
use crate::peer_registry::PeerPhase;
use crate::{LaneBinding, LaneError, LaneHandle};

type Lanes = ComponentSuspensionLanes<(), ()>;

fn setup() -> (Lanes, LaneHandle, PeerRegistry, PeerInstallation) {
    let mut lanes = Lanes::new(1, 1);
    let lane = lanes
        .allocate(LaneBinding {
            executor_id: 11,
            receive_endpoint: 22,
            reply_object: 33,
        })
        .unwrap();
    let mut peers = PeerRegistry::new(22, 1);
    let registration = peers.stage_lane(7, 8, &lanes, lane).unwrap();
    let owner = PeerInstallation::new(registration, 44).ok().unwrap();
    (lanes, lane, peers, owner)
}

#[test]
fn publication_requires_install_ack_and_retains_capability_owner() {
    let (lanes, _, mut peers, mut owner) = setup();
    let route = owner.route();
    assert_eq!(
        owner.publish(&mut peers, 7, 8, &lanes),
        Err(PeerInstallationError::InvalidPhase)
    );
    assert_eq!(peers.resolve(route.badge()), None);
    owner
        .install(|actual, slot| {
            assert_eq!(actual, route);
            assert_eq!(slot, 44);
            Ok::<_, u8>(())
        })
        .unwrap();
    assert_eq!(peers.resolve(route.badge()), None);
    assert_eq!(owner.publish(&mut peers, 7, 8, &lanes), Ok(route));
    assert_eq!(owner.phase(), PeerInstallationPhase::Published);
    assert_eq!(peers.resolve(route.badge()), Some(route));
    assert_eq!(
        owner.delete_staged(|_| -> Result<(), u8> { panic!("published deletion") }),
        Err(PeerInstallationError::InvalidPhase)
    );
    assert_eq!(
        owner.finish_abort(&mut peers),
        Err(PeerInstallationError::InvalidPhase)
    );
    assert_eq!(owner.slot(), 44);
}

#[test]
fn failed_installation_remains_reserved_and_cannot_replay_or_abort() {
    let (lanes, _, mut peers, mut owner) = setup();
    assert_eq!(
        owner.install(|_, _| Err(9u8)),
        Err(PeerInstallationError::Invoke(9))
    );
    assert_eq!(owner.phase(), PeerInstallationPhase::Installing);
    assert_eq!(
        owner.install(|_, _| -> Result<(), u8> { panic!("replay") }),
        Err(PeerInstallationError::InvalidPhase)
    );
    assert_eq!(
        owner.delete_staged(|_| -> Result<(), u8> { panic!("uncertain delete") }),
        Err(PeerInstallationError::InvalidPhase)
    );
    assert_eq!(
        owner.publish(&mut peers, 7, 8, &lanes),
        Err(PeerInstallationError::InvalidPhase)
    );
    assert_eq!(
        owner.finish_abort(&mut peers),
        Err(PeerInstallationError::InvalidPhase)
    );
    assert_eq!(peers.state(owner.route()), Ok((PeerPhase::Staged, 0)));
}

#[test]
fn stale_lane_publication_keeps_installed_capability_until_delete_ack() {
    let (mut lanes, lane, mut peers, mut owner) = setup();
    owner.install(|_, _| Ok::<_, u8>(())).unwrap();
    let binding = lanes.release(lane, 33).unwrap();
    lanes.allocate(binding).unwrap();
    assert_eq!(
        owner.publish(&mut peers, 7, 8, &lanes),
        Err(PeerInstallationError::Lane(PeerLaneError::Lane(
            LaneError::StaleGeneration
        )))
    );
    assert_eq!(owner.phase(), PeerInstallationPhase::Installed);
    assert_eq!(
        owner.finish_abort(&mut peers),
        Err(PeerInstallationError::InvalidPhase)
    );
    owner
        .delete_staged(|slot| {
            assert_eq!(slot, 44);
            Ok::<_, u8>(())
        })
        .unwrap();
    let mut foreign = PeerRegistry::new(22, 1);
    assert!(owner.finish_abort(&mut foreign).is_err());
    assert_eq!(owner.phase(), PeerInstallationPhase::Deleted);
    assert_eq!(owner.finish_abort(&mut peers), Ok(44));
    assert_eq!(owner.phase(), PeerInstallationPhase::Aborted);
    assert!(peers.state(owner.route()).is_err());
    assert_eq!(
        owner.finish_abort(&mut peers),
        Err(PeerInstallationError::InvalidPhase)
    );
}

#[test]
fn delete_error_retains_route_and_never_authorizes_recycling() {
    let (_, _, mut peers, mut owner) = setup();
    assert_eq!(
        owner.delete_staged(|_| Err(3u8)),
        Err(PeerInstallationError::Invoke(3))
    );
    assert_eq!(owner.phase(), PeerInstallationPhase::Deleting);
    assert_eq!(
        owner.delete_staged(|_| -> Result<(), u8> { panic!("delete replay") }),
        Err(PeerInstallationError::InvalidPhase)
    );
    assert_eq!(
        owner.finish_abort(&mut peers),
        Err(PeerInstallationError::InvalidPhase)
    );
    assert_eq!(peers.state(owner.route()), Ok((PeerPhase::Staged, 0)));
}

#[test]
fn invalid_destination_preserves_original_registration() {
    for slot in [0, 11, 22] {
        let (lanes, lane, _, _) = setup();
        let mut peers = PeerRegistry::new(22, 1);
        let registration = peers.stage_lane(7, 8, &lanes, lane).unwrap();
        let route = registration.route();
        let (error, mut original) = PeerInstallation::new(registration, slot).err().unwrap();
        assert_eq!(error, PeerInstallationError::InvalidSlot);
        assert_eq!(original.route(), route);
        peers.abort(&mut original).unwrap();
    }
}

#[test]
fn wrong_domain_refusal_can_publish_after_exact_revalidation() {
    let (lanes, _, mut peers, mut owner) = setup();
    owner.install(|_, _| Ok::<_, u8>(())).unwrap();
    assert!(owner.publish(&mut peers, 7, 9, &lanes).is_err());
    assert_eq!(owner.phase(), PeerInstallationPhase::Installed);
    assert_eq!(peers.resolve(owner.route().badge()), None);
    owner.publish(&mut peers, 7, 8, &lanes).unwrap();
}

#[test]
fn failed_mint_keeps_registration_capacity_charged() {
    let (lanes, lane, mut peers, mut owner) = setup();
    assert_eq!(
        owner.install(|_, _| Err(7u64)),
        Err(PeerInstallationError::Invoke(7))
    );
    let mut other_lanes = Lanes::new(1, 1);
    let other = other_lanes
        .allocate(LaneBinding {
            executor_id: 12,
            receive_endpoint: 22,
            reply_object: 34,
        })
        .unwrap();
    assert_eq!(
        peers.stage_lane(9, 8, &other_lanes, other).err(),
        Some(PeerLaneError::Peer(PeerError::NoCapacity))
    );
    assert_eq!(owner.phase(), PeerInstallationPhase::Installing);
    assert_eq!(peers.resolve(owner.route().badge()), None);
    assert_eq!(lanes.binding(lane).unwrap().executor_id, 11);
    assert_eq!(peers.state(owner.route()), Ok((PeerPhase::Staged, 0)));
}

fn published() -> (Lanes, LaneHandle, PeerRegistry, PeerInstallation) {
    let (lanes, lane, mut peers, mut owner) = setup();
    owner.install(|_, _| Ok::<_, u8>(())).unwrap();
    owner.publish(&mut peers, 7, 8, &lanes).unwrap();
    (lanes, lane, peers, owner)
}

#[test]
fn child_export_requires_publication_and_acknowledges_exact_destination() {
    let (lanes, _, mut peers, mut owner) = setup();
    let destination = PeerCapabilityDestination { cnode: 55, slot: 0 };
    assert_eq!(
        owner.export(
            &peers,
            7,
            8,
            &lanes,
            destination,
            |_, _| -> Result<(), u8> { panic!("unpublished export") }
        ),
        Err(PeerInstallationError::InvalidPhase)
    );
    assert_eq!(owner.child_destination(), None);
    owner.install(|_, _| Ok::<_, u8>(())).unwrap();
    owner.publish(&mut peers, 7, 8, &lanes).unwrap();
    owner
        .export(&peers, 7, 8, &lanes, destination, |source, child| {
            assert_eq!(source, 44);
            assert_eq!(child, destination);
            Ok::<_, u8>(())
        })
        .unwrap();
    assert_eq!(owner.phase(), PeerInstallationPhase::Exported);
    assert_eq!(owner.child_destination(), Some(destination));
    assert_eq!(owner.slot(), 44);
    assert_eq!(peers.resolve(owner.route().badge()), Some(owner.route()));
    assert_eq!(
        owner.export(&peers, 7, 8, &lanes, destination, |_, _| Ok::<_, u8>(())),
        Err(PeerInstallationError::InvalidPhase)
    );
    assert_eq!(
        owner.delete_staged(|_| Ok::<_, u8>(())),
        Err(PeerInstallationError::InvalidPhase)
    );
    assert_eq!(
        owner.finish_abort(&mut peers),
        Err(PeerInstallationError::InvalidPhase)
    );
}

#[test]
fn uncertain_child_copy_keeps_both_aliases_and_cannot_replay() {
    let (lanes, _, mut peers, mut owner) = published();
    let destination = PeerCapabilityDestination {
        cnode: 55,
        slot: 44,
    };
    assert_eq!(
        owner.export(&peers, 7, 8, &lanes, destination, |_, _| Err(9u8)),
        Err(PeerInstallationError::Invoke(9))
    );
    assert_eq!(owner.phase(), PeerInstallationPhase::Exporting);
    assert_eq!(owner.child_destination(), Some(destination));
    assert_eq!(owner.slot(), 44);
    assert_eq!(
        owner.export(&peers, 7, 8, &lanes, destination, |_, _| Ok::<_, u8>(())),
        Err(PeerInstallationError::InvalidPhase)
    );
    assert_eq!(
        owner.delete_staged(|_| Ok::<_, u8>(())),
        Err(PeerInstallationError::InvalidPhase)
    );
    assert_eq!(
        owner.finish_abort(&mut peers),
        Err(PeerInstallationError::InvalidPhase)
    );
    assert_eq!(peers.resolve(owner.route().badge()), Some(owner.route()));
}

#[test]
fn invalid_child_cnode_preserves_published_owner_without_effects() {
    let (lanes, _, peers, mut owner) = published();
    for cnode in [0, 11, 22, 44] {
        assert_eq!(
            owner.export(
                &peers,
                7,
                8,
                &lanes,
                PeerCapabilityDestination { cnode, slot: 1 },
                |_, _| -> Result<(), u8> { panic!("invalid CNode") }
            ),
            Err(PeerInstallationError::InvalidDestination)
        );
        assert_eq!(owner.phase(), PeerInstallationPhase::Published);
        assert_eq!(owner.child_destination(), None);
    }
}

#[test]
fn child_export_revalidates_domain_registry_retirement_and_lane_generation() {
    let destination = PeerCapabilityDestination { cnode: 55, slot: 1 };
    let (mut lanes, lane, mut peers, mut owner) = published();
    let foreign = PeerRegistry::new(22, 1);
    for (registry, domain, generation) in [(&foreign, 7, 8), (&peers, 9, 8), (&peers, 7, 9)] {
        assert!(owner
            .export(
                registry,
                domain,
                generation,
                &lanes,
                destination,
                |_, _| -> Result<(), u8> { panic!("stale domain") }
            )
            .is_err());
        assert_eq!(owner.phase(), PeerInstallationPhase::Published);
        assert_eq!(owner.child_destination(), None);
    }
    let binding = lanes.release(lane, 33).unwrap();
    lanes.allocate(binding).unwrap();
    assert!(owner
        .export(
            &peers,
            7,
            8,
            &lanes,
            destination,
            |_, _| -> Result<(), u8> { panic!("stale lane") }
        )
        .is_err());
    assert_eq!(owner.child_destination(), None);
    peers.begin_retirement(owner.route()).unwrap();
    assert!(owner
        .export(
            &peers,
            7,
            8,
            &lanes,
            destination,
            |_, _| -> Result<(), u8> { panic!("retiring peer") }
        )
        .is_err());
    assert_eq!(owner.phase(), PeerInstallationPhase::Published);
    assert_eq!(owner.child_destination(), None);
}
