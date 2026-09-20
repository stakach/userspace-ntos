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
