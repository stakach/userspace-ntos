use super::*;
use crate::{LaneBinding, LanePhase};

type Lanes = ComponentSuspensionLanes<(), ()>;

fn prepared() -> (Lanes, PeerRegistry, PeerInstallation) {
    let mut lanes = Lanes::new(2, 2);
    let mut peers = PeerRegistry::new(22, 2);
    let (_, registration) = lanes
        .allocate_shared_staged(
            &mut peers,
            7,
            8,
            LaneBinding {
                executor_id: 11,
                receive_endpoint: 22,
                reply_object: 33,
            },
        )
        .unwrap();
    let mut installation = PeerInstallation::new(registration, 44).ok().unwrap();
    installation.install(|_, _| Ok::<_, u8>(())).unwrap();
    installation.publish(&mut peers, 7, 8, &lanes).unwrap();
    installation
        .export(
            &peers,
            7,
            8,
            &lanes,
            PeerCapabilityDestination { cnode: 55, slot: 6 },
            |_, _| Ok::<_, u8>(()),
        )
        .unwrap();
    installation.bind_space(66, |_| Ok::<_, u8>(())).unwrap();
    (lanes, peers, installation)
}

fn yes(_: PeerRoute) -> Result<bool, u8> {
    Ok(true)
}
fn ack(_: PeerRetirementEffect) -> Result<(), u8> {
    Ok(())
}
fn no_effect(_: PeerRetirementEffect) -> Result<(), u8> {
    panic!("unexpected effect")
}

fn stopped(lanes: &Lanes, peers: &mut PeerRegistry, owner: &mut PeerInstallation) {
    owner.begin_retirement(peers, 7, 8, lanes).unwrap();
    owner.retire_effect(peers, lanes, ack).unwrap();
}

#[test]
fn retirement_orders_stop_drain_and_all_aliases_before_route_removal() {
    let (lanes, mut peers, mut owner) = prepared();
    let route = owner.route();
    owner.begin_retirement(&mut peers, 7, 8, &lanes).unwrap();
    assert_eq!(peers.resolve(route.badge()), None);
    assert_eq!(peers.resolve_retiring(route.badge()), Some(route));
    owner
        .retire_effect(&peers, &lanes, |effect| {
            assert_eq!(effect, PeerRetirementEffect::StopExecutor(11));
            Ok::<_, u8>(())
        })
        .unwrap();
    assert_eq!(
        owner.retire_effect(&peers, &lanes, no_effect),
        Err(PeerRetirementError::InvalidPhase)
    );
    owner.prove_retirement_drain(&peers, &lanes, yes).unwrap();
    for expected in [
        PeerRetirementEffect::ClearFaultHandler(PeerSpaceBinding {
            executor: 11,
            cnode: 55,
            vspace: 66,
            fault_slot: 6,
        }),
        PeerRetirementEffect::DeleteChildAlias(PeerCapabilityDestination { cnode: 55, slot: 6 }),
        PeerRetirementEffect::DeleteRootAlias(44),
    ] {
        assert_eq!(
            owner.finish_retirement(&mut peers, &lanes, yes),
            Err(PeerRetirementError::InvalidPhase)
        );
        owner
            .retire_effect(&peers, &lanes, |effect| {
                assert_eq!(effect, expected);
                Ok::<_, u8>(())
            })
            .unwrap();
        assert_eq!(peers.resolve_retiring(route.badge()), Some(route));
    }
    owner.finish_retirement(&mut peers, &lanes, yes).unwrap();
    assert_eq!(owner.phase(), PeerInstallationPhase::Retired);
    assert_eq!(peers.resolve_retiring(route.badge()), None);
    assert_eq!(owner.slot(), 44);
    assert!(owner.space_binding().is_some());
    assert!(owner.child_destination().is_some());
    assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Staged));
    assert_eq!(
        owner.retire_effect(&peers, &lanes, no_effect),
        Err(PeerRetirementError::InvalidPhase)
    );
    assert_eq!(
        owner.finish_retirement(&mut peers, &lanes, yes),
        Err(PeerRetirementError::InvalidPhase)
    );
}

#[test]
fn every_uncertain_retirement_effect_is_nonreplayable() {
    use PeerRetirementPhase::*;
    for (index, entered) in [Stopping, ClearingFault, DeletingChild, DeletingRoot]
        .into_iter()
        .enumerate()
    {
        let (lanes, mut peers, mut owner) = prepared();
        owner.begin_retirement(&mut peers, 7, 8, &lanes).unwrap();
        for step in 0..index {
            owner.retire_effect(&peers, &lanes, ack).unwrap();
            if step == 0 {
                owner.prove_retirement_drain(&peers, &lanes, yes).unwrap();
            }
        }
        assert_eq!(
            owner.retire_effect(&peers, &lanes, |_| Err(9u8)),
            Err(PeerRetirementError::Invoke(9))
        );
        assert_eq!(owner.phase(), PeerInstallationPhase::Retiring(entered));
        assert_eq!(
            owner.retire_effect(&peers, &lanes, no_effect),
            Err(PeerRetirementError::InvalidPhase)
        );
        assert_eq!(
            owner.finish_retirement(&mut peers, &lanes, yes),
            Err(PeerRetirementError::InvalidPhase)
        );
        assert_eq!(
            owner.begin_retirement(&mut peers, 7, 8, &lanes),
            Err(PeerRetirementError::InvalidPhase)
        );
        assert_eq!(
            owner.delete_staged(|_| Ok::<_, u8>(())),
            Err(PeerInstallationError::InvalidPhase)
        );
        assert_eq!(
            peers.resolve_retiring(owner.route().badge()),
            Some(owner.route())
        );
    }
}

#[test]
fn retirement_drain_requires_both_retention_zero_and_external_proof() {
    let (lanes, mut peers, mut owner) = prepared();
    let route = owner.route();
    let mut retained = peers.retain(route).unwrap();
    stopped(&lanes, &mut peers, &mut owner);
    assert_eq!(
        owner.prove_retirement_drain(&peers, &lanes, |_| -> Result<bool, u8> {
            panic!("retained work must refuse before proof")
        }),
        Err(PeerRetirementError::NotDrained)
    );
    peers.release(&mut retained).unwrap();
    assert_eq!(
        owner.prove_retirement_drain(&peers, &lanes, |_| Ok::<_, u8>(false)),
        Err(PeerRetirementError::NotDrained)
    );
    assert_eq!(
        owner.prove_retirement_drain(&peers, &lanes, |_| Err(3u8)),
        Err(PeerRetirementError::Invoke(3))
    );
    assert_eq!(
        owner.phase(),
        PeerInstallationPhase::Retiring(PeerRetirementPhase::Stopped)
    );
    owner.prove_retirement_drain(&peers, &lanes, yes).unwrap();
    let mut late = peers.retain(route).unwrap();
    assert_eq!(
        owner.retire_effect(&peers, &lanes, no_effect),
        Err(PeerRetirementError::NotDrained)
    );
    peers.release(&mut late).unwrap();
    for _ in 0..3 {
        owner.retire_effect(&peers, &lanes, ack).unwrap();
    }
    let mut late = peers.retain(route).unwrap();
    assert_eq!(
        owner.finish_retirement(&mut peers, &lanes, yes),
        Err(PeerRetirementError::NotDrained)
    );
    peers.release(&mut late).unwrap();
    assert_eq!(
        owner.finish_retirement(&mut peers, &lanes, |_| Ok::<_, u8>(false)),
        Err(PeerRetirementError::NotDrained)
    );
    assert_eq!(
        owner.finish_retirement(&mut peers, &lanes, |_| Err(4u8)),
        Err(PeerRetirementError::Invoke(4))
    );
    assert_eq!(peers.resolve_retiring(route.badge()), Some(route));
    owner.finish_retirement(&mut peers, &lanes, yes).unwrap();
}

#[test]
fn retirement_requires_exact_live_shared_route_and_binding() {
    let (lanes, mut peers, mut owner) = prepared();
    for (domain, generation) in [(9, 8), (7, 9), (0, 8)] {
        assert!(matches!(
            owner.begin_retirement(&mut peers, domain, generation, &lanes),
            Err(PeerRetirementError::Lane(_))
        ));
    }
    let mut foreign = PeerRegistry::new(22, 2);
    assert!(matches!(
        owner.begin_retirement(&mut foreign, 7, 8, &lanes),
        Err(PeerRetirementError::Lane(_))
    ));
    let replacement = Lanes::new(2, 2);
    assert!(matches!(
        owner.begin_retirement(&mut peers, 7, 8, &replacement),
        Err(PeerRetirementError::Lane(_))
    ));
    assert_eq!(owner.phase(), PeerInstallationPhase::SpaceBound);
    assert_eq!(peers.resolve(owner.route().badge()), Some(owner.route()));
}

#[test]
fn native_true_drain_proof_cannot_override_canonical_ownership() {
    for phase in [
        LanePhase::Starting,
        LanePhase::StartupStopped,
        LanePhase::Running,
        LanePhase::Suspended,
        LanePhase::Terminal,
    ] {
        let (mut lanes, mut peers, mut owner) = prepared();
        stopped(&lanes, &mut peers, &mut owner);
        lanes.lane_mut(owner.route().identity().lane).unwrap().phase = phase;
        assert_eq!(
            owner.prove_retirement_drain(&peers, &lanes, yes),
            Err(PeerRetirementError::NotDrained)
        );
    }
    for state in 0..3 {
        let (mut lanes, mut peers, mut owner) = prepared();
        stopped(&lanes, &mut peers, &mut owner);
        let handle = owner.route().identity().lane;
        match state {
            0 => lanes.running = Some(handle),
            1 => {
                lanes.lane_mut(handle).unwrap().dispatch = Some(crate::LaneDispatchIdentity {
                    lane: handle,
                    epoch: 1,
                })
            }
            _ => lanes.lane_mut(handle).unwrap().external_tokens.push(1),
        }
        assert_eq!(
            owner.prove_retirement_drain(&peers, &lanes, yes),
            Err(PeerRetirementError::NotDrained)
        );
    }
    let (mut lanes, mut peers, mut owner) = prepared();
    stopped(&lanes, &mut peers, &mut owner);
    owner.prove_retirement_drain(&peers, &lanes, yes).unwrap();
    for _ in 0..3 {
        owner.retire_effect(&peers, &lanes, ack).unwrap();
    }
    lanes.running = Some(owner.route().identity().lane);
    assert_eq!(
        owner.finish_retirement(&mut peers, &lanes, yes),
        Err(PeerRetirementError::NotDrained)
    );
    assert_eq!(
        peers.resolve_retiring(owner.route().badge()),
        Some(owner.route())
    );
}

#[test]
fn retiring_one_domain_preserves_other_routes_and_retention() {
    let (mut lanes, mut peers, mut owner) = prepared();
    let (_, mut registration) = lanes
        .allocate_shared_staged(
            &mut peers,
            9,
            10,
            LaneBinding {
                executor_id: 71,
                receive_endpoint: 22,
                reply_object: 72,
            },
        )
        .unwrap();
    let other = peers
        .publish_lane(&mut registration, 9, 10, &lanes)
        .unwrap();
    let retained = peers.retain(other).unwrap();
    stopped(&lanes, &mut peers, &mut owner);
    owner.prove_retirement_drain(&peers, &lanes, yes).unwrap();
    for _ in 0..3 {
        owner.retire_effect(&peers, &lanes, ack).unwrap();
    }
    owner.finish_retirement(&mut peers, &lanes, yes).unwrap();
    assert_eq!(peers.resolve_lane(other.badge(), 9, 10, &lanes), Ok(other));
    assert_eq!(peers.state(other), Ok((PeerPhase::Active, 1)));
    assert_eq!(retained.route(), Some(other));
}
