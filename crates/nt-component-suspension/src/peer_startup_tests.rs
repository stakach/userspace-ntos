use super::*;
use crate::{LaneError, LanePhase};

type Lanes = ComponentSuspensionLanes<(), ()>;

fn binding() -> LaneBinding {
    LaneBinding {
        executor_id: 11,
        receive_endpoint: 22,
        reply_object: 33,
    }
}

fn space() -> PeerSpaceBinding {
    PeerSpaceBinding {
        executor: 11,
        cnode: 55,
        vspace: 66,
        fault_slot: 6,
    }
}

fn published(shared: bool) -> (Lanes, PeerRegistry, PeerInstallation) {
    let mut lanes = Lanes::new(2, 2);
    let mut peers = PeerRegistry::new(22, 2);
    let registration = if shared {
        lanes
            .allocate_shared_staged(&mut peers, 7, 8, binding())
            .unwrap()
            .1
    } else {
        let lane = lanes.allocate_staged(binding()).unwrap();
        peers.stage_lane(7, 8, &lanes, lane).unwrap()
    };
    let mut owner = PeerInstallation::new(registration, 44).ok().unwrap();
    owner.install(|_, _| Ok::<_, u8>(())).unwrap();
    owner.publish(&mut peers, 7, 8, &lanes).unwrap();
    (lanes, peers, owner)
}

fn exported(shared: bool) -> (Lanes, PeerRegistry, PeerInstallation) {
    let (lanes, peers, mut owner) = published(shared);
    owner
        .export(
            &peers,
            7,
            8,
            &lanes,
            PeerCapabilityDestination { cnode: 55, slot: 6 },
            |_, _| Ok::<_, u8>(()),
        )
        .unwrap();
    (lanes, peers, owner)
}

fn prepared(shared: bool) -> (Lanes, PeerRegistry, PeerInstallation) {
    let (lanes, peers, mut owner) = exported(shared);
    owner.bind_space(66, |_| Ok::<_, u8>(())).unwrap();
    (lanes, peers, owner)
}

fn no_query(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    panic!("refused startup must not query")
}

fn no_resume(_: u64) -> Result<(), u8> {
    panic!("refused startup must not resume")
}

#[test]
fn shared_start_ack_keeps_execution_fenced_and_all_aliases_owned() {
    let (mut lanes, peers, mut owner) = prepared(true);
    let route = owner.route();
    let mut queried = 0;
    let mut resumed = 0;
    assert_eq!(
        owner.start(
            &peers,
            7,
            8,
            &mut lanes,
            binding(),
            space(),
            |tcb, reply| {
                assert_eq!((tcb, reply), (11, 33));
                queried += 1;
                Ok::<_, u8>(ReplyBindingObservation::Free)
            },
            |tcb| {
                assert_eq!(tcb, 11);
                resumed += 1;
                Ok::<_, u8>(())
            }
        ),
        Ok(())
    );
    assert_eq!((queried, resumed), (1, 1));
    assert_eq!(owner.phase(), PeerInstallationPhase::ResumeAcknowledged);
    assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Starting));
    assert_eq!(lanes.running(), Some(route.identity().lane));
    assert_eq!(lanes.binding(route.identity().lane), Ok(binding()));
    assert_eq!(owner.space_binding(), Some(space()));
    assert_eq!(
        owner.child_destination(),
        Some(PeerCapabilityDestination { cnode: 55, slot: 6 })
    );
    assert_eq!(owner.slot(), 44);
    assert_eq!(peers.resolve(route.badge()), Some(route));
    assert_eq!(
        owner.start(
            &peers,
            7,
            8,
            &mut lanes,
            binding(),
            space(),
            no_query,
            no_resume
        ),
        Err(PeerStartupError::InvalidPhase)
    );
    assert_eq!(
        owner.delete_staged(|_| Ok::<_, u8>(())),
        Err(PeerInstallationError::InvalidPhase)
    );
}

#[test]
fn uncertain_resume_retains_entered_state_and_excludes_replay() {
    let (mut lanes, peers, mut owner) = prepared(true);
    let lane = owner.route().identity().lane;
    assert_eq!(
        owner.start(
            &peers,
            7,
            8,
            &mut lanes,
            binding(),
            space(),
            |_, _| Ok::<_, u8>(ReplyBindingObservation::Free),
            |_| Err(9u8)
        ),
        Err(PeerStartupError::Resume(9))
    );
    assert_eq!(owner.phase(), PeerInstallationPhase::Resuming);
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Starting));
    assert_eq!(lanes.running(), Some(lane));
    assert_eq!(owner.space_binding(), Some(space()));
    assert_eq!(owner.slot(), 44);
    assert_eq!(
        owner.start(
            &peers,
            7,
            8,
            &mut lanes,
            binding(),
            space(),
            no_query,
            no_resume
        ),
        Err(PeerStartupError::InvalidPhase)
    );
    assert_eq!(
        owner.delete_staged(|_| Ok::<_, u8>(())),
        Err(PeerInstallationError::InvalidPhase)
    );
}

#[test]
fn startup_requires_acknowledged_space_binding() {
    for (mut lanes, peers, mut owner) in [published(true), exported(true)] {
        assert_eq!(
            owner.start(
                &peers,
                7,
                8,
                &mut lanes,
                binding(),
                space(),
                no_query,
                no_resume
            ),
            Err(PeerStartupError::InvalidPhase)
        );
        assert_eq!(lanes.running(), None);
    }
    let (mut lanes, peers, mut owner) = exported(true);
    assert_eq!(
        owner.bind_space(66, |_| Err(3u8)),
        Err(PeerInstallationError::Invoke(3))
    );
    assert_eq!(
        owner.start(
            &peers,
            7,
            8,
            &mut lanes,
            binding(),
            space(),
            no_query,
            no_resume
        ),
        Err(PeerStartupError::InvalidPhase)
    );
    assert_eq!(owner.phase(), PeerInstallationPhase::BindingSpace);
    assert_eq!(lanes.running(), None);
}

#[test]
fn changed_physical_bindings_are_rejected_before_query() {
    let (mut lanes, peers, mut owner) = prepared(true);
    for wrong in [
        PeerSpaceBinding {
            executor: 12,
            ..space()
        },
        PeerSpaceBinding {
            cnode: 56,
            ..space()
        },
        PeerSpaceBinding {
            vspace: 67,
            ..space()
        },
        PeerSpaceBinding {
            fault_slot: 7,
            ..space()
        },
    ] {
        assert_eq!(
            owner.start(
                &peers,
                7,
                8,
                &mut lanes,
                binding(),
                wrong,
                no_query,
                no_resume
            ),
            Err(PeerStartupError::BindingMismatch)
        );
    }
    for wrong in [
        LaneBinding {
            executor_id: 12,
            ..binding()
        },
        LaneBinding {
            receive_endpoint: 23,
            ..binding()
        },
        LaneBinding {
            reply_object: 34,
            ..binding()
        },
    ] {
        assert_eq!(
            owner.start(
                &peers,
                7,
                8,
                &mut lanes,
                wrong,
                space(),
                no_query,
                no_resume
            ),
            Err(PeerStartupError::BindingMismatch)
        );
    }
    assert_eq!(owner.phase(), PeerInstallationPhase::SpaceBound);
    assert_eq!(lanes.running(), None);
}

#[test]
fn wrong_domain_generation_registry_and_table_are_rejected() {
    let (mut lanes, peers, mut owner) = prepared(true);
    for (domain, generation) in [(0, 8), (9, 8), (7, 0), (7, 9)] {
        assert!(matches!(
            owner.start(
                &peers,
                domain,
                generation,
                &mut lanes,
                binding(),
                space(),
                no_query,
                no_resume
            ),
            Err(PeerStartupError::Route(_))
        ));
    }
    let foreign = PeerRegistry::new(22, 2);
    assert!(matches!(
        owner.start(
            &foreign,
            7,
            8,
            &mut lanes,
            binding(),
            space(),
            no_query,
            no_resume
        ),
        Err(PeerStartupError::Route(_))
    ));
    let mut foreign_lanes = Lanes::new(2, 2);
    assert!(matches!(
        owner.start(
            &peers,
            7,
            8,
            &mut foreign_lanes,
            binding(),
            space(),
            no_query,
            no_resume
        ),
        Err(PeerStartupError::Route(_))
    ));
    assert_eq!(owner.phase(), PeerInstallationPhase::SpaceBound);
    assert_eq!(lanes.running(), None);
}

#[test]
fn busy_execution_preserves_staged_startup_without_query() {
    let (mut lanes, peers, mut owner) = prepared(true);
    let other = lanes
        .allocate(LaneBinding {
            executor_id: 71,
            receive_endpoint: 72,
            reply_object: 73,
        })
        .unwrap();
    lanes.begin_dispatch(other, 73).unwrap();
    assert_eq!(
        owner.start(
            &peers,
            7,
            8,
            &mut lanes,
            binding(),
            space(),
            no_query,
            no_resume
        ),
        Err(PeerStartupError::Startup(StartupError::Lane(
            LaneError::Busy
        )))
    );
    assert_eq!(lanes.running(), Some(other));
    assert_eq!(
        lanes.phase(owner.route().identity().lane),
        Ok(LanePhase::Staged)
    );
    assert_eq!(owner.phase(), PeerInstallationPhase::SpaceBound);
}

#[test]
fn failed_or_nonfree_binding_query_never_resumes() {
    let (mut lanes, peers, mut owner) = prepared(true);
    assert_eq!(
        owner.start(
            &peers,
            7,
            8,
            &mut lanes,
            binding(),
            space(),
            |_, _| Err(4u8),
            no_resume
        ),
        Err(PeerStartupError::Startup(StartupError::Query(4)))
    );
    assert_eq!(
        owner.start(
            &peers,
            7,
            8,
            &mut lanes,
            binding(),
            space(),
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
            no_resume
        ),
        Err(PeerStartupError::Startup(StartupError::BindingMismatch))
    );
    assert_eq!(owner.phase(), PeerInstallationPhase::SpaceBound);
    assert_eq!(
        lanes.phase(owner.route().identity().lane),
        Ok(LanePhase::Staged)
    );
    assert_eq!(lanes.running(), None);
}

#[test]
fn private_lane_cannot_start_through_shared_installation() {
    let (mut lanes, peers, mut owner) = prepared(false);
    assert_eq!(
        owner.start(
            &peers,
            7,
            8,
            &mut lanes,
            binding(),
            space(),
            no_query,
            no_resume
        ),
        Err(PeerStartupError::BindingMismatch)
    );
    assert_eq!(owner.phase(), PeerInstallationPhase::SpaceBound);
    assert_eq!(lanes.running(), None);
}
