use super::*;

type Lanes = ComponentSuspensionLanes<(), (), ()>;
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
fn no_query(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    panic!("must reject before query")
}
fn no_resume(_: u64) -> Result<(), u8> {
    panic!("must reject before resume")
}

fn setup() -> (Lanes, PeerRegistry, PeerInstallation) {
    let mut lanes = Lanes::new(2, 2);
    let mut peers = PeerRegistry::new(22, 2);
    let (_, registration) = lanes
        .allocate_shared_staged(&mut peers, 7, 8, binding())
        .unwrap();
    let mut owner = PeerInstallation::new(registration, 44).ok().unwrap();
    owner.install(|_, _| Ok::<_, u8>(())).unwrap();
    owner.publish(&mut peers, 7, 8, &lanes).unwrap();
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
    owner.bind_space(66, |_| Ok::<_, u8>(())).unwrap();
    (lanes, peers, owner)
}

#[test]
fn acknowledged_bootstrap_is_running_with_real_epoch_and_no_ready_call() {
    let (mut lanes, peers, mut owner) = setup();
    let route = owner.route();
    let dispatch = owner
        .start_bootstrap(
            &peers,
            7,
            8,
            &mut lanes,
            binding(),
            space(),
            |tcb, reply| {
                assert_eq!((tcb, reply), (11, 33));
                Ok::<_, u8>(ReplyBindingObservation::Free)
            },
            |tcb| {
                assert_eq!(tcb, 11);
                Ok::<_, u8>(())
            },
        )
        .unwrap();
    assert_ne!(dispatch.epoch(), 0);
    assert_eq!(dispatch.lane(), route.identity().lane);
    assert_eq!(lanes.phase(dispatch.lane()), Ok(LanePhase::Running));
    assert_eq!(lanes.running(), Some(dispatch.lane()));
    assert_eq!(
        lanes.active_dispatch_identity(dispatch.lane()),
        Ok(Some(dispatch))
    );
    assert_eq!(lanes.binding(dispatch.lane()), Ok(binding()));
    assert_eq!(owner.phase(), PeerInstallationPhase::ResumeAcknowledged);
    assert_eq!(peers.state(route).unwrap().1, 0);
    assert_eq!(owner.space_binding(), Some(space()));
    assert_eq!(
        owner.start_bootstrap(
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
}

#[test]
fn uncertain_resume_keeps_epoch_fence_and_aliases_and_cannot_replay() {
    let (mut lanes, peers, mut owner) = setup();
    assert_eq!(
        owner.start_bootstrap(
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
    let lane = owner.route().identity().lane;
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    assert_eq!(owner.phase(), PeerInstallationPhase::Resuming);
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Running));
    assert_eq!(lanes.running(), Some(lane));
    assert_eq!(owner.space_binding(), Some(space()));
    assert_eq!(owner.slot(), 44);
    assert_eq!(
        owner.start_bootstrap(
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
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));
}

#[test]
fn bootstrap_query_failure_and_nonfree_refuse_without_allocating_epoch() {
    let (mut lanes, peers, mut owner) = setup();
    for (result, expected) in [
        (Err(3u8), PeerStartupError::Startup(StartupError::Query(3))),
        (
            Ok(ReplyBindingObservation::BoundToTarget),
            PeerStartupError::Startup(StartupError::BindingMismatch),
        ),
    ] {
        assert_eq!(
            owner.start_bootstrap(
                &peers,
                7,
                8,
                &mut lanes,
                binding(),
                space(),
                |_, _| result,
                no_resume
            ),
            Err(expected)
        );
        assert_eq!(owner.phase(), PeerInstallationPhase::SpaceBound);
        assert_eq!(
            lanes.phase(owner.route().identity().lane),
            Ok(LanePhase::Staged)
        );
        assert_eq!(lanes.running(), None);
        assert_eq!(
            lanes.lane(owner.route().identity().lane).unwrap().dispatch,
            None
        );
    }
}

#[test]
fn bootstrap_requires_exact_installation_domain_and_idle_execution() {
    let (mut lanes, peers, mut owner) = setup();
    assert!(owner
        .start_bootstrap(
            &peers,
            7,
            9,
            &mut lanes,
            binding(),
            space(),
            no_query,
            no_resume
        )
        .is_err());
    assert_eq!(
        owner.start_bootstrap(
            &peers,
            7,
            8,
            &mut lanes,
            LaneBinding {
                reply_object: 34,
                ..binding()
            },
            space(),
            no_query,
            no_resume
        ),
        Err(PeerStartupError::BindingMismatch)
    );
    assert_eq!(
        owner.start_bootstrap(
            &peers,
            7,
            8,
            &mut lanes,
            binding(),
            PeerSpaceBinding {
                vspace: 67,
                ..space()
            },
            no_query,
            no_resume
        ),
        Err(PeerStartupError::BindingMismatch)
    );
    let other = lanes
        .allocate(LaneBinding {
            executor_id: 71,
            receive_endpoint: 72,
            reply_object: 73,
        })
        .unwrap();
    lanes.begin_dispatch(other, 73).unwrap();
    assert_eq!(
        owner.start_bootstrap(
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
    assert_eq!(owner.phase(), PeerInstallationPhase::SpaceBound);
}

#[test]
fn uncertain_space_binding_never_enters_bootstrap() {
    let (mut lanes, peers, mut owner) = setup();
    owner.phase = PeerInstallationPhase::BindingSpace;
    assert_eq!(
        owner.start_bootstrap(
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
