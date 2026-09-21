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
fn free(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::Free)
}
fn no_query(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    panic!("preflight refusal")
}
fn no_resume(_: u64) -> Result<(), u8> {
    panic!("resume forbidden")
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
fn acknowledged_autonomous_start_is_idle_without_epoch_or_readiness() {
    let (mut lanes, peers, mut owner) = setup();
    let route = owner.route();
    owner
        .start_autonomous(&peers, 7, 8, &mut lanes, binding(), space(), free, |tcb| {
            assert_eq!(tcb, 11);
            Ok::<_, u8>(())
        })
        .unwrap();
    assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Idle));
    assert_eq!(
        lanes.active_dispatch_identity(route.identity().lane),
        Ok(None)
    );
    assert_eq!(lanes.running(), None);
    assert_eq!(peers.state(route).unwrap().1, 0);
    assert_eq!(owner.phase(), PeerInstallationPhase::ResumeAcknowledged);
    assert_eq!(
        owner.start_autonomous(
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
fn uncertain_resume_preserves_staged_fence_and_forbids_replay() {
    let (mut lanes, peers, mut owner) = setup();
    let route = owner.route();
    assert_eq!(
        owner.start_autonomous(&peers, 7, 8, &mut lanes, binding(), space(), free, |_| Err(
            9
        )),
        Err(PeerStartupError::Resume(9))
    );
    assert_eq!(owner.phase(), PeerInstallationPhase::Resuming);
    assert_eq!(lanes.phase(route.identity().lane), Ok(LanePhase::Staged));
    assert!(lanes.begin_dispatch(route.identity().lane, 33).is_err());
    assert_eq!(
        owner.start_autonomous(
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
    assert_eq!(owner.space_binding(), Some(space()));
}

#[test]
fn wrong_identity_and_query_refusals_never_enter_resume() {
    let (mut lanes, peers, mut owner) = setup();
    let mut wrong = binding();
    wrong.reply_object = 99;
    assert_eq!(
        owner.start_autonomous(
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
    let mut wrong_space = space();
    wrong_space.vspace = 99;
    assert_eq!(
        owner.start_autonomous(
            &peers,
            7,
            8,
            &mut lanes,
            binding(),
            wrong_space,
            no_query,
            no_resume
        ),
        Err(PeerStartupError::BindingMismatch)
    );
    assert!(owner
        .start_autonomous(
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
    assert!(owner
        .start_autonomous(
            &peers,
            7,
            8,
            &mut lanes,
            binding(),
            space(),
            |_, _| Err(3u8),
            no_resume
        )
        .is_err());
    assert_eq!(
        owner.start_autonomous(
            &peers,
            7,
            8,
            &mut lanes,
            binding(),
            space(),
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
            no_resume
        ),
        Err(PeerStartupError::BindingMismatch)
    );
    assert_eq!(owner.phase(), PeerInstallationPhase::SpaceBound);
    assert_eq!(
        lanes.phase(owner.route().identity().lane),
        Ok(LanePhase::Staged)
    );
}

#[test]
fn autonomous_resume_does_not_steal_other_running_execution() {
    let (mut lanes, peers, mut owner) = setup();
    let other = lanes
        .allocate(LaneBinding {
            executor_id: 100,
            receive_endpoint: 200,
            reply_object: 300,
        })
        .unwrap();
    lanes.begin_dispatch(other, 300).unwrap();
    let dispatch = lanes.active_dispatch_identity(other).unwrap();
    owner
        .start_autonomous(&peers, 7, 8, &mut lanes, binding(), space(), free, |_| {
            Ok::<_, u8>(())
        })
        .unwrap();
    assert_eq!(lanes.running(), Some(other));
    assert_eq!(lanes.active_dispatch_identity(other), Ok(dispatch));
}
