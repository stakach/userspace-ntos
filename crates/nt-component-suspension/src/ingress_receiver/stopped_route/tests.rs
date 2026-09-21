use super::*;
use crate::{
    IngressReplyObservation, LaneBinding, LaneDispatchIdentity, PeerCapabilityDestination,
    PeerSpaceBinding,
};

type Lanes = ComponentSuspensionLanes<(), (), ()>;
fn free(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::Free)
}
fn bound(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::BoundToTarget)
}
fn no_query(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    panic!("preflight refusal")
}
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

struct Fixture {
    lanes: Lanes,
    peers: PeerRegistry,
    owner: PeerInstallation,
    receiver: IngressReceiver<u64>,
    pending: Option<ComponentIngress<u64>>,
}

impl Fixture {
    fn new() -> Self {
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
        Self {
            lanes,
            peers,
            owner,
            receiver: IngressReceiver::new(22, 40, 3).unwrap(),
            pending: None,
        }
    }
    fn bootstrap(&mut self) -> LaneDispatchIdentity {
        self.owner
            .start_bootstrap(
                &self.peers,
                7,
                8,
                &mut self.lanes,
                binding(),
                space(),
                free,
                |_| Ok::<_, u8>(()),
            )
            .unwrap()
    }
    fn capture(&mut self, dispatch: LaneDispatchIdentity, message: u64) {
        let reply = self.receiver.reply();
        self.receiver
            .begin_receive_for_owner(&self.lanes, IngressExecutionOwner::Dispatch(dispatch))
            .unwrap();
        self.receiver.capture(message).ok().unwrap();
        self.receiver
            .resolve(IngressReceiveDisposition::Call)
            .ok()
            .unwrap();
        self.receiver
            .retain(
                &self.lanes,
                ComponentIngress::new(22, reply + 1).unwrap(),
                &mut self.peers,
                self.owner.route().badge(),
                bound,
            )
            .ok()
            .unwrap();
    }
    fn admitted(&mut self) -> LaneDispatchIdentity {
        let dispatch = self.bootstrap();
        self.capture(dispatch, 100);
        self.receiver
            .adopt_bootstrap_call(
                self.owner.route(),
                dispatch,
                40,
                &mut self.lanes,
                &self.peers,
                &mut self.pending,
                |_, cap| {
                    Ok::<_, u8>(if cap == 33 {
                        ReplyBindingObservation::Free
                    } else {
                        ReplyBindingObservation::BoundToTarget
                    })
                },
            )
            .unwrap();
        dispatch
    }
    fn stop(&mut self) {
        self.owner
            .begin_retirement(&mut self.peers, 7, 8, &self.lanes)
            .unwrap();
        self.owner
            .retire_effect(&self.peers, &self.lanes, |_| Ok::<_, u8>(()))
            .unwrap();
    }
}

#[test]
fn stopped_ack_drains_canonical_and_queued_call_without_releasing_aliases() {
    let mut f = Fixture::new();
    let dispatch = f.admitted();
    f.receiver
        .reply_stored(f.owner.route(), dispatch, &f.lanes, bound, |_| {
            IngressReplyObservation::Acknowledged
        })
        .unwrap();
    f.capture(dispatch, 200);
    f.stop();
    let mut output = Vec::new();
    let mut queried = Vec::new();
    f.receiver
        .cancel_stopped_route(
            &f.owner,
            &mut f.lanes,
            &mut f.peers,
            &mut output,
            |tcb, reply| {
                queried.push((tcb, reply));
                free(tcb, reply)
            },
        )
        .unwrap();
    assert_eq!(queried, [(11, 40), (11, 41)]);
    assert_eq!(output.len(), 2);
    assert!(output[0].reply.is_none());
    assert_eq!(output[0].message, 100);
    assert_eq!(output[1].reply.as_ref().unwrap().reply(), 41);
    assert_eq!(output[1].message, 200);
    assert_eq!(f.lanes.binding(dispatch.lane()).unwrap().reply_object, 40);
    assert_eq!(f.lanes.active_dispatch_identity(dispatch.lane()), Ok(None));
    assert_eq!(f.peers.state(f.owner.route()), Ok((PeerPhase::Retiring, 0)));
    assert_eq!(
        f.owner.child_destination(),
        Some(PeerCapabilityDestination { cnode: 55, slot: 6 })
    );
    assert_eq!(f.owner.space_binding(), Some(space()));
    let mut pool = crate::IngressReplyPool::new(22, 2).unwrap();
    pool.insert_pending(&mut output[1].reply, &f.receiver, &f.lanes, |_| {
        Ok::<_, u8>(ReplyBindingObservation::Free)
    })
    .unwrap();
    assert!(output[1].reply.is_none());
    f.owner
        .prove_retirement_drain(&f.peers, &f.lanes, |_| Ok::<_, u8>(true))
        .unwrap();
}

#[test]
fn stop_uncertainty_and_free_alone_never_cancel() {
    let mut f = Fixture::new();
    let dispatch = f.admitted();
    let mut output = Vec::new();
    assert_eq!(
        f.receiver.cancel_stopped_route(
            &f.owner,
            &mut f.lanes,
            &mut f.peers,
            &mut output,
            no_query
        ),
        Err(StoppedRouteError::NotStopped)
    );
    f.owner
        .begin_retirement(&mut f.peers, 7, 8, &f.lanes)
        .unwrap();
    assert!(f
        .owner
        .retire_effect(&f.peers, &f.lanes, |_| Err(7u8))
        .is_err());
    assert_eq!(
        f.receiver.cancel_stopped_route(
            &f.owner,
            &mut f.lanes,
            &mut f.peers,
            &mut output,
            no_query
        ),
        Err(StoppedRouteError::NotStopped)
    );
    assert_eq!(f.lanes.running(), Some(dispatch.lane()));
    assert!(output.is_empty());
}

#[test]
fn failed_final_query_keeps_all_calls_and_uncertain_reply_attempt() {
    let mut f = Fixture::new();
    let dispatch = f.admitted();
    f.receiver
        .reply_stored(f.owner.route(), dispatch, &f.lanes, bound, |_| {
            IngressReplyObservation::Indeterminate
        })
        .unwrap();
    f.capture(dispatch, 200);
    f.stop();
    let mut output = Vec::new();
    assert_eq!(
        f.receiver.cancel_stopped_route(
            &f.owner,
            &mut f.lanes,
            &mut f.peers,
            &mut output,
            |_, reply| if reply == 41 {
                Err(8u8)
            } else {
                Ok(ReplyBindingObservation::Free)
            }
        ),
        Err(StoppedRouteError::Query(8))
    );
    assert!(output.is_empty());
    assert_eq!(f.peers.state(f.owner.route()).unwrap().1, 2);
    assert_eq!(f.lanes.running(), Some(dispatch.lane()));
    assert!(f
        .receiver
        .reply_stored(f.owner.route(), dispatch, &f.lanes, bound, |_| panic!(
            "uncertain Reply cannot replay"
        ))
        .is_err());
    f.receiver
        .cancel_stopped_route(&f.owner, &mut f.lanes, &mut f.peers, &mut output, free)
        .unwrap();
    assert_eq!(output.len(), 2);
}

#[test]
fn semantic_owner_blocks_transport_cancellation() {
    let mut f = Fixture::new();
    let dispatch = f.admitted();
    f.lanes.suspend_running(dispatch.lane(), 40, 9).unwrap();
    f.lanes.resume_external(dispatch.lane(), 40, 9).unwrap();
    f.stop();
    assert_eq!(
        f.receiver.cancel_stopped_route(
            &f.owner,
            &mut f.lanes,
            &mut f.peers,
            &mut Vec::new(),
            no_query
        ),
        Err(StoppedRouteError::SemanticOwners)
    );
    assert_eq!(f.lanes.external_top(dispatch.lane()), Ok(Some(9)));
}

#[test]
fn checked_out_call_and_pending_receive_remain_owned() {
    let mut f = Fixture::new();
    let dispatch = f.admitted();
    let checkout = f.receiver.checkout(f.owner.route()).unwrap();
    f.stop();
    assert_eq!(
        f.receiver.cancel_stopped_route(
            &f.owner,
            &mut f.lanes,
            &mut f.peers,
            &mut Vec::new(),
            no_query
        ),
        Err(StoppedRouteError::Busy)
    );
    f.receiver.restore(checkout).ok().unwrap();
    f.receiver
        .begin_receive_for_owner(&f.lanes, IngressExecutionOwner::Dispatch(dispatch))
        .unwrap();
    assert_eq!(
        f.receiver.cancel_stopped_route(
            &f.owner,
            &mut f.lanes,
            &mut f.peers,
            &mut Vec::new(),
            no_query
        ),
        Err(StoppedRouteError::Busy)
    );
    assert!(f.receiver.phase().is_some());
    assert_eq!(f.peers.state(f.owner.route()).unwrap().1, 1);
}

#[test]
fn foreign_registry_lane_table_and_canonical_alias_refuse() {
    let mut f = Fixture::new();
    let dispatch = f.admitted();
    f.stop();
    let mut foreign_peers = PeerRegistry::new(22, 2);
    assert_eq!(
        f.receiver.cancel_stopped_route(
            &f.owner,
            &mut f.lanes,
            &mut foreign_peers,
            &mut Vec::new(),
            no_query
        ),
        Err(StoppedRouteError::WrongOwner)
    );
    let mut foreign_lanes = Lanes::new(2, 2);
    assert_eq!(
        f.receiver.cancel_stopped_route(
            &f.owner,
            &mut foreign_lanes,
            &mut f.peers,
            &mut Vec::new(),
            no_query
        ),
        Err(StoppedRouteError::WrongOwner)
    );
    let other = f
        .lanes
        .allocate(LaneBinding {
            executor_id: 99,
            receive_endpoint: 100,
            reply_object: 101,
        })
        .unwrap();
    f.lanes.lane_mut(other).unwrap().binding.reply_object = 40;
    assert_eq!(
        f.receiver.cancel_stopped_route(
            &f.owner,
            &mut f.lanes,
            &mut f.peers,
            &mut Vec::new(),
            no_query
        ),
        Err(StoppedRouteError::WrongOwner)
    );
    assert_eq!(f.lanes.running(), Some(dispatch.lane()));
}

#[test]
fn startup_and_empty_bootstrap_require_canonical_free_then_discharge_fence() {
    for bootstrap in [false, true] {
        let mut f = Fixture::new();
        if bootstrap {
            f.bootstrap();
        } else {
            f.owner
                .start(
                    &f.peers,
                    7,
                    8,
                    &mut f.lanes,
                    binding(),
                    space(),
                    free,
                    |_| Ok::<_, u8>(()),
                )
                .unwrap();
        }
        f.stop();
        assert_eq!(
            f.receiver.cancel_stopped_route(
                &f.owner,
                &mut f.lanes,
                &mut f.peers,
                &mut Vec::new(),
                bound
            ),
            Err(StoppedRouteError::NotFree)
        );
        let mut queries = 0;
        f.receiver
            .cancel_stopped_route(
                &f.owner,
                &mut f.lanes,
                &mut f.peers,
                &mut Vec::new(),
                |tcb, reply| {
                    assert_eq!((tcb, reply), (11, 33));
                    queries += 1;
                    free(tcb, reply)
                },
            )
            .unwrap();
        assert_eq!(queries, 1);
        assert_eq!(f.lanes.running(), None);
        assert_eq!(
            f.lanes.phase(f.owner.route().identity().lane),
            Ok(LanePhase::Idle)
        );
    }
}

#[test]
fn stopped_external_cancellation_preserves_epoch_until_transport_drain() {
    let mut f = Fixture::new();
    let dispatch = f.admitted();
    f.lanes.suspend_running(dispatch.lane(), 40, 9).unwrap();
    f.stop();
    let other = f
        .lanes
        .allocate(LaneBinding {
            executor_id: 99,
            receive_endpoint: 100,
            reply_object: 101,
        })
        .unwrap();
    f.lanes.begin_dispatch(other, 101).unwrap();
    f.lanes
        .cancel_external_stopped(&f.owner, &f.peers, dispatch, 9)
        .unwrap();
    assert_eq!(f.lanes.external_top(dispatch.lane()), Ok(None));
    assert_eq!(f.lanes.phase(dispatch.lane()), Ok(LanePhase::Suspended));
    assert_eq!(
        f.lanes.active_dispatch_identity(dispatch.lane()),
        Ok(Some(dispatch))
    );
    assert_eq!(f.lanes.running(), Some(other));
    assert!(f
        .lanes
        .cancel_external_stopped(&f.owner, &f.peers, dispatch, 9)
        .is_err());
    let mut output = Vec::new();
    f.receiver
        .cancel_stopped_route(&f.owner, &mut f.lanes, &mut f.peers, &mut output, free)
        .unwrap();
    assert_eq!(output.len(), 1);
    assert!(output[0].reply.is_none());
    assert_eq!(f.lanes.phase(dispatch.lane()), Ok(LanePhase::Idle));
    assert_eq!(f.lanes.running(), Some(other));
}

#[test]
fn external_cancellation_requires_stop_ack_exact_token_registry_and_epoch() {
    let mut f = Fixture::new();
    let dispatch = f.admitted();
    f.lanes.suspend_running(dispatch.lane(), 40, 9).unwrap();
    assert!(f
        .lanes
        .cancel_external_stopped(&f.owner, &f.peers, dispatch, 9)
        .is_err());
    f.stop();
    let foreign = PeerRegistry::new(22, 2);
    assert!(f
        .lanes
        .cancel_external_stopped(&f.owner, &foreign, dispatch, 9)
        .is_err());
    for token in [0, 8] {
        assert!(f
            .lanes
            .cancel_external_stopped(&f.owner, &f.peers, dispatch, token)
            .is_err());
    }
    let stale = LaneDispatchIdentity {
        lane: dispatch.lane(),
        epoch: dispatch.epoch() + 1,
    };
    assert!(f
        .lanes
        .cancel_external_stopped(&f.owner, &f.peers, stale, 9)
        .is_err());
    assert_eq!(f.lanes.external_top(dispatch.lane()), Ok(Some(9)));
}

#[test]
fn typed_frame_is_not_erased_by_external_cancellation() {
    let mut f = Fixture::new();
    let dispatch = f.admitted();
    let lane = dispatch.lane();
    let key = crate::SuspensionKey::provider_wait(1);
    f.lanes
        .admit_running(
            lane,
            40,
            key,
            1,
            crate::SuspensionOwner {
                provider_domain: 7,
                provider_generation: 8,
                dispatch_id: dispatch.epoch(),
                caller: crate::SuspensionCaller::Kernel { lane },
            },
            (),
        )
        .unwrap();
    f.lanes.select(key, ()).unwrap();
    f.lanes.begin_resume(lane, 40, key).unwrap();
    f.lanes.suspend_running(lane, 40, 9).unwrap();
    f.stop();
    assert!(f
        .lanes
        .cancel_external_stopped(&f.owner, &f.peers, dispatch, 9)
        .is_err());
    assert_eq!(f.lanes.external_top(lane), Ok(Some(9)));
    assert_eq!(f.lanes.suspension_count(lane), Ok(1));
}
