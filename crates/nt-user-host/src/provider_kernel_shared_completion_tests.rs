use super::*;
use nt_component_suspension::peer_registry::{PeerRegistry, PeerRoute};
use nt_component_suspension::{
    ComponentIngress, IngressExecutionOwner, IngressReceiveDisposition, IngressReceiver,
    IngressReplyObservation, IngressReplyPool, IpcBufferSnapshot, ReceivedMessage,
    ReplyBindingObservation,
};

type SharedLanes = ComponentSuspensionLanes<u64, i32, u64>;
const STATUS: u32 = 0xc000_0001;

fn bound(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::BoundToTarget)
}

struct Fixture {
    pm: ProcessManager,
    catalog: ProviderDomainCatalog,
    lanes: SharedLanes,
    activations: KernelProviderActivations,
    caller: KernelProviderCaller,
    peers: PeerRegistry,
    route: PeerRoute,
    receiver: IngressReceiver<ReceivedMessage>,
}

impl Fixture {
    fn new() -> Self {
        let mut pm = bootstrap().into_parts().pm;
        let native = requestor(&mut pm, 0x3000);
        let mut catalog = ProviderDomainCatalog::new();
        let provider = catalog.register().unwrap();
        let mut lanes = SharedLanes::new(1, 4);
        let mut peers = PeerRegistry::new(20, 1);
        let (lane, mut registration) = lanes
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
        let route = peers.publish_lane(&mut registration, 1, 2, &lanes).unwrap();
        lanes
            .begin_startup(lane, 30, |_, _| Ok::<_, u8>(ReplyBindingObservation::Free))
            .unwrap();
        lanes.complete_startup(lane, 30, bound).unwrap();
        let mut receiver = IngressReceiver::new(20, 40, 2).unwrap();
        receiver.begin_receive(&lanes).unwrap();
        receiver
            .capture(ReceivedMessage::new(
                route.badge(),
                55 << 12,
                [0; 4],
                IpcBufferSnapshot::capture(|_| 0),
            ))
            .ok()
            .unwrap();
        receiver
            .resolve(IngressReceiveDisposition::Call)
            .ok()
            .unwrap();
        receiver
            .retain(
                &lanes,
                ComponentIngress::new(20, 41).unwrap(),
                &mut peers,
                route.badge(),
                bound,
            )
            .ok()
            .unwrap();
        let mut pool = IngressReplyPool::new(20, 1).unwrap();
        let dispatch = pool
            .admit(
                &mut receiver,
                route,
                &mut lanes,
                &peers,
                1,
                2,
                |_, reply| {
                    Ok::<_, u8>(if reply == 30 {
                        ReplyBindingObservation::Free
                    } else {
                        ReplyBindingObservation::BoundToTarget
                    })
                },
            )
            .unwrap();
        receiver
            .reply_stored(route, dispatch, &lanes, bound, |_| {
                IngressReplyObservation::Acknowledged
            })
            .unwrap();
        let mut activations = KernelProviderActivations::new();
        let caller = activations
            .capture(&mut pm, &catalog, &lanes, provider, lane, native)
            .unwrap();
        Self {
            pm,
            catalog,
            lanes,
            activations,
            caller,
            peers,
            route,
            receiver,
        }
    }

    fn begin(&mut self) -> KernelProviderSharedCompletion {
        self.activations
            .begin_shared_completion(self.caller, &self.pm, &self.catalog, &self.lanes, STATUS)
            .unwrap()
    }

    fn receive_completion(&mut self) {
        self.receiver
            .begin_receive_for_owner(
                &self.lanes,
                IngressExecutionOwner::Dispatch(self.caller.dispatch()),
            )
            .unwrap();
        self.receiver
            .capture(ReceivedMessage::new(
                self.route.badge(),
                55 << 12,
                [0; 4],
                IpcBufferSnapshot::capture(|_| 0),
            ))
            .ok()
            .unwrap();
        self.receiver
            .resolve(IngressReceiveDisposition::Call)
            .ok()
            .unwrap();
        self.receiver
            .retain(
                &self.lanes,
                ComponentIngress::new(20, 42).unwrap(),
                &mut self.peers,
                self.route.badge(),
                bound,
            )
            .ok()
            .unwrap();
    }

    fn complete_ingress(&mut self) {
        self.receiver
            .complete_from_message(
                self.route,
                self.caller.dispatch(),
                41,
                55,
                &mut self.lanes,
                &mut self.peers,
                |_, reply| {
                    Ok::<_, u8>(if reply == 41 {
                        ReplyBindingObservation::BoundToTarget
                    } else {
                        ReplyBindingObservation::Free
                    })
                },
            )
            .unwrap();
    }

    fn assert_fenced(&mut self) {
        assert!(self.activations.completion(self.caller).is_err());
        assert!(!self.activations.has_ready_completion());
        let mut cursor = self.activations.completion_cursor();
        assert!(self
            .activations
            .next_ready_completion(&mut cursor)
            .is_none());
        assert!(self
            .activations
            .begin_shared_completion(self.caller, &self.pm, &self.catalog, &self.lanes, STATUS)
            .is_err());
        assert_eq!(references(&self.pm, self.caller.thread()), (1, 1));
        assert!(self.activations.release(self.caller, &mut self.pm).is_err());
    }
}

#[test]
fn shared_return_preserves_epoch_until_authenticated_completion_and_then_publishes() {
    let mut f = Fixture::new();
    let attempt = f.begin();
    assert_eq!(attempt.route(), f.route);
    assert_eq!(attempt.dispatch(), f.caller.dispatch());
    assert_eq!(attempt.reply(), 40);
    assert_eq!(
        f.lanes.phase(f.caller.dispatch().lane()),
        Ok(LanePhase::Running)
    );
    f.assert_fenced();
    f.receive_completion();
    f.complete_ingress();
    let receipt = f
        .activations
        .record_shared_completion(attempt, &f.pm, &f.lanes, Ok(()))
        .unwrap();
    assert_eq!(receipt.status(), STATUS);
    assert_eq!(f.activations.completion(f.caller), Ok(receipt));
    assert_eq!(
        f.activations.acknowledge_completion(receipt, &mut f.pm),
        Ok(STATUS)
    );
    assert_eq!(references(&f.pm, f.caller.thread()), (0, 0));
}

#[test]
fn acknowledged_request_is_not_completion_and_failure_never_replays() {
    let mut f = Fixture::new();
    let attempt = f.begin();
    assert!(f
        .activations
        .record_shared_completion(attempt, &f.pm, &f.lanes, Ok(()))
        .is_err());
    f.assert_fenced();
    let mut f = Fixture::new();
    let attempt = f.begin();
    assert_eq!(
        f.activations.record_shared_completion(
            attempt,
            &f.pm,
            &f.lanes,
            Err(STATUS_INVALID_PARAMETER)
        ),
        Err(STATUS_INVALID_PARAMETER)
    );
    f.assert_fenced();
    assert_eq!(
        f.lanes.active_dispatch_identity(f.caller.dispatch().lane()),
        Ok(Some(f.caller.dispatch()))
    );
}

#[test]
fn shared_terminal_ack_is_not_a_ready_receipt_and_local_refusal_preserves_owner() {
    let mut f = Fixture::new();
    let lane = f.caller.dispatch().lane();
    let key = SuspensionKey::provider_wait(71);
    f.lanes
        .admit_running(lane, 40, key, 1, f.caller.owner(), 500)
        .unwrap();
    f.lanes.select(key, 258).unwrap();
    f.lanes.begin_resume(lane, 40, key).unwrap();
    let terminal = f
        .activations
        .retain_terminal_completion(f.caller, &f.pm, &f.catalog, &mut f.lanes, key, 1234, STATUS)
        .unwrap();
    assert!(f
        .activations
        .finish_shared_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Ok(()))
        .is_err());
    let mut local = f
        .lanes
        .begin_terminal_stage(terminal, 40, TerminalStage::LocalDelivery)
        .unwrap();
    f.lanes
        .record_terminal_stage(&mut local, 40, TerminalStageOutcome::Acknowledged)
        .unwrap();
    assert!(f
        .activations
        .finish_shared_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Err(7))
        .unwrap()
        .is_none());
    assert!(f.activations.completion(f.caller).is_err());
    let (attempt, retired) = f
        .activations
        .finish_shared_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Ok(()))
        .unwrap()
        .unwrap();
    drop(retired);
    assert_eq!(f.lanes.phase(lane), Ok(LanePhase::Running));
    assert_eq!(
        f.lanes.active_dispatch_identity(lane),
        Ok(Some(f.caller.dispatch()))
    );
    f.assert_fenced();
    f.receive_completion();
    f.complete_ingress();
    assert!(f
        .activations
        .record_shared_completion(attempt, &f.pm, &f.lanes, Ok(()))
        .is_ok());
}
