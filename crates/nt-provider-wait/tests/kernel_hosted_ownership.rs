//! Host composition of dispatch authority, the wire request, and dispatcher wait ownership.
//! The event backend models canonical leases; this does not execute native IPC.

use std::collections::BTreeMap;

use nt_component_suspension::{
    ComponentSuspensionLanes, LaneBinding, LaneError, LanePhase, SuspensionKey, SuspensionScope,
    TerminalStage, TerminalStageOutcome,
};
use nt_provider_wait::*;
use nt_time::TimeSnapshot;

type Lanes = ComponentSuspensionLanes<u64, i32>;

#[derive(Default)]
struct EventBackend {
    signaled: bool,
    next_lease: u64,
    leases: BTreeMap<u64, ProviderWaitOwner>,
    acquisitions: usize,
    consumptions: usize,
}

impl ProviderDispatcherWaitBackend for EventBackend {
    type Lease = u64;
    type Error = &'static str;

    fn acquire_dispatcher_wait(
        &mut self,
        owner: ProviderWaitOwner,
        object: ProviderWaitObject,
    ) -> Result<u64, Self::Error> {
        if (owner.provider_domain, owner.provider_generation) != (7, 3) || object != event() {
            return Err("wrong canonical event");
        }
        self.next_lease += 1;
        self.acquisitions += 1;
        assert!(self.leases.insert(self.next_lease, owner).is_none());
        Ok(self.next_lease)
    }

    fn dispatcher_is_ready(&self, lease: u64) -> bool {
        assert!(self.leases.contains_key(&lease));
        self.signaled
    }

    fn consume_ready_dispatcher(&mut self, lease: u64) {
        assert!(self.dispatcher_is_ready(lease));
        self.signaled = false;
        self.consumptions += 1;
    }

    fn release_dispatcher_wait(&mut self, lease: u64) {
        assert!(self.leases.remove(&lease).is_some());
    }
}

fn binding(id: u64) -> LaneBinding {
    LaneBinding {
        executor_id: 100 + id,
        receive_endpoint: 200 + id,
        reply_object: 300 + id,
    }
}

fn kernel_owner(lanes: &Lanes, lane: LaneHandle) -> ProviderWaitOwner {
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    ProviderWaitOwner {
        provider_domain: 7,
        provider_generation: 3,
        dispatch_id: dispatch.epoch(),
        caller: SuspensionCaller::Kernel {
            lane: dispatch.lane(),
        },
    }
}

fn hosted_owner() -> ProviderWaitOwner {
    ProviderWaitOwner {
        provider_domain: 7,
        provider_generation: 3,
        dispatch_id: 900,
        caller: SuspensionCaller::Hosted(SuspensionHostedClient {
            client_pi: 2,
            client_generation: 4,
            client_tid: 8,
            client_badge: 16,
        }),
    }
}

fn event() -> ProviderWaitObject {
    ProviderWaitObject::new(ProviderWaitObjectType::Event, 31, 2)
}

fn request(owner: ProviderWaitOwner, wait_id: u64) -> ProviderWaitRequest {
    let mut request = ProviderWaitRequest::empty();
    request
        .begin(
            ProviderWaitRequestMetadata {
                wait_id,
                owner,
                wait_type: ProviderWaitType::Any,
                wait_mode: ProviderWaitMode::Kernel,
                alertable: false,
                timeout_kind: ProviderWaitTimeoutKind::Infinite,
                timeout_100ns: 0,
            },
            &[event()],
        )
        .unwrap();
    assert_eq!(request.validate().unwrap().owner, owner);
    request
}

fn now() -> TimeSnapshot {
    TimeSnapshot {
        monotonic_100ns: 10,
        system_time_100ns: 100,
        clock_generation: 0,
    }
}

fn retire(
    lanes: &mut Lanes,
    lane: LaneHandle,
    reply: u64,
    key: SuspensionKey,
    owner: ProviderWaitOwner,
    continuation: u64,
    cancelled: bool,
) {
    let receipt = lanes
        .retain_terminal_running(lane, reply, key, owner, ())
        .unwrap();
    for stage in [
        TerminalStage::Output,
        TerminalStage::Context,
        TerminalStage::Publication,
        TerminalStage::Reply,
    ] {
        let mut attempt = lanes.begin_terminal_stage(receipt, reply, stage).unwrap();
        lanes
            .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
            .unwrap();
    }
    let retired = lanes
        .finish_terminal(receipt, reply, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(retired.suspension.owner, owner);
    assert_eq!(retired.suspension.continuation, continuation);
    assert_eq!(retired.suspension.cancelled, cancelled);
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
}

#[test]
fn kernel_dispatch_authority_survives_wire_encoding_and_completion_before_wait() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let owner = kernel_owner(&lanes, lane);
    let key = SuspensionKey::provider_wait(10);
    let mut backend = EventBackend {
        signaled: true,
        ..Default::default()
    };
    let mut arbiter = ProviderDispatcherWaitArbiter::new();

    let mut stale_lane = owner;
    stale_lane.caller = SuspensionCaller::Kernel {
        lane: LaneHandle {
            generation: lane.generation + 1,
            ..lane
        },
    };
    let mut stale_dispatch = owner;
    stale_dispatch.dispatch_id += 1;
    for claim in [stale_lane, stale_dispatch] {
        assert_eq!(
            lanes.admit_running(lane, reply, key, 1, claim, 44),
            Err(LaneError::InvalidIdentity)
        );
        assert_eq!(lanes.phase(lane), Ok(LanePhase::Running));
        assert_eq!(lanes.total_suspensions(), 0);
    }
    for claim in [stale_lane, stale_dispatch, hosted_owner()] {
        assert_eq!(
            arbiter.admit(&mut backend, &request(claim, 10), owner, 1, now()),
            Err(ProviderDispatcherWaitError::OwnerMismatch)
        );
    }
    assert_eq!(backend.acquisitions, 0);
    assert!(backend.signaled);

    lanes.admit_running(lane, reply, key, 1, owner, 44).unwrap();
    assert_eq!(
        arbiter.admit(&mut backend, &request(owner, 10), owner, 1, now()),
        Ok(ProviderDispatcherWaitAdmission::Satisfied {
            wait_id: 10,
            status: STATUS_WAIT_0,
        })
    );
    assert_eq!(lanes.rollback_admission(lane, reply, key), Ok(44));
    assert_eq!(kernel_owner(&lanes, lane), owner);
    assert!(arbiter.is_empty());
    assert!(backend.leases.is_empty());
    assert_eq!(backend.consumptions, 1);
    lanes.finish_dispatch(lane, reply).unwrap();

    lanes.begin_dispatch(lane, reply).unwrap();
    assert_ne!(kernel_owner(&lanes, lane).dispatch_id, owner.dispatch_id);
    assert_eq!(
        lanes.admit_running(lane, reply, key, 2, owner, 45),
        Err(LaneError::InvalidIdentity)
    );
    lanes.finish_dispatch(lane, reply).unwrap();
}

#[test]
fn hosted_teardown_and_kernel_rearm_keep_distinct_pending_owners() {
    let mut lanes = Lanes::new(2, 4);
    let kernel_lane = lanes.allocate(binding(1)).unwrap();
    let hosted_lane = lanes.allocate(binding(2)).unwrap();
    let kernel_reply = binding(1).reply_object;
    let hosted_reply = binding(2).reply_object;
    let mut backend = EventBackend::default();
    let mut arbiter = ProviderDispatcherWaitArbiter::new();

    lanes.begin_dispatch(kernel_lane, kernel_reply).unwrap();
    let kernel = kernel_owner(&lanes, kernel_lane);
    let kernel_key = SuspensionKey::provider_wait(20);
    lanes
        .admit_running(kernel_lane, kernel_reply, kernel_key, 1, kernel, 100)
        .unwrap();
    assert_eq!(
        arbiter.admit(&mut backend, &request(kernel, 20), kernel, 1, now()),
        Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 20 })
    );

    lanes.begin_dispatch(hosted_lane, hosted_reply).unwrap();
    let hosted = ProviderWaitOwner {
        dispatch_id: kernel.dispatch_id,
        ..hosted_owner()
    };
    let hosted_key = SuspensionKey::provider_wait(21);
    lanes
        .admit_running(hosted_lane, hosted_reply, hosted_key, 2, hosted, 200)
        .unwrap();
    assert_eq!(
        arbiter.admit(&mut backend, &request(hosted, 21), hosted, 2, now()),
        Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 21 })
    );
    assert_eq!(backend.leases.len(), 2);
    assert!(arbiter.pop_ready(&mut backend).is_none());

    backend.signaled = true;
    let ready = arbiter.pop_ready(&mut backend).unwrap();
    assert_eq!(ready.owner, kernel);
    assert_eq!(ready.wait_id, 20);
    assert_eq!(ready.admission_sequence, 1);
    assert!(!ready.cancelled);
    assert_eq!(
        backend.leases.values().copied().collect::<Vec<_>>(),
        [hosted]
    );
    assert!(arbiter.pop_ready(&mut backend).is_none());
    lanes.select(kernel_key, ready.status).unwrap();
    lanes
        .begin_resume(kernel_lane, kernel_reply, kernel_key)
        .unwrap();

    let lpc_key = SuspensionKey::lpc_request(22);
    lanes
        .rearm_running(
            kernel_lane,
            kernel_reply,
            kernel_key,
            lpc_key,
            3,
            kernel,
            101,
        )
        .unwrap();
    assert_eq!(kernel_owner(&lanes, kernel_lane), kernel);
    assert!(lanes.locate(kernel_key).is_none());
    assert_eq!(lanes.locate(lpc_key).unwrap().1.owner, kernel);

    let thread_scope = SuspensionScope::Thread {
        domain: 7,
        provider_generation: 3,
        client_pi: 2,
        client_generation: 4,
        client_tid: 8,
        client_badge: 16,
    };
    assert_eq!(
        lanes.next_cancellable_in_scope(thread_scope),
        Some((hosted_lane, hosted_key))
    );
    let kernel_scope = SuspensionScope::KernelLane {
        domain: 7,
        provider_generation: 3,
        lane: kernel_lane,
    };
    assert!(kernel_scope.matches(kernel));
    assert!(!kernel_scope.matches(hosted));
    let cancelled = arbiter
        .cancel(&mut backend, 21, 0xc000_0120u32 as i32)
        .unwrap();
    assert_eq!(cancelled.owner, hosted);
    assert!(cancelled.cancelled);
    lanes.cancel(hosted_key, cancelled.status).unwrap();
    lanes
        .begin_resume(hosted_lane, hosted_reply, hosted_key)
        .unwrap();
    retire(
        &mut lanes,
        hosted_lane,
        hosted_reply,
        hosted_key,
        hosted,
        200,
        true,
    );
    assert!(lanes.locate(lpc_key).is_some());
    assert!(arbiter.is_empty());
    assert!(backend.leases.is_empty());

    lanes.select(lpc_key, STATUS_WAIT_0).unwrap();
    lanes
        .begin_resume(kernel_lane, kernel_reply, lpc_key)
        .unwrap();
    retire(
        &mut lanes,
        kernel_lane,
        kernel_reply,
        lpc_key,
        kernel,
        101,
        false,
    );
    assert_eq!(lanes.total_suspensions(), 0);
    assert_eq!(backend.acquisitions, 2);
    assert_eq!(backend.consumptions, 1);
}
