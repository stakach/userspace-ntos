use super::*;
use crate::provider_kernel_pump::{
    KernelProviderPumpFacts, KernelProviderPumpProgress, PumpProgressError,
};
use nt_component_suspension::SuspensionHostedClient;
use nt_provider_wait::{
    ProviderWaitMode, ProviderWaitObject, ProviderWaitObjectType, ProviderWaitRequest,
    ProviderWaitRequestMetadata, ProviderWaitTimeoutKind, ProviderWaitType,
};

fn request(owner: SuspensionOwner) -> ProviderWaitRequest {
    let mut request = ProviderWaitRequest::empty();
    request
        .begin(
            ProviderWaitRequestMetadata {
                wait_id: 71,
                owner,
                wait_type: ProviderWaitType::Any,
                wait_mode: ProviderWaitMode::Kernel,
                alertable: false,
                timeout_kind: ProviderWaitTimeoutKind::Relative,
                timeout_100ns: -100_000,
            },
            &[ProviderWaitObject::new(
                ProviderWaitObjectType::Event,
                81,
                1,
            )],
        )
        .unwrap();
    request
}

fn observed(reply_cap: u64, mask: u8) -> KernelProviderPumpProgress {
    let mut progress = KernelProviderPumpProgress::new(reply_cap).unwrap();
    let mut attempt = progress.begin_initial().unwrap();
    progress
        .observe(
            &mut attempt,
            KernelProviderPumpFacts {
                observed_at: nt_kernel_exec::TimeSnapshot {
                    monotonic_100ns: 10,
                    system_time_100ns: 100,
                    clock_generation: 0,
                },
                reply_cap,
                completed: mask & 1 != 0,
                callback_suspended: mask & 2 != 0,
                provider_wait_suspended: mask & 4 != 0,
                lpc_wait_suspended: mask & 8 != 0,
                scheduler_yielded: mask & 16 != 0,
            },
            if mask == 1 { Some(0) } else { None },
        )
        .unwrap();
    progress
}

#[test]
fn shared_interim_handoff_preserves_caller_but_rejects_old_transport_observations() {
    use nt_component_suspension::{
        peer_registry::PeerRegistry, ComponentIngress, IngressExecutionOwner,
        IngressReceiveDisposition, IngressReceiver, IngressReplyObservation, IngressReplyPool,
        ReplyBindingObservation,
    };
    let mut pm = bootstrap().into_parts().pm;
    let native = requestor(&mut pm, 0x3000);
    let mut catalog = ProviderDomainCatalog::new();
    let provider = catalog.register().unwrap();
    let mut lanes = ComponentSuspensionLanes::<KernelProviderWaitCapture, u32, ()>::new(1, 4);
    let mut peers = PeerRegistry::new(22, 1);
    let (lane, mut registration) = lanes
        .allocate_shared_staged(
            &mut peers,
            provider.domain,
            provider.generation,
            LaneBinding {
                executor_id: 11,
                receive_endpoint: 22,
                reply_object: 33,
            },
        )
        .unwrap();
    let route = peers
        .publish_lane(
            &mut registration,
            provider.domain,
            provider.generation,
            &lanes,
        )
        .unwrap();
    lanes
        .begin_startup(lane, 33, |_, _| Ok::<_, u8>(ReplyBindingObservation::Free))
        .unwrap();
    lanes
        .complete_startup(lane, 33, |_, _| {
            Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)
        })
        .unwrap();
    let mut receiver = IngressReceiver::new(22, 40, 2).unwrap();
    receiver.begin_receive(&lanes).unwrap();
    receiver.capture(1u64).ok().unwrap();
    receiver
        .resolve(IngressReceiveDisposition::Call)
        .ok()
        .unwrap();
    receiver
        .retain(
            &lanes,
            ComponentIngress::new(22, 41).unwrap(),
            &mut peers,
            route.badge(),
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
        )
        .ok()
        .unwrap();
    let mut pool = IngressReplyPool::new(22, 1).unwrap();
    let dispatch = pool
        .admit(
            &mut receiver,
            route,
            &mut lanes,
            &peers,
            provider.domain,
            provider.generation,
            |_, reply| {
                Ok::<_, u8>(if reply == 33 {
                    ReplyBindingObservation::Free
                } else {
                    ReplyBindingObservation::BoundToTarget
                })
            },
        )
        .unwrap();
    let mut activations = KernelProviderActivations::new();
    let caller = activations
        .capture_with_recipient(
            &mut pm,
            &catalog,
            &lanes,
            provider,
            lane,
            native,
            crate::provider_kernel_wait::KernelProviderWaitState::new(40).unwrap(),
        )
        .unwrap();
    let old_progress = observed(40, 4);
    let wait = request(caller.owner());
    let mut initial = activations
        .recipient_mut(caller)
        .unwrap()
        .begin_initial()
        .unwrap();
    let wait_facts = KernelProviderPumpFacts {
        observed_at: nt_kernel_exec::TimeSnapshot {
            monotonic_100ns: 10,
            system_time_100ns: 100,
            clock_generation: 0,
        },
        reply_cap: 40,
        completed: false,
        callback_suspended: false,
        provider_wait_suspended: true,
        lpc_wait_suspended: false,
        scheduler_yielded: false,
    };
    activations
        .recipient_mut(caller)
        .unwrap()
        .observe(&mut initial, wait_facts, None)
        .unwrap();
    let old_capture = activations
        .capture_provider_wait(
            caller,
            &pm,
            &catalog,
            &lanes,
            40,
            activations.recipient(caller).unwrap().progress(),
            wait,
        )
        .unwrap();
    activations
        .recipient_mut(caller)
        .unwrap()
        .retain_provider_wait(wait, Ok(old_capture))
        .unwrap();
    lanes
        .admit_running(lane, 40, old_capture.key(), 1, caller.owner(), old_capture)
        .unwrap();
    lanes.select(old_capture.key(), 0).unwrap();
    let (_, mut resume_attempt, _) = activations
        .begin_wait_resume(caller, &pm, &catalog, &mut lanes, old_capture)
        .unwrap()
        .into_parts();
    receiver
        .reply_stored(
            route,
            dispatch,
            &lanes,
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
            |_| IngressReplyObservation::Acknowledged,
        )
        .unwrap();
    receiver
        .begin_receive_for_owner(&lanes, IngressExecutionOwner::Dispatch(dispatch))
        .unwrap();
    receiver.capture(2u64).ok().unwrap();
    receiver
        .resolve(IngressReceiveDisposition::Call)
        .ok()
        .unwrap();
    receiver
        .retain(
            &lanes,
            ComponentIngress::new(22, 42).unwrap(),
            &mut peers,
            route.badge(),
            |_, _| Ok::<_, u8>(ReplyBindingObservation::BoundToTarget),
        )
        .ok()
        .unwrap();
    let mut pending = None;
    receiver
        .adopt_interim_call(
            route,
            dispatch,
            41,
            &mut lanes,
            &mut peers,
            &mut pending,
            |_, reply| {
                Ok::<_, u8>(if reply == 40 {
                    ReplyBindingObservation::Free
                } else {
                    ReplyBindingObservation::BoundToTarget
                })
            },
        )
        .unwrap();
    assert_eq!(caller.current_binding(&lanes).unwrap().reply_object, 41);
    assert_eq!(activations.validate(caller, &pm, &catalog, &lanes), Ok(()));
    assert_eq!(
        activations.validate_wait_execution(
            caller,
            &pm,
            &catalog,
            &lanes,
            old_capture,
            &resume_attempt
        ),
        Ok(())
    );
    let yielded = KernelProviderPumpFacts {
        reply_cap: 41,
        provider_wait_suspended: false,
        scheduler_yielded: true,
        ..wait_facts
    };
    activations
        .recipient_mut(caller)
        .unwrap()
        .observe_current(&mut resume_attempt, yielded, None, 41)
        .unwrap();
    let receive_attempt = activations
        .recipient_mut(caller)
        .unwrap()
        .begin_receive_after_yield()
        .unwrap();
    assert_eq!(
        activations.validate_wait_execution(
            caller,
            &pm,
            &catalog,
            &lanes,
            old_capture,
            &receive_attempt
        ),
        Ok(())
    );
    assert!(activations
        .capture_provider_wait(caller, &pm, &catalog, &lanes, 40, &old_progress, wait)
        .is_err());
    assert!(activations
        .capture_provider_wait(caller, &pm, &catalog, &lanes, 41, &old_progress, wait)
        .is_err());
    let envelope = KernelProviderServiceEnvelope {
        badge: route.badge(),
        message_info: 77 << 12,
        reply_cap: 40,
    };
    assert!(activations
        .validate_service_call(caller, &pm, &catalog, &lanes, envelope, 77 << 12)
        .is_err());
    assert_eq!(
        activations.validate_service_call(
            caller,
            &pm,
            &catalog,
            &lanes,
            KernelProviderServiceEnvelope {
                reply_cap: 41,
                ..envelope
            },
            77 << 12
        ),
        Ok(())
    );
    for badge in [0, route.badge() + 1] {
        assert!(activations
            .validate_service_call(
                caller,
                &pm,
                &catalog,
                &lanes,
                KernelProviderServiceEnvelope {
                    badge,
                    reply_cap: 41,
                    ..envelope
                },
                77 << 12
            )
            .is_err());
    }
    let mut progress = KernelProviderPumpProgress::new(40).unwrap();
    let mut attempt = progress.begin_initial().unwrap();
    let facts = KernelProviderPumpFacts {
        observed_at: old_capture.observed_at(),
        reply_cap: 41,
        completed: false,
        callback_suspended: false,
        provider_wait_suspended: true,
        lpc_wait_suspended: false,
        scheduler_yielded: false,
    };
    progress
        .observe_current(
            &mut attempt,
            facts,
            None,
            caller.current_binding(&lanes).unwrap().reply_object,
        )
        .unwrap();
    assert!(!progress.observed_provider_wait(40));
    let current = activations
        .capture_provider_wait(caller, &pm, &catalog, &lanes, 41, &progress, wait)
        .unwrap();
    assert_eq!(current.caller(), old_capture.caller());
    assert_ne!(current.observation(), old_capture.observation());
    assert!(progress
        .observe_current(&mut attempt, facts, None, 41)
        .is_err());
}

struct Fixture {
    pm: ProcessManager,
    catalog: ProviderDomainCatalog,
    provider: ProviderDomainIdentity,
    lanes: Lanes,
    activations: KernelProviderActivations,
    caller: KernelProviderCaller,
    progress: KernelProviderPumpProgress,
    request: ProviderWaitRequest,
    received_reply: u64,
}

impl Fixture {
    fn new() -> Self {
        let mut pm = bootstrap().into_parts().pm;
        let native = requestor(&mut pm, 0x3000);
        let mut catalog = ProviderDomainCatalog::new();
        let provider = catalog.register().unwrap();
        let mut lanes = Lanes::new(1, 4);
        let lane = lanes.allocate(binding(1)).unwrap();
        lanes.begin_dispatch(lane, binding(1).reply_object).unwrap();
        let mut activations = KernelProviderActivations::new();
        let caller = activations
            .capture(&mut pm, &catalog, &lanes, provider, lane, native)
            .unwrap();
        let received_reply = caller.current_binding(&lanes).unwrap().reply_object;
        Self {
            pm,
            catalog,
            provider,
            lanes,
            activations,
            caller,
            progress: observed(binding(1).reply_object, 4),
            request: request(caller.owner()),
            received_reply,
        }
    }

    fn capture(&self) -> Result<KernelProviderWaitCapture, u32> {
        self.activations.capture_provider_wait(
            self.caller,
            &self.pm,
            &self.catalog,
            &self.lanes,
            self.received_reply,
            &self.progress,
            self.request,
        )
    }

    fn assert_unmodified(&self) {
        let lane = self.caller.dispatch.lane();
        assert_eq!(self.lanes.phase(lane), Ok(LanePhase::Running));
        assert_eq!(
            self.lanes.active_dispatch_identity(lane),
            Ok(Some(self.caller.dispatch))
        );
        assert_eq!(self.lanes.suspension_count(lane), Ok(0));
        assert_eq!(self.lanes.external_depth(lane), Ok(0));
        assert_eq!(references(&self.pm, self.caller.thread()), (1, 1));
        assert!(self.activations.completion(self.caller).is_err());
    }
}

#[test]
fn capture_owns_copied_request_without_admitting_wait_or_execution() {
    let mut f = Fixture::new();
    let expected = f.request;
    let captured = f.capture().unwrap();
    assert_eq!(captured.caller(), f.caller);
    assert_eq!(captured.owner(), f.caller.owner());
    assert_eq!(captured.key(), SuspensionKey::provider_wait(71));
    assert_eq!(captured.request(), &expected);
    f.request = ProviderWaitRequest::empty();
    assert_eq!(captured.request(), &expected);
    f.assert_unmodified();
    assert_eq!(
        f.activations.validate_resume(
            captured.caller(),
            &f.pm,
            &f.catalog,
            &f.lanes,
            captured.key()
        ),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        f.progress.begin_initial().unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(
        f.progress.begin_receive_after_yield().unwrap_err(),
        PumpProgressError::NotReady
    );
    assert!(f
        .progress
        .observed_provider_wait(f.caller.current_binding(&f.lanes).unwrap().reply_object));
}

#[test]
fn only_exact_provider_wait_stop_and_reply_can_be_captured() {
    let mut f = Fixture::new();
    let reply = f.caller.current_binding(&f.lanes).unwrap().reply_object;
    for mask in 0..32 {
        f.progress = observed(reply, mask);
        assert_eq!(f.progress.observed_provider_wait(reply), mask == 4);
        assert!(!f.progress.observed_provider_wait(0));
        assert!(!f.progress.observed_provider_wait(reply + 1));
        assert_eq!(f.capture().is_ok(), mask == 4);
        f.assert_unmodified();
    }
    f.progress = observed(reply, 4);
    for wrong in [0, reply + 1] {
        assert_eq!(
            f.activations.capture_provider_wait(
                f.caller,
                &f.pm,
                &f.catalog,
                &f.lanes,
                wrong,
                &f.progress,
                f.request,
            ),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
    f.progress = observed(reply + 1, 4);
    assert_eq!(f.capture(), Err(STATUS_INVALID_PARAMETER));
    f.assert_unmodified();
}

#[test]
fn fresh_or_unobserved_pump_is_not_a_stopped_wait() {
    let mut f = Fixture::new();
    let reply = f.caller.current_binding(&f.lanes).unwrap().reply_object;
    f.progress = KernelProviderPumpProgress::new(reply).unwrap();
    assert!(!f.progress.observed_provider_wait(reply));
    assert_eq!(f.capture(), Err(STATUS_INVALID_PARAMETER));
    let attempt = f.progress.begin_initial().unwrap();
    assert!(!f.progress.observed_provider_wait(reply));
    assert_eq!(f.capture(), Err(STATUS_INVALID_PARAMETER));
    drop(attempt);
    assert_eq!(f.capture(), Err(STATUS_INVALID_PARAMETER));
    f.assert_unmodified();
}

#[test]
fn malformed_wire_requests_are_rejected_without_lane_or_reference_effects() {
    let mut f = Fixture::new();
    let valid = f.request;
    for case in 0..8 {
        f.request = valid;
        match case {
            0 => f.request.header.magic = 0,
            1 => f.request.header.wait_id = 0,
            2 => f.request.header.object_count = 0,
            3 => f.request.header.request_size += 1,
            4 => f.request.header.wait_mode = u32::MAX,
            5 => f.request.header.timeout_100ns = 1,
            6 => f.request.objects[0].flags = u32::MAX,
            7 => f.request.objects[1] = f.request.objects[0],
            _ => unreachable!(),
        }
        assert!(f.request.validate().is_err());
        assert_eq!(f.capture(), Err(STATUS_INVALID_PARAMETER));
        f.assert_unmodified();
        assert!(f
            .progress
            .observed_provider_wait(f.caller.current_binding(&f.lanes).unwrap().reply_object));
    }
}

#[test]
fn valid_foreign_hosted_kernel_and_dispatch_owners_are_not_kernel_authority() {
    let mut f = Fixture::new();
    let owner = f.caller.owner();
    let lane = f.caller.dispatch.lane();
    let owners = [
        SuspensionOwner {
            caller: SuspensionCaller::Hosted(SuspensionHostedClient {
                client_pi: 2,
                client_generation: 1,
                client_tid: 24,
                client_badge: 4,
            }),
            ..owner
        },
        SuspensionOwner {
            caller: SuspensionCaller::Kernel {
                lane: LaneHandle {
                    generation: lane.generation + 1,
                    ..lane
                },
            },
            ..owner
        },
        SuspensionOwner {
            provider_generation: owner.provider_generation + 1,
            ..owner
        },
        SuspensionOwner {
            dispatch_id: owner.dispatch_id + 1,
            ..owner
        },
    ];
    for foreign in owners {
        f.request = request(foreign);
        assert!(f.request.validate().is_ok());
        assert_eq!(f.capture(), Err(STATUS_INVALID_PARAMETER));
        f.assert_unmodified();
    }
}

#[test]
fn foreign_authority_and_retired_provider_do_not_capture_request() {
    let mut f = Fixture::new();
    let mut other_pm = bootstrap().into_parts().pm;
    requestor(&mut other_pm, 0x3000);
    assert_eq!(
        f.activations.capture_provider_wait(
            f.caller,
            &other_pm,
            &f.catalog,
            &f.lanes,
            f.caller.current_binding(&f.lanes).unwrap().reply_object,
            &f.progress,
            f.request,
        ),
        Err(STATUS_INVALID_HANDLE)
    );
    let mut other_catalog = ProviderDomainCatalog::new();
    assert_eq!(other_catalog.register().unwrap(), f.provider);
    assert_eq!(
        f.activations.capture_provider_wait(
            f.caller,
            &f.pm,
            &other_catalog,
            &f.lanes,
            f.caller.current_binding(&f.lanes).unwrap().reply_object,
            &f.progress,
            f.request,
        ),
        Err(STATUS_INVALID_HANDLE)
    );
    let mut other_lanes = Lanes::new(1, 4);
    let other_lane = other_lanes.allocate(binding(2)).unwrap();
    assert_eq!(other_lane, f.caller.dispatch.lane());
    other_lanes
        .begin_dispatch(other_lane, binding(2).reply_object)
        .unwrap();
    assert_eq!(
        f.activations.capture_provider_wait(
            f.caller,
            &f.pm,
            &f.catalog,
            &other_lanes,
            f.caller.current_binding(&f.lanes).unwrap().reply_object,
            &f.progress,
            f.request,
        ),
        Err(STATUS_INVALID_HANDLE)
    );
    f.catalog.retire(f.provider, 0).unwrap();
    assert_eq!(f.capture(), Err(STATUS_INVALID_HANDLE));
    f.assert_unmodified();
}

#[test]
fn old_dispatch_and_suspended_lane_cannot_capture_fresh_provider_request() {
    let mut f = Fixture::new();
    let lane = f.caller.dispatch.lane();
    let reply = f.caller.current_binding(&f.lanes).unwrap().reply_object;
    f.lanes.suspend_running(lane, reply, 91).unwrap();
    assert_eq!(f.capture(), Err(STATUS_INVALID_HANDLE));
    assert_eq!(f.lanes.phase(lane), Ok(LanePhase::Suspended));
    assert_eq!(f.lanes.external_depth(lane), Ok(1));
    f.lanes.resume_external(lane, reply, 91).unwrap();
    f.lanes.complete_external(lane, reply, 91).unwrap();
    assert_eq!(f.lanes.phase(lane), Ok(LanePhase::Idle));
    f.lanes.begin_dispatch(lane, reply).unwrap();
    let current = f.lanes.active_dispatch_identity(lane).unwrap();
    assert_ne!(current, Some(f.caller.dispatch));
    assert_eq!(f.capture(), Err(STATUS_INVALID_HANDLE));
    assert_eq!(f.lanes.active_dispatch_identity(lane).unwrap(), current);
    assert_eq!(f.lanes.phase(lane), Ok(LanePhase::Running));
    assert_eq!(f.lanes.suspension_count(lane), Ok(0));
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
}

#[test]
fn exited_original_caller_is_retained_but_cannot_capture_new_wait() {
    let mut f = Fixture::new();
    f.pm.terminate_thread(f.caller.thread().thread_id(), 0)
        .unwrap();
    assert_eq!(
        f.activations
            .validate_retained(f.caller, &f.pm, &f.catalog, &f.lanes),
        Ok(())
    );
    assert!(f.capture().is_err());
    f.assert_unmodified();
    assert!(f
        .progress
        .observed_provider_wait(f.caller.current_binding(&f.lanes).unwrap().reply_object));
}
