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

struct Fixture {
    pm: ProcessManager,
    catalog: ProviderDomainCatalog,
    provider: ProviderDomainIdentity,
    lanes: Lanes,
    activations: KernelProviderActivations,
    caller: KernelProviderCaller,
    progress: KernelProviderPumpProgress,
    request: ProviderWaitRequest,
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
        Self {
            pm,
            catalog,
            provider,
            lanes,
            activations,
            caller,
            progress: observed(binding(1).reply_object, 4),
            request: request(caller.owner()),
        }
    }

    fn capture(&self) -> Result<KernelProviderWaitCapture, u32> {
        self.activations.capture_provider_wait(
            self.caller,
            &self.pm,
            &self.catalog,
            &self.lanes,
            self.caller.binding.reply_object,
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
        .observed_provider_wait(f.caller.binding.reply_object));
}

#[test]
fn only_exact_provider_wait_stop_and_reply_can_be_captured() {
    let mut f = Fixture::new();
    let reply = f.caller.binding.reply_object;
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
    let reply = f.caller.binding.reply_object;
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
            .observed_provider_wait(f.caller.binding.reply_object));
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
            f.caller.binding.reply_object,
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
            f.caller.binding.reply_object,
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
            f.caller.binding.reply_object,
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
    let reply = f.caller.binding.reply_object;
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
        .observed_provider_wait(f.caller.binding.reply_object));
}
