use super::*;

const MESSAGE_INFO: u64 = (0x785 << 12) | 4;

struct Fixture {
    pm: ProcessManager,
    catalog: ProviderDomainCatalog,
    provider: ProviderDomainIdentity,
    lanes: Lanes,
    activations: KernelProviderActivations,
    caller: KernelProviderCaller,
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
        }
    }

    fn envelope(&self) -> KernelProviderServiceEnvelope {
        KernelProviderServiceEnvelope {
            badge: 0,
            message_info: MESSAGE_INFO,
            reply_cap: self.caller.binding.reply_object,
        }
    }

    fn validate(&self, envelope: KernelProviderServiceEnvelope) -> Result<(), u32> {
        let lane = self.caller.dispatch.lane();
        let phase = self.lanes.phase(lane).unwrap();
        let dispatch = self.lanes.active_dispatch_identity(lane).unwrap();
        let depth = self.lanes.external_depth(lane).unwrap();
        let count = self.lanes.suspension_count(lane).unwrap();
        let refs = references(&self.pm, self.caller.thread());
        let result = self.activations.validate_service_call(
            self.caller,
            &self.pm,
            &self.catalog,
            &self.lanes,
            envelope,
            MESSAGE_INFO,
        );
        assert_eq!(self.lanes.phase(lane).unwrap(), phase);
        assert_eq!(self.lanes.active_dispatch_identity(lane).unwrap(), dispatch);
        assert_eq!(self.lanes.external_depth(lane).unwrap(), depth);
        assert_eq!(self.lanes.suspension_count(lane).unwrap(), count);
        assert_eq!(references(&self.pm, self.caller.thread()), refs);
        result
    }
}

#[test]
fn exact_envelope_requires_and_preserves_live_kernel_activation() {
    let f = Fixture::new();
    assert_eq!(f.validate(f.envelope()), Ok(()));
    assert_eq!(f.validate(f.envelope()), Ok(()));
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    assert!(f.activations.completion(f.caller).is_err());
    assert_eq!(
        f.lanes.phase(f.caller.dispatch.lane()),
        Ok(LanePhase::Running)
    );
}

#[test]
fn malformed_label_length_cap_fields_reserved_bits_badge_and_reply_are_rejected() {
    let f = Fixture::new();
    let valid = f.envelope();
    // Low seven bits are length; bits 7..11 carry capability fields; all higher bits are label.
    for bit in 0..64 {
        let envelope = KernelProviderServiceEnvelope {
            message_info: valid.message_info ^ (1u64 << bit),
            ..valid
        };
        assert_eq!(f.validate(envelope), Err(STATUS_INVALID_PARAMETER));
    }
    for length in [0, 1, 3, 5, 0x7f] {
        assert_eq!(
            f.validate(KernelProviderServiceEnvelope {
                message_info: (MESSAGE_INFO & !0x7f) | length,
                ..valid
            }),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
    for badge in [1, 4, u64::MAX] {
        assert_eq!(
            f.validate(KernelProviderServiceEnvelope { badge, ..valid }),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
    for reply_cap in [0, valid.reply_cap + 1, u64::MAX] {
        assert_eq!(
            f.validate(KernelProviderServiceEnvelope { reply_cap, ..valid }),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
    assert_eq!(f.validate(valid), Ok(()));
}

#[test]
fn valid_envelope_does_not_replace_foreign_manager_catalog_lane_or_caller_authority() {
    let f = Fixture::new();
    let mut foreign_pm = bootstrap().into_parts().pm;
    requestor(&mut foreign_pm, 0x3000);
    let mut foreign_catalog = ProviderDomainCatalog::new();
    assert_eq!(foreign_catalog.register().unwrap(), f.provider);
    let mut foreign_lanes = Lanes::new(1, 4);
    let foreign_lane = foreign_lanes.allocate(binding(1)).unwrap();
    assert_eq!(foreign_lane, f.caller.dispatch.lane());
    foreign_lanes
        .begin_dispatch(foreign_lane, binding(1).reply_object)
        .unwrap();
    for (pm, catalog, lanes) in [
        (&foreign_pm, &f.catalog, &f.lanes),
        (&f.pm, &foreign_catalog, &f.lanes),
        (&f.pm, &f.catalog, &foreign_lanes),
    ] {
        assert_eq!(
            f.activations.validate_service_call(
                f.caller,
                pm,
                catalog,
                lanes,
                f.envelope(),
                MESSAGE_INFO,
            ),
            Err(STATUS_INVALID_HANDLE)
        );
    }
    let mut forged = f.caller;
    forged.binding.executor_id += 1;
    assert_eq!(
        f.activations.validate_service_call(
            forged,
            &f.pm,
            &f.catalog,
            &f.lanes,
            f.envelope(),
            MESSAGE_INFO,
        ),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(f.validate(f.envelope()), Ok(()));
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
}

#[test]
fn suspended_or_replaced_dispatch_refuses_service_without_resuming_stack() {
    let mut f = Fixture::new();
    let lane = f.caller.dispatch.lane();
    let reply = f.caller.binding.reply_object;
    f.lanes.suspend_running(lane, reply, 91).unwrap();
    assert_eq!(f.validate(f.envelope()), Err(STATUS_INVALID_HANDLE));
    assert_eq!(f.lanes.phase(lane), Ok(LanePhase::Suspended));
    f.lanes.resume_external(lane, reply, 91).unwrap();
    assert_eq!(f.validate(f.envelope()), Ok(()));
    f.lanes.complete_external(lane, reply, 91).unwrap();
    f.lanes.begin_dispatch(lane, reply).unwrap();
    assert_ne!(
        f.lanes.active_dispatch_identity(lane).unwrap(),
        Some(f.caller.dispatch)
    );
    assert_eq!(f.validate(f.envelope()), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn exited_caller_and_retired_provider_keep_references_without_service_authority() {
    let mut exited = Fixture::new();
    exited
        .pm
        .terminate_thread(exited.caller.thread().thread_id(), 0)
        .unwrap();
    assert!(exited.validate(exited.envelope()).is_err());
    assert_eq!(
        exited.activations.validate_retained(
            exited.caller,
            &exited.pm,
            &exited.catalog,
            &exited.lanes,
        ),
        Ok(())
    );
    assert_eq!(references(&exited.pm, exited.caller.thread()), (1, 1));
    let mut retired = Fixture::new();
    retired.catalog.retire(retired.provider, 0).unwrap();
    assert_eq!(
        retired.validate(retired.envelope()),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(references(&retired.pm, retired.caller.thread()), (1, 1));
}

#[test]
fn completed_activation_cannot_service_calls_or_lose_pending_receipt() {
    let mut f = Fixture::new();
    let receipt = f
        .activations
        .record_completion(f.caller, &f.pm, &f.catalog, &mut f.lanes, 0xc000_0001)
        .unwrap();
    assert_eq!(f.validate(f.envelope()), Err(STATUS_INVALID_HANDLE));
    assert_eq!(f.activations.completion(f.caller), Ok(receipt));
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    assert_eq!(f.lanes.phase(f.caller.dispatch.lane()), Ok(LanePhase::Idle));
}
