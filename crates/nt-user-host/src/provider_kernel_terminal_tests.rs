use super::*;
use nt_component_suspension::TerminalPhase;

type TerminalLanes = ComponentSuspensionLanes<u64, i32, u64>;
const STATUS: u32 = 0xc000_0001;
const PAYLOAD: u64 = 0x1234;
const STAGES: [TerminalStage; 1] = [TerminalStage::LocalDelivery];

struct Fixture {
    pm: ProcessManager,
    catalog: ProviderDomainCatalog,
    provider: ProviderDomainIdentity,
    lanes: TerminalLanes,
    activations: KernelProviderActivations,
    caller: KernelProviderCaller,
    key: SuspensionKey,
}

impl Fixture {
    fn new() -> Self {
        let mut pm = bootstrap().into_parts().pm;
        let native = requestor(&mut pm, 0x3000);
        let mut catalog = ProviderDomainCatalog::new();
        let provider = catalog.register().unwrap();
        let mut lanes = TerminalLanes::new(1, 4);
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
            key: SuspensionKey::provider_wait(71),
        }
    }

    fn admit(&mut self) {
        self.lanes
            .admit_running(
                self.caller.dispatch.lane(),
                self.caller
                    .current_binding(&self.lanes)
                    .unwrap()
                    .reply_object,
                self.key,
                1,
                self.caller.owner(),
                500,
            )
            .unwrap();
    }

    fn resume(&mut self) {
        self.lanes.select(self.key, 258).unwrap();
        self.lanes
            .begin_resume(
                self.caller.dispatch.lane(),
                self.caller
                    .current_binding(&self.lanes)
                    .unwrap()
                    .reply_object,
                self.key,
            )
            .unwrap();
    }

    fn retain(&mut self) -> Result<TerminalIdentity, (u32, u64)> {
        self.activations.retain_terminal_completion(
            self.caller,
            &self.pm,
            &self.catalog,
            &mut self.lanes,
            self.key,
            PAYLOAD,
            STATUS,
        )
    }

    fn pending(&mut self) -> TerminalIdentity {
        self.admit();
        self.resume();
        self.retain().unwrap()
    }

    fn ack_stage(&mut self, terminal: TerminalIdentity, stage: TerminalStage) {
        let reply = self
            .caller
            .current_binding(&self.lanes)
            .unwrap()
            .reply_object;
        let mut attempt = self
            .lanes
            .begin_terminal_stage(terminal, reply, stage)
            .unwrap();
        self.lanes
            .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
            .unwrap();
    }

    fn assert_pending(&self, terminal: TerminalIdentity) {
        assert!(self.activations.completion(self.caller).is_err());
        assert_eq!(references(&self.pm, self.caller.thread()), (1, 1));
        assert_eq!(
            self.activations.validate_terminal_completion(
                self.caller,
                &self.pm,
                &self.lanes,
                terminal,
            ),
            Ok(())
        );
    }
}

#[test]
fn terminal_admission_rejects_wrong_phase_key_owner_catalog_and_manager_atomically() {
    let mut f = Fixture::new();
    assert_eq!(f.retain(), Err((STATUS_INVALID_HANDLE, PAYLOAD)));
    f.admit();
    assert_eq!(f.retain(), Err((STATUS_INVALID_HANDLE, PAYLOAD)));
    f.lanes.select(f.key, 0).unwrap();
    assert_eq!(f.retain(), Err((STATUS_INVALID_HANDLE, PAYLOAD)));
    let lane = f.caller.dispatch.lane();
    f.lanes
        .begin_resume(
            lane,
            f.caller.current_binding(&f.lanes).unwrap().reply_object,
            f.key,
        )
        .unwrap();
    let original_key = f.key;
    f.key = SuspensionKey::provider_wait(72);
    assert_eq!(f.retain(), Err((STATUS_INVALID_HANDLE, PAYLOAD)));
    f.key = original_key;
    f.lanes
        .frame_mut(lane, f.key)
        .unwrap()
        .unwrap()
        .owner
        .provider_generation += 1;
    assert_eq!(f.retain(), Err((STATUS_INVALID_HANDLE, PAYLOAD)));
    f.lanes.frame_mut(lane, f.key).unwrap().unwrap().owner = f.caller.owner();
    let mut foreign = bootstrap().into_parts();
    requestor(&mut foreign.pm, 0x3000);
    assert_eq!(
        f.activations.retain_terminal_completion(
            f.caller,
            &foreign.pm,
            &f.catalog,
            &mut f.lanes,
            f.key,
            PAYLOAD,
            STATUS,
        ),
        Err((STATUS_INVALID_HANDLE, PAYLOAD))
    );
    let mut foreign_catalog = ProviderDomainCatalog::new();
    assert_eq!(foreign_catalog.register().unwrap(), f.provider);
    assert_eq!(
        f.activations.retain_terminal_completion(
            f.caller,
            &f.pm,
            &foreign_catalog,
            &mut f.lanes,
            f.key,
            PAYLOAD,
            STATUS,
        ),
        Err((STATUS_INVALID_HANDLE, PAYLOAD))
    );
    assert_eq!(f.lanes.phase(lane), Ok(LanePhase::Running));
    assert_eq!(f.lanes.terminal_identities().count(), 0);
    assert_eq!(f.lanes.suspension_count(lane), Ok(1));
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    let terminal = f.retain().unwrap();
    f.assert_pending(terminal);
}

#[test]
fn extra_frames_and_external_tokens_prevent_whole_activation_completion() {
    for external in [false, true] {
        let mut f = Fixture::new();
        let lane = f.caller.dispatch.lane();
        let reply = f.caller.current_binding(&f.lanes).unwrap().reply_object;
        if external {
            f.lanes.suspend_running(lane, reply, 70).unwrap();
            f.lanes.resume_external(lane, reply, 70).unwrap();
        } else {
            let outer_provider = f.catalog.register().unwrap();
            let outer_owner = SuspensionOwner {
                provider_domain: outer_provider.domain,
                provider_generation: outer_provider.generation,
                ..f.caller.owner()
            };
            f.lanes
                .admit_running(lane, reply, f.key, 1, outer_owner, 400)
                .unwrap();
            f.resume();
            f.key = SuspensionKey::provider_wait(72);
        }
        f.admit();
        f.resume();
        let count = f.lanes.suspension_count(lane).unwrap();
        let depth = f.lanes.external_depth(lane).unwrap();
        assert_eq!(f.retain(), Err((STATUS_INVALID_HANDLE, PAYLOAD)));
        assert_eq!(f.lanes.suspension_count(lane), Ok(count));
        assert_eq!(f.lanes.external_depth(lane), Ok(depth));
        assert_eq!(f.lanes.phase(lane), Ok(LanePhase::Running));
        assert_eq!(f.lanes.terminal_identities().count(), 0);
        assert!(f.activations.completion(f.caller).is_err());
        assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    }
}

#[test]
fn pending_return_cannot_be_acknowledged_released_or_recorded_twice() {
    let mut f = Fixture::new();
    let terminal = f.pending();
    let premature = KernelProviderCompletionReceipt {
        caller: f.caller,
        status: STATUS,
    };
    assert!(f
        .activations
        .acknowledge_completion(premature, &mut f.pm)
        .is_err());
    assert!(f.activations.release(f.caller, &mut f.pm).is_err());
    assert!(f
        .activations
        .record_completion(f.caller, &f.pm, &f.catalog, &mut f.lanes, STATUS,)
        .is_err());
    assert_eq!(f.retain(), Err((STATUS_INVALID_HANDLE, PAYLOAD)));
    assert!(f
        .activations
        .finish_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Ok(()),)
        .is_err());
    f.assert_pending(terminal);
}

#[test]
fn cancellation_is_not_a_return_but_cancelled_resume_can_retain_its_actual_status() {
    let mut f = Fixture::new();
    f.admit();
    let cancelled = 0xc000_0120u32 as i32;
    f.lanes.cancel(f.key, cancelled).unwrap();
    assert_eq!(f.retain(), Err((STATUS_INVALID_HANDLE, PAYLOAD)));
    assert_eq!(f.lanes.terminal_identities().count(), 0);
    f.lanes
        .begin_resume(
            f.caller.dispatch.lane(),
            f.caller.current_binding(&f.lanes).unwrap().reply_object,
            f.key,
        )
        .unwrap();
    let terminal = f.retain().unwrap();
    f.assert_pending(terminal);
    for stage in STAGES {
        f.ack_stage(terminal, stage);
    }
    let (receipt, retired) = f
        .activations
        .finish_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Ok(()))
        .unwrap()
        .unwrap();
    assert!(retired.suspension.cancelled);
    assert_eq!(retired.suspension.completion, cancelled);
    assert_eq!(receipt.status(), STATUS);
    assert_eq!(
        f.activations.acknowledge_completion(receipt, &mut f.pm),
        Ok(STATUS)
    );
    assert_eq!(references(&f.pm, f.caller.thread()), (0, 0));
}

#[test]
fn every_terminal_stage_preserves_pending_authority_on_failure_uncertainty_or_lost_ticket() {
    for (index, stage) in STAGES.into_iter().enumerate() {
        for mode in 0..3 {
            let mut f = Fixture::new();
            let terminal = f.pending();
            let reply = f.caller.current_binding(&f.lanes).unwrap().reply_object;
            for previous in &STAGES[..index] {
                f.ack_stage(terminal, *previous);
            }
            let mut attempt = f
                .lanes
                .begin_terminal_stage(terminal, reply, stage)
                .unwrap();
            match mode {
                0 => f
                    .lanes
                    .record_terminal_stage(
                        &mut attempt,
                        reply,
                        TerminalStageOutcome::NoEffects(STATUS),
                    )
                    .unwrap(),
                1 => f
                    .lanes
                    .record_terminal_stage(
                        &mut attempt,
                        reply,
                        TerminalStageOutcome::Indeterminate(STATUS),
                    )
                    .unwrap(),
                _ => drop(attempt),
            }
            assert!(f
                .activations
                .finish_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Ok(()),)
                .is_err());
            f.assert_pending(terminal);
            if mode == 0 {
                assert_eq!(
                    f.lanes.terminal(terminal, reply).unwrap().phase,
                    TerminalPhase::Ready {
                        stage,
                        last_error: Some(STATUS)
                    }
                );
                for remaining in &STAGES[index..] {
                    f.ack_stage(terminal, *remaining);
                }
                let (receipt, _) = f
                    .activations
                    .finish_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Ok(()))
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    f.activations.acknowledge_completion(receipt, &mut f.pm),
                    Ok(STATUS)
                );
            } else {
                assert!(f
                    .lanes
                    .begin_terminal_stage(terminal, reply, stage)
                    .is_err());
                assert!(f.lanes.next_terminal().is_none());
                assert!(f.activations.release(f.caller, &mut f.pm).is_err());
            }
        }
    }
}

#[test]
fn local_retirement_and_receipt_acknowledgment_retry_after_caller_and_provider_exit() {
    let mut f = Fixture::new();
    f.admit();
    f.resume();
    f.pm.terminate_thread(f.caller.thread().thread_id(), 0)
        .unwrap();
    let terminal = f.retain().unwrap();
    let reply = f.caller.current_binding(&f.lanes).unwrap().reply_object;
    for stage in STAGES {
        f.ack_stage(terminal, stage);
    }
    f.catalog.retire(f.provider, 0).unwrap();
    let mut foreign = bootstrap().into_parts();
    requestor(&mut foreign.pm, 0x3000);
    assert!(f
        .activations
        .finish_terminal_completion(f.caller, &foreign.pm, &mut f.lanes, terminal, Ok(()),)
        .is_err());
    assert!(f
        .activations
        .finish_terminal_completion(
            f.caller,
            &f.pm,
            &mut f.lanes,
            terminal,
            Err(STATUS_INVALID_HANDLE),
        )
        .unwrap()
        .is_none());
    assert_eq!(
        f.lanes.terminal(terminal, reply).unwrap().phase,
        TerminalPhase::Acknowledged {
            local_error: Some(STATUS_INVALID_HANDLE)
        }
    );
    for stage in STAGES {
        assert!(f
            .lanes
            .begin_terminal_stage(terminal, reply, stage)
            .is_err());
    }
    f.assert_pending(terminal);
    let (receipt, retired) = f
        .activations
        .finish_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(retired.payload, PAYLOAD);
    assert_eq!(retired.suspension.completion, 258);
    assert_eq!(receipt.status(), STATUS);
    assert_eq!(f.lanes.phase(f.caller.dispatch.lane()), Ok(LanePhase::Idle));
    assert_eq!(
        f.lanes.active_dispatch_identity(f.caller.dispatch.lane()),
        Ok(None)
    );
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    assert!(!f.pm.can_reclaim_thread(f.caller.thread().thread_id()));
    assert!(f
        .activations
        .acknowledge_completion(receipt, &mut foreign.pm)
        .is_err());
    assert_eq!(f.activations.completion(f.caller), Ok(receipt));
    assert_eq!(
        f.activations.acknowledge_completion(receipt, &mut f.pm),
        Ok(STATUS)
    );
    assert_eq!(references(&f.pm, f.caller.thread()), (0, 0));
    assert!(f.pm.can_reclaim_thread(f.caller.thread().thread_id()));
    assert!(f
        .activations
        .finish_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Ok(()),)
        .is_err());
}

#[test]
fn retired_terminal_cannot_complete_a_replacement_lane_or_foreign_activation() {
    for replace_lane in [false, true] {
        let mut f = Fixture::new();
        let old_caller = f.caller;
        let reply = f.caller.current_binding(&f.lanes).unwrap().reply_object;
        let old = f.pending();
        for stage in STAGES {
            f.ack_stage(old, stage);
        }
        let (old_receipt, _) = f
            .activations
            .finish_terminal_completion(f.caller, &f.pm, &mut f.lanes, old, Ok(()))
            .unwrap()
            .unwrap();
        let lane = if replace_lane {
            f.lanes.release(f.caller.dispatch.lane(), reply).unwrap();
            let replacement = f.lanes.allocate(binding(1)).unwrap();
            assert_ne!(replacement, f.caller.dispatch.lane());
            replacement
        } else {
            f.caller.dispatch.lane()
        };
        f.lanes.begin_dispatch(lane, reply).unwrap();
        let native =
            f.pm.capture_native_handle_caller(f.caller.thread(), AccessMode::KernelMode)
                .unwrap();
        f.caller = f
            .activations
            .capture(&mut f.pm, &f.catalog, &f.lanes, f.provider, lane, native)
            .unwrap();
        let mut foreign = KernelProviderActivations::new();
        let foreign_caller = foreign
            .capture(&mut f.pm, &f.catalog, &f.lanes, f.provider, lane, native)
            .unwrap();
        let next = f.pending();
        assert_ne!(next, old);
        assert_ne!(f.caller.owner().dispatch_id, old_caller.owner().dispatch_id);
        for stage in STAGES {
            f.ack_stage(next, stage);
        }
        for (caller, terminal) in [(old_caller, old), (f.caller, old), (old_caller, next)] {
            assert!(f
                .activations
                .finish_terminal_completion(caller, &f.pm, &mut f.lanes, terminal, Ok(()),)
                .is_err());
        }
        for caller in [f.caller, foreign_caller] {
            assert!(foreign
                .finish_terminal_completion(caller, &f.pm, &mut f.lanes, next, Ok(()),)
                .is_err());
        }
        assert_eq!(references(&f.pm, f.caller.thread()), (3, 3));
        foreign.release(foreign_caller, &mut f.pm).unwrap();
        f.activations
            .acknowledge_completion(old_receipt, &mut f.pm)
            .unwrap();
        f.assert_pending(next);
        let (receipt, _) = f
            .activations
            .finish_terminal_completion(f.caller, &f.pm, &mut f.lanes, next, Ok(()))
            .unwrap()
            .unwrap();
        assert!(f
            .activations
            .acknowledge_completion(old_receipt, &mut f.pm)
            .is_err());
        assert_eq!(
            f.activations.acknowledge_completion(receipt, &mut f.pm),
            Ok(STATUS)
        );
    }
}

#[test]
fn failed_admission_returns_noncopy_owned_payload_for_retry() {
    let mut pm = bootstrap().into_parts().pm;
    let native = requestor(&mut pm, 0x3000);
    let mut catalog = ProviderDomainCatalog::new();
    let provider = catalog.register().unwrap();
    let mut lanes = ComponentSuspensionLanes::<u64, i32, alloc::boxed::Box<u64>>::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let mut activations = KernelProviderActivations::new();
    let caller = activations
        .capture(&mut pm, &catalog, &lanes, provider, lane, native)
        .unwrap();
    let key = SuspensionKey::provider_wait(71);
    let payload = alloc::boxed::Box::new(PAYLOAD);
    let address = &*payload as *const u64;
    let (status, payload) = activations
        .retain_terminal_completion(caller, &pm, &catalog, &mut lanes, key, payload, STATUS)
        .unwrap_err();
    assert_eq!(status, STATUS_INVALID_HANDLE);
    assert_eq!(&*payload as *const u64, address);
    lanes
        .admit_running(lane, reply, key, 1, caller.owner(), 500)
        .unwrap();
    lanes.select(key, 0).unwrap();
    lanes.begin_resume(lane, reply, key).unwrap();
    let (status, payload) = activations
        .retain_terminal_completion(
            caller,
            &pm,
            &catalog,
            &mut lanes,
            SuspensionKey::provider_wait(72),
            payload,
            STATUS,
        )
        .unwrap_err();
    assert_eq!(status, STATUS_INVALID_HANDLE);
    assert_eq!(&*payload as *const u64, address);
    let terminal = activations
        .retain_terminal_completion(caller, &pm, &catalog, &mut lanes, key, payload, STATUS)
        .unwrap();
    assert_eq!(
        &**lanes.terminal(terminal, reply).unwrap().payload as *const u64,
        address
    );
}
