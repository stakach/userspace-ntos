use super::*;
use nt_component_suspension::{LaneError, SuspensionPhase, SuspensionResume};

type ResumeLanes = ComponentSuspensionLanes<u64, i32, u64>;

struct Fixture {
    pm: ProcessManager,
    catalog: ProviderDomainCatalog,
    provider: ProviderDomainIdentity,
    lanes: ResumeLanes,
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
        let mut lanes = ResumeLanes::new(2, 4);
        let lane = lanes.allocate(binding(1)).unwrap();
        lanes.begin_dispatch(lane, binding(1).reply_object).unwrap();
        let mut activations = KernelProviderActivations::new();
        let caller = activations
            .capture(&mut pm, &catalog, &lanes, provider, lane, native)
            .unwrap();
        let key = SuspensionKey::provider_wait(91);
        lanes
            .admit_running(lane, binding(1).reply_object, key, 1, caller.owner(), 500)
            .unwrap();
        Self {
            pm,
            catalog,
            provider,
            lanes,
            activations,
            caller,
            key,
        }
    }

    fn select(&mut self, cancelled: bool) {
        if cancelled {
            self.lanes.cancel(self.key, -1).unwrap();
        } else {
            self.lanes.select(self.key, 258).unwrap();
        }
    }

    fn resume(&mut self) -> Result<SuspensionResume<i32>, KernelProviderResumeError> {
        self.activations.begin_resume(
            self.caller,
            &self.pm,
            &self.catalog,
            &mut self.lanes,
            self.key,
        )
    }

    fn assert_resume_rejected_unchanged(&mut self) -> KernelProviderResumeError {
        let lane = self.caller.dispatch.lane();
        let phase = self.lanes.phase(lane).unwrap();
        let frame = self.lanes.top(lane).unwrap().cloned();
        let dispatch = self.lanes.active_dispatch_identity(lane).unwrap();
        let depth = self.lanes.external_depth(lane).unwrap();
        let refs = references(&self.pm, self.caller.thread());
        let error = self.resume().unwrap_err();
        assert_eq!(self.lanes.phase(lane).unwrap(), phase);
        assert_eq!(self.lanes.top(lane).unwrap().cloned(), frame);
        assert_eq!(self.lanes.active_dispatch_identity(lane).unwrap(), dispatch);
        assert_eq!(self.lanes.external_depth(lane).unwrap(), depth);
        assert_eq!(references(&self.pm, self.caller.thread()), refs);
        error
    }
}

#[test]
fn selected_and_cancelled_frames_resume_once_through_live_authority() {
    for cancelled in [false, true] {
        let mut f = Fixture::new();
        f.select(cancelled);
        assert_eq!(
            f.activations
                .validate_resume(f.caller, &f.pm, &f.catalog, &f.lanes, f.key),
            Ok(())
        );
        assert_eq!(
            f.lanes.phase(f.caller.dispatch.lane()),
            Ok(LanePhase::Suspended)
        );
        let resumed = f.resume().unwrap();
        assert_eq!(
            f.activations
                .validate(f.caller, &f.pm, &f.catalog, &f.lanes),
            Ok(())
        );
        assert_eq!(
            resumed,
            SuspensionResume {
                key: f.key,
                completion: if cancelled { -1 } else { 258 },
                cancelled,
            }
        );
        assert_eq!(
            f.lanes.phase(f.caller.dispatch.lane()),
            Ok(LanePhase::Running)
        );
        assert_eq!(
            f.lanes
                .top(f.caller.dispatch.lane())
                .unwrap()
                .unwrap()
                .phase,
            SuspensionPhase::Resuming {
                completion: resumed.completion,
                cancelled
            }
        );
        assert_eq!(
            f.assert_resume_rejected_unchanged(),
            KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
        );
    }
}

#[test]
fn exited_caller_retains_selected_or_cancelled_stack_without_reentry() {
    for cancelled in [false, true] {
        let mut f = Fixture::new();
        f.select(cancelled);
        f.pm.terminate_thread(f.caller.thread().thread_id(), 0)
            .unwrap();
        assert_eq!(
            f.activations
                .validate_retained(f.caller, &f.pm, &f.catalog, &f.lanes),
            Ok(())
        );
        assert!(matches!(
            f.assert_resume_rejected_unchanged(),
            KernelProviderResumeError::Authority(_)
        ));
        assert_eq!(
            f.lanes.phase(f.caller.dispatch.lane()),
            Ok(LanePhase::Suspended)
        );
        assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
        assert!(f.activations.completion(f.caller).is_err());
    }
}

#[test]
fn wrong_manager_catalog_and_retired_provider_leave_selection_intact() {
    let mut f = Fixture::new();
    f.select(false);
    let lane = f.caller.dispatch.lane();
    let frame = f.lanes.top(lane).unwrap().unwrap().clone();
    let mut foreign_pm = bootstrap().into_parts().pm;
    requestor(&mut foreign_pm, 0x3000);
    assert_eq!(
        f.activations
            .begin_resume(f.caller, &foreign_pm, &f.catalog, &mut f.lanes, f.key),
        Err(KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE))
    );
    let mut foreign_catalog = ProviderDomainCatalog::new();
    assert_eq!(foreign_catalog.register().unwrap(), f.provider);
    assert_eq!(
        f.activations
            .begin_resume(f.caller, &f.pm, &foreign_catalog, &mut f.lanes, f.key),
        Err(KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE))
    );
    assert_eq!(f.lanes.top(lane).unwrap(), Some(&frame));
    assert_eq!(f.lanes.phase(lane), Ok(LanePhase::Suspended));
    f.catalog.retire(f.provider, 0).unwrap();
    assert_eq!(
        f.assert_resume_rejected_unchanged(),
        KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn waiting_wrong_key_owner_and_forged_binding_reject_without_mutation() {
    let mut f = Fixture::new();
    assert_eq!(
        f.assert_resume_rejected_unchanged(),
        KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
    );
    f.select(false);
    let key = f.key;
    f.key = SuspensionKey::provider_wait(key.id + 1);
    assert_eq!(
        f.assert_resume_rejected_unchanged(),
        KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
    );
    f.key = key;
    let lane = f.caller.dispatch.lane();
    f.lanes
        .frame_mut(lane, key)
        .unwrap()
        .unwrap()
        .owner
        .provider_generation += 1;
    assert_eq!(
        f.assert_resume_rejected_unchanged(),
        KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
    );
    f.lanes.frame_mut(lane, key).unwrap().unwrap().owner = f.caller.owner();
    let caller = f.caller;
    f.caller.binding.reply_object += 1;
    assert_eq!(
        f.assert_resume_rejected_unchanged(),
        KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
    );
    f.caller = caller;
    f.resume().unwrap();
}

#[test]
fn competing_execution_returns_lane_busy_without_consuming_selected_frame() {
    let mut f = Fixture::new();
    f.select(false);
    let other = f.lanes.allocate(binding(2)).unwrap();
    f.lanes
        .begin_dispatch(other, binding(2).reply_object)
        .unwrap();
    assert_eq!(
        f.activations
            .validate_resume(f.caller, &f.pm, &f.catalog, &f.lanes, f.key),
        Ok(())
    );
    assert_eq!(
        f.assert_resume_rejected_unchanged(),
        KernelProviderResumeError::Lane(LaneError::Busy)
    );
    assert_eq!(f.lanes.phase(other), Ok(LanePhase::Running));
    f.lanes
        .finish_dispatch(other, binding(2).reply_object)
        .unwrap();
    f.resume().unwrap();
}

#[test]
fn same_lane_replacement_dispatch_cannot_resume_previous_activation() {
    let mut f = Fixture::new();
    f.select(false);
    f.resume().unwrap();
    let lane = f.caller.dispatch.lane();
    let reply = f.caller.binding.reply_object;
    let terminal = f
        .lanes
        .retain_terminal_running(lane, reply, f.key, f.caller.owner(), 99)
        .unwrap();
    for stage in [
        TerminalStage::Output,
        TerminalStage::Context,
        TerminalStage::Publication,
        TerminalStage::Reply,
    ] {
        let mut attempt = f
            .lanes
            .begin_terminal_stage(terminal, reply, stage)
            .unwrap();
        f.lanes
            .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
            .unwrap();
    }
    f.lanes
        .finish_terminal(terminal, reply, Ok(()))
        .unwrap()
        .unwrap();
    f.lanes.begin_dispatch(lane, reply).unwrap();
    let current_dispatch = f.lanes.active_dispatch_identity(lane).unwrap().unwrap();
    assert_ne!(current_dispatch, f.caller.dispatch);
    let owner = SuspensionOwner {
        dispatch_id: current_dispatch.epoch(),
        ..f.caller.owner()
    };
    f.lanes
        .admit_running(lane, reply, f.key, 2, owner, 501)
        .unwrap();
    f.select(false);
    assert_eq!(
        f.assert_resume_rejected_unchanged(),
        KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn terminal_pending_result_excludes_resume_even_while_native_authority_is_retained() {
    let mut f = Fixture::new();
    f.select(false);
    f.resume().unwrap();
    let terminal = f
        .activations
        .retain_terminal_completion(f.caller, &f.pm, &f.catalog, &mut f.lanes, f.key, 99, 0)
        .unwrap();
    assert_eq!(
        f.assert_resume_rejected_unchanged(),
        KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        f.activations
            .validate_terminal_completion(f.caller, &f.pm, &f.lanes, terminal),
        Ok(())
    );
    assert!(f.activations.completion(f.caller).is_err());
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
}
