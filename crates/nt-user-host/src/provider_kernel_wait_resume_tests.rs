use super::*;
use crate::provider_kernel_pump::{
    KernelProviderPumpDisposition, KernelProviderPumpFacts, PumpProgressError,
};
use crate::provider_kernel_wait::{
    KernelProviderWaitRecipient, KernelProviderWaitResume, KernelProviderWaitState,
};
use alloc::boxed::Box;
use nt_component_suspension::{LaneError, SuspensionPhase};
use nt_provider_wait::{
    ProviderWaitMode, ProviderWaitObject, ProviderWaitObjectType, ProviderWaitRequest,
    ProviderWaitRequestMetadata, ProviderWaitTimeoutKind, ProviderWaitType,
};

#[path = "provider_kernel_wait_execution_tests.rs"]
mod execution;

struct Recipient {
    state: KernelProviderWaitState,
    bank: Box<u64>,
}

impl KernelProviderWaitRecipient for Recipient {
    fn kernel_wait_state(&mut self) -> &mut KernelProviderWaitState {
        &mut self.state
    }
}

type WaitLanes = ComponentSuspensionLanes<KernelProviderWaitCapture, i32, u64>;

struct Fixture {
    pm: ProcessManager,
    catalog: ProviderDomainCatalog,
    provider: ProviderDomainIdentity,
    lanes: WaitLanes,
    activations: KernelProviderActivations<Recipient>,
    caller: KernelProviderCaller,
    capture: KernelProviderWaitCapture,
}

fn facts(reply_cap: u64, completed: bool) -> KernelProviderPumpFacts {
    KernelProviderPumpFacts {
        reply_cap,
        completed,
        callback_suspended: false,
        provider_wait_suspended: !completed,
        lpc_wait_suspended: false,
        scheduler_yielded: false,
    }
}

fn request(owner: SuspensionOwner, id: u64) -> ProviderWaitRequest {
    let mut request = ProviderWaitRequest::empty();
    request
        .begin(
            ProviderWaitRequestMetadata {
                wait_id: id,
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

impl Fixture {
    fn new() -> Self {
        let mut pm = bootstrap().into_parts().pm;
        let native = requestor(&mut pm, 0x3000);
        let mut catalog = ProviderDomainCatalog::new();
        let provider = catalog.register().unwrap();
        let mut lanes = WaitLanes::new(2, 4);
        let lane = lanes.allocate(binding(1)).unwrap();
        let reply = binding(1).reply_object;
        lanes.begin_dispatch(lane, reply).unwrap();
        let mut state = KernelProviderWaitState::new(reply).unwrap();
        let mut initial = state.begin_initial().unwrap();
        state
            .observe(&mut initial, facts(reply, false), None)
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
                Recipient {
                    state,
                    bank: Box::new(0x1234),
                },
            )
            .unwrap_or_else(|(status, _)| panic!("capture failed: {status:x}"));
        let request = request(caller.owner(), 71);
        let capture = activations
            .capture_provider_wait(
                caller,
                &pm,
                &catalog,
                &lanes,
                reply,
                activations.recipient(caller).unwrap().state.progress(),
                request,
            )
            .unwrap();
        activations
            .recipient_mut(caller)
            .unwrap()
            .state
            .retain_provider_wait(request, Ok(capture))
            .unwrap();
        lanes
            .admit_running(lane, reply, capture.key(), 1, caller.owner(), capture)
            .unwrap();
        Self {
            pm,
            catalog,
            provider,
            lanes,
            activations,
            caller,
            capture,
        }
    }

    fn state(&self) -> &KernelProviderWaitState {
        &self.activations.recipient(self.caller).unwrap().state
    }

    fn resume(&mut self) -> Result<KernelProviderWaitResume<i32>, KernelProviderResumeError> {
        self.activations.begin_wait_resume(
            self.caller,
            &self.pm,
            &self.catalog,
            &mut self.lanes,
            self.capture,
        )
    }

    fn assert_refused_unchanged(&mut self) -> KernelProviderResumeError {
        let lane = self.caller.dispatch.lane();
        let phase = self.lanes.phase(lane).unwrap();
        let frame = self.lanes.top(lane).unwrap().cloned();
        let dispatch = self.lanes.active_dispatch_identity(lane).unwrap();
        let observation = self
            .state()
            .progress()
            .provider_wait_observation(self.caller.binding.reply_object);
        let capture = self.state().captured_wait();
        let bank = &*self.activations.recipient(self.caller).unwrap().bank as *const u64;
        let error = self.resume().unwrap_err();
        assert_eq!(self.lanes.phase(lane).unwrap(), phase);
        assert_eq!(self.lanes.top(lane).unwrap().cloned(), frame);
        assert_eq!(self.lanes.active_dispatch_identity(lane).unwrap(), dispatch);
        assert_eq!(
            self.state()
                .progress()
                .provider_wait_observation(self.caller.binding.reply_object),
            observation
        );
        assert_eq!(self.state().captured_wait(), capture);
        assert_eq!(
            &*self.activations.recipient(self.caller).unwrap().bank as *const u64,
            bank
        );
        assert_eq!(references(&self.pm, self.caller.thread()), (1, 1));
        assert!(self.activations.completion(self.caller).is_err());
        error
    }

    fn repark(&mut self, next_id: u64, sequence: u64) -> KernelProviderWaitCapture {
        let ticket = self.resume().unwrap();
        let (_, mut attempt, _) = ticket.into_parts();
        let reply = self.caller.binding.reply_object;
        self.activations
            .recipient_mut(self.caller)
            .unwrap()
            .state
            .observe(&mut attempt, facts(reply, false), None)
            .unwrap();
        let request = request(self.caller.owner(), next_id);
        let capture = self
            .activations
            .capture_provider_wait(
                self.caller,
                &self.pm,
                &self.catalog,
                &self.lanes,
                reply,
                self.state().progress(),
                request,
            )
            .unwrap();
        self.activations
            .recipient_mut(self.caller)
            .unwrap()
            .state
            .retain_provider_wait(request, Ok(capture))
            .unwrap();
        let previous = self
            .lanes
            .rearm_running_owned(
                self.caller.dispatch.lane(),
                reply,
                self.capture.key(),
                capture.key(),
                sequence,
                self.caller.owner(),
                capture,
            )
            .unwrap();
        assert_eq!(previous, self.capture);
        self.capture = capture;
        self.lanes.select(capture.key(), 258).unwrap();
        capture
    }
}

#[test]
fn selected_and_cancelled_waits_claim_exact_pump_entry_once() {
    for cancelled in [false, true] {
        let mut f = Fixture::new();
        if cancelled {
            f.lanes.cancel(f.capture.key(), -1).unwrap();
        } else {
            f.lanes.select(f.capture.key(), 258).unwrap();
        }
        let ticket = f.resume().unwrap();
        assert_eq!(ticket.caller(), f.caller);
        assert_eq!(ticket.selection().key, f.capture.key());
        assert_eq!(ticket.selection().cancelled, cancelled);
        assert_eq!(
            ticket.selection().completion,
            if cancelled { -1 } else { 258 }
        );
        assert!(f.state().captured_wait().is_none());
        assert_eq!(f.state().progress().disposition(), None);
        assert_eq!(
            f.lanes.phase(f.caller.dispatch.lane()),
            Ok(LanePhase::Running)
        );
        assert_eq!(
            f.assert_refused_unchanged(),
            KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
        );
        let (capture, mut attempt, selection) = ticket.into_parts();
        assert_eq!(capture, f.capture);
        let reply = f.caller.binding.reply_object;
        let state = &mut f.activations.recipient_mut(f.caller).unwrap().state;
        assert_eq!(
            state.observe(&mut attempt, facts(reply, true), Some(7)),
            Ok(KernelProviderPumpDisposition::Returned(7))
        );
        assert_eq!(
            state.observe(&mut attempt, facts(reply, true), Some(7)),
            Err(PumpProgressError::WrongAttempt)
        );
        assert_eq!(
            f.lanes
                .top(f.caller.dispatch.lane())
                .unwrap()
                .unwrap()
                .phase,
            SuspensionPhase::Resuming {
                completion: selection.completion,
                cancelled
            }
        );
        assert!(f.activations.completion(f.caller).is_err());
    }
}

#[test]
fn busy_lane_preserves_selected_capture_for_later_single_entry() {
    let mut f = Fixture::new();
    f.lanes.select(f.capture.key(), 258).unwrap();
    let other = f.lanes.allocate(binding(2)).unwrap();
    f.lanes
        .begin_dispatch(other, binding(2).reply_object)
        .unwrap();
    assert_eq!(
        f.assert_refused_unchanged(),
        KernelProviderResumeError::Lane(LaneError::Busy)
    );
    f.lanes
        .finish_dispatch(other, binding(2).reply_object)
        .unwrap();
    let ticket = f.resume().unwrap();
    assert_eq!(ticket.selection().completion, 258);
}

#[test]
fn waiting_wrong_owner_and_retired_provider_do_not_consume_capture() {
    let mut f = Fixture::new();
    assert_eq!(
        f.assert_refused_unchanged(),
        KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
    );
    f.lanes.select(f.capture.key(), 258).unwrap();
    let lane = f.caller.dispatch.lane();
    f.lanes
        .frame_mut(lane, f.capture.key())
        .unwrap()
        .unwrap()
        .owner
        .provider_generation += 1;
    assert_eq!(
        f.assert_refused_unchanged(),
        KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
    );
    f.lanes
        .frame_mut(lane, f.capture.key())
        .unwrap()
        .unwrap()
        .owner = f.caller.owner();
    f.catalog.retire(f.provider, 0).unwrap();
    assert_eq!(
        f.assert_refused_unchanged(),
        KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn foreign_manager_and_catalog_preserve_wait_ownership() {
    let mut f = Fixture::new();
    f.lanes.select(f.capture.key(), 258).unwrap();
    let mut foreign = bootstrap().into_parts().pm;
    requestor(&mut foreign, 0x3000);
    let mut catalog = ProviderDomainCatalog::new();
    assert_eq!(catalog.register().unwrap(), f.provider);
    for (pm, catalog) in [(&foreign, &f.catalog), (&f.pm, &catalog)] {
        assert_eq!(
            f.activations
                .begin_wait_resume(f.caller, pm, catalog, &mut f.lanes, f.capture)
                .unwrap_err(),
            KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
        );
        assert_eq!(f.state().captured_wait(), Some(f.capture));
        assert_eq!(
            f.lanes.phase(f.caller.dispatch.lane()),
            Ok(LanePhase::Suspended)
        );
        assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    }
    drop(f.resume().unwrap());
}

#[test]
fn mismatched_caller_and_exited_requestor_leave_selected_capture_intact() {
    let mut f = Fixture::new();
    f.lanes.select(f.capture.key(), 258).unwrap();
    let mut wrong = f.caller;
    wrong.binding.reply_object += 1;
    assert_eq!(
        f.activations
            .begin_wait_resume(wrong, &f.pm, &f.catalog, &mut f.lanes, f.capture)
            .unwrap_err(),
        KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
    );
    assert_eq!(f.state().captured_wait(), Some(f.capture));
    f.pm.terminate_thread(f.caller.thread().thread_id(), 0)
        .unwrap();
    assert!(matches!(
        f.assert_refused_unchanged(),
        KernelProviderResumeError::Authority(_)
    ));
    assert_eq!(
        f.lanes.phase(f.caller.dispatch.lane()),
        Ok(LanePhase::Suspended)
    );
}

#[test]
fn dropped_entered_ticket_does_not_reopen_wait_or_initial_receive() {
    let mut f = Fixture::new();
    f.lanes.select(f.capture.key(), 258).unwrap();
    drop(f.resume().unwrap());
    assert_eq!(
        f.assert_refused_unchanged(),
        KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
    );
    let state = &mut f.activations.recipient_mut(f.caller).unwrap().state;
    assert_eq!(
        state.begin_initial().unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(
        state.begin_receive_after_yield().unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(state.progress().disposition(), None);
    assert!(state.captured_wait().is_none());
}

#[test]
fn same_wait_id_after_repark_rejects_old_observation_atomically() {
    let mut f = Fixture::new();
    let original = f.capture;
    f.lanes.select(original.key(), 258).unwrap();
    f.repark(72, 2);
    let current = f.repark(71, 3);
    assert_eq!(current.key(), original.key());
    assert_eq!(current.caller(), original.caller());
    assert_eq!(current.request(), original.request());
    assert_ne!(current, original);
    f.capture = original;
    assert_eq!(
        f.assert_refused_unchanged(),
        KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
    );
    assert_eq!(f.state().captured_wait(), Some(current));
    let lane = f.caller.dispatch.lane();
    f.lanes
        .frame_mut(lane, current.key())
        .unwrap()
        .unwrap()
        .continuation = original;
    assert_eq!(
        f.assert_refused_unchanged(),
        KernelProviderResumeError::Pump(PumpProgressError::NotReady)
    );
    assert_eq!(f.state().captured_wait(), Some(current));
    f.capture = current;
    assert_eq!(
        f.assert_refused_unchanged(),
        KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
    );
    assert_eq!(f.state().captured_wait(), Some(current));
    f.lanes
        .frame_mut(lane, current.key())
        .unwrap()
        .unwrap()
        .continuation = current;
    drop(f.resume().unwrap());
}

#[test]
fn rejected_request_remains_retained_without_capture_or_reply_retry() {
    let mut f = Fixture::new();
    f.lanes.select(f.capture.key(), 258).unwrap();
    let (_, mut attempt, _) = f.resume().unwrap().into_parts();
    let reply = f.caller.binding.reply_object;
    let mut request = request(f.caller.owner(), 72);
    request.header.magic = 0;
    f.activations
        .recipient_mut(f.caller)
        .unwrap()
        .state
        .observe(&mut attempt, facts(reply, false), None)
        .unwrap();
    let result = f.activations.capture_provider_wait(
        f.caller,
        &f.pm,
        &f.catalog,
        &f.lanes,
        reply,
        f.state().progress(),
        request,
    );
    assert_eq!(result, Err(STATUS_INVALID_PARAMETER));
    let state = &mut f.activations.recipient_mut(f.caller).unwrap().state;
    assert_eq!(
        state.retain_provider_wait(request, result),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        state.rejected_wait(),
        Some((&request, STATUS_INVALID_PARAMETER))
    );
    assert_eq!(
        state.retain_provider_wait(request, Err(STATUS_INVALID_HANDLE)),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        state.rejected_wait(),
        Some((&request, STATUS_INVALID_PARAMETER))
    );
    assert!(state.captured_wait().is_none());
    assert_eq!(
        state.begin_receive_after_yield().unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(
        f.assert_refused_unchanged(),
        KernelProviderResumeError::Authority(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn repeated_waits_return_only_through_terminal_retirement_and_exact_ack() {
    let mut f = Fixture::new();
    let bank = &*f.activations.recipient(f.caller).unwrap().bank as *const u64;
    f.lanes.select(f.capture.key(), 258).unwrap();
    f.repark(72, 2);
    let (_, mut attempt, _) = f.resume().unwrap().into_parts();
    let reply = f.caller.binding.reply_object;
    f.activations
        .recipient_mut(f.caller)
        .unwrap()
        .state
        .observe(&mut attempt, facts(reply, true), Some(7))
        .unwrap();
    let terminal = f
        .activations
        .retain_terminal_completion(
            f.caller,
            &f.pm,
            &f.catalog,
            &mut f.lanes,
            f.capture.key(),
            456,
            7,
        )
        .unwrap();
    assert!(f.activations.recipient_mut(f.caller).is_err());
    assert!(f.activations.completion(f.caller).is_err());
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    for stage in [
        TerminalStage::Output,
        TerminalStage::Context,
        TerminalStage::Publication,
        TerminalStage::Reply,
    ] {
        let mut stage_attempt = f
            .lanes
            .begin_terminal_stage(terminal, reply, stage)
            .unwrap();
        f.lanes
            .record_terminal_stage(
                &mut stage_attempt,
                reply,
                TerminalStageOutcome::Acknowledged,
            )
            .unwrap();
    }
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
    assert!(f.activations.completion(f.caller).is_err());
    let (receipt, retired) = f
        .activations
        .finish_terminal_completion(f.caller, &f.pm, &mut f.lanes, terminal, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(retired.payload, 456);
    assert_eq!(retired.suspension.completion, 258);
    assert_eq!(f.lanes.suspension_count(f.caller.dispatch.lane()), Ok(0));
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    let wrong = KernelProviderCompletionReceipt {
        status: 8,
        ..receipt
    };
    assert!(f
        .activations
        .acknowledge_completion_with_recipient(wrong, &mut f.pm)
        .is_err());
    assert_eq!(
        &*f.activations.recipient(f.caller).unwrap().bank as *const u64,
        bank
    );
    let (status, recipient) = f
        .activations
        .acknowledge_completion_with_recipient(receipt, &mut f.pm)
        .unwrap();
    assert_eq!(status, 7);
    assert_eq!(&*recipient.bank as *const u64, bank);
    assert_eq!(
        recipient.state.progress().disposition(),
        Some(KernelProviderPumpDisposition::Returned(7))
    );
    assert_eq!(references(&f.pm, f.caller.thread()), (0, 0));
    assert!(f
        .activations
        .acknowledge_completion_with_recipient(receipt, &mut f.pm)
        .is_err());
}
