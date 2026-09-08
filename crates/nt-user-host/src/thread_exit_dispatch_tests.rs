use super::*;
use crate::gui_exit::GuiExitPhase;
use crate::process_identity::ProcessGeneration;
use crate::provider_finalization::ProviderFinalizationResult as Outcome;
use crate::thread_binding::ThreadBinding;
use crate::thread_publication::ThreadPublicationSlot;
use crate::thread_slot::{RuntimeMechanismHandoff, RuntimeTcbProjection};

struct Runtime {
    binding: ThreadBinding<()>,
    publication: ThreadPublicationSlot,
    gui: GuiExitOwner,
    caller: ProviderLogicalCaller,
    mechanisms: [u64; 4],
}
impl RuntimeIdentity for Runtime {
    type Role = ();
    fn binding(&self) -> ThreadBinding<()> {
        self.binding
    }
    fn publication(&self) -> &ThreadPublicationSlot {
        &self.publication
    }
}
impl RuntimeGuiExit for Runtime {
    fn gui_exit_owner(&self) -> Option<&GuiExitOwner> {
        Some(&self.gui)
    }
    fn gui_exit_owner_mut(&mut self) -> Option<&mut GuiExitOwner> {
        Some(&mut self.gui)
    }
    fn gui_exit_logical_caller(&self) -> Option<ProviderLogicalCaller> {
        Some(self.caller)
    }
}
impl RuntimeTcbProjection for Runtime {
    fn clear_retired_tcb_projection(&mut self, expected: u64) -> Result<(), u32> {
        if self.binding.tcb != expected && self.binding.tcb != 1 {
            return Err(1);
        }
        self.binding.tcb = 1;
        Ok(())
    }
}
impl RuntimeMechanismHandoff for Runtime {
    fn registered_mechanism_slots(&self) -> Result<[u64; 4], u32> {
        Ok(self.mechanisms)
    }
    fn clear_registered_mechanism_projections(
        &mut self,
        id: ThreadRollbackId,
        expected: [u64; 4],
    ) -> Result<(), u32> {
        if id.identity().tid != self.binding.tid || expected != self.mechanisms {
            return Err(1);
        }
        self.mechanisms = [0; 4];
        Ok(())
    }
}
type Slot = ThreadRuntimeSlot<Runtime>;

fn make_runtime(final_mechanism: bool, job: bool, designated: bool) -> (ProcessManager, Runtime) {
    let mut pm = ProcessManager::new();
    let system = pm.create_process("kernel", None, None);
    let system_thread = pm.create_thread(system, 0, 0, true).unwrap();
    if designated {
        pm.designate_initial_system(system, system_thread).unwrap();
    }
    let pid = pm.create_process("gui", None, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    assert!(pm.publish_process_kernel_object(pid, 0x3000));
    assert!(pm.publish_thread_kernel_object(tid, 0x4000));
    assert!(pm.set_thread_win32(tid, 0x5000));
    assert!(pm.set_process_win32(pid, 0x6000));
    let job = if job {
        let job = pm.create_job(0).unwrap();
        pm.assign_process_to_job(job, pid).unwrap();
        Some(job)
    } else {
        None
    };
    let binding = ThreadBinding {
        pi: 2,
        process: ProcessIdentity {
            pid,
            generation: ProcessGeneration::Hosted(8),
        },
        tid: u64::from(tid),
        tcb: 9,
        badge: 7,
        role: (),
        reservations: None,
    };
    let caller = ProviderLogicalCaller::capture(binding, pm.thread_lifetime(tid).unwrap()).unwrap();
    let gui = GuiExitOwner::new(GuiExitContext {
        pi: binding.pi,
        process: binding.process,
        thread: caller.thread(),
        eprocess: 0x3000,
        ethread: 0x4000,
        win32_thread: Some(0x5000),
        win32_process: final_mechanism.then_some(0x6000),
        job,
        final_mechanism,
    })
    .unwrap();
    (
        pm,
        Runtime {
            binding,
            publication: ThreadPublicationSlot::empty(),
            gui,
            caller,
            mechanisms: [10, 11, 9, 12],
        },
    )
}
fn pending(runtime: Runtime) -> (Slot, ThreadRollbackId) {
    let binding = runtime.binding;
    let mut slot = Slot::empty();
    assert!(slot.insert(runtime).is_ok());
    let id = slot.begin_pending(binding).unwrap();
    (slot, id)
}
fn process(slot: &Slot) -> ProcessIdentity {
    slot.owner().unwrap().binding.process
}
fn admit(
    slot: &Slot,
    id: ThreadRollbackId,
    pm: &ProcessManager,
    call: &GuiExitInvocation,
) -> Result<ThreadExitDispatchAuthority, ThreadExitDispatchError> {
    ThreadExitDispatchAuthority::admit(slot, id, process(slot), pm, call)
}

#[test]
fn pending_exit_proof_does_not_reopen_ordinary_ingress() {
    let (pm, runtime) = make_runtime(false, false, true);
    let (mut slot, id) = pending(runtime);
    let call = slot.begin_gui_exit(id).unwrap();
    let proof = admit(&slot, id, &pm, &call).unwrap();
    assert_eq!(proof.rollback_id(), id);
    assert_eq!(proof.stage(), GuiExitStage::Thread);
    assert!(proof.validate(&slot, process(&slot), &pm).is_ok());
    assert_eq!(
        slot.admit_ingress(7, Some(process(&slot))).err(),
        Some(crate::thread_slot::ThreadIngressError::Pending)
    );
    assert!(slot.ordinary_mut().is_none());
    assert!(slot.release_published().is_none());
    assert!(slot.begin_gui_exit(id).is_err());
    slot.record_gui_exit(id, call, Outcome::Returned(0))
        .unwrap();
    assert_eq!(
        proof.validate(&slot, process(&slot), &pm),
        Err(ThreadExitDispatchError::InvocationChanged)
    );
}

#[test]
fn foreign_gui_token_or_pending_attempt_cannot_authorize_dispatch() {
    let (pm, runtime) = make_runtime(false, false, true);
    let mut foreign = GuiExitOwner::new(runtime.gui.context()).unwrap();
    let (mut slot, id) = pending(runtime);
    let call = slot.begin_gui_exit(id).unwrap();
    let foreign_call = foreign.begin().unwrap();
    assert_eq!(
        admit(&slot, id, &pm, &foreign_call),
        Err(ThreadExitDispatchError::InvocationChanged)
    );
    let (_, other_runtime) = runtime_fixture();
    let (_, other_id) = pending(other_runtime);
    assert_eq!(
        admit(&slot, other_id, &pm, &call),
        Err(ThreadExitDispatchError::StaleRuntime)
    );
    let (error, call) = slot
        .record_gui_exit(other_id, call, Outcome::Returned(0))
        .unwrap_err();
    assert_eq!(error, ThreadExitDispatchError::StaleRuntime);
    assert!(admit(&slot, id, &pm, &call).is_ok());
    slot.record_gui_exit(id, call, Outcome::Returned(0))
        .unwrap();
}
fn runtime_fixture() -> (ProcessManager, Runtime) {
    make_runtime(false, false, true)
}

#[test]
fn every_recorded_outcome_invalidates_proof_and_notentered_retry_has_fresh_identity() {
    for outcome in [
        Outcome::Returned(0),
        Outcome::Returned(123),
        Outcome::Indeterminate(124),
        Outcome::NotEntered(125),
    ] {
        let (pm, runtime) = make_runtime(false, false, true);
        let (mut slot, id) = pending(runtime);
        let call = slot.begin_gui_exit(id).unwrap();
        let proof = admit(&slot, id, &pm, &call).unwrap();
        slot.record_gui_exit(id, call, outcome).unwrap();
        assert_eq!(
            proof.validate(&slot, process(&slot), &pm),
            Err(ThreadExitDispatchError::InvocationChanged)
        );
        if matches!(outcome, Outcome::NotEntered(_)) {
            let next = slot.begin_gui_exit(id).unwrap();
            let next_proof = admit(&slot, id, &pm, &next).unwrap();
            assert_ne!(proof, next_proof);
            assert!(proof.validate(&slot, process(&slot), &pm).is_err());
        } else {
            assert!(slot.begin_gui_exit(id).is_err());
        }
    }
}

#[test]
fn exact_process_manager_and_process_incarnation_are_required() {
    let (pm, runtime) = make_runtime(false, false, true);
    let (mut slot, id) = pending(runtime);
    let call = slot.begin_gui_exit(id).unwrap();
    let proof = admit(&slot, id, &pm, &call).unwrap();
    let (other_pm, _) = runtime_fixture();
    assert_eq!(
        pm.thread_lifetime(proof.logical_caller().thread().thread_id()),
        other_pm.thread_lifetime(proof.logical_caller().thread().thread_id())
    );
    assert_eq!(
        proof.validate(&slot, process(&slot), &other_pm),
        Err(ThreadExitDispatchError::ManagerChanged)
    );
    let changed = ProcessIdentity {
        generation: ProcessGeneration::Hosted(9),
        ..process(&slot)
    };
    assert_eq!(
        proof.validate(&slot, changed, &pm),
        Err(ThreadExitDispatchError::ProcessChanged)
    );
    let (undesignated, runtime) = make_runtime(false, false, false);
    let (mut slot, id) = pending(runtime);
    let call = slot.begin_gui_exit(id).unwrap();
    assert_eq!(
        admit(&slot, id, &undesignated, &call),
        Err(ThreadExitDispatchError::MissingManagerDesignation)
    );
}

#[test]
fn exact_body_and_current_win32_state_are_required() {
    let (mut pm, mut runtime) = make_runtime(false, false, true);
    let mut context = runtime.gui.context();
    context.ethread = 0x8000;
    runtime.gui = GuiExitOwner::new(context).unwrap();
    let (mut slot, id) = pending(runtime);
    let call = slot.begin_gui_exit(id).unwrap();
    assert_eq!(
        admit(&slot, id, &pm, &call),
        Err(ThreadExitDispatchError::BodiesChanged)
    );
    let (other_pm, runtime) = runtime_fixture();
    pm = other_pm;
    let (mut slot, id) = pending(runtime);
    let call = slot.begin_gui_exit(id).unwrap();
    let proof = admit(&slot, id, &pm, &call).unwrap();
    assert!(pm.clear_thread_win32_exact(call.context().thread.thread_id(), 0x5000));
    assert_eq!(
        proof.validate(&slot, process(&slot), &pm),
        Err(ThreadExitDispatchError::Win32StateChanged)
    );
}

#[test]
fn thread_activation_invalidates_proof_even_when_pid_tid_and_body_are_reused() {
    let (mut pm, runtime) = make_runtime(false, false, true);
    let (mut slot, id) = pending(runtime);
    let call = slot.begin_gui_exit(id).unwrap();
    let proof = admit(&slot, id, &pm, &call).unwrap();
    let tid = call.context().thread.thread_id();
    pm.exit_thread(tid, 0).unwrap();
    assert!(
        proof.validate(&slot, process(&slot), &pm).is_ok(),
        "termination is not a new activation"
    );
    assert!(pm.clear_thread_win32_exact(tid, 0x5000));
    let plan = pm
        .prepare_thread_activation(tid, 0x1000, 0, true, 0x7000, 123, true)
        .unwrap();
    pm.commit_thread_activation(plan).unwrap();
    assert_eq!(
        proof.validate(&slot, process(&slot), &pm),
        Err(ThreadExitDispatchError::ThreadChanged)
    );
}

#[test]
fn mechanism_handoff_revokes_dispatch_but_does_not_lose_returned_evidence() {
    let (pm, runtime) = make_runtime(false, false, true);
    let (mut slot, id) = pending(runtime);
    let call = slot.begin_gui_exit(id).unwrap();
    let proof = admit(&slot, id, &pm, &call).unwrap();
    slot.handoff_registered_mechanisms(id).unwrap();
    assert_eq!(
        proof.validate(&slot, process(&slot), &pm),
        Err(ThreadExitDispatchError::RetirementStarted)
    );
    assert_eq!(
        slot.begin_gui_exit(id).err(),
        Some(ThreadExitDispatchError::RetirementStarted)
    );
    slot.record_gui_exit(id, call, Outcome::Returned(0))
        .unwrap();
    let context = slot.owner().unwrap().gui.context();
    slot.acknowledge_gui_exit(id, context, GuiExitAcknowledgment::ThreadClear, Err(77))
        .unwrap_err();
    assert_eq!(
        slot.owner().unwrap().gui.phase(),
        GuiExitPhase::Local(GuiExitAcknowledgment::ThreadClear)
    );
    slot.acknowledge_gui_exit(id, context, GuiExitAcknowledgment::ThreadClear, Ok(()))
        .unwrap();
    assert!(slot.owner().unwrap().gui.ready());
}

#[test]
fn final_process_job_and_process_dispatches_require_exact_captured_pm_state() {
    let (mut pm, runtime) = make_runtime(true, true, true);
    let (mut slot, id) = pending(runtime);
    let call = slot.begin_gui_exit(id).unwrap();
    let context = call.context();
    admit(&slot, id, &pm, &call).unwrap();
    slot.record_gui_exit(id, call, Outcome::Returned(0))
        .unwrap();
    assert!(pm.clear_thread_win32_exact(context.thread.thread_id(), 0x5000));
    slot.acknowledge_gui_exit(id, context, GuiExitAcknowledgment::ThreadClear, Ok(()))
        .unwrap();
    let job_call = slot.begin_gui_exit(id).unwrap();
    let job_proof = admit(&slot, id, &pm, &job_call).unwrap();
    assert_eq!(job_proof.stage(), GuiExitStage::JobRemoval);
    slot.record_gui_exit(id, job_call, Outcome::Returned(0))
        .unwrap();
    let process_call = slot.begin_gui_exit(id).unwrap();
    let proof = admit(&slot, id, &pm, &process_call).unwrap();
    assert_eq!(proof.stage(), GuiExitStage::Process);
    assert!(job_proof.validate(&slot, process(&slot), &pm).is_err());
    assert_eq!(
        pm.remove_process_job_reference(context.process.pid),
        context.job
    );
    assert_eq!(
        proof.validate(&slot, process(&slot), &pm),
        Err(ThreadExitDispatchError::JobChanged)
    );
}
