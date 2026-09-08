//! Exact pending-runtime authority for the retained GUI lifecycle invocation, not ordinary ingress.
use crate::gui_exit::{
    GuiExitAcknowledgment, GuiExitContext, GuiExitDispatchIdentity, GuiExitError,
    GuiExitInvocation, GuiExitOwner, GuiExitStage,
};
use crate::process_identity::ProcessIdentity;
use crate::provider_logical_caller::ProviderLogicalCaller;
use crate::thread_rollback::ThreadRollbackId;
use crate::thread_slot::{RuntimeIdentity, ThreadRuntimeSlot};
use nt_process::{InitialSystemIdentity, ProcessManager};

/// Read the owner and original caller retained in this exact runtime row. Capture the caller
/// through ordinary ingress before pending admission; never manufacture it from a pending row.
/// These references are only borrowed for validation and must not cross provider IPC.
pub trait RuntimeGuiExit: RuntimeIdentity {
    fn gui_exit_owner(&self) -> Option<&GuiExitOwner>;
    /// This does not expose a pending runtime mutably: only the slot's specific GUI operations
    /// reach it after exact pending-ID validation. Do not replace the retained GUI owner.
    fn gui_exit_owner_mut(&mut self) -> Option<&mut GuiExitOwner>;
    fn gui_exit_logical_caller(&self) -> Option<ProviderLogicalCaller>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadExitDispatchError {
    NotPending,
    StaleRuntime,
    RetirementStarted,
    MissingGuiOwner,
    InvocationChanged,
    MissingCaller,
    CallerChanged,
    ProcessChanged,
    MissingManagerDesignation,
    ManagerChanged,
    ThreadChanged,
    BodiesChanged,
    Win32StateChanged,
    JobChanged,
    GuiExit(GuiExitError),
}

/// A restricted dispatch proof, not a PM reference or a general memory-access permit. It permits
/// only its captured Thread EXIT, JobRemoval, or Process EXIT operation. A native adapter must
/// additionally bind it to the actual provider catalog/lane/job and revalidate before each effect.
/// Keep ordinary ingress, user callbacks and wait-resume paths separate and rejecting pending rows.
///
/// For attachment/demand faults, carry this proof to the actual access gate, validate it there,
/// and exclude only its exact rollback ID from the pending-memory deny set. All other pending,
/// registry-transfer, pagefile and scratch exclusions still apply. Never convert it into a global
/// boolean bypass. The adapter must retain PM/body/VSpace owners and finish or retain the GUI
/// outcome before allowing mechanism handoff; this metadata alone cannot stop a running provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadExitDispatchAuthority {
    pending: ThreadRollbackId,
    manager: InitialSystemIdentity,
    caller: ProviderLogicalCaller,
    invocation: GuiExitDispatchIdentity,
}

impl ThreadExitDispatchAuthority {
    /// `current_process` must come from the canonical native process/VSpace authority. PM cannot
    /// reconstruct a hosted or temporary-slot generation. No allocation, mutation or backend call.
    pub fn admit<R: RuntimeGuiExit>(
        slot: &ThreadRuntimeSlot<R>,
        expected: ThreadRollbackId,
        current_process: ProcessIdentity,
        pm: &ProcessManager,
        invocation: &GuiExitInvocation,
    ) -> Result<Self, ThreadExitDispatchError> {
        let pending = slot.pending().ok_or(ThreadExitDispatchError::NotPending)?;
        if pending.id() != expected {
            return Err(ThreadExitDispatchError::StaleRuntime);
        }
        let runtime = pending.runtime();
        let gui = runtime
            .gui_exit_owner()
            .ok_or(ThreadExitDispatchError::MissingGuiOwner)?;
        let authority = Self {
            pending: expected,
            manager: pm
                .initial_system_identity()
                .ok_or(ThreadExitDispatchError::MissingManagerDesignation)?,
            caller: runtime
                .gui_exit_logical_caller()
                .ok_or(ThreadExitDispatchError::MissingCaller)?,
            invocation: gui
                .dispatch_identity(invocation)
                .map_err(|_| ThreadExitDispatchError::InvocationChanged)?,
        };
        authority.validate(slot, current_process, pm)?;
        Ok(authority)
    }

    /// Fresh validation, including after a provider reentry or failed entry. Every recorded GUI
    /// outcome invalidates the old proof; a genuine NotEntered retry requires a new invocation.
    pub fn validate<R: RuntimeGuiExit>(
        &self,
        slot: &ThreadRuntimeSlot<R>,
        current_process: ProcessIdentity,
        pm: &ProcessManager,
    ) -> Result<(), ThreadExitDispatchError> {
        let pending = slot.pending().ok_or(ThreadExitDispatchError::NotPending)?;
        if pending.id() != self.pending {
            return Err(ThreadExitDispatchError::StaleRuntime);
        }
        if !pending.permits_gui_exit_dispatch() {
            return Err(ThreadExitDispatchError::RetirementStarted);
        }
        let runtime = pending.runtime();
        let binding = runtime.binding();
        let identity = self.pending.identity();
        if runtime.publication().is_busy()
            || binding.pi != identity.pi
            || binding.process.pid != identity.pid
            || binding.process.generation != identity.process_generation
            || binding.tid != identity.tid
            || binding.reservations != pending.reservations()
        {
            return Err(ThreadExitDispatchError::StaleRuntime);
        }
        if current_process != binding.process {
            return Err(ThreadExitDispatchError::ProcessChanged);
        }
        if pm.initial_system_identity() != Some(self.manager) {
            return Err(ThreadExitDispatchError::ManagerChanged);
        }
        if runtime.gui_exit_logical_caller() != Some(self.caller)
            || binding.tcb <= 1
            || self.caller.tcb() != binding.tcb
            || self.caller.badge() != binding.badge
            || self.caller.pi() != binding.pi
            || self.caller.process() != binding.process
            || u64::from(self.caller.thread().thread_id()) != binding.tid
        {
            return Err(ThreadExitDispatchError::CallerChanged);
        }
        if pm.thread_lifetime(self.caller.thread().thread_id()) != Some(self.caller.thread()) {
            return Err(ThreadExitDispatchError::ThreadChanged);
        }
        let gui = runtime
            .gui_exit_owner()
            .ok_or(ThreadExitDispatchError::MissingGuiOwner)?;
        if !gui.matches_dispatch_identity(self.invocation) {
            return Err(ThreadExitDispatchError::InvocationChanged);
        }
        let context = self.invocation.context();
        if context.pi != binding.pi
            || context.process != binding.process
            || context.thread != self.caller.thread()
        {
            return Err(ThreadExitDispatchError::CallerChanged);
        }
        if context.eprocess == 0
            || context.ethread == 0
            || pm.process_kernel_object(context.process.pid) != Some(context.eprocess)
            || pm.thread_kernel_object(context.thread.thread_id()) != Some(context.ethread)
        {
            return Err(ThreadExitDispatchError::BodiesChanged);
        }
        let thread_win32 = pm.thread_win32(context.thread.thread_id());
        match self.invocation.stage() {
            GuiExitStage::Thread if thread_win32 != context.win32_thread => {
                return Err(ThreadExitDispatchError::Win32StateChanged)
            }
            GuiExitStage::JobRemoval | GuiExitStage::Process if thread_win32.is_some() => {
                return Err(ThreadExitDispatchError::Win32StateChanged)
            }
            _ => {}
        }
        if context.win32_process.is_some()
            && pm.process_win32(context.process.pid) != context.win32_process
        {
            return Err(ThreadExitDispatchError::Win32StateChanged);
        }
        if context.win32_process.is_some()
            && (pm.process_job(context.process.pid) != context.job
                || context.job.is_some_and(|job| !pm.job_exists(job)))
        {
            return Err(ThreadExitDispatchError::JobChanged);
        }
        Ok(())
    }

    pub const fn rollback_id(self) -> ThreadRollbackId {
        self.pending
    }
    pub const fn logical_caller(self) -> ProviderLogicalCaller {
        self.caller
    }
    pub const fn stage(self) -> GuiExitStage {
        self.invocation.stage()
    }
    pub const fn invocation(self) -> GuiExitDispatchIdentity {
        self.invocation
    }
}

impl<R: RuntimeGuiExit> ThreadRuntimeSlot<R> {
    pub fn begin_gui_exit(
        &mut self,
        expected: ThreadRollbackId,
    ) -> Result<GuiExitInvocation, ThreadExitDispatchError> {
        let pending = self.pending_mut_exact(expected).map_err(slot_error)?;
        if !pending.permits_gui_exit_dispatch() {
            return Err(ThreadExitDispatchError::RetirementStarted);
        }
        pending
            .gui_exit_owner_mut()
            .ok_or(ThreadExitDispatchError::MissingGuiOwner)?
            .begin()
            .map_err(ThreadExitDispatchError::GuiExit)
    }

    /// Always preserve the exact returned evidence, even if later dispatch admission is closed.
    /// Rejection returns the invocation unchanged; it must not be dropped or replayed implicitly.
    pub fn record_gui_exit(
        &mut self,
        expected: ThreadRollbackId,
        invocation: GuiExitInvocation,
        outcome: crate::provider_finalization::ProviderFinalizationResult,
    ) -> Result<(), (ThreadExitDispatchError, GuiExitInvocation)> {
        let pending = match self.pending_mut_exact(expected) {
            Ok(pending) => pending,
            Err(error) => return Err((slot_error(error), invocation)),
        };
        let Some(gui) = pending.gui_exit_owner_mut() else {
            return Err((ThreadExitDispatchError::MissingGuiOwner, invocation));
        };
        gui.record(invocation, outcome)
            .map_err(|(error, invocation)| (ThreadExitDispatchError::GuiExit(error), invocation))
    }

    pub fn acknowledge_gui_exit(
        &mut self,
        expected: ThreadRollbackId,
        context: GuiExitContext,
        action: GuiExitAcknowledgment,
        result: Result<(), u32>,
    ) -> Result<(), ThreadExitDispatchError> {
        self.pending_mut_exact(expected)
            .map_err(slot_error)?
            .gui_exit_owner_mut()
            .ok_or(ThreadExitDispatchError::MissingGuiOwner)?
            .acknowledge(context, action, result)
            .map_err(ThreadExitDispatchError::GuiExit)
    }
}

fn slot_error(error: crate::thread_slot::SlotError) -> ThreadExitDispatchError {
    match error {
        crate::thread_slot::SlotError::OwnerChanged => ThreadExitDispatchError::StaleRuntime,
        _ => ThreadExitDispatchError::NotPending,
    }
}

#[cfg(test)]
#[path = "thread_exit_dispatch_tests.rs"]
mod tests;
