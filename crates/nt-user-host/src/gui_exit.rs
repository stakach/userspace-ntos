//! Retained GUI EXIT progress, separate from ordinary runtime ingress and mechanism retirement.
use crate::process_identity::ProcessIdentity;
use crate::provider_finalization::{
    ProviderFinalization, ProviderFinalizationPhase, ProviderFinalizationResult,
};
use core::sync::atomic::{AtomicU64, Ordering};
use nt_process::ThreadLifetime;

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

/// Captured from the canonical PM and retained runtime before teardown. This is metadata, not
/// provider admission or a PM reference. The adapter must retain those authorities separately and
/// prevent new GUI attachment throughout this owner's lifetime. ThreadLifetime is manager-scoped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuiExitContext {
    pub pi: usize,
    pub process: ProcessIdentity,
    pub thread: ThreadLifetime,
    pub eprocess: u64,
    pub ethread: u64,
    pub win32_thread: Option<u64>,
    /// Capture only the final mechanism's process EXIT obligation.
    pub win32_process: Option<u64>,
    /// Actual PM job membership for that process EXIT. None is a captured absence, not a request
    /// to resolve the current job later. The adapter must retain the canonical job lifetime.
    pub job: Option<nt_process::job::JobId>,
    pub final_mechanism: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuiExitStage {
    Thread,
    JobRemoval,
    Process,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuiExitAcknowledgment {
    ThreadClear,
    ProcessClear,
    CallbackRetirement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuiExitPhase {
    ThreadExit(ProviderFinalizationPhase),
    JobRemoval(ProviderFinalizationPhase),
    ProcessExit(ProviderFinalizationPhase),
    Local(GuiExitAcknowledgment),
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuiExitError {
    InvalidContext,
    WrongPhase,
    WrongInvocation,
    Exhausted,
    LocalFailure(u32),
}

/// No mutable owner or table borrow need cross IPC. Dropping this token leaves the retained
/// owner Invoking; neither a new token nor a synthetic completion can recover that ambiguity.
///
/// ```compile_fail
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<nt_user_host::gui_exit::GuiExitInvocation>();
/// ```
#[derive(Debug)]
pub struct GuiExitInvocation {
    owner: u64,
    epoch: u64,
    stage: GuiExitStage,
    context: GuiExitContext,
}

/// Non-owning evidence for one retained in-flight attempt. Every use must revalidate against the
/// original owner and the adapter's independent runtime/PM/provider lifetime authorities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuiExitDispatchIdentity {
    owner: u64,
    epoch: u64,
    stage: GuiExitStage,
    context: GuiExitContext,
}

impl GuiExitDispatchIdentity {
    pub const fn context(self) -> GuiExitContext {
        self.context
    }
    pub const fn stage(self) -> GuiExitStage {
        self.stage
    }
}

impl GuiExitInvocation {
    pub const fn context(&self) -> GuiExitContext {
        self.context
    }
    pub const fn stage(&self) -> GuiExitStage {
        self.stage
    }
    pub fn expected_pointer(&self) -> u64 {
        match self.stage {
            GuiExitStage::Thread => self.context.win32_thread.unwrap(),
            GuiExitStage::JobRemoval | GuiExitStage::Process => self.context.win32_process.unwrap(),
        }
    }
    pub const fn retain_thread_context(&self) -> bool {
        matches!(self.stage, GuiExitStage::Thread) && self.context.final_mechanism
    }
}

/// Retain in its original row until Complete. The private nonce fences independent owners even
/// when all routing metadata collides. Neither ownership nor an invocation token is cloneable.
///
/// ```compile_fail
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<nt_user_host::gui_exit::GuiExitOwner>();
/// ```
#[derive(Debug)]
pub struct GuiExitOwner {
    id: u64,
    epoch: u64,
    context: GuiExitContext,
    thread: ProviderFinalization,
    job: ProviderFinalization,
    process: ProviderFinalization,
    thread_cleared: bool,
    process_cleared: bool,
    callbacks_retired: bool,
}

impl GuiExitOwner {
    pub fn new(context: GuiExitContext) -> Result<Self, GuiExitError> {
        Self::with_counter(context, &NEXT_OWNER)
    }

    fn with_counter(context: GuiExitContext, counter: &AtomicU64) -> Result<Self, GuiExitError> {
        if !context.process.is_valid()
            || context.thread.process_id() != context.process.pid
            || context.thread.thread_id() == 0
            || context.thread.generation() == 0
            || context.win32_thread == Some(0)
            || context.win32_process == Some(0)
            || context.job == Some(0)
            || (context.job.is_some() && context.win32_process.is_none())
            || (context.win32_process.is_some() && !context.final_mechanism)
            || (context.win32_thread.is_some() && (context.ethread == 0 || context.eprocess == 0))
            || (context.win32_process.is_some() && context.eprocess == 0)
            || (context.eprocess != 0 && context.eprocess == context.ethread)
        {
            return Err(GuiExitError::InvalidContext);
        }
        let id = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                if value == 0 {
                    None
                } else {
                    value.checked_add(1)
                }
            })
            .map_err(|_| GuiExitError::Exhausted)?;
        Ok(Self {
            id,
            epoch: 0,
            context,
            thread: ProviderFinalization::new(context.win32_thread.is_some()),
            job: ProviderFinalization::new(context.job.is_some()),
            process: ProviderFinalization::new(context.win32_process.is_some()),
            thread_cleared: context.win32_thread.is_none(),
            process_cleared: context.win32_process.is_none(),
            callbacks_retired: !context.final_mechanism,
        })
    }

    pub const fn context(&self) -> GuiExitContext {
        self.context
    }

    pub fn phase(&self) -> GuiExitPhase {
        if !self.thread.ready() {
            return GuiExitPhase::ThreadExit(self.thread.phase());
        }
        if !self.thread_cleared {
            return GuiExitPhase::Local(GuiExitAcknowledgment::ThreadClear);
        }
        if !self.job.ready() {
            return GuiExitPhase::JobRemoval(self.job.phase());
        }
        if !self.process.ready() {
            return GuiExitPhase::ProcessExit(self.process.phase());
        }
        if !self.process_cleared {
            return GuiExitPhase::Local(GuiExitAcknowledgment::ProcessClear);
        }
        if !self.callbacks_retired {
            return GuiExitPhase::Local(GuiExitAcknowledgment::CallbackRetirement);
        }
        GuiExitPhase::Complete
    }

    pub fn ready(&self) -> bool {
        self.phase() == GuiExitPhase::Complete
    }

    pub fn dispatch_identity(
        &self,
        invocation: &GuiExitInvocation,
    ) -> Result<GuiExitDispatchIdentity, GuiExitError> {
        let identity = GuiExitDispatchIdentity {
            owner: invocation.owner,
            epoch: invocation.epoch,
            stage: invocation.stage,
            context: invocation.context,
        };
        if !self.matches_dispatch_identity(identity) {
            return Err(GuiExitError::WrongInvocation);
        }
        Ok(identity)
    }

    pub fn matches_dispatch_identity(&self, identity: GuiExitDispatchIdentity) -> bool {
        let expected = match identity.stage {
            GuiExitStage::Thread => GuiExitPhase::ThreadExit(ProviderFinalizationPhase::Invoking),
            GuiExitStage::JobRemoval => {
                GuiExitPhase::JobRemoval(ProviderFinalizationPhase::Invoking)
            }
            GuiExitStage::Process => GuiExitPhase::ProcessExit(ProviderFinalizationPhase::Invoking),
        };
        identity.owner == self.id
            && identity.epoch == self.epoch
            && identity.context == self.context
            && self.phase() == expected
    }

    /// Store Invoking before releasing the table borrow and entering the component. No allocation.
    pub fn begin(&mut self) -> Result<GuiExitInvocation, GuiExitError> {
        let stage = match self.phase() {
            GuiExitPhase::ThreadExit(ProviderFinalizationPhase::Pending) => GuiExitStage::Thread,
            GuiExitPhase::JobRemoval(ProviderFinalizationPhase::Pending) => {
                GuiExitStage::JobRemoval
            }
            GuiExitPhase::ProcessExit(ProviderFinalizationPhase::Pending) => GuiExitStage::Process,
            _ => return Err(GuiExitError::WrongPhase),
        };
        let epoch = self.epoch.checked_add(1).ok_or(GuiExitError::Exhausted)?;
        match stage {
            GuiExitStage::Thread => &mut self.thread,
            GuiExitStage::JobRemoval => &mut self.job,
            GuiExitStage::Process => &mut self.process,
        }
        .begin()
        .expect("pending EXIT preflight");
        self.epoch = epoch;
        Ok(GuiExitInvocation {
            owner: self.id,
            epoch,
            stage,
            context: self.context,
        })
    }

    /// Record only the exact detached token. Wrong-owner/phase rejection returns it unchanged.
    /// Unlike generic finalization, a returned EXIT failure is never proof of safe replay: the
    /// actual callout may already have changed provider state before reporting its failure.
    pub fn record(
        &mut self,
        invocation: GuiExitInvocation,
        outcome: ProviderFinalizationResult,
    ) -> Result<(), (GuiExitError, GuiExitInvocation)> {
        if self.dispatch_identity(&invocation).is_err() {
            return Err((GuiExitError::WrongInvocation, invocation));
        }
        let outcome = match outcome {
            ProviderFinalizationResult::Returned(0) => ProviderFinalizationResult::Returned(0),
            ProviderFinalizationResult::NotEntered(status) => {
                ProviderFinalizationResult::NotEntered(status)
            }
            ProviderFinalizationResult::Returned(status)
            | ProviderFinalizationResult::Indeterminate(status) => {
                ProviderFinalizationResult::Indeterminate(status)
            }
        };
        match invocation.stage {
            GuiExitStage::Thread => &mut self.thread,
            GuiExitStage::JobRemoval => &mut self.job,
            GuiExitStage::Process => &mut self.process,
        }
        .record(outcome)
        .expect("exact invoking EXIT owner");
        Ok(())
    }

    /// Call after the exact local operation. Failure preserves acceptance and retries only this
    /// local stage; it cannot cause another provider invocation. No backend call is made here.
    pub fn acknowledge(
        &mut self,
        expected: GuiExitContext,
        action: GuiExitAcknowledgment,
        result: Result<(), u32>,
    ) -> Result<(), GuiExitError> {
        if expected != self.context {
            return Err(GuiExitError::InvalidContext);
        }
        if self.phase() != GuiExitPhase::Local(action) {
            return Err(GuiExitError::WrongPhase);
        }
        result.map_err(GuiExitError::LocalFailure)?;
        match action {
            GuiExitAcknowledgment::ThreadClear => self.thread_cleared = true,
            GuiExitAcknowledgment::ProcessClear => self.process_cleared = true,
            GuiExitAcknowledgment::CallbackRetirement => self.callbacks_retired = true,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
