//! Process-owned one-shot native creation admission for its already allocated main ETHREAD.

use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InitialThreadCreationState {
    Unclaimed,
    Reserved {
        nonce: u64,
        lifetime: ThreadLifetime,
    },
    Committed {
        lifetime: ThreadLifetime,
    },
}

impl InitialThreadCreationState {
    pub(super) fn is_reserved(self) -> bool {
        matches!(self, Self::Reserved { .. })
    }
}

/// Opaque reservation, not evidence that any native effect has completed. The host retains this
/// plan across uncertain effects; it must never cancel simply because its constructor returned.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "retain through native ACK or proven mutation-free rejection"]
pub struct InitialThreadCreationPlan {
    nonce: u64,
    lifetime: ThreadLifetime,
}

impl InitialThreadCreationPlan {
    pub const fn lifetime(&self) -> ThreadLifetime {
        self.lifetime
    }
}

impl ProcessManager {
    /// Reserve the initial creation once. `None` means its creation was already committed,
    /// including after main-thread exit; subsequent creations must use ordinary worker admission.
    pub fn prepare_initial_thread_creation(
        &mut self,
        pid: ProcessId,
    ) -> Result<Option<InitialThreadCreationPlan>, u32> {
        let process = self.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
        if matches!(
            process.state,
            ProcessState::Exiting | ProcessState::Terminated
        ) || process.exit_status.is_some()
        {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        match process.initial_creation {
            InitialThreadCreationState::Committed { .. } => return Ok(None),
            InitialThreadCreationState::Reserved { .. } => return Err(STATUS_DEVICE_BUSY),
            InitialThreadCreationState::Unclaimed => {}
        }
        let tid = process.main_thread.ok_or(STATUS_INVALID_PARAMETER)?;
        let thread = self.thread(tid).ok_or(STATUS_INVALID_HANDLE)?;
        if thread.process_id != pid || !process.threads.iter().any(|&member| member == tid) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if thread.state == ThreadState::Terminated || thread.exit_status.is_some() {
            return Err(STATUS_THREAD_IS_TERMINATING);
        }
        if thread.activation_generation != 1 || thread.state == ThreadState::Initialized {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if thread.pending_suspend_control.is_some() {
            return Err(STATUS_DEVICE_BUSY);
        }
        let lifetime = self.thread_lifetime(tid).ok_or(STATUS_INVALID_HANDLE)?;
        let nonce = NEXT_NONCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        self.processes.get_mut(&pid).unwrap().initial_creation =
            InitialThreadCreationState::Reserved { nonce, lifetime };
        Ok(Some(InitialThreadCreationPlan { nonce, lifetime }))
    }

    fn validate_initial_thread_creation(
        &self,
        plan: &InitialThreadCreationPlan,
    ) -> Result<(), u32> {
        let process = self
            .process(plan.lifetime.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if matches!(
            process.state,
            ProcessState::Exiting | ProcessState::Terminated
        ) || process.exit_status.is_some()
        {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        let thread = self
            .thread(plan.lifetime.thread_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if process.main_thread != Some(plan.lifetime.thread_id)
            || !self.validate_thread_lifetime(plan.lifetime)
            || process.initial_creation
                != (InitialThreadCreationState::Reserved {
                    nonce: plan.nonce,
                    lifetime: plan.lifetime,
                })
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if thread.state == ThreadState::Terminated || thread.exit_status.is_some() {
            return Err(STATUS_THREAD_IS_TERMINATING);
        }
        if thread.state == ThreadState::Initialized {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if thread.pending_suspend_control.is_some() {
            return Err(STATUS_DEVICE_BUSY);
        }
        Ok(())
    }

    /// The host may commit only after its actual native creation/publication ACK. This records
    /// creation, not a scheduling transition: created-suspended threads retain their suspend state.
    pub fn commit_initial_thread_creation(
        &mut self,
        plan: &InitialThreadCreationPlan,
    ) -> Result<(), u32> {
        self.validate_initial_thread_creation(plan)?;
        self.processes
            .get_mut(&plan.lifetime.process_id)
            .unwrap()
            .initial_creation = InitialThreadCreationState::Committed {
            lifetime: plan.lifetime,
        };
        Ok(())
    }

    /// Cancel only before entering native effects or after a proven mutation-free rejection.
    /// Unknown effects must keep the reservation and plan held; cancellation is not native cleanup.
    pub fn cancel_initial_thread_creation(
        &mut self,
        plan: &InitialThreadCreationPlan,
    ) -> Result<(), u32> {
        self.validate_initial_thread_creation(plan)?;
        self.processes
            .get_mut(&plan.lifetime.process_id)
            .unwrap()
            .initial_creation = InitialThreadCreationState::Unclaimed;
        Ok(())
    }

    pub(super) fn has_initial_thread_creation_pending(&self, pid: ProcessId) -> bool {
        self.process(pid)
            .is_some_and(|process| process.initial_creation.is_reserved())
    }

    pub(super) fn has_initial_thread_creation_pending_for(&self, tid: ThreadId) -> bool {
        self.thread(tid)
            .and_then(|thread| self.process(thread.process_id))
            .is_some_and(|process| {
                matches!(process.initial_creation,
                InitialThreadCreationState::Reserved { lifetime, .. }
                    if lifetime.thread_id == tid)
            })
    }
}

#[cfg(test)]
#[path = "initial_thread_creation_tests.rs"]
mod tests;
