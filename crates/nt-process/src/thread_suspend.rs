//! Counted NT suspension, independent of the underlying dispatcher wait state.
//!
//! A prepared plan reserves one ETHREAD until exact commit or pre-effect cancellation. The native
//! owner must retain the plan across mechanism IPC and only commit after its execution-hold ACK.
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{
    NtThread, ProcessId, ProcessManager, ThreadId, ThreadLifetime, ThreadState, STATUS_DEVICE_BUSY,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_SUSPEND_COUNT_EXCEEDED,
};

pub const MAXIMUM_SUSPEND_COUNT: u32 = 0x7f;
static NEXT_MANAGER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadSuspendOperation {
    Suspend,
    Resume,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadSuspendTransition {
    None,
    AcquireHold,
    ReleaseHold,
}

/// Opaque admission identity for a retained native mechanism ticket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadSuspendIdentity {
    manager: u64,
    lifetime: ThreadLifetime,
    revision: u64,
}

/// Exact, once-only count admission. Dropping this does not release the ETHREAD reservation.
/// CREATE_SUSPENDED threads require the host's initial-start protocol before a ReleaseHold can
/// execute: the count alone does not prove that their initially inactive TCB owns a physical hold.
#[must_use = "commit after mechanism ACK, or cancel only when no physical change occurred"]
#[derive(Debug)]
pub struct ThreadSuspendPlan {
    manager: u64,
    lifetime: ThreadLifetime,
    revision: u64,
    operation: ThreadSuspendOperation,
    previous: u32,
    next: u32,
}

impl ThreadSuspendPlan {
    pub const fn identity(&self) -> ThreadSuspendIdentity {
        ThreadSuspendIdentity {
            manager: self.manager,
            lifetime: self.lifetime,
            revision: self.revision,
        }
    }
    pub const fn lifetime(&self) -> ThreadLifetime {
        self.lifetime
    }
    pub const fn operation(&self) -> ThreadSuspendOperation {
        self.operation
    }
    pub const fn previous_count(&self) -> u32 {
        self.previous
    }
    pub const fn next_count(&self) -> u32 {
        self.next
    }
    pub const fn transition(&self) -> ThreadSuspendTransition {
        match (self.previous, self.next) {
            (0, 1) => ThreadSuspendTransition::AcquireHold,
            (1, 0) => ThreadSuspendTransition::ReleaseHold,
            _ => ThreadSuspendTransition::None,
        }
    }
}

impl NtThread {
    fn project_scheduling_state(&mut self) {
        self.state = if self.suspend_count != 0 && self.scheduling_state != ThreadState::Terminated
        {
            ThreadState::Suspended
        } else {
            self.scheduling_state
        };
    }
}

impl ProcessManager {
    pub fn has_thread_suspend_control(&self, tid: ThreadId) -> bool {
        self.threads
            .get(&tid)
            .is_some_and(|thread| thread.pending_suspend_control.is_some())
    }

    pub fn has_process_suspend_control(&self, pid: ProcessId) -> bool {
        self.threads
            .values()
            .any(|thread| thread.process_id == pid && thread.pending_suspend_control.is_some())
    }

    /// Reserve without changing count or scheduling state. No allocation or native IPC occurs.
    pub fn prepare_thread_suspend_control(
        &mut self,
        lifetime: ThreadLifetime,
        operation: ThreadSuspendOperation,
    ) -> Result<ThreadSuspendPlan, u32> {
        if !self.validate_thread_lifetime(lifetime) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let thread = self
            .threads
            .get(&lifetime.thread_id())
            .ok_or(STATUS_INVALID_HANDLE)?;
        if thread.state == ThreadState::Terminated {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if thread.pending_suspend_control.is_some() {
            return Err(STATUS_DEVICE_BUSY);
        }
        let previous = thread.suspend_count;
        let next = match operation {
            ThreadSuspendOperation::Suspend if previous >= MAXIMUM_SUSPEND_COUNT => {
                return Err(STATUS_SUSPEND_COUNT_EXCEEDED);
            }
            ThreadSuspendOperation::Suspend => previous + 1,
            ThreadSuspendOperation::Resume => previous.saturating_sub(1),
        };
        let revision = thread
            .suspend_revision
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        if self.suspend_manager_identity == 0 {
            self.suspend_manager_identity = NEXT_MANAGER
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        }
        let thread = self
            .threads
            .get_mut(&lifetime.thread_id())
            .ok_or(STATUS_INVALID_HANDLE)?;
        thread.suspend_revision = revision;
        thread.pending_suspend_control = Some(revision);
        Ok(ThreadSuspendPlan {
            manager: self.suspend_manager_identity,
            lifetime,
            revision,
            operation,
            previous,
            next,
        })
    }

    /// Validate after reentry without consuming admission or changing any state.
    pub fn validate_thread_suspend_control(&self, plan: &ThreadSuspendPlan) -> Result<(), u32> {
        if self.suspend_manager_identity != plan.manager
            || !self.validate_thread_lifetime(plan.lifetime)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let thread = self
            .threads
            .get(&plan.lifetime.thread_id())
            .ok_or(STATUS_INVALID_HANDLE)?;
        if thread.state == ThreadState::Terminated
            || thread.pending_suspend_control != Some(plan.revision)
            || thread.suspend_revision != plan.revision
            || thread.suspend_count != plan.previous
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(())
    }

    /// Commit after the exact physical transition has been acknowledged. The latest wait state is
    /// read here, not captured in the plan, so a concurrent wait completion cannot be overwritten.
    pub fn commit_thread_suspend_control(&mut self, plan: &ThreadSuspendPlan) -> Result<u32, u32> {
        self.validate_thread_suspend_control(plan)?;
        let thread = self
            .threads
            .get_mut(&plan.lifetime.thread_id())
            .ok_or(STATUS_INVALID_HANDLE)?;
        thread.suspend_count = plan.next;
        if plan.next != 0 && thread.scheduling_state == ThreadState::Running {
            thread.scheduling_state = ThreadState::Ready;
        }
        thread.project_scheduling_state();
        thread.pending_suspend_control = None;
        Ok(plan.previous)
    }

    /// The caller must prove native entry did not occur, or that it was canonically rejected.
    /// An indeterminate native outcome must retain this plan and its ETHREAD reservation.
    pub fn cancel_thread_suspend_control(&mut self, plan: &ThreadSuspendPlan) -> Result<(), u32> {
        self.validate_thread_suspend_control(plan)?;
        self.threads
            .get_mut(&plan.lifetime.thread_id())
            .ok_or(STATUS_INVALID_HANDLE)?
            .pending_suspend_control = None;
        Ok(())
    }

    /// Update the underlying wait/run state while preserving counted suspension. Suspended is a
    /// projection, not an independently writable dispatcher state; use suspend_thread for it.
    pub fn set_thread_state(&mut self, tid: ThreadId, state: ThreadState) -> Result<(), u32> {
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        if thread.state == ThreadState::Terminated || state == ThreadState::Suspended {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if matches!(state, ThreadState::Initialized | ThreadState::Terminated)
            && thread.pending_suspend_control.is_some()
        {
            return Err(STATUS_DEVICE_BUSY);
        }
        if state == ThreadState::Initialized {
            thread.suspend_count = 0;
        }
        thread.scheduling_state = if state == ThreadState::Running && thread.suspend_count != 0 {
            ThreadState::Ready
        } else {
            state
        };
        thread.project_scheduling_state();
        if state == ThreadState::Terminated {
            thread.user_apc_queue.clear();
        }
        Ok(())
    }

    /// Host-only convenience for an already serialized, purely local count transition.
    pub fn suspend_thread(&mut self, tid: ThreadId) -> Result<u32, u32> {
        let lifetime = self.thread_lifetime(tid).ok_or(STATUS_INVALID_HANDLE)?;
        let plan =
            self.prepare_thread_suspend_control(lifetime, ThreadSuspendOperation::Suspend)?;
        self.commit_thread_suspend_control(&plan)
    }

    /// Final resume reveals the retained wait/ready state; a zero-count resume is a no-op.
    pub fn resume_thread(&mut self, tid: ThreadId) -> Result<u32, u32> {
        let lifetime = self.thread_lifetime(tid).ok_or(STATUS_INVALID_HANDLE)?;
        let plan = self.prepare_thread_suspend_control(lifetime, ThreadSuspendOperation::Resume)?;
        self.commit_thread_suspend_control(&plan)
    }
}

#[cfg(test)]
mod tests;
