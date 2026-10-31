//! Checked PM half of `KeSetPriorityThread`; native TCB work precedes commit.

use crate::{
    ProcessManager, ThreadLifetime, ThreadState, HIGH_PRIORITY, LOW_PRIORITY,
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
};

#[must_use = "commit only after the exact native TCB priority change is acknowledged"]
#[derive(Debug)]
pub struct KernelThreadPriorityPlan {
    manager: u64,
    ethread: u64,
    lifetime: ThreadLifetime,
    state: ThreadState,
    base_priority: i32,
    previous: i32,
    next: i32,
}

impl KernelThreadPriorityPlan {
    pub const fn lifetime(&self) -> ThreadLifetime { self.lifetime }
    pub const fn kernel_object(&self) -> u64 { self.ethread }
    pub const fn previous(&self) -> i32 { self.previous }
    pub const fn next(&self) -> i32 { self.next }
}

impl ProcessManager {
    pub fn prepare_kernel_thread_priority(
        &mut self, ethread: u64, priority: i32,
    ) -> Result<KernelThreadPriorityPlan, u32> {
        if !(LOW_PRIORITY..=HIGH_PRIORITY).contains(&priority) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let tid = self.tid_for_kernel_thread_object(ethread).ok_or(STATUS_INVALID_HANDLE)?;
        let thread = self.thread(tid).ok_or(STATUS_INVALID_HANDLE)?;
        if matches!(thread.state, ThreadState::Initialized | ThreadState::Terminated) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let lifetime = self.thread_lifetime(tid).ok_or(STATUS_INVALID_HANDLE)?;
        let state = thread.state;
        let base_priority = thread.base_priority;
        let previous = thread.priority;
        let next = if priority == LOW_PRIORITY && base_priority != LOW_PRIORITY {
            LOW_PRIORITY + 1
        } else {
            priority
        };
        let manager = self.ensure_priority_plan_manager_identity()?;
        Ok(KernelThreadPriorityPlan {
            manager, ethread, lifetime, state, base_priority, previous, next,
        })
    }

    /// Validate the exact activation and captured scheduler state before any PM write.
    pub fn commit_kernel_thread_priority(
        &mut self, plan: KernelThreadPriorityPlan,
    ) -> Result<i32, u32> {
        self.commit_kernel_thread_priority_retained(&plan)
    }

    /// Checked commit that preserves the plan on a stale post-effect refusal.
    pub fn commit_kernel_thread_priority_retained(
        &mut self, plan: &KernelThreadPriorityPlan,
    ) -> Result<i32, u32> {
        if self.priority_plan_manager_identity != plan.manager
            || self.tid_for_kernel_thread_object(plan.ethread) != Some(plan.lifetime.thread_id())
            || !self.validate_thread_lifetime(plan.lifetime)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let thread = self.thread(plan.lifetime.thread_id()).ok_or(STATUS_INVALID_HANDLE)?;
        if thread.state != plan.state
            || thread.base_priority != plan.base_priority
            || thread.priority != plan.previous
            || thread.kernel_thread_object != Some(plan.ethread)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.threads.get_mut(&plan.lifetime.thread_id()).unwrap().priority = plan.next;
        Ok(plan.previous)
    }
}
