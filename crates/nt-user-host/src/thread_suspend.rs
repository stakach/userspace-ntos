//! Retained suspension delivery. Count reservations and physical execution holds are separate.
//! The native runtime must retain this owner and its TCB while any attempt is pending. No method
//! invokes a backend; only the detached invocation may cross native IPC.

use crate::thread_binding::ThreadBinding;
use nt_process::thread_suspend::{
    ThreadSuspendIdentity, ThreadSuspendOperation, ThreadSuspendPlan, ThreadSuspendTransition,
};
use nt_process::{ProcessManager, ThreadLifetime};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadExecutionState {
    Running,
    /// The exact initially inactive mechanism has never been resumed.
    Dormant,
    Held {
        generation: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadSuspendAction {
    Acquire { tcb: u64 },
    Release { tcb: u64, generation: u64 },
    Start { tcb: u64 },
}

/// Only definitive kernel replies may be classified as Acknowledged or Rejected. A transport
/// error or malformed reply is not rejection. Acquire ACK carries its nonzero generation;
/// Release and Start ACKs carry no generation. Native adapters check reply label and length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadSuspendOutcome {
    Acknowledged { generation: Option<u64> },
    Rejected { status: u32 },
    Indeterminate { status: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadSuspendError {
    InvalidBinding,
    OwnerChanged,
    Busy,
    WrongPhase,
    WrongInvocation,
    InconsistentState,
    MalformedAcknowledgment,
    Indeterminate(u32),
    Process(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadSuspendPhase {
    Idle,
    Local,
    Prepared,
    Invoking,
    Acknowledged,
    Rejected(u32),
    Indeterminate(ThreadSuspendError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadSuspendCompletion {
    pub previous_count: u32,
    pub count: u32,
    /// A canonical rejection cancels the reservation without changing the count or mechanism.
    pub rejection: Option<u32>,
}

/// Once-only dispatch authority for the original retained owner. Dropping this token leaves the
/// owner Invoking and the PM reserved. It cannot be reconstructed to retry an uncertain call.
///
/// ```compile_fail
/// fn clone_required<T: Clone>() {}
/// clone_required::<nt_user_host::thread_suspend::ThreadSuspendInvocation<()>>();
/// ```
#[derive(Debug)]
pub struct ThreadSuspendInvocation<R> {
    identity: ThreadSuspendIdentity,
    binding: ThreadBinding<R>,
    lifetime: ThreadLifetime,
    action: ThreadSuspendAction,
}

impl<R: Copy> ThreadSuspendInvocation<R> {
    pub fn binding(&self) -> ThreadBinding<R> {
        self.binding
    }
    pub fn lifetime(&self) -> ThreadLifetime {
        self.lifetime
    }
    pub fn action(&self) -> ThreadSuspendAction {
        self.action
    }
}

struct Pending {
    plan: ThreadSuspendPlan,
    action: Option<ThreadSuspendAction>,
    phase: ThreadSuspendPhase,
    acknowledged_state: Option<ThreadExecutionState>,
}

/// Embed exactly once in the native runtime. Running means no suspension hold, not that the
/// underlying NT wait has completed. This owner never restores a saved wait/scheduling state.
///
/// ```compile_fail
/// fn clone_required<T: Clone>() {}
/// clone_required::<nt_user_host::thread_suspend::ThreadSuspendOwner<()>>();
/// ```
pub struct ThreadSuspendOwner<R> {
    binding: ThreadBinding<R>,
    lifetime: ThreadLifetime,
    state: ThreadExecutionState,
    pending: Option<Pending>,
}

impl<R: Copy + Eq> ThreadSuspendOwner<R> {
    /// Construct after the real initial-start acknowledgment, with no execution hold present.
    pub fn running(
        binding: ThreadBinding<R>,
        lifetime: ThreadLifetime,
    ) -> Result<Self, ThreadSuspendError> {
        Self::new(binding, lifetime, ThreadExecutionState::Running)
    }

    /// Construct only for a CREATE_SUSPENDED mechanism that has never entered userspace.
    ///
    /// # Safety
    /// The caller must retain the exact initially inactive TCB and prevent every other Resume or
    /// restart path until this owner acknowledges Start. A merely suspended former runner is not
    /// Dormant, and cannot be admitted here to bypass generation-checked hold release.
    pub unsafe fn dormant(
        binding: ThreadBinding<R>,
        lifetime: ThreadLifetime,
    ) -> Result<Self, ThreadSuspendError> {
        Self::new(binding, lifetime, ThreadExecutionState::Dormant)
    }

    fn new(
        binding: ThreadBinding<R>,
        lifetime: ThreadLifetime,
        state: ThreadExecutionState,
    ) -> Result<Self, ThreadSuspendError> {
        if !binding.process.is_valid()
            || binding.tcb <= 1
            || binding.tid != u64::from(lifetime.thread_id())
            || binding.process.pid != lifetime.process_id()
            || binding
                .reservations
                .is_some_and(|r| r.badge != binding.badge)
        {
            return Err(ThreadSuspendError::InvalidBinding);
        }
        Ok(Self {
            binding,
            lifetime,
            state,
            pending: None,
        })
    }

    pub fn execution_state(&self) -> ThreadExecutionState {
        self.state
    }
    pub fn phase(&self) -> ThreadSuspendPhase {
        self.pending
            .as_ref()
            .map_or(ThreadSuspendPhase::Idle, |p| p.phase)
    }
    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// No unresolved native attempt prevents retirement. A Held owner may only be discarded
    /// after actual TCB deletion has retired the hold; this is not permission to release it.
    pub fn can_retire(&self) -> bool {
        self.pending.is_none()
    }

    /// Reserve the real first start without fabricating a suspend count. Ordinary zero-count
    /// NtResumeThread remains a local no-op; only the constructor may request this Start action.
    pub fn prepare_initial_start(
        &mut self,
        pm: &mut ProcessManager,
        binding: ThreadBinding<R>,
        lifetime: ThreadLifetime,
    ) -> Result<ThreadSuspendPhase, ThreadSuspendError> {
        self.validate_owner(pm, binding, lifetime)?;
        if self.pending.is_some() {
            return Err(ThreadSuspendError::Busy);
        }
        if self.state != ThreadExecutionState::Dormant
            || pm
                .thread(lifetime.thread_id())
                .ok_or(ThreadSuspendError::OwnerChanged)?
                .suspend_count
                != 0
        {
            return Err(ThreadSuspendError::InconsistentState);
        }
        let plan = pm
            .prepare_thread_suspend_control(lifetime, ThreadSuspendOperation::Resume)
            .map_err(ThreadSuspendError::Process)?;
        self.pending = Some(Pending {
            plan,
            action: Some(ThreadSuspendAction::Start { tcb: binding.tcb }),
            phase: ThreadSuspendPhase::Prepared,
            acknowledged_state: None,
        });
        Ok(ThreadSuspendPhase::Prepared)
    }

    fn validate_owner(
        &self,
        pm: &ProcessManager,
        binding: ThreadBinding<R>,
        lifetime: ThreadLifetime,
    ) -> Result<(), ThreadSuspendError> {
        if self.binding != binding
            || self.lifetime != lifetime
            || !pm.validate_thread_lifetime(lifetime)
        {
            return Err(ThreadSuspendError::OwnerChanged);
        }
        Ok(())
    }

    /// Reserve PM count admission before native entry. Even local/nested changes remain retained
    /// until finish. Validate physical/count consistency before creating the reservation.
    pub fn prepare(
        &mut self,
        pm: &mut ProcessManager,
        binding: ThreadBinding<R>,
        lifetime: ThreadLifetime,
        operation: ThreadSuspendOperation,
    ) -> Result<ThreadSuspendPhase, ThreadSuspendError> {
        self.validate_owner(pm, binding, lifetime)?;
        if self.pending.is_some() {
            return Err(ThreadSuspendError::Busy);
        }
        let count = pm
            .thread(lifetime.thread_id())
            .ok_or(ThreadSuspendError::OwnerChanged)?
            .suspend_count;
        if !matches!(
            (self.state, count),
            (ThreadExecutionState::Running, 0)
                | (ThreadExecutionState::Dormant, _)
                | (ThreadExecutionState::Held { .. }, 1..)
        ) {
            return Err(ThreadSuspendError::InconsistentState);
        }
        let plan = pm
            .prepare_thread_suspend_control(lifetime, operation)
            .map_err(ThreadSuspendError::Process)?;
        let action = match plan.transition() {
            ThreadSuspendTransition::None => None,
            ThreadSuspendTransition::AcquireHold if self.state == ThreadExecutionState::Dormant => {
                None
            }
            ThreadSuspendTransition::AcquireHold => {
                Some(ThreadSuspendAction::Acquire { tcb: binding.tcb })
            }
            ThreadSuspendTransition::ReleaseHold => Some(match self.state {
                ThreadExecutionState::Held { generation } => ThreadSuspendAction::Release {
                    tcb: binding.tcb,
                    generation,
                },
                ThreadExecutionState::Dormant => ThreadSuspendAction::Start { tcb: binding.tcb },
                ThreadExecutionState::Running => unreachable!("count consistency preflight"),
            }),
        };
        let phase = if action.is_some() {
            ThreadSuspendPhase::Prepared
        } else {
            ThreadSuspendPhase::Local
        };
        self.pending = Some(Pending {
            plan,
            action,
            phase,
            acknowledged_state: None,
        });
        Ok(phase)
    }

    /// No manager, runtime-table or backend borrow is carried by the returned invocation.
    pub fn begin(&mut self) -> Result<ThreadSuspendInvocation<R>, ThreadSuspendError> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(ThreadSuspendError::WrongPhase)?;
        if pending.phase != ThreadSuspendPhase::Prepared {
            return Err(ThreadSuspendError::WrongPhase);
        }
        let action = pending.action.ok_or(ThreadSuspendError::WrongPhase)?;
        pending.phase = ThreadSuspendPhase::Invoking;
        Ok(ThreadSuspendInvocation {
            identity: pending.plan.identity(),
            binding: self.binding,
            lifetime: self.lifetime,
            action,
        })
    }

    /// Retain the exact receipt before any fallible PM commit. Rejected identity/phase returns the
    /// invocation intact. Malformed ACK is retained as indeterminate, never reclassified as failure.
    pub fn record(
        &mut self,
        invocation: ThreadSuspendInvocation<R>,
        outcome: ThreadSuspendOutcome,
    ) -> Result<ThreadSuspendPhase, (ThreadSuspendError, ThreadSuspendInvocation<R>)> {
        let Some(pending) = self.pending.as_mut() else {
            return Err((ThreadSuspendError::WrongPhase, invocation));
        };
        if pending.phase != ThreadSuspendPhase::Invoking {
            return Err((ThreadSuspendError::WrongPhase, invocation));
        }
        if invocation.identity != pending.plan.identity()
            || invocation.binding != self.binding
            || invocation.lifetime != self.lifetime
            || Some(invocation.action) != pending.action
        {
            return Err((ThreadSuspendError::WrongInvocation, invocation));
        }
        pending.phase = match outcome {
            ThreadSuspendOutcome::Acknowledged { generation } => {
                pending.acknowledged_state = match (invocation.action, generation) {
                    (ThreadSuspendAction::Acquire { .. }, Some(generation)) if generation != 0 => {
                        Some(ThreadExecutionState::Held { generation })
                    }
                    (
                        ThreadSuspendAction::Release { .. } | ThreadSuspendAction::Start { .. },
                        None,
                    ) => Some(ThreadExecutionState::Running),
                    _ => None,
                };
                if pending.acknowledged_state.is_some() {
                    ThreadSuspendPhase::Acknowledged
                } else {
                    ThreadSuspendPhase::Indeterminate(ThreadSuspendError::MalformedAcknowledgment)
                }
            }
            ThreadSuspendOutcome::Rejected { status } if status != 0 => {
                ThreadSuspendPhase::Rejected(status)
            }
            ThreadSuspendOutcome::Rejected { .. } => {
                ThreadSuspendPhase::Indeterminate(ThreadSuspendError::MalformedAcknowledgment)
            }
            ThreadSuspendOutcome::Indeterminate { status } => {
                ThreadSuspendPhase::Indeterminate(ThreadSuspendError::Indeterminate(status))
            }
        };
        Ok(pending.phase)
    }

    /// Finish locally, without IPC. Wrong manager/identity or a failed canonical validation leaves
    /// both plan and receipt retained. A retry of finish never repeats Acquire, Release or Start.
    pub fn finish(
        &mut self,
        pm: &mut ProcessManager,
        binding: ThreadBinding<R>,
        lifetime: ThreadLifetime,
    ) -> Result<ThreadSuspendCompletion, ThreadSuspendError> {
        self.validate_owner(pm, binding, lifetime)?;
        let pending = self
            .pending
            .as_ref()
            .ok_or(ThreadSuspendError::WrongPhase)?;
        let previous_count = pending.plan.previous_count();
        let completion = match pending.phase {
            ThreadSuspendPhase::Local | ThreadSuspendPhase::Acknowledged => {
                pm.commit_thread_suspend_control(&pending.plan)
                    .map_err(ThreadSuspendError::Process)?;
                ThreadSuspendCompletion {
                    previous_count,
                    count: pending.plan.next_count(),
                    rejection: None,
                }
            }
            ThreadSuspendPhase::Rejected(status) => {
                pm.cancel_thread_suspend_control(&pending.plan)
                    .map_err(ThreadSuspendError::Process)?;
                ThreadSuspendCompletion {
                    previous_count,
                    count: previous_count,
                    rejection: Some(status),
                }
            }
            ThreadSuspendPhase::Indeterminate(error) => return Err(error),
            _ => return Err(ThreadSuspendError::WrongPhase),
        };
        if let Some(state) = pending.acknowledged_state {
            self.state = state;
        }
        self.pending = None;
        Ok(completion)
    }
}

#[cfg(test)]
#[path = "thread_suspend_tests.rs"]
mod tests;
