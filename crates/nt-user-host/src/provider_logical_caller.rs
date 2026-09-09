//! Logical caller provenance retained by a provider dispatch independently of its executor TCB.
use crate::process_identity::ProcessIdentity;
use crate::thread_binding::ThreadBinding;
use nt_process::ThreadLifetime;

/// Non-owning routing metadata, not token authority or a reference to the thread. Keep this exact
/// value through callbacks and parked waits; a newly captured value cannot validate an old job.
/// Provider initialization without a hosted caller must retain `None`, not invent a privileged
/// default. The provider's physical executor TCB is not this caller's TCB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderLogicalCaller {
    pi: usize,
    process: ProcessIdentity,
    thread: ThreadLifetime,
    badge: u64,
    tcb: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderCallerError {
    InvalidBinding,
    ThreadMismatch,
    MissingRuntime,
    MissingThread,
    BindingChanged,
    LifetimeChanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderWaitAdmission {
    Ready,
    Deferred,
}

impl ProviderLogicalCaller {
    /// The adapter must first admit the runtime using the authenticated ingress badge and current
    /// process authority. A caller-supplied binding or a pending/constructing row is not admission.
    /// `thread` must come from that adapter's canonical ProcessManager, not a foreign manager.
    /// Roles and reservation ownership remain the live-runtime admission policy's responsibility.
    pub fn capture<R>(
        admitted: ThreadBinding<R>,
        thread: ThreadLifetime,
    ) -> Result<Self, ProviderCallerError> {
        if admitted.tcb <= 1 || !admitted.process.is_valid() || admitted.tid == 0 {
            return Err(ProviderCallerError::InvalidBinding);
        }
        if admitted.tid != u64::from(thread.thread_id())
            || admitted.process.pid != thread.process_id()
        {
            return Err(ProviderCallerError::ThreadMismatch);
        }
        Ok(Self {
            pi: admitted.pi,
            process: admitted.process,
            thread,
            badge: admitted.badge,
            tcb: admitted.tcb,
        })
    }

    /// Revalidate against fresh, independently admitted metadata. Missing or failed admission is
    /// `None`; never substitute an ownership-visible pending row. This does not mutate the retained
    /// generation or select tokens. Resolve token references only after this check succeeds.
    pub fn validate<R>(
        &self,
        admitted: Option<ThreadBinding<R>>,
        thread: Option<ThreadLifetime>,
    ) -> Result<(), ProviderCallerError> {
        self.validate_identity(admitted, thread)
    }

    /// Classify an already retained wait without confusing blocked ingress with identity loss.
    /// `published` must exclude construction and retirement rows, but may include a published
    /// runtime with an unresolved control operation. `admitted` still requires ordinary ingress.
    /// Deferred preserves the waiter, selected event and Reply; it grants no provider execution.
    /// Actual PM/process termination must be checked independently by the adapter.
    pub fn retained_wait_admission<R: Copy>(
        &self,
        published: Option<ThreadBinding<R>>,
        admitted: Option<ThreadBinding<R>>,
        thread: Option<ThreadLifetime>,
    ) -> Result<ProviderWaitAdmission, ProviderCallerError> {
        self.validate_identity(published, thread)?;
        match admitted {
            Some(binding) => {
                self.validate_identity(Some(binding), thread)?;
                Ok(ProviderWaitAdmission::Ready)
            }
            None => Ok(ProviderWaitAdmission::Deferred),
        }
    }

    fn validate_identity<R>(
        &self,
        admitted: Option<ThreadBinding<R>>,
        thread: Option<ThreadLifetime>,
    ) -> Result<(), ProviderCallerError> {
        let admitted = admitted.ok_or(ProviderCallerError::MissingRuntime)?;
        let thread = thread.ok_or(ProviderCallerError::MissingThread)?;
        let current = Self::capture(admitted, thread)?;
        if self.pi != current.pi
            || self.process != current.process
            || self.thread.thread_id() != current.thread.thread_id()
            || self.badge != current.badge
            || self.tcb != current.tcb
        {
            return Err(ProviderCallerError::BindingChanged);
        }
        if self.thread != current.thread {
            return Err(ProviderCallerError::LifetimeChanged);
        }
        Ok(())
    }

    pub const fn pi(self) -> usize {
        self.pi
    }

    pub const fn process(self) -> ProcessIdentity {
        self.process
    }

    pub const fn thread(self) -> ThreadLifetime {
        self.thread
    }

    pub const fn badge(self) -> u64 {
        self.badge
    }

    pub const fn tcb(self) -> u64 {
        self.tcb
    }
}

#[cfg(test)]
#[path = "provider_logical_caller_tests.rs"]
mod tests;
