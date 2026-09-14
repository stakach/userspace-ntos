//! Single-use pump entries retained by a canonical kernel activation recipient.
//! This guard records execution progress, not scheduler or provider authority.

use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelProviderPumpFacts {
    pub reply_cap: u64,
    pub completed: bool,
    pub callback_suspended: bool,
    pub provider_wait_suspended: bool,
    pub lpc_wait_suspended: bool,
    pub scheduler_yielded: bool,
}

impl KernelProviderPumpFacts {
    /// Only this shape permits the native adapter to read the actual provider return bank.
    /// The generic pump status bank is not evidence of a DriverEntry return.
    pub const fn is_return(self, expected_cap: u64) -> bool {
        expected_cap != 0
            && self.reply_cap == expected_cap
            && self.completed
            && !self.callback_suspended
            && !self.provider_wait_suspended
            && !self.lpc_wait_suspended
            && !self.scheduler_yielded
    }

    fn classify(
        self,
        expected_cap: u64,
        returned_status: Option<u32>,
    ) -> KernelProviderPumpDisposition {
        use KernelProviderPumpDisposition::*;
        let outcomes = self.completed as u8
            + self.callback_suspended as u8
            + self.provider_wait_suspended as u8
            + self.lpc_wait_suspended as u8
            + self.scheduler_yielded as u8;
        if self.reply_cap != expected_cap || outcomes > 1 {
            return Invalid;
        }
        if self.completed {
            return returned_status.map_or(Invalid, Returned);
        }
        if returned_status.is_some() {
            return Invalid;
        }
        if self.callback_suspended {
            CallbackSuspended
        } else if self.provider_wait_suspended {
            ProviderWaitSuspended
        } else if self.lpc_wait_suspended {
            LpcWaitSuspended
        } else if self.scheduler_yielded {
            SchedulerYielded
        } else {
            Walled
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelProviderPumpDisposition {
    Returned(u32),
    CallbackSuspended,
    ProviderWaitSuspended,
    LpcWaitSuspended,
    SchedulerYielded,
    Walled,
    /// Malformed observation. Ownership remains retained; no automatic replay is permitted.
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PumpProgressError {
    InvalidReplyCap,
    NotReady,
    IdentityExhausted,
    WrongAttempt,
}

/// The exact suspended pump entry, not authority to resume its activation.
///
/// ```compile_fail
/// use nt_user_host::provider_kernel_pump::KernelProviderPumpObservation;
/// let forged = KernelProviderPumpObservation { reply_cap: 42, nonce: 1 };
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelProviderPumpObservation {
    reply_cap: u64,
    nonce: u64,
}

/// One pump entry ticket. Once committed, dropping it leaves canonical progress Invoking.
///
/// ```compile_fail
/// use nt_user_host::provider_kernel_pump::KernelProviderPumpAttempt;
/// fn duplicate(attempt: KernelProviderPumpAttempt) { let _ = attempt.clone(); }
/// ```
#[must_use = "observe the entered pump; dropping its ticket does not permit retry"]
#[derive(Debug)]
pub struct KernelProviderPumpAttempt {
    reply_cap: u64,
    nonce: u64,
    consumed: bool,
    resume_from: Option<KernelProviderPumpObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Progress {
    Ready,
    Invoking(u64),
    Observed {
        nonce: u64,
        disposition: KernelProviderPumpDisposition,
    },
}

/// Owned by the activation recipient; dropping a ticket never grants a replacement entry.
/// Authentication must precede each entry, and no coordinator borrow may cross the pump.
#[derive(Debug)]
pub struct KernelProviderPumpProgress {
    reply_cap: u64,
    progress: Progress,
}

impl KernelProviderPumpProgress {
    pub fn new(reply_cap: u64) -> Result<Self, PumpProgressError> {
        if reply_cap == 0 {
            return Err(PumpProgressError::InvalidReplyCap);
        }
        Ok(Self {
            reply_cap,
            progress: Progress::Ready,
        })
    }

    pub fn begin_initial(&mut self) -> Result<KernelProviderPumpAttempt, PumpProgressError> {
        self.begin_entry(Progress::Ready, &NEXT_ATTEMPT)
    }

    /// Claim receive continuation before native scheduler effects can perform nested IPC.
    /// Authenticate the same live activation/channel before claiming and again after scheduling,
    /// then receive without transmitting another request. Failure never reopens the claim.
    /// This is not a reply/resume operation for a callback, provider wait, LPC wait, or wall.
    pub fn begin_receive_after_yield(
        &mut self,
    ) -> Result<KernelProviderPumpAttempt, PumpProgressError> {
        if self.disposition() != Some(KernelProviderPumpDisposition::SchedulerYielded) {
            return Err(PumpProgressError::NotReady);
        }
        self.begin_entry(self.progress, &NEXT_ATTEMPT)
    }

    fn begin_entry(
        &mut self,
        expected: Progress,
        counter: &AtomicU64,
    ) -> Result<KernelProviderPumpAttempt, PumpProgressError> {
        if self.progress != expected {
            return Err(PumpProgressError::NotReady);
        }
        let attempt = self.allocate_attempt(counter, None)?;
        self.progress = Progress::Invoking(attempt.nonce);
        Ok(attempt)
    }

    fn allocate_attempt(
        &self,
        counter: &AtomicU64,
        resume_from: Option<KernelProviderPumpObservation>,
    ) -> Result<KernelProviderPumpAttempt, PumpProgressError> {
        let nonce = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                if value == 0 {
                    None
                } else {
                    value.checked_add(1)
                }
            })
            .map_err(|_| PumpProgressError::IdentityExhausted)?;
        Ok(KernelProviderPumpAttempt {
            reply_cap: self.reply_cap,
            nonce,
            consumed: false,
            resume_from,
        })
    }

    /// Reserve the next identity before the activation owner changes canonical wait lanes.
    /// Rejection by those lanes can drop this reservation without changing pump progress.
    pub(crate) fn prepare_provider_wait_resume(
        &self,
        observation: KernelProviderPumpObservation,
    ) -> Result<KernelProviderPumpAttempt, PumpProgressError> {
        self.prepare_provider_wait_resume_with_counter(observation, &NEXT_ATTEMPT)
    }

    fn prepare_provider_wait_resume_with_counter(
        &self,
        observation: KernelProviderPumpObservation,
        counter: &AtomicU64,
    ) -> Result<KernelProviderPumpAttempt, PumpProgressError> {
        if self.provider_wait_observation(observation.reply_cap) != Some(observation) {
            return Err(PumpProgressError::NotReady);
        }
        self.allocate_attempt(counter, Some(observation))
    }

    /// Called only after canonical lane admission, under the same exclusive progress borrow.
    pub(crate) fn commit_provider_wait_resume(
        &mut self,
        observation: KernelProviderPumpObservation,
        attempt: &KernelProviderPumpAttempt,
    ) {
        assert_eq!(
            self.provider_wait_observation(observation.reply_cap),
            Some(observation)
        );
        assert_eq!(attempt.resume_from, Some(observation));
        assert_eq!(attempt.reply_cap, self.reply_cap);
        assert!(!attempt.consumed);
        self.progress = Progress::Invoking(attempt.nonce);
    }

    /// Seal every exact entered observation, including malformed outcomes. A wrong ticket
    /// changes neither owner nor ticket. This API does not re-admit any stopped execution.
    pub fn observe(
        &mut self,
        attempt: &mut KernelProviderPumpAttempt,
        facts: KernelProviderPumpFacts,
        returned_status: Option<u32>,
    ) -> Result<KernelProviderPumpDisposition, PumpProgressError> {
        if attempt.consumed
            || attempt.reply_cap != self.reply_cap
            || self.progress != Progress::Invoking(attempt.nonce)
        {
            return Err(PumpProgressError::WrongAttempt);
        }
        let disposition = facts.classify(self.reply_cap, returned_status);
        self.progress = Progress::Observed {
            nonce: attempt.nonce,
            disposition,
        };
        attempt.consumed = true;
        Ok(disposition)
    }

    pub const fn disposition(&self) -> Option<KernelProviderPumpDisposition> {
        match self.progress {
            Progress::Observed { disposition, .. } => Some(disposition),
            _ => None,
        }
    }

    pub fn observed_provider_wait(&self, reply_cap: u64) -> bool {
        self.provider_wait_observation(reply_cap).is_some()
    }

    pub fn provider_wait_observation(
        &self,
        reply_cap: u64,
    ) -> Option<KernelProviderPumpObservation> {
        if reply_cap != self.reply_cap {
            return None;
        }
        match self.progress {
            Progress::Observed {
                nonce,
                disposition: KernelProviderPumpDisposition::ProviderWaitSuspended,
            } => Some(KernelProviderPumpObservation { reply_cap, nonce }),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "provider_kernel_pump_tests.rs"]
mod tests;
