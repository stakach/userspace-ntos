//! Single-use first-pump observation retained by a canonical kernel activation recipient.
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

/// One claimed pump entry. Dropping it leaves the canonical progress Invoking.
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Progress {
    Ready,
    Invoking(u64),
    Observed(KernelProviderPumpDisposition),
}

/// Owned by the activation recipient; neither cloning nor dropping grants a second entry.
/// Authentication must precede begin_initial, and no coordinator borrow may cross the pump.
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
        self.begin_initial_with_counter(&NEXT_ATTEMPT)
    }

    fn begin_initial_with_counter(
        &mut self,
        counter: &AtomicU64,
    ) -> Result<KernelProviderPumpAttempt, PumpProgressError> {
        if self.progress != Progress::Ready {
            return Err(PumpProgressError::NotReady);
        }
        let nonce = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                if value == 0 {
                    None
                } else {
                    value.checked_add(1)
                }
            })
            .map_err(|_| PumpProgressError::IdentityExhausted)?;
        self.progress = Progress::Invoking(nonce);
        Ok(KernelProviderPumpAttempt {
            reply_cap: self.reply_cap,
            nonce,
            consumed: false,
        })
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
        self.progress = Progress::Observed(disposition);
        attempt.consumed = true;
        Ok(disposition)
    }

    pub const fn disposition(&self) -> Option<KernelProviderPumpDisposition> {
        match self.progress {
            Progress::Observed(disposition) => Some(disposition),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "provider_kernel_pump_tests.rs"]
mod tests;
