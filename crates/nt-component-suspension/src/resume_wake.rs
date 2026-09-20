//! Coalesced scheduling demand for original selected continuations.
//!
//! This owns a wake/retry deadline, not a continuation or physical execution authority. Native
//! adapters must scan canonical lanes, leave all state borrows, and claim each lane before IPC.

use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_PASS: AtomicU64 = AtomicU64::new(1);

/// A scheduling observation, never authority to execute a lane or consume a wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumeDemand {
    ExecutionBlocked,
    Empty,
    Pending,
}

impl ResumeDemand {
    /// A captured but unpublished wait can release its physical owner through publication.
    /// Otherwise physical exclusion makes a negative readiness observation inconclusive.
    /// Readiness is inspected lazily and must be memory-local, without provider execution.
    pub fn observe(
        execution_busy: bool,
        stopped_publication: bool,
        ready: impl FnOnce() -> bool,
    ) -> Self {
        if execution_busy && !stopped_publication {
            Self::ExecutionBlocked
        } else if stopped_publication || ready() {
            Self::Pending
        } else {
            Self::Empty
        }
    }

    pub const fn can_schedule(self) -> bool {
        !matches!(self, Self::ExecutionBlocked)
    }

    pub const fn retains_work(self) -> bool {
        !matches!(self, Self::Empty)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumeWakeError {
    InvalidIntervals,
    IdentityExhausted,
    WrongPass,
    DeadlineOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Idle,
    Pending { deadline: u64 },
    Running { identity: u64 },
}

/// Exact, non-clone pass ownership. Dropping it cannot acknowledge uncertain execution;
/// the wake owner stays Running and excludes another pass until this ticket is finished.
///
/// ```compile_fail
/// use nt_component_suspension::ResumeWakePass;
/// let forged = ResumeWakePass { identity: 1 };
/// ```
#[derive(Debug)]
#[must_use = "finish the exact wake pass after scanning retained work"]
pub struct ResumeWakePass {
    identity: u64,
}

#[derive(Debug)]
pub struct ResumeWake {
    state: State,
    minimum_delay: u64,
    maximum_delay: u64,
    retry_delay: u64,
}

impl ResumeWake {
    /// Intervals and clock samples use the same canonical monotonic clock units.
    /// A positive minimum guarantees a yield even after a pass makes progress but work remains.
    pub const fn new(minimum_delay: u64, maximum_delay: u64) -> Result<Self, ResumeWakeError> {
        if minimum_delay == 0 || maximum_delay < minimum_delay {
            return Err(ResumeWakeError::InvalidIntervals);
        }
        Ok(Self {
            state: State::Idle,
            minimum_delay,
            maximum_delay,
            retry_delay: minimum_delay,
        })
    }

    /// Refresh from canonical work, without treating a repeated scan as new scheduling demand.
    /// Do not pass false merely because physical execution is temporarily unavailable: suppress
    /// deadline programming instead, and reconcile/rearm after the execution token is released.
    /// During a pass only its exact finish may clear demand, using a fresh post-effect scan.
    pub fn reconcile(&mut self, has_work: bool, now: u64) {
        match (self.state, has_work) {
            (State::Idle, true) => self.state = State::Pending { deadline: now },
            (State::Pending { .. }, false) => {
                self.state = State::Idle;
                self.retry_delay = self.minimum_delay;
            }
            _ => {}
        }
    }

    /// Physical exclusion suppresses scheduling, not the original deadline or retry backoff.
    pub fn reconcile_demand(&mut self, demand: ResumeDemand, now: u64) {
        if demand.can_schedule() {
            self.reconcile(demand.retains_work(), now);
        }
    }

    /// Observing/programming a timer never acknowledges this demand. Failed programming must
    /// retain the deadline; a nested timer handler must not enter a scheduler pass.
    pub fn next_deadline(&self) -> Option<u64> {
        match self.state {
            State::Pending { deadline } => Some(deadline),
            State::Idle | State::Running { .. } => None,
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self.state, State::Running { .. })
    }

    /// Called only by the outer execution owner. Claiming the wake grants no authority over a
    /// frame, caller or physical lane; those still require their normal exact resume claim.
    pub fn begin_pass(&mut self, now: u64) -> Result<Option<ResumeWakePass>, ResumeWakeError> {
        self.begin_pass_with_counter(now, &NEXT_PASS)
    }

    fn begin_pass_with_counter(
        &mut self,
        now: u64,
        counter: &AtomicU64,
    ) -> Result<Option<ResumeWakePass>, ResumeWakeError> {
        if !matches!(self.state, State::Pending { deadline } if deadline <= now) {
            return Ok(None);
        }
        let identity = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                if next == 0 {
                    None
                } else {
                    next.checked_add(1)
                }
            })
            .map_err(|_| ResumeWakeError::IdentityExhausted)?;
        self.state = State::Running { identity };
        Ok(Some(ResumeWakePass { identity }))
    }

    /// Complete a bounded pass after all terminal/repark effects, with a fresh canonical scan.
    /// Productive passes yield for the minimum interval; refused/no-progress passes back off to
    /// the configured cap. Incoming scans cannot continually restart or shorten that backoff.
    /// Errors preserve both the active pass and its ticket, including deadline overflow.
    pub fn finish_pass(
        &mut self,
        pass: &mut ResumeWakePass,
        now: u64,
        has_work: bool,
        made_progress: bool,
    ) -> Result<(), ResumeWakeError> {
        if pass.identity == 0
            || self.state
                != (State::Running {
                    identity: pass.identity,
                })
        {
            return Err(ResumeWakeError::WrongPass);
        }
        let (state, retry_delay) = if has_work {
            let delay = if made_progress {
                self.minimum_delay
            } else {
                self.retry_delay
            };
            let deadline = now
                .checked_add(delay)
                .ok_or(ResumeWakeError::DeadlineOverflow)?;
            let next_retry = if made_progress {
                self.minimum_delay
            } else {
                delay.saturating_mul(2).min(self.maximum_delay)
            };
            (State::Pending { deadline }, next_retry)
        } else {
            (State::Idle, self.minimum_delay)
        };
        self.state = state;
        self.retry_delay = retry_delay;
        pass.identity = 0;
        Ok(())
    }
}

#[cfg(test)]
#[path = "resume_wake_tests.rs"]
mod tests;
