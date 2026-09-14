//! Hosted reply delivery and sticky abandonment. Canonical ownership remains in the native
//! continuation frame; a copied snapshot must never become a second independently driven owner.

use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedReply<C: Copy> {
    Syscall { reply_cap: u64 },
    Callback { reply_cap: u64, context: C },
}

impl<C: Copy> HostedReply<C> {
    pub const fn reply_cap(self) -> u64 {
        match self {
            Self::Syscall { reply_cap } | Self::Callback { reply_cap, .. } => reply_cap,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementEffect {
    Delete,
    Retype,
    ReleasePool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementPhase {
    Ready {
        effect: RetirementEffect,
        last_error: Option<u32>,
    },
    Invoking {
        effect: RetirementEffect,
        attempt: u64,
    },
    Indeterminate {
        effect: RetirementEffect,
        status: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetirementView {
    pub reply_cap: u64,
    pub phase: RetirementPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementOutcome {
    Acknowledged,
    /// The adapter proves the entered operation had no effects, so it may be retried.
    NoEffects(u32),
    /// Effects are uncertain. Preserve the capability and forbid automatic replay.
    Indeterminate(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedReturnTargetError {
    InvalidReplyCap,
    NotRetiring,
    NotReady,
    IdentityExhausted,
    WrongAttempt,
}

/// One entered native mechanism. Dropping it leaves the canonical target Invoking.
///
/// ```compile_fail
/// use nt_user_host::hosted_return_target::RetirementAttempt;
/// fn duplicate(attempt: RetirementAttempt) { let _ = attempt.clone(); }
/// ```
#[must_use = "record the entered effect; dropping its ticket does not permit retry"]
#[derive(Debug)]
pub struct RetirementAttempt {
    reply_cap: u64,
    effect: RetirementEffect,
    nonce: u64,
    consumed: bool,
}

impl RetirementAttempt {
    pub const fn reply_cap(&self) -> u64 {
        self.reply_cap
    }
    pub const fn effect(&self) -> RetirementEffect {
        self.effect
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Target<C: Copy> {
    Live(HostedReply<C>),
    Retiring(RetirementView),
    Abandoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedReturnTarget<C: Copy> {
    target: Target<C>,
}

impl<C: Copy> HostedReturnTarget<C> {
    pub fn new(reply_cap: u64, context: Option<C>) -> Result<Self, HostedReturnTargetError> {
        if reply_cap == 0 {
            return Err(HostedReturnTargetError::InvalidReplyCap);
        }
        let reply = match context {
            Some(context) => HostedReply::Callback { reply_cap, context },
            None => HostedReply::Syscall { reply_cap },
        };
        Ok(Self {
            target: Target::Live(reply),
        })
    }

    pub const fn delivery(self) -> Option<HostedReply<C>> {
        match self.target {
            Target::Live(reply) => Some(reply),
            _ => None,
        }
    }

    pub const fn is_abandoned(self) -> bool {
        matches!(self.target, Target::Abandoned)
    }

    pub const fn can_resume(self) -> bool {
        matches!(self.target, Target::Live(_) | Target::Abandoned)
    }

    pub const fn retirement(self) -> Option<RetirementView> {
        match self.target {
            Target::Retiring(view) => Some(view),
            _ => None,
        }
    }

    pub fn request_abandonment(&mut self) {
        if let Target::Live(reply) = self.target {
            self.target = Target::Retiring(RetirementView {
                reply_cap: reply.reply_cap(),
                phase: RetirementPhase::Ready {
                    effect: RetirementEffect::Delete,
                    last_error: None,
                },
            });
        }
    }

    pub fn begin_retirement(&mut self) -> Result<RetirementAttempt, HostedReturnTargetError> {
        self.begin_retirement_with_counter(&NEXT_ATTEMPT)
    }

    fn begin_retirement_with_counter(
        &mut self,
        counter: &AtomicU64,
    ) -> Result<RetirementAttempt, HostedReturnTargetError> {
        let Target::Retiring(view) = self.target else {
            return Err(HostedReturnTargetError::NotRetiring);
        };
        let RetirementPhase::Ready { effect, .. } = view.phase else {
            return Err(HostedReturnTargetError::NotReady);
        };
        let nonce = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                if value == 0 {
                    None
                } else {
                    value.checked_add(1)
                }
            })
            .map_err(|_| HostedReturnTargetError::IdentityExhausted)?;
        self.target = Target::Retiring(RetirementView {
            reply_cap: view.reply_cap,
            phase: RetirementPhase::Invoking {
                effect,
                attempt: nonce,
            },
        });
        Ok(RetirementAttempt {
            reply_cap: view.reply_cap,
            effect,
            nonce,
            consumed: false,
        })
    }

    pub fn record_retirement(
        &mut self,
        attempt: &mut RetirementAttempt,
        outcome: RetirementOutcome,
    ) -> Result<(), HostedReturnTargetError> {
        let Target::Retiring(view) = self.target else {
            return Err(HostedReturnTargetError::WrongAttempt);
        };
        if attempt.consumed
            || view.reply_cap != attempt.reply_cap
            || view.phase
                != (RetirementPhase::Invoking {
                    effect: attempt.effect,
                    attempt: attempt.nonce,
                })
        {
            return Err(HostedReturnTargetError::WrongAttempt);
        }
        let phase = match outcome {
            RetirementOutcome::Acknowledged => match attempt.effect {
                RetirementEffect::Delete => Some(RetirementPhase::Ready {
                    effect: RetirementEffect::Retype,
                    last_error: None,
                }),
                RetirementEffect::Retype => Some(RetirementPhase::Ready {
                    effect: RetirementEffect::ReleasePool,
                    last_error: None,
                }),
                RetirementEffect::ReleasePool => None,
            },
            RetirementOutcome::NoEffects(status) => Some(RetirementPhase::Ready {
                effect: attempt.effect,
                last_error: Some(status),
            }),
            RetirementOutcome::Indeterminate(status) => Some(RetirementPhase::Indeterminate {
                effect: attempt.effect,
                status,
            }),
        };
        self.target = match phase {
            Some(phase) => Target::Retiring(RetirementView {
                reply_cap: view.reply_cap,
                phase,
            }),
            None => Target::Abandoned,
        };
        attempt.consumed = true;
        Ok(())
    }
}

#[cfg(test)]
#[path = "hosted_return_target_tests.rs"]
mod tests;
