//! Retained APC interruption of an exact object-wait row.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectWaitApcEffect {
    ReleaseReference { index: usize },
    ReferenceFollowup { index: usize },
    Stage,
    Send,
    RetireSentReply,
    RevokeReply,
    RetypeReply,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectWaitApcPhase {
    Ready {
        effect: ObjectWaitApcEffect,
        last_error: Option<u32>,
    },
    Invoking {
        effect: ObjectWaitApcEffect,
        attempt: u64,
    },
    Indeterminate {
        effect: ObjectWaitApcEffect,
        status: u32,
    },
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectWaitApcDisposition {
    UserApc,
    Teardown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectWaitApcOutcome {
    Completed(ObjectWaitApcEffect),
    /// The adapter proves this effect committed no ownership changes.
    NotEntered(u32),
    /// Partial, failed, or abandoned execution is not permission to replay an effect.
    Indeterminate(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectWaitApcError {
    WrongIdentity,
    InvalidPhase,
    WrongEffect,
    Exhausted,
}

#[derive(Debug)]
pub(super) struct Control {
    phase: ObjectWaitApcPhase,
    disposition: ObjectWaitApcDisposition,
    teardown_requested: bool,
    remaining_references: usize,
    next_attempt: u64,
}

impl Control {
    fn ready(&mut self, effect: ObjectWaitApcEffect) {
        self.phase = ObjectWaitApcPhase::Ready {
            effect,
            last_error: None,
        };
    }

    fn after_references(&self) -> ObjectWaitApcEffect {
        match self.disposition {
            ObjectWaitApcDisposition::UserApc => ObjectWaitApcEffect::Stage,
            ObjectWaitApcDisposition::Teardown => ObjectWaitApcEffect::RevokeReply,
        }
    }
}

#[derive(Debug)]
pub struct ObjectWaitApcView<'a, T> {
    pub payload: &'a T,
    pub phase: ObjectWaitApcPhase,
    pub disposition: ObjectWaitApcDisposition,
    pub teardown_requested: bool,
    pub remaining_references: usize,
}

/// One exact invocation receipt. Dropping an entered attempt leaves the row owned and invoking.
///
/// ```compile_fail
/// use nt_user_host::object_wait::ObjectWaitApcAttempt;
/// fn duplicate(attempt: ObjectWaitApcAttempt) { let _copy = attempt.clone(); }
/// ```
#[derive(Debug)]
pub struct ObjectWaitApcAttempt {
    identity: ObjectWaiterIdentity,
    effect: ObjectWaitApcEffect,
    attempt: u64,
    disposition: ObjectWaitApcDisposition,
    teardown_requested: bool,
    consumed: bool,
}

impl ObjectWaitApcAttempt {
    pub const fn identity(&self) -> ObjectWaiterIdentity {
        self.identity
    }
    pub const fn effect(&self) -> ObjectWaitApcEffect {
        self.effect
    }
    /// Entry snapshot; a reentrant teardown request is reflected in the row's current view.
    pub const fn disposition(&self) -> ObjectWaitApcDisposition {
        self.disposition
    }
    pub const fn teardown_requested(&self) -> bool {
        self.teardown_requested
    }
}

impl<T> ObjectWaiterTable<T> {
    /// Caller admission checks alertability, no selected wake, and the exact retained reference
    /// count before claiming. Native APC payload/context storage must also be reserved first.
    pub fn claim_apc(
        &mut self,
        identity: ObjectWaiterIdentity,
        reference_count: usize,
    ) -> Result<(), ObjectWaitApcError> {
        let entry = self
            .owned_exact(identity)
            .ok_or(ObjectWaitApcError::WrongIdentity)?;
        if entry.apc.is_some() {
            return Err(ObjectWaitApcError::InvalidPhase);
        }
        let effect = if reference_count == 0 {
            ObjectWaitApcEffect::Stage
        } else {
            ObjectWaitApcEffect::ReleaseReference {
                index: reference_count - 1,
            }
        };
        self.entries[identity.slot].as_mut().unwrap().apc = Some(Control {
            phase: ObjectWaitApcPhase::Ready {
                effect,
                last_error: None,
            },
            disposition: ObjectWaitApcDisposition::UserApc,
            teardown_requested: false,
            remaining_references: reference_count,
            next_attempt: 1,
        });
        Ok(())
    }

    pub fn is_claimed(&self, identity: ObjectWaiterIdentity) -> bool {
        self.owned_exact(identity)
            .is_some_and(|entry| entry.apc.is_some())
    }

    pub fn apc(
        &self,
        identity: ObjectWaiterIdentity,
    ) -> Result<ObjectWaitApcView<'_, T>, ObjectWaitApcError> {
        let entry = self
            .owned_exact(identity)
            .ok_or(ObjectWaitApcError::WrongIdentity)?;
        let control = entry.apc.as_ref().ok_or(ObjectWaitApcError::InvalidPhase)?;
        Ok(ObjectWaitApcView {
            payload: &entry.payload,
            phase: control.phase,
            disposition: control.disposition,
            teardown_requested: control.teardown_requested,
            remaining_references: control.remaining_references,
        })
    }

    /// APC context ownership pins the target until final removal or definite conversion to
    /// teardown. Captured reference and capability cleanup can outlive the target runtime;
    /// entered or uncertain Stage/Send remains UserApc until its exact outcome is known.
    pub fn has_runtime_dependency_matching(&self, mut matches: impl FnMut(&T) -> bool) -> bool {
        self.entries.iter().flatten().any(|entry| {
            entry
                .apc
                .as_ref()
                .is_some_and(|control| control.disposition == ObjectWaitApcDisposition::UserApc)
                && matches(&entry.payload)
        })
    }

    pub fn next_apc_after(&self, after: Option<usize>) -> Option<ObjectWaiterIdentity> {
        self.iter().find_map(|(identity, _)| {
            if after.is_some_and(|after| identity.slot <= after) {
                return None;
            }
            let phase = self.apc(identity).ok()?.phase;
            matches!(
                phase,
                ObjectWaitApcPhase::Ready { .. } | ObjectWaitApcPhase::Complete
            )
            .then_some(identity)
        })
    }

    pub fn begin_apc_step(
        &mut self,
        identity: ObjectWaiterIdentity,
    ) -> Result<ObjectWaitApcAttempt, ObjectWaitApcError> {
        let view = self.apc(identity)?;
        let ObjectWaitApcPhase::Ready { effect, .. } = view.phase else {
            return Err(ObjectWaitApcError::InvalidPhase);
        };
        let control = self.entries[identity.slot]
            .as_mut()
            .unwrap()
            .apc
            .as_mut()
            .unwrap();
        let attempt = control.next_attempt;
        control.next_attempt = attempt
            .checked_add(1)
            .ok_or(ObjectWaitApcError::Exhausted)?;
        control.phase = ObjectWaitApcPhase::Invoking { effect, attempt };
        Ok(ObjectWaitApcAttempt {
            identity,
            effect,
            attempt,
            disposition: control.disposition,
            teardown_requested: control.teardown_requested,
            consumed: false,
        })
    }

    pub fn request_teardown(
        &mut self,
        identity: ObjectWaiterIdentity,
    ) -> Result<(), ObjectWaitApcError> {
        self.apc(identity)?;
        let control = self.entries[identity.slot]
            .as_mut()
            .unwrap()
            .apc
            .as_mut()
            .unwrap();
        if control.teardown_requested {
            return Ok(());
        }
        control.teardown_requested = true;
        use ObjectWaitApcEffect as Effect;
        use ObjectWaitApcPhase as Phase;
        match control.phase {
            Phase::Ready {
                effect: Effect::Stage | Effect::Send,
                ..
            } => {
                control.disposition = ObjectWaitApcDisposition::Teardown;
                control.ready(Effect::RevokeReply);
            }
            Phase::Invoking {
                effect: Effect::Stage | Effect::Send,
                ..
            }
            | Phase::Indeterminate {
                effect: Effect::Stage | Effect::Send,
                ..
            } => {}
            _ => control.disposition = ObjectWaitApcDisposition::Teardown,
        }
        Ok(())
    }

    pub fn record_apc_step(
        &mut self,
        ticket: &mut ObjectWaitApcAttempt,
        outcome: ObjectWaitApcOutcome,
    ) -> Result<ObjectWaitApcPhase, ObjectWaitApcError> {
        let view = self.apc(ticket.identity)?;
        if ticket.consumed
            || view.phase
                != (ObjectWaitApcPhase::Invoking {
                    effect: ticket.effect,
                    attempt: ticket.attempt,
                })
        {
            return Err(ObjectWaitApcError::InvalidPhase);
        }
        if let ObjectWaitApcOutcome::Completed(effect) = outcome {
            if effect != ticket.effect {
                return Err(ObjectWaitApcError::WrongEffect);
            }
        }
        let control = self.entries[ticket.identity.slot]
            .as_mut()
            .unwrap()
            .apc
            .as_mut()
            .unwrap();
        use ObjectWaitApcEffect as Effect;
        use ObjectWaitApcOutcome as Outcome;
        use ObjectWaitApcPhase as Phase;
        match outcome {
            Outcome::Completed(effect) => match effect {
                Effect::ReleaseReference { index } => {
                    control.remaining_references = index;
                    control.ready(Effect::ReferenceFollowup { index });
                }
                Effect::ReferenceFollowup { index } => {
                    control.ready(if index == 0 {
                        control.after_references()
                    } else {
                        Effect::ReleaseReference { index: index - 1 }
                    });
                }
                Effect::Stage => {
                    if control.teardown_requested {
                        control.disposition = ObjectWaitApcDisposition::Teardown;
                        control.ready(Effect::RevokeReply);
                    } else {
                        control.ready(Effect::Send);
                    }
                }
                Effect::Send => {
                    if control.teardown_requested {
                        control.disposition = ObjectWaitApcDisposition::Teardown;
                    }
                    control.ready(Effect::RetireSentReply);
                }
                Effect::RevokeReply => control.ready(Effect::RetypeReply),
                Effect::RetireSentReply | Effect::RetypeReply => control.phase = Phase::Complete,
            },
            Outcome::NotEntered(status) => {
                if control.teardown_requested
                    && matches!(ticket.effect, Effect::Stage | Effect::Send)
                {
                    control.disposition = ObjectWaitApcDisposition::Teardown;
                    control.ready(Effect::RevokeReply);
                } else {
                    control.phase = Phase::Ready {
                        effect: ticket.effect,
                        last_error: Some(status),
                    };
                }
            }
            Outcome::Indeterminate(status) => {
                control.phase = Phase::Indeterminate {
                    effect: ticket.effect,
                    status,
                }
            }
        }
        ticket.consumed = true;
        Ok(control.phase)
    }

    /// The adapter retires its native APC metadata before this final, allocation-free removal.
    pub fn finish_apc(&mut self, identity: ObjectWaiterIdentity) -> Option<T> {
        if self.apc(identity).ok()?.phase != ObjectWaitApcPhase::Complete {
            return None;
        }
        self.take_owned(identity).map(|entry| entry.payload)
    }
}

#[cfg(test)]
mod tests;
