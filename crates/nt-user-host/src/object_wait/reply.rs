//! Retained ordinary completion and teardown of an exact object-wait row.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectWaitReplyEffect {
    ReleaseReference { index: usize },
    ReferenceFollowup { index: usize },
    Send,
    RetireSentReply,
    RevokeReply,
    RetypeReply,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectWaitReplyPhase {
    Ready {
        effect: ObjectWaitReplyEffect,
        last_error: Option<u32>,
    },
    Invoking {
        effect: ObjectWaitReplyEffect,
        attempt: u64,
    },
    Indeterminate {
        effect: ObjectWaitReplyEffect,
        status: u32,
    },
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectWaitReplyDisposition {
    Reply,
    Teardown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectWaitReplyOutcome {
    Completed(ObjectWaitReplyEffect),
    /// The adapter proves this effect committed no ownership changes.
    NotEntered(u32),
    /// Uncertain execution is not permission to retry or discard an effect.
    Indeterminate(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectWaitReplyError {
    WrongIdentity,
    InvalidPhase,
    WrongEffect,
    Exhausted,
}

#[derive(Debug)]
pub(super) struct Control {
    phase: ObjectWaitReplyPhase,
    disposition: ObjectWaitReplyDisposition,
    status: u64,
    teardown_requested: bool,
    remaining_references: usize,
    next_attempt: u64,
}

impl Control {
    fn ready(&mut self, effect: ObjectWaitReplyEffect) {
        self.phase = ObjectWaitReplyPhase::Ready {
            effect,
            last_error: None,
        };
    }

    fn after_references(&self) -> ObjectWaitReplyEffect {
        match self.disposition {
            ObjectWaitReplyDisposition::Reply => ObjectWaitReplyEffect::Send,
            ObjectWaitReplyDisposition::Teardown => ObjectWaitReplyEffect::RevokeReply,
        }
    }
}

#[derive(Debug)]
pub struct ObjectWaitReplyView<'a, T> {
    pub payload: &'a T,
    pub phase: ObjectWaitReplyPhase,
    pub disposition: ObjectWaitReplyDisposition,
    pub status: u64,
    pub teardown_requested: bool,
    pub remaining_references: usize,
}

/// One exact invocation receipt. A dropped attempt leaves its row owned and invoking.
///
/// ```compile_fail
/// use nt_user_host::object_wait::ObjectWaitReplyAttempt;
/// fn duplicate(attempt: ObjectWaitReplyAttempt) { let _copy = attempt.clone(); }
/// ```
#[derive(Debug)]
pub struct ObjectWaitReplyAttempt {
    identity: ObjectWaiterIdentity,
    effect: ObjectWaitReplyEffect,
    attempt: u64,
    disposition: ObjectWaitReplyDisposition,
    status: u64,
    teardown_requested: bool,
    consumed: bool,
}

impl ObjectWaitReplyAttempt {
    pub const fn identity(&self) -> ObjectWaiterIdentity {
        self.identity
    }
    pub const fn effect(&self) -> ObjectWaitReplyEffect {
        self.effect
    }
    /// Entry snapshot; reentrant teardown intent is visible in the current row view.
    pub const fn disposition(&self) -> ObjectWaitReplyDisposition {
        self.disposition
    }
    pub const fn status(&self) -> u64 {
        self.status
    }
    pub const fn teardown_requested(&self) -> bool {
        self.teardown_requested
    }
}

impl<T> ObjectWaiterTable<T> {
    /// Claim an already selected wake and its exact retained references without allocating.
    /// Selection status remains immutable through all retries and teardown. Ordinary payload
    /// mutation is disabled; exact entered attempts may publish native side-effect receipts.
    pub fn claim_reply(
        &mut self,
        identity: ObjectWaiterIdentity,
        reference_count: usize,
        status: u64,
    ) -> Result<(), ObjectWaitReplyError> {
        self.claim_reply_with_disposition(
            identity,
            reference_count,
            status,
            ObjectWaitReplyDisposition::Reply,
        )
    }

    /// Claim teardown before any wake was selected. The unused status is zero; no Send occurs.
    pub fn claim_reply_teardown(
        &mut self,
        identity: ObjectWaiterIdentity,
        reference_count: usize,
    ) -> Result<(), ObjectWaitReplyError> {
        self.claim_reply_with_disposition(
            identity,
            reference_count,
            0,
            ObjectWaitReplyDisposition::Teardown,
        )
    }

    fn claim_reply_with_disposition(
        &mut self,
        identity: ObjectWaiterIdentity,
        reference_count: usize,
        status: u64,
        disposition: ObjectWaitReplyDisposition,
    ) -> Result<(), ObjectWaitReplyError> {
        let entry = self
            .owned_exact(identity)
            .ok_or(ObjectWaitReplyError::WrongIdentity)?;
        if entry.apc.is_some() || entry.reply.is_some() {
            return Err(ObjectWaitReplyError::InvalidPhase);
        }
        let mut control = Control {
            phase: ObjectWaitReplyPhase::Complete,
            disposition,
            status,
            teardown_requested: disposition == ObjectWaitReplyDisposition::Teardown,
            remaining_references: reference_count,
            next_attempt: 1,
        };
        control.ready(if reference_count == 0 {
            control.after_references()
        } else {
            ObjectWaitReplyEffect::ReleaseReference {
                index: reference_count - 1,
            }
        });
        self.entries[identity.slot].as_mut().unwrap().reply = Some(control);
        Ok(())
    }

    pub fn reply(
        &self,
        identity: ObjectWaiterIdentity,
    ) -> Result<ObjectWaitReplyView<'_, T>, ObjectWaitReplyError> {
        let entry = self
            .owned_exact(identity)
            .ok_or(ObjectWaitReplyError::WrongIdentity)?;
        let control = entry
            .reply
            .as_ref()
            .ok_or(ObjectWaitReplyError::InvalidPhase)?;
        Ok(ObjectWaitReplyView {
            payload: &entry.payload,
            phase: control.phase,
            disposition: control.disposition,
            status: control.status,
            teardown_requested: control.teardown_requested,
            remaining_references: control.remaining_references,
        })
    }

    /// Teardown cleanup can outlive the runtime. An entered or uncertain Send still pins its
    /// original target until an exact definite result permits conversion to teardown.
    pub fn has_reply_runtime_dependency_matching(
        &self,
        mut matches: impl FnMut(&T) -> bool,
    ) -> bool {
        self.entries.iter().flatten().any(|entry| {
            entry
                .reply
                .as_ref()
                .is_some_and(|control| control.disposition == ObjectWaitReplyDisposition::Reply)
                && matches(&entry.payload)
        })
    }

    pub fn next_reply_after(&self, after: Option<usize>) -> Option<ObjectWaiterIdentity> {
        self.iter().find_map(|(identity, _)| {
            if after.is_some_and(|after| identity.slot <= after) {
                return None;
            }
            let phase = self.reply(identity).ok()?.phase;
            matches!(
                phase,
                ObjectWaitReplyPhase::Ready { .. } | ObjectWaitReplyPhase::Complete
            )
            .then_some(identity)
        })
    }

    pub fn begin_reply_step(
        &mut self,
        identity: ObjectWaiterIdentity,
    ) -> Result<ObjectWaitReplyAttempt, ObjectWaitReplyError> {
        let view = self.reply(identity)?;
        let ObjectWaitReplyPhase::Ready { effect, .. } = view.phase else {
            return Err(ObjectWaitReplyError::InvalidPhase);
        };
        let control = self.entries[identity.slot]
            .as_mut()
            .unwrap()
            .reply
            .as_mut()
            .unwrap();
        let attempt = control.next_attempt;
        control.next_attempt = attempt
            .checked_add(1)
            .ok_or(ObjectWaitReplyError::Exhausted)?;
        control.phase = ObjectWaitReplyPhase::Invoking { effect, attempt };
        Ok(ObjectWaitReplyAttempt {
            identity,
            effect,
            attempt,
            disposition: control.disposition,
            status: control.status,
            teardown_requested: control.teardown_requested,
            consumed: false,
        })
    }

    pub fn request_reply_teardown(
        &mut self,
        identity: ObjectWaiterIdentity,
    ) -> Result<(), ObjectWaitReplyError> {
        self.reply(identity)?;
        let control = self.entries[identity.slot]
            .as_mut()
            .unwrap()
            .reply
            .as_mut()
            .unwrap();
        if control.teardown_requested {
            return Ok(());
        }
        control.teardown_requested = true;
        use ObjectWaitReplyEffect as Effect;
        use ObjectWaitReplyPhase as Phase;
        match control.phase {
            Phase::Ready {
                effect: Effect::Send,
                ..
            } => {
                control.disposition = ObjectWaitReplyDisposition::Teardown;
                control.ready(Effect::RevokeReply);
            }
            Phase::Invoking {
                effect: Effect::Send,
                ..
            }
            | Phase::Indeterminate {
                effect: Effect::Send,
                ..
            } => {}
            _ => control.disposition = ObjectWaitReplyDisposition::Teardown,
        }
        Ok(())
    }

    pub fn record_reply_step(
        &mut self,
        ticket: &mut ObjectWaitReplyAttempt,
        outcome: ObjectWaitReplyOutcome,
    ) -> Result<ObjectWaitReplyPhase, ObjectWaitReplyError> {
        let view = self.reply(ticket.identity)?;
        if ticket.consumed
            || view.phase
                != (ObjectWaitReplyPhase::Invoking {
                    effect: ticket.effect,
                    attempt: ticket.attempt,
                })
        {
            return Err(ObjectWaitReplyError::InvalidPhase);
        }
        if let ObjectWaitReplyOutcome::Completed(effect) = outcome {
            if effect != ticket.effect {
                return Err(ObjectWaitReplyError::WrongEffect);
            }
        }
        let control = self.entries[ticket.identity.slot]
            .as_mut()
            .unwrap()
            .reply
            .as_mut()
            .unwrap();
        use ObjectWaitReplyEffect as Effect;
        use ObjectWaitReplyOutcome as Outcome;
        use ObjectWaitReplyPhase as Phase;
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
                Effect::Send => {
                    if control.teardown_requested {
                        control.disposition = ObjectWaitReplyDisposition::Teardown;
                    }
                    control.ready(Effect::RetireSentReply);
                }
                Effect::RevokeReply => control.ready(Effect::RetypeReply),
                Effect::RetireSentReply | Effect::RetypeReply => control.phase = Phase::Complete,
            },
            Outcome::NotEntered(status) => {
                if control.teardown_requested && ticket.effect == Effect::Send {
                    control.disposition = ObjectWaitReplyDisposition::Teardown;
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
                };
            }
        }
        ticket.consumed = true;
        Ok(control.phase)
    }

    /// Publish a native side-effect receipt for this exact entered attempt. The closure must
    /// preserve original caller/selection metadata and cannot retain a borrow across callouts.
    pub fn update_reply_payload(
        &mut self,
        ticket: &ObjectWaitReplyAttempt,
        update: impl FnOnce(&mut T),
    ) -> Result<(), ObjectWaitReplyError> {
        let view = self.reply(ticket.identity)?;
        if ticket.consumed
            || view.phase
                != (ObjectWaitReplyPhase::Invoking {
                    effect: ticket.effect,
                    attempt: ticket.attempt,
                })
        {
            return Err(ObjectWaitReplyError::InvalidPhase);
        }
        update(&mut self.entries[ticket.identity.slot].as_mut().unwrap().payload);
        Ok(())
    }

    /// Remove only after all exact reference and Reply-capability receipts are settled.
    pub fn finish_reply(&mut self, identity: ObjectWaiterIdentity) -> Option<T> {
        if self.reply(identity).ok()?.phase != ObjectWaitReplyPhase::Complete {
            return None;
        }
        self.take_owned(identity).map(|entry| entry.payload)
    }
}

#[cfg(test)]
mod tests;
