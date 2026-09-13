//! Retained APC return from a current syscall, after its original dispatch tail finishes.
//!
//! Native captures the original caller and continuation in `P`, reserves a row and PM APC claim,
//! then transfers the bound main Reply and publishes before any callback-capable effect. This
//! protocol owns that Reply; native retains the exact PM claim until ReleaseClaim is acknowledged.

use crate::object_wait::{ObjectWaiterIdentity, ObjectWaiterTable};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentApcIdentity(ObjectWaiterIdentity);

impl CurrentApcIdentity {
    pub const fn slot(self) -> usize {
        self.0.slot()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentApcReservation(CurrentApcIdentity);

impl CurrentApcReservation {
    pub const fn identity(self) -> CurrentApcIdentity {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrentApcEffect {
    Stage,
    Send,
    RetireSentReply,
    RevokeReply,
    RetypeReply,
    ReleaseClaim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrentApcPhase {
    AwaitTail,
    Ready {
        effect: CurrentApcEffect,
        last_error: Option<u32>,
    },
    Invoking {
        effect: CurrentApcEffect,
        attempt: u64,
    },
    Indeterminate {
        effect: CurrentApcEffect,
        status: u32,
    },
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrentApcOutcome {
    Completed(CurrentApcEffect),
    NotEntered(u32),
    Indeterminate(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrentApcError {
    ReservationFailed,
    WrongIdentity,
    InvalidPhase,
    InvalidReply,
    WrongEffect,
    Exhausted,
}

#[derive(Clone, Copy, Debug)]
pub struct CurrentApcView<P> {
    pub payload: P,
    pub reply_cap: u64,
    pub phase: CurrentApcPhase,
    pub teardown_requested: bool,
}

#[derive(Clone, Copy, Debug)]
enum Slot<P> {
    Reserved,
    Published(CurrentApcView<P>),
}

/// Exact storage uses the common object-owner identity implementation, but these are current
/// syscall returns, not synthetic dispatcher waits or acquisition/reference owners.
#[derive(Debug)]
pub struct CurrentApcTable<P: Copy> {
    rows: ObjectWaiterTable<Slot<P>>,
    next_attempt: u64,
}

impl<P: Copy> Default for CurrentApcTable<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// Enter before invoking the effect. Dropped or indeterminate attempts never authorize replay.
///
/// ```compile_fail
/// use nt_user_host::current_apc::CurrentApcAttempt;
/// fn duplicate(attempt: CurrentApcAttempt<()>) { let _copy = attempt.clone(); }
/// ```
#[derive(Debug)]
pub struct CurrentApcAttempt<P: Copy> {
    identity: CurrentApcIdentity,
    effect: CurrentApcEffect,
    attempt: u64,
    view: CurrentApcView<P>,
    consumed: bool,
}

impl<P: Copy> CurrentApcAttempt<P> {
    pub const fn identity(&self) -> CurrentApcIdentity {
        self.identity
    }
    pub const fn effect(&self) -> CurrentApcEffect {
        self.effect
    }
    pub const fn payload(&self) -> P {
        self.view.payload
    }
    pub const fn reply_cap(&self) -> u64 {
        self.view.reply_cap
    }
    /// Entry snapshot. Reentrant teardown is reflected in the table's current view.
    pub const fn teardown_requested(&self) -> bool {
        self.view.teardown_requested
    }
}

impl<P: Copy> CurrentApcTable<P> {
    pub const fn new() -> Self {
        Self {
            rows: ObjectWaiterTable::new(),
            next_attempt: 1,
        }
    }

    /// Reserve storage and an exact owner identity before transferring a bound main Reply.
    /// Pre-publication reservations remain with the admitting caller, without execution authority.
    pub fn reserve(&mut self) -> Result<CurrentApcReservation, CurrentApcError> {
        self.rows
            .insert(Slot::Reserved)
            .map(|id| CurrentApcReservation(CurrentApcIdentity(id)))
            .map_err(|_| CurrentApcError::ReservationFailed)
    }

    pub fn publish(
        &mut self,
        reservation: CurrentApcReservation,
        payload: P,
        reply_cap: u64,
    ) -> Result<CurrentApcIdentity, CurrentApcError> {
        self.reserved(reservation)?;
        if reply_cap == 0
            || self.rows.iter().any(
                |(_, slot)| matches!(slot, Slot::Published(view) if view.reply_cap == reply_cap),
            )
        {
            return Err(CurrentApcError::InvalidReply);
        }
        let updated = self.rows.update_exact(reservation.0 .0, |slot| {
            *slot = Slot::Published(CurrentApcView {
                payload,
                reply_cap,
                phase: CurrentApcPhase::AwaitTail,
                teardown_requested: false,
            });
        });
        debug_assert!(updated);
        Ok(reservation.0)
    }

    fn reserved(&self, reservation: CurrentApcReservation) -> Result<(), CurrentApcError> {
        match self.rows.get_exact(reservation.0 .0) {
            Some(Slot::Reserved) => Ok(()),
            Some(Slot::Published(_)) => Err(CurrentApcError::InvalidPhase),
            None => Err(CurrentApcError::WrongIdentity),
        }
    }

    pub fn cancel_reserved(
        &mut self,
        reservation: CurrentApcReservation,
    ) -> Result<(), CurrentApcError> {
        self.reserved(reservation)?;
        let removed = self.rows.take(reservation.0 .0);
        debug_assert!(matches!(removed, Some(Slot::Reserved)));
        Ok(())
    }

    pub fn get(&self, identity: CurrentApcIdentity) -> Result<CurrentApcView<P>, CurrentApcError> {
        match self.rows.get_exact(identity.0) {
            Some(Slot::Published(view)) => Ok(*view),
            Some(Slot::Reserved) => Err(CurrentApcError::InvalidPhase),
            None => Err(CurrentApcError::WrongIdentity),
        }
    }

    fn update(
        &mut self,
        identity: CurrentApcIdentity,
        update: impl FnOnce(&mut CurrentApcView<P>),
    ) {
        let updated = self.rows.update_exact(identity.0, |slot| {
            let Slot::Published(view) = slot else {
                unreachable!();
            };
            update(view);
        });
        debug_assert!(updated);
    }

    fn ready(effect: CurrentApcEffect) -> CurrentApcPhase {
        CurrentApcPhase::Ready {
            effect,
            last_error: None,
        }
    }

    /// Only the original syscall's tail may release this gate, after its remaining side effects
    /// and cleanup. Teardown intent while AwaitTail does not make that active context disposable.
    pub fn release_tail(&mut self, identity: CurrentApcIdentity) -> Result<(), CurrentApcError> {
        if self.get(identity)?.phase != CurrentApcPhase::AwaitTail {
            return Err(CurrentApcError::InvalidPhase);
        }
        self.update(identity, |view| {
            view.phase = Self::ready(if view.teardown_requested {
                CurrentApcEffect::RevokeReply
            } else {
                CurrentApcEffect::Stage
            });
        });
        Ok(())
    }

    pub fn begin_step(
        &mut self,
        identity: CurrentApcIdentity,
    ) -> Result<CurrentApcAttempt<P>, CurrentApcError> {
        let view = self.get(identity)?;
        let CurrentApcPhase::Ready { effect, .. } = view.phase else {
            return Err(CurrentApcError::InvalidPhase);
        };
        let attempt = self.next_attempt;
        if attempt == 0 {
            return Err(CurrentApcError::Exhausted);
        }
        self.next_attempt = attempt.checked_add(1).unwrap_or(0);
        self.update(identity, |view| {
            view.phase = CurrentApcPhase::Invoking { effect, attempt }
        });
        Ok(CurrentApcAttempt {
            identity,
            effect,
            attempt,
            view,
            consumed: false,
        })
    }

    pub fn record_step(
        &mut self,
        ticket: &mut CurrentApcAttempt<P>,
        outcome: CurrentApcOutcome,
    ) -> Result<CurrentApcPhase, CurrentApcError> {
        let view = self.get(ticket.identity)?;
        if ticket.consumed
            || view.phase
                != (CurrentApcPhase::Invoking {
                    effect: ticket.effect,
                    attempt: ticket.attempt,
                })
        {
            return Err(CurrentApcError::InvalidPhase);
        }
        if let CurrentApcOutcome::Completed(effect) = outcome {
            if effect != ticket.effect {
                return Err(CurrentApcError::WrongEffect);
            }
        }
        self.update(ticket.identity, |view| {
            view.phase = match outcome {
                CurrentApcOutcome::NotEntered(status) => CurrentApcPhase::Ready {
                    effect: ticket.effect,
                    last_error: Some(status),
                },
                CurrentApcOutcome::Indeterminate(status) => CurrentApcPhase::Indeterminate {
                    effect: ticket.effect,
                    status,
                },
                CurrentApcOutcome::Completed(effect) => match effect {
                    CurrentApcEffect::Stage => Self::ready(CurrentApcEffect::Send),
                    CurrentApcEffect::Send => Self::ready(CurrentApcEffect::RetireSentReply),
                    CurrentApcEffect::RevokeReply => Self::ready(CurrentApcEffect::RetypeReply),
                    CurrentApcEffect::RetireSentReply | CurrentApcEffect::RetypeReply => {
                        view.reply_cap = 0;
                        Self::ready(CurrentApcEffect::ReleaseClaim)
                    }
                    CurrentApcEffect::ReleaseClaim => CurrentApcPhase::Complete,
                },
            };
            if view.teardown_requested {
                Self::apply_teardown(view);
            }
        });
        ticket.consumed = true;
        Ok(self.get(ticket.identity)?.phase)
    }

    pub fn request_teardown(
        &mut self,
        identity: CurrentApcIdentity,
    ) -> Result<(), CurrentApcError> {
        self.get(identity)?;
        self.update(identity, |view| {
            view.teardown_requested = true;
            Self::apply_teardown(view);
        });
        Ok(())
    }

    fn apply_teardown(view: &mut CurrentApcView<P>) {
        if matches!(
            view.phase,
            CurrentApcPhase::Ready {
                effect: CurrentApcEffect::Stage | CurrentApcEffect::Send,
                ..
            }
        ) {
            view.phase = Self::ready(CurrentApcEffect::RevokeReply);
        }
    }

    pub fn finish(&mut self, identity: CurrentApcIdentity) -> Option<P> {
        if self.get(identity).ok()?.phase != CurrentApcPhase::Complete {
            return None;
        }
        match self.rows.take(identity.0)? {
            Slot::Published(view) => Some(view.payload),
            Slot::Reserved => unreachable!(),
        }
    }

    pub fn has_owned_matching(&self, mut matches: impl FnMut(&P) -> bool) -> bool {
        self.rows.iter().any(|(_, slot)| match slot {
            Slot::Published(view) => matches(&view.payload),
            Slot::Reserved => false,
        })
    }

    pub fn has_runtime_dependency_matching(&self, mut matches: impl FnMut(&P) -> bool) -> bool {
        self.rows.iter().any(|(_, slot)| {
            let Slot::Published(view) = slot else {
                return false;
            };
            (!view.teardown_requested
                || matches!(
                    view.phase,
                    CurrentApcPhase::AwaitTail
                        | CurrentApcPhase::Invoking {
                            effect: CurrentApcEffect::Stage | CurrentApcEffect::Send,
                            ..
                        }
                        | CurrentApcPhase::Indeterminate {
                            effect: CurrentApcEffect::Stage | CurrentApcEffect::Send,
                            ..
                        }
                ))
                && matches(&view.payload)
        })
    }

    pub fn next_ready_after(&self, cursor: Option<usize>) -> Option<CurrentApcIdentity> {
        self.rows.iter().find_map(|(id, slot)| {
            let Slot::Published(view) = slot else {
                return None;
            };
            (cursor.is_none_or(|cursor| id.slot() > cursor)
                && matches!(
                    view.phase,
                    CurrentApcPhase::Ready { .. } | CurrentApcPhase::Complete
                ))
            .then_some(CurrentApcIdentity(id))
        })
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    pub fn capacity(&self) -> usize {
        self.rows.capacity()
    }
    pub fn reset(&mut self) -> bool {
        self.rows.reset(0)
    }
}

#[cfg(test)]
#[path = "current_apc_tests.rs"]
mod tests;
