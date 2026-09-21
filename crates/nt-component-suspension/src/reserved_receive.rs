//! Reserve bounded retained-Call storage before claiming an ingress receive.

use core::convert::Infallible;

mod external;

use crate::peer_registry::PeerRegistry;
use crate::{
    ComponentIngress, ComponentSuspensionLanes, IngressError, IngressExecutionOwner,
    IngressReceiveAttempt, IngressReceiveDisposition, ReplyBindingObservation,
    RetainedIngressError, RetainedWork, RetainedWorkError, RetainedWorkReservation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservedReceivePhase {
    Receiving,
    Captured,
    Held,
    Finished,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservedReceiveError<E> {
    InvalidPhase,
    WrongIngress,
    Store(RetainedWorkError),
    Ingress(IngressError),
    Retain(RetainedIngressError<E>),
}

/// Owns the exact receive attempt and its storage reservation. Dropping it does not release
/// capacity or authorize another receive. Native adapters must capture the complete message
/// before query IPC and independently establish Call/NoCall provenance and physical lifetimes.
///
/// ```compile_fail
/// use nt_component_suspension::ReservedIngressReceive;
/// fn duplicate(ticket: ReservedIngressReceive) { let _ = ticket.clone(); }
/// ```
#[must_use = "resolve and retain this receive without losing its reserved storage"]
pub struct ReservedIngressReceive {
    reservation: Option<RetainedWorkReservation>,
    attempt: IngressReceiveAttempt,
    receive_identity: u64,
    execution_owner: IngressExecutionOwner,
    endpoint: u64,
    reply: u64,
    phase: ReservedReceivePhase,
}

impl<M> RetainedWork<M> {
    /// Reservation failure never starts a receive. A failed canonical receive claim has no
    /// native effects and rolls back only the newly acquired storage reservation.
    pub fn begin_receive<C, R, T>(
        &mut self,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        ingress: &mut ComponentIngress<M>,
    ) -> Result<ReservedIngressReceive, ReservedReceiveError<Infallible>> {
        self.begin_receive_for_owner(lanes, ingress, IngressExecutionOwner::Idle)
    }

    pub fn begin_receive_for_owner<C, R, T>(
        &mut self,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        ingress: &mut ComponentIngress<M>,
        owner: IngressExecutionOwner,
    ) -> Result<ReservedIngressReceive, ReservedReceiveError<Infallible>> {
        if ingress.endpoint() != self.endpoint() {
            return Err(ReservedReceiveError::WrongIngress);
        }
        let mut reservation = self
            .reserve(ingress.reply())
            .map_err(ReservedReceiveError::Store)?;
        let attempt = match lanes.begin_ingress_receive_for_owner(ingress, owner) {
            Ok(attempt) => attempt,
            Err(error) => {
                self.release_reservation(&mut reservation)
                    .expect("owned unused receive reservation");
                return Err(ReservedReceiveError::Ingress(error));
            }
        };
        Ok(ReservedIngressReceive {
            reservation: Some(reservation),
            receive_identity: attempt.identity(),
            execution_owner: owner,
            attempt,
            endpoint: ingress.endpoint(),
            reply: ingress.reply(),
            phase: ReservedReceivePhase::Receiving,
        })
    }
}

impl ReservedIngressReceive {
    pub const fn phase(&self) -> ReservedReceivePhase {
        self.phase
    }

    fn validate<M, E>(
        &self,
        store: &RetainedWork<M>,
        ingress: &ComponentIngress<M>,
    ) -> Result<(), ReservedReceiveError<E>> {
        if store.endpoint() != self.endpoint
            || ingress.endpoint() != self.endpoint
            || ingress.reply() != self.reply
        {
            return Err(ReservedReceiveError::WrongIngress);
        }
        if !self
            .reservation
            .as_ref()
            .is_some_and(|reservation| store.owns_reservation(reservation))
        {
            return Err(ReservedReceiveError::Store(RetainedWorkError::WrongOwner));
        }
        if self.phase == ReservedReceivePhase::Held
            && !ingress.held_receive_matches(self.receive_identity)
        {
            return Err(ReservedReceiveError::Ingress(IngressError::WrongAttempt));
        }
        Ok(())
    }

    pub fn capture<M>(
        &mut self,
        store: &RetainedWork<M>,
        ingress: &mut ComponentIngress<M>,
        message: M,
    ) -> Result<(), (ReservedReceiveError<Infallible>, M)> {
        if self.phase != ReservedReceivePhase::Receiving {
            return Err((ReservedReceiveError::InvalidPhase, message));
        }
        if let Err(error) = self.validate(store, ingress) {
            return Err((error, message));
        }
        ingress
            .capture_receive(&mut self.attempt, message)
            .map_err(|(error, message)| (ReservedReceiveError::Ingress(error), message))?;
        self.phase = ReservedReceivePhase::Captured;
        Ok(())
    }

    pub fn resolve<M>(
        &mut self,
        store: &mut RetainedWork<M>,
        ingress: &mut ComponentIngress<M>,
        disposition: IngressReceiveDisposition,
    ) -> Result<Option<M>, ReservedReceiveError<Infallible>> {
        if self.phase != ReservedReceivePhase::Captured {
            return Err(ReservedReceiveError::InvalidPhase);
        }
        self.validate(store, ingress)?;
        let message = ingress
            .resolve_receive(&mut self.attempt, disposition)
            .map_err(ReservedReceiveError::Ingress)?;
        match disposition {
            IngressReceiveDisposition::Call => self.phase = ReservedReceivePhase::Held,
            IngressReceiveDisposition::NoCall => {
                let mut reservation = self
                    .reservation
                    .take()
                    .expect("validated receive reservation");
                store
                    .release_reservation(&mut reservation)
                    .expect("validated NoCall reservation");
                self.phase = ReservedReceivePhase::Finished;
            }
        }
        Ok(message)
    }

    /// Authenticate and hand off the held Call, committing it into its already reserved slot.
    /// The adapter must prove replacement Free and exclude aliases in every other domain/store
    /// or native owner; this checks canonical lanes and this store, not global capability state.
    /// Query callbacks must only observe and cannot reenter or mutate ownership. Every refusal
    /// preserves this ticket and original ingress, returning the untouched replacement.
    pub fn retain<M, C, R, T, E>(
        &mut self,
        store: &mut RetainedWork<M>,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        ingress: &mut ComponentIngress<M>,
        replacement: ComponentIngress<M>,
        peers: &mut PeerRegistry,
        badge: u64,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(), (ReservedReceiveError<E>, ComponentIngress<M>)> {
        if self.phase != ReservedReceivePhase::Held {
            return Err((ReservedReceiveError::InvalidPhase, replacement));
        }
        if let Err(error) = self.validate(store, ingress) {
            return Err((error, replacement));
        }
        if store.excludes_reply(replacement.reply()) {
            return Err((
                ReservedReceiveError::Store(RetainedWorkError::ReplyInUse),
                replacement,
            ));
        }
        let call = lanes
            .retain_peer_ingress_for_owner(
                ingress,
                replacement,
                peers,
                badge,
                query,
                self.execution_owner,
            )
            .map_err(|(error, replacement)| (ReservedReceiveError::Retain(error), replacement))?;
        let reservation = self
            .reservation
            .take()
            .expect("validated retained Call reservation");
        if store.commit(reservation, call).is_err() {
            panic!("validated retained Call commit cannot fail without intervening effects");
        }
        self.phase = ReservedReceivePhase::Finished;
        Ok(())
    }
}

#[cfg(test)]
#[path = "reserved_receive_tests.rs"]
mod tests;
