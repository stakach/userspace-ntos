//! Bounded storage for retained Calls, reserved before native receive or Reply handoff.

use alloc::vec::Vec;
use core::convert::Infallible;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::peer_registry::{PeerRegistry, PeerRoute};
use crate::{ComponentIngress, RetainedIngress, RetainedIngressError};

static NEXT_RESERVATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedWorkError {
    InvalidConfiguration,
    NoCapacity,
    IdentityExhausted,
    WrongOwner,
    WrongEndpoint,
    ReplyInUse,
    InvalidReply,
    NotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedWorkFinishError {
    Store(RetainedWorkError),
    Call(RetainedIngressError<Infallible>),
}

/// Dropping a reservation does not release capacity while a native receive may be in flight.
///
/// ```compile_fail
/// use nt_component_suspension::RetainedWorkReservation;
/// fn duplicate(ticket: RetainedWorkReservation) { let _ = ticket.clone(); }
/// ```
#[must_use = "commit the retained Call or explicitly release this reservation"]
pub struct RetainedWorkReservation {
    slot: usize,
    identity: u64,
    reply: u64,
}

/// The store keeps this Call's slot, route and Reply registered until restoration or exact finish.
///
/// ```compile_fail
/// use nt_component_suspension::RetainedWorkCheckout;
/// fn duplicate(ticket: RetainedWorkCheckout<u64>) { let _ = ticket.clone(); }
/// ```
#[must_use = "restore or finish this retained Call through its owning store"]
pub struct RetainedWorkCheckout<M> {
    slot: usize,
    identity: u64,
    call: RetainedIngress<M>,
}

impl<M> RetainedWorkCheckout<M> {
    pub fn call(&self) -> &RetainedIngress<M> {
        &self.call
    }

    pub fn begin_reply(&mut self) -> Result<crate::IngressReplyAttempt, crate::IngressError> {
        self.call.begin_reply()
    }

    pub fn observe_reply(
        &mut self,
        attempt: &mut crate::IngressReplyAttempt,
        observation: crate::IngressReplyObservation,
    ) -> Result<(), crate::IngressError> {
        self.call.observe_reply(attempt, observation)
    }

    pub fn begin_dispatch<C, R, T, E>(
        &mut self,
        lanes: &mut crate::ComponentSuspensionLanes<C, R, T>,
        peers: &PeerRegistry,
        domain: u64,
        generation: u64,
        query: impl FnMut(u64, u64) -> Result<crate::ReplyBindingObservation, E>,
    ) -> Result<crate::RetainedDispatch, crate::RetainedDispatchError<E>> {
        lanes.begin_retained_dispatch(peers, &mut self.call, domain, generation, query)
    }

    pub fn finish_dispatch<C, R, T>(
        &mut self,
        lanes: &mut crate::ComponentSuspensionLanes<C, R, T>,
    ) -> Result<(), crate::RetainedDispatchError<Infallible>> {
        lanes.finish_retained_dispatch(&mut self.call)
    }
}

enum Slot<M> {
    Vacant,
    Reserved {
        identity: u64,
        reply: u64,
    },
    Stored {
        identity: u64,
        call: RetainedIngress<M>,
    },
    CheckedOut {
        identity: u64,
        route: PeerRoute,
        reply: u64,
    },
}

/// Native adapters must reserve before receiving and keep this store alive until all Calls and
/// reservations are drained. No operation after construction allocates. This owns storage, not
/// execution permission; canonical admission and kernel Reply authentication remain separate.
pub struct RetainedWork<M> {
    endpoint: u64,
    slots: Vec<Slot<M>>,
}

impl<M> RetainedWork<M> {
    pub fn new(endpoint: u64, capacity: usize) -> Result<Self, RetainedWorkError> {
        if endpoint == 0 || capacity == 0 {
            return Err(RetainedWorkError::InvalidConfiguration);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| RetainedWorkError::NoCapacity)?;
        slots.resize_with(capacity, || Slot::Vacant);
        Ok(Self { endpoint, slots })
    }

    pub fn endpoint(&self) -> u64 {
        self.endpoint
    }

    pub fn available(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot, Slot::Vacant))
            .count()
    }

    pub fn excludes_reply(&self, reply: u64) -> bool {
        self.slots.iter().any(|slot| match slot {
            Slot::Stored { call, .. } => call.reply() == reply,
            Slot::CheckedOut { reply: owned, .. } => *owned == reply,
            Slot::Reserved { reply: owned, .. } => *owned == reply,
            _ => false,
        })
    }

    pub fn reserve(&mut self, reply: u64) -> Result<RetainedWorkReservation, RetainedWorkError> {
        self.reserve_with_counter(reply, &NEXT_RESERVATION)
    }

    fn reserve_with_counter(
        &mut self,
        reply: u64,
        counter: &AtomicU64,
    ) -> Result<RetainedWorkReservation, RetainedWorkError> {
        if reply == 0 || reply == self.endpoint {
            return Err(RetainedWorkError::InvalidReply);
        }
        if self.excludes_reply(reply) {
            return Err(RetainedWorkError::ReplyInUse);
        }
        let slot = self
            .slots
            .iter()
            .position(|slot| matches!(slot, Slot::Vacant))
            .ok_or(RetainedWorkError::NoCapacity)?;
        let identity = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                if next == 0 {
                    None
                } else {
                    next.checked_add(1)
                }
            })
            .map_err(|_| RetainedWorkError::IdentityExhausted)?;
        self.slots[slot] = Slot::Reserved { identity, reply };
        Ok(RetainedWorkReservation {
            slot,
            identity,
            reply,
        })
    }

    fn owns_reservation(&self, reservation: &RetainedWorkReservation) -> bool {
        reservation.identity != 0
            && matches!(self.slots.get(reservation.slot),
            Some(Slot::Reserved { identity, reply }) if *identity == reservation.identity && *reply == reservation.reply)
    }

    /// Only release a never-started receive, proven NoCall, or completed native cancellation.
    /// An ambiguous receive remains reserved even when no RetainedIngress was committed.
    pub fn release_reservation(
        &mut self,
        reservation: &mut RetainedWorkReservation,
    ) -> Result<(), RetainedWorkError> {
        if !self.owns_reservation(reservation) {
            return Err(RetainedWorkError::WrongOwner);
        }
        self.slots[reservation.slot] = Slot::Vacant;
        reservation.identity = 0;
        Ok(())
    }

    pub fn commit(
        &mut self,
        reservation: RetainedWorkReservation,
        call: RetainedIngress<M>,
    ) -> Result<
        (),
        (
            RetainedWorkError,
            RetainedWorkReservation,
            RetainedIngress<M>,
        ),
    > {
        let error = if !self.owns_reservation(&reservation) {
            Some(RetainedWorkError::WrongOwner)
        } else if call.route().endpoint() != self.endpoint {
            Some(RetainedWorkError::WrongEndpoint)
        } else if call.reply() != reservation.reply {
            Some(RetainedWorkError::InvalidReply)
        } else {
            None
        };
        if let Some(error) = error {
            return Err((error, reservation, call));
        }
        self.slots[reservation.slot] = Slot::Stored {
            identity: reservation.identity,
            call,
        };
        Ok(())
    }

    pub fn checkout(
        &mut self,
        route: PeerRoute,
    ) -> Result<RetainedWorkCheckout<M>, RetainedWorkError> {
        let index = self
            .slots
            .iter()
            .position(|slot| {
                matches!(slot,
            Slot::Stored { call, .. } if call.route() == route)
            })
            .ok_or(RetainedWorkError::NotFound)?;
        let Slot::Stored { identity, call } =
            core::mem::replace(&mut self.slots[index], Slot::Vacant)
        else {
            unreachable!("selected stored Call")
        };
        self.slots[index] = Slot::CheckedOut {
            identity,
            route,
            reply: call.reply(),
        };
        Ok(RetainedWorkCheckout {
            slot: index,
            identity,
            call,
        })
    }

    fn owns_checkout(&self, checkout: &RetainedWorkCheckout<M>) -> bool {
        matches!(self.slots.get(checkout.slot), Some(Slot::CheckedOut { identity, route, reply })
            if *identity == checkout.identity && *route == checkout.call.route() && *reply == checkout.call.reply())
    }

    pub fn restore(
        &mut self,
        checkout: RetainedWorkCheckout<M>,
    ) -> Result<(), (RetainedWorkError, RetainedWorkCheckout<M>)> {
        if !self.owns_checkout(&checkout) {
            return Err((RetainedWorkError::WrongOwner, checkout));
        }
        self.slots[checkout.slot] = Slot::Stored {
            identity: checkout.identity,
            call: checkout.call,
        };
        Ok(())
    }

    pub fn finish_checkout(
        &mut self,
        checkout: RetainedWorkCheckout<M>,
        peers: &mut PeerRegistry,
    ) -> Result<(ComponentIngress<M>, M), (RetainedWorkFinishError, RetainedWorkCheckout<M>)> {
        if !self.owns_checkout(&checkout) {
            return Err((
                RetainedWorkFinishError::Store(RetainedWorkError::WrongOwner),
                checkout,
            ));
        }
        let RetainedWorkCheckout {
            slot,
            identity,
            call,
        } = checkout;
        match call.finish(peers) {
            Ok(completed) => {
                self.slots[slot] = Slot::Vacant;
                Ok(completed)
            }
            Err((error, call)) => Err((
                RetainedWorkFinishError::Call(error),
                RetainedWorkCheckout {
                    slot,
                    identity,
                    call,
                },
            )),
        }
    }
}

#[cfg(test)]
#[path = "retained_work_tests.rs"]
mod tests;
