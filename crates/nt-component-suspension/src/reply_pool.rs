//! Fixed-capacity ownership of spare ingress Replies, checked again before each handoff.

use alloc::vec::Vec;
use core::convert::Infallible;

use crate::peer_registry::PeerRoute;
use crate::{peer_registry::PeerRegistry, ReservedReceiveError};
use crate::{ComponentIngress, ComponentSuspensionLanes, IngressReceiver, ReplyBindingObservation};
use crate::{LaneDispatchIdentity, RetainedDispatchError, RetainedWorkError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyAdmissionError<E> {
    Pool(ReplyPoolError<E>),
    Store(RetainedWorkError),
    Dispatch(RetainedDispatchError<E>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyPoolError<E> {
    InvalidConfiguration,
    NoCapacity,
    Empty,
    WrongEndpoint,
    NotReady,
    ReplyInUse,
    NotFree,
    Query(E),
    Retain(ReservedReceiveError<E>),
}

/// Each entry is an owned Ready ingress, never a reconstructed numeric Reply capability.
/// Native adapters must preserve capability lifetimes and exclude aliases in other domains,
/// pools and native owners. Query callbacks may observe only and must not reenter ownership.
/// Dropping this pool does not delete capabilities or authorize their reuse.
///
/// ```compile_fail
/// use nt_component_suspension::IngressReplyPool;
/// fn duplicate(pool: IngressReplyPool<u64>) { let _ = pool.clone(); }
/// ```
#[must_use = "retain owned spare ingress Replies"]
pub struct IngressReplyPool<M> {
    endpoint: u64,
    capacity: usize,
    entries: Vec<ComponentIngress<M>>,
}

impl<M> IngressReplyPool<M> {
    /// Admit a stored Call and recycle the displaced canonical Reply in one transaction.
    /// All fallible pool checks precede dispatch mutation; the final push uses reserved capacity
    /// and the Free proof collected by canonical admission, not another native query.
    /// Queries must be observational and nonreentrant. The Call stays in its charged receiver
    /// slot throughout queries, admission and execution; no local checkout can lose ownership.
    pub fn admit<C, R, T, E>(
        &mut self,
        receiver: &mut IngressReceiver<M>,
        route: PeerRoute,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        peers: &PeerRegistry,
        domain: u64,
        generation: u64,
        query: impl FnMut(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<LaneDispatchIdentity, ReplyAdmissionError<E>> {
        if receiver.endpoint() != self.endpoint || route.endpoint() != self.endpoint {
            return Err(ReplyAdmissionError::Pool(ReplyPoolError::WrongEndpoint));
        }
        if receiver.phase().is_some() {
            return Err(ReplyAdmissionError::Pool(ReplyPoolError::NotReady));
        }
        if self.entries.len() == self.capacity {
            return Err(ReplyAdmissionError::Pool(ReplyPoolError::NoCapacity));
        }
        let binding = lanes
            .binding(route.identity().lane)
            .map_err(|error| ReplyAdmissionError::Dispatch(RetainedDispatchError::Lane(error)))?;
        let old = binding.reply_object;
        if receiver.excludes_reply(old) || self.excludes_reply(old) {
            return Err(ReplyAdmissionError::Pool(ReplyPoolError::ReplyInUse));
        }
        let replacement = ComponentIngress::new(self.endpoint, old)
            .map_err(|_| ReplyAdmissionError::Pool(ReplyPoolError::InvalidConfiguration))?;
        let call = receiver
            .stored_call_mut(route)
            .map_err(ReplyAdmissionError::Store)?;
        if self.excludes_reply(call.reply()) {
            return Err(ReplyAdmissionError::Pool(ReplyPoolError::ReplyInUse));
        }
        let receipt = lanes
            .begin_retained_dispatch(peers, call, domain, generation, query)
            .map_err(ReplyAdmissionError::Dispatch)?;
        debug_assert_eq!(receipt.displaced_reply, old);
        self.entries.push(replacement);
        Ok(receipt.dispatch)
    }

    pub fn new(endpoint: u64, capacity: usize) -> Result<Self, ReplyPoolError<Infallible>> {
        if endpoint == 0 || capacity == 0 {
            return Err(ReplyPoolError::InvalidConfiguration);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(capacity)
            .map_err(|_| ReplyPoolError::NoCapacity)?;
        Ok(Self {
            endpoint,
            capacity,
            entries,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn excludes_reply(&self, reply: u64) -> bool {
        self.entries.iter().any(|owner| owner.reply() == reply)
    }

    fn validate<C, R, T, E>(
        &self,
        owner: &ComponentIngress<M>,
        receiver: &IngressReceiver<M>,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        query: impl FnOnce(u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(), ReplyPoolError<E>> {
        if owner.endpoint() != self.endpoint || receiver.endpoint() != self.endpoint {
            return Err(ReplyPoolError::WrongEndpoint);
        }
        if !owner.is_ready() {
            return Err(ReplyPoolError::NotReady);
        }
        if receiver.excludes_reply(owner.reply())
            || lanes.slots.iter().any(|slot| {
                slot.lane
                    .as_ref()
                    .is_some_and(|lane| lane.binding.reply_object == owner.reply())
            })
        {
            return Err(ReplyPoolError::ReplyInUse);
        }
        if query(owner.reply()).map_err(ReplyPoolError::Query)? != ReplyBindingObservation::Free {
            return Err(ReplyPoolError::NotFree);
        }
        Ok(())
    }

    pub fn insert<C, R, T, E>(
        &mut self,
        owner: ComponentIngress<M>,
        receiver: &IngressReceiver<M>,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        query: impl FnOnce(u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(), (ReplyPoolError<E>, ComponentIngress<M>)> {
        let mut pending = Some(owner);
        self.insert_pending(&mut pending, receiver, lanes, query)
            .map_err(|error| (error, pending.take().expect("refused Reply remains owned")))
    }

    /// Keep native pending ownership published through all binding queries. Only a successful
    /// in-memory insertion consumes the slot; every refusal leaves it unchanged.
    pub fn insert_pending<C, R, T, E>(
        &mut self,
        pending: &mut Option<ComponentIngress<M>>,
        receiver: &IngressReceiver<M>,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        query: impl FnOnce(u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(), ReplyPoolError<E>> {
        let owner = pending.as_ref().ok_or(ReplyPoolError::Empty)?;
        if self.entries.len() == self.capacity {
            return Err(ReplyPoolError::NoCapacity);
        }
        if self.excludes_reply(owner.reply()) {
            return Err(ReplyPoolError::ReplyInUse);
        }
        self.validate(owner, receiver, lanes, query)?;
        self.entries.push(pending.take().expect("validated pending Reply"));
        Ok(())
    }

    /// Transfer a spare only as part of committing the receiver's held Call. Refusal restores the
    /// same owned replacement into its reserved vector capacity, without allocation or a public
    /// checkout interval. Both queries must be observational and nonreentrant.
    pub fn retain<C, R, T, E>(
        &mut self,
        receiver: &mut IngressReceiver<M>,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        peers: &mut PeerRegistry,
        badge: u64,
        free_query: impl FnOnce(u64) -> Result<ReplyBindingObservation, E>,
        binding_query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(), ReplyPoolError<E>> {
        let owner = self.entries.last().ok_or(ReplyPoolError::Empty)?;
        self.validate(owner, receiver, lanes, free_query)?;
        let owner = self.entries.pop().expect("validated last spare Reply");
        match receiver.retain(lanes, owner, peers, badge, binding_query) {
            Ok(()) => Ok(()),
            Err((error, owner)) => {
                self.entries.push(owner);
                Err(ReplyPoolError::Retain(error))
            }
        }
    }
}

#[cfg(test)]
#[path = "reply_pool_tests.rs"]
mod tests;
