//! Owned unrelated Calls for a future shared ingress adapter; no native routing is installed here.

use crate::peer_registry::{PeerError, PeerRegistry, PeerRetention, PeerRoute};
use crate::{
    ComponentIngress, ComponentSuspensionLanes, IngressError, IngressReplyAttempt,
    IngressReplyObservation, ReplyBindingObservation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedIngressError<E> {
    UnknownPeer,
    WrongEndpoint,
    BindingMismatch,
    Query(E),
    Peer(PeerError),
    Ingress(IngressError),
    NotAcknowledged,
    DispatchActive,
}

/// Keeps the exact Reply, complete payload and peer lifetime reservation together. This grants
/// neither lane execution nor permission to dispatch a retiring peer. Dropping it does not release
/// registry retention or acknowledge the Call.
///
/// ```compile_fail
/// use nt_component_suspension::RetainedIngress;
/// fn duplicate(call: RetainedIngress<u64>) { let _ = call.clone(); }
/// ```
#[must_use = "retain until acknowledged completion and exact peer release"]
pub struct RetainedIngress<M> {
    ingress: ComponentIngress<M>,
    retention: PeerRetention,
    completed: Option<M>,
    pub(crate) admitted: Option<crate::LaneDispatchIdentity>,
}

impl<M> RetainedIngress<M> {
    pub(crate) fn is_held(&self) -> bool {
        self.admitted.is_none() && self.completed.is_none() && self.ingress.is_held()
    }

    pub fn route(&self) -> PeerRoute {
        self.retention.route().expect("owned peer retention")
    }

    pub fn reply(&self) -> u64 {
        self.ingress.reply()
    }

    /// Borrow for canonical lane admission; this does not permit releasing or replacing ownership.
    pub fn retention(&self) -> &PeerRetention {
        &self.retention
    }

    pub fn message(&self) -> &M {
        self.completed
            .as_ref()
            .or_else(|| self.ingress.message())
            .expect("owned ingress payload")
    }

    pub fn begin_reply(&mut self) -> Result<IngressReplyAttempt, IngressError> {
        self.ingress.begin_reply()
    }

    /// Indeterminate keeps the exact attempt locked; NoEffects permits a new attempt. ACK retains
    /// the payload here until registry release succeeds, rather than returning it prematurely.
    pub fn observe_reply(
        &mut self,
        attempt: &mut IngressReplyAttempt,
        observation: IngressReplyObservation,
    ) -> Result<(), IngressError> {
        if let Some(message) = self.ingress.observe_reply(attempt, observation)? {
            self.completed = Some(message);
        }
        Ok(())
    }

    /// On any refusal return all ownership, including an already acknowledged payload, intact.
    /// Cancellation completion is not modeled here; only confirmed reply ACK permits release.
    pub fn finish(
        mut self,
        peers: &mut PeerRegistry,
    ) -> Result<(ComponentIngress<M>, M), (RetainedIngressError<core::convert::Infallible>, Self)>
    {
        if self.admitted.is_some() {
            return Err((RetainedIngressError::DispatchActive, self));
        }
        if self.completed.is_none() {
            return Err((RetainedIngressError::NotAcknowledged, self));
        }
        if let Err(error) = peers.release(&mut self.retention) {
            return Err((RetainedIngressError::Peer(error), self));
        }
        Ok((
            self.ingress,
            self.completed.take().expect("acknowledged payload"),
        ))
    }
}

impl<C, R, T> ComponentSuspensionLanes<C, R, T> {
    /// Transfer a classified held Call to an owned retention and install the fresh receive owner.
    /// The complete payload must already be owned and badge must come from that captured message.
    /// The non-mutating native query may reuse the IPC bank, but must authenticate
    /// the exact expected executor and Reply, after validating canonical physical lifetime/domain;
    /// route metadata and badge alone do not establish this. Retiring arrivals are retained only
    /// for draining/cancellation. No callback runs between registry retention and memory handoff.
    ///
    /// The adapter must exclusively own both Replies, prove the replacement unbound, and exclude
    /// capabilities retained by other physical domains and non-component owners, as required by
    /// handoff_ingress_call. Registry metadata does not validate those canonical lifetimes.
    /// Every refusal leaves the original ingress intact and returns the replacement intact.
    pub fn retain_peer_ingress<M, E>(
        &self,
        ingress: &mut ComponentIngress<M>,
        replacement: ComponentIngress<M>,
        peers: &mut PeerRegistry,
        badge: u64,
        query_binding: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<RetainedIngress<M>, (RetainedIngressError<E>, ComponentIngress<M>)> {
        let route = match peers
            .resolve(badge)
            .or_else(|| peers.resolve_retiring(badge))
        {
            Some(route) => route,
            None => return Err((RetainedIngressError::UnknownPeer, replacement)),
        };
        if route.endpoint() != ingress.endpoint() {
            return Err((RetainedIngressError::WrongEndpoint, replacement));
        }
        match query_binding(route.identity().executor, ingress.reply()) {
            Ok(ReplyBindingObservation::BoundToTarget) => {}
            Ok(_) => return Err((RetainedIngressError::BindingMismatch, replacement)),
            Err(error) => return Err((RetainedIngressError::Query(error), replacement)),
        }
        let mut retention = match peers.retain(route) {
            Ok(retention) => retention,
            Err(error) => return Err((RetainedIngressError::Peer(error), replacement)),
        };
        match self.handoff_ingress_call(ingress, replacement) {
            Ok(ingress) => Ok(RetainedIngress {
                ingress,
                retention,
                completed: None,
                admitted: None,
            }),
            Err((error, replacement)) => {
                // No external effects or registry mutation intervened since retain succeeded.
                peers
                    .release(&mut retention)
                    .expect("rollback exact peer reservation");
                Err((RetainedIngressError::Ingress(error), replacement))
            }
        }
    }
}

#[cfg(test)]
#[path = "retained_ingress_tests.rs"]
mod tests;
