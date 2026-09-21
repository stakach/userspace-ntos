//! Sealed receive and retained-work ownership; no mutable inner owner can escape.

use core::convert::Infallible;

use crate::peer_registry::{PeerRegistry, PeerRoute};
use crate::{
    ComponentIngress, ComponentSuspensionLanes, IngressExecutionOwner, IngressReceiveDisposition,
    ReplyBindingObservation, ReservedIngressReceive, ReservedReceiveError, ReservedReceivePhase,
    RetainedWork, RetainedWorkCheckout, RetainedWorkError, RetainedWorkFinishError,
};

#[cfg(test)]
#[path = "ingress_receiver_tests.rs"]
mod tests;

/// Native adapters must capture the full received message before issuing binding-query IPC.
/// This owns ingress and storage exclusively; Call provenance, exact physical lifetime and
/// capability alias exclusions outside this receiver remain native obligations.
///
/// ```compile_fail
/// use nt_component_suspension::IngressReceiver;
/// fn duplicate(owner: IngressReceiver<u64>) { let _ = owner.clone(); }
/// ```
#[must_use = "retain the receiver and its unresolved or retained Calls"]
pub struct IngressReceiver<M> {
    ingress: ComponentIngress<M>,
    store: RetainedWork<M>,
    receive: Option<ReservedIngressReceive>,
}

impl<M> IngressReceiver<M> {
    pub fn new(
        endpoint: u64,
        reply: u64,
        capacity: usize,
    ) -> Result<Self, ReservedReceiveError<Infallible>> {
        let store = RetainedWork::new(endpoint, capacity).map_err(ReservedReceiveError::Store)?;
        let ingress =
            ComponentIngress::new(endpoint, reply).map_err(ReservedReceiveError::Ingress)?;
        Ok(Self {
            ingress,
            store,
            receive: None,
        })
    }

    pub fn endpoint(&self) -> u64 {
        self.ingress.endpoint()
    }

    pub fn reply(&self) -> u64 {
        self.ingress.reply()
    }

    pub fn message(&self) -> Option<&M> {
        self.ingress.message()
    }

    pub fn available(&self) -> usize {
        self.store.available()
    }

    /// Includes the currently owned receive Reply even before its next reservation begins.
    pub fn excludes_reply(&self, reply: u64) -> bool {
        self.ingress.reply() == reply || self.store.excludes_reply(reply)
    }

    pub fn phase(&self) -> Option<ReservedReceivePhase> {
        self.receive.as_ref().map(ReservedIngressReceive::phase)
    }

    pub fn begin_receive<C, R, T>(
        &mut self,
        lanes: &ComponentSuspensionLanes<C, R, T>,
    ) -> Result<(), ReservedReceiveError<Infallible>> {
        self.begin_receive_for_owner(lanes, IngressExecutionOwner::Idle)
    }

    pub fn begin_receive_for_owner<C, R, T>(
        &mut self,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        owner: IngressExecutionOwner,
    ) -> Result<(), ReservedReceiveError<Infallible>> {
        if self.receive.is_some() {
            return Err(ReservedReceiveError::InvalidPhase);
        }
        self.receive = Some(
            self.store
                .begin_receive_for_owner(lanes, &mut self.ingress, owner)?,
        );
        Ok(())
    }

    pub fn capture(&mut self, message: M) -> Result<(), (ReservedReceiveError<Infallible>, M)> {
        let Some(receive) = self.receive.as_mut() else {
            return Err((ReservedReceiveError::InvalidPhase, message));
        };
        receive.capture(&self.store, &mut self.ingress, message)
    }

    pub fn resolve(
        &mut self,
        disposition: IngressReceiveDisposition,
    ) -> Result<Option<M>, ReservedReceiveError<Infallible>> {
        let receive = self
            .receive
            .as_mut()
            .ok_or(ReservedReceiveError::InvalidPhase)?;
        let message = receive.resolve(&mut self.store, &mut self.ingress, disposition)?;
        if disposition == IngressReceiveDisposition::NoCall {
            self.receive = None;
        }
        Ok(message)
    }

    pub fn retain<C, R, T, E>(
        &mut self,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        replacement: ComponentIngress<M>,
        peers: &mut PeerRegistry,
        badge: u64,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(), (ReservedReceiveError<E>, ComponentIngress<M>)> {
        let Some(receive) = self.receive.as_mut() else {
            return Err((ReservedReceiveError::InvalidPhase, replacement));
        };
        receive.retain(
            &mut self.store,
            lanes,
            &mut self.ingress,
            replacement,
            peers,
            badge,
            query,
        )?;
        self.receive = None;
        Ok(())
    }

    pub fn checkout(
        &mut self,
        route: PeerRoute,
    ) -> Result<RetainedWorkCheckout<M>, RetainedWorkError> {
        self.store.checkout(route)
    }

    pub(crate) fn stored_call_mut(
        &mut self,
        route: PeerRoute,
    ) -> Result<&mut crate::RetainedIngress<M>, RetainedWorkError> {
        self.store.stored_call_mut(route)
    }

    pub fn restore(
        &mut self,
        checkout: RetainedWorkCheckout<M>,
    ) -> Result<(), (RetainedWorkError, RetainedWorkCheckout<M>)> {
        self.store.restore(checkout)
    }

    pub fn finish_checkout(
        &mut self,
        checkout: RetainedWorkCheckout<M>,
        peers: &mut PeerRegistry,
    ) -> Result<(ComponentIngress<M>, M), (RetainedWorkFinishError, RetainedWorkCheckout<M>)> {
        self.store.finish_checkout(checkout, peers)
    }
}
