//! Sealed receive and retained-work ownership; no mutable inner owner can escape.

use core::convert::Infallible;

use crate::peer_registry::{PeerRegistry, PeerRoute};
use crate::{
    ComponentIngress, ComponentSuspensionLanes, IngressExecutionOwner, IngressReceiveDisposition,
    ReplyBindingObservation, ReservedIngressReceive, ReservedReceiveError, ReservedReceivePhase,
    RetainedWork, RetainedWorkCheckout, RetainedWorkError, RetainedWorkFinishError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalCompletionError<E> {
    WrongOwner,
    NotIdle,
    NotFree,
    Query(E),
    Finish(RetainedWorkFinishError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoredReplyError<E> {
    Store(RetainedWorkError),
    DispatchMismatch,
    BindingMismatch,
    Query(E),
    Ingress(crate::IngressError),
}

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
    /// Reply only for the exact admitted running dispatch. Keep its attempt and payload stored
    /// before the native effect; ACK does not end dispatch or release peer/storage ownership.
    /// Both callbacks must preserve physical lifetimes and must not reenter this owner.
    pub fn reply_stored<C, R, T, E>(
        &mut self,
        route: PeerRoute,
        dispatch: crate::LaneDispatchIdentity,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
        invoke: impl FnOnce(u64) -> crate::IngressReplyObservation,
    ) -> Result<crate::IngressReplyObservation, StoredReplyError<E>> {
        let call = self
            .store
            .stored_call_mut(route)
            .map_err(StoredReplyError::Store)?;
        let lane = lanes
            .lane(route.identity().lane)
            .map_err(|_| StoredReplyError::DispatchMismatch)?;
        if call.admitted != Some(dispatch)
            || lanes
                .validate_ingress_execution(IngressExecutionOwner::Dispatch(dispatch))
                .is_err()
            || lane.dispatch != Some(dispatch)
            || lanes.running() != Some(route.identity().lane)
            || lane.phase != crate::LanePhase::Running
            || lane.shared_peer != Some(route)
            || lane.binding.executor_id != route.identity().executor
            || lane.binding.receive_endpoint != route.endpoint()
            || lane.binding.reply_object != call.reply()
        {
            return Err(StoredReplyError::DispatchMismatch);
        }
        if query(route.identity().executor, call.reply()).map_err(StoredReplyError::Query)?
            != ReplyBindingObservation::BoundToTarget
        {
            return Err(StoredReplyError::BindingMismatch);
        }
        call.reply_owned(invoke).map_err(StoredReplyError::Ingress)
    }

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

    /// Consume an acknowledged Ready ingress into its exact shared lane's canonical Reply
    /// ownership. Return only the payload, never a second reusable owner for that Reply.
    /// The adapter must validate physical domain/capability lifetimes. The binding query must be
    /// observational and nonreentrant; every refusal returns the complete checkout unchanged.
    pub fn finish_canonical_checkout<C, R, T, E>(
        &mut self,
        checkout: RetainedWorkCheckout<M>,
        peers: &mut PeerRegistry,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<M, (CanonicalCompletionError<E>, RetainedWorkCheckout<M>)> {
        let validate = || {
            if !self.store.owns_checkout(&checkout) {
                return Err(CanonicalCompletionError::WrongOwner);
            }
            let call = checkout.call();
            let route = call.route();
            let lane = lanes
                .lane(route.identity().lane)
                .map_err(|_| CanonicalCompletionError::WrongOwner)?;
            if lane.shared_peer != Some(route)
                || lane.binding.executor_id != route.identity().executor
                || lane.binding.receive_endpoint != route.endpoint()
                || lane.binding.reply_object != call.reply()
            {
                return Err(CanonicalCompletionError::WrongOwner);
            }
            if lane.phase != crate::LanePhase::Idle || lane.dispatch.is_some() {
                return Err(CanonicalCompletionError::NotIdle);
            }
            if query(lane.binding.executor_id, call.reply())
                .map_err(CanonicalCompletionError::Query)?
                != ReplyBindingObservation::Free
            {
                return Err(CanonicalCompletionError::NotFree);
            }
            Ok(())
        };
        if let Err(error) = validate() {
            return Err((error, checkout));
        }
        match self.store.finish_checkout(checkout, peers) {
            Ok((ready, message)) => {
                // No native effect: canonical LaneBinding already owns this exact Reply. Consuming
                // the Ready wrapper closes the retained-call ownership without recycling the cap.
                drop(ready);
                Ok(message)
            }
            Err((error, checkout)) => Err((CanonicalCompletionError::Finish(error), checkout)),
        }
    }
}
