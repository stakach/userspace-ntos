//! Move a running dispatch to its next retained Call without allocating another epoch.

use super::*;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterimAdoptionError<E> {
    PendingReply,
    WrongOwner,
    TerminalActive,
    NotAcknowledged,
    NotHeld,
    ReplyInUse,
    OldReplyNotFree,
    IncomingNotBound,
    Query(E),
    Store(RetainedWorkError),
    Finish(RetainedWorkFinishError),
}

impl<M> IngressReceiver<M> {
    /// The native caller authenticates the physical domain/worker lifetime and incoming protocol
    /// before entering. Queries are observational and nonreentrant; no service, reply or receive
    /// occurs here. Running suspension frames and external tokens retain their exact identities;
    /// native continuation channels must resolve the current binding before reuse. An entered
    /// terminal owner forbids handoff because its attempts can retain exact Reply authority.
    /// All refusals preserve both Calls, the dispatch and pending Reply. Success transfers the
    /// unchanged epoch to the incoming Call and publishes the old Free Reply before returning its
    /// acknowledged payload. The caller must retain `pending` through checked pool insertion.
    pub fn adopt_interim_call<C, R, T, E>(
        &mut self,
        route: PeerRoute,
        dispatch: crate::LaneDispatchIdentity,
        incoming_reply: u64,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        peers: &mut PeerRegistry,
        pending: &mut Option<ComponentIngress<M>>,
        mut query: impl FnMut(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<M, InterimAdoptionError<E>> {
        if pending.is_some() {
            return Err(InterimAdoptionError::PendingReply);
        }
        if self.phase().is_some()
            || self.endpoint() != route.endpoint()
            || lanes
                .validate_ingress_execution(IngressExecutionOwner::Dispatch(dispatch))
                .is_err()
            || peers
                .resolve_lane(
                    route.badge(),
                    route.identity().domain,
                    route.identity().domain_generation,
                    lanes,
                )
                .ok()
                != Some(route)
        {
            return Err(InterimAdoptionError::WrongOwner);
        }
        let lane = lanes
            .lane(route.identity().lane)
            .map_err(|_| InterimAdoptionError::WrongOwner)?;
        if dispatch.lane != route.identity().lane
            || lane.shared_peer != Some(route)
            || lane.dispatch != Some(dispatch)
            || lane.binding.executor_id != route.identity().executor
            || lane.binding.receive_endpoint != route.endpoint()
        {
            return Err(InterimAdoptionError::WrongOwner);
        }
        if lane.terminal.is_some() {
            return Err(InterimAdoptionError::TerminalActive);
        }
        let old_reply = lane.binding.reply_object;
        if incoming_reply == old_reply
            || lanes.slots.iter().any(|slot| {
                slot.lane
                    .as_ref()
                    .is_some_and(|lane| lane.binding.reply_object == incoming_reply)
            })
        {
            return Err(InterimAdoptionError::ReplyInUse);
        }
        let old = self
            .store
            .stored_reply(route, old_reply)
            .map_err(InterimAdoptionError::Store)?;
        if old.admitted != Some(dispatch) {
            return Err(InterimAdoptionError::WrongOwner);
        }
        if !old.is_acknowledged() {
            return Err(InterimAdoptionError::NotAcknowledged);
        }
        if !self
            .store
            .stored_reply(route, incoming_reply)
            .map_err(InterimAdoptionError::Store)?
            .is_held()
        {
            return Err(InterimAdoptionError::NotHeld);
        }
        if !matches!(peers.state(route), Ok((_, count)) if count >= 2) {
            return Err(InterimAdoptionError::WrongOwner);
        }
        if query(route.identity().executor, old_reply).map_err(InterimAdoptionError::Query)?
            != ReplyBindingObservation::Free
        {
            return Err(InterimAdoptionError::OldReplyNotFree);
        }
        if query(route.identity().executor, incoming_reply).map_err(InterimAdoptionError::Query)?
            != ReplyBindingObservation::BoundToTarget
        {
            return Err(InterimAdoptionError::IncomingNotBound);
        }

        // No callbacks follow preflight. Finish only the old Call; any refusal restores its
        // admitted marker before returning, while canonical binding and incoming Call are intact.
        self.store
            .stored_reply_mut(route, old_reply)
            .expect("preflight old Call")
            .admitted = None;
        let checkout = match self.store.checkout_reply(route, old_reply) {
            Ok(checkout) => checkout,
            Err(error) => {
                self.store
                    .stored_reply_mut(route, old_reply)
                    .expect("preflight old Call")
                    .admitted = Some(dispatch);
                return Err(InterimAdoptionError::Store(error));
            }
        };
        let (displaced, payload) = match self.store.finish_checkout(checkout, peers) {
            Ok(result) => result,
            Err((error, checkout)) => {
                assert!(self.store.restore(checkout).is_ok());
                self.store
                    .stored_reply_mut(route, old_reply)
                    .expect("restored old Call")
                    .admitted = Some(dispatch);
                return Err(InterimAdoptionError::Finish(error));
            }
        };
        self.store
            .stored_reply_mut(route, incoming_reply)
            .expect("preflight incoming Call")
            .admitted = Some(dispatch);
        lanes
            .lane_mut(route.identity().lane)
            .expect("preflight running lane")
            .binding
            .reply_object = incoming_reply;
        *pending = Some(displaced);
        Ok(payload)
    }
}
