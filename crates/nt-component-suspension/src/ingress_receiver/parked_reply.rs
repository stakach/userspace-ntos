//! Complete an external wait's Call without borrowing another provider's execution fence.

use super::*;

#[cfg(test)]
mod tests;

impl<M> IngressReceiver<M> {
    /// A source continuation is proof that the parked Reply reached its exact caller even when
    /// the native Reply wrapper reported uncertainty. This consumes only an existing uncertain
    /// attempt; it never invokes or retries the Reply. The native adapter must authenticate the
    /// source continuation's physical IRP, caller and Reply provenance before calling here.
    pub fn acknowledge_parked_stored_from_source_continuation<C, R, T>(
        &mut self,
        route: PeerRoute,
        dispatch: crate::LaneDispatchIdentity,
        reply: u64,
        token: u64,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        peers: &PeerRegistry,
    ) -> Result<(), StoredReplyError<core::convert::Infallible>> {
        let call = self.store.stored_dispatch_mut(route, dispatch)
            .map_err(StoredReplyError::Store)?;
        let lane = lanes.lane(route.identity().lane)
            .map_err(|_| StoredReplyError::DispatchMismatch)?;
        if token == 0
            || reply == 0
            || call.reply() != reply
            || call.admitted != Some(dispatch)
            || lane.phase != crate::LanePhase::Suspended
            || lane.external_tokens.last().copied() != Some(token)
            || lane.dispatch != Some(dispatch)
            || lane.shared_peer != Some(route)
            || lane.binding.reply_object != reply
            || lane.binding.executor_id != route.identity().executor
            || lane.binding.receive_endpoint != route.endpoint()
            || peers.resolve_lane(
                route.badge(), route.identity().domain,
                route.identity().domain_generation, lanes,
            ).ok() != Some(route)
        {
            return Err(StoredReplyError::DispatchMismatch);
        }
        call.acknowledge_attempted_reply_from_source_continuation()
            .map_err(StoredReplyError::Ingress)
    }

    /// The external token authorizes only this retained reply, not component service execution.
    /// Keep the token and epoch parked after ACK; the scheduler must separately resume the exact
    /// continuation once execution admission is available. Uncertain effects cannot be replayed.
    pub fn reply_parked_stored<C, R, T, E>(
        &mut self,
        route: PeerRoute,
        dispatch: crate::LaneDispatchIdentity,
        token: u64,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        peers: &PeerRegistry,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
        invoke: impl FnOnce(u64) -> crate::IngressReplyObservation,
    ) -> Result<crate::IngressReplyObservation, StoredReplyError<E>> {
        let call = self
            .store
            .stored_dispatch_mut(route, dispatch)
            .map_err(StoredReplyError::Store)?;
        let lane = lanes
            .lane(route.identity().lane)
            .map_err(|_| StoredReplyError::DispatchMismatch)?;
        if token == 0
            || lane.phase != crate::LanePhase::Suspended
            || lane.external_tokens.last().copied() != Some(token)
            || lane.dispatch != Some(dispatch)
            || call.admitted != Some(dispatch)
            || lane.shared_peer != Some(route)
            || lane.binding.reply_object != call.reply()
            || lane.binding.executor_id != route.identity().executor
            || lane.binding.receive_endpoint != route.endpoint()
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
            return Err(StoredReplyError::DispatchMismatch);
        }
        if query(route.identity().executor, call.reply()).map_err(StoredReplyError::Query)?
            != ReplyBindingObservation::BoundToTarget
        {
            return Err(StoredReplyError::BindingMismatch);
        }
        call.reply_owned(invoke).map_err(StoredReplyError::Ingress)
    }
}
