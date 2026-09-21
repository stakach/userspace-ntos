//! Complete an external wait's Call without borrowing another provider's execution fence.

use super::*;

#[cfg(test)]
mod tests;

impl<M> IngressReceiver<M> {
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
