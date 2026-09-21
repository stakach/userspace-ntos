//! The first genuine bootstrap Call may itself be ordinary completion.

use super::*;
use crate::{LaneDispatchIdentity, LanePhase, ReceivedMessage};

impl IngressReceiver<ReceivedMessage> {
    /// End an untouched bootstrap dispatch whose first Call is its genuine final message. The
    /// sealed lane marker was created before native execution and is consumed by first-Call
    /// adoption, so missing retained work alone never supplies bootstrap authority. The adapter
    /// authenticates physical lifetime and supplies the configured ordinary completion label.
    /// The independently held completion remains stored; no Reply or synthetic ACK occurs.
    pub fn complete_bootstrap_from_message<C, R, T, E>(
        &mut self,
        route: PeerRoute,
        dispatch: LaneDispatchIdentity,
        completion_reply: u64,
        completion_label: u64,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        peers: &PeerRegistry,
        mut query: impl FnMut(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(), StoredCompletionError<E>> {
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
            || self.store.excludes_bootstrap_dispatch(dispatch)
        {
            return Err(StoredCompletionError::WrongOwner);
        }
        let lane = lanes
            .lane(route.identity().lane)
            .map_err(|_| StoredCompletionError::WrongOwner)?;
        let reply = lane.binding.reply_object;
        if lane.shared_peer != Some(route)
            || lane.dispatch != Some(dispatch)
            || lane.bootstrap_dispatch != Some((dispatch, reply))
            || dispatch.lane() != route.identity().lane
            || lane.binding.executor_id != route.identity().executor
            || lane.binding.receive_endpoint != route.endpoint()
            || reply == completion_reply
            || self.excludes_reply(reply)
            || lane.terminal.is_some()
            || !lane.external_tokens.is_empty()
            || !lane.suspensions.is_empty()
        {
            return Err(StoredCompletionError::WrongOwner);
        }
        let completion = self
            .store
            .stored_reply(route, completion_reply)
            .map_err(StoredCompletionError::Store)?;
        if !completion.is_held()
            || completion_label == 0
            || completion_label > (u64::MAX >> 12)
            || completion.message().badge() != route.badge()
            || completion.message().info() != completion_label << 12
        {
            return Err(StoredCompletionError::InvalidCompletionMessage);
        }
        if query(route.identity().executor, reply).map_err(StoredCompletionError::Query)?
            != ReplyBindingObservation::Free
        {
            return Err(StoredCompletionError::NotFree);
        }
        if query(route.identity().executor, completion_reply)
            .map_err(StoredCompletionError::Query)?
            != ReplyBindingObservation::BoundToTarget
        {
            return Err(StoredCompletionError::CompletionNotBound);
        }
        let lane = lanes
            .lane_mut(dispatch.lane())
            .expect("preflight bootstrap completion");
        lane.phase = LanePhase::Idle;
        lane.dispatch = None;
        lane.bootstrap_dispatch = None;
        lanes.running = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
