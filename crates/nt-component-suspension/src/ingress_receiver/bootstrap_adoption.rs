//! First retained Call ownership for a physical bootstrap dispatch already in progress.

use super::*;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapAdoptionError<E> {
    PendingReply,
    WrongOwner,
    AlreadyAdmitted,
    ReplyInUse,
    NotHeld,
    OldReplyNotFree,
    IncomingNotBound,
    Query(E),
    Store(RetainedWorkError),
}

impl<M> IngressReceiver<M> {
    /// Adopt the first authenticated Call without inventing readiness or starting another epoch.
    /// The adapter proves physical worker/domain lifetime, incoming protocol, and exclusion of
    /// Replies in other owners. Queries must be observational and nonreentrant. Every refusal
    /// leaves the lane, retained Call and pending slot unchanged. Running semantic frames/tokens
    /// survive unchanged; entered terminal ownership is excluded by execution validation.
    pub fn adopt_bootstrap_call<C, R, T, E>(
        &mut self,
        route: PeerRoute,
        dispatch: crate::LaneDispatchIdentity,
        incoming_reply: u64,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        peers: &PeerRegistry,
        pending: &mut Option<ComponentIngress<M>>,
        mut query: impl FnMut(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(), BootstrapAdoptionError<E>> {
        if pending.is_some() {
            return Err(BootstrapAdoptionError::PendingReply);
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
            return Err(BootstrapAdoptionError::WrongOwner);
        }
        let lane = lanes
            .lane(route.identity().lane)
            .map_err(|_| BootstrapAdoptionError::WrongOwner)?;
        if dispatch.lane() != route.identity().lane
            || lane.shared_peer != Some(route)
            || lane.dispatch != Some(dispatch)
            || lane.terminal.is_some()
            || lane.binding.executor_id != route.identity().executor
            || lane.binding.receive_endpoint != route.endpoint()
        {
            return Err(BootstrapAdoptionError::WrongOwner);
        }
        if self.store.excludes_bootstrap_dispatch(dispatch) {
            return Err(BootstrapAdoptionError::AlreadyAdmitted);
        }
        if lane.bootstrap_dispatch != Some((dispatch, lane.binding.reply_object)) {
            return Err(BootstrapAdoptionError::WrongOwner);
        }
        let old_reply = lane.binding.reply_object;
        if self.excludes_reply(old_reply)
            || lanes.slots.iter().any(|slot| {
                slot.lane
                    .as_ref()
                    .is_some_and(|lane| lane.binding.reply_object == incoming_reply)
            })
        {
            return Err(BootstrapAdoptionError::ReplyInUse);
        }
        let incoming = self
            .store
            .stored_reply(route, incoming_reply)
            .map_err(BootstrapAdoptionError::Store)?;
        if !incoming.is_held() {
            return Err(BootstrapAdoptionError::NotHeld);
        }
        let displaced = ComponentIngress::new(self.endpoint(), old_reply)
            .map_err(|_| BootstrapAdoptionError::WrongOwner)?;
        if query(route.identity().executor, old_reply).map_err(BootstrapAdoptionError::Query)?
            != ReplyBindingObservation::Free
        {
            return Err(BootstrapAdoptionError::OldReplyNotFree);
        }
        if query(route.identity().executor, incoming_reply)
            .map_err(BootstrapAdoptionError::Query)?
            != ReplyBindingObservation::BoundToTarget
        {
            return Err(BootstrapAdoptionError::IncomingNotBound);
        }
        // No effect or allocation follows the final binding proof; publish all three owners in
        // this single nonreentrant transition. The retained payload and peer charge never move.
        self.store
            .stored_reply_mut(route, incoming_reply)
            .expect("preflight held Call")
            .admitted = Some(dispatch);
        let lane = lanes
            .lane_mut(route.identity().lane)
            .expect("preflight running lane");
        lane.binding.reply_object = incoming_reply;
        lane.bootstrap_dispatch = None;
        *pending = Some(displaced);
        Ok(())
    }
}
