//! Adopt an authenticated retained Call's Reply into its canonical idle execution lane.

use crate::peer_registry::{PeerError, PeerRegistry};
use crate::{
    ComponentSuspensionLanes, LaneDispatchIdentity, LaneError, LaneHandle, LanePhase,
    PeerLaneError, ReplyBindingObservation, RetainedIngress,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedDispatchError<E> {
    NotHeld,
    Peer(PeerLaneError),
    Lane(LaneError),
    ReplyInUse,
    OldReplyNotFree,
    BindingMismatch,
    Query(E),
    NotAdmitted,
    DispatchMismatch,
}

/// The displaced Reply was proven Free. The incoming Reply remains canonical after dispatch;
/// even an acknowledged ingress returned by `RetainedIngress::finish` cannot receive on it until
/// another canonical ownership transition displaces it. This receipt does not release the peer.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "retain ownership of the displaced free Reply"]
pub struct RetainedDispatch {
    pub lane: LaneHandle,
    pub dispatch: LaneDispatchIdentity,
    pub displaced_reply: u64,
}

impl<C, R, T> ComponentSuspensionLanes<C, R, T> {
    /// Adopt a retained Call and start its lane without any native effect between the final
    /// binding proof and mutation. Keep `retained` alive through execution and completion; this
    /// borrow neither consumes nor duplicates its peer/Reply ownership.
    /// Complete this dispatch with `finish_retained_dispatch`, not the untracked `finish_dispatch`.
    /// External continuations must use `retire_external_running` before retained completion;
    /// `complete_external` would discard the epoch needed to release the retained owner.
    ///
    /// The adapter must validate physical/domain lifetimes and exclude aliases held by other
    /// tables or non-component owners before calling. `query_binding` must only observe the exact
    /// executor/Reply pair, without changing canonical ownership or invoking unrelated work.
    /// All refusals preserve the retained Call, canonical binding, phase and dispatch identity.
    pub fn begin_retained_dispatch<M, E>(
        &mut self,
        peers: &PeerRegistry,
        retained: &mut RetainedIngress<M>,
        domain: u64,
        domain_generation: u64,
        query_binding: impl FnMut(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<RetainedDispatch, RetainedDispatchError<E>> {
        self.begin_retained_dispatch_with_counter(
            peers,
            retained,
            domain,
            domain_generation,
            query_binding,
            &crate::NEXT_DISPATCH_EPOCH,
        )
    }

    fn begin_retained_dispatch_with_counter<M, E>(
        &mut self,
        peers: &PeerRegistry,
        retained: &mut RetainedIngress<M>,
        domain: u64,
        domain_generation: u64,
        mut query_binding: impl FnMut(u64, u64) -> Result<ReplyBindingObservation, E>,
        counter: &core::sync::atomic::AtomicU64,
    ) -> Result<RetainedDispatch, RetainedDispatchError<E>> {
        if !retained.is_held() {
            return Err(RetainedDispatchError::NotHeld);
        }
        let route = retained.route();
        let resolved = peers
            .resolve_lane(route.badge(), domain, domain_generation, self)
            .map_err(RetainedDispatchError::Peer)?;
        if resolved != route {
            return Err(RetainedDispatchError::Peer(PeerLaneError::Peer(
                PeerError::WrongOwner,
            )));
        }
        let handle = route.identity().lane;
        if self.execution_busy() {
            return Err(RetainedDispatchError::Lane(LaneError::Busy));
        }
        let lane = self.lane(handle).map_err(RetainedDispatchError::Lane)?;
        if lane.phase != LanePhase::Idle
            || lane.dispatch.is_some()
            || !lane.external_tokens.is_empty()
            || !lane.suspensions.is_empty()
        {
            return Err(RetainedDispatchError::Lane(LaneError::InvalidPhase));
        }
        let old = lane.binding;
        let incoming = retained.reply();
        if self.slots.iter().any(|slot| {
            slot.lane
                .as_ref()
                .is_some_and(|lane| lane.binding.reply_object == incoming)
        }) {
            return Err(RetainedDispatchError::ReplyInUse);
        }
        if query_binding(old.executor_id, old.reply_object).map_err(RetainedDispatchError::Query)?
            != ReplyBindingObservation::Free
        {
            return Err(RetainedDispatchError::OldReplyNotFree);
        }
        if query_binding(old.executor_id, incoming).map_err(RetainedDispatchError::Query)?
            != ReplyBindingObservation::BoundToTarget
        {
            return Err(RetainedDispatchError::BindingMismatch);
        }
        self.begin_dispatch_with_counter(handle, old.reply_object, counter)
            .map_err(RetainedDispatchError::Lane)?;
        let lane = self.lane_mut(handle).expect("admitted canonical lane");
        lane.binding.reply_object = incoming;
        let dispatch = lane.dispatch.expect("admitted dispatch identity");
        retained.admitted = Some(dispatch);
        Ok(RetainedDispatch {
            lane: handle,
            dispatch,
            displaced_reply: old.reply_object,
        })
    }

    /// End only the exact admitted execution. Reply acknowledgement alone never permits peer
    /// release while this dispatch, a suspension or an external continuation still owns the lane.
    pub fn finish_retained_dispatch<M>(
        &mut self,
        retained: &mut RetainedIngress<M>,
    ) -> Result<(), RetainedDispatchError<core::convert::Infallible>> {
        let dispatch = retained
            .admitted
            .ok_or(RetainedDispatchError::NotAdmitted)?;
        if self
            .active_dispatch_identity(dispatch.lane)
            .map_err(RetainedDispatchError::Lane)?
            != Some(dispatch)
        {
            return Err(RetainedDispatchError::DispatchMismatch);
        }
        self.finish_dispatch(dispatch.lane, retained.reply())
            .map_err(RetainedDispatchError::Lane)?;
        retained.admitted = None;
        Ok(())
    }
}

#[cfg(test)]
#[path = "retained_dispatch_tests.rs"]
mod tests;
