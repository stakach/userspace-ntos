//! Temporarily lend execution to another provider without retiring the parent Call.

use super::*;
use crate::{LaneDispatchIdentity, LanePhase};
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_SCOPE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NestedExecutionError<E> {
    WrongOwner,
    Busy,
    InvalidReplyState,
    BindingMismatch,
    NoCapacity,
    Consumed,
    Query(E),
}

/// No native effect is performed by this scope. The adapter must keep the parent stopped while
/// nested work runs, including after an ACK: a Free Reply alone does not stop its physical TCB.
/// Dropping this owner deliberately leaves the parent fenced, never implicitly resumable.
#[must_use = "retain and explicitly restore the parent execution scope"]
#[derive(Debug)]
pub struct NestedExecutionScope {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    sequence: u64,
    expected: ReplyBindingObservation,
    consumed: bool,
}

impl NestedExecutionScope {
    pub const fn dispatch(&self) -> LaneDispatchIdentity {
        self.dispatch
    }
    pub const fn route(&self) -> PeerRoute {
        self.route
    }
    pub const fn is_consumed(&self) -> bool {
        self.consumed
    }
}

impl<M> IngressReceiver<M> {
    fn nested_call_state<C, R, T>(
        &self,
        route: PeerRoute,
        dispatch: LaneDispatchIdentity,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        peers: &PeerRegistry,
    ) -> Result<(u64, ReplyBindingObservation), NestedExecutionError<core::convert::Infallible>>
    {
        let bad = NestedExecutionError::WrongOwner;
        if self.phase().is_some()
            || self.endpoint() != route.endpoint()
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
            return Err(bad);
        }
        let lane = lanes.lane(dispatch.lane()).map_err(|_| bad)?;
        if lane.shared_peer != Some(route)
            || lane.dispatch != Some(dispatch)
            || dispatch.lane() != route.identity().lane
            || lane.binding.executor_id != route.identity().executor
            || lane.binding.receive_endpoint != route.endpoint()
            || lane.terminal.is_some()
        {
            return Err(bad);
        }
        if lane.bootstrap_dispatch == Some((dispatch, lane.binding.reply_object))
            && !self.store.excludes_bootstrap_dispatch(dispatch)
            && !self.excludes_reply(lane.binding.reply_object)
        {
            return Ok((lane.binding.reply_object, ReplyBindingObservation::Free));
        }
        let call = self
            .store
            .stored_reply(route, lane.binding.reply_object)
            .map_err(|_| bad)?;
        if call.admitted != Some(dispatch) {
            return Err(bad);
        }
        let expected = if call.is_acknowledged() {
            ReplyBindingObservation::Free
        } else if call.is_admitted_held() {
            ReplyBindingObservation::BoundToTarget
        } else {
            return Err(NestedExecutionError::InvalidReplyState);
        };
        Ok((call.reply(), expected))
    }

    /// Park a canonical admitted Call or sealed bootstrap epoch, preserving semantic owners. Before
    /// calling, native code must exclude parent execution independently (Held Call, or an exact
    /// stopped pump continuation after ACK). An indeterminate Reply attempt cannot be parked.
    pub fn suspend_for_nested_execution<C, R, T, E>(
        &mut self,
        route: PeerRoute,
        dispatch: LaneDispatchIdentity,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        peers: &PeerRegistry,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<NestedExecutionScope, NestedExecutionError<E>> {
        if lanes
            .validate_ingress_execution(IngressExecutionOwner::Dispatch(dispatch))
            .is_err()
        {
            return Err(NestedExecutionError::WrongOwner);
        }
        let (reply, expected) = self
            .nested_call_state(route, dispatch, lanes, peers)
            .map_err(widen)?;
        if query(route.identity().executor, reply).map_err(NestedExecutionError::Query)? != expected
        {
            return Err(NestedExecutionError::BindingMismatch);
        }
        let sequence = NEXT_SCOPE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                if next == 0 {
                    None
                } else {
                    next.checked_add(1)
                }
            })
            .map_err(|_| NestedExecutionError::NoCapacity)?;
        lanes
            .lane_mut(dispatch.lane())
            .expect("preflight parent")
            .phase = LanePhase::NestedExecution(sequence);
        lanes.running = None;
        Ok(NestedExecutionScope {
            route,
            dispatch,
            reply,
            sequence,
            expected,
            consumed: false,
        })
    }

    /// Restore exactly once and in nesting order. Failed queries, active child execution and
    /// changed Calls keep both the scope and the parked epoch intact. No native resume occurs.
    pub fn resume_nested_execution<C, R, T, E>(
        &mut self,
        scope: &mut NestedExecutionScope,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        peers: &PeerRegistry,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(), NestedExecutionError<E>> {
        if scope.consumed {
            return Err(NestedExecutionError::Consumed);
        }
        if lanes.execution_busy() || lanes.slots.iter().any(|slot| slot.lane.as_ref()
            .is_some_and(|lane| matches!(lane.phase, LanePhase::NestedExecution(sequence) if sequence > scope.sequence))) {
            return Err(NestedExecutionError::Busy);
        }
        let (reply, expected) = self
            .nested_call_state(scope.route, scope.dispatch, lanes, peers)
            .map_err(widen)?;
        if lanes.phase(scope.dispatch.lane()) != Ok(LanePhase::NestedExecution(scope.sequence))
            || reply != scope.reply
            || expected != scope.expected
        {
            return Err(NestedExecutionError::WrongOwner);
        }
        if query(scope.route.identity().executor, reply).map_err(NestedExecutionError::Query)?
            != expected
        {
            return Err(NestedExecutionError::BindingMismatch);
        }
        lanes
            .lane_mut(scope.dispatch.lane())
            .expect("preflight parent")
            .phase = LanePhase::Running;
        lanes.running = Some(scope.dispatch.lane());
        scope.consumed = true;
        Ok(())
    }
}

fn widen<E>(error: NestedExecutionError<core::convert::Infallible>) -> NestedExecutionError<E> {
    match error {
        NestedExecutionError::WrongOwner => NestedExecutionError::WrongOwner,
        NestedExecutionError::InvalidReplyState => NestedExecutionError::InvalidReplyState,
        _ => unreachable!("nested Call validation returns only ownership errors"),
    }
}

#[cfg(test)]
mod tests;
