//! Cancel transport only after a retained installation acknowledged the exact physical stop.

use super::*;
use crate::peer_registry::PeerPhase;
use crate::{LanePhase, PeerInstallation, PeerInstallationPhase, PeerRetirementPhase};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoppedRouteError<E> {
    WrongOwner,
    NotStopped,
    Busy,
    SemanticOwners,
    OutputOccupied,
    NoCapacity,
    NotFree,
    Query(E),
}

/// Canceled transport payload, not a provider success or permission to repeat uncertain work.
/// `reply` is None for the canonical Reply, whose sole owner remains the exact lane. Keep every
/// other Reply here until its insertion into the native spare pool is acknowledged.
#[must_use = "retain canceled payloads and recycle owned Replies explicitly"]
pub struct CancelledStoppedCall<M> {
    pub reply: Option<ComponentIngress<M>>,
    pub message: M,
}

impl<M> IngressReceiver<M> {
    /// The installation's Retiring(Stopped) phase is sealed stop-ACK authority. Querying Free
    /// alone can never cancel a Call. Root must authenticate and retain physical lifetimes and
    /// drain queued arrivals separately before releasing aliases. Any pending receive, checked
    /// out Call or semantic continuation refuses. All binding queries and output allocation
    /// finish before mutation; query failure leaves Calls, epochs, attempts and aliases intact.
    /// On success uncertain Reply attempts are canceled, not replayed or marked acknowledged.
    pub fn cancel_stopped_route<C, R, T, E>(
        &mut self,
        installation: &PeerInstallation,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        peers: &mut PeerRegistry,
        output: &mut Vec<CancelledStoppedCall<M>>,
        mut query: impl FnMut(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(), StoppedRouteError<E>> {
        if !output.is_empty() {
            return Err(StoppedRouteError::OutputOccupied);
        }
        if installation.phase() != PeerInstallationPhase::Retiring(PeerRetirementPhase::Stopped) {
            return Err(StoppedRouteError::NotStopped);
        }
        let route = installation.route();
        if self.endpoint() != route.endpoint() {
            return Err(StoppedRouteError::WrongOwner);
        }
        if self.phase().is_some() {
            return Err(StoppedRouteError::Busy);
        }
        let (phase, retained) = peers
            .state(route)
            .map_err(|_| StoppedRouteError::WrongOwner)?;
        if phase != PeerPhase::Retiring {
            return Err(StoppedRouteError::WrongOwner);
        }
        let lane = lanes
            .lane(route.identity().lane)
            .map_err(|_| StoppedRouteError::WrongOwner)?;
        if lane.shared_peer != Some(route)
            || lane.binding.executor_id != route.identity().executor
            || lane.binding.receive_endpoint != route.endpoint()
        {
            return Err(StoppedRouteError::WrongOwner);
        }
        if lane.terminal.is_some()
            || !lane.suspensions.is_empty()
            || !lane.external_tokens.is_empty()
        {
            return Err(StoppedRouteError::SemanticOwners);
        }
        if !matches!(
            lane.phase,
            LanePhase::Staged
                | LanePhase::Idle
                | LanePhase::Starting
                | LanePhase::Running
                | LanePhase::Suspended
        ) || (matches!(lane.phase, LanePhase::Starting | LanePhase::Running)
            && lanes.running != Some(route.identity().lane))
        {
            return Err(StoppedRouteError::Busy);
        }
        let count = self.store.stopped_route_count(route)?;
        if count != retained {
            return Err(StoppedRouteError::WrongOwner);
        }
        let canonical = lane.binding.reply_object;
        if self.reply() == canonical {
            return Err(StoppedRouteError::WrongOwner);
        }
        for reply in core::iter::once(canonical).chain(self.store.stopped_route_replies(route)) {
            if lanes.slots.iter().enumerate().any(|(index, slot)| {
                slot.lane.as_ref().is_some_and(|other| {
                    index != route.identity().lane.index as usize
                        && other.binding.reply_object == reply
                })
            }) {
                return Err(StoppedRouteError::WrongOwner);
            }
        }
        output
            .try_reserve_exact(count)
            .map_err(|_| StoppedRouteError::NoCapacity)?;
        if query(route.identity().executor, canonical).map_err(StoppedRouteError::Query)?
            != ReplyBindingObservation::Free
        {
            return Err(StoppedRouteError::NotFree);
        }
        for reply in self
            .store
            .stopped_route_replies(route)
            .filter(|reply| *reply != canonical)
        {
            if query(route.identity().executor, reply).map_err(StoppedRouteError::Query)?
                != ReplyBindingObservation::Free
            {
                return Err(StoppedRouteError::NotFree);
            }
        }
        self.store
            .drain_stopped_route(route, canonical, peers, output);
        let lane = lanes
            .lane_mut(route.identity().lane)
            .expect("preflight stopped lane");
        lane.phase = LanePhase::Idle;
        lane.dispatch = None;
        lane.bootstrap_dispatch = None;
        if lanes.running == Some(route.identity().lane) {
            lanes.running = None;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
