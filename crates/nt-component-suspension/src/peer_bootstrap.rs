//! Enter a real bootstrap dispatch before first execution, without a synthetic ready message.

use super::*;
use crate::{
    LaneBinding, LaneDispatchIdentity, LaneError, LanePhase, ReplyBindingObservation, StartupError,
};

#[cfg(test)]
#[path = "peer_bootstrap/tests.rs"]
mod tests;

impl<C, R, T> ComponentSuspensionLanes<C, R, T> {
    /// The physical startup owner has acknowledged fault endpoint installation and retains the
    /// stopped worker. Claim its real bootstrap epoch before native resume; first-Call adoption
    /// will transfer its initially Free Reply. This does not send or manufacture readiness.
    pub fn begin_bootstrap_dispatch<E>(
        &mut self,
        route: PeerRoute,
        peers: &PeerRegistry,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<LaneDispatchIdentity, StartupError<E>> {
        if self.execution_busy() {
            return Err(StartupError::Lane(LaneError::Busy));
        }
        if peers
            .resolve_lane(
                route.badge(),
                route.identity().domain,
                route.identity().domain_generation,
                self,
            )
            .ok()
            != Some(route)
        {
            return Err(StartupError::BindingMismatch);
        }
        let handle = route.identity().lane;
        let lane = self.lane(handle).map_err(StartupError::Lane)?;
        if lane.shared_peer != Some(route) {
            return Err(StartupError::BindingMismatch);
        }
        if lane.phase != LanePhase::Staged
            || lane.dispatch.is_some()
            || lane.terminal.is_some()
            || !lane.suspensions.is_empty()
            || !lane.external_tokens.is_empty()
        {
            return Err(StartupError::Lane(LaneError::InvalidPhase));
        }
        if query(lane.binding.executor_id, lane.binding.reply_object)
            .map_err(StartupError::Query)?
            != ReplyBindingObservation::Free
        {
            return Err(StartupError::BindingMismatch);
        }
        let epoch = crate::NEXT_DISPATCH_EPOCH
            .fetch_update(
                core::sync::atomic::Ordering::Relaxed,
                core::sync::atomic::Ordering::Relaxed,
                |next| {
                    if next == 0 {
                        None
                    } else {
                        next.checked_add(1)
                    }
                },
            )
            .map_err(|_| StartupError::Lane(LaneError::NoCapacity))?;
        let dispatch = LaneDispatchIdentity {
            lane: handle,
            epoch,
        };
        let lane = self.lane_mut(handle).expect("validated bootstrap lane");
        lane.dispatch = Some(dispatch);
        lane.bootstrap_dispatch = Some((dispatch, lane.binding.reply_object));
        lane.phase = LanePhase::Running;
        self.running = Some(handle);
        Ok(dispatch)
    }
}

impl PeerInstallation {
    /// Same installation proof as ordinary startup, but the provider executes a genuine first
    /// dispatch (for example DriverEntry) before it can issue its first retained Call. Every
    /// resume error keeps the allocated epoch and entered owner, and never permits resume replay.
    pub fn start_bootstrap<C, R, T, Q, E>(
        &mut self,
        peers: &PeerRegistry,
        domain: u64,
        generation: u64,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        binding: LaneBinding,
        space: PeerSpaceBinding,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, Q>,
        resume: impl FnOnce(u64) -> Result<(), E>,
    ) -> Result<LaneDispatchIdentity, PeerStartupError<Q, E>> {
        if self.phase != PeerInstallationPhase::SpaceBound {
            return Err(PeerStartupError::InvalidPhase);
        }
        let route = peers
            .resolve_lane(self.route.badge(), domain, generation, lanes)
            .map_err(PeerStartupError::Route)?;
        let lane = lanes
            .lane(route.identity().lane)
            .map_err(|error| PeerStartupError::Route(PeerLaneError::Lane(error)))?;
        if route != self.route
            || lane.shared_peer != Some(route)
            || lane.binding != binding
            || self.space_binding != Some(space)
            || space.executor != binding.executor_id
        {
            return Err(PeerStartupError::BindingMismatch);
        }
        let dispatch = lanes
            .begin_bootstrap_dispatch(route, peers, query)
            .map_err(PeerStartupError::Startup)?;
        self.phase = PeerInstallationPhase::Resuming;
        resume(binding.executor_id).map_err(PeerStartupError::Resume)?;
        self.phase = PeerInstallationPhase::ResumeAcknowledged;
        Ok(dispatch)
    }
}
