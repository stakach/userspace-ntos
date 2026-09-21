//! Join acknowledged capability installation to exclusive, one-shot worker startup.

use super::*;
use crate::{LaneBinding, ReplyBindingObservation, StartupError};

#[cfg(test)]
#[path = "peer_startup_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerStartupError<Q, R> {
    InvalidPhase,
    BindingMismatch,
    Route(PeerLaneError),
    Startup(StartupError<Q>),
    Resume(R),
}

impl PeerInstallation {
    /// The adapter independently authenticates and retains the exact stopped physical worker,
    /// domain generation, CSpace, VSpace, Reply and scheduler. Callbacks are synchronous and
    /// cannot reenter scheduling or ownership. A resume error is indeterminate: both the entered
    /// installation and startup execution fence remain owned, with no retry or alias recycling.
    /// Resume acknowledgment is not readiness; the retained ready protocol releases the fence.
    pub fn start<C, R, T, Q, E>(
        &mut self,
        peers: &PeerRegistry,
        domain: u64,
        generation: u64,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        binding: LaneBinding,
        space: PeerSpaceBinding,
        query: impl FnMut(u64, u64) -> Result<ReplyBindingObservation, Q>,
        resume: impl FnOnce(u64) -> Result<(), E>,
    ) -> Result<(), PeerStartupError<Q, E>> {
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
        lanes
            .begin_startup(route.identity().lane, binding.reply_object, query)
            .map_err(PeerStartupError::Startup)?;
        self.phase = PeerInstallationPhase::Resuming;
        resume(binding.executor_id).map_err(PeerStartupError::Resume)?;
        self.phase = PeerInstallationPhase::ResumeAcknowledged;
        Ok(())
    }
}
