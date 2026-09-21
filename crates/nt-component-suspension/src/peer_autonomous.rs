//! One-shot startup for autonomous producers without a readiness or dispatch loop.

use super::*;
use crate::{LaneBinding, LanePhase, ReplyBindingObservation, StartupError};

impl PeerInstallation {
    /// Authenticate the stopped physical source before a one-shot resume. The caller retains
    /// all physical resources and excludes reentrant root receive during the effect. Successful
    /// resume makes this source eligible for its first independently authenticated service Call,
    /// not "ready" for dispatch. No execution epoch or readiness message is synthesized.
    /// An uncertain resume keeps Staged and Resuming; no Call admission or replay is authorized.
    pub fn start_autonomous<C, R, T, Q, E>(
        &mut self,
        peers: &PeerRegistry,
        domain: u64,
        generation: u64,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        binding: LaneBinding,
        space: PeerSpaceBinding,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, Q>,
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
        if lane.phase != LanePhase::Staged
            || lane.dispatch.is_some()
            || lane.bootstrap_dispatch.is_some()
            || lane.terminal.is_some()
            || !lane.suspensions.is_empty()
            || !lane.external_tokens.is_empty()
        {
            return Err(PeerStartupError::InvalidPhase);
        }
        if query(binding.executor_id, binding.reply_object)
            .map_err(|error| PeerStartupError::Startup(StartupError::Query(error)))?
            != ReplyBindingObservation::Free
        {
            return Err(PeerStartupError::BindingMismatch);
        }
        self.phase = PeerInstallationPhase::Resuming;
        resume(binding.executor_id).map_err(PeerStartupError::Resume)?;
        lanes
            .lane_mut(route.identity().lane)
            .expect("preflight autonomous source")
            .phase = LanePhase::Idle;
        self.phase = PeerInstallationPhase::ResumeAcknowledged;
        Ok(())
    }
}

#[cfg(test)]
#[path = "peer_autonomous/tests.rs"]
mod tests;
