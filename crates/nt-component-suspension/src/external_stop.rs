//! Explicit semantic cancellation after acknowledged physical stop, never successful delivery.

use crate::peer_registry::{PeerPhase, PeerRegistry};
use crate::{
    ComponentSuspensionLanes, LaneDispatchIdentity, LaneError, LanePhase, PeerInstallation,
    PeerInstallationPhase, PeerRetirementPhase,
};

impl<C, R, T> ComponentSuspensionLanes<C, R, T> {
    /// The adapter must independently establish cancellation of the native wait (thread
    /// termination/provider unload), not ordinary successful completion. A retained stop ACK
    /// permits canceling exactly the top external owner, never typed frames or terminal work.
    /// Preserve Suspended and the transport epoch for `IngressReceiver::cancel_stopped_route`.
    /// No Reply is sent, no effect is replayed, and unrelated execution ownership is unchanged.
    pub fn cancel_external_stopped(
        &mut self,
        installation: &PeerInstallation,
        peers: &PeerRegistry,
        dispatch: LaneDispatchIdentity,
        token: u64,
    ) -> Result<(), LaneError> {
        if installation.phase() != PeerInstallationPhase::Retiring(PeerRetirementPhase::Stopped) {
            return Err(LaneError::InvalidPhase);
        }
        let route = installation.route();
        if token == 0
            || route.identity().lane != dispatch.lane()
            || !matches!(peers.state(route), Ok((PeerPhase::Retiring, _)))
        {
            return Err(LaneError::InvalidIdentity);
        }
        let lane = self.lane(dispatch.lane())?;
        if lane.shared_peer != Some(route)
            || lane.dispatch != Some(dispatch)
            || lane.binding.executor_id != route.identity().executor
            || lane.binding.receive_endpoint != route.endpoint()
        {
            return Err(LaneError::InvalidIdentity);
        }
        if lane.phase != LanePhase::Suspended
            || self.running == Some(dispatch.lane())
            || lane.external_tokens.last().copied() != Some(token)
            || !lane.suspensions.is_empty()
            || lane.terminal.is_some()
        {
            return Err(LaneError::InvalidPhase);
        }
        self.lane_mut(dispatch.lane())
            .expect("validated stopped external owner")
            .external_tokens
            .pop();
        Ok(())
    }
}
