//! Canonical lane checks for shared-ingress peer publication and dispatch admission.
//!
//! Lane handles are table-local. The adapter's physical domain generation must cover the
//! canonical table lifetime, including replacement, not just equality of reused capability slots.

use crate::peer_registry::{
    PeerError, PeerIdentity, PeerRegistration, PeerRegistry, PeerRetention, PeerRoute,
};
use crate::{ComponentSuspensionLanes, LaneError, LaneHandle};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerLaneError {
    Peer(PeerError),
    Lane(LaneError),
}

impl PeerRegistry {
    /// Derive the executor from the canonical lane, not a separately supplied TCB value.
    /// The native adapter must supply the current canonical physical domain identity.
    pub fn stage_lane<C, R, T>(
        &mut self,
        domain: u64,
        domain_generation: u64,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        lane: LaneHandle,
    ) -> Result<PeerRegistration, PeerLaneError> {
        let binding = lanes.binding(lane).map_err(PeerLaneError::Lane)?;
        if binding.receive_endpoint != self.endpoint() {
            return Err(PeerLaneError::Peer(PeerError::WrongOwner));
        }
        self.stage(PeerIdentity {
            domain,
            domain_generation,
            executor: binding.executor_id,
            lane,
        })
        .map_err(PeerLaneError::Peer)
    }

    fn validate_lane<C, R, T>(
        &self,
        route: PeerRoute,
        domain: u64,
        domain_generation: u64,
        lanes: &ComponentSuspensionLanes<C, R, T>,
    ) -> Result<(), PeerLaneError> {
        self.state(route).map_err(PeerLaneError::Peer)?;
        let identity = route.identity();
        if domain == 0
            || domain_generation == 0
            || identity.domain != domain
            || identity.domain_generation != domain_generation
        {
            return Err(PeerLaneError::Peer(PeerError::WrongOwner));
        }
        let binding = lanes.binding(identity.lane).map_err(PeerLaneError::Lane)?;
        if binding.executor_id != identity.executor || binding.receive_endpoint != route.endpoint()
        {
            return Err(PeerLaneError::Peer(PeerError::WrongOwner));
        }
        Ok(())
    }

    /// Capability installation may have performed other work since staging. Revalidate before
    /// publication; refusal preserves the staged registration for explicit cleanup.
    pub fn publish_lane<C, R, T>(
        &mut self,
        registration: &mut PeerRegistration,
        domain: u64,
        domain_generation: u64,
        lanes: &ComponentSuspensionLanes<C, R, T>,
    ) -> Result<PeerRoute, PeerLaneError> {
        let route = registration
            .route()
            .ok_or(PeerLaneError::Peer(PeerError::WrongOwner))?;
        self.validate_lane(route, domain, domain_generation, lanes)?;
        self.publish(registration).map_err(PeerLaneError::Peer)
    }

    /// Resolve only active peers whose domain, lane generation, executor and endpoint still match.
    /// This does not inspect a kernel Reply binding, retain a TCB capability, or claim execution.
    pub fn resolve_lane<C, R, T>(
        &self,
        badge: u64,
        domain: u64,
        domain_generation: u64,
        lanes: &ComponentSuspensionLanes<C, R, T>,
    ) -> Result<PeerRoute, PeerLaneError> {
        let route = self
            .resolve(badge)
            .ok_or(PeerLaneError::Peer(PeerError::WrongOwner))?;
        self.validate_lane(route, domain, domain_generation, lanes)?;
        Ok(route)
    }
}

impl<C, R, T> ComponentSuspensionLanes<C, R, T> {
    /// Validate retained work and claim its lane without an intervening native effect. The Reply
    /// must be the independently authenticated canonical lane Reply, not an outer ingress Reply.
    /// Keep the retention ticket until completion/cancellation; admission does not consume it.
    /// Existing physical exclusion and exact dispatch-epoch allocation remain authoritative.
    pub fn begin_peer_dispatch(
        &mut self,
        peers: &PeerRegistry,
        retention: &PeerRetention,
        domain: u64,
        domain_generation: u64,
        reply: u64,
    ) -> Result<LaneHandle, PeerLaneError> {
        let route = retention
            .route()
            .ok_or(PeerLaneError::Peer(PeerError::WrongOwner))?;
        let resolved = peers.resolve_lane(route.badge(), domain, domain_generation, self)?;
        if resolved != route {
            return Err(PeerLaneError::Peer(PeerError::WrongOwner));
        }
        let lane = route.identity().lane;
        self.begin_dispatch(lane, reply)
            .map_err(PeerLaneError::Lane)?;
        Ok(lane)
    }
}

#[cfg(test)]
#[path = "lane_peer_tests.rs"]
mod tests;
