//! Canonical lane checks for shared-ingress peer publication and dispatch admission.
//!
//! Lane handles are table-local. The adapter's physical domain generation must cover the
//! canonical table lifetime, including replacement, not just equality of reused capability slots.

use crate::peer_registry::{
    PeerError, PeerIdentity, PeerRegistration, PeerRegistry, PeerRetention, PeerRoute,
};
use crate::{ComponentSuspensionLanes, LaneBinding, LaneError, LaneHandle, LanePhase};

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
        if lanes
            .lane(identity.lane)
            .map_err(PeerLaneError::Lane)?
            .shared_peer
            .is_some_and(|canonical| canonical != route)
        {
            return Err(PeerLaneError::Peer(PeerError::WrongOwner));
        }
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
    /// Reserve a stopped shared-endpoint lane and its exact peer identity together, before any
    /// native capability effects. The caller retains the registration through mint/publication.
    /// This grants no startup or dispatch authority and never mixes private and shared lanes on
    /// one endpoint. Physical domain generations must cover the entire table lifetime.
    pub fn allocate_shared_staged(
        &mut self,
        peers: &mut PeerRegistry,
        domain: u64,
        domain_generation: u64,
        binding: LaneBinding,
    ) -> Result<(LaneHandle, PeerRegistration), PeerLaneError> {
        if domain == 0 || domain_generation == 0 || binding.receive_endpoint != peers.endpoint() {
            return Err(PeerLaneError::Peer(PeerError::WrongOwner));
        }
        for slot in &self.slots {
            let Some(lane) = &slot.lane else { continue };
            if lane.binding.receive_endpoint != binding.receive_endpoint {
                continue;
            }
            let route = lane
                .shared_peer
                .ok_or(PeerLaneError::Lane(LaneError::DuplicateBinding))?;
            let identity = route.identity();
            peers.validate_lane(route, identity.domain, identity.domain_generation, self)?;
            if peers.state(route).map_err(PeerLaneError::Peer)?.0
                == crate::peer_registry::PeerPhase::Retiring
            {
                return Err(PeerLaneError::Peer(PeerError::WrongPhase));
            }
        }
        let lane = self
            .allocate_with_phase(binding, LanePhase::Staged, true)
            .map_err(PeerLaneError::Lane)?;
        match peers.stage_lane(domain, domain_generation, self, lane) {
            Ok(registration) => {
                self.slots[lane.index as usize]
                    .lane
                    .as_mut()
                    .unwrap()
                    .shared_peer = registration.route();
                Ok((lane, registration))
            }
            Err(error) => {
                // No capability effect or caller-visible handle exists yet. Keep the consumed
                // slot generation so a failed reservation can never alias a later lane.
                self.slots[lane.index as usize].lane = None;
                Err(error)
            }
        }
    }

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
