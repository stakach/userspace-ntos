//! Active peer retirement preserves physical aliases until acknowledged quiescence and drain.

use super::*;
use crate::peer_registry::PeerPhase;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRetirementPhase {
    AdmissionStopped,
    Stopping,
    Stopped,
    Drained,
    ClearingFault,
    FaultCleared,
    DeletingChild,
    ChildDeleted,
    DeletingRoot,
    RootDeleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRetirementEffect {
    StopExecutor(u64),
    ClearFaultHandler(PeerSpaceBinding),
    DeleteChildAlias(PeerCapabilityDestination),
    DeleteRootAlias(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRetirementError<E> {
    InvalidPhase,
    WrongOwner,
    NotDrained,
    Peer(PeerError),
    Lane(PeerLaneError),
    Invoke(E),
}

impl PeerInstallation {
    /// Block new route admission, without cancelling or dropping outstanding work. The adapter
    /// authenticates the live physical domain and retains all worker resources. This covers peers
    /// with known child and TCB bindings, including uncertain bind/resume; earlier construction
    /// failures require their separate construction owner. No native effect occurs here.
    pub fn begin_retirement<C, R, T>(
        &mut self,
        peers: &mut PeerRegistry,
        domain: u64,
        generation: u64,
        lanes: &ComponentSuspensionLanes<C, R, T>,
    ) -> Result<(), PeerRetirementError<Infallible>> {
        if !matches!(
            self.phase,
            PeerInstallationPhase::BindingSpace
                | PeerInstallationPhase::SpaceBound
                | PeerInstallationPhase::Resuming
                | PeerInstallationPhase::ResumeAcknowledged
        ) {
            return Err(PeerRetirementError::InvalidPhase);
        }
        if peers
            .resolve_lane(self.route.badge(), domain, generation, lanes)
            .map_err(PeerRetirementError::Lane)?
            != self.route
            || lanes
                .lane(self.route.identity().lane)
                .map_err(|error| PeerRetirementError::Lane(PeerLaneError::Lane(error)))?
                .shared_peer
                != Some(self.route)
            || self.space_binding.is_none()
            || self.exported_destination.is_none()
        {
            return Err(PeerRetirementError::WrongOwner);
        }
        peers
            .begin_retirement(self.route)
            .map_err(PeerRetirementError::Peer)?;
        self.phase = PeerInstallationPhase::Retiring(PeerRetirementPhase::AdmissionStopped);
        Ok(())
    }

    fn retirement_registry<E>(
        &self,
        peers: &PeerRegistry,
        drained: bool,
    ) -> Result<(), PeerRetirementError<E>> {
        let (phase, retained) = peers.state(self.route).map_err(PeerRetirementError::Peer)?;
        if phase != PeerPhase::Retiring {
            return Err(PeerRetirementError::WrongOwner);
        }
        if drained && retained != 0 {
            return Err(PeerRetirementError::NotDrained);
        }
        Ok(())
    }

    fn retirement_lane<C, R, T, E>(
        &self,
        lanes: &ComponentSuspensionLanes<C, R, T>,
    ) -> Result<(), PeerRetirementError<E>> {
        let handle = self.route.identity().lane;
        let lane = lanes
            .lane(handle)
            .map_err(|error| PeerRetirementError::Lane(PeerLaneError::Lane(error)))?;
        if lane.shared_peer != Some(self.route)
            || lane.binding.executor_id != self.route.identity().executor
            || lane.binding.receive_endpoint != self.route.endpoint()
        {
            return Err(PeerRetirementError::WrongOwner);
        }
        if lanes.running == Some(handle)
            || !matches!(
                lane.phase,
                crate::LanePhase::Staged | crate::LanePhase::Idle
            )
            || lane.dispatch.is_some()
            || !lane.suspensions.is_empty()
            || !lane.external_tokens.is_empty()
            || lane.terminal.is_some()
        {
            return Err(PeerRetirementError::NotDrained);
        }
        Ok(())
    }

    /// Execute one ordered physical effect, storing its entered state before invoking it.
    /// Callbacks are synchronous/nonreentrant and must validate exact capability lifetimes.
    /// Any error is uncertain and cannot replay. Stop acknowledgement proves physical inactivity,
    /// not NT cancellation or Reply release. ClearFaultHandler removes the TCB-owned derived cap
    /// without restarting it; deleting the child slot alone cannot do that. DeleteRootAlias targets
    /// the peer's minted slot, NEVER the shared endpoint. No capability slots may be recycled here.
    pub fn retire_effect<C, R, T, E>(
        &mut self,
        peers: &PeerRegistry,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        invoke: impl FnOnce(PeerRetirementEffect) -> Result<(), E>,
    ) -> Result<(), PeerRetirementError<E>> {
        use PeerRetirementPhase::*;
        let (entered, acknowledged, effect, drained) = match self.phase {
            PeerInstallationPhase::Retiring(AdmissionStopped) => (
                Stopping,
                Stopped,
                PeerRetirementEffect::StopExecutor(self.route.identity().executor),
                false,
            ),
            PeerInstallationPhase::Retiring(Drained) => (
                ClearingFault,
                FaultCleared,
                PeerRetirementEffect::ClearFaultHandler(
                    self.space_binding.expect("retiring binding"),
                ),
                true,
            ),
            PeerInstallationPhase::Retiring(FaultCleared) => (
                DeletingChild,
                ChildDeleted,
                PeerRetirementEffect::DeleteChildAlias(
                    self.exported_destination.expect("retiring destination"),
                ),
                true,
            ),
            PeerInstallationPhase::Retiring(ChildDeleted) => (
                DeletingRoot,
                RootDeleted,
                PeerRetirementEffect::DeleteRootAlias(self.destination_slot),
                true,
            ),
            _ => return Err(PeerRetirementError::InvalidPhase),
        };
        self.retirement_registry(peers, drained)?;
        if drained {
            self.retirement_lane(lanes)?;
        }
        self.phase = PeerInstallationPhase::Retiring(entered);
        invoke(effect).map_err(PeerRetirementError::Invoke)?;
        self.phase = PeerInstallationPhase::Retiring(acknowledged);
        Ok(())
    }

    /// The observational proof must establish all senders are stopped, queued arrivals and native
    /// continuations/Replies are drained, and no alias can introduce future traffic. Zero registry
    /// retention alone is insufficient. Keep those exclusions valid through final retirement;
    /// callbacks must not dispatch, release resources or reenter ownership. Refusal is retryable.
    /// Canonical dispatch, suspension, terminal and startup ownership must first be discharged
    /// through their own cancellation/retirement protocols; a physical stop cannot erase them.
    pub fn prove_retirement_drain<C, R, T, E>(
        &mut self,
        peers: &PeerRegistry,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        prove: impl FnOnce(PeerRoute) -> Result<bool, E>,
    ) -> Result<(), PeerRetirementError<E>> {
        if self.phase != PeerInstallationPhase::Retiring(PeerRetirementPhase::Stopped) {
            return Err(PeerRetirementError::InvalidPhase);
        }
        self.retirement_registry(peers, true)?;
        self.retirement_lane(lanes)?;
        if !prove(self.route).map_err(PeerRetirementError::Invoke)? {
            return Err(PeerRetirementError::NotDrained);
        }
        self.phase = PeerInstallationPhase::Retiring(PeerRetirementPhase::Drained);
        Ok(())
    }

    /// Remove only the route after all three known alias deletions acknowledged and a fresh
    /// observational proof confirms external drain/quiescence. Historical metadata stays retained.
    /// This does not free the canonical lane, worker, scheduling context, CSpace, VSpace or slots.
    pub fn finish_retirement<C, R, T, E>(
        &mut self,
        peers: &mut PeerRegistry,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        prove: impl FnOnce(PeerRoute) -> Result<bool, E>,
    ) -> Result<(), PeerRetirementError<E>> {
        if self.phase != PeerInstallationPhase::Retiring(PeerRetirementPhase::RootDeleted) {
            return Err(PeerRetirementError::InvalidPhase);
        }
        self.retirement_registry(peers, true)?;
        self.retirement_lane(lanes)?;
        if !prove(self.route).map_err(PeerRetirementError::Invoke)? {
            return Err(PeerRetirementError::NotDrained);
        }
        peers
            .finish_retirement(self.route)
            .map_err(PeerRetirementError::Peer)?;
        self.phase = PeerInstallationPhase::Retired;
        Ok(())
    }
}

#[cfg(test)]
#[path = "peer_retirement_tests.rs"]
mod tests;
