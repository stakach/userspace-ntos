//! Retained capability installation ownership before a staged peer becomes routable.

use core::convert::Infallible;

use crate::peer_registry::{PeerError, PeerRegistration, PeerRegistry, PeerRoute};
use crate::{ComponentSuspensionLanes, PeerLaneError};

#[cfg(test)]
#[path = "peer_installation_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerInstallationPhase {
    Reserved,
    Installing,
    Installed,
    Published,
    Deleting,
    Deleted,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerInstallationError<E> {
    InvalidSlot,
    InvalidPhase,
    Peer(PeerError),
    Lane(PeerLaneError),
    Invoke(E),
}

/// Owns the registration ticket and a preallocated root-CSpace destination slot. The adapter must
/// exclusively retain that initially empty root slot and validate its namespace, physical lifetime,
/// endpoint capability and executor before effects. Callbacks are synchronous and must not
/// reenter registration, scheduling, or capability ownership. Errors preserve all ownership;
/// entered operations cannot replay without a future explicit reconciliation protocol.
/// Drop does not delete a capability, release a slot, or remove a route.
#[must_use = "retain peer capability ownership through publication or acknowledged abort"]
pub struct PeerInstallation {
    registration: PeerRegistration,
    route: PeerRoute,
    destination_slot: u64,
    phase: PeerInstallationPhase,
}

impl PeerInstallation {
    pub fn new(
        registration: PeerRegistration,
        destination_slot: u64,
    ) -> Result<Self, (PeerInstallationError<Infallible>, PeerRegistration)> {
        let Some(route) = registration.route() else {
            return Err((
                PeerInstallationError::Peer(PeerError::WrongOwner),
                registration,
            ));
        };
        if destination_slot == 0
            || destination_slot == route.endpoint()
            || destination_slot == route.identity().executor
        {
            return Err((PeerInstallationError::InvalidSlot, registration));
        }
        Ok(Self {
            registration,
            route,
            destination_slot,
            phase: PeerInstallationPhase::Reserved,
        })
    }

    pub const fn phase(&self) -> PeerInstallationPhase {
        self.phase
    }

    /// Historical routing metadata, not independent capability or execution authority.
    pub const fn route(&self) -> PeerRoute {
        self.route
    }

    /// Slot attribution only; this does not authorize deletion or recycling.
    pub const fn slot(&self) -> u64 {
        self.destination_slot
    }

    /// Create only the root-owned unpublished endpoint alias at this slot. Do not copy or export
    /// it into a child CSpace before publication; that would escape this staged cleanup owner.
    pub fn install<E>(
        &mut self,
        install: impl FnOnce(PeerRoute, u64) -> Result<(), E>,
    ) -> Result<(), PeerInstallationError<E>> {
        if self.phase != PeerInstallationPhase::Reserved {
            return Err(PeerInstallationError::InvalidPhase);
        }
        self.phase = PeerInstallationPhase::Installing;
        install(self.route, self.destination_slot).map_err(PeerInstallationError::Invoke)?;
        self.phase = PeerInstallationPhase::Installed;
        Ok(())
    }

    /// Revalidate the exact canonical lane after acknowledged native capability installation.
    /// Publication retains this capability owner; active-route retirement is a separate protocol.
    pub fn publish<C, R, T>(
        &mut self,
        peers: &mut PeerRegistry,
        domain: u64,
        domain_generation: u64,
        lanes: &ComponentSuspensionLanes<C, R, T>,
    ) -> Result<PeerRoute, PeerInstallationError<Infallible>> {
        if self.phase != PeerInstallationPhase::Installed {
            return Err(PeerInstallationError::InvalidPhase);
        }
        let route = peers
            .publish_lane(&mut self.registration, domain, domain_generation, lanes)
            .map_err(PeerInstallationError::Lane)?;
        self.phase = PeerInstallationPhase::Published;
        Ok(route)
    }

    /// Delete an installed staged capability or acknowledge its never-installed empty slot.
    /// The adapter must preserve sole unpublished-alias provenance: no copied capability aliases
    /// or in-flight use may escape this owner. A delete ACK cannot retire unknown descendants.
    /// Installing uncertainty and published capabilities cannot use this abort path.
    pub fn delete_staged<E>(
        &mut self,
        delete: impl FnOnce(u64) -> Result<(), E>,
    ) -> Result<(), PeerInstallationError<E>> {
        if !matches!(
            self.phase,
            PeerInstallationPhase::Reserved | PeerInstallationPhase::Installed
        ) {
            return Err(PeerInstallationError::InvalidPhase);
        }
        self.phase = PeerInstallationPhase::Deleting;
        delete(self.destination_slot).map_err(PeerInstallationError::Invoke)?;
        self.phase = PeerInstallationPhase::Deleted;
        Ok(())
    }

    /// Remove only the exact staged route after native deletion ACK. The returned empty slot
    /// still requires independent checked recycling; the badge remains permanently burned.
    pub fn finish_abort(
        &mut self,
        peers: &mut PeerRegistry,
    ) -> Result<u64, PeerInstallationError<Infallible>> {
        if self.phase != PeerInstallationPhase::Deleted {
            return Err(PeerInstallationError::InvalidPhase);
        }
        peers
            .abort(&mut self.registration)
            .map_err(PeerInstallationError::Peer)?;
        self.phase = PeerInstallationPhase::Aborted;
        Ok(self.destination_slot)
    }
}
