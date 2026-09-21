//! Retained capability installation ownership before a staged peer becomes routable.

use core::convert::Infallible;

use crate::peer_registry::{PeerError, PeerRegistration, PeerRegistry, PeerRoute};
use crate::{ComponentSuspensionLanes, PeerLaneError};

#[cfg(test)]
#[path = "peer_installation_tests.rs"]
mod tests;

#[path = "peer_startup.rs"]
mod startup;
pub use startup::PeerStartupError;

#[path = "peer_retirement.rs"]
mod retirement;
pub use retirement::{PeerRetirementEffect, PeerRetirementError, PeerRetirementPhase};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerInstallationPhase {
    Reserved,
    Installing,
    Installed,
    Published,
    Exporting,
    Exported,
    BindingSpace,
    SpaceBound,
    Resuming,
    ResumeAcknowledged,
    Retiring(PeerRetirementPhase),
    Retired,
    Deleting,
    Deleted,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerInstallationError<E> {
    InvalidSlot,
    InvalidDestination,
    InvalidSpace,
    InvalidPhase,
    Peer(PeerError),
    Lane(PeerLaneError),
    Invoke(E),
}

/// Root-owned CNode capability and child-local slot attribution, not mutation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCapabilityDestination {
    pub cnode: u64,
    pub slot: u64,
}

/// Attribution of the exact stopped executor's address-space and fault endpoint binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerSpaceBinding {
    pub executor: u64,
    pub cnode: u64,
    pub vspace: u64,
    pub fault_slot: u64,
}

/// Owns the registration ticket and a preallocated root-CSpace destination slot. The adapter must
/// exclusively retain that initially empty root slot and validate its namespace, physical lifetime,
/// endpoint capability and executor before effects. Callbacks are synchronous and must not
/// reenter registration, scheduling, or capability ownership. Errors preserve all ownership;
/// entered operations cannot replay without a future explicit reconciliation protocol.
/// Drop does not delete a capability, release a slot, or remove a route.
///
/// ```compile_fail
/// use nt_component_suspension::PeerInstallation;
/// fn duplicate(owner: PeerInstallation) { let _ = owner.clone(); }
/// ```
#[must_use = "retain peer capability ownership through publication or acknowledged abort"]
pub struct PeerInstallation {
    registration: PeerRegistration,
    route: PeerRoute,
    destination_slot: u64,
    exported_destination: Option<PeerCapabilityDestination>,
    space_binding: Option<PeerSpaceBinding>,
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
            exported_destination: None,
            space_binding: None,
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

    /// Retained destination attribution, including an uncertain entered export. Not permission
    /// to delete, overwrite or recycle the child slot.
    pub const fn child_destination(&self) -> Option<PeerCapabilityDestination> {
        self.exported_destination
    }

    /// Includes entered but unacknowledged bindings; metadata never permits teardown or reuse.
    pub const fn space_binding(&self) -> Option<PeerSpaceBinding> {
        self.space_binding
    }

    /// Bind the stopped executor to its live child CSpace/VSpace and exported fault endpoint.
    /// The adapter must prove these are the exact owned physical objects, keep them alive, and
    /// invoke synchronously without reentry. Root, child and TCB-derived endpoint aliases remain
    /// owned on success or uncertainty. This grants no execution permission and never resumes.
    pub fn bind_space<E>(
        &mut self,
        vspace: u64,
        bind: impl FnOnce(PeerSpaceBinding) -> Result<(), E>,
    ) -> Result<(), PeerInstallationError<E>> {
        if self.phase != PeerInstallationPhase::Exported {
            return Err(PeerInstallationError::InvalidPhase);
        }
        let destination = self
            .exported_destination
            .expect("exported peer destination");
        if vspace == 0
            || vspace == self.route.identity().executor
            || vspace == self.route.endpoint()
            || vspace == self.destination_slot
            || vspace == destination.cnode
        {
            return Err(PeerInstallationError::InvalidSpace);
        }
        let binding = PeerSpaceBinding {
            executor: self.route.identity().executor,
            cnode: destination.cnode,
            vspace,
            fault_slot: destination.slot,
        };
        self.space_binding = Some(binding);
        self.phase = PeerInstallationPhase::BindingSpace;
        bind(binding).map_err(PeerInstallationError::Invoke)?;
        self.phase = PeerInstallationPhase::SpaceBound;
        Ok(())
    }

    /// Copy the published root alias into the exact peer's live child CSpace. The adapter must
    /// prove this is not the root CNode and exclusively reserve the initially empty child slot
    /// (child-local slot zero is valid). It must preserve both CNode and peer lifetimes, forbid
    /// additional copies, and not resume the peer until ACK and the startup protocol permit it.
    /// An error leaves the active route and both capability owners retained; quarantine is
    /// required until a future reconciliation protocol, never staged abort or blind replay.
    pub fn export<C, R, T, E>(
        &mut self,
        peers: &PeerRegistry,
        domain: u64,
        domain_generation: u64,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        destination: PeerCapabilityDestination,
        export: impl FnOnce(u64, PeerCapabilityDestination) -> Result<(), E>,
    ) -> Result<(), PeerInstallationError<E>> {
        if self.phase != PeerInstallationPhase::Published {
            return Err(PeerInstallationError::InvalidPhase);
        }
        if destination.cnode == 0
            || destination.cnode == self.destination_slot
            || destination.cnode == self.route.endpoint()
            || destination.cnode == self.route.identity().executor
        {
            return Err(PeerInstallationError::InvalidDestination);
        }
        let route = peers
            .resolve_lane(self.route.badge(), domain, domain_generation, lanes)
            .map_err(PeerInstallationError::Lane)?;
        if route != self.route {
            return Err(PeerInstallationError::Peer(PeerError::WrongOwner));
        }
        self.exported_destination = Some(destination);
        self.phase = PeerInstallationPhase::Exporting;
        export(self.destination_slot, destination).map_err(PeerInstallationError::Invoke)?;
        self.phase = PeerInstallationPhase::Exported;
        Ok(())
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
