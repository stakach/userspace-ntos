//! Admission of a bus child whose canonical driver runs through a separate provider domain.
//!
//! The caller supplies independently revalidated observations. This contract never discovers a
//! route by scanning pointer domains: an accepted relation supplies its child registration before
//! publication, and the accepted-PDO catalog supplies it afterwards. Neither a numeric pointer
//! nor a canonical driver ID alone grants physical dispatch authority.

use crate::source_irp_auxiliary::SourcePoolAllocationIdentity;
use crate::{DeviceId, DriverId, HostedDevicePointerRegistration, HostedDomainIdentity};

/// Facts re-observed from the canonical Device, live pointer registration, physical pool, and
/// published provider dependency. The caller must obtain them from those independent owners.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HostedProviderChildRouteEvidence {
    pub device_id: DeviceId,
    pub driver_id: DriverId,
    pub dependent_domain: HostedDomainIdentity,
    pub provider_domain: HostedDomainIdentity,
    pub provider_publication_cookie: u64,
    pub provider_driver_object: u64,
    pub registration: HostedDevicePointerRegistration,
    pub allocation: SourcePoolAllocationIdentity,
}

impl HostedProviderChildRouteEvidence {
    pub fn is_well_formed(self) -> bool {
        !self.device_id.is_null()
            && !self.driver_id.is_null()
            && self.dependent_domain.domain_id.raw() != 0
            && self.dependent_domain.cookie != 0
            && self.provider_domain.domain_id.raw() != 0
            && self.provider_domain.cookie != 0
            && self.dependent_domain != self.provider_domain
            && self.provider_publication_cookie != 0
            && self.provider_driver_object != 0
            && self.registration.device_id() == self.device_id
            && self.registration.domain() == self.provider_domain
            && self.registration.address() == self.allocation.component_address
            && self.registration.generation() != 0
            && self.allocation.capacity != 0
            && self.allocation.pool_generation != 0
    }
}

#[cfg(test)]
#[path = "hosted_provider_child_route/tests.rs"]
mod tests;
