//! Canonical Device publication sequencing, separate from physical allocation retirement.
use super::*;

pub(super) struct ProjectionPublicationError {
    pub(super) status: nt_status::NtStatus,
    pub(super) retained: bool,
    accepted: Option<nt_io_manager::HostedDevicePointerRegistration>,
    pub(super) cleanup_unbound: bool,
}

impl ProjectionPublicationError {
    /// Newly accepted canonical bind provenance, not permission to retire its live projection.
    pub(super) fn accepted_registration(&self) -> Option<nt_io_manager::HostedDevicePointerRegistration> {
        self.accepted
    }
}

pub(super) fn register_hosted_device_projection(
    inst: DriverInstance,
    domain: HostedDomainIdentity,
    address: u64,
    device: nt_io_manager::DeviceId,
) -> Result<nt_io_manager::HostedDevicePointerRegistration, ProjectionPublicationError> {
    register_with_list_owner(inst, domain, address, device,
        hosted_device_allocations::DeviceListOwner::Linked)
}

pub(super) fn register_unlinked_hosted_device_projection(
    inst: DriverInstance,
    domain: HostedDomainIdentity,
    address: u64,
    device: nt_io_manager::DeviceId,
) -> Result<nt_io_manager::HostedDevicePointerRegistration, ProjectionPublicationError> {
    register_with_list_owner(inst, domain, address, device,
        hosted_device_allocations::DeviceListOwner::Unlinked)
}

fn register_with_list_owner(
    inst: DriverInstance,
    domain: HostedDomainIdentity,
    address: u64,
    device: nt_io_manager::DeviceId,
    list_owner: hosted_device_allocations::DeviceListOwner,
) -> Result<nt_io_manager::HostedDevicePointerRegistration, ProjectionPublicationError> {
    if io_manager_mut().hosted_domain_identity(domain.domain_id) != Some(domain) {
        return Err(ProjectionPublicationError { status: nt_status::NtStatus::ACCESS_DENIED, retained: false, accepted: None, cleanup_unbound: false });
    }
    // Existing registrations belong to their prior owner. A failed attempted publication cannot
    // convert that observation into permission to retire or free its storage.
    let existing = io_manager_mut().hosted_device_by_identity(domain, address).is_some()
        || io_manager_mut().hosted_device_pointer_registration(domain, address).is_some();
    if existing {
        return Err(ProjectionPublicationError {
            status: nt_status::NtStatus::OBJECT_NAME_COLLISION,
            retained: true,
            accepted: None,
            cleanup_unbound: false,
        });
    }
    unsafe { hosted_device_allocations::protect_allocation(inst, address) }.map_err(|status|
        ProjectionPublicationError { status, retained: hosted_device_allocations::protects_allocation(inst, address), accepted: None, cleanup_unbound: !existing })?;
    unsafe { hosted_device_allocations::stage_driver_object(inst, address, list_owner) }.map_err(|status|
        ProjectionPublicationError { status, retained: true, accepted: None, cleanup_unbound: !existing })?;
    let registration = io_manager_mut().bind_hosted_device_pointer(domain, address, device)
        .map_err(|status| ProjectionPublicationError { status, retained: true, accepted: None, cleanup_unbound: !existing })?;
    hosted_device_allocations::record_accepted_registration(inst, registration)
        .map_err(|status| ProjectionPublicationError { status, retained: true, accepted: Some(registration), cleanup_unbound: false })?;
    hosted_device_allocations::publish_registration(inst, registration)
        .map_err(|status| ProjectionPublicationError { status, retained: true, accepted: (!existing).then_some(registration), cleanup_unbound: false })?;
    Ok(registration)
}
