//! Root-owned DMA reservation for an accepted SCSI child of a hosted controller.
//!
//! The child is not the DMA owner. Its exact accepted parent relation selects the started
//! controller and that controller's PnP-granted window. The reservation is independent of the
//! adapter Storport later chooses for a scatter/gather view.

use super::*;
use nt_dma_manager::CoherentWindowIdentity;
use nt_io_abi::{select_scsi_coherent_controller, ScsiControllerAuthority, ScsiControllerCandidate};

#[must_use = "a coherent SCSI reservation must be retained until canonical acknowledgement"]
#[derive(Clone, Copy)]
pub(super) struct HostedScsiDmaReservation {
    pub irp_id: u64,
    pub controller_device_id: u64,
    pub child_pdo: u64,
    pub relation_generation: u64,
    pub owner: DmaOwner,
    pub window: CoherentWindowIdentity,
    pub reservation_id: u64,
    pub provider_va: u64,
    pub broker_va: u64,
    pub logical: u64,
    pub length: u64,
    pub provider_domain: HostedDomainIdentity,
    pub provider_pdo: u64,
}

static mut RESERVATIONS: Vec<HostedScsiDmaReservation> = Vec::new();

fn reservations() -> &'static mut Vec<HostedScsiDmaReservation> {
    unsafe { &mut *core::ptr::addr_of_mut!(RESERVATIONS) }
}

pub(super) unsafe fn reserve_for_dispatch(
    request: &IrpDispatchRequest,
    provider_pdo: u64,
    length: u64,
) -> Result<(), nt_status::NtStatus> {
    if reservations().iter().any(|row| row.irp_id == request.irp_id) {
        return Err(nt_status::NtStatus::OBJECT_NAME_COLLISION);
    }
    reservations().try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let row = reserve_scsi_dma_data(request, provider_pdo, length)?;
    reservations().push(row);
    Ok(())
}

pub(super) unsafe fn for_provider(
    provider: HostedDomainIdentity,
    irp_id: u64,
    provider_pdo: u64,
) -> Option<HostedScsiDmaReservation> {
    reservations().iter().copied().find(|row| {
        row.irp_id == irp_id && row.provider_domain == provider
            && row.provider_pdo == provider_pdo
            && row.child_pdo != 0
            && row.length != 0
    })
}

pub(super) unsafe fn for_source(
    provider: HostedDomainIdentity,
    source_va: u64,
    length: u64,
) -> Option<(HostedScsiDmaReservation, u64, u64)> {
    let source_end = source_va.checked_add(length).filter(|_| length != 0)?;
    let mut found = None;
    for row in reservations().iter().copied() {
        let row_end = row.provider_va.checked_add(row.length)?;
        if row.provider_domain != provider || source_va < row.provider_va
            || source_end > row_end { continue; }
        let offset = source_va - row.provider_va;
        let logical = row.logical.checked_add(offset)?;
        let broker_va = row.broker_va.checked_add(offset)?;
        if found.is_some() { return None; }
        found = Some((row, logical, broker_va));
    }
    found
}

pub(super) unsafe fn overlaps(
    provider: HostedDomainIdentity,
    logical: u64,
    length: u64,
) -> Result<Option<u64>, nt_status::NtStatus> {
    let end = logical.checked_add(length)
        .filter(|_| length != 0)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    Ok(reservations().iter()
        .filter(|row| row.provider_domain == provider)
        .filter_map(|row| row.logical.checked_add(row.length)
            .filter(|row_end| logical < *row_end && row.logical < end))
        .max())
}

pub(super) unsafe fn release_after_ack(irp_id: u64) -> Result<(), nt_status::NtStatus> {
    let Some(index) = reservations().iter().position(|row| row.irp_id == irp_id) else {
        return Ok(());
    };
    let row = reservations()[index];
    hosted_dma_manager_mut().release_coherent_reservation(
        row.owner, row.window, row.reservation_id,
    ).map_err(hosted_dma_status)?;
    reservations().swap_remove(index);
    Ok(())
}

pub(super) unsafe fn quarantine(irp_id: u64) {
    if let Some(row) = reservations().iter().find(|row| row.irp_id == irp_id).copied() {
        let _ = hosted_dma_manager_mut().quarantine_coherent_reservation(
            row.owner, row.window, row.reservation_id,
        );
    }
}

/// Resolve a child only through its live BusRelations publication and one started controller
/// binding. The provider's numeric PDO pointer is accepted only with its exact registration.
unsafe fn controller_for_scsi_child(
    request: &IrpDispatchRequest,
    provider_pdo: u64,
) -> Result<(HostedDeviceBinding, ScsiControllerCandidate), nt_status::NtStatus> {
    if request._reserved0 != nt_io_abi::IRP_DISPATCH_SCSI_SRB
        || request.irp_id == 0 || request.device_id == 0
        || request.scsi_relation_generation == 0 || provider_pdo == 0
        || request.target_domain_id == 0 || request.target_domain_cookie == 0
    { return Err(nt_status::NtStatus::INVALID_PARAMETER); }
    let provider = HostedDomainIdentity {
        domain_id: nt_io_manager::HostedDomainId(request.target_domain_id),
        cookie: request.target_domain_cookie,
    };
    hosted_device_pointer_registration(
        provider, provider_pdo, nt_io_manager::DeviceId(request.device_id),
    )?;
    let relation = hosted_pnp_manager_mut()
        .parent_relation_for_pdo(request.device_id)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if relation.relation().generation() != request.scsi_relation_generation
        || !hosted_bus_relations().relation_contains(relation.relation(), request.device_id)
        || !hosted_pnp_manager_mut().relation_parent_is_started(relation)
    { return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST); }
    let parent = relation.parent();
    let authority = ScsiControllerAuthority {
        child_pdo: request.device_id,
        relation_generation: request.scsi_relation_generation,
        parent_pdo: parent.pdo_object_id(),
        parent_generation: parent.generation(),
        provider_domain_id: request.target_domain_id,
        provider_cookie: request.target_domain_cookie,
    };
    let mut candidates: Vec<ScsiControllerCandidate> = Vec::new();
    for binding in hosted_device_bindings().into_iter().flatten().copied() {
        if !binding.used || binding.pdo_device_id != parent.pdo_object_id()
            || binding.projection_domain != provider
            || hosted_dma_pdo_generation(binding.pdo_device_id)
                .is_none_or(|generation| !hosted_dma_pdo_generation_is_live(binding.pdo_device_id, generation))
        { continue; }
        let Some(state) = hosted_device_resource_state_by_device_id(binding.device_id) else {
            continue;
        };
        if state.instance != binding.instance
            || state.projection_domain != binding.projection_domain
            || state.pdo_object != binding.pdo_object
            || hosted_device_pointer_registration(
                provider, binding.pdo_object,
                nt_io_manager::DeviceId(binding.pdo_device_id),
            ).is_err()
        { continue; }
        let Some(context_lease) = state.pnp_context_lease else { continue; };
        if state.interface_type != HOSTED_INTERFACE_TYPE_PCIBUS
            || state.bus_number > u8::MAX as u32
            || state.address & !0x001F_0007 != 0
            || state.dma_frame_base == 0 || state.dma_pages == 0
            || state.dma_broker_va == 0
        { continue; }
        let Ok((_, window)) = crate::hosted_pnp_context::hosted_pnp_pci_window_by_lease(
            context_lease,
            state.bus_number as u8,
            (state.address >> 16) as u8,
            state.address as u8,
        ) else { continue; };
        if !window.dma_grant_valid()
            || state.dma_frame_base != window.dma_frame_base
            || state.dma_pages != window.dma_pages
            || state.dma_broker_va != window.dma_seed_va
            || state.evidence.dma_common_va != window.dma_va
            || state.evidence.dma_common_len != window.dma_len
            || state.evidence.dma_common_logical != window.dma_logical
        { continue; }
        let grant = (window.dma_va, window.dma_len, window.dma_logical);
        let owner = hosted_dma_owner(binding);
        let lease_live = hosted_dma_adapter_leases_mut().iter().any(|lease| {
            lease.owner == owner && lease.consumer_domain == provider
                && lease.pdo_registration.device_id().raw() == binding.pdo_device_id
                && lease.grant == Some(grant)
                && hosted_dma_pdo_generation_is_live(binding.pdo_device_id, lease.pdo_generation)
                && io_manager_mut().hosted_device_pointer_registration(
                    lease.pdo_registration.domain(), lease.pdo_registration.address(),
                ) == Some(lease.pdo_registration)
        });
        let candidate = ScsiControllerCandidate {
            controller_device_id: binding.device_id,
            child_pdo: request.device_id,
            relation_generation: relation.relation().generation(),
            parent_pdo: binding.pdo_device_id,
            parent_generation: parent.generation(),
            provider_domain_id: binding.projection_domain.domain_id.raw(),
            provider_cookie: binding.projection_domain.cookie,
            window_lease_id: context_lease.token(),
            window_generation: parent.generation(),
            grant_va: grant.0,
            broker_va: state.dma_broker_va,
            grant_length: grant.1,
            grant_logical: grant.2,
            live: lease_live,
        };
        candidates.try_reserve(1).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        candidates.push(candidate);
    }
    let selected = select_scsi_coherent_controller(authority, &candidates)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let binding = hosted_device_binding_by_device_id(selected.controller_device_id)
        .filter(|binding| binding.pdo_device_id == selected.parent_pdo
            && binding.projection_domain == provider)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    Ok((binding, selected))
}

/// Reserve one non-overlapping grant slice under root ownership before a native SCSI entry.
/// The returned identity must be retained through provider completion and canonical ACK.
pub(super) unsafe fn reserve_scsi_dma_data(
    request: &IrpDispatchRequest,
    provider_pdo: u64,
    length: u64,
) -> Result<HostedScsiDmaReservation, nt_status::NtStatus> {
    if length == 0 || length > u32::MAX as u64 {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let (binding, controller) = controller_for_scsi_child(request, provider_pdo)?;
    let owner = hosted_dma_owner(binding);
    let window = CoherentWindowIdentity::new(
        controller.window_lease_id, controller.window_generation,
    );
    // Every ordinary common buffer and packet map is claimed by the root manager before the
    // provider can publish or write its grant bytes. Shared records are projections only.
    hosted_dma_manager_mut().register_coherent_window(
        owner, window, controller.grant_logical,
        controller.grant_length, controller.broker_va,
    ).map_err(hosted_dma_status)?;
    let mut offset = 0u64;
    loop {
        let aligned = align_up(offset, HOSTED_DMA_COMMON_ALIGNMENT)
            .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        if aligned > controller.grant_length
            || length > controller.grant_length - aligned
        { return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES); }
        let provider_va = controller.grant_va.checked_add(aligned)
            .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
        let broker_va = controller.broker_va.checked_add(aligned)
            .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
        let logical = controller.grant_logical.checked_add(aligned)
            .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
        match hosted_dma_manager_mut().register_coherent_reservation_at(
            owner, window, logical, length, broker_va,
        ) {
            Ok(reservation) => return Ok(HostedScsiDmaReservation {
                irp_id: request.irp_id,
                controller_device_id: binding.device_id,
                child_pdo: request.device_id,
                relation_generation: request.scsi_relation_generation,
                owner, window, reservation_id: reservation.reservation_id,
                provider_va, broker_va, logical, length,
                provider_domain: HostedDomainIdentity {
                    domain_id: nt_io_manager::HostedDomainId(request.target_domain_id),
                    cookie: request.target_domain_cookie,
                },
                provider_pdo,
            }),
            Err(DmaError::LogicalViolation) => {
                offset = aligned.checked_add(HOSTED_DMA_COMMON_ALIGNMENT)
                    .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
            }
            Err(error) => return Err(hosted_dma_status(error)),
        }
    }
}
