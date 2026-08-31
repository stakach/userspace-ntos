use alloc::vec::Vec;

use nt_pnp::{
    AcpiPciProviderEndpoint, AcpiPciScopeCatalog, AcpiPciScopeError, AcpiPciScopeSource,
    PciDevice, PciInterruptRouteOwner, PciInventory, PciInventoryError,
    PreparedAcpiPciScopeCatalogUpdate,
};

struct HostedPciTopologyAuthority {
    inventory: PciInventory,
    scopes: AcpiPciScopeCatalog,
    routes: PciInterruptRouteOwner,
}

static mut HOSTED_PCI_TOPOLOGY: Option<HostedPciTopologyAuthority> = None;

fn inventory_status(error: PciInventoryError) -> nt_status::NtStatus {
    match error {
        PciInventoryError::Allocation => nt_status::NtStatus::INSUFFICIENT_RESOURCES,
        PciInventoryError::InvalidLocation(_)
        | PciInventoryError::DuplicateLocation(_)
        | PciInventoryError::InvalidBridgeWindow(_)
        | PciInventoryError::DuplicateSecondaryBus(_)
        | PciInventoryError::GenerationExhausted
        | PciInventoryError::StaleUpdate => nt_status::NtStatus::INVALID_DEVICE_REQUEST,
    }
}

fn scope_status(error: AcpiPciScopeError) -> nt_status::NtStatus {
    if error == AcpiPciScopeError::Allocation {
        nt_status::NtStatus::INSUFFICIENT_RESOURCES
    } else {
        nt_status::NtStatus::INVALID_DEVICE_REQUEST
    }
}

fn copy_inventory_devices(inventory: &PciInventory) -> Result<Vec<PciDevice>, nt_status::NtStatus> {
    let mut snapshot = Vec::new();
    snapshot
        .try_reserve_exact(inventory.devices().len())
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    snapshot.extend_from_slice(inventory.devices());
    Ok(snapshot)
}

/// Install the one live PCI topology authority from the platform discovery result. The returned
/// vector is an immutable observation for boot resource projection, not a second authority.
pub(crate) unsafe fn install_hosted_pci_topology(
    devices: Vec<PciDevice>,
) -> Result<Vec<PciDevice>, nt_status::NtStatus> {
    let slot = &mut *core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY);
    if slot.is_some() {
        return Err(nt_status::NtStatus::OBJECT_NAME_COLLISION);
    }
    let inventory = PciInventory::try_from_initial(devices).map_err(inventory_status)?;
    let snapshot = copy_inventory_devices(&inventory)?;
    *slot = Some(HostedPciTopologyAuthority {
        inventory,
        scopes: AcpiPciScopeCatalog::default(),
        routes: PciInterruptRouteOwner::default(),
    });
    Ok(snapshot)
}

pub(crate) unsafe fn hosted_pci_topology_generations() -> Option<(u64, u64, u64)> {
    let authority = (*core::ptr::addr_of!(HOSTED_PCI_TOPOLOGY)).as_ref()?;
    Some((
        authority.inventory.generation(),
        authority.scopes.generation(),
        authority.routes.generation(),
    ))
}

pub(crate) unsafe fn hosted_acpi_pci_relation_has_sources(
    relation_owner: AcpiPciProviderEndpoint,
) -> bool {
    (*core::ptr::addr_of!(HOSTED_PCI_TOPOLOGY))
        .as_ref()
        .is_some_and(|authority| authority.scopes.relation_has_sources(relation_owner))
}

pub(crate) unsafe fn invalidate_hosted_pci_routes_for_relation(
    relation_owner: AcpiPciProviderEndpoint,
) -> Result<bool, nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY))
        .as_mut()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if !authority.scopes.relation_has_sources(relation_owner) {
        return Ok(false);
    }
    authority
        .routes
        .invalidate()
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    Ok(true)
}

pub(crate) unsafe fn prepare_hosted_acpi_pci_relation_sources(
    relation_owner: AcpiPciProviderEndpoint,
    sources: &[AcpiPciScopeSource],
) -> Result<PreparedAcpiPciScopeCatalogUpdate, nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of!(HOSTED_PCI_TOPOLOGY))
        .as_ref()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    authority
        .scopes
        .prepare_replace_relation_sources(relation_owner, sources)
        .map_err(scope_status)
}

pub(crate) unsafe fn commit_hosted_acpi_pci_relation_sources(
    prepared: PreparedAcpiPciScopeCatalogUpdate,
) -> Result<u64, nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY))
        .as_mut()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    authority.scopes.commit(prepared).map_err(scope_status)
}
