use alloc::vec::Vec;

use nt_pnp::{
    AcpiPciScopeCatalog, PciDevice, PciInterruptRouteOwner, PciInventory, PciInventoryError,
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
