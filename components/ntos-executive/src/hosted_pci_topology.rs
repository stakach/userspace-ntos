use alloc::vec::Vec;

use nt_pnp::{
    AcpiPciCrsMethodSource, AcpiPciLinkCandidateFact, AcpiPciProviderEndpoint, AcpiPciScopeCatalog,
    AcpiPciScopeError, AcpiPciScopeSource, PciDevice, PciInterruptRouteOwner, PciInventory,
    PciInventoryError, PreparedAcpiPciInterruptLinkDiscovery, PreparedAcpiPciRoutingDiscovery,
    PreparedAcpiPciRoutingTables,
    PreparedAcpiPciScopeCatalogUpdate,
};

struct HostedPciTopologyAuthority {
    inventory: PciInventory,
    scopes: AcpiPciScopeCatalog,
    routes: PciInterruptRouteOwner,
    dirty_relations: Vec<AcpiPciProviderEndpoint>,
    reconcile_ready: bool,
    interrupt_overrides: Option<Vec<nt_acpi::LegacyIrqOverride>>,
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
        dirty_relations: Vec::new(),
        reconcile_ready: false,
        interrupt_overrides: None,
    });
    Ok(snapshot)
}

pub(crate) unsafe fn install_hosted_pci_interrupt_overrides(
    overrides: Vec<nt_acpi::LegacyIrqOverride>,
) -> Result<(), nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY))
        .as_mut()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if authority.interrupt_overrides.is_some() {
        return Err(nt_status::NtStatus::OBJECT_NAME_COLLISION);
    }
    authority.interrupt_overrides = Some(overrides);
    Ok(())
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

pub(crate) unsafe fn note_hosted_pci_relation_queued(
    relation_owner: AcpiPciProviderEndpoint,
) -> Result<bool, nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY))
        .as_mut()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if authority.dirty_relations.contains(&relation_owner) {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    authority
        .dirty_relations
        .try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let relevant = authority.scopes.relation_has_sources(relation_owner);
    if relevant {
        authority
            .routes
            .invalidate()
            .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        authority.reconcile_ready = false;
    }
    authority.dirty_relations.push(relation_owner);
    Ok(relevant)
}

pub(crate) unsafe fn note_hosted_pci_relation_completion(
    relation_owner: AcpiPciProviderEndpoint,
    completion: nt_pnp_manager::DeviceRelationInvalidationCompletion,
) -> Result<bool, nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY))
        .as_mut()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let index = authority
        .dirty_relations
        .iter()
        .position(|dirty| *dirty == relation_owner)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if matches!(
        completion,
        nt_pnp_manager::DeviceRelationInvalidationCompletion::Requeued(_)
    ) {
        authority.reconcile_ready = false;
        return Ok(false);
    }
    authority.dirty_relations.remove(index);
    let relevant_dirty = authority
        .dirty_relations
        .iter()
        .any(|dirty| authority.scopes.relation_has_sources(*dirty));
    let needs_reconcile = !authority.scopes.sources().is_empty()
        && (authority.routes.inventory_generation() != Some(authority.inventory.generation())
            || authority.routes.provider_scope_generation()
                != Some(authority.scopes.generation()));
    authority.reconcile_ready = needs_reconcile && !relevant_dirty;
    Ok(authority.reconcile_ready)
}

pub(crate) unsafe fn begin_hosted_pci_route_reconciliation(
) -> Result<Option<PreparedAcpiPciRoutingDiscovery>, nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY))
        .as_mut()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if !authority.reconcile_ready || authority.interrupt_overrides.is_none() {
        return Ok(None);
    }
    if authority
        .dirty_relations
        .iter()
        .any(|dirty| authority.scopes.relation_has_sources(*dirty))
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let discovery = authority
        .scopes
        .prepare_routing_discovery(&authority.inventory, &authority.routes)
        .map_err(scope_status)?;
    authority.reconcile_ready = false;
    Ok(Some(discovery))
}

pub(crate) unsafe fn hosted_pci_route_discovery_is_current(
    discovery: &PreparedAcpiPciRoutingDiscovery,
) -> bool {
    (*core::ptr::addr_of!(HOSTED_PCI_TOPOLOGY))
        .as_ref()
        .is_some_and(|authority| {
            discovery.is_current(&authority.scopes, &authority.inventory, &authority.routes)
        })
}

pub(crate) unsafe fn accept_hosted_pci_routing_tables(
    discovery: PreparedAcpiPciRoutingDiscovery,
    tables: Vec<nt_acpi::PciRoutingTable>,
) -> Result<PreparedAcpiPciRoutingTables, nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of!(HOSTED_PCI_TOPOLOGY))
        .as_ref()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    discovery
        .accept_routing_tables(
            &authority.scopes,
            &authority.inventory,
            &authority.routes,
            tables,
        )
        .map_err(|error| match error {
            nt_pnp::AcpiPciRoutingDiscoveryError::Allocation => {
                nt_status::NtStatus::INSUFFICIENT_RESOURCES
            }
            _ => nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        })
}

pub(crate) unsafe fn hosted_pci_routing_tables_are_current(
    tables: &PreparedAcpiPciRoutingTables,
) -> bool {
    (*core::ptr::addr_of!(HOSTED_PCI_TOPOLOGY))
        .as_ref()
        .is_some_and(|authority| {
            tables.is_current(&authority.scopes, &authority.inventory, &authority.routes)
        })
}

pub(crate) unsafe fn prepare_hosted_pci_interrupt_link_discovery(
    tables: PreparedAcpiPciRoutingTables,
    filtered_sources: Vec<AcpiPciCrsMethodSource>,
) -> Result<PreparedAcpiPciInterruptLinkDiscovery, nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of!(HOSTED_PCI_TOPOLOGY))
        .as_ref()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    tables
        .prepare_interrupt_link_discovery(
            &authority.scopes,
            &authority.inventory,
            &authority.routes,
            filtered_sources,
        )
        .map_err(|error| match error {
            nt_pnp::AcpiPciRoutingDiscoveryError::Allocation => {
                nt_status::NtStatus::INSUFFICIENT_RESOURCES
            }
            _ => nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        })
}

pub(crate) unsafe fn hosted_pci_interrupt_link_discovery_is_current(
    discovery: &PreparedAcpiPciInterruptLinkDiscovery,
) -> bool {
    (*core::ptr::addr_of!(HOSTED_PCI_TOPOLOGY))
        .as_ref()
        .is_some_and(|authority| {
            discovery.is_current(&authority.scopes, &authority.inventory, &authority.routes)
        })
}

pub(crate) unsafe fn retry_hosted_pci_route_reconciliation() {
    if let Some(authority) =
        (*core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY)).as_mut()
    {
        let relevant_dirty = authority
            .dirty_relations
            .iter()
            .any(|dirty| authority.scopes.relation_has_sources(*dirty));
        authority.reconcile_ready = !authority.scopes.sources().is_empty()
            && !relevant_dirty
            && (authority.routes.inventory_generation() != Some(authority.inventory.generation())
                || authority.routes.provider_scope_generation()
                    != Some(authority.scopes.generation()));
    }
}

pub(crate) unsafe fn prepare_hosted_acpi_pci_relation_facts(
    relation_owner: AcpiPciProviderEndpoint,
    sources: &[AcpiPciScopeSource],
    link_candidates: &[AcpiPciLinkCandidateFact],
) -> Result<PreparedAcpiPciScopeCatalogUpdate, nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of!(HOSTED_PCI_TOPOLOGY))
        .as_ref()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    authority
        .scopes
        .prepare_replace_relation_facts(relation_owner, sources, link_candidates)
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
