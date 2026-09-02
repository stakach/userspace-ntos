use alloc::vec::Vec;

use nt_pnp::{
    AcpiPciCrsMethodSource, AcpiPciLinkCandidateFact, AcpiPciProviderEndpoint, AcpiPciScopeCatalog,
    AcpiPciScopeError, AcpiPciScopeSource, PciDevice, PciInterruptRouteClaim,
    PciInterruptRouteOwner, PciInventory, PciInventoryError, PciLocation,
    PreparedAcpiPciInterruptLinkDiscovery, PreparedAcpiPciRoutingDiscovery,
    PreparedAcpiPciRoutingTables, PreparedAcpiPciScopeCatalogUpdate,
    PreparedPciInterruptRoutePublication,
};

struct HostedPciTopologyAuthority {
    inventory: PciInventory,
    scopes: AcpiPciScopeCatalog,
    routes: PciInterruptRouteOwner,
    interrupt_claims: Vec<nt_interrupt_authority::PhysicalInterruptAssignment>,
    dirty_relations: Vec<HostedPciDirtyRelation>,
    reconcile_ready: bool,
    interrupt_overrides: Option<Vec<nt_acpi::LegacyIrqOverride>>,
    route_blocked: Option<HostedPciRouteBlock>,
}

#[derive(Clone, Copy)]
struct HostedPciDirtyRelation {
    endpoint: AcpiPciProviderEndpoint,
    routing_fenced: bool,
}

#[derive(Clone, Copy)]
struct HostedPciRouteBlock {
    catalog_generation: u64,
    inventory_generation: u64,
    route_owner_generation: u64,
    status: nt_status::NtStatus,
}

#[derive(Clone, Copy)]
pub(crate) struct HostedPciInterruptRouteClaim {
    claim: PciInterruptRouteClaim,
    physical: nt_interrupt_authority::PhysicalInterruptClaim,
    vector: u32,
}

#[derive(Clone, Copy)]
pub(crate) struct HostedPciInterruptRouteAssignment {
    pub(crate) gsi: u32,
    pub(crate) vector: u32,
    pub(crate) level_sensitive: bool,
    pub(crate) active_low: bool,
    pub(crate) shared: bool,
    pub(crate) physical: nt_interrupt_authority::PhysicalInterruptClaim,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostedPciInterruptRouteAdmission {
    Current,
    Pending,
    Blocked(nt_status::NtStatus),
}

impl HostedPciInterruptRouteClaim {
    pub(crate) fn resource_assignment(self) -> nt_pnp::PciInterruptAssignment {
        let route = self.claim.route();
        nt_pnp::PciInterruptAssignment {
            bus_level: route.gsi,
            vector: self.vector,
            latched: !route.level_sensitive,
            shared: route.shared,
            affinity: 1,
        }
    }
}

static mut HOSTED_PCI_TOPOLOGY: Option<HostedPciTopologyAuthority> = None;

fn routing_is_fenced(authority: &HostedPciTopologyAuthority) -> bool {
    authority
        .dirty_relations
        .iter()
        .any(|dirty| dirty.routing_fenced)
}

fn routing_reconciliation_pending(authority: &HostedPciTopologyAuthority) -> bool {
    routing_is_fenced(authority)
        || (!authority.scopes.sources().is_empty()
            && (authority.routes.inventory_generation() != Some(authority.inventory.generation())
                || authority.routes.provider_scope_generation()
                    != Some(authority.scopes.generation())))
        || (authority.scopes.sources().is_empty()
            && authority.routes.inventory_generation().is_none()
            && !authority.dirty_relations.is_empty())
}

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

fn refresh_hosted_pci_route_reconciliation(authority: &mut HostedPciTopologyAuthority) {
    if authority.route_blocked.is_some_and(|blocked| {
        blocked.catalog_generation != authority.scopes.generation()
            || blocked.inventory_generation != authority.inventory.generation()
            || blocked.route_owner_generation != authority.routes.generation()
    }) {
        authority.route_blocked = None;
    }
    authority.reconcile_ready = !authority.scopes.sources().is_empty()
        && authority.dirty_relations.is_empty()
        && authority.route_blocked.is_none()
        && (authority.routes.inventory_generation() != Some(authority.inventory.generation())
            || authority.routes.provider_scope_generation() != Some(authority.scopes.generation()));
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
        interrupt_claims: Vec::new(),
        dirty_relations: Vec::new(),
        reconcile_ready: false,
        interrupt_overrides: None,
        route_blocked: None,
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

fn route_status(_error: nt_pnp::PciInterruptRouteError) -> nt_status::NtStatus {
    nt_status::NtStatus::INVALID_DEVICE_REQUEST
}

/// Retain the exact route generation selected for one current PCI function.
pub(crate) unsafe fn acquire_hosted_pci_interrupt_route(
    device: &PciDevice,
) -> Result<Option<HostedPciInterruptRouteClaim>, nt_status::NtStatus> {
    if device.irq_pin == 0 {
        return Ok(None);
    }
    let authority = (*core::ptr::addr_of!(HOSTED_PCI_TOPOLOGY))
        .as_ref()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if routing_reconciliation_pending(authority) || authority.route_blocked.is_some() {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let claim = authority
        .routes
        .resolve(
            &authority.inventory,
            authority.scopes.generation(),
            0,
            PciLocation {
                bus: device.bus,
                device: device.dev,
                function: device.func,
            },
        )
        .map_err(route_status)?;
    let Some(claim) = claim else {
        return Ok(None);
    };
    let physical = authority
        .interrupt_claims
        .iter()
        .find(|assignment| assignment.route.gsi == claim.route().gsi)
        .copied()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    Ok(Some(HostedPciInterruptRouteClaim {
        claim,
        physical: physical.claim,
        vector: physical.route.vector,
    }))
}

/// Report whether this exact PCI function may enter interrupt resource arbitration. Initial
/// provider discovery, a relevant BusRelations refresh, and route-generation reconciliation are
/// transient ownership (`Pending`); a failed reconciliation or missing current route is terminal.
/// Pinless functions never depend on PCI interrupt routing.
pub(crate) unsafe fn hosted_pci_interrupt_route_admission(
    device: &PciDevice,
) -> HostedPciInterruptRouteAdmission {
    if device.irq_pin == 0 {
        return HostedPciInterruptRouteAdmission::Current;
    }
    let Some(authority) = (*core::ptr::addr_of!(HOSTED_PCI_TOPOLOGY)).as_ref() else {
        return HostedPciInterruptRouteAdmission::Blocked(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        );
    };
    if let Some(blocked) = authority.route_blocked {
        return HostedPciInterruptRouteAdmission::Blocked(blocked.status);
    }
    if routing_reconciliation_pending(authority) {
        return HostedPciInterruptRouteAdmission::Pending;
    }
    match acquire_hosted_pci_interrupt_route(device) {
        Ok(Some(_)) => HostedPciInterruptRouteAdmission::Current,
        Ok(None) => HostedPciInterruptRouteAdmission::Blocked(
            nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        ),
        Err(status) => HostedPciInterruptRouteAdmission::Blocked(status),
    }
}

/// Revalidate a retained route immediately before resource publication and capability minting.
pub(crate) unsafe fn validate_hosted_pci_interrupt_route(
    retained: HostedPciInterruptRouteClaim,
) -> Result<HostedPciInterruptRouteAssignment, nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of!(HOSTED_PCI_TOPOLOGY))
        .as_ref()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if routing_reconciliation_pending(authority) || authority.route_blocked.is_some() {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let route = authority
        .routes
        .validate(
            &authority.inventory,
            authority.scopes.generation(),
            retained.claim,
        )
        .map_err(route_status)?;
    let physical = crate::validate_physical_interrupt_claim(retained.physical)?;
    if physical.gsi != route.gsi
        || physical.level_sensitive != route.level_sensitive
        || physical.active_low != route.active_low
        || physical.shared != route.shared
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    Ok(HostedPciInterruptRouteAssignment {
        gsi: route.gsi,
        vector: physical.vector,
        level_sensitive: route.level_sensitive,
        active_low: route.active_low,
        shared: route.shared,
        physical: retained.physical,
    })
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
    let Some(authority) = (*core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY)).as_mut() else {
        return Ok(false);
    };
    if authority
        .dirty_relations
        .iter()
        .any(|dirty| dirty.endpoint == relation_owner)
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    authority
        .dirty_relations
        .try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let relevant = authority.scopes.relation_has_sources(relation_owner);
    if relevant {
        crate::fence_pci_interrupt_claims(authority.routes.generation())?;
        authority
            .routes
            .invalidate()
            .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        authority.interrupt_claims.clear();
        authority.reconcile_ready = false;
        authority.route_blocked = None;
    }
    authority.dirty_relations.push(HostedPciDirtyRelation {
        endpoint: relation_owner,
        routing_fenced: relevant,
    });
    authority.reconcile_ready = false;
    Ok(relevant)
}

pub(crate) unsafe fn note_hosted_pci_relation_completion(
    relation_owner: AcpiPciProviderEndpoint,
    completion: nt_pnp_manager::DeviceRelationInvalidationCompletion,
) -> Result<bool, nt_status::NtStatus> {
    let Some(authority) = (*core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY)).as_mut() else {
        return Ok(false);
    };
    let index = authority
        .dirty_relations
        .iter()
        .position(|dirty| dirty.endpoint == relation_owner)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if matches!(
        completion,
        nt_pnp_manager::DeviceRelationInvalidationCompletion::Requeued(_)
    ) {
        authority.reconcile_ready = false;
        return Ok(false);
    }
    let completed = authority.dirty_relations.remove(index);
    if completed.routing_fenced {
        authority.route_blocked = None;
    }
    refresh_hosted_pci_route_reconciliation(authority);
    Ok(authority.reconcile_ready)
}

pub(crate) unsafe fn note_hosted_pci_relation_failure(
    parent_device_id: u64,
    status: nt_status::NtStatus,
) -> Result<(), nt_status::NtStatus> {
    let Some(authority) = (*core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY)).as_mut() else {
        return Ok(());
    };
    let mut matches = authority
        .dirty_relations
        .iter()
        .enumerate()
        .filter(|(_, dirty)| dirty.endpoint.device_id == parent_device_id);
    let Some((index, _)) = matches.next() else {
        return Ok(());
    };
    if matches.next().is_some() {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let failed = authority.dirty_relations.remove(index);
    authority.reconcile_ready = false;
    if failed.routing_fenced {
        authority.route_blocked = Some(HostedPciRouteBlock {
            catalog_generation: authority.scopes.generation(),
            inventory_generation: authority.inventory.generation(),
            route_owner_generation: authority.routes.generation(),
            status,
        });
    }
    Ok(())
}

pub(crate) unsafe fn begin_hosted_pci_route_reconciliation(
) -> Result<Option<PreparedAcpiPciRoutingDiscovery>, nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY))
        .as_mut()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    refresh_hosted_pci_route_reconciliation(authority);
    if let Some(blocked) = authority.route_blocked {
        let _blocked_status = blocked.status;
        return Ok(None);
    }
    if !authority.reconcile_ready || authority.interrupt_overrides.is_none() {
        return Ok(None);
    }
    if !authority.dirty_relations.is_empty() {
        return Ok(None);
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
            authority.dirty_relations.is_empty()
                && discovery.is_current(&authority.scopes, &authority.inventory, &authority.routes)
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
            authority.dirty_relations.is_empty()
                && tables.is_current(&authority.scopes, &authority.inventory, &authority.routes)
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
            authority.dirty_relations.is_empty()
                && discovery.is_current(&authority.scopes, &authority.inventory, &authority.routes)
        })
}

pub(crate) unsafe fn prepare_hosted_pci_interrupt_route_publication(
    discovery: PreparedAcpiPciInterruptLinkDiscovery,
    evaluations: Vec<nt_pnp::AcpiPciInterruptLinkEvaluation>,
) -> Result<PreparedPciInterruptRoutePublication, nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of!(HOSTED_PCI_TOPOLOGY))
        .as_ref()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let overrides = authority
        .interrupt_overrides
        .as_deref()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    discovery
        .prepare_route_publication(
            &authority.scopes,
            &authority.inventory,
            &authority.routes,
            overrides,
            evaluations,
        )
        .map_err(|error| match error {
            nt_pnp::AcpiPciRoutingDiscoveryError::Allocation => {
                nt_status::NtStatus::INSUFFICIENT_RESOURCES
            }
            _ => nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        })
}

pub(crate) unsafe fn hosted_pci_route_publication_is_current(
    publication: &PreparedPciInterruptRoutePublication,
) -> bool {
    (*core::ptr::addr_of!(HOSTED_PCI_TOPOLOGY))
        .as_ref()
        .is_some_and(|authority| {
            authority.dirty_relations.is_empty()
                && publication.base_generation() == authority.routes.generation()
                && publication.inventory_generation() == authority.inventory.generation()
                && publication.provider_scope_generation() == authority.scopes.generation()
        })
}

pub(crate) unsafe fn commit_hosted_pci_interrupt_routes(
    publication: PreparedPciInterruptRoutePublication,
) -> Result<u64, nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY))
        .as_mut()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if !authority.dirty_relations.is_empty() || authority.route_blocked.is_some() {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let physical =
        crate::prepare_pci_interrupt_claims(publication.target_generation(), publication.routes())?;
    let generation = authority
        .routes
        .commit(
            publication,
            &authority.inventory,
            authority.scopes.generation(),
        )
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    authority.interrupt_claims = crate::commit_physical_interrupt_claims(physical)
        .expect("serialized PCI route commit must preserve the prepared physical-line mutation");
    authority.reconcile_ready = false;
    Ok(generation)
}

pub(crate) unsafe fn block_hosted_pci_route_reconciliation(
    catalog_generation: u64,
    inventory_generation: u64,
    route_owner_generation: u64,
    status: nt_status::NtStatus,
) -> Result<bool, nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY))
        .as_mut()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if !authority.dirty_relations.is_empty()
        || catalog_generation != authority.scopes.generation()
        || inventory_generation != authority.inventory.generation()
        || route_owner_generation != authority.routes.generation()
    {
        return Ok(false);
    }
    authority.route_blocked = Some(HostedPciRouteBlock {
        catalog_generation,
        inventory_generation,
        route_owner_generation,
        status,
    });
    authority.reconcile_ready = false;
    Ok(true)
}

pub(crate) unsafe fn recover_hosted_pci_route_reconciliation_block(
    catalog_generation: u64,
    inventory_generation: u64,
    route_owner_generation: u64,
) -> Result<(), nt_status::NtStatus> {
    let authority = (*core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY))
        .as_mut()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if authority.route_blocked.is_some_and(|blocked| {
        blocked.catalog_generation == catalog_generation
            && blocked.inventory_generation == inventory_generation
            && blocked.route_owner_generation == route_owner_generation
    }) {
        authority.route_blocked = None;
    }
    refresh_hosted_pci_route_reconciliation(authority);
    Ok(())
}

pub(crate) unsafe fn retry_hosted_pci_route_reconciliation() {
    if let Some(authority) = (*core::ptr::addr_of_mut!(HOSTED_PCI_TOPOLOGY)).as_mut() {
        refresh_hosted_pci_route_reconciliation(authority);
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
