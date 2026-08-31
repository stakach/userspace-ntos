use alloc::vec::Vec;

use nt_acpi::{
    resolve_namespace_reference, AcpiNamespaceMatches, AcpiNamespacePath, PciRouteSource,
    PciRoutingTable,
};

use crate::{
    AcpiPciProviderEndpoint, AcpiPciScopeCatalog, AcpiPciScopeError, PciInterruptRouteOwner,
    PciInventory, PciLocation,
};

/// One exact full-path `_PRT` evaluation derived from accepted ACPI and PCI topology facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiPciRoutingMethodQuery {
    pub relation_owner: AcpiPciProviderEndpoint,
    pub endpoint: AcpiPciProviderEndpoint,
    pub scope: AcpiNamespacePath,
    pub method_path: AcpiNamespacePath,
    pub segment: u16,
    pub bus: u8,
    pub bridge: Option<PciLocation>,
}

/// Immutable routing workset tied to one exact scope-catalog and PCI-inventory generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAcpiPciRoutingDiscovery {
    catalog_generation: u64,
    inventory_generation: u64,
    route_owner_generation: u64,
    queries: Vec<AcpiPciRoutingMethodQuery>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcpiPciRoutingDiscoveryError {
    Allocation,
    StaleTopology,
    IncompleteRoutingTables,
    MismatchedRoutingTable(usize),
    IncompleteLinkCandidateSets,
    DuplicateLinkCandidateEndpoint(AcpiPciProviderEndpoint),
    InvalidFilteredLinkMethod,
    LinkCandidateOutsideEndpoint,
    InvalidLinkReference {
        table_index: usize,
        entry_index: usize,
    },
}

/// Complete filtered `_CRS` method result from one authenticated PCI-root endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiPciCrsMethodSource {
    pub endpoint: AcpiPciProviderEndpoint,
    pub methods: AcpiNamespaceMatches,
}

/// One deduplicated full-path `_CRS` evaluation. Route-specific bindings remain private to the
/// prepared link-discovery object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiPciInterruptLinkMethodQuery {
    pub endpoint: AcpiPciProviderEndpoint,
    pub relation_owner: AcpiPciProviderEndpoint,
    pub object_path: AcpiNamespacePath,
    pub method_path: AcpiNamespacePath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AcpiPciInterruptLinkBinding {
    table_index: usize,
    entry_index: usize,
    query_index: usize,
}

/// Exact parsed routing tables plus every deduplicated interrupt-link method required to resolve
/// them. This remains inert until all indexed `_CRS` results are accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAcpiPciInterruptLinkDiscovery {
    catalog_generation: u64,
    inventory_generation: u64,
    route_owner_generation: u64,
    routing_queries: Vec<AcpiPciRoutingMethodQuery>,
    tables: Vec<PciRoutingTable>,
    link_queries: Vec<AcpiPciInterruptLinkMethodQuery>,
    bindings: Vec<AcpiPciInterruptLinkBinding>,
}

/// Complete checked `_PRT` results retained with their exact discovery workset. Link-candidate
/// enumeration is required only for the listed provider endpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAcpiPciRoutingTables {
    catalog_generation: u64,
    inventory_generation: u64,
    route_owner_generation: u64,
    queries: Vec<AcpiPciRoutingMethodQuery>,
    tables: Vec<PciRoutingTable>,
    link_candidate_endpoints: Vec<AcpiPciProviderEndpoint>,
}

impl PreparedAcpiPciRoutingDiscovery {
    pub fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    pub fn inventory_generation(&self) -> u64 {
        self.inventory_generation
    }

    pub fn route_owner_generation(&self) -> u64 {
        self.route_owner_generation
    }

    pub fn queries(&self) -> &[AcpiPciRoutingMethodQuery] {
        &self.queries
    }

    pub fn is_current(
        &self,
        catalog: &AcpiPciScopeCatalog,
        inventory: &PciInventory,
        routes: &PciInterruptRouteOwner,
    ) -> bool {
        self.catalog_generation == catalog.generation()
            && self.inventory_generation == inventory.generation()
            && self.route_owner_generation == routes.generation()
    }

    /// Accept one parser-validated table for every exact `_PRT` query. No missing or reordered
    /// provider result can advance to link discovery.
    pub fn accept_routing_tables(
        self,
        catalog: &AcpiPciScopeCatalog,
        inventory: &PciInventory,
        routes: &PciInterruptRouteOwner,
        tables: Vec<PciRoutingTable>,
    ) -> Result<PreparedAcpiPciRoutingTables, AcpiPciRoutingDiscoveryError> {
        if !self.is_current(catalog, inventory, routes) {
            return Err(AcpiPciRoutingDiscoveryError::StaleTopology);
        }
        if tables.len() != self.queries.len() {
            return Err(AcpiPciRoutingDiscoveryError::IncompleteRoutingTables);
        }
        let mut link_candidate_endpoints = Vec::new();
        link_candidate_endpoints
            .try_reserve_exact(self.queries.len())
            .map_err(|_| AcpiPciRoutingDiscoveryError::Allocation)?;
        for (index, (query, table)) in self.queries.iter().zip(&tables).enumerate() {
            if table.segment != query.segment || table.bus != query.bus {
                return Err(AcpiPciRoutingDiscoveryError::MismatchedRoutingTable(index));
            }
            if table
                .entries
                .iter()
                .any(|entry| matches!(entry.source, PciRouteSource::InterruptLink { .. }))
                && !link_candidate_endpoints.contains(&query.endpoint)
            {
                link_candidate_endpoints
                    .try_reserve(1)
                    .map_err(|_| AcpiPciRoutingDiscoveryError::Allocation)?;
                link_candidate_endpoints.push(query.endpoint);
            }
        }
        link_candidate_endpoints.sort_unstable();
        Ok(PreparedAcpiPciRoutingTables {
            catalog_generation: self.catalog_generation,
            inventory_generation: self.inventory_generation,
            route_owner_generation: self.route_owner_generation,
            queries: self.queries,
            tables,
            link_candidate_endpoints,
        })
    }
}

impl PreparedAcpiPciRoutingTables {
    pub fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    pub fn inventory_generation(&self) -> u64 {
        self.inventory_generation
    }

    pub fn route_owner_generation(&self) -> u64 {
        self.route_owner_generation
    }

    pub fn queries(&self) -> &[AcpiPciRoutingMethodQuery] {
        &self.queries
    }

    pub fn tables(&self) -> &[PciRoutingTable] {
        &self.tables
    }

    pub fn link_candidate_endpoints(&self) -> &[AcpiPciProviderEndpoint] {
        &self.link_candidate_endpoints
    }

    pub fn is_current(
        &self,
        catalog: &AcpiPciScopeCatalog,
        inventory: &PciInventory,
        routes: &PciInterruptRouteOwner,
    ) -> bool {
        self.catalog_generation == catalog.generation()
            && self.inventory_generation == inventory.generation()
            && self.route_owner_generation == routes.generation()
    }

    /// Resolve every link-backed `_PRT` entry against the union of exact relation-published ACPI
    /// objects and filtered `_CRS` owners below its root endpoint.
    pub fn prepare_interrupt_link_discovery(
        self,
        catalog: &AcpiPciScopeCatalog,
        inventory: &PciInventory,
        routes: &PciInterruptRouteOwner,
        mut filtered_sources: Vec<AcpiPciCrsMethodSource>,
    ) -> Result<PreparedAcpiPciInterruptLinkDiscovery, AcpiPciRoutingDiscoveryError> {
        if !self.is_current(catalog, inventory, routes) {
            return Err(AcpiPciRoutingDiscoveryError::StaleTopology);
        }
        filtered_sources.sort_unstable_by_key(|source| source.endpoint);
        if let Some(pair) = filtered_sources
            .windows(2)
            .find(|pair| pair[0].endpoint == pair[1].endpoint)
        {
            return Err(
                AcpiPciRoutingDiscoveryError::DuplicateLinkCandidateEndpoint(pair[0].endpoint),
            );
        }
        if filtered_sources.len() != self.link_candidate_endpoints.len()
            || filtered_sources
                .iter()
                .zip(&self.link_candidate_endpoints)
                .any(|(source, endpoint)| source.endpoint != *endpoint)
        {
            return Err(AcpiPciRoutingDiscoveryError::IncompleteLinkCandidateSets);
        }

        let link_count = self.tables.iter().try_fold(0usize, |count, table| {
            count.checked_add(
                table
                    .entries
                    .iter()
                    .filter(|entry| matches!(entry.source, PciRouteSource::InterruptLink { .. }))
                    .count(),
            )
        });
        let mut link_queries = Vec::new();
        let mut bindings = Vec::new();
        let link_count = link_count.ok_or(AcpiPciRoutingDiscoveryError::Allocation)?;
        link_queries
            .try_reserve_exact(link_count)
            .map_err(|_| AcpiPciRoutingDiscoveryError::Allocation)?;
        bindings
            .try_reserve_exact(link_count)
            .map_err(|_| AcpiPciRoutingDiscoveryError::Allocation)?;

        for (table_index, (routing_query, table)) in
            self.queries.iter().zip(&self.tables).enumerate()
        {
            let filtered = filtered_sources
                .binary_search_by_key(&routing_query.endpoint, |source| source.endpoint)
                .ok()
                .map(|index| &filtered_sources[index]);
            let mut candidates = Vec::new();
            let relation_count = catalog
                .relation_link_candidates(routing_query.relation_owner)
                .count();
            let filtered_count = filtered.map_or(0, |source| source.methods.objects().len());
            candidates
                .try_reserve_exact(relation_count.saturating_add(filtered_count))
                .map_err(|_| AcpiPciRoutingDiscoveryError::Allocation)?;
            for candidate in catalog.relation_link_candidates(routing_query.relation_owner) {
                push_unique_path(&mut candidates, &candidate.path)?;
            }
            if let Some(filtered) = filtered {
                let root = catalog
                    .sources()
                    .iter()
                    .find(|source| source.endpoint == routing_query.endpoint)
                    .ok_or(AcpiPciRoutingDiscoveryError::StaleTopology)?;
                for method in filtered.methods.objects() {
                    if method.path.name_seg() != Some("_CRS") {
                        return Err(AcpiPciRoutingDiscoveryError::InvalidFilteredLinkMethod);
                    }
                    let owner = method
                        .path
                        .try_parent()
                        .map_err(|error| match error {
                            nt_acpi::AcpiNamespaceError::Allocation => {
                                AcpiPciRoutingDiscoveryError::Allocation
                            }
                            _ => AcpiPciRoutingDiscoveryError::InvalidFilteredLinkMethod,
                        })?
                        .ok_or(AcpiPciRoutingDiscoveryError::InvalidFilteredLinkMethod)?;
                    if owner != root.root.path
                        && !strict_descendant(owner.as_str(), root.root.path.as_str())
                    {
                        return Err(AcpiPciRoutingDiscoveryError::LinkCandidateOutsideEndpoint);
                    }
                    push_unique_owned_path(&mut candidates, owner)?;
                }
            }

            for (entry_index, entry) in table.entries.iter().enumerate() {
                let PciRouteSource::InterruptLink { name, .. } = &entry.source else {
                    continue;
                };
                let candidate_index =
                    resolve_namespace_reference(&routing_query.scope, name, &candidates).map_err(
                        |_| AcpiPciRoutingDiscoveryError::InvalidLinkReference {
                            table_index,
                            entry_index,
                        },
                    )?;
                let object_path = &candidates[candidate_index];
                let query_index = if let Some(index) =
                    link_queries
                        .iter()
                        .position(|query: &AcpiPciInterruptLinkMethodQuery| {
                            query.endpoint == routing_query.endpoint
                                && query.object_path == *object_path
                        }) {
                    index
                } else {
                    let retained_object = object_path
                        .try_clone()
                        .map_err(|_| AcpiPciRoutingDiscoveryError::Allocation)?;
                    let method_path =
                        object_path
                            .try_join_name_seg(*b"_CRS")
                            .map_err(|error| match error {
                                nt_acpi::AcpiNamespaceError::Allocation => {
                                    AcpiPciRoutingDiscoveryError::Allocation
                                }
                                _ => AcpiPciRoutingDiscoveryError::InvalidFilteredLinkMethod,
                            })?;
                    link_queries.push(AcpiPciInterruptLinkMethodQuery {
                        endpoint: routing_query.endpoint,
                        relation_owner: routing_query.relation_owner,
                        object_path: retained_object,
                        method_path,
                    });
                    link_queries.len() - 1
                };
                bindings.push(AcpiPciInterruptLinkBinding {
                    table_index,
                    entry_index,
                    query_index,
                });
            }
        }
        Ok(PreparedAcpiPciInterruptLinkDiscovery {
            catalog_generation: self.catalog_generation,
            inventory_generation: self.inventory_generation,
            route_owner_generation: self.route_owner_generation,
            routing_queries: self.queries,
            tables: self.tables,
            link_queries,
            bindings,
        })
    }
}

impl PreparedAcpiPciInterruptLinkDiscovery {
    pub fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    pub fn inventory_generation(&self) -> u64 {
        self.inventory_generation
    }

    pub fn route_owner_generation(&self) -> u64 {
        self.route_owner_generation
    }

    pub fn routing_queries(&self) -> &[AcpiPciRoutingMethodQuery] {
        &self.routing_queries
    }

    pub fn tables(&self) -> &[PciRoutingTable] {
        &self.tables
    }

    pub fn link_queries(&self) -> &[AcpiPciInterruptLinkMethodQuery] {
        &self.link_queries
    }

    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }

    pub fn is_current(
        &self,
        catalog: &AcpiPciScopeCatalog,
        inventory: &PciInventory,
        routes: &PciInterruptRouteOwner,
    ) -> bool {
        self.catalog_generation == catalog.generation()
            && self.inventory_generation == inventory.generation()
            && self.route_owner_generation == routes.generation()
    }
}

fn push_unique_path(
    paths: &mut Vec<AcpiNamespacePath>,
    path: &AcpiNamespacePath,
) -> Result<(), AcpiPciRoutingDiscoveryError> {
    if paths.iter().any(|candidate| candidate == path) {
        return Ok(());
    }
    paths
        .try_reserve(1)
        .map_err(|_| AcpiPciRoutingDiscoveryError::Allocation)?;
    paths.push(
        path.try_clone()
            .map_err(|_| AcpiPciRoutingDiscoveryError::Allocation)?,
    );
    Ok(())
}

fn push_unique_owned_path(
    paths: &mut Vec<AcpiNamespacePath>,
    path: AcpiNamespacePath,
) -> Result<(), AcpiPciRoutingDiscoveryError> {
    if !paths.iter().any(|candidate| candidate == &path) {
        paths
            .try_reserve(1)
            .map_err(|_| AcpiPciRoutingDiscoveryError::Allocation)?;
        paths.push(path);
    }
    Ok(())
}

fn strict_descendant(path: &str, ancestor: &str) -> bool {
    if ancestor == "\\" {
        return path != "\\";
    }
    path.strip_prefix(ancestor)
        .is_some_and(|suffix| suffix.starts_with('.'))
}

impl AcpiPciScopeCatalog {
    /// Resolve the accepted namespace catalog against the live inventory and derive the complete
    /// `_PRT` evaluation workset. The result remains inert and must be generation-checked after
    /// every asynchronous provider completion.
    pub fn prepare_routing_discovery(
        &self,
        inventory: &PciInventory,
        routes: &PciInterruptRouteOwner,
    ) -> Result<PreparedAcpiPciRoutingDiscovery, AcpiPciScopeError> {
        let resolution = self.prepare_resolution(inventory)?;
        let routing_count = resolution
            .scopes()
            .iter()
            .filter(|scope| scope.routing_table)
            .count();
        let mut queries = Vec::new();
        queries
            .try_reserve_exact(routing_count)
            .map_err(|_| AcpiPciScopeError::Allocation)?;
        for scope in resolution
            .scopes()
            .iter()
            .filter(|scope| scope.routing_table)
        {
            let owner = scope
                .path
                .try_clone()
                .map_err(|_| AcpiPciScopeError::Allocation)?;
            let method_path =
                scope
                    .path
                    .try_join_name_seg(*b"_PRT")
                    .map_err(|error| match error {
                        nt_acpi::AcpiNamespaceError::Allocation => AcpiPciScopeError::Allocation,
                        _ => AcpiPciScopeError::InvalidFilteredMethod,
                    })?;
            queries.push(AcpiPciRoutingMethodQuery {
                relation_owner: scope.relation_owner,
                endpoint: scope.endpoint,
                scope: owner,
                method_path,
                segment: scope.segment,
                bus: scope.bus,
                bridge: scope.bridge,
            });
        }
        Ok(PreparedAcpiPciRoutingDiscovery {
            catalog_generation: resolution.catalog_generation(),
            inventory_generation: resolution.inventory_generation(),
            route_owner_generation: routes.generation(),
            queries,
        })
    }
}
