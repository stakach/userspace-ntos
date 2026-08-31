use alloc::vec::Vec;

use nt_acpi::{AcpiNamespacePath, PciRouteSource, PciRoutingTable};

use crate::{
    AcpiPciProviderEndpoint, AcpiPciScopeCatalog, AcpiPciScopeError, PciInventory, PciLocation,
};

/// One exact full-path `_PRT` evaluation derived from accepted ACPI and PCI topology facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiPciRoutingMethodQuery {
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
    queries: Vec<AcpiPciRoutingMethodQuery>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcpiPciRoutingDiscoveryError {
    Allocation,
    StaleTopology,
    IncompleteRoutingTables,
    MismatchedRoutingTable(usize),
}

/// Complete checked `_PRT` results retained with their exact discovery workset. Link-candidate
/// enumeration is required only for the listed provider endpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAcpiPciRoutingTables {
    catalog_generation: u64,
    inventory_generation: u64,
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

    pub fn queries(&self) -> &[AcpiPciRoutingMethodQuery] {
        &self.queries
    }

    pub fn is_current(&self, catalog: &AcpiPciScopeCatalog, inventory: &PciInventory) -> bool {
        self.catalog_generation == catalog.generation()
            && self.inventory_generation == inventory.generation()
    }

    /// Accept one parser-validated table for every exact `_PRT` query. No missing or reordered
    /// provider result can advance to link discovery.
    pub fn accept_routing_tables(
        self,
        catalog: &AcpiPciScopeCatalog,
        inventory: &PciInventory,
        tables: Vec<PciRoutingTable>,
    ) -> Result<PreparedAcpiPciRoutingTables, AcpiPciRoutingDiscoveryError> {
        if !self.is_current(catalog, inventory) {
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

    pub fn queries(&self) -> &[AcpiPciRoutingMethodQuery] {
        &self.queries
    }

    pub fn tables(&self) -> &[PciRoutingTable] {
        &self.tables
    }

    pub fn link_candidate_endpoints(&self) -> &[AcpiPciProviderEndpoint] {
        &self.link_candidate_endpoints
    }

    pub fn is_current(&self, catalog: &AcpiPciScopeCatalog, inventory: &PciInventory) -> bool {
        self.catalog_generation == catalog.generation()
            && self.inventory_generation == inventory.generation()
    }
}

impl AcpiPciScopeCatalog {
    /// Resolve the accepted namespace catalog against the live inventory and derive the complete
    /// `_PRT` evaluation workset. The result remains inert and must be generation-checked after
    /// every asynchronous provider completion.
    pub fn prepare_routing_discovery(
        &self,
        inventory: &PciInventory,
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
            queries,
        })
    }
}
