use alloc::vec::Vec;

use nt_acpi::AcpiNamespacePath;

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
