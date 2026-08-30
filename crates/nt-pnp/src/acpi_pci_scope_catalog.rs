use alloc::vec::Vec;

use nt_acpi::{AcpiNamespaceChildren, AcpiNamespaceMatches, AcpiNamespacePath};
use nt_cm_resources::{
    decode_single_bus_number_resource, CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE, INTERFACE_TYPE_INTERNAL,
};

use crate::{PciInventory, PciLocation};

/// Complete authenticated identity of the hosted ACPI PDO used as the evaluation endpoint.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AcpiPciProviderEndpoint {
    pub device_id: u64,
    pub hosted_domain_id: u64,
    pub hosted_domain_cookie: u64,
    pub pdo_object: u64,
}

impl AcpiPciProviderEndpoint {
    fn is_valid(self) -> bool {
        self.device_id != 0
            && self.hosted_domain_id != 0
            && self.hosted_domain_cookie != 0
            && self.pdo_object != 0
    }
}

/// Provider facts evaluated on one exact ACPI PCI-root PDO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiPciRootScopeFact {
    pub hardware_id: AcpiPciRootHardwareId,
    pub path: AcpiNamespacePath,
    pub segment: u16,
    pub base_bus: u8,
    pub routing_table: bool,
}

/// Exact ACPI hardware identity of a PCI root bridge PDO.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcpiPciRootHardwareId {
    Pci,
    PciExpress,
}

/// One HID-less descendant address scope discovered below an ACPI PCI-root PDO. Ordinary PCI
/// endpoints may own `_ADR`; reconciliation retains only functions that are live PCI bridges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiPciAddressScopeFact {
    pub path: AcpiNamespacePath,
    pub adr: u64,
    pub routing_table: bool,
}

/// One checked full-path `_ADR` evaluation requested by filtered namespace discovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiPciAddressMethodQuery {
    pub scope: AcpiNamespacePath,
    pub method_path: AcpiNamespacePath,
    pub routing_table: bool,
}

/// Complete method plan for one root PDO before any `_ADR` values are evaluated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiPciScopeMethodPlan {
    pub root_routing_table: bool,
    pub addresses: Vec<AcpiPciAddressMethodQuery>,
}

/// Complete provider-owned scope facts for one ACPI PCI-root PDO endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiPciScopeSource {
    pub endpoint: AcpiPciProviderEndpoint,
    pub root: AcpiPciRootScopeFact,
    pub addresses: Vec<AcpiPciAddressScopeFact>,
}

/// One ACPI routing scope correlated to an exact live PCI bus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiPciResolvedScope {
    pub endpoint: AcpiPciProviderEndpoint,
    pub path: AcpiNamespacePath,
    pub segment: u16,
    pub bus: u8,
    pub bridge: Option<PciLocation>,
    pub routing_table: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcpiPciScopeError {
    Allocation,
    InvalidProviderEndpoint,
    InvalidRootHardwareId,
    InvalidRootSegment,
    InvalidRootBus,
    InvalidRootBusResource,
    InvalidFilteredMethod,
    RoutingScopeWithoutAddress,
    InvalidAddressScope(u64),
    AddressOutsideRoot,
    DuplicateProviderEndpoint(AcpiPciProviderEndpoint),
    DuplicateNamespacePath,
    GenerationExhausted,
    StaleCatalog,
    UnacceptedCatalog,
    UnacceptedInventory,
    UnsupportedSegment(u16),
    MissingParentScope,
    MissingPciBridge(PciLocation),
    InvalidPciBridge(PciLocation),
    DuplicateResolvedBus(u8),
    MissingRoutingScope(u8),
}

/// Correlate exact multilevel `_ADR` and `_PRT` filter results by their canonical owning scope.
/// The returned `_ADR` queries remain parent-first. A descendant routing scope without an exact
/// `_ADR` owner is ambiguous and rejected; the root scope itself is the sole exception.
pub fn plan_acpi_pci_scope_methods(
    root: &AcpiNamespacePath,
    adr_matches: &AcpiNamespaceMatches,
    prt_matches: &AcpiNamespaceMatches,
) -> Result<AcpiPciScopeMethodPlan, AcpiPciScopeError> {
    let mut prt_scopes = Vec::new();
    prt_scopes
        .try_reserve_exact(prt_matches.objects().len())
        .map_err(|_| AcpiPciScopeError::Allocation)?;
    for method in prt_matches.objects() {
        prt_scopes.push(method_owner(&method.path, "_PRT")?);
    }
    prt_scopes.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
    if prt_scopes.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AcpiPciScopeError::DuplicateNamespacePath);
    }

    let root_routing_table = prt_scopes
        .binary_search_by(|scope| scope.as_str().cmp(root.as_str()))
        .is_ok();
    let mut addresses = Vec::new();
    addresses
        .try_reserve_exact(adr_matches.objects().len())
        .map_err(|_| AcpiPciScopeError::Allocation)?;
    for method in adr_matches.objects() {
        let scope = method_owner(&method.path, "_ADR")?;
        if !strict_descendant(scope.as_str(), root.as_str()) {
            return Err(AcpiPciScopeError::AddressOutsideRoot);
        }
        let routing_table = prt_scopes
            .binary_search_by(|candidate| candidate.as_str().cmp(scope.as_str()))
            .is_ok();
        addresses.push(AcpiPciAddressMethodQuery {
            scope,
            method_path: method.path.clone(),
            routing_table,
        });
    }
    addresses.sort_unstable_by(|left, right| {
        left.scope
            .as_str()
            .len()
            .cmp(&right.scope.as_str().len())
            .then_with(|| left.scope.as_str().cmp(right.scope.as_str()))
    });
    if addresses
        .windows(2)
        .any(|pair| pair[0].scope == pair[1].scope)
    {
        return Err(AcpiPciScopeError::DuplicateNamespacePath);
    }
    if prt_scopes
        .iter()
        .any(|scope| scope != root && !addresses.iter().any(|query| query.scope == *scope))
    {
        return Err(AcpiPciScopeError::RoutingScopeWithoutAddress);
    }
    Ok(AcpiPciScopeMethodPlan {
        root_routing_table,
        addresses,
    })
}

fn method_owner(
    method_path: &AcpiNamespacePath,
    method: &str,
) -> Result<AcpiNamespacePath, AcpiPciScopeError> {
    if method_path.name_seg() != Some(method) {
        return Err(AcpiPciScopeError::InvalidFilteredMethod);
    }
    let owner = match method_path.as_str().rsplit_once('.') {
        Some((owner, _)) => owner,
        None if method_path.as_str().len() == 5 && method_path.as_str().starts_with('\\') => "\\",
        None => return Err(AcpiPciScopeError::InvalidFilteredMethod),
    };
    AcpiNamespacePath::parse(owner).map_err(|_| AcpiPciScopeError::InvalidFilteredMethod)
}

/// Classify only the two ACPI-defined PCI root bridge device identities.
pub fn acpi_pci_root_hardware_id(device_id: &str) -> Option<AcpiPciRootHardwareId> {
    if device_id.eq_ignore_ascii_case("ACPI\\PNP0A03") {
        Some(AcpiPciRootHardwareId::Pci)
    } else if device_id.eq_ignore_ascii_case("ACPI\\PNP0A08") {
        Some(AcpiPciRootHardwareId::PciExpress)
    } else {
        None
    }
}

/// Accept one root scope only when `_BBN` agrees with the exact BusNumber resource emitted by the
/// ReactOS ACPI PDO. The caller resolves missing-method `_SEG`/`_BBN` defaults before this boundary.
pub fn build_acpi_pci_root_scope_fact(
    device_id: &str,
    namespace: &AcpiNamespaceChildren,
    segment: u32,
    base_bus: u32,
    routing_table: bool,
    boot_resources: &[u8],
) -> Result<AcpiPciRootScopeFact, AcpiPciScopeError> {
    let hardware_id =
        acpi_pci_root_hardware_id(device_id).ok_or(AcpiPciScopeError::InvalidRootHardwareId)?;
    let segment = u16::try_from(segment).map_err(|_| AcpiPciScopeError::InvalidRootSegment)?;
    let base_bus = u8::try_from(base_bus).map_err(|_| AcpiPciScopeError::InvalidRootBus)?;
    let resource = decode_single_bus_number_resource(boot_resources)
        .map_err(|_| AcpiPciScopeError::InvalidRootBusResource)?;
    if resource.interface_type != INTERFACE_TYPE_INTERNAL
        || resource.bus_number != 0
        || resource.version != 1
        || resource.revision != 1
        || resource.share != CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE
        || resource.flags != 0
        || resource.start != base_bus as u32
        || resource.length != 1
        || resource.reserved != 0
    {
        return Err(AcpiPciScopeError::InvalidRootBusResource);
    }
    Ok(AcpiPciRootScopeFact {
        hardware_id,
        path: namespace.self_path().clone(),
        segment,
        base_bus,
        routing_table,
    })
}

/// Inert complete catalog replacement. Dropping it leaves accepted provider facts unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAcpiPciScopeCatalogUpdate {
    base_generation: u64,
    target_generation: u64,
    changed: bool,
    next: Vec<AcpiPciScopeSource>,
}

impl PreparedAcpiPciScopeCatalogUpdate {
    pub fn base_generation(&self) -> u64 {
        self.base_generation
    }

    pub fn target_generation(&self) -> u64 {
        self.target_generation
    }

    pub fn changed(&self) -> bool {
        self.changed
    }

    pub fn sources(&self) -> &[AcpiPciScopeSource] {
        &self.next
    }
}

/// Exact catalog/inventory snapshot produced by pure scope reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAcpiPciScopeResolution {
    catalog_generation: u64,
    inventory_generation: u64,
    scopes: Vec<AcpiPciResolvedScope>,
}

impl PreparedAcpiPciScopeResolution {
    pub fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    pub fn inventory_generation(&self) -> u64 {
        self.inventory_generation
    }

    pub fn scopes(&self) -> &[AcpiPciResolvedScope] {
        &self.scopes
    }

    pub fn is_current(&self, catalog: &AcpiPciScopeCatalog, inventory: &PciInventory) -> bool {
        self.catalog_generation == catalog.generation()
            && self.inventory_generation == inventory.generation()
    }
}

/// Durable provider facts. Its generation changes only when accepted ACPI PCI scope facts change;
/// unrelated PnP bus-relation publications cannot invalidate PCI interrupt authority.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AcpiPciScopeCatalog {
    generation: u64,
    sources: Vec<AcpiPciScopeSource>,
}

impl AcpiPciScopeCatalog {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn sources(&self) -> &[AcpiPciScopeSource] {
        &self.sources
    }

    pub fn prepare_replace_source(
        &self,
        mut source: AcpiPciScopeSource,
    ) -> Result<PreparedAcpiPciScopeCatalogUpdate, AcpiPciScopeError> {
        canonicalize_source(&mut source)?;
        let mut next = Vec::new();
        next.try_reserve_exact(self.sources.len().saturating_add(1))
            .map_err(|_| AcpiPciScopeError::Allocation)?;
        next.extend(
            self.sources
                .iter()
                .filter(|accepted| accepted.endpoint != source.endpoint)
                .cloned(),
        );
        next.push(source);
        self.prepare_complete(next)
    }

    pub fn prepare_remove_source(
        &self,
        endpoint: AcpiPciProviderEndpoint,
    ) -> Result<PreparedAcpiPciScopeCatalogUpdate, AcpiPciScopeError> {
        if !endpoint.is_valid() {
            return Err(AcpiPciScopeError::InvalidProviderEndpoint);
        }
        let mut next = Vec::new();
        next.try_reserve_exact(self.sources.len())
            .map_err(|_| AcpiPciScopeError::Allocation)?;
        next.extend(
            self.sources
                .iter()
                .filter(|source| source.endpoint != endpoint)
                .cloned(),
        );
        self.prepare_complete(next)
    }

    fn prepare_complete(
        &self,
        mut next: Vec<AcpiPciScopeSource>,
    ) -> Result<PreparedAcpiPciScopeCatalogUpdate, AcpiPciScopeError> {
        canonicalize_catalog(&mut next)?;
        let changed = next != self.sources;
        let target_generation = if changed {
            self.generation
                .checked_add(1)
                .ok_or(AcpiPciScopeError::GenerationExhausted)?
        } else {
            self.generation
        };
        Ok(PreparedAcpiPciScopeCatalogUpdate {
            base_generation: self.generation,
            target_generation,
            changed,
            next,
        })
    }

    pub fn commit(
        &mut self,
        prepared: PreparedAcpiPciScopeCatalogUpdate,
    ) -> Result<u64, AcpiPciScopeError> {
        let expected_target = if prepared.changed {
            self.generation.wrapping_add(1)
        } else {
            self.generation
        };
        if prepared.base_generation != self.generation
            || prepared.target_generation != expected_target
        {
            return Err(AcpiPciScopeError::StaleCatalog);
        }
        self.generation = prepared.target_generation;
        self.sources = prepared.next;
        Ok(self.generation)
    }

    /// Correlate accepted provider facts to exact retained PCI bridge resources. This does not
    /// mutate the catalog, inventory, or route owner.
    pub fn prepare_resolution(
        &self,
        inventory: &PciInventory,
    ) -> Result<PreparedAcpiPciScopeResolution, AcpiPciScopeError> {
        if self.generation == 0 || self.sources.is_empty() {
            return Err(AcpiPciScopeError::UnacceptedCatalog);
        }
        if inventory.generation() == 0 {
            return Err(AcpiPciScopeError::UnacceptedInventory);
        }

        let scope_capacity = self.sources.iter().try_fold(0usize, |count, source| {
            count.checked_add(source.addresses.len().saturating_add(1))
        });
        let mut scopes = Vec::new();
        scopes
            .try_reserve_exact(scope_capacity.ok_or(AcpiPciScopeError::Allocation)?)
            .map_err(|_| AcpiPciScopeError::Allocation)?;

        for source in &self.sources {
            if source.root.segment != 0 {
                return Err(AcpiPciScopeError::UnsupportedSegment(source.root.segment));
            }
            push_resolved_scope(
                &mut scopes,
                AcpiPciResolvedScope {
                    endpoint: source.endpoint,
                    path: source.root.path.clone(),
                    segment: source.root.segment,
                    bus: source.root.base_bus,
                    bridge: None,
                    routing_table: source.root.routing_table,
                },
            )?;

            for address_fact in &source.addresses {
                let Some(parent) = scopes
                    .iter()
                    .filter(|scope| {
                        scope.endpoint == source.endpoint
                            && strict_descendant(address_fact.path.as_str(), scope.path.as_str())
                    })
                    .max_by_key(|scope| scope.path.as_str().len())
                else {
                    if address_fact.routing_table {
                        return Err(AcpiPciScopeError::MissingParentScope);
                    }
                    continue;
                };
                let (device, function) = decode_pci_adr(address_fact.adr)
                    .ok_or(AcpiPciScopeError::InvalidAddressScope(address_fact.adr))?;
                let location = PciLocation::new(parent.bus, device, function);
                let Some(pci_bridge) = inventory.device(location) else {
                    if address_fact.routing_table {
                        return Err(AcpiPciScopeError::MissingPciBridge(location));
                    }
                    continue;
                };
                let Some(buses) = pci_bridge.bridge.filter(|_| pci_bridge.is_pci_bridge()) else {
                    if address_fact.routing_table {
                        return Err(AcpiPciScopeError::InvalidPciBridge(location));
                    }
                    continue;
                };
                if buses.primary != parent.bus {
                    return Err(AcpiPciScopeError::InvalidPciBridge(location));
                }
                push_resolved_scope(
                    &mut scopes,
                    AcpiPciResolvedScope {
                        endpoint: source.endpoint,
                        path: address_fact.path.clone(),
                        segment: source.root.segment,
                        bus: buses.secondary,
                        bridge: Some(location),
                        routing_table: address_fact.routing_table,
                    },
                )?;
            }
        }

        for device in inventory.devices() {
            if (1..=4).contains(&device.irq_pin)
                && !scopes
                    .iter()
                    .any(|scope| scope.bus == device.bus && scope.routing_table)
            {
                return Err(AcpiPciScopeError::MissingRoutingScope(device.bus));
            }
        }

        Ok(PreparedAcpiPciScopeResolution {
            catalog_generation: self.generation,
            inventory_generation: inventory.generation(),
            scopes,
        })
    }
}

fn canonicalize_source(source: &mut AcpiPciScopeSource) -> Result<(), AcpiPciScopeError> {
    if !source.endpoint.is_valid() {
        return Err(AcpiPciScopeError::InvalidProviderEndpoint);
    }
    source.addresses.sort_unstable_by(|left, right| {
        left.path
            .as_str()
            .len()
            .cmp(&right.path.as_str().len())
            .then_with(|| left.path.as_str().cmp(right.path.as_str()))
    });
    let mut previous_path: Option<&str> = None;
    for address in &source.addresses {
        if !strict_descendant(address.path.as_str(), source.root.path.as_str()) {
            return Err(AcpiPciScopeError::AddressOutsideRoot);
        }
        if decode_pci_adr(address.adr).is_none() {
            return Err(AcpiPciScopeError::InvalidAddressScope(address.adr));
        }
        if previous_path == Some(address.path.as_str()) {
            return Err(AcpiPciScopeError::DuplicateNamespacePath);
        }
        previous_path = Some(address.path.as_str());
    }
    Ok(())
}

fn canonicalize_catalog(sources: &mut [AcpiPciScopeSource]) -> Result<(), AcpiPciScopeError> {
    for source in sources.iter_mut() {
        canonicalize_source(source)?;
    }
    sources.sort_unstable_by_key(|source| source.endpoint);
    for index in 0..sources.len() {
        if index != 0 && sources[index - 1].endpoint == sources[index].endpoint {
            return Err(AcpiPciScopeError::DuplicateProviderEndpoint(
                sources[index].endpoint,
            ));
        }
        for other in 0..index {
            if source_paths_overlap(&sources[index], &sources[other]) {
                return Err(AcpiPciScopeError::DuplicateNamespacePath);
            }
        }
    }
    Ok(())
}

fn source_paths_overlap(left: &AcpiPciScopeSource, right: &AcpiPciScopeSource) -> bool {
    core::iter::once(&left.root.path)
        .chain(left.addresses.iter().map(|address| &address.path))
        .any(|left_path| {
            core::iter::once(&right.root.path)
                .chain(right.addresses.iter().map(|address| &address.path))
                .any(|right_path| left_path == right_path)
        })
}

fn strict_descendant(path: &str, ancestor: &str) -> bool {
    if ancestor == "\\" {
        return path != "\\";
    }
    path.strip_prefix(ancestor)
        .is_some_and(|suffix| suffix.starts_with('.'))
}

fn decode_pci_adr(adr: u64) -> Option<(u8, u8)> {
    if adr > u32::MAX as u64 {
        return None;
    }
    let device = ((adr >> 16) & 0xffff) as u16;
    let function = (adr & 0xffff) as u16;
    (device < 32 && function < 8).then_some((device as u8, function as u8))
}

fn push_resolved_scope(
    scopes: &mut Vec<AcpiPciResolvedScope>,
    scope: AcpiPciResolvedScope,
) -> Result<(), AcpiPciScopeError> {
    if scopes.iter().any(|accepted| accepted.bus == scope.bus) {
        return Err(AcpiPciScopeError::DuplicateResolvedBus(scope.bus));
    }
    scopes.push(scope);
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::{PciBridgeBusNumbers, PciDevice};

    fn path(value: &str) -> AcpiNamespacePath {
        AcpiNamespacePath::parse(value).unwrap()
    }

    fn provider(device_id: u64) -> AcpiPciProviderEndpoint {
        AcpiPciProviderEndpoint {
            device_id,
            hosted_domain_id: 7,
            hosted_domain_cookie: 9,
            pdo_object: 0x1000 + device_id,
        }
    }

    fn source(provider: u64) -> AcpiPciScopeSource {
        AcpiPciScopeSource {
            endpoint: self::provider(provider),
            root: AcpiPciRootScopeFact {
                hardware_id: AcpiPciRootHardwareId::PciExpress,
                path: path("\\_SB_.PCI0"),
                segment: 0,
                base_bus: 0,
                routing_table: true,
            },
            addresses: vec![AcpiPciAddressScopeFact {
                path: path("\\_SB_.PCI0.BRG0"),
                adr: 1 << 16,
                routing_table: true,
            }],
        }
    }

    fn endpoint(bus: u8, device: u8, pin: u8) -> PciDevice {
        PciDevice {
            bus,
            dev: device,
            func: 0,
            vendor: 0x8086,
            device: 0x100e,
            class: 0x020000,
            header_type: 0,
            bridge: None,
            irq_line: 0xff,
            irq_pin: pin,
            bars: vec![],
        }
    }

    fn bridge() -> PciDevice {
        PciDevice {
            bus: 0,
            dev: 1,
            func: 0,
            vendor: 0x8086,
            device: 0x1111,
            class: 0x060400,
            header_type: 1,
            bridge: Some(PciBridgeBusNumbers {
                primary: 0,
                secondary: 2,
                subordinate: 2,
            }),
            irq_line: 0xff,
            irq_pin: 0,
            bars: vec![],
        }
    }

    fn namespace(value: &str) -> AcpiNamespaceChildren {
        nt_acpi::parse_namespace_children(&namespace_output(&[value]), 1).unwrap()
    }

    fn namespace_matches(values: &[&str]) -> AcpiNamespaceMatches {
        nt_acpi::parse_namespace_matches(&namespace_output(values), values.len()).unwrap()
    }

    fn namespace_output(values: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::from_be_bytes(*b"GieA").to_le_bytes());
        bytes.extend_from_slice(&(values.len() as u32).to_le_bytes());
        for value in values {
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&((value.len() + 1) as u32).to_le_bytes());
            bytes.extend_from_slice(value.as_bytes());
            bytes.push(0);
        }
        bytes
    }

    fn root_bus_resources(base_bus: u32) -> [u8; 40] {
        let mut bytes = [0u8; 40];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&(INTERFACE_TYPE_INTERNAL as u32).to_le_bytes());
        bytes[8..12].copy_from_slice(&0u32.to_le_bytes());
        bytes[12..14].copy_from_slice(&1u16.to_le_bytes());
        bytes[14..16].copy_from_slice(&1u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[20] = nt_cm_resources::CM_RESOURCE_TYPE_BUS_NUMBER;
        bytes[21] = CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE;
        bytes[24..28].copy_from_slice(&base_bus.to_le_bytes());
        bytes[28..32].copy_from_slice(&1u32.to_le_bytes());
        bytes
    }

    #[test]
    fn exact_root_identity_and_bus_resource_acceptance_are_provider_shaped() {
        let namespace = namespace("\\_SB_.PCI0");
        let resources = root_bus_resources(7);
        assert_eq!(
            build_acpi_pci_root_scope_fact("acpi\\pnp0a08", &namespace, 0, 7, true, &resources,),
            Ok(AcpiPciRootScopeFact {
                hardware_id: AcpiPciRootHardwareId::PciExpress,
                path: path("\\_SB_.PCI0"),
                segment: 0,
                base_bus: 7,
                routing_table: true,
            })
        );
        assert_eq!(
            acpi_pci_root_hardware_id("ACPI\\PNP0A03"),
            Some(AcpiPciRootHardwareId::Pci)
        );
        assert_eq!(acpi_pci_root_hardware_id("ACPI\\PNP0A08X"), None);

        assert_eq!(
            build_acpi_pci_root_scope_fact("ACPI\\PNP0A08", &namespace, 0, 8, true, &resources,),
            Err(AcpiPciScopeError::InvalidRootBusResource)
        );
        assert_eq!(
            build_acpi_pci_root_scope_fact(
                "ACPI\\PNP0A08",
                &namespace,
                0x1_0000,
                7,
                true,
                &resources,
            ),
            Err(AcpiPciScopeError::InvalidRootSegment)
        );
    }

    #[test]
    fn filtered_method_plan_correlates_exact_adr_and_prt_owners() {
        let root = path("\\_SB_.PCI0");
        let addresses = namespace_matches(&["\\_SB_.PCI0.DEV0._ADR", "\\_SB_.PCI0.BRG0._ADR"]);
        let routes = namespace_matches(&["\\_SB_.PCI0._PRT", "\\_SB_.PCI0.BRG0._PRT"]);
        let plan = plan_acpi_pci_scope_methods(&root, &addresses, &routes).unwrap();
        assert!(plan.root_routing_table);
        assert_eq!(plan.addresses.len(), 2);
        assert_eq!(plan.addresses[0].scope, path("\\_SB_.PCI0.BRG0"));
        assert!(plan.addresses[0].routing_table);
        assert_eq!(plan.addresses[0].method_path, path("\\_SB_.PCI0.BRG0._ADR"));
        assert_eq!(plan.addresses[1].scope, path("\\_SB_.PCI0.DEV0"));
        assert!(!plan.addresses[1].routing_table);

        let orphan_route = namespace_matches(&["\\_SB_.PCI0.GHST._PRT"]);
        assert_eq!(
            plan_acpi_pci_scope_methods(&root, &addresses, &orphan_route),
            Err(AcpiPciScopeError::RoutingScopeWithoutAddress)
        );
        let wrong_filter = namespace_matches(&["\\_SB_.PCI0.BRG0._CRS"]);
        assert_eq!(
            plan_acpi_pci_scope_methods(&root, &wrong_filter, &routes),
            Err(AcpiPciScopeError::InvalidFilteredMethod)
        );
    }

    #[test]
    fn source_updates_are_inert_generation_owned_and_semantic_noops() {
        let mut catalog = AcpiPciScopeCatalog::default();
        let dropped = catalog.prepare_replace_source(source(44)).unwrap();
        assert_eq!(dropped.base_generation(), 0);
        assert_eq!(dropped.target_generation(), 1);
        assert_eq!(catalog.generation(), 0);

        let stale = dropped.clone();
        catalog.commit(dropped).unwrap();
        assert_eq!(catalog.generation(), 1);
        assert_eq!(catalog.commit(stale), Err(AcpiPciScopeError::StaleCatalog));

        let same = catalog.prepare_replace_source(source(44)).unwrap();
        assert!(!same.changed());
        assert_eq!(catalog.commit(same), Ok(1));

        let removal = catalog.prepare_remove_source(provider(44)).unwrap();
        assert!(removal.changed());
        assert_eq!(catalog.commit(removal), Ok(2));
        assert!(catalog.sources().is_empty());
    }

    #[test]
    fn source_identity_requires_the_complete_authenticated_pdo_endpoint() {
        let catalog = AcpiPciScopeCatalog::default();
        let mut invalid = source(44);
        invalid.endpoint.hosted_domain_cookie = 0;
        assert_eq!(
            catalog.prepare_replace_source(invalid),
            Err(AcpiPciScopeError::InvalidProviderEndpoint)
        );

        let mut first = source(44);
        first.addresses.clear();
        let mut second = first.clone();
        second.endpoint.hosted_domain_cookie += 1;
        second.root.path = path("\\_SB_.PCI1");
        let mut accepted = AcpiPciScopeCatalog::default();
        let update = accepted.prepare_replace_source(first).unwrap();
        accepted.commit(update).unwrap();
        let update = accepted.prepare_replace_source(second).unwrap();
        accepted.commit(update).unwrap();
        assert_eq!(accepted.sources().len(), 2);
    }

    #[test]
    fn bridge_resolution_uses_exact_parent_adr_and_retained_secondary_bus() {
        let inventory =
            PciInventory::try_from_initial(vec![bridge(), endpoint(0, 3, 0), endpoint(2, 4, 1)])
                .unwrap();
        let mut catalog = AcpiPciScopeCatalog::default();
        let mut facts = source(44);
        facts.addresses.push(AcpiPciAddressScopeFact {
            path: path("\\_SB_.PCI0.DEV0"),
            adr: 3 << 16,
            routing_table: false,
        });
        let update = catalog.prepare_replace_source(facts).unwrap();
        catalog.commit(update).unwrap();

        let resolved = catalog.prepare_resolution(&inventory).unwrap();
        assert_eq!(resolved.catalog_generation(), 1);
        assert_eq!(resolved.inventory_generation(), 1);
        assert_eq!(resolved.scopes().len(), 2);
        assert_eq!(resolved.scopes()[0].bus, 0);
        assert_eq!(resolved.scopes()[1].bus, 2);
        assert_eq!(resolved.scopes()[1].bridge, Some(PciLocation::new(0, 1, 0)));
        assert!(resolved.is_current(&catalog, &inventory));
    }

    #[test]
    fn ordinary_address_scopes_are_ignored_but_prt_owners_must_be_bridges() {
        let inventory = PciInventory::try_from_initial(vec![endpoint(0, 3, 0)]).unwrap();
        let mut facts = source(44);
        facts.addresses.clear();
        facts.addresses.push(AcpiPciAddressScopeFact {
            path: path("\\_SB_.PCI0.DEV0"),
            adr: 3 << 16,
            routing_table: true,
        });
        let mut catalog = AcpiPciScopeCatalog::default();
        let update = catalog.prepare_replace_source(facts).unwrap();
        catalog.commit(update).unwrap();
        assert_eq!(
            catalog.prepare_resolution(&inventory),
            Err(AcpiPciScopeError::InvalidPciBridge(PciLocation::new(
                0, 3, 0
            )))
        );
    }

    #[test]
    fn incomplete_ambiguous_and_unsupported_scope_facts_fail_closed() {
        let inventory = PciInventory::try_from_initial(vec![endpoint(2, 4, 1)]).unwrap();
        let mut catalog = AcpiPciScopeCatalog::default();
        let update = catalog.prepare_replace_source(source(44)).unwrap();
        catalog.commit(update).unwrap();
        assert_eq!(
            catalog.prepare_resolution(&inventory),
            Err(AcpiPciScopeError::MissingPciBridge(PciLocation::new(
                0, 1, 0
            )))
        );

        let removal = catalog.prepare_remove_source(provider(44)).unwrap();
        catalog.commit(removal).unwrap();

        let mut unsupported = source(45);
        unsupported.root.path = path("\\_SB_.PCI1");
        unsupported.root.segment = 1;
        unsupported.addresses.clear();
        let update = catalog.prepare_replace_source(unsupported).unwrap();
        catalog.commit(update).unwrap();
        assert_eq!(
            catalog.prepare_resolution(&inventory),
            Err(AcpiPciScopeError::UnsupportedSegment(1))
        );
    }

    #[test]
    fn catalog_acceptance_is_independent_of_pci_arrival_order_and_resolution_is_fenced() {
        let mut catalog = AcpiPciScopeCatalog::default();
        let update = catalog.prepare_replace_source(source(44)).unwrap();
        catalog.commit(update).unwrap();

        let inventory = PciInventory::try_from_initial(vec![bridge(), endpoint(2, 4, 1)]).unwrap();
        let resolved = catalog.prepare_resolution(&inventory).unwrap();
        let inventory_update = inventory
            .prepare_rescan(vec![bridge(), endpoint(2, 5, 1)])
            .unwrap();
        let mut newer_inventory = inventory.clone();
        newer_inventory.commit(inventory_update).unwrap();
        assert!(!resolved.is_current(&catalog, &newer_inventory));

        let removal = catalog.prepare_remove_source(provider(44)).unwrap();
        catalog.commit(removal).unwrap();
        assert!(!resolved.is_current(&catalog, &inventory));
    }
}
