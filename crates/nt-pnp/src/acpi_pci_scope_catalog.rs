use alloc::vec::Vec;

use nt_acpi::AcpiNamespacePath;

use crate::{PciInventory, PciLocation};

/// Provider facts evaluated on one exact ACPI PCI-root PDO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiPciRootScopeFact {
    pub path: AcpiNamespacePath,
    pub segment: u16,
    pub base_bus: u8,
}

/// One HID-less descendant PCI bridge discovered below an ACPI PCI-root PDO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiPciBridgeScopeFact {
    pub path: AcpiNamespacePath,
    pub adr: u64,
}

/// Complete provider-owned scope facts for one ACPI PCI-root PDO endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiPciScopeSource {
    pub provider_pdo_device_id: u64,
    pub root: AcpiPciRootScopeFact,
    pub bridges: Vec<AcpiPciBridgeScopeFact>,
}

/// One ACPI routing scope correlated to an exact live PCI bus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiPciResolvedScope {
    pub provider_pdo_device_id: u64,
    pub path: AcpiNamespacePath,
    pub segment: u16,
    pub bus: u8,
    pub bridge: Option<PciLocation>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcpiPciScopeError {
    Allocation,
    InvalidProviderEndpoint,
    InvalidBridgeAddress(u64),
    BridgeOutsideRoot,
    DuplicateProviderEndpoint(u64),
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
                .filter(|accepted| accepted.provider_pdo_device_id != source.provider_pdo_device_id)
                .cloned(),
        );
        next.push(source);
        self.prepare_complete(next)
    }

    pub fn prepare_remove_source(
        &self,
        provider_pdo_device_id: u64,
    ) -> Result<PreparedAcpiPciScopeCatalogUpdate, AcpiPciScopeError> {
        if provider_pdo_device_id == 0 {
            return Err(AcpiPciScopeError::InvalidProviderEndpoint);
        }
        let mut next = Vec::new();
        next.try_reserve_exact(self.sources.len())
            .map_err(|_| AcpiPciScopeError::Allocation)?;
        next.extend(
            self.sources
                .iter()
                .filter(|source| source.provider_pdo_device_id != provider_pdo_device_id)
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
            count.checked_add(source.bridges.len().saturating_add(1))
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
                    provider_pdo_device_id: source.provider_pdo_device_id,
                    path: source.root.path.clone(),
                    segment: source.root.segment,
                    bus: source.root.base_bus,
                    bridge: None,
                },
            )?;

            for bridge_fact in &source.bridges {
                let parent = scopes
                    .iter()
                    .filter(|scope| {
                        scope.provider_pdo_device_id == source.provider_pdo_device_id
                            && strict_descendant(bridge_fact.path.as_str(), scope.path.as_str())
                    })
                    .max_by_key(|scope| scope.path.as_str().len())
                    .ok_or(AcpiPciScopeError::MissingParentScope)?;
                let (device, function) = decode_pci_adr(bridge_fact.adr)
                    .ok_or(AcpiPciScopeError::InvalidBridgeAddress(bridge_fact.adr))?;
                let location = PciLocation::new(parent.bus, device, function);
                let pci_bridge = inventory
                    .device(location)
                    .ok_or(AcpiPciScopeError::MissingPciBridge(location))?;
                let buses = pci_bridge
                    .bridge
                    .filter(|_| pci_bridge.is_pci_bridge())
                    .ok_or(AcpiPciScopeError::InvalidPciBridge(location))?;
                if buses.primary != parent.bus {
                    return Err(AcpiPciScopeError::InvalidPciBridge(location));
                }
                push_resolved_scope(
                    &mut scopes,
                    AcpiPciResolvedScope {
                        provider_pdo_device_id: source.provider_pdo_device_id,
                        path: bridge_fact.path.clone(),
                        segment: source.root.segment,
                        bus: buses.secondary,
                        bridge: Some(location),
                    },
                )?;
            }
        }

        for device in inventory.devices() {
            if (1..=4).contains(&device.irq_pin)
                && !scopes.iter().any(|scope| scope.bus == device.bus)
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
    if source.provider_pdo_device_id == 0 {
        return Err(AcpiPciScopeError::InvalidProviderEndpoint);
    }
    source.bridges.sort_unstable_by(|left, right| {
        left.path
            .as_str()
            .len()
            .cmp(&right.path.as_str().len())
            .then_with(|| left.path.as_str().cmp(right.path.as_str()))
    });
    let mut previous_path: Option<&str> = None;
    for bridge in &source.bridges {
        if !strict_descendant(bridge.path.as_str(), source.root.path.as_str()) {
            return Err(AcpiPciScopeError::BridgeOutsideRoot);
        }
        if decode_pci_adr(bridge.adr).is_none() {
            return Err(AcpiPciScopeError::InvalidBridgeAddress(bridge.adr));
        }
        if previous_path == Some(bridge.path.as_str()) {
            return Err(AcpiPciScopeError::DuplicateNamespacePath);
        }
        previous_path = Some(bridge.path.as_str());
    }
    Ok(())
}

fn canonicalize_catalog(sources: &mut [AcpiPciScopeSource]) -> Result<(), AcpiPciScopeError> {
    for source in sources.iter_mut() {
        canonicalize_source(source)?;
    }
    sources.sort_unstable_by_key(|source| source.provider_pdo_device_id);
    for index in 0..sources.len() {
        if index != 0
            && sources[index - 1].provider_pdo_device_id == sources[index].provider_pdo_device_id
        {
            return Err(AcpiPciScopeError::DuplicateProviderEndpoint(
                sources[index].provider_pdo_device_id,
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
        .chain(left.bridges.iter().map(|bridge| &bridge.path))
        .any(|left_path| {
            core::iter::once(&right.root.path)
                .chain(right.bridges.iter().map(|bridge| &bridge.path))
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

    fn source(provider: u64) -> AcpiPciScopeSource {
        AcpiPciScopeSource {
            provider_pdo_device_id: provider,
            root: AcpiPciRootScopeFact {
                path: path("\\_SB_.PCI0"),
                segment: 0,
                base_bus: 0,
            },
            bridges: vec![AcpiPciBridgeScopeFact {
                path: path("\\_SB_.PCI0.BRG0"),
                adr: 1 << 16,
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

        let removal = catalog.prepare_remove_source(44).unwrap();
        assert!(removal.changed());
        assert_eq!(catalog.commit(removal), Ok(2));
        assert!(catalog.sources().is_empty());
    }

    #[test]
    fn bridge_resolution_uses_exact_parent_adr_and_retained_secondary_bus() {
        let inventory = PciInventory::try_from_initial(vec![bridge(), endpoint(2, 4, 1)]).unwrap();
        let mut catalog = AcpiPciScopeCatalog::default();
        let update = catalog.prepare_replace_source(source(44)).unwrap();
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

        let removal = catalog.prepare_remove_source(44).unwrap();
        catalog.commit(removal).unwrap();

        let mut unsupported = source(45);
        unsupported.root.path = path("\\_SB_.PCI1");
        unsupported.root.segment = 1;
        unsupported.bridges.clear();
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

        let removal = catalog.prepare_remove_source(44).unwrap();
        catalog.commit(removal).unwrap();
        assert!(!resolved.is_current(&catalog, &inventory));
    }
}
