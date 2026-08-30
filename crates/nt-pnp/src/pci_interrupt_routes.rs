use alloc::vec::Vec;

use crate::{PciDevice, PciInventory, PciLocation, PreparedPciInventoryUpdate};

/// Function selector carried by an ACPI `_PRT` entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PciRouteFunction {
    /// The ACPI wildcard function (`0xffff`).
    Any,
    Exact(u8),
}

/// Provider-owned PCI INTx route after `_PRT`, link `_CRS`, and MADT override resolution.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PciInterruptRoute {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: PciRouteFunction,
    /// ACPI pin numbering: 0 = INTA through 3 = INTD.
    pub pin: u8,
    /// Physical Global System Interrupt. Zero is valid.
    pub gsi: u32,
    pub level_sensitive: bool,
    pub active_low: bool,
    pub shared: bool,
}

impl PciInterruptRoute {
    fn key(self) -> (u16, u8, u8, u8, PciRouteFunction) {
        (self.segment, self.bus, self.device, self.pin, self.function)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PciInterruptRouteError {
    UnacceptedInventory,
    InvalidAddress(PciInterruptRoute),
    DuplicateRoute(PciInterruptRoute),
    ConflictingSharedGsi(u32),
    MissingRoute(PciLocation, u8),
    InvalidInventoryPin(PciLocation, u8),
    GenerationExhausted,
    StaleOwner,
    StaleInventory,
}

/// Exact authority retained with a downstream interrupt resource assignment.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PciInterruptRouteClaim {
    publication_generation: u64,
    inventory_generation: u64,
    route: PciInterruptRoute,
}

impl PciInterruptRouteClaim {
    pub fn publication_generation(self) -> u64 {
        self.publication_generation
    }

    pub fn inventory_generation(self) -> u64 {
        self.inventory_generation
    }

    pub fn route(self) -> PciInterruptRoute {
        self.route
    }
}

/// Fallibly prepared route replacement. It is inert until committed against the exact inventory
/// generation for which it was decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPciInterruptRoutePublication {
    base_generation: u64,
    target_generation: u64,
    inventory_generation: u64,
    segment: u16,
    routes: Vec<PciInterruptRoute>,
}

impl PreparedPciInterruptRoutePublication {
    pub fn base_generation(&self) -> u64 {
        self.base_generation
    }

    pub fn target_generation(&self) -> u64 {
        self.target_generation
    }

    pub fn inventory_generation(&self) -> u64 {
        self.inventory_generation
    }

    pub fn segment(&self) -> u16 {
        self.segment
    }

    pub fn routes(&self) -> &[PciInterruptRoute] {
        &self.routes
    }
}

/// Accepted provider route set. A topology generation change makes the entire set unusable until
/// the bus transaction publishes a replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciInterruptRouteOwner {
    generation: u64,
    inventory_generation: Option<u64>,
    segment: Option<u16>,
    routes: Vec<PciInterruptRoute>,
}

impl Default for PciInterruptRouteOwner {
    fn default() -> Self {
        Self {
            generation: 0,
            inventory_generation: None,
            segment: None,
            routes: Vec::new(),
        }
    }
}

impl PciInterruptRouteOwner {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn inventory_generation(&self) -> Option<u64> {
        self.inventory_generation
    }

    pub fn segment(&self) -> Option<u16> {
        self.segment
    }

    pub fn routes(&self) -> &[PciInterruptRoute] {
        &self.routes
    }

    /// Prepare routes for the currently accepted inventory. Every present function advertising an
    /// INTx pin must be covered; extra firmware routes for empty slots remain valid for hotplug.
    pub fn prepare_replace(
        &self,
        segment: u16,
        inventory: &PciInventory,
        routes: Vec<PciInterruptRoute>,
    ) -> Result<PreparedPciInterruptRoutePublication, PciInterruptRouteError> {
        self.prepare_for_generation(segment, inventory.generation(), inventory.devices(), routes)
    }

    /// Prepare routes alongside a rescan. Commit the inventory first, then this publication while
    /// the serialized bus transaction still owns both generations.
    pub fn prepare_replace_for_update(
        &self,
        segment: u16,
        inventory: &PreparedPciInventoryUpdate,
        routes: Vec<PciInterruptRoute>,
    ) -> Result<PreparedPciInterruptRoutePublication, PciInterruptRouteError> {
        self.prepare_for_generation(
            segment,
            inventory.target_generation(),
            inventory.devices(),
            routes,
        )
    }

    fn prepare_for_generation(
        &self,
        segment: u16,
        inventory_generation: u64,
        devices: &[PciDevice],
        mut routes: Vec<PciInterruptRoute>,
    ) -> Result<PreparedPciInterruptRoutePublication, PciInterruptRouteError> {
        if inventory_generation == 0 {
            return Err(PciInterruptRouteError::UnacceptedInventory);
        }
        let target_generation = self
            .generation
            .checked_add(1)
            .ok_or(PciInterruptRouteError::GenerationExhausted)?;
        canonicalize(segment, &mut routes)?;
        validate_coverage(segment, devices, &routes)?;
        Ok(PreparedPciInterruptRoutePublication {
            base_generation: self.generation,
            target_generation,
            inventory_generation,
            segment,
            routes,
        })
    }

    /// Publish only while both the owner and inventory generations remain exact.
    pub fn commit(
        &mut self,
        prepared: PreparedPciInterruptRoutePublication,
        inventory: &PciInventory,
    ) -> Result<u64, PciInterruptRouteError> {
        if prepared.base_generation != self.generation
            || prepared.target_generation != self.generation.wrapping_add(1)
        {
            return Err(PciInterruptRouteError::StaleOwner);
        }
        if prepared.inventory_generation != inventory.generation() {
            return Err(PciInterruptRouteError::StaleInventory);
        }
        self.generation = prepared.target_generation;
        self.inventory_generation = Some(prepared.inventory_generation);
        self.segment = Some(prepared.segment);
        self.routes = prepared.routes;
        Ok(self.generation)
    }

    /// Revoke the complete publication. No inventory is required on this failure/removal path.
    pub fn revoke(&mut self, expected_generation: u64) -> Result<u64, PciInterruptRouteError> {
        if expected_generation != self.generation {
            return Err(PciInterruptRouteError::StaleOwner);
        }
        let next = self
            .generation
            .checked_add(1)
            .ok_or(PciInterruptRouteError::GenerationExhausted)?;
        self.generation = next;
        self.inventory_generation = None;
        self.segment = None;
        self.routes.clear();
        Ok(next)
    }

    /// Resolve the route for a currently present function and its bus-reported interrupt pin.
    /// Exact-function entries override a wildcard entry for the same slot and pin.
    pub fn resolve(
        &self,
        inventory: &PciInventory,
        segment: u16,
        location: PciLocation,
    ) -> Result<Option<PciInterruptRouteClaim>, PciInterruptRouteError> {
        if self.inventory_generation != Some(inventory.generation())
            || self.segment != Some(segment)
        {
            return Err(PciInterruptRouteError::StaleInventory);
        }
        let Some(device) = inventory.device(location) else {
            return Ok(None);
        };
        if device.irq_pin == 0 {
            return Ok(None);
        }
        if device.irq_pin > 4 {
            return Err(PciInterruptRouteError::InvalidInventoryPin(
                location,
                device.irq_pin,
            ));
        }
        let pin = device.irq_pin - 1;
        let exact = self.routes.iter().copied().find(|route| {
            route_matches(*route, segment, location, pin)
                && matches!(route.function, PciRouteFunction::Exact(_))
        });
        let route = exact.or_else(|| {
            self.routes.iter().copied().find(|route| {
                route_matches(*route, segment, location, pin)
                    && route.function == PciRouteFunction::Any
            })
        });
        Ok(route.map(|route| PciInterruptRouteClaim {
            publication_generation: self.generation,
            inventory_generation: inventory.generation(),
            route,
        }))
    }

    /// Revalidate a retained claim immediately before resource publication or capability minting.
    pub fn validate(
        &self,
        inventory: &PciInventory,
        claim: PciInterruptRouteClaim,
    ) -> Result<PciInterruptRoute, PciInterruptRouteError> {
        if claim.publication_generation != self.generation {
            return Err(PciInterruptRouteError::StaleOwner);
        }
        if claim.inventory_generation != inventory.generation()
            || self.inventory_generation != Some(claim.inventory_generation)
            || self.segment != Some(claim.route.segment)
        {
            return Err(PciInterruptRouteError::StaleInventory);
        }
        if self
            .routes
            .binary_search_by_key(&claim.route.key(), |route| route.key())
            .is_err()
        {
            return Err(PciInterruptRouteError::StaleOwner);
        }
        Ok(claim.route)
    }
}

fn route_matches(route: PciInterruptRoute, segment: u16, location: PciLocation, pin: u8) -> bool {
    route.segment == segment
        && route.bus == location.bus
        && route.device == location.device
        && route.pin == pin
        && match route.function {
            PciRouteFunction::Any => true,
            PciRouteFunction::Exact(function) => function == location.function,
        }
}

fn validate_coverage(
    segment: u16,
    devices: &[PciDevice],
    routes: &[PciInterruptRoute],
) -> Result<(), PciInterruptRouteError> {
    for device in devices {
        if device.irq_pin == 0 {
            continue;
        }
        let location = PciLocation::from(device);
        if device.irq_pin > 4 {
            return Err(PciInterruptRouteError::InvalidInventoryPin(
                location,
                device.irq_pin,
            ));
        }
        let pin = device.irq_pin - 1;
        if !routes
            .iter()
            .copied()
            .any(|route| route_matches(route, segment, location, pin))
        {
            return Err(PciInterruptRouteError::MissingRoute(location, pin));
        }
    }
    Ok(())
}

fn canonicalize(
    segment: u16,
    routes: &mut [PciInterruptRoute],
) -> Result<(), PciInterruptRouteError> {
    routes.sort_unstable_by_key(|route| route.key());
    let mut previous = None;
    for route in routes.iter().copied() {
        if route.segment != segment
            || route.device >= 32
            || route.pin >= 4
            || matches!(route.function, PciRouteFunction::Exact(function) if function >= 8)
        {
            return Err(PciInterruptRouteError::InvalidAddress(route));
        }
        if previous == Some(route.key()) {
            return Err(PciInterruptRouteError::DuplicateRoute(route));
        }
        previous = Some(route.key());
    }
    for (index, route) in routes.iter().enumerate() {
        for alias in &routes[index + 1..] {
            if alias.gsi == route.gsi
                && (!route.shared
                    || !alias.shared
                    || alias.level_sensitive != route.level_sensitive
                    || alias.active_low != route.active_low)
            {
                return Err(PciInterruptRouteError::ConflictingSharedGsi(route.gsi));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn device(bus: u8, slot: u8, function: u8, pin: u8) -> PciDevice {
        PciDevice {
            bus,
            dev: slot,
            func: function,
            vendor: 0x8086,
            device: 0x100e,
            class: 0x020000,
            irq_line: 0xff,
            irq_pin: pin,
            bars: vec![],
        }
    }

    fn route(
        bus: u8,
        slot: u8,
        function: PciRouteFunction,
        pin: u8,
        gsi: u32,
    ) -> PciInterruptRoute {
        PciInterruptRoute {
            segment: 0,
            bus,
            device: slot,
            function,
            pin,
            gsi,
            level_sensitive: true,
            active_low: true,
            shared: true,
        }
    }

    #[test]
    fn wildcard_routes_cover_multiple_functions_and_buses_without_swizzling() {
        let inventory = PciInventory::try_from_initial(vec![
            device(0, 3, 0, 1),
            device(0, 3, 3, 1),
            device(2, 3, 0, 2),
        ])
        .unwrap();
        let mut owner = PciInterruptRouteOwner::default();
        let prepared = owner
            .prepare_replace(
                0,
                &inventory,
                vec![
                    route(2, 3, PciRouteFunction::Any, 1, 33),
                    route(0, 3, PciRouteFunction::Any, 0, 17),
                ],
            )
            .unwrap();
        owner.commit(prepared, &inventory).unwrap();

        for (location, gsi) in [
            (PciLocation::new(0, 3, 0), 17),
            (PciLocation::new(0, 3, 3), 17),
            (PciLocation::new(2, 3, 0), 33),
        ] {
            assert_eq!(
                owner
                    .resolve(&inventory, 0, location)
                    .unwrap()
                    .unwrap()
                    .route()
                    .gsi,
                gsi
            );
        }
    }

    #[test]
    fn exact_route_overrides_wildcard_deterministically() {
        let inventory =
            PciInventory::try_from_initial(vec![device(0, 3, 0, 1), device(0, 3, 1, 1)]).unwrap();
        let mut owner = PciInterruptRouteOwner::default();
        let prepared = owner
            .prepare_replace(
                0,
                &inventory,
                vec![
                    route(0, 3, PciRouteFunction::Any, 0, 16),
                    route(0, 3, PciRouteFunction::Exact(1), 0, 17),
                ],
            )
            .unwrap();
        owner.commit(prepared, &inventory).unwrap();
        assert_eq!(
            owner
                .resolve(&inventory, 0, PciLocation::new(0, 3, 0))
                .unwrap()
                .unwrap()
                .route()
                .gsi,
            16
        );
        assert_eq!(
            owner
                .resolve(&inventory, 0, PciLocation::new(0, 3, 1))
                .unwrap()
                .unwrap()
                .route()
                .gsi,
            17
        );
    }

    #[test]
    fn incomplete_candidate_cannot_replace_active_routes() {
        let inventory =
            PciInventory::try_from_initial(vec![device(0, 3, 0, 1), device(0, 4, 0, 1)]).unwrap();
        let mut owner = PciInterruptRouteOwner::default();
        let accepted = owner
            .prepare_replace(
                0,
                &inventory,
                vec![
                    route(0, 3, PciRouteFunction::Any, 0, 16),
                    route(0, 4, PciRouteFunction::Any, 0, 17),
                ],
            )
            .unwrap();
        owner.commit(accepted, &inventory).unwrap();
        let generation = owner.generation();
        assert_eq!(
            owner.prepare_replace(
                0,
                &inventory,
                vec![route(0, 3, PciRouteFunction::Any, 0, 16)],
            ),
            Err(PciInterruptRouteError::MissingRoute(
                PciLocation::new(0, 4, 0),
                0,
            ))
        );
        assert_eq!(owner.generation(), generation);
        assert_eq!(owner.routes().len(), 2);
    }

    #[test]
    fn stale_inventory_cannot_publish_or_resolve_routes() {
        let first = device(0, 3, 0, 1);
        let mut inventory = PciInventory::try_from_initial(vec![first.clone()]).unwrap();
        let mut owner = PciInterruptRouteOwner::default();
        let stale = owner
            .prepare_replace(
                0,
                &inventory,
                vec![route(0, 3, PciRouteFunction::Any, 0, 16)],
            )
            .unwrap();
        let update = inventory
            .prepare_rescan(vec![first, device(0, 4, 0, 1)])
            .unwrap();
        inventory.commit(update).unwrap();
        assert_eq!(
            owner.commit(stale, &inventory),
            Err(PciInterruptRouteError::StaleInventory)
        );

        let current = owner
            .prepare_replace(
                0,
                &inventory,
                vec![
                    route(0, 3, PciRouteFunction::Any, 0, 16),
                    route(0, 4, PciRouteFunction::Any, 0, 17),
                ],
            )
            .unwrap();
        owner.commit(current, &inventory).unwrap();
        let next = inventory.prepare_rescan(vec![device(0, 4, 0, 1)]).unwrap();
        inventory.commit(next).unwrap();
        assert_eq!(
            owner.resolve(&inventory, 0, PciLocation::new(0, 4, 0)),
            Err(PciInterruptRouteError::StaleInventory)
        );
    }

    #[test]
    fn routes_prepare_for_target_inventory_generation() {
        let first = device(0, 3, 0, 1);
        let mut inventory = PciInventory::try_from_initial(vec![first.clone()]).unwrap();
        let mut owner = PciInterruptRouteOwner::default();
        let update = inventory
            .prepare_rescan(vec![first, device(5, 2, 0, 4)])
            .unwrap();
        let routes = owner
            .prepare_replace_for_update(
                0,
                &update,
                vec![
                    route(0, 3, PciRouteFunction::Any, 0, 16),
                    route(5, 2, PciRouteFunction::Any, 3, 72),
                ],
            )
            .unwrap();
        assert_eq!(routes.inventory_generation(), update.target_generation());
        inventory.commit(update).unwrap();
        owner.commit(routes, &inventory).unwrap();
        assert_eq!(
            owner
                .resolve(&inventory, 0, PciLocation::new(5, 2, 0))
                .unwrap()
                .unwrap()
                .route()
                .gsi,
            72
        );
    }

    #[test]
    fn pinless_devices_accept_empty_authoritative_set_without_irq_line_fallback() {
        let mut no_pin = device(0, 3, 0, 0);
        no_pin.irq_line = 11;
        let inventory = PciInventory::try_from_initial(vec![no_pin]).unwrap();
        let mut owner = PciInterruptRouteOwner::default();
        let prepared = owner.prepare_replace(0, &inventory, vec![]).unwrap();
        owner.commit(prepared, &inventory).unwrap();
        assert_eq!(
            owner
                .resolve(&inventory, 0, PciLocation::new(0, 3, 0))
                .unwrap(),
            None
        );
    }

    #[test]
    fn malformed_addresses_duplicate_routes_and_inventory_pins_fail_closed() {
        let inventory = PciInventory::try_from_initial(vec![device(0, 3, 0, 1)]).unwrap();
        let owner = PciInterruptRouteOwner::default();
        let invalid = route(0, 32, PciRouteFunction::Any, 0, 16);
        assert_eq!(
            owner.prepare_replace(0, &inventory, vec![invalid]),
            Err(PciInterruptRouteError::InvalidAddress(invalid))
        );
        let duplicate = route(0, 3, PciRouteFunction::Any, 0, 16);
        assert_eq!(
            owner.prepare_replace(0, &inventory, vec![duplicate, duplicate]),
            Err(PciInterruptRouteError::DuplicateRoute(duplicate))
        );

        let invalid_pin_inventory =
            PciInventory::try_from_initial(vec![device(0, 3, 0, 5)]).unwrap();
        assert_eq!(
            owner.prepare_replace(0, &invalid_pin_inventory, vec![]),
            Err(PciInterruptRouteError::InvalidInventoryPin(
                PciLocation::new(0, 3, 0),
                5,
            ))
        );
    }

    #[test]
    fn shared_gsi_requires_consistent_electrical_attributes_and_sharing() {
        let inventory =
            PciInventory::try_from_initial(vec![device(0, 3, 0, 1), device(0, 4, 0, 1)]).unwrap();
        let owner = PciInterruptRouteOwner::default();
        let first = route(0, 3, PciRouteFunction::Any, 0, 0);
        let mut conflicting = route(0, 4, PciRouteFunction::Any, 0, 0);
        conflicting.active_low = false;
        assert_eq!(
            owner.prepare_replace(0, &inventory, vec![first, conflicting]),
            Err(PciInterruptRouteError::ConflictingSharedGsi(0))
        );
        let mut exclusive = route(0, 4, PciRouteFunction::Any, 0, 0);
        exclusive.shared = false;
        assert_eq!(
            owner.prepare_replace(0, &inventory, vec![first, exclusive]),
            Err(PciInterruptRouteError::ConflictingSharedGsi(0))
        );
        assert!(owner
            .prepare_replace(
                0,
                &inventory,
                vec![first, route(0, 4, PciRouteFunction::Any, 0, 0)],
            )
            .is_ok());
    }

    #[test]
    fn revocation_invalidates_retained_claims() {
        let inventory = PciInventory::try_from_initial(vec![device(0, 3, 0, 1)]).unwrap();
        let mut owner = PciInterruptRouteOwner::default();
        let first = owner
            .prepare_replace(
                0,
                &inventory,
                vec![route(0, 3, PciRouteFunction::Any, 0, 0)],
            )
            .unwrap();
        owner.commit(first, &inventory).unwrap();
        let claim = owner
            .resolve(&inventory, 0, PciLocation::new(0, 3, 0))
            .unwrap()
            .unwrap();
        assert_eq!(owner.validate(&inventory, claim).unwrap().gsi, 0);
        owner.revoke(claim.publication_generation()).unwrap();
        assert_eq!(
            owner.validate(&inventory, claim),
            Err(PciInterruptRouteError::StaleOwner)
        );
        assert_eq!(
            owner.resolve(&inventory, 0, PciLocation::new(0, 3, 0)),
            Err(PciInterruptRouteError::StaleInventory)
        );
    }
}
