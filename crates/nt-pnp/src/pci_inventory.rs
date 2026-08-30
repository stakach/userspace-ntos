use alloc::vec::Vec;

use crate::{PciDevice, PciFunctionSnapshot};

/// Stable bus identity for one PCI function.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PciLocation {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciLocation {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }
}

impl From<&PciDevice> for PciLocation {
    fn from(device: &PciDevice) -> Self {
        Self::new(device.bus, device.dev, device.func)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PciInventoryError {
    Allocation,
    InvalidLocation(PciLocation),
    DuplicateLocation(PciLocation),
    GenerationExhausted,
    StaleUpdate,
}

/// A bus-owned resource change for an otherwise identical function at the same BDF.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciResourceChange {
    pub previous: PciDevice,
    pub current: PciDevice,
}

/// A fallibly prepared inventory transition. Preparing this value never mutates the accepted
/// inventory, so callers can reserve PDOs, resource grants, and notification records first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPciInventoryUpdate {
    base_generation: u64,
    target_generation: u64,
    next: Vec<PciDevice>,
    departures: Vec<PciDevice>,
    arrivals: Vec<PciDevice>,
    resource_changes: Vec<PciResourceChange>,
}

/// Read-only topology delta. It never authorizes BAR probing or inventory mutation; arrivals must
/// first complete any same-location departure and then be probed as quiescent functions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPciCensus {
    base_generation: u64,
    snapshots: Vec<PciFunctionSnapshot>,
    departures: Vec<PciDevice>,
    arrivals: Vec<PciFunctionSnapshot>,
    retained: Vec<PciLocation>,
}

impl PreparedPciCensus {
    pub fn base_generation(&self) -> u64 {
        self.base_generation
    }

    pub fn snapshots(&self) -> &[PciFunctionSnapshot] {
        &self.snapshots
    }

    pub fn departures(&self) -> &[PciDevice] {
        &self.departures
    }

    pub fn arrivals(&self) -> &[PciFunctionSnapshot] {
        &self.arrivals
    }

    pub fn retained(&self) -> &[PciLocation] {
        &self.retained
    }
}

impl PreparedPciInventoryUpdate {
    pub fn base_generation(&self) -> u64 {
        self.base_generation
    }

    pub fn target_generation(&self) -> u64 {
        self.target_generation
    }

    pub fn devices(&self) -> &[PciDevice] {
        &self.next
    }

    pub fn departures(&self) -> &[PciDevice] {
        &self.departures
    }

    pub fn arrivals(&self) -> &[PciDevice] {
        &self.arrivals
    }

    pub fn resource_changes(&self) -> &[PciResourceChange] {
        &self.resource_changes
    }

    pub fn has_actions(&self) -> bool {
        !self.departures.is_empty()
            || !self.arrivals.is_empty()
            || !self.resource_changes.is_empty()
    }
}

/// The exact action set committed with one accepted scan generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedPciInventoryUpdate {
    pub generation: u64,
    pub departures: Vec<PciDevice>,
    pub arrivals: Vec<PciDevice>,
    pub resource_changes: Vec<PciResourceChange>,
}

/// Accepted PCI topology and resource snapshot. Only [`PciInventory::commit`] mutates it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciInventory {
    generation: u64,
    devices: Vec<PciDevice>,
}

impl Default for PciInventory {
    fn default() -> Self {
        Self {
            generation: 0,
            devices: Vec::new(),
        }
    }
}

impl PciInventory {
    /// Install the initial accepted bus snapshot without manufacturing arrival actions.
    pub fn try_from_initial(mut devices: Vec<PciDevice>) -> Result<Self, PciInventoryError> {
        canonicalize(&mut devices)?;
        Ok(Self {
            generation: 1,
            devices,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn devices(&self) -> &[PciDevice] {
        &self.devices
    }

    pub fn device(&self, location: PciLocation) -> Option<&PciDevice> {
        self.devices
            .binary_search_by_key(&location, PciLocation::from)
            .ok()
            .map(|index| &self.devices[index])
    }

    /// Prepare a complete replacement snapshot without changing accepted state.
    pub fn prepare_rescan(
        &self,
        mut next: Vec<PciDevice>,
    ) -> Result<PreparedPciInventoryUpdate, PciInventoryError> {
        canonicalize(&mut next)?;
        let target_generation = self
            .generation
            .checked_add(1)
            .ok_or(PciInventoryError::GenerationExhausted)?;

        let mut departures = Vec::new();
        let mut arrivals = Vec::new();
        let mut resource_changes = Vec::new();
        departures
            .try_reserve_exact(self.devices.len())
            .map_err(|_| PciInventoryError::Allocation)?;
        arrivals
            .try_reserve_exact(next.len())
            .map_err(|_| PciInventoryError::Allocation)?;
        resource_changes
            .try_reserve_exact(core::cmp::min(self.devices.len(), next.len()))
            .map_err(|_| PciInventoryError::Allocation)?;

        let mut old_index = 0;
        let mut new_index = 0;
        while old_index < self.devices.len() || new_index < next.len() {
            let old = self.devices.get(old_index);
            let new = next.get(new_index);
            match (old, new) {
                (Some(old), Some(new)) => {
                    let old_location = PciLocation::from(old);
                    let new_location = PciLocation::from(new);
                    match old_location.cmp(&new_location) {
                        core::cmp::Ordering::Less => {
                            departures.push(old.clone());
                            old_index += 1;
                        }
                        core::cmp::Ordering::Greater => {
                            arrivals.push(new.clone());
                            new_index += 1;
                        }
                        core::cmp::Ordering::Equal => {
                            if !same_hardware_identity(old, new) {
                                departures.push(old.clone());
                                arrivals.push(new.clone());
                            } else if bus_owned_resources_changed(old, new) {
                                resource_changes.push(PciResourceChange {
                                    previous: old.clone(),
                                    current: new.clone(),
                                });
                            }
                            old_index += 1;
                            new_index += 1;
                        }
                    }
                }
                (Some(old), None) => {
                    departures.push(old.clone());
                    old_index += 1;
                }
                (None, Some(new)) => {
                    arrivals.push(new.clone());
                    new_index += 1;
                }
                (None, None) => break,
            }
        }

        Ok(PreparedPciInventoryUpdate {
            base_generation: self.generation,
            target_generation,
            next,
            departures,
            arrivals,
            resource_changes,
        })
    }

    /// Compare a non-mutating hardware census with the accepted inventory. This prepares only
    /// topology ownership; it cannot commit because newly arrived functions do not yet have probed
    /// resource extents.
    pub fn prepare_census(
        &self,
        mut snapshots: Vec<PciFunctionSnapshot>,
    ) -> Result<PreparedPciCensus, PciInventoryError> {
        canonicalize_snapshots(&mut snapshots)?;
        let mut departures = Vec::new();
        let mut arrivals = Vec::new();
        let mut retained = Vec::new();
        departures
            .try_reserve_exact(self.devices.len())
            .map_err(|_| PciInventoryError::Allocation)?;
        arrivals
            .try_reserve_exact(snapshots.len())
            .map_err(|_| PciInventoryError::Allocation)?;
        retained
            .try_reserve_exact(core::cmp::min(self.devices.len(), snapshots.len()))
            .map_err(|_| PciInventoryError::Allocation)?;

        let mut old_index = 0;
        let mut new_index = 0;
        while old_index < self.devices.len() || new_index < snapshots.len() {
            let old = self.devices.get(old_index);
            let new = snapshots.get(new_index);
            match (old, new) {
                (Some(old), Some(new)) => match PciLocation::from(old).cmp(&new.location()) {
                    core::cmp::Ordering::Less => {
                        departures.push(old.clone());
                        old_index += 1;
                    }
                    core::cmp::Ordering::Greater => {
                        arrivals.push(*new);
                        new_index += 1;
                    }
                    core::cmp::Ordering::Equal => {
                        if new.same_hardware_identity(old) {
                            retained.push(new.location());
                        } else {
                            departures.push(old.clone());
                            arrivals.push(*new);
                        }
                        old_index += 1;
                        new_index += 1;
                    }
                },
                (Some(old), None) => {
                    departures.push(old.clone());
                    old_index += 1;
                }
                (None, Some(new)) => {
                    arrivals.push(*new);
                    new_index += 1;
                }
                (None, None) => break,
            }
        }
        Ok(PreparedPciCensus {
            base_generation: self.generation,
            snapshots,
            departures,
            arrivals,
            retained,
        })
    }

    pub fn commit(
        &mut self,
        prepared: PreparedPciInventoryUpdate,
    ) -> Result<CommittedPciInventoryUpdate, PciInventoryError> {
        if prepared.base_generation != self.generation
            || prepared.target_generation != self.generation.wrapping_add(1)
        {
            return Err(PciInventoryError::StaleUpdate);
        }
        self.generation = prepared.target_generation;
        self.devices = prepared.next;
        Ok(CommittedPciInventoryUpdate {
            generation: self.generation,
            departures: prepared.departures,
            arrivals: prepared.arrivals,
            resource_changes: prepared.resource_changes,
        })
    }
}

fn canonicalize(devices: &mut [PciDevice]) -> Result<(), PciInventoryError> {
    devices.sort_unstable_by_key(|device| PciLocation::from(device));
    let mut previous = None;
    for device in devices {
        let location = PciLocation::from(&*device);
        if location.device >= 32 || location.function >= 8 {
            return Err(PciInventoryError::InvalidLocation(location));
        }
        if previous == Some(location) {
            return Err(PciInventoryError::DuplicateLocation(location));
        }
        previous = Some(location);
    }
    Ok(())
}

fn canonicalize_snapshots(snapshots: &mut [PciFunctionSnapshot]) -> Result<(), PciInventoryError> {
    snapshots.sort_unstable_by_key(|snapshot| snapshot.location());
    let mut previous = None;
    for snapshot in snapshots {
        let location = snapshot.location();
        if location.device >= 32 || location.function >= 8 {
            return Err(PciInventoryError::InvalidLocation(location));
        }
        if previous == Some(location) {
            return Err(PciInventoryError::DuplicateLocation(location));
        }
        previous = Some(location);
    }
    Ok(())
}

fn same_hardware_identity(previous: &PciDevice, current: &PciDevice) -> bool {
    previous.vendor == current.vendor
        && previous.device == current.device
        && previous.class == current.class
}

fn bus_owned_resources_changed(previous: &PciDevice, current: &PciDevice) -> bool {
    previous.irq_pin != current.irq_pin || previous.bars != current.bars
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn function(bus: u8, device: u8, vendor: u16, product: u16, bar_base: u64) -> PciDevice {
        PciDevice {
            bus,
            dev: device,
            func: 0,
            vendor,
            device: product,
            class: 0x020000,
            irq_line: 11,
            irq_pin: 1,
            bars: vec![crate::Bar {
                index: 0,
                is_io: false,
                is_64bit: false,
                prefetchable: false,
                base: bar_base,
                size: 0x20_000,
                maximum_address: u32::MAX as u64,
            }],
        }
    }

    fn snapshot(device: &PciDevice) -> PciFunctionSnapshot {
        let mut raw_bars = [0; crate::PCI_NUM_BARS];
        for bar in &device.bars {
            raw_bars[bar.index as usize] = bar.base as u32
                | u32::from(bar.is_io)
                | (u32::from(bar.is_64bit) << 2)
                | (u32::from(bar.prefetchable) << 3);
            if bar.is_64bit {
                raw_bars[bar.index as usize + 1] = (bar.base >> 32) as u32;
            }
        }
        PciFunctionSnapshot {
            bus: device.bus,
            dev: device.dev,
            func: device.func,
            vendor: device.vendor,
            device: device.device,
            class: device.class,
            irq_line: device.irq_line,
            irq_pin: device.irq_pin,
            header_type: 0,
            bar_count: 6,
            raw_bars,
        }
    }

    #[test]
    fn two_functions_remove_and_readd_without_disturbing_the_sibling() {
        let removed = function(0, 3, 0x8086, 0x100e, 0xfebc_0000);
        let sibling = function(0, 4, 0x8086, 0x100e, 0xfeba_0000);
        let mut inventory =
            PciInventory::try_from_initial(vec![sibling.clone(), removed.clone()]).unwrap();
        assert_eq!(inventory.devices(), &[removed.clone(), sibling.clone()]);

        let removal = inventory.prepare_rescan(vec![sibling.clone()]).unwrap();
        assert_eq!(removal.departures(), &[removed.clone()]);
        assert!(removal.arrivals().is_empty());
        inventory.commit(removal).unwrap();
        assert_eq!(inventory.devices(), &[sibling.clone()]);

        let arrival = inventory
            .prepare_rescan(vec![sibling.clone(), removed.clone()])
            .unwrap();
        assert_eq!(arrival.arrivals(), &[removed.clone()]);
        assert!(arrival.departures().is_empty());
        inventory.commit(arrival).unwrap();
        assert_eq!(inventory.devices(), &[removed, sibling]);
    }

    #[test]
    fn occupied_location_hardware_replacement_is_departure_then_arrival() {
        let old = function(0, 3, 0x8086, 0x100e, 0xfebc_0000);
        let replacement = function(0, 3, 0x1234, 0x5678, 0xfebc_0000);
        let inventory = PciInventory::try_from_initial(vec![old.clone()]).unwrap();

        let prepared = inventory.prepare_rescan(vec![replacement.clone()]).unwrap();
        assert_eq!(prepared.departures(), &[old]);
        assert_eq!(prepared.arrivals(), &[replacement]);
        assert!(prepared.resource_changes().is_empty());
    }

    #[test]
    fn resource_change_is_distinct_from_observed_irq_line_refresh() {
        let old = function(0, 3, 0x8086, 0x100e, 0xfebc_0000);
        let mut refreshed = old.clone();
        refreshed.irq_line = 5;
        let mut inventory = PciInventory::try_from_initial(vec![old]).unwrap();

        let refresh = inventory.prepare_rescan(vec![refreshed.clone()]).unwrap();
        assert!(!refresh.has_actions());
        inventory.commit(refresh).unwrap();
        assert_eq!(inventory.devices()[0].irq_line, 5);

        let mut moved = refreshed;
        moved.bars[0].base = 0xfeba_0000;
        let rebalance = inventory.prepare_rescan(vec![moved.clone()]).unwrap();
        assert_eq!(rebalance.resource_changes().len(), 1);
        assert_eq!(rebalance.resource_changes()[0].current, moved);
        assert!(rebalance.arrivals().is_empty());
        assert!(rebalance.departures().is_empty());
    }

    #[test]
    fn stale_prepared_update_cannot_replace_newer_accepted_state() {
        let first = function(0, 3, 0x8086, 0x100e, 0xfebc_0000);
        let sibling = function(0, 4, 0x8086, 0x100e, 0xfeba_0000);
        let mut inventory = PciInventory::try_from_initial(vec![first.clone()]).unwrap();
        let stale = inventory.prepare_rescan(vec![]).unwrap();
        let newer = inventory
            .prepare_rescan(vec![first.clone(), sibling.clone()])
            .unwrap();

        inventory.commit(newer).unwrap();
        assert_eq!(inventory.commit(stale), Err(PciInventoryError::StaleUpdate));
        assert_eq!(inventory.devices(), &[first, sibling]);
    }

    #[test]
    fn invalid_and_duplicate_locations_are_rejected_before_publication() {
        let valid = function(0, 3, 0x8086, 0x100e, 0xfebc_0000);
        assert_eq!(
            PciInventory::try_from_initial(vec![valid.clone(), valid]),
            Err(PciInventoryError::DuplicateLocation(PciLocation::new(
                0, 3, 0
            )))
        );
        assert_eq!(
            PciInventory::try_from_initial(vec![function(0, 32, 0x8086, 0x100e, 0xfebc_0000)]),
            Err(PciInventoryError::InvalidLocation(PciLocation::new(
                0, 32, 0
            )))
        );
    }

    #[test]
    fn read_only_census_fences_departure_replacement_and_sibling() {
        let removed = function(0, 3, 0x8086, 0x100e, 0xfebc_0000);
        let sibling = function(0, 4, 0x8086, 0x100e, 0xfeba_0000);
        let inventory =
            PciInventory::try_from_initial(vec![removed.clone(), sibling.clone()]).unwrap();
        let mut replacement = snapshot(&removed);
        replacement.vendor = 0x1234;
        replacement.device = 0x5678;

        let census = inventory
            .prepare_census(vec![snapshot(&sibling), replacement])
            .unwrap();
        assert_eq!(census.base_generation(), inventory.generation());
        assert_eq!(census.departures(), &[removed]);
        assert_eq!(census.arrivals(), &[replacement]);
        assert_eq!(census.retained(), &[PciLocation::new(0, 4, 0)]);
        assert_eq!(
            inventory.devices(),
            &[function(0, 3, 0x8086, 0x100e, 0xfebc_0000), sibling]
        );
    }
}
