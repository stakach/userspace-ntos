//! # `nt-pnp-manager` — the PnP Manager core
//!
//! The devnode table + the v0.1 device-lifecycle state machine (spec: NT PnP
//! Manager, Milestone 12, §8). It validates every state transition, tracks
//! service-bound device identity, PDO/FDO/driver bindings, and raw/translated
//! resource assignment, and rejects stale devnode IDs after removal. `no_std` +
//! `alloc`. It holds no driver pointers — only IDs + resource values (§7.3).

#![no_std]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub use nt_pnp_abi::DeviceState;

/// A device's assigned resources (raw == translated for the simulated backend).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResourceAssignment {
    pub mem_start: u64,
    pub mem_length: u32,
    pub int_vector: u32,
    pub int_level: u32,
    pub int_affinity: u64,
    pub int_latched: bool,
}

/// Resource assignment for devices that do not need hardware resources.
pub const NO_RESOURCES: ResourceAssignment = ResourceAssignment {
    mem_start: 0,
    mem_length: 0,
    int_vector: 0,
    int_level: 0,
    int_affinity: 0,
    int_latched: false,
};

/// The legacy MMIO interrupt fixture resources used by older hosted-driver proofs.
pub const MMIO_INTERRUPT_TEST_RESOURCES: ResourceAssignment = ResourceAssignment {
    mem_start: 0x1000_0000,
    mem_length: 0x1000,
    int_vector: 5,
    int_level: 5,
    int_affinity: 1,
    int_latched: false,
};

/// Why a PnP operation was rejected (spec §8.3, §25).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PnpError {
    /// The requested state transition is not allowed from the current state.
    InvalidTransition,
    /// The devnode ID is unknown or refers to a removed (stale) devnode.
    StaleId,
}

struct Devnode {
    id: u64,
    generation: u64,
    instance_id: Option<String>,
    service: Option<String>,
    state: DeviceState,
    pdo_object_id: u64,
    fdo_object_id: u64,
    driver_id: u64,
    resources: ResourceAssignment,
}

/// Whether the v0.1 state machine permits `from -> to` (spec §8.2/§8.3). `Failed` is
/// reachable from any active state.
pub fn can_transition(from: DeviceState, to: DeviceState) -> bool {
    use DeviceState::*;
    if to == Failed {
        return from != Removed;
    }
    matches!(
        (from, to),
        (Uninitialized, Enumerated)
            | (Enumerated, DriverLoaded)
            | (DriverLoaded, AddDeviceCalled)
            | (AddDeviceCalled, DeviceStackBuilt)
            | (DeviceStackBuilt, ResourcesAssigned)
            | (ResourcesAssigned, StartIrpSent)
            | (StartIrpSent, Started)
            // Started -> stop / remove paths.
            | (Started, QueryStopPending)
            | (Started, QueryRemovePending)
            | (Started, RemovePending)
            | (QueryStopPending, Stopped)
            | (QueryStopPending, Started) // cancel-stop
            | (Stopped, StartIrpSent) // restart
            | (QueryRemovePending, RemovePending)
            | (QueryRemovePending, Started) // cancel-remove
            | (RemovePending, Removed)
    )
}

/// The PnP Manager: a service-bound devnode table and lifecycle state machine.
#[derive(Default)]
pub struct PnpManager {
    devnodes: Vec<Devnode>,
    next_id: u64,
    next_gen: u64,
}

impl PnpManager {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            next_gen: 1,
            ..Default::default()
        }
    }

    fn find(&self, id: u64) -> Option<&Devnode> {
        self.devnodes.iter().find(|d| d.id == id)
    }
    fn find_mut(&mut self, id: u64) -> Option<&mut Devnode> {
        self.devnodes.iter_mut().find(|d| d.id == id)
    }

    fn push_devnode(
        &mut self,
        instance_id: Option<&str>,
        service: Option<&str>,
        pdo_object_id: u64,
        resources: ResourceAssignment,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let generation = self.next_gen;
        self.next_gen += 1;
        self.devnodes.push(Devnode {
            id,
            generation,
            instance_id: instance_id.map(ToString::to_string),
            service: service.map(ToString::to_string),
            state: DeviceState::Enumerated,
            pdo_object_id,
            fdo_object_id: 0,
            driver_id: 0,
            resources,
        });
        id
    }

    /// Enumerate a registry/service-bound devnode in state `Enumerated`.
    ///
    /// The Configuration Manager owns `Enum\<InstanceId>` parsing and service binding. The PnP
    /// Manager records the already-resolved identity plus resource assignment and owns only the
    /// lifecycle state.
    pub fn create_service_bound_devnode(
        &mut self,
        instance_id: &str,
        service: Option<&str>,
        pdo_object_id: u64,
        resources: ResourceAssignment,
    ) -> u64 {
        self.push_devnode(Some(instance_id), service, pdo_object_id, resources)
    }

    /// Enumerate a service-bound devnode with no assigned hardware resources.
    pub fn create_service_bound_devnode_without_resources(
        &mut self,
        instance_id: &str,
        service: Option<&str>,
        pdo_object_id: u64,
    ) -> u64 {
        self.create_service_bound_devnode(instance_id, service, pdo_object_id, NO_RESOURCES)
    }

    /// Enumerate the `MmioInterruptTest` fixture device (spec §9): create a devnode
    /// in state `Enumerated` with the fixture's memory (`0x1000_0000`) + interrupt
    /// (vector 5) resources. Returns its devnode ID.
    pub fn create_mmio_fixture_devnode(&mut self, pdo_object_id: u64) -> u64 {
        self.push_devnode(None, None, pdo_object_id, MMIO_INTERRUPT_TEST_RESOURCES)
    }

    /// Enumerate a devnode with no assigned resources (a device whose function driver needs no
    /// hardware — e.g. a registry/interface KMDF device). Created in state `Enumerated`.
    pub fn create_devnode(&mut self, pdo_object_id: u64) -> u64 {
        self.push_devnode(None, None, pdo_object_id, NO_RESOURCES)
    }

    pub fn state(&self, id: u64) -> Option<DeviceState> {
        self.find(id).map(|d| d.state)
    }

    pub fn generation(&self, id: u64) -> Option<u64> {
        self.find(id).map(|d| d.generation)
    }

    pub fn instance_id(&self, id: u64) -> Option<&str> {
        self.find(id).and_then(|d| d.instance_id.as_deref())
    }

    pub fn service(&self, id: u64) -> Option<&str> {
        self.find(id).and_then(|d| d.service.as_deref())
    }

    pub fn devnodes_for_service(&self, service: &str) -> Vec<u64> {
        self.devnodes
            .iter()
            .filter(|d| {
                d.service
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(service))
            })
            .map(|d| d.id)
            .collect()
    }

    pub fn resources(&self, id: u64) -> Option<ResourceAssignment> {
        self.find(id).map(|d| d.resources)
    }

    pub fn pdo(&self, id: u64) -> Option<u64> {
        self.find(id).map(|d| d.pdo_object_id)
    }
    pub fn fdo(&self, id: u64) -> Option<u64> {
        self.find(id).map(|d| d.fdo_object_id)
    }

    pub fn set_fdo(&mut self, id: u64, fdo_object_id: u64) -> Result<(), PnpError> {
        self.find_mut(id).ok_or(PnpError::StaleId)?.fdo_object_id = fdo_object_id;
        Ok(())
    }
    pub fn set_driver(&mut self, id: u64, driver_id: u64) -> Result<(), PnpError> {
        self.find_mut(id).ok_or(PnpError::StaleId)?.driver_id = driver_id;
        Ok(())
    }

    /// Attempt a state transition, validating it against the state machine (spec
    /// §8.3). A devnode already `Removed` is stale.
    pub fn transition(&mut self, id: u64, to: DeviceState) -> Result<(), PnpError> {
        let d = self.find_mut(id).ok_or(PnpError::StaleId)?;
        if d.state == DeviceState::Removed {
            return Err(PnpError::StaleId);
        }
        if !can_transition(d.state, to) {
            return Err(PnpError::InvalidTransition);
        }
        d.state = to;
        Ok(())
    }

    /// True once the device is `Started` — resource mapping / interrupt connect is
    /// allowed only then (spec §15.2).
    pub fn mapping_allowed(&self, id: u64) -> bool {
        self.state(id) == Some(DeviceState::Started)
    }

    /// True if the devnode ID resolves to a device that is not removed.
    pub fn is_live(&self, id: u64) -> bool {
        matches!(self.state(id), Some(s) if s != DeviceState::Removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use DeviceState::*;

    #[test]
    fn fixture_creates_enumerated_devnode_with_resources() {
        let mut p = PnpManager::new();
        let id = p.create_mmio_fixture_devnode(0xBD0);
        assert_eq!(p.state(id), Some(Enumerated));
        assert_eq!(p.pdo(id), Some(0xBD0));
        assert_eq!(p.instance_id(id), None);
        assert_eq!(p.service(id), None);
        let r = p.resources(id).unwrap();
        assert_eq!(r.mem_start, 0x1000_0000);
        assert_eq!(r.int_vector, 5);
    }

    #[test]
    fn service_bound_devnode_tracks_registry_identity() {
        let mut p = PnpManager::new();
        let resources = ResourceAssignment {
            mem_start: 0x2000_0000,
            mem_length: 0x2000,
            int_vector: 9,
            int_level: 9,
            int_affinity: 3,
            int_latched: true,
        };

        let id = p.create_service_bound_devnode(
            r"PCI\VEN_8086&DEV_100E\3&11583659&0&18",
            Some("E1000"),
            0x1000,
            resources,
        );

        assert_eq!(p.state(id), Some(Enumerated));
        assert_eq!(
            p.instance_id(id),
            Some(r"PCI\VEN_8086&DEV_100E\3&11583659&0&18")
        );
        assert_eq!(p.service(id), Some("E1000"));
        assert_eq!(p.pdo(id), Some(0x1000));
        assert_eq!(p.resources(id), Some(resources));
        assert_eq!(p.devnodes_for_service("e1000"), vec![id]);
    }

    #[test]
    fn service_bound_devnode_without_resources_is_enumerated() {
        let mut p = PnpManager::new();
        let id = p.create_service_bound_devnode_without_resources(
            r"ROOT\KMDF_INTERFACE_REGISTRY_TEST\0001",
            Some("KmdfInterfaceRegistryTest"),
            0x3000,
        );

        assert_eq!(p.state(id), Some(Enumerated));
        assert_eq!(p.resources(id), Some(NO_RESOURCES));
        assert_eq!(
            p.devnodes_for_service("KmdfInterfaceRegistryTest"),
            vec![id]
        );
    }

    #[test]
    fn full_start_lifecycle() {
        let mut p = PnpManager::new();
        let id = p.create_mmio_fixture_devnode(0);
        for s in [
            DriverLoaded,
            AddDeviceCalled,
            DeviceStackBuilt,
            ResourcesAssigned,
            StartIrpSent,
            Started,
        ] {
            assert_eq!(p.transition(id, s), Ok(()), "to {s:?}");
        }
        assert!(p.mapping_allowed(id));
        assert!(p.is_live(id));
    }

    #[test]
    fn invalid_transitions_rejected() {
        let mut p = PnpManager::new();
        let id = p.create_mmio_fixture_devnode(0);
        // No START before AddDevice.
        assert_eq!(
            p.transition(id, StartIrpSent),
            Err(PnpError::InvalidTransition)
        );
        assert!(!p.mapping_allowed(id)); // not Started
    }

    #[test]
    fn no_duplicate_start() {
        let mut p = PnpManager::new();
        let id = p.create_mmio_fixture_devnode(0);
        for s in [
            DriverLoaded,
            AddDeviceCalled,
            DeviceStackBuilt,
            ResourcesAssigned,
            StartIrpSent,
            Started,
        ] {
            p.transition(id, s).unwrap();
        }
        // Started -> StartIrpSent is not allowed (no restart without Stop).
        assert_eq!(
            p.transition(id, StartIrpSent),
            Err(PnpError::InvalidTransition)
        );
    }

    #[test]
    fn remove_then_stale() {
        let mut p = PnpManager::new();
        let id = p.create_mmio_fixture_devnode(0);
        for s in [
            DriverLoaded,
            AddDeviceCalled,
            DeviceStackBuilt,
            ResourcesAssigned,
            StartIrpSent,
            Started,
            RemovePending,
            Removed,
        ] {
            p.transition(id, s).unwrap();
        }
        assert_eq!(p.state(id), Some(Removed));
        assert!(!p.is_live(id));
        assert!(!p.mapping_allowed(id));
        // Any further transition on a removed devnode is stale.
        assert_eq!(p.transition(id, Started), Err(PnpError::StaleId));
    }
}
