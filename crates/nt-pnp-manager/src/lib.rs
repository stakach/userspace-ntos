//! # `nt-pnp-manager` — the PnP Manager core
//!
//! The devnode table + the v0.1 device-lifecycle state machine (spec: NT PnP
//! Manager, Milestone 12, §8), driven by static fixtures (§9). It validates every
//! state transition, tracks the PDO/FDO/driver bindings and the raw/translated
//! resource assignment, and rejects stale devnode IDs after removal. `no_std` +
//! `alloc`. It holds no driver pointers — only IDs + resource values (§7.3).

#![no_std]

extern crate alloc;

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

/// The PnP Manager: a devnode table over static fixtures.
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

    /// Enumerate the `MmioInterruptTest` fixture device (spec §9): create a devnode
    /// in state `Enumerated` with the fixture's memory (`0x1000_0000`) + interrupt
    /// (vector 5) resources. Returns its devnode ID.
    pub fn create_mmio_fixture_devnode(&mut self, pdo_object_id: u64) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let generation = self.next_gen;
        self.next_gen += 1;
        self.devnodes.push(Devnode {
            id,
            generation,
            state: DeviceState::Enumerated,
            pdo_object_id,
            fdo_object_id: 0,
            driver_id: 0,
            resources: ResourceAssignment {
                mem_start: 0x1000_0000,
                mem_length: 0x1000,
                int_vector: 5,
                int_level: 5,
                int_affinity: 1,
                int_latched: false,
            },
        });
        id
    }

    pub fn state(&self, id: u64) -> Option<DeviceState> {
        self.find(id).map(|d| d.state)
    }

    pub fn generation(&self, id: u64) -> Option<u64> {
        self.find(id).map(|d| d.generation)
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
    use DeviceState::*;

    #[test]
    fn fixture_creates_enumerated_devnode_with_resources() {
        let mut p = PnpManager::new();
        let id = p.create_mmio_fixture_devnode(0xBD0);
        assert_eq!(p.state(id), Some(Enumerated));
        assert_eq!(p.pdo(id), Some(0xBD0));
        let r = p.resources(id).unwrap();
        assert_eq!(r.mem_start, 0x1000_0000);
        assert_eq!(r.int_vector, 5);
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
