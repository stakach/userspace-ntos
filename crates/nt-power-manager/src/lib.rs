//! # `nt-power-manager` — the Power Manager core
//!
//! Per-devnode power records + the D0/D3 device power transition state machine
//! (spec: NT Power Manager, Milestone 13, §7, §10, §16). It enforces one power IRP
//! in flight per devnode, rejects transitions after remove, and (with the caller's
//! query result) implements query-fails-prevents-set / set-fails-preserves-old.
//! `no_std` + `alloc`; holds no driver pointers — only IDs + power states.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

pub use nt_power_types::{DevicePowerState, SystemPowerState};

/// Why a power operation was rejected (spec §16, §19.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerError {
    /// The devnode has no power record (never registered, or stale after remove).
    NotRegistered,
    /// The devnode is being removed — no new transitions (spec §11.3).
    Removed,
    /// A power IRP is already in flight for this devnode (spec §16.1).
    Busy,
    /// The requested device power state is not valid.
    InvalidState,
}

struct Record {
    devnode_id: u64,
    device_power_state: DevicePowerState,
    system_power_state: SystemPowerState,
    in_flight: bool,
    remove_in_progress: bool,
    generation: u32,
}

/// The Power Manager: a table of per-devnode power records.
#[derive(Default)]
pub struct PowerManager {
    records: Vec<Record>,
    next_gen: u32,
}

impl PowerManager {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            next_gen: 1,
        }
    }

    fn find(&self, id: u64) -> Option<&Record> {
        self.records.iter().find(|r| r.devnode_id == id)
    }
    fn find_mut(&mut self, id: u64) -> Option<&mut Record> {
        self.records.iter_mut().find(|r| r.devnode_id == id)
    }

    /// Register a devnode after a successful `START_DEVICE` (spec §11.1): the device
    /// enters `D0` at system `Working`.
    pub fn register_device(&mut self, devnode_id: u64) {
        let generation = self.next_gen;
        self.next_gen += 1;
        if let Some(r) = self.find_mut(devnode_id) {
            r.device_power_state = DevicePowerState::D0;
            r.system_power_state = SystemPowerState::Working;
            r.in_flight = false;
            r.remove_in_progress = false;
            r.generation = generation;
            return;
        }
        self.records.push(Record {
            devnode_id,
            device_power_state: DevicePowerState::D0,
            system_power_state: SystemPowerState::Working,
            in_flight: false,
            remove_in_progress: false,
            generation,
        });
    }

    /// Unregister a devnode after `REMOVE_DEVICE` completes (spec §11.3).
    pub fn unregister_device(&mut self, devnode_id: u64) {
        self.records.retain(|r| r.devnode_id != devnode_id);
    }

    pub fn is_registered(&self, devnode_id: u64) -> bool {
        self.find(devnode_id).is_some()
    }

    pub fn device_state(&self, devnode_id: u64) -> Option<DevicePowerState> {
        self.find(devnode_id).map(|r| r.device_power_state)
    }

    pub fn system_state(&self, devnode_id: u64) -> Option<SystemPowerState> {
        self.find(devnode_id).map(|r| r.system_power_state)
    }

    /// True if the device is in `D0` (usable — I/O + interrupt delivery allowed,
    /// spec §8.1/§12).
    pub fn is_on(&self, devnode_id: u64) -> bool {
        self.device_state(devnode_id) == Some(DevicePowerState::D0)
    }

    /// Mark a devnode as removing — new transitions are rejected (spec §11.3).
    pub fn mark_remove(&mut self, devnode_id: u64) -> Result<(), PowerError> {
        self.find_mut(devnode_id)
            .ok_or(PowerError::NotRegistered)?
            .remove_in_progress = true;
        Ok(())
    }

    /// Begin a device power transition (spec §10.1, §16.1): validate the devnode is
    /// registered, not removing, and has no power IRP in flight; mark it in-flight.
    /// Returns the old device power state. The caller then sends QUERY + SET IRPs to
    /// the driver and calls [`Self::complete_device_transition`].
    pub fn begin_device_transition(
        &mut self,
        devnode_id: u64,
        target: DevicePowerState,
    ) -> Result<DevicePowerState, PowerError> {
        if !matches!(
            target,
            DevicePowerState::D0
                | DevicePowerState::D1
                | DevicePowerState::D2
                | DevicePowerState::D3
        ) {
            return Err(PowerError::InvalidState);
        }
        let r = self.find_mut(devnode_id).ok_or(PowerError::NotRegistered)?;
        if r.remove_in_progress {
            return Err(PowerError::Removed);
        }
        if r.in_flight {
            return Err(PowerError::Busy);
        }
        r.in_flight = true;
        Ok(r.device_power_state)
    }

    /// Complete a transition: on `success` the canonical state moves to `target`; on
    /// failure the old state is preserved (spec §10.1, §9.4). Always clears in-flight.
    pub fn complete_device_transition(
        &mut self,
        devnode_id: u64,
        target: DevicePowerState,
        success: bool,
    ) -> Result<DevicePowerState, PowerError> {
        let r = self.find_mut(devnode_id).ok_or(PowerError::NotRegistered)?;
        r.in_flight = false;
        if success {
            r.device_power_state = target;
        }
        Ok(r.device_power_state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use DevicePowerState::*;

    const DN: u64 = 42;

    #[test]
    fn register_starts_d0() {
        let mut p = PowerManager::new();
        p.register_device(DN);
        assert_eq!(p.device_state(DN), Some(D0));
        assert!(p.is_on(DN));
    }

    #[test]
    fn d0_d3_d0_transitions() {
        let mut p = PowerManager::new();
        p.register_device(DN);
        // D0 -> D3.
        assert_eq!(p.begin_device_transition(DN, D3), Ok(D0));
        assert_eq!(p.complete_device_transition(DN, D3, true), Ok(D3));
        assert!(!p.is_on(DN));
        // D3 -> D0.
        assert_eq!(p.begin_device_transition(DN, D0), Ok(D3));
        assert_eq!(p.complete_device_transition(DN, D0, true), Ok(D0));
        assert!(p.is_on(DN));
    }

    #[test]
    fn one_transition_in_flight() {
        let mut p = PowerManager::new();
        p.register_device(DN);
        p.begin_device_transition(DN, D3).unwrap();
        // A second begin while in flight is busy.
        assert_eq!(p.begin_device_transition(DN, D0), Err(PowerError::Busy));
        p.complete_device_transition(DN, D3, true).unwrap();
        // Now free.
        assert!(p.begin_device_transition(DN, D0).is_ok());
    }

    #[test]
    fn set_failure_preserves_old_state() {
        let mut p = PowerManager::new();
        p.register_device(DN);
        p.begin_device_transition(DN, D3).unwrap();
        // SET failed → stays D0.
        assert_eq!(p.complete_device_transition(DN, D3, false), Ok(D0));
        assert!(p.is_on(DN));
    }

    #[test]
    fn no_transition_after_remove() {
        let mut p = PowerManager::new();
        p.register_device(DN);
        p.mark_remove(DN).unwrap();
        assert_eq!(p.begin_device_transition(DN, D3), Err(PowerError::Removed));
    }

    #[test]
    fn stale_devnode_rejected() {
        let mut p = PowerManager::new();
        p.register_device(DN);
        p.unregister_device(DN);
        assert!(!p.is_registered(DN));
        assert_eq!(
            p.begin_device_transition(DN, D3),
            Err(PowerError::NotRegistered)
        );
    }
}
