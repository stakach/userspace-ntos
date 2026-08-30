//! # `nt-power-manager` — the Power Manager core
//!
//! Per-devnode power records, the D0/D3 device power transition state machine, and
//! per-thread execution-state accounting (spec: NT Power Manager, Milestone 13,
//! §7, §10, §16). `no_std` + `alloc`; holds no driver pointers, only stable IDs and
//! power-policy state.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

pub use nt_power_types::{
    DevicePowerState, SystemPowerState, WakeupLatency, ES_CONTINUOUS, ES_DISPLAY_REQUIRED,
    ES_SYSTEM_REQUIRED, ES_USER_PRESENT, THREAD_EXECUTION_STATE_MASK,
    THREAD_EXECUTION_STATE_VALID_MASK,
};

/// Why a power operation was rejected (spec §16, §19.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerError {
    /// The growable record table cannot accept another registration.
    InsufficientResources,
    /// The devnode has no power record (never registered, or stale after remove).
    NotRegistered,
    /// The devnode is known but has not completed `START_DEVICE`.
    NotStarted,
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
    started: bool,
    in_flight: bool,
    remove_in_progress: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct ThreadExecutionRecord {
    thread_id: u64,
    persistent_flags: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct ProcessWakeupLatencyRecord {
    process_id: u64,
}

/// Aggregate policy state produced by current thread assertions and one-shot pulses.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionStateSnapshot {
    pub system_required_count: u64,
    pub display_required_count: u64,
    /// Changes when a zero-count system assertion is first set or pulsed.
    pub system_activity_generation: u64,
    /// Changes when the effective display-required state changes or is pulsed while clear.
    pub display_activity_generation: u64,
}

/// Aggregate policy produced by the process-scoped `LT_LOWEST_LATENCY` attribute.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WakeupLatencySnapshot {
    pub lowest_latency_count: u64,
    /// Advances when the effective low-latency constraint changes between clear and asserted.
    pub policy_generation: u64,
}

/// The Power Manager: a table of per-devnode power records.
#[derive(Default)]
pub struct PowerManager {
    records: Vec<Record>,
    thread_execution_records: Vec<ThreadExecutionRecord>,
    process_wakeup_latency_records: Vec<ProcessWakeupLatencyRecord>,
    execution_state: ExecutionStateSnapshot,
    wakeup_latency: WakeupLatencySnapshot,
}

impl PowerManager {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            thread_execution_records: Vec::new(),
            process_wakeup_latency_records: Vec::new(),
            execution_state: ExecutionStateSnapshot::default(),
            wakeup_latency: WakeupLatencySnapshot::default(),
        }
    }

    fn thread_execution_record(&self, thread_id: u64) -> Option<&ThreadExecutionRecord> {
        self.thread_execution_records
            .iter()
            .find(|record| record.thread_id == thread_id)
    }

    fn apply_persistent_execution_change(&mut self, old_flags: u32, new_flags: u32) {
        let changed = (old_flags ^ new_flags) & THREAD_EXECUTION_STATE_MASK;
        if changed & ES_SYSTEM_REQUIRED != 0 {
            if new_flags & ES_SYSTEM_REQUIRED != 0 {
                if self.execution_state.system_required_count == 0 {
                    self.execution_state.system_activity_generation = self
                        .execution_state
                        .system_activity_generation
                        .wrapping_add(1);
                }
                self.execution_state.system_required_count += 1;
            } else {
                debug_assert!(self.execution_state.system_required_count != 0);
                self.execution_state.system_required_count -= 1;
            }
        }
        if changed & ES_DISPLAY_REQUIRED != 0 {
            if new_flags & ES_DISPLAY_REQUIRED != 0 {
                if self.execution_state.display_required_count == 0 {
                    self.execution_state.display_activity_generation = self
                        .execution_state
                        .display_activity_generation
                        .wrapping_add(1);
                }
                self.execution_state.display_required_count += 1;
            } else {
                debug_assert!(self.execution_state.display_required_count != 0);
                self.execution_state.display_required_count -= 1;
                if self.execution_state.display_required_count == 0 {
                    self.execution_state.display_activity_generation = self
                        .execution_state
                        .display_activity_generation
                        .wrapping_add(1);
                }
            }
        }
    }

    /// Apply `NtSetThreadExecutionState` for one current thread and return its previous persistent
    /// assertions with `ES_CONTINUOUS` set, as the native API requires.
    ///
    /// A request without `ES_CONTINUOUS` is a pulse: it leaves the thread record unchanged and
    /// advances an activity generation only when no persistent owner already holds that attribute.
    pub fn set_thread_execution_state(
        &mut self,
        thread_id: u64,
        requested_flags: u32,
    ) -> Result<u32, PowerError> {
        if thread_id == 0 || requested_flags & !THREAD_EXECUTION_STATE_VALID_MASK != 0 {
            return Err(PowerError::InvalidState);
        }
        let old_flags = self
            .thread_execution_record(thread_id)
            .map_or(0, |record| record.persistent_flags);
        let previous = old_flags | ES_CONTINUOUS;

        if requested_flags & ES_CONTINUOUS == 0 {
            if requested_flags & ES_SYSTEM_REQUIRED != 0
                && self.execution_state.system_required_count == 0
            {
                self.execution_state.system_activity_generation = self
                    .execution_state
                    .system_activity_generation
                    .wrapping_add(1);
            }
            if requested_flags & ES_DISPLAY_REQUIRED != 0
                && self.execution_state.display_required_count == 0
            {
                self.execution_state.display_activity_generation = self
                    .execution_state
                    .display_activity_generation
                    .wrapping_add(1);
            }
            return Ok(previous);
        }

        let new_flags = requested_flags & THREAD_EXECUTION_STATE_MASK;
        let position = self
            .thread_execution_records
            .iter()
            .position(|record| record.thread_id == thread_id);
        match (position, new_flags) {
            (Some(index), 0) => {
                self.thread_execution_records.remove(index);
            }
            (Some(index), _) => {
                self.thread_execution_records[index].persistent_flags = new_flags;
            }
            (None, 0) => {}
            (None, _) => {
                self.thread_execution_records
                    .try_reserve(1)
                    .map_err(|_| PowerError::InsufficientResources)?;
                self.thread_execution_records.push(ThreadExecutionRecord {
                    thread_id,
                    persistent_flags: new_flags,
                });
            }
        }
        self.apply_persistent_execution_change(old_flags, new_flags);
        Ok(previous)
    }

    /// Release persistent assertions when a thread leaves the kernel thread namespace.
    /// Repeated rundown is harmless and cannot decrement another thread's counts.
    pub fn remove_thread_execution_state(&mut self, thread_id: u64) -> bool {
        let Some(index) = self
            .thread_execution_records
            .iter()
            .position(|record| record.thread_id == thread_id)
        else {
            return false;
        };
        let old_flags = self.thread_execution_records.remove(index).persistent_flags;
        self.apply_persistent_execution_change(old_flags, 0);
        true
    }

    pub fn thread_execution_state(&self, thread_id: u64) -> u32 {
        self.thread_execution_record(thread_id)
            .map_or(ES_CONTINUOUS, |record| {
                record.persistent_flags | ES_CONTINUOUS
            })
    }

    pub fn execution_state_snapshot(&self) -> ExecutionStateSnapshot {
        self.execution_state
    }

    /// Apply `NtRequestWakeupLatency` for one current process. Repeating the same request is
    /// idempotent: the global attribute count tracks owning processes, not syscall calls.
    pub fn set_process_wakeup_latency(
        &mut self,
        process_id: u64,
        latency: WakeupLatency,
    ) -> Result<(), PowerError> {
        if process_id == 0 {
            return Err(PowerError::InvalidState);
        }
        let position = self
            .process_wakeup_latency_records
            .iter()
            .position(|record| record.process_id == process_id);
        match (position, latency) {
            (Some(_), WakeupLatency::LowestLatency) | (None, WakeupLatency::DontCare) => Ok(()),
            (Some(index), WakeupLatency::DontCare) => {
                self.process_wakeup_latency_records.remove(index);
                debug_assert!(self.wakeup_latency.lowest_latency_count != 0);
                self.wakeup_latency.lowest_latency_count -= 1;
                if self.wakeup_latency.lowest_latency_count == 0 {
                    self.wakeup_latency.policy_generation =
                        self.wakeup_latency.policy_generation.wrapping_add(1);
                }
                Ok(())
            }
            (None, WakeupLatency::LowestLatency) => {
                self.process_wakeup_latency_records
                    .try_reserve(1)
                    .map_err(|_| PowerError::InsufficientResources)?;
                self.process_wakeup_latency_records
                    .push(ProcessWakeupLatencyRecord { process_id });
                if self.wakeup_latency.lowest_latency_count == 0 {
                    self.wakeup_latency.policy_generation =
                        self.wakeup_latency.policy_generation.wrapping_add(1);
                }
                self.wakeup_latency.lowest_latency_count += 1;
                Ok(())
            }
        }
    }

    /// Release a process's low-latency assertion during process rundown. This is exact and
    /// idempotent, so a repeated teardown cannot decrement another process's request.
    pub fn remove_process_wakeup_latency(&mut self, process_id: u64) -> bool {
        let Some(index) = self
            .process_wakeup_latency_records
            .iter()
            .position(|record| record.process_id == process_id)
        else {
            return false;
        };
        self.process_wakeup_latency_records.remove(index);
        debug_assert!(self.wakeup_latency.lowest_latency_count != 0);
        self.wakeup_latency.lowest_latency_count -= 1;
        if self.wakeup_latency.lowest_latency_count == 0 {
            self.wakeup_latency.policy_generation =
                self.wakeup_latency.policy_generation.wrapping_add(1);
        }
        true
    }

    pub fn process_wakeup_latency(&self, process_id: u64) -> WakeupLatency {
        if self
            .process_wakeup_latency_records
            .iter()
            .any(|record| record.process_id == process_id)
        {
            WakeupLatency::LowestLatency
        } else {
            WakeupLatency::DontCare
        }
    }

    pub fn wakeup_latency_snapshot(&self) -> WakeupLatencySnapshot {
        self.wakeup_latency
    }

    /// Apply NT5's low-latency sleep-policy bound. An asserted request can make the selected sleep
    /// state shallower, but can never deepen a policy maximum that is already more restrictive.
    pub fn constrain_deepest_sleep(
        &self,
        policy_maximum: SystemPowerState,
        reduced_latency_sleep: SystemPowerState,
    ) -> SystemPowerState {
        if self.wakeup_latency.lowest_latency_count != 0
            && policy_maximum as u32 >= reduced_latency_sleep as u32
        {
            reduced_latency_sleep
        } else {
            policy_maximum
        }
    }

    fn find(&self, id: u64) -> Option<&Record> {
        self.records.iter().find(|r| r.devnode_id == id)
    }
    fn find_mut(&mut self, id: u64) -> Option<&mut Record> {
        self.records.iter_mut().find(|r| r.devnode_id == id)
    }

    /// Prepare a devnode before invoking `AddDevice`, allowing a driver to report its initial
    /// state through `PoSetPowerState` without making the device queryable or usable yet.
    pub fn prepare_device(&mut self, devnode_id: u64) -> Result<(), PowerError> {
        if self.find(devnode_id).is_some() {
            return Err(PowerError::Busy);
        }
        self.records
            .try_reserve(1)
            .map_err(|_| PowerError::InsufficientResources)?;
        self.records.push(Record {
            devnode_id,
            device_power_state: DevicePowerState::Unspecified,
            system_power_state: SystemPowerState::Unspecified,
            started: false,
            in_flight: false,
            remove_in_progress: false,
        });
        Ok(())
    }

    /// Publish a prepared devnode after successful `START_DEVICE`. States explicitly reported by
    /// the driver are retained; otherwise NT's initial started state is D0 at system Working.
    pub fn complete_start(&mut self, devnode_id: u64) -> Result<(), PowerError> {
        let record = self.find_mut(devnode_id).ok_or(PowerError::NotRegistered)?;
        if record.remove_in_progress {
            return Err(PowerError::Removed);
        }
        if record.started {
            return Ok(());
        }
        if record.device_power_state == DevicePowerState::Unspecified {
            record.device_power_state = DevicePowerState::D0;
        }
        if record.system_power_state == SystemPowerState::Unspecified {
            record.system_power_state = SystemPowerState::Working;
        }
        record.started = true;
        Ok(())
    }

    /// Publish a completed PnP STOP without discarding the devnode's durable power record.
    pub fn complete_stop(&mut self, devnode_id: u64) -> Result<(), PowerError> {
        let record = self.find_mut(devnode_id).ok_or(PowerError::NotRegistered)?;
        if record.remove_in_progress {
            return Err(PowerError::Removed);
        }
        record.started = false;
        Ok(())
    }

    /// Register an already-started devnode in one operation.
    pub fn register_device(&mut self, devnode_id: u64) -> Result<(), PowerError> {
        self.prepare_device(devnode_id)?;
        self.complete_start(devnode_id)
    }

    /// Unregister a devnode after `REMOVE_DEVICE` completes (spec §11.3).
    pub fn unregister_device(&mut self, devnode_id: u64) {
        self.records.retain(|r| r.devnode_id != devnode_id);
    }

    pub fn is_registered(&self, devnode_id: u64) -> bool {
        self.find(devnode_id).is_some()
    }

    pub fn is_started(&self, devnode_id: u64) -> bool {
        self.find(devnode_id).is_some_and(|record| record.started)
    }

    pub fn device_state(&self, devnode_id: u64) -> Option<DevicePowerState> {
        self.find(devnode_id).map(|r| r.device_power_state)
    }

    pub fn system_state(&self, devnode_id: u64) -> Option<SystemPowerState> {
        self.find(devnode_id).map(|r| r.system_power_state)
    }

    /// Return the device state only after `START_DEVICE` has completed successfully.
    pub fn started_device_state(&self, devnode_id: u64) -> Option<DevicePowerState> {
        self.find(devnode_id)
            .filter(|record| record.started)
            .map(|record| record.device_power_state)
    }

    /// Record a device state reported by `PoSetPowerState` and return the previous state.
    ///
    /// This is distinct from an executive-initiated power IRP transition: drivers report the
    /// state of their exact device object directly, including `Unspecified`, and reporting does
    /// not fabricate or register a missing devnode.
    pub fn report_device_state(
        &mut self,
        devnode_id: u64,
        state: DevicePowerState,
    ) -> Result<DevicePowerState, PowerError> {
        if state == DevicePowerState::Maximum {
            return Err(PowerError::InvalidState);
        }
        let record = self.find_mut(devnode_id).ok_or(PowerError::NotRegistered)?;
        let previous = record.device_power_state;
        record.device_power_state = state;
        Ok(previous)
    }

    /// Record a system state reported for one device object and return its previous state.
    pub fn report_system_state(
        &mut self,
        devnode_id: u64,
        state: SystemPowerState,
    ) -> Result<SystemPowerState, PowerError> {
        if state == SystemPowerState::Maximum {
            return Err(PowerError::InvalidState);
        }
        let record = self.find_mut(devnode_id).ok_or(PowerError::NotRegistered)?;
        let previous = record.system_power_state;
        record.system_power_state = state;
        Ok(previous)
    }

    /// True if the device is in `D0` (usable — I/O + interrupt delivery allowed,
    /// spec §8.1/§12).
    pub fn is_on(&self, devnode_id: u64) -> bool {
        self.started_device_state(devnode_id) == Some(DevicePowerState::D0)
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
        if !r.started {
            return Err(PowerError::NotStarted);
        }
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
        p.register_device(DN).unwrap();
        assert_eq!(p.device_state(DN), Some(D0));
        assert!(p.is_on(DN));
    }

    #[test]
    fn d0_d3_d0_transitions() {
        let mut p = PowerManager::new();
        p.register_device(DN).unwrap();
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
        p.register_device(DN).unwrap();
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
        p.register_device(DN).unwrap();
        p.begin_device_transition(DN, D3).unwrap();
        // SET failed → stays D0.
        assert_eq!(p.complete_device_transition(DN, D3, false), Ok(D0));
        assert!(p.is_on(DN));
    }

    #[test]
    fn no_transition_after_remove() {
        let mut p = PowerManager::new();
        p.register_device(DN).unwrap();
        p.mark_remove(DN).unwrap();
        assert_eq!(p.begin_device_transition(DN, D3), Err(PowerError::Removed));
    }

    #[test]
    fn stale_devnode_rejected() {
        let mut p = PowerManager::new();
        p.register_device(DN).unwrap();
        p.unregister_device(DN);
        assert!(!p.is_registered(DN));
        assert_eq!(
            p.begin_device_transition(DN, D3),
            Err(PowerError::NotRegistered)
        );
    }

    #[test]
    fn driver_reports_are_isolated_per_devnode() {
        let mut p = PowerManager::new();
        p.register_device(DN).unwrap();
        p.register_device(DN + 1).unwrap();

        assert_eq!(p.report_device_state(DN, D3), Ok(D0));
        assert_eq!(p.device_state(DN), Some(D3));
        assert_eq!(p.device_state(DN + 1), Some(D0));
        assert_eq!(
            p.report_system_state(DN, SystemPowerState::Sleeping3),
            Ok(SystemPowerState::Working)
        );
        assert_eq!(p.system_state(DN), Some(SystemPowerState::Sleeping3));
        assert_eq!(p.system_state(DN + 1), Some(SystemPowerState::Working));
    }

    #[test]
    fn stop_hides_only_the_exact_devnode_and_restart_republishes_it() {
        let mut p = PowerManager::new();
        p.register_device(DN).unwrap();
        p.register_device(DN + 1).unwrap();

        p.complete_stop(DN).unwrap();
        assert!(!p.is_started(DN));
        assert_eq!(p.started_device_state(DN), None);
        assert!(p.is_started(DN + 1));
        assert_eq!(p.started_device_state(DN + 1), Some(D0));

        p.complete_start(DN).unwrap();
        assert!(p.is_started(DN));
        assert_eq!(p.started_device_state(DN), Some(D0));
    }

    #[test]
    fn add_device_report_is_preserved_but_not_queryable_until_start() {
        let mut p = PowerManager::new();
        p.prepare_device(DN).unwrap();
        assert!(!p.is_started(DN));
        assert_eq!(p.started_device_state(DN), None);
        assert_eq!(
            p.begin_device_transition(DN, D0),
            Err(PowerError::NotStarted)
        );

        assert_eq!(p.report_device_state(DN, D3), Ok(Unspecified));
        assert_eq!(
            p.report_system_state(DN, SystemPowerState::Sleeping3),
            Ok(SystemPowerState::Unspecified)
        );
        p.complete_start(DN).unwrap();

        assert_eq!(p.started_device_state(DN), Some(D3));
        assert_eq!(p.system_state(DN), Some(SystemPowerState::Sleeping3));
        assert!(!p.is_on(DN));
    }

    #[test]
    fn reports_reject_missing_devnodes_and_maximum_sentinels() {
        let mut p = PowerManager::new();
        assert_eq!(
            p.report_device_state(DN, D3),
            Err(PowerError::NotRegistered)
        );
        p.register_device(DN).unwrap();
        assert_eq!(
            p.report_device_state(DN, DevicePowerState::Maximum),
            Err(PowerError::InvalidState)
        );
        assert_eq!(
            p.report_system_state(DN, SystemPowerState::Maximum),
            Err(PowerError::InvalidState)
        );
        assert_eq!(p.device_state(DN), Some(D0));
        assert_eq!(p.system_state(DN), Some(SystemPowerState::Working));
    }

    #[test]
    fn continuous_execution_state_is_per_thread_and_counted() {
        let mut p = PowerManager::new();
        assert_eq!(
            p.set_thread_execution_state(10, ES_CONTINUOUS | ES_SYSTEM_REQUIRED),
            Ok(ES_CONTINUOUS)
        );
        assert_eq!(
            p.set_thread_execution_state(
                20,
                ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED
            ),
            Ok(ES_CONTINUOUS)
        );
        assert_eq!(
            p.thread_execution_state(10),
            ES_CONTINUOUS | ES_SYSTEM_REQUIRED
        );
        assert_eq!(
            p.thread_execution_state(20),
            ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED
        );
        assert_eq!(
            p.execution_state_snapshot(),
            ExecutionStateSnapshot {
                system_required_count: 2,
                display_required_count: 1,
                system_activity_generation: 1,
                display_activity_generation: 1,
            }
        );

        assert_eq!(
            p.set_thread_execution_state(10, ES_CONTINUOUS | ES_DISPLAY_REQUIRED),
            Ok(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
        );
        let snapshot = p.execution_state_snapshot();
        assert_eq!(snapshot.system_required_count, 1);
        assert_eq!(snapshot.display_required_count, 2);
    }

    #[test]
    fn execution_state_pulses_do_not_replace_persistent_state() {
        let mut p = PowerManager::new();
        p.set_thread_execution_state(10, ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
            .unwrap();
        let before = p.execution_state_snapshot();

        assert_eq!(
            p.set_thread_execution_state(10, ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED),
            Ok(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
        );
        assert_eq!(
            p.thread_execution_state(10),
            ES_CONTINUOUS | ES_SYSTEM_REQUIRED
        );
        let after = p.execution_state_snapshot();
        assert_eq!(
            after.system_activity_generation,
            before.system_activity_generation
        );
        assert_eq!(
            after.display_activity_generation,
            before.display_activity_generation + 1
        );
        assert_eq!(after.display_required_count, 0);
    }

    #[test]
    fn thread_rundown_releases_only_its_assertions() {
        let mut p = PowerManager::new();
        p.set_thread_execution_state(10, ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED)
            .unwrap();
        p.set_thread_execution_state(20, ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
            .unwrap();

        assert!(p.remove_thread_execution_state(10));
        assert!(!p.remove_thread_execution_state(10));
        assert_eq!(p.thread_execution_state(10), ES_CONTINUOUS);
        assert_eq!(
            p.thread_execution_state(20),
            ES_CONTINUOUS | ES_SYSTEM_REQUIRED
        );
        let snapshot = p.execution_state_snapshot();
        assert_eq!(snapshot.system_required_count, 1);
        assert_eq!(snapshot.display_required_count, 0);
        assert_eq!(snapshot.display_activity_generation, 2);

        assert_eq!(
            p.set_thread_execution_state(20, ES_USER_PRESENT),
            Err(PowerError::InvalidState)
        );
    }

    #[test]
    fn wakeup_latency_is_process_scoped_and_reference_counted() {
        let mut p = PowerManager::new();
        assert_eq!(
            p.set_process_wakeup_latency(10, WakeupLatency::LowestLatency),
            Ok(())
        );
        assert_eq!(
            p.set_process_wakeup_latency(10, WakeupLatency::LowestLatency),
            Ok(())
        );
        assert_eq!(
            p.set_process_wakeup_latency(20, WakeupLatency::LowestLatency),
            Ok(())
        );
        assert_eq!(
            p.wakeup_latency_snapshot(),
            WakeupLatencySnapshot {
                lowest_latency_count: 2,
                policy_generation: 1,
            }
        );
        assert_eq!(p.process_wakeup_latency(10), WakeupLatency::LowestLatency);

        assert_eq!(
            p.set_process_wakeup_latency(10, WakeupLatency::DontCare),
            Ok(())
        );
        assert_eq!(p.wakeup_latency_snapshot().lowest_latency_count, 1);
        assert_eq!(p.wakeup_latency_snapshot().policy_generation, 1);
        assert_eq!(p.process_wakeup_latency(10), WakeupLatency::DontCare);

        assert!(p.remove_process_wakeup_latency(20));
        assert!(!p.remove_process_wakeup_latency(20));
        assert_eq!(
            p.wakeup_latency_snapshot(),
            WakeupLatencySnapshot {
                lowest_latency_count: 0,
                policy_generation: 2,
            }
        );
        assert_eq!(
            p.set_process_wakeup_latency(0, WakeupLatency::LowestLatency),
            Err(PowerError::InvalidState)
        );
    }

    #[test]
    fn low_latency_attribute_constrains_only_deeper_sleep_policy() {
        let mut p = PowerManager::new();
        assert_eq!(
            p.constrain_deepest_sleep(SystemPowerState::Hibernate, SystemPowerState::Sleeping2),
            SystemPowerState::Hibernate
        );
        p.set_process_wakeup_latency(10, WakeupLatency::LowestLatency)
            .unwrap();
        assert_eq!(
            p.constrain_deepest_sleep(SystemPowerState::Hibernate, SystemPowerState::Sleeping2),
            SystemPowerState::Sleeping2
        );
        assert_eq!(
            p.constrain_deepest_sleep(SystemPowerState::Sleeping1, SystemPowerState::Sleeping2),
            SystemPowerState::Sleeping1
        );
    }
}
