//! Generation-exact boot evidence, never process admission or routing authority.
//!
//! Native adapters must authenticate current process/thread state and the actual publication,
//! GUI, terminal, or retirement acknowledgement before recording it. This store cannot inspect
//! a native runtime, retain its lifetime, or turn a captured caller into authority.

use crate::process_identity::ProcessIdentity;
use crate::provider_logical_caller::ProviderLogicalCaller;
use alloc::vec::Vec;
use nt_process::ThreadLifetime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservationKey {
    pub pi: usize,
    pub process: ProcessIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationFact {
    ProcessCatalog,
    VSpace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationAck {
    Recorded,
    Duplicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationError {
    InvalidIdentity,
    UnknownProcess,
    ConflictingRegistration,
    ConflictingReceipt,
    StaleCaller,
    UnacknowledgedCaller,
    Inactive,
    TerminalRequired,
    AmbiguousRole,
    InvalidCount,
    CountOverflow,
    InsufficientResources,
}

struct FactCount<F> {
    kind: F,
    count: u64,
}

/// Immutable image identity and accumulated evidence for one process incarnation.
pub struct ProcessObservation<R, I, F> {
    key: ObservationKey,
    role: R,
    image: I,
    process_catalog: bool,
    vspace: bool,
    main: Option<ProviderLogicalCaller>,
    workers: Vec<ProviderLogicalCaller>,
    gui: Vec<FactCount<F>>,
    terminal: Option<u32>,
    retired: bool,
}

impl<R: Copy, I, F: Eq> ProcessObservation<R, I, F> {
    pub const fn key(&self) -> ObservationKey {
        self.key
    }
    pub fn role(&self) -> R {
        self.role
    }
    pub fn image(&self) -> &I {
        &self.image
    }
    pub fn publication(&self, fact: PublicationFact) -> bool {
        match fact {
            PublicationFact::ProcessCatalog => self.process_catalog,
            PublicationFact::VSpace => self.vspace,
        }
    }
    pub fn fully_published(&self) -> bool {
        self.process_catalog && self.vspace && self.main.is_some()
    }
    pub const fn main_publication(&self) -> Option<ProviderLogicalCaller> {
        self.main
    }
    pub fn worker_activations(&self) -> &[ProviderLogicalCaller] {
        &self.workers
    }
    pub fn gui_count(&self, kind: F) -> u64 {
        self.gui
            .iter()
            .find(|fact| fact.kind == kind)
            .map_or(0, |fact| fact.count)
    }
    pub fn gui_fact_kinds(&self) -> usize {
        self.gui.len()
    }
    pub const fn terminal_status(&self) -> Option<u32> {
        self.terminal
    }
    pub const fn is_retired(&self) -> bool {
        self.retired
    }

    fn active(&self) -> Result<(), ObservationError> {
        if self.terminal.is_some() || self.retired {
            Err(ObservationError::Inactive)
        } else {
            Ok(())
        }
    }

    fn caller_is_current(
        &self,
        caller: ProviderLogicalCaller,
        current: ThreadLifetime,
    ) -> Result<(), ObservationError> {
        if caller.pi() != self.key.pi
            || caller.process() != self.key.process
            || caller.thread() != current
            || current.process_id() != self.key.process.pid
        {
            Err(ObservationError::StaleCaller)
        } else {
            Ok(())
        }
    }
}

/// `R`, `I`, and `F` are adapter-owned role, immutable image identity, and finite GUI fact kinds.
/// GUI history is bounded by distinct kinds rather than the number of draw calls.
pub struct ProcessObservations<R, I, F> {
    rows: Vec<ProcessObservation<R, I, F>>,
}

impl<R: Copy + Eq, I: Eq, F: Eq> Default for ProcessObservations<R, I, F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Copy + Eq, I: Eq, F: Eq> ProcessObservations<R, I, F> {
    pub const fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub fn register(
        &mut self,
        key: ObservationKey,
        role: R,
        image: I,
    ) -> Result<ObservationAck, ObservationError> {
        if !key.process.is_valid() {
            return Err(ObservationError::InvalidIdentity);
        }
        if let Some(row) = self.rows.iter().find(|row| row.key == key) {
            return if row.role == role && row.image == image {
                Ok(ObservationAck::Duplicate)
            } else {
                Err(ObservationError::ConflictingRegistration)
            };
        }
        self.rows
            .try_reserve(1)
            .map_err(|_| ObservationError::InsufficientResources)?;
        self.rows.push(ProcessObservation {
            key,
            role,
            image,
            process_catalog: false,
            vspace: false,
            main: None,
            workers: Vec::new(),
            gui: Vec::new(),
            terminal: None,
            retired: false,
        });
        Ok(ObservationAck::Recorded)
    }

    fn row_mut(
        &mut self,
        key: ObservationKey,
    ) -> Result<&mut ProcessObservation<R, I, F>, ObservationError> {
        self.rows
            .iter_mut()
            .find(|row| row.key == key)
            .ok_or(ObservationError::UnknownProcess)
    }

    pub fn record_publication(
        &mut self,
        key: ObservationKey,
        fact: PublicationFact,
    ) -> Result<ObservationAck, ObservationError> {
        let row = self.row_mut(key)?;
        if row.publication(fact) {
            return Ok(ObservationAck::Duplicate);
        }
        row.active()?;
        match fact {
            PublicationFact::ProcessCatalog => row.process_catalog = true,
            PublicationFact::VSpace => row.vspace = true,
        }
        Ok(ObservationAck::Recorded)
    }

    /// Record only the actual main-thread publication ACK; an arbitrary live worker is not main.
    pub fn record_main_publication(
        &mut self,
        key: ObservationKey,
        caller: ProviderLogicalCaller,
        current: ThreadLifetime,
    ) -> Result<ObservationAck, ObservationError> {
        let row = self.row_mut(key)?;
        row.caller_is_current(caller, current)?;
        if let Some(main) = row.main {
            return if main == caller {
                Ok(ObservationAck::Duplicate)
            } else {
                Err(ObservationError::ConflictingReceipt)
            };
        }
        row.active()?;
        row.main = Some(caller);
        Ok(ObservationAck::Recorded)
    }

    pub fn record_worker_activation(
        &mut self,
        key: ObservationKey,
        caller: ProviderLogicalCaller,
        current: ThreadLifetime,
    ) -> Result<ObservationAck, ObservationError> {
        let row = self.row_mut(key)?;
        row.caller_is_current(caller, current)?;
        if row.workers.contains(&caller) {
            return Ok(ObservationAck::Duplicate);
        }
        if row.workers.iter().any(|worker| worker.thread() == caller.thread()) {
            return Err(ObservationError::ConflictingReceipt);
        }
        row.active()?;
        row.workers
            .try_reserve(1)
            .map_err(|_| ObservationError::InsufficientResources)?;
        row.workers.push(caller);
        Ok(ObservationAck::Recorded)
    }

    /// Caller must match an acknowledged activation, not merely have the observed PID/badge.
    /// `amount` is the adapter's count of actual acknowledged events, not a progress clock.
    pub fn record_gui_fact(
        &mut self,
        key: ObservationKey,
        caller: ProviderLogicalCaller,
        current: ThreadLifetime,
        kind: F,
        amount: u64,
    ) -> Result<u64, ObservationError> {
        let row = self.row_mut(key)?;
        row.caller_is_current(caller, current)?;
        row.active()?;
        if row.main != Some(caller) && !row.workers.contains(&caller) {
            return Err(ObservationError::UnacknowledgedCaller);
        }
        if amount == 0 {
            return Err(ObservationError::InvalidCount);
        }
        if let Some(fact) = row.gui.iter_mut().find(|fact| fact.kind == kind) {
            let count = fact
                .count
                .checked_add(amount)
                .ok_or(ObservationError::CountOverflow)?;
            fact.count = count;
            return Ok(count);
        }
        row.gui
            .try_reserve(1)
            .map_err(|_| ObservationError::InsufficientResources)?;
        row.gui.push(FactCount {
            kind,
            count: amount,
        });
        Ok(amount)
    }

    /// The adapter must have a genuine immutable terminal receipt for this exact key.
    pub fn record_terminal(
        &mut self,
        key: ObservationKey,
        status: u32,
    ) -> Result<ObservationAck, ObservationError> {
        let row = self.row_mut(key)?;
        if let Some(terminal) = row.terminal {
            return if terminal == status {
                Ok(ObservationAck::Duplicate)
            } else {
                Err(ObservationError::ConflictingReceipt)
            };
        }
        row.terminal = Some(status);
        Ok(ObservationAck::Recorded)
    }

    /// Record only completed exact retirement. History remains separate from live selection.
    pub fn retire(&mut self, key: ObservationKey) -> Result<ObservationAck, ObservationError> {
        let row = self.row_mut(key)?;
        if row.terminal.is_none() {
            return Err(ObservationError::TerminalRequired);
        }
        if row.retired {
            return Ok(ObservationAck::Duplicate);
        }
        row.retired = true;
        Ok(ObservationAck::Recorded)
    }

    pub fn historical_snapshot(&self, key: ObservationKey) -> Option<&ProcessObservation<R, I, F>> {
        self.rows.iter().find(|row| row.key == key)
    }

    /// `current` comes from independently validated native process state, never from this store.
    pub fn current_live_snapshot(
        &self,
        key: ObservationKey,
        current: ObservationKey,
    ) -> Option<&ProcessObservation<R, I, F>> {
        if key != current {
            return None;
        }
        self.historical_snapshot(key)
            .filter(|row| row.active().is_ok())
    }

    /// An absent or ambiguous current role is not permission to choose a historical/first row.
    pub fn live_for_role(
        &self,
        role: R,
        current: &[ObservationKey],
    ) -> Result<Option<&ProcessObservation<R, I, F>>, ObservationError> {
        let mut selected = None;
        for row in &self.rows {
            if row.role == role && row.active().is_ok() && current.contains(&row.key) {
                if selected.is_some() {
                    return Err(ObservationError::AmbiguousRole);
                }
                selected = Some(row);
            }
        }
        Ok(selected)
    }
}

#[cfg(test)]
#[path = "process_observation_tests.rs"]
mod tests;
