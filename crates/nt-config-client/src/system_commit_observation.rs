//! Exact, move-only observations of an in-flight SYSTEM CM COMMIT.
//!
//! This is process-local bookkeeping, not a storage lease or durability proof. The native
//! executive owns the collection and records transport entry before calling CM. A flush may
//! hold a ticket until the exact positive receipt or acknowledged no-effect abort settles.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{
    PreparedSystemHiveMutation, SystemHiveMount, SystemHiveMutationAbortAcknowledgement,
    SystemHiveMutationCommitReceipt, SystemHiveMutationStorageBinding,
};

static NEXT_MANAGER_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemCommitObservationError {
    Invalid,
    Busy,
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemCommitOutcome {
    Pending,
    Published,
    NoEffect,
}

#[derive(Clone, Copy)]
enum State {
    Armed,
    Pending,
    Published(SystemHiveMutationCommitReceipt),
    NoEffect(SystemHiveMutationAbortAcknowledgement),
}

struct Record {
    nonce: u64,
    work_id: u64,
    mount: SystemHiveMount,
    generation: u64,
    storage_binding: SystemHiveMutationStorageBinding,
    state: State,
    row_retired: bool,
    observers: usize,
}

/// One executive-owned collection. Moving it preserves its ticket domain; replacing it does
/// not grant a new instance authority over tickets minted by the previous instance.
pub struct SystemCommitObservations {
    manager_nonce: u64,
    next_record_nonce: u64,
    records: Vec<Option<Record>>,
}

/// One exact observation, including the manager incarnation and reused slot nonce.
/// Dropping this value does not release its observer count; the executive retains and releases
/// it explicitly, including after a parked flush resumes.
#[derive(Debug)]
#[must_use = "release the exact COMMIT observation after its outcome fixes the flush target"]
pub struct SystemCommitObservationTicket {
    manager_nonce: u64,
    slot: usize,
    nonce: u64,
    work_id: u64,
    mount: SystemHiveMount,
    generation: u64,
}

impl SystemCommitObservationTicket {
    pub const fn work_id(&self) -> u64 {
        self.work_id
    }
    pub const fn mount(&self) -> SystemHiveMount {
        self.mount
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

impl Default for SystemCommitObservations {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemCommitObservations {
    pub const fn new() -> Self {
        Self {
            manager_nonce: 0,
            next_record_nonce: 1,
            records: Vec::new(),
        }
    }

    fn exact(&self, record: &Record, ticket: &SystemCommitObservationTicket) -> bool {
        self.manager_nonce != 0
            && self.manager_nonce == ticket.manager_nonce
            && record.nonce == ticket.nonce
            && record.work_id == ticket.work_id
            && record.mount == ticket.mount
            && record.generation == ticket.generation
    }

    fn terminal(record: &Record) -> bool {
        matches!(record.state, State::Published(_) | State::NoEffect(_))
    }

    /// Reserve the observation slot before any CM COMMIT IPC or other entered effect.
    pub fn arm(
        &mut self,
        work_id: u64,
        prepared: &PreparedSystemHiveMutation,
    ) -> Result<(), SystemCommitObservationError> {
        let mount = prepared.mount();
        let generation = prepared.next_generation();
        let storage_binding = prepared.storage_binding();
        if let Some(record) = self
            .records
            .iter()
            .flatten()
            .find(|record| record.work_id == work_id)
        {
            return if record.mount == mount
                && record.generation == generation
                && record.storage_binding == storage_binding
                && matches!(record.state, State::Armed | State::Pending)
            {
                Ok(())
            } else {
                Err(SystemCommitObservationError::Invalid)
            };
        }
        if self.records.iter().flatten().any(|record| {
            record.mount == mount && matches!(record.state, State::Armed | State::Pending)
        }) {
            return Err(SystemCommitObservationError::Busy);
        }
        let slot = if let Some(slot) = self.records.iter().position(Option::is_none) {
            slot
        } else {
            self.records
                .try_reserve(1)
                .map_err(|_| SystemCommitObservationError::Exhausted)?;
            self.records.push(None);
            self.records.len() - 1
        };
        let next = self
            .next_record_nonce
            .checked_add(1)
            .ok_or(SystemCommitObservationError::Exhausted)?;
        let manager = if self.manager_nonce == 0 {
            NEXT_MANAGER_NONCE
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(1)
                })
                .map_err(|_| SystemCommitObservationError::Exhausted)?
        } else {
            self.manager_nonce
        };
        self.manager_nonce = manager;
        let nonce = self.next_record_nonce;
        self.next_record_nonce = next;
        self.records[slot] = Some(Record {
            nonce,
            work_id,
            mount,
            generation,
            storage_binding,
            state: State::Armed,
            row_retired: false,
            observers: 0,
        });
        Ok(())
    }

    pub fn enter(
        &mut self,
        work_id: u64,
        prepared: &PreparedSystemHiveMutation,
    ) -> Result<(), SystemCommitObservationError> {
        let record = self
            .records
            .iter_mut()
            .flatten()
            .find(|record| {
                record.work_id == work_id
                    && record.mount == prepared.mount()
                    && record.generation == prepared.next_generation()
                    && record.storage_binding == prepared.storage_binding()
            })
            .ok_or(SystemCommitObservationError::Invalid)?;
        match record.state {
            State::Armed => {
                record.state = State::Pending;
                Ok(())
            }
            State::Pending => Ok(()),
            _ => Err(SystemCommitObservationError::Invalid),
        }
    }

    pub fn publish(
        &mut self,
        work_id: u64,
        prepared: &PreparedSystemHiveMutation,
        receipt: SystemHiveMutationCommitReceipt,
    ) -> Result<(), SystemCommitObservationError> {
        if !receipt.matches_storage_binding(prepared.storage_binding())
            || receipt.outcome().generation != prepared.next_generation()
        {
            return Err(SystemCommitObservationError::Invalid);
        }
        let record = self
            .records
            .iter_mut()
            .flatten()
            .find(|record| {
                record.work_id == work_id
                    && record.mount == prepared.mount()
                    && record.generation == prepared.next_generation()
                    && record.storage_binding == prepared.storage_binding()
            })
            .ok_or(SystemCommitObservationError::Invalid)?;
        match record.state {
            State::Pending => {
                record.state = State::Published(receipt);
                Ok(())
            }
            State::Published(previous) if previous == receipt => Ok(()),
            _ => Err(SystemCommitObservationError::Invalid),
        }
    }

    pub fn no_effect(
        &mut self,
        work_id: u64,
        prepared: &PreparedSystemHiveMutation,
        ack: SystemHiveMutationAbortAcknowledgement,
    ) -> Result<(), SystemCommitObservationError> {
        if !ack
            .receipt()
            .matches_storage_binding(prepared.storage_binding())
        {
            return Err(SystemCommitObservationError::Invalid);
        }
        let Some(record) = self
            .records
            .iter_mut()
            .flatten()
            .find(|record| record.work_id == work_id)
        else {
            return Ok(()); // The row never armed or entered CM COMMIT.
        };
        if record.mount != prepared.mount()
            || record.generation != prepared.next_generation()
            || record.storage_binding != prepared.storage_binding()
        {
            return Err(SystemCommitObservationError::Invalid);
        }
        match record.state {
            State::Armed | State::Pending => {
                record.state = State::NoEffect(ack);
                Ok(())
            }
            State::NoEffect(previous) if previous == ack => Ok(()),
            _ => Err(SystemCommitObservationError::Invalid),
        }
    }

    /// Capture the sole entered attempt at this mount. A published record is already visible
    /// through CM's published-generation observation and does not need a pending ticket.
    pub fn capture(
        &mut self,
        mount: SystemHiveMount,
    ) -> Result<Option<SystemCommitObservationTicket>, SystemCommitObservationError> {
        let mut selected = None;
        for (slot, record) in self.records.iter().enumerate() {
            if record.as_ref().is_some_and(|record| {
                record.mount == mount && matches!(record.state, State::Pending)
            }) {
                if selected.replace(slot).is_some() {
                    return Err(SystemCommitObservationError::Busy);
                }
            }
        }
        let Some(slot) = selected else {
            return Ok(None);
        };
        let record = self.records[slot]
            .as_mut()
            .ok_or(SystemCommitObservationError::Invalid)?;
        record.observers = record
            .observers
            .checked_add(1)
            .ok_or(SystemCommitObservationError::Exhausted)?;
        Ok(Some(SystemCommitObservationTicket {
            manager_nonce: self.manager_nonce,
            slot,
            nonce: record.nonce,
            work_id: record.work_id,
            mount: record.mount,
            generation: record.generation,
        }))
    }

    pub fn poll(
        &self,
        ticket: &SystemCommitObservationTicket,
    ) -> Result<SystemCommitOutcome, SystemCommitObservationError> {
        let record = self
            .records
            .get(ticket.slot)
            .and_then(Option::as_ref)
            .ok_or(SystemCommitObservationError::Invalid)?;
        if !self.exact(record, ticket) || record.observers == 0 {
            return Err(SystemCommitObservationError::Invalid);
        }
        Ok(match record.state {
            State::Armed | State::Pending => SystemCommitOutcome::Pending,
            State::Published(_) => SystemCommitOutcome::Published,
            State::NoEffect(_) => SystemCommitOutcome::NoEffect,
        })
    }

    /// Consume exactly one observer. A refusal returns its ticket unchanged for retention.
    pub fn release(
        &mut self,
        ticket: SystemCommitObservationTicket,
    ) -> Result<(), (SystemCommitObservationError, SystemCommitObservationTicket)> {
        let valid = self
            .records
            .get(ticket.slot)
            .and_then(Option::as_ref)
            .is_some_and(|record| self.exact(record, &ticket) && record.observers > 0);
        if !valid {
            return Err((SystemCommitObservationError::Invalid, ticket));
        }
        let Some(record) = self.records[ticket.slot].as_mut() else {
            return Err((SystemCommitObservationError::Invalid, ticket));
        };
        record.observers -= 1;
        if record.observers == 0 && record.row_retired && Self::terminal(record) {
            self.records[ticket.slot] = None;
        }
        Ok(())
    }

    /// A row may retire only after its normal terminal path; an observer keeps its record.
    pub fn retire(&mut self, work_id: u64) {
        if let Some(slot) = self.records.iter().position(|record| {
            record
                .as_ref()
                .is_some_and(|record| record.work_id == work_id)
        }) {
            let remove = if let Some(record) = self.records[slot].as_mut() {
                record.row_retired = true;
                record.observers == 0 && Self::terminal(record)
            } else {
                false
            };
            if remove {
                self.records[slot] = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation_commit::test_support::{client, prepare};

    #[test]
    fn pending_ticket_follows_exact_receipt_after_row_retires() {
        let mut client = client(1);
        let prepared = prepare(&mut client, 1, "Observed");
        let mut records = SystemCommitObservations::new();
        records.arm(41, &prepared).unwrap();
        assert!(records.capture(prepared.mount()).unwrap().is_none());
        records.enter(41, &prepared).unwrap();
        let ticket = records.capture(prepared.mount()).unwrap().unwrap();
        assert_eq!(records.poll(&ticket), Ok(SystemCommitOutcome::Pending));
        let receipt = client
            .commit_system_hive_mutation_retained(&prepared)
            .unwrap();
        records.publish(41, &prepared, receipt).unwrap();
        records.retire(41);
        assert_eq!(records.poll(&ticket), Ok(SystemCommitOutcome::Published));
        records.release(ticket).unwrap();
        assert!(records.capture(prepared.mount()).unwrap().is_none());
    }

    #[test]
    fn acknowledged_abort_is_the_only_no_effect_terminal() {
        let mut client = client(1);
        let prepared = prepare(&mut client, 1, "Aborted");
        let mut records = SystemCommitObservations::new();
        records.arm(42, &prepared).unwrap();
        records.enter(42, &prepared).unwrap();
        let ticket = records.capture(prepared.mount()).unwrap().unwrap();
        let receipt = client
            .abort_prepared_system_hive_mutation_retained(&prepared)
            .unwrap();
        assert_eq!(records.poll(&ticket), Ok(SystemCommitOutcome::Pending));
        let ack = client
            .acknowledge_system_hive_mutation_abort(receipt)
            .unwrap();
        records.no_effect(42, &prepared, ack).unwrap();
        records.retire(42);
        assert_eq!(records.poll(&ticket), Ok(SystemCommitOutcome::NoEffect));
        records.release(ticket).unwrap();
    }

    #[test]
    fn foreign_manager_and_reused_slot_cannot_release_ticket() {
        let mut client = client(1);
        let first = prepare(&mut client, 1, "First");
        let mut records = SystemCommitObservations::new();
        records.arm(43, &first).unwrap();
        records.enter(43, &first).unwrap();
        let ticket = records.capture(first.mount()).unwrap().unwrap();
        let mut foreign = SystemCommitObservations::new();
        foreign.arm(43, &first).unwrap();
        let (error, ticket) = foreign.release(ticket).unwrap_err();
        assert_eq!(error, SystemCommitObservationError::Invalid);
        let receipt = client.commit_system_hive_mutation_retained(&first).unwrap();
        records.publish(43, &first, receipt).unwrap();
        let _ = client.acknowledge_system_hive_mutation_commit(receipt).unwrap();
        records.retire(43);
        let stale_identity = (ticket.manager_nonce, ticket.slot, ticket.nonce,
            ticket.work_id, ticket.mount, ticket.generation);
        records.release(ticket).unwrap();
        let next = prepare(&mut client, 2, "Second");
        records.arm(44, &next).unwrap();
        records.enter(44, &next).unwrap();
        let next_ticket = records.capture(next.mount()).unwrap().unwrap();
        assert_eq!(next_ticket.work_id(), 44);
        let (manager_nonce, slot, nonce, work_id, mount, generation) = stale_identity;
        let stale = SystemCommitObservationTicket {
            manager_nonce, slot, nonce, work_id, mount, generation,
        };
        assert_eq!(records.poll(&stale), Err(SystemCommitObservationError::Invalid));
        let (error, _) = records.release(stale).unwrap_err();
        assert_eq!(error, SystemCommitObservationError::Invalid);
        records.release(next_ticket).unwrap();
    }

    #[test]
    fn different_preparation_at_same_mount_and_generation_cannot_settle_ticket() {
        let mut client = client(1);
        let first = prepare(&mut client, 1, "First");
        let mut records = SystemCommitObservations::new();
        records.arm(45, &first).unwrap();
        records.enter(45, &first).unwrap();
        let ticket = records.capture(first.mount()).unwrap().unwrap();

        let aborted = client
            .abort_prepared_system_hive_mutation_retained(&first)
            .unwrap();
        let first_ack = client
            .acknowledge_system_hive_mutation_abort(aborted)
            .unwrap();
        let other = prepare(&mut client, 1, "Other");
        assert_eq!(first.mount(), other.mount());
        assert_eq!(first.next_generation(), other.next_generation());
        assert_ne!(first.storage_binding(), other.storage_binding());
        assert_eq!(
            records.enter(45, &other),
            Err(SystemCommitObservationError::Invalid)
        );
        let other_receipt = client.commit_system_hive_mutation_retained(&other).unwrap();
        assert_eq!(
            records.publish(45, &other, other_receipt),
            Err(SystemCommitObservationError::Invalid)
        );
        assert_eq!(records.poll(&ticket), Ok(SystemCommitOutcome::Pending));

        let _ = client.acknowledge_system_hive_mutation_commit(other_receipt).unwrap();
        records.no_effect(45, &first, first_ack).unwrap();
        records.retire(45);
        assert_eq!(records.poll(&ticket), Ok(SystemCommitOutcome::NoEffect));
        records.release(ticket).unwrap();
    }
}
