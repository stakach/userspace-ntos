#![no_std]

extern crate alloc;

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchToken {
    driver_id: u64,
    devnode_index: usize,
}

impl DispatchToken {
    pub const fn driver_id(self) -> u64 {
        self.driver_id
    }

    pub const fn devnode_index(self) -> usize {
        self.devnode_index
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchPhase {
    Ready,
    Dispatching { devnode_index: usize },
    Awaiting { devnode_index: usize, irp_id: u64 },
    Complete,
    OwnershipLost { status: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchError {
    Complete,
    OwnershipLost,
    WrongPhase,
    WrongDriver,
    WrongDevnode,
    WrongIrp,
    InvalidIrp,
}

/// Pure coordinator for a serialized multi-devnode driver START batch.
///
/// The caller owns dispatch, completion observation, reports, and transport. This type only
/// enforces that a devnode is dispatched once, an exact pending IRP is observed once, and later
/// devnodes cannot pass an unfinished or indeterminate predecessor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriverStartBatch {
    driver_id: u64,
    devnode_count: usize,
    next_devnode: usize,
    phase: BatchPhase,
}

impl DriverStartBatch {
    pub const fn new(driver_id: u64, devnode_count: usize) -> Self {
        Self {
            driver_id,
            devnode_count,
            next_devnode: 0,
            phase: if devnode_count == 0 {
                BatchPhase::Complete
            } else {
                BatchPhase::Ready
            },
        }
    }

    pub const fn driver_id(&self) -> u64 {
        self.driver_id
    }

    pub const fn devnode_count(&self) -> usize {
        self.devnode_count
    }

    pub const fn next_devnode(&self) -> usize {
        self.next_devnode
    }

    pub const fn phase(&self) -> BatchPhase {
        self.phase
    }

    pub fn begin_next(&mut self) -> Result<DispatchToken, BatchError> {
        match self.phase {
            BatchPhase::Ready if self.next_devnode < self.devnode_count => {
                let token = DispatchToken {
                    driver_id: self.driver_id,
                    devnode_index: self.next_devnode,
                };
                self.phase = BatchPhase::Dispatching {
                    devnode_index: self.next_devnode,
                };
                Ok(token)
            }
            BatchPhase::Complete => Err(BatchError::Complete),
            BatchPhase::OwnershipLost { .. } => Err(BatchError::OwnershipLost),
            _ => Err(BatchError::WrongPhase),
        }
    }

    pub fn dispatch_terminal(&mut self, token: DispatchToken) -> Result<(), BatchError> {
        self.validate_dispatch(token)?;
        self.advance_terminal();
        Ok(())
    }

    pub fn dispatch_pending(
        &mut self,
        token: DispatchToken,
        irp_id: u64,
    ) -> Result<(), BatchError> {
        if irp_id == 0 {
            return Err(BatchError::InvalidIrp);
        }
        self.validate_dispatch(token)?;
        self.phase = BatchPhase::Awaiting {
            devnode_index: token.devnode_index,
            irp_id,
        };
        Ok(())
    }

    pub fn observe_terminal(&mut self, irp_id: u64) -> Result<(), BatchError> {
        self.validate_observation(irp_id)?;
        self.advance_terminal();
        Ok(())
    }

    pub fn observe_indeterminate(&mut self, irp_id: u64) -> Result<(), BatchError> {
        self.validate_observation(irp_id)?;
        self.phase = BatchPhase::Complete;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), BatchError> {
        match self.phase {
            BatchPhase::Ready | BatchPhase::Complete => {
                self.phase = BatchPhase::Complete;
                Ok(())
            }
            BatchPhase::OwnershipLost { .. } => Err(BatchError::OwnershipLost),
            _ => Err(BatchError::WrongPhase),
        }
    }

    pub fn lose_ownership(&mut self, irp_id: u64, status: u32) -> Result<(), BatchError> {
        self.validate_observation(irp_id)?;
        self.phase = BatchPhase::OwnershipLost { status };
        Ok(())
    }

    fn validate_dispatch(&self, token: DispatchToken) -> Result<(), BatchError> {
        if token.driver_id != self.driver_id {
            return Err(BatchError::WrongDriver);
        }
        if token.devnode_index != self.next_devnode {
            return Err(BatchError::WrongDevnode);
        }
        match self.phase {
            BatchPhase::Dispatching { devnode_index } if devnode_index == token.devnode_index => {
                Ok(())
            }
            _ => Err(BatchError::WrongPhase),
        }
    }

    fn validate_observation(&self, irp_id: u64) -> Result<(), BatchError> {
        match self.phase {
            BatchPhase::Awaiting {
                devnode_index,
                irp_id: expected,
            } if devnode_index == self.next_devnode && expected == irp_id => Ok(()),
            BatchPhase::Awaiting { .. } => Err(BatchError::WrongIrp),
            BatchPhase::Complete => Err(BatchError::Complete),
            BatchPhase::OwnershipLost { .. } => Err(BatchError::OwnershipLost),
            _ => Err(BatchError::WrongPhase),
        }
    }

    fn advance_terminal(&mut self) {
        self.next_devnode += 1;
        self.phase = if self.next_devnode == self.devnode_count {
            BatchPhase::Complete
        } else {
            BatchPhase::Ready
        };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingStartIdentity {
    pub irp_id: u64,
    pub devnode_id: u64,
    pub devnode_generation: u64,
    pub dispatch_generation: u64,
    pub pdo_device_id: u64,
    pub fdo_device_id: u64,
    pub origin_driver_id: u64,
    pub completion_driver_id: u64,
    pub completion_device_id: u64,
}

impl PendingStartIdentity {
    const fn is_valid(self) -> bool {
        self.irp_id != 0
            && self.devnode_id != 0
            && self.devnode_generation != 0
            && self.dispatch_generation != 0
            && self.pdo_device_id != 0
            && self.fdo_device_id != 0
            && self.origin_driver_id != 0
            && self.completion_driver_id != 0
            && self.completion_device_id != 0
    }
}

const PROOF_RETURNED_PENDING: u8 = 1 << 0;
const PROOF_COMPLETION_IDENTITY: u8 = 1 << 1;
const PROOF_LIFECYCLE_COMMITTED: u8 = 1 << 2;
const PROOF_IRP_ACKNOWLEDGED: u8 = 1 << 3;
const PROOF_IRP_RETIRED: u8 = 1 << 4;
const PROOF_PUBLICATION_COMMITTED: u8 = 1 << 5;
const PROOF_OBSERVED: u8 = 1 << 6;
pub const PENDING_START_PROOF_COMPLETE_MASK: u8 = PROOF_RETURNED_PENDING
    | PROOF_COMPLETION_IDENTITY
    | PROOF_LIFECYCLE_COMMITTED
    | PROOF_IRP_ACKNOWLEDGED
    | PROOF_IRP_RETIRED
    | PROOF_PUBLICATION_COMMITTED
    | PROOF_OBSERVED;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingStartProofError {
    InvalidIdentity,
    WrongStage,
    Duplicate,
    AllocationFailed,
}

/// Ordered proof state for one START IRP that genuinely returned `STATUS_PENDING`.
///
/// Runtime owners advance this tracker only after the corresponding external operation succeeds.
/// The tracker deliberately knows nothing about services or image names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingStartProofTracker {
    identity: PendingStartIdentity,
    terminal_status: Option<i32>,
    stages: u8,
}

impl PendingStartProofTracker {
    pub fn returned_pending(
        identity: PendingStartIdentity,
    ) -> Result<Self, PendingStartProofError> {
        if !identity.is_valid() {
            return Err(PendingStartProofError::InvalidIdentity);
        }
        Ok(Self {
            identity,
            terminal_status: None,
            stages: PROOF_RETURNED_PENDING,
        })
    }

    pub const fn identity(&self) -> PendingStartIdentity {
        self.identity
    }

    pub const fn stage_mask(&self) -> u8 {
        self.stages
    }

    pub fn completion_identity_validated(&mut self) -> Result<(), PendingStartProofError> {
        self.advance(PROOF_RETURNED_PENDING, PROOF_COMPLETION_IDENTITY)
    }

    pub fn lifecycle_committed(
        &mut self,
        terminal_status: i32,
    ) -> Result<(), PendingStartProofError> {
        if self.terminal_status.is_some() {
            return Err(PendingStartProofError::WrongStage);
        }
        self.advance(
            PROOF_RETURNED_PENDING | PROOF_COMPLETION_IDENTITY,
            PROOF_LIFECYCLE_COMMITTED,
        )?;
        self.terminal_status = Some(terminal_status);
        Ok(())
    }

    pub fn irp_acknowledged(&mut self) -> Result<(), PendingStartProofError> {
        self.advance(
            PROOF_RETURNED_PENDING | PROOF_COMPLETION_IDENTITY | PROOF_LIFECYCLE_COMMITTED,
            PROOF_IRP_ACKNOWLEDGED,
        )
    }

    pub fn irp_retired(&mut self) -> Result<(), PendingStartProofError> {
        self.advance(
            PROOF_RETURNED_PENDING
                | PROOF_COMPLETION_IDENTITY
                | PROOF_LIFECYCLE_COMMITTED
                | PROOF_IRP_ACKNOWLEDGED,
            PROOF_IRP_RETIRED,
        )
    }

    pub fn publication_committed(&mut self) -> Result<(), PendingStartProofError> {
        self.advance(
            PROOF_RETURNED_PENDING
                | PROOF_COMPLETION_IDENTITY
                | PROOF_LIFECYCLE_COMMITTED
                | PROOF_IRP_ACKNOWLEDGED
                | PROOF_IRP_RETIRED,
            PROOF_PUBLICATION_COMMITTED,
        )
    }

    pub fn terminal_proof(&self) -> Result<PendingStartTerminalProof, PendingStartProofError> {
        let required = PENDING_START_PROOF_COMPLETE_MASK & !PROOF_OBSERVED;
        if self.stages != required {
            return Err(PendingStartProofError::WrongStage);
        }
        Ok(PendingStartTerminalProof {
            identity: self.identity,
            terminal_status: self
                .terminal_status
                .ok_or(PendingStartProofError::WrongStage)?,
            stages: self.stages | PROOF_OBSERVED,
        })
    }

    fn advance(&mut self, required: u8, stage: u8) -> Result<(), PendingStartProofError> {
        if self.stages != required || self.stages & stage != 0 {
            return Err(PendingStartProofError::WrongStage);
        }
        self.stages |= stage;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingStartTerminalProof {
    identity: PendingStartIdentity,
    terminal_status: i32,
    stages: u8,
}

impl PendingStartTerminalProof {
    pub const fn identity(self) -> PendingStartIdentity {
        self.identity
    }

    pub const fn terminal_status(self) -> i32 {
        self.terminal_status
    }

    pub const fn stage_mask(self) -> u8 {
        self.stages
    }

    pub const fn is_complete(self) -> bool {
        self.stages == PENDING_START_PROOF_COMPLETE_MASK
    }
}

/// Immutable terminal rows for pending STARTs that reached exact observation.
#[derive(Default)]
pub struct PendingStartProofLedger {
    rows: Vec<PendingStartTerminalProof>,
}

impl PendingStartProofLedger {
    pub const fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub fn publish(
        &mut self,
        proof: PendingStartTerminalProof,
    ) -> Result<(), PendingStartProofError> {
        if !proof.is_complete() {
            return Err(PendingStartProofError::WrongStage);
        }
        let identity = proof.identity();
        if self.rows.iter().any(|row| {
            let current = row.identity();
            current.irp_id == identity.irp_id
                || (current.devnode_id == identity.devnode_id
                    && current.devnode_generation == identity.devnode_generation
                    && current.dispatch_generation == identity.dispatch_generation)
        }) {
            return Err(PendingStartProofError::Duplicate);
        }
        self.rows
            .try_reserve(1)
            .map_err(|_| PendingStartProofError::AllocationFailed)?;
        self.rows.push(proof);
        Ok(())
    }

    pub fn rows(&self) -> &[PendingStartTerminalProof] {
        self.rows.as_slice()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingOperationReservation {
    slot: usize,
    generation: u64,
}

impl PendingOperationReservation {
    /// Stable table slot reserved for the continuation. The generation remains private so callers
    /// can correlate external ownership without gaining the ability to forge a reservation.
    pub const fn slot(self) -> usize {
        self.slot
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingOperationTableError {
    Full,
    StaleReservation,
}

enum Slot<T> {
    Empty { generation: u64 },
    Reserved { generation: u64 },
    Occupied { generation: u64, value: T },
}

/// Generation-exact publication table for pending continuations.
///
/// Growth occurs only in `reserve`, so callers can establish storage before driver side effects.
pub struct PendingOperationTable<T> {
    slots: Vec<Slot<T>>,
}

impl<T> PendingOperationTable<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(Slot::Empty { generation: 0 });
        }
        Self { slots }
    }

    pub fn is_empty(&self) -> bool {
        self.slots
            .iter()
            .all(|slot| matches!(slot, Slot::Empty { .. }))
    }

    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    pub fn allocation_capacity(&self) -> usize {
        self.slots.capacity()
    }

    pub fn reserve(&mut self) -> Result<PendingOperationReservation, PendingOperationTableError> {
        let available = self.slots.iter().enumerate().find_map(|(slot, entry)| {
            if let Slot::Empty { generation } = entry {
                Some((slot, generation.wrapping_add(1).max(1)))
            } else {
                None
            }
        });
        let (slot, generation) = if let Some(available) = available {
            available
        } else {
            self.slots
                .try_reserve(1)
                .map_err(|_| PendingOperationTableError::Full)?;
            let slot = self.slots.len();
            self.slots.push(Slot::Empty { generation: 0 });
            (slot, 1)
        };
        self.slots[slot] = Slot::Reserved { generation };
        Ok(PendingOperationReservation { slot, generation })
    }

    pub fn cancel(
        &mut self,
        reservation: PendingOperationReservation,
    ) -> Result<(), PendingOperationTableError> {
        match self.slots.get(reservation.slot) {
            Some(Slot::Reserved { generation }) if *generation == reservation.generation => {
                self.slots[reservation.slot] = Slot::Empty {
                    generation: reservation.generation,
                };
                Ok(())
            }
            _ => Err(PendingOperationTableError::StaleReservation),
        }
    }

    pub fn publish(
        &mut self,
        reservation: PendingOperationReservation,
        value: T,
    ) -> Result<usize, PendingOperationTableError> {
        match self.slots.get(reservation.slot) {
            Some(Slot::Reserved { generation }) if *generation == reservation.generation => {
                self.slots[reservation.slot] = Slot::Occupied {
                    generation: reservation.generation,
                    value,
                };
                Ok(reservation.slot)
            }
            _ => Err(PendingOperationTableError::StaleReservation),
        }
    }

    pub fn get(&self, slot: usize) -> Option<&T> {
        match self.slots.get(slot) {
            Some(Slot::Occupied { value, .. }) => Some(value),
            _ => None,
        }
    }

    pub fn get_mut(&mut self, slot: usize) -> Option<&mut T> {
        match self.slots.get_mut(slot) {
            Some(Slot::Occupied { value, .. }) => Some(value),
            _ => None,
        }
    }

    pub fn occupied_slots(&self) -> impl Iterator<Item = usize> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(slot, entry)| matches!(entry, Slot::Occupied { .. }).then_some(slot))
    }

    pub fn take(&mut self, slot: usize) -> Option<T> {
        let entry = self.slots.get_mut(slot)?;
        let generation = match entry {
            Slot::Occupied { generation, .. } => *generation,
            _ => return None,
        };
        let old = core::mem::replace(entry, Slot::Empty { generation });
        match old {
            Slot::Occupied { value, .. } => Some(value),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_exposes_only_its_stable_owner_slot() {
        let mut table = PendingOperationTable::<u32>::with_capacity(2);
        let first = table.reserve().unwrap();
        let second = table.reserve().unwrap();
        assert_eq!(first.slot(), 0);
        assert_eq!(second.slot(), 1);
        table.cancel(first).unwrap();
        let replacement = table.reserve().unwrap();
        assert_eq!(replacement.slot(), 0);
        assert_ne!(replacement, first);
    }

    #[test]
    fn serializes_multiple_pending_devnodes() {
        let mut batch = DriverStartBatch::new(7, 3);
        let first = batch.begin_next().unwrap();
        batch.dispatch_pending(first, 101).unwrap();
        assert_eq!(batch.begin_next(), Err(BatchError::WrongPhase));
        assert_eq!(batch.observe_terminal(999), Err(BatchError::WrongIrp));
        batch.observe_terminal(101).unwrap();

        let second = batch.begin_next().unwrap();
        assert_eq!(second.devnode_index(), 1);
        batch.dispatch_terminal(second).unwrap();

        let third = batch.begin_next().unwrap();
        batch.dispatch_pending(third, 303).unwrap();
        assert_eq!(batch.observe_terminal(101), Err(BatchError::WrongIrp));
        batch.observe_terminal(303).unwrap();
        assert_eq!(batch.phase(), BatchPhase::Complete);
        assert_eq!(batch.next_devnode(), 3);
    }

    #[test]
    fn ownership_loss_is_a_permanent_barrier() {
        let mut batch = DriverStartBatch::new(9, 2);
        let token = batch.begin_next().unwrap();
        batch.dispatch_pending(token, 44).unwrap();
        batch.lose_ownership(44, 0xc000_0001).unwrap();
        assert_eq!(
            batch.phase(),
            BatchPhase::OwnershipLost {
                status: 0xc000_0001
            }
        );
        assert_eq!(batch.begin_next(), Err(BatchError::OwnershipLost));
        assert_eq!(batch.observe_terminal(44), Err(BatchError::OwnershipLost));
    }

    #[test]
    fn terminal_failure_can_stop_before_later_devnodes() {
        let mut batch = DriverStartBatch::new(3, 3);
        let first = batch.begin_next().unwrap();
        batch.dispatch_terminal(first).unwrap();
        batch.stop().unwrap();
        assert_eq!(batch.phase(), BatchPhase::Complete);
        assert_eq!(batch.next_devnode(), 1);
        assert_eq!(batch.begin_next(), Err(BatchError::Complete));
    }

    #[test]
    fn reservation_generation_rejects_stale_publication() {
        let mut table = PendingOperationTable::with_capacity(1);
        let first = table.reserve().unwrap();
        table.cancel(first).unwrap();
        let second = table.reserve().unwrap();
        assert_ne!(first, second);
        assert_eq!(
            table.publish(first, 1),
            Err(PendingOperationTableError::StaleReservation)
        );
        let slot = table.publish(second, 2).unwrap();
        assert_eq!(table.get(slot), Some(&2));
        assert_eq!(table.take(slot), Some(2));
        assert!(table.is_empty());
    }

    #[test]
    fn table_grows_only_during_reservation() {
        let mut table = PendingOperationTable::<u64>::with_capacity(1);
        let first = table.reserve().unwrap();
        table.publish(first, 5).unwrap();
        let second = table.reserve().unwrap();
        table.publish(second, 6).unwrap();
        assert_eq!(table.slot_count(), 2);
        assert_eq!(table.get(0), Some(&5));
        assert_eq!(table.get(1), Some(&6));
    }

    fn pending_identity(irp_id: u64, dispatch_generation: u64) -> PendingStartIdentity {
        PendingStartIdentity {
            irp_id,
            devnode_id: 7,
            devnode_generation: 3,
            dispatch_generation,
            pdo_device_id: 70,
            fdo_device_id: 71,
            origin_driver_id: 8,
            completion_driver_id: 9,
            completion_device_id: 71,
        }
    }

    #[test]
    fn pending_start_proof_requires_every_external_stage_in_order() {
        let mut tracker =
            PendingStartProofTracker::returned_pending(pending_identity(101, 4)).unwrap();
        assert_eq!(
            tracker.lifecycle_committed(0),
            Err(PendingStartProofError::WrongStage)
        );
        tracker.completion_identity_validated().unwrap();
        tracker.lifecycle_committed(0).unwrap();
        tracker.irp_acknowledged().unwrap();
        tracker.irp_retired().unwrap();
        assert_eq!(
            tracker.terminal_proof(),
            Err(PendingStartProofError::WrongStage)
        );
        tracker.publication_committed().unwrap();
        let proof = tracker.terminal_proof().unwrap();
        assert!(proof.is_complete());
        assert_eq!(proof.terminal_status(), 0);
    }

    #[test]
    fn pending_start_ledger_rejects_duplicate_irp_and_dispatch_identity() {
        fn terminal(identity: PendingStartIdentity) -> PendingStartTerminalProof {
            let mut tracker = PendingStartProofTracker::returned_pending(identity).unwrap();
            tracker.completion_identity_validated().unwrap();
            tracker.lifecycle_committed(-1).unwrap();
            tracker.irp_acknowledged().unwrap();
            tracker.irp_retired().unwrap();
            tracker.publication_committed().unwrap();
            tracker.terminal_proof().unwrap()
        }

        let mut ledger = PendingStartProofLedger::new();
        ledger.publish(terminal(pending_identity(101, 4))).unwrap();
        assert_eq!(
            ledger.publish(terminal(pending_identity(101, 5))),
            Err(PendingStartProofError::Duplicate)
        );
        assert_eq!(
            ledger.publish(terminal(pending_identity(102, 4))),
            Err(PendingStartProofError::Duplicate)
        );
        ledger.publish(terminal(pending_identity(102, 5))).unwrap();
        assert_eq!(ledger.len(), 2);
    }
}
