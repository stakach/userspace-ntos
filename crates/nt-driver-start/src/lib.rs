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
pub struct Reservation {
    slot: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableError {
    Full,
    StaleReservation,
}

enum Slot<T> {
    Empty { generation: u64 },
    Reserved { generation: u64 },
    Occupied { generation: u64, value: T },
}

/// Generation-exact publication table for pending load continuations.
///
/// Growth occurs only in `reserve`, so callers can establish storage before driver side effects.
pub struct PendingDriverStartTable<T> {
    slots: Vec<Slot<T>>,
}

impl<T> PendingDriverStartTable<T> {
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

    pub fn reserve(&mut self) -> Result<Reservation, TableError> {
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
            self.slots.try_reserve(1).map_err(|_| TableError::Full)?;
            let slot = self.slots.len();
            self.slots.push(Slot::Empty { generation: 0 });
            (slot, 1)
        };
        self.slots[slot] = Slot::Reserved { generation };
        Ok(Reservation { slot, generation })
    }

    pub fn cancel(&mut self, reservation: Reservation) -> Result<(), TableError> {
        match self.slots.get(reservation.slot) {
            Some(Slot::Reserved { generation }) if *generation == reservation.generation => {
                self.slots[reservation.slot] = Slot::Empty {
                    generation: reservation.generation,
                };
                Ok(())
            }
            _ => Err(TableError::StaleReservation),
        }
    }

    pub fn publish(&mut self, reservation: Reservation, value: T) -> Result<usize, TableError> {
        match self.slots.get(reservation.slot) {
            Some(Slot::Reserved { generation }) if *generation == reservation.generation => {
                self.slots[reservation.slot] = Slot::Occupied {
                    generation: reservation.generation,
                    value,
                };
                Ok(reservation.slot)
            }
            _ => Err(TableError::StaleReservation),
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
        let mut table = PendingDriverStartTable::with_capacity(1);
        let first = table.reserve().unwrap();
        table.cancel(first).unwrap();
        let second = table.reserve().unwrap();
        assert_ne!(first, second);
        assert_eq!(table.publish(first, 1), Err(TableError::StaleReservation));
        let slot = table.publish(second, 2).unwrap();
        assert_eq!(table.get(slot), Some(&2));
        assert_eq!(table.take(slot), Some(2));
        assert!(table.is_empty());
    }

    #[test]
    fn table_grows_only_during_reservation() {
        let mut table = PendingDriverStartTable::<u64>::with_capacity(1);
        let first = table.reserve().unwrap();
        table.publish(first, 5).unwrap();
        let second = table.reserve().unwrap();
        table.publish(second, 6).unwrap();
        assert_eq!(table.slot_count(), 2);
        assert_eq!(table.get(0), Some(&5));
        assert_eq!(table.get(1), Some(&6));
    }
}
