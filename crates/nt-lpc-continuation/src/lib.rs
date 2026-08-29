//! Kernel-owned continuation state for blocking NT LPC receive services.
//!
//! The broker owns ports, messages, and connection identity. This crate owns the small piece of
//! kernel policy needed between a broker `STATUS_PENDING` result and the eventual syscall resume:
//! reserve storage before the reply/wait transition, publish exactly one typed receive, and take it
//! exactly once when data, disconnect, cancellation, or copyout completes the wait.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

const DEFAULT_INITIAL_RESERVE: usize = 16;

/// Native service operation represented by a blocked receive continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveOperation {
    Listen,
    ReplyWaitReceive,
}

/// Broker endpoint and native output addresses retained while a receive is blocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveRequest {
    pub port_handle: u64,
    pub receive_message: u64,
    pub port_context: u64,
    pub operation: ReceiveOperation,
}

impl ReceiveRequest {
    pub const fn is_valid(self) -> bool {
        self.port_handle != 0
            && self.receive_message != 0
            && (matches!(self.operation, ReceiveOperation::ReplyWaitReceive)
                || self.port_context == 0)
    }
}

/// One typed blocked receive plus the executive-specific continuation needed to resume it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingReceive<C> {
    pub request: ReceiveRequest,
    pub continuation: C,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    slot: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError {
    Full,
    InvalidRequest,
    StaleReservation,
}

enum Slot<C> {
    Empty,
    Reserved {
        generation: u64,
    },
    Occupied {
        generation: u64,
        value: PendingReceive<C>,
    },
}

/// Growable, generation-exact ownership table for pending LPC receives.
///
/// Allocation happens only in [`Self::reserve`], before the broker is allowed to commit the reply
/// half of `NtReplyWaitReceivePort`. Publishing and completing a wait cannot allocate.
pub struct ReceiveWaitTable<C> {
    slots: Vec<Slot<C>>,
    initial_reserve: usize,
    next_generation: u64,
}

impl<C> Default for ReceiveWaitTable<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> ReceiveWaitTable<C> {
    pub const fn new() -> Self {
        Self::with_initial_reserve(DEFAULT_INITIAL_RESERVE)
    }

    pub const fn with_initial_reserve(initial_reserve: usize) -> Self {
        Self {
            slots: Vec::new(),
            initial_reserve,
            next_generation: 1,
        }
    }

    pub fn reset(&mut self) -> Result<(), TableError> {
        self.slots.clear();
        if self.slots.capacity() < self.initial_reserve {
            self.slots
                .try_reserve(self.initial_reserve - self.slots.capacity())
                .map_err(|_| TableError::Full)?;
        }
        for _ in 0..self.initial_reserve {
            self.slots.push(Slot::Empty);
        }
        Ok(())
    }

    pub fn reserve(&mut self) -> Result<Reservation, TableError> {
        let available = self
            .slots
            .iter()
            .position(|entry| matches!(entry, Slot::Empty));
        let slot = if let Some(slot) = available {
            slot
        } else {
            self.slots.try_reserve(1).map_err(|_| TableError::Full)?;
            let slot = self.slots.len();
            self.slots.push(Slot::Empty);
            slot
        };
        let generation = self.next_generation.max(1);
        self.next_generation = generation.wrapping_add(1).max(1);
        self.slots[slot] = Slot::Reserved { generation };
        Ok(Reservation { slot, generation })
    }

    pub fn cancel(&mut self, reservation: Reservation) -> Result<(), TableError> {
        match self.slots.get(reservation.slot) {
            Some(Slot::Reserved { generation }) if *generation == reservation.generation => {
                self.slots[reservation.slot] = Slot::Empty;
                Ok(())
            }
            _ => Err(TableError::StaleReservation),
        }
    }

    pub fn publish(
        &mut self,
        reservation: Reservation,
        value: PendingReceive<C>,
    ) -> Result<usize, TableError> {
        if !value.request.is_valid() {
            return Err(TableError::InvalidRequest);
        }
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

    pub fn get(&self, slot: usize) -> Option<&PendingReceive<C>> {
        match self.slots.get(slot) {
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

    /// Return the next occupied slot in reservation order. This keeps receive polling FIFO even
    /// after a low-numbered slot has been freed and reused by a newer waiter.
    pub fn next_occupied_after(&self, generation: u64) -> Option<(usize, u64, &PendingReceive<C>)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(slot, entry)| match entry {
                Slot::Occupied {
                    generation: current,
                    value,
                } if *current > generation => Some((slot, *current, value)),
                _ => None,
            })
            .min_by_key(|(_, current, _)| *current)
    }

    pub fn take(&mut self, slot: usize) -> Option<PendingReceive<C>> {
        let entry = self.slots.get_mut(slot)?;
        if !matches!(entry, Slot::Occupied { .. }) {
            return None;
        }
        let old = core::mem::replace(entry, Slot::Empty);
        match old {
            Slot::Occupied { value, .. } => Some(value),
            _ => unreachable!(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(|slot| matches!(slot, Slot::Empty))
    }

    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    pub fn allocation_capacity(&self) -> usize {
        self.slots.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receive(port_handle: u64, token: u64) -> PendingReceive<u64> {
        PendingReceive {
            request: ReceiveRequest {
                port_handle,
                receive_message: 0x1000 + token,
                port_context: 0x2000 + token,
                operation: ReceiveOperation::ReplyWaitReceive,
            },
            continuation: token,
        }
    }

    #[test]
    fn reservation_is_generation_exact() {
        let mut table = ReceiveWaitTable::with_initial_reserve(1);
        table.reset().unwrap();
        let stale = table.reserve().unwrap();
        table.cancel(stale).unwrap();
        let current = table.reserve().unwrap();
        assert_ne!(stale, current);
        assert_eq!(
            table.publish(stale, receive(1, 10)),
            Err(TableError::StaleReservation)
        );
        assert_eq!(table.publish(current, receive(1, 11)), Ok(0));
        assert_eq!(table.take(0).unwrap().continuation, 11);
        assert!(table.is_empty());
    }

    #[test]
    fn multiple_receivers_may_wait_on_one_endpoint() {
        let mut table = ReceiveWaitTable::new();
        for token in 1..=3 {
            let reservation = table.reserve().unwrap();
            table.publish(reservation, receive(7, token)).unwrap();
        }
        let slots: alloc::vec::Vec<_> = table.occupied_slots().collect();
        assert_eq!(slots, [0, 1, 2]);
        assert_eq!(table.take(1).unwrap().continuation, 2);
        assert_eq!(table.get(0).unwrap().continuation, 1);
        assert_eq!(table.get(2).unwrap().continuation, 3);
    }

    #[test]
    fn invalid_native_output_state_is_rejected_without_consuming_reservation() {
        let mut table = ReceiveWaitTable::new();
        let reservation = table.reserve().unwrap();
        let invalid = PendingReceive {
            request: ReceiveRequest {
                port_handle: 1,
                receive_message: 0,
                port_context: 0,
                operation: ReceiveOperation::Listen,
            },
            continuation: 9,
        };
        assert_eq!(
            table.publish(reservation, invalid),
            Err(TableError::InvalidRequest)
        );
        table.cancel(reservation).unwrap();
    }

    #[test]
    fn reset_preserves_reserve_and_invalidates_old_tokens() {
        let mut table = ReceiveWaitTable::with_initial_reserve(4);
        let stale = table.reserve().unwrap();
        table.reset().unwrap();
        assert!(table.allocation_capacity() >= 4);
        assert_eq!(table.slot_count(), 4);
        assert_eq!(table.cancel(stale), Err(TableError::StaleReservation));
        let current = table.reserve().unwrap();
        assert_ne!(stale, current);
        table.publish(current, receive(2, 4)).unwrap();
    }

    #[test]
    fn occupied_iteration_preserves_wait_order_after_slot_reuse() {
        let mut table = ReceiveWaitTable::new();
        for token in 1..=3 {
            let reservation = table.reserve().unwrap();
            table.publish(reservation, receive(7, token)).unwrap();
        }
        table.take(0).unwrap();
        let reused = table.reserve().unwrap();
        table.publish(reused, receive(7, 4)).unwrap();

        let mut generation = 0;
        let mut tokens = alloc::vec::Vec::new();
        while let Some((_, current, wait)) = table.next_occupied_after(generation) {
            generation = current;
            tokens.push(wait.continuation);
        }
        assert_eq!(tokens, [2, 3, 4]);
    }
}
