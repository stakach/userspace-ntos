//! Generic move-only owner storage, reserved before an effect can return an uncertain result.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_TABLE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedOwnerReservation {
    table: u64,
    slot: usize,
    generation: u64,
}

#[cfg(test)]
impl RetainedOwnerReservation {
    pub(crate) fn slot(self) -> usize { self.slot }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedOwnerTicket<K> {
    reservation: RetainedOwnerReservation,
    key: K,
}

impl<K: Copy> RetainedOwnerTicket<K> {
    pub const fn key(self) -> K { self.key }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedOwnerError {
    NoCapacity,
    StaleReservation,
}

#[derive(Debug, Eq, PartialEq)]
pub enum RetainedOwnerTransitionError<E> {
    StaleTicket,
    Refused(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedOwnerFinishError {
    StaleTicket,
}

enum Slot<K, B> {
    Reserved(u64),
    Held { generation: u64, key: K, bundle: B },
    Taken { generation: u64, key: K },
}

/// A ticket selects storage; only the row holds the retained bundle.
pub struct RetainedOwnerTable<K, B> {
    table: u64,
    next_generation: u64,
    slots: Vec<Option<Slot<K, B>>>,
}

impl<K: Copy + Eq, B> Default for RetainedOwnerTable<K, B> {
    fn default() -> Self { Self::new() }
}

impl<K: Copy + Eq, B> RetainedOwnerTable<K, B> {
    pub const fn new() -> Self {
        Self { table: 0, next_generation: 1, slots: Vec::new() }
    }

    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize { self.slots.capacity() }

    /// Reserve the row before removing the sole selected bundle from its pending owner.
    pub fn reserve(&mut self) -> Result<RetainedOwnerReservation, RetainedOwnerError> {
        let slot = self.slots.iter().position(Option::is_none).unwrap_or(self.slots.len());
        if slot == self.slots.len() {
            self.slots.try_reserve(1).map_err(|_| RetainedOwnerError::NoCapacity)?;
        }
        let next = self.next_generation.checked_add(1)
            .ok_or(RetainedOwnerError::NoCapacity)?;
        let table = if self.table == 0 {
            NEXT_TABLE.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| value.checked_add(1))
                .map_err(|_| RetainedOwnerError::NoCapacity)?
        } else { self.table };
        self.table = table;
        let generation = self.next_generation;
        self.next_generation = next;
        if slot == self.slots.len() { self.slots.push(None); }
        self.slots[slot] = Some(Slot::Reserved(generation));
        Ok(RetainedOwnerReservation { table, slot, generation })
    }

    pub fn cancel_reservation(&mut self, reservation: RetainedOwnerReservation) -> bool {
        if self.table != reservation.table
            || !matches!(self.slots.get(reservation.slot), Some(Some(Slot::Reserved(generation)))
                if *generation == reservation.generation)
        { return false; }
        self.slots[reservation.slot] = None;
        true
    }

    /// A failed identity check returns the untouched bundle and leaves the reservation usable.
    pub fn retain(
        &mut self, reservation: RetainedOwnerReservation,
        key: K, bundle: B,
    ) -> Result<RetainedOwnerTicket<K>, (RetainedOwnerError, B)> {
        if self.table != reservation.table
            || !matches!(self.slots.get(reservation.slot), Some(Some(Slot::Reserved(generation)))
                if *generation == reservation.generation)
        { return Err((RetainedOwnerError::StaleReservation, bundle)); }
        self.slots[reservation.slot] = Some(Slot::Held {
            generation: reservation.generation, key, bundle,
        });
        Ok(RetainedOwnerTicket { reservation, key })
    }

    pub fn get(&self, ticket: RetainedOwnerTicket<K>) -> Option<&B> {
        if ticket.reservation.table != self.table { return None; }
        match self.slots.get(ticket.reservation.slot)?.as_ref()? {
            Slot::Held { generation, key, bundle }
                if *generation == ticket.reservation.generation && *key == ticket.key => Some(bundle),
            _ => None,
        }
    }

    /// Run a serialized, move-only owner transition in its exact held row. A refusal must
    /// return the original owner; the row is restored before the refusal reaches the caller.
    pub fn transition_held<E>(
        &mut self, ticket: RetainedOwnerTicket<K>,
        transition: impl FnOnce(B) -> Result<B, (E, B)>,
    ) -> Result<(), RetainedOwnerTransitionError<E>> {
        if self.get(ticket).is_none() {
            return Err(RetainedOwnerTransitionError::StaleTicket);
        }
        let Some(slot) = self.slots[ticket.reservation.slot].take() else {
            return Err(RetainedOwnerTransitionError::StaleTicket);
        };
        let Slot::Held { generation, key, bundle } = slot else {
            self.slots[ticket.reservation.slot] = Some(slot);
            return Err(RetainedOwnerTransitionError::StaleTicket);
        };
        let (bundle, result) = match transition(bundle) {
            Ok(next) => (next, Ok(())),
            Err((error, original)) => (original, Err(RetainedOwnerTransitionError::Refused(error))),
        };
        self.slots[ticket.reservation.slot] = Some(Slot::Held { generation, key, bundle });
        result
    }

    /// Extract once for a checked transfer. A refused transfer must restore the same bundle.
    pub fn take(&mut self, ticket: RetainedOwnerTicket<K>) -> Option<B> {
        self.get(ticket)?;
        let slot = self.slots[ticket.reservation.slot].take()?;
        let Slot::Held { generation, key, bundle } = slot else { unreachable!("checked held slot changed") };
        self.slots[ticket.reservation.slot] = Some(Slot::Taken { generation, key });
        Some(bundle)
    }

    pub fn restore(&mut self, ticket: RetainedOwnerTicket<K>, bundle: B) -> Result<(), B> {
        if ticket.reservation.table != self.table
            || !matches!(self.slots.get(ticket.reservation.slot), Some(Some(Slot::Taken { generation, key }))
                if *generation == ticket.reservation.generation && *key == ticket.key)
        { return Err(bundle); }
        self.slots[ticket.reservation.slot] = Some(Slot::Held {
            generation: ticket.reservation.generation, key: ticket.key, bundle,
        });
        Ok(())
    }

    /// Release a checked-out row only after its bundle is acknowledged by the next owner.
    /// A held or foreign ticket cannot retire an owner that has not transferred.
    pub fn finish_taken(
        &mut self, ticket: RetainedOwnerTicket<K>,
    ) -> Result<(), RetainedOwnerFinishError> {
        if ticket.reservation.table != self.table
            || !matches!(self.slots.get(ticket.reservation.slot), Some(Some(Slot::Taken { generation, key }))
                if *generation == ticket.reservation.generation && *key == ticket.key)
        { return Err(RetainedOwnerFinishError::StaleTicket); }
        self.slots[ticket.reservation.slot] = None;
        Ok(())
    }
}
