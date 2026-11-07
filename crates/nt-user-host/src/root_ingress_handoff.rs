//! Move-only storage for a selected root Call's held physical parent and pump snapshot.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_component_suspension::{ExternalAdmissionKey, NestedExecutionIdentity};

static NEXT_TABLE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootIngressHandoffKey {
    parent: NestedExecutionIdentity,
    child: ExternalAdmissionKey,
    root_reply: u64,
}

impl RootIngressHandoffKey {
    pub fn new(parent: NestedExecutionIdentity, child: ExternalAdmissionKey, root_reply: u64) -> Option<Self> {
        (root_reply != 0 && child.reply() != 0 && child.executor() != 0
            && child.admission_sequence() != 0)
            .then_some(Self { parent, child, root_reply })
    }

    pub const fn parent(self) -> NestedExecutionIdentity { self.parent }
    pub const fn child(self) -> ExternalAdmissionKey { self.child }
    pub const fn root_reply(self) -> u64 { self.root_reply }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootIngressHandoffReservation {
    table: u64,
    slot: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootIngressHandoffTicket {
    reservation: RootIngressHandoffReservation,
    key: RootIngressHandoffKey,
}

impl RootIngressHandoffTicket {
    pub const fn key(self) -> RootIngressHandoffKey { self.key }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootIngressHandoffError {
    NoCapacity,
    StaleReservation,
}

enum Slot<B> {
    Reserved(u64),
    Held { generation: u64, key: RootIngressHandoffKey, bundle: B },
    Taken { generation: u64, key: RootIngressHandoffKey },
}

/// A ticket selects storage; only the row holds the actual physical parent and snapshot.
pub struct RootIngressHandoffTable<B> {
    table: u64,
    next_generation: u64,
    slots: Vec<Option<Slot<B>>>,
}

impl<B> Default for RootIngressHandoffTable<B> {
    fn default() -> Self { Self::new() }
}

impl<B> RootIngressHandoffTable<B> {
    pub const fn new() -> Self {
        Self { table: 0, next_generation: 1, slots: Vec::new() }
    }

    /// Reserve the row before removing the sole selected bundle from its pending owner.
    pub fn reserve(&mut self) -> Result<RootIngressHandoffReservation, RootIngressHandoffError> {
        let slot = self.slots.iter().position(Option::is_none).unwrap_or(self.slots.len());
        if slot == self.slots.len() {
            self.slots.try_reserve(1).map_err(|_| RootIngressHandoffError::NoCapacity)?;
        }
        let next = self.next_generation.checked_add(1)
            .ok_or(RootIngressHandoffError::NoCapacity)?;
        let table = if self.table == 0 {
            NEXT_TABLE.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| value.checked_add(1))
                .map_err(|_| RootIngressHandoffError::NoCapacity)?
        } else { self.table };
        self.table = table;
        let generation = self.next_generation;
        self.next_generation = next;
        if slot == self.slots.len() { self.slots.push(None); }
        self.slots[slot] = Some(Slot::Reserved(generation));
        Ok(RootIngressHandoffReservation { table, slot, generation })
    }

    pub fn cancel_reservation(&mut self, reservation: RootIngressHandoffReservation) -> bool {
        if self.table != reservation.table
            || !matches!(self.slots.get(reservation.slot), Some(Some(Slot::Reserved(generation)))
                if *generation == reservation.generation)
        { return false; }
        self.slots[reservation.slot] = None;
        true
    }

    /// A failed identity check returns the untouched bundle and leaves the reservation usable.
    pub fn retain(
        &mut self, reservation: RootIngressHandoffReservation,
        key: RootIngressHandoffKey, bundle: B,
    ) -> Result<RootIngressHandoffTicket, (RootIngressHandoffError, B)> {
        if self.table != reservation.table
            || !matches!(self.slots.get(reservation.slot), Some(Some(Slot::Reserved(generation)))
                if *generation == reservation.generation)
        { return Err((RootIngressHandoffError::StaleReservation, bundle)); }
        self.slots[reservation.slot] = Some(Slot::Held {
            generation: reservation.generation, key, bundle,
        });
        Ok(RootIngressHandoffTicket { reservation, key })
    }

    pub fn get(&self, ticket: RootIngressHandoffTicket) -> Option<&B> {
        if ticket.reservation.table != self.table { return None; }
        match self.slots.get(ticket.reservation.slot)?.as_ref()? {
            Slot::Held { generation, key, bundle }
                if *generation == ticket.reservation.generation && *key == ticket.key => Some(bundle),
            _ => None,
        }
    }

    /// Extract once for a checked transfer. A refused transfer must restore the same bundle.
    pub fn take(&mut self, ticket: RootIngressHandoffTicket) -> Option<B> {
        self.get(ticket)?;
        let slot = self.slots[ticket.reservation.slot].take()?;
        let Slot::Held { generation, key, bundle } = slot else { unreachable!("checked held slot changed") };
        self.slots[ticket.reservation.slot] = Some(Slot::Taken { generation, key });
        Some(bundle)
    }

    pub fn restore(&mut self, ticket: RootIngressHandoffTicket, bundle: B) -> Result<(), B> {
        if ticket.reservation.table != self.table
            || !matches!(self.slots.get(ticket.reservation.slot), Some(Some(Slot::Taken { generation, key }))
                if *generation == ticket.reservation.generation && *key == ticket.key)
        { return Err(bundle); }
        self.slots[ticket.reservation.slot] = Some(Slot::Held {
            generation: ticket.reservation.generation, key: ticket.key, bundle,
        });
        Ok(())
    }
}
