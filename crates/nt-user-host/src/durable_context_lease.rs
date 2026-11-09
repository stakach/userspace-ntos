//! Durable context rows with a transient LIFO binding for reentrant native pump slices.
//!
//! A binding is only a selector. The generation-keyed table retains the bundle after an
//! unbind, and retirement is a separate exact-ticket operation for the owning adapter.

use alloc::vec::Vec;
use crate::retained_owner_table::{
    RetainedOwnerError, RetainedOwnerReservation, RetainedOwnerTable, RetainedOwnerTicket,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableContextLeaseError {
    NoCapacity,
    StaleTicket,
    AlreadyBound,
    NotTop,
    StillBound,
    ConflictingRetained,
}

/// The native adapter owns the decision to retire after a genuine terminal acknowledgement.
/// Unbinding a slice never releases its retained bundle.
pub struct DurableContextLeases<K, B> {
    rows: RetainedOwnerTable<K, B>,
    active: Vec<RetainedOwnerTicket<K>>,
}

impl<K: Copy + Eq, B> Default for DurableContextLeases<K, B> {
    fn default() -> Self { Self::new() }
}

impl<K: Copy + Eq, B> DurableContextLeases<K, B> {
    pub const fn new() -> Self {
        Self { rows: RetainedOwnerTable::new(), active: Vec::new() }
    }

    /// Reserve storage before the adapter performs an effect that could require retention.
    pub fn reserve(&mut self) -> Result<RetainedOwnerReservation, DurableContextLeaseError> {
        self.rows.reserve().map_err(|_| DurableContextLeaseError::NoCapacity)
    }

    pub fn cancel_reservation(&mut self, reservation: RetainedOwnerReservation) -> bool {
        self.rows.cancel_reservation(reservation)
    }

    /// Preflight both row and binding-stack capacity for a later native effect. This creates
    /// no held owner or active selector; the caller still reserves an exact row at entry.
    pub fn prepare_one(&mut self) -> Result<(), DurableContextLeaseError> {
        self.rows.prepare_one().map_err(|_| DurableContextLeaseError::NoCapacity)?;
        self.active.try_reserve(1).map_err(|_| DurableContextLeaseError::NoCapacity)
    }

    /// A refusal returns the original bundle to its caller; no owner is dropped.
    pub fn retain(
        &mut self, reservation: RetainedOwnerReservation, key: K, bundle: B,
    ) -> Result<RetainedOwnerTicket<K>, (DurableContextLeaseError, B)> {
        self.rows.retain(reservation, key, bundle).map_err(|(error, bundle)| {
            (match error {
                RetainedOwnerError::NoCapacity => DurableContextLeaseError::NoCapacity,
                RetainedOwnerError::StaleReservation => DurableContextLeaseError::StaleTicket,
            }, bundle)
        })
    }

    /// Admit a row only while no retained owner holds the same physical resource. This
    /// check and insertion share one mutable borrow, so an unbound parent remains exclusive
    /// across nested callback admission. A refusal returns the bundle and leaves the exact
    /// reservation available for cancellation by its caller.
    pub fn retain_exclusive_by(
        &mut self, reservation: RetainedOwnerReservation, key: K, bundle: B,
        matches: impl FnMut(&B) -> bool,
    ) -> Result<RetainedOwnerTicket<K>, (DurableContextLeaseError, B)> {
        if self.rows.any_held(matches) {
            return Err((DurableContextLeaseError::ConflictingRetained, bundle));
        }
        self.retain(reservation, key, bundle)
    }

    pub fn get(&self, ticket: RetainedOwnerTicket<K>) -> Option<&B> {
        self.rows.get(ticket)
    }

    pub fn get_mut(&mut self, ticket: RetainedOwnerTicket<K>) -> Option<&mut B> {
        self.rows.get_mut(ticket)
    }

    /// Read-only physical exclusion includes unbound rows retained across a native yield.
    pub fn any_held(&self, matches: impl FnMut(&B) -> bool) -> bool {
        self.rows.any_held(matches)
    }

    /// Bind an exact retained row for this synchronous slice. The active selector stack has
    /// capacity before it changes, so a refusal leaves both row and previous binding intact.
    pub fn bind(&mut self, ticket: RetainedOwnerTicket<K>) -> Result<(), DurableContextLeaseError> {
        if self.rows.get(ticket).is_none() { return Err(DurableContextLeaseError::StaleTicket); }
        if self.active.contains(&ticket) { return Err(DurableContextLeaseError::AlreadyBound); }
        self.active.try_reserve(1).map_err(|_| DurableContextLeaseError::NoCapacity)?;
        self.active.push(ticket);
        Ok(())
    }

    /// End only the top slice. The retained row remains available for exact rebind.
    pub fn unbind(&mut self, ticket: RetainedOwnerTicket<K>) -> Result<(), DurableContextLeaseError> {
        if self.rows.get(ticket).is_none() { return Err(DurableContextLeaseError::StaleTicket); }
        if self.active.last() != Some(&ticket) { return Err(DurableContextLeaseError::NotTop); }
        self.active.pop();
        Ok(())
    }

    pub fn active_ticket(&self) -> Option<RetainedOwnerTicket<K>> {
        self.active.last().copied()
    }

    pub fn active_len(&self) -> usize { self.active.len() }

    pub fn active(&self) -> Option<&B> {
        self.rows.get(self.active_ticket()?)
    }

    /// Select the nearest matching active context without exposing the binding stack. An
    /// unrelated nested slice does not hide an older context for another instance.
    pub fn find_active(&self, mut matches: impl FnMut(&B) -> bool) -> Option<&B> {
        self.active.iter().rev()
            .filter_map(|ticket| self.rows.get(*ticket))
            .find(|bundle| matches(bundle))
    }

    pub fn active_mut(&mut self) -> Option<&mut B> {
        let ticket = self.active_ticket()?;
        self.rows.get_mut(ticket)
    }

    /// The adapter calls this only after terminal acknowledgement. A still-bound row cannot
    /// retire, and a recycled ticket can never remove another generation's bundle.
    pub fn retire(&mut self, ticket: RetainedOwnerTicket<K>) -> Result<B, DurableContextLeaseError> {
        if self.rows.get(ticket).is_none() { return Err(DurableContextLeaseError::StaleTicket); }
        if self.active.contains(&ticket) { return Err(DurableContextLeaseError::StillBound); }
        let bundle = self.rows.take(ticket).ok_or(DurableContextLeaseError::StaleTicket)?;
        // No other operation can touch `rows` between take and finish under this &mut self.
        self.rows.finish_taken(ticket).expect("exact held row changed during retirement");
        Ok(bundle)
    }
}
