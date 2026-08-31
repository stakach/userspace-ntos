//! Generation-owned PnP publication contexts.
//!
//! A context description is ordinary clonable data. Its owner is deliberately
//! opaque to this crate and is returned exactly once, after the context has
//! been replaced and its last exact lease has drained.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::num::NonZeroU64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextId(NonZeroU64);

impl ContextId {
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextLeaseIdentity {
    context: ContextId,
    token: NonZeroU64,
}

impl ContextLeaseIdentity {
    pub const fn context(self) -> ContextId {
        self.context
    }

    pub const fn token(self) -> u64 {
        self.token.get()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ContextLease(ContextLeaseIdentity);

impl ContextLease {
    pub const fn context(&self) -> ContextId {
        self.0.context
    }

    pub const fn identity(&self) -> ContextLeaseIdentity {
        self.0
    }

    pub const fn into_identity(self) -> ContextLeaseIdentity {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcquireError {
    NoActiveContext,
    IdExhausted,
    InsufficientResources,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseError {
    UnknownContext,
    UnknownLease,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotError {
    InvalidRange,
    InsufficientResources,
    UnknownReservation,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SlotReservation {
    first: u64,
    count: NonZeroU64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SlotReleaseError {
    error: SlotError,
    reservation: SlotReservation,
}

impl SlotReleaseError {
    pub const fn error(&self) -> SlotError {
        self.error
    }

    pub fn into_reservation(self) -> SlotReservation {
        self.reservation
    }
}

impl SlotReservation {
    pub const fn first(&self) -> u64 {
        self.first
    }

    pub const fn count(&self) -> u64 {
        self.count.get()
    }
}

pub struct SlotAllocator {
    occupied: Vec<bool>,
    limit: u64,
}

/// A byte-addressed arena backed by [`SlotAllocator`].
///
/// Callers lease address spans rather than combining a slot index with a separately maintained
/// base constant. This keeps the arena bounds, granularity, and ownership record in one authority.
pub struct AddressSlotAllocator {
    base: u64,
    limit: u64,
    stride: u64,
    slots: SlotAllocator,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AddressSlotReservation {
    address: u64,
    bytes: u64,
    slots: SlotReservation,
}

impl AddressSlotReservation {
    pub const fn address(&self) -> u64 {
        self.address
    }

    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AddressSlotReleaseError {
    error: SlotError,
    reservation: AddressSlotReservation,
}

impl AddressSlotReleaseError {
    pub const fn error(&self) -> SlotError {
        self.error
    }

    pub fn into_reservation(self) -> AddressSlotReservation {
        self.reservation
    }
}

impl AddressSlotAllocator {
    pub const fn new(base: u64, limit: u64, stride: u64) -> Self {
        assert!(stride != 0 && stride.is_power_of_two());
        assert!(base < limit);
        let slots = (limit - base) / stride;
        assert!(slots != 0);
        Self {
            base,
            limit,
            stride,
            slots: SlotAllocator::new(slots),
        }
    }

    pub fn allocate(&mut self, bytes: u64) -> Result<AddressSlotReservation, SlotError> {
        if bytes == 0 {
            return Err(SlotError::InvalidRange);
        }
        let rounded = bytes
            .checked_add(self.stride - 1)
            .ok_or(SlotError::InvalidRange)?
            & !(self.stride - 1);
        let slots = self.slots.allocate(rounded / self.stride)?;
        let address = slots
            .first()
            .checked_mul(self.stride)
            .and_then(|offset| self.base.checked_add(offset))
            .filter(|address| {
                address
                    .checked_add(rounded)
                    .is_some_and(|end| end <= self.limit)
            });
        let Some(address) = address else {
            let _ = self.slots.release(slots);
            return Err(SlotError::InvalidRange);
        };
        Ok(AddressSlotReservation {
            address,
            bytes: rounded,
            slots,
        })
    }

    pub fn release(
        &mut self,
        reservation: AddressSlotReservation,
    ) -> Result<(), AddressSlotReleaseError> {
        let expected = reservation
            .slots
            .first()
            .checked_mul(self.stride)
            .and_then(|offset| self.base.checked_add(offset));
        if expected != Some(reservation.address)
            || reservation.bytes != reservation.slots.count().saturating_mul(self.stride)
        {
            return Err(AddressSlotReleaseError {
                error: SlotError::UnknownReservation,
                reservation,
            });
        }
        self.slots
            .release(reservation.slots)
            .map_err(|error| AddressSlotReleaseError {
                error: error.error(),
                reservation: AddressSlotReservation {
                    address: reservation.address,
                    bytes: reservation.bytes,
                    slots: error.into_reservation(),
                },
            })
    }

    pub fn occupied_slots(&self) -> usize {
        self.slots.occupied_slots()
    }
}

impl SlotAllocator {
    pub const fn new(limit: u64) -> Self {
        Self {
            occupied: Vec::new(),
            limit,
        }
    }

    pub fn allocate(&mut self, count: u64) -> Result<SlotReservation, SlotError> {
        let count = NonZeroU64::new(count).ok_or(SlotError::InvalidRange)?;
        if count.get() > self.limit || count.get() > usize::MAX as u64 {
            return Err(SlotError::InvalidRange);
        }
        let count_usize = count.get() as usize;
        let mut first = 0usize;
        while first
            .checked_add(count_usize)
            .is_some_and(|end| end <= self.occupied.len())
        {
            if self.occupied[first..first + count_usize]
                .iter()
                .all(|occupied| !occupied)
            {
                self.occupied[first..first + count_usize].fill(true);
                return Ok(SlotReservation {
                    first: first as u64,
                    count,
                });
            }
            first += 1;
        }

        let first = self.occupied.len() as u64;
        let end = first
            .checked_add(count.get())
            .ok_or(SlotError::InvalidRange)?;
        if end > self.limit {
            return Err(SlotError::InsufficientResources);
        }
        self.occupied
            .try_reserve(count_usize)
            .map_err(|_| SlotError::InsufficientResources)?;
        self.occupied.resize(end as usize, true);
        Ok(SlotReservation { first, count })
    }

    pub fn release(&mut self, reservation: SlotReservation) -> Result<(), SlotReleaseError> {
        let invalid = |reservation| SlotReleaseError {
            error: SlotError::UnknownReservation,
            reservation,
        };
        let Ok(first) = usize::try_from(reservation.first) else {
            return Err(invalid(reservation));
        };
        let Ok(count) = usize::try_from(reservation.count.get()) else {
            return Err(invalid(reservation));
        };
        let Some(end) = first.checked_add(count) else {
            return Err(invalid(reservation));
        };
        if end > self.occupied.len() || !self.occupied[first..end].iter().all(|occupied| *occupied)
        {
            return Err(invalid(reservation));
        }
        self.occupied[first..end].fill(false);
        while self.occupied.last() == Some(&false) {
            self.occupied.pop();
        }
        Ok(())
    }

    pub fn occupied_slots(&self) -> usize {
        self.occupied.iter().filter(|occupied| **occupied).count()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PublishError<T> {
    IdExhausted(T),
    InsufficientResources(T),
}

impl<T> PublishError<T> {
    pub fn into_inner(self) -> T {
        match self {
            Self::IdExhausted(value) | Self::InsufficientResources(value) => value,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PublishOutcome<O> {
    pub context: ContextId,
    pub retired_owner: Option<O>,
}

struct ContextRecord<D, O> {
    id: ContextId,
    description: D,
    owner: O,
    leases: Vec<NonZeroU64>,
}

impl<D, O> ContextRecord<D, O> {
    fn contains(&self, lease: ContextLeaseIdentity) -> bool {
        self.id == lease.context && self.leases.contains(&lease.token)
    }
}

pub struct ContextRegistry<D, O> {
    active: Option<ContextRecord<D, O>>,
    retired: Vec<ContextRecord<D, O>>,
    next_context_id: u64,
    next_lease_token: u64,
}

impl<D, O> Default for ContextRegistry<D, O> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D, O> ContextRegistry<D, O> {
    pub const fn new() -> Self {
        Self {
            active: None,
            retired: Vec::new(),
            next_context_id: 1,
            next_lease_token: 1,
        }
    }

    pub fn active_id(&self) -> Option<ContextId> {
        self.active.as_ref().map(|record| record.id)
    }

    pub fn active_description(&self) -> Option<&D> {
        self.active.as_ref().map(|record| &record.description)
    }

    pub fn retired_contexts(&self) -> usize {
        self.retired.len()
    }

    pub fn publish(
        &mut self,
        description: D,
        owner: O,
    ) -> Result<PublishOutcome<O>, PublishError<(D, O)>> {
        let Some(raw_id) = NonZeroU64::new(self.next_context_id) else {
            return Err(PublishError::IdExhausted((description, owner)));
        };
        let Some(next_id) = self.next_context_id.checked_add(1) else {
            return Err(PublishError::IdExhausted((description, owner)));
        };
        let old_has_leases = self
            .active
            .as_ref()
            .is_some_and(|record| !record.leases.is_empty());
        if old_has_leases && self.retired.try_reserve(1).is_err() {
            return Err(PublishError::InsufficientResources((description, owner)));
        }

        let id = ContextId(raw_id);
        let replacement = ContextRecord {
            id,
            description,
            owner,
            leases: Vec::new(),
        };
        let old = self.active.replace(replacement);
        self.next_context_id = next_id;
        let retired_owner = match old {
            Some(record) if record.leases.is_empty() => Some(record.owner),
            Some(record) => {
                self.retired.push(record);
                None
            }
            None => None,
        };
        Ok(PublishOutcome {
            context: id,
            retired_owner,
        })
    }

    pub fn acquire_active(&mut self) -> Result<ContextLease, AcquireError> {
        let Some(token) = NonZeroU64::new(self.next_lease_token) else {
            return Err(AcquireError::IdExhausted);
        };
        let Some(next_token) = self.next_lease_token.checked_add(1) else {
            return Err(AcquireError::IdExhausted);
        };
        let active = self.active.as_mut().ok_or(AcquireError::NoActiveContext)?;
        active
            .leases
            .try_reserve(1)
            .map_err(|_| AcquireError::InsufficientResources)?;
        active.leases.push(token);
        self.next_lease_token = next_token;
        Ok(ContextLease(ContextLeaseIdentity {
            context: active.id,
            token,
        }))
    }

    pub fn description(&self, lease: &ContextLease) -> Result<&D, LeaseError> {
        self.description_by_identity(lease.identity())
    }

    pub fn description_by_identity(&self, lease: ContextLeaseIdentity) -> Result<&D, LeaseError> {
        let record = self
            .record(lease.context)
            .ok_or(LeaseError::UnknownContext)?;
        record
            .contains(lease)
            .then_some(&record.description)
            .ok_or(LeaseError::UnknownLease)
    }

    pub fn release(&mut self, lease: ContextLeaseIdentity) -> Result<Option<O>, LeaseError> {
        if let Some(active) = self.active.as_mut() {
            if active.id == lease.context {
                remove_lease(active, lease)?;
                return Ok(None);
            }
        }
        let Some(index) = self
            .retired
            .iter()
            .position(|record| record.id == lease.context)
        else {
            return Err(LeaseError::UnknownContext);
        };
        remove_lease(&mut self.retired[index], lease)?;
        if self.retired[index].leases.is_empty() {
            return Ok(Some(self.retired.remove(index).owner));
        }
        Ok(None)
    }

    fn record(&self, id: ContextId) -> Option<&ContextRecord<D, O>> {
        self.active
            .as_ref()
            .filter(|record| record.id == id)
            .or_else(|| self.retired.iter().find(|record| record.id == id))
    }
}

fn remove_lease<D, O>(
    record: &mut ContextRecord<D, O>,
    lease: ContextLeaseIdentity,
) -> Result<(), LeaseError> {
    let Some(index) = record.leases.iter().position(|token| *token == lease.token) else {
        return Err(LeaseError::UnknownLease);
    };
    record.leases.remove(index);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_without_leases_returns_old_owner_immediately() {
        let mut registry = ContextRegistry::new();
        let first = registry.publish("first", 10).unwrap();
        assert_eq!(first.retired_owner, None);

        let second = registry.publish("second", 20).unwrap();
        assert_eq!(second.retired_owner, Some(10));
        assert_eq!(registry.active_description(), Some(&"second"));
        assert_eq!(registry.retired_contexts(), 0);
    }

    #[test]
    fn replacement_waits_for_last_exact_lease() {
        let mut registry = ContextRegistry::new();
        let first = registry.publish("first", 10).unwrap();
        let lease_a = registry.acquire_active().unwrap().into_identity();
        let lease_b = registry.acquire_active().unwrap().into_identity();

        let second = registry.publish("second", 20).unwrap();
        assert_ne!(first.context, second.context);
        assert_eq!(second.retired_owner, None);
        assert_eq!(registry.retired_contexts(), 1);
        assert_eq!(registry.release(lease_a), Ok(None));
        assert_eq!(registry.release(lease_b), Ok(Some(10)));
        assert_eq!(registry.retired_contexts(), 0);
    }

    #[test]
    fn stale_or_duplicate_release_cannot_touch_replacement() {
        let mut registry = ContextRegistry::new();
        registry.publish("first", 10).unwrap();
        let stale = registry.acquire_active().unwrap().into_identity();
        registry.publish("second", 20).unwrap();
        let live = registry.acquire_active().unwrap().into_identity();

        assert_eq!(registry.release(stale), Ok(Some(10)));
        assert_eq!(registry.release(stale), Err(LeaseError::UnknownContext));
        assert_eq!(registry.active_description(), Some(&"second"));
        assert_eq!(registry.description_by_identity(live), Ok(&"second"));
        assert_eq!(registry.release(live), Ok(None));
    }

    #[test]
    fn leased_retired_description_remains_available() {
        let mut registry = ContextRegistry::new();
        registry.publish("first", 10).unwrap();
        let lease = registry.acquire_active().unwrap();
        registry.publish("second", 20).unwrap();

        assert_eq!(registry.description(&lease), Ok(&"first"));
        assert_eq!(registry.release(lease.into_identity()), Ok(Some(10)));
    }

    #[test]
    fn no_active_context_is_reported() {
        let mut registry: ContextRegistry<(), ()> = ContextRegistry::new();
        assert_eq!(
            registry.acquire_active(),
            Err(AcquireError::NoActiveContext)
        );
    }

    #[test]
    fn failed_publication_preserves_active_context_and_candidate_owner() {
        let mut registry = ContextRegistry::new();
        let first = registry.publish("first", 10).unwrap();
        registry.next_context_id = u64::MAX;

        let error = registry.publish("candidate", 20).unwrap_err();
        assert_eq!(error.into_inner(), ("candidate", 20));
        assert_eq!(registry.active_id(), Some(first.context));
        assert_eq!(registry.active_description(), Some(&"first"));
        assert_eq!(registry.retired_contexts(), 0);
    }

    #[test]
    fn ownership_is_returned_once_after_out_of_order_retirement() {
        let mut registry = ContextRegistry::new();
        registry.publish(1, "owner-1").unwrap();
        let lease_1 = registry.acquire_active().unwrap().into_identity();
        registry.publish(2, "owner-2").unwrap();
        let lease_2 = registry.acquire_active().unwrap().into_identity();
        registry.publish(3, "owner-3").unwrap();

        assert_eq!(registry.retired_contexts(), 2);
        assert_eq!(registry.release(lease_2), Ok(Some("owner-2")));
        assert_eq!(registry.release(lease_1), Ok(Some("owner-1")));
        assert_eq!(registry.retired_contexts(), 0);
        assert_eq!(registry.active_description(), Some(&3));
    }

    #[test]
    fn slots_are_not_reused_until_exact_reservation_release() {
        let mut allocator = SlotAllocator::new(4);
        let first = allocator.allocate(2).unwrap();
        let second = allocator.allocate(2).unwrap();
        assert_eq!(first.first(), 0);
        assert_eq!(second.first(), 2);
        assert_eq!(allocator.allocate(1), Err(SlotError::InsufficientResources));

        allocator.release(first).unwrap();
        let replacement = allocator.allocate(2).unwrap();
        assert_eq!(replacement.first(), 0);
        assert_eq!(allocator.occupied_slots(), 4);
    }

    #[test]
    fn invalid_slot_release_preserves_other_reservations() {
        let mut allocator = SlotAllocator::new(4);
        let first = allocator.allocate(1).unwrap();
        let duplicate = SlotReservation {
            first: first.first(),
            count: NonZeroU64::new(first.count()).unwrap(),
        };
        let second = allocator.allocate(1).unwrap();
        allocator.release(first).unwrap();
        let error = allocator.release(duplicate).unwrap_err();
        assert_eq!(error.error(), SlotError::UnknownReservation);
        let duplicate = error.into_reservation();
        assert_eq!(duplicate.first(), 0);
        assert_eq!(duplicate.count(), 1);
        assert_eq!(allocator.occupied_slots(), 1);
        assert_eq!(second.first(), 1);
        assert_eq!(allocator.allocate(1).unwrap().first(), 0);
    }

    #[test]
    fn address_slots_keep_bounds_and_ownership_together() {
        let mut allocator = AddressSlotAllocator::new(0x4000_0000, 0x4080_0000, 0x20_0000);
        let first = allocator.allocate(0x1000).unwrap();
        let second = allocator.allocate(0x20_0001).unwrap();
        assert_eq!((first.address(), first.bytes()), (0x4000_0000, 0x20_0000));
        assert_eq!((second.address(), second.bytes()), (0x4020_0000, 0x40_0000));
        assert_eq!(allocator.occupied_slots(), 3);
        allocator.release(first).unwrap();
        let replacement = allocator.allocate(0x20_0000).unwrap();
        assert_eq!(replacement.address(), 0x4000_0000);
    }

    #[test]
    fn address_slots_fail_closed_at_arena_limit() {
        let mut allocator = AddressSlotAllocator::new(0x8000_0000, 0x8040_0000, 0x20_0000);
        assert_eq!(allocator.allocate(0), Err(SlotError::InvalidRange));
        let reservation = allocator.allocate(0x40_0000).unwrap();
        assert_eq!(allocator.allocate(1), Err(SlotError::InsufficientResources));
        allocator.release(reservation).unwrap();
        assert_eq!(allocator.occupied_slots(), 0);
    }
}
