use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_ALLOCATION_CATALOG_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderArenaIdentity {
    pub id: u64,
    pub generation: u64,
}

impl ProviderArenaIdentity {
    pub const fn is_valid(self) -> bool {
        self.id != 0 && self.generation != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderAllocationIdentity {
    pub arena: ProviderArenaIdentity,
    pub allocation_id: u64,
    pub generation: u64,
}

impl ProviderAllocationIdentity {
    pub const fn is_valid(self) -> bool {
        self.arena.is_valid() && self.allocation_id != 0 && self.generation != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderAllocationSnapshot {
    pub identity: ProviderAllocationIdentity,
    pub base: u64,
    pub capacity: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderAllocationPin {
    catalog_id: u64,
    identity: ProviderAllocationIdentity,
    id: u64,
}

impl ProviderAllocationPin {
    pub const fn identity(self) -> ProviderAllocationIdentity {
        self.identity
    }
}

impl ProviderAllocationSnapshot {
    pub fn offset_of(self, address: u64) -> Option<u64> {
        if address < self.base {
            return None;
        }
        let offset = address - self.base;
        (offset < self.capacity).then_some(offset)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderAllocationError {
    InvalidArena,
    InvalidRange,
    AddressInUse,
    AmbiguousOwner,
    IdentityExhausted,
    NoCapacity,
    NotFound,
    StaleIdentity,
    ContainsLiveAllocations,
    Pinned,
    StalePin,
    Retiring,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProviderAllocationPinRecord {
    identity: ProviderAllocationIdentity,
    id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProviderAllocationRecord {
    arena: ProviderArenaIdentity,
    generation: u64,
    live: bool,
    retiring: bool,
    base: u64,
    capacity: u64,
}

impl ProviderAllocationRecord {
    const EMPTY: Self = Self {
        arena: ProviderArenaIdentity {
            id: 0,
            generation: 0,
        },
        generation: 0,
        live: false,
        retiring: false,
        base: 0,
        capacity: 0,
    };

    fn snapshot(self, slot: usize) -> Result<ProviderAllocationSnapshot, ProviderAllocationError> {
        let allocation_id = u64::try_from(slot)
            .ok()
            .and_then(|slot| slot.checked_add(1))
            .ok_or(ProviderAllocationError::IdentityExhausted)?;
        Ok(ProviderAllocationSnapshot {
            identity: ProviderAllocationIdentity {
                arena: self.arena,
                allocation_id,
                generation: self.generation,
            },
            base: self.base,
            capacity: self.capacity,
        })
    }

    fn end(self) -> u64 {
        self.base + self.capacity
    }
}

/// Component-private identities for reclaimable provider allocations.
///
/// Arenas may be nested: a desktop heap is backed by an allocation in the session heap and owns
/// allocations of its own. Overlap is therefore rejected within an arena but permitted across
/// arenas. Containment resolves to the smallest live allocation so embedded-object ownership
/// follows the innermost heap allocation.
pub struct ProviderAllocationCatalog {
    catalog_id: u64,
    records: Vec<ProviderAllocationRecord>,
    pins: Vec<ProviderAllocationPinRecord>,
    next_pin_id: u64,
}

impl ProviderAllocationCatalog {
    pub const fn new() -> Self {
        Self {
            catalog_id: 0,
            records: Vec::new(),
            pins: Vec::new(),
            next_pin_id: 1,
        }
    }

    pub fn register(
        &mut self,
        arena: ProviderArenaIdentity,
        base: u64,
        capacity: u64,
    ) -> Result<ProviderAllocationSnapshot, ProviderAllocationError> {
        if !arena.is_valid() {
            return Err(ProviderAllocationError::InvalidArena);
        }
        let end = base
            .checked_add(capacity)
            .filter(|_| base != 0 && capacity != 0)
            .ok_or(ProviderAllocationError::InvalidRange)?;
        if self.records.iter().any(|record| {
            if !record.live || base >= record.end() || record.base >= end {
                return false;
            }
            if record.retiring || record.arena == arena {
                return true;
            }
            let new_contains_existing = base < record.base && end >= record.end();
            let existing_contains_new = record.base < base && record.end() >= end;
            !new_contains_existing && !existing_contains_new
        }) {
            return Err(ProviderAllocationError::AddressInUse);
        }

        let slot = if let Some(slot) = self
            .records
            .iter()
            .position(|record| !record.live && record.arena == arena && record.base == base)
        {
            slot
        } else if let Some(slot) = self.records.iter().position(|record| !record.live) {
            slot
        } else {
            self.records
                .try_reserve(1)
                .map_err(|_| ProviderAllocationError::NoCapacity)?;
            self.records.push(ProviderAllocationRecord::EMPTY);
            self.records.len() - 1
        };
        let generation = self.records[slot]
            .generation
            .checked_add(1)
            .ok_or(ProviderAllocationError::IdentityExhausted)?;
        self.records[slot] = ProviderAllocationRecord {
            arena,
            generation,
            live: true,
            retiring: false,
            base,
            capacity,
        };
        self.records[slot].snapshot(slot)
    }

    pub fn snapshot(
        &self,
        identity: ProviderAllocationIdentity,
    ) -> Result<ProviderAllocationSnapshot, ProviderAllocationError> {
        let slot = self.slot(identity)?;
        self.records[slot].snapshot(slot)
    }

    pub fn exact(
        &self,
        arena: ProviderArenaIdentity,
        base: u64,
    ) -> Result<ProviderAllocationSnapshot, ProviderAllocationError> {
        let (slot, record) = self
            .records
            .iter()
            .enumerate()
            .find(|(_, record)| record.live && record.arena == arena && record.base == base)
            .ok_or(ProviderAllocationError::NotFound)?;
        record.snapshot(slot)
    }

    pub fn containing(
        &self,
        address: u64,
        required: u64,
    ) -> Result<ProviderAllocationSnapshot, ProviderAllocationError> {
        let end = address
            .checked_add(required)
            .filter(|_| address != 0 && required != 0)
            .ok_or(ProviderAllocationError::InvalidRange)?;
        let mut owner: Option<(usize, ProviderAllocationRecord)> = None;
        for (slot, record) in self.records.iter().copied().enumerate() {
            if !record.live || address < record.base || address >= record.end() {
                continue;
            }
            match owner {
                None => owner = Some((slot, record)),
                Some((_, current)) if record.capacity < current.capacity => {
                    owner = Some((slot, record));
                }
                Some((_, current)) if record.capacity == current.capacity => {
                    return Err(ProviderAllocationError::AmbiguousOwner);
                }
                Some(_) => {}
            }
        }
        let (slot, record) = owner.ok_or(ProviderAllocationError::NotFound)?;
        if end > record.end() {
            return Err(ProviderAllocationError::InvalidRange);
        }
        record.snapshot(slot)
    }

    pub fn pin_containing(
        &mut self,
        address: u64,
        required: u64,
    ) -> Result<(ProviderAllocationSnapshot, ProviderAllocationPin), ProviderAllocationError> {
        let snapshot = self.containing(address, required)?;
        if self.records[self.slot(snapshot.identity)?].retiring {
            return Err(ProviderAllocationError::Retiring);
        }
        let id = self.next_pin_id;
        let next = id
            .checked_add(1)
            .ok_or(ProviderAllocationError::IdentityExhausted)?;
        self.pins
            .try_reserve(1)
            .map_err(|_| ProviderAllocationError::NoCapacity)?;
        if self.catalog_id == 0 {
            self.catalog_id = loop {
                let id = NEXT_ALLOCATION_CATALOG_ID.load(Ordering::Relaxed);
                let next = id
                    .checked_add(1)
                    .ok_or(ProviderAllocationError::IdentityExhausted)?;
                if NEXT_ALLOCATION_CATALOG_ID
                    .compare_exchange_weak(id, next, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break id;
                }
            };
        }
        self.pins.push(ProviderAllocationPinRecord {
            identity: snapshot.identity,
            id,
        });
        self.next_pin_id = next;
        Ok((
            snapshot,
            ProviderAllocationPin {
                catalog_id: self.catalog_id,
                identity: snapshot.identity,
                id,
            },
        ))
    }

    pub fn release_pin(
        &mut self,
        pin: ProviderAllocationPin,
    ) -> Result<(), ProviderAllocationError> {
        if pin.catalog_id != self.catalog_id || self.catalog_id == 0 {
            return Err(ProviderAllocationError::StalePin);
        }
        let index = self
            .pins
            .iter()
            .position(|record| record.id == pin.id && record.identity == pin.identity)
            .ok_or(ProviderAllocationError::StalePin)?;
        self.pins.swap_remove(index);
        Ok(())
    }

    pub fn retire(
        &mut self,
        identity: ProviderAllocationIdentity,
    ) -> Result<ProviderAllocationSnapshot, ProviderAllocationError> {
        let snapshot = self.validate_retirement(identity)?;
        let slot = self.slot(identity)?;
        self.records[slot].live = false;
        Ok(snapshot)
    }

    /// Reserve this exact allocation for a native teardown that may cross a
    /// reentrant IPC boundary. A failed or uncertain teardown stays reserved.
    pub fn begin_retirement(
        &mut self,
        identity: ProviderAllocationIdentity,
    ) -> Result<ProviderAllocationSnapshot, ProviderAllocationError> {
        let slot = self.slot(identity)?;
        if self.records[slot].retiring {
            return Err(ProviderAllocationError::Retiring);
        }
        let snapshot = self.validate_retirement(identity)?;
        self.records[slot].retiring = true;
        Ok(snapshot)
    }

    pub fn validate_retirement(
        &self,
        identity: ProviderAllocationIdentity,
    ) -> Result<ProviderAllocationSnapshot, ProviderAllocationError> {
        let slot = self.slot(identity)?;
        let retiring = self.records[slot];
        if self.pins.iter().any(|pin| pin.identity == identity) {
            return Err(ProviderAllocationError::Pinned);
        }
        if self.records.iter().enumerate().any(|(index, record)| {
            index != slot
                && record.live
                && record.base >= retiring.base
                && record.end() <= retiring.end()
        }) {
            return Err(ProviderAllocationError::ContainsLiveAllocations);
        }
        retiring.snapshot(slot)
    }

    fn slot(&self, identity: ProviderAllocationIdentity) -> Result<usize, ProviderAllocationError> {
        if !identity.is_valid() {
            return Err(ProviderAllocationError::StaleIdentity);
        }
        let slot = usize::try_from(identity.allocation_id - 1)
            .map_err(|_| ProviderAllocationError::StaleIdentity)?;
        self.records
            .get(slot)
            .filter(|record| {
                record.live
                    && record.arena == identity.arena
                    && record.generation == identity.generation
            })
            .map(|_| slot)
            .ok_or(ProviderAllocationError::StaleIdentity)
    }
}

impl Default for ProviderAllocationCatalog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arena(id: u64) -> ProviderArenaIdentity {
        ProviderArenaIdentity { id, generation: 1 }
    }

    #[test]
    fn address_reuse_advances_generation_and_rejects_stale_identity() {
        let mut catalog = ProviderAllocationCatalog::new();
        let first = catalog.register(arena(1), 0x1000, 0x100).unwrap();
        catalog.retire(first.identity).unwrap();
        let second = catalog.register(arena(1), 0x1000, 0x80).unwrap();
        assert_eq!(second.identity.allocation_id, first.identity.allocation_id);
        assert!(second.identity.generation > first.identity.generation);
        assert_eq!(
            catalog.snapshot(first.identity),
            Err(ProviderAllocationError::StaleIdentity)
        );
        assert_eq!(
            catalog.retire(first.identity),
            Err(ProviderAllocationError::StaleIdentity)
        );
        let wrong_arena = ProviderAllocationIdentity {
            arena: arena(2),
            ..second.identity
        };
        assert_eq!(
            catalog.retire(wrong_arena),
            Err(ProviderAllocationError::StaleIdentity)
        );
        assert_eq!(catalog.snapshot(second.identity).unwrap(), second);
        assert_eq!(catalog.exact(arena(1), 0x1000).unwrap(), second);
    }

    #[test]
    fn innermost_nested_arena_owns_contained_storage() {
        let mut catalog = ProviderAllocationCatalog::new();
        let outer = catalog.register(arena(1), 0x1000, 0x2000).unwrap();
        let inner = catalog.register(arena(2), 0x1800, 0x400).unwrap();
        assert_eq!(catalog.containing(0x1900, 0x18).unwrap(), inner);
        assert_eq!(catalog.containing(0x1400, 0x18).unwrap(), outer);
    }

    #[test]
    fn containment_is_end_exclusive_and_overflow_checked() {
        let mut catalog = ProviderAllocationCatalog::new();
        let allocation = catalog.register(arena(1), 0x2000, 0x100).unwrap();
        assert_eq!(catalog.containing(0x20e8, 0x18).unwrap(), allocation);
        assert_eq!(
            catalog.containing(0x20e9, 0x18),
            Err(ProviderAllocationError::InvalidRange)
        );
        assert_eq!(
            catalog.containing(u64::MAX - 7, 8),
            Err(ProviderAllocationError::InvalidRange)
        );
    }

    #[test]
    fn a_range_crossing_the_innermost_boundary_does_not_fall_back_to_its_parent() {
        let mut catalog = ProviderAllocationCatalog::new();
        catalog.register(arena(1), 0x1000, 0x2000).unwrap();
        catalog.register(arena(2), 0x1800, 0x400).unwrap();
        assert_eq!(
            catalog.containing(0x1bf8, 0x10),
            Err(ProviderAllocationError::InvalidRange)
        );
    }

    #[test]
    fn same_arena_overlap_and_non_hierarchical_cross_arena_overlap_fail_closed() {
        let mut catalog = ProviderAllocationCatalog::new();
        catalog.register(arena(1), 0x3000, 0x200).unwrap();
        assert_eq!(
            catalog.register(arena(1), 0x3100, 0x200),
            Err(ProviderAllocationError::AddressInUse)
        );
        assert_eq!(
            catalog.register(arena(2), 0x3000, 0x200),
            Err(ProviderAllocationError::AddressInUse)
        );
        assert_eq!(
            catalog.register(arena(2), 0x2f80, 0x100),
            Err(ProviderAllocationError::AddressInUse)
        );
    }

    #[test]
    fn outer_retirement_waits_for_nested_allocations() {
        let mut catalog = ProviderAllocationCatalog::new();
        let outer = catalog.register(arena(1), 0x4000, 0x1000).unwrap();
        let inner = catalog.register(arena(2), 0x4800, 0x100).unwrap();
        assert_eq!(
            catalog.retire(outer.identity),
            Err(ProviderAllocationError::ContainsLiveAllocations)
        );
        catalog.retire(inner.identity).unwrap();
        catalog.retire(outer.identity).unwrap();
    }

    #[test]
    fn moved_reallocation_has_a_distinct_identity() {
        let mut catalog = ProviderAllocationCatalog::new();
        let old = catalog.register(arena(1), 0x5000, 0x80).unwrap();
        let moved = catalog.register(arena(1), 0x6000, 0x100).unwrap();
        catalog.retire(old.identity).unwrap();
        assert_ne!(old.identity, moved.identity);
        assert_eq!(catalog.exact(arena(1), 0x6000).unwrap(), moved);
    }

    #[test]
    fn pins_hold_exact_allocations_until_each_receipt_is_released() {
        let mut catalog = ProviderAllocationCatalog::new();
        let allocation = catalog.register(arena(1), 0x7000, 0x100).unwrap();
        let (snapshot, first) = catalog.pin_containing(0x7010, 0x10).unwrap();
        let (_, second) = catalog.pin_containing(0x7020, 0x10).unwrap();
        assert_eq!(snapshot, allocation);
        assert_ne!(first, second);
        assert_eq!(
            catalog.validate_retirement(allocation.identity),
            Err(ProviderAllocationError::Pinned)
        );
        catalog.release_pin(first).unwrap();
        assert_eq!(
            catalog.release_pin(first),
            Err(ProviderAllocationError::StalePin)
        );
        assert_eq!(
            catalog.retire(allocation.identity),
            Err(ProviderAllocationError::Pinned)
        );
        catalog.release_pin(second).unwrap();
        catalog.retire(allocation.identity).unwrap();
        let reused = catalog.register(arena(1), 0x7000, 0x100).unwrap();
        assert_ne!(reused.identity, allocation.identity);
        assert_eq!(
            catalog.release_pin(second),
            Err(ProviderAllocationError::StalePin)
        );
        catalog.retire(reused.identity).unwrap();
    }

    #[test]
    fn pin_range_requires_the_innermost_owner_and_keeps_parent_live() {
        let mut catalog = ProviderAllocationCatalog::new();
        let outer = catalog.register(arena(1), 0x8000, 0x1000).unwrap();
        let inner = catalog.register(arena(2), 0x8800, 0x100).unwrap();
        assert_eq!(
            catalog.pin_containing(0x88f8, 0x10),
            Err(ProviderAllocationError::InvalidRange)
        );
        let (snapshot, pin) = catalog.pin_containing(0x8810, 0x20).unwrap();
        assert_eq!(snapshot, inner);
        assert_eq!(
            catalog.retire(outer.identity),
            Err(ProviderAllocationError::ContainsLiveAllocations)
        );
        assert_eq!(
            catalog.retire(inner.identity),
            Err(ProviderAllocationError::Pinned)
        );
        catalog.release_pin(pin).unwrap();
        catalog.retire(inner.identity).unwrap();
        catalog.retire(outer.identity).unwrap();
    }

    #[test]
    fn colliding_catalogs_cannot_release_each_others_pin() {
        let mut first = ProviderAllocationCatalog::new();
        let mut second = ProviderAllocationCatalog::new();
        let a = first.register(arena(1), 0x9000, 0x100).unwrap();
        let b = second.register(arena(1), 0x9000, 0x100).unwrap();
        assert_eq!(a.identity, b.identity);
        let (_, first_pin) = first.pin_containing(0x9010, 0x10).unwrap();
        let (_, second_pin) = second.pin_containing(0x9010, 0x10).unwrap();
        assert_eq!(
            first.release_pin(second_pin),
            Err(ProviderAllocationError::StalePin)
        );
        assert_eq!(
            second.release_pin(first_pin),
            Err(ProviderAllocationError::StalePin)
        );
        assert_eq!(
            first.retire(a.identity),
            Err(ProviderAllocationError::Pinned)
        );
        assert_eq!(
            second.retire(b.identity),
            Err(ProviderAllocationError::Pinned)
        );
        first.release_pin(first_pin).unwrap();
        second.release_pin(second_pin).unwrap();
    }

    #[test]
    fn retirement_reservation_blocks_new_pins_and_nested_reuse_until_commit() {
        let mut catalog = ProviderAllocationCatalog::new();
        let allocation = catalog.register(arena(1), 0xa000, 0x1000).unwrap();
        let (_, pin) = catalog.pin_containing(0xa100, 0x10).unwrap();
        assert_eq!(
            catalog.begin_retirement(allocation.identity),
            Err(ProviderAllocationError::Pinned)
        );
        catalog.release_pin(pin).unwrap();
        assert_eq!(
            catalog.begin_retirement(allocation.identity),
            Ok(allocation)
        );
        assert_eq!(
            catalog.begin_retirement(allocation.identity),
            Err(ProviderAllocationError::Retiring)
        );
        assert_eq!(
            catalog.pin_containing(0xa100, 0x10),
            Err(ProviderAllocationError::Retiring)
        );
        assert_eq!(
            catalog.register(arena(2), 0xa200, 0x100),
            Err(ProviderAllocationError::AddressInUse)
        );
        assert_eq!(
            catalog.register(arena(1), 0xa000, 0x1000),
            Err(ProviderAllocationError::AddressInUse)
        );
        assert_eq!(catalog.snapshot(allocation.identity), Ok(allocation));
        catalog.retire(allocation.identity).unwrap();
        let reused = catalog.register(arena(1), 0xa000, 0x1000).unwrap();
        assert_ne!(reused.identity, allocation.identity);
        assert_eq!(catalog.pin_containing(0xa100, 0x10).unwrap().0, reused);
    }
}
