use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderAllocationIdentity {
    pub arena_id: u64,
    pub allocation_id: u64,
    pub generation: u64,
}

impl ProviderAllocationIdentity {
    pub const fn is_valid(self) -> bool {
        self.arena_id != 0 && self.allocation_id != 0 && self.generation != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderAllocationSnapshot {
    pub identity: ProviderAllocationIdentity,
    pub base: u64,
    pub capacity: u64,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProviderAllocationRecord {
    arena_id: u64,
    generation: u64,
    live: bool,
    base: u64,
    capacity: u64,
}

impl ProviderAllocationRecord {
    const EMPTY: Self = Self {
        arena_id: 0,
        generation: 0,
        live: false,
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
                arena_id: self.arena_id,
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
    records: Vec<ProviderAllocationRecord>,
}

impl ProviderAllocationCatalog {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub fn register(
        &mut self,
        arena_id: u64,
        base: u64,
        capacity: u64,
    ) -> Result<ProviderAllocationSnapshot, ProviderAllocationError> {
        if arena_id == 0 {
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
            if record.arena_id == arena_id {
                return true;
            }
            let new_contains_existing = base < record.base && end >= record.end();
            let existing_contains_new = record.base < base && record.end() >= end;
            !new_contains_existing && !existing_contains_new
        }) {
            return Err(ProviderAllocationError::AddressInUse);
        }

        let slot =
            if let Some(slot) = self.records.iter().position(|record| {
                !record.live && record.arena_id == arena_id && record.base == base
            }) {
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
            arena_id,
            generation,
            live: true,
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
        arena_id: u64,
        base: u64,
    ) -> Result<ProviderAllocationSnapshot, ProviderAllocationError> {
        let (slot, record) = self
            .records
            .iter()
            .enumerate()
            .find(|(_, record)| record.live && record.arena_id == arena_id && record.base == base)
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
            if !record.live || address < record.base || end > record.end() {
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
        record.snapshot(slot)
    }

    pub fn retire(
        &mut self,
        identity: ProviderAllocationIdentity,
    ) -> Result<ProviderAllocationSnapshot, ProviderAllocationError> {
        let slot = self.slot(identity)?;
        let retiring = self.records[slot];
        if self.records.iter().enumerate().any(|(index, record)| {
            index != slot
                && record.live
                && record.base >= retiring.base
                && record.end() <= retiring.end()
        }) {
            return Err(ProviderAllocationError::ContainsLiveAllocations);
        }
        let snapshot = retiring.snapshot(slot)?;
        self.records[slot].live = false;
        Ok(snapshot)
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
                    && record.arena_id == identity.arena_id
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

    #[test]
    fn address_reuse_advances_generation_and_rejects_stale_identity() {
        let mut catalog = ProviderAllocationCatalog::new();
        let first = catalog.register(1, 0x1000, 0x100).unwrap();
        catalog.retire(first.identity).unwrap();
        let second = catalog.register(1, 0x1000, 0x80).unwrap();
        assert_eq!(second.identity.allocation_id, first.identity.allocation_id);
        assert!(second.identity.generation > first.identity.generation);
        assert_eq!(
            catalog.snapshot(first.identity),
            Err(ProviderAllocationError::StaleIdentity)
        );
    }

    #[test]
    fn innermost_nested_arena_owns_contained_storage() {
        let mut catalog = ProviderAllocationCatalog::new();
        let outer = catalog.register(1, 0x1000, 0x2000).unwrap();
        let inner = catalog.register(2, 0x1800, 0x400).unwrap();
        assert_eq!(catalog.containing(0x1900, 0x18).unwrap(), inner);
        assert_eq!(catalog.containing(0x1400, 0x18).unwrap(), outer);
    }

    #[test]
    fn containment_is_end_exclusive_and_overflow_checked() {
        let mut catalog = ProviderAllocationCatalog::new();
        let allocation = catalog.register(1, 0x2000, 0x100).unwrap();
        assert_eq!(catalog.containing(0x20e8, 0x18).unwrap(), allocation);
        assert_eq!(
            catalog.containing(0x20e9, 0x18),
            Err(ProviderAllocationError::NotFound)
        );
        assert_eq!(
            catalog.containing(u64::MAX - 7, 8),
            Err(ProviderAllocationError::InvalidRange)
        );
    }

    #[test]
    fn same_arena_overlap_and_non_hierarchical_cross_arena_overlap_fail_closed() {
        let mut catalog = ProviderAllocationCatalog::new();
        catalog.register(1, 0x3000, 0x200).unwrap();
        assert_eq!(
            catalog.register(1, 0x3100, 0x200),
            Err(ProviderAllocationError::AddressInUse)
        );
        assert_eq!(
            catalog.register(2, 0x3000, 0x200),
            Err(ProviderAllocationError::AddressInUse)
        );
        assert_eq!(
            catalog.register(2, 0x2f80, 0x100),
            Err(ProviderAllocationError::AddressInUse)
        );
    }

    #[test]
    fn outer_retirement_waits_for_nested_allocations() {
        let mut catalog = ProviderAllocationCatalog::new();
        let outer = catalog.register(1, 0x4000, 0x1000).unwrap();
        let inner = catalog.register(2, 0x4800, 0x100).unwrap();
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
        let old = catalog.register(1, 0x5000, 0x80).unwrap();
        let moved = catalog.register(1, 0x6000, 0x100).unwrap();
        catalog.retire(old.identity).unwrap();
        assert_ne!(old.identity, moved.identity);
        assert_eq!(catalog.exact(1, 0x6000).unwrap(), moved);
    }
}
