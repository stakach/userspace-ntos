use alloc::vec::Vec;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

#[path = "client_frame_transfer.rs"]
mod transfer;
pub use transfer::{ClientFrameTransfer, ClientFrameTransferError};

static NEXT_RECORD_ID: AtomicU64 = AtomicU64::new(1);

fn allocate_record_id(counter: &AtomicU64) -> Result<u64, ClientFrameInsertError> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .map_err(|_| ClientFrameInsertError::IdentityExhausted)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientFrameRecord {
    // Independent of working-set age and cap values, which may recur after row/cap-slot reuse.
    record_id: u64,
    pub pi: u64,
    pub page: u64,
    pub frame: u64,
    pub alias: u64,
    pub alias_cap: u64,
    pub source_cap: u64,
    pub owns_frame: bool,
    pub age: u64,
    pub frame_unmapped: bool,
    pub alias_unmapped: bool,
    reclaim_started: bool,
    transfer_id: Option<NonZeroU64>,
}

impl ClientFrameRecord {
    /// Reclamation is terminal for access, even while some capabilities remain live.
    pub const fn is_resident(self) -> bool {
        self.frame != 0 && !self.reclaim_started && !self.frame_unmapped && !self.alias_unmapped
    }

    pub const fn is_reclaiming(self) -> bool {
        self.reclaim_started
    }

    pub fn mapped_alias(self) -> Option<u64> {
        (self.is_resident() && self.alias != 0 && self.alias_cap != 0).then_some(self.alias)
    }

    pub fn clone_source_cap(self) -> Option<u64> {
        self.is_resident().then_some(if self.source_cap != 0 {
            self.source_cap
        } else {
            self.frame
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientFrameInsert {
    Inserted { grew: bool },
    Updated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientFrameInsertError {
    InvalidRecord,
    ConflictingFrame,
    ConflictingOwnership,
    ConflictingAlias,
    ConflictingSource,
    Reclaiming,
    IdentityExhausted,
    AllocationFailed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientFrameRegistryStats {
    pub records: usize,
    pub capacity: usize,
    pub high_water: usize,
    pub growths: u64,
    pub allocation_failures: u64,
    pub frame_conflicts: u64,
    pub ownership_conflicts: u64,
    pub alias_conflicts: u64,
    pub source_conflicts: u64,
    pub invalid_records: u64,
    pub reclaim_refusals: u64,
    pub identity_exhaustions: u64,
}

pub struct ClientFrameRegistry {
    records: Vec<ClientFrameRecord>,
    next_age: u64,
    high_water: usize,
    growths: u64,
    allocation_failures: u64,
    frame_conflicts: u64,
    ownership_conflicts: u64,
    alias_conflicts: u64,
    source_conflicts: u64,
    invalid_records: u64,
    reclaim_refusals: u64,
    identity_exhaustions: u64,
}

impl ClientFrameRegistry {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            next_age: 1,
            high_water: 0,
            growths: 0,
            allocation_failures: 0,
            frame_conflicts: 0,
            ownership_conflicts: 0,
            alias_conflicts: 0,
            source_conflicts: 0,
            invalid_records: 0,
            reclaim_refusals: 0,
            identity_exhaustions: 0,
        }
    }

    pub fn reserve_initial(&mut self, records: usize) -> bool {
        if self.records.try_reserve(records).is_err() {
            self.allocation_failures = self.allocation_failures.saturating_add(1);
            false
        } else {
            true
        }
    }

    fn index_for(&self, pi: u64, page: u64) -> Option<usize> {
        self.records
            .iter()
            .position(|record| record.pi == pi && record.page == page)
    }

    pub fn insert(
        &mut self,
        pi: u64,
        page: u64,
        frame: u64,
        alias: u64,
        alias_cap: u64,
        source_cap: u64,
        owns_frame: bool,
    ) -> Result<ClientFrameInsert, ClientFrameInsertError> {
        let age = self.next_age;
        self.insert_at_age(
            pi, page, frame, alias, alias_cap, source_cap, owns_frame, age,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_at_age(
        &mut self,
        pi: u64,
        page: u64,
        frame: u64,
        alias: u64,
        alias_cap: u64,
        source_cap: u64,
        owns_frame: bool,
        age: u64,
    ) -> Result<ClientFrameInsert, ClientFrameInsertError> {
        if frame == 0 || (alias != 0 && alias_cap == 0) {
            self.invalid_records = self.invalid_records.saturating_add(1);
            return Err(ClientFrameInsertError::InvalidRecord);
        }
        if let Some(index) = self.index_for(pi, page) {
            let record = &mut self.records[index];
            if record.is_reclaiming() {
                self.reclaim_refusals = self.reclaim_refusals.saturating_add(1);
                return Err(ClientFrameInsertError::Reclaiming);
            }
            if record.frame != frame {
                self.frame_conflicts = self.frame_conflicts.saturating_add(1);
                return Err(ClientFrameInsertError::ConflictingFrame);
            }
            if record.owns_frame != owns_frame {
                self.ownership_conflicts = self.ownership_conflicts.saturating_add(1);
                return Err(ClientFrameInsertError::ConflictingOwnership);
            }
            // An omitted pair preserves existing ownership. A dormant copy (0, cap) may acquire
            // a mapped address only when the caller explicitly supplies that same capability.
            if (alias_cap != 0 && record.alias_cap != 0 && alias_cap != record.alias_cap)
                || (alias != 0 && record.alias != 0 && alias != record.alias)
            {
                self.alias_conflicts = self.alias_conflicts.saturating_add(1);
                return Err(ClientFrameInsertError::ConflictingAlias);
            }
            if source_cap != 0 && record.source_cap != 0 && source_cap != record.source_cap {
                self.source_conflicts = self.source_conflicts.saturating_add(1);
                return Err(ClientFrameInsertError::ConflictingSource);
            }
            // Every conflict is checked before any metadata, including working-set age, changes.
            if record.alias_cap == 0 && alias_cap != 0 {
                record.alias_cap = alias_cap;
            }
            if record.alias == 0 && alias != 0 {
                record.alias = alias;
            }
            if record.source_cap == 0 && source_cap != 0 {
                record.source_cap = source_cap;
            }
            record.age = age;
            self.next_age = self.next_age.max(age.saturating_add(1));
            return Ok(ClientFrameInsert::Updated);
        }

        let old_capacity = self.records.capacity();
        if self.records.try_reserve(1).is_err() {
            self.allocation_failures = self.allocation_failures.saturating_add(1);
            return Err(ClientFrameInsertError::AllocationFailed);
        }
        let record_id = allocate_record_id(&NEXT_RECORD_ID).map_err(|error| {
            self.identity_exhaustions = self.identity_exhaustions.saturating_add(1);
            error
        })?;
        let grew = self.records.capacity() != old_capacity;
        if grew {
            self.growths = self.growths.saturating_add(1);
        }
        self.records.push(ClientFrameRecord {
            record_id,
            pi,
            page,
            frame,
            alias,
            alias_cap,
            source_cap,
            owns_frame,
            age,
            frame_unmapped: false,
            alias_unmapped: false,
            reclaim_started: false,
            transfer_id: None,
        });
        self.next_age = self.next_age.max(age.saturating_add(1));
        self.high_water = self.high_water.max(self.records.len());
        Ok(ClientFrameInsert::Inserted { grew })
    }

    pub fn get_with_index(&self, pi: u64, page: u64) -> Option<(usize, ClientFrameRecord)> {
        let index = self.index_for(pi, page)?;
        Some((index, self.records[index]))
    }

    pub fn get(&self, pi: u64, page: u64) -> Option<ClientFrameRecord> {
        self.get_with_index(pi, page).map(|(_, record)| record)
    }

    pub fn touch(&mut self, pi: u64, page: u64) -> bool {
        let Some(index) = self.index_for(pi, page) else {
            return false;
        };
        if self.records[index].is_reclaiming() {
            return false;
        }
        self.records[index].age = self.next_age;
        self.next_age = self.next_age.saturating_add(1);
        true
    }

    pub fn take(&mut self, pi: u64, page: u64) -> Option<ClientFrameRecord> {
        let index = self.index_for(pi, page)?;
        if self.records[index].transfer_id.is_some() {
            return None;
        }
        Some(self.records.swap_remove(index))
    }

    pub fn mark_frame_unmapped_exact(
        &mut self,
        expected: ClientFrameRecord,
    ) -> Option<ClientFrameRecord> {
        let record = self.exact_mut(expected)?;
        if record.frame == 0 || record.frame_unmapped {
            return None;
        }
        record.frame_unmapped = true;
        record.reclaim_started = true;
        Some(*record)
    }

    pub fn mark_alias_unmapped_exact(
        &mut self,
        expected: ClientFrameRecord,
    ) -> Option<ClientFrameRecord> {
        let record = self.exact_mut(expected)?;
        if record.alias_cap == 0 || record.alias_unmapped {
            return None;
        }
        record.alias_unmapped = true;
        record.reclaim_started = true;
        Some(*record)
    }

    pub fn clear_frame_cap_exact(
        &mut self,
        expected: ClientFrameRecord,
    ) -> Option<ClientFrameRecord> {
        let record = self.exact_mut(expected)?;
        if record.frame == 0 || !record.frame_unmapped || record.owns_frame {
            return None;
        }
        let frame = record.frame;
        record.reclaim_started = true;
        record.frame = 0;
        if record.alias_cap == frame {
            record.alias_cap = 0;
            record.alias_unmapped = false;
        }
        if record.source_cap == frame {
            record.source_cap = 0;
        }
        Some(*record)
    }

    pub fn clear_alias_cap_exact(
        &mut self,
        expected: ClientFrameRecord,
    ) -> Option<ClientFrameRecord> {
        let record = self.exact_mut(expected)?;
        if record.alias_cap == 0 || !record.alias_unmapped {
            return None;
        }
        let alias = record.alias_cap;
        record.reclaim_started = true;
        record.alias_cap = 0;
        record.alias_unmapped = false;
        if record.source_cap == alias {
            record.source_cap = 0;
        }
        Some(*record)
    }

    pub fn clear_source_cap_exact(
        &mut self,
        expected: ClientFrameRecord,
    ) -> Option<ClientFrameRecord> {
        let record = self.exact_mut(expected)?;
        if record.source_cap == 0 {
            return None;
        }
        record.reclaim_started = true;
        record.source_cap = 0;
        Some(*record)
    }

    /// Close registration and resident access before the first destructive backend operation.
    /// A failed unmap/delete retains this terminal state and its exact capabilities for retry.
    pub fn begin_reclaim_exact(
        &mut self,
        expected: ClientFrameRecord,
    ) -> Option<ClientFrameRecord> {
        let record = self.exact_mut(expected)?;
        record.reclaim_started = true;
        Some(*record)
    }

    pub fn take_exact(&mut self, expected: ClientFrameRecord) -> Option<ClientFrameRecord> {
        let index = self.index_for(expected.pi, expected.page)?;
        if self.records[index] != expected || self.records[index].transfer_id.is_some() {
            return None;
        }
        Some(self.records.swap_remove(index))
    }

    fn exact_mut(&mut self, expected: ClientFrameRecord) -> Option<&mut ClientFrameRecord> {
        let index = self.index_for(expected.pi, expected.page)?;
        if self.records[index] != expected || self.records[index].transfer_id.is_some() {
            return None;
        }
        Some(&mut self.records[index])
    }

    pub fn first_page_for_process(&self, pi: u64) -> Option<u64> {
        self.records
            .iter()
            .find(|record| record.pi == pi)
            .map(|record| record.page)
    }

    pub fn is_process_empty(&self, pi: u64) -> bool {
        self.first_page_for_process(pi).is_none()
    }

    pub fn next_page_after(&self, pi: u64, page: u64) -> Option<u64> {
        self.records
            .iter()
            .filter(|record| record.pi == pi && record.page > page)
            .map(|record| record.page)
            .min()
    }

    pub fn records(&self) -> &[ClientFrameRecord] {
        &self.records
    }

    pub fn stats(&self) -> ClientFrameRegistryStats {
        ClientFrameRegistryStats {
            records: self.records.len(),
            capacity: self.records.capacity(),
            high_water: self.high_water,
            growths: self.growths,
            allocation_failures: self.allocation_failures,
            frame_conflicts: self.frame_conflicts,
            ownership_conflicts: self.ownership_conflicts,
            alias_conflicts: self.alias_conflicts,
            source_conflicts: self.source_conflicts,
            invalid_records: self.invalid_records,
            reclaim_refusals: self.reclaim_refusals,
            identity_exhaustions: self.identity_exhaustions,
        }
    }
}

impl Default for ClientFrameRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "client_frame_lifetime_tests.rs"]
mod lifetime_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn insert(registry: &mut ClientFrameRegistry, pi: u64, page: u64, frame: u64) {
        registry.insert(pi, page, frame, 0, 0, 0, true).unwrap();
    }

    #[test]
    fn grows_beyond_initial_reservation() {
        let mut registry = ClientFrameRegistry::new();
        assert!(registry.reserve_initial(1));
        let initial_capacity = registry.stats().capacity;
        for index in 0..=initial_capacity {
            insert(
                &mut registry,
                2,
                0x1000 + index as u64 * 0x1000,
                0x100 + index as u64,
            );
        }
        let stats = registry.stats();
        assert_eq!(stats.records, initial_capacity + 1);
        assert_eq!(stats.high_water, initial_capacity + 1);
        assert!(stats.capacity > initial_capacity);
        assert_eq!(stats.growths, 1);
        assert_eq!(stats.allocation_failures, 0);
    }

    #[test]
    fn duplicate_registration_enriches_missing_caps() {
        let mut registry = ClientFrameRegistry::new();
        assert_eq!(
            registry.insert(2, 0x1000, 0x40, 0, 0, 0, true),
            Ok(ClientFrameInsert::Inserted { grew: true })
        );
        assert_eq!(
            registry.insert(2, 0x1000, 0x40, 0x2000, 0x44, 0x48, true),
            Ok(ClientFrameInsert::Updated)
        );
        let record = registry.get(2, 0x1000).unwrap();
        assert_eq!(record.alias, 0x2000);
        assert_eq!(record.alias_cap, 0x44);
        assert_eq!(record.source_cap, 0x48);
    }

    #[test]
    fn conflicting_duplicate_does_not_partially_update() {
        let mut registry = ClientFrameRegistry::new();
        insert(&mut registry, 2, 0x1000, 0x40);
        assert_eq!(
            registry.insert(2, 0x1000, 0x44, 0x2000, 0x48, 0x4c, true),
            Err(ClientFrameInsertError::ConflictingFrame)
        );
        assert_eq!(registry.get(2, 0x1000).unwrap().alias, 0);
        assert_eq!(registry.stats().frame_conflicts, 1);
        assert_eq!(
            registry.insert(2, 0x1000, 0x40, 0x2000, 0x48, 0x4c, false),
            Err(ClientFrameInsertError::ConflictingOwnership)
        );
        assert_eq!(registry.get(2, 0x1000).unwrap().alias, 0);
        assert_eq!(registry.stats().ownership_conflicts, 1);
    }

    #[test]
    fn take_compacts_without_losing_other_records() {
        let mut registry = ClientFrameRegistry::new();
        insert(&mut registry, 2, 0x1000, 0x40);
        insert(&mut registry, 3, 0x2000, 0x44);
        insert(&mut registry, 2, 0x3000, 0x48);
        assert_eq!(registry.take(2, 0x1000).unwrap().frame, 0x40);
        assert!(registry.get(2, 0x1000).is_none());
        assert_eq!(registry.get(3, 0x2000).unwrap().frame, 0x44);
        assert_eq!(registry.next_page_after(2, 0x1000), Some(0x3000));
        assert_eq!(registry.first_page_for_process(3), Some(0x2000));
    }

    #[test]
    fn process_empty_tracks_insert_and_take() {
        let mut registry = ClientFrameRegistry::new();
        assert!(registry.is_process_empty(7));
        insert(&mut registry, 7, 0x1000, 11);
        insert(&mut registry, 8, 0x1000, 12);
        assert!(!registry.is_process_empty(7));
        assert!(!registry.is_process_empty(8));
        assert!(registry.take(7, 0x1000).is_some());
        assert!(registry.is_process_empty(7));
        assert!(!registry.is_process_empty(8));
    }

    #[test]
    fn exact_reclaim_progress_rejects_stale_snapshots() {
        let mut registry = ClientFrameRegistry::new();
        registry
            .insert(7, 0x1000, 11, 0x2000, 12, 13, false)
            .unwrap();
        let initial = registry.get(7, 0x1000).unwrap();
        let frame_unmapped = registry.mark_frame_unmapped_exact(initial).unwrap();
        assert!(registry.mark_frame_unmapped_exact(initial).is_none());
        let frame_released = registry.clear_frame_cap_exact(frame_unmapped).unwrap();
        let alias_unmapped = registry.mark_alias_unmapped_exact(frame_released).unwrap();
        let alias_released = registry.clear_alias_cap_exact(alias_unmapped).unwrap();
        let source_released = registry.clear_source_cap_exact(alias_released).unwrap();
        for record in [
            frame_unmapped,
            frame_released,
            alias_unmapped,
            alias_released,
            source_released,
        ] {
            assert!(!record.is_resident());
            assert_eq!(record.mapped_alias(), None);
            assert_eq!(record.clone_source_cap(), None);
        }
        assert_eq!(registry.take_exact(source_released), Some(source_released));
        assert!(registry.is_process_empty(7));
    }

    #[test]
    fn copy_access_requires_owned_alias_and_live_backing() {
        let mut registry = ClientFrameRegistry::new();
        registry
            .insert(7, 0x1000, 11, 0x2000, 12, 13, false)
            .unwrap();
        let record = registry.get(7, 0x1000).unwrap();
        assert_eq!(record.mapped_alias(), Some(0x2000));
        assert_eq!(record.clone_source_cap(), Some(13));
        let unowned_alias = ClientFrameRecord {
            alias_cap: 0,
            ..record
        };
        assert_eq!(unowned_alias.mapped_alias(), None);
        assert_eq!(unowned_alias.clone_source_cap(), Some(13));
        assert_eq!(
            ClientFrameRecord {
                source_cap: 0,
                ..unowned_alias
            }
            .clone_source_cap(),
            Some(11)
        );
        for unavailable in [
            ClientFrameRecord { frame: 0, ..record },
            ClientFrameRecord {
                alias_unmapped: true,
                ..record
            },
            ClientFrameRecord {
                frame_unmapped: true,
                ..record
            },
        ] {
            assert_eq!(unavailable.mapped_alias(), None);
            assert_eq!(unavailable.clone_source_cap(), None);
        }
    }

    #[test]
    fn copy_access_tracks_replacement_eviction_and_process_identity() {
        let mut registry = ClientFrameRegistry::new();
        registry
            .insert(7, 0x1000, 11, 0x2000, 12, 13, false)
            .unwrap();
        registry
            .insert(8, 0x1000, 21, 0x3000, 22, 23, false)
            .unwrap();
        registry.take(7, 0x1000).unwrap();
        assert!(registry.get(7, 0x1000).is_none());
        assert_eq!(
            registry.get(8, 0x1000).unwrap().mapped_alias(),
            Some(0x3000)
        );
        registry
            .insert(7, 0x1000, 31, 0x4000, 32, 33, true)
            .unwrap();
        let replacement = registry.get(7, 0x1000).unwrap();
        assert_eq!(replacement.mapped_alias(), Some(0x4000));
        assert_eq!(replacement.clone_source_cap(), Some(33));
        registry.take_exact(replacement).unwrap();
        assert!(registry.get(7, 0x1000).is_none());
        registry.insert(7, 0x1000, 41, 0, 0, 0, true).unwrap();
        let restored = registry.get(7, 0x1000).unwrap();
        assert_eq!(restored.mapped_alias(), None);
        assert_eq!(restored.clone_source_cap(), Some(41));
    }
}
