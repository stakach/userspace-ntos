use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientFrameRecord {
    pub pi: u64,
    pub page: u64,
    pub frame: u64,
    pub alias: u64,
    pub alias_cap: u64,
    pub source_cap: u64,
    pub owns_frame: bool,
    pub age: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientFrameInsert {
    Inserted { grew: bool },
    Updated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientFrameInsertError {
    ConflictingFrame,
    ConflictingOwnership,
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
}

pub struct ClientFrameRegistry {
    records: Vec<ClientFrameRecord>,
    next_age: u64,
    high_water: usize,
    growths: u64,
    allocation_failures: u64,
    frame_conflicts: u64,
    ownership_conflicts: u64,
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
        self.next_age = self.next_age.saturating_add(1);
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
        self.next_age = self.next_age.max(age.saturating_add(1));
        if let Some(index) = self.index_for(pi, page) {
            let record = &mut self.records[index];
            if record.frame != frame {
                self.frame_conflicts = self.frame_conflicts.saturating_add(1);
                return Err(ClientFrameInsertError::ConflictingFrame);
            }
            if record.owns_frame != owns_frame {
                self.ownership_conflicts = self.ownership_conflicts.saturating_add(1);
                return Err(ClientFrameInsertError::ConflictingOwnership);
            }
            if record.alias == 0 && alias != 0 {
                record.alias = alias;
            }
            if record.alias_cap == 0 && alias_cap != 0 {
                record.alias_cap = alias_cap;
            }
            if record.source_cap == 0 && source_cap != 0 {
                record.source_cap = source_cap;
            }
            record.age = age;
            return Ok(ClientFrameInsert::Updated);
        }

        let old_capacity = self.records.capacity();
        if self.records.try_reserve(1).is_err() {
            self.allocation_failures = self.allocation_failures.saturating_add(1);
            return Err(ClientFrameInsertError::AllocationFailed);
        }
        let grew = self.records.capacity() != old_capacity;
        if grew {
            self.growths = self.growths.saturating_add(1);
        }
        self.records.push(ClientFrameRecord {
            pi,
            page,
            frame,
            alias,
            alias_cap,
            source_cap,
            owns_frame,
            age,
        });
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
        self.records[index].age = self.next_age;
        self.next_age = self.next_age.saturating_add(1);
        true
    }

    pub fn take(&mut self, pi: u64, page: u64) -> Option<ClientFrameRecord> {
        let index = self.index_for(pi, page)?;
        Some(self.records.swap_remove(index))
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
        }
    }
}

impl Default for ClientFrameRegistry {
    fn default() -> Self {
        Self::new()
    }
}

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
}
