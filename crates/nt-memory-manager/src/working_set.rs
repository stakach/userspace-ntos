use alloc::boxed::Box;
use alloc::vec::Vec;

pub const WORKING_SET_PAGE_SIZE: u64 = 0x1000;
pub const FLUID_WORKING_SET_PAGES: u64 = 8;

pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
pub const STATUS_BAD_WORKING_SET_LIMIT: u32 = 0xC000_004C;

pub type WorkingSetOwnerId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkingSetLimits {
    pub minimum_pages: u64,
    pub maximum_pages: u64,
    pub hard_limit: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkingSetPage {
    pub page: u64,
    pub age: u64,
    pub locked: bool,
    pub evictable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkingSetAdjustmentPlan {
    owner: WorkingSetOwnerId,
    generation: u64,
    limits: WorkingSetLimits,
    victims: Vec<u64>,
}

impl WorkingSetAdjustmentPlan {
    pub fn owner(&self) -> WorkingSetOwnerId {
        self.owner
    }

    pub fn limits(&self) -> WorkingSetLimits {
        self.limits
    }

    pub fn victims(&self) -> &[u64] {
        &self.victims
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WorkingSetEntry {
    owner: WorkingSetOwnerId,
    limits: WorkingSetLimits,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkingSetTableStats {
    pub owners: usize,
    pub adjustments: u64,
    pub admissions: u64,
    pub planned_evictions: u64,
    pub stale_commits: u64,
    pub bad_limits: u64,
}

pub struct WorkingSetTable {
    entries: Vec<WorkingSetEntry>,
    next_generation: u64,
    stats: WorkingSetTableStats,
}

impl WorkingSetTable {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_generation: 1,
            stats: WorkingSetTableStats {
                owners: 0,
                adjustments: 0,
                admissions: 0,
                planned_evictions: 0,
                stale_commits: 0,
                bad_limits: 0,
            },
        }
    }

    fn index_for(&self, owner: WorkingSetOwnerId) -> Option<usize> {
        self.entries.iter().position(|entry| entry.owner == owner)
    }

    pub fn register(
        &mut self,
        owner: WorkingSetOwnerId,
        minimum_pages: u64,
        maximum_pages: u64,
    ) -> Result<(), u32> {
        if self.index_for(owner).is_some()
            || minimum_pages > maximum_pages
            || maximum_pages <= FLUID_WORKING_SET_PAGES
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let generation = self.allocate_generation()?;
        self.entries.push(WorkingSetEntry {
            owner,
            limits: WorkingSetLimits {
                minimum_pages,
                maximum_pages,
                hard_limit: false,
            },
            generation,
        });
        self.stats.owners = self.entries.len();
        Ok(())
    }

    pub fn unregister(&mut self, owner: WorkingSetOwnerId) -> bool {
        let Some(index) = self.index_for(owner) else {
            return false;
        };
        self.entries.swap_remove(index);
        self.stats.owners = self.entries.len();
        true
    }

    pub fn limits(&self, owner: WorkingSetOwnerId) -> Option<WorkingSetLimits> {
        self.index_for(owner)
            .map(|index| self.entries[index].limits)
    }

    pub fn prepare_adjustment(
        &mut self,
        owner: WorkingSetOwnerId,
        minimum_bytes: u64,
        maximum_bytes: u64,
        increase_ok: bool,
        hard_limit: bool,
        pages: &[WorkingSetPage],
    ) -> Result<WorkingSetAdjustmentPlan, u32> {
        let index = self.index_for(owner).ok_or(STATUS_INVALID_HANDLE)?;
        let current = self.entries[index];
        let minimum_pages = if minimum_bytes == 0 {
            current.limits.minimum_pages
        } else {
            minimum_bytes / WORKING_SET_PAGE_SIZE
        };
        let maximum_pages = if maximum_bytes == 0 {
            current.limits.maximum_pages
        } else {
            maximum_bytes / WORKING_SET_PAGE_SIZE
        };
        if minimum_pages > current.limits.minimum_pages && !increase_ok {
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
        let limits = WorkingSetLimits {
            minimum_pages,
            maximum_pages,
            hard_limit,
        };
        let victims = match select_victims(pages, maximum_pages, None) {
            Ok(victims) if minimum_pages <= maximum_pages => victims,
            _ => {
                self.stats.bad_limits = self.stats.bad_limits.saturating_add(1);
                return Err(STATUS_BAD_WORKING_SET_LIMIT);
            }
        };
        Ok(WorkingSetAdjustmentPlan {
            owner,
            generation: current.generation,
            limits,
            victims,
        })
    }

    pub fn prepare_admission(
        &mut self,
        owner: WorkingSetOwnerId,
        page: u64,
        pages: &[WorkingSetPage],
    ) -> Result<WorkingSetAdjustmentPlan, u32> {
        let index = self.index_for(owner).ok_or(STATUS_INVALID_HANDLE)?;
        let current = self.entries[index];
        let victims =
            if !current.limits.hard_limit || pages.iter().any(|resident| resident.page == page) {
                Vec::new()
            } else {
                let target = current
                    .limits
                    .maximum_pages
                    .checked_sub(1)
                    .ok_or(STATUS_BAD_WORKING_SET_LIMIT)?;
                select_victims(pages, target, Some(page))?
            };
        self.stats.admissions = self.stats.admissions.saturating_add(1);
        self.stats.planned_evictions = self
            .stats
            .planned_evictions
            .saturating_add(victims.len() as u64);
        Ok(WorkingSetAdjustmentPlan {
            owner,
            generation: current.generation,
            limits: current.limits,
            victims,
        })
    }

    pub fn commit_adjustment(&mut self, plan: &WorkingSetAdjustmentPlan) -> Result<(), u32> {
        let index = self.index_for(plan.owner).ok_or(STATUS_INVALID_HANDLE)?;
        if self.entries[index].generation != plan.generation {
            self.stats.stale_commits = self.stats.stale_commits.saturating_add(1);
            return Err(STATUS_INVALID_PARAMETER);
        }
        let generation = self.allocate_generation()?;
        self.entries[index].limits = plan.limits;
        self.entries[index].generation = generation;
        self.stats.adjustments = self.stats.adjustments.saturating_add(1);
        self.stats.planned_evictions = self
            .stats
            .planned_evictions
            .saturating_add(plan.victims.len() as u64);
        Ok(())
    }

    pub fn validate_admission(&self, plan: &WorkingSetAdjustmentPlan) -> Result<(), u32> {
        let index = self.index_for(plan.owner).ok_or(STATUS_INVALID_HANDLE)?;
        if self.entries[index].generation == plan.generation
            && self.entries[index].limits == plan.limits
        {
            Ok(())
        } else {
            Err(STATUS_INVALID_PARAMETER)
        }
    }

    pub fn stats(&self) -> WorkingSetTableStats {
        self.stats
    }

    fn allocate_generation(&mut self) -> Result<u64, u32> {
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(generation)
    }
}

impl Default for WorkingSetTable {
    fn default() -> Self {
        Self::new()
    }
}

fn select_victims(
    pages: &[WorkingSetPage],
    target_pages: u64,
    excluded_page: Option<u64>,
) -> Result<Vec<u64>, u32> {
    let mut candidates = Vec::new();
    candidates
        .try_reserve(pages.len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let mut locked_pages = 0u64;
    for (index, page) in pages.iter().enumerate() {
        if page.page & (WORKING_SET_PAGE_SIZE - 1) != 0
            || pages[..index]
                .iter()
                .any(|existing| existing.page == page.page)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if page.locked {
            locked_pages = locked_pages.saturating_add(1);
        } else if page.evictable && Some(page.page) != excluded_page {
            candidates.push(*page);
        }
    }
    if target_pages <= locked_pages.saturating_add(FLUID_WORKING_SET_PAGES) {
        return Err(STATUS_BAD_WORKING_SET_LIMIT);
    }
    let resident_pages = pages.len() as u64;
    let needed = resident_pages.saturating_sub(target_pages) as usize;
    if candidates.len() < needed {
        return Err(STATUS_BAD_WORKING_SET_LIMIT);
    }
    candidates.sort_unstable_by_key(|page| (page.age, page.page));
    candidates.truncate(needed);
    Ok(candidates.into_iter().map(|page| page.page).collect())
}

struct PagefileRecord {
    owner: WorkingSetOwnerId,
    page: u64,
    bytes: Box<[u8]>,
}

pub struct PagefileWritePlan {
    owner: WorkingSetOwnerId,
    page: u64,
    generation: u64,
    bytes: Box<[u8]>,
}

#[derive(Clone, Copy, Debug)]
pub struct PagefileWrite<'a> {
    pub owner: WorkingSetOwnerId,
    pub page: u64,
    pub bytes: &'a [u8],
}

pub struct PagefileBatchPlan {
    generation: u64,
    writes: Vec<PagefileRecord>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PagefileStoreStats {
    pub pages: usize,
    pub high_water: usize,
    pub writes: u64,
    pub replacements: u64,
    pub reads: u64,
    pub removals: u64,
    pub stale_commits: u64,
}

pub struct PagefileStore {
    records: Vec<PagefileRecord>,
    generation: u64,
    stats: PagefileStoreStats,
}

impl PagefileStore {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            generation: 1,
            stats: PagefileStoreStats {
                pages: 0,
                high_water: 0,
                writes: 0,
                replacements: 0,
                reads: 0,
                removals: 0,
                stale_commits: 0,
            },
        }
    }

    fn index_for(&self, owner: WorkingSetOwnerId, page: u64) -> Option<usize> {
        self.records
            .iter()
            .position(|record| record.owner == owner && record.page == page)
    }

    pub fn prepare_write(
        &mut self,
        owner: WorkingSetOwnerId,
        page: u64,
        bytes: &[u8],
    ) -> Result<PagefileWritePlan, u32> {
        if page & (WORKING_SET_PAGE_SIZE - 1) != 0 || bytes.len() != WORKING_SET_PAGE_SIZE as usize
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.index_for(owner, page).is_none() {
            self.records
                .try_reserve(1)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        owned.extend_from_slice(bytes);
        Ok(PagefileWritePlan {
            owner,
            page,
            generation: self.generation,
            bytes: owned.into_boxed_slice(),
        })
    }

    pub fn commit_write(&mut self, plan: PagefileWritePlan) -> Result<(), u32> {
        if self.generation != plan.generation {
            self.stats.stale_commits = self.stats.stale_commits.saturating_add(1);
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        if let Some(index) = self.index_for(plan.owner, plan.page) {
            self.records[index].bytes = plan.bytes;
            self.stats.replacements = self.stats.replacements.saturating_add(1);
        } else {
            self.records.push(PagefileRecord {
                owner: plan.owner,
                page: plan.page,
                bytes: plan.bytes,
            });
            self.stats.pages = self.records.len();
            self.stats.high_water = self.stats.high_water.max(self.records.len());
        }
        self.stats.writes = self.stats.writes.saturating_add(1);
        Ok(())
    }

    pub fn prepare_write_batch(
        &mut self,
        writes: &[PagefileWrite<'_>],
    ) -> Result<PagefileBatchPlan, u32> {
        let mut new_records = 0usize;
        for (index, write) in writes.iter().enumerate() {
            if write.page & (WORKING_SET_PAGE_SIZE - 1) != 0
                || write.bytes.len() != WORKING_SET_PAGE_SIZE as usize
                || writes[..index]
                    .iter()
                    .any(|existing| existing.owner == write.owner && existing.page == write.page)
            {
                return Err(STATUS_INVALID_PARAMETER);
            }
            if self.index_for(write.owner, write.page).is_none() {
                new_records += 1;
            }
        }
        self.records
            .try_reserve(new_records)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(writes.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        for write in writes {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(write.bytes.len())
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            bytes.extend_from_slice(write.bytes);
            owned.push(PagefileRecord {
                owner: write.owner,
                page: write.page,
                bytes: bytes.into_boxed_slice(),
            });
        }
        Ok(PagefileBatchPlan {
            generation: self.generation,
            writes: owned,
        })
    }

    pub fn commit_write_batch(&mut self, plan: PagefileBatchPlan) -> Result<(), u32> {
        if self.generation != plan.generation {
            self.stats.stale_commits = self.stats.stale_commits.saturating_add(1);
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        for write in plan.writes {
            if let Some(index) = self.index_for(write.owner, write.page) {
                self.records[index].bytes = write.bytes;
                self.stats.replacements = self.stats.replacements.saturating_add(1);
            } else {
                self.records.push(write);
            }
            self.stats.writes = self.stats.writes.saturating_add(1);
        }
        self.stats.pages = self.records.len();
        self.stats.high_water = self.stats.high_water.max(self.records.len());
        Ok(())
    }

    pub fn page(&mut self, owner: WorkingSetOwnerId, page: u64) -> Option<&[u8]> {
        let index = self.index_for(owner, page)?;
        self.stats.reads = self.stats.reads.saturating_add(1);
        Some(&self.records[index].bytes)
    }

    pub fn remove(&mut self, owner: WorkingSetOwnerId, page: u64) -> bool {
        let Some(index) = self.index_for(owner, page) else {
            return false;
        };
        self.records.swap_remove(index);
        self.generation = self.generation.saturating_add(1);
        self.stats.pages = self.records.len();
        self.stats.removals = self.stats.removals.saturating_add(1);
        true
    }

    pub fn retire_owner(&mut self, owner: WorkingSetOwnerId) -> usize {
        let before = self.records.len();
        self.records.retain(|record| record.owner != owner);
        let removed = before - self.records.len();
        if removed != 0 {
            self.generation = self.generation.saturating_add(1);
            self.stats.pages = self.records.len();
            self.stats.removals = self.stats.removals.saturating_add(removed as u64);
        }
        removed
    }

    pub fn stats(&self) -> PagefileStoreStats {
        self.stats
    }
}

impl Default for PagefileStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(page: u64, age: u64) -> WorkingSetPage {
        WorkingSetPage {
            page,
            age,
            locked: false,
            evictable: true,
        }
    }

    #[test]
    fn adjustment_selects_oldest_unlocked_pages_and_commits_limits() {
        let mut table = WorkingSetTable::new();
        table.register(4, 20, 45).unwrap();
        let mut pages = Vec::new();
        for index in 0..32 {
            pages.push(page(0x1000 + index * 0x1000, 32 - index));
        }
        pages[31].locked = true;
        let plan = table
            .prepare_adjustment(4, 20 * 0x1000, 24 * 0x1000, true, true, &pages)
            .unwrap();
        assert_eq!(plan.victims().len(), 8);
        assert!(!plan.victims().contains(&pages[31].page));
        assert_eq!(plan.victims()[0], pages[30].page);
        table.commit_adjustment(&plan).unwrap();
        assert_eq!(
            table.limits(4),
            Some(WorkingSetLimits {
                minimum_pages: 20,
                maximum_pages: 24,
                hard_limit: true,
            })
        );
    }

    #[test]
    fn hard_admission_plans_replacement_before_growth() {
        let mut table = WorkingSetTable::new();
        table.register(4, 12, 16).unwrap();
        let pages: Vec<_> = (0..16)
            .map(|index| page(0x1000 + index * 0x1000, index))
            .collect();
        let limits = table
            .prepare_adjustment(4, 12 * 0x1000, 16 * 0x1000, true, true, &pages)
            .unwrap();
        table.commit_adjustment(&limits).unwrap();
        let admission = table.prepare_admission(4, 0x40_000, &pages).unwrap();
        assert_eq!(admission.victims(), &[0x1000]);
        assert_eq!(table.validate_admission(&admission), Ok(()));
    }

    #[test]
    fn locked_pages_and_fluid_reserve_reject_an_impossible_limit() {
        let mut table = WorkingSetTable::new();
        table.register(2, 20, 45).unwrap();
        let mut pages: Vec<_> = (0..20)
            .map(|index| page(0x1000 + index * 0x1000, index))
            .collect();
        for resident in pages.iter_mut().take(12) {
            resident.locked = true;
        }
        assert_eq!(
            table.prepare_adjustment(2, 12 * 0x1000, 20 * 0x1000, true, true, &pages),
            Err(STATUS_BAD_WORKING_SET_LIMIT)
        );
    }

    #[test]
    fn increasing_minimum_requires_privilege() {
        let mut table = WorkingSetTable::new();
        table.register(2, 20, 45).unwrap();
        assert_eq!(
            table.prepare_adjustment(2, 21 * 0x1000, 45 * 0x1000, false, true, &[]),
            Err(STATUS_PRIVILEGE_NOT_HELD)
        );
    }

    #[test]
    fn stale_limit_plan_cannot_overwrite_new_policy() {
        let mut table = WorkingSetTable::new();
        table.register(2, 20, 45).unwrap();
        let first = table
            .prepare_adjustment(2, 20 * 0x1000, 40 * 0x1000, true, true, &[])
            .unwrap();
        let stale = first.clone();
        table.commit_adjustment(&first).unwrap();
        assert_eq!(
            table.commit_adjustment(&stale),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn pagefile_write_is_owned_before_frame_teardown_and_restorable() {
        let mut store = PagefileStore::new();
        let mut contents = [0u8; 0x1000];
        contents[0] = 0x4d;
        contents[0xfff] = 0x5a;
        let plan = store.prepare_write(7, 0x20_000, &contents).unwrap();
        assert!(store.page(7, 0x20_000).is_none());
        store.commit_write(plan).unwrap();
        let restored = store.page(7, 0x20_000).unwrap();
        assert_eq!(restored[0], 0x4d);
        assert_eq!(restored[0xfff], 0x5a);
        assert!(store.remove(7, 0x20_000));
        assert!(store.page(7, 0x20_000).is_none());
    }

    #[test]
    fn stale_pagefile_plan_cannot_replace_newer_contents() {
        let mut store = PagefileStore::new();
        let old = store.prepare_write(7, 0x20_000, &[1; 0x1000]).unwrap();
        let new = store.prepare_write(7, 0x30_000, &[2; 0x1000]).unwrap();
        store.commit_write(new).unwrap();
        assert_eq!(store.commit_write(old), Err(STATUS_INVALID_PARAMETER));
        assert!(store.page(7, 0x20_000).is_none());
    }

    #[test]
    fn owner_rundown_removes_only_its_pagefile_records() {
        let mut store = PagefileStore::new();
        for (owner, page) in [(2, 0x1000), (2, 0x2000), (3, 0x1000)] {
            let plan = store
                .prepare_write(owner, page, &[owner as u8; 0x1000])
                .unwrap();
            store.commit_write(plan).unwrap();
        }
        assert_eq!(store.retire_owner(2), 2);
        assert!(store.page(2, 0x1000).is_none());
        assert_eq!(store.page(3, 0x1000).unwrap()[0], 3);
    }

    #[test]
    fn pagefile_batch_owns_every_page_before_publication() {
        let mut store = PagefileStore::new();
        let first = [0x11; 0x1000];
        let second = [0x22; 0x1000];
        let plan = store
            .prepare_write_batch(&[
                PagefileWrite {
                    owner: 2,
                    page: 0x1000,
                    bytes: &first,
                },
                PagefileWrite {
                    owner: 2,
                    page: 0x2000,
                    bytes: &second,
                },
            ])
            .unwrap();
        assert!(store.page(2, 0x1000).is_none());
        assert!(store.page(2, 0x2000).is_none());
        store.commit_write_batch(plan).unwrap();
        assert_eq!(store.page(2, 0x1000).unwrap()[0], 0x11);
        assert_eq!(store.page(2, 0x2000).unwrap()[0], 0x22);
    }
}
