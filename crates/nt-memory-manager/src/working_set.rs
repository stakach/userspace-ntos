use alloc::vec::Vec;

pub const WORKING_SET_PAGE_SIZE: u64 = 0x1000;
pub const FLUID_WORKING_SET_PAGES: u64 = 8;
pub const DEFAULT_WORKING_SET_MINIMUM_PAGES: u64 = 20;
pub const DEFAULT_WORKING_SET_MAXIMUM_PAGES: u64 = 45;

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
            (minimum_bytes / WORKING_SET_PAGE_SIZE).max(DEFAULT_WORKING_SET_MINIMUM_PAGES)
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

    pub fn prepare_enforcement(
        &self,
        owner: WorkingSetOwnerId,
        hard_limit: bool,
    ) -> Result<WorkingSetAdjustmentPlan, u32> {
        let index = self.index_for(owner).ok_or(STATUS_INVALID_HANDLE)?;
        let current = self.entries[index];
        Ok(WorkingSetAdjustmentPlan {
            owner,
            generation: current.generation,
            limits: WorkingSetLimits {
                hard_limit,
                ..current.limits
            },
            victims: Vec::new(),
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
    let mut fixed_pages = 0u64;
    for (index, page) in pages.iter().enumerate() {
        if page.page & (WORKING_SET_PAGE_SIZE - 1) != 0
            || pages[..index]
                .iter()
                .any(|existing| existing.page == page.page)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if page.locked || !page.evictable {
            fixed_pages = fixed_pages.saturating_add(1);
        } else if Some(page.page) != excluded_page {
            candidates.push(*page);
        }
    }
    if target_pages <= fixed_pages.saturating_add(FLUID_WORKING_SET_PAGES) {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagefilePage {
    pub owner: WorkingSetOwnerId,
    pub page: u64,
    pub protection: u32,
    pub backing: u64,
}

#[path = "pagefile_retirement.rs"]
mod pagefile_retirement;
pub use pagefile_retirement::{PagefileRetirement, PagefileRetirementIo};

static NEXT_PAGEFILE_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

fn allocate_pagefile_id(counter: &core::sync::atomic::AtomicU64) -> Result<u64, u32> {
    counter
        .fetch_update(
            core::sync::atomic::Ordering::Relaxed,
            core::sync::atomic::Ordering::Relaxed,
            |value| {
                if value == 0 {
                    None
                } else {
                    value.checked_add(1)
                }
            },
        )
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PagefileState {
    Available,
    Retiring { unmapped: bool, revoked: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PagefileRecord {
    id: u64,
    page: PagefilePage,
    state: PagefileState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagefilePublishPlan {
    store_id: u64,
    record_id: u64,
    generation: u64,
    next_generation: u64,
    page: PagefilePage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagefileProtectionPlan {
    store_id: u64,
    generation: u64,
    next_generation: u64,
    owner: WorkingSetOwnerId,
    base: u64,
    end: u64,
    protection: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PagefileStoreStats {
    pub pages: usize,
    pub high_water: usize,
    pub publications: u64,
    pub restores: u64,
    pub takes: u64,
    pub stale_commits: u64,
    pub retiring: usize,
    pub retirements: u64,
}

pub struct PagefileStore {
    records: Vec<PagefileRecord>,
    identity: u64,
    generation: u64,
    stats: PagefileStoreStats,
}

impl PagefileStore {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            identity: 0,
            generation: 1,
            stats: PagefileStoreStats {
                pages: 0,
                high_water: 0,
                publications: 0,
                restores: 0,
                takes: 0,
                stale_commits: 0,
                retiring: 0,
                retirements: 0,
            },
        }
    }

    fn index_for(&self, owner: WorkingSetOwnerId, page: u64) -> Option<usize> {
        self.records
            .iter()
            .position(|record| record.page.owner == owner && record.page.page == page)
    }

    pub fn contains(&self, owner: WorkingSetOwnerId, page: u64) -> bool {
        self.index_for(owner, page).is_some()
    }

    pub fn prepare_publish(&mut self, page: PagefilePage) -> Result<PagefilePublishPlan, u32> {
        self.prepare_publish_with_counter(page, &NEXT_PAGEFILE_ID)
    }

    fn prepare_publish_with_counter(
        &mut self,
        page: PagefilePage,
        counter: &core::sync::atomic::AtomicU64,
    ) -> Result<PagefilePublishPlan, u32> {
        if page.page & (WORKING_SET_PAGE_SIZE - 1) != 0
            || page.page.checked_add(WORKING_SET_PAGE_SIZE).is_none()
            || page.backing == 0
            || self.index_for(page.owner, page.page).is_some()
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.records
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        if self.identity == 0 {
            self.identity = allocate_pagefile_id(counter)?;
        }
        let record_id = allocate_pagefile_id(counter)?;
        Ok(PagefilePublishPlan {
            store_id: self.identity,
            record_id,
            generation: self.generation,
            next_generation,
            page,
        })
    }

    pub fn commit_publish(&mut self, plan: PagefilePublishPlan) -> Result<(), u32> {
        self.commit_insert(plan, false)
    }

    fn commit_insert(&mut self, plan: PagefilePublishPlan, restoration: bool) -> Result<(), u32> {
        if self.identity == 0
            || self.identity != plan.store_id
            || self.generation != plan.generation
            || self.index_for(plan.page.owner, plan.page.page).is_some()
        {
            self.stats.stale_commits = self.stats.stale_commits.saturating_add(1);
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.generation = plan.next_generation;
        self.records.push(PagefileRecord {
            id: plan.record_id,
            page: plan.page,
            state: PagefileState::Available,
        });
        self.stats.pages = self.records.len();
        self.stats.high_water = self.stats.high_water.max(self.records.len());
        if restoration {
            self.stats.restores = self.stats.restores.saturating_add(1);
        } else {
            self.stats.publications = self.stats.publications.saturating_add(1);
        }
        Ok(())
    }

    pub fn page(&self, owner: WorkingSetOwnerId, page: u64) -> Option<PagefilePage> {
        let index = self.index_for(owner, page)?;
        let record = self.records[index];
        (record.state == PagefileState::Available).then_some(record.page)
    }

    /// Reserve the fallible generation change before altering resident or VAD protection.
    pub fn prepare_protection(
        &self,
        owner: WorkingSetOwnerId,
        page: u64,
        protection: u32,
    ) -> Result<Option<PagefileProtectionPlan>, u32> {
        self.prepare_protection_range(owner, page, WORKING_SET_PAGE_SIZE, protection)
    }

    /// Prepare one uniform range change without allocating or changing backing residency.
    pub fn prepare_protection_range(
        &self,
        owner: WorkingSetOwnerId,
        base: u64,
        size: u64,
        protection: u32,
    ) -> Result<Option<PagefileProtectionPlan>, u32> {
        if base & (WORKING_SET_PAGE_SIZE - 1) != 0
            || size == 0
            || size & (WORKING_SET_PAGE_SIZE - 1) != 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let end = base.checked_add(size).ok_or(STATUS_INVALID_PARAMETER)?;
        if !self.memory_available(owner, base, size) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if !self.records.iter().any(|record| {
            record.page.owner == owner
                && record.page.page >= base
                && record.page.page < end
                && record.page.protection != protection
        }) {
            return Ok(None);
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(Some(PagefileProtectionPlan {
            store_id: self.identity,
            generation: self.generation,
            next_generation,
            owner,
            base,
            end,
            protection,
        }))
    }

    pub fn commit_protection(&mut self, plan: PagefileProtectionPlan) -> Result<(), u32> {
        if self.identity == 0
            || self.identity != plan.store_id
            || self.generation != plan.generation
            || !self.memory_available(plan.owner, plan.base, plan.end - plan.base)
        {
            self.stats.stale_commits = self.stats.stale_commits.saturating_add(1);
            return Err(STATUS_INVALID_PARAMETER);
        }
        for record in &mut self.records {
            if record.page.owner == plan.owner
                && record.page.page >= plan.base
                && record.page.page < plan.end
            {
                record.page.protection = plan.protection;
            }
        }
        self.generation = plan.next_generation;
        Ok(())
    }

    pub fn take(
        &mut self,
        owner: WorkingSetOwnerId,
        page: u64,
    ) -> Result<Option<PagefilePage>, u32> {
        let Some(index) = self.index_for(owner, page) else {
            return Ok(None);
        };
        if self.records[index].state != PagefileState::Available {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let record = self.records.swap_remove(index);
        self.generation = next_generation;
        self.stats.pages = self.records.len();
        self.stats.takes = self.stats.takes.saturating_add(1);
        Ok(Some(record.page))
    }

    pub fn restore(&mut self, page: PagefilePage) -> Result<(), u32> {
        let plan = self.prepare_publish(page)?;
        self.commit_insert(plan, true)
    }

    pub fn first_for_owner(&self, owner: WorkingSetOwnerId) -> Option<PagefilePage> {
        self.records
            .iter()
            .find(|record| record.page.owner == owner)
            .map(|record| record.page)
    }

    pub fn pages_for_owner(&self, owner: WorkingSetOwnerId) -> impl Iterator<Item = u64> + '_ {
        self.records
            .iter()
            .filter(move |record| record.page.owner == owner)
            .map(|record| record.page.page)
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
        table.register(4, 20, 32).unwrap();
        let pages: Vec<_> = (0..32)
            .map(|index| page(0x1000 + index * 0x1000, index))
            .collect();
        let limits = table
            .prepare_adjustment(4, 20 * 0x1000, 32 * 0x1000, true, true, &pages)
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
    fn requested_minimum_is_clamped_to_the_native_process_floor() {
        let mut table = WorkingSetTable::new();
        table.register(2, 20, 45).unwrap();
        let plan = table
            .prepare_adjustment(2, 1, 30 * WORKING_SET_PAGE_SIZE, true, true, &[])
            .unwrap();
        assert_eq!(plan.limits().minimum_pages, 20);
    }

    #[test]
    fn non_evictable_entries_count_ahead_of_the_fluid_reserve() {
        let mut table = WorkingSetTable::new();
        table.register(2, 20, 45).unwrap();
        let mut pages: Vec<_> = (0..9)
            .map(|index| page(0x1000 + index * 0x1000, index))
            .collect();
        pages[0].evictable = false;
        assert_eq!(
            table.prepare_adjustment(2, 0, 9 * WORKING_SET_PAGE_SIZE, true, true, &pages,),
            Err(STATUS_BAD_WORKING_SET_LIMIT)
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
    fn pagefile_transition_is_reserved_before_publication_and_restorable() {
        let mut store = PagefileStore::new();
        let page = PagefilePage {
            owner: 7,
            page: 0x20_000,
            protection: 0x04,
            backing: 0x4d5a,
        };
        let plan = store.prepare_publish(page).unwrap();
        assert!(store.page(7, 0x20_000).is_none());
        store.commit_publish(plan).unwrap();
        assert_eq!(store.page(7, 0x20_000), Some(page));
        let taken = store.take(7, 0x20_000).unwrap().unwrap();
        assert!(store.page(7, 0x20_000).is_none());
        store.restore(taken).unwrap();
        assert_eq!(store.page(7, 0x20_000), Some(page));
    }

    #[test]
    fn stale_pagefile_plan_cannot_publish_after_a_newer_transition() {
        let mut store = PagefileStore::new();
        let old = store
            .prepare_publish(PagefilePage {
                owner: 7,
                page: 0x20_000,
                protection: 0x04,
                backing: 1,
            })
            .unwrap();
        let new = store
            .prepare_publish(PagefilePage {
                owner: 7,
                page: 0x30_000,
                protection: 0x04,
                backing: 2,
            })
            .unwrap();
        store.commit_publish(new).unwrap();
        assert_eq!(store.commit_publish(old), Err(STATUS_INVALID_PARAMETER));
        assert!(store.page(7, 0x20_000).is_none());
    }

    #[test]
    fn pagefile_protection_change_is_prepared_without_mutating_backing() {
        let mut store = PagefileStore::new();
        let original = PagefilePage {
            owner: 7,
            page: 0x1000,
            protection: 0x104,
            backing: 0xabcd,
        };
        let publish = store.prepare_publish(original).unwrap();
        store.commit_publish(publish).unwrap();
        let change = store.prepare_protection(7, 0x1000, 0x04).unwrap().unwrap();
        assert_eq!(store.page(7, 0x1000), Some(original));
        store.commit_protection(change).unwrap();
        let updated = store.take(7, 0x1000).unwrap().unwrap();
        assert_eq!(
            updated,
            PagefilePage {
                protection: 0x04,
                ..original
            }
        );
        store.restore(updated).unwrap();
        assert_eq!(store.page(7, 0x1000), Some(updated));
        assert_eq!(store.stats().publications, 1);
    }

    #[test]
    fn stale_protection_plan_cannot_change_replaced_transition_backing() {
        let mut store = PagefileStore::new();
        let original = PagefilePage {
            owner: 7,
            page: 0x1000,
            protection: 0x104,
            backing: 1,
        };
        let publish = store.prepare_publish(original).unwrap();
        store.commit_publish(publish).unwrap();
        let change = store.prepare_protection(7, 0x1000, 0x04).unwrap().unwrap();
        store.take(7, 0x1000).unwrap();
        let replacement = PagefilePage {
            backing: 2,
            ..original
        };
        store.restore(replacement).unwrap();
        assert_eq!(
            store.commit_protection(change),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(store.page(7, 0x1000), Some(replacement));
    }

    #[test]
    fn protection_updates_isolate_owners_and_invalidate_older_publication_plans() {
        let mut store = PagefileStore::new();
        for owner in [7, 8] {
            let publish = store
                .prepare_publish(PagefilePage {
                    owner,
                    page: 0x1000,
                    protection: 0x104,
                    backing: owner,
                })
                .unwrap();
            store.commit_publish(publish).unwrap();
        }
        let publish = store
            .prepare_publish(PagefilePage {
                owner: 7,
                page: 0x2000,
                protection: 0x04,
                backing: 9,
            })
            .unwrap();
        let change = store.prepare_protection(7, 0x1000, 0x04).unwrap().unwrap();
        store.commit_protection(change).unwrap();
        assert_eq!(store.page(8, 0x1000).unwrap().protection, 0x104);
        assert_eq!(store.commit_publish(publish), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(store.prepare_protection(7, 0x2000, 0x04), Ok(None));
        assert_eq!(store.prepare_protection(7, 0x1000, 0x04), Ok(None));
        assert_eq!(
            store.prepare_protection(7, 0x1001, 0x04),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn protection_generation_exhaustion_fails_before_any_mutation() {
        let mut store = PagefileStore::new();
        let original = PagefilePage {
            owner: 7,
            page: 0x1000,
            protection: 0x104,
            backing: 1,
        };
        let publish = store.prepare_publish(original).unwrap();
        store.commit_publish(publish).unwrap();
        store.generation = u64::MAX;
        assert_eq!(
            store.prepare_protection(7, 0x1000, 0x04),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(store.page(7, 0x1000), Some(original));
    }

    #[test]
    fn protection_range_updates_one_owner_once_and_preserves_sparse_backing() {
        let mut store = PagefileStore::new();
        for (owner, page, protection, backing) in [
            (7, 0x1000, 0x104, 1),
            (7, 0x3000, 0x40, 2),
            (7, 0x4000, 0x04, 3),
            (8, 0x1000, 0x04, 4),
        ] {
            let publish = store
                .prepare_publish(PagefilePage {
                    owner,
                    page,
                    protection,
                    backing,
                })
                .unwrap();
            store.commit_publish(publish).unwrap();
        }
        let original = store.records.clone();
        let generation = store.generation;
        let plan = store
            .prepare_protection_range(7, 0x1000, 0x3000, 0x02)
            .unwrap()
            .unwrap();
        assert_eq!(store.records, original);
        store.commit_protection(plan).unwrap();
        assert_eq!(store.generation, generation + 1);
        for record in original {
            let record = record.page;
            let expected = if record.owner == 7 && record.page < 0x4000 {
                PagefilePage {
                    protection: 0x02,
                    ..record
                }
            } else {
                record
            };
            assert_eq!(store.page(record.owner, record.page), Some(expected));
        }
        assert!(!store.contains(7, 0x2000));
        assert_eq!(store.stats().pages, 4);
        assert_eq!(store.stats().restores, 0);
        assert_eq!(store.stats().takes, 0);
    }

    #[test]
    fn rejected_or_stale_range_plan_changes_no_transition() {
        let mut store = PagefileStore::new();
        for page in [0x1000, 0x2000] {
            let publish = store
                .prepare_publish(PagefilePage {
                    owner: 7,
                    page,
                    protection: 0x104,
                    backing: page,
                })
                .unwrap();
            store.commit_publish(publish).unwrap();
        }
        let before = store.records.clone();
        let abandoned = store
            .prepare_protection_range(7, 0x1000, 0x2000, 0x01)
            .unwrap()
            .unwrap();
        assert_eq!(store.records, before);
        let newer = store.prepare_protection(7, 0x1000, 0x04).unwrap().unwrap();
        store.commit_protection(newer).unwrap();
        let updated = store.records.clone();
        assert_eq!(
            store.commit_protection(abandoned),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(store.records, updated);
    }

    #[test]
    fn protection_range_validation_and_noops_do_not_reserve_generations() {
        let mut store = PagefileStore::new();
        let publish = store
            .prepare_publish(PagefilePage {
                owner: 7,
                page: 0x1000,
                protection: 0x104,
                backing: 1,
            })
            .unwrap();
        store.commit_publish(publish).unwrap();
        for (base, size) in [
            (0x1001, 0x1000),
            (0x1000, 0),
            (0x1000, 1),
            (u64::MAX & !0xfff, 0x1000),
        ] {
            assert_eq!(
                store.prepare_protection_range(7, base, size, 0x04),
                Err(STATUS_INVALID_PARAMETER)
            );
        }
        store.generation = u64::MAX;
        assert_eq!(
            store.prepare_protection_range(7, 0x1000, 0x3000, 0x104),
            Ok(None)
        );
        assert_eq!(
            store.prepare_protection_range(8, 0x1000, 0x3000, 0x04),
            Ok(None)
        );
        assert_eq!(
            store.prepare_protection_range(7, 0x2000, 0x3000, 0x04),
            Ok(None)
        );
        assert_eq!(
            store.prepare_protection_range(7, 0x1000, 0x3000, 0x04),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(store.page(7, 0x1000).unwrap().protection, 0x104);
    }

    #[test]
    fn private_page_enumeration_follows_owner_and_transition_lifetime() {
        let mut store = PagefileStore::new();
        for (owner, page, backing) in [(2, 0x1000, 1), (2, 0x2000, 2), (3, 0x1000, 3)] {
            let plan = store
                .prepare_publish(PagefilePage {
                    owner,
                    page,
                    protection: 0x04,
                    backing,
                })
                .unwrap();
            store.commit_publish(plan).unwrap();
        }
        assert_eq!(
            store.pages_for_owner(2).collect::<Vec<_>>(),
            [0x1000, 0x2000]
        );
        assert_eq!(store.pages_for_owner(3).collect::<Vec<_>>(), [0x1000]);
        let taken = store.take(2, 0x1000).unwrap().unwrap();
        assert_eq!(store.pages_for_owner(2).collect::<Vec<_>>(), [0x2000]);
        store.restore(taken).unwrap();
        let protection = store
            .prepare_protection_range(2, 0x1000, 0x2000, 0x02)
            .unwrap()
            .unwrap();
        store.commit_protection(protection).unwrap();
        let mut pages = store.pages_for_owner(2).collect::<Vec<_>>();
        pages.sort_unstable();
        assert_eq!(pages, [0x1000, 0x2000]);
        assert_eq!(store.pages_for_owner(4).count(), 0);
    }

    #[test]
    fn owner_rundown_enumerates_only_its_transition_records() {
        let mut store = PagefileStore::new();
        for (owner, page, backing) in [(2, 0x1000, 1), (2, 0x2000, 2), (3, 0x1000, 3)] {
            let plan = store
                .prepare_publish(PagefilePage {
                    owner,
                    page,
                    protection: 0x04,
                    backing,
                })
                .unwrap();
            store.commit_publish(plan).unwrap();
        }
        let mut removed = 0;
        while let Some(page) = store.first_for_owner(2) {
            assert_eq!(store.take(2, page.page), Ok(Some(page)));
            removed += 1;
        }
        assert_eq!(removed, 2);
        assert!(store.page(2, 0x1000).is_none());
        assert_eq!(store.page(3, 0x1000).unwrap().backing, 3);
    }
}
