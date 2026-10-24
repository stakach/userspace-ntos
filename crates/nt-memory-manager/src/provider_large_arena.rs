//! Inline ownership ledger for a provider-only demand-mapped pool.
//!
//! The executive and provider share image data but have distinct heaps. No heap pointer may
//! occur in this structure: both sides must see the same allocation and page-effect state.

pub const PAGE_SIZE: u64 = 0x1000;
pub const MAX_PAGES: usize = 16_384;
// Every arena page may be a distinct allocation, so metadata cannot cap the arena early.
pub const MAX_ALLOCATIONS: usize = MAX_PAGES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LargeAllocation {
    pub base: u64,
    pub capacity: u64,
    pub generation: u64,
}

/// Catalog identity published after successful registration. The paired allocation supplies
/// the exact catalog snapshot base and capacity, which `publish` verifies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LargePublication {
    pub arena_id: u64,
    pub arena_generation: u64,
    pub allocation_id: u64,
    pub allocation_generation: u64,
}

impl LargePublication {
    pub const fn is_valid(self) -> bool {
        self.arena_id != 0 && self.arena_generation != 0
            && self.allocation_id != 0 && self.allocation_generation != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LargeArenaError {
    InvalidArena, InvalidSize, OutOfSpace, NoCapacity, IdentityExhausted,
    OutsideArena, UnreservedPage, Protection, InvalidPage, StaleAllocation,
    EffectInProgress, Retiring, Quarantined, Unpublished, InvalidPublication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageMapDecision { Map, AlreadyMapped }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AllocationState { Reserved, Published, Retiring, Quarantined }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PageState { Uncommitted, Mapping, Mapped, Unmapping, Quarantined }

#[derive(Clone, Copy)]
struct Page {
    owner: u16, // allocation record index plus one; zero means free
    state: PageState,
    cap: u64,
}

impl Page {
    const EMPTY: Self = Self { owner: 0, state: PageState::Uncommitted, cap: 0 };
}

#[derive(Clone, Copy)]
struct Record {
    used: bool,
    base_page: u16,
    page_count: u16,
    generation: u64,
    state: AllocationState,
    publication: Option<LargePublication>,
}

impl Record {
    const EMPTY: Self = Self {
        used: false, base_page: 0, page_count: 0, generation: 0,
        state: AllocationState::Reserved, publication: None,
    };

    fn allocation(self, arena_base: u64) -> LargeAllocation {
        LargeAllocation {
            base: arena_base + u64::from(self.base_page) * PAGE_SIZE,
            capacity: u64::from(self.page_count) * PAGE_SIZE,
            generation: self.generation,
        }
    }
}

/// Fixed-capacity, page-granular first-fit arena with no heap-backed metadata.
pub struct LargeArena {
    base: u64,
    end: u64,
    page_count: usize,
    next_generation: u64,
    allocation_count: usize,
    pages: [Page; MAX_PAGES],
    records: [Record; MAX_ALLOCATIONS],
}

impl LargeArena {
    /// `const` lets native initialize the shared-image static without a bounded-stack copy.
    pub const fn new(base: u64, bytes: u64) -> Result<Self, LargeArenaError> {
        if base == 0 || bytes == 0 || base % PAGE_SIZE != 0 || bytes % PAGE_SIZE != 0
            || bytes / PAGE_SIZE > MAX_PAGES as u64
        { return Err(LargeArenaError::InvalidArena); }
        let end = match base.checked_add(bytes) {
            Some(end) => end,
            None => return Err(LargeArenaError::InvalidArena),
        };
        Ok(Self {
            base, end, page_count: (bytes / PAGE_SIZE) as usize,
            next_generation: 1, allocation_count: 0,
            pages: [Page::EMPTY; MAX_PAGES],
            records: [Record::EMPTY; MAX_ALLOCATIONS],
        })
    }

    pub const fn contains(&self, address: u64) -> bool {
        address >= self.base && address < self.end
    }

    pub const fn allocation_count(&self) -> usize { self.allocation_count }

    /// Reserve all payload pages before catalog registration; faults remain unpublished.
    pub fn reserve(&mut self, bytes: u64) -> Result<LargeAllocation, LargeArenaError> {
        let capacity = bytes.checked_add(PAGE_SIZE - 1)
            .map(|sum| sum & !(PAGE_SIZE - 1))
            .filter(|capacity| *capacity != 0)
            .ok_or(LargeArenaError::InvalidSize)?;
        let wanted = usize::try_from(capacity / PAGE_SIZE).map_err(|_| LargeArenaError::OutOfSpace)?;
        if wanted > self.page_count { return Err(LargeArenaError::OutOfSpace); }
        let record_index = self.records.iter().position(|record| !record.used)
            .ok_or(LargeArenaError::NoCapacity)?;
        let mut first = 0usize;
        let base_page = loop {
            if first + wanted > self.page_count { return Err(LargeArenaError::OutOfSpace); }
            match self.pages[first..first + wanted].iter().position(|page| page.owner != 0) {
                None => break first,
                Some(occupied) => first += occupied + 1,
            }
        };
        let next = self.next_generation.checked_add(1)
            .ok_or(LargeArenaError::IdentityExhausted)?;
        let record = Record {
            used: true, base_page: base_page as u16, page_count: wanted as u16,
            generation: self.next_generation, state: AllocationState::Reserved,
            publication: None,
        };
        self.records[record_index] = record;
        for page in &mut self.pages[base_page..base_page + wanted] {
            *page = Page { owner: record_index as u16 + 1, ..Page::EMPTY };
        }
        self.next_generation = next;
        self.allocation_count += 1;
        Ok(record.allocation(self.base))
    }

    /// Publish only the exact catalog snapshot returned by registration.
    pub fn publish(&mut self, allocation: LargeAllocation, publication: LargePublication,
        catalog_base: u64, catalog_capacity: u64) -> Result<(), LargeArenaError>
    {
        if !publication.is_valid() || catalog_base != allocation.base
            || catalog_capacity != allocation.capacity
        { return Err(LargeArenaError::InvalidPublication); }
        let record = self.exact_mut(allocation)?;
        if record.state != AllocationState::Reserved || record.publication.is_some() {
            return Err(LargeArenaError::InvalidPublication);
        }
        record.publication = Some(publication);
        record.state = AllocationState::Published;
        Ok(())
    }

    pub fn publication(&self, allocation: LargeAllocation)
        -> Result<LargePublication, LargeArenaError>
    {
        let record = self.exact(allocation)?;
        match record.state {
            AllocationState::Published => record.publication.ok_or(LargeArenaError::Unpublished),
            AllocationState::Reserved => Err(LargeArenaError::Unpublished),
            AllocationState::Retiring => Err(LargeArenaError::Retiring),
            AllocationState::Quarantined => Err(LargeArenaError::Quarantined),
        }
    }

    /// Root-side retirement broker reads only shared inline metadata. The provider's catalog
    /// lives in its private heap, so its exact published witness is retained here until every
    /// root-owned page cap has been released and the provider commits retirement.
    pub fn retiring_snapshot(&self, base: u64, generation: u64)
        -> Result<(LargeAllocation, LargePublication), LargeArenaError>
    {
        let record = self.records.iter().find(|record|
            record.used && record.generation == generation
                && record.allocation(self.base).base == base)
            .ok_or(LargeArenaError::StaleAllocation)?;
        if record.state != AllocationState::Retiring {
            return Err(LargeArenaError::Retiring);
        }
        let publication = record.publication.ok_or(LargeArenaError::Unpublished)?;
        Ok((record.allocation(self.base), publication))
    }

    /// Admit only a published allocation's non-present data fault.
    pub fn authorize_fault(&self, address: u64, fault_status: u64)
        -> Result<LargeAllocation, LargeArenaError>
    {
        if !self.contains(address) { return Err(LargeArenaError::OutsideArena); }
        if fault_status & !6 != 0 { return Err(LargeArenaError::Protection); }
        let page = ((address - self.base) / PAGE_SIZE) as usize;
        let owner = self.pages[page].owner;
        if owner == 0 { return Err(LargeArenaError::UnreservedPage); }
        let record = &self.records[usize::from(owner - 1)];
        if !record.used { return Err(LargeArenaError::UnreservedPage); }
        match record.state {
            AllocationState::Published => Ok(record.allocation(self.base)),
            AllocationState::Reserved => Err(LargeArenaError::Unpublished),
            AllocationState::Retiring => Err(LargeArenaError::Retiring),
            AllocationState::Quarantined => Err(LargeArenaError::Quarantined),
        }
    }

    pub fn begin_page_map(&mut self, allocation: LargeAllocation, address: u64, cap: u64)
        -> Result<PageMapDecision, LargeArenaError>
    {
        let index = self.exact_index(allocation)?;
        if self.records[index].state != AllocationState::Published {
            return Err(self.state_error(index));
        }
        let page = self.page_index(index, address)?;
        match self.pages[page].state {
            PageState::Mapped => Ok(PageMapDecision::AlreadyMapped),
            PageState::Quarantined => Err(LargeArenaError::Quarantined),
            PageState::Mapping | PageState::Unmapping => Err(LargeArenaError::EffectInProgress),
            PageState::Uncommitted => {
                if cap == 0 { return Err(LargeArenaError::InvalidPage); }
                self.pages[page].cap = cap;
                self.pages[page].state = PageState::Mapping;
                Ok(PageMapDecision::Map)
            }
        }
    }

    pub fn complete_page_map(&mut self, allocation: LargeAllocation, address: u64)
        -> Result<(), LargeArenaError>
    { self.transition_page(allocation, address, PageState::Mapping, PageState::Mapped) }

    pub fn quarantine_page_map(&mut self, allocation: LargeAllocation, address: u64)
        -> Result<(), LargeArenaError>
    {
        let index = self.exact_index(allocation)?;
        let page = self.page_index(index, address)?;
        if self.pages[page].state != PageState::Mapping {
            return Err(LargeArenaError::EffectInProgress);
        }
        self.pages[page].state = PageState::Quarantined;
        self.records[index].state = AllocationState::Quarantined;
        Ok(())
    }

    pub fn page_cap(&self, allocation: LargeAllocation, address: u64)
        -> Result<Option<u64>, LargeArenaError>
    {
        let index = self.exact_index(allocation)?;
        let page = self.page_index(index, address)?;
        Ok((self.pages[page].cap != 0).then_some(self.pages[page].cap))
    }

    pub fn begin_retirement(&mut self, allocation: LargeAllocation)
        -> Result<(), LargeArenaError>
    {
        let index = self.exact_index(allocation)?;
        match self.records[index].state {
            AllocationState::Retiring => return Err(LargeArenaError::Retiring),
            AllocationState::Quarantined => return Err(LargeArenaError::Quarantined),
            AllocationState::Reserved | AllocationState::Published => {}
        }
        let start = usize::from(self.records[index].base_page);
        let end = start + usize::from(self.records[index].page_count);
        if self.pages[start..end].iter().any(|page|
            !matches!(page.state, PageState::Uncommitted | PageState::Mapped))
        { return Err(LargeArenaError::EffectInProgress); }
        self.records[index].state = AllocationState::Retiring;
        Ok(())
    }

    pub fn begin_page_unmap(&mut self, allocation: LargeAllocation, address: u64)
        -> Result<(), LargeArenaError>
    {
        let index = self.exact_index(allocation)?;
        if self.records[index].state != AllocationState::Retiring {
            return Err(self.state_error(index));
        }
        let page = self.page_index(index, address)?;
        if self.pages[page].state != PageState::Mapped {
            return Err(LargeArenaError::EffectInProgress);
        }
        self.pages[page].state = PageState::Unmapping;
        Ok(())
    }

    /// Call only after both native unmap and cap deletion have confirmed success.
    pub fn complete_page_unmap(&mut self, allocation: LargeAllocation, address: u64)
        -> Result<(), LargeArenaError>
    {
        let index = self.exact_index(allocation)?;
        let page = self.page_index(index, address)?;
        if self.pages[page].state != PageState::Unmapping {
            return Err(LargeArenaError::EffectInProgress);
        }
        self.pages[page].state = PageState::Uncommitted;
        self.pages[page].cap = 0;
        Ok(())
    }

    pub fn quarantine_page_unmap(&mut self, allocation: LargeAllocation, address: u64)
        -> Result<(), LargeArenaError>
    {
        let index = self.exact_index(allocation)?;
        let page = self.page_index(index, address)?;
        if self.pages[page].state != PageState::Unmapping {
            return Err(LargeArenaError::EffectInProgress);
        }
        self.pages[page].state = PageState::Quarantined;
        self.records[index].state = AllocationState::Quarantined;
        Ok(())
    }

    pub fn complete_retirement(&mut self, allocation: LargeAllocation)
        -> Result<(), LargeArenaError>
    {
        let index = self.exact_index(allocation)?;
        if self.records[index].state != AllocationState::Retiring {
            return Err(self.state_error(index));
        }
        let start = usize::from(self.records[index].base_page);
        let end = start + usize::from(self.records[index].page_count);
        if self.pages[start..end].iter().any(|page|
            page.state != PageState::Uncommitted || page.cap != 0)
        { return Err(LargeArenaError::EffectInProgress); }
        for page in &mut self.pages[start..end] { *page = Page::EMPTY; }
        self.records[index] = Record::EMPTY;
        self.allocation_count -= 1;
        Ok(())
    }

    fn transition_page(&mut self, allocation: LargeAllocation, address: u64,
        old: PageState, new: PageState) -> Result<(), LargeArenaError>
    {
        let index = self.exact_index(allocation)?;
        let page = self.page_index(index, address)?;
        if self.pages[page].state != old { return Err(LargeArenaError::EffectInProgress); }
        self.pages[page].state = new;
        Ok(())
    }

    fn exact_index(&self, allocation: LargeAllocation) -> Result<usize, LargeArenaError> {
        self.records.iter().position(|record|
            record.used && record.allocation(self.base) == allocation)
            .ok_or(LargeArenaError::StaleAllocation)
    }

    fn exact(&self, allocation: LargeAllocation) -> Result<&Record, LargeArenaError> {
        Ok(&self.records[self.exact_index(allocation)?])
    }

    fn exact_mut(&mut self, allocation: LargeAllocation) -> Result<&mut Record, LargeArenaError> {
        let index = self.exact_index(allocation)?;
        Ok(&mut self.records[index])
    }

    fn page_index(&self, record_index: usize, address: u64)
        -> Result<usize, LargeArenaError>
    {
        let record = self.records[record_index];
        let allocation = record.allocation(self.base);
        if address % PAGE_SIZE != 0 || address < allocation.base
            || address >= allocation.base + allocation.capacity
        { return Err(LargeArenaError::InvalidPage); }
        let page = ((address - self.base) / PAGE_SIZE) as usize;
        if self.pages[page].owner != record_index as u16 + 1 {
            return Err(LargeArenaError::StaleAllocation);
        }
        Ok(page)
    }

    fn state_error(&self, record_index: usize) -> LargeArenaError {
        match self.records[record_index].state {
            AllocationState::Reserved => LargeArenaError::Unpublished,
            AllocationState::Published => LargeArenaError::EffectInProgress,
            AllocationState::Retiring => LargeArenaError::Retiring,
            AllocationState::Quarantined => LargeArenaError::Quarantined,
        }
    }
}
