use super::{
    PagefilePage, PagefileRecord, PagefileState, PagefileStore, WorkingSetOwnerId,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, WORKING_SET_PAGE_SIZE,
};

/// An exact, immutable retirement revision. Obtain a fresh snapshot after a failed cleanup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagefileRetirement {
    store_id: u64,
    record_id: u64,
    page: PagefilePage,
    unmapped: bool,
    revoked: bool,
}

impl PagefileRetirement {
    pub const fn page(self) -> PagefilePage {
        self.page
    }

    pub const fn cleanup_complete(self) -> bool {
        self.unmapped && self.revoked
    }

    fn from_record(store_id: u64, record: PagefileRecord) -> Option<Self> {
        let PagefileState::Retiring { unmapped, revoked } = record.state else {
            return None;
        };
        Some(Self {
            store_id,
            record_id: record.id,
            page: record.page,
            unmapped,
            revoked,
        })
    }
}

/// Each successful operation acknowledges its complete effect. Failure must leave the backing
/// capability owned by the caller; implementations must not reenter the store.
pub trait PagefileRetirementIo {
    fn unmap(&mut self, backing: u64) -> Result<(), u32>;
    fn revoke(&mut self, backing: u64) -> Result<(), u32>;
}

impl PagefileStore {
    pub fn begin_retirement(
        &mut self,
        owner: WorkingSetOwnerId,
        page: u64,
    ) -> Result<Option<PagefileRetirement>, u32> {
        let Some(index) = self.index_for(owner, page) else {
            return Ok(None);
        };
        if let Some(snapshot) = PagefileRetirement::from_record(self.identity, self.records[index])
        {
            return Ok(Some(snapshot));
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        self.records[index].state = PagefileState::Retiring {
            unmapped: false,
            revoked: false,
        };
        self.generation = next_generation;
        self.stats.retiring += 1;
        Ok(PagefileRetirement::from_record(
            self.identity,
            self.records[index],
        ))
    }

    fn retirement_index_exact(&self, snapshot: PagefileRetirement) -> Result<usize, u32> {
        if self.identity == 0 || snapshot.store_id != self.identity {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let index = self
            .index_for(snapshot.page.owner, snapshot.page.page)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        if PagefileRetirement::from_record(self.identity, self.records[index]) != Some(snapshot) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(index)
    }

    pub fn cleanup_retirement_exact(
        &mut self,
        snapshot: PagefileRetirement,
        io: &mut impl PagefileRetirementIo,
    ) -> Result<PagefileRetirement, u32> {
        let index = self.retirement_index_exact(snapshot)?;
        let mut current = snapshot;
        if !current.unmapped {
            io.unmap(current.page.backing)?;
            current.unmapped = true;
            self.records[index].state = PagefileState::Retiring {
                unmapped: true,
                revoked: false,
            };
        }
        if !current.revoked {
            io.revoke(current.page.backing)?;
            current.revoked = true;
            self.records[index].state = PagefileState::Retiring {
                unmapped: true,
                revoked: true,
            };
        }
        Ok(current)
    }

    /// The terminal publication must be failure-atomic and must not yield or reenter the store.
    /// All store checks precede publication; successful publication is followed only by infallible
    /// removal and bookkeeping, without allocation or backend calls.
    pub fn complete_retirement_with(
        &mut self,
        snapshot: PagefileRetirement,
        publish: impl FnOnce(u64) -> Result<(), u32>,
    ) -> Result<(), u32> {
        let index = self.retirement_index_exact(snapshot)?;
        if !snapshot.cleanup_complete() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        publish(snapshot.page.backing)?;
        self.records.swap_remove(index);
        self.generation = next_generation;
        self.stats.pages = self.records.len();
        self.stats.retiring -= 1;
        self.stats.retirements = self.stats.retirements.saturating_add(1);
        Ok(())
    }

    pub fn retiring_count(&self) -> usize {
        self.stats.retiring
    }

    pub fn retirements(&self) -> impl Iterator<Item = PagefileRetirement> + '_ {
        self.records
            .iter()
            .filter_map(|record| PagefileRetirement::from_record(self.identity, *record))
    }

    /// Deny ordinary access to retained terminal ownership, without a scan in the common case.
    pub fn memory_available(&self, owner: WorkingSetOwnerId, base: u64, size: u64) -> bool {
        if size == 0 {
            return true;
        }
        let Some(end) = base.checked_add(size) else {
            return false;
        };
        if self.retiring_count() == 0 {
            return true;
        }
        !self.records.iter().any(|record| {
            if record.page.owner != owner || record.state == PagefileState::Available {
                return false;
            }
            let Some(page_end) = record.page.page.checked_add(WORKING_SET_PAGE_SIZE) else {
                return true;
            };
            base < page_end && record.page.page < end
        })
    }
}

#[cfg(test)]
#[path = "pagefile_retirement_tests.rs"]
mod tests;
