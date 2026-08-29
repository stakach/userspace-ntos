use alloc::vec::Vec;

pub const PAGE_SIZE: u64 = 0x1000;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const STATUS_COMMITMENT_LIMIT: u32 = 0xC000_012D;

pub type CommitOwnerId = u32;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessCommitAccounting {
    pub current_bytes: u64,
    pub peak_bytes: u64,
    /// Zero means no per-process limit.
    pub limit_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitChargePlan {
    owner: CommitOwnerId,
    previous_bytes: u64,
    next_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitLimitPlan {
    owner: CommitOwnerId,
    previous_limit_bytes: u64,
    next_limit_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessCommitRecord {
    owner: CommitOwnerId,
    accounting: ProcessCommitAccounting,
}

/// Memory Manager authority for per-process private commitment.
///
/// A caller first prepares a charge, asks any higher-level quota owner to admit the same delta,
/// performs the address-space mutation, and commits this plan only after the mutation succeeds.
/// The executive is serialized today, but the previous-value check keeps stale plans from silently
/// corrupting accounting when that changes.
#[derive(Default)]
pub struct ProcessCommitLedger {
    records: Vec<ProcessCommitRecord>,
}

impl ProcessCommitLedger {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    fn validate_page_bytes(bytes: u64) -> Result<(), u32> {
        if bytes & (PAGE_SIZE - 1) != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(())
    }

    fn index(&self, owner: CommitOwnerId) -> Option<usize> {
        self.records.iter().position(|record| record.owner == owner)
    }

    pub fn register(&mut self, owner: CommitOwnerId, initial_bytes: u64) -> Result<(), u32> {
        self.register_with_limit(owner, initial_bytes, 0)
    }

    pub fn register_with_limit(
        &mut self,
        owner: CommitOwnerId,
        initial_bytes: u64,
        limit_bytes: u64,
    ) -> Result<(), u32> {
        Self::validate_page_bytes(initial_bytes)?;
        Self::validate_page_bytes(limit_bytes)?;
        if limit_bytes != 0 && initial_bytes > limit_bytes {
            return Err(STATUS_COMMITMENT_LIMIT);
        }
        if self.index(owner).is_some() {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        }
        self.records
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        self.records.push(ProcessCommitRecord {
            owner,
            accounting: ProcessCommitAccounting {
                current_bytes: initial_bytes,
                peak_bytes: initial_bytes,
                limit_bytes,
            },
        });
        Ok(())
    }

    pub fn contains(&self, owner: CommitOwnerId) -> bool {
        self.index(owner).is_some()
    }

    pub fn accounting(&self, owner: CommitOwnerId) -> Option<ProcessCommitAccounting> {
        self.index(owner)
            .map(|index| self.records[index].accounting)
    }

    pub fn set_limit(&mut self, owner: CommitOwnerId, limit_bytes: u64) -> Result<(), u32> {
        let plan = self.prepare_limit_update(owner, limit_bytes)?;
        self.commit_limit_update(plan).map(|_| ())
    }

    pub fn prepare_limit_update(
        &self,
        owner: CommitOwnerId,
        limit_bytes: u64,
    ) -> Result<CommitLimitPlan, u32> {
        Self::validate_page_bytes(limit_bytes)?;
        let index = self.index(owner).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(CommitLimitPlan {
            owner,
            previous_limit_bytes: self.records[index].accounting.limit_bytes,
            next_limit_bytes: limit_bytes,
        })
    }

    pub fn commit_limit_update(
        &mut self,
        plan: CommitLimitPlan,
    ) -> Result<ProcessCommitAccounting, u32> {
        let owner = plan.owner;
        self.commit_limit_updates(&[plan])?;
        self.accounting(owner).ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn commit_limit_updates(&mut self, plans: &[CommitLimitPlan]) -> Result<(), u32> {
        for (position, plan) in plans.iter().enumerate() {
            let index = self.index(plan.owner).ok_or(STATUS_INVALID_HANDLE)?;
            if self.records[index].accounting.limit_bytes != plan.previous_limit_bytes
                || plans[..position]
                    .iter()
                    .any(|previous| previous.owner == plan.owner)
            {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
        }
        for plan in plans {
            let index = self
                .index(plan.owner)
                .expect("validated commit owner remains present during serialized publication");
            self.records[index].accounting.limit_bytes = plan.next_limit_bytes;
        }
        Ok(())
    }

    pub fn prepare_charge(
        &self,
        owner: CommitOwnerId,
        bytes: u64,
    ) -> Result<CommitChargePlan, u32> {
        Self::validate_page_bytes(bytes)?;
        if bytes == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let accounting = self.accounting(owner).ok_or(STATUS_INVALID_HANDLE)?;
        let next_bytes = accounting
            .current_bytes
            .checked_add(bytes)
            .ok_or(STATUS_COMMITMENT_LIMIT)?;
        if accounting.limit_bytes != 0 && next_bytes > accounting.limit_bytes {
            return Err(STATUS_COMMITMENT_LIMIT);
        }
        Ok(CommitChargePlan {
            owner,
            previous_bytes: accounting.current_bytes,
            next_bytes,
        })
    }

    pub fn commit_charge(
        &mut self,
        plan: CommitChargePlan,
    ) -> Result<ProcessCommitAccounting, u32> {
        let index = self.index(plan.owner).ok_or(STATUS_INVALID_HANDLE)?;
        let accounting = &mut self.records[index].accounting;
        if accounting.current_bytes != plan.previous_bytes {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        }
        accounting.current_bytes = plan.next_bytes;
        accounting.peak_bytes = accounting.peak_bytes.max(plan.next_bytes);
        Ok(*accounting)
    }

    pub fn release(
        &mut self,
        owner: CommitOwnerId,
        bytes: u64,
    ) -> Result<ProcessCommitAccounting, u32> {
        Self::validate_page_bytes(bytes)?;
        let index = self.index(owner).ok_or(STATUS_INVALID_HANDLE)?;
        let accounting = &mut self.records[index].accounting;
        accounting.current_bytes = accounting
            .current_bytes
            .checked_sub(bytes)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        Ok(*accounting)
    }

    pub fn unregister(&mut self, owner: CommitOwnerId) -> Option<ProcessCommitAccounting> {
        let index = self.index(owner)?;
        Some(self.records.swap_remove(index).accounting)
    }

    pub fn owner_count(&self) -> usize {
        self.records.len()
    }
}
