//! Selected range/accounting evidence retained until an ordinary thread's memory is retired.
use crate::process_identity::ProcessIdentity;
use crate::thread_resources::ThreadMemoryRange;
use crate::thread_rollback::{ThreadRollback, ThreadRollbackId, ThreadRollbackStage};
use alloc::vec::Vec;
use nt_address_space::{
    VmBasicInformation, VmCommittedRangeTable, VmRegionMap, MEM_COMMIT, MEM_PRIVATE, MEM_RELEASE,
    MEM_RESERVE, PAGE_SIZE, STATUS_CONFLICTING_ADDRESSES, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_PARAMETER,
};
use nt_memory_manager::ProcessCommitLedger;
use nt_process::{ProcessManager, ThreadLifetime};

/// The executor must use an exact pending-range permit and retain resident/pagefile cleanup
/// owners on failure. Success means both kinds of backing and all external aliases are gone.
/// These calls must be synchronous and must not reenter the owner or either VM table.
pub trait ThreadChargeRetirementIo {
    fn is_current(
        &self,
        id: ThreadRollbackId,
        process: ProcessIdentity,
        thread: ThreadLifetime,
    ) -> bool;
    fn retire_dynamic_page(&mut self, page: u64) -> Result<(), u32>;
}

/// Scratch tables are never retained by the owner. They must be disjoint from the canonical
/// tables and stay exclusively borrowed through the complete final publication.
pub struct ThreadChargeTables<'a, const FIXED: usize, const PRIVATE: usize> {
    pub fixed: &'a mut VmCommittedRangeTable<FIXED>,
    pub private: &'a mut VmRegionMap<PRIVATE>,
    pub fixed_scratch: &'a mut VmCommittedRangeTable<FIXED>,
    pub private_scratch: &'a mut VmRegionMap<PRIVATE>,
}

/// This is not page-release authority. The caller must retain the exact pending runtime and its
/// full-range exclusions, and bind all supplied tables/ledgers to that runtime's actual process.
/// In particular, a PI/PID pair alone does not authenticate an alternative table or manager.
/// No Drop path releases memory, ranges, accounting or pool/window reservations.
///
/// ```compile_fail
/// use nt_user_host::thread_charge_retirement::ThreadChargeRetirement;
/// fn duplicate(owner: &ThreadChargeRetirement) -> ThreadChargeRetirement { owner.clone() }
/// ```
#[must_use = "retain the charge owner until physical retirement and accounting commit finish"]
pub struct ThreadChargeRetirement {
    id: ThreadRollbackId,
    process: ProcessIdentity,
    thread: ThreadLifetime,
    fixed_ranges: Vec<ThreadMemoryRange>,
    fixed_witnesses: Vec<VmBasicInformation>,
    dynamic_range: Option<ThreadMemoryRange>,
    dynamic_witnesses: Vec<VmBasicInformation>,
    fixed_bytes: u64,
    dynamic_bytes: u64,
    dynamic_index: usize,
    dynamic_page: u64,
    fixed_complete: bool,
    committed: bool,
}

fn end(range: ThreadMemoryRange) -> Result<u64, u32> {
    if range.base == 0
        || range.base % PAGE_SIZE != 0
        || range.size == 0
        || range.size % PAGE_SIZE != 0
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    range
        .base
        .checked_add(range.size)
        .ok_or(STATUS_INVALID_PARAMETER)
}

fn same_attributes(a: VmBasicInformation, b: VmBasicInformation) -> bool {
    a.allocation_base == b.allocation_base
        && a.allocation_protect == b.allocation_protect
        && a.state == b.state
        && a.protect == b.protect
        && a.type_ == b.type_
}

fn capture(
    range: ThreadMemoryRange,
    mut query: impl FnMut(u64) -> Result<VmBasicInformation, u32>,
    output: &mut Vec<VmBasicInformation>,
    dynamic: bool,
) -> Result<u64, u32> {
    let limit = end(range)?;
    let mut page = range.base;
    let mut charge = 0u64;
    while page < limit {
        let mut info = query(page)?;
        let info_end = info
            .base_address
            .checked_add(info.region_size)
            .ok_or(STATUS_INVALID_PARAMETER)?
            .min(limit);
        if info.base_address > page
            || info_end <= page
            || info_end % PAGE_SIZE != 0
            || info.type_ != MEM_PRIVATE
            || !(info.state == MEM_COMMIT || dynamic && info.state == MEM_RESERVE)
            || dynamic && info.allocation_base != range.base
        {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        }
        info.base_address = page;
        info.region_size = info_end - page;
        if info.state == MEM_COMMIT {
            charge = charge
                .checked_add(info.region_size)
                .ok_or(STATUS_INVALID_PARAMETER)?;
        }
        output
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        output.push(info);
        page = info_end;
    }
    Ok(charge)
}

fn validate_witnesses(
    witnesses: &[VmBasicInformation],
    mut query: impl FnMut(u64) -> Result<VmBasicInformation, u32>,
) -> Result<(), u32> {
    for expected in witnesses {
        let limit = expected.base_address + expected.region_size;
        let mut page = expected.base_address;
        while page < limit {
            let current = query(page)?;
            let next = current
                .base_address
                .checked_add(current.region_size)
                .ok_or(STATUS_INVALID_PARAMETER)?
                .min(limit);
            if current.base_address > page || next <= page || !same_attributes(*expected, current) {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
            page = next;
        }
    }
    Ok(())
}

impl ThreadChargeRetirement {
    /// Capture only ranges actually owned by the runtime, after pending admission has closed
    /// their geometry. Main-thread and worker layouts need not charge the same TEB span.
    /// Missing fixed ranges are errors; no dynamic stack is represented explicitly by None.
    pub fn prepare<const F: usize, const V: usize>(
        id: ThreadRollbackId,
        process: ProcessIdentity,
        thread: ThreadLifetime,
        fixed_ranges: &[ThreadMemoryRange],
        dynamic_range: Option<ThreadMemoryRange>,
        fixed: &VmCommittedRangeTable<F>,
        private: &VmRegionMap<V>,
    ) -> Result<Self, u32> {
        let identity = id.identity();
        if !process.is_valid()
            || identity.pid != process.pid
            || identity.process_generation != process.generation
            || u64::from(thread.thread_id()) != identity.tid
            || thread.process_id() != process.pid
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if let Some(range) = dynamic_range {
            end(range)?;
        }
        for (index, range) in fixed_ranges.iter().copied().enumerate() {
            end(range)?;
            if fixed_ranges[..index]
                .iter()
                .any(|other| other.overlaps(range.base, range.size))
                || dynamic_range.is_some_and(|other| other.overlaps(range.base, range.size))
            {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
        }
        let mut owner = Self {
            id,
            process,
            thread,
            fixed_ranges: Vec::new(),
            fixed_witnesses: Vec::new(),
            dynamic_range,
            dynamic_witnesses: Vec::new(),
            fixed_bytes: 0,
            dynamic_bytes: 0,
            dynamic_index: 0,
            dynamic_page: 0,
            fixed_complete: false,
            committed: false,
        };
        owner
            .fixed_ranges
            .try_reserve_exact(fixed_ranges.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        owner.fixed_ranges.extend_from_slice(fixed_ranges);
        for range in fixed_ranges.iter().copied() {
            let bytes = capture(
                range,
                |page| fixed.query_basic(page).ok_or(STATUS_CONFLICTING_ADDRESSES),
                &mut owner.fixed_witnesses,
                false,
            )?;
            owner.fixed_bytes = owner
                .fixed_bytes
                .checked_add(bytes)
                .ok_or(STATUS_INVALID_PARAMETER)?;
        }
        if let Some(range) = dynamic_range {
            let limit = end(range)?;
            // Reject a truncated allocation claim without cloning or mutating the full VAD map.
            if private
                .extent_at(limit)
                .is_some_and(|entry| entry.allocation_base == range.base)
            {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
            owner.dynamic_bytes = capture(
                range,
                |page| private.query_basic(page, limit),
                &mut owner.dynamic_witnesses,
                true,
            )?;
        }
        owner
            .fixed_bytes
            .checked_add(owner.dynamic_bytes)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        Ok(owner)
    }

    pub fn owner(&self) -> ThreadRollbackId {
        self.id
    }
    pub fn charged_bytes(&self) -> u64 {
        self.fixed_bytes + self.dynamic_bytes
    }
    pub fn is_complete(&self) -> bool {
        self.committed
    }
    pub fn dynamic_pages_complete(&self) -> bool {
        self.dynamic_index == self.dynamic_witnesses.len()
    }

    fn validate_identity(
        &self,
        id: ThreadRollbackId,
        process: ProcessIdentity,
        thread: ThreadLifetime,
    ) -> Result<(), u32> {
        if id != self.id || process != self.process || thread != self.thread {
            Err(STATUS_INVALID_PARAMETER)
        } else {
            Ok(())
        }
    }

    /// Only the exact journal's post-transfer state acknowledges fixed physical retirement.
    pub fn acknowledge_fixed_retirement(&mut self, rollback: &ThreadRollback) -> Result<(), u32> {
        if rollback.id() != self.id
            || !matches!(
                rollback.stage(),
                ThreadRollbackStage::Commit | ThreadRollbackStage::Complete
            )
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.fixed_complete = true;
        Ok(())
    }

    /// A failed page is retried at the same cursor. No numeric cap inventory is cached here;
    /// the resident/pagefile tables retain their own checked partial cleanup states.
    pub fn advance_dynamic<const V: usize>(
        &mut self,
        id: ThreadRollbackId,
        process: ProcessIdentity,
        thread: ThreadLifetime,
        private: &VmRegionMap<V>,
        page_budget: usize,
        io: &mut impl ThreadChargeRetirementIo,
    ) -> Result<bool, u32> {
        self.validate_identity(id, process, thread)?;
        if self.committed {
            return Ok(true);
        }
        if !io.is_current(id, process, thread) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if let Some(range) = self.dynamic_range {
            let limit = end(range)?;
            if private
                .extent_at(limit)
                .is_some_and(|entry| entry.allocation_base == range.base)
            {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
            validate_witnesses(&self.dynamic_witnesses, |page| {
                private.query_basic(page, limit)
            })?;
        }
        let mut used = 0;
        while let Some(witness) = self.dynamic_witnesses.get(self.dynamic_index) {
            // Reserved pages contribute no charge but can still have a retained transition owner.
            let page = if self.dynamic_page == 0 {
                witness.base_address
            } else {
                self.dynamic_page
            };
            if used == page_budget {
                return Ok(false);
            }
            io.retire_dynamic_page(page)?;
            used += 1;
            let next = page + PAGE_SIZE;
            if next == witness.base_address + witness.region_size {
                self.dynamic_index += 1;
                self.dynamic_page = 0;
            } else {
                self.dynamic_page = next;
            }
        }
        Ok(true)
    }

    /// Rebuild candidates from current tables only after physical completion. Paired accounting
    /// release is the last fallible operation; publication and acknowledgement cannot reenter.
    pub fn commit<const F: usize, const V: usize>(
        &mut self,
        id: ThreadRollbackId,
        process: ProcessIdentity,
        thread: ThreadLifetime,
        tables: ThreadChargeTables<'_, F, V>,
        mm: &mut ProcessCommitLedger,
        pm: &mut ProcessManager,
    ) -> Result<(), u32> {
        self.validate_identity(id, process, thread)?;
        if self.committed {
            return Ok(());
        }
        if !pm.validate_thread_lifetime(thread)
            || !self.fixed_complete
            || !self.dynamic_pages_complete()
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        validate_witnesses(&self.fixed_witnesses, |page| {
            tables
                .fixed
                .query_basic(page)
                .ok_or(STATUS_CONFLICTING_ADDRESSES)
        })?;
        if let Some(range) = self.dynamic_range {
            let limit = end(range)?;
            if tables
                .private
                .extent_at(limit)
                .is_some_and(|entry| entry.allocation_base == range.base)
            {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
            validate_witnesses(&self.dynamic_witnesses, |page| {
                tables.private.query_basic(page, limit)
            })?;
        }
        *tables.fixed_scratch = *tables.fixed;
        *tables.private_scratch = *tables.private;
        for range in &self.fixed_ranges {
            tables
                .fixed_scratch
                .unregister_range(range.base, range.size)?;
        }
        if let Some(range) = self.dynamic_range {
            let plan = tables.private_scratch.free(range.base, 0, MEM_RELEASE)?;
            if plan.base != range.base || plan.size != range.size {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
        }
        if tables
            .fixed
            .process_commit_bytes()
            .checked_sub(tables.fixed_scratch.process_commit_bytes())
            != Some(self.fixed_bytes)
            || tables
                .private
                .private_committed_bytes()
                .checked_sub(tables.private_scratch.private_committed_bytes())
                != Some(self.dynamic_bytes)
        {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        }
        crate::commit_release::release(mm, pm, process.pid, self.charged_bytes())?;
        *tables.fixed = *tables.fixed_scratch;
        *tables.private = *tables.private_scratch;
        self.committed = true;
        Ok(())
    }
}

#[cfg(test)]
#[path = "thread_charge_retirement_tests.rs"]
mod tests;
