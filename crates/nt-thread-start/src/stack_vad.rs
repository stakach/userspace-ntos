//! Geometry-driven stack reservation and NT5 guard-fault policy.
//!
//! Sizing belongs to the user-mode stack creator. These plans own no frames, commit charges,
//! mappings or TEB access. The caller supplies scratch VAD tables and must perform the physical
//! work and publish the resulting TEB fields in one externally serialized transaction. A plan
//! is not a durable rollback owner; discard it if that transaction cannot finish.

use nt_address_space::{
    VmExtentState, VmRegionMap, ALLOCATION_GRANULARITY, MEM_COMMIT, MEM_PRIVATE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_GUARD, PAGE_READWRITE, PAGE_SIZE,
};

/// Actual `INITIAL_TEB` / TEB geometry, not an image-derived sizing request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StackGeometry {
    pub allocation_base: u64,
    pub stack_base: u64,
    /// Lowest usable byte. An optional committed guard page immediately precedes it.
    pub stack_limit: u64,
    pub guard_base: Option<u64>,
}

impl StackGeometry {
    fn validate(self) -> Result<(), StackVadError> {
        if self.allocation_base == 0
            || self.allocation_base % ALLOCATION_GRANULARITY != 0
            || self.stack_base % PAGE_SIZE != 0
            || self.stack_limit % PAGE_SIZE != 0
            || self.allocation_base > self.stack_limit
            || self.stack_limit >= self.stack_base
        {
            return Err(StackVadError::InvalidGeometry);
        }
        if let Some(guard) = self.guard_base {
            if guard < self.allocation_base
                || guard.checked_add(PAGE_SIZE) != Some(self.stack_limit)
            {
                return Err(StackVadError::InvalidGeometry);
            }
        }
        Ok(())
    }

    fn committed_base(self) -> u64 {
        self.guard_base.unwrap_or(self.stack_limit)
    }
}

/// Effective stack execution policy is supplied by the caller, not inferred from the image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StackGrowthPolicy {
    pub extension_disabled: bool,
    /// Exactly PAGE_READWRITE or PAGE_EXECUTE_READWRITE, without PAGE_GUARD.
    pub protection: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StackVadOutcome {
    Initialized,
    Grown,
    /// No next guard exists. The caller must deliver stack overflow, not retry expansion.
    StackOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StackVadError {
    InvalidGeometry,
    InvalidProtection,
    InvalidStackPointer,
    NotStackGuard,
    AllocationChanged,
    CommitLimit,
    StaleMap,
    Vm(u32),
}

/// Compact description of the physical and TEB changes still required by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StackVadChanges {
    pub geometry: StackGeometry,
    pub outcome: StackVadOutcome,
    /// Newly committed contiguous bytes, including a new guard if present.
    pub commit_base: Option<u64>,
    pub commit_bytes: u64,
    pub consumed_guard: Option<u64>,
    pub new_guard: Option<u64>,
    pub protection: u32,
}

/// Borrows caller-owned scratch tables, preventing candidate changes after validation.
///
/// This only authenticates the VAD contents, not a process identity, physical mappings, charges,
/// or an ABA change outside the externally serialized transaction.
pub struct StackVadPlan<'a, const N: usize> {
    before: &'a VmRegionMap<N>,
    candidate: &'a VmRegionMap<N>,
    changes: StackVadChanges,
}

impl<const N: usize> StackVadPlan<'_, N> {
    pub fn changes(&self) -> StackVadChanges {
        self.changes
    }

    pub fn candidate(&self) -> &VmRegionMap<N> {
        self.candidate
    }

    /// Publish only this validated candidate, after the caller's physical/accounting preflight.
    /// On rejection the live table is unchanged; there are no owned resources in this plan.
    pub fn apply_exact(self, current: &mut VmRegionMap<N>) -> Result<(), StackVadError> {
        if *current != *self.before {
            return Err(StackVadError::StaleMap);
        }
        *current = *self.candidate;
        Ok(())
    }
}

fn check_protection(protection: u32) -> Result<(), StackVadError> {
    if matches!(protection, PAGE_READWRITE | PAGE_EXECUTE_READWRITE) {
        Ok(())
    } else {
        Err(StackVadError::InvalidProtection)
    }
}

/// Reserve the entire supplied stack and commit its suffix (including the optional guard).
/// The available commitment is an input preflight, not a reservation of accounting authority.
/// On error only scratch storage may have changed, and no plan authorizes its publication.
pub fn prepare_initial_into<'a, const N: usize>(
    before: &'a VmRegionMap<N>,
    candidate: &'a mut VmRegionMap<N>,
    geometry: StackGeometry,
    protection: u32,
    available_commit: u64,
) -> Result<StackVadPlan<'a, N>, StackVadError> {
    geometry.validate()?;
    check_protection(protection)?;
    let commit_base = geometry.committed_base();
    let commit_bytes = geometry.stack_base - commit_base;
    if commit_bytes > available_commit {
        return Err(StackVadError::CommitLimit);
    }
    *candidate = *before;
    let reservation = candidate
        .allocate(
            Some(geometry.allocation_base),
            geometry.stack_base - geometry.allocation_base,
            MEM_RESERVE,
            protection,
        )
        .map_err(StackVadError::Vm)?;
    if reservation.base != geometry.allocation_base
        || reservation.size != geometry.stack_base - geometry.allocation_base
    {
        return Err(StackVadError::InvalidGeometry);
    }
    candidate
        .allocate(Some(commit_base), commit_bytes, MEM_COMMIT, protection)
        .map_err(StackVadError::Vm)?;
    if let Some(guard) = geometry.guard_base {
        candidate
            .protect(guard, PAGE_SIZE, protection | PAGE_GUARD)
            .map_err(StackVadError::Vm)?;
    }
    Ok(StackVadPlan {
        before,
        candidate,
        changes: StackVadChanges {
            geometry,
            outcome: StackVadOutcome::Initialized,
            commit_base: Some(commit_base),
            commit_bytes,
            consumed_guard: None,
            new_guard: geometry.guard_base,
            protection,
        },
    })
}

// Walk extents, not every page in a potentially large reservation. Protection overrides on
// already usable stack pages are deliberately preserved; only the actual guard is consumed.
fn check_allocation<const N: usize>(
    map: &VmRegionMap<N>,
    geometry: StackGeometry,
) -> Result<(), StackVadError> {
    let committed_base = geometry.committed_base();
    let mut address = geometry.allocation_base;
    while address < geometry.stack_base {
        let extent = map
            .extent_at(address)
            .ok_or(StackVadError::AllocationChanged)?;
        let end = extent
            .base
            .checked_add(extent.size)
            .ok_or(StackVadError::AllocationChanged)?;
        let expected_state = if address < committed_base {
            VmExtentState::Reserved
        } else {
            VmExtentState::Committed
        };
        if extent.allocation_base != geometry.allocation_base
            || extent.type_ != MEM_PRIVATE
            || extent.state != expected_state
            || end <= address
            || end > geometry.stack_base
            || (address < committed_base && end > committed_base)
        {
            return Err(StackVadError::AllocationChanged);
        }
        address = end;
    }
    if map
        .extent_at(geometry.stack_base)
        .is_some_and(|extent| extent.allocation_base == geometry.allocation_base)
    {
        return Err(StackVadError::AllocationChanged);
    }
    Ok(())
}

/// Validate a caller's existing private stack without changing its VAD, accounting or RSP.
///
/// The supplied INITIAL_TEB must describe the complete allocation and its committed suffix.
/// A guard is inferred only from the actual page immediately below StackLimit, within this
/// allocation, and must use the managed growth model's RW or executable-RW protection. RSP
/// must identify a writable, non-guard byte in [StackLimit, StackBase). Other committed-page
/// protections are preserved, not normalized. This validates metadata in the supplied map;
/// the caller still owns process identity, physical mapping and concurrent-mutation checks.
pub fn validate_existing<const N: usize>(
    map: &VmRegionMap<N>,
    initial_teb: crate::InitialTeb64,
    rsp: u64,
) -> Result<StackGeometry, StackVadError> {
    let mut geometry = StackGeometry {
        allocation_base: initial_teb.allocated_stack_base,
        stack_base: initial_teb.stack_base,
        stack_limit: initial_teb.stack_limit,
        guard_base: None,
    };
    geometry.validate()?;
    if geometry.stack_limit > geometry.allocation_base {
        let page = geometry.stack_limit - PAGE_SIZE;
        if let Some(protection) = map.protection_at(page) {
            if protection & PAGE_GUARD != 0 {
                check_protection(protection & !PAGE_GUARD)?;
                geometry.guard_base = Some(page);
            }
        }
    }
    check_allocation(map, geometry)?;
    if rsp < geometry.stack_limit || rsp >= geometry.stack_base || !map.permits_write(rsp) {
        return Err(StackVadError::InvalidStackPointer);
    }
    Ok(geometry)
}

/// Prepare one native NT5 guard fault from the still-guarded VAD state.
///
/// `MiCheckForUserStackOverflow` (NT5 `mm/acceschk.c`) is entered after the memory manager
/// consumes the old guard. This combines that consumption with the checked next-page plan.
/// The bottom-boundary case commits the emergency page at allocation_base + PAGE_SIZE and
/// reports overflow; it does not manufacture another guard or a fallback growth route.
/// Known insufficient commitment likewise produces a zero-new-charge overflow plan that
/// consumes the old guard. Initial reservation, in contrast, rejects insufficient commitment.
/// This native geometry API does not implement WOW64's separate TEB32 stack selection.
pub fn prepare_guard_growth_into<'a, const N: usize>(
    before: &'a VmRegionMap<N>,
    candidate: &'a mut VmRegionMap<N>,
    geometry: StackGeometry,
    fault_address: u64,
    policy: StackGrowthPolicy,
    available_commit: u64,
) -> Result<StackVadPlan<'a, N>, StackVadError> {
    geometry.validate()?;
    check_protection(policy.protection)?;
    let guard = geometry.guard_base.ok_or(StackVadError::NotStackGuard)?;
    if fault_address & !(PAGE_SIZE - 1) != guard
        || before.protection_at(guard) != Some(policy.protection | PAGE_GUARD)
    {
        return Err(StackVadError::NotStackGuard);
    }
    check_allocation(before, geometry)?;

    let mut next = StackGeometry {
        guard_base: None,
        ..geometry
    };
    let (mut outcome, commit_page) = if policy.extension_disabled {
        (StackVadOutcome::StackOverflow, None)
    } else if guard - geometry.allocation_base <= 2 * PAGE_SIZE {
        // Checked geometry guarantees at least one usable page above the guard. Avoid the
        // unsigned subtraction wrap of the old NT code for a guard at the reservation base.
        let emergency = geometry.allocation_base + PAGE_SIZE;
        next.stack_limit = emergency;
        (StackVadOutcome::StackOverflow, Some(emergency))
    } else {
        let new_guard = guard - PAGE_SIZE;
        next.stack_limit = guard;
        next.guard_base = Some(new_guard);
        (StackVadOutcome::Grown, Some(new_guard))
    };
    let mut newly_committed = commit_page.filter(|page| !before.is_committed(*page));
    let mut commit_bytes = if newly_committed.is_some() {
        PAGE_SIZE
    } else {
        0
    };
    if commit_bytes > available_commit {
        // NT5 advances the ordinary StackLimit before trying the next commit, but updates
        // the emergency-page StackLimit only after that commit succeeds.
        if outcome == StackVadOutcome::StackOverflow {
            next.stack_limit = geometry.stack_limit;
        }
        outcome = StackVadOutcome::StackOverflow;
        next.guard_base = None;
        newly_committed = None;
        commit_bytes = 0;
    }
    *candidate = *before;
    candidate
        .protect(guard, PAGE_SIZE, policy.protection)
        .map_err(StackVadError::Vm)?;
    if let Some(page) = newly_committed {
        candidate
            .allocate(Some(page), PAGE_SIZE, MEM_COMMIT, policy.protection)
            .map_err(StackVadError::Vm)?;
    }
    if let Some(page) = next.guard_base {
        candidate
            .protect(page, PAGE_SIZE, policy.protection | PAGE_GUARD)
            .map_err(StackVadError::Vm)?;
    }
    Ok(StackVadPlan {
        before,
        candidate,
        changes: StackVadChanges {
            geometry: next,
            outcome,
            commit_base: newly_committed,
            commit_bytes,
            consumed_guard: Some(guard),
            new_guard: next.guard_base,
            protection: policy.protection,
        },
    })
}

#[cfg(test)]
mod tests;
