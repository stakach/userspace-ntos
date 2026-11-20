//! Reuse policy of the durable heap: exact-size caches ahead of the address-ordered list.
//!
//! The policy is host-testable against ordinary aligned memory; the native allocator supplies
//! its heap-resident list and caches, records the walk counts and maps faults to corruption.
//! Bump growth, commitment and OOM reporting stay with the caller.

use super::free_list::{Corruption, FreeList, TakeFitError};
use super::quick_lists::{QuickCorruption, QuickLists, QUICK_MAX_BLOCK};

pub(super) struct DurablePolicy {
    pub list: FreeList,
    pub quick: QuickLists,
}

#[derive(Debug)]
pub(super) enum PolicyFault {
    Quick(QuickCorruption),
    TakeFit(TakeFitError),
    Insert { start: usize, size: usize, corruption: Corruption },
}

/// One reuse attempt: the address, or `None` when the caller must grow the bump.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Reuse {
    pub address: Option<usize>,
    /// Nodes the first-fit walk inspected, when it ran.
    pub fit_visits: Option<usize>,
    /// Nodes an address-ordered insertion of a spilled suffix visited, when one ran.
    pub insert_visits: Option<usize>,
}

impl DurablePolicy {
    /// Serve `needed` bytes from the cache of that exact size, else by first fit. A small
    /// split suffix is cached rather than linked into the list, where it would otherwise be a
    /// fragment that every later walk crosses but cached small allocations never consume.
    pub(super) unsafe fn reuse(&self, align: usize, needed: usize, top: usize)
        -> Result<Reuse, PolicyFault> {
        if let Some(address) = unsafe { self.quick.pop(needed, align, top) }
            .map_err(PolicyFault::Quick)?
        {
            return Ok(Reuse { address: Some(address), ..Reuse::default() });
        }
        let taken = unsafe { self.list.take_fit_spilling(align, needed, QUICK_MAX_BLOCK + 1) }
            .map_err(PolicyFault::TakeFit)?;
        let insert_visits = match taken.spilled_suffix {
            Some((start, size)) if !unsafe { self.quick.push(start, size) } =>
                Some(unsafe { self.insert(start, size) }?),
            _ => None,
        };
        Ok(Reuse { address: taken.address, fit_visits: Some(taken.inspected), insert_visits })
    }

    /// Release a dead block. A small block not at the bump top is cached; everything else is
    /// inserted (coalesced, or trimmed from the top). Returns the insertion's visits, if any.
    pub(super) unsafe fn release(&self, start: usize, size: usize, top: usize)
        -> Result<Option<usize>, PolicyFault> {
        let at_top = start.checked_add(size) == Some(top);
        if !at_top && unsafe { self.quick.push(start, size) } {
            return Ok(None);
        }
        unsafe { self.insert(start, size) }.map(Some)
    }

    unsafe fn insert(&self, start: usize, size: usize) -> Result<usize, PolicyFault> {
        unsafe { self.list.insert(start, size) }
            .map_err(|corruption| PolicyFault::Insert { start, size, corruption })
    }
}
