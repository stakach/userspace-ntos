//! Sparse observation of private-page retirement candidates, not retirement authority.

use crate::{ClientFrameRegistry, PagefileStore, WORKING_SET_PAGE_SIZE};
use crate::working_set::STATUS_INVALID_PARAMETER;

/// Select the lowest recorded client-frame or pagefile address in `[base, end)` for `pi`.
///
/// Bounds must be page aligned and ordered; an empty aligned range has no candidate. This
/// allocates nothing and scans records, not virtual pages. It intentionally includes non-owning
/// mappings, reclaiming/retiring rows and foreign lifetime generations: none is absent backing.
/// The caller must revalidate exact ownership, access, locks and retirement state before effects,
/// and enumerate again after callbacks. The returned address is not a retained snapshot or grant.
pub fn next_private_page_in_range(
    pi: u64,
    base: u64,
    end: u64,
    frames: &ClientFrameRegistry,
    pagefile: &PagefileStore,
) -> Result<Option<u64>, u32> {
    if base > end
        || base & (WORKING_SET_PAGE_SIZE - 1) != 0
        || end & (WORKING_SET_PAGE_SIZE - 1) != 0
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let resident = frames
        .records()
        .filter(|record| record.pi == pi)
        .map(|record| record.page);
    Ok(resident
        .chain(pagefile.pages_for_owner(pi))
        .filter(|page| *page >= base && *page < end)
        .min())
}

#[cfg(test)]
#[path = "private_page_range_tests.rs"]
mod tests;
