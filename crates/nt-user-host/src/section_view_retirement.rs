//! Checked retirement of a hosted generic section view.

use nt_address_space::{
    VmCommittedRangeTable, VmRegionMap, MEM_MAPPED, PAGE_SIZE, STATUS_CONFLICTING_ADDRESSES,
};
use nt_memory_manager::{GenericSectionTable, GenericSectionView, STATUS_NOT_MAPPED_VIEW};

/// Validate one exact view and stage its metadata removal in caller-owned scratch tables.
/// Physical page detachment happens after this returns, without borrows of these tables.
pub fn prepare_generic_section_view_retirement<const V: usize, const C: usize>(
    view: GenericSectionView,
    sections: &GenericSectionTable,
    vad: &VmRegionMap<V>,
    committed: &VmCommittedRangeTable<C>,
    vad_scratch: &mut VmRegionMap<V>,
    committed_scratch: &mut VmCommittedRangeTable<C>,
) -> Result<(), u32> {
    if sections.view_for_page(view.pi, view.base) != Some((view.section_index, view)) {
        return Err(STATUS_NOT_MAPPED_VIEW);
    }

    *vad_scratch = *vad;
    let plan = vad_scratch.unmap_mapped(view.base)?;
    if plan.base != view.base || plan.size != view.size {
        return Err(STATUS_CONFLICTING_ADDRESSES);
    }

    let end = view
        .base
        .checked_add(view.size)
        .ok_or(STATUS_CONFLICTING_ADDRESSES)?;
    let mut page = view.base;
    while page < end {
        let info = committed.query_basic(page).ok_or(STATUS_CONFLICTING_ADDRESSES)?;
        if info.type_ != MEM_MAPPED || info.allocation_base != view.base {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        }
        page = page.checked_add(PAGE_SIZE).ok_or(STATUS_CONFLICTING_ADDRESSES)?;
    }

    *committed_scratch = *committed;
    if committed_scratch.unregister_range(view.base, view.size)? == 0 {
        return Err(STATUS_CONFLICTING_ADDRESSES);
    }
    Ok(())
}

/// Revalidate after physical cleanup, then publish both staged tables and retire the exact view.
/// The caller must have detached every page and must keep its process identity pinned across the
/// prepare/detach/commit interval. A failed revalidation leaves canonical metadata unchanged.
pub fn commit_generic_section_view_retirement<const V: usize, const C: usize>(
    view: GenericSectionView,
    sections: &mut GenericSectionTable,
    vad: &mut VmRegionMap<V>,
    committed: &mut VmCommittedRangeTable<C>,
    vad_scratch: &mut VmRegionMap<V>,
    committed_scratch: &mut VmCommittedRangeTable<C>,
) -> Result<(), u32> {
    prepare_generic_section_view_retirement(
        view,
        sections,
        vad,
        committed,
        vad_scratch,
        committed_scratch,
    )?;
    if sections.unmap_view_identity(view) != Some(view) {
        return Err(STATUS_NOT_MAPPED_VIEW);
    }
    *vad = *vad_scratch;
    *committed = *committed_scratch;
    Ok(())
}
