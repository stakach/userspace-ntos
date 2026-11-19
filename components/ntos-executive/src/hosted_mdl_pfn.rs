//! Real PFNs for hosted MDLs, read from frame capabilities the executive owns for the instance.
//!
//! A driver's VSpace is assembled from executive-owned frame runs (image, pool, data, shared, arg
//! and the primary stack) and from contiguous RAM published by the broker. Each PFN comes from the
//! exact frame capability behind that component page, never from driver-writable metadata. Pages
//! outside these owned regions (for example a dynamic worker stack) have no translation here, so the
//! MDL operation is refused before any PFN is written.

use super::*;

/// The physical address of one page-aligned component VA of this live instance.
unsafe fn owned_page_physical(instance: usize, inst: DriverInstance, page: u64) -> Option<u64> {
    if page & 0xfff != 0 {
        return None;
    }
    let image_frames = if inst.image_frames == 0 { FSD_IMAGE_FRAMES } else { inst.image_frames };
    for (base, cap_base, frames) in [
        (FSD_CODE_VA, inst.image_frame_base, image_frames),
        (FSD_POOL_VADDR, inst.pool_frame_base, FSD_POOL_FRAMES),
        (FSD_DATA_VADDR, inst.data_frame_base, FSD_DATA_FRAMES),
        (FSD_SHARED_VADDR, inst.shared_frame_base, FSD_SHARED_FRAMES),
        (FSD_ARG_VADDR, inst.arg_frame_base, FSD_ARG_FRAMES),
        (FSD_STACK_VADDR, inst.stack_frame_base, inst.stack_frame_count),
    ] {
        let Some(index) = page.checked_sub(base).map(|offset| offset / 0x1000) else {
            continue;
        };
        if index >= frames {
            continue;
        }
        if cap_base == 0 {
            return None;
        }
        return get_frame_paddr_checked(cap_base.checked_add(index)?).ok();
    }
    hosted_contiguous_ram_broker::instance_physical_address(instance, inst, page)
}

/// Write the PFN array of the MDL at `mdl_exec` (the executive alias of a live pool allocation of
/// `allocated` bytes) from its validated header, translating every page before writing any PFN.
pub(super) unsafe fn populate(
    instance: usize,
    inst: DriverInstance,
    mdl_exec: u64,
    allocated: u16,
) -> Result<u64, nt_mdl::pfn::PfnError> {
    let size = read_unaligned((mdl_exec + nt_mdl::MDL_OFF_SIZE) as *const i16);
    if size as i32 != i32::from(allocated) {
        return Err(nt_mdl::pfn::PfnError::Capacity);
    }
    let capacity = nt_mdl::pfn::pfn_capacity(size).ok_or(nt_mdl::pfn::PfnError::Capacity)?;
    let pfns = mdl_exec + nt_mdl::MDL_SIZE as u64;
    nt_mdl::pfn::populate(
        read_unaligned((mdl_exec + nt_mdl::MDL_OFF_START_VA) as *const u64),
        read_unaligned((mdl_exec + nt_mdl::MDL_OFF_BYTE_OFFSET) as *const u32),
        read_unaligned((mdl_exec + nt_mdl::MDL_OFF_BYTE_COUNT) as *const u32),
        capacity,
        |page| unsafe { owned_page_physical(instance, inst, page) },
        |index, pfn| unsafe { write_unaligned((pfns + index * 8) as *mut u64, pfn) },
    )
}

/// `IoBuildPartialMdl`'s PFN copy: the source pages spanned by the target's subrange.
pub(super) unsafe fn copy_partial(
    source_exec: u64,
    source_allocated: u16,
    target_exec: u64,
    target_allocated: u16,
) -> Result<(), nt_mdl::pfn::PfnError> {
    let field = |mdl: u64, offset: u64| unsafe { read_unaligned((mdl + offset) as *const u32) };
    let start = |mdl: u64| unsafe { read_unaligned((mdl + nt_mdl::MDL_OFF_START_VA) as *const u64) };
    let source_start = start(source_exec);
    let target_address = start(target_exec)
        .checked_add(u64::from(field(target_exec, nt_mdl::MDL_OFF_BYTE_OFFSET)))
        .ok_or(nt_mdl::pfn::PfnError::InvalidRange)?;
    let (offset, count) = nt_mdl::pfn::partial_window(
        source_start,
        field(source_exec, nt_mdl::MDL_OFF_BYTE_OFFSET),
        field(source_exec, nt_mdl::MDL_OFF_BYTE_COUNT),
        target_address,
        field(target_exec, nt_mdl::MDL_OFF_BYTE_COUNT),
    )?;
    let capacity = |allocated: u16| {
        nt_mdl::pfn::pfn_capacity(allocated as i16).ok_or(nt_mdl::pfn::PfnError::Capacity)
    };
    if offset.checked_add(count).ok_or(nt_mdl::pfn::PfnError::Capacity)?
        > capacity(source_allocated)?
        || count > capacity(target_allocated)?
    {
        return Err(nt_mdl::pfn::PfnError::Capacity);
    }
    core::ptr::copy(
        (source_exec + nt_mdl::MDL_SIZE as u64 + offset * 8) as *const u8,
        (target_exec + nt_mdl::MDL_SIZE as u64) as *mut u8,
        (count * 8) as usize,
    );
    Ok(())
}
