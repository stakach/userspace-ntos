//! Section resource release after explicit view/handle retirement.
use super::*;
use nt_memory_manager::{GenericSectionBacking, PendingSectionFrames, SectionRetirementIo};

static mut PENDING_PAGEIN_FRAMES: PendingSectionFrames = PendingSectionFrames::new();

pub(super) unsafe fn reserve_pagein_cleanup() -> Result<(), u32> {
    if (&mut *core::ptr::addr_of_mut!(PENDING_PAGEIN_FRAMES)).reserve() {
        Ok(())
    } else {
        Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}

pub(super) unsafe fn release_unpublished_section_frame(frame: u64) {
    (&mut *core::ptr::addr_of_mut!(PENDING_PAGEIN_FRAMES))
        .release_or_defer(frame, &mut RetirementIo);
}

struct RetirementIo;

impl SectionRetirementIo for RetirementIo {
    fn release_frame(&mut self, frame: u64) -> Result<(), u32> {
        unsafe {
            let free = &mut *core::ptr::addr_of_mut!(VM_FREE_FRAMES);
            if !free.reserve(1) {
                return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
            }
            // The view paths remove registered aliases first. Revoke is the final physical
            // safety barrier for any remaining descendants before the owner is recycled.
            if cnode_revoke_r(frame) != 0 || page_unmap_r(frame) != 0 {
                return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
            }
            free.try_recycle(frame)
                .expect("section retirement reserved its frame slot");
            Ok(())
        }
    }

    fn release_backing(&mut self, backing: GenericSectionBacking) -> Result<(), u32> {
        if backing.kind == GENERIC_SECTION_BACKING_OVERLAY {
            unsafe { crate::writable_fs::release_io_reference(backing.overlay_file_id) }
        } else {
            Ok(()) // Anonymous and immutable boot-disk backing hold no FILE_OBJECT reference.
        }
    }
}

pub(crate) unsafe fn service_drain_section_retirement(
    table: &mut GenericSectionTable,
) -> Result<(), u32> {
    section_scratch::drain_section_scratch()?;
    (&mut *core::ptr::addr_of_mut!(PENDING_PAGEIN_FRAMES)).drain(&mut RetirementIo)?;
    table.drain_retired(&mut RetirementIo)
}

/// Detach every page, not just dirty writeback pages, before the view identity is discarded.
/// Partial capability cleanup retains exact registry progress for a later retry.
pub(crate) unsafe fn service_unmap_section_view_mappings(
    view: GenericSectionView,
) -> Result<(), u32> {
    hosted_thread_memory_access(view.pi as u64, view.base, view.size)?;
    let end = view
        .base
        .checked_add(view.size)
        .ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?;
    let mut page = view.base;
    while page < end {
        crate::win32k_glue::detach_attached_client_page(view.pi as u64, page)?;
        if vm_page_lock_is_locked(view.pi as u64, page)
            || !csrss_frame_reclaim_exact(view.pi as u64, page)
        {
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        }
        process_pagefile_discard(view.pi as u64, page);
        page = page
            .checked_add(0x1000)
            .ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?;
    }
    Ok(())
}
