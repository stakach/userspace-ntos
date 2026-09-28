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
            frame_recycle::prepare(frame)?;
            // The view paths remove registered aliases first. Revoke is the final physical
            // safety barrier for any remaining descendants before the owner is recycled.
            if cnode_revoke_r(frame) != 0 || page_unmap_r(frame) != 0 {
                return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
            }
            frame_recycle::publish(frame)
        }
    }

    fn release_backing(
        &mut self,
        _: nt_memory_manager::SectionIdentity,
        backing: GenericSectionBacking,
    ) -> Result<(), u32> {
        match backing.kind {
            GENERIC_SECTION_BACKING_OVERLAY => unsafe {
                crate::writable_fs::release_io_reference(backing.overlay_file_id)
            },
            nt_memory_manager::GENERIC_SECTION_BACKING_ANON | GENERIC_SECTION_BACKING_DISK => Ok(()),
            _ => Err(nt_fs::STATUS_INVALID_HANDLE),
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
    handler: &ExecNtHandler,
) -> Result<(), u32> {
    let nt_memory_manager::MemoryLifetime::Process(process) = view.lifetime else {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    };
    if handler.capture_process_identity(view.pi) != Some(process)
        || handler
            .loop_ctx
            .and_then(|ctx| (&*ctx.generic_sections).view_for_page(view.pi, view.base))
            .is_none_or(|(_, current)| current != view)
    {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    let access = retirement_memory_access::Access::Process { process, handler };
    hosted_thread_memory_retirement_access(view.pi as u64, view.base, view.size)?;
    let end = view
        .base
        .checked_add(view.size)
        .ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?;
    let mut page = view.base;
    while page < end {
        access.check(view.pi as u64, page)?;
        if !view.permits_retirement_page(
            process,
            page,
            csrss_frame_get_exact_record(view.pi as u64, page).map(|record| record.lifetime),
            (&*core::ptr::addr_of!(PROCESS_PAGEFILE)).lifetime(view.pi as u64, page),
        ) {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
        if vm_page_lock_is_locked(view.pi as u64, page) {
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        }
        crate::win32k_glue::detach_attached_client_page_with_access(
            view.pi as u64,
            page,
            &access,
        )?;
        client_frame_cleanup::release_with_access(view.pi as u64, page, &access)?;
        pagefile_retirement::discard_with_access(view.pi as u64, page, &access)?;
        page = page
            .checked_add(0x1000)
            .ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?;
    }
    Ok(())
}
