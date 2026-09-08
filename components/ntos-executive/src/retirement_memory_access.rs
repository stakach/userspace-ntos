//! Narrow dynamic-stack cleanup admission through the retained runtime, never ordinary mapping.
use super::*;
use nt_user_host::thread_memory_retirement_access::UserStackRetirementPermit;

pub(crate) enum Access<'a> {
    Ordinary,
    UserStack {
        permit: &'a UserStackRetirementPermit<'a>,
        handler: &'a ExecNtHandler,
    },
}

impl Access<'_> {
    pub(crate) fn check(&self, pi: u64, page: u64) -> Result<(), u32> {
        match self {
            Self::Ordinary => hosted_thread_memory_retirement_access(pi, page, 4096),
            Self::UserStack { permit, handler } => {
                let pi =
                    usize::try_from(pi).map_err(|_| nt_address_space::STATUS_ACCESS_VIOLATION)?;
                let current = handler
                    .capture_process_identity(pi)
                    .ok_or(nt_address_space::STATUS_ACCESS_VIOLATION)?;
                let tid = u32::try_from(permit.owner().identity().tid)
                    .map_err(|_| nt_address_space::STATUS_ACCESS_VIOLATION)?;
                if !handler
                    .pm
                    .thread(tid)
                    .is_some_and(|thread| thread.process_id == current.pid)
                {
                    return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
                }
                hosted_thread_runtime::check_user_stack_retirement_access(
                    permit, current, pi, page,
                )?;
                if unsafe { win32k_glue::client_has_active_callback_frames(pi as u32) }
                    || unsafe { service_sec_image::client_has_vm_continuations(pi as u32) }
                {
                    return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
                }
                Ok(())
            }
        }
    }

    /// Called only for an actual retained provider mapping. No provider at all needs no lane
    /// proof, but missing lane ownership for an existing alias must remain a hard refusal.
    pub(crate) fn check_attachment_retirement(&self) -> Result<(), u32> {
        if matches!(self, Self::UserStack { .. })
            && !unsafe { win32k_glue::win32k_physical_lanes_quiescent() }
        {
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        }
        Ok(())
    }
}

/// The charged-memory owner must validate its retained private VAD witness before calling this
/// backend. Both resident and transition cleanup retain their own per-cap retry acknowledgments.
/// This function neither removes the VAD nor releases accounting or runtime reservations.
pub(crate) unsafe fn release_user_stack_page(
    permit: &UserStackRetirementPermit<'_>,
    handler: &ExecNtHandler,
    page: u64,
) -> Result<(), u32> {
    let pi = permit.owner().identity().pi as u64;
    let access = Access::UserStack { permit, handler };
    access.check(pi, page)?;
    // These are independent owners, not private VAD backing. Never revoke or recycle through
    // them simply because their numeric VA happens to lie in the retained allocation.
    if !client_prefetch::page_is_unowned(pi, page)
        || !win32k_glue::provider_client_page_is_unowned(pi as usize, page)
    {
        return Err(nt_address_space::STATUS_CONFLICTING_ADDRESSES);
    }
    win32k_glue::detach_attached_client_page_with_access(pi, page, &access)?;
    let _ = vm_page_lock_retire_range(pi, page, 4096);
    if vm_page_lock_is_locked(pi, page) {
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    pagefile_retirement::discard_with_access(pi, page, &access)?;
    client_frame_cleanup::release_with_access(pi, page, &access)?;
    Ok(())
}
