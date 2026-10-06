//! Shared image range retirement; private backing keeps its exact per-page cleanup owner.
use super::*;

pub(crate) unsafe fn vm_unmap_shared_image_mapping_range(
    pi: usize,
    process: nt_user_host::process_identity::ProcessIdentity,
    base: u64,
    end: u64,
    handler: &ExecNtHandler,
) -> Result<(), u32> {
    let size = end.checked_sub(base).ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?;
    hosted_thread_memory_retirement_access(pi as u64, base, size)?;
    if vm_page_lock_range_is_locked(pi as u64, base, end) {
        VM_LOCK_RECLAIM_REFUSALS.fetch_add(1, Ordering::Relaxed);
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    shared_image_mapping_validate_range_for(pi as u64, process, base, end)?;
    if !process.is_valid() || handler.capture_process_identity(pi) != Some(process) {
        return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
    }
    let mut cursor = base;
    while let Some(page) = nt_memory_manager::next_private_page_in_range(
        pi as u64,
        cursor,
        end,
        &*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY),
        &*core::ptr::addr_of!(PROCESS_PAGEFILE),
    )? {
        vm_unmap_private_page(pi, process, page, handler)?;
        cursor = page + nt_address_space::PAGE_SIZE;
    }
    shared_image_mapping_unmap_range(pi as u64, process, base, end)
}
