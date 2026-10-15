//! Owner-inclusive, swap-aware process frame retirement at the serialized service boundary.
use super::*;

pub(crate) unsafe fn csrss_frame_drop_process_all(
    pi: u64,
    process: nt_memory_manager::ProcessIdentity,
    handler: &ExecNtHandler,
) -> Result<u64, u32> {
    hosted_private_page_installation::drain_for_process(handler, process)?;
    if !hosted_private_page_installation::process_available(pi) {
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    let lifetime = nt_memory_manager::MemoryLifetime::Process(process);
    let access = retirement_memory_access::Access::Process { process, handler };
    let mut dropped = 0u64;
    let mut index = 0;
    while let Some(record) = (&*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY)).record_at(index) {
        if record.pi != pi {
            index += 1;
            continue;
        }
        let page = record.page;
        if record.lifetime != lifetime {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
        if vm_page_lock_is_locked(pi, page) {
            VM_LOCK_RECLAIM_REFUSALS.fetch_add(1, Ordering::Relaxed);
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        }
        client_frame_cleanup::release_at_exact_with_access(index, record, &access)?;
        // Successful removal moves an unvisited row into this index.
        dropped = dropped.saturating_add(1);
    }
    Ok(dropped)
}

pub(super) unsafe fn csrss_frame_drop_unpublished_process_all(
    pi: u64,
    lifetime: nt_memory_manager::MemoryLifetime,
) -> Result<u64, u32> {
    if !matches!(lifetime, nt_memory_manager::MemoryLifetime::UnpublishedImage(token) if token != 0)
    {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    let mut dropped = 0u64;
    let mut index = 0;
    while let Some(record) = (&*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY)).record_at(index) {
        if record.pi != pi {
            index += 1;
            continue;
        }
        let page = record.page;
        if record.lifetime != lifetime {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
        if vm_page_lock_is_locked(pi, page) {
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        }
        hosted_thread_memory_retirement_access(pi, page, 0x1000)?;
        client_frame_cleanup::release_at_exact_with_access(
            index,
            record,
            &retirement_memory_access::Access::Ordinary,
        )?;
        dropped = dropped.saturating_add(1);
    }
    Ok(dropped)
}
