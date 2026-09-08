//! Exact resident ownership until checked release or pagefile publication completes.
use super::*;
use nt_memory_manager::{ClientFrameReclaimError, ClientFrameReclaimIntent, ClientFrameReclaimIo};

struct Io;
fn checked(label: u64) -> Result<(), u32> {
    if label == 0 {
        Ok(())
    } else {
        Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}
fn status(error: ClientFrameReclaimError) -> u32 {
    match error {
        ClientFrameReclaimError::Backend(status) => status,
        ClientFrameReclaimError::StaleRecord | ClientFrameReclaimError::InvalidState => {
            nt_address_space::STATUS_INVALID_PARAMETER
        }
    }
}
impl ClientFrameReclaimIo for Io {
    fn revoke(&mut self, cap: u64) -> Result<(), u32> {
        checked(unsafe { cnode_revoke_r(cap) })
    }
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        checked(unsafe { page_unmap_r(cap) })
    }
    fn delete(&mut self, cap: u64) -> Result<(), u32> {
        checked(unsafe { cnode_delete_r(cap) })
    }
    fn recycle_empty(&mut self, cap: u64) -> Result<(), u32> {
        unsafe { root_slot_recycle::publish_empty(cap) }
            .map_err(|_| nt_address_space::STATUS_INVALID_PARAMETER)
    }
}

unsafe fn admit(record: ClientFrameRecord, access: &retirement_memory_access::Access<'_>) -> Result<(), u32> {
    access.check(record.pi, record.page)?;
    if hosted_thread_retains_page_backing(record.pi, record.page) {
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    if record.owns_frame {
        frame_recycle::validate_owned_backing(record.owned_backing_cap)?;
    }
    if !service_sec_image::section_scratch_is_quiescent()
        || [record.frame, record.alias_cap, record.source_cap]
            .into_iter()
            .any(frame_acquisition::owns_root_cap)
    {
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    win32k_glue::detach_attached_client_page_with_access(record.pi, record.page, access)
}

/// The caller is retiring this page's VM ownership, not merely trimming its working set.
/// That permits cancelling an unfinished pageout while preserving all cleanup acknowledgements.
pub(super) unsafe fn release(pi: u64, page: u64) -> Result<bool, u32> {
    release_with_access(pi, page, &retirement_memory_access::Access::Ordinary)
}

pub(super) unsafe fn release_with_access(
    pi: u64,
    page: u64,
    access: &retirement_memory_access::Access<'_>,
) -> Result<bool, u32> {
    access.check(pi, page)?;
    let Some(mut record) = (&*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY)).get(pi, page) else {
        return Ok(false);
    };
    admit(record, access)?;
    if record.owns_frame {
        frame_recycle::prepare(record.owned_backing_cap)?;
    }
    let registry = &mut *core::ptr::addr_of_mut!(CLIENT_FRAME_REGISTRY);
    if matches!(
        record.reclaim_intent(),
        Some(ClientFrameReclaimIntent::Pageout { .. })
    ) {
        record = registry
            .cancel_pageout_to_release_exact(record)
            .map_err(status)?;
    }
    let intent = ClientFrameReclaimIntent::Release;
    record = registry
        .begin_reclaim_exact(record, intent)
        .map_err(status)?;
    record = registry
        .cleanup_reclaim_exact(record, intent, &mut Io)
        .map_err(status)?;
    registry
        .commit_reclaim_exact(record, intent, |ready| {
            if ready.owns_frame {
                frame_recycle::publish(ready.owned_backing_cap)
            } else {
                Ok(())
            }
        })
        .map_err(status)?;
    Ok(true)
}

pub(super) unsafe fn pageout(pi: u64, page: u64, protection: u32) -> Result<bool, u32> {
    let _durable = allocator::enter_durable();
    let Some(mut record) = (&*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY)).get(pi, page) else {
        return Ok(false);
    };
    if !record.owns_frame {
        return Ok(false);
    }
    admit(record, &retirement_memory_access::Access::Ordinary)?;
    let intent = ClientFrameReclaimIntent::Pageout { protection };
    let registry = &mut *core::ptr::addr_of_mut!(CLIENT_FRAME_REGISTRY);
    record = registry
        .begin_reclaim_exact(record, intent)
        .map_err(status)?;
    record = registry
        .cleanup_reclaim_exact(record, intent, &mut Io)
        .map_err(status)?;
    let pagefile = &mut *core::ptr::addr_of_mut!(PROCESS_PAGEFILE);
    let publish = pagefile.prepare_publish(nt_memory_manager::PagefilePage {
        owner: pi,
        page,
        protection,
        backing: record.owned_backing_cap,
    })?;
    registry
        .commit_reclaim_exact(record, intent, |_| pagefile.commit_publish(publish))
        .map_err(status)?;
    Ok(true)
}

/// Retry each pending cleanup at most once at the serialized event boundary. Ordinary memory
/// admission remains closed until the exact row has transferred its backing or retired its caps.
pub(super) unsafe fn retry_pending() {
    if (&*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY)).reclaiming_count() == 0 {
        return;
    }
    let mut index = 0;
    loop {
        let Some(record) = (&*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY))
            .records()
            .get(index)
            .copied()
        else {
            break;
        };
        let Some(intent) = record.reclaim_intent() else {
            index += 1;
            continue;
        };
        let result = match intent {
            ClientFrameReclaimIntent::Release => release(record.pi, record.page),
            ClientFrameReclaimIntent::Pageout { protection } => {
                pageout(record.pi, record.page, protection)
            }
        };
        match result {
            Ok(true) => {} // swap_remove moved an unvisited row into this index.
            Ok(false) => index += 1,
            Err(status) => {
                note_failure(record, status);
                index += 1;
            }
        }
    }
}

static RETRY_FAILURES: AtomicU64 = AtomicU64::new(0);
fn note_failure(record: ClientFrameRecord, status: u32) {
    let count = RETRY_FAILURES
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    if count > 16 && !count.is_power_of_two() {
        return;
    }
    print_str(b"[client-frame-cleanup] retained #");
    print_u64(count);
    print_str(b" pi=");
    print_u64(record.pi);
    print_str(b" page=0x");
    print_hex_u64(record.page);
    print_str(b" backing=0x");
    print_hex_u64(record.owned_backing_cap);
    print_str(b" pageout=");
    print_u64(matches!(
        record.reclaim_intent(),
        Some(ClientFrameReclaimIntent::Pageout { .. })
    ) as u64);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b"\n");
}
