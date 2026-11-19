//! Resident section pages stay coherent with routed NtWriteFile.
//!
//! NT has one copy of a file's cached data: a cached write lands in the same section pages every
//! view maps (CcCopyWrite), and a non-cached write flushes and purges them first (CcFlushCache,
//! MmFlushSection, CcPurgeCacheSection). A routed filesystem writes its volume directly, so once
//! it accepts a write the accepted bytes are copied into every resident page of the same stream
//! (`plan_stream_write`/`commit_stream_write`). A pending write keeps its own copy of the bytes
//! until its exact terminal completion.

use super::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_memory_manager::GenericSectionTable;

struct PendingWrite {
    irp_id: u64,
    device_id: u64,
    fs_context: u64,
    offset: u64,
    data: Vec<u8>,
}

static mut PENDING: Vec<PendingWrite> = Vec::new();
static APPLIED_TRACE_N: AtomicU64 = AtomicU64::new(0);

/// Only an offset known here can be reconciled; a file-pointer or end-of-file sentinel is
/// resolved by the filesystem's own FILE_OBJECT.
const fn known_offset(offset: u64) -> bool {
    (offset as i64) >= 0
}

unsafe fn stream_maps_sections(table: &GenericSectionTable, device_id: u64, fs_context: u64) -> bool {
    table.retained_routed_sections().into_iter().any(|(section, lease)| {
        crate::hosted_routed_section_capture::route(lease, section)
            .is_some_and(|route| route.device_id == device_id && route.fs_context == fs_context)
    })
}

/// Copy `data`, which the stream's filesystem accepted at `offset`, into its resident pages.
pub(crate) unsafe fn apply(handler: &ExecNtHandler, device_id: u64, fs_context: u64, offset: u64, data: &[u8]) {
    let Some(ctx) = handler.loop_ctx else { return; };
    if data.is_empty() || !known_offset(offset) {
        return;
    }
    let table = &mut *ctx.generic_sections;
    for (section, lease) in table.retained_routed_sections() {
        let matches = crate::hosted_routed_section_capture::route(lease, section)
            .is_some_and(|route| route.device_id == device_id && route.fs_context == fs_context);
        if !matches {
            continue;
        }
        let Ok(plan) = table.plan_stream_write(section, offset, data.len() as u64) else { continue; };
        let mut copied = true;
        for page in plan.pages() {
            let source = &data[page.data_offset..page.data_offset + page.length];
            let (status, _) = super::section_scratch::with_section_frame(page.frame, ctx.scratch_base, |address| {
                core::ptr::copy_nonoverlapping(
                    source.as_ptr(), (address + page.page_offset as u64) as *mut u8, source.len(),
                );
                (0, source.len())
            });
            copied &= status == 0;
        }
        let pages = plan.pages().len() as u64;
        // A page whose copy failed must not be dirtied again: its older bytes would be written
        // over the completed write.
        if !copied || !table.commit_stream_write(plan) {
            print_str(b"[section-coherence] resident page update failed offset=0x");
            print_hex_u64(offset);
            print_str(b"\n");
            continue;
        }
        if pages != 0 && APPLIED_TRACE_N.fetch_add(1, Ordering::Relaxed) < 8 {
            print_str(b"[section-coherence] routed write updated resident pages=");
            print_u64(pages);
            print_str(b"\n");
        }
        if table.has_async_dirty_pages() {
            super::section_writeback_work::request_scan();
        }
    }
}

/// A routed write pended: keep its bytes until its exact terminal completion, but only for a
/// stream that has section pages to reconcile.
pub(crate) unsafe fn retain_pending(
    handler: &ExecNtHandler, irp_id: u64, device_id: u64, fs_context: u64, offset: u64, data: &[u8],
) {
    let Some(ctx) = handler.loop_ctx else { return; };
    if irp_id == 0 || data.is_empty() || !known_offset(offset)
        || !stream_maps_sections(&*ctx.generic_sections, device_id, fs_context)
    {
        return;
    }
    let _durable = allocator::enter_durable();
    let rows = &mut *core::ptr::addr_of_mut!(PENDING);
    let mut owned = Vec::new();
    if rows.try_reserve(1).is_err() || owned.try_reserve_exact(data.len()).is_err() {
        print_str(b"[section-coherence] pending write bytes not retained\n");
        return;
    }
    owned.extend_from_slice(data);
    rows.push(PendingWrite { irp_id, device_id, fs_context, offset, data: owned });
}

/// The pended write reached its exact terminal completion: reconcile the accepted prefix.
pub(crate) unsafe fn settle_pending(handler: &ExecNtHandler, irp_id: u64, status: u32, information: u64) {
    let rows = &mut *core::ptr::addr_of_mut!(PENDING);
    let Some(index) = rows.iter().position(|row| row.irp_id == irp_id) else { return; };
    let row = rows.swap_remove(index);
    if (status as i32) >= 0 {
        let accepted = (information as usize).min(row.data.len());
        apply(handler, row.device_id, row.fs_context, row.offset, &row.data[..accepted]);
    }
}
