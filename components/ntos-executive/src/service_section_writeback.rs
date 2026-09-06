//! Mapped-file snapshot publication, retaining retry ownership until the checkpoint completes.

use super::*;
use nt_memory_manager::writeback::{SectionWritebackIo, SectionWritebackPage, WritebackResult};

struct WritebackIo {
    file_id: u64,
    scratch_base: u64,
}

impl SectionWritebackIo for WritebackIo {
    fn write_page(&mut self, page: SectionWritebackPage) -> (u32, usize) {
        unsafe {
            let scratch = self.scratch_base + DEMAND_SCRATCH_WINDOW - 0x4000;
            let (alias, error) = copy_cap_r(page.frame);
            if error != 0 {
                if alias != 0 {
                    let _ = cnode_delete_recycle_r(alias);
                }
                return (nt_address_space::STATUS_INSUFFICIENT_RESOURCES, 0);
            }
            if page_map_r(alias, scratch, RO_NX, CAP_INIT_THREAD_VSPACE) != 0 {
                let _ = cnode_delete_recycle_r(alias);
                return (nt_address_space::STATUS_INSUFFICIENT_RESOURCES, 0);
            }
            let bytes = core::slice::from_raw_parts(scratch as *const u8, page.length);
            let result = crate::writable_fs::write(self.file_id, Some(page.file_offset), bytes);
            let _ = page_unmap_r(alias);
            let _ = cnode_delete_recycle_r(alias);
            result
        }
    }

    fn persist(&mut self) -> u32 {
        unsafe {
            let status = crate::writable_fs::flush(self.file_id);
            if status != 0 {
                return status;
            }
            let _transient = allocator::enter_transient();
            let _alloc_ctx = allocator::enter_context(allocator::ALLOC_CTX_WRITABLE_SNAPSHOT);
            crate::writable_fs::checkpoint_dirty_volume()
                .err()
                .unwrap_or(0)
        }
    }
}

pub(crate) unsafe fn service_generic_section_writeback_view(
    table: &mut GenericSectionTable,
    view: GenericSectionView,
    scratch_base: u64,
) -> WritebackResult {
    let Some(section) = table.section(view.section_index) else {
        return WritebackResult::failure(nt_fs::STATUS_INVALID_HANDLE);
    };
    service_generic_section_writeback_plan(
        table,
        GenericSectionFlushPlan {
            view,
            section,
            base: view.base,
            size: view.size,
            section_offset: view.section_offset,
        },
        scratch_base,
    )
}

pub(crate) unsafe fn service_generic_section_writeback_plan(
    table: &mut GenericSectionTable,
    plan: GenericSectionFlushPlan,
    scratch_base: u64,
) -> WritebackResult {
    if !generic_section_writes_back(plan.section) {
        return WritebackResult::default();
    }
    let result = table.writeback(
        plan,
        &mut WritebackIo {
            file_id: plan.section.backing.overlay_file_id,
            scratch_base,
        },
    );
    GENERIC_SECTION_WRITEBACKS.fetch_add(result.pages_written, Ordering::Relaxed);
    GENERIC_SECTION_WRITEBACK_BYTES.fetch_add(result.bytes_written, Ordering::Relaxed);
    if result.status != 0 {
        GENERIC_SECTION_WRITEBACK_FAILS.fetch_add(1, Ordering::Relaxed);
    }
    result
}
