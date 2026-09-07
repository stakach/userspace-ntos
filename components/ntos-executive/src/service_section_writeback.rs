//! Mapped-file snapshot publication, retaining retry ownership until the checkpoint completes.

use super::*;
use nt_memory_manager::writeback::{
    SectionPageAlias, SectionWritebackIo, SectionWritebackPage, WritebackResult,
};

struct WritebackIo {
    file_id: u64,
    scratch_base: u64,
    context: Option<ExecLoopCtx>,
}

impl SectionWritebackIo for WritebackIo {
    fn rearm_alias(&mut self, alias: SectionPageAlias) -> Result<(), u32> {
        rearm_section_alias(alias, self.context)
    }

    fn write_page(&mut self, page: SectionWritebackPage) -> (u32, usize) {
        unsafe {
            section_scratch::with_section_frame(page.frame, self.scratch_base, |scratch| {
                let bytes = core::slice::from_raw_parts(scratch as *const u8, page.length);
                crate::writable_fs::write(self.file_id, Some(page.file_offset), bytes)
            })
        }
    }

    fn persist(&mut self) -> u32 {
        unsafe {
            if let Err(status) = section_scratch::drain_section_scratch() {
                return status;
            }
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
    context: Option<ExecLoopCtx>,
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
        context,
    )
}

pub(crate) unsafe fn service_generic_section_writeback_plan(
    table: &mut GenericSectionTable,
    plan: GenericSectionFlushPlan,
    scratch_base: u64,
    context: Option<ExecLoopCtx>,
) -> WritebackResult {
    if table.section(plan.view.section_index) != Some(plan.section) {
        return WritebackResult::failure(nt_memory_manager::STATUS_NOT_MAPPED_VIEW);
    }
    if !generic_section_writes_back(plan.section) {
        return WritebackResult::default();
    }
    let Some(info) = crate::writable_fs::standard_information(plan.section.backing.overlay_file_id)
    else {
        return WritebackResult::failure(nt_fs::STATUS_INVALID_HANDLE);
    };
    if let Err(status) = table.refresh_file_extent(plan.view.section_index, info.end_of_file) {
        return WritebackResult::failure(status);
    }
    let result = table.writeback(
        plan,
        &mut WritebackIo {
            file_id: plan.section.backing.overlay_file_id,
            scratch_base,
            context,
        },
    );
    record_writeback(result)
}

pub(crate) unsafe fn service_generic_section_writeback_file(
    table: &mut GenericSectionTable,
    file_id: u64,
    scratch_base: u64,
    context: Option<ExecLoopCtx>,
) -> WritebackResult {
    let backing = match crate::writable_fs::section_backing(file_id) {
        Ok(backing) => backing,
        Err(status) => return record_writeback(WritebackResult::failure(status)),
    };
    record_writeback(table.writeback_file(
        backing,
        &mut WritebackIo {
            file_id,
            scratch_base,
            context,
        },
    ))
}

fn record_writeback(result: WritebackResult) -> WritebackResult {
    GENERIC_SECTION_WRITEBACKS.fetch_add(result.pages_written, Ordering::Relaxed);
    GENERIC_SECTION_WRITEBACK_BYTES.fetch_add(result.bytes_written, Ordering::Relaxed);
    if result.status != 0 {
        GENERIC_SECTION_WRITEBACK_FAILS.fetch_add(1, Ordering::Relaxed);
    }
    result
}

pub(super) fn rearm_section_alias(
    alias: SectionPageAlias,
    context: Option<ExecLoopCtx>,
) -> Result<(), u32> {
    unsafe {
        crate::hosted_thread_memory_access(alias.pi as u64, alias.page, 4096)?;
        // An attachment can outlive client residency (or retain the pre-COW frame).
        crate::win32k_glue::detach_attached_client_page(alias.pi as u64, alias.page)?;
        let Some(record) = csrss_frame_get_exact_record(alias.pi as u64, alias.page) else {
            return Ok(());
        };
        if record.owns_frame {
            return Ok(());
        }
        let context = context
            .and_then(|ctx| ctx.for_process(alias.pi))
            .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
        let info = process_committed_mapping_basic_information(alias.pi as u64, alias.page)
            .filter(|info| info.type_ == nt_address_space::MEM_MAPPED)
            .ok_or(nt_memory_manager::STATUS_NOT_MAPPED_VIEW)?;
        // Section records have no permanent executive alias. Refuse an unexpected bypass.
        if record.alias != 0 {
            return Err(nt_address_space::STATUS_CONFLICTING_ADDRESSES);
        }
        let protection =
            nt_address_space::mapped_view_fault_plan(info.protect, false).map_protection;
        vm_reprotect_private_page(alias.pi, alias.page, info.protect, protection, context.pml4)
    }
}
