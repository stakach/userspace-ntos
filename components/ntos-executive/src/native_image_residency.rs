//! Canonical area/RVA backing and separately owned per-view mapping caps.

use super::*;
use core::fmt::Write;
use exec_handler::native_image_view::NativeImageViewDescriptor;
use nt_address_space::FaultAccess;
use nt_memory_manager::borrowed_page_installation::{
    BorrowedPageInstallOutcome, BorrowedPageInstallation, BorrowedPageInstallationIo,
};
use nt_memory_manager::image_section::ImageAreaId;
use nt_memory_manager::image_source_page::{
    ImageSourcePage, ImageSourcePageIo, ImageSourcePageOutcome,
};
use nt_memory_manager::private_page_installation::{InstallationCap, InstallationEffect};

const RESOURCES: u32 = nt_address_space::STATUS_INSUFFICIENT_RESOURCES;
const INVALID: u32 = nt_address_space::STATUS_INVALID_PARAMETER;

#[derive(Clone, Copy, Eq, PartialEq)]
struct SourceKey {
    area: ImageAreaId,
    rva: u32,
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct ViewPage {
    view: NativeImageViewDescriptor,
    page: u64,
    protection: u32,
}

struct SourceRow {
    owner: ImageSourcePage<SourceKey>,
    retiring: bool,
    revoke_acked: bool,
}
static mut SOURCES: Vec<SourceRow> = Vec::new();
static mut INSTALL: Option<BorrowedPageInstallation<ViewPage>> = None;
static mut COW_SOURCE: Option<(ViewPage, u64)> = None;
static BORROWED: AtomicBool = AtomicBool::new(false);
struct Borrow;
impl Borrow {
    fn acquire() -> Result<Self, u32> {
        BORROWED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| RESOURCES)
    }
}
impl Drop for Borrow {
    fn drop(&mut self) {
        BORROWED.store(false, Ordering::Release);
    }
}

fn effect(label: u64) -> InstallationEffect {
    if label == 0 {
        InstallationEffect::Acknowledged
    } else {
        InstallationEffect::Refused(RESOURCES)
    }
}
fn current(handler: &ExecNtHandler, view: NativeImageViewDescriptor, page: u64) -> bool {
    handler
        .native_image_view_for_page(view.pi, page)
        .ok()
        .flatten()
        == Some(view)
}

struct SourceIo<'a> {
    handler: &'a ExecNtHandler,
    view: NativeImageViewDescriptor,
    revoke_acked: &'a mut bool,
}
impl ImageSourcePageIo<SourceKey> for SourceIo<'_> {
    fn acquire(&mut self, _: SourceKey) -> Result<InstallationCap, u32> {
        unsafe {
            frame_acquisition::acquire(self.view.scratch_base).map(|cap| InstallationCap { cap })
        }
    }
    fn initialize(&mut self, key: SourceKey, frame: InstallationCap) -> InstallationEffect {
        let Some(source) = self.handler.image_sections.source_for_view(self.view.view) else {
            return InstallationEffect::Refused(INVALID);
        };
        if key.area != self.view.view.area() || !source.has_readable_image() {
            return InstallationEffect::Refused(INVALID);
        }
        let plan = match source
            .layout
            .image_page_fill_plan(key.rva, source.backing.file_extent)
        {
            Ok(plan) => plan,
            Err(_) => return InstallationEffect::Refused(INVALID),
        };
        let mut wrote = false;
        let result = unsafe {
            temporary_frame_alias::with_scratch_range(
                frame.cap,
                self.view.scratch_base,
                0..4096,
                true,
                |address| {
                    // read_into_page zeroes before its first read. Any refusal after entry
                    // therefore retains this initializer owner rather than replaying it.
                    wrote = true;
                    let page = core::slice::from_raw_parts_mut(address as *mut u8, 4096);
                    plan.read_into_page(page, |offset, output| {
                        source.read_exact(self.handler, offset, output)?;
                        Ok::<usize, u32>(output.len())
                    })
                    .map_err(|error| match error {
                        nt_pe_loader::ImagePageReadError::Read(status) => status,
                        nt_pe_loader::ImagePageReadError::ShortRead { .. } => 0xc000_0185,
                        nt_pe_loader::ImagePageReadError::InvalidPageSize(_) => INVALID,
                    })
                },
            )
        };
        match result {
            Ok(Ok(())) => InstallationEffect::Acknowledged,
            Ok(Err(status)) => InstallationEffect::Uncertain(status),
            Err(status) if wrote || !temporary_frame_alias::backing_release_available() => {
                InstallationEffect::Uncertain(status)
            }
            Err(status) => InstallationEffect::Refused(status),
        }
    }
    fn release(&mut self, key: SourceKey, frame: InstallationCap) -> InstallationEffect {
        release_source(key, frame, self.revoke_acked)
    }
}

fn release_source(
    _: SourceKey,
    frame: InstallationCap,
    revoke_acked: &mut bool,
) -> InstallationEffect {
    unsafe {
        if let Err(status) = frame_recycle::prepare(frame.cap) {
            return InstallationEffect::Refused(status);
        }
        // Cache originals are never mapped. All copied caps must have drained before purge.
        if !*revoke_acked {
            let label = cnode_revoke_r(frame.cap);
            if label != 0 {
                return effect(label);
            }
            *revoke_acked = true;
        }
        match frame_recycle::publish(frame.cap) {
            Ok(()) => InstallationEffect::Acknowledged,
            Err(status) => InstallationEffect::Refused(status),
        }
    }
}

unsafe fn ensure_source_page(
    handler: &ExecNtHandler,
    view: NativeImageViewDescriptor,
    rva: u32,
) -> Result<u64, u32> {
    let key = SourceKey {
        area: view.view.area(),
        rva,
    };
    let rows = &mut *core::ptr::addr_of_mut!(SOURCES);
    let index = match rows.iter().position(|row| row.owner.descriptor() == key) {
        Some(index) => index,
        None => {
            let _durable = allocator::enter_durable();
            rows.try_reserve(1).map_err(|_| RESOURCES)?;
            rows.push(SourceRow {
                owner: ImageSourcePage::new(key),
                retiring: false,
                revoke_acked: false,
            });
            rows.len() - 1
        }
    };
    let row = &mut rows[index];
    if row.retiring {
        return Err(RESOURCES);
    }
    match row.owner.advance(&mut SourceIo {
        handler,
        view,
        revoke_acked: &mut row.revoke_acked,
    }) {
        ImageSourcePageOutcome::Ready(frame) => Ok(frame.cap),
        ImageSourcePageOutcome::Failed(status) => {
            rows.remove(index);
            Err(status)
        }
        ImageSourcePageOutcome::Retained(status) | ImageSourcePageOutcome::Quarantined(status) => {
            Err(status)
        }
        ImageSourcePageOutcome::Retired => Err(INVALID),
    }
}

struct ViewIo<'a> {
    handler: &'a ExecNtHandler,
}
impl BorrowedPageInstallationIo<ViewPage> for ViewIo<'_> {
    fn reserve(&mut self) -> Result<InstallationCap, u32> {
        try_alloc_slot()
            .map(|cap| InstallationCap { cap })
            .ok_or(RESOURCES)
    }
    fn copy(
        &mut self,
        source: InstallationCap,
        destination: InstallationCap,
    ) -> InstallationEffect {
        unsafe { effect(copy_cap_into_r(source.cap, destination.cap)) }
    }
    fn map(&mut self, target: ViewPage, destination: InstallationCap) -> InstallationEffect {
        if !current(self.handler, target.view, target.page) {
            return InstallationEffect::Refused(INVALID);
        }
        unsafe {
            effect(page_map_r(
                destination.cap,
                target.page,
                vm_page_rights(target.protection),
                target.view.pml4,
            ))
        }
    }
    fn publish(&mut self, target: ViewPage, destination: InstallationCap) -> InstallationEffect {
        if !current(self.handler, target.view, target.page) {
            return InstallationEffect::Refused(INVALID);
        }
        if unsafe {
            csrss_frame_put_section_mapping(
                target.view.pi as u64,
                nt_memory_manager::MemoryLifetime::Process(target.view.process),
                target.page,
                destination.cap,
                0,
            )
        } {
            InstallationEffect::Acknowledged
        } else {
            InstallationEffect::Refused(RESOURCES)
        }
    }
    fn unmap(&mut self, cap: InstallationCap) -> InstallationEffect {
        unsafe { effect(page_unmap_r(cap.cap)) }
    }
    fn delete(&mut self, cap: InstallationCap) -> InstallationEffect {
        unsafe { effect(cnode_delete_r(cap.cap)) }
    }
    fn recycle(&mut self, cap: InstallationCap) -> InstallationEffect {
        match unsafe { root_slot_recycle::publish_unretyped(cap.cap) } {
            Ok(()) => InstallationEffect::Acknowledged,
            Err(_) => InstallationEffect::Refused(INVALID),
        }
    }
}

unsafe fn install_view_page(
    handler: &mut ExecNtHandler,
    target: ViewPage,
    source: u64,
) -> Result<(), u32> {
    let pending = &mut *core::ptr::addr_of_mut!(INSTALL);
    if let Some(owner) = pending.as_mut() {
        match owner.advance(&mut ViewIo { handler }) {
            BorrowedPageInstallOutcome::Published | BorrowedPageInstallOutcome::Failed(_) => {
                *pending = None
            }
            BorrowedPageInstallOutcome::Retained(status)
            | BorrowedPageInstallOutcome::Quarantined(status) => return Err(status),
        }
    }
    let registry = &*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY);
    if !registry.memory_available(target.view.pi as u64, target.page, 4096) {
        return Err(RESOURCES);
    }
    if let Some(record) = registry.get(target.view.pi as u64, target.page) {
        return if record.is_resident()
            && record.lifetime == nt_memory_manager::MemoryLifetime::Process(target.view.process)
        {
            Ok(())
        } else {
            Err(INVALID)
        };
    }
    handler.ensure_process_working_set_admission(
        target.view.pi,
        target.page,
        target.view.scratch_base,
    )?;
    hosted_thread_memory_access(target.view.pi as u64, target.page, 4096)?;
    ensure_process_user_page_table(handler, target.view.pi, target.page, target.view.pml4)?;
    *pending = BorrowedPageInstallation::new(target, InstallationCap { cap: source });
    let outcome = pending
        .as_mut()
        .ok_or(INVALID)?
        .advance(&mut ViewIo { handler });
    match outcome {
        BorrowedPageInstallOutcome::Published => {
            *pending = None;
            Ok(())
        }
        BorrowedPageInstallOutcome::Failed(status) => {
            *pending = None;
            Err(status)
        }
        BorrowedPageInstallOutcome::Retained(status)
        | BorrowedPageInstallOutcome::Quarantined(status) => Err(status),
    }
}

pub(crate) unsafe fn service_native_image_page_residency(
    handler: &mut ExecNtHandler,
    view: NativeImageViewDescriptor,
    page: u64,
    access: FaultAccess,
    fault_observed: bool,
) -> Result<(), u32> {
    let mut stage = "borrow";
    let result = service_page_residency(handler, view, page, access, fault_observed, &mut stage);
    if let Err(status) = result {
        if fault_observed {
            trace_image_fault_failure(handler, view, page, access, stage, status);
        }
    }
    result
}

unsafe fn trace_image_fault_failure(
    handler: &ExecNtHandler,
    view: NativeImageViewDescriptor,
    page: u64,
    access: FaultAccess,
    stage: &str,
    status: u32,
) {
    // Copy evidence after the residency borrow ends; the record grants no new access authority.
    let current_process = handler.capture_process_identity(view.pi);
    let source = handler.image_sections.source_for_view(view.view).map(|source| {
        (source.backing, source.layout.headers().image_base)
    });
    let mapping = process_committed_mapping_basic_information(view.pi as u64, page);
    let resident = (&*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY)).get(view.pi as u64, page);
    let rva = page.checked_sub(view.base).and_then(|offset| view.section_offset.checked_add(offset));
    let mut record = nt_printf::record::RecordBuffer::<3072>::new();
    let _ = writeln!(
        record,
        "[native-image-fault-failure] stage={stage} status=0x{status:08x} access={access:?} page=0x{page:x} rva={rva:x?} view={view:x?} current-process={current_process:?} source-and-preferred={source:x?} mapping={mapping:x?} resident={resident:x?}"
    );
    sel4_rt::print_record(if record.overflowed() {
        b"[native-image-fault-failure] record-truncated\n"
    } else {
        record.bytes()
    });
}

unsafe fn service_page_residency(
    handler: &mut ExecNtHandler,
    view: NativeImageViewDescriptor,
    page: u64,
    access: FaultAccess,
    fault_observed: bool,
    stage: &mut &'static str,
) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    *stage = "view-identity";
    if !current(handler, view, page) || page & 0xfff != 0 {
        return Err(INVALID);
    }
    *stage = "memory-access";
    hosted_thread_memory_access(view.pi as u64, page, 4096)?;
    *stage = "rva";
    let rva = view
        .section_offset
        .checked_add(page.checked_sub(view.base).ok_or(INVALID)?)
        .and_then(|rva| u32::try_from(rva).ok())
        .ok_or(INVALID)?;
    *stage = "source";
    let source = handler
        .image_sections
        .source_for_view(view.view)
        .ok_or(INVALID)?;
    *stage = "fill-plan";
    source
        .layout
        .image_page_fill_plan(rva, source.backing.file_extent)
        .map_err(|_| INVALID)?;
    *stage = "committed-mapping";
    let info = process_committed_mapping_basic_information(view.pi as u64, page)
        .ok_or(nt_address_space::STATUS_NOT_COMMITTED)?;
    *stage = "mapping-identity";
    if info.allocation_base != view.base
        || info.type_ != nt_address_space::MEM_IMAGE
        || info.state != nt_address_space::MEM_COMMIT
    {
        return Err(INVALID);
    }
    let protection = info.protect;
    *stage = "access";
    nt_address_space::image_view_fault_access_status(protection, access)?;
    let fault_plan =
        nt_address_space::image_view_fault_plan(protection, access == FaultAccess::Write);
    if let Some(record) = (&*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY)).get(view.pi as u64, page) {
        *stage = "resident-identity";
        if !record.is_resident()
            || record.lifetime != nt_memory_manager::MemoryLifetime::Process(view.process)
        {
            return Err(INVALID);
        }
        if record.owns_frame {
            // A private COW page already contains loader/application changes; never refill it.
            if fault_observed {
                if !fault_plan.copy_on_write {
                    *stage = "resident-private-fault";
                    return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
                }
                *stage = "private-reprotect";
                return vm_reprotect_private_page(
                    view.pi,
                    view.process,
                    page,
                    nt_address_space::image_view_fault_plan(protection, false).map_protection,
                    fault_plan.map_protection,
                    view.pml4,
                );
            }
            return Ok(());
        }
        if fault_observed && !fault_plan.copy_on_write {
            *stage = "resident-shared-fault";
            return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
        }
    }
    *stage = "pagefile-restore";
    if handler.restore_process_pagefile_page(view.pi, page, view.pml4, view.scratch_base)? {
        return Ok(());
    }
    *stage = "source-page";
    let source_frame = ensure_source_page(handler, view, rva)?;
    if fault_plan.copy_on_write {
        let target = ViewPage {
            view,
            page,
            protection: fault_plan.map_protection,
        };
        let preparation = &mut *core::ptr::addr_of_mut!(COW_SOURCE);
        *stage = "cow-owner";
        if preparation.is_some_and(|(old, frame)| old != target || frame != source_frame) {
            return Err(RESOURCES);
        }
        // Retain the exact source fence before withdrawing the borrowed mapping. This persists
        // through cleanup/initializer refusal, independently of the old resident row.
        *preparation = Some((target, source_frame));
        let access = retirement_memory_access::Access::Ordinary;
        *stage = "cow-withdraw";
        client_frame_cleanup::release_with_access(view.pi as u64, page, &access)?;
        *stage = "cow-install";
        let result = hosted_private_page_installation::map_private_page_from_frame(
            handler,
            view.pi,
            page,
            fault_plan.map_protection,
            view.pml4,
            view.scratch_base,
            source_frame,
        );
        if result.is_ok() || !hosted_private_page_installation::references_source_cap(source_frame)
        {
            *preparation = None;
        }
        return result;
    }
    *stage = "shared-install";
    install_view_page(
        handler,
        ViewPage {
            view,
            page,
            protection: fault_plan.map_protection,
        },
        source_frame,
    )
}

/// Invoked only by checked ImageSectionPurge after the authority's references have drained.
pub(crate) unsafe fn purge_area(area: ImageAreaId) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    if (&*core::ptr::addr_of!(INSTALL))
        .as_ref()
        .is_some_and(|owner| owner.descriptor().view.view.area() == area)
    {
        return Err(RESOURCES);
    }
    if (&*core::ptr::addr_of!(COW_SOURCE))
        .is_some_and(|(target, _)| target.view.view.area() == area)
    {
        return Err(RESOURCES);
    }
    let rows = &mut *core::ptr::addr_of_mut!(SOURCES);
    let mut index = 0;
    while index < rows.len() {
        let key = rows[index].owner.descriptor();
        if key.area != area {
            index += 1;
            continue;
        }
        let row = &mut rows[index];
        // A refused initializer may already own retirement cleanup without ever becoming Ready.
        row.retiring |= row.owner.is_retiring();
        if !row.retiring {
            if frame_acquisition::backing_release_available()
                && temporary_frame_alias::backing_release_available()
                && row.owner.abort_unentered(key)
            {
                rows.remove(index);
                continue;
            }
            let frame = row.owner.ready_frame().ok_or(RESOURCES)?;
            if hosted_private_page_installation::references_source_cap(frame.cap) {
                return Err(RESOURCES);
            }
            if !row.owner.begin_retirement(key) {
                return Err(RESOURCES);
            }
            row.retiring = true;
        }
        match row.owner.advance(&mut PurgeIo {
            revoke_acked: &mut row.revoke_acked,
        }) {
            ImageSourcePageOutcome::Retired | ImageSourcePageOutcome::Failed(_) => {
                rows.remove(index);
            }
            ImageSourcePageOutcome::Retained(status)
            | ImageSourcePageOutcome::Quarantined(status) => return Err(status),
            ImageSourcePageOutcome::Ready(_) => return Err(INVALID),
        }
    }
    Ok(())
}

struct PurgeIo<'a> {
    revoke_acked: &'a mut bool,
}
impl ImageSourcePageIo<SourceKey> for PurgeIo<'_> {
    fn acquire(&mut self, _: SourceKey) -> Result<InstallationCap, u32> {
        Err(INVALID)
    }
    fn initialize(&mut self, _: SourceKey, _: InstallationCap) -> InstallationEffect {
        InstallationEffect::Refused(INVALID)
    }
    fn release(&mut self, key: SourceKey, frame: InstallationCap) -> InstallationEffect {
        release_source(key, frame, self.revoke_acked)
    }
}

pub(crate) unsafe fn drain_view(
    handler: &ExecNtHandler,
    view: NativeImageViewDescriptor,
) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    let pending = &mut *core::ptr::addr_of_mut!(INSTALL);
    if let Some(owner) = pending
        .as_mut()
        .filter(|owner| owner.descriptor().view == view)
    {
        if owner.abort_unentered(owner.descriptor()) {
            *pending = None;
        } else {
            match owner.advance(&mut ViewIo { handler }) {
                BorrowedPageInstallOutcome::Published | BorrowedPageInstallOutcome::Failed(_) => {
                    *pending = None
                }
                BorrowedPageInstallOutcome::Retained(status)
                | BorrowedPageInstallOutcome::Quarantined(status) => return Err(status),
            }
        }
    }
    hosted_private_page_installation::drain_for_process(handler, view.process)?;
    let preparation = &mut *core::ptr::addr_of_mut!(COW_SOURCE);
    if preparation.is_some_and(|(target, _)| target.view == view) {
        *preparation = None;
    }
    Ok(())
}
