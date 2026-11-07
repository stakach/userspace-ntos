//! Retained routed SEC_IMAGE page-ins for faults and syscall copy probes.

use crate::*;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_address_space::{FaultAccess, ImageFaultObservation};
use nt_io_manager::{DeviceId, ExternalDispatchResult, FileId, IoParameters, ReadWriteParameters};
use nt_memory_manager::image_section::ImageAreaId;
use nt_memory_manager::image_source_page::{
    routed_source_read_decision, RoutedSourceReadDecision,
};
use nt_memory_manager::local_pagein_drive::{DriveDecision, DriveStep, LocalDriveBudget};
use nt_memory_manager::routed_image_read::RoutedImageRead;
use nt_memory_manager::RoutedSectionLease;
use nt_pe_loader::{ImagePageFileSpan, ImagePageFillCapture};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

type ImageRead = RoutedImageRead<
    (ImageAreaId, RoutedSectionLease), u64, driver_launch::hosted_file_capture::Capture,
>;
const RESOURCES: u32 = nt_address_space::STATUS_INSUFFICIENT_RESOURCES;
const INVALID: u32 = nt_fs::STATUS_INVALID_HANDLE;
const RETRY_DELAY: u64 = 1_000_000;
const COPY_FAULT: u32 = nt_address_space::STATUS_ACCESS_VIOLATION;

#[derive(Clone, Copy)]
struct SyscallCopy {
    service: CopyService,
    args: [u64; 4],
    origin: nt_syscall::SyscallOrigin,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
}

#[derive(Clone, Copy)]
enum CopyService { NtQuerySystemInformation, NtQueryDefaultLocale }
impl CopyService {
    const fn number(self) -> u32 {
        match self {
            Self::NtQuerySystemInformation => SSN_NT_QUERY_SYSTEM_INFO as u32,
            Self::NtQueryDefaultLocale => SSN_NT_QUERY_DEFAULT_LOCALE as u32,
        }
    }
    const fn argument_count(self) -> usize {
        match self { Self::NtQuerySystemInformation => 4, Self::NtQueryDefaultLocale => 2 }
    }
}

#[derive(Clone, Copy)]
enum Purpose {
    Fault,
    SyscallCopy(SyscallCopy),
    VmLock { token: u64, caller_pi: usize },
    VmCopy { token: u64, caller_pi: usize, service_number: u32 },
    RoutedFileModeInput {
        identity: nt_io_manager::PendingFileIoIdentity,
        irp_id: u64,
        token: u64,
    },
}

#[derive(Clone, Copy)]
enum Phase { AwaitSource, Read, Publish, MapPage, ScanSyscall, DispatchSyscall, ReplyReady, ReadyError, ReplyEntered, ReplySent, Cancel, Cancelled, Indeterminate }
const LOCAL_FAULT_STEPS: usize = 16;

struct Work {
    pi: usize,
    tid: u64,
    badge: u64,
    reply: u64,
    logical: ProviderLogicalCaller,
    view: exec_handler::native_image_view::NativeImageViewDescriptor,
    page: u64,
    rva: u32,
    access: FaultAccess,
    observation: ImageFaultObservation,
    info: nt_address_space::VmBasicInformation,
    lease: RoutedSectionLease,
    origin_driver: u64,
    capture: Option<driver_launch::hosted_file_capture::Capture>,
    fill: ImagePageFillCapture,
    span: Option<ImagePageFileSpan>,
    read: Option<ImageRead>,
    phase: Phase,
    failure: Option<u32>,
    failure_logged: bool,
    cancel_requested: bool,
    purpose: Purpose,
    progress: nt_syscall::copy_preflight::CopyOutputContinuation,
    drive_progress: bool,
}

impl Work {
    fn capture(&self) -> &driver_launch::hosted_file_capture::Capture {
        self.read.as_ref().map(ImageRead::owner)
            .or(self.capture.as_ref())
            .expect("retained native image File capture")
    }
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);
static EXECUTING_TID: AtomicU64 = AtomicU64::new(0);
static EXECUTING_PI: AtomicU64 = AtomicU64::new(u64::MAX);
static EXECUTING_CALLER_PI: AtomicU64 = AtomicU64::new(u64::MAX);
static EXECUTING_INDEX: AtomicU64 = AtomicU64::new(u64::MAX);
// The active row is temporarily absent from WORK while redrive can pump a provider.
// Keep its exact source key visible to a nested fault admission until it is reinserted.
static mut EXECUTING_SOURCE: Option<(ImageAreaId, u32, Phase)> = None;
static NEXT: AtomicU64 = AtomicU64::new(0);
static ADMISSIONS: AtomicU64 = AtomicU64::new(0);
static UNREADY_FAULT_TRACE: AtomicU64 = AtomicU64::new(0);

fn has_source_producer(area: ImageAreaId, rva: u32) -> bool {
    unsafe {
        (&*core::ptr::addr_of!(EXECUTING_SOURCE))
            .is_some_and(|(active_area, active_rva, phase)|
                active_area == area && active_rva == rva
                    && matches!(phase, Phase::Read | Phase::Publish))
            || (&*core::ptr::addr_of!(WORK)).iter().flatten().any(|row|
                row.view.view.area() == area && row.rva == rva
                    && matches!(row.phase, Phase::Read | Phase::Publish))
    }
}

fn has_uncertain_source_owner(area: ImageAreaId, rva: u32) -> bool {
    unsafe { (&*core::ptr::addr_of!(WORK)).iter().flatten().any(|row|
        row.view.view.area() == area && row.rva == rva
            && matches!(row.phase, Phase::Indeterminate)) }
}

unsafe fn prepare_page(
    handler: &mut ExecNtHandler, pi: usize, page: u64, access: FaultAccess,
    observation: ImageFaultObservation, purpose: Purpose, reply: u64,
    parked: bool,
) -> Result<Option<Work>, u32> {
    let Some(view) = handler.native_image_view_for_page(pi, page)? else { return Ok(None); };
    let Some(source) = handler.image_sections.source_for_view(view.view) else { return Err(INVALID); };
    if !matches!(source.contents, crate::native_image_sections::NativeImageContents::RetainedRouted) {
        return Ok(None);
    }
    if !source.has_readable_image() { return Err(INVALID); }
    let rva = view.section_offset.checked_add(page - view.base)
        .and_then(|offset| u32::try_from(offset).ok()).ok_or(INVALID)?;
    let existing = crate::native_image_residency::has_source_row(view.view.area(), rva);
    let source_ready = crate::native_image_residency::source_page_ready(view.view.area(), rva);
    let producer = has_source_producer(view.view.area(), rva);
    let uncertain = has_uncertain_source_owner(view.view.area(), rva);
    let decision = routed_source_read_decision(existing, source_ready, producer, uncertain);
    if matches!(purpose, Purpose::Fault) && existing && !source_ready {
        let sequence = UNREADY_FAULT_TRACE.fetch_add(1, Ordering::Relaxed);
        if sequence < 16 || sequence.is_power_of_two() {
            let mut record = nt_printf::record::RecordBuffer::<320>::new();
            let _ = writeln!(record,
                "[native-image-pagein] unready fault area={:?} rva=0x{:x} state={:?} producer={} page=0x{:x}",
                view.view.area(), rva,
                crate::native_image_residency::source_page_state(view.view.area(), rva),
                producer, page);
            sel4_rt::print_record(if record.overflowed() {
                b"[native-image-pagein] unready fault trace truncated\n"
            } else { record.bytes() });
        }
    }
    if matches!(purpose, Purpose::Fault)
        && decision == RoutedSourceReadDecision::Ready
    { return Ok(None); }
    if matches!(purpose, Purpose::SyscallCopy(_) | Purpose::VmLock { .. } | Purpose::VmCopy { .. }
        | Purpose::RoutedFileModeInput { .. })
        && (source_ready
            || crate::native_image_residency::has_private_page(view, page))
    { return Ok(None); }
    if existing && !parked && matches!(purpose, Purpose::SyscallCopy(_) | Purpose::VmLock { .. }
        | Purpose::VmCopy { .. } | Purpose::RoutedFileModeInput { .. })
        && !producer
    {
        // A retained synchronous source initializer has no asynchronous producer here.
        // The canonical probe owns its result; a second File READ would be a replay.
        return Ok(None);
    }
    let lease = source.backing.routed_lease.ok_or(INVALID)?;
    let plan = source.layout.image_page_fill_plan(rva, source.backing.file_extent)
        .map_err(|_| INVALID)?;
    let (file, device, context, granted_access) =
        crate::hosted_routed_image_capture::route(lease, view.view.area()).ok_or(INVALID)?;
    let info = process_committed_mapping_basic_information(pi as u64, page)
        .ok_or(nt_address_space::STATUS_NOT_COMMITTED)?;
    if info.state != nt_address_space::MEM_COMMIT || info.type_ != nt_address_space::MEM_IMAGE
        || info.allocation_base != view.base
    {
        return Err(INVALID);
    }
    nt_address_space::image_view_fault_access_status(info.protect, access)?;
    let tid = handler.current_tid;
    let tcb = handler.hosted_thread_tcb(tid).ok_or(INVALID)?;
    let caller_pi = match purpose {
        Purpose::VmLock { caller_pi, .. } | Purpose::VmCopy { caller_pi, .. } => caller_pi,
        _ => pi,
    };
    let logical = handler.capture_provider_logical_caller(
        caller_pi, tid, handler.current_badge, tcb,
    ).ok_or(INVALID)?;
    let capture = driver_launch::hosted_file_capture::capture_owned(file, device, granted_access)?;
    if capture.fs_context() != context { return Err(INVALID); }
    let origin_driver = driver_launch::io_manager_mut().device(DeviceId(device))
        .ok_or(INVALID)?.driver_id.raw();
    Ok(Some(Work {
        pi, tid, badge: handler.current_badge, reply, logical, view, page, rva, access,
        observation, info, lease, origin_driver, capture: Some(capture),
        fill: ImagePageFillCapture::new(plan), span: None, read: None,
        phase: if decision == RoutedSourceReadDecision::EnterRead {
            Phase::Read
        } else { Phase::AwaitSource },
        failure: None, failure_logged: false, cancel_requested: false,
        purpose, progress: nt_syscall::copy_preflight::CopyOutputContinuation::PageReady,
        drive_progress: false,
    }))
}

unsafe fn install_work(work: Work, reply_already_parked: bool) -> Result<(), u32> {
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let index = rows.iter().enumerate().find_map(|(index, row)|
        (row.is_none() && EXECUTING_INDEX.load(Ordering::Acquire) != index as u64).then_some(index));
    if index.is_none() && rows.try_reserve(1).is_err() { return Err(RESOURCES); }
    let park = if reply_already_parked { None } else {
        Some(root_reply_park::RootReplyPark::prepare().ok_or(RESOURCES)?)
    };
    match index { Some(index) => rows[index] = Some(work), None => rows.push(Some(work)) }
    if let Some(park) = park { park.commit(); }
    ADMISSIONS.fetch_add(1, Ordering::Release);
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    Ok(())
}

/// Returns false for local images, protection faults, or a source page already owned by the
/// canonical cache. No provider effect enters before the original fault Reply is parked.
pub(crate) unsafe fn submit(
    handler: &mut ExecNtHandler, pi: usize, page: u64,
    access: FaultAccess, observation: ImageFaultObservation,
) -> Result<bool, u32> {
    if observation != ImageFaultObservation::NotPresent { return Ok(false); }
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let Some(work) = prepare_page(handler, pi, page, access, observation, Purpose::Fault,
        reply, false)?
        else { return Ok(false); };
    install_work(work, false)?;
    Ok(true)
}

unsafe fn next_syscall_page(
    handler: &mut ExecNtHandler, pi: usize, reply: u64, call: SyscallCopy,
    parked: bool,
) -> Result<Option<Work>, u32> {
    enum Prepared { NoImage, Work(Work), HandlerError }
    let mut prepare = |page| {
        let prepared = unsafe { prepare_page(handler, pi, page, FaultAccess::Write,
            ImageFaultObservation::CopyAccess, Purpose::SyscallCopy(call), reply, parked) };
        match prepared {
            Ok(Some(work)) => Ok(Prepared::Work(work)),
            Ok(None) => Ok(Prepared::NoImage),
            Err(_) if !parked => {
                // The handler owns semantic probe errors before Reply transfer.
                Ok(Prepared::HandlerError)
            }
            Err(status) => Err(status),
        }
    };
    match call.service {
        CopyService::NtQuerySystemInformation => {
            let Ok(pages) = nt_syscall::system_information::QueryOutputPages::new(
                call.args[0] as u32, call.args[1], call.args[2] as u32 as u64,
                call.args[3], USER_ADDRESS_LIMIT,
            ) else {
                // Preserve the ordinary handler's class, alignment, and probe precedence.
                return Ok(None);
            };
            for page in pages {
                match prepare(page)? {
                    Prepared::Work(work) => return Ok(Some(work)),
                    Prepared::HandlerError => return Ok(None),
                    Prepared::NoImage => {}
                }
            }
        }
        CopyService::NtQueryDefaultLocale => {
            // The handler owns null, alignment and range errors before any user copyout.
            if let Some(page) = nt_syscall::copy_preflight::query_default_locale_output_page(
                call.args[1], USER_ADDRESS_LIMIT,
            ) {
                return match prepare(page)? {
                    Prepared::Work(work) => Ok(Some(work)),
                    Prepared::NoImage | Prepared::HandlerError => Ok(None),
                };
            }
        }
    }
    Ok(None)
}

/// Park a native Call before a routed image output probe can enter a pending File READ.
/// No syscall handler or user-output probe runs until every required source is ready.
pub(crate) unsafe fn submit_syscall_copy(
    handler: &mut ExecNtHandler, pi: usize, service_number: u32, args: [u64; 4],
    origin: nt_syscall::SyscallOrigin, resume_ip: u64, sp: u64, flags: u64,
    native_call_transport: bool,
) -> Result<bool, u32> {
    let service = match service_number {
        number if number == SSN_NT_QUERY_SYSTEM_INFO as u32 =>
            CopyService::NtQuerySystemInformation,
        number if number == SSN_NT_QUERY_DEFAULT_LOCALE as u32 =>
            CopyService::NtQueryDefaultLocale,
        _ => return Ok(false),
    };
    let call = SyscallCopy { service, args, origin, resume_ip, sp, flags, native_call_transport };
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let Some(work) = next_syscall_page(handler, pi, reply, call, false)?
        else { return Ok(false); };
    install_work(work, false)?;
    Ok(true)
}

/// The VM-lock coordinator owns the parked syscall Reply; this row owns only
/// the target image source and page mapping. Foreign caller PI is retained separately.
pub(crate) unsafe fn submit_for_vm_lock(
    handler: &mut ExecNtHandler, caller_pi: usize, target_pi: usize,
    page: u64, access: FaultAccess, reply: u64, token: u64,
) -> Result<Option<crate::routed_pagein_source::RoutedPageInSource>, u32> {
    let Some(work) = prepare_page(handler, target_pi, page, access,
        ImageFaultObservation::CopyAccess, Purpose::VmLock { token, caller_pi }, reply, true)?
    else { return Ok(None); };
    let source = crate::routed_pagein_source::RoutedPageInSource::Image {
        view: work.view, lease: work.lease,
    };
    install_work(work, true)?;
    Ok(Some(source))
}

/// The VM-copy coordinator owns the parked syscall Reply. This row owns only the exact routed
/// image page and provider read until terminal copy, ACK and target map proof.
pub(crate) unsafe fn submit_for_vm_copy(
    handler: &mut ExecNtHandler, caller_pi: usize, target_pi: usize,
    page: u64, access: FaultAccess, reply: u64, token: u64,
) -> Result<Option<crate::routed_pagein_source::RoutedPageInSource>, u32> {
    let service_number = handler.current_service_number;
    let Some(work) = prepare_page(handler, target_pi, page, access,
        ImageFaultObservation::CopyAccess,
        Purpose::VmCopy { token, caller_pi, service_number }, reply, true)?
    else { return Ok(None); };
    let source = crate::routed_pagein_source::RoutedPageInSource::Image {
        view: work.view, lease: work.lease,
    };
    install_work(work, true)?;
    Ok(Some(source))
}

/// The pending File row has already parked the original syscall Reply; this worker owns only
/// its exact image source and maps the input page before returning a tokenized completion.
pub(crate) unsafe fn submit_for_file_mode_input(
    handler: &mut ExecNtHandler, pi: usize, page: u64, reply: u64,
    identity: nt_io_manager::PendingFileIoIdentity, irp_id: u64, token: u64,
) -> Result<Option<crate::routed_pagein_source::RoutedPageInSource>, u32> {
    let Some(work) = prepare_page(handler, pi, page, FaultAccess::Read,
        ImageFaultObservation::CopyAccess,
        Purpose::RoutedFileModeInput { identity, irp_id, token }, reply, true)?
    else { return Ok(None); };
    let source = crate::routed_pagein_source::RoutedPageInSource::Image {
        view: work.view, lease: work.lease,
    };
    install_work(work, true)?;
    Ok(Some(source))
}

pub(crate) fn has_thread(tid: u64) -> bool {
    EXECUTING_TID.load(Ordering::Acquire) == tid
        || unsafe { (&*core::ptr::addr_of!(WORK)).iter().flatten().any(|work| work.tid == tid) }
}

pub(crate) fn has_process(pi: usize, preserve_tid: Option<u64>) -> bool {
    ((EXECUTING_PI.load(Ordering::Acquire) == pi as u64
        || EXECUTING_CALLER_PI.load(Ordering::Acquire) == pi as u64)
        && preserve_tid != Some(EXECUTING_TID.load(Ordering::Acquire)))
        || unsafe { (&*core::ptr::addr_of!(WORK)).iter().flatten()
            .any(|work| (work.pi == pi || work.logical.pi() == pi)
                && preserve_tid != Some(work.tid)) }
}

pub(crate) fn next_deadline() -> Option<u64> {
    (EXECUTING_TID.load(Ordering::Acquire) != 0
        || unsafe { (&*core::ptr::addr_of!(WORK)).iter().any(Option::is_some) })
        .then(|| NEXT.load(Ordering::Acquire))
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

fn valid(handler: &ExecNtHandler, work: &Work) -> bool {
    if handler.capture_process_identity(work.pi) != Some(work.view.process)
        || !handler.validate_provider_logical_caller(work.logical)
        || handler.native_image_view_for_page(work.pi, work.page).ok().flatten() != Some(work.view)
    { return false; }
    let Some(source) = handler.image_sections.source_for_view(work.view.view) else { return false; };
    if !source.has_readable_image()
        || !matches!(source.contents, crate::native_image_sections::NativeImageContents::RetainedRouted)
        || source.backing.routed_lease != Some(work.lease)
    { return false; }
    let Some((file, device, context, granted_access)) =
        (unsafe { crate::hosted_routed_image_capture::route(work.lease, work.view.view.area()) })
    else { return false; };
    let capture = work.capture();
    file == capture.file_id() && device == capture.device_id()
        && context == capture.fs_context() && granted_access == capture.granted_access()
        && unsafe { process_committed_mapping_basic_information(work.pi as u64, work.page) }
            == Some(work.info)
        && nt_address_space::image_view_fault_access_status(work.info.protect, work.access).is_ok()
}

unsafe fn advance_read(work: &mut Work, cancelled: bool) {
    if work.read.is_none() {
        if cancelled { work.phase = Phase::Cancel; return; }
        let Some(span) = work.fill.next_span() else { work.phase = Phase::Publish; return; };
        let capture = work.capture.take().expect("native image File between spans");
        let read = match ImageRead::new_at(
            (work.view.view.area(), work.lease), span.file_offset,
            u64::from(span.length), 4096, capture,
        ) {
            Ok(read) => read,
            Err(capture) => {
                work.capture = Some(capture);
                work.failure = Some(RESOURCES);
                work.phase = if matches!(work.purpose, Purpose::SyscallCopy(_)) {
                    Phase::ReadyError
                } else { Phase::Cancel };
                return;
            }
        };
        work.span = Some(span);
        work.read = Some(read);
    }
    let read = work.read.as_mut().unwrap();
    if let Some(result) = read.terminal_result() {
        let (capture, bytes) = work.read.take().unwrap().into_terminal()
            .ok().expect("terminal native image page span");
        work.capture = Some(capture);
        match (result, bytes) {
            (Ok(()), Ok(bytes)) if !cancelled => {
                if !work.fill.accept_acknowledged_span(work.span.take().unwrap(), &bytes) {
                    work.phase = Phase::Indeterminate;
                    return;
                }
                work.drive_progress = true;
            }
            (Err(status), _) => {
                work.failure = Some(status);
                work.phase = if !cancelled
                    && matches!(work.purpose, Purpose::SyscallCopy(_))
                { Phase::ReadyError } else { Phase::Cancel };
            }
            _ => work.phase = Phase::Cancel,
        }
        return;
    }
    if cancelled && read.pending_key().is_none() {
        let capture = work.read.take().unwrap().abort_ready()
            .ok().expect("unentered cancelled native image span");
        work.capture = Some(capture);
        work.phase = Phase::Cancel;
        return;
    }
    if let Some((key, offset, remaining)) = read.copy_position() {
        let mut bytes = [0u8; 4096];
        let limit = remaining.min(bytes.len());
        let copied = match driver_launch::copy_completed_irp_output_exact(
            key, offset as u64, &mut bytes[..limit],
        ) {
            Ok(copied) if copied != 0 && copied <= limit => copied,
            Ok(_) => {
                if !read.fail_copy(key, nt_memory_manager::routed_image_read::STATUS_IO_DEVICE_ERROR) {
                    read.quarantine();
                    work.phase = Phase::Indeterminate;
                } else {
                    work.drive_progress = true;
                }
                return;
            }
            Err(status) => {
                if !read.fail_copy(key, status) {
                    read.quarantine();
                    work.phase = Phase::Indeterminate;
                } else {
                    work.drive_progress = true;
                }
                return;
            }
        };
        if !read.copy_fragment(key, offset, &bytes[..copied]) {
            read.quarantine();
            work.phase = Phase::Indeterminate;
        } else {
            work.drive_progress = true;
        }
        return;
    }
    if let Some(key) = read.acknowledgment_key() {
        work.phase = Phase::Indeterminate;
        if driver_launch::io_manager_mut()
            .acknowledge_completed_irp_strict(nt_io_manager::IrpId(key)).is_err()
        { return; }
        if !read.acknowledge(key) { read.quarantine(); return; }
        work.phase = Phase::Read;
        work.drive_progress = true;
        return;
    }
    if let Some(key) = read.pending_key() {
        if cancelled && !work.cancel_requested {
            work.cancel_requested = true;
            let _ = driver_launch::cancel_irp_if_pending(key);
        }
        let Some(completion) = driver_launch::completed_irp_exact(key) else { return; };
        let capture = read.owner();
        if completion.client_id != driver_launch::IO_MANAGER_COMPONENT_ID
            || completion.driver_id != work.origin_driver
            || completion.completion_driver_id != work.origin_driver
            || completion.file_id != capture.file_id()
            || completion.device_id != capture.device_id()
            || completion.completion_device_id != capture.device_id()
            || completion.requestor_tid != work.tid
            || completion.major != nt_io_abi::major::IRP_MJ_READ
        {
            read.quarantine();
            work.phase = Phase::Indeterminate;
            return;
        }
        if !read.terminal(key, completion.status, completion.information) {
            read.quarantine();
            work.phase = Phase::Indeterminate;
        } else {
            work.drive_progress = true;
        }
        return;
    }
    if cancelled { work.phase = Phase::Cancel; return; }
    let (area, lease) = read.source();
    let capture = read.owner();
    let Some((file, device, context, _)) =
        crate::hosted_routed_image_capture::route(lease, area)
    else {
        let _ = read.enter_window();
        if !read.reject_entry(INVALID) {
            read.quarantine();
            work.phase = Phase::Indeterminate;
        } else {
            work.drive_progress = true;
        }
        return;
    };
    if (file, device, context) != (capture.file_id(), capture.device_id(), capture.fs_context()) {
        let _ = read.enter_window();
        if !read.reject_entry(INVALID) {
            read.quarantine();
            work.phase = Phase::Indeterminate;
        } else {
            work.drive_progress = true;
        }
        return;
    }
    let Some(window) = read.enter_window() else { return; };
    let mut output = Vec::new();
    if output.try_reserve_exact(window.length).is_err() {
        if !read.reject_entry(RESOURCES) {
            read.quarantine();
            work.phase = Phase::Indeterminate;
        } else {
            work.drive_progress = true;
        }
        return;
    }
    output.resize(window.length, 0);
    let result = driver_launch::io_manager_mut().build_and_dispatch_external_to_device(
        nt_types::ClientId(driver_launch::IO_MANAGER_COMPONENT_ID), DeviceId(device),
        Some(FileId(file)), 0, work.tid, nt_io_abi::major::IRP_MJ_READ,
        IoParameters::Read(ReadWriteParameters {
            length: window.length as u32, key: 0, offset: window.offset,
        }),
        0, window.length as u32, &mut output,
    );
    match result {
        Ok(ExternalDispatchResult::Completed { status, information, .. }) => {
            if !read.complete_inline(status.raw() as u32, information, &output) {
                read.quarantine();
                work.phase = Phase::Indeterminate;
            } else {
                work.drive_progress = true;
            }
        }
        Ok(ExternalDispatchResult::Pending { irp_id }) => {
            if !read.bind_pending(irp_id.raw()) {
                read.quarantine();
                work.phase = Phase::Indeterminate;
            }
        }
        Err(status) => {
            if !read.reject_entry(status.raw() as u32) {
                read.quarantine();
                work.phase = Phase::Indeterminate;
            } else {
                work.drive_progress = true;
            }
        }
    }
}

unsafe fn advance(
    handler: &mut ExecNtHandler, dispatcher: &NativeSyscallDispatcher, work: &mut Work,
) -> bool {
    let cancelled = spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(work.reply)
        || handler.pm.thread(work.logical.thread().thread_id())
            .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
        || handler.pm.process(work.logical.process().pid)
            .is_some_and(|process| process.state == nt_process::ProcessState::Terminated)
        || !valid(handler, work);
    match work.phase {
        Phase::AwaitSource => {
            if cancelled { work.phase = Phase::Cancel; }
            else {
                let area = work.view.view.area();
                match routed_source_read_decision(
                    crate::native_image_residency::has_source_row(area, work.rva),
                    crate::native_image_residency::source_page_ready(area, work.rva),
                    has_source_producer(area, work.rva),
                    has_uncertain_source_owner(area, work.rva),
                ) {
                    RoutedSourceReadDecision::Ready => work.phase = Phase::MapPage,
                    RoutedSourceReadDecision::EnterRead => work.phase = Phase::Read,
                    RoutedSourceReadDecision::AwaitProducer => {},
                    RoutedSourceReadDecision::RetainUncertain => {
                        // No exact producer can complete the source. Keep the original Reply.
                        work.failure = Some(RESOURCES);
                        work.phase = Phase::Indeterminate;
                    }
                }
            }
            false
        }
        Phase::Read => { advance_read(work, cancelled); false }
        Phase::Publish => {
            if cancelled { work.phase = Phase::Cancel; return false; }
            let Some(bytes) = work.fill.completed_page() else {
                work.phase = Phase::Indeterminate;
                return false;
            };
            if let Err(status) = crate::native_image_residency::ensure_source_page_from_acknowledged_bytes(
                handler, work.view, work.rva, bytes,
            ) {
                work.failure = Some(status);
                work.phase = if matches!(work.purpose, Purpose::Fault) {
                    Phase::Cancel
                } else {
                    // The source owner can be retained or quarantined after a physical effect.
                    Phase::Indeterminate
                };
                return false;
            }
            work.phase = Phase::MapPage;
            false
        }
        Phase::MapPage => {
            if cancelled { work.phase = Phase::Cancel; return false; }
            if matches!(work.purpose, Purpose::SyscallCopy(_))
                && !work.progress.enter_map()
            { work.phase = Phase::Indeterminate; return false; }
            let mapped = handler.service_native_image_page_residency(
                work.pi, work.page, work.access, work.observation,
            );
            match mapped {
                Ok(Some(())) if valid(handler, work) => {}
                other => {
                    work.failure = Some(other.err().unwrap_or(INVALID));
                    work.phase = if matches!(work.purpose, Purpose::Fault) {
                        Phase::Cancel
                    } else { Phase::Indeterminate };
                    return false;
                }
            }
            if matches!(work.purpose, Purpose::SyscallCopy(_)) {
                assert!(work.progress.map_completed());
                work.phase = Phase::ScanSyscall;
            } else {
                work.phase = Phase::ReplyReady;
            }
            false
        }
        Phase::ScanSyscall => {
            if cancelled { work.phase = Phase::Cancel; return false; }
            let Purpose::SyscallCopy(call) = work.purpose else {
                work.phase = Phase::Indeterminate;
                return false;
            };
            match next_syscall_page(handler, work.pi, work.reply, call, true) {
                Ok(Some(next)) => { *work = next; }
                Err(RESOURCES) => {}
                Err(status) => {
                    work.failure = Some(status);
                    assert!(work.progress.fail_before_dispatch(COPY_FAULT));
                    work.phase = Phase::ReplyReady;
                }
                Ok(None) => work.phase = Phase::DispatchSyscall,
            }
            false
        }
        Phase::DispatchSyscall => {
            if cancelled { work.phase = Phase::Cancel; return false; }
            let Purpose::SyscallCopy(call) = work.purpose else {
                work.phase = Phase::Indeterminate;
                return false;
            };
            if !work.progress.enter_dispatch() { work.phase = Phase::Indeterminate; return false; }
            // Entered before dispatch: even an uncertain handler effect cannot be replayed.
            work.phase = Phase::Indeterminate;
            let previous_memory = handler.current_user_memory;
            let previous_post = handler.post_action;
            let previous_stop = handler.stop;
            let previous_writes = handler.out_writes_n;
            handler.current_user_memory = SyscallUserMemory::CurrentProcess;
            handler.post_action = ExecPostAction::None;
            handler.stop = false;
            handler.out_writes_n = 0;
            crate::probe_reset();
            let result = dispatcher.dispatch(call.service.number(),
                &call.args[..call.service.argument_count()], &call.origin, handler);
            assert_eq!(handler.post_action, ExecPostAction::None,
                "copy output continuation cannot transfer its Reply");
            assert!(!handler.stop && handler.out_writes_n == 0
                && handler.current_apc_handoff.is_none()
                && handler.pending_synchronous_file_wait.is_none(),
                "copy output continuation cannot enter another async effect");
            handler.current_user_memory = previous_memory;
            handler.post_action = previous_post;
            handler.stop = previous_stop;
            handler.out_writes_n = previous_writes;
            assert!(work.progress.dispatch_completed(result.status));
            work.phase = Phase::ReplyReady;
            false
        }
        Phase::ReplyReady => {
            if cancelled { work.phase = Phase::Cancel; return false; }
            if parked_reply::validate_saved(work.reply).is_err() { return false; }
            work.phase = Phase::ReplyEntered;
            if matches!(work.purpose, Purpose::VmLock { .. } | Purpose::VmCopy { .. }
                | Purpose::RoutedFileModeInput { .. }) {
                let source = crate::routed_pagein_source::RoutedPageInSource::Image {
                    view: work.view, lease: work.lease,
                };
                let completed = match work.purpose {
                    Purpose::VmLock { token, .. } => crate::vm_lock_pagein_work::page_completed(
                        token, work.pi, work.page, source, 0),
                    Purpose::VmCopy { token, .. } => crate::vm_copy_work::page_completed(
                        token, work.pi, work.page, source, 0),
                    Purpose::RoutedFileModeInput { identity, irp_id, token } =>
                        crate::service_sec_image::file_mode_input_page_completed(
                            identity, irp_id, token, work.pi, work.page, 0),
                    Purpose::Fault | Purpose::SyscallCopy(_) => unreachable!(),
                };
                if completed {
                    return true;
                }
                work.phase = Phase::Indeterminate;
                return false;
            }
            let sent = match work.purpose {
                Purpose::Fault => client_reply_on(work.reply, 0, 0, 0, 0, 0),
                Purpose::SyscallCopy(_) => {
                    let status = work.progress.reply_status()
                        .expect("retained copy Reply has terminal status");
                    assert!(work.progress.enter_reply());
                    reply_parked_syscall(work.reply, u64::from(status))
                }
                Purpose::VmLock { .. } | Purpose::VmCopy { .. }
                | Purpose::RoutedFileModeInput { .. } =>
                    unreachable!("retained VM operation returns through its coordinator"),
            };
            if !sent { return false; }
            crate::note_boot_progress(crate::BootProgress::PageMappingPublished);
            work.phase = Phase::ReplySent;
            false
        }
        Phase::ReadyError => {
            if cancelled { work.phase = Phase::Cancel; return false; }
            if !work.progress.fail_before_dispatch(COPY_FAULT) {
                work.phase = Phase::Indeterminate;
                return false;
            }
            work.phase = Phase::ReplyReady;
            false
        }
        Phase::ReplyEntered => {
            match spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                work.reply,
            ) {
                Ok(true) => work.phase = Phase::ReplySent,
                _ if cancelled => work.phase = Phase::Indeterminate,
                _ => {}
            }
            false
        }
        Phase::ReplySent => {
            if parked_reply::retire_sent(work.reply).is_err() { return false; }
            thread_wait_state_clear_badge_ready(handler, work.badge);
            true
        }
        Phase::Cancel => {
            if matches!(work.purpose, Purpose::VmLock { .. } | Purpose::VmCopy { .. }
                | Purpose::RoutedFileModeInput { .. }) {
                let source = crate::routed_pagein_source::RoutedPageInSource::Image {
                    view: work.view, lease: work.lease,
                };
                let status = work.failure.unwrap_or(INVALID);
                let completed = match work.purpose {
                    Purpose::VmLock { token, .. } => crate::vm_lock_pagein_work::page_completed(
                        token, work.pi, work.page, source, status),
                    Purpose::VmCopy { token, .. } => crate::vm_copy_work::page_completed(
                        token, work.pi, work.page, source, status),
                    Purpose::RoutedFileModeInput { identity, irp_id, token } =>
                        crate::service_sec_image::file_mode_input_page_completed(
                            identity, irp_id, token, work.pi, work.page, status),
                    Purpose::Fault | Purpose::SyscallCopy(_) => unreachable!(),
                };
                if completed {
                    return true;
                }
                work.phase = Phase::Indeterminate;
                return false;
            }
            if let Some(status) = work.failure.filter(|_| !work.failure_logged) {
                print_str(b"[native-image-pagein] failed pi="); print_u64(work.pi as u64);
                print_str(b" page=0x");
                print_hex((work.page >> 32) as u32);
                print_hex(work.page as u32);
                print_str(b" status=0x"); print_hex(status);
                print_str(b"\n");
                work.failure_logged = true;
            }
            if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(work.reply) {
                if !spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(work.reply)
                    && spawn_hosts::shared_ingress::owner::runtime::stop_and_cancel_hosted(work.reply)
                        .is_err()
                { return false; }
            } else if parked_reply::revoke(work.reply).is_err() { return false; }
            work.phase = Phase::Cancelled;
            false
        }
        Phase::Cancelled => {
            if parked_reply::retype(work.reply).is_err() { return false; }
            true
        }
        Phase::Indeterminate => {
            if !work.failure_logged {
                print_str(b"[native-image-pagein] retained uncertain owner pi=");
                print_u64(work.pi as u64);
                print_str(b" page=0x");
                print_hex((work.page >> 32) as u32);
                print_hex(work.page as u32);
                print_str(b" status=0x");
                print_hex(work.failure.unwrap_or(RESOURCES));
                print_str(b"\n");
                work.failure_logged = true;
            }
            false
        }
    }
}

pub(crate) unsafe fn redrive(
    handler: &mut ExecNtHandler, dispatcher: &NativeSyscallDispatcher,
) {
    if next_deadline().is_none_or(|deadline| monotonic_time_100ns() < deadline)
        || ACTIVE.swap(true, Ordering::AcqRel)
    { return; }
    let _durable = allocator::enter_durable();
    let admissions_before = ADMISSIONS.load(Ordering::Acquire);
    let mut immediate_followup = false;
    let count = (&*core::ptr::addr_of!(WORK)).len();
    for index in 0..count {
        let Some(mut work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].take() else { continue; };
        EXECUTING_INDEX.store(index as u64, Ordering::Release);
        EXECUTING_TID.store(work.tid, Ordering::Release);
        EXECUTING_PI.store(work.pi as u64, Ordering::Release);
        *core::ptr::addr_of_mut!(EXECUTING_SOURCE) =
            Some((work.view.view.area(), work.rva, work.phase));
        let (caller_pi, resume_ip, sp, flags, transport, service) = match work.purpose {
            Purpose::Fault => (work.pi, 0, 0, 0, false, 0),
            Purpose::SyscallCopy(call) =>
                (work.pi, call.resume_ip, call.sp, call.flags, call.native_call_transport,
                    call.service.number()),
            Purpose::VmLock { caller_pi, .. } =>
                (caller_pi, 0, 0, 0, false, SSN_NT_LOCK_VM as u32),
            Purpose::VmCopy { caller_pi, service_number, .. } =>
                (caller_pi, 0, 0, 0, false, service_number),
            Purpose::RoutedFileModeInput { .. } => (work.pi, 0, 0, 0, false, 0),
        };
        EXECUTING_CALLER_PI.store(caller_pi as u64, Ordering::Release);
        let is_fault = matches!(work.purpose, Purpose::Fault);
        let mut budget = LocalDriveBudget::new(LOCAL_FAULT_STEPS);
        let done = service_sec_image::with_pagein_caller_target_context(
            handler, caller_pi, work.pi, work.tid, work.badge,
            resume_ip, sp, flags, transport, service,
            |handler| loop {
                // A nested admission can inspect this exact source while its row is absent.
                *core::ptr::addr_of_mut!(EXECUTING_SOURCE) =
                    Some((work.view.view.area(), work.rva, work.phase));
                work.drive_progress = false;
                let before = core::mem::discriminant(&work.phase);
                let done = advance(handler, dispatcher, &mut work);
                if !is_fault { break done; }
                let step = if done { DriveStep::Done }
                    else if matches!(work.phase, Phase::ReplyEntered | Phase::ReplySent) {
                        DriveStep::ReplyEntered
                    } else if work.drive_progress
                        || core::mem::discriminant(&work.phase) != before {
                        DriveStep::LocalProgress
                    } else { DriveStep::AwaitExternal };
                match budget.observe(step) {
                    DriveDecision::Continue => {},
                    DriveDecision::RetryNow => {
                        immediate_followup = true;
                        break false;
                    }
                    DriveDecision::RetryLater => break false,
                    DriveDecision::Complete => break true,
                }
            },
        ).unwrap_or_else(|| {
            let stopped = spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(work.reply)
                || handler.capture_process_identity(work.pi) != Some(work.view.process)
                || !handler.validate_provider_logical_caller(work.logical)
                || handler.pm.thread(work.logical.thread().thread_id())
                    .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
                || handler.pm.process(work.logical.process().pid)
                    .is_some_and(|process| process.state == nt_process::ProcessState::Terminated);
            if !stopped { return false; }
            match work.phase {
                Phase::Read if work.read.as_ref().is_some_and(|read| read.pending_key().is_none()) => {
                    advance_read(&mut work, true);
                    false
                }
                Phase::AwaitSource | Phase::Publish | Phase::MapPage
                    | Phase::ScanSyscall | Phase::DispatchSyscall | Phase::ReplyReady
                    | Phase::ReadyError =>
                    { work.phase = Phase::Cancel; false }
                Phase::Read | Phase::ReplyEntered | Phase::ReplySent | Phase::Cancel
                    | Phase::Cancelled | Phase::Indeterminate =>
                        advance(handler, dispatcher, &mut work),
            }
        });
        if !done { (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work); }
        *core::ptr::addr_of_mut!(EXECUTING_SOURCE) = None;
        EXECUTING_TID.store(0, Ordering::Release);
        EXECUTING_PI.store(u64::MAX, Ordering::Release);
        EXECUTING_CALLER_PI.store(u64::MAX, Ordering::Release);
        EXECUTING_INDEX.store(u64::MAX, Ordering::Release);
    }
    let now = monotonic_time_100ns();
    NEXT.store(if immediate_followup
        || ADMISSIONS.load(Ordering::Acquire) != admissions_before {
        now
    } else { now.saturating_add(RETRY_DELAY) }, Ordering::Release);
    ACTIVE.store(false, Ordering::Release);
}
