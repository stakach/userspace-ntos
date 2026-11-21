//! Retained routed SEC_IMAGE page-ins for faults and syscall copy probes.
//! A selected Receive child's fault is owned here too, with its held parent still parked.

use nt_hosted_runtime::CompletionStep;
use crate::*;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_address_space::{FaultAccess, ImageFaultObservation};
use nt_io_manager::{DeviceId, ExternalDispatchResult, FileId};
use nt_memory_manager::image_section::ImageAreaId;
use nt_memory_manager::image_source_page::{
    routed_source_read_decision, RoutedSourceReadDecision,
};
use nt_memory_manager::local_pagein_drive::{DriveDecision, DriveStep, LocalDriveBudget};
use nt_memory_manager::routed_image_read::RoutedImageRead;
use nt_memory_manager::RoutedSectionLease;
use nt_pe_loader::{ImagePageFileSpan, ImagePageFillCapture};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;
use nt_user_host::receive_child_pagein::{
    ReceiveChildPageIn, ReceiveChildRootAction, ReceiveChildRootEvent,
};

type ReceiveTurn = ReceiveChildPageIn<
    nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
    nt_component_suspension::ExternalAdmissionKey,
    nt_component_suspension::NestedExecutionIdentity,
>;

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
    /// The selected Receive child's fault. This row owns the child's Reply; its CALLS row
    /// owns the held parent and settles it from that one acknowledged Reply.
    ReceiveChild,
    SyscallCopy(SyscallCopy),
    VmLock { token: u64, caller_pi: usize },
    VmCopy { token: u64, caller_pi: usize, service_number: u32 },
    RoutedFileModeInput {
        identity: nt_io_manager::PendingFileIoIdentity,
        irp_id: u64,
        token: u64,
    },
    /// A returned NT dispatch whose input capture needed this page. This row owns the caller's
    /// Reply: a mapped page reissues the call, a failed page-in returns `status`, the
    /// handler's own result.
    SyscallRetry {
        caller_pi: usize,
        retry: nt_syscall_abi::SyscallRetryReply,
        status: u32,
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
    phase_entered_at_100ns: u64,
    pending_irp_since_100ns: Option<u64>,
    failure: Option<u32>,
    failure_logged: bool,
    cancel_requested: bool,
    purpose: Purpose,
    progress: nt_syscall::copy_preflight::CopyOutputContinuation,
    drive_progress: bool,
    receive: Option<ReceiveTurn>,
}

impl Purpose {
    const fn is_fault(self) -> bool { matches!(self, Self::Fault | Self::ReceiveChild) }
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
static mut EXECUTING_PROBE: Option<(nt_hosted_runtime::SpanOwner, u64,
    crate::installer_child_span_census::PageInProbe)> = None;
static NEXT: AtomicU64 = AtomicU64::new(0);
static ADMISSIONS: AtomicU64 = AtomicU64::new(0);
static UNREADY_FAULT_TRACE: AtomicU64 = AtomicU64::new(0);
static SYSCALL_RETRY_TRACE: AtomicU64 = AtomicU64::new(0);

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
    let (tid, badge) = (handler.current_tid, handler.current_badge);
    prepare_page_as(handler, pi, page, access, observation, purpose, reply, parked, tid, badge)
}

/// `tid` and `badge` name the faulting thread explicitly. The Receive root boundary runs
/// before the handler's current-thread selection for its event.
#[allow(clippy::too_many_arguments)]
unsafe fn prepare_page_as(
    handler: &mut ExecNtHandler, pi: usize, page: u64, access: FaultAccess,
    observation: ImageFaultObservation, purpose: Purpose, reply: u64,
    parked: bool, tid: u64, badge: u64,
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
    if purpose.is_fault() && existing && !source_ready {
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
    if purpose.is_fault()
        && decision == RoutedSourceReadDecision::Ready
    { return Ok(None); }
    if matches!(purpose, Purpose::SyscallCopy(_) | Purpose::VmLock { .. } | Purpose::VmCopy { .. }
        | Purpose::RoutedFileModeInput { .. } | Purpose::SyscallRetry { .. })
        && (source_ready
            || crate::native_image_residency::has_private_page(view, page))
    { return Ok(None); }
    if existing && !parked && matches!(purpose, Purpose::SyscallCopy(_) | Purpose::VmLock { .. }
        | Purpose::VmCopy { .. } | Purpose::RoutedFileModeInput { .. }
        | Purpose::SyscallRetry { .. })
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
    let tcb = handler.hosted_thread_tcb(tid).ok_or(INVALID)?;
    let caller_pi = match purpose {
        Purpose::VmLock { caller_pi, .. } | Purpose::VmCopy { caller_pi, .. }
        | Purpose::SyscallRetry { caller_pi, .. } => caller_pi,
        _ => pi,
    };
    let logical = handler.capture_provider_logical_caller(
        caller_pi, tid, badge, tcb,
    ).ok_or(INVALID)?;
    let capture = driver_launch::hosted_file_capture::capture_owned(file, device, granted_access)?;
    if capture.fs_context() != context { return Err(INVALID); }
    let origin_driver = driver_launch::io_manager_mut().device(DeviceId(device))
        .ok_or(INVALID)?.driver_id.raw();
    Ok(Some(Work {
        pi, tid, badge, reply, logical, view, page, rva, access,
        observation, info, lease, origin_driver, capture: Some(capture),
        fill: ImagePageFillCapture::new(plan), span: None, read: None,
        phase: if decision == RoutedSourceReadDecision::EnterRead {
            Phase::Read
        } else { Phase::AwaitSource },
        phase_entered_at_100ns: monotonic_time_100ns(),
        pending_irp_since_100ns: None,
        failure: None, failure_logged: false, cancel_requested: false,
        purpose, progress: nt_syscall::copy_preflight::CopyOutputContinuation::PageReady,
        drive_progress: false, receive: None,
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

/// Own the selected Receive child's fault when its routed source page is not ready. The child
/// Reply is parked before any provider READ; the held parent stays in the child's CALLS row.
/// Returns false, with no effect, for a ready, local or legacy page.
pub(crate) unsafe fn submit_receive_child(
    handler: &mut ExecNtHandler,
    child: nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
    admission: nt_component_suspension::ExternalAdmissionKey,
    parent: nt_component_suspension::NestedExecutionIdentity,
    page: u64, access: FaultAccess, observation: ImageFaultObservation,
) -> Result<bool, u32> {
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    if admission.reply() != reply || admission.executor() != child.tcb
        || handler.hosted_thread_tcb(child.tid) != Some(child.tcb)
        || owns_receive_child()
    {
        return Err(INVALID);
    }
    let turn = ReceiveTurn::admit(child, admission, parent, page).map_err(|_| INVALID)?;
    let Some(mut work) = prepare_page_as(handler, child.pi, page, access, observation,
        Purpose::ReceiveChild, reply, false, child.tid, child.badge)?
        else { return Ok(false); };
    work.receive = Some(turn);
    install_work(work, false)?;
    print_str(b"[native-image-pagein] receive child owned pi=");
    print_u64(child.pi as u64);
    print_str(b" tid="); print_u64(child.tid);
    print_str(b" page=0x"); print_hex((page >> 32) as u32); print_hex(page as u32);
    print_str(b"\n");
    Ok(true)
}

static RECEIVE_CHILD_STEP_TRACES: AtomicU64 = AtomicU64::new(0);

/// #351 (multicore) diagnosis: each phase change of the Receive child's page-in, and whether its provider
/// READ is dispatched and pending. Bounded: the first 256 steps, then powers of two. Read-only.
fn trace_receive_child_step(work: &Work, done: bool, read_pending: bool) {
    let sample = RECEIVE_CHILD_STEP_TRACES.fetch_add(1, Ordering::Relaxed) + 1;
    if sample > 256 && !sample.is_power_of_two() { return; }
    let phase = match work.phase {
        Phase::AwaitSource => 1, Phase::Read => 2, Phase::Publish => 3,
        Phase::MapPage => 4, Phase::ScanSyscall => 5,
        Phase::DispatchSyscall => 6, Phase::ReplyReady => 7,
        Phase::ReadyError => 8, Phase::ReplyEntered => 9,
        Phase::ReplySent => 10, Phase::Cancel => 11,
        Phase::Cancelled => 12, Phase::Indeterminate => 13,
    };
    print_str(b"[receive-child-pagein-step] sample/tid/page/phase/read-dispatched/read-pending/done/next=");
    for value in [sample, work.tid, work.page, phase, u64::from(work.read.is_some()),
        u64::from(read_pending), u64::from(done), NEXT.load(Ordering::Acquire)] {
        print_str(b"/");
        print_hex_u64(value);
    }
    print_str(b"\n");
}

/// True while a page-in row owns the selected Receive child's Reply. The turn is consumed
/// at the acknowledged settlement; retiring the parked Reply after that is ordinary work.
pub(crate) fn owns_receive_child() -> bool {
    unsafe { (&*core::ptr::addr_of!(WORK)).iter().flatten().any(|row| row.receive.is_some()) }
}

/// The root's admission of one event while the Receive child's page-in owns its Reply.
fn owned_receive_child_action(event: ReceiveChildRootEvent) -> Option<ReceiveChildRootAction> {
    unsafe { (&*core::ptr::addr_of!(WORK)).iter().flatten()
        .find_map(|row| row.receive.as_ref()) }
        .map(|turn| turn.root_action(event))
}

/// The root's action for one delivery while a page-in owns the selected Receive child. A child
/// that delivers again after its Reply was sent (it can run on another core before the root
/// acknowledges) first has its page-in settled; the delivery is then classified afresh, and
/// `None` means no page-in owns the child any more. Never returns `SettleFirst`.
pub(crate) unsafe fn receive_child_root_action(
    handler: &mut ExecNtHandler,
    dispatcher: &NativeSyscallDispatcher,
    event: ReceiveChildRootEvent,
) -> Option<ReceiveChildRootAction> {
    match owned_receive_child_action(event)? {
        ReceiveChildRootAction::SettleFirst => {
            redrive_receive_child(handler, dispatcher);
            match owned_receive_child_action(event)? {
                // Still unacknowledged: the delivery cannot be admitted or returned.
                ReceiveChildRootAction::SettleFirst => Some(ReceiveChildRootAction::RefuseIdentity),
                action => Some(action),
            }
        }
        action => Some(action),
    }
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

/// Park a returned NT dispatch on the routed image page its input capture needed. Returns
/// false, with the Reply untouched, when no owned page-in can make that capture succeed; the
/// caller then replies the handler's status as before.
pub(crate) unsafe fn submit_syscall_retry(
    handler: &mut ExecNtHandler, input: nt_syscall::input_pagein::DeferredInputPage,
    retry: nt_syscall_abi::SyscallRetryReply, status: u32,
) -> bool {
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let access = if input.write { FaultAccess::Write } else { FaultAccess::Read };
    let purpose = Purpose::SyscallRetry { caller_pi: handler.pi, retry, status };
    let parked = match prepare_page(handler, input.process_index, input.page, access,
        ImageFaultObservation::CopyAccess, purpose, reply, false)
    {
        Ok(Some(work)) => install_work(work, false).is_ok(),
        Ok(None) | Err(_) => false,
    };
    let sequence = SYSCALL_RETRY_TRACE.fetch_add(1, Ordering::Relaxed);
    if sequence < 32 || sequence.is_power_of_two() {
        let mut record = nt_printf::record::RecordBuffer::<256>::new();
        let _ = writeln!(record,
            "[syscall-input-pagein] #{} parked={} caller_pi={} tid={} ssn=0x{:x} target_pi={} page=0x{:x} write={} status=0x{:x}",
            sequence, parked, handler.pi, handler.current_tid, handler.current_service_number,
            input.process_index, input.page, input.write, status);
        sel4_rt::print_record(if record.overflowed() {
            b"[syscall-input-pagein] trace truncated\n"
        } else { record.bytes() });
    }
    parked
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
        .then(|| completion_retry::row_deadline(NEXT.load(Ordering::Acquire)))
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

fn diagnostic_probe(work: &Work, executing: bool) -> Option<(
    nt_hosted_runtime::SpanOwner, u64, crate::installer_child_span_census::PageInProbe,
)> {
    if !work.purpose.is_fault() { return None; }
    let nt_user_host::process_identity::ProcessGeneration::Hosted(process_generation) =
        work.view.process.generation else { return None; };
    let phase = match work.phase {
        Phase::AwaitSource => 1, Phase::Read => 2, Phase::Publish => 3,
        Phase::MapPage => 4, Phase::ScanSyscall => 5,
        Phase::DispatchSyscall => 6, Phase::ReplyReady => 7,
        Phase::ReadyError => 8, Phase::ReplyEntered => 9,
        Phase::ReplySent => 10, Phase::Cancel => 11,
        Phase::Cancelled => 12, Phase::Indeterminate => 13,
    };
    let read_subphase = match work.read.as_ref() {
        Some(read) if read.acknowledgment_key().is_some() => 3,
        Some(read) if read.copy_position().is_some() => 2,
        Some(read) if read.pending_key().is_some() => 1,
        Some(read) if read.terminal_result().is_some() => 4,
        Some(_) => 5,
        None => 0,
    };
    Some((nt_hosted_runtime::SpanOwner {
        process_index: work.pi, process_generation,
        thread_id: work.tid, thread_generation: work.logical.thread().generation(),
    }, work.badge, crate::installer_child_span_census::PageInProbe {
        source: crate::installer_child_span_census::PageInSource::Image(work.view.view.area()),
        phase, phase_entered_at_100ns: work.phase_entered_at_100ns,
        irp_id: work.read.as_ref().and_then(ImageRead::pending_key),
        irp_entered_at_100ns: work.pending_irp_since_100ns,
        read_subphase, page: work.page, reply: work.reply, executing,
    }))
}

/// Value-only observation; an executing row is represented even while removed from WORK.
pub(crate) fn diagnostic_snapshot(owner: nt_hosted_runtime::SpanOwner, badge: u64,
    page: u64, reply: u64) -> Option<crate::installer_child_span_census::PageInProbe> {
    let mut found = None;
    unsafe {
        if let Some((row_owner, row_badge, probe)) =
            *core::ptr::addr_of!(EXECUTING_PROBE) {
            if row_owner == owner && row_badge == badge && probe.page == page
                && probe.reply == reply { found = Some(probe); }
        }
        for work in (&*core::ptr::addr_of!(WORK)).iter().flatten() {
            let Some((row_owner, row_badge, probe)) = diagnostic_probe(work, false) else {
                continue;
            };
            if row_owner == owner && row_badge == badge && probe.page == page
                && probe.reply == reply {
                if found.is_some() { return None; }
                found = Some(probe);
            }
        }
    }
    found
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
                work.phase = if matches!(work.purpose,
                    Purpose::SyscallCopy(_) | Purpose::SyscallRetry { .. })
                {
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
                work.phase = if !cancelled && matches!(work.purpose,
                    Purpose::SyscallCopy(_) | Purpose::SyscallRetry { .. })
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
        let copied = match completion_retry::step(driver_launch::copy_completed_irp_output_exact(
            key, offset as u64, &mut bytes[..limit],
        )) {
            CompletionStep::Done(copied) if copied != 0 && copied <= limit => copied,
            // Still running: the identical copy collects it on a later turn.
            CompletionStep::Retry => return,
            CompletionStep::Done(_) => {
                if !read.fail_copy(key, nt_memory_manager::routed_image_read::STATUS_IO_DEVICE_ERROR) {
                    read.quarantine();
                    work.phase = Phase::Indeterminate;
                } else {
                    work.drive_progress = true;
                }
                return;
            }
            CompletionStep::Failed(status) => {
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
        match completion_retry::step_status(driver_launch::io_manager_mut()
            .acknowledge_completed_irp_strict(nt_io_manager::IrpId(key)))
        {
            CompletionStep::Done(_) => {}
            CompletionStep::Retry => { work.phase = Phase::Read; return; }
            CompletionStep::Failed(_) => return,
        }
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
    // IoPageRead for an image page: paging I/O never moves the File's CurrentByteOffset.
    let result = driver_launch::io_manager_mut().build_and_dispatch_paging_to_device(
        nt_types::ClientId(driver_launch::IO_MANAGER_COMPONENT_ID), DeviceId(device),
        FileId(file), work.tid, nt_io_manager::irp_request_flags::PagingTransfer::Read, window.offset, &mut output,
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
                work.phase = match work.purpose {
                    Purpose::Fault | Purpose::ReceiveChild => Phase::Cancel,
                    // The Reply is this row's alone; returning the handler's status replays
                    // nothing, whatever state the source owner was left in.
                    Purpose::SyscallRetry { .. } => Phase::ReplyReady,
                    // The source owner can be retained or quarantined after a physical effect.
                    _ => Phase::Indeterminate,
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
                    work.phase = match work.purpose {
                        Purpose::Fault | Purpose::ReceiveChild => Phase::Cancel,
                        Purpose::SyscallRetry { .. } => Phase::ReplyReady,
                        _ => Phase::Indeterminate,
                    };
                    return false;
                }
            }
            if matches!(work.purpose, Purpose::SyscallCopy(_)) {
                assert!(work.progress.map_completed());
                work.phase = Phase::ScanSyscall;
            } else if work.receive.as_mut().is_some_and(|turn| turn.page_mapped().is_err()) {
                work.phase = Phase::Indeterminate;
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
                    Purpose::Fault | Purpose::ReceiveChild | Purpose::SyscallCopy(_)
                    | Purpose::SyscallRetry { .. } => unreachable!(),
                };
                if completed {
                    return true;
                }
                work.phase = Phase::Indeterminate;
                return false;
            }
            let sent = match work.purpose {
                Purpose::SyscallRetry { retry, status, .. } => match work.failure {
                    None => reply_parked_syscall_retry(work.reply, &retry),
                    Some(_) => reply_parked_syscall(work.reply, u64::from(status)),
                },
                Purpose::Fault => client_reply_on(work.reply, 0, 0, 0, 0, 0),
                Purpose::ReceiveChild => {
                    if work.receive.as_mut().is_none_or(|turn| turn.enter_reply().is_err()) {
                        work.phase = Phase::Indeterminate;
                        return false;
                    }
                    // The child's CALLS row settles its held parent from this one Reply.
                    client_reply_on(work.reply, 0, 0, 0, 0, 0)
                }
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
            if matches!(work.purpose, Purpose::SyscallRetry { .. }) {
                // `failure` selects the handler's status over the retry envelope.
                work.phase = Phase::ReplyReady;
                return false;
            }
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
            if let Some(turn) = work.receive.take() {
                match turn.acknowledge() {
                    Ok(settled) => {
                        print_str(b"[native-image-pagein] receive child settled tid=");
                        print_u64(settled.child().tid);
                        print_str(b" page=0x");
                        print_hex((settled.page() >> 32) as u32);
                        print_hex(settled.page() as u32);
                        print_str(b"\n");
                    }
                    Err((_, turn)) => {
                        work.receive = Some(turn);
                        work.phase = Phase::Indeterminate;
                        return false;
                    }
                }
            }
            if parked_reply::retire_sent(work.reply).is_err() { return false; }
            thread_wait_state_clear_badge_ready(handler, work.badge);
            true
        }
        Phase::Cancel => {
            if matches!(work.purpose, Purpose::ReceiveChild) {
                // A held Receive parent has no cancellation settlement. Retain the child's
                // Call and Reply with the parent; the root stops rather than replaying.
                let status = work.failure.unwrap_or(INVALID);
                work.failure = Some(status);
                if let Some(turn) = work.receive.as_mut() { turn.retain(status); }
                work.phase = Phase::Indeterminate;
                return false;
            }
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
                    Purpose::Fault | Purpose::ReceiveChild | Purpose::SyscallCopy(_)
                    | Purpose::SyscallRetry { .. } => unreachable!(),
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
            if let Some(turn) = work.receive.as_mut() {
                turn.retain(work.failure.unwrap_or(RESOURCES));
            }
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
    if next_deadline().is_none_or(|deadline| monotonic_time_100ns() < deadline) { return; }
    redrive_rows(handler, dispatcher, false);
}

/// Drive only the Receive child's row, at each root notification while its parent is held.
/// No other row can reply, dispatch a syscall or enter a provider from this turn.
pub(crate) unsafe fn redrive_receive_child(
    handler: &mut ExecNtHandler, dispatcher: &NativeSyscallDispatcher,
) {
    if owns_receive_child() { redrive_rows(handler, dispatcher, true); }
}

/// While a Receive child's page-in owns the root: its own rows, and the exact producer of a
/// source page one of them awaits (another row already reading it), which nothing else drives.
unsafe fn runs_with_receive_child(row: &Work) -> bool {
    let awaited = (&*core::ptr::addr_of!(WORK)).iter().flatten()
        .filter(|child| matches!(child.purpose, Purpose::ReceiveChild)
            && matches!(child.phase, Phase::AwaitSource))
        .map(|child| (child.view.view.area(), child.rva));
    nt_memory_manager::image_source_page::runs_during_receive_child(
        matches!(row.purpose, Purpose::ReceiveChild),
        (row.view.view.area(), row.rva),
        matches!(row.phase, Phase::Read | Phase::Publish),
        awaited,
    )
}

unsafe fn redrive_rows(
    handler: &mut ExecNtHandler, dispatcher: &NativeSyscallDispatcher, receive_child_only: bool,
) {
    if ACTIVE.swap(true, Ordering::AcqRel) { return; }
    let _durable = allocator::enter_durable();
    let admissions_before = ADMISSIONS.load(Ordering::Acquire);
    let mut immediate_followup = false;
    let count = (&*core::ptr::addr_of!(WORK)).len();
    for index in 0..count {
        if receive_child_only && !(&*core::ptr::addr_of!(WORK))[index].as_ref()
            .is_some_and(|row| runs_with_receive_child(row))
        { continue; }
        let Some(mut work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].take() else { continue; };
        EXECUTING_INDEX.store(index as u64, Ordering::Release);
        EXECUTING_TID.store(work.tid, Ordering::Release);
        EXECUTING_PI.store(work.pi as u64, Ordering::Release);
        *core::ptr::addr_of_mut!(EXECUTING_SOURCE) =
            Some((work.view.view.area(), work.rva, work.phase));
        let (caller_pi, resume_ip, sp, flags, transport, service) = match work.purpose {
            Purpose::Fault | Purpose::ReceiveChild => (work.pi, 0, 0, 0, false, 0),
            Purpose::SyscallCopy(call) =>
                (work.pi, call.resume_ip, call.sp, call.flags, call.native_call_transport,
                    call.service.number()),
            Purpose::VmLock { caller_pi, .. } =>
                (caller_pi, 0, 0, 0, false, SSN_NT_LOCK_VM as u32),
            Purpose::VmCopy { caller_pi, service_number, .. } =>
                (caller_pi, 0, 0, 0, false, service_number),
            Purpose::RoutedFileModeInput { .. } => (work.pi, 0, 0, 0, false, 0),
            Purpose::SyscallRetry { caller_pi, .. } => (caller_pi, 0, 0, 0, false, 0),
        };
        EXECUTING_CALLER_PI.store(caller_pi as u64, Ordering::Release);
        let is_fault = work.purpose.is_fault();
        let mut budget = LocalDriveBudget::new(LOCAL_FAULT_STEPS);
        let done = service_sec_image::with_pagein_caller_target_context(
            handler, caller_pi, work.pi, work.tid, work.badge,
            resume_ip, sp, flags, transport, service,
            |handler| loop {
                // A nested admission can inspect this exact source while its row is absent.
                *core::ptr::addr_of_mut!(EXECUTING_SOURCE) =
                    Some((work.view.view.area(), work.rva, work.phase));
                *core::ptr::addr_of_mut!(EXECUTING_PROBE) = diagnostic_probe(&work, true);
                work.drive_progress = false;
                let before = core::mem::discriminant(&work.phase);
                let pending_before = work.read.as_ref().and_then(ImageRead::pending_key);
                let done = advance(handler, dispatcher, &mut work);
                if core::mem::discriminant(&work.phase) != before {
                    work.phase_entered_at_100ns = monotonic_time_100ns();
                }
                let pending_after = work.read.as_ref().and_then(ImageRead::pending_key);
                if pending_after != pending_before {
                    work.pending_irp_since_100ns =
                        pending_after.map(|_| monotonic_time_100ns());
                }
                if matches!(work.purpose, Purpose::ReceiveChild)
                    && (core::mem::discriminant(&work.phase) != before
                        || pending_after.is_some() != pending_before.is_some())
                {
                    trace_receive_child_step(&work, done, pending_after.is_some());
                }
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
        *core::ptr::addr_of_mut!(EXECUTING_PROBE) = None;
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
