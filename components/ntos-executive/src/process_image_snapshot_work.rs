//! Retained native process image reads from the exact routed Section File.
//!
//! Process construction needs one private raw PE. A mounted installed File can only provide
//! that snapshot through pending IRPs after native disk handoff. This owner keeps the original
//! syscall Reply, parent/requestor references and Section view until every read is acknowledged.

use crate::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_io_manager::{DeviceId, ExternalDispatchResult, FileId, IoParameters, ReadWriteParameters};
use nt_memory_manager::image_section::{ImageAreaId, ImageViewRef};
use nt_memory_manager::routed_image_read::RoutedImageRead;
use nt_memory_manager::RoutedSectionLease;
use nt_process::native_handle::{NativeHandleCaller, NativeObjectReference,
    NativeThreadProcessReference, PsHandleType};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

const RESOURCES: u32 = nt_address_space::STATUS_INSUFFICIENT_RESOURCES;
const NOT_READY: u32 = 0xc000_00a3;
const RETRY_DELAY: u64 = 1_000_000;
const WINDOW: usize = 32 * 1024;

struct Capture {
    caller: NativeHandleCaller,
    logical: ProviderLogicalCaller,
    requestor: NativeThreadProcessReference,
    parent: NativeObjectReference,
    parent_pid: nt_process::ProcessId,
    view: Option<ImageViewRef>,
    create: nt_process::ProcessCreateInput,
    desired_access: u32,
    output: u64,
    previous_mode: nt_syscall::ProcessorMode,
    file: u64,
    device: u64,
    file_context: u64,
    origin_driver: u64,
}

type ImageRead = RoutedImageRead<(ImageAreaId, RoutedSectionLease), u64, Capture>;

enum Phase { Read, Spawn, ReadyReply, ReplyEntered, ReplySent,
    RevokeReply, RetypeReply, ReconcileRuntime, Indeterminate }

struct Work {
    pi: usize,
    tid: u64,
    badge: u64,
    reply: u64,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
    service_number: u32,
    logical: ProviderLogicalCaller,
    read: Option<ImageRead>,
    capture: Option<Capture>,
    bytes: Option<Vec<u8>>,
    phase: Phase,
    status: u32,
    published_handle: Option<u64>,
    cancel_requested: bool,
    cancelled: bool,
}

impl Work {
    fn capture(&self) -> &Capture {
        if let Some(read) = self.read.as_ref() { read.owner() }
        else { self.capture.as_ref().expect("retained process image capture") }
    }
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);
static TRANSFERRED: AtomicBool = AtomicBool::new(false);
static NEXT: AtomicU64 = AtomicU64::new(0);
static CURSOR: AtomicU64 = AtomicU64::new(0);
static EXECUTING_INDEX: AtomicU64 = AtomicU64::new(u64::MAX);
static EXECUTING_TID: AtomicU64 = AtomicU64::new(0);
static EXECUTING_PI: AtomicU64 = AtomicU64::new(u64::MAX);
static IMAGE_NOT_SUPPORTED_TRACE_N: AtomicU64 = AtomicU64::new(0);

fn trace_image_not_supported(work: &Work, phase: &[u8], status: u32) {
    if status != 0xc000_00bb
        || IMAGE_NOT_SUPPORTED_TRACE_N.fetch_add(1, Ordering::Relaxed) >= 8
    { return; }
    print_str(b"[process-image-not-supported] phase=");
    print_str(phase);
    print_str(b" tid=");
    print_u64(work.tid);
    print_str(b" section=0x");
    print_hex(work.capture().create.section_handle as u32);
    print_str(b"\n");
}

fn release_capture(handler: &mut ExecNtHandler, capture: &mut Capture) {
    if let Some(view) = capture.view.take() {
        handler.image_sections.release_view(view)
            .expect("retired process snapshot Section view");
    }
    capture.parent.release(&mut handler.pm)
        .expect("retired process snapshot parent reference");
    capture.requestor.release(&mut handler.pm)
        .expect("retired process snapshot requestor reference");
}

/// Return false only when this is not a native routed image Section. No physical image read
/// enters until the whole source, parent and original Reply are owned by the work queue.
pub(crate) unsafe fn submit_routed_process_image(
    handler: &mut ExecNtHandler,
    parent_pid: nt_process::ProcessId,
    parent_handle: u64,
    create: nt_process::ProcessCreateInput,
    desired_access: u32,
    output: u64,
    previous_mode: nt_syscall::ProcessorMode,
) -> Result<bool, u32> {
    let _durable = allocator::enter_durable();
    let caller = handler.native_handle_caller(previous_mode)?;
    let section = match handler.pm.lookup_native_section_handle(caller, create.section_handle) {
        Ok(section) => section,
        Err(nt_process::STATUS_INVALID_HANDLE) => return Ok(false),
        Err(status) => return Err(status),
    };
    let id = crate::native_image_sections::NativeImageSectionId::from_section_id(
        section.section()).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    if caller.mode() == nt_types::AccessMode::UserMode
        && section.granted_access()
            & nt_memory_manager::section_view_access::SECTION_MAP_EXECUTE == 0
    { return Err(nt_process::STATUS_ACCESS_DENIED); }
    let area = handler.image_sections.area(id).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let source = handler.image_sections.source(id).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    if !matches!(source.contents, crate::native_image_sections::NativeImageContents::RetainedRouted) {
        return Ok(false);
    }
    if !source.has_readable_image() { return Err(nt_fs::STATUS_INVALID_HANDLE); }
    let lease = source.backing.routed_lease.ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let extent = source.backing.file_extent;
    let (file, device, file_context, _) =
        crate::hosted_routed_image_capture::route(lease, area)
            .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let origin_driver = driver_launch::io_manager_mut()
        .device(DeviceId(device)).ok_or(nt_fs::STATUS_INVALID_HANDLE)?.driver_id.raw();
    let tid = handler.current_tid;
    if has_thread(tid) { return Err(nt_fs::STATUS_INVALID_HANDLE); }
    let tcb = handler.hosted_thread_tcb(tid).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let logical = handler.capture_provider_logical_caller(handler.pi, tid,
        handler.current_badge, tcb).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let park = root_reply_park::RootReplyPark::prepare().ok_or(RESOURCES)?;
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let index = rows.iter().enumerate().find_map(|(index, row)|
        (row.is_none() && EXECUTING_INDEX.load(Ordering::Acquire) != index as u64)
            .then_some(index));
    if index.is_none() { rows.try_reserve(1).map_err(|_| RESOURCES)?; }
    let view = handler.image_sections.reference_view(id)
        .map_err(crate::exec_handler::image_section_create::map_image_error)?;
    // NtCreateProcessEx already admitted PROCESS_CREATE_PROCESS on this handle before
    // submission. Pin the same live Process object without rechecking a pseudo-handle's
    // unpublished grant; the exact PID and body are checked below before any File read.
    let mut parent = match handler.pm.reference_native_ps_handle(caller, parent_handle,
        Some(PsHandleType::Process), 0)
    {
        Ok(parent) => parent,
        Err(status) => {
            handler.image_sections.release_view(view).expect("unsubmitted Section view");
            return Err(status);
        }
    };
    if parent.object() != nt_process::HandleObject::Process(parent_pid)
        || handler.pm.process_kernel_object(parent_pid) != Some(parent.body())
    {
        parent.release(&mut handler.pm).expect("unsubmitted parent reference");
        handler.image_sections.release_view(view).expect("unsubmitted Section view");
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    let requestor_caller = match handler.pm.capture_native_handle_caller(
        logical.thread(), nt_types::AccessMode::KernelMode)
    {
        Ok(caller) => caller,
        Err(status) => {
            parent.release(&mut handler.pm).expect("unsubmitted parent reference");
            handler.image_sections.release_view(view).expect("unsubmitted Section view");
            return Err(status);
        }
    };
    let requestor = match handler.pm.reference_native_requestor(requestor_caller) {
        Ok(requestor) => requestor,
        Err(status) => {
            parent.release(&mut handler.pm).expect("unsubmitted parent reference");
            handler.image_sections.release_view(view).expect("unsubmitted Section view");
            return Err(status);
        }
    };
    let capture = Capture { caller, logical, requestor, parent, parent_pid, view: Some(view),
        create, desired_access, output, previous_mode,
        file, device, file_context, origin_driver };
    let read = match ImageRead::new((area, lease), extent, WINDOW, capture) {
        Ok(read) => read,
        Err(mut capture) => {
            release_capture(handler, &mut capture);
            return Err(RESOURCES);
        }
    };
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(reply, 0);
    let work = Work { pi: handler.pi, tid, badge: handler.current_badge, reply,
        resume_ip: handler.current_resume_ip, sp: handler.current_sp,
        flags: handler.current_flags, native_call_transport: handler.current_native_call_transport,
        service_number: handler.current_service_number, logical,
        read: Some(read), capture: None, bytes: None, phase: Phase::Read,
        status: 0, published_handle: None, cancel_requested: false, cancelled: false };
    match index { Some(index) => rows[index] = Some(work), None => rows.push(Some(work)) }
    park.commit();
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    assert!(!TRANSFERRED.swap(true, Ordering::AcqRel));
    Ok(true)
}

pub(crate) fn take_transferred() -> bool { TRANSFERRED.swap(false, Ordering::AcqRel) }

pub(crate) fn has_thread(tid: u64) -> bool {
    EXECUTING_TID.load(Ordering::Acquire) == tid || unsafe {
        (&*core::ptr::addr_of!(WORK)).iter().flatten().any(|work|
            work.tid == tid && !matches!(work.phase, Phase::ReplySent | Phase::ReconcileRuntime))
    }
}

pub(crate) fn has_process(pi: usize, preserve_tid: Option<u64>) -> bool {
    (EXECUTING_PI.load(Ordering::Acquire) == pi as u64
        && preserve_tid != Some(EXECUTING_TID.load(Ordering::Acquire))) || unsafe {
        (&*core::ptr::addr_of!(WORK)).iter().flatten().any(|work|
            work.pi == pi && preserve_tid != Some(work.tid)
                && !matches!(work.phase, Phase::ReplySent | Phase::ReconcileRuntime))
    }
}

pub(crate) fn next_deadline() -> Option<u64> {
    (EXECUTING_TID.load(Ordering::Acquire) != 0 || unsafe {
        (&*core::ptr::addr_of!(WORK)).iter().any(Option::is_some)
    }).then(|| NEXT.load(Ordering::Acquire))
}

/// Periodic read-only census at the serialized service-loop boundary.
pub(crate) fn census_snapshot() -> (Option<u64>, bool, u64, usize) {
    let pending = unsafe { (&*core::ptr::addr_of!(WORK)).iter().filter(|work| work.is_some()).count() };
    (next_deadline(), ACTIVE.load(Ordering::Acquire),
        EXECUTING_TID.load(Ordering::Acquire), pending)
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

enum Step { Progress, Wait, Done }

pub(crate) unsafe fn redrive(
    handler: &mut ExecNtHandler,
    delay_queue: &mut nt_delay_execution::Queue,
    ntdll: (u64, &nt_pe_loader::PeFile),
    fault_ep: u64,
    procs: &mut [ProcExec],
    exe_images: &mut nt_exe_image::ImageTable<HOSTED_PROCESS_IMAGE_CAP>,
    catalog: &nt_exe_image::OwnedHostedImageCatalog<HOSTED_PROCESS_IMAGE_CAP>,
    loaded_images: *mut HostedLoadedImageTable,
) {
    if next_deadline().is_none_or(|deadline| monotonic_time_100ns() < deadline)
        || ACTIVE.swap(true, Ordering::AcqRel) { return; }
    let _durable = allocator::enter_durable();
    let selected = {
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        if rows.is_empty() { None } else {
            let start = CURSOR.load(Ordering::Relaxed) as usize % rows.len();
            (0..rows.len()).find_map(|step| {
                let index = (start + step) % rows.len();
                rows[index].take().map(|work| (index, work))
            })
        }
    };
    if let Some((index, mut work)) = selected {
        CURSOR.store(index as u64 + 1, Ordering::Relaxed);
        EXECUTING_INDEX.store(index as u64, Ordering::Release);
        EXECUTING_TID.store(work.tid, Ordering::Release);
        EXECUTING_PI.store(work.pi as u64, Ordering::Release);
        let mut done = false;
        for _ in 0..8 {
            let step = service_sec_image::with_section_metadata_context(handler,
                work.pi, work.tid, work.badge, work.resume_ip, work.sp, work.flags,
                work.native_call_transport, work.service_number,
                |handler| advance(handler, delay_queue, &mut work, ntdll, fault_ep,
                    procs, exe_images, catalog, loaded_images));
            match step {
                Some(Step::Progress) => {},
                Some(Step::Wait) | None => break,
                Some(Step::Done) => { done = true; break; }
            }
        }
        if !done {
            let slot = &mut (&mut *core::ptr::addr_of_mut!(WORK))[index];
            assert!(slot.is_none(), "executing process snapshot slot reused");
            *slot = Some(work);
        }
        EXECUTING_TID.store(0, Ordering::Release);
        EXECUTING_PI.store(u64::MAX, Ordering::Release);
        EXECUTING_INDEX.store(u64::MAX, Ordering::Release);
    }
    NEXT.store(monotonic_time_100ns().saturating_add(RETRY_DELAY), Ordering::Release);
    ACTIVE.store(false, Ordering::Release);
}

unsafe fn advance(
    handler: &mut ExecNtHandler,
    delay_queue: &mut nt_delay_execution::Queue,
    work: &mut Work,
    ntdll: (u64, &nt_pe_loader::PeFile),
    fault_ep: u64,
    procs: &mut [ProcExec],
    exe_images: &mut nt_exe_image::ImageTable<HOSTED_PROCESS_IMAGE_CAP>,
    catalog: &nt_exe_image::OwnedHostedImageCatalog<HOSTED_PROCESS_IMAGE_CAP>,
    loaded_images: *mut HostedLoadedImageTable,
) -> Step {
    work.cancelled |= spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(work.reply)
        || handler.pm.thread(work.logical.thread().thread_id())
            .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
        || handler.pm.process(work.logical.process().pid)
            .is_some_and(|process| process.state == nt_process::ProcessState::Terminated);
    match work.phase {
        Phase::Read => advance_read(work),
        Phase::Spawn => {
            if work.cancelled { work.phase = Phase::RevokeReply; return Step::Progress; }
            let capture = work.capture.as_mut().expect("acknowledged process snapshot capture");
            if capture.requestor.validate(&handler.pm).is_err()
                || !handler.validate_provider_logical_caller(capture.logical)
                || handler.pm.process_kernel_object(capture.parent_pid) != Some(capture.parent.body())
                || handler.native_handle_caller(capture.previous_mode).ok() != Some(capture.caller)
            {
                work.cancelled = true;
                work.phase = Phase::RevokeReply;
                return Step::Progress;
            }
            let view = capture.view.take().expect("pinned process snapshot Section view");
            let result = handler.reserve_native_image_process_with_bytes(
                capture.parent_pid, capture.create, capture.desired_access, capture.output,
                capture.previous_mode, view, work.bytes.take().expect("acknowledged PE bytes"));
            work.status = match result {
                Ok(Some(request)) => match service_sec_image::publish_reserved_hosted_exe(
                    request, catalog, loaded_images, ntdll, fault_ep, procs, handler, exe_images)
                {
                    Ok((handle, _)) => { work.published_handle = Some(handle); 0 },
                    Err(service_sec_image::HostedExeSpawnError::Unentered(status)) => {
                        if !handler.abort_unentered_native_image_process(request) {
                            work.status = status;
                            work.phase = Phase::Indeterminate;
                            return Step::Wait;
                        }
                        status
                    }
                    Err(service_sec_image::HostedExeSpawnError::Entered(status)) => {
                        work.status = status;
                        work.phase = Phase::Indeterminate;
                        return Step::Wait;
                    }
                },
                Ok(None) => nt_fs::STATUS_INVALID_HANDLE,
                Err(status) => {
                    trace_image_not_supported(work, b"admission", status);
                    status
                },
            };
            work.phase = Phase::ReadyReply;
            Step::Progress
        }
        Phase::ReadyReply => {
            trace_image_not_supported(work, b"reply", work.status);
            if work.cancelled {
                if work.published_handle.is_some() {
                    // The child and its caller-visible output are already committed.
                    // A cancelled Reply cannot roll them back or release their exact owner.
                    work.phase = Phase::Indeterminate;
                    return Step::Wait;
                }
                work.phase = Phase::RevokeReply;
                return Step::Progress;
            }
            if parked_reply::validate_saved(work.reply).is_err() { return Step::Wait; }
            work.phase = Phase::ReplyEntered;
            if !reply_parked_syscall(work.reply, work.status as u64) { return Step::Wait; }
            work.phase = Phase::ReplySent;
            Step::Progress
        }
        Phase::ReplyEntered => match spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(work.reply) {
            Ok(true) => { work.phase = Phase::ReplySent; Step::Progress },
            _ if work.cancelled && work.published_handle.is_some() => {
                work.phase = Phase::Indeterminate;
                Step::Wait
            },
            _ if work.cancelled => { work.phase = Phase::RevokeReply; Step::Progress },
            _ => Step::Wait,
        },
        Phase::ReplySent => {
            if parked_reply::retire_sent(work.reply).is_err() { return Step::Wait; }
            thread_wait_state_clear_badge_ready(handler, work.badge);
            release_capture(handler, work.capture.as_mut().expect("terminal process snapshot capture"));
            Step::Done
        }
        Phase::RevokeReply => {
            if !spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(work.reply)
                && parked_reply::revoke(work.reply).is_err() { return Step::Wait; }
            work.phase = Phase::RetypeReply;
            Step::Progress
        }
        Phase::RetypeReply => {
            if parked_reply::retype(work.reply).is_err() { return Step::Wait; }
            work.phase = Phase::ReconcileRuntime;
            Step::Progress
        }
        Phase::ReconcileRuntime => {
            if !hosted_termination::reconcile(handler, delay_queue, work.logical) {
                return Step::Wait;
            }
            release_capture(handler, work.capture.as_mut().expect("cancelled process snapshot capture"));
            Step::Done
        }
        Phase::Indeterminate => Step::Wait,
    }
}

unsafe fn advance_read(work: &mut Work) -> Step {
    let read = work.read.as_mut().expect("retained process image read");
    if let Some(result) = read.terminal_result() {
        let (capture, bytes) = work.read.take().unwrap().into_terminal()
            .ok().expect("terminal process image read");
        work.capture = Some(capture);
        match result {
            Ok(()) if !work.cancelled => {
                work.bytes = Some(bytes.expect("complete process image bytes"));
                work.phase = Phase::Spawn;
            }
            Ok(()) => work.phase = Phase::RevokeReply,
            Err(status) if work.cancelled => { work.status = status; work.phase = Phase::RevokeReply; }
            Err(status) => {
                trace_image_not_supported(work, b"read", status);
                work.status = status;
                work.phase = Phase::ReadyReply;
            }
        }
        return Step::Progress;
    }
    if work.cancelled && read.pending_key().is_none() {
        let capture = work.read.take().unwrap().abort_ready()
            .ok().expect("unentered cancelled process read");
        work.capture = Some(capture);
        work.phase = Phase::RevokeReply;
        return Step::Progress;
    }
    if let Some((key, offset, remaining)) = read.copy_position() {
        let mut bytes = [0u8; 4096];
        let limit = remaining.min(bytes.len());
        let copied = match driver_launch::copy_completed_irp_output_exact(
            key, offset as u64, &mut bytes[..limit])
        {
            Ok(copied) if copied != 0 && copied <= limit => copied,
            Ok(_) => { assert!(read.fail_copy(key, nt_memory_manager::routed_image_read::STATUS_IO_DEVICE_ERROR)); return Step::Progress; }
            Err(status) => { assert!(read.fail_copy(key, status)); return Step::Progress; }
        };
        if !read.copy_fragment(key, offset, &bytes[..copied]) {
            read.quarantine();
            work.phase = Phase::Indeterminate;
        }
        return Step::Progress;
    }
    if let Some(key) = read.acknowledgment_key() {
        // The backend may have consumed this ACK even if its return is an error.
        // Retain all owners and never replay it after entry.
        work.phase = Phase::Indeterminate;
        if driver_launch::io_manager_mut()
            .acknowledge_completed_irp_strict(nt_io_manager::IrpId(key)).is_err()
        { return Step::Wait; }
        if !read.acknowledge(key) {
            read.quarantine();
            return Step::Wait;
        }
        work.phase = Phase::Read;
        return Step::Progress;
    }
    if let Some(key) = read.pending_key() {
        if work.cancelled && !work.cancel_requested {
            work.cancel_requested = true;
            let _ = driver_launch::cancel_irp_if_pending(key);
        }
        let Some(completion) = driver_launch::completed_irp_exact(key) else { return Step::Wait; };
        let capture = read.owner();
        if completion.client_id != driver_launch::IO_MANAGER_COMPONENT_ID
            || completion.driver_id != capture.origin_driver
            || completion.completion_driver_id != capture.origin_driver
            || completion.file_id != capture.file
            || completion.device_id != capture.device
            || completion.completion_device_id != capture.device
            || completion.requestor_tid != work.tid
            || completion.major != nt_io_abi::major::IRP_MJ_READ
        {
            read.quarantine();
            work.phase = Phase::Indeterminate;
            return Step::Wait;
        }
        if !read.terminal(key, completion.status, completion.information) {
            read.quarantine();
            work.phase = Phase::Indeterminate;
            return Step::Wait;
        }
        return Step::Progress;
    }
    let (area, lease) = read.source();
    let capture = read.owner();
    let Some((file, device, context, _)) = crate::hosted_routed_image_capture::route(lease, area) else {
        let _ = read.enter_window();
        assert!(read.reject_entry(nt_fs::STATUS_INVALID_HANDLE));
        return Step::Progress;
    };
    if (file, device, context) != (capture.file, capture.device, capture.file_context) {
        let _ = read.enter_window();
        assert!(read.reject_entry(nt_fs::STATUS_INVALID_HANDLE));
        return Step::Progress;
    }
    let Some(window) = read.enter_window() else { return Step::Wait; };
    let mut output = Vec::new();
    if output.try_reserve_exact(window.length).is_err() {
        assert!(read.reject_entry(RESOURCES));
        return Step::Progress;
    }
    output.resize(window.length, 0);
    let result = driver_launch::io_manager_mut().build_and_dispatch_external_to_device(
        nt_types::ClientId(driver_launch::IO_MANAGER_COMPONENT_ID), DeviceId(device),
        Some(FileId(file)), 0, work.tid, nt_io_abi::major::IRP_MJ_READ,
        IoParameters::Read(ReadWriteParameters { length: window.length as u32, key: 0,
            offset: window.offset }),
        0, window.length as u32, &mut output,
    );
    match result {
        Ok(ExternalDispatchResult::Completed { status, information, .. }) => {
            assert!(read.complete_inline(status.raw() as u32, information, &output));
        }
        Ok(ExternalDispatchResult::Pending { irp_id }) => {
            if !read.bind_pending(irp_id.raw()) {
                read.quarantine();
                work.phase = Phase::Indeterminate;
                return Step::Wait;
            }
        }
        Err(status) => { assert!(read.reject_entry(status.raw() as u32)); }
    }
    Step::Progress
}
