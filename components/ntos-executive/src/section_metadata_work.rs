//! Retained native NtCreateSection metadata I/O for routed Files.

use crate::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_io_manager::{
    DeviceId, ExternalDispatchResult, FileId, InformationParameters, IoParameters, IrpId,
};
use nt_memory_manager::{
    CompletedFileQuery, PendingSectionMetadataId, PendingSectionMetadataQueries,
};
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

const STATUS_CANCELLED: u32 = 0xc000_0120;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xc000_007b;
const RETRY_DELAY: u64 = 1_000_000;
const IMAGE_HEADER_READ_SIZE: usize = 0x1000;

pub(crate) struct ImageObjectName {
    pub(crate) root_index: usize,
    pub(crate) root_identity: u64,
    pub(crate) path: Vec<u8>,
}

enum Phase {
    Query,
    Pending {
        irp: IrpId,
        length: usize,
    },
    Copying {
        irp: IrpId,
        length: usize,
        offset: usize,
    },
    AckPending {
        irp: IrpId,
    },
    HeaderDispatch,
    HeaderPending { irp: IrpId, length: usize },
    HeaderCopying { irp: IrpId, length: usize, offset: usize },
    HeaderAckPending { irp: IrpId },
    Publish,
    CopyOut,
    ReadyReply,
    ReplyEntered,
    ReplySent,
    RevokeReply,
    RetypeReply,
    ReconcileRuntime,
    Indeterminate,
}

enum ReservedSection {
    Data(crate::exec_handler::section_create::ReservedGenericDataSection),
    Image(crate::exec_handler::image_section_create::ReservedNativeImageSection),
}

impl ReservedSection {
    fn value(&self) -> u64 {
        match self {
            Self::Data(section) => section.value(),
            Self::Image(section) => section.value(),
        }
    }

    fn publish(&mut self, handler: &mut ExecNtHandler) -> Result<u64, u32> {
        match self {
            Self::Data(section) => section.publish(handler),
            Self::Image(section) => section.publish(handler),
        }
    }

    fn abort(&mut self, handler: &mut ExecNtHandler) {
        match self {
            Self::Data(section) => section.abort(handler),
            Self::Image(section) => section.abort(handler),
        }
    }
}

struct Work {
    caller: NativeHandleCaller,
    logical: ProviderLogicalCaller,
    reference: NativeThreadProcessReference,
    pi: usize,
    tid: u64,
    badge: u64,
    reply: u64,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
    service_number: u32,
    output: u64,
    desired_access: u32,
    attributes: u32,
    maxsize: u64,
    page_protection: u32,
    allocation_attrs: u32,
    file_handle: u64,
    image_name: Option<ImageObjectName>,
    capture: Option<driver_launch::hosted_file_capture::Capture>,
    origin_driver: u64,
    metadata: PendingSectionMetadataQueries<(), u64>,
    metadata_id: PendingSectionMetadataId,
    file_metadata: Option<nt_memory_manager::RoutedSectionMetadata>,
    image_header: Vec<u8>,
    image_path: Option<Vec<u8>>,
    observation_target: Option<nt_exe_image::CapturedImageObservation>,
    reserved: Option<ReservedSection>,
    published_handle: Option<u64>,
    phase: Phase,
    status: u32,
    cancelled: bool,
    cancel_requested: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);
static TRANSFERRED: AtomicBool = AtomicBool::new(false);
static EXECUTING_TID: AtomicU64 = AtomicU64::new(0);
static EXECUTING_PI: AtomicU64 = AtomicU64::new(u64::MAX);
static EXECUTING_INDEX: AtomicU64 = AtomicU64::new(u64::MAX);
static EXECUTING_ADMISSION_RELEASED: AtomicBool = AtomicBool::new(false);
static CURSOR: AtomicU64 = AtomicU64::new(0);
static NEXT: AtomicU64 = AtomicU64::new(0);

pub(crate) unsafe fn submit_hosted(
    handler: &mut ExecNtHandler,
    caller: NativeHandleCaller,
    source: nt_process::NativeSectionFileSource,
    output: u64,
    desired_access: u32,
    attributes: u32,
    maxsize: u64,
    page_protection: u32,
    allocation_attrs: u32,
    file_handle: u64,
    image_name: Option<ImageObjectName>,
) -> Result<(), u32> {
    let _durable = allocator::enter_durable();
    let nt_process::HandleObject::RoutedFile { file_id, device_id } = source.object() else {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    };
    if allocation_attrs & 0x0100_0000 != 0
        && !matches!(page_protection, 0x02 | 0x10 | 0x20)
    {
        return Err(nt_fs::STATUS_ACCESS_DENIED);
    }
    nt_memory_manager::data_section::check_data_section_file_access(
        page_protection,
        source.granted_access(),
    )?;
    let mount = mounted_volume::mount_id_for_live_device(device_id).ok_or(0xc000_0020u32)?;
    let capture = driver_launch::hosted_file_capture::capture_native_section_source(source)?;
    let observation_target = handler.capture_native_image_observation(file_handle);
    let image_path = if allocation_attrs & 0x0100_0000 != 0 {
        Some(capture.owned_image_path()?)
    } else {
        None
    };
    let origin_driver = driver_launch::io_manager_mut()
        .device(DeviceId(device_id))
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?
        .driver_id
        .raw();
    let tid = handler.current_tid;
    if has_thread(tid) {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    let tcb = handler
        .hosted_thread_tcb(tid)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let logical = handler
        .capture_provider_logical_caller(handler.pi, tid, handler.current_badge, tcb)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let requestor = handler
        .pm
        .capture_native_handle_caller(logical.thread(), nt_types::AccessMode::KernelMode)?;
    let mut reference = handler.pm.reference_native_requestor(requestor)?;
    let mut metadata = PendingSectionMetadataQueries::<(), u64>::new();
    let metadata_id = match metadata.reserve(mount, ()) {
        Ok(id) => id,
        Err(()) => {
            reference
                .release(&mut handler.pm)
                .expect("unsubmitted Section requestor");
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    let Some(park) = root_reply_park::RootReplyPark::prepare() else {
        reference
            .release(&mut handler.pm)
            .expect("unsubmitted Section requestor");
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    };
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let index = rows.iter().enumerate().find_map(|(index, row)| {
        (row.is_none() && EXECUTING_INDEX.load(Ordering::Acquire) != index as u64).then_some(index)
    });
    if index.is_none() && rows.try_reserve(1).is_err() {
        reference
            .release(&mut handler.pm)
            .expect("unsubmitted Section requestor");
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(reply, 0);
    let work = Work {
        caller,
        logical,
        reference,
        pi: handler.pi,
        tid,
        badge: handler.current_badge,
        reply,
        resume_ip: handler.current_resume_ip,
        sp: handler.current_sp,
        flags: handler.current_flags,
        native_call_transport: handler.current_native_call_transport,
        service_number: handler.current_service_number,
        output,
        desired_access,
        attributes,
        maxsize,
        page_protection,
        allocation_attrs,
        file_handle,
        image_name,
        capture: Some(capture),
        origin_driver,
        metadata,
        metadata_id,
        file_metadata: None,
        image_header: Vec::new(),
        image_path,
        observation_target,
        reserved: None,
        published_handle: None,
        phase: Phase::Query,
        status: 0,
        cancelled: false,
        cancel_requested: false,
    };
    match index {
        Some(index) => rows[index] = Some(work),
        None => rows.push(Some(work)),
    }
    park.commit();
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    assert!(!TRANSFERRED.swap(true, Ordering::AcqRel));
    Ok(())
}

pub(crate) fn take_transferred() -> bool {
    TRANSFERRED.swap(false, Ordering::AcqRel)
}

pub(crate) fn has_thread(tid: u64) -> bool {
    (EXECUTING_TID.load(Ordering::Acquire) == tid
        && !EXECUTING_ADMISSION_RELEASED.load(Ordering::Acquire))
        || unsafe {
            (&*core::ptr::addr_of!(WORK))
                .iter()
                .flatten()
                .any(|work| {
                    work.tid == tid
                        && !matches!(&work.phase, Phase::ReplySent | Phase::ReconcileRuntime)
                })
        }
}

pub(crate) fn has_process(pi: usize, preserve_tid: Option<u64>) -> bool {
    (EXECUTING_PI.load(Ordering::Acquire) == pi as u64
        && !EXECUTING_ADMISSION_RELEASED.load(Ordering::Acquire)
        && preserve_tid != Some(EXECUTING_TID.load(Ordering::Acquire)))
        || unsafe {
            (&*core::ptr::addr_of!(WORK)).iter().flatten().any(|work| {
                work.pi == pi
                    && preserve_tid != Some(work.tid)
                    && !matches!(&work.phase, Phase::ReplySent | Phase::ReconcileRuntime)
            })
        }
}

pub(crate) fn next_deadline() -> Option<u64> {
    (EXECUTING_TID.load(Ordering::Acquire) != 0
        || unsafe { (&*core::ptr::addr_of!(WORK)).iter().any(Option::is_some) })
    .then(|| NEXT.load(Ordering::Acquire))
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

enum Step {
    Progress,
    Wait,
    Done,
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler, queue: &mut nt_delay_execution::Queue) {
    if next_deadline().is_none_or(|deadline| monotonic_time_100ns() < deadline)
        || ACTIVE.swap(true, Ordering::AcqRel)
    {
        return;
    }
    let _durable = allocator::enter_durable();
    let selected = {
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        let start = CURSOR.load(Ordering::Relaxed) as usize % rows.len();
        (0..rows.len()).find_map(|step| {
            let index = (start + step) % rows.len();
            rows[index].take().map(|work| (index, work))
        })
    };
    if let Some((index, mut work)) = selected {
        CURSOR.store(index as u64 + 1, Ordering::Relaxed);
        EXECUTING_INDEX.store(index as u64, Ordering::Release);
        EXECUTING_TID.store(work.tid, Ordering::Release);
        EXECUTING_PI.store(work.pi as u64, Ordering::Release);
        let mut done = false;
        for _ in 0..8 {
            let step = service_sec_image::with_section_metadata_context(
                handler,
                work.pi,
                work.tid,
                work.badge,
                work.resume_ip,
                work.sp,
                work.flags,
                work.native_call_transport,
                work.service_number,
                |handler| advance(handler, queue, &mut work),
            );
            let step = match step {
                Some(step) => step,
                None if spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(
                    work.reply,
                ) || handler
                    .pm
                    .thread(work.logical.thread().thread_id())
                    .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
                    || handler
                        .pm
                        .process(work.logical.process().pid)
                        .is_some_and(|process| {
                            process.state == nt_process::ProcessState::Terminated
                        }) =>
                {
                    work.cancelled = true;
                    advance(handler, queue, &mut work)
                }
                None => break,
            };
            match step {
                Step::Progress => {}
                Step::Wait => break,
                Step::Done => {
                    done = true;
                    break;
                }
            }
        }
        if !done {
            let slot = &mut (&mut *core::ptr::addr_of_mut!(WORK))[index];
            assert!(slot.is_none(), "executing Section metadata slot was reused");
            *slot = Some(work);
        }
        EXECUTING_TID.store(0, Ordering::Release);
        EXECUTING_PI.store(u64::MAX, Ordering::Release);
        EXECUTING_ADMISSION_RELEASED.store(false, Ordering::Release);
        EXECUTING_INDEX.store(u64::MAX, Ordering::Release);
    }
    NEXT.store(
        monotonic_time_100ns().saturating_add(RETRY_DELAY),
        Ordering::Release,
    );
    ACTIVE.store(false, Ordering::Release);
}

unsafe fn advance(
    handler: &mut ExecNtHandler,
    queue: &mut nt_delay_execution::Queue,
    work: &mut Work,
) -> Step {
    work.cancelled |=
        spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(work.reply)
            || handler
                .pm
                .thread(work.logical.thread().thread_id())
                .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
            || handler
                .pm
                .process(work.logical.process().pid)
                .is_some_and(|process| process.state == nt_process::ProcessState::Terminated);
    match work.phase {
        Phase::Query => {
            if work.cancelled {
                work.status = STATUS_CANCELLED;
                work.capture.take();
                work.phase = Phase::RevokeReply;
                return Step::Progress;
            }
            let Some(class) = work.metadata.next_query(work.metadata_id) else {
                let (_, result) = work
                    .metadata
                    .take_terminal(work.metadata_id)
                    .expect("Section metadata did not reach a terminal phase");
                match result {
                    Ok(metadata) => {
                        work.file_metadata = Some(metadata);
                        work.phase = if work.allocation_attrs & 0x0100_0000 != 0 {
                            Phase::HeaderDispatch
                        } else {
                            Phase::Publish
                        };
                    }
                    Err(status) => {
                        work.capture.take();
                        work.status = status;
                        work.phase = Phase::ReadyReply;
                    }
                }
                return Step::Progress;
            };
            let length = if class == nt_fs::FILE_STANDARD_INFORMATION {
                24
            } else {
                8
            };
            let capture = work
                .capture
                .as_ref()
                .expect("Section metadata File capture");
            let mut output = [0u8; 24];
            let result = driver_launch::io_manager_mut().build_and_dispatch_external_to_device(
                nt_types::ClientId(driver_launch::IO_MANAGER_COMPONENT_ID),
                DeviceId(capture.device_id()),
                Some(FileId(capture.file_id())),
                0,
                work.tid,
                nt_io_abi::major::IRP_MJ_QUERY_INFORMATION,
                IoParameters::QueryInformation(InformationParameters {
                    info_class: class,
                    length: length as u32,
                }),
                0,
                length as u32,
                &mut output[..length],
            );
            match result {
                Ok(ExternalDispatchResult::Completed {
                    status,
                    information,
                    ..
                }) => {
                    assert!(work.metadata.complete_inline(
                        work.metadata_id,
                        CompletedFileQuery {
                            status: status.raw() as u32,
                            information,
                            output: &output[..length],
                        }
                    ));
                }
                Ok(ExternalDispatchResult::Pending { irp_id }) => {
                    assert!(work.metadata.bind_pending(work.metadata_id, irp_id.raw()));
                    work.phase = Phase::Pending {
                        irp: irp_id,
                        length,
                    };
                }
                Err(status) => {
                    assert!(work.metadata.complete_inline(
                        work.metadata_id,
                        CompletedFileQuery {
                            status: status.raw() as u32,
                            information: 0,
                            output: &[],
                        }
                    ));
                }
            }
            Step::Progress
        }
        Phase::Pending { irp, length } => {
            if work.cancelled && !work.cancel_requested {
                work.cancel_requested = true;
                let _ = driver_launch::cancel_irp_if_pending(irp.raw());
            }
            let Some(completion) = driver_launch::completed_irp_exact(irp.raw()) else {
                return Step::Wait;
            };
            let capture = work
                .capture
                .as_ref()
                .expect("pending Section metadata File capture");
            if completion.client_id != driver_launch::IO_MANAGER_COMPONENT_ID
                || completion.driver_id != work.origin_driver
                || completion.file_id != capture.file_id()
                || completion.device_id != capture.device_id()
                || completion.requestor_tid != work.tid
                || completion.major != nt_io_abi::major::IRP_MJ_QUERY_INFORMATION
            {
                work.phase = Phase::Indeterminate;
                return Step::Wait;
            }
            if !work.metadata.terminal(
                work.metadata_id,
                irp.raw(),
                completion.status,
                completion.information,
            ) {
                work.phase = Phase::Indeterminate;
                return Step::Wait;
            }
            work.phase = if completion.status == 0 && completion.information == length as u64 {
                Phase::Copying {
                    irp,
                    length,
                    offset: 0,
                }
            } else {
                Phase::AckPending { irp }
            };
            Step::Progress
        }
        Phase::Copying {
            irp,
            length,
            offset,
        } => {
            let mut bytes = [0u8; 24];
            let remaining = length - offset;
            let copied = match driver_launch::copy_completed_irp_output_exact(
                irp.raw(),
                offset as u64,
                &mut bytes[..remaining],
            ) {
                Ok(copied) if copied != 0 && copied <= remaining => copied,
                _ => return Step::Wait,
            };
            assert!(work
                .metadata
                .append(work.metadata_id, irp.raw(), offset, &bytes[..copied],));
            let next = offset + copied;
            work.phase = if next == length {
                Phase::AckPending { irp }
            } else {
                Phase::Copying {
                    irp,
                    length,
                    offset: next,
                }
            };
            Step::Progress
        }
        Phase::AckPending { irp } => {
            // The backend ACK is entered once. An uncertain result retains all owners.
            work.phase = Phase::Indeterminate;
            if driver_launch::io_manager_mut()
                .acknowledge_completed_irp_strict(irp)
                .is_err()
            {
                return Step::Wait;
            }
            assert!(work
                .metadata
                .acknowledge_backend(work.metadata_id, irp.raw()));
            work.phase = Phase::Query;
            Step::Progress
        }
        Phase::HeaderDispatch => {
            if work.cancelled {
                work.capture.take();
                work.status = STATUS_CANCELLED;
                work.phase = Phase::RevokeReply;
                return Step::Progress;
            }
            let metadata = work.file_metadata.expect("image file metadata");
            let offset = work.image_header.len();
            let Ok(file_size) = usize::try_from(metadata.end_of_file) else {
                work.status = STATUS_INSUFFICIENT_RESOURCES;
                work.phase = Phase::ReadyReply;
                return Step::Progress;
            };
            if metadata.is_directory || file_size == 0 || offset > file_size {
                work.status = STATUS_INVALID_IMAGE_FORMAT;
                work.phase = Phase::ReadyReply;
                return Step::Progress;
            }
            if offset as u64 == metadata.end_of_file {
                if nt_pe_loader::PeFile::parse(&work.image_header).is_ok() {
                    work.phase = Phase::Publish;
                } else {
                    work.status = STATUS_INVALID_IMAGE_FORMAT;
                    work.phase = Phase::ReadyReply;
                }
                return Step::Progress;
            }
            let length = IMAGE_HEADER_READ_SIZE.min(file_size - offset);
            if nt_pe_loader::reserve_file_snapshot_capacity(&mut work.image_header, file_size).is_err() {
                work.status = STATUS_INSUFFICIENT_RESOURCES;
                work.phase = Phase::ReadyReply;
                return Step::Progress;
            }
            let capture = work.capture.as_ref().expect("image header File capture");
            let mut output = [0u8; IMAGE_HEADER_READ_SIZE];
            let result = driver_launch::io_manager_mut().build_and_dispatch_external_to_device(
                nt_types::ClientId(driver_launch::IO_MANAGER_COMPONENT_ID),
                DeviceId(capture.device_id()),
                Some(FileId(capture.file_id())),
                0,
                work.tid,
                nt_io_abi::major::IRP_MJ_READ,
                IoParameters::Read(nt_io_manager::ReadWriteParameters {
                    length: length as u32,
                    key: 0,
                    offset: offset as u64,
                }),
                0,
                length as u32,
                &mut output[..length],
            );
            match result {
                Ok(ExternalDispatchResult::Completed { status, information, .. })
                    if status.raw() == 0 && information == length as u64 =>
                {
                    work.image_header.extend_from_slice(&output[..length]);
                }
                Ok(ExternalDispatchResult::Completed { status, .. }) => {
                    work.status = if status.raw() == 0 {
                        STATUS_INVALID_IMAGE_FORMAT
                    } else {
                        status.raw() as u32
                    };
                    work.phase = Phase::ReadyReply;
                }
                Ok(ExternalDispatchResult::Pending { irp_id }) => {
                    work.phase = Phase::HeaderPending { irp: irp_id, length };
                }
                Err(status) => {
                    work.status = status.raw() as u32;
                    work.phase = Phase::ReadyReply;
                }
            }
            Step::Progress
        }
        Phase::HeaderPending { irp, length } => {
            if work.cancelled && !work.cancel_requested {
                work.cancel_requested = true;
                let _ = driver_launch::cancel_irp_if_pending(irp.raw());
            }
            let Some(completion) = driver_launch::completed_irp_exact(irp.raw()) else {
                return Step::Wait;
            };
            let capture = work.capture.as_ref().expect("pending image header File capture");
            if completion.client_id != driver_launch::IO_MANAGER_COMPONENT_ID
                || completion.driver_id != work.origin_driver
                || completion.file_id != capture.file_id()
                || completion.device_id != capture.device_id()
                || completion.requestor_tid != work.tid
                || completion.major != nt_io_abi::major::IRP_MJ_READ
            {
                work.phase = Phase::Indeterminate;
                return Step::Wait;
            }
            if completion.status == 0 && completion.information == length as u64 {
                work.phase = Phase::HeaderCopying { irp, length, offset: 0 };
            } else {
                work.status = if completion.status == 0 {
                    STATUS_INVALID_IMAGE_FORMAT
                } else {
                    completion.status
                };
                work.phase = Phase::HeaderAckPending { irp };
            }
            Step::Progress
        }
        Phase::HeaderCopying { irp, length, offset } => {
            let mut bytes = [0u8; IMAGE_HEADER_READ_SIZE];
            let remaining = length - offset;
            let copied = match driver_launch::copy_completed_irp_output_exact(
                irp.raw(),
                offset as u64,
                &mut bytes[..remaining],
            ) {
                Ok(copied) if copied != 0 && copied <= remaining => copied,
                _ => return Step::Wait,
            };
            work.image_header.extend_from_slice(&bytes[..copied]);
            let next = offset + copied;
            work.phase = if next == length {
                Phase::HeaderAckPending { irp }
            } else {
                Phase::HeaderCopying { irp, length, offset: next }
            };
            Step::Progress
        }
        Phase::HeaderAckPending { irp } => {
            work.phase = Phase::Indeterminate;
            if driver_launch::io_manager_mut()
                .acknowledge_completed_irp_strict(irp)
                .is_err()
            {
                return Step::Wait;
            }
            work.phase = if work.status == 0 {
                Phase::HeaderDispatch
            } else {
                Phase::ReadyReply
            };
            Step::Progress
        }
        Phase::Publish => {
            let metadata = work.file_metadata.take().expect("Section publication metadata");
            if work.cancelled
                || work.reference.validate(&handler.pm).is_err()
                || !handler.validate_provider_logical_caller(work.logical)
            {
                work.capture.take();
                work.status = STATUS_CANCELLED;
                work.phase = Phase::RevokeReply;
                return Step::Progress;
            }
            let capture = work.capture.take().expect("Section publication File capture");
            let result = if work.allocation_attrs & 0x0100_0000 != 0 {
                handler.reserve_native_image_section(
                    work.caller,
                    work.desired_access,
                    work.attributes,
                    work.maxsize,
                    work.page_protection,
                    work.allocation_attrs,
                    crate::exec_handler::image_section_create::RoutedImageAdmission {
                        capture,
                        metadata,
                        header: core::mem::take(&mut work.image_header),
                        image_path: work.image_path.take().expect("captured image File name"),
                        observation_target: work.observation_target,
                        name: work.image_name.take(),
                    },
                ).map(ReservedSection::Image)
            } else {
                handler.reserve_generic_data_section(
                    work.caller,
                    work.pi,
                    work.desired_access,
                    work.attributes,
                    work.maxsize,
                    work.page_protection,
                    work.allocation_attrs,
                    work.file_handle,
                    Some(crate::exec_handler::section_create::RoutedSectionAdmission {
                        capture,
                        metadata,
                    }),
                ).map(ReservedSection::Data)
            };
            match result {
                Ok(reserved) => {
                    work.reserved = Some(reserved);
                    work.phase = Phase::CopyOut;
                    return Step::Progress;
                }
                Err(status) => {
                    work.status = status;
                }
            }
            work.phase = Phase::ReadyReply;
            Step::Progress
        }
        Phase::CopyOut => {
            if work.cancelled {
                work.reserved
                    .take()
                    .expect("cancelled Section reservation")
                    .abort(handler);
                work.phase = Phase::RevokeReply;
                return Step::Progress;
            }
            let handle = work
                .reserved
                .as_ref()
                .expect("Section output reservation")
                .value();
            match handler.process_memory_write_checked(work.pi, work.output, &handle.to_le_bytes())
            {
                Ok(()) => {
                    if spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(
                        work.reply,
                    ) || work.reference.validate(&handler.pm).is_err()
                        || !handler.validate_provider_logical_caller(work.logical)
                    {
                        work.reserved.take().unwrap().abort(handler);
                        work.cancelled = true;
                        work.phase = Phase::RevokeReply;
                        return Step::Progress;
                    }
                    if let Err(status) = work.reserved.as_mut().unwrap().publish(handler) {
                        work.reserved.take().unwrap().abort(handler);
                        work.status = status;
                        work.phase = Phase::ReadyReply;
                        return Step::Progress;
                    }
                    work.reserved.take();
                    work.published_handle = Some(handle);
                    loader_trace_record(
                        work.pi,
                        LoaderOp::CreateSection,
                        0,
                        None,
                        work.file_handle,
                        handle,
                        b"",
                    );
                    work.status = 0;
                    work.phase = Phase::ReadyReply;
                    Step::Progress
                }
                Err(nt_address_space::copy::MemoryCopyFailure::UserFault(status)) => {
                    work.reserved.take().unwrap().abort(handler);
                    work.status = status;
                    work.phase = Phase::ReadyReply;
                    Step::Progress
                }
                Err(nt_address_space::copy::MemoryCopyFailure::Retry(_)) => Step::Wait,
            }
        }
        Phase::ReadyReply => {
            if work.cancelled {
                if let Some(handle) = work.published_handle {
                    match handler.close_native_table_handle(work.caller, handle) {
                        Ok(_) => work.published_handle = None,
                        Err(_)
                            if handler
                                .pm
                                .process(work.caller.effective_process())
                                .is_none_or(|process| {
                                    matches!(
                                        process.state,
                                        nt_process::ProcessState::Exiting
                                            | nt_process::ProcessState::Terminated
                                    )
                                }) =>
                        {
                            work.published_handle = None
                        }
                        Err(_) => return Step::Wait,
                    }
                }
                work.phase = Phase::RevokeReply;
                return Step::Progress;
            }
            if parked_reply::validate_saved(work.reply).is_err() {
                return Step::Wait;
            }
            work.phase = Phase::ReplyEntered;
            if !reply_parked_syscall(work.reply, work.status as u64) {
                return Step::Wait;
            }
            work.phase = Phase::ReplySent;
            EXECUTING_ADMISSION_RELEASED.store(true, Ordering::Release);
            Step::Progress
        }
        Phase::ReplyEntered => {
            match spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                work.reply,
            ) {
                Ok(true) => {
                    work.phase = Phase::ReplySent;
                    EXECUTING_ADMISSION_RELEASED.store(true, Ordering::Release);
                    Step::Progress
                }
                _ if work.cancelled => {
                    work.phase = Phase::RevokeReply;
                    Step::Progress
                }
                _ => Step::Wait,
            }
        }
        Phase::ReplySent => {
            if parked_reply::retire_sent(work.reply).is_err() {
                return Step::Wait;
            }
            thread_wait_state_clear_badge_ready(handler, work.badge);
            work.reference
                .release(&mut handler.pm)
                .expect("Section requestor reference");
            Step::Done
        }
        Phase::RevokeReply => {
            if !spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(work.reply)
                && parked_reply::revoke(work.reply).is_err()
            {
                return Step::Wait;
            }
            work.phase = Phase::RetypeReply;
            Step::Progress
        }
        Phase::RetypeReply => {
            if parked_reply::retype(work.reply).is_err() {
                return Step::Wait;
            }
            work.phase = Phase::ReconcileRuntime;
            Step::Progress
        }
        Phase::ReconcileRuntime => {
            EXECUTING_ADMISSION_RELEASED.store(true, Ordering::Release);
            if !hosted_termination::reconcile(handler, queue, work.logical) {
                return Step::Wait;
            }
            work.reference
                .release(&mut handler.pm)
                .expect("retired Section requestor reference");
            Step::Done
        }
        Phase::Indeterminate => Step::Wait,
    }
}
