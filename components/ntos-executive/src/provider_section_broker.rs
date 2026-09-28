//! Dispatch-bound publication of win32k-created native data sections.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_io_manager::{
    win32k_section_create_wire::{self as wire, SectionCreateRequest},
    DeviceId, ExternalDispatchResult, FileId, InformationParameters, IoParameters, IrpId,
};
use nt_memory_manager::{
    CompletedFileQuery, PendingSectionMetadataId, PendingSectionMetadataQueries,
};
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

use crate::exec_handler::section_create::{ReservedGenericDataSection, RoutedSectionAdmission};
use crate::{driver_launch, mounted_volume, spawn_hosts, ExecNtHandler};

pub(crate) const OP_CREATE: u64 = 1;
pub(crate) const OP_PUBLISH: u64 = 2;
pub(crate) const OP_ABORT: u64 = 3;
pub(crate) const OP_ACK: u64 = 4;

const STATUS_INVALID_HANDLE: u32 = nt_process::STATUS_INVALID_HANDLE;
const STATUS_INVALID_PARAMETER: u32 = nt_process::STATUS_INVALID_PARAMETER;
const STATUS_INSUFFICIENT_RESOURCES: u32 = nt_process::STATUS_INSUFFICIENT_RESOURCES;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const SEC_IMAGE: u32 = 0x0100_0000;
const STATUS_CANCELLED: u32 = 0xc000_0120;
const RETRY_DELAY: u64 = 1_000_000;

pub(crate) enum SubmitResult {
    Ready((i32, u64, u64, u64)),
    Deferred,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Owner {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    caller: NativeHandleCaller,
    token: u64,
}

enum Phase {
    Creating,
    CancelledCreating,
    Reserved(ReservedGenericDataSection),
    Publishing,
    Aborted,
    PublishedUnacknowledged,
    EffectUncertain,
}

struct Pending {
    owner: Owner,
    handle: u64,
    phase: Phase,
    metadata: Option<MetadataWork>,
}

enum MetadataPhase {
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
    Reserve,
    ReadyReply,
    ReplyEntered,
    Indeterminate,
}

struct MetadataWork {
    reply: u64,
    reference: NativeThreadProcessReference,
    owner_pi: usize,
    request: SectionCreateRequest,
    capture: Option<driver_launch::hosted_file_capture::Capture>,
    origin_driver: u64,
    metadata: PendingSectionMetadataQueries<(), u64>,
    metadata_id: PendingSectionMetadataId,
    reserved: Option<ReservedGenericDataSection>,
    phase: MetadataPhase,
    status: u32,
    cancel_requested: bool,
}

static mut PENDING: Vec<Pending> = Vec::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static NEXT_RETRY: AtomicU64 = AtomicU64::new(0);
static CURSOR: AtomicU64 = AtomicU64::new(0);
static EXECUTING: AtomicBool = AtomicBool::new(false);

unsafe fn position(owner: Owner, handle: u64) -> Option<usize> {
    (&*core::ptr::addr_of!(PENDING))
        .iter()
        .position(|entry| entry.owner == owner && entry.handle == handle)
}

unsafe fn decode_request(packet: u64, length: u64) -> Result<SectionCreateRequest, u32> {
    if length != wire::PACKET_BYTES as u64 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let (_, bytes) =
        crate::win32k_subsystem::capture_provider_pool_packet(packet, wire::PACKET_BYTES)?;
    let request = wire::decode(&bytes).map_err(|_| STATUS_INVALID_PARAMETER)?;
    if request.allocation_attributes & SEC_IMAGE != 0 {
        return Err(STATUS_NOT_SUPPORTED);
    }
    Ok(request)
}

unsafe fn create(
    handler: &mut ExecNtHandler,
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    caller: NativeHandleCaller,
    request: SectionCreateRequest,
) -> Result<(u64, u64), u32> {
    let owner_pi = handler.native_section_owner_pi(caller)?;
    let token = NEXT_TOKEN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let owner = Owner {
        route,
        dispatch,
        caller,
        token,
    };
    {
        let pending = &mut *core::ptr::addr_of_mut!(PENDING);
        pending
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        pending.push(Pending {
            owner,
            handle: 0,
            phase: Phase::Creating,
            metadata: None,
        });
    }
    let result = handler.reserve_generic_data_section(
        caller,
        owner_pi,
        request.desired_access,
        request.object_attributes.unwrap_or(0),
        request.maximum_size.unwrap_or(0),
        request.page_protection,
        request.allocation_attributes,
        request.file_handle,
        None,
    );
    match result {
        Ok(mut reserved) => {
            let handle = reserved.value();
            let Some(index) = position(owner, 0) else {
                reserved.abort(handler);
                return Err(STATUS_INVALID_HANDLE);
            };
            let mut reserved = Some(reserved);
            let active = {
                let pending = &mut *core::ptr::addr_of_mut!(PENDING);
                if matches!(pending[index].phase, Phase::Creating) {
                    pending[index].handle = handle;
                    pending[index].phase = Phase::Reserved(reserved.take().unwrap());
                    true
                } else {
                    pending.swap_remove(index);
                    false
                }
            };
            if !active {
                let mut reserved = reserved.unwrap();
                reserved.abort(handler);
                return Err(STATUS_INVALID_HANDLE);
            }
            Ok((token, handle))
        }
        Err(status) => {
            if let Some(index) = position(owner, 0) {
                (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
            }
            Err(status)
        }
    }
}

pub(crate) unsafe fn submit(
    handler: &mut ExecNtHandler,
    channel: &spawn_hosts::PumpChannel,
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    caller: NativeHandleCaller,
    op: u64,
    first: u64,
    second: u64,
    third: u64,
) -> SubmitResult {
    if op != OP_CREATE || third != 0 {
        return SubmitResult::Ready(dispatch_op(
            handler, route, dispatch, caller, op, first, second, third,
        ));
    }
    let request = match decode_request(first, second) {
        Ok(request) => request,
        Err(status) => return SubmitResult::Ready((status as i32, 0, 0, 0)),
    };
    let source = if request.file_handle == 0 {
        None
    } else {
        match handler
            .pm
            .lookup_native_section_file_source(caller, request.file_handle)
        {
            Ok(source) => Some(source),
            Err(status) => return SubmitResult::Ready((status as i32, 0, 0, 0)),
        }
    };
    let Some(source) = source else {
        return SubmitResult::Ready(result_words(create(
            handler, route, dispatch, caller, request,
        )));
    };
    let nt_process::HandleObject::RoutedFile { file_id, device_id } = source.object() else {
        return SubmitResult::Ready(result_words(create(
            handler, route, dispatch, caller, request,
        )));
    };
    let _durable = crate::allocator::enter_durable();
    let result = (|| -> Result<(), u32> {
        nt_memory_manager::data_section::check_data_section_file_access(
            request.page_protection,
            source.granted_access(),
        )?;
        let owner_pi = handler.native_section_owner_pi(caller)?;
        let mount = mounted_volume::mount_id_for_live_device(device_id).ok_or(0xc000_0020u32)?;
        let capture = driver_launch::hosted_file_capture::capture(
            file_id,
            device_id,
            source.granted_access(),
        )?;
        let origin_driver = driver_launch::io_manager_mut()
            .device(DeviceId(device_id))
            .ok_or(STATUS_INVALID_HANDLE)?
            .driver_id
            .raw();
        let mut reference = handler.pm.reference_native_requestor(caller)?;
        let mut metadata = PendingSectionMetadataQueries::<(), u64>::new();
        let metadata_id = match metadata.reserve(mount, ()) {
            Ok(id) => id,
            Err(()) => {
                reference
                    .release(&mut handler.pm)
                    .expect("unsubmitted provider Section requestor");
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
        };
        let reply = match spawn_hosts::shared_ingress::owner::runtime::current_reply(route) {
            Ok(reply) if reply == channel.reply_cap => reply,
            _ => {
                reference
                    .release(&mut handler.pm)
                    .expect("unsubmitted provider Section requestor");
                return Err(STATUS_INVALID_HANDLE);
            }
        };
        let token = match NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        }) {
            Ok(token) => token,
            Err(_) => {
                reference
                    .release(&mut handler.pm)
                    .expect("unsubmitted provider Section requestor");
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
        };
        if (&mut *core::ptr::addr_of_mut!(PENDING))
            .try_reserve(1)
            .is_err()
        {
            reference
                .release(&mut handler.pm)
                .expect("unsubmitted provider Section requestor");
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let owner = Owner {
            route,
            dispatch,
            caller,
            token,
        };
        (&mut *core::ptr::addr_of_mut!(PENDING)).push(Pending {
            owner,
            handle: 0,
            phase: Phase::Creating,
            metadata: Some(MetadataWork {
                reply,
                reference,
                owner_pi,
                request,
                capture: Some(capture),
                origin_driver,
                metadata,
                metadata_id,
                reserved: None,
                phase: MetadataPhase::Query,
                status: 0,
                cancel_requested: false,
            }),
        });
        if spawn_hosts::shared_ingress::owner::runtime::park_retained_service(route, token).is_err()
        {
            let index = position(owner, 0).expect("unparked provider Section owner");
            let mut entry = (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
            let mut work = entry
                .metadata
                .take()
                .expect("unparked provider Section work");
            work.reference
                .release(&mut handler.pm)
                .expect("unparked provider Section requestor");
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        NEXT_RETRY.store(crate::monotonic_time_100ns(), Ordering::Release);
        Ok(())
    })();
    match result {
        Ok(()) => SubmitResult::Deferred,
        Err(status) => SubmitResult::Ready((status as i32, 0, 0, 0)),
    }
}

fn result_words(result: Result<(u64, u64), u32>) -> (i32, u64, u64, u64) {
    match result {
        Ok((token, handle)) => (0, token, handle, 0),
        Err(status) => (status as i32, 0, 0, 0),
    }
}

enum MetadataStep {
    Progress,
    Wait,
    Replied,
    Cancelled,
}

impl MetadataWork {
    unsafe fn advance(
        &mut self,
        handler: &mut ExecNtHandler,
        owner: Owner,
        cancelled: bool,
    ) -> MetadataStep {
        use spawn_hosts::shared_ingress::owner::runtime;
        let cancelled = cancelled
            || runtime::retained_service_cancelled(
                owner.route,
                owner.dispatch,
                self.reply,
                owner.token,
            );
        match self.phase {
            MetadataPhase::Query => {
                if cancelled {
                    return MetadataStep::Cancelled;
                }
                let Some(class) = self.metadata.next_query(self.metadata_id) else {
                    self.phase = MetadataPhase::Reserve;
                    return MetadataStep::Progress;
                };
                let length = if class == nt_fs::FILE_STANDARD_INFORMATION {
                    24
                } else {
                    8
                };
                let capture = self
                    .capture
                    .as_ref()
                    .expect("provider Section File capture");
                let mut output = [0u8; 24];
                let result = driver_launch::io_manager_mut().build_and_dispatch_external_to_device(
                    nt_types::ClientId(driver_launch::IO_MANAGER_COMPONENT_ID),
                    DeviceId(capture.device_id()),
                    Some(FileId(capture.file_id())),
                    0,
                    u64::from(owner.caller.original_thread().thread_id()),
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
                        assert!(self.metadata.complete_inline(
                            self.metadata_id,
                            CompletedFileQuery {
                                status: status.raw() as u32,
                                information,
                                output: &output[..length],
                            }
                        ));
                    }
                    Ok(ExternalDispatchResult::Pending { irp_id }) => {
                        assert!(self.metadata.bind_pending(self.metadata_id, irp_id.raw()));
                        self.phase = MetadataPhase::Pending {
                            irp: irp_id,
                            length,
                        };
                    }
                    Err(status) => {
                        assert!(self.metadata.complete_inline(
                            self.metadata_id,
                            CompletedFileQuery {
                                status: status.raw() as u32,
                                information: 0,
                                output: &[],
                            }
                        ));
                    }
                }
                MetadataStep::Progress
            }
            MetadataPhase::Pending { irp, length } => {
                if cancelled && !self.cancel_requested {
                    self.cancel_requested = true;
                    let _ = driver_launch::cancel_irp_if_pending(irp.raw());
                }
                let Some(completion) = driver_launch::completed_irp_exact(irp.raw()) else {
                    return MetadataStep::Wait;
                };
                let capture = self
                    .capture
                    .as_ref()
                    .expect("pending provider Section File capture");
                if completion.client_id != driver_launch::IO_MANAGER_COMPONENT_ID
                    || completion.driver_id != self.origin_driver
                    || completion.file_id != capture.file_id()
                    || completion.device_id != capture.device_id()
                    || completion.requestor_tid
                        != u64::from(owner.caller.original_thread().thread_id())
                    || completion.major != nt_io_abi::major::IRP_MJ_QUERY_INFORMATION
                    || !self.metadata.terminal(
                        self.metadata_id,
                        irp.raw(),
                        completion.status,
                        completion.information,
                    )
                {
                    self.phase = MetadataPhase::Indeterminate;
                    return MetadataStep::Wait;
                }
                self.phase = if completion.status == 0 && completion.information == length as u64 {
                    MetadataPhase::Copying {
                        irp,
                        length,
                        offset: 0,
                    }
                } else {
                    MetadataPhase::AckPending { irp }
                };
                MetadataStep::Progress
            }
            MetadataPhase::Copying {
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
                    _ => return MetadataStep::Wait,
                };
                assert!(self.metadata.append(
                    self.metadata_id,
                    irp.raw(),
                    offset,
                    &bytes[..copied]
                ));
                let next = offset + copied;
                self.phase = if next == length {
                    MetadataPhase::AckPending { irp }
                } else {
                    MetadataPhase::Copying {
                        irp,
                        length,
                        offset: next,
                    }
                };
                MetadataStep::Progress
            }
            MetadataPhase::AckPending { irp } => {
                self.phase = MetadataPhase::Indeterminate;
                if driver_launch::io_manager_mut()
                    .acknowledge_completed_irp_strict(irp)
                    .is_err()
                {
                    return MetadataStep::Wait;
                }
                assert!(self
                    .metadata
                    .acknowledge_backend(self.metadata_id, irp.raw()));
                self.phase = MetadataPhase::Query;
                MetadataStep::Progress
            }
            MetadataPhase::Reserve => {
                let (_, result) = self
                    .metadata
                    .take_terminal(self.metadata_id)
                    .expect("provider Section metadata terminal");
                let metadata = match result {
                    Ok(metadata) => metadata,
                    Err(status) => {
                        self.capture.take();
                        self.status = status;
                        self.phase = MetadataPhase::ReadyReply;
                        return MetadataStep::Progress;
                    }
                };
                if cancelled {
                    self.capture.take();
                    return MetadataStep::Cancelled;
                }
                if let Err(status) = self.reference.validate(&handler.pm) {
                    self.capture.take();
                    self.status = status;
                    self.phase = MetadataPhase::ReadyReply;
                    return MetadataStep::Progress;
                }
                let admission = RoutedSectionAdmission {
                    capture: self
                        .capture
                        .take()
                        .expect("provider Section admission capture"),
                    metadata,
                };
                match handler.reserve_generic_data_section(
                    owner.caller,
                    self.owner_pi,
                    self.request.desired_access,
                    self.request.object_attributes.unwrap_or(0),
                    self.request.maximum_size.unwrap_or(0),
                    self.request.page_protection,
                    self.request.allocation_attributes,
                    self.request.file_handle,
                    Some(admission),
                ) {
                    Ok(reserved) => self.reserved = Some(reserved),
                    Err(status) => self.status = status,
                }
                self.phase = MetadataPhase::ReadyReply;
                MetadataStep::Progress
            }
            MetadataPhase::ReadyReply => {
                if cancelled {
                    return MetadataStep::Cancelled;
                }
                if self.reference.validate(&handler.pm).is_err() {
                    self.status = STATUS_CANCELLED;
                    if let Some(mut reserved) = self.reserved.take() {
                        reserved.abort(handler);
                    }
                }
                self.phase = MetadataPhase::ReplyEntered;
                let handle = self
                    .reserved
                    .as_ref()
                    .map_or(0, ReservedGenericDataSection::value);
                if runtime::wake_section_create_service(
                    owner.route,
                    owner.dispatch,
                    self.reply,
                    owner.token,
                    self.status as i32,
                    handle,
                )
                .is_err()
                    && matches!(
                        runtime::retained_service_reply_not_entered(
                            owner.route,
                            owner.dispatch,
                            self.reply,
                            owner.token,
                        ),
                        Ok(true)
                    )
                {
                    self.phase = MetadataPhase::ReadyReply;
                }
                MetadataStep::Wait
            }
            MetadataPhase::ReplyEntered => {
                if matches!(
                    runtime::reconcile_retained_service_reply(
                        owner.route,
                        owner.dispatch,
                        self.reply,
                        owner.token,
                    ),
                    Ok(true)
                ) {
                    runtime::retire_stopped_acknowledged_retained_service(
                        owner.route,
                        owner.dispatch,
                        self.reply,
                        owner.token,
                    )
                    .expect("acknowledged provider Section Reply retirement");
                    return MetadataStep::Replied;
                }
                if cancelled {
                    return MetadataStep::Cancelled;
                }
                MetadataStep::Wait
            }
            MetadataPhase::Indeterminate => MetadataStep::Wait,
        }
    }
}

pub(crate) fn next_deadline() -> Option<u64> {
    (EXECUTING.load(Ordering::Acquire)
        || unsafe {
            (&*core::ptr::addr_of!(PENDING))
                .iter()
                .any(|entry| entry.metadata.is_some())
        })
    .then(|| NEXT_RETRY.load(Ordering::Acquire))
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    if next_deadline().is_none_or(|deadline| crate::monotonic_time_100ns() < deadline) {
        return;
    }
    if EXECUTING.swap(true, Ordering::AcqRel) {
        return;
    }
    let _durable = crate::allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(PENDING)).len();
    if count == 0 {
        EXECUTING.store(false, Ordering::Release);
        return;
    }
    let start = CURSOR.load(Ordering::Relaxed) as usize % count;
    let selected = (0..count).find_map(|step| {
        let index = (start + step) % count;
        let entry = &mut (&mut *core::ptr::addr_of_mut!(PENDING))[index];
        entry.metadata.take().map(|work| (entry.owner, work, index))
    });
    if let Some((owner, mut work, selected_index)) = selected {
        CURSOR.store(selected_index as u64 + 1, Ordering::Relaxed);
        let mut step = MetadataStep::Progress;
        for _ in 0..8 {
            let cancelled = position(owner, 0).is_some_and(|index| {
                matches!(
                    (&*core::ptr::addr_of!(PENDING))[index].phase,
                    Phase::CancelledCreating,
                )
            });
            step = work.advance(handler, owner, cancelled);
            if !matches!(step, MetadataStep::Progress) {
                break;
            }
        }
        let Some(index) = position(owner, 0) else {
            panic!("provider Section metadata lost its broker owner");
        };
        match step {
            MetadataStep::Replied => {
                work.reference
                    .release(&mut handler.pm)
                    .expect("acknowledged provider Section requestor");
                if matches!(
                    (&*core::ptr::addr_of!(PENDING))[index].phase,
                    Phase::CancelledCreating,
                ) {
                    if let Some(mut reserved) = work.reserved.take() {
                        reserved.abort(handler);
                    }
                    (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
                } else if let Some(reserved) = work.reserved.take() {
                    let handle = reserved.value();
                    let entry = &mut (&mut *core::ptr::addr_of_mut!(PENDING))[index];
                    entry.handle = handle;
                    entry.phase = Phase::Reserved(reserved);
                } else {
                    (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
                }
            }
            MetadataStep::Cancelled => {
                if !spawn_hosts::shared_ingress::owner::runtime::retained_service_cancelled(
                    owner.route,
                    owner.dispatch,
                    work.reply,
                    owner.token,
                ) {
                    (&mut *core::ptr::addr_of_mut!(PENDING))[index].metadata = Some(work);
                    NEXT_RETRY.store(
                        crate::monotonic_time_100ns().saturating_add(RETRY_DELAY),
                        Ordering::Release,
                    );
                    EXECUTING.store(false, Ordering::Release);
                    return;
                }
                if let Some(mut reserved) = work.reserved.take() {
                    reserved.abort(handler);
                }
                work.capture.take();
                spawn_hosts::shared_ingress::owner::runtime::acknowledge_retained_service_cancellation(
                    owner.route, owner.dispatch, work.reply, owner.token,
                ).expect("cancelled provider Section Reply retirement");
                work.reference
                    .release(&mut handler.pm)
                    .expect("cancelled provider Section requestor");
                (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
            }
            _ => (&mut *core::ptr::addr_of_mut!(PENDING))[index].metadata = Some(work),
        }
    }
    NEXT_RETRY.store(
        crate::monotonic_time_100ns().saturating_add(RETRY_DELAY),
        Ordering::Release,
    );
    EXECUTING.store(false, Ordering::Release);
}

unsafe fn publish(handler: &mut ExecNtHandler, owner: Owner, handle: u64) -> Result<(), u32> {
    let index = position(owner, handle).ok_or(STATUS_INVALID_HANDLE)?;
    let mut reserved = {
        let pending = &mut *core::ptr::addr_of_mut!(PENDING);
        if !matches!(pending[index].phase, Phase::Reserved(_)) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let Phase::Reserved(reserved) =
            core::mem::replace(&mut pending[index].phase, Phase::Publishing)
        else {
            unreachable!()
        };
        reserved
    };
    match reserved.publish(handler) {
        Ok(value) => {
            assert_eq!(
                value, handle,
                "Section publication changed its reserved handle"
            );
            let index = position(owner, handle).ok_or(STATUS_INVALID_HANDLE)?;
            (&mut *core::ptr::addr_of_mut!(PENDING))[index].phase = Phase::PublishedUnacknowledged;
            Ok(())
        }
        Err(status) => {
            reserved.abort(handler);
            let index = position(owner, handle).ok_or(STATUS_INVALID_HANDLE)?;
            (&mut *core::ptr::addr_of_mut!(PENDING))[index].phase = Phase::Aborted;
            Err(status)
        }
    }
}

unsafe fn abort(handler: &mut ExecNtHandler, owner: Owner, handle: u64) -> Result<(), u32> {
    let index = position(owner, handle).ok_or(STATUS_INVALID_HANDLE)?;
    if !matches!(
        (&*core::ptr::addr_of!(PENDING))[index].phase,
        Phase::Reserved(_) | Phase::Aborted
    ) {
        return Err(STATUS_INVALID_HANDLE);
    }
    let pending = (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
    if let Phase::Reserved(mut reserved) = pending.phase {
        reserved.abort(handler);
    }
    Ok(())
}

unsafe fn dispatch_op(
    handler: &mut ExecNtHandler,
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    caller: NativeHandleCaller,
    op: u64,
    first: u64,
    second: u64,
    third: u64,
) -> (i32, u64, u64, u64) {
    let result = match op {
        OP_CREATE if third == 0 => decode_request(first, second)
            .and_then(|request| create(handler, route, dispatch, caller, request)),
        OP_PUBLISH | OP_ABORT | OP_ACK if third == 0 && first != 0 && second != 0 => {
            let owner = Owner {
                route,
                dispatch,
                caller,
                token: first,
            };
            match op {
                OP_PUBLISH => publish(handler, owner, second).map(|()| (0, 0)),
                OP_ABORT => abort(handler, owner, second).map(|()| (0, 0)),
                OP_ACK => {
                    let index = match position(owner, second) {
                        Some(index) => index,
                        None => return (STATUS_INVALID_HANDLE as i32, 0, 0, 0),
                    };
                    if !matches!(
                        (&*core::ptr::addr_of!(PENDING))[index].phase,
                        Phase::PublishedUnacknowledged
                    ) {
                        Err(STATUS_INVALID_HANDLE)
                    } else {
                        (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
                        Ok((0, 0))
                    }
                }
                _ => unreachable!(),
            }
        }
        _ => Err(STATUS_INVALID_PARAMETER),
    };
    result_words(result)
}

/// Called after exact physical dispatch retirement, not merely after a Reply is sent.
pub(crate) unsafe fn retire_completed(
    handler: &mut ExecNtHandler,
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
) {
    let mut index = 0;
    while index < (&*core::ptr::addr_of!(PENDING)).len() {
        let owner = (&*core::ptr::addr_of!(PENDING))[index].owner;
        if owner.route != route || owner.dispatch != dispatch {
            index += 1;
            continue;
        }
        let phase = match (&*core::ptr::addr_of!(PENDING))[index].phase {
            Phase::Creating => 0,
            Phase::Reserved(_) => 1,
            Phase::Aborted => 2,
            Phase::Publishing => 3,
            Phase::PublishedUnacknowledged => 4,
            Phase::CancelledCreating => 5,
            Phase::EffectUncertain => 6,
        };
        match phase {
            0 => {
                (&mut *core::ptr::addr_of_mut!(PENDING))[index].phase = Phase::CancelledCreating;
                index += 1;
            }
            1 | 2 => {
                let entry = (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
                if let Phase::Reserved(mut reserved) = entry.phase {
                    reserved.abort(handler);
                }
            }
            3 | 4 => {
                (&mut *core::ptr::addr_of_mut!(PENDING))[index].phase = Phase::EffectUncertain;
                index += 1;
            }
            _ => index += 1,
        }
    }
}
