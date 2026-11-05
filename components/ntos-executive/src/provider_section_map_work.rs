//! Retained provider kernel Section maps. A routed page read owns its Reply,
//! canonical File, exact Section view, and IRP through terminal copy and ACK.

use crate::spawn_hosts::shared_ingress::owner::runtime::{self, PhysicalSource};
use crate::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_io_manager::{
    DeviceId, ExternalDispatchResult, FileId, InformationParameters, IoParameters, IrpId,
    ReadWriteParameters,
};
use nt_memory_manager::data_section::{
    plan_data_section_read_window, DataSectionReadWindow, DATA_PAGE_SIZE, STATUS_IO_DEVICE_ERROR,
};
use nt_memory_manager::pending_section_pagein::{
    PendingSectionPageReadId, PendingSectionPageReads,
};
use nt_memory_manager::CompletedFileQuery;
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

const RETRY_DELAY: u64 = 1_000_000;
const INVALID: u32 = nt_process::STATUS_INVALID_HANDLE;
const NO_MEMORY: u32 = nt_process::STATUS_INSUFFICIENT_RESOURCES;
const CANCELLED: u32 = 0xc000_0120;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Prepare,
    Tables,
    Query,
    QueryPending(IrpId),
    QueryCopying(IrpId, usize),
    QueryAck(IrpId),
    Frame,
    ReadPending(IrpId),
    ReadCopying(IrpId, usize),
    ReadAck(IrpId),
    PublishFrame,
    Abort,
    ReadyReply,
    ReplyEntered,
    Release,
    ReleaseOnly,
    Done,
    Indeterminate,
}

struct Work {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    caller: NativeHandleCaller,
    physical: PhysicalSource,
    reply: u64,
    token: u64,
    reference: NativeThreadProcessReference,
    address: u64,
    requested_size: u64,
    prepared: Option<crate::provider_mm_section_objects::PreparedMap>,
    capture: Option<driver_launch::hosted_file_capture::Capture>,
    lease: Option<nt_memory_manager::RoutedSectionLease>,
    origin_driver: u64,
    page: usize,
    file_size: u64,
    query_output: [u8; 24],
    query_status: u32,
    query_information: u64,
    read: Option<PendingSectionPageReadId>,
    plan: Option<DataSectionReadWindow>,
    bytes: Option<Vec<u8>>,
    result: (u32, u64, u64),
    published: bool,
    retry_at: u64,
    phase: Phase,
    cancel_requested: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut READS: PendingSectionPageReads<(), u64> = PendingSectionPageReads::new();
static EXECUTING: AtomicBool = AtomicBool::new(false);
static NEXT: AtomicU64 = AtomicU64::new(0);

pub(crate) unsafe fn submit(
    handler: &mut ExecNtHandler,
    channel: &spawn_hosts::PumpChannel,
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    caller: NativeHandleCaller,
    physical: PhysicalSource,
    address: u64,
    requested_size: u64,
) -> crate::provider_section_broker::SubmitResult {
    use crate::provider_section_broker::SubmitResult;
    let _durable = allocator::enter_durable();
    let reply = match runtime::current_reply(route) {
        Ok(reply) if reply == channel.reply_cap => reply,
        _ => return SubmitResult::Ready((INVALID as i32, 0, 0, 0)),
    };
    let token = match runtime::next_service_wait_token() {
        Ok(token) => token,
        Err(_) => return SubmitResult::Ready((NO_MEMORY as i32, 0, 0, 0)),
    };
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let index = rows.iter().position(Option::is_none);
    if index.is_none() && rows.try_reserve(1).is_err() {
        return SubmitResult::Ready((NO_MEMORY as i32, 0, 0, 0));
    }
    let reference = match handler.pm.reference_native_requestor(caller) {
        Ok(reference) => reference,
        Err(status) => return SubmitResult::Ready((status as i32, 0, 0, 0)),
    };
    let work = Work {
        route,
        dispatch,
        caller,
        physical,
        reply,
        token,
        reference,
        address,
        requested_size,
        prepared: None,
        capture: None,
        lease: None,
        origin_driver: 0,
        page: 0,
        file_size: 0,
        query_output: [0; 24],
        query_status: 0,
        query_information: 0,
        read: None,
        plan: None,
        bytes: None,
        result: (0, 0, 0),
        published: false,
        retry_at: 0,
        phase: Phase::Prepare,
        cancel_requested: false,
    };
    let slot = if let Some(index) = index {
        rows[index] = Some(work);
        index
    } else {
        rows.push(Some(work));
        rows.len() - 1
    };
    if runtime::park_retained_service(route, token).is_err() {
        rows[slot].as_mut().unwrap().phase = Phase::ReleaseOnly;
        NEXT.store(monotonic_time_100ns(), Ordering::Release);
        return SubmitResult::Ready((NO_MEMORY as i32, 0, 0, 0));
    }
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    SubmitResult::Deferred
}

unsafe fn valid(handler: &ExecNtHandler, work: &Work) -> bool {
    if work.reference.validate(&handler.pm).is_err()
        || !matches!(runtime::physical_source(work.route), Ok(source) if source == work.physical)
        || !matches!(runtime::dispatch(work.route), Ok(dispatch) if dispatch == work.dispatch)
    {
        return false;
    }
    let Some(prepared) = work.prepared else {
        return true;
    };
    let Ok(table) = (unsafe {
        crate::provider_mm_section_objects::table_for_map_validation(handler as *const _ as *mut _)
    }) else {
        return false;
    };
    let table = unsafe { &*table };
    if table.section_identity(prepared.section.index()) != Some(prepared.section)
        || table.provider_view_for_page(prepared.view.owner, prepared.base) != Some(prepared.view)
    {
        return false;
    }
    if let (Some(lease), Some(capture)) = (work.lease, work.capture.as_ref()) {
        unsafe { hosted_routed_section_capture::route(lease, prepared.section) }.is_some_and(
            |route| {
                route.file_id == capture.file_id()
                    && route.device_id == capture.device_id()
                    && route.fs_context == capture.fs_context()
                    && route.granted_access == capture.granted_access()
            },
        )
    } else {
        true
    }
}

unsafe fn advance(handler: &mut ExecNtHandler, work: &mut Work) {
    let cancelled =
        runtime::retained_service_cancelled(work.route, work.dispatch, work.reply, work.token)
            || !valid(handler, work);
    match work.phase {
        Phase::Prepare => {
            if cancelled {
                work.result.0 = CANCELLED;
                work.phase = Phase::ReadyReply;
                return;
            }
            let prepared = match crate::provider_mm_section_objects::prepare_map(
                handler as *mut _,
                work.address,
                work.physical,
                work.requested_size,
                work.caller,
            ) {
                Ok(prepared) => prepared,
                Err(status) => {
                    work.result.0 = status;
                    work.phase = Phase::ReadyReply;
                    return;
                }
            };
            work.prepared = Some(prepared);
            if let Some(lease) = prepared.backing.backing.routed_lease {
                let Some(route) = hosted_routed_section_capture::route(lease, prepared.section)
                else {
                    work.result.0 = INVALID;
                    work.phase = Phase::Abort;
                    return;
                };
                let capture = match driver_launch::hosted_file_capture::capture_owned(
                    route.file_id,
                    route.device_id,
                    route.granted_access,
                ) {
                    Ok(capture) if capture.fs_context() == route.fs_context => capture,
                    _ => {
                        work.result.0 = INVALID;
                        work.phase = Phase::Abort;
                        return;
                    }
                };
                work.origin_driver =
                    match driver_launch::io_manager_mut().device(DeviceId(route.device_id)) {
                        Some(device) => device.driver_id.raw(),
                        None => {
                            work.result.0 = INVALID;
                            work.phase = Phase::Abort;
                            return;
                        }
                    };
                work.lease = Some(lease);
                work.capture = Some(capture);
            }
            work.phase = Phase::Tables;
        }
        Phase::Tables => {
            let prepared = work.prepared.unwrap();
            if cancelled {
                work.result.0 = CANCELLED;
                work.phase = Phase::Abort;
                return;
            }
            match crate::provider_mm_section_objects::map_prepared_tables(prepared) {
                Ok(()) => {
                    work.phase = if work.lease.is_some() {
                        Phase::Query
                    } else {
                        Phase::Frame
                    }
                }
                Err(status) => {
                    work.result.0 = status;
                    work.phase = Phase::Abort;
                }
            }
        }
        Phase::Query => {
            if cancelled {
                work.result.0 = CANCELLED;
                work.phase = Phase::Abort;
                return;
            }
            let capture = work.capture.as_ref().unwrap();
            let result = driver_launch::io_manager_mut().build_and_dispatch_external_to_device(
                nt_types::ClientId(driver_launch::IO_MANAGER_COMPONENT_ID),
                DeviceId(capture.device_id()),
                Some(FileId(capture.file_id())),
                0,
                0,
                nt_io_abi::major::IRP_MJ_QUERY_INFORMATION,
                IoParameters::QueryInformation(InformationParameters {
                    info_class: nt_fs::FILE_STANDARD_INFORMATION,
                    length: 24,
                }),
                0,
                24,
                &mut work.query_output,
            );
            match result {
                Ok(ExternalDispatchResult::Completed {
                    status,
                    information,
                    ..
                }) => {
                    work.query_status = status.raw() as u32;
                    work.query_information = information;
                    work.phase = Phase::Frame;
                }
                Ok(ExternalDispatchResult::Pending { irp_id }) => {
                    work.phase = Phase::QueryPending(irp_id)
                }
                Err(status) => {
                    work.result.0 = status.raw() as u32;
                    work.phase = Phase::Abort;
                }
            }
        }
        Phase::QueryPending(irp) => {
            if cancelled && !work.cancel_requested {
                work.cancel_requested = true;
                let _ = driver_launch::cancel_irp_if_pending(irp.raw());
            }
            let Some(done) = driver_launch::completed_irp_exact(irp.raw()) else {
                return;
            };
            let capture = work.capture.as_ref().unwrap();
            if done.client_id != driver_launch::IO_MANAGER_COMPONENT_ID
                || done.driver_id != work.origin_driver
                || done.file_id != capture.file_id()
                || done.device_id != capture.device_id()
                || done.requestor_tid != 0
                || done.major != nt_io_abi::major::IRP_MJ_QUERY_INFORMATION
                || done.status == 0x103
            {
                work.phase = Phase::Indeterminate;
                return;
            }
            work.query_status = done.status;
            work.query_information = done.information;
            work.phase = if done.status == 0 && done.information == 24 {
                Phase::QueryCopying(irp, 0)
            } else {
                Phase::QueryAck(irp)
            };
        }
        Phase::QueryCopying(irp, offset) => {
            match driver_launch::copy_completed_irp_output_exact(
                irp.raw(),
                offset as u64,
                &mut work.query_output[offset..],
            ) {
                Ok(n) if n != 0 && n <= 24 - offset => {
                    work.phase = if offset + n == 24 {
                        Phase::QueryAck(irp)
                    } else {
                        Phase::QueryCopying(irp, offset + n)
                    };
                }
                _ => {
                    work.query_status = STATUS_IO_DEVICE_ERROR;
                    work.phase = Phase::QueryAck(irp);
                }
            }
        }
        Phase::QueryAck(irp) => {
            work.phase = Phase::Indeterminate;
            if driver_launch::io_manager_mut()
                .acknowledge_completed_irp_strict(irp)
                .is_ok()
            {
                work.phase = if cancelled {
                    work.result.0 = CANCELLED;
                    Phase::Abort
                } else {
                    Phase::Frame
                };
            }
        }
        Phase::Frame => {
            if cancelled {
                work.result.0 = CANCELLED;
                work.phase = Phase::Abort;
                return;
            }
            let prepared = work.prepared.unwrap();
            let sections = match crate::provider_mm_section_objects::table_for_map_validation(
                handler as *mut _,
            ) {
                Ok(table) => table,
                Err(status) => {
                    work.result.0 = status;
                    work.phase = Phase::Abort;
                    return;
                }
            };
            if work.page == 0 && work.lease.is_some() {
                let eof = nt_memory_manager::routed_section_metadata::decode_standard_query(
                    CompletedFileQuery {
                        status: work.query_status,
                        information: work.query_information,
                        output: &work.query_output,
                    },
                );
                match eof {
                    Ok((size, false)) => work.file_size = size,
                    Ok((_, true)) => {
                        work.result.0 = STATUS_IO_DEVICE_ERROR;
                        work.phase = Phase::Abort;
                        return;
                    }
                    Err(status) => {
                        work.result.0 = status;
                        work.phase = Phase::Abort;
                        return;
                    }
                }
                if let Err(status) =
                    (&mut *sections).refresh_file_extent(prepared.section.index(), work.file_size)
                {
                    work.result.0 = status;
                    work.phase = Phase::Abort;
                    return;
                }
            }
            if work.page == prepared.pages {
                work.phase = Phase::ReadyReply;
                return;
            }
            if let Some(frame) = (&*sections).page_frame(prepared.section.index(), work.page as u64)
            {
                if let Err(status) = crate::provider_mm_section_objects::map_prepared_frame(
                    handler as *mut _,
                    prepared,
                    work.page,
                    frame,
                ) {
                    work.result.0 = status;
                    work.phase = Phase::Abort;
                } else {
                    work.page += 1;
                }
                return;
            }
            if let Some(lease) = work.lease {
                let plan = match plan_data_section_read_window(
                    work.page as u64,
                    prepared.backing.size,
                    work.file_size,
                    (prepared.pages - work.page).min(8),
                ) {
                    Ok(plan) => plan,
                    Err(status) => {
                        work.result.0 = status;
                        work.phase = Phase::Abort;
                        return;
                    }
                };
                let read = match (&mut *core::ptr::addr_of_mut!(READS)).reserve_window(
                    prepared.section,
                    lease,
                    work.page as u64,
                    plan,
                    (),
                ) {
                    Ok(read) => read,
                    Err(()) => {
                        work.result.0 = NO_MEMORY;
                        work.phase = Phase::Abort;
                        return;
                    }
                };
                work.plan = Some(plan);
                work.read = Some(read);
                let mut output = Vec::new();
                if output.try_reserve_exact(plan.length()).is_err() {
                    let _ = (&mut *core::ptr::addr_of_mut!(READS)).cancel_reserved(read);
                    work.result.0 = NO_MEMORY;
                    work.phase = Phase::Abort;
                    return;
                }
                output.resize(plan.length(), 0);
                let capture = work.capture.as_ref().unwrap();
                let result = driver_launch::io_manager_mut().build_and_dispatch_external_to_device(
                    nt_types::ClientId(driver_launch::IO_MANAGER_COMPONENT_ID),
                    DeviceId(capture.device_id()),
                    Some(FileId(capture.file_id())),
                    0,
                    0,
                    nt_io_abi::major::IRP_MJ_READ,
                    IoParameters::Read(ReadWriteParameters {
                        length: plan.length() as u32,
                        key: 0,
                        offset: plan.offset(),
                    }),
                    0,
                    plan.length() as u32,
                    &mut output,
                );
                match result {
                    Ok(ExternalDispatchResult::Completed {
                        status,
                        information,
                        ..
                    }) => {
                        let (_, result) = (&mut *core::ptr::addr_of_mut!(READS))
                            .complete_inline(read, status.raw() as u32, information, &output)
                            .expect("reserved provider MAP read");
                        match result {
                            Ok(bytes) => {
                                work.bytes = Some(bytes);
                                work.phase = Phase::PublishFrame;
                            }
                            Err(status) => {
                                work.result.0 = status;
                                work.phase = Phase::Abort;
                            }
                        }
                    }
                    Ok(ExternalDispatchResult::Pending { irp_id }) => {
                        assert!((&mut *core::ptr::addr_of_mut!(READS)).bind(read, irp_id.raw()));
                        work.phase = Phase::ReadPending(irp_id);
                    }
                    Err(status) => {
                        let _ = (&mut *core::ptr::addr_of_mut!(READS)).cancel_reserved(read);
                        work.result.0 = status.raw() as u32;
                        work.phase = Phase::Abort;
                    }
                }
            } else {
                match crate::service_sec_image::service_generic_section_frame(
                    sections,
                    prepared.section.index(),
                    prepared.section,
                    prepared.backing,
                    work.page as u64,
                    EXECUTIVE_WIN32K_SCRATCH_BASE,
                    false,
                ) {
                    Ok(frame) => {
                        if let Err(status) = crate::provider_mm_section_objects::map_prepared_frame(
                            handler as *mut _,
                            prepared,
                            work.page,
                            frame,
                        ) {
                            work.result.0 = status;
                            work.phase = Phase::Abort;
                        } else {
                            work.page += 1;
                        }
                    }
                    Err(status) => {
                        work.result.0 = status;
                        work.phase = Phase::Abort;
                    }
                }
            }
        }
        Phase::ReadPending(irp) => {
            if cancelled && !work.cancel_requested {
                work.cancel_requested = true;
                let _ = driver_launch::cancel_irp_if_pending(irp.raw());
            }
            let Some(done) = driver_launch::completed_irp_exact(irp.raw()) else {
                return;
            };
            let capture = work.capture.as_ref().unwrap();
            if done.client_id != driver_launch::IO_MANAGER_COMPONENT_ID
                || done.driver_id != work.origin_driver
                || done.file_id != capture.file_id()
                || done.device_id != capture.device_id()
                || done.requestor_tid != 0
                || done.major != nt_io_abi::major::IRP_MJ_READ
                || !(&mut *core::ptr::addr_of_mut!(READS)).terminal(
                    work.read.unwrap(),
                    irp.raw(),
                    done.status,
                    done.information,
                )
            {
                work.phase = Phase::Indeterminate;
                return;
            }
            work.phase = if (&*core::ptr::addr_of!(READS))
                .failure(work.read.unwrap(), irp.raw())
                .is_some()
            {
                Phase::ReadAck(irp)
            } else {
                Phase::ReadCopying(irp, 0)
            };
        }
        Phase::ReadCopying(irp, offset) => {
            let mut bytes = [0u8; DATA_PAGE_SIZE];
            let Some(length) = work.plan.unwrap().next_copy_len(offset, bytes.len()) else {
                work.phase = Phase::Indeterminate;
                return;
            };
            match driver_launch::copy_completed_irp_output_exact(
                irp.raw(),
                offset as u64,
                &mut bytes[..length],
            ) {
                Ok(n) if n != 0 && n <= length => {
                    if !(&mut *core::ptr::addr_of_mut!(READS)).append(
                        work.read.unwrap(),
                        irp.raw(),
                        offset,
                        &bytes[..n],
                    ) {
                        work.phase = Phase::Indeterminate;
                        return;
                    }
                    work.phase = if (&*core::ptr::addr_of!(READS))
                        .ready_page(work.read.unwrap(), irp.raw())
                        .is_some()
                    {
                        Phase::ReadAck(irp)
                    } else {
                        Phase::ReadCopying(irp, offset + n)
                    };
                }
                _ => {
                    let _ = (&mut *core::ptr::addr_of_mut!(READS)).fail_copy(
                        work.read.unwrap(),
                        irp.raw(),
                        STATUS_IO_DEVICE_ERROR,
                    );
                    work.phase = Phase::ReadAck(irp);
                }
            }
        }
        Phase::ReadAck(irp) => {
            work.phase = Phase::Indeterminate;
            if driver_launch::io_manager_mut()
                .acknowledge_completed_irp_strict(irp)
                .is_err()
            {
                return;
            }
            assert!((&mut *core::ptr::addr_of_mut!(READS))
                .acknowledge_backend(work.read.unwrap(), irp.raw()));
            let prepared = work.prepared.unwrap();
            let expected = work.lease.unwrap();
            let page = work.page as u64;
            let exact = valid(handler, work);
            let result = (&mut *core::ptr::addr_of_mut!(READS)).take_acknowledged_if(
                work.read.unwrap(),
                irp.raw(),
                |_, section, lease, index| {
                    exact && section == prepared.section && lease == expected && index == page
                },
            );
            let Some((_, result)) = result else {
                return;
            };
            match result {
                Ok(bytes) if !cancelled => {
                    work.bytes = Some(bytes);
                    work.phase = Phase::PublishFrame;
                }
                Err(status) => {
                    work.result.0 = status;
                    work.phase = Phase::Abort;
                }
                _ => {
                    work.result.0 = CANCELLED;
                    work.phase = Phase::Abort;
                }
            }
        }
        Phase::PublishFrame => {
            if cancelled {
                work.result.0 = CANCELLED;
                work.phase = Phase::Abort;
                return;
            }
            let prepared = work.prepared.unwrap();
            let sections = match crate::provider_mm_section_objects::table_for_map_validation(
                handler as *mut _,
            ) {
                Ok(table) => table,
                Err(status) => {
                    work.result.0 = status;
                    work.phase = Phase::Abort;
                    return;
                }
            };
            let plan = work.plan.unwrap();
            let bytes = work.bytes.as_ref().unwrap();
            let Some(page_bytes) = plan.page_bytes(work.page as u64, bytes) else {
                work.result.0 = STATUS_IO_DEVICE_ERROR;
                work.phase = Phase::Abort;
                return;
            };
            let frame =
                crate::service_sec_image::section_pagein::service_publish_section_frame_from_bytes(
                    sections,
                    prepared.section,
                    work.page as u64,
                    page_bytes,
                    EXECUTIVE_WIN32K_SCRATCH_BASE,
                );
            match frame.and_then(|frame| {
                crate::provider_mm_section_objects::map_prepared_frame(
                    handler as *mut _,
                    prepared,
                    work.page,
                    frame,
                )
            }) {
                Ok(()) => {
                    work.page += 1;
                    if plan.page_bytes(work.page as u64, work.bytes.as_ref().unwrap()).is_some() {
                        work.phase = Phase::PublishFrame;
                    } else {
                        work.bytes = None;
                        work.read = None;
                        work.plan = None;
                        work.phase = Phase::Frame;
                    }
                }
                Err(status) => {
                    work.result.0 = status;
                    work.phase = Phase::Abort;
                }
            }
        }
        Phase::Abort => {
            if let Some(prepared) = work.prepared {
                let cleanup = if work.published {
                    crate::provider_mm_section_objects::retire_cancelled_map(
                        handler as *mut _,
                        prepared,
                    )
                } else {
                    crate::provider_mm_section_objects::abort_map(handler as *mut _, prepared)
                };
                if cleanup.is_err() {
                    // The exact map receipt remains owned. A later drain may
                    // settle a no-effect refusal; uncertain caps never replay.
                    return;
                }
                work.prepared = None;
                work.published = false;
            }
            if runtime::retained_service_cancelled(
                work.route,
                work.dispatch,
                work.reply,
                work.token,
            ) {
                if runtime::acknowledge_retained_service_cancellation(
                    work.route,
                    work.dispatch,
                    work.reply,
                    work.token,
                )
                .is_err()
                {
                    work.phase = Phase::Indeterminate;
                    return;
                }
                work.phase = Phase::Release;
                return;
            }
            work.phase = Phase::ReadyReply;
        }
        Phase::ReadyReply => {
            if cancelled {
                work.result.0 = CANCELLED;
                work.phase = Phase::Abort;
                return;
            }
            if work.result.0 == 0 && !work.published {
                let prepared = work.prepared.unwrap();
                match crate::provider_mm_section_objects::publish_map(handler as *mut _, prepared) {
                    Ok((base, size)) => {
                        work.result.1 = base;
                        work.result.2 = size;
                        work.published = true;
                    }
                    Err(status) => {
                        work.result.0 = status;
                        work.phase = Phase::Abort;
                        return;
                    }
                }
            }
            work.phase = Phase::ReplyEntered;
            if runtime::wake_section_map_service(
                work.route,
                work.dispatch,
                work.reply,
                work.token,
                work.result.0 as i32,
                work.result.1,
                work.result.2,
            )
            .is_err()
                && matches!(
                    runtime::retained_service_reply_not_entered(
                        work.route,
                        work.dispatch,
                        work.reply,
                        work.token
                    ),
                    Ok(true)
                )
            {
                work.phase = Phase::ReadyReply;
            }
        }
        Phase::ReplyEntered => {
            if matches!(
                runtime::reconcile_retained_service_reply(
                    work.route,
                    work.dispatch,
                    work.reply,
                    work.token
                ),
                Ok(true)
            ) {
                runtime::retire_stopped_acknowledged_retained_service(
                    work.route,
                    work.dispatch,
                    work.reply,
                    work.token,
                )
                .expect("acknowledged provider MAP Reply retirement");
                work.phase = Phase::Release;
            } else if runtime::retained_service_cancelled(
                work.route,
                work.dispatch,
                work.reply,
                work.token,
            ) {
                work.result.0 = CANCELLED;
                work.phase = Phase::Abort;
            }
        }
        Phase::Release | Phase::ReleaseOnly => {
            if work.reference.release(&mut handler.pm).is_ok() {
                work.phase = Phase::Done;
            }
        }
        Phase::Done => {}
        Phase::Indeterminate => {}
    }
}

pub(crate) fn next_deadline() -> Option<u64> {
    (EXECUTING.load(Ordering::Acquire)
        || unsafe { (&*core::ptr::addr_of!(WORK)).iter().any(Option::is_some) })
    .then(|| NEXT.load(Ordering::Acquire))
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    if next_deadline().is_none_or(|deadline| monotonic_time_100ns() < deadline)
        || EXECUTING.swap(true, Ordering::AcqRel)
    {
        return;
    }
    let _durable = allocator::enter_durable();
    let now = monotonic_time_100ns();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    for index in 0..count {
        let Some(mut work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].take() else {
            continue;
        };
        if work.retry_at > now {
            (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
            continue;
        }
        // Bound inline page progress per owner so a large font never monopolizes
        // the service loop. Pending IRPs and uncertain effects wait for evidence.
        for _ in 0..8 {
            let (phase, page) = (work.phase, work.page);
            advance(handler, &mut work);
            if work.phase == phase && work.page == page {
                work.retry_at = now.saturating_add(RETRY_DELAY);
                break;
            }
            work.retry_at = 0;
            if matches!(
                work.phase,
                Phase::ReplyEntered | Phase::Indeterminate | Phase::Done
            ) {
                break;
            }
        }
        if !matches!(work.phase, Phase::Done) {
            (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        }
    }
    let next = (&*core::ptr::addr_of!(WORK))
        .iter()
        .flatten()
        .map(|work| {
            if work.retry_at == 0 {
                now
            } else {
                work.retry_at
            }
        })
        .min()
        .unwrap_or(now.saturating_add(RETRY_DELAY));
    NEXT.store(next, Ordering::Release);
    EXECUTING.store(false, Ordering::Release);
}
