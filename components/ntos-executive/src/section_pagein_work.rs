//! Retained routed data-section VM faults. Provider reads may outlive the fault ingress.

use crate::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_io_manager::{
    DeviceId, ExternalDispatchResult, FileId, InformationParameters, IoParameters, IrpId,
    ReadWriteParameters,
};
use nt_memory_manager::data_section::{
    plan_data_section_read_window, DataSectionReadWindow, DATA_PAGE_SIZE,
};
use nt_memory_manager::pending_section_pagein::{
    PendingSectionPageReadId, PendingSectionPageReads,
};
use nt_memory_manager::CompletedFileQuery;
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

const RETRY_DELAY: u64 = 1_000_000;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;

enum Phase {
    QueryDispatch,
    QueryPending(IrpId),
    QueryCopying(IrpId, usize),
    QueryAckPending(IrpId),
    PlanRead,
    Dispatch,
    Pending(IrpId),
    Copying(IrpId, usize),
    AckPending(IrpId),
    Publish(Vec<u8>),
    ReadyReply,
    ReplyEntered,
    ReplySent,
    Cancel,
    Cancelled,
    Indeterminate,
}

struct Work {
    pi: usize,
    tid: u64,
    badge: u64,
    reply: u64,
    logical: ProviderLogicalCaller,
    process: nt_user_host::process_identity::ProcessIdentity,
    view: GenericSectionView,
    info: nt_address_space::VmBasicInformation,
    section: nt_memory_manager::SectionIdentity,
    lease: nt_memory_manager::RoutedSectionLease,
    page: u64,
    page_index: u64,
    plan: Option<DataSectionReadWindow>,
    access: nt_address_space::FaultAccess,
    capture: driver_launch::hosted_file_capture::Capture,
    origin_driver: u64,
    read_id: Option<PendingSectionPageReadId>,
    query_output: [u8; 24],
    query_status: u32,
    query_information: u64,
    failure: Option<u32>,
    failure_logged: bool,
    phase: Phase,
    cancel_requested: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut READS: PendingSectionPageReads<(), u64> = PendingSectionPageReads::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);
static EXECUTING_TID: AtomicU64 = AtomicU64::new(0);
static EXECUTING_PI: AtomicU64 = AtomicU64::new(u64::MAX);
static EXECUTING_INDEX: AtomicU64 = AtomicU64::new(u64::MAX);
static NEXT: AtomicU64 = AtomicU64::new(0);

pub(crate) unsafe fn submit(
    handler: &mut ExecNtHandler,
    pi: usize,
    page: u64,
    access: nt_address_space::FaultAccess,
) -> Result<(), u32> {
    let _durable = allocator::enter_durable();
    let ctx = handler.loop_ctx.ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let table = &*ctx.generic_sections;
    let (section_index, view) = table
        .view_for_page(pi, page)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let section = table
        .section_identity(section_index)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let backing = table
        .section(section_index)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    if backing.backing.kind != nt_memory_manager::GENERIC_SECTION_BACKING_ROUTED {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    let lease = backing
        .backing
        .routed_lease
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let route =
        hosted_routed_section_capture::route(lease, section).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let process = handler
        .capture_process_identity(pi)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    if view.lifetime != nt_memory_manager::MemoryLifetime::Process(process) {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    let info = process_committed_mapping_basic_information(pi as u64, page)
        .ok_or(nt_address_space::STATUS_NOT_COMMITTED)?;
    if info.type_ != nt_address_space::MEM_MAPPED {
        return Err(nt_address_space::STATUS_CONFLICTING_ADDRESSES);
    }
    nt_address_space::mapped_view_fault_access_status(info.protect, access)?;
    let page_index = view
        .section_offset
        .checked_add(page - view.base)
        .ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?
        / DATA_PAGE_SIZE as u64;
    let tid = handler.current_tid;
    let tcb = handler
        .hosted_thread_tcb(tid)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let logical = handler
        .capture_provider_logical_caller(pi, tid, handler.current_badge, tcb)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let capture = driver_launch::hosted_file_capture::capture_owned(
        route.file_id,
        route.device_id,
        route.granted_access,
    )?;
    let origin_driver = driver_launch::io_manager_mut()
        .device(DeviceId(route.device_id))
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?
        .driver_id
        .raw();
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let index = rows.iter().enumerate().find_map(|(index, row)| {
        (row.is_none() && EXECUTING_INDEX.load(Ordering::Acquire) != index as u64).then_some(index)
    });
    if index.is_none() && rows.try_reserve(1).is_err() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let Some(park) = root_reply_park::RootReplyPark::prepare() else {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    };
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let work = Work {
        pi,
        tid,
        badge: handler.current_badge,
        reply,
        logical,
        process,
        view,
        info,
        section,
        lease,
        page,
        page_index,
        plan: None,
        access,
        capture,
        origin_driver,
        read_id: None,
        query_output: [0; 24],
        query_status: 0,
        query_information: 0,
        phase: Phase::QueryDispatch,
        cancel_requested: false,
        failure: None,
        failure_logged: false,
    };
    match index {
        Some(index) => rows[index] = Some(work),
        None => rows.push(Some(work)),
    }
    park.commit();
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    Ok(())
}

pub(crate) fn has_thread(tid: u64) -> bool {
    EXECUTING_TID.load(Ordering::Acquire) == tid
        || unsafe {
            (&*core::ptr::addr_of!(WORK))
                .iter()
                .flatten()
                .any(|work| work.tid == tid)
        }
}

pub(crate) fn has_process(pi: usize, preserve_tid: Option<u64>) -> bool {
    (EXECUTING_PI.load(Ordering::Acquire) == pi as u64
        && preserve_tid != Some(EXECUTING_TID.load(Ordering::Acquire)))
        || unsafe {
            (&*core::ptr::addr_of!(WORK))
                .iter()
                .flatten()
                .any(|work| work.pi == pi && preserve_tid != Some(work.tid))
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

fn valid(handler: &ExecNtHandler, work: &Work) -> bool {
    if handler.capture_process_identity(work.pi) != Some(work.process)
        || !handler.validate_provider_logical_caller(work.logical)
    {
        return false;
    }
    let Some(ctx) = handler.loop_ctx else {
        return false;
    };
    let table = unsafe { &*ctx.generic_sections };
    let Some((index, view)) = table.view_for_page(work.pi, work.page) else {
        return false;
    };
    index == work.view.section_index
        && view == work.view
        && table.section_identity(index) == Some(work.section)
        && unsafe { hosted_routed_section_capture::route(work.lease, work.section) }.is_some_and(
            |route| {
                route.file_id == work.capture.file_id()
                    && route.device_id == work.capture.device_id()
                    && route.fs_context == work.capture.fs_context()
                    && route.granted_access == work.capture.granted_access()
            },
        )
        && unsafe { process_committed_mapping_basic_information(work.pi as u64, work.page) }
            == Some(work.info)
        && nt_address_space::mapped_view_fault_access_status(work.info.protect, work.access).is_ok()
}

unsafe fn advance(handler: &mut ExecNtHandler, work: &mut Work) -> bool {
    let cancelled = spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(work.reply)
        || handler
            .pm
            .thread(work.logical.thread().thread_id())
            .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
        || handler
            .pm
            .process(work.logical.process().pid)
            .is_some_and(|process| process.state == nt_process::ProcessState::Terminated)
        || !valid(handler, work);
    match &mut work.phase {
        Phase::QueryDispatch => {
            if cancelled {
                work.phase = Phase::Cancel;
                return false;
            }
            let result = driver_launch::io_manager_mut().build_and_dispatch_external_to_device(
                nt_types::ClientId(driver_launch::IO_MANAGER_COMPONENT_ID),
                DeviceId(work.capture.device_id()),
                Some(FileId(work.capture.file_id())),
                0,
                work.tid,
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
                    work.phase = Phase::PlanRead;
                }
                Ok(ExternalDispatchResult::Pending { irp_id }) => {
                    work.phase = Phase::QueryPending(irp_id);
                }
                Err(status) => {
                    work.failure = Some(status.raw() as u32);
                    work.phase = Phase::Cancel;
                }
            }
            false
        }
        Phase::QueryPending(irp) => {
            let irp = *irp;
            if cancelled && !work.cancel_requested {
                work.cancel_requested = true;
                let _ = driver_launch::cancel_irp_if_pending(irp.raw());
            }
            let Some(completion) = driver_launch::completed_irp_exact(irp.raw()) else {
                return false;
            };
            if completion.client_id != driver_launch::IO_MANAGER_COMPONENT_ID
                || completion.driver_id != work.origin_driver
                || completion.file_id != work.capture.file_id()
                || completion.device_id != work.capture.device_id()
                || completion.requestor_tid != work.tid
                || completion.major != nt_io_abi::major::IRP_MJ_QUERY_INFORMATION
                || completion.status == 0x103
            {
                work.phase = Phase::Indeterminate;
                return false;
            }
            work.query_status = completion.status;
            work.query_information = completion.information;
            work.phase = if completion.status == 0 && completion.information == 24 {
                Phase::QueryCopying(irp, 0)
            } else {
                Phase::QueryAckPending(irp)
            };
            false
        }
        Phase::QueryCopying(irp, offset) => {
            let (irp, offset) = (*irp, *offset);
            let copied = match driver_launch::copy_completed_irp_output_exact(
                irp.raw(),
                offset as u64,
                &mut work.query_output[offset..],
            ) {
                Ok(copied) if copied != 0 && copied <= 24 - offset => copied,
                Ok(_) => {
                    work.query_status = nt_memory_manager::data_section::STATUS_IO_DEVICE_ERROR;
                    work.phase = Phase::QueryAckPending(irp);
                    return false;
                }
                Err(status) => {
                    work.query_status = status;
                    work.phase = Phase::QueryAckPending(irp);
                    return false;
                }
            };
            let next = offset + copied;
            work.phase = if next == 24 {
                Phase::QueryAckPending(irp)
            } else {
                Phase::QueryCopying(irp, next)
            };
            false
        }
        Phase::QueryAckPending(irp) => {
            let irp = *irp;
            work.phase = Phase::Indeterminate;
            if driver_launch::io_manager_mut()
                .acknowledge_completed_irp_strict(irp)
                .is_err()
            {
                return false;
            }
            work.phase = if cancelled {
                Phase::Cancel
            } else {
                Phase::PlanRead
            };
            false
        }
        Phase::PlanRead => {
            if cancelled {
                work.phase = Phase::Cancel;
                return false;
            }
            let end_of_file =
                match nt_memory_manager::routed_section_metadata::decode_standard_query(
                    CompletedFileQuery {
                        status: work.query_status,
                        information: work.query_information,
                        output: &work.query_output,
                    },
                ) {
                    Ok((end_of_file, false)) => end_of_file,
                    Ok((_, true)) => {
                        work.failure =
                            Some(nt_memory_manager::data_section::STATUS_INVALID_FILE_FOR_SECTION);
                        work.phase = Phase::Cancel;
                        return false;
                    }
                    Err(status) => {
                        work.failure = Some(status);
                        work.phase = Phase::Cancel;
                        return false;
                    }
                };
            let ctx = handler.loop_ctx.unwrap();
            let table = &mut *ctx.generic_sections;
            if let Err(status) = table.refresh_file_extent(work.view.section_index, end_of_file) {
                work.failure = Some(status);
                work.phase = Phase::Cancel;
                return false;
            }
            if table
                .page_frame(work.view.section_index, work.page_index)
                .is_some()
            {
                work.phase = Phase::ReadyReply;
                return false;
            }
            let Some(section) = table.section(work.view.section_index) else {
                work.phase = Phase::Cancel;
                return false;
            };
            let plan = match plan_data_section_read_window(
                work.page_index, section.size, end_of_file, 8,
            )
            {
                Ok(plan) => plan,
                Err(status) => {
                    work.failure = Some(status);
                    work.phase = Phase::Cancel;
                    return false;
                }
            };
            let read_id = match (&mut *core::ptr::addr_of_mut!(READS)).reserve_window(
                work.section,
                work.lease,
                work.page_index,
                plan,
                (),
            ) {
                Ok(id) => id,
                Err(()) => {
                    work.failure = Some(STATUS_INSUFFICIENT_RESOURCES);
                    work.phase = Phase::Cancel;
                    return false;
                }
            };
            work.plan = Some(plan);
            work.read_id = Some(read_id);
            work.phase = Phase::Dispatch;
            false
        }
        Phase::Dispatch => {
            if cancelled {
                (&mut *core::ptr::addr_of_mut!(READS)).cancel_reserved(work.read_id.unwrap());
                work.phase = Phase::Cancel;
                return false;
            }
            let (_, _, page_index) = (&*core::ptr::addr_of!(READS))
                .identity(work.read_id.unwrap())
                .unwrap();
            assert_eq!(page_index, work.page_index);
            let plan = work.plan.unwrap();
            let mut output = Vec::new();
            if output.try_reserve_exact(plan.length()).is_err() {
                (&mut *core::ptr::addr_of_mut!(READS)).cancel_reserved(work.read_id.unwrap());
                work.failure = Some(STATUS_INSUFFICIENT_RESOURCES);
                work.phase = Phase::Cancel;
                return false;
            }
            output.resize(plan.length(), 0);
            let result = driver_launch::io_manager_mut().build_and_dispatch_external_to_device(
                nt_types::ClientId(driver_launch::IO_MANAGER_COMPONENT_ID),
                DeviceId(work.capture.device_id()),
                Some(FileId(work.capture.file_id())),
                0,
                work.tid,
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
                        .complete_inline(
                            work.read_id.unwrap(),
                            status.raw() as u32,
                            information,
                            &output,
                        )
                        .expect("reserved Section page read");
                    work.phase = match result {
                        Ok(bytes) => Phase::Publish(bytes),
                        Err(status) => {
                            work.failure = Some(status);
                            Phase::Cancel
                        }
                    };
                }
                Ok(ExternalDispatchResult::Pending { irp_id }) => {
                    assert!((&mut *core::ptr::addr_of_mut!(READS))
                        .bind(work.read_id.unwrap(), irp_id.raw()));
                    work.phase = Phase::Pending(irp_id);
                }
                Err(status) => {
                    (&mut *core::ptr::addr_of_mut!(READS)).cancel_reserved(work.read_id.unwrap());
                    work.failure = Some(status.raw() as u32);
                    work.phase = Phase::Cancel;
                }
            }
            false
        }
        Phase::Pending(irp) => {
            let irp = *irp;
            if cancelled && !work.cancel_requested {
                work.cancel_requested = true;
                let _ = driver_launch::cancel_irp_if_pending(irp.raw());
            }
            let Some(completion) = driver_launch::completed_irp_exact(irp.raw()) else {
                return false;
            };
            if completion.client_id != driver_launch::IO_MANAGER_COMPONENT_ID
                || completion.driver_id != work.origin_driver
                || completion.file_id != work.capture.file_id()
                || completion.device_id != work.capture.device_id()
                || completion.requestor_tid != work.tid
                || completion.major != nt_io_abi::major::IRP_MJ_READ
                || !(&mut *core::ptr::addr_of_mut!(READS)).terminal(
                    work.read_id.unwrap(),
                    irp.raw(),
                    completion.status,
                    completion.information,
                )
            {
                work.phase = Phase::Indeterminate;
                return false;
            }
            work.phase = if (&*core::ptr::addr_of!(READS))
                .failure(work.read_id.unwrap(), irp.raw())
                .is_some()
            {
                Phase::AckPending(irp)
            } else {
                Phase::Copying(irp, 0)
            };
            false
        }
        Phase::Copying(irp, offset) => {
            let (irp, offset) = (*irp, *offset);
            let remaining = work.plan.unwrap().length() - offset;
            let mut bytes = [0u8; DATA_PAGE_SIZE];
            let copied = match driver_launch::copy_completed_irp_output_exact(
                irp.raw(),
                offset as u64,
                &mut bytes[..remaining],
            ) {
                Ok(copied) if copied != 0 && copied <= remaining => copied,
                Ok(_) => {
                    assert!((&mut *core::ptr::addr_of_mut!(READS)).fail_copy(
                        work.read_id.unwrap(),
                        irp.raw(),
                        nt_memory_manager::data_section::STATUS_IO_DEVICE_ERROR
                    ));
                    work.phase = Phase::AckPending(irp);
                    return false;
                }
                Err(status) => {
                    assert!((&mut *core::ptr::addr_of_mut!(READS)).fail_copy(
                        work.read_id.unwrap(),
                        irp.raw(),
                        status
                    ));
                    work.phase = Phase::AckPending(irp);
                    return false;
                }
            };
            if !(&mut *core::ptr::addr_of_mut!(READS)).append(
                work.read_id.unwrap(),
                irp.raw(),
                offset,
                &bytes[..copied],
            ) {
                work.phase = Phase::Indeterminate;
                return false;
            }
            work.phase = if (&*core::ptr::addr_of!(READS))
                .ready_page(work.read_id.unwrap(), irp.raw())
                .is_some()
            {
                Phase::AckPending(irp)
            } else {
                Phase::Copying(irp, offset + copied)
            };
            false
        }
        Phase::AckPending(irp) => {
            let irp = *irp;
            work.phase = Phase::Indeterminate;
            if driver_launch::io_manager_mut()
                .acknowledge_completed_irp_strict(irp)
                .is_err()
            {
                return false;
            }
            assert!((&mut *core::ptr::addr_of_mut!(READS))
                .acknowledge_backend(work.read_id.unwrap(), irp.raw()));
            let (_, result) = (&mut *core::ptr::addr_of_mut!(READS))
                .take_acknowledged(work.read_id.unwrap(), irp.raw())
                .unwrap();
            work.phase = match result {
                Ok(bytes) if !cancelled => Phase::Publish(bytes),
                Err(status) => {
                    work.failure = Some(status);
                    Phase::Cancel
                }
                _ => Phase::Cancel,
            };
            false
        }
        Phase::Publish(_) => {
            if cancelled {
                work.phase = Phase::Cancel;
                return false;
            }
            let Phase::Publish(bytes) = &work.phase else {
                unreachable!()
            };
            let ctx = handler.loop_ctx.unwrap();
            let plan = work.plan.unwrap();
            for (index, page) in bytes.chunks_exact(DATA_PAGE_SIZE).enumerate().take(plan.pages()) {
                if service_sec_image::section_pagein::service_publish_section_frame_from_bytes(
                    ctx.generic_sections,
                    work.section,
                    work.page_index + index as u64,
                    page,
                    hosted_scratch_base_for_pi(work.pi),
                ).is_err() {
                    if index == 0 {
                        work.phase = Phase::Cancel;
                        return false;
                    }
                    break;
                }
            }
            work.phase = Phase::ReadyReply;
            false
        }
        Phase::ReadyReply => {
            if cancelled {
                work.phase = Phase::Cancel;
                return false;
            }
            let ctx = handler.loop_ctx.unwrap();
            match service_generic_section_fault(
                handler,
                ctx.generic_sections,
                work.pi,
                work.page,
                ctx.pml4,
                hosted_scratch_base_for_pi(work.pi),
                work.access,
                false,
                true,
            ) {
                Ok(service_sec_image::GenericSectionFaultResult::Mapped)
                    if valid(handler, work) => {}
                _ => {
                    work.phase = Phase::Cancel;
                    return false;
                }
            }
            if parked_reply::validate_saved(work.reply).is_err() {
                return false;
            }
            work.phase = Phase::ReplyEntered;
            if !client_reply_on(work.reply, 0, 0, 0, 0, 0) {
                return false;
            }
            crate::note_boot_progress(crate::BootProgress::PageMappingPublished);
            work.phase = Phase::ReplySent;
            false
        }
        Phase::ReplyEntered => {
            match spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                work.reply,
            ) {
                Ok(true) => work.phase = Phase::ReplySent,
                _ if cancelled => work.phase = Phase::Cancel,
                _ => {}
            }
            false
        }
        Phase::ReplySent => {
            if parked_reply::retire_sent(work.reply).is_err() {
                return false;
            }
            thread_wait_state_clear_badge_ready(handler, work.badge);
            true
        }
        Phase::Cancel => {
            if let Some(status) = work.failure.filter(|_| !work.failure_logged) {
                print_str(b"[section] routed page-in failed pi=");
                print_u64(work.pi as u64);
                print_str(b" page=0x");
                print_hex((work.page >> 32) as u32);
                print_hex(work.page as u32);
                print_str(b" status=0x");
                print_hex(status);
                print_str(b"; cancelling fault Reply\n");
                work.failure_logged = true;
            }
            if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(work.reply) {
                if !spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(work.reply)
                    && spawn_hosts::shared_ingress::owner::runtime::stop_and_cancel_hosted(
                        work.reply,
                    )
                    .is_err()
                {
                    return false;
                }
            } else if parked_reply::revoke(work.reply).is_err() {
                return false;
            }
            work.phase = Phase::Cancelled;
            false
        }
        Phase::Cancelled => {
            if parked_reply::retype(work.reply).is_err() {
                return false;
            }
            true
        }
        Phase::Indeterminate => false,
    }
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    if next_deadline().is_none_or(|deadline| monotonic_time_100ns() < deadline)
        || ACTIVE.swap(true, Ordering::AcqRel)
    {
        return;
    }
    let _durable = allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    for index in 0..count {
        let Some(mut work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].take() else {
            continue;
        };
        EXECUTING_INDEX.store(index as u64, Ordering::Release);
        EXECUTING_TID.store(work.tid, Ordering::Release);
        EXECUTING_PI.store(work.pi as u64, Ordering::Release);
        let done = service_sec_image::with_section_metadata_context(
            handler,
            work.pi,
            work.tid,
            work.badge,
            0,
            0,
            0,
            false,
            0,
            |handler| advance(handler, &mut work),
        )
        .unwrap_or_else(|| {
            let stopped =
                spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(work.reply)
                    || handler
                        .pm
                        .thread(work.logical.thread().thread_id())
                        .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
                    || handler
                        .pm
                        .process(work.logical.process().pid)
                        .is_some_and(|process| {
                            process.state == nt_process::ProcessState::Terminated
                        });
            if !stopped {
                return false;
            }
            match &work.phase {
                Phase::QueryDispatch | Phase::PlanRead => {
                    work.phase = Phase::Cancel;
                    false
                }
                Phase::Dispatch => {
                    (&mut *core::ptr::addr_of_mut!(READS)).cancel_reserved(work.read_id.unwrap());
                    work.phase = Phase::Cancel;
                    false
                }
                Phase::Publish(_) | Phase::ReadyReply => {
                    work.phase = Phase::Cancel;
                    false
                }
                Phase::QueryPending(_)
                | Phase::QueryCopying(_, _)
                | Phase::QueryAckPending(_)
                | Phase::Pending(_)
                | Phase::Copying(_, _)
                | Phase::AckPending(_)
                | Phase::Cancel
                | Phase::Cancelled
                | Phase::ReplyEntered
                | Phase::ReplySent
                | Phase::Indeterminate => advance(handler, &mut work),
            }
        });
        if !done {
            (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        }
        EXECUTING_TID.store(0, Ordering::Release);
        EXECUTING_PI.store(u64::MAX, Ordering::Release);
        EXECUTING_INDEX.store(u64::MAX, Ordering::Release);
    }
    NEXT.store(
        monotonic_time_100ns().saturating_add(RETRY_DELAY),
        Ordering::Release,
    );
    ACTIVE.store(false, Ordering::Release);
}
