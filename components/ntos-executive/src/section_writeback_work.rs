//! Retained paging writes of routed Section pages through their own filesystem.
//!
//! NT writes a mapped file's modified pages with paging IRPs to the file's driver: a view flush
//! and a cache flush through `MmFlushSection` and `IoSynchronousPageWrite` (NT5 flushsec.c),
//! section deletion through `MiCleanSection` (sectsup.c), and unmapped modified pages through the
//! mapped page writer's `IoAsynchronousPageWrite` (modwrite.c). A routed driver may pend any of
//! them. Each write owns its dirty page and frame from dispatch until the exact terminal
//! completion and strict acknowledgement; a failure leaves the page dirty, and an uncertain
//! effect quarantines it, so a write is never replayed.
//!
//! A flushing caller's Reply is parked here at syscall ingress, before any write effect, and is
//! answered only after every page it started has settled.

use super::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_io_manager::irp_request_flags::PagingTransfer;
use nt_io_manager::{DeviceId, ExternalDispatchResult, FileId, IrpId};
use nt_memory_manager::writeback::{PageWriteOutcome, PageWriteRefusal, PageWriteState, SectionPageWrite};
use nt_memory_manager::{GenericSectionFlushPlan, GenericSectionTable, SectionIdentity};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

const RETRY_DELAY: u64 = 1_000_000;
const RESOURCES: u32 = 0xc000_009a;
const INVALID: u32 = nt_fs::STATUS_INVALID_HANDLE;
const STATUS_UNSUCCESSFUL: u32 = 0xc000_0001;
const STATUS_IO_DEVICE_ERROR: u32 = nt_memory_manager::data_section::STATUS_IO_DEVICE_ERROR;
/// Bounded local work per service turn; a pended write stops nothing else.
const SCAN_BUDGET: usize = 16;

enum WritePhase {
    Dispatch,
    Pending(IrpId),
    /// Terminal and validated; the outcome settles only after the strict acknowledgement.
    Acknowledge { irp: IrpId, outcome: PageWriteOutcome },
    Settled(PageWriteOutcome),
}

struct PageWrite {
    write: SectionPageWrite,
    transfer: PagingTransfer,
    flush: Option<u64>,
    route: Option<crate::hosted_routed_section_capture::Route>,
    phase: WritePhase,
}

#[derive(Clone, Copy)]
enum Scope {
    View(GenericSectionFlushPlan),
    /// Every section mapping the routed stream, named by its device and FCB (`FsContext`): the
    /// stream NT's `SectionObjectPointers` belong to.
    Stream { device_id: u64, fs_context: u64 },
}

enum Finish {
    VmFlush(nt_address_space::native_output::VmFlushOutput),
    /// The cache flush continues with its own FLUSH_BUFFERS once the pages are durable.
    Reissue { retry: nt_syscall_abi::SyscallRetryReply, iosb: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlushPhase { Scan, Waiting, Ready(u32), ReplyEntered, ReplySent, Cancel, RetypeReply, Done }

struct Flush {
    token: u64,
    caller: ProviderLogicalCaller,
    target_pi: usize,
    target: nt_user_host::process_identity::ProcessIdentity,
    reply: u64,
    scope: Scope,
    finish: Finish,
    /// Versions dirtied after this flush began are not its obligation.
    start_epoch: u64,
    outstanding: usize,
    failure: Option<u32>,
    bytes_written: u64,
    phase: FlushPhase,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
    service: u32,
}

static mut WRITES: Vec<Option<PageWrite>> = Vec::new();
static mut FLUSHES: Vec<Option<Flush>> = Vec::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);
static SCAN: AtomicBool = AtomicBool::new(false);
static NEXT: AtomicU64 = AtomicU64::new(0);
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static EXECUTING_TID: AtomicU64 = AtomicU64::new(0);
static EXECUTING_PI: AtomicU64 = AtomicU64::new(u64::MAX);
static WRITES_SETTLED: AtomicU64 = AtomicU64::new(0);
static WRITES_FAILED: AtomicU64 = AtomicU64::new(0);
static WRITES_UNCERTAIN: AtomicU64 = AtomicU64::new(0);

/// A routed page became dirty; once unmapped it is the page writer's work.
pub(crate) fn request_scan() {
    if !SCAN.swap(true, Ordering::AcqRel) {
        NEXT.store(monotonic_time_100ns(), Ordering::Release);
    }
}

pub(crate) fn next_deadline() -> Option<u64> {
    (ACTIVE.load(Ordering::Acquire)
        || SCAN.load(Ordering::Acquire)
        || unsafe {
            (&*core::ptr::addr_of!(WRITES)).iter().any(Option::is_some)
                || (&*core::ptr::addr_of!(FLUSHES)).iter().any(Option::is_some)
        })
    .then(|| NEXT.load(Ordering::Acquire))
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

pub(crate) fn has_thread(tid: u64) -> bool {
    EXECUTING_TID.load(Ordering::Acquire) == tid
        || unsafe {
            (&*core::ptr::addr_of!(FLUSHES)).iter().flatten()
                .any(|flush| flush.caller.thread().thread_id() as u64 == tid)
        }
}

pub(crate) fn has_process(pi: usize, preserve_tid: Option<u64>) -> bool {
    (EXECUTING_PI.load(Ordering::Acquire) == pi as u64
        && preserve_tid != Some(EXECUTING_TID.load(Ordering::Acquire)))
        || unsafe {
            (&*core::ptr::addr_of!(FLUSHES)).iter().flatten().any(|flush| {
                (flush.target_pi == pi || flush.caller.pi() == pi)
                    && preserve_tid != Some(flush.caller.thread().thread_id() as u64)
            })
        }
}

fn fresh_token() -> Option<u64> {
    NEXT_TOKEN
        .try_update(Ordering::AcqRel, Ordering::Acquire, |value| value.checked_add(1))
        .ok()
        .filter(|value| *value != 0)
}

unsafe fn table(handler: &ExecNtHandler) -> Option<&'static mut GenericSectionTable> {
    handler.loop_ctx.map(|ctx| &mut *ctx.generic_sections)
}

/// Whether any page in scope still owes this flush a write.
fn scope_tickets(
    table: &GenericSectionTable,
    scope: Scope,
) -> Result<Vec<(SectionIdentity, nt_memory_manager::writeback::SectionWritebackPage)>, u32> {
    let mut tickets = Vec::new();
    match scope {
        Scope::View(plan) => {
            let via = table
                .section_identity(plan.view.section_index)
                .ok_or(nt_memory_manager::STATUS_NOT_MAPPED_VIEW)?;
            for ticket in table.prepare_writeback(plan)? {
                tickets.try_reserve(1).map_err(|_| RESOURCES)?;
                tickets.push((via, ticket));
            }
        }
        Scope::Stream { device_id, fs_context } => {
            for (section, lease) in table.retained_routed_sections() {
                let matches = unsafe { crate::hosted_routed_section_capture::route(lease, section) }
                    .is_some_and(|route| route.device_id == device_id && route.fs_context == fs_context);
                if !matches {
                    continue;
                }
                for ticket in table.prepare_section_writeback(section)? {
                    tickets.try_reserve(1).map_err(|_| RESOURCES)?;
                    tickets.push((section, ticket));
                }
            }
        }
    }
    Ok(tickets)
}

unsafe fn park(
    handler: &mut ExecNtHandler,
    target_pi: usize,
    scope: Scope,
    finish: Finish,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
    service: u32,
) -> Result<(), u32> {
    let table = table(handler).ok_or(INVALID)?;
    let caller_pi = handler.pi;
    let tid = handler.current_tid;
    let badge = handler.current_badge;
    let tcb = handler.hosted_thread_tcb(tid).ok_or(INVALID)?;
    let caller = handler.capture_provider_logical_caller(caller_pi, tid, badge, tcb).ok_or(INVALID)?;
    let target = handler.capture_process_identity(target_pi).ok_or(INVALID)?;
    let token = fresh_token().ok_or(RESOURCES)?;
    let rows = &mut *core::ptr::addr_of_mut!(FLUSHES);
    let index = rows.iter().position(Option::is_none);
    if index.is_none() && rows.try_reserve(1).is_err() {
        return Err(RESOURCES);
    }
    let park = root_reply_park::RootReplyPark::prepare().ok_or(RESOURCES)?;
    let flush = Flush {
        token, caller, target_pi, target,
        reply: REPLY_MAIN_SLOT.load(Ordering::Relaxed),
        scope, finish,
        start_epoch: table.dirty_epoch(),
        outstanding: 0, failure: None, bytes_written: 0,
        phase: FlushPhase::Scan,
        resume_ip, sp, flags, native_call_transport, service,
    };
    match index { Some(index) => rows[index] = Some(flush), None => rows.push(Some(flush)) }
    park.commit();
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    Ok(())
}

/// Syscall ingress for NtFlushVirtualMemory: a routed view with dirty pages parks the caller on
/// retained paging writes. `Ok(false)` leaves every other request to the ordinary service.
pub(crate) unsafe fn submit_vm_flush(
    handler: &mut ExecNtHandler,
    args: &[u64],
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
) -> Result<bool, u32> {
    let _durable = allocator::enter_durable();
    let Ok(crate::exec_handler::VmFlushRequest::Planned { output, target_pi, plan }) =
        handler.capture_vm_flush(args)
    else {
        return Ok(false);
    };
    if plan.section.backing.kind != nt_memory_manager::GENERIC_SECTION_BACKING_ROUTED {
        return Ok(false);
    }
    let table = table(handler).ok_or(INVALID)?;
    if scope_tickets(table, Scope::View(plan)).map_or(true, |tickets| tickets.is_empty()) {
        return Ok(false);
    }
    park(handler, target_pi, Scope::View(plan), Finish::VmFlush(output),
        resume_ip, sp, flags, native_call_transport, SSN_NT_FLUSH_VM as u32)?;
    print_str(b"[section-writeback] vm-flush parked pages=routed\n");
    Ok(true)
}

/// Syscall ingress for NtFlushBuffersFile on a routed File: the Section pages of its stream are
/// written first (CcFlushCache -> MmFlushSection), then the call is reissued to send the
/// filesystem its FLUSH_BUFFERS.
pub(crate) unsafe fn submit_cache_flush(
    handler: &mut ExecNtHandler,
    args: &[u64],
    retry: Option<nt_syscall_abi::SyscallRetryReply>,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
) -> Result<bool, u32> {
    let _durable = allocator::enter_durable();
    let (Some(&handle), Some(&iosb)) = (args.first(), args.get(1)) else {
        return Ok(false);
    };
    let Some((device_id, fs_context)) = handler.routed_flush_stream(handle) else {
        return Ok(false);
    };
    let scope = Scope::Stream { device_id, fs_context };
    let table = table(handler).ok_or(INVALID)?;
    if scope_tickets(table, scope).map_or(true, |tickets| tickets.is_empty()) {
        return Ok(false);
    }
    // Without a reissue envelope the caller could not continue to its FLUSH_BUFFERS.
    let retry = retry.ok_or(0xc000_0005u32)?;
    let pi = handler.pi;
    park(handler, pi, scope, Finish::Reissue { retry, iosb },
        resume_ip, sp, flags, native_call_transport, SSN_NT_FLUSH_BUFFERS_FILE as u32)?;
    print_str(b"[section-writeback] cache-flush parked\n");
    Ok(true)
}

fn begin_write(
    table: &mut GenericSectionTable,
    via: SectionIdentity,
    ticket: nt_memory_manager::writeback::SectionWritebackPage,
    transfer: PagingTransfer,
    flush: Option<u64>,
) -> Result<(), PageWriteRefusal> {
    let rows = unsafe { &mut *core::ptr::addr_of_mut!(WRITES) };
    let index = rows.iter().position(Option::is_none);
    if index.is_none() && rows.try_reserve(1).is_err() {
        return Err(PageWriteRefusal::Exhausted);
    }
    let write = table.begin_page_write(via, ticket)?;
    let job = PageWrite { write, transfer, flush, route: None, phase: WritePhase::Dispatch };
    match index { Some(index) => rows[index] = Some(job), None => rows.push(Some(job)) }
    Ok(())
}

/// NT_SUCCESS and exactly the ticket's bytes, or the definite failure the driver reported.
fn terminal_outcome(status: u32, information: u64, length: usize) -> PageWriteOutcome {
    if (status as i32) < 0 {
        PageWriteOutcome::Failed(status)
    } else if information == length as u64 {
        PageWriteOutcome::Written
    } else if information > length as u64 {
        PageWriteOutcome::Failed(STATUS_IO_DEVICE_ERROR)
    } else {
        PageWriteOutcome::Failed(STATUS_UNSUCCESSFUL)
    }
}

/// Advance one write. Returns true once it settled and its row can be released.
unsafe fn advance_write(handler: &ExecNtHandler, table: &mut GenericSectionTable, job: &mut PageWrite) -> bool {
    let ticket = job.write.ticket();
    match job.phase {
        WritePhase::Dispatch => {
            let Some(route) = table.routed_lease_exact(job.write.via())
                .and_then(|lease| crate::hosted_routed_section_capture::route(lease, job.write.via()))
            else {
                job.phase = WritePhase::Settled(PageWriteOutcome::Failed(INVALID));
                return false;
            };
            // Write-protect every alias before the copy so a later store dirties a new version.
            let aliases = match table.page_write_aliases(job.write) {
                Ok(aliases) => aliases,
                Err(status) => {
                    job.phase = WritePhase::Settled(PageWriteOutcome::Failed(status));
                    return false;
                }
            };
            for alias in aliases {
                if let Err(status) = super::section_writeback::rearm_section_alias(alias, handler.loop_ctx) {
                    job.phase = WritePhase::Settled(PageWriteOutcome::Failed(status));
                    return false;
                }
            }
            let mut bytes = Vec::new();
            if bytes.try_reserve_exact(ticket.length).is_err() {
                job.phase = WritePhase::Settled(PageWriteOutcome::Failed(RESOURCES));
                return false;
            }
            bytes.resize(ticket.length, 0);
            let Some(scratch) = handler.loop_ctx.map(|ctx| ctx.scratch_base) else {
                job.phase = WritePhase::Settled(PageWriteOutcome::Failed(INVALID));
                return false;
            };
            let (copy_status, copied) = super::section_scratch::with_section_frame(ticket.frame, scratch, |address| {
                bytes.copy_from_slice(core::slice::from_raw_parts(address as *const u8, ticket.length));
                (0, ticket.length)
            });
            if copy_status != 0 || copied != ticket.length {
                job.phase = WritePhase::Settled(PageWriteOutcome::Failed(
                    if copy_status != 0 { copy_status } else { STATUS_IO_DEVICE_ERROR }));
                return false;
            }
            job.route = Some(route);
            // IoSynchronousPageWrite / IoAsynchronousPageWrite: IRP_PAGING_IO|IRP_NOCACHE.
            let result = driver_launch::io_manager_mut().build_and_dispatch_paging_to_device(
                nt_types::ClientId(driver_launch::IO_MANAGER_COMPONENT_ID),
                DeviceId(route.device_id),
                FileId(route.file_id),
                0,
                job.transfer,
                ticket.file_offset,
                &mut bytes,
            );
            job.phase = match result {
                Ok(ExternalDispatchResult::Completed { status, information, .. }) => {
                    WritePhase::Settled(terminal_outcome(status.raw() as u32, information, ticket.length))
                }
                Ok(ExternalDispatchResult::Pending { irp_id }) => WritePhase::Pending(irp_id),
                // Refused before any canonical IRP was retained: a definite failure.
                Err(status) => WritePhase::Settled(PageWriteOutcome::Failed(status.raw() as u32)),
            };
            false
        }
        WritePhase::Pending(irp) => {
            let Some(completion) = driver_launch::completed_irp_exact(irp.raw()) else {
                return false;
            };
            let route = job.route.expect("dispatched write retains its route");
            job.phase = if completion.client_id != driver_launch::IO_MANAGER_COMPONENT_ID
                || completion.file_id != route.file_id
                || completion.device_id != route.device_id
                || completion.major != nt_io_abi::major::IRP_MJ_WRITE
            {
                // A foreign terminal cannot say what this write did.
                WritePhase::Settled(PageWriteOutcome::Uncertain)
            } else {
                WritePhase::Acknowledge {
                    irp,
                    outcome: terminal_outcome(completion.status, completion.information, ticket.length),
                }
            };
            false
        }
        WritePhase::Acknowledge { irp, outcome } => {
            // The page stays owned until the canonical completion is released; retry on refusal.
            if driver_launch::io_manager_mut().acknowledge_completed_irp_strict(irp).is_ok() {
                job.phase = WritePhase::Settled(outcome);
            }
            false
        }
        WritePhase::Settled(outcome) => {
            if !table.finish_page_write(job.write, outcome) {
                print_str(b"[section-writeback] settlement lost its page owner\n");
            }
            WRITES_SETTLED.fetch_add(1, Ordering::Relaxed);
            match outcome {
                PageWriteOutcome::Written => {}
                PageWriteOutcome::Failed(status) => {
                    WRITES_FAILED.fetch_add(1, Ordering::Relaxed);
                    print_str(b"[section-writeback] page write failed status=0x");
                    print_hex(status);
                    print_str(b" offset=0x");
                    print_hex_u64(ticket.file_offset);
                    print_str(b"\n");
                    request_scan();
                }
                PageWriteOutcome::Uncertain => {
                    WRITES_UNCERTAIN.fetch_add(1, Ordering::Relaxed);
                    print_str(b"[section-writeback] page write uncertain; page quarantined\n");
                }
            }
            if let Some(token) = job.flush {
                flush_page_settled(token, outcome, ticket.length);
            }
            true
        }
    }
}

unsafe fn flush_page_settled(token: u64, outcome: PageWriteOutcome, length: usize) {
    let Some(flush) = (&mut *core::ptr::addr_of_mut!(FLUSHES)).iter_mut().flatten()
        .find(|flush| flush.token == token)
    else {
        return;
    };
    flush.outstanding = flush.outstanding.saturating_sub(1);
    match outcome {
        PageWriteOutcome::Written => flush.bytes_written = flush.bytes_written.saturating_add(length as u64),
        PageWriteOutcome::Failed(status) => { flush.failure.get_or_insert(status); }
        PageWriteOutcome::Uncertain => { flush.failure.get_or_insert(STATUS_IO_DEVICE_ERROR); }
    }
}

/// MmFlushSection over the flush's scope: start a write for every version dirtied before the
/// flush began; wait for writes another owner started.
unsafe fn scan_flush(table: &mut GenericSectionTable, flush: &mut Flush) {
    let tickets = match scope_tickets(table, flush.scope) {
        Ok(tickets) => tickets,
        Err(status) => {
            flush.failure.get_or_insert(status);
            flush.phase = if flush.outstanding == 0 {
                FlushPhase::Ready(status)
            } else {
                FlushPhase::Waiting
            };
            return;
        }
    };
    let mut waiting = false;
    for (via, ticket) in tickets {
        if ticket.dirty_epoch() > flush.start_epoch || flush.failure.is_some() {
            continue;
        }
        match table.page_write_state(ticket) {
            Some(PageWriteState::Idle) => {
                match begin_write(table, via, ticket, PagingTransfer::SynchronousWrite, Some(flush.token)) {
                    Ok(()) => flush.outstanding += 1,
                    Err(PageWriteRefusal::Uncertain) => { flush.failure = Some(STATUS_IO_DEVICE_ERROR); }
                    Err(PageWriteRefusal::Exhausted) => { flush.failure = Some(RESOURCES); }
                    Err(PageWriteRefusal::InFlight | PageWriteRefusal::Stale) => waiting = true,
                }
            }
            Some(PageWriteState::InFlight) => waiting = true,
            Some(PageWriteState::Uncertain) => flush.failure = Some(STATUS_IO_DEVICE_ERROR),
            None => {}
        }
    }
    flush.phase = match (flush.outstanding, waiting, flush.failure) {
        (0, false, failure) => FlushPhase::Ready(failure.unwrap_or(0)),
        (0, true, Some(failure)) => FlushPhase::Ready(failure),
        _ => FlushPhase::Waiting,
    };
}

unsafe fn advance_flush(handler: &mut ExecNtHandler, table: &mut GenericSectionTable, flush: &mut Flush) {
    let reply = flush.reply;
    let cancelled = spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(reply)
        || handler.pm.thread(flush.caller.thread().thread_id())
            .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
        || handler.pm.process(flush.caller.process().pid)
            .is_some_and(|process| process.state == nt_process::ProcessState::Terminated)
        || !handler.validate_provider_logical_caller(flush.caller)
        || handler.capture_process_identity(flush.target_pi) != Some(flush.target);
    match flush.phase {
        FlushPhase::Scan => {
            if cancelled && flush.outstanding == 0 { flush.phase = FlushPhase::Cancel; return; }
            scan_flush(table, flush);
        }
        FlushPhase::Waiting => {
            // Started writes settle independently of the caller; never replay them.
            if flush.outstanding != 0 { return; }
            if cancelled { flush.phase = FlushPhase::Cancel; return; }
            flush.phase = match flush.failure {
                Some(status) => FlushPhase::Ready(status),
                None => FlushPhase::Scan,
            };
        }
        FlushPhase::Ready(status) => {
            if cancelled { flush.phase = FlushPhase::Cancel; return; }
            if parked_reply::validate_saved(reply).is_err() { return; }
            flush.phase = FlushPhase::ReplyEntered;
            let sent = match &flush.finish {
                Finish::VmFlush(output) => {
                    let Scope::View(plan) = flush.scope else { unreachable!() };
                    let status = handler.publish_vm_flush(*output, plan.base, plan.size, status,
                        flush.bytes_written);
                    reply_parked_syscall(reply, u64::from(status))
                }
                Finish::Reissue { retry, .. } if status == 0 => reply_parked_syscall_retry(reply, retry),
                Finish::Reissue { iosb, .. } => {
                    handler.write_current_iosb(*iosb, status, 0);
                    reply_parked_syscall(reply, u64::from(status))
                }
            };
            if sent {
                flush.phase = FlushPhase::ReplySent;
            }
        }
        FlushPhase::ReplyEntered => {
            match spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(reply) {
                Ok(true) => flush.phase = FlushPhase::ReplySent,
                _ if cancelled => flush.phase = FlushPhase::Cancel,
                _ => {}
            }
        }
        FlushPhase::ReplySent => {
            if parked_reply::retire_sent(reply).is_ok() {
                thread_wait_state_clear_badge_ready(handler, flush.caller.badge());
                flush.phase = FlushPhase::Done;
            }
        }
        FlushPhase::Cancel => {
            if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(reply) {
                if !spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(reply)
                    && spawn_hosts::shared_ingress::owner::runtime::stop_and_cancel_hosted(reply).is_err()
                {
                    return;
                }
            } else if parked_reply::revoke(reply).is_err() {
                return;
            }
            flush.phase = FlushPhase::RetypeReply;
        }
        FlushPhase::RetypeReply => {
            if parked_reply::retype(reply).is_ok() { flush.phase = FlushPhase::Done; }
        }
        FlushPhase::Done => {}
    }
}

/// The mapped page writer and MiCleanSection: write modified pages no view maps any longer.
unsafe fn scan_unmapped(table: &mut GenericSectionTable) {
    for _ in 0..SCAN_BUDGET {
        let Some(next) = table.next_unmapped_page_write() else { break; };
        let transfer = if next.released {
            PagingTransfer::SynchronousWrite
        } else {
            PagingTransfer::AsynchronousWrite
        };
        if begin_write(table, next.via, next.ticket, transfer, None).is_err() {
            break;
        }
    }
    if !table.has_async_dirty_pages() {
        SCAN.store(false, Ordering::Release);
    }
}

unsafe fn drive_flushes(handler: &mut ExecNtHandler, table: &mut GenericSectionTable) {
    let flushes = (&*core::ptr::addr_of!(FLUSHES)).len();
    for index in 0..flushes {
        let Some(mut flush) = (&mut *core::ptr::addr_of_mut!(FLUSHES))[index].take() else { continue; };
        EXECUTING_TID.store(flush.caller.thread().thread_id() as u64, Ordering::Release);
        EXECUTING_PI.store(flush.caller.pi() as u64, Ordering::Release);
        let caller = flush.caller;
        let done = crate::service_sec_image::with_pagein_caller_target_context(
            handler, caller.pi(), flush.target_pi, caller.thread().thread_id() as u64,
            caller.badge(), flush.resume_ip, flush.sp, flush.flags, flush.native_call_transport,
            flush.service, |handler| {
                for _ in 0..4 {
                    let before = flush.phase;
                    advance_flush(handler, table, &mut flush);
                    if flush.phase == before || flush.phase == FlushPhase::Waiting { break; }
                }
            },
        );
        if done.is_none() && flush.outstanding == 0
            && !matches!(flush.phase, FlushPhase::ReplyEntered | FlushPhase::ReplySent
                | FlushPhase::Cancel | FlushPhase::RetypeReply | FlushPhase::Done)
        {
            // The caller's memory context is gone: its Reply can only be cancelled.
            flush.phase = FlushPhase::Cancel;
        }
        if flush.phase != FlushPhase::Done {
            (&mut *core::ptr::addr_of_mut!(FLUSHES))[index] = Some(flush);
        }
        EXECUTING_TID.store(0, Ordering::Release);
        EXECUTING_PI.store(u64::MAX, Ordering::Release);
    }
}

unsafe fn drive_writes(handler: &ExecNtHandler, table: &mut GenericSectionTable) {
    let writes = (&*core::ptr::addr_of!(WRITES)).len();
    for index in 0..writes {
        let Some(mut job) = (&mut *core::ptr::addr_of_mut!(WRITES))[index].take() else { continue; };
        let mut settled = false;
        for _ in 0..4 {
            settled = advance_write(handler, table, &mut job);
            if settled || matches!(job.phase, WritePhase::Pending(_) | WritePhase::Acknowledge { .. }) {
                break;
            }
        }
        if !settled {
            (&mut *core::ptr::addr_of_mut!(WRITES))[index] = Some(job);
        }
    }
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    if next_deadline().is_none_or(|deadline| monotonic_time_100ns() < deadline)
        || ACTIVE.swap(true, Ordering::AcqRel)
    {
        return;
    }
    let _durable = allocator::enter_durable();
    if let Some(table) = table(handler) {
        // A flush starts its writes, inline completions settle them, and the flush answers in
        // the same turn; a pended write is observed again at the retry deadline.
        drive_flushes(handler, table);
        if SCAN.load(Ordering::Acquire) {
            scan_unmapped(table);
        }
        drive_writes(handler, table);
        drive_flushes(handler, table);
    }
    NEXT.store(monotonic_time_100ns().saturating_add(RETRY_DELAY), Ordering::Release);
    ACTIVE.store(false, Ordering::Release);
}
