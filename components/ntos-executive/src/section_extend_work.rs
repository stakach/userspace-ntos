//! NtExtendSection (NT5 mm/extsect.c, ReactOS mm/section.c MmExtendSection).
//!
//! The section never shrinks; a request it already covers reports its size. When the file is
//! smaller, MmExtendSection first has the file's own filesystem set its end of file
//! (`FsRtlSetFileSize`: IRP_MJ_SET_INFORMATION FileEndOfFileInformation with
//! IRP_PAGING_IO|IRP_SYNCHRONOUS_PAGING_IO). A routed filesystem may pend that IRP: the caller's
//! Reply is parked at ingress, the IRP is owned through its exact terminal completion and strict
//! acknowledgement, and the section grows only once the file covers it.

use nt_hosted_runtime::CompletionStep;
use super::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_io_manager::{DeviceId, ExternalDispatchResult, FileId, IrpId};
use nt_memory_manager::section_extension::SectionExtension;
use nt_memory_manager::{GenericSectionTable, SectionIdentity};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

const RETRY_DELAY: u64 = 1_000_000;
const SECTION_EXTEND_SIZE: u32 = 0x0010;
const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;
const STATUS_MEDIA_WRITE_PROTECTED: u32 = 0xc000_00a2;
const RESOURCES: u32 = 0xc000_009a;
const INVALID: u32 = nt_fs::STATUS_INVALID_HANDLE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Pending(IrpId),
    Acknowledge { irp: IrpId, status: u32 },
    Ready(u32),
    ReplyEntered,
    ReplySent,
    Cancel,
    RetypeReply,
    /// A foreign terminal cannot say what the file did: everything stays owned.
    Indeterminate,
    Done,
}

struct Extend {
    caller: ProviderLogicalCaller,
    pi: usize,
    target: nt_user_host::process_identity::ProcessIdentity,
    reply: u64,
    section: SectionIdentity,
    route: crate::hosted_routed_section_capture::Route,
    new_size: u64,
    output: u64,
    result_size: u64,
    phase: Phase,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
}

static mut ROWS: Vec<Option<Extend>> = Vec::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);
static NEXT: AtomicU64 = AtomicU64::new(0);
static EXECUTING_TID: AtomicU64 = AtomicU64::new(0);

fn has_rows() -> bool {
    unsafe { (&*core::ptr::addr_of!(ROWS)).iter().any(Option::is_some) }
}

pub(crate) fn next_deadline() -> Option<u64> {
    (ACTIVE.load(Ordering::Acquire) || has_rows())
        .then(|| crate::completion_retry::row_deadline(NEXT.load(Ordering::Acquire)))
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

pub(crate) fn has_thread(tid: u64) -> bool {
    EXECUTING_TID.load(Ordering::Acquire) == tid
        || unsafe {
            (&*core::ptr::addr_of!(ROWS)).iter().flatten()
                .any(|row| row.caller.thread().thread_id() as u64 == tid)
        }
}

pub(crate) fn has_process(pi: usize, preserve_tid: Option<u64>) -> bool {
    unsafe {
        (&*core::ptr::addr_of!(ROWS)).iter().flatten().any(|row| {
            row.pi == pi && preserve_tid != Some(row.caller.thread().thread_id() as u64)
        })
    }
}

unsafe fn table(handler: &ExecNtHandler) -> Result<&'static mut GenericSectionTable, u32> {
    handler.loop_ctx.map(|ctx| &mut *ctx.generic_sections).ok_or(INVALID)
}

/// NtExtendSection(SectionHandle, NewSectionSize). `Ok(true)` parks the caller on its file's
/// pended end-of-file update; `Err(status)` completes the call with `status`, success included.
pub(crate) unsafe fn submit(
    handler: &mut ExecNtHandler,
    args: &[u64],
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
) -> Result<bool, u32> {
    let _durable = allocator::enter_durable();
    let (Some(&handle), Some(&output)) = (args.first(), args.get(1)) else {
        return Err(nt_fs::STATUS_INVALID_PARAMETER);
    };
    let pi = handler.pi;
    let mut captured = [0u8; 8];
    handler.process_memory_read_status(pi, output, &mut captured)?;
    let requested = u64::from_le_bytes(captured);
    let caller = handler.native_handle_caller(nt_syscall::ProcessorMode::UserMode)?;
    let section_handle = handler.pm.lookup_native_section_handle(caller, handle)?;
    if section_handle.granted_access() & SECTION_EXTEND_SIZE == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    if crate::native_image_sections::NativeImageSectionId::from_section_id(
        section_handle.section(),
    ).is_some() {
        return Err(nt_memory_manager::section_extension::STATUS_SECTION_NOT_EXTENDED);
    }
    let table = table(handler)?;
    let index = section_handle.section() as usize;
    let section = table.section_identity(index).ok_or(INVALID)?;
    let backing = table.section(index).ok_or(INVALID)?.backing;
    let (status, size) = match table.plan_section_extension(section, requested) {
        Err(status) => (status, requested),
        Ok(SectionExtension::Unchanged(size)) => (0, size),
        Ok(SectionExtension::Grow { new_size, end_of_file }) => {
            match table.commit_section_extension(section, new_size, end_of_file) {
                Ok(size) => (0, size),
                Err(status) => (status, requested),
            }
        }
        Ok(SectionExtension::ExtendFile { new_size }) => match backing.kind {
            nt_memory_manager::GENERIC_SECTION_BACKING_ROUTED => {
                return extend_routed(handler, section, backing, new_size, output,
                    resume_ip, sp, flags, native_call_transport);
            }
            nt_memory_manager::GENERIC_SECTION_BACKING_OVERLAY => {
                let ctx = handler.loop_ctx.ok_or(INVALID)?;
                match super::service_resize_file_coherent(table, backing.overlay_file_id, new_size, ctx) {
                    0 => match table.commit_section_extension(section, new_size, new_size) {
                        Ok(size) => (0, size),
                        Err(status) => (status, requested),
                    },
                    status => (status, requested),
                }
            }
            // A local disk-image file is read-only media.
            _ => (STATUS_MEDIA_WRITE_PROTECTED, requested),
        },
    };
    // The size is reported even on failure; a faulting output is ignored (extsect.c).
    let _ = handler.process_memory_write_checked(pi, output, &size.to_le_bytes());
    Err(status)
}

unsafe fn extend_routed(
    handler: &mut ExecNtHandler,
    section: SectionIdentity,
    backing: nt_memory_manager::GenericSectionBacking,
    new_size: u64,
    output: u64,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
) -> Result<bool, u32> {
    let route = backing.routed_lease
        .and_then(|lease| crate::hosted_routed_section_capture::route(lease, section))
        .ok_or(INVALID)?;
    let pi = handler.pi;
    let tid = handler.current_tid;
    let badge = handler.current_badge;
    let tcb = handler.hosted_thread_tcb(tid).ok_or(INVALID)?;
    let caller = handler.capture_provider_logical_caller(pi, tid, badge, tcb).ok_or(INVALID)?;
    let target = handler.capture_process_identity(pi).ok_or(INVALID)?;
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    let slot = rows.iter().position(Option::is_none);
    if slot.is_none() && rows.try_reserve(1).is_err() {
        return Err(RESOURCES);
    }
    let park = root_reply_park::RootReplyPark::prepare().ok_or(RESOURCES)?;
    // FsRtlSetFileSize: the end-of-file update the filesystem may pend.
    let result = driver_launch::io_manager_mut().build_and_dispatch_file_size_update(
        nt_types::ClientId(driver_launch::IO_MANAGER_COMPONENT_ID),
        DeviceId(route.device_id),
        FileId(route.file_id),
        tid,
        new_size,
    );
    let irp = match result {
        Ok(ExternalDispatchResult::Pending { irp_id }) => irp_id,
        Ok(ExternalDispatchResult::Completed { status, .. }) => {
            drop(park);
            let (status, size) = commit(handler, section, new_size, status.raw() as u32);
            let _ = handler.process_memory_write_checked(pi, output, &size.to_le_bytes());
            return Err(status);
        }
        // Refused before any canonical IRP was retained.
        Err(status) => {
            drop(park);
            let _ = handler.process_memory_write_checked(pi, output, &new_size.to_le_bytes());
            return Err(status.raw() as u32);
        }
    };
    let row = Extend {
        caller, pi, target,
        reply: REPLY_MAIN_SLOT.load(Ordering::Relaxed),
        section, route, new_size, output, result_size: new_size,
        phase: Phase::Pending(irp),
        resume_ip, sp, flags, native_call_transport,
    };
    match slot { Some(index) => rows[index] = Some(row), None => rows.push(Some(row)) }
    park.commit();
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    print_str(b"[section-extend] parked on routed end-of-file update\n");
    Ok(true)
}

/// The file's terminal end-of-file update: the section grows only when the file covers it.
unsafe fn commit(handler: &ExecNtHandler, section: SectionIdentity, new_size: u64, status: u32) -> (u32, u64) {
    if (status as i32) < 0 {
        return (status, new_size);
    }
    let Ok(table) = table(handler) else { return (INVALID, new_size); };
    match table.commit_section_extension(section, new_size, new_size) {
        Ok(size) => (0, size),
        Err(status) => (status, new_size),
    }
}

unsafe fn advance(handler: &mut ExecNtHandler, row: &mut Extend) {
    let reply = row.reply;
    let cancelled = spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(reply)
        || handler.pm.thread(row.caller.thread().thread_id())
            .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
        || handler.pm.process(row.caller.process().pid)
            .is_some_and(|process| process.state == nt_process::ProcessState::Terminated)
        || !handler.validate_provider_logical_caller(row.caller)
        || handler.capture_process_identity(row.pi) != Some(row.target);
    match row.phase {
        Phase::Pending(irp) => {
            // The IRP's effect on the file is owned to its terminal even for a cancelled caller.
            let Some(completion) = driver_launch::completed_irp_exact(irp.raw()) else { return; };
            row.phase = if completion.client_id != driver_launch::IO_MANAGER_COMPONENT_ID
                || completion.file_id != row.route.file_id
                || completion.device_id != row.route.device_id
                || completion.major != nt_io_abi::major::IRP_MJ_SET_INFORMATION
            {
                Phase::Indeterminate
            } else {
                Phase::Acknowledge { irp, status: completion.status }
            };
        }
        Phase::Acknowledge { irp, status } => {
            // A refused or still-running ACK keeps the IRP owned; retry it.
            if !matches!(crate::completion_retry::step_status(
                driver_launch::io_manager_mut().acknowledge_completed_irp_strict(irp)),
                CompletionStep::Done(_))
            {
                return;
            }
            let (status, size) = commit(handler, row.section, row.new_size, status);
            row.result_size = size;
            row.phase = Phase::Ready(status);
        }
        Phase::Ready(status) => {
            if cancelled { row.phase = Phase::Cancel; return; }
            if parked_reply::validate_saved(reply).is_err() { return; }
            let _ = handler.process_memory_write_checked(row.pi, row.output, &row.result_size.to_le_bytes());
            row.phase = Phase::ReplyEntered;
            if reply_parked_syscall(reply, u64::from(status)) {
                row.phase = Phase::ReplySent;
            }
        }
        Phase::ReplyEntered => {
            match spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(reply) {
                Ok(true) => row.phase = Phase::ReplySent,
                _ if cancelled => row.phase = Phase::Cancel,
                _ => {}
            }
        }
        Phase::ReplySent => {
            if parked_reply::retire_sent(reply).is_ok() {
                thread_wait_state_clear_badge_ready(handler, row.caller.badge());
                row.phase = Phase::Done;
            }
        }
        Phase::Cancel => {
            if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(reply) {
                if !spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(reply)
                    && spawn_hosts::shared_ingress::owner::runtime::stop_and_cancel_hosted(reply).is_err()
                {
                    return;
                }
            } else if parked_reply::revoke(reply).is_err() {
                return;
            }
            row.phase = Phase::RetypeReply;
        }
        Phase::RetypeReply => {
            if parked_reply::retype(reply).is_ok() { row.phase = Phase::Done; }
        }
        Phase::Indeterminate | Phase::Done => {}
    }
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    if next_deadline().is_none_or(|deadline| monotonic_time_100ns() < deadline)
        || ACTIVE.swap(true, Ordering::AcqRel)
    {
        return;
    }
    let _durable = allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(ROWS)).len();
    for index in 0..count {
        let Some(mut row) = (&mut *core::ptr::addr_of_mut!(ROWS))[index].take() else { continue; };
        EXECUTING_TID.store(row.caller.thread().thread_id() as u64, Ordering::Release);
        let caller = row.caller;
        let ran = crate::service_sec_image::with_pagein_caller_target_context(
            handler, caller.pi(), row.pi, caller.thread().thread_id() as u64, caller.badge(),
            row.resume_ip, row.sp, row.flags, row.native_call_transport, SSN_NT_EXTEND_SECTION as u32,
            |handler| {
                for _ in 0..4 {
                    let before = row.phase;
                    advance(handler, &mut row);
                    if row.phase == before { break; }
                }
            },
        );
        if ran.is_none() {
            // The file's update stays owned to its terminal without the caller's context, which
            // only the output and Reply need; that Reply can then only be cancelled.
            for _ in 0..4 {
                if matches!(row.phase, Phase::Ready(_)) {
                    row.phase = Phase::Cancel;
                }
                if !matches!(row.phase, Phase::Pending(_) | Phase::Acknowledge { .. }
                    | Phase::Cancel | Phase::RetypeReply)
                {
                    break;
                }
                let before = row.phase;
                advance(handler, &mut row);
                if row.phase == before { break; }
            }
        }
        if row.phase != Phase::Done {
            (&mut *core::ptr::addr_of_mut!(ROWS))[index] = Some(row);
        }
        EXECUTING_TID.store(0, Ordering::Release);
    }
    NEXT.store(monotonic_time_100ns().saturating_add(RETRY_DELAY), Ordering::Release);
    ACTIVE.store(false, Ordering::Release);
}
