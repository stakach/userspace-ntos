//! Retained native File opens across Object Manager channel contention.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_object_client::{FileTargetOwnedOutcome, FileTargetOwnedTerminal, PendingFileTargetCall};
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

use crate::exec_handler::{CapturedFileObjectAttributes, FileParseRoot};
use crate::*;

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const RETRY_100NS: u64 = 1_000_000;
const MAX_PENDING: usize = 64;

#[derive(Copy, Clone)]
pub(crate) enum Kind { Open, Create }

enum Phase {
    Lookup,
    Submitted(PendingFileTargetCall),
    Resolved(Result<(u64, Vec<u16>), u32>),
    ReplyReady(u32),
    ReplyIndeterminate,
    Quarantined,
    Done,
}

/// The name, EA, output addresses, process identity and Reply are captured once at ingress.
/// Neither a busy Object Manager channel nor a later user-memory edit can change this request.
pub(crate) struct PendingNativeFileTargetOpen {
    kind: Kind,
    args: Vec<u64>,
    captured: CapturedFileObjectAttributes,
    name: Vec<u16>,
    ea: Vec<u8>,
    reference: NativeThreadProcessReference,
    caller: NativeHandleCaller,
    pi: usize,
    tid: u64,
    badge: u64,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
    service_number: u32,
    reply: u64,
    abandoned: bool,
    phase: Phase,
}

static mut PENDING: Vec<PendingNativeFileTargetOpen> = Vec::new();
static mut SELECTED: *mut PendingNativeFileTargetOpen = core::ptr::null_mut();
static ACTIVE: AtomicBool = AtomicBool::new(false);
static NEXT_RETRY: AtomicU64 = AtomicU64::new(0);
static CURSOR: AtomicU64 = AtomicU64::new(0);

pub(crate) fn occupied() -> bool {
    ACTIVE.load(Ordering::Acquire)
        || unsafe { !(&*core::ptr::addr_of!(PENDING)).is_empty() }
}

pub(crate) unsafe fn capture(
    handler: &mut ExecNtHandler,
    kind: Kind,
    args: &[u64],
    captured: CapturedFileObjectAttributes,
    name: &[u16],
    ea: Vec<u8>,
) -> Result<(), u32> {
    assert!(handler.pending_native_file_target_transfer.is_none());
    let caller = handler.native_handle_caller(nt_syscall::ProcessorMode::KernelMode)?;
    let reference = handler.pm.reference_native_requestor(caller)?;
    let mut owned_args = Vec::new();
    let mut owned_name = Vec::new();
    if owned_args.try_reserve_exact(args.len()).is_err()
        || owned_name.try_reserve_exact(name.len()).is_err()
    {
        let mut reference = reference;
        reference.release(&mut handler.pm)
            .expect("unsubmitted file lookup retained its requestor reference");
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    owned_args.extend_from_slice(args);
    owned_name.extend_from_slice(name);
    handler.pending_native_file_target_transfer = Some(PendingNativeFileTargetOpen {
        kind, args: owned_args, captured, name: owned_name, ea, reference, caller,
        pi: handler.pi, tid: handler.current_tid, badge: handler.current_badge,
        resume_ip: handler.current_resume_ip, sp: handler.current_sp,
        flags: handler.current_flags, native_call_transport: handler.current_native_call_transport,
        service_number: handler.current_service_number, reply: 0, abandoned: false,
        phase: Phase::Lookup,
    });
    Ok(())
}

pub(crate) unsafe fn park(
    handler: &mut ExecNtHandler,
    mut work: PendingNativeFileTargetOpen,
) -> Result<(), u32> {
    let _durable = allocator::enter_durable();
    let queue = &mut *core::ptr::addr_of_mut!(PENDING);
    if queue.len() >= MAX_PENDING || queue.try_reserve(1).is_err() {
        work.reference.release(&mut handler.pm)
            .expect("unsubmitted file lookup retained its requestor reference");
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else {
        work.reference.release(&mut handler.pm)
            .expect("unsubmitted file lookup retained its requestor reference");
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    };
    work.reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(work.reply, 0);
    let badge = work.badge;
    queue.push(work);
    reply_park.commit();
    thread_wait_state_park_badge_waiting(handler, badge);
    NEXT_RETRY.store(monotonic_time_100ns(), Ordering::Release);
    crate::service_sec_image::rearm_registered_active_delay_timer();
    Ok(())
}

pub(crate) unsafe fn abandon_thread(tid: u64) {
    let selected = *core::ptr::addr_of!(SELECTED);
    if !selected.is_null() && (*selected).tid == tid {
        abandon_one(&mut *selected);
    }
    for work in (&mut *core::ptr::addr_of_mut!(PENDING)).iter_mut().filter(|work| work.tid == tid) {
        abandon_one(work);
    }
    NEXT_RETRY.store(monotonic_time_100ns(), Ordering::Release);
}

unsafe fn abandon_one(work: &mut PendingNativeFileTargetOpen) {
    work.abandoned = true;
    if work.reply != 0 && cancel_parked_reply_transport(work.reply) {
        release_reply_pool_cap(work.reply);
        work.reply = 0;
    }
}

unsafe fn terminal(
    terminal: FileTargetOwnedTerminal,
) -> Phase {
    match terminal {
        FileTargetOwnedTerminal::Success(target) => Phase::Resolved(
            crate::driver_launch::registered_device_for_file_target(target)),
        FileTargetOwnedTerminal::Failure(status) => Phase::Resolved(Err(status.raw() as u32)),
        FileTargetOwnedTerminal::Incoherent(_) => Phase::Quarantined,
    }
}

unsafe fn poll_file_target_owned(
    pending: &PendingFileTargetCall,
) -> Option<FileTargetOwnedTerminal> {
    object_manager_poll_file_target_async(pending)
}

unsafe fn step(handler: &mut ExecNtHandler, work: &mut PendingNativeFileTargetOpen) -> bool {
    let phase = core::mem::replace(&mut work.phase, Phase::Quarantined);
    match phase {
        Phase::Lookup => {
            if work.abandoned {
                work.phase = Phase::ReplyReady(nt_process::STATUS_INVALID_HANDLE);
                return true;
            }
            if work.reference.validate(&handler.pm).is_err()
                || handler.pm.validate_native_handle_caller(work.caller).is_err()
            {
                work.phase = Phase::ReplyReady(nt_process::STATUS_INVALID_HANDLE);
                return true;
            }
            work.phase = match object_manager_resolve_file_target_async(
                &work.name, work.captured.attributes & 0x40 != 0,
            ) {
                FileTargetOwnedOutcome::NoEffect(status)
                    if status == nt_status::NtStatus::DEVICE_BUSY => Phase::Lookup,
                FileTargetOwnedOutcome::NoEffect(status) => Phase::ReplyReady(status.raw() as u32),
                FileTargetOwnedOutcome::Completed(terminal_result) => terminal(terminal_result),
                FileTargetOwnedOutcome::Indeterminate(pending) => Phase::Submitted(pending),
            };
            !matches!(work.phase, Phase::Lookup)
        }
        Phase::Submitted(pending) => {
            match poll_file_target_owned(&pending) {
                Some(result) => {
                    work.phase = terminal(result);
                    true
                }
                None => {
                    work.phase = Phase::Submitted(pending);
                    false
                }
            }
        }
        Phase::Resolved(resolved) => {
            if work.abandoned || work.reference.validate(&handler.pm).is_err()
                || handler.pm.validate_native_handle_caller(work.caller).is_err()
            {
                work.phase = Phase::ReplyReady(nt_process::STATUS_INVALID_HANDLE);
                return true;
            }
            if handler.pending_file_io_transfer.is_some()
                || handler.pending_file_io_reservation.is_some()
            {
                work.phase = Phase::Resolved(resolved);
                return false;
            }
            let outcome = crate::service_sec_image::with_section_metadata_context(
                handler, work.pi, work.tid, work.badge, work.resume_ip, work.sp,
                work.flags, work.native_call_transport, work.service_number,
                |handler| {
                    let status = match work.kind {
                        Kind::Open => handler.nt_open_file_captured(
                            &work.args, &work.captured, FileParseRoot::Absolute,
                            &work.name, Some(&resolved)),
                        Kind::Create => handler.nt_create_file_captured(
                            &work.args, &work.captured, FileParseRoot::Absolute,
                            &work.name, &work.ea, Some(&resolved)),
                    };
                    let transferred = crate::service_sec_image::finish_preparked_file_target_dispatch(
                        handler, status, work.reply, work.native_call_transport,
                        work.resume_ip, work.sp, work.flags,
                    );
                    (status, transferred)
                },
            );
            match outcome {
                Some((_, true)) => {
                    work.reply = 0;
                    work.phase = if work.reference.release(&mut handler.pm).is_ok() {
                        Phase::Done
                    } else { Phase::Quarantined };
                }
                Some((status, false)) if status != nt_status::NtStatus::PENDING.raw() as u32 => {
                    work.phase = Phase::ReplyReady(status);
                }
                Some(_) => work.phase = Phase::Quarantined,
                None => work.phase = Phase::ReplyReady(nt_process::STATUS_INVALID_HANDLE),
            }
            true
        }
        Phase::ReplyReady(status) => {
            if work.reply == 0 {
                thread_wait_state_clear_badge_ready(handler, work.badge);
                work.phase = if work.reference.release(&mut handler.pm).is_ok() {
                    Phase::Done
                } else { Phase::Quarantined };
                return true;
            }
            let delivered = reply_parked_syscall(work.reply, status as u64)
                || (spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(work.reply)
                    && matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                        work.reply), Ok(true)));
            if !delivered {
                work.phase = if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(work.reply) {
                    Phase::ReplyIndeterminate
                } else { Phase::Quarantined };
                return false;
            }
            release_reply_pool_cap(work.reply);
            work.reply = 0;
            thread_wait_state_clear_badge_ready(handler, work.badge);
            work.phase = if work.reference.release(&mut handler.pm).is_ok() {
                Phase::Done
            } else { Phase::Quarantined };
            true
        }
        Phase::ReplyIndeterminate => {
            if work.reply == 0 {
                work.phase = Phase::Quarantined;
                return false;
            }
            if matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                work.reply), Ok(true)) {
                release_reply_pool_cap(work.reply);
                work.reply = 0;
                thread_wait_state_clear_badge_ready(handler, work.badge);
                work.phase = if work.reference.release(&mut handler.pm).is_ok() {
                    Phase::Done
                } else { Phase::Quarantined };
                true
            } else {
                work.phase = Phase::ReplyIndeterminate;
                false
            }
        }
        Phase::Quarantined => { work.phase = Phase::Quarantined; false }
        Phase::Done => { work.phase = Phase::Done; false }
    }
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) -> bool {
    if monotonic_time_100ns() < NEXT_RETRY.load(Ordering::Acquire)
        || ACTIVE.swap(true, Ordering::AcqRel)
    { return false; }
    let queue = &mut *core::ptr::addr_of_mut!(PENDING);
    if queue.is_empty() {
        ACTIVE.store(false, Ordering::Release);
        return false;
    }
    let len = queue.len();
    let start = (CURSOR.fetch_add(1, Ordering::Relaxed) as usize) % len;
    let Some(index) = (0..len).map(|offset| (start + offset) % len)
        .find(|&index| !matches!(queue[index].phase, Phase::Quarantined | Phase::Done))
    else {
        ACTIVE.store(false, Ordering::Release);
        return false;
    };
    let mut work = queue.swap_remove(index);
    *core::ptr::addr_of_mut!(SELECTED) = &mut work;
    let mut progress = false;
    for _ in 0..4 {
        let step_progress = step(handler, &mut work);
        progress |= step_progress;
        if !step_progress || matches!(work.phase, Phase::Quarantined | Phase::Done) { break; }
    }
    *core::ptr::addr_of_mut!(SELECTED) = core::ptr::null_mut();
    if !matches!(work.phase, Phase::Done) { queue.push(work); }
    NEXT_RETRY.store(monotonic_time_100ns().saturating_add(RETRY_100NS), Ordering::Release);
    ACTIVE.store(false, Ordering::Release);
    progress
}

pub(crate) fn wake_due(now: u64) -> u64 {
    let runnable = unsafe { (&*core::ptr::addr_of!(PENDING)).iter().any(|work|
        !matches!(work.phase, Phase::Quarantined | Phase::Done)) };
    u64::from(runnable && now >= NEXT_RETRY.load(Ordering::Acquire))
}
