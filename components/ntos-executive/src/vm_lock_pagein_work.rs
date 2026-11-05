//! Retained NtLockVirtualMemory page traversal. The caller owns the Reply and
//! output pointers; an independently captured target owns each page and VSpace.

use crate::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_address_space::{vm_lock_continuation::VmLockPageContinuation,
    VmResidencyRangePlan, VmResidencySource};
use crate::routed_pagein_source::RoutedPageInSource;
use nt_user_host::vm_lock_owner::VmLockInvocationOwner;

const RESOURCES: u32 = nt_address_space::STATUS_INSUFFICIENT_RESOURCES;
const INVALID: u32 = nt_fs::STATUS_INVALID_HANDLE;
const CANCELLED: u32 = 0xc000_0120;
const RETRY_DELAY: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { Scan, Waiting, ReadyReply(u32), ReplyEntered, ReplySent, Cancel, RetypeReply, Done, Indeterminate }

struct Work {
    owner: VmLockInvocationOwner,
    progress: VmLockPageContinuation<VmLockInvocationOwner, RoutedPageInSource, u64>,
    range: VmResidencyRangePlan,
    map_type: u32,
    base_pointer: u64,
    size_pointer: u64,
    token: Option<u64>,
    phase: Phase,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);
static EXECUTING_INDEX: AtomicU64 = AtomicU64::new(u64::MAX);
static EXECUTING_TID: AtomicU64 = AtomicU64::new(0);
static EXECUTING_TARGET: AtomicU64 = AtomicU64::new(u64::MAX);
static EXECUTING_CALLER: AtomicU64 = AtomicU64::new(u64::MAX);
static NEXT: AtomicU64 = AtomicU64::new(0);
static NEXT_PAGE_TOKEN: AtomicU64 = AtomicU64::new(1);

fn fresh_page_token() -> Option<u64> {
    NEXT_PAGE_TOKEN.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |value| value.checked_add(1)).ok().filter(|value| *value != 0)
}

/// Called at the syscall ingress, before any target page or provider File effect.
pub(crate) unsafe fn submit(
    handler: &mut ExecNtHandler, args: &[u64], resume_ip: u64, sp: u64, flags: u64,
    native_call_transport: bool,
) -> Result<(), u32> {
    let _durable = allocator::enter_durable();
    let (target_pi, range, map_type, base_pointer, size_pointer) = handler
        .capture_virtual_memory_lock_request(args, SyscallUserMemory::CurrentProcess)?;
    // Match the ordinary handler's full-range admission before any residency effect.
    for page in range.pages() {
        let info = handler.query_memory_basic_information(target_pi, page)?;
        nt_address_space::vm_residency_page_plan(page, info)?;
    }
    let target = handler.capture_process_identity(target_pi).ok_or(INVALID)?;
    let caller_pi = handler.pi;
    let tid = handler.current_tid;
    let badge = handler.current_badge;
    let tcb = handler.hosted_thread_tcb(tid).ok_or(INVALID)?;
    let caller = handler.capture_provider_logical_caller(caller_pi, tid, badge, tcb)
        .ok_or(INVALID)?;
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let owner = VmLockInvocationOwner::capture(caller, target_pi, target, reply).ok_or(INVALID)?;
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let index = rows.iter().enumerate().find_map(|(index, row)|
        (row.is_none() && EXECUTING_INDEX.load(Ordering::Acquire) != index as u64).then_some(index));
    if index.is_none() && rows.try_reserve(1).is_err() { return Err(RESOURCES); }
    let park = root_reply_park::RootReplyPark::prepare().ok_or(RESOURCES)?;
    let work = Work { owner, progress: VmLockPageContinuation::new(owner, range), range,
        map_type, base_pointer, size_pointer, token: None, phase: Phase::Scan,
        resume_ip, sp, flags, native_call_transport };
    match index { Some(index) => rows[index] = Some(work), None => rows.push(Some(work)) }
    park.commit();
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    Ok(())
}

pub(crate) fn has_thread(tid: u64) -> bool {
    EXECUTING_TID.load(Ordering::Acquire) == tid
        || unsafe { (&*core::ptr::addr_of!(WORK)).iter().flatten()
            .any(|work| work.owner.caller().thread().thread_id() as u64 == tid) }
}

pub(crate) fn has_process(pi: usize, preserve_tid: Option<u64>) -> bool {
    ((EXECUTING_TARGET.load(Ordering::Acquire) == pi as u64
        || EXECUTING_CALLER.load(Ordering::Acquire) == pi as u64)
        && preserve_tid != Some(EXECUTING_TID.load(Ordering::Acquire)))
        || unsafe { (&*core::ptr::addr_of!(WORK)).iter().flatten().any(|work|
            (work.owner.target_pi() == pi || work.owner.caller().pi() == pi)
                && preserve_tid != Some(work.owner.caller().thread().thread_id() as u64)) }
}

pub(crate) fn next_deadline() -> Option<u64> {
    (ACTIVE.load(Ordering::Acquire)
        || unsafe { (&*core::ptr::addr_of!(WORK)).iter().any(Option::is_some) })
        .then(|| NEXT.load(Ordering::Acquire))
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

fn valid(handler: &ExecNtHandler, work: &Work) -> bool {
    let owner = work.owner;
    handler.validate_provider_logical_caller(owner.caller())
        && handler.capture_process_identity(owner.target_pi()) == Some(owner.target())
}

fn exact_target_scratch(owner: VmLockInvocationOwner) -> Option<u64> {
    let nt_user_host::process_identity::ProcessGeneration::Hosted(generation) =
        owner.target().generation else { return None; };
    hosted_process_runtime_for_exact(owner.target_pi(), generation)
        .map(|runtime| runtime.scratch_base)
}

/// A page worker reports only after its own exact terminal/copy/ACK and target map proof.
/// It never consumes or replies through the coordinator's original syscall Reply.
pub(crate) unsafe fn page_completed(
    token: u64, target_pi: usize, page: u64, source: RoutedPageInSource, status: u32,
) -> bool {
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let mut found = None;
    for (index, row) in rows.iter().enumerate() {
        if row.as_ref().is_some_and(|row| row.token == Some(token)) {
            if found.replace(index).is_some() { return false; }
        }
    }
    let Some(index) = found else { return false; };
    let work = rows[index].as_mut().unwrap();
    if work.owner.target_pi() != target_pi || work.progress.next_page(work.owner).is_some()
        || !matches!(work.phase, Phase::Waiting) || work.token != Some(token) {
        return false;
    }
    if status == 0 {
        if !work.progress.acknowledge_pending(work.owner, page, source, token)
            || !work.progress.mark_pending_resident(work.owner, page, source, token) {
            work.phase = Phase::Indeterminate;
            return false;
        }
        work.token = None;
        work.phase = Phase::Scan;
    } else {
        // A failed page worker must still match the retained page and source. Its
        // terminal failure cannot authorize another page or a lock-table commit.
        if !work.progress.quarantine(work.owner, page, source, token) {
            work.phase = Phase::Indeterminate;
            return false;
        }
        work.token = None;
        work.phase = Phase::ReadyReply(status);
    }
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    true
}

unsafe fn advance(handler: &mut ExecNtHandler, work: &mut Work) {
    let owner = work.owner;
    let cancelled = spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(owner.reply())
        || handler.pm.thread(owner.caller().thread().thread_id())
            .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
        || handler.pm.process(owner.caller().process().pid)
            .is_some_and(|process| process.state == nt_process::ProcessState::Terminated)
        || !valid(handler, work);
    match work.phase {
        Phase::Scan => {
            if cancelled { work.phase = Phase::Cancel; return; }
            let target_pi = owner.target_pi();
            if let nt_user_host::process_identity::ProcessGeneration::Hosted(generation) =
                owner.target().generation
            {
                if hosted_process_runtime_for_exact(target_pi, generation).is_none() {
                    work.phase = Phase::ReadyReply(INVALID);
                    return;
                }
            }
            let Some(page) = work.progress.next_page(owner) else {
                if !work.progress.ready_to_commit(owner) { work.phase = Phase::Indeterminate; return; }
                // The lock table is the sole publication point. Enter once before the effect.
                work.phase = Phase::Indeterminate;
                let status = match vm_page_lock_range(target_pi as u64, work.range, work.map_type) {
                    Ok(status) if (status as i32) >= 0 => handler.publish_vm_range(
                        SyscallUserMemory::CurrentProcess,
                        nt_address_space::native_output::VmRangeOutput {
                            base_pointer: work.base_pointer, size_pointer: work.size_pointer,
                        }, work.range.base, work.range.size, None,
                    ).map_or_else(|error| error, |_| status),
                    Ok(status) | Err(status) => status,
                };
                work.phase = Phase::ReadyReply(status);
                return;
            };
            let info = match handler.query_memory_basic_information(target_pi, page) {
                Ok(info) => info,
                Err(status) => { work.phase = Phase::ReadyReply(status); return; }
            };
            let plan = match nt_address_space::vm_residency_page_plan(page, info) {
                Ok(plan) => plan,
                Err(status) => { work.phase = Phase::ReadyReply(status); return; }
            };
            let result = match plan.source {
                VmResidencySource::Private => handler.ensure_residency_page(target_pi, plan),
                VmResidencySource::Mapped => {
                    let Some(target_scratch) = exact_target_scratch(owner) else {
                        work.phase = Phase::ReadyReply(INVALID);
                        return;
                    };
                    let Some(ctx) = handler.loop_ctx else {
                        work.phase = Phase::ReadyReply(INVALID);
                        return;
                    };
                    let fault = crate::service_sec_image::service_generic_section_fault(
                        handler, ctx.generic_sections, target_pi, page, ctx.pml4,
                        target_scratch, plan.access, true, false);
                    match fault {
                        Ok(crate::service_sec_image::GenericSectionFaultResult::Mapped) => Ok(()),
                        Ok(crate::service_sec_image::GenericSectionFaultResult::RoutedPageIn) => {
                            let Some(token) = fresh_page_token() else {
                                work.phase = Phase::ReadyReply(RESOURCES); return;
                            };
                            match crate::section_pagein_work::submit_for_vm_lock(handler,
                                owner.caller().pi(), target_pi, page, plan.access,
                                owner.reply(), token) {
                                Ok(source) => {
                                    if !work.progress.begin_pending(owner, page, source, token) {
                                        work.phase = Phase::Indeterminate; return;
                                    }
                                    work.token = Some(token);
                                    work.phase = Phase::Waiting;
                                    return;
                                }
                                Err(status) => Err(status),
                            }
                        }
                        Ok(crate::service_sec_image::GenericSectionFaultResult::Unmapped) =>
                            Err(nt_address_space::STATUS_CONFLICTING_ADDRESSES),
                        Err(status) => Err(status),
                    }
                }
                VmResidencySource::Image => {
                    let Some(token) = fresh_page_token() else {
                        work.phase = Phase::ReadyReply(RESOURCES); return;
                    };
                    match crate::native_image_pagein_work::submit_for_vm_lock(handler,
                        owner.caller().pi(), target_pi, page, plan.access,
                        owner.reply(), token) {
                        Ok(Some(source)) => {
                            if !work.progress.begin_pending(owner, page, source, token) {
                                work.phase = Phase::Indeterminate; return;
                            }
                            work.token = Some(token);
                            work.phase = Phase::Waiting;
                            return;
                        }
                        Ok(None) => handler.ensure_residency_page(target_pi, plan),
                        Err(status) => Err(status),
                    }
                }
            };
            match result {
                Ok(()) if work.progress.mark_inline_resident(owner, page) => {},
                Ok(()) => work.phase = Phase::Indeterminate,
                Err(status) => work.phase = Phase::ReadyReply(status),
            }
        }
        Phase::Waiting => {
            // The page worker owns any pending IRP. Do not replay it on a timer tick.
            if cancelled && work.token.is_none() { work.phase = Phase::Cancel; }
        }
        Phase::ReadyReply(status) => {
            if cancelled { work.phase = Phase::Cancel; return; }
            if parked_reply::validate_saved(owner.reply()).is_err() { return; }
            work.phase = Phase::ReplyEntered;
            if reply_parked_syscall(owner.reply(), u64::from(status)) {
                work.phase = Phase::ReplySent;
            }
        }
        Phase::ReplyEntered => {
            match spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                owner.reply()) {
                Ok(true) => work.phase = Phase::ReplySent,
                _ if cancelled => work.phase = Phase::Cancel,
                _ => {}
            }
        }
        Phase::ReplySent => {
            if parked_reply::retire_sent(owner.reply()).is_ok() {
                thread_wait_state_clear_badge_ready(handler, owner.caller().badge());
                work.phase = Phase::Done;
            }
        }
        Phase::Cancel => {
            if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(owner.reply()) {
                if !spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(owner.reply())
                    && spawn_hosts::shared_ingress::owner::runtime::stop_and_cancel_hosted(owner.reply()).is_err() {
                    return;
                }
            } else if parked_reply::revoke(owner.reply()).is_err() { return; }
            work.phase = Phase::RetypeReply;
        }
        Phase::RetypeReply => {
            if parked_reply::retype(owner.reply()).is_ok() { work.phase = Phase::Done; }
        }
        Phase::Done => {}
        Phase::Indeterminate => {}
    }
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    if next_deadline().is_none_or(|deadline| monotonic_time_100ns() < deadline)
        || ACTIVE.swap(true, Ordering::AcqRel) { return; }
    let _durable = allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    for index in 0..count {
        let Some(mut work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].take() else { continue; };
        EXECUTING_INDEX.store(index as u64, Ordering::Release);
        EXECUTING_TID.store(work.owner.caller().thread().thread_id() as u64, Ordering::Release);
        EXECUTING_TARGET.store(work.owner.target_pi() as u64, Ordering::Release);
        EXECUTING_CALLER.store(work.owner.caller().pi() as u64, Ordering::Release);
        let caller = work.owner.caller();
        let done = crate::service_sec_image::with_pagein_caller_target_context(
            handler, caller.pi(), work.owner.target_pi(),
            caller.thread().thread_id() as u64, caller.badge(),
            work.resume_ip, work.sp, work.flags, work.native_call_transport,
            SSN_NT_LOCK_VM as u32, |handler| {
                // Inline pages are local work. A timer tick must not add 100 ms per
                // page, while a Pending provider read must stop the scan immediately.
                for _ in 0..32 {
                    let before = work.progress.next_page(work.owner);
                    advance(handler, &mut work);
                    if !matches!(work.phase, Phase::Scan)
                        || work.progress.next_page(work.owner) == before {
                        break;
                    }
                }
            },
        );
        if done.is_none() {
            // A lost physical target cannot authorize another read or a lock-table commit.
            work.phase = Phase::Indeterminate;
        }
        if !matches!(work.phase, Phase::Done) {
            (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        }
        EXECUTING_TID.store(0, Ordering::Release);
        EXECUTING_TARGET.store(u64::MAX, Ordering::Release);
        EXECUTING_CALLER.store(u64::MAX, Ordering::Release);
        EXECUTING_INDEX.store(u64::MAX, Ordering::Release);
    }
    NEXT.store(monotonic_time_100ns().saturating_add(RETRY_DELAY), Ordering::Release);
    ACTIVE.store(false, Ordering::Release);
}
