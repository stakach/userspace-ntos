//! Root-visible waits for contended hosted driver spin-style locks.
//!
//! A hosted lane can hold a driver spin lock (KSPIN_LOCK, the cancel spin lock, an in-stack
//! queued lock or an EX_SPIN_LOCK) while it is blocked in a root call such as IoCompleteRequest.
//! The root is single-threaded: when it is servicing another lane of the same domain (for example
//! a nested provider callback) and that lane spins for the lock, the holder's root call is never
//! answered and nothing progresses (mouclass ClassCallback vs. ClassRead, boot 44677193307).
//!
//! So a contended acquire never spins across lanes. It publishes WAITERS in the lock word and
//! parks through the ordinary provider wait owner, which suspends the waiter's pump and lets the
//! root finish the holder's call. The holder's release sees WAITERS and asks the root to wake;
//! the parked lane is ready once the word differs from the exact value it observed, and retries.

use super::*;
use core::sync::atomic::{AtomicU32, AtomicU64};

pub(super) const LABEL: u64 = 0x7DD;
const WAIT64: u64 = 1;
const WAIT32: u64 = 2;
const WAKE: u64 = 3;

/// The calling lane's identity: the base of the hosted stack it runs on. Two live lanes never
/// share a stack, so the token names the holder in diagnostics and in-stack ownership checks.
pub(super) fn lane_token() -> u64 {
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem, preserves_flags)); }
    if (FSD_STACK_VADDR..FSD_STACK_VADDR + FSD_STACK_BYTES).contains(&rsp) {
        FSD_STACK_VADDR
    } else if rsp >= FSD_WORKER_VADDR && FSD_WORKER_STRIDE != 0 {
        FSD_WORKER_VADDR + (rsp - FSD_WORKER_VADDR) / FSD_WORKER_STRIDE * FSD_WORKER_STRIDE
    } else {
        rsp & !0xfff
    }
}

static CONTENTION_TRACES: AtomicU64 = AtomicU64::new(0);

fn trace(lock: u64, observed: u64, holder: u64) {
    if CONTENTION_TRACES.fetch_add(1, Ordering::Relaxed) < 16 {
        print_str(b"[spin-wait] lock=0x");
        print_hex_u64(lock);
        print_str(b" observed=0x");
        print_hex_u64(observed);
        print_str(b" holder-lane=0x");
        print_hex_u64(holder);
        print_str(b" waiter-lane=0x");
        print_hex_u64(lane_token());
        print_str(b"\n");
    }
}

/// Park the calling lane until the lock word at `lock` no longer equals `observed`. An IRQ lane
/// has no provider wait owner; it can only retry after yielding its processor.
pub(super) fn park(lock: u64, observed: u64, wide: bool, holder: u64) {
    trace(lock, observed, holder);
    if unsafe { hosted_irq_lane_context() }.is_some() {
        core::hint::spin_loop();
        crate::yield_now();
        return;
    }
    let op = if wide { WAIT64 } else { WAIT32 };
    let (label, status, _, _, _) = unsafe { call_on4((LABEL << 12) | 3, op, lock, observed, 0) };
    if label != 0 || status as u32 as i32 != STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, op, lock, status]); }
    }
}

/// A release that cleared WAITERS: wake every lane parked on this lock.
pub(super) fn wake(lock: u64) {
    let (label, status, _, _, _) = unsafe { call_on4((LABEL << 12) | 3, WAKE, lock, 0, 0) };
    if label != 0 || status as u32 as i32 != STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, WAKE, lock, status]); }
    }
}

/// Acquire a KSPIN_LOCK-style word for `owner`, parking instead of spinning while it is held.
pub(super) fn acquire(word: &AtomicU64, lock: u64, owner: u64) -> Result<(), nt_kernel_exec::hosted_spin_wait::SpinError> {
    use nt_kernel_exec::hosted_spin_wait::{acquire, Acquire};
    loop {
        match acquire(word, owner)? {
            Acquire::Acquired => return Ok(()),
            Acquire::Park { observed, holder } => park(lock, observed, true, holder),
        }
    }
}

struct Pending {
    instance: usize,
    domain: HostedDomainIdentity,
    exec: u64,
    wide: bool,
    observed: u64,
    thread_handle: u64,
    reply: u64,
}

static mut PENDING: Vec<Pending> = Vec::new();

fn pending() -> &'static mut Vec<Pending> {
    // Wait admission, readiness and wake all run on the serialized root owner.
    unsafe { &mut *core::ptr::addr_of_mut!(PENDING) }
}

unsafe fn current(exec: u64, wide: bool) -> u64 {
    if wide {
        unsafe { (*(exec as *const AtomicU64)).load(Ordering::Acquire) }
    } else {
        u64::from(unsafe { (*(exec as *const AtomicU32)).load(Ordering::Acquire) })
    }
}

/// The cancel spin lock is one executive-image word shared by every hosted domain at the same
/// address as the root's own static; any other lock lives in the caller's mapped memory.
fn lock_exec(instance: usize, inst: DriverInstance, lock: u64, bytes: u64) -> Option<u64> {
    if lock == core::ptr::addr_of!(IO_CANCEL_SPIN_LOCK) as u64 {
        return Some(lock);
    }
    let exec = hosted_driver_component_object_exec_va(instance, inst, lock, bytes)?;
    (exec & (bytes - 1) == 0).then_some(exec)
}

pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    operation: u64,
    lock: u64,
    observed: u64,
    badge: u64,
    reply: u64,
) -> HostedDriverWaitServiceResult {
    let Some((instance, inst)) = instance_for_pump_channel(ch, reply) else {
        return HostedDriverWaitServiceResult::Reply(STATUS_ACCESS_DENIED);
    };
    let wide = match operation {
        WAIT64 => true,
        WAIT32 => false,
        WAKE => {
            let Some(exec) = lock_exec(instance, inst, lock, 4) else {
                return HostedDriverWaitServiceResult::Reply(STATUS_INVALID_PARAMETER);
            };
            let mut woken = Vec::new();
            if woken.try_reserve(pending().len()).is_err() {
                return HostedDriverWaitServiceResult::Reply(STATUS_INSUFFICIENT_RESOURCES);
            }
            for row in pending().iter().filter(|row| row.exec == exec) {
                if !woken.contains(&row.instance) { woken.push(row.instance); }
            }
            for waiter in woken { let _ = wake_hosted_driver_waiters_for_instance(waiter); }
            return HostedDriverWaitServiceResult::Reply(STATUS_SUCCESS);
        }
        _ => return HostedDriverWaitServiceResult::Reply(STATUS_INVALID_PARAMETER),
    };
    let Some(caller) = hosted_driver_caller(instance, inst, badge) else {
        return HostedDriverWaitServiceResult::Reply(STATUS_ACCESS_DENIED);
    };
    let Some(domain) = instance_domain_identity(inst) else {
        return HostedDriverWaitServiceResult::Reply(STATUS_ACCESS_DENIED);
    };
    let Some(exec) = lock_exec(instance, inst, lock, if wide { 8 } else { 4 }) else {
        return HostedDriverWaitServiceResult::Reply(STATUS_INVALID_PARAMETER);
    };
    if !wide && observed > u64::from(u32::MAX) {
        return HostedDriverWaitServiceResult::Reply(STATUS_INVALID_PARAMETER);
    }
    // The holder already released (or the word changed): retry without parking.
    if unsafe { current(exec, wide) } != observed {
        return HostedDriverWaitServiceResult::Reply(STATUS_SUCCESS);
    }
    let Some(owner_body) = hosted_driver_kmutex::owner_body(ch, inst) else {
        return HostedDriverWaitServiceResult::Reply(STATUS_ACCESS_DENIED);
    };
    let mut objects = Vec::new();
    let mut keys = Vec::new();
    if pending().try_reserve(1).is_err() || objects.try_reserve_exact(1).is_err()
        || keys.try_reserve_exact(1).is_err()
    {
        return HostedDriverWaitServiceResult::Reply(STATUS_INSUFFICIENT_RESOURCES);
    }
    pending().push(Pending { instance, domain, exec, wide, observed, thread_handle: caller.thread_handle, reply });
    objects.push(exec);
    keys.push(None);
    match park_hosted_driver_wait(instance, caller.thread_handle, caller.route, reply, objects,
        keys, owner_body, false, false, nt_kernel_exec::Deadline::Infinite)
    {
        Some(parked) => parked,
        None => {
            cancel_pending(instance, caller.thread_handle, reply);
            HostedDriverWaitServiceResult::Reply(STATUS_INSUFFICIENT_RESOURCES)
        }
    }
}

/// Readiness for a parked spin-lock wait: the word differs from the value the lane observed.
pub(super) fn ready(object: u64, thread_handle: u64) -> Option<Result<bool, i32>> {
    let row = pending().iter().find(|row| row.exec == object && row.thread_handle == thread_handle)?;
    Some(Ok(unsafe { current(row.exec, row.wide) } != row.observed))
}

/// The woken lane retries its own acquisition; the root takes nothing on its behalf.
pub(super) fn consume(object: u64, thread_handle: u64) -> Option<bool> {
    pending().iter().any(|row| row.exec == object && row.thread_handle == thread_handle)
        .then_some(true)
}

pub(super) fn cancel_pending(instance: usize, thread_handle: u64, reply: u64) {
    pending().retain(|row| !(row.instance == instance && row.thread_handle == thread_handle
        && row.reply == reply));
}

pub(super) fn acknowledged(instance: usize, thread_handle: u64, reply: u64) {
    cancel_pending(instance, thread_handle, reply);
}

pub(super) fn quiesced(domain: HostedDomainIdentity) -> bool {
    pending().iter().all(|row| row.domain != domain)
}
