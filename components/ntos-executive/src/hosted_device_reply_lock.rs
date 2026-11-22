//! The component device-reply lock: PASSIVE lanes hold it across device-service root Calls.
//!
//! A DPC that reached it over a holder could only spin, because root cannot answer the holder's
//! Call while it drives the DPC (#420, boot 44963863150). Root therefore never starts a DPC on
//! an instance whose word is held (`nt_hosted_runtime::admit_dpc_over_device_reply_lock`), and
//! the holder's release wakes root, whose next DPC pass delivers the still-queued DPC.

use super::*;
use nt_hosted_runtime::{admit_dpc_over_device_reply_lock, release_device_reply_lock,
    try_acquire_device_reply_lock, DeviceReplyDpcAdmission, DeviceReplyRelease};

const COMPONENT_DEVICE_REPLY_LOCK_OFF: u64 = 0x18;
const _: () = assert!(COMPONENT_DEVICE_REPLY_LOCK_OFF == COMPONENT_POOL_LOCK_OFF + 8
    && COMPONENT_DEVICE_REPLY_LOCK_OFF + 8 == COMPONENT_POOL_GENERATION_OFF);

fn component_word() -> &'static AtomicU64 {
    unsafe { &*((FSD_POOL_VADDR + COMPONENT_DEVICE_REPLY_LOCK_OFF) as *const AtomicU64) }
}

/// Component view only. The holder is named by this lane's stack pointer.
pub(super) struct ComponentDeviceReplyLockGuard(u64);

impl Drop for ComponentDeviceReplyLockGuard {
    fn drop(&mut self) {
        match release_device_reply_lock(component_word(), self.0) {
            Ok(DeviceReplyRelease::Released) => {}
            // An IRQ lane holder runs inside root's DPC dispatch, whose return is root's event.
            Ok(DeviceReplyRelease::WakeDeferredDpc) if unsafe { hosted_irq_lane_context() }.is_some() => {}
            // The Call is root's event: its next DPC pass delivers the deferred DPC. No lane is
            // parked on this word, so the wake itself has no other effect.
            Ok(DeviceReplyRelease::WakeDeferredDpc) =>
                hosted_driver_spin_wait::wake(FSD_POOL_VADDR + COMPONENT_DEVICE_REPLY_LOCK_OFF),
            Err(actual) => unsafe {
                crate::provider_bugcheck::report(0xc4, [0x4452_4c4b, self.0, actual, 0]);
            },
        }
    }
}

pub(super) unsafe fn component_device_reply_lock() -> ComponentDeviceReplyLockGuard {
    let stack_pointer: u64;
    core::arch::asm!("mov {}, rsp", out(reg) stack_pointer, options(nostack, nomem, preserves_flags));
    while try_acquire_device_reply_lock(component_word(), stack_pointer).is_err() {
        // Another PASSIVE lane of this component holds it across a root Call that root answers;
        // a DPC never gets here over a holder (see `dpc_may_start`).
        crate::yield_now();
    }
    ComponentDeviceReplyLockGuard(stack_pointer)
}

/// Root's DPC admission for one instance. False keeps the DPC queued; the holder's release
/// wakes root for the next DPC pass.
pub(super) unsafe fn dpc_may_start(exec_pool_va: u64) -> bool {
    if exec_pool_va == 0 {
        return true;
    }
    let word = &*((exec_pool_va + COMPONENT_DEVICE_REPLY_LOCK_OFF) as *const AtomicU64);
    match admit_dpc_over_device_reply_lock(word) {
        DeviceReplyDpcAdmission::Start => true,
        DeviceReplyDpcAdmission::Deferred { holder_stack_pointer } => {
            trace_deferred(exec_pool_va, holder_stack_pointer);
            false
        }
    }
}

fn trace_deferred(pool: u64, holder: u64) {
    static DEFERRALS: AtomicU64 = AtomicU64::new(0);
    let sample = DEFERRALS.fetch_add(1, Ordering::Relaxed) + 1;
    if sample > 16 && !sample.is_power_of_two() {
        return;
    }
    print_str(b"[hosted-dpc] deferred over device-reply holder sample/pool/holder-stack=");
    for value in [sample, pool, holder] {
        print_str(b"/");
        print_hex_u64(value);
    }
    print_str(b"\n");
}
