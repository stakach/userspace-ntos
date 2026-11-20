//! Root owner of pumps whose synchronous caller cannot keep a continuation (#333).
//!
//! A legacy caller needs a finished result. When its pump stops unfinished (a held lane or an
//! owed nested restore), the caller gets an uncertain result that never reports completion,
//! and the pump itself is kept here. Its outer parent is restored first, or, if that is
//! refused, the running lane's reply waits for it. The root then drives the kept pump to the
//! end of its dispatch at its own boundaries. A fenced pump keeps every resource; nothing is
//! replayed.

use super::*;

static mut KEPT: Vec<HostedPumpRestore> = Vec::new();

pub(super) unsafe fn keep(mut pump: HostedPumpRestore) -> crate::spawn_hosts::PumpResult {
    use crate::spawn_hosts::shared_ingress::owner::runtime;
    let mut parent = pump.take_outer_parent();
    if runtime::nested::restore(&mut parent).is_err() {
        if let Some(parent) = parent {
            crate::spawn_hosts::defer_reply_until_restored(parent);
        }
    }
    let mut result = pump.result();
    result.completed = false;
    result.scheduler_yielded = false;
    result.nested_restore_yield = None;
    result.nested_restore_quarantined = None;
    result.nested_child_work = None;
    result.status = nt_status::NtStatus::DEVICE_BUSY.raw();
    let kept = &mut *core::ptr::addr_of_mut!(KEPT);
    if kept.try_reserve(1).is_ok() {
        kept.push(pump);
    } else {
        // No row can keep it: every handle it holds drops to the root restore queue.
        print_str(b"[pump-keeper] no capacity; parents are root-owned\n");
    }
    trace(b"kept", kept.len());
    result
}

/// Root boundary only: drive each retryable kept pump once; a finished one is released.
pub(crate) unsafe fn drive() -> usize {
    let kept = &mut *core::ptr::addr_of_mut!(KEPT);
    if kept.is_empty() { return 0; }
    let mut finished = 0;
    let pumps = core::mem::take(kept);
    for pump in pumps {
        let next = if pump.retryable_continuation() {
            retry_child_work(pump)
        } else {
            retry_retained_add_device_restore(pump)
        };
        match next {
            HostedPumpRestore::Restored(_) | HostedPumpRestore::Unattributed(_) => finished += 1,
            unfinished => (&mut *core::ptr::addr_of_mut!(KEPT)).push(unfinished),
        }
    }
    if finished != 0 { trace(b"finished", finished); }
    finished
}

fn trace(stage: &[u8], count: usize) {
    static TRACED: AtomicU64 = AtomicU64::new(0);
    let n = TRACED.fetch_add(1, Ordering::Relaxed) + 1;
    if n > 16 && !n.is_power_of_two() { return; }
    print_str(b"[pump-keeper] n=");
    print_u64(n);
    print_str(b" stage=");
    print_str(stage);
    print_str(b" count=");
    print_u64(count as u64);
    print_str(b"\n");
}
