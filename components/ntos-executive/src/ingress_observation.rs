//! Copied ingress evidence, never scheduling or admission authority.

pub(crate) fn print_hold_snapshot(now: u64) {
    use core::fmt::Write;
    let snapshot = unsafe {
        crate::spawn_hosts::shared_ingress::owner::runtime::hold_snapshot()
    };
    let logical = snapshot.running.and_then(|running| unsafe {
        crate::win32k_glue::dispatch_observation_snapshot(running.lane)
    });
    let mut record = nt_printf::record::RecordBuffer::<4096>::new();
    let _ = writeln!(record, "[ingress-hold] t_ms={} running={:?} oldest={:?} logical={:?}",
        now / 10_000, snapshot.running, snapshot.oldest, logical);
    sel4_rt::print_record(if record.overflowed() {
        b"[ingress-hold] record-truncated\n"
    } else {
        record.bytes()
    });
    // Read-only scheduler/Reply snapshots every fifteenth hold, at most eight times.
    static FONT_HOLD_SAMPLES: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    if logical.is_some_and(|dispatch| dispatch.ssn == 0x125a) {
        let sample = FONT_HOLD_SAMPLES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if sample % 15 == 0 && sample < 120 {
            if let Some(running) = snapshot.running {
                if let Some(binding) = running.binding {
                    unsafe { crate::win32k_glue::trace_hosted_tcb_debug_state(
                        b"font-provider", binding.executor_id, binding.reply_object,
                    ); }
                }
            }
            if let Some(caller) = logical.and_then(|dispatch| dispatch.logical_caller) {
                unsafe { crate::win32k_glue::trace_hosted_tcb_debug_state(
                    b"font-caller", caller.tcb(), 0,
                ); }
            }
        }
    }
}
