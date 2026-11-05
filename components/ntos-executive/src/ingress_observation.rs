//! Copied ingress evidence, never scheduling or admission authority.

pub(crate) fn print_hold_snapshot(now: u64) {
    use core::fmt::Write;
    let snapshot = unsafe {
        crate::spawn_hosts::shared_ingress::owner::runtime::hold_snapshot()
    };
    let gate = unsafe {
        crate::spawn_hosts::shared_ingress::owner::runtime::delivery_gate_snapshot()
    };
    let logical = snapshot.running.and_then(|running| unsafe {
        crate::win32k_glue::dispatch_observation_snapshot(running.lane)
    });
    let mut record = nt_printf::record::RecordBuffer::<4096>::new();
    let _ = writeln!(record, "[ingress-hold] t_ms={} running={:?} oldest={:?} logical={:?}",
        now / 10_000, snapshot.running, snapshot.oldest, logical);
    let _ = writeln!(record, "[ingress-gate] t_ms={} {:?}", now / 10_000, gate);
    let registry = unsafe { crate::registry_mutation_work::census_snapshot() };
    let _ = writeln!(record, "[registry-work] t_ms={} {:?}", now / 10_000, registry);
    let (messages, info, op) = crate::spawn_hosts::ps_create_parent_progress();
    let _ = writeln!(record, "[ps-create-parent-progress] count={} label={} op={}",
        messages, info >> 12, op);
    // Only copied, exact CSRSS-role ALPC ownership is sampled; this does not
    // poll, select, cancel, or wake the retained native request.
    static CSRSS_ALPC_SAMPLES: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    if CSRSS_ALPC_SAMPLES.load(core::sync::atomic::Ordering::Relaxed) < 16 {
        if let Some(wait) = crate::native_alpc_send_receive_work::csrss_wait_census(now) {
            if wait.parked_ms >= 1_000 {
                CSRSS_ALPC_SAMPLES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                let _ = writeln!(record,
                    "[csrss-wait-live] kind=alpc pi/tid/gen/badge/tcb/seq/port/reply/flight/age-ms={}/{}/{}/{}/{}/{}/{}/{}/{}/{}",
                    wait.pi, wait.caller.thread, wait.caller.generation,
                    wait.caller.badge, wait.caller.tcb, wait.sequence, wait.port,
                    wait.reply, wait.flight, wait.parked_ms);
            }
        }
    }
    sel4_rt::print_record(if record.overflowed() {
        b"[ingress-hold] record-truncated\n"
    } else {
        record.bytes()
    });
    unsafe {
        if let Some(oldest) = snapshot.oldest {
            crate::win32k_glue::trace_hosted_tcb_debug_state(
                b"oldest-hosted", oldest.binding.tcb, oldest.reply,
            );
        }
        crate::driver_launch::trace_hosted_system_thread_census();
        crate::driver_launch::trace_hosted_driver_wait_census();
    }
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
