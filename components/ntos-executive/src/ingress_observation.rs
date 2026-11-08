//! Copied ingress evidence, never scheduling or admission authority.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_hosted_runtime::{
    WaitLatencyInterval, WaitLatencyKey, WaitLatencyLedger, WaitLatencyOwner, WaitLatencyRole,
    WaitLatencyThreadIdentity,
};

use crate::object_wait::ObjectWaiterRecord;

// An observation can be dropped when the census interrupts another observation.
// Neither this lock nor a full ledger may alter the retained wait or Reply.
static WAIT_LATENCY_BUSY: AtomicBool = AtomicBool::new(false);
static WAIT_LATENCY_SKIPPED: AtomicU64 = AtomicU64::new(0);
static mut WAIT_LATENCY: WaitLatencyLedger<256> = WaitLatencyLedger::new();

struct WaitLatencyGuard;
impl Drop for WaitLatencyGuard {
    fn drop(&mut self) { WAIT_LATENCY_BUSY.store(false, Ordering::Release); }
}

fn with_wait_latency<R>(f: impl FnOnce(&mut WaitLatencyLedger<256>) -> R) -> Option<R> {
    if WAIT_LATENCY_BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        WAIT_LATENCY_SKIPPED.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let _guard = WaitLatencyGuard;
    Some(f(unsafe { &mut *core::ptr::addr_of_mut!(WAIT_LATENCY) }))
}

fn object_wait_key(record: &ObjectWaiterRecord) -> WaitLatencyKey {
    let process_generation = match record.caller.process().generation {
        nt_types::ProcessGeneration::Hosted(value)
        | nt_types::ProcessGeneration::Temporary(value) => value,
    };
    WaitLatencyKey {
        process_index: record.pi as u64,
        process_generation,
        thread_id: record.tid,
        thread_generation: record.caller.thread().generation(),
        badge: record.caller.badge(),
        tcb: record.caller.tcb(),
        wait_sequence: record.sequence,
        reply: record.reply_cap,
    }
}

pub(crate) fn object_wait_parked(
    record: &ObjectWaiterRecord,
    role: Option<nt_exe_image::HostedProcessRole>,
    now_100ns: u64,
) {
    let key = object_wait_key(record);
    let role = match role {
        Some(nt_exe_image::HostedProcessRole::NativeSession) => WaitLatencyRole::SessionManager,
        Some(nt_exe_image::HostedProcessRole::Win32Subsystem) => WaitLatencyRole::ClientServer,
        Some(nt_exe_image::HostedProcessRole::InteractiveLogon) => WaitLatencyRole::Winlogon,
        Some(nt_exe_image::HostedProcessRole::ServiceControlManager) => WaitLatencyRole::Services,
        Some(nt_exe_image::HostedProcessRole::InteractiveShellBootstrap) => WaitLatencyRole::Userinit,
        Some(nt_exe_image::HostedProcessRole::InteractiveShell) => WaitLatencyRole::Explorer,
        Some(_) => WaitLatencyRole::Other,
        None => WaitLatencyRole::Unknown,
    };
    let _ = with_wait_latency(|ledger| {
        let _ = ledger.park(key, role, WaitLatencyOwner::Object, now_100ns);
    });
}

pub(crate) fn object_wait_selected(record: &ObjectWaiterRecord, now_100ns: u64) {
    let key = object_wait_key(record);
    let _ = with_wait_latency(|ledger| { let _ = ledger.selected(key, now_100ns); });
}

pub(crate) fn object_wait_reply_delivered(record: &ObjectWaiterRecord, now_100ns: u64) {
    let key = object_wait_key(record);
    let _ = with_wait_latency(|ledger| { let _ = ledger.reply_delivered(key, now_100ns); });
}

pub(crate) fn object_wait_retired_without_reply(record: &ObjectWaiterRecord) {
    let key = object_wait_key(record);
    let _ = with_wait_latency(|ledger| { let _ = ledger.retire_incomplete(key); });
}

/// Call only after independently authenticating the current process and thread
/// generations and TCB. A badge or timer notification is insufficient.
pub(crate) fn authenticated_thread_ingress(
    thread: WaitLatencyThreadIdentity, now_100ns: u64,
) {
    let _ = with_wait_latency(|ledger| {
        let _ = ledger.next_ingress_for_thread(thread, now_100ns);
    });
}

fn append_wait_latency_census(record: &mut nt_printf::record::RecordBuffer<4096>, now: u64) {
    use core::fmt::Write;
    let skipped = WAIT_LATENCY_SKIPPED.load(Ordering::Relaxed);
    let _ = with_wait_latency(|ledger| {
        let counters = ledger.counters();
        let _ = writeln!(record,
            "[wait-owner] t_ms={} live={} skipped={} invalid={} unmatched={} ambiguous={} phase={} full={} clock={} unknown={}",
            now / 10_000, ledger.live_count(), skipped, counters.invalid_identity,
            counters.unmatched, counters.ambiguous_ingress, counters.phase_refusal,
            counters.capacity_overflow, counters.clock_regression, counters.unknown_intervals);
        if let Some(oldest) = ledger.oldest_live() {
            let _ = writeln!(record,
                "[wait-owner-oldest] pi/tid/pgen/tgen/tcb/seq/reply/age-ms={}/{}/{}/{}/{}/{}/{}/{} phase={:?}",
                oldest.key.process_index, oldest.key.thread_id,
                oldest.key.process_generation, oldest.key.thread_generation,
                oldest.key.tcb, oldest.key.wait_sequence, oldest.key.reply,
                now.saturating_sub(oldest.parked_at_100ns) / 10_000, oldest.phase);
        }
        let mut emitted = 0;
        let mut omitted = 0;
        for role in WaitLatencyRole::ALL {
            for interval in [WaitLatencyInterval::ParkToSelected,
                WaitLatencyInterval::SelectedToReply,
                WaitLatencyInterval::ReplyToNextIngress] {
                let sample = ledger.sample(role, WaitLatencyOwner::Object, interval);
                if sample.count != 0 {
                    if emitted < 6 {
                        let _ = writeln!(record,
                            "[wait-owner-sample] role={:?} owner=object interval={:?} n={} total-ms={} max-ms={}",
                            role, interval, sample.count, sample.total_100ns / 10_000,
                            sample.max_100ns / 10_000);
                        emitted += 1;
                    } else {
                        omitted += 1;
                    }
                }
            }
        }
        if omitted != 0 { let _ = writeln!(record, "[wait-owner-sample] omitted={}", omitted); }
    });
}

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
    append_wait_latency_census(&mut record, now);
    crate::hpet_read_observation::append_census(&mut record);
    crate::calibrated_tsc_clock::append_census(&mut record);
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
    static HOSTED_CALL_CENSUS_SAMPLES: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    if (gate.retained.iter().any(Option::is_some) || gate.retained_overflow != 0)
        && HOSTED_CALL_CENSUS_SAMPLES.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 64
    {
        let mut calls_record = nt_printf::record::RecordBuffer::<4096>::new();
        let _ = writeln!(calls_record, "[ingress-calls] t_ms={} overflow={}",
            now / 10_000, gate.retained_overflow);
        for call in gate.retained.into_iter().flatten() {
            let (generation_kind, generation) = match call.binding.process.generation {
                nt_user_host::process_identity::ProcessGeneration::Hosted(value) =>
                    ("hosted", value),
                nt_user_host::process_identity::ProcessGeneration::Temporary(value) =>
                    ("temporary", value),
            };
            let _ = writeln!(calls_record,
                "[ingress-call] pi/pid/pgen/tid/badge/tcb/seq/reply/label/ssn/delivered/settlement={}/{}/{}:{}/{}/{}/{}/{}/{}/{}/{}/{}/{}",
                call.binding.pi, call.binding.process.pid, generation_kind, generation,
                call.binding.tid, call.binding.badge, call.binding.tcb,
                call.admission_sequence, call.reply, call.label, call.ssn,
                u8::from(call.delivered), u8::from(call.settlement_prepared));
        }
        sel4_rt::print_record(if calls_record.overflowed() {
            b"[ingress-calls] record-truncated\n"
        } else {
            calls_record.bytes()
        });
    }
    let calls = crate::MONOTONIC_CALLS.snapshot::<8>();
    let mut callers = nt_printf::record::RecordBuffer::<2048>::new();
    let _ = write!(callers, "[clock-callers] calls={} sampled={} overflow={}",
        calls.calls, calls.sampled, calls.overflow);
    for sample in calls.top.into_iter().flatten() {
        let location = sample.location;
        let _ = write!(callers, " {}:{}:{}={}", location.file(), location.line(),
            location.column(), sample.samples);
    }
    let _ = writeln!(callers);
    sel4_rt::print_record(if callers.overflowed() {
        b"[clock-callers] record-truncated\n"
    } else {
        callers.bytes()
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
