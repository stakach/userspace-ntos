//! Bounded, read-only CSRSS main-thread startup evidence.
//!
//! Role and thread are selected from published hosted metadata and PM lifetime,
//! never an image name, numeric process slot, or remembered TCB alone.

use crate::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_user_host::startup_thread_sample::StartupThreadSampleGate;

const SAMPLE_INTERVAL_100NS: u64 = 10 * 10_000_000;
// Cover the observed ~485-second subsystem-ready wait at ten-second cadence.
const SAMPLE_LIMIT: u64 = 52;

static NEXT_SAMPLE_100NS: AtomicU64 = AtomicU64::new(0);
static SAMPLE_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
// The syscall tap sees the entire published CSRSS role, including workers.
static LAST_CSRSS_ROLE_SSN: AtomicU64 = AtomicU64::new(0);
static CSRSS_ROLE_SSN_COUNT: AtomicU64 = AtomicU64::new(0);
static mut GATE: Option<StartupThreadSampleGate<HostedThreadRole>> = None;

struct SampleInFlight;

impl Drop for SampleInFlight {
    fn drop(&mut self) {
        SAMPLE_IN_FLIGHT.store(false, Ordering::Release);
    }
}

pub(crate) fn record_syscall(ssn: u64) {
    LAST_CSRSS_ROLE_SSN.store(ssn, Ordering::Relaxed);
    CSRSS_ROLE_SSN_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Called from the existing periodic-census entry, before its 30-second gate.
/// An in-flight claim excludes overlapping register reads even if a sample
/// lasts longer than the cadence or the census entry reenters.
pub(crate) fn maybe_sample(now_100ns: u64) {
    if SAMPLE_IN_FLIGHT.compare_exchange(false, true,
        Ordering::AcqRel, Ordering::Acquire).is_err() {
        return;
    }
    let _in_flight = SampleInFlight;
    let due = NEXT_SAMPLE_100NS.load(Ordering::Acquire);
    if due == u64::MAX || now_100ns < due { return; }
    if NEXT_SAMPLE_100NS.compare_exchange(
        due, now_100ns.saturating_add(SAMPLE_INTERVAL_100NS),
        Ordering::AcqRel, Ordering::Acquire,
    ).is_err() {
        return;
    }
    unsafe { sample_once(now_100ns) }
}

unsafe fn sample_once(now_100ns: u64) {
    let Ok(handler_ptr) = service_sec_image::registry_live_handler_pointer() else { return };
    // Copy exact identities and wait evidence before diagnostic seL4 calls.
    // The handler borrow ends here and does not cross an IPC buffer mutation.
    let (pi, binding, lifetime, smss_wait) = {
        let handler = &*handler_ptr;
        let Some(pi) = service_sec_image::live_hosted_pi_for_observation_role(
            handler, nt_exe_image::HostedProcessRole::Win32Subsystem,
        ) else { return };
        let Some((binding, lifetime)) = handler.hosted_main_thread_sample_owner(pi) else { return };
        let smss_wait = service_sec_image::live_hosted_pi_for_observation_role(
            handler, nt_exe_image::HostedProcessRole::NativeSession,
        ).and_then(|smss_pi| handler.capture_process_identity(smss_pi)
            .and_then(|process| object_wait::object_waiter_oldest_unselected_for_process(
                smss_pi, process, now_100ns,
            )));
        (pi, binding, lifetime, smss_wait)
    };

    let ordinal = {
        let gate = &mut *core::ptr::addr_of_mut!(GATE);
        if gate.is_none() {
            *gate = StartupThreadSampleGate::new(binding, lifetime,
                SAMPLE_INTERVAL_100NS, SAMPLE_LIMIT);
        }
        let Some(ordinal) = gate.as_mut().and_then(|gate| {
            gate.claim_sample(Some(binding), Some(lifetime), now_100ns)
        }) else { return };
        ordinal
    };
    if ordinal == SAMPLE_LIMIT {
        NEXT_SAMPLE_100NS.store(u64::MAX, Ordering::Release);
    }

    // Both diagnostic seL4 calls use the executive IPC buffer. Preserve the
    // enclosing received message, including on an early stale-owner return.
    let _message = ipc_message::SavedMessageBuffer::capture();
    // No handler or gate borrow crosses the seL4 register read. Recheck the
    // current exact owner before reporting any sampled state.
    let mut regs = [0u64; 20];
    let valid = win32k_glue::tcb_read_regs20_checked(binding.tcb, &mut regs);
    let exact_after = (&*handler_ptr).hosted_main_thread_sample_owner(pi)
        == Some((binding, lifetime))
        && service_sec_image::live_hosted_pi_for_observation_role(
            &*handler_ptr, nt_exe_image::HostedProcessRole::Win32Subsystem,
        ) == Some(pi);
    if !exact_after { return; }

    let process_generation = match binding.process.generation {
        nt_types::ProcessGeneration::Hosted(generation)
        | nt_types::ProcessGeneration::Temporary(generation) => generation,
    };
    print_str(b"[csrss-main-sample] n/t-ms/pi/pid/pgen/tid/tgen/badge/tcb/last-role-ssn/role-ssn-count/smss-wait-seq/object/age-ms/regs-valid=");
    for (index, value) in [
        ordinal, now_100ns / 10_000, pi as u64, u64::from(binding.process.pid),
        process_generation, binding.tid, lifetime.generation(), binding.badge,
        binding.tcb, LAST_CSRSS_ROLE_SSN.load(Ordering::Relaxed),
        CSRSS_ROLE_SSN_COUNT.load(Ordering::Relaxed),
        smss_wait.map_or(0, |(sequence, _, _)| sequence),
        smss_wait.map_or(0, |(_, object, _)| object),
        smss_wait.map_or(0, |(_, _, age)| age / 10_000),
        u64::from(valid),
    ].into_iter().enumerate() {
        if index != 0 { print_str(b"/"); }
        print_u64(value);
    }
    if valid {
        print_str(b" rip=0x"); print_hex_u64(regs[0]);
        print_str(b" rsp=0x"); print_hex_u64(regs[1]);
    }
    print_str(b"\n");
    win32k_glue::trace_hosted_tcb_debug_state(b"csrss-main-sample", binding.tcb, 0);
}
