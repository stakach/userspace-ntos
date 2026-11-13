//! Finite, read-only main-thread evidence for post-font service readiness.
//! Each role is selected through published metadata and revalidated after a TCB read.

use crate::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_user_host::startup_thread_sample::StartupThreadSampleRoster;

const INTERVAL_100NS: u64 = 10 * 10_000_000;
const SAMPLES_PER_ROLE: u64 = 60;
const ROLES: [(nt_exe_image::HostedProcessRole, &[u8]); 3] = [
    (nt_exe_image::HostedProcessRole::InteractiveLogon, b"winlogon"),
    (nt_exe_image::HostedProcessRole::ServiceControlManager, b"services"),
    (nt_exe_image::HostedProcessRole::LocalSecurityAuthority, b"lsass"),
];

static NEXT_SAMPLE: AtomicU64 = AtomicU64::new(0);
static IN_FLIGHT: AtomicBool = AtomicBool::new(false);
static mut ROSTER: Option<StartupThreadSampleRoster<HostedThreadRole, 3>> = None;

struct InFlight;
impl Drop for InFlight {
    fn drop(&mut self) { IN_FLIGHT.store(false, Ordering::Release); }
}

pub(crate) fn maybe_sample(now_100ns: u64) {
    if IN_FLIGHT.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return;
    }
    let _in_flight = InFlight;
    let due = NEXT_SAMPLE.load(Ordering::Acquire);
    if now_100ns < due { return; }
    if NEXT_SAMPLE.compare_exchange(due, now_100ns.saturating_add(INTERVAL_100NS),
        Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
    unsafe {
        for (index, (role, label)) in ROLES.into_iter().enumerate() {
            sample_role(index, role, label, now_100ns);
        }
    }
}

unsafe fn sample_role(
    index: usize, role: nt_exe_image::HostedProcessRole, label: &[u8], now: u64,
) {
    let Ok(handler_ptr) = service_sec_image::registry_live_handler_pointer() else { return; };
    let (pi, binding, lifetime, object_wait, event_state) = {
        let handler = &*handler_ptr;
        let Some(pi) = service_sec_image::live_hosted_pi_for_observation_role(handler, role)
            else { return; };
        let Some((binding, lifetime)) = handler.hosted_main_thread_sample_owner(pi)
            else { return; };
        let object_wait = handler.capture_process_identity(pi).and_then(|process|
            object_wait::object_waiter_oldest_unselected_for_thread(
                pi, process, binding.tid, now));
        (pi, binding, lifetime, object_wait, handler.lsa_rpc_server_active_state())
    };
    let ordinal = {
        let roster = &mut *core::ptr::addr_of_mut!(ROSTER);
        if roster.is_none() {
            *roster = StartupThreadSampleRoster::new(INTERVAL_100NS, SAMPLES_PER_ROLE);
        }
        let Some(ordinal) = roster.as_mut().and_then(|roster|
            roster.claim(index, Some(binding), Some(lifetime), now)) else { return; };
        ordinal
    };

    // The register/debug reads use the executive IPC buffer; restore the received message.
    let _message = ipc_message::SavedMessageBuffer::capture();
    let mut regs = [0u64; 20];
    let valid = win32k_glue::tcb_read_regs20_checked(binding.tcb, &mut regs);
    let handler = &*handler_ptr;
    if handler.hosted_main_thread_sample_owner(pi) != Some((binding, lifetime))
        || service_sec_image::live_hosted_pi_for_observation_role(handler, role) != Some(pi)
    { return; }

    let process_generation = match binding.process.generation {
        nt_types::ProcessGeneration::Hosted(generation)
        | nt_types::ProcessGeneration::Temporary(generation) => generation,
    };
    print_str(b"[startup-readiness-sample] role="); print_str(label);
    print_str(b" n/t-ms/pi/pid/pgen/tid/tgen/tcb/wait-seq/object/age-ms/event-present/event-signaled/event-ever-set/srm-connected/regs-valid=");
    for (position, value) in [
        ordinal, now / 10_000, pi as u64, u64::from(binding.process.pid),
        process_generation, binding.tid, lifetime.generation(), binding.tcb,
        object_wait.map_or(0, |(sequence, _, _)| sequence),
        object_wait.map_or(0, |(_, object, _)| object),
        object_wait.map_or(0, |(_, _, age)| age / 10_000),
        u64::from(event_state.is_some()), u64::from(event_state.unwrap_or(false)),
        LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed),
        LSASS_SRM_CONNECTED.load(Ordering::Relaxed), u64::from(valid),
    ].into_iter().enumerate() {
        if position != 0 { print_str(b"/"); }
        print_u64(value);
    }
    if valid {
        print_str(b" rip=0x"); print_hex_u64(regs[0]);
        print_str(b" rsp=0x"); print_hex_u64(regs[1]);
    }
    print_str(b"\n");
    win32k_glue::trace_hosted_tcb_debug_state(b"startup-readiness-sample", binding.tcb, 0);
}
