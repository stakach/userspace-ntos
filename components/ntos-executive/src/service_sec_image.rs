//! `service_sec_image` — the per-process SEC_IMAGE demand-fault service loop.
//! Extracted verbatim from `main.rs` (pure reorg; no logic change).
#![allow(clippy::all)]
use crate::exec_handler::HostedCreatePublication;
use crate::fault_stack_diagnostics::read_fault_stack_word;
use crate::*;
use nt_user_host::hosted_return_target::HostedReturnTarget;

#[path = "executor/loop_state.rs"]
mod loop_state;
use loop_state::{Diag, Images, Ingress, LoopExit, LoopState, Message, Parks, Procs, Turn};
#[path = "executor/receive.rs"]
mod loop_receive;
#[path = "executor/flow.rs"]
mod loop_flow;
#[path = "executor/syscall.rs"]
mod loop_syscall;
use loop_syscall::{Syscall, SyscallOutcome};
use loop_flow::QueuedCallbackPark;
#[path = "executor/syscall_tail.rs"]
mod loop_syscall_tail;
#[path = "executor/admission.rs"]
mod loop_admission;
use loop_admission::Event;
#[path = "executor/syscall_nt.rs"]
mod loop_syscall_nt;
#[path = "executor/syscall_win32k.rs"]
mod loop_syscall_win32k;
#[path = "executor/native_call.rs"]
mod loop_native_call;
#[path = "executor/vm_fault.rs"]
mod loop_vm_fault;
#[path = "executor/exceptions.rs"]
mod loop_exceptions;
#[path = "executor/maintenance.rs"]
mod loop_maintenance;
use core::ops::ControlFlow;
#[path = "hosted_quiesce.rs"]
mod hosted_quiesce;
use hosted_quiesce::dump_all_hosted_thread_quiesce;

#[path = "component_continuation.rs"]
mod component_continuation;
use component_continuation::{HostedContinuationDestination, HostedNativeContinuation,
    PendingComponentDispatch, PendingNestedTerminalDispatch};
pub(crate) use component_continuation::{ComponentNativeContinuation, ComponentSuspensionCompletion};
#[path = "root_maintenance_owner.rs"]
pub(crate) mod root_maintenance_owner;
#[path = "root_ingress_owner.rs"]
pub(crate) mod root_ingress_owner;
#[path = "nested_restore_owner.rs"]
pub(crate) mod nested_restore_owner;

#[path = "bootstrap_wait_selftest.rs"]
pub(crate) mod bootstrap_wait_selftest;

#[path = "provider_wait_selection.rs"]
mod wait_selection;
#[path = "component_terminal.rs"]
mod component_terminal;
#[path = "component_resume.rs"]
pub(crate) mod component_resume;
#[path = "component_return.rs"]
mod component_return;
#[path = "component_callback_transfer.rs"]
mod component_callback_transfer;
#[path = "kernel_provider_activation.rs"]
pub(crate) mod kernel_provider_activation;
#[path = "synchronous_file_retry.rs"]
mod synchronous_file_retry;
#[path = "synchronous_file_wait.rs"]
mod synchronous_file_wait;
#[path = "synchronous_file_cancellation.rs"]
pub(crate) mod synchronous_file_cancellation;
#[path = "synchronous_file_apc.rs"]
mod synchronous_file_apc;
#[path = "pending_file_busy.rs"]
mod pending_file_busy;
#[path = "pending_file_delivery.rs"]
mod pending_file_delivery;
#[path = "file_dispatch_handoff.rs"]
mod file_dispatch_handoff;
#[path = "mounted_create_owner_trace.rs"]
pub(crate) mod mounted_create_owner_trace;
#[path = "mounted_read_owner_trace.rs"]
pub(crate) mod mounted_read_owner_trace;
#[path = "pending_pipe_read_trace.rs"]
pub(crate) mod pending_pipe_read_trace;
#[path = "mounted_read_lifetime_trace.rs"]
pub(crate) mod mounted_read_lifetime_trace;
#[path = "mounted_installer_file_trace.rs"]
pub(crate) mod mounted_installer_file_trace;
#[path = "native_process_time_census.rs"]
pub(crate) mod native_process_time_census;
#[path = "installer_child_span_census.rs"]
pub(crate) mod installer_child_span_census;
#[path = "inline_file_retirement.rs"]
pub(crate) mod inline_file_retirement;
#[path = "hosted_gui_client_info.rs"]
mod hosted_gui_client_info;
#[path = "provider_file_objects.rs"]
mod provider_file_objects;
pub(crate) use provider_file_objects::service_win32k_file_object_request;
#[path = "process_information_native.rs"]
mod process_information_native;
pub(crate) use process_information_native::service_win32k_process_query_request;

pub(crate) static FILE_IO_DELIVERY_RETRY_PENDING: AtomicBool = AtomicBool::new(false);
const PRIMARY_ALIAS_RETRY_DELAY_100NS: u64 = 10_000_000;
static PRIMARY_ALIAS_RETRY_DEADLINE: AtomicU64 = AtomicU64::new(u64::MAX);
static PRIMARY_ALIAS_RETRY_WAKE_PENDING: AtomicBool = AtomicBool::new(false);

pub(crate) fn primary_alias_retry_deadline() -> Option<u64> {
    let deadline = PRIMARY_ALIAS_RETRY_DEADLINE.load(Ordering::Acquire);
    (deadline != u64::MAX).then_some(deadline)
}

/// The timer owner only records demand. The service loop owns the exact TCB and
/// process generation and is the only place that may retry the native effect.
pub(crate) fn primary_alias_retry_wake_due(now: u64) -> u64 {
    let Some(deadline) = primary_alias_retry_deadline() else { return 0 };
    if now < deadline { return 0; }
    if PRIMARY_ALIAS_RETRY_DEADLINE.compare_exchange(
        deadline, u64::MAX, Ordering::AcqRel, Ordering::Acquire,
    ).is_err() { return 0; }
    PRIMARY_ALIAS_RETRY_WAKE_PENDING.store(true, Ordering::Release);
    1
}

#[cfg(not(feature = "mup-provider-kernel-only"))]
unsafe fn attempt_primary_alias_activation(
    handler: &mut ExecNtHandler,
    activation: &mut nt_hosted_runtime::PrimaryAliasActivation,
) {
    let owner = activation.owner();
    if !activation.ready(owner) { return; }
    if handler.hosted_process_generation(owner.process_index) != Some(owner.process_generation) {
        activation.fail_uncertain(owner);
        print_str(b"[debug-filter] primary owner changed before alias installation\n");
        return;
    }
    match hosted_debug_filter_process::install_hosted_user_alias(handler, owner.process_index) {
        Ok(()) => {
            let resume_error = handler.start_configured_initial_thread(owner.process_index, owner.tcb);
            if resume_error == nt_user_callback::STATUS_PENDING as u32
                && crate::exec_handler::initial_thread_creation::configured_retry_no_effect(
                    handler, owner.process_index, owner.tcb,
                ) {
                // A pre-entry Win32k shared-page refusal retained the exact configured plan.
                // The existing timer wakes this same owner after other page work can settle.
                let deadline = activation.fail_definitive(
                    owner, monotonic_time_100ns(), PRIMARY_ALIAS_RETRY_DELAY_100NS,
                ).expect("configured initial retry owns exact alias activation");
                PRIMARY_ALIAS_RETRY_DEADLINE.store(deadline, Ordering::Release);
                let _ = rearm_registered_delay_timer();
                return;
            }
            if resume_error != 0 {
                // Initial-thread creation can have entered native effects. Do not
                // replay it from a timer merely because it returned an error.
                activation.fail_uncertain(owner);
                print_str(b"[thread-life] primary resume after alias installation failed pi=");
                print_u64(owner.process_index as u64);
                print_str(b" error=");
                print_u64(u64::from(resume_error));
                print_str(b"\n");
                return;
            }
            activation.start(owner);
            if let Some(tid) = handler.pm_main_tid_for_pi(owner.process_index) {
                handler.observe_desktop_thread_activation(u64::from(tid));
            }
        }
        Err(error) if error.retained_uncertain => {
            activation.fail_uncertain(owner);
            print_str(b"[debug-filter] primary alias retained uncertain pi=");
            print_u64(owner.process_index as u64);
            print_str(b" status=0x");
            print_hex(error.status);
            print_str(b"\n");
        }
        Err(error) => {
            let now = monotonic_time_100ns();
            let deadline = activation.fail_definitive(
                owner, now, PRIMARY_ALIAS_RETRY_DELAY_100NS,
            ).expect("ready exact primary alias owner");
            PRIMARY_ALIAS_RETRY_DEADLINE.store(deadline, Ordering::Release);
            let rearm = rearm_registered_delay_timer();
            print_str(b"[debug-filter] primary alias retry pi=");
            print_u64(owner.process_index as u64);
            print_str(b" status=0x");
            print_hex(error.status);
            print_str(b" timer=");
            print_u64(rearm.owner_available() as u64);
            print_str(b"\n");
        }
    }
}

#[cfg(not(feature = "mup-provider-kernel-only"))]
unsafe fn service_primary_alias_retry(
    handler: &mut ExecNtHandler,
    activation: &mut nt_hosted_runtime::PrimaryAliasActivation,
) {
    if !PRIMARY_ALIAS_RETRY_WAKE_PENDING.swap(false, Ordering::AcqRel) { return; }
    let owner = activation.owner();
    if !activation.wake_due(owner, monotonic_time_100ns()) { return; }
    attempt_primary_alias_activation(handler, activation);
}
static FILE_IO_COMPLETION_TRACE: AtomicU64 = AtomicU64::new(0);
static PIPE_TRANSCEIVE_COMPLETION_TRACE: AtomicU64 = AtomicU64::new(0);
static mut FILE_IO_COPY_WORK: [u8; 4096] = [0; 4096];
static CALLBACK_MESSAGE_COMPLETION_TRACE: AtomicU64 = AtomicU64::new(0);
static WINLOGON_MESSAGE_TRACE: AtomicU64 = AtomicU64::new(0);
static CSRSS_RESUME_REPLIES: AtomicU64 = AtomicU64::new(0);
static CSRSS_POST_RESUME_TCB: AtomicU64 = AtomicU64::new(0);

/// Bounded boot diagnostic: sample the CSRSS main thread after its SB worker resume reply.
pub(crate) fn trace_csrss_post_resume_census(census: u64) {
    if census > 5 {
        return;
    }
    let tcb = CSRSS_POST_RESUME_TCB.load(Ordering::Relaxed);
    if tcb == 0 {
        return;
    }
    let mut regs = [0u64; 20];
    let valid = unsafe { crate::win32k_glue::tcb_read_regs20_checked(tcb, &mut regs) };
    print_str(b"[csrss-post-resume] census=");
    print_u64(census);
    print_str(b" tcb=0x");
    print_hex_u64(tcb);
    print_str(b" registers-valid=");
    print_u64(valid as u64);
    if valid {
        print_str(b" rip=0x");
        print_hex_u64(regs[0]);
        print_str(b" rsp=0x");
        print_hex_u64(regs[1]);
        print_str(b" rax=0x");
        print_hex_u64(regs[3]);
    }
    print_str(b"\n");
    unsafe { crate::win32k_glue::trace_hosted_tcb_debug_state(b"csrss-post-resume", tcb, 0) };
}

pub(crate) fn synchronous_file_retry_stats() -> (nt_io_manager::SynchronousFileRetryStats, u64, u64, u64) {
    let stats = unsafe { (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS)).retry_stats() };
    let (delivered, retired, failures) = synchronous_file_retry::counters();
    (stats, delivered, retired, failures)
}

pub(crate) const SEC_IMAGE_FAULT_CAP: u64 = 15000;
const SEC_IMAGE_PREFETCH_STEADY_PAGES: u64 = 16;
const SEC_IMAGE_PREFETCH_SOFT_PAGES: u64 = 8;
const SEC_IMAGE_PREFETCH_LOW_PAGES: u64 = 1;
const SEC_IMAGE_PREFETCH_SOFT_UNTYPED_MARGIN_BYTES: u64 = 64 * 1024 * 1024;
const SEC_IMAGE_PREFETCH_LOW_UNTYPED_MARGIN_BYTES: u64 = 32 * 1024 * 1024;
const SEC_IMAGE_PREFETCH_CRITICAL_UNTYPED_MARGIN_BYTES: u64 = 8 * 1024 * 1024;
const SEC_IMAGE_PREFETCH_SOFT_SLOT_HEADROOM: u64 = 96 * 1024;
const SEC_IMAGE_PREFETCH_LOW_SLOT_HEADROOM: u64 = 64 * 1024;
const SEC_IMAGE_PREFETCH_CRITICAL_SLOT_HEADROOM: u64 = 16 * 1024;
static SEC_IMAGE_PREFETCH_THROTTLE_LOGGED: AtomicU64 = AtomicU64::new(0);
pub(crate) static SEC_IMAGE_PRIVATE_PREFETCH_SKIPS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SEC_IMAGE_CLEAN_WRITECOPY_SHARED: AtomicU64 = AtomicU64::new(0);
pub(crate) static SEC_IMAGE_WRITECOPY_PRIVATE_LOADER_STATE: AtomicU64 = AtomicU64::new(0);
pub(crate) static SEC_IMAGE_WRITECOPY_PRIVATE_IAT: AtomicU64 = AtomicU64::new(0);
pub(crate) static SEC_IMAGE_WRITECOPY_PRIVATE_RELOC: AtomicU64 = AtomicU64::new(0);
pub(crate) static SEC_IMAGE_WRITECOPY_PRIVATE_COOKIE: AtomicU64 = AtomicU64::new(0);
pub(crate) static SEC_IMAGE_WRITECOPY_PRIVATE_TLS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SEC_IMAGE_WRITECOPY_PREDICATE_ERRORS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SEC_IMAGE_WRITECOPY_PREDICATE_IMPORT_ERRORS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SEC_IMAGE_WRITECOPY_PREDICATE_RELOC_ERRORS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SEC_IMAGE_WRITECOPY_PREDICATE_LOAD_CONFIG_ERRORS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SEC_IMAGE_WRITECOPY_PREDICATE_TLS_ERRORS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
struct SecImageForwardPolicy {
    pages: u64,
    private_neighbours: bool,
}
static GUI_CLIENTINFO_SEED_TRACE: AtomicU64 = AtomicU64::new(0);
static INTERACTIVE_SHELL_CREATE_WINDOW_ATTEMPT_MASK: AtomicU64 = AtomicU64::new(0);
static SHELL_LAUNCH_QUIESCE_DUMPED: AtomicU64 = AtomicU64::new(0);
static LSA_READINESS_QUIESCE_DUMPED: AtomicU64 = AtomicU64::new(0);
static SERVICES_START_QUIESCE_DUMPED: AtomicU64 = AtomicU64::new(0);
static HOT_HOSTED_QUIESCE_DUMPED: AtomicU64 = AtomicU64::new(0);
static PRE_USER_SHELL_QUIESCE_DEFER_TRACE: AtomicU64 = AtomicU64::new(0);
static SHELL_CHROME_QUIESCE_DEFER_TRACE: AtomicU64 = AtomicU64::new(0);
static HOSTED_IPC_QUIESCE_DEFER_TRACE: AtomicU64 = AtomicU64::new(0);
static GUI_MESSAGE_DIAG_N: AtomicU64 = AtomicU64::new(0);
static EXPLORER_FLUSH_ICACHE_TRACE: AtomicU64 = AtomicU64::new(0);
static EXPLORER_CALLBACK_SSN_TRACE: AtomicU64 = AtomicU64::new(0);
static INTERACTIVE_SYSCALL_CONTEXT_TRACE: AtomicU64 = AtomicU64::new(0);
static UNKNOWN_SYSCALL_TCB_RESTAGE_TRACE: AtomicU64 = AtomicU64::new(0);
static SERVICES_NQIP_TRACE: AtomicU64 = AtomicU64::new(0);
static LSASS_LISTENER_SSN_TRACE: AtomicU64 = AtomicU64::new(0);
static LSASS_LISTENER2_SSN_TRACE: AtomicU64 = AtomicU64::new(0);
static LSASS_LISTENER3_NATIVE_SSN_TRACE: AtomicU64 = AtomicU64::new(0);
static THREAD_TERM_ROOT_TCB_TRACE: AtomicU64 = AtomicU64::new(0);
static GENERIC_TP_WORKER_FAULT_TRACE: AtomicU64 = AtomicU64::new(0);
static GENERIC_SECTION_FAULT_TRACE: AtomicU64 = AtomicU64::new(0);
static PRIVATE_GUARD_PAGE_TRACE: AtomicU64 = AtomicU64::new(0);
static STACK_GROWTH_REPLY_TRACE: AtomicU64 = AtomicU64::new(0);
static GENERIC_SECTION_DIRTY_MARKS: AtomicU64 = AtomicU64::new(0);
static GENERIC_SECTION_WRITEBACKS: AtomicU64 = AtomicU64::new(0);
static GENERIC_SECTION_WRITEBACK_BYTES: AtomicU64 = AtomicU64::new(0);
static GENERIC_SECTION_WRITEBACK_FAILS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_DEFERRED_RETURNS_PARKED: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_DEFERRED_RETURNS_WOKEN: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_DEFERRED_RETURNS_FULL: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_DEFERRED_RETURNS_TRACE: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_QUIESCE_DEFER_TRACE: AtomicU64 = AtomicU64::new(0);
static WIN32K_CONTEXT_IMPORT_TRACE: AtomicU64 = AtomicU64::new(0);
static LPC_RECEIVE_WAIT_PARKED: AtomicU64 = AtomicU64::new(0);
static LPC_RECEIVE_WAIT_WOKEN: AtomicU64 = AtomicU64::new(0);
static LPC_RECEIVE_WAIT_REDRIVES: AtomicU64 = AtomicU64::new(0);
static LPC_RECEIVE_WAIT_FAILURES: AtomicU64 = AtomicU64::new(0);
static LPC_CONNECT_WAIT_PARKED: AtomicU64 = AtomicU64::new(0);
static LPC_CONNECT_WAIT_WOKEN: AtomicU64 = AtomicU64::new(0);
static LPC_CONNECT_WAIT_FAILURES: AtomicU64 = AtomicU64::new(0);
static LPC_REQUEST_WAIT_PARKED: AtomicU64 = AtomicU64::new(0);
static LPC_REQUEST_WAIT_WOKEN: AtomicU64 = AtomicU64::new(0);
static LPC_REQUEST_WAIT_REDRIVES: AtomicU64 = AtomicU64::new(0);
static LPC_REQUEST_WAIT_FAILURES: AtomicU64 = AtomicU64::new(0);
static USERCONNECT_COPY_FAILURES: AtomicU64 = AtomicU64::new(0);
static WIN32K_MSG_COPY_FAILURES: AtomicU64 = AtomicU64::new(0);
static BUILD_HWND_LIST_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static GET_ICON_INFO_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static CREATE_BITMAP_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static CREATE_DIB_SECTION_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static CREATE_DIBITMAP_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static TEXT_METRICS_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static TEXT_EXTENT_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static CHAR_WIDTH_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static OPEN_DCW_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static LOAD_KEYBOARD_LAYOUT_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static MESSAGE_CALL_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static SET_WINDOW_POS_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static DEFER_WINDOW_POS_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static GET_ATOM_NAME_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static SESSION_ATOM_NAME_SERVE_TRACE: AtomicU64 = AtomicU64::new(0);
static SESSION_BUILTIN_CLASS_SERVE_TRACE: AtomicU64 = AtomicU64::new(0);
static DEF_SET_TEXT_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static SET_CURSOR_ICON_DATA_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static STRETCH_DIBITS_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static FIND_CURSOR_ICON_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static CURSOR_LOOKUP_OWNER_TRACE: AtomicU64 = AtomicU64::new(0);
static CURSOR_LOOKUP_LAST_INCOMPLETE_DISPATCH: AtomicU64 = AtomicU64::new(0);
static CURSOR_LOOKUP_LAST_INCOMPLETE_LANE_INDEX: AtomicU64 = AtomicU64::new(0);
static CURSOR_LOOKUP_LAST_INCOMPLETE_LANE_GENERATION: AtomicU64 = AtomicU64::new(0);

pub(crate) fn cursor_lookup_last_incomplete() -> Option<(u64, nt_component_suspension::LaneHandle)> {
    let dispatch = CURSOR_LOOKUP_LAST_INCOMPLETE_DISPATCH.load(Ordering::Relaxed);
    (dispatch != 0).then_some((dispatch, nt_component_suspension::LaneHandle {
        index: CURSOR_LOOKUP_LAST_INCOMPLETE_LANE_INDEX.load(Ordering::Relaxed) as u32,
        generation: CURSOR_LOOKUP_LAST_INCOMPLETE_LANE_GENERATION.load(Ordering::Relaxed),
    }))
}

/// Log copied pump flags before its completion moves into an exact pending owner.
/// This may run at an isolated provider boundary, so it never reads CALLS.
pub(crate) fn trace_cursor_lookup_pump(
    client: win32k_glue::Win32kClientContext,
    ssn: u64,
    dispatch_id: u64,
    lane: nt_component_suspension::LaneHandle,
    flags: u16,
) {
    if ssn != 0x103d
        || CURSOR_LOOKUP_OWNER_TRACE.fetch_add(1, Ordering::Relaxed) >= 4096
    {
        return;
    }
    use core::fmt::Write;
    let mut record = nt_printf::record::RecordBuffer::<384>::new();
    let _ = writeln!(record,
        "[cursor-lookup-pump] pi/pid/gen/tid/tcb={}/{}/{}/{}/{} dispatch={} lane={:?} flags=0x{:03x} bits=complete/callback/provider/lpc/receive/root/service/maintenance/nested/quarantine",
        client.pi, client.pid, client.generation, client.tid, client.tcb,
        dispatch_id, lane, flags);
    sel4_rt::print_record(record.bytes());
}

/// Bounded root-side trace of one original Call across GUI staging and provider entry.
/// Neither the copied key nor the numeric Reply authorizes a settlement.
pub(crate) unsafe fn trace_cursor_lookup_owner(
    stage: &str,
    client: win32k_glue::Win32kClientContext,
    ssn: u64,
    dispatch_id: u64,
    lane: Option<nt_component_suspension::LaneHandle>,
    entered: bool,
    not_completed: bool,
    callback_suspended: bool,
) {
    if ssn != 0x103d {
        return;
    }
    if stage == "provider-return" && not_completed {
        if let Some(lane) = lane {
            CURSOR_LOOKUP_LAST_INCOMPLETE_LANE_INDEX.store(u64::from(lane.index), Ordering::Relaxed);
            CURSOR_LOOKUP_LAST_INCOMPLETE_LANE_GENERATION.store(lane.generation, Ordering::Relaxed);
        }
        CURSOR_LOOKUP_LAST_INCOMPLETE_DISPATCH.store(dispatch_id, Ordering::Relaxed);
    }
    if CURSOR_LOOKUP_OWNER_TRACE.fetch_add(1, Ordering::Relaxed) >= 4096 {
        return;
    }
    use core::fmt::Write;
    let key = crate::spawn_hosts::shared_ingress::owner::runtime::observed_win32k_call_for_client(
        client, ssn,
    );
    let mut record = nt_printf::record::RecordBuffer::<512>::new();
    let _ = writeln!(record,
        "[cursor-lookup-owner] stage={} pi/pid/gen/tid/badge/tcb={}/{}/{}/{}/{}/{} original-tcb/seq/reply={:?} dispatch={} lane={:?} entered={} not-completed={} callback-suspended={}",
        stage, client.pi, client.pid, client.generation, client.tid, client.badge, client.tcb,
        key, dispatch_id, lane, u8::from(entered), u8::from(not_completed),
        u8::from(callback_suspended));
    sel4_rt::print_record(record.bytes());
}

/// The provider entry boundary may be nested: log copied dispatch metadata only.
/// CALLS is root owned and must never be scanned from the isolated provider pump.
pub(crate) fn trace_cursor_lookup_lane(
    stage: &str,
    client: win32k_glue::Win32kClientContext,
    ssn: u64,
    dispatch_id: u64,
    lane: nt_component_suspension::LaneHandle,
) {
    if ssn != 0x103d
        || CURSOR_LOOKUP_OWNER_TRACE.fetch_add(1, Ordering::Relaxed) >= 4096
    {
        return;
    }
    use core::fmt::Write;
    let mut record = nt_printf::record::RecordBuffer::<512>::new();
    let _ = writeln!(record,
        "[cursor-lookup-owner] stage={} pi/pid/gen/tid/badge/tcb={}/{}/{}/{}/{}/{} dispatch={} lane={:?} original-key=root-only",
        stage, client.pi, client.pid, client.generation, client.tid, client.badge, client.tcb,
        dispatch_id, lane);
    sel4_rt::print_record(record.bytes());
}
static SESSION_CURSOR_SERVE_TRACE: AtomicU64 = AtomicU64::new(0);
static EXT_TEXT_OUT_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static PAINTSTRUCT_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static USER_RECT_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static NTUSER_CALL_ONE_PARAM_TRACE: AtomicU64 = AtomicU64::new(0);
static mut SERVICE_SSN_RING_WORK: [u16; 32] = [0; 32];
static mut SERVICE_SSN_RING_BADGE_WORK: [u8; 32] = [0; 32];
static mut SERVICE_WL_RING_WORK: [u16; 48] = [0; 48];
static mut SERVICE_PROCS_WORK: alloc::vec::Vec<ProcExec> = alloc::vec::Vec::new();
#[path = "component_receive_vspace.rs"]
pub(crate) mod receive_vspace;
static SERVICE_PROCS_ALLOCATION_FAILURES: AtomicU64 = AtomicU64::new(0);
static mut SERVICE_EXE_IMAGES_WORK: nt_exe_image::ImageTable<HOSTED_PROCESS_IMAGE_CAP> =
    nt_exe_image::ImageTable::new();
static mut SERVICE_EXE_IMAGE_CATALOG_WORK: nt_exe_image::OwnedHostedImageCatalog<
    HOSTED_PROCESS_IMAGE_CAP,
> = nt_exe_image::OwnedHostedImageCatalog::new();
static mut SERVICE_HOSTED_LOADED_IMAGES_WORK: HostedLoadedImageTable =
    HostedLoadedImageTable::new();
static mut SERVICE_GENERIC_SECTIONS_WORK: GenericSectionTable = GenericSectionTable::new();
static SERVICE_GENERIC_SECTIONS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static BOOTSTRAP_SECTION_OWNER_ACTIVE: AtomicBool = AtomicBool::new(false);
static mut SERVICE_DELAY_QUEUE_WORK: Option<nt_delay_execution::Queue> = None;
static SERVICE_DELAY_DRAIN_HANDLER: AtomicU64 = AtomicU64::new(0);
static SERVICE_DELAY_DRAIN_QUEUE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
struct ComponentCallbackTransfer {
    token: u64,
    context: win32k_glue::StagedUserCallbackContext,
}

/// A running callback's nested syscall transfers only its active external token. The staged
/// context belongs to a *completed* NtCallbackReturn and is never inferred from that token.
#[derive(Clone, Copy)]
enum NestedWaitTransfer {
    None,
    CallbackReturn(ComponentCallbackTransfer),
    InCallback { lane: nt_component_suspension::LaneHandle, token: u64 },
}

impl NestedWaitTransfer {
    fn from_completed(transfer: Option<ComponentCallbackTransfer>) -> Self {
        transfer.map(Self::CallbackReturn).unwrap_or(Self::None)
    }

    fn token(self) -> Option<u64> {
        match self {
            Self::None => None,
            Self::CallbackReturn(transfer) => Some(transfer.token),
            Self::InCallback { token, .. } => Some(token),
        }
    }

    fn context(self) -> Option<win32k_glue::StagedUserCallbackContext> {
        match self {
            Self::CallbackReturn(transfer) => Some(transfer.context),
            Self::None | Self::InCallback { .. } => None,
        }
    }

    unsafe fn admits(self, client: win32k_glue::Win32kClientContext,
        lane: nt_component_suspension::LaneHandle) -> bool
    {
        match self {
            Self::None => true,
            Self::CallbackReturn(transfer) => transfer.token != 0,
            Self::InCallback { lane: captured, token } => captured == lane
                && win32k_glue::in_callback_nested_wait_token_is_current(
                    client, captured, token,
                )
                && (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
                    .external_top(lane).ok().flatten() == Some(token),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RetainedWaitAdmission {
    Accepted,
    RefusedNoEffect,
    Indeterminate,
}

const COMPONENT_SUSPENSION_MAX_DEPTH: usize = 64;
const COMPONENT_EXECUTION_LANE_CAPACITY: usize = 256;
static mut PROVIDER_WAIT_ARBITER: nt_provider_wait::ProviderDispatcherWaitArbiter<
    crate::exec_handler::ProviderDispatcherLease,
> = nt_provider_wait::ProviderDispatcherWaitArbiter::new();
pub(crate) type ComponentLanes = nt_component_suspension::ComponentSuspensionLanes<
    ComponentNativeContinuation,
    ComponentSuspensionCompletion,
    component_terminal::NativeTerminal,
>;
pub(crate) static mut COMPONENT_SUSPENSIONS: ComponentLanes = nt_component_suspension::ComponentSuspensionLanes::new(
    COMPONENT_EXECUTION_LANE_CAPACITY,
    COMPONENT_SUSPENSION_MAX_DEPTH,
);

/// Copy the exact lane's retained frames before writing a one-time stall trace. These numeric
/// observations cannot select, complete, or recycle any continuation or physical Reply.
pub(crate) unsafe fn trace_stale_suspension_frames(lane_index: u64, lane_generation: u64) {
    const CAP: usize = 16;
    let mut rows = [[0u64; 19]; CAP];
    let mut mutant_objects: [Option<(nt_provider_wait::ProviderDomainIdentity, nt_provider_wait::ProviderWaitObject)>; CAP] = [None; CAP];
    let mut count = 0usize;
    let mut overflow = 0u64;
    {
        let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
        let arbiter = &*core::ptr::addr_of!(PROVIDER_WAIT_ARBITER);
        for (lane, frame) in lanes.frames() {
            if lane.index as u64 != lane_index || lane.generation != lane_generation {
                continue;
            }
            if count == CAP { overflow += 1; continue; }
            let client = frame.owner.hosted_client();
            let phase = match &frame.phase {
                nt_component_suspension::SuspensionPhase::Waiting => 1,
                nt_component_suspension::SuspensionPhase::Selected { .. } => 2,
                nt_component_suspension::SuspensionPhase::Resuming { .. } => 3,
                nt_component_suspension::SuspensionPhase::ResumingChildParked { .. } => 9,
                nt_component_suspension::SuspensionPhase::ResumingChildQuarantined { .. } => 10,
                nt_component_suspension::SuspensionPhase::Cancelled { .. } => 4,
                nt_component_suspension::SuspensionPhase::MaintenanceWaiting { .. } => 5,
                nt_component_suspension::SuspensionPhase::MaintenanceReady { .. } => 6,
                nt_component_suspension::SuspensionPhase::MaintenanceResuming { .. } => 7,
                nt_component_suspension::SuspensionPhase::NestedTerminal => 8,
            };
            let no_wait_details = [0u64; 7];
            let (pending_kind, wait_id, pending_dispatch, pending_ssn, admitted, wait_details) =
                match frame.continuation.hosted().map(|hosted| &hosted.pending) {
                    Some(component_continuation::PendingComponentDispatch::Provider(pending)) => {
                        let first = (pending.request.header.object_count != 0)
                            .then(|| pending.request.objects.first()).flatten();
                        if let Some(object) = first.filter(|object| object.object_type == nt_provider_wait::ProviderWaitObjectType::Mutant as u32) {
                            mutant_objects[count] = Some((nt_provider_wait::ProviderDomainIdentity {
                                domain: pending.request.header.provider_domain,
                                generation: pending.request.header.provider_generation,
                            }, *object));
                        }
                        (1, pending.request.header.wait_id, pending.dispatch.dispatch_id,
                            pending.dispatch.ssn, arbiter.contains(pending.request.header.wait_id) as u64,
                            [pending.request.header.wait_type as u64,
                                pending.request.header.timeout_kind as u64,
                                pending.request.header.timeout_100ns as u64,
                                pending.request.header.object_count as u64,
                                first.map_or(0, |object| object.object_type as u64),
                                first.map_or(0, |object| object.object_id),
                                first.map_or(0, |object| object.object_generation)])
                    },
                    Some(component_continuation::PendingComponentDispatch::Lpc(pending)) =>
                        (2, 0, pending.dispatch.dispatch_id, pending.dispatch.ssn, 0, no_wait_details),
                    Some(component_continuation::PendingComponentDispatch::Receive(pending)) =>
                        (3, 0, pending.snapshot.dispatch.dispatch_id, pending.snapshot.dispatch.ssn, 0, no_wait_details),
                    Some(component_continuation::PendingComponentDispatch::ServiceWait(pending)) =>
                        (4, 0, pending.snapshot.dispatch.dispatch_id, pending.snapshot.dispatch.ssn, 0, no_wait_details),
                    Some(component_continuation::PendingComponentDispatch::RootMaintenance(pending)) =>
                        (5, 0, pending.snapshot.dispatch.dispatch_id, pending.snapshot.dispatch.ssn, 0, no_wait_details),
                    Some(component_continuation::PendingComponentDispatch::NestedRestore(_)) =>
                        (6, 0, 0, 0, 0, no_wait_details),
                    None => (7, 0, 0, 0, 0, no_wait_details),
                };
            rows[count][..12].copy_from_slice(&[
                frame.key.kind as u64, frame.key.id, frame.admission_sequence, phase,
                frame.owner.dispatch_id, client.map_or(0, |row| row.client_pi as u64),
                client.map_or(0, |row| row.client_tid), pending_kind, wait_id,
                pending_dispatch, pending_ssn, admitted,
            ]);
            rows[count][12..].copy_from_slice(&wait_details);
            count += 1;
        }
    }
    for (index, row) in rows[..count].iter().enumerate() {
        print_str(b"[pump-stale-suspension] kind/id/admission/phase/owner-dispatch/pi/tid/pending-kind/wait-id/pending-dispatch/ssn/arbiter/wait-type/timeout-kind/timeout-raw-100ns/object-count/first-type/first-id/first-generation=");
        print_u64(row[0]);
        for value in &row[1..] { print_str(b"/"); print_u64(*value); }
        print_str(b"\n");
        if let Some((provider, object)) = mutant_objects[index] {
            print_str(b"[pump-stale-mutant] provider-domain/generation/object-id/generation/flags/wait-id=");
            print_u64(provider.domain); print_str(b"/"); print_u64(provider.generation);
            print_str(b"/"); print_u64(object.object_id);
            print_str(b"/"); print_u64(object.object_generation);
            print_str(b"/"); print_u64(object.flags as u64);
            print_str(b"/"); print_u64(row[8]);
            if let Some(snapshot) = crate::provider_dispatcher_backend::snapshot_sync_for_stale_trace(provider, object) {
                print_str(b" canonical-generation/local-id/body/signal-state/wait-leases/storage-offset=");
                print_u64(snapshot.canonical.map_or(0, |canonical| canonical.object_generation));
                print_str(b"/"); print_u64(snapshot.id.raw());
                print_str(b"/"); print_hex_u64(snapshot.body);
                print_str(b"/");
                if snapshot.signal_state < 0 { print_str(b"-"); }
                print_u64(snapshot.signal_state.unsigned_abs() as u64);
                print_str(b"/"); print_u64(snapshot.wait_leases as u64);
                print_str(b"/"); print_u64(snapshot.storage.offset);
                match snapshot.storage.backing {
                    nt_provider_wait::ProviderEventBacking::Static { instance_generation } => {
                        print_str(b" storage=static/"); print_u64(instance_generation);
                    }
                    nt_provider_wait::ProviderEventBacking::Allocation { arena_id, arena_generation, allocation_id, allocation_generation } => {
                        print_str(b" storage=allocation/"); print_u64(arena_id);
                        print_str(b"/"); print_u64(arena_generation);
                        print_str(b"/"); print_u64(allocation_id);
                        print_str(b"/"); print_u64(allocation_generation);
                    }
                    nt_provider_wait::ProviderEventBacking::Stack { lane_id, lane_generation, dispatch_id, activation_generation } => {
                        print_str(b" storage=stack/"); print_u64(lane_id);
                        print_str(b"/"); print_u64(lane_generation);
                        print_str(b"/"); print_u64(dispatch_id);
                        print_str(b"/"); print_u64(activation_generation);
                    }
                }
                match snapshot.mutant_owner {
                    Some(nt_component_suspension::SuspensionCaller::Hosted(holder)) => {
                        print_str(b" holder=hosted/"); print_u64(holder.client_pi as u64);
                        print_str(b"/"); print_u64(holder.client_generation);
                        print_str(b"/"); print_u64(holder.client_tid);
                        print_str(b"/"); print_u64(holder.client_badge);
                    }
                    Some(nt_component_suspension::SuspensionCaller::Kernel { lane }) => {
                        print_str(b" holder=kernel/"); print_u64(lane.index as u64);
                        print_str(b"/"); print_u64(lane.generation);
                    }
                    None => print_str(b" holder=none"),
                }
            } else {
                print_str(b" snapshot=absent");
            }
            print_str(b"\n");
        }
    }
    if overflow != 0 {
        print_str(b"[pump-stale-suspension] overflow=");
        print_u64(overflow);
        print_str(b"\n");
    }
}

// Advances only after the independent outer worker has returned. A parked native syscall
// captures this epoch; timer notification alone cannot authorize its resume.
static ROOT_MAINTENANCE_PASS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn root_maintenance_pass() -> u64 {
    ROOT_MAINTENANCE_PASS.load(Ordering::Acquire)
}

/// Identify a startup completion's protocol shape without changing its retained owner.
pub(crate) unsafe fn component_execution_lane_is_starting(
    lane: nt_component_suspension::LaneHandle,
) -> bool {
    let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
    lanes.running() == Some(lane)
        && lanes.phase(lane) == Ok(nt_component_suspension::LanePhase::Starting)
}

pub(crate) unsafe fn component_execution_lane_binding(
    lane: nt_component_suspension::LaneHandle,
) -> Option<nt_component_suspension::LaneBinding> {
    (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .binding(lane)
        .ok()
}

/// Current transport snapshot only. Admission still requires the retained activation, physical
/// provider lifetime and phase-specific owner; a copied caller cannot authorize execution.
pub(crate) unsafe fn kernel_provider_current_binding(
    caller: nt_user_host::provider_kernel_activation::KernelProviderCaller,
) -> Result<nt_component_suspension::LaneBinding, u32> {
    caller.current_binding(&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
}

fn component_execution_lane_reply(
    lanes: &nt_component_suspension::ComponentSuspensionLanes<
        ComponentNativeContinuation,
        ComponentSuspensionCompletion,
        component_terminal::NativeTerminal,
    >,
    lane: nt_component_suspension::LaneHandle,
) -> Option<u64> {
    lanes.binding(lane).ok().map(|binding| binding.reply_object)
}

pub(crate) unsafe fn component_execution_dispatch_identity(
    lane: nt_component_suspension::LaneHandle,
) -> Option<nt_component_suspension::LaneDispatchIdentity> {
    (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .active_dispatch_identity(lane)
        .ok()
        .flatten()
}

pub(crate) unsafe fn component_execution_lane_is_idle(
    lane: nt_component_suspension::LaneHandle,
) -> bool {
    (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).phase(lane)
        == Ok(nt_component_suspension::LanePhase::Idle)
}

/// Read-only canonical phase for physical-lane admission diagnostics.
pub(crate) unsafe fn component_execution_lane_phase(
    lane: nt_component_suspension::LaneHandle,
) -> Option<nt_component_suspension::LanePhase> {
    (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).phase(lane).ok()
}

pub(crate) unsafe fn component_execution_lane_is_running(
    lane: nt_component_suspension::LaneHandle,
) -> bool {
    (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).phase(lane)
        == Ok(nt_component_suspension::LanePhase::Running)
}

pub(crate) unsafe fn component_execution_lane_can_grow() -> bool {
    (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).can_add_lane()
}

pub(crate) unsafe fn component_execution_is_busy() -> bool {
    (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).execution_busy()
}

pub(crate) unsafe fn component_shared_publication_is_busy() -> bool {
    (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).fresh_dispatch_busy()
}

pub(crate) unsafe fn component_has_retained_terminal() -> bool {
    (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .terminal_identities()
        .next()
        .is_some()
}

pub(crate) unsafe fn resume_external_component_execution_lane(
    lane: nt_component_suspension::LaneHandle,
    token: u64,
) -> bool {
    let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
    let Some(reply_object) = component_execution_lane_reply(lanes, lane) else {
        return false;
    };
    lanes.resume_external(lane, reply_object, token).is_ok()
}

pub(crate) unsafe fn component_external_resume_ready(
    lane: nt_component_suspension::LaneHandle,
    token: u64,
) -> bool {
    let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
    let Some(reply_object) = component_execution_lane_reply(lanes, lane) else {
        return false;
    };
    lanes.can_resume_external(lane, reply_object, token) == Ok(true)
}

pub(crate) unsafe fn suspend_component_execution_lane_for_callback(
    lane: nt_component_suspension::LaneHandle,
    token: u64,
) -> bool {
    let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
    let Some(reply_object) = component_execution_lane_reply(lanes, lane) else {
        return false;
    };
    lanes.suspend_running(lane, reply_object, token).is_ok()
}

pub(crate) unsafe fn repark_external_component_execution_lane(
    lane: nt_component_suspension::LaneHandle,
    token: u64,
) -> bool {
    let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
    let Some(reply_object) = component_execution_lane_reply(lanes, lane) else {
        return false;
    };
    lanes.repark_external(lane, reply_object, token).is_ok()
}

pub(crate) unsafe fn complete_external_component_execution_lane(
    lane: nt_component_suspension::LaneHandle,
    token: u64,
) -> bool {
    let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
    let Some(reply_object) = component_execution_lane_reply(lanes, lane) else {
        return false;
    };
    let completed = lanes.complete_external(lane, reply_object, token).is_ok();
    if completed {
        crate::driver_launch::win32k_device_properties::retire_completed_transfers();
    }
    completed
}

/// Retire only a final callback token, preserving the dispatch for shared transport completion.
/// False leaves nested ownership unchanged so the caller can adopt the returned Call before
/// completing the token through the ordinary suspension-preserving transition.
pub(crate) unsafe fn retire_external_component_execution_lane(
    lane: nt_component_suspension::LaneHandle,
    token: u64,
) -> Result<bool, ()> {
    let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
    let reply = component_execution_lane_reply(lanes, lane).ok_or(())?;
    if lanes.phase(lane) != Ok(nt_component_suspension::LanePhase::Running)
        || lanes.running() != Some(lane)
        || lanes.external_top(lane) != Ok(Some(token))
    {
        return Err(());
    }
    if lanes.external_depth(lane).map_err(|_| ())? != 1
        || lanes.suspension_count(lane).map_err(|_| ())? != 0
    {
        return Ok(false);
    }
    lanes.retire_external_running(lane, reply, token).map_err(|_| ())?;
    Ok(true)
}

pub(crate) unsafe fn replace_external_component_execution_lane(
    lane: nt_component_suspension::LaneHandle,
    completed_token: u64,
    next_token: u64,
) -> bool {
    let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
    let Some(reply_object) = component_execution_lane_reply(lanes, lane) else {
        return false;
    };
    lanes
        .replace_external_running(lane, reply_object, completed_token, next_token)
        .is_ok()
}

static PROVIDER_WAIT_DISPATCH_ADMISSIONS: AtomicU64 = AtomicU64::new(0);
static COMPONENT_WAIT_DISPATCH_ADMISSIONS: AtomicU64 = AtomicU64::new(0);
static PROVIDER_WAIT_PARKED_ADMISSIONS: AtomicU64 = AtomicU64::new(0);
static PROVIDER_WAIT_RESUMES: AtomicU64 = AtomicU64::new(0);
static PROVIDER_WAIT_SUCCESSFUL_RESUMES: AtomicU64 = AtomicU64::new(0);
static PROVIDER_WAIT_REARMS: AtomicU64 = AtomicU64::new(0);
static PROVIDER_WAIT_DISPATCH_COMPLETIONS: AtomicU64 = AtomicU64::new(0);
static COMPONENT_WAIT_DISPATCH_COMPLETIONS: AtomicU64 = AtomicU64::new(0);
static PROVIDER_WAIT_CANCELLATIONS: AtomicU64 = AtomicU64::new(0);
static PROVIDER_WAIT_NATIVE_REPLIES_ABANDONED: AtomicU64 = AtomicU64::new(0);
static PROVIDER_WAIT_DISPATCHER_LEASES_ACQUIRED: AtomicU64 = AtomicU64::new(0);
static PROVIDER_WAIT_DISPATCHER_LEASES_RELEASED: AtomicU64 = AtomicU64::new(0);
static PROVIDER_WAIT_ADMISSION_TRACE_N: AtomicU64 = AtomicU64::new(0);
static SERVICE_DELAY_NESTED_DRAINS: AtomicU64 = AtomicU64::new(0);
static SERVICE_CRASH_PARKED_MASK: AtomicU64 = AtomicU64::new(0);
static WATCHDOG_RUNNABLE_DEFER_TRACE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub(crate) struct ProviderWaitRuntimeStats {
    pub dispatch_admissions: u64,
    pub component_dispatch_admissions: u64,
    pub parked_admissions: u64,
    pub resumes: u64,
    pub successful_resumes: u64,
    pub rearms: u64,
    pub dispatch_completions: u64,
    pub component_dispatch_completions: u64,
    pub cancellations: u64,
    pub native_replies_abandoned: u64,
    pub dispatcher_leases_acquired: u64,
    pub dispatcher_leases_released: u64,
    pub active_continuations: usize,
    pub active_component_continuations: usize,
    pub active_waiters: usize,
    pub active_dispatcher_leases: usize,
    pub terminal: component_terminal::Stats,
}

pub(crate) fn provider_wait_record_dispatcher_lease_acquired() {
    PROVIDER_WAIT_DISPATCHER_LEASES_ACQUIRED.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn provider_wait_record_dispatcher_lease_released() {
    PROVIDER_WAIT_DISPATCHER_LEASES_RELEASED.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn provider_wait_runtime_stats() -> ProviderWaitRuntimeStats {
    unsafe {
        ProviderWaitRuntimeStats {
            dispatch_admissions: PROVIDER_WAIT_DISPATCH_ADMISSIONS.load(Ordering::Relaxed),
            component_dispatch_admissions: COMPONENT_WAIT_DISPATCH_ADMISSIONS
                .load(Ordering::Relaxed),
            parked_admissions: PROVIDER_WAIT_PARKED_ADMISSIONS.load(Ordering::Relaxed),
            resumes: PROVIDER_WAIT_RESUMES.load(Ordering::Relaxed),
            successful_resumes: PROVIDER_WAIT_SUCCESSFUL_RESUMES.load(Ordering::Relaxed),
            rearms: PROVIDER_WAIT_REARMS.load(Ordering::Relaxed),
            dispatch_completions: PROVIDER_WAIT_DISPATCH_COMPLETIONS.load(Ordering::Relaxed),
            component_dispatch_completions: COMPONENT_WAIT_DISPATCH_COMPLETIONS
                .load(Ordering::Relaxed),
            cancellations: PROVIDER_WAIT_CANCELLATIONS.load(Ordering::Relaxed),
            native_replies_abandoned: PROVIDER_WAIT_NATIVE_REPLIES_ABANDONED
                .load(Ordering::Relaxed),
            dispatcher_leases_acquired: PROVIDER_WAIT_DISPATCHER_LEASES_ACQUIRED.load(Ordering::Relaxed),
            dispatcher_leases_released: PROVIDER_WAIT_DISPATCHER_LEASES_RELEASED.load(Ordering::Relaxed),
            active_continuations: (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
                .frames()
                .filter(|(_, frame)| {
                    match frame.continuation {
                        ComponentNativeContinuation::Hosted(hosted) => {
                            matches!(hosted.pending, PendingComponentDispatch::Provider(_))
                        }
                        ComponentNativeContinuation::Kernel(_) => true,
                        ComponentNativeContinuation::RootIngress(_) => false,
                    }
                })
                .count(),
            active_component_continuations: (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
                .total_suspensions(),
            active_waiters: (&*core::ptr::addr_of!(PROVIDER_WAIT_ARBITER)).len(),
            active_dispatcher_leases: (&*core::ptr::addr_of!(PROVIDER_WAIT_ARBITER)).lease_count(),
            terminal: component_terminal::stats(),
        }
    }
}

fn trace_stack_growth_reply(
    pi: usize,
    old_badge: u64,
    new_badge: u64,
    msginfo: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) {
    if STACK_GROWTH_REPLY_TRACE.fetch_add(1, Ordering::Relaxed) >= 32 {
        return;
    }
    print_str(b"[stack-growth-reply] pi=");
    print_u64(pi as u64);
    print_str(b" old-badge=");
    print_u64(old_badge);
    print_str(b" new-badge=");
    print_u64(new_badge);
    print_str(b" mi=0x");
    print_hex((msginfo >> 32) as u32);
    print_hex(msginfo as u32);
    print_str(b" m0=0x");
    print_hex((mr0 >> 32) as u32);
    print_hex(mr0 as u32);
    print_str(b" m1=0x");
    print_hex((mr1 >> 32) as u32);
    print_hex(mr1 as u32);
    print_str(b" m2=0x");
    print_hex((mr2 >> 32) as u32);
    print_hex(mr2 as u32);
    print_str(b" m3=0x");
    print_hex((mr3 >> 32) as u32);
    print_hex(mr3 as u32);
    print_str(b"\n");
}

static mut SERVICE_DLL_PE_STORE_WORK: DllPeStore = DllPeStore::new();

const WIN32K_MSG_BYTES: usize = 48;
const WIN32K_BUILD_HWND_LIST_STAGE_BYTES: usize = 0x1000;
const WIN32K_BUILD_HWND_LIST_COUNT_OFFSET: u64 = 0x0ff0;
const WIN32K_BUILD_HWND_LIST_MAX_HANDLES: u64 = WIN32K_BUILD_HWND_LIST_COUNT_OFFSET / 8;
const WIN32K_CREATE_BITMAP_STAGE_BYTES: usize = 0x4000;
const WIN32K_TEXT_METRICS_STAGE_BYTES: usize = 68;
const WIN32K_TEXT_EXTENT_STAGE_BYTES: usize = 0x4000;
const WIN32K_CHAR_WIDTH_STAGE_BYTES: usize = 0x4000;
const WIN32K_PAINTSTRUCT_STAGE_BYTES: usize = 72;
const WIN32K_RECT_STAGE_BYTES: usize = 16;
const NTGDI_BIT_BLT_SSN: u64 = 0x1008;
const NTUSER_INVALIDATE_RECT_SSN: u64 = 0x1004;
const NTUSER_REDRAW_WINDOW_SSN: u64 = 0x1012;
const NTUSER_BEGIN_PAINT_SSN: u64 = 0x1016;
const NTUSER_END_PAINT_SSN: u64 = 0x1018;
const NTUSER_MESSAGE_CALL_SSN: u64 = 0x1007;
const NTUSER_SET_WINDOW_POS_SSN: u64 = 0x1023;
const NTUSER_DEFER_WINDOW_POS_SSN: u64 = 0x1052;
const NTUSER_GET_UPDATE_RECT_SSN: u64 = 0x1053;
const NTUSER_VALIDATE_RECT_SSN: u64 = 0x10d1;
const NTGDI_STRETCH_BLT_SSN: u64 = 0x1030;
const NTGDI_LINE_TO_SSN: u64 = 0x1040;
const NTGDI_PAT_BLT_SSN: u64 = 0x1059;
const NTGDI_POLY_PAT_BLT_SSN: u64 = 0x106f;
const NTGDI_ALPHA_BLEND_SSN: u64 = 0x107d;
const NTGDI_STRETCH_DIBITS_INTERNAL_SSN: u64 = 0x1082;
const NTUSER_FILL_WINDOW_SSN: u64 = 0x108a;
const NTGDI_RECTANGLE_SSN: u64 = 0x1091;
const NTGDI_GET_TEXT_METRICS_W_SSN: u64 = 0x1076;
const NTGDI_GET_TEXT_EXTENT_SSN: u64 = 0x1095;
const FNID_DEFWINDOWPROC: u64 = 0x029e;
const FNID_SENDMESSAGE: u64 = 0x02b1;
const ETO_PDY: u64 = 0x02000;
const WM_QUIT: u32 = 0x0012;
const STRETCH_DIBITS_FAIL_MISSING_SP: u64 = 1;
const STRETCH_DIBITS_FAIL_STACK_TAIL: u64 = 2;
const STRETCH_DIBITS_FAIL_LAYOUT: u64 = 3;
const STRETCH_DIBITS_FAIL_BITS_OVERFLOW: u64 = 4;
const STRETCH_DIBITS_FAIL_BMI_OVERFLOW: u64 = 5;
const STRETCH_DIBITS_FAIL_BITS_COPY: u64 = 6;
const STRETCH_DIBITS_FAIL_BMI_COPY: u64 = 7;
const CREATE_DIBITMAP_FAIL_MISSING_SP: u64 = 1;
const CREATE_DIBITMAP_FAIL_STACK_TAIL: u64 = 2;
const CREATE_DIBITMAP_FAIL_LAYOUT: u64 = 3;
const CREATE_DIBITMAP_FAIL_BITS_OVERFLOW: u64 = 4;
const CREATE_DIBITMAP_FAIL_BMI_OVERFLOW: u64 = 5;
const CREATE_DIBITMAP_FAIL_BITS_COPY: u64 = 6;
const CREATE_DIBITMAP_FAIL_BMI_COPY: u64 = 7;
const CREATE_DIBITMAP_FAIL_STAGE_RESOURCE: u64 = 8;
const CREATE_DIB_SECTION_FAIL_MISSING_SP: u64 = 1;
const CREATE_DIB_SECTION_FAIL_STACK_TAIL: u64 = 2;
const CREATE_DIB_SECTION_FAIL_LAYOUT: u64 = 3;
const CREATE_DIB_SECTION_FAIL_BMI_COPY: u64 = 4;
const CREATE_DIB_SECTION_FAIL_BMI_SIZE: u64 = 5;
const GET_ICON_INFO_FAIL_MISSING_SP: u64 = 1;
const GET_ICON_INFO_FAIL_STACK_TAIL: u64 = 2;
const GET_ICON_INFO_FAIL_DESC_COPY: u64 = 3;
const CBM_INIT: u64 = 0x04;
const CURSORDATA_BYTES: usize = 0x88;
const CURSORDATA_FLAGS_OFF: usize = 0x14;
const CURSORDATA_CPCUR_OFF: usize = 0x5c;
const CURSORDATA_CICUR_OFF: usize = 0x60;
const CURSORDATA_ASPCUR_OFF: usize = 0x68;
const CURSORDATA_AICUR_OFF: usize = 0x70;
const CURSORDATA_AJIFRATE_OFF: usize = 0x78;
const CURSORF_ACON: u32 = 0x0008;
const CURSORDATA_ACON_LIMIT: u32 = 1000;
const DEFERRED_CALLBACK_RETURN_N: usize = nt_user_callback::MAX_CONTINUATION_DEPTH;
static mut LPC_RECEIVE_WAITS: nt_lpc_continuation::ReceiveWaitTable<LpcReceiveContinuation> =
    nt_lpc_continuation::ReceiveWaitTable::new();
static mut LPC_CONNECT_WAITS: nt_lpc_continuation::ConnectWaitTable<LpcConnectContinuation, PendingLpcConnectCompletion> =
    nt_lpc_continuation::ConnectWaitTable::with_completion_storage(16);
static mut LPC_REQUEST_WAITS: nt_lpc_continuation::RequestWaitTable<LpcRequestContinuation> =
    nt_lpc_continuation::RequestWaitTable::new();
static mut LPC_COMPONENT_WAITS: nt_lpc_continuation::BrokerRequestWaitTable<
    nt_component_suspension::SuspensionKey,
> = nt_lpc_continuation::BrokerRequestWaitTable::new();

#[derive(Clone, Copy)]
struct SyscallReplyContext {
    regs: [u64; 18],
}

#[derive(Clone, Copy)]
struct AuthoritativeUnknownSyscallContext {
    tcb: u64,
    user: [u64; 20],
    msg_r8: u64,
    msg_r9: u64,
    msg_r10: u64,
    msg_sp: u64,
    msg_flags: u64,
}

impl SyscallReplyContext {
    unsafe fn capture(m0: u64, m1: u64, m2: u64, m3: u64) -> Self {
        let mut regs = [0u64; 18];
        regs[0] = m0;
        regs[1] = m1;
        regs[2] = m2;
        regs[3] = m3;
        let mut i = 4;
        while i < regs.len() {
            regs[i] = get_recv_mr(i);
            i += 1;
        }
        Self { regs }
    }

    fn from_unknown_syscall_user_context(user: &[u64; 20], next_ip: u64) -> Self {
        let mut regs = [0u64; 18];
        regs[0] = user[nt_user_callback::USER_CONTEXT_RAX];
        regs[1] = user[nt_user_callback::USER_CONTEXT_RBX];
        // seL4 reports UnknownSyscall slot 2 as the syscall return address
        // saved by SYSCALL. `TCBReadRegisters` reports the fault IP instead.
        // The reply path skips RCX, but preserving the wire shape keeps the
        // executive's register view coherent while the syscall is serviced.
        regs[2] = next_ip;
        regs[3] = user[nt_user_callback::USER_CONTEXT_RDX];
        regs[4] = user[nt_user_callback::USER_CONTEXT_RSI];
        regs[5] = user[nt_user_callback::USER_CONTEXT_RDI];
        regs[6] = user[nt_user_callback::USER_CONTEXT_RBP];
        regs[7] = user[nt_user_callback::USER_CONTEXT_R8];
        regs[8] = user[nt_user_callback::USER_CONTEXT_R9];
        regs[9] = user[nt_user_callback::USER_CONTEXT_R10];
        regs[10] = user[nt_user_callback::USER_CONTEXT_R11];
        regs[11] = user[nt_user_callback::USER_CONTEXT_R12];
        regs[12] = user[nt_user_callback::USER_CONTEXT_R13];
        regs[13] = user[nt_user_callback::USER_CONTEXT_R14];
        regs[14] = user[nt_user_callback::USER_CONTEXT_R15];
        regs[15] = user[nt_user_callback::USER_CONTEXT_RIP];
        regs[16] = user[nt_user_callback::USER_CONTEXT_RSP];
        regs[17] = user[nt_user_callback::USER_CONTEXT_RFLAGS];
        Self { regs }
    }

    unsafe fn restage_unknown_syscall_recv_from_user_context(
        user: &[u64; 20],
        next_ip: u64,
    ) -> Self {
        let context = Self::from_unknown_syscall_user_context(user, next_ip);
        let mut i = 4;
        while i < context.regs.len() {
            set_recv_mr(i, context.regs[i]);
            i += 1;
        }
        context
    }

}

unsafe fn capture_authoritative_unknown_syscall_context(
    nt_handler: &ExecNtHandler,
    badge: u64,
    next_ip: u64,
) -> Option<(AuthoritativeUnknownSyscallContext, SyscallReplyContext)> {
    let tcb = nt_handler.hosted_thread_tcb_for_badge(badge)?;
    let msg_r8 = get_recv_mr(7);
    let msg_r9 = get_recv_mr(8);
    let msg_r10 = get_recv_mr(9);
    let msg_sp = get_recv_mr(16);
    let msg_flags = get_recv_mr(17);
    let mut user = [0u64; 20];
    crate::win32k_glue::tcb_read_regs20(tcb, &mut user);
    let context =
        SyscallReplyContext::restage_unknown_syscall_recv_from_user_context(&user, next_ip);
    Some((
        AuthoritativeUnknownSyscallContext {
            tcb,
            user,
            msg_r8,
            msg_r9,
            msg_r10,
            msg_sp,
            msg_flags,
        },
        context,
    ))
}

fn trace_unknown_syscall_tcb_restage(
    ssn: u64,
    badge: u64,
    pi: usize,
    ctx: &AuthoritativeUnknownSyscallContext,
) {
    let user_r8 = ctx.user[nt_user_callback::USER_CONTEXT_R8];
    let user_r9 = ctx.user[nt_user_callback::USER_CONTEXT_R9];
    let user_r10 = ctx.user[nt_user_callback::USER_CONTEXT_R10];
    let user_sp = ctx.user[nt_user_callback::USER_CONTEXT_RSP];
    let user_flags = ctx.user[nt_user_callback::USER_CONTEXT_RFLAGS];
    let changed = ctx.msg_r8 != user_r8
        || ctx.msg_r9 != user_r9
        || ctx.msg_r10 != user_r10
        || ctx.msg_sp != user_sp
        || ctx.msg_flags != user_flags;
    let n = UNKNOWN_SYSCALL_TCB_RESTAGE_TRACE.fetch_add(1, Ordering::Relaxed);
    if !(n < 24 || ssn == 0x1286 || (changed && n < 128)) {
        return;
    }
    print_str(b"[unknown-syscall-tcb] #");
    print_u64(n);
    print_str(b" ssn=0x");
    print_hex_u64(ssn);
    print_str(b" badge=");
    print_u64(badge);
    print_str(b" pi=");
    print_u64(pi as u64);
    print_str(b" tcb=0x");
    print_hex_u64(ctx.tcb);
    print_str(b" msg-sp=0x");
    print_hex_u64(ctx.msg_sp);
    print_str(b" tcb-sp=0x");
    print_hex_u64(user_sp);
    print_str(b" msg-r8=0x");
    print_hex_u64(ctx.msg_r8);
    print_str(b" tcb-r8=0x");
    print_hex_u64(user_r8);
    print_str(b" msg-r9=0x");
    print_hex_u64(ctx.msg_r9);
    print_str(b" tcb-r9=0x");
    print_hex_u64(user_r9);
    print_str(b" msg-r10=0x");
    print_hex_u64(ctx.msg_r10);
    print_str(b" tcb-r10=0x");
    print_hex_u64(user_r10);
    print_str(b" msg-flags=0x");
    print_hex_u64(ctx.msg_flags);
    print_str(b" tcb-flags=0x");
    print_hex_u64(user_flags);
    print_str(b"\n");
}

#[derive(Clone, Copy)]
struct DeferredCallbackReturn {
    used: bool,
    pi: u32,
    badge: u64,
    tid: u64,
    result_pointer: u64,
    result_length: u64,
    callback_status: u64,
    reply: nt_syscall_abi::ParkedSyscallReply,
    reply_cap: u64,
}

impl DeferredCallbackReturn {
    const EMPTY: Self = Self {
        used: false,
        pi: 0,
        badge: 0,
        tid: 0,
        result_pointer: 0,
        result_length: 0,
        callback_status: 0,
        reply: nt_syscall_abi::ParkedSyscallReply::native_call(),
        reply_cap: 0,
    };
}

static mut DEFERRED_CALLBACK_RETURNS: [DeferredCallbackReturn; DEFERRED_CALLBACK_RETURN_N] =
    [DeferredCallbackReturn::EMPTY; DEFERRED_CALLBACK_RETURN_N];

unsafe fn reset_deferred_user_callback_returns() {
    let table = &mut *core::ptr::addr_of_mut!(DEFERRED_CALLBACK_RETURNS);
    for index in 0..DEFERRED_CALLBACK_RETURN_N {
        table[index] = DeferredCallbackReturn::EMPTY;
    }
}

unsafe fn reset_lpc_receive_waits() -> bool {
    (&mut *core::ptr::addr_of_mut!(LPC_RECEIVE_WAITS))
        .reset()
        .is_ok()
}

unsafe fn reset_lpc_connect_waits() -> bool {
    (&mut *core::ptr::addr_of_mut!(LPC_CONNECT_WAITS))
        .reset()
        .is_ok()
}

unsafe fn reset_lpc_request_waits() -> bool {
    (&mut *core::ptr::addr_of_mut!(LPC_REQUEST_WAITS))
        .reset()
        .is_ok()
}

unsafe fn reset_lpc_component_waits() -> bool {
    (&mut *core::ptr::addr_of_mut!(LPC_COMPONENT_WAITS))
        .reset()
        .is_ok()
}

pub(crate) unsafe fn lpc_request_wait_reserve() -> Result<nt_lpc_continuation::Reservation, u32> {
    (&mut *core::ptr::addr_of_mut!(LPC_REQUEST_WAITS))
        .reserve()
        .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
}

pub(crate) unsafe fn lpc_request_wait_cancel_reservation(
    reservation: nt_lpc_continuation::Reservation,
) {
    let _ = (&mut *core::ptr::addr_of_mut!(LPC_REQUEST_WAITS)).cancel(reservation);
}

pub(crate) unsafe fn lpc_connect_wait_reserve() -> Result<nt_lpc_continuation::Reservation, u32> {
    let _durable = crate::allocator::enter_durable();
    (&mut *core::ptr::addr_of_mut!(LPC_CONNECT_WAITS))
        .reserve()
        .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
}

pub(crate) unsafe fn lpc_connect_wait_cancel_reservation(
    reservation: nt_lpc_continuation::Reservation,
) {
    let _ = (&mut *core::ptr::addr_of_mut!(LPC_CONNECT_WAITS)).cancel(reservation);
}

pub(crate) unsafe fn lpc_connect_wait_is_pending(connection_id: u64) -> bool {
    (&*core::ptr::addr_of!(LPC_CONNECT_WAITS))
        .find_connection(connection_id)
        .is_some()
}

unsafe fn lpc_thread_has_wait(tid: u64, badge: u64) -> bool {
    let receives = &*core::ptr::addr_of!(LPC_RECEIVE_WAITS);
    let connects = &*core::ptr::addr_of!(LPC_CONNECT_WAITS);
    let requests = &*core::ptr::addr_of!(LPC_REQUEST_WAITS);
    (0..receives.slot_count()).any(|slot| {
        receives
            .get(slot)
            .is_some_and(|wait| wait.continuation.tid == tid || wait.continuation.badge == badge)
    }) || (0..connects.slot_count()).any(|slot| {
        connects
            .get(slot)
            .is_some_and(|wait| wait.continuation.tid == tid || wait.continuation.badge == badge)
    }) || (0..requests.slot_count()).any(|slot| {
        requests
            .get(slot)
            .is_some_and(|wait| wait.continuation.tid == tid || wait.continuation.badge == badge)
    })
}

pub(crate) unsafe fn lpc_receive_wait_reserve() -> Result<nt_lpc_continuation::Reservation, u32> {
    (&mut *core::ptr::addr_of_mut!(LPC_RECEIVE_WAITS))
        .reserve()
        .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
}

pub(crate) unsafe fn lpc_receive_wait_cancel_reservation(
    reservation: nt_lpc_continuation::Reservation,
) {
    let _ = (&mut *core::ptr::addr_of_mut!(LPC_RECEIVE_WAITS)).cancel(reservation);
}

unsafe fn lpc_receive_wait_park(
    pending: PendingLpcReceivePark,
    pi: u32,
    process: nt_user_host::process_identity::ProcessIdentity,
    badge: u64,
    tid: u64,
) -> bool {
    if tid == 0 {
        return false;
    }
    let table = &mut *core::ptr::addr_of_mut!(LPC_RECEIVE_WAITS);
    if lpc_thread_has_wait(tid, badge) {
        return false;
    }
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else {
        return false;
    };
    if stolen == 0 {
        return false;
    }
    let continuation = LpcReceiveContinuation {
        pi,
        process,
        badge,
        tid,
        memory: pending.memory,
        reply_cap: stolen,
    };
    if table
        .publish(
            pending.reservation,
            nt_lpc_continuation::PendingReceive {
                request: pending.request,
                continuation,
            },
        )
        .is_err()
    {
        return false;
    }
    reply_park.commit();
    LPC_RECEIVE_WAIT_PARKED.fetch_add(1, Ordering::Relaxed);
    if lpc_client()
        .and_then(|client| client.query_handle(pending.request.port_handle).ok())
        .is_some_and(|port| lpc_name_is(&port.name, b"\\LsaAuthenticationPort"))
    {
        LSA_SERVER_PARKS.fetch_add(1, Ordering::Relaxed);
    }
    print_str(b"[lpc-recv] pi=");
    print_u64(pi as u64);
    print_str(b" badge=");
    print_u64(badge);
    print_str(b" tid=");
    print_u64(tid);
    print_str(b" port=0x");
    print_hex_u64(pending.request.port_handle);
    print_str(b" msg=0x");
    print_hex_u64(pending.request.receive_message);
    if pending.request.port_context != 0 {
        print_str(b" ctx=0x");
        print_hex_u64(pending.request.port_context);
    }
    print_str(
        if matches!(
            pending.request.operation,
            nt_lpc_continuation::ReceiveOperation::Listen
        ) {
            b" listen=1"
        } else {
            b" listen=0"
        },
    );
    print_str(b" -> PARK LPC receiver\n");
    true
}

unsafe fn lpc_connect_wait_park(
    pending: PendingLpcConnectPark,
    pi: u32,
    badge: u64,
    tid: u64,
) -> bool {
    if tid == 0 || lpc_thread_has_wait(tid, badge) {
        return false;
    }
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else {
        return false;
    };
    if stolen == 0 {
        return false;
    }
    let continuation = LpcConnectContinuation {
        pi,
        badge,
        tid,
        memory: pending.memory,
        name: pending.name,
        name_len: pending.name_len,
        reply_cap: stolen,
    };
    if (&mut *core::ptr::addr_of_mut!(LPC_CONNECT_WAITS))
        .publish(
            pending.reservation,
            nt_lpc_continuation::PendingConnect {
                request: pending.request,
                continuation,
            },
        )
        .is_err()
    {
        return false;
    }
    reply_park.commit();
    LPC_CONNECT_WAIT_PARKED.fetch_add(1, Ordering::Relaxed);
    print_str(b"[lpc-connect-wait] pi=");
    print_u64(pi as u64);
    print_str(b" badge=");
    print_u64(badge);
    print_str(b" tid=");
    print_u64(tid);
    print_str(b" conn=");
    print_u64(pending.request.connection_id);
    print_str(b" -> PARK connector\n");
    true
}

unsafe fn lpc_request_wait_park(
    pending: PendingLpcRequestPark,
    pi: u32,
    process: nt_user_host::process_identity::ProcessIdentity,
    badge: u64,
    tid: u64,
) -> bool {
    if tid == 0 || lpc_thread_has_wait(tid, badge) {
        return false;
    }
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else {
        return false;
    };
    if stolen == 0 {
        return false;
    }
    let continuation = LpcRequestContinuation {
        pi,
        process,
        badge,
        tid,
        memory: pending.memory,
        completion: pending.completion,
        reply_cap: stolen,
    };
    if (&mut *core::ptr::addr_of_mut!(LPC_REQUEST_WAITS))
        .publish(
            pending.reservation,
            nt_lpc_continuation::PendingRequestWait {
                request: pending.request,
                continuation,
            },
        )
        .is_err()
    {
        return false;
    }
    reply_park.commit();
    LPC_REQUEST_WAIT_PARKED.fetch_add(1, Ordering::Relaxed);
    print_str(b"[lpc-request-wait] pi=");
    print_u64(pi as u64);
    print_str(b" badge=");
    print_u64(badge);
    print_str(b" tid=");
    print_u64(tid);
    print_str(b" port=0x");
    print_hex_u64(pending.request.port_handle);
    print_str(b" msgid=");
    print_u64(pending.request.message_id as u64);
    print_str(b" -> PARK requester\n");
    true
}

/// Transfer the current Call to its semantic continuation. Shared ingress already owns its
/// next receive Reply; only a private root channel needs a replacement pool object.
pub(crate) unsafe fn steal_main_reply() -> Option<u64> {
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    if stolen == 0 {
        return None;
    }
    let reply_park = root_reply_park::RootReplyPark::prepare()?;
    reply_park.commit();
    Some(stolen)
}

fn provider_wait_status_for_error<E>(error: nt_provider_wait::ProviderDispatcherWaitError<E>) -> i32 {
    match error {
        nt_provider_wait::ProviderDispatcherWaitError::NoCapacity => 0xC000_009Au32 as i32,
        _ => 0xC000_000Du32 as i32,
    }
}

fn provider_wait_error_detail(
    error: nt_provider_wait::ProviderDispatcherWaitError<u32>,
) -> u64 {
    match error {
        nt_provider_wait::ProviderDispatcherWaitError::InvalidRequest(error) => {
            0x100 | error as u64
        }
        nt_provider_wait::ProviderDispatcherWaitError::OwnerMismatch => 2,
        nt_provider_wait::ProviderDispatcherWaitError::UnsupportedObjectType => 3,
        nt_provider_wait::ProviderDispatcherWaitError::InvalidAdmissionSequence => 4,
        nt_provider_wait::ProviderDispatcherWaitError::DuplicateWait => 5,
        nt_provider_wait::ProviderDispatcherWaitError::NoCapacity => 6,
        nt_provider_wait::ProviderDispatcherWaitError::NotPoll => 7,
        nt_provider_wait::ProviderDispatcherWaitError::Backend(status) => {
            0x1_0000_0000 | u64::from(status)
        }
    }
}

fn trace_provider_wait_admission(stage: &[u8], wait_id: u64, status: i32, detail: u64) {
    let n = PROVIDER_WAIT_ADMISSION_TRACE_N.fetch_add(1, Ordering::Relaxed);
    if n >= 64 {
        return;
    }
    print_str(b"[provider-wait-admit] #");
    print_u64(n + 1);
    print_str(b" stage=");
    print_str(stage);
    print_str(b" wait=");
    print_u64(wait_id);
    print_str(b" status=0x");
    print_hex(status as u32);
    print_str(b" detail=0x");
    print_hex((detail >> 32) as u32);
    print_hex(detail as u32);
    print_str(b"\n");
}

fn provider_wait_expected_owner(
    pending: win32k_glue::PendingProviderWaitDispatch,
) -> Option<nt_provider_wait::ProviderWaitOwner> {
    let identity = crate::current_win32k_provider_domain()?;
    let owner = nt_provider_wait::ProviderWaitOwner {
        provider_domain: identity.domain,
        provider_generation: identity.generation,
        caller: nt_component_suspension::SuspensionCaller::Hosted(
            nt_component_suspension::SuspensionHostedClient {
                client_pi: pending.client.pi,
                client_generation: pending.client.generation,
                client_tid: pending.client.tid,
                client_badge: pending.client.badge,
            },
        ),
        dispatch_id: pending.dispatch.dispatch_id,
    };
    owner.is_valid().then_some(owner)
}

/// Complete an explicit zero-time poll on the current pump's bound Reply. No logical lane
/// suspension, continuation allocation, waiter registration or nested dispatch is allowed here.
pub(crate) unsafe fn service_provider_wait_poll(
    channel: &spawn_hosts::PumpChannel,
    envelope: nt_user_host::provider_kernel_activation::KernelProviderServiceEnvelope,
) -> bool {
    let Some(page) = win32k_glue::provider_wait_page_for_channel(channel) else {
        return false;
    };
    let request = core::ptr::read_volatile(core::ptr::addr_of!((*page).request));
    if request.header.timeout_kind != nt_provider_wait::ProviderWaitTimeoutKind::Poll as u32
    {
        return false;
    }
    let handler = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    let status = if channel.kernel_caller.is_some() {
        // Polls keep their distinct synchronous authority; blocking requests are captured below
        // the pump by the kernel activation's retained wait owner.
        kernel_provider_activation::service_event_poll(channel, envelope, &request)
    } else {
        match win32k_glue::current_provider_poll_owner(channel) {
            Some(owner) if !handler.is_null()
                && request.validate().is_ok_and(|validated| validated.owner == owner) => {
                let _durable = allocator::enter_durable();
                // Select older waiters before a new poll can consume a just-expired synchronization
                // timer. Selection only records completions; it cannot resume another provider lane.
                let _ = provider_timer_wake_due(&mut *handler, nt_time_snapshot());
                match (&*core::ptr::addr_of!(PROVIDER_WAIT_ARBITER)).poll(
                    &mut *handler, &request, owner,
                ) {
                    Ok(status) => status,
                    Err(error) => provider_wait_status_for_error(error),
                }
            }
            _ => 0xC000_000Du32 as i32,
        }
    };
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*page).result),
        nt_provider_wait::ProviderWaitResult::completed(request.header.wait_id, status),
    );
    trace_provider_wait_admission(
        if channel.kernel_caller.is_some() { b"poll-kernel" } else { b"poll-inline" },
        request.header.wait_id,
        status,
        request.header.object_count as u64,
    );
    true
}

fn lpc_wait_expected_owner(
    pending: win32k_glue::PendingLpcWaitDispatch,
) -> Option<nt_provider_wait::ProviderWaitOwner> {
    if pending.request.client_process != pending.client.pid
        || pending.request.client_thread != pending.client.tid
    {
        return None;
    }
    let identity = crate::current_win32k_provider_domain()?;
    let owner = nt_provider_wait::ProviderWaitOwner {
        provider_domain: identity.domain,
        provider_generation: identity.generation,
        caller: nt_component_suspension::SuspensionCaller::Hosted(
            nt_component_suspension::SuspensionHostedClient {
                client_pi: pending.client.pi,
                client_generation: pending.client.generation,
                client_tid: pending.client.tid,
                client_badge: pending.client.badge,
            },
        ),
        dispatch_id: pending.dispatch.dispatch_id,
    };
    owner.is_valid().then_some(owner)
}

fn component_expected_owner(
    pending: PendingComponentDispatch,
) -> Option<nt_provider_wait::ProviderWaitOwner> {
    match pending {
        PendingComponentDispatch::Provider(pending) => provider_wait_expected_owner(pending),
        PendingComponentDispatch::Lpc(pending) => lpc_wait_expected_owner(pending),
        PendingComponentDispatch::Receive(pending) => Some(pending.yielded.owner),
        PendingComponentDispatch::ServiceWait(pending) => service_wait_expected_owner(pending),
        PendingComponentDispatch::RootMaintenance(pending) => Some(pending.yielded.owner),
        PendingComponentDispatch::NestedRestore(pending) => Some(pending.ticket.key().owner()),
    }
}

fn service_wait_expected_owner(
    pending: win32k_glue::PendingServiceWaitDispatch,
) -> Option<nt_provider_wait::ProviderWaitOwner> {
    let identity = crate::current_win32k_provider_domain()?;
    let owner = nt_provider_wait::ProviderWaitOwner {
        provider_domain: identity.domain,
        provider_generation: identity.generation,
        caller: nt_component_suspension::SuspensionCaller::Hosted(
            nt_component_suspension::SuspensionHostedClient {
                client_pi: pending.snapshot.client.pi,
                client_generation: pending.snapshot.client.generation,
                client_tid: pending.snapshot.client.tid,
                client_badge: pending.snapshot.client.badge,
            },
        ),
        dispatch_id: pending.snapshot.dispatch.dispatch_id,
    };
    owner.is_valid().then_some(owner)
}

fn provider_wait_key(wait_id: u64) -> nt_component_suspension::SuspensionKey {
    nt_component_suspension::SuspensionKey::provider_wait(wait_id)
}

fn component_suspension_key(
    pending: PendingComponentDispatch,
) -> nt_component_suspension::SuspensionKey {
    match pending {
        PendingComponentDispatch::Provider(pending) => {
            provider_wait_key(pending.request.header.wait_id)
        }
        PendingComponentDispatch::Lpc(pending) => {
            nt_component_suspension::SuspensionKey::lpc_request(pending.request.generation)
        }
        PendingComponentDispatch::Receive(pending) => {
            nt_component_suspension::SuspensionKey::receive(pending.yielded.child.admission_sequence())
        }
        PendingComponentDispatch::ServiceWait(pending) => {
            nt_component_suspension::SuspensionKey::service_wait(pending.yielded.token)
        }
        PendingComponentDispatch::RootMaintenance(pending) => {
            nt_component_suspension::SuspensionKey::root_maintenance(pending.yielded.dispatch.epoch())
        }
        PendingComponentDispatch::NestedRestore(pending) => {
            nt_component_suspension::SuspensionKey::nested_restore(
                pending.ticket.key().scope().sequence(),
            )
        }
    }
}

unsafe fn lpc_wait_begin_after_stack_admission(
    nt_handler: &mut ExecNtHandler,
    pending: win32k_glue::PendingLpcWaitDispatch,
    key: nt_component_suspension::SuspensionKey,
    reservation: nt_lpc_continuation::Reservation,
) -> bool {
    let begin = lpc_client().map(|client| {
        client.begin_retained_request_wait_reply(
            pending.request.port_handle,
            pending.request.message(),
            pending.request.client_process,
            pending.request.client_thread,
        )
    });
    match begin {
        Some(Ok(nt_lpc_client::BeginRequestWaitReply::Pending { message_id })) => {
            let identity = nt_lpc_continuation::BrokerRequestIdentity {
                port_handle: pending.request.port_handle,
                client_process: pending.request.client_process,
                client_thread: pending.request.client_thread,
                message_id,
            };
            if (&mut *core::ptr::addr_of_mut!(LPC_COMPONENT_WAITS))
                .publish(
                    reservation,
                    nt_lpc_continuation::PendingBrokerRequest {
                        identity,
                        continuation: key,
                    },
                )
                .is_ok()
            {
                // This broker mutation happened inside a component dispatch rather than an Nt*
                // syscall. Publish the same progress signal so the common drain wakes a parked LPC
                // server receiver before the executive blocks again.
                nt_handler.lpc_endpoint_progress = true;
                let alpc_reply_committed =
                    crate::native_alpc_send_receive_work::redrive_after_lpc_publish(nt_handler);
                nt_handler.lpc_reply_published |= alpc_reply_committed;
                return true;
            }
            if let Some(client) = lpc_client() {
                let _ = client.cancel_request(
                    identity.port_handle,
                    identity.client_process,
                    identity.client_thread,
                    identity.message_id,
                );
            }
            let _ = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS)).cancel(
                key,
                ComponentSuspensionCompletion::provider(0xC000_009Au32 as i32),
            );
        }
        Some(Ok(nt_lpc_client::BeginRequestWaitReply::Completed { message_id, reply })) => {
            let _ = (&mut *core::ptr::addr_of_mut!(LPC_COMPONENT_WAITS)).cancel(reservation);
            let completion = ComponentSuspensionCompletion::lpc(0, message_id, &reply)
                .unwrap_or_else(|| ComponentSuspensionCompletion::provider(0xC000_000Du32 as i32));
            let _ = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS)).select(key, completion);
        }
        Some(Err(status)) => {
            let _ = (&mut *core::ptr::addr_of_mut!(LPC_COMPONENT_WAITS)).cancel(reservation);
            let _ = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .select(key, ComponentSuspensionCompletion::provider(status.raw()));
        }
        None => {
            let _ = (&mut *core::ptr::addr_of_mut!(LPC_COMPONENT_WAITS)).cancel(reservation);
            let _ = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS)).select(
                key,
                ComponentSuspensionCompletion::provider(0xC000_0001u32 as i32),
            );
        }
    }
    false
}

unsafe fn lpc_component_wait_take(
    key: nt_component_suspension::SuspensionKey,
) -> Option<nt_lpc_continuation::PendingBrokerRequest<nt_component_suspension::SuspensionKey>> {
    let mut generation = 0;
    while let Some((slot, current_generation, wait)) = (&*core::ptr::addr_of!(LPC_COMPONENT_WAITS))
        .next_occupied_after(generation)
        .map(|(slot, generation, wait)| (slot, generation, *wait))
    {
        generation = current_generation;
        if wait.continuation == key {
            return (&mut *core::ptr::addr_of_mut!(LPC_COMPONENT_WAITS)).take(slot);
        }
    }
    None
}

unsafe fn lpc_component_wait_select_ready() -> u64 {
    let mut selected = 0;
    let mut generation = 0;
    while let Some((slot, current_generation, wait)) = (&*core::ptr::addr_of!(LPC_COMPONENT_WAITS))
        .next_occupied_after(generation)
        .map(|(slot, generation, wait)| (slot, generation, *wait))
    {
        generation = current_generation;
        let completion = match lpc_client().map(|client| {
            client.receive_reply(
                wait.identity.port_handle,
                wait.identity.client_process,
                wait.identity.client_thread,
                wait.identity.message_id,
            )
        }) {
            Some(Ok(Some(reply))) => {
                ComponentSuspensionCompletion::lpc(0, wait.identity.message_id, &reply)
            }
            Some(Ok(None)) => continue,
            Some(Err(status)) => Some(ComponentSuspensionCompletion::provider(status.raw())),
            None => Some(ComponentSuspensionCompletion::provider(
                0xC000_0001u32 as i32,
            )),
        };
        let Some(completion) = completion else {
            panic!("LPC broker returned a reply larger than the ABI limit");
        };
        let completed = (&mut *core::ptr::addr_of_mut!(LPC_COMPONENT_WAITS))
            .take(slot)
            .expect("selected LPC readiness entry disappeared");
        if (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
            .select(completed.continuation, completion)
            .is_err()
        {
            panic!("LPC readiness selected an unowned component continuation");
        }
        selected += 1;
    }
    selected
}

unsafe fn lpc_component_reply_commit_drain(
    nt_handler: &mut ExecNtHandler,
) -> u64 {
    let selected = lpc_component_wait_select_ready();
    if selected != 0 {
        let _ = component_resume::drain_hosted_ready(core::ptr::from_mut(nt_handler));
    }
    selected
}

enum ComponentPumpCompletion {
    Completed(win32k_glue::CompletedWin32kDispatch),
    Reparked(PendingComponentDispatch),
    CaptureRefused(PendingComponentDispatch, spawn_hosts::PumpResult, spawn_hosts::PumpChannel),
    UserCallbackSuspended,
    FailedRetained(PendingComponentDispatch, i32),
    Failed(i32),
}

enum ComponentSuspensionRuntimeOutcome {
    Parked,
    Terminal,
    Rearmed,
}

pub(crate) fn provider_wait_oldest_event_consumer_sequence<B>(
    backend: &B,
    id: nt_kernel_exec::EventObjectId,
) -> Option<u64>
where
    B: nt_provider_wait::ProviderDispatcherWaitBackend<Lease = crate::exec_handler::ProviderDispatcherLease>,
{
    let object = nt_provider_wait::ProviderWaitObject::new(
        nt_provider_wait::ProviderWaitObjectType::Event,
        id.0.slot().checked_add(1)?,
        u64::from(id.0.generation().0),
    );
    unsafe {
        (&*core::ptr::addr_of!(PROVIDER_WAIT_ARBITER))
            .oldest_event_consumer_sequence(backend, object)
    }
}

pub(crate) unsafe fn provider_wait_select_event_consumer<B>(
    backend: &mut B,
    id: nt_kernel_exec::EventObjectId,
    expected_sequence: u64,
) -> bool
where
    B: nt_provider_wait::ProviderDispatcherWaitBackend<Lease = crate::exec_handler::ProviderDispatcherLease>,
{
    let object = nt_provider_wait::ProviderWaitObject::new(
        nt_provider_wait::ProviderWaitObjectType::Event,
        id.0.slot() + 1,
        u64::from(id.0.generation().0),
    );
    (&mut *core::ptr::addr_of_mut!(PROVIDER_WAIT_ARBITER))
        .pop_event_ready_with(backend, object, expected_sequence, |completion| {
            wait_selection::publish(completion)
        })
        .expect("provider Event selection lost its exact owned continuation")
        .is_some()
}

pub(crate) unsafe fn provider_wait_select_ready<B>(backend: &mut B) -> u64
where
    B: nt_provider_wait::ProviderDispatcherWaitBackend<Lease = crate::exec_handler::ProviderDispatcherLease>,
{
    let mut selected = 0;
    while (&mut *core::ptr::addr_of_mut!(PROVIDER_WAIT_ARBITER))
        .pop_ready_with(backend, |completion| wait_selection::publish(completion))
        .expect("provider readiness lost its exact owned continuation")
        .is_some()
    {
        selected += 1;
    }
    selected
}

pub(crate) fn provider_wait_next_deadline(now: nt_delay_execution::TimeSnapshot) -> Option<u64> {
    unsafe { (&*core::ptr::addr_of!(PROVIDER_WAIT_ARBITER)).next_deadline(now) }
}

pub(crate) unsafe fn provider_wait_scan_timed<B: nt_user_host::provider_dispatcher_backend::ProviderEventBacking>(
    objects: &mut nt_user_host::provider_dispatcher_backend::ProviderDispatcherObjects<'_, B>,
    now: nt_delay_execution::TimeSnapshot,
) -> Result<
    nt_user_host::provider_dispatcher_backend::ProviderTimedScan,
    nt_user_host::provider_wait_selection::ProviderWaitSelectionError<u32>,
> {
    objects.scan_timed(
        &mut *core::ptr::addr_of_mut!(PROVIDER_WAIT_ARBITER),
        now,
        |completion| wait_selection::publish(completion),
    ).map_err(|(_, error)| error)
}

pub(crate) unsafe fn provider_wait_select_due<B>(
    backend: &mut B,
    now: nt_delay_execution::TimeSnapshot,
) -> u64
where
    B: nt_provider_wait::ProviderDispatcherWaitBackend<Lease = crate::exec_handler::ProviderDispatcherLease>,
{
    let mut selected = 0;
    while (&mut *core::ptr::addr_of_mut!(PROVIDER_WAIT_ARBITER))
        .pop_due_with(backend, now, |completion| wait_selection::publish(completion))
        .expect("provider timeout lost its exact owned continuation")
        .is_some()
    {
        selected += 1;
    }
    selected
}

pub(crate) unsafe fn provider_timer_wake_due(
    nt_handler: &mut ExecNtHandler,
    now: nt_delay_execution::TimeSnapshot,
) -> u64 {
    let mut objects = nt_handler.dispatcher_objects(None);
    let expired = objects.expire_timers(now);
    if expired == 0 {
        return 0;
    }
    expired.saturating_add(provider_wait_select_ready(&mut objects))
}

unsafe fn provider_wait_admit_retained(
    nt_handler: &mut ExecNtHandler,
    pending: win32k_glue::PendingProviderWaitDispatch,
    reply_cap: u64,
    callback_transfer: Option<ComponentCallbackTransfer>,
    destination: HostedContinuationDestination,
) -> RetainedWaitAdmission {
    provider_wait_admit_with_transfer(
        nt_handler, pending, reply_cap,
        NestedWaitTransfer::from_completed(callback_transfer), destination,
    )
}

unsafe fn provider_wait_admit_with_transfer(
    nt_handler: &mut ExecNtHandler,
    pending: win32k_glue::PendingProviderWaitDispatch,
    reply_cap: u64,
    transfer: NestedWaitTransfer,
    destination: HostedContinuationDestination,
) -> RetainedWaitAdmission {
    let lane = pending.dispatch.lane;
    if !transfer.admits(pending.client, lane) {
        return RetainedWaitAdmission::RefusedNoEffect;
    }
    let initial_target = matches!(destination, HostedContinuationDestination::InitialThread(_));
    if initial_target {
        print_str(b"[initial-provider-wait] stage=request pi/tid/wait/type/timeout-kind/timeout/count=");
        print_u64(pending.client.pi as u64);
        print_str(b"/"); print_u64(pending.client.tid);
        print_str(b"/"); print_u64(pending.request.header.wait_id);
        print_str(b"/"); print_u64(pending.request.header.wait_type as u64);
        print_str(b"/"); print_u64(pending.request.header.timeout_kind as u64);
        print_str(b"/"); print_hex_u64(pending.request.header.timeout_100ns as u64);
        print_str(b"/"); print_u64(pending.request.header.object_count as u64);
        print_str(b"\n");
        for object in pending.request.objects.iter()
            .take(pending.request.header.object_count as usize)
        {
            print_str(b"[initial-provider-wait] object type/id/generation=");
            print_u64(object.object_type as u64);
            print_str(b"/"); print_u64(object.object_id);
            print_str(b"/"); print_u64(object.object_generation);
            print_str(b"\n");
        }
    }
    let Ok(return_target) = HostedReturnTarget::new(
        reply_cap, transfer.context(),
    ) else {
        return RetainedWaitAdmission::RefusedNoEffect;
    };
    let Some(owner) = provider_wait_expected_owner(pending) else {
        return RetainedWaitAdmission::RefusedNoEffect;
    };
    let wait_id = pending.request.header.wait_id;
    let sequence = next_dispatcher_wait_sequence();
    let continuation = ComponentNativeContinuation::Hosted(HostedNativeContinuation {
        pending: PendingComponentDispatch::Provider(pending),
        return_target,
        destination,
    });
    let Ok(binding) = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).binding(lane) else {
        return RetainedWaitAdmission::RefusedNoEffect;
    };
    let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
    let admitted = if let Some(token) = transfer.token() {
        lanes.transfer_external_to_suspension_running(
            lane,
            binding.reply_object,
            token,
            provider_wait_key(wait_id),
            sequence,
            owner,
            continuation,
        )
    } else {
        lanes.admit_running(
            lane,
            binding.reply_object,
            provider_wait_key(wait_id),
            sequence,
            owner,
            continuation,
        )
    };
    if admitted.is_err() {
        return RetainedWaitAdmission::RefusedNoEffect;
    }
    PROVIDER_WAIT_DISPATCH_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
    COMPONENT_WAIT_DISPATCH_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
    match (&mut *core::ptr::addr_of_mut!(PROVIDER_WAIT_ARBITER)).admit(
        nt_handler,
        &pending.request,
        owner,
        sequence,
        nt_time_snapshot(),
    ) {
        Ok(nt_provider_wait::ProviderDispatcherWaitAdmission::Parked { .. }) => {
            if initial_target { print_str(b"[initial-provider-wait] stage=parked\n"); }
            PROVIDER_WAIT_PARKED_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
            trace_provider_wait_admission(
                b"park",
                wait_id,
                0x0000_0103,
                pending.request.header.object_count as u64,
            );
        }
        Ok(nt_provider_wait::ProviderDispatcherWaitAdmission::Satisfied { wait_id, status }) => {
            if initial_target { print_str(b"[initial-provider-wait] stage=satisfied\n"); }
            trace_provider_wait_admission(
                b"ready",
                wait_id,
                status,
                pending.request.header.object_count as u64,
            );
            if (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .select(
                    provider_wait_key(wait_id),
                    ComponentSuspensionCompletion::provider(status),
                )
                .is_err()
            {
                panic!("provider wait immediate completion lost its continuation");
            }
        }
        Ok(nt_provider_wait::ProviderDispatcherWaitAdmission::TimedOut { wait_id }) => {
            if initial_target { print_str(b"[initial-provider-wait] stage=timeout\n"); }
            trace_provider_wait_admission(
                b"timeout",
                wait_id,
                nt_provider_wait::STATUS_TIMEOUT,
                pending.request.header.object_count as u64,
            );
            if (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .select(
                    provider_wait_key(wait_id),
                    ComponentSuspensionCompletion::provider(nt_provider_wait::STATUS_TIMEOUT),
                )
                .is_err()
            {
                panic!("provider wait poll completion lost its continuation");
            }
        }
        Err(error) => {
            if initial_target { print_str(b"[initial-provider-wait] stage=rejected\n"); }
            let status = provider_wait_status_for_error(error);
            trace_provider_wait_admission(
                b"reject",
                wait_id,
                status,
                provider_wait_error_detail(error),
            );
            if (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .cancel(
                    provider_wait_key(wait_id),
                    ComponentSuspensionCompletion::provider(status),
                )
                .is_err()
            {
                panic!("provider wait rejection lost its continuation");
            }
        }
    }
    RetainedWaitAdmission::Accepted
}

unsafe fn provider_wait_admit_current(
    nt_handler: &mut ExecNtHandler,
    pending: win32k_glue::PendingProviderWaitDispatch,
    callback_transfer: Option<ComponentCallbackTransfer>,
    destination: HostedContinuationDestination,
) -> RetainedWaitAdmission {
    let active_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else {
        return RetainedWaitAdmission::RefusedNoEffect;
    };
    if active_reply == 0 {
        return RetainedWaitAdmission::RefusedNoEffect;
    }
    let admitted = provider_wait_admit_retained(
        nt_handler,
        pending,
        active_reply,
        callback_transfer,
        destination,
    );
    if admitted != RetainedWaitAdmission::Accepted {
        return admitted;
    }
    reply_park.commit();
    RetainedWaitAdmission::Accepted
}

unsafe fn receive_admit_retained(
    pending: win32k_glue::PendingReceiveDispatch,
    reply_cap: u64,
    callback_transfer: Option<ComponentCallbackTransfer>,
    destination: HostedContinuationDestination,
) -> bool {
    receive_admit_with_transfer(
        pending, reply_cap, NestedWaitTransfer::from_completed(callback_transfer), destination,
    ) == RetainedWaitAdmission::Accepted
}

unsafe fn receive_admit_with_transfer(
    pending: win32k_glue::PendingReceiveDispatch,
    reply_cap: u64,
    transfer: NestedWaitTransfer,
    destination: HostedContinuationDestination,
) -> RetainedWaitAdmission {
    if pending.yielded.replaces.is_some()
        || pending.snapshot.callback_token != transfer.token()
        || !transfer.admits(pending.snapshot.client, pending.snapshot.dispatch.lane)
    { return RetainedWaitAdmission::RefusedNoEffect; }
    let Ok(return_target) = HostedReturnTarget::new(
        reply_cap, transfer.context(),
    ) else { return RetainedWaitAdmission::RefusedNoEffect; };
    let key = nt_component_suspension::SuspensionKey::receive(pending.yielded.child.admission_sequence());
    let sequence = next_dispatcher_wait_sequence();
    let continuation = ComponentNativeContinuation::Hosted(HostedNativeContinuation {
        pending: PendingComponentDispatch::Receive(pending), return_target, destination,
    });
    let admitted = crate::spawn_hosts::shared_ingress::owner::runtime::with_bound_receive_scope(
        pending.yielded.parent, |scope| {
            let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
            let admitted = if let Some(token) = transfer.token() {
                lanes.transfer_callback_to_receive_owned(
                    scope, token, key, sequence, pending.yielded.owner,
                    pending.yielded.child, continuation,
                )
            } else {
                lanes.admit_receive_owned(
                    scope, key, sequence, pending.yielded.owner,
                    pending.yielded.child, continuation,
                )
            };
            admitted
                .map_err(|_| crate::spawn_hosts::shared_ingress::owner::runtime::Error::Protocol)
        },
    );
    if admitted.is_ok() { RetainedWaitAdmission::Accepted }
    else { RetainedWaitAdmission::RefusedNoEffect }
}

unsafe fn receive_admit_current(
    pending: win32k_glue::PendingReceiveDispatch,
    destination: HostedContinuationDestination,
) -> bool {
    let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else { return false; };
    if pending.snapshot.callback_token.is_some()
        || !receive_admit_retained(pending, REPLY_MAIN_SLOT.load(Ordering::Relaxed), None, destination)
    {
        return false;
    }
    reply_park.commit();
    true
}

unsafe fn service_wait_admit_retained(
    pending: win32k_glue::PendingServiceWaitDispatch,
    reply_cap: u64,
    callback_transfer: Option<ComponentCallbackTransfer>,
    destination: HostedContinuationDestination,
) -> bool {
    service_wait_admit_with_transfer(
        pending, reply_cap, NestedWaitTransfer::from_completed(callback_transfer), destination,
    ) == RetainedWaitAdmission::Accepted
}

unsafe fn service_wait_admit_with_transfer(
    pending: win32k_glue::PendingServiceWaitDispatch,
    reply_cap: u64,
    transfer: NestedWaitTransfer,
    destination: HostedContinuationDestination,
) -> RetainedWaitAdmission {
    let lane = pending.snapshot.dispatch.lane;
    let origin_valid = match transfer {
        NestedWaitTransfer::InCallback { lane: captured, token } => captured == lane
            && win32k_glue::in_callback_nested_wait_token_is_current(
                pending.snapshot.client, captured, token,
            ),
        _ => transfer.admits(pending.snapshot.client, lane),
    };
    if pending.snapshot.callback_token != transfer.token() {
        trace_win32k_handoff_refusal(b"service-wait-callback-token");
        return RetainedWaitAdmission::RefusedNoEffect;
    }
    if !origin_valid {
        trace_win32k_handoff_refusal(b"service-wait-callback-origin");
        return RetainedWaitAdmission::RefusedNoEffect;
    }
    let Ok(return_target) = HostedReturnTarget::new(
        reply_cap, transfer.context(),
    ) else {
        trace_win32k_handoff_refusal(b"service-wait-return-target");
        return RetainedWaitAdmission::RefusedNoEffect;
    };
    let Some(owner) = service_wait_expected_owner(pending) else {
        trace_win32k_handoff_refusal(b"service-wait-expected-owner");
        return RetainedWaitAdmission::RefusedNoEffect;
    };
    let yielded = pending.yielded;
    let key = nt_component_suspension::SuspensionKey::service_wait(yielded.token);
    let sequence = next_dispatcher_wait_sequence();
    let continuation = ComponentNativeContinuation::Hosted(HostedNativeContinuation {
        pending: PendingComponentDispatch::ServiceWait(pending), return_target, destination,
    });
    let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
    let admitted = match transfer {
        NestedWaitTransfer::InCallback { token, .. } =>
            lanes.admit_in_callback_service_wait_external_owned(
                yielded.route.identity().lane, yielded.reply, yielded.dispatch,
                token, yielded.token, key, sequence, owner, continuation,
            ),
        NestedWaitTransfer::CallbackReturn(completed) =>
            lanes.transfer_callback_to_service_wait_external_owned(
                yielded.route.identity().lane, yielded.reply, yielded.dispatch,
                completed.token, yielded.token, key, sequence, owner, continuation,
            ),
        NestedWaitTransfer::None => lanes.admit_service_wait_external_owned(
            yielded.route.identity().lane, yielded.reply, yielded.dispatch,
            yielded.token, key, sequence, owner, continuation,
        ),
    };
    if admitted.is_ok() { RetainedWaitAdmission::Accepted }
    else {
        trace_win32k_handoff_refusal(b"service-wait-lane-admission");
        RetainedWaitAdmission::RefusedNoEffect
    }
}

unsafe fn service_wait_admit_current(
    pending: win32k_glue::PendingServiceWaitDispatch,
    destination: HostedContinuationDestination,
) -> RetainedWaitAdmission {
    let root_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let reply_park = if pending.snapshot.callback_token.is_some() {
        root_reply_park::RootReplyPark::prepare_exact_hosted(root_reply)
    } else {
        root_reply_park::RootReplyPark::prepare()
    };
    let Some(reply_park) = reply_park else {
        trace_win32k_handoff_refusal(b"service-wait-root-park-prepare");
        return RetainedWaitAdmission::RefusedNoEffect;
    };
    let transfer = match pending.snapshot.callback_token {
        Some(token) => NestedWaitTransfer::InCallback {
            lane: pending.snapshot.dispatch.lane, token,
        },
        None => NestedWaitTransfer::None,
    };
    let admitted = service_wait_admit_with_transfer(
        pending, root_reply, transfer, destination,
    );
    if admitted != RetainedWaitAdmission::Accepted { return admitted; }
    if reply_park.try_commit().is_err() {
        trace_win32k_handoff_refusal(b"service-wait-root-park-commit");
        RetainedWaitAdmission::Indeterminate
    }
    else { RetainedWaitAdmission::Accepted }
}

unsafe fn lpc_wait_admit_retained(
    nt_handler: &mut ExecNtHandler,
    pending: win32k_glue::PendingLpcWaitDispatch,
    reply_cap: u64,
    callback_transfer: Option<ComponentCallbackTransfer>,
    destination: HostedContinuationDestination,
) -> RetainedWaitAdmission {
    lpc_wait_admit_with_transfer(
        nt_handler, pending, reply_cap,
        NestedWaitTransfer::from_completed(callback_transfer), destination,
    )
}

unsafe fn lpc_wait_admit_with_transfer(
    nt_handler: &mut ExecNtHandler,
    pending: win32k_glue::PendingLpcWaitDispatch,
    reply_cap: u64,
    transfer: NestedWaitTransfer,
    destination: HostedContinuationDestination,
) -> RetainedWaitAdmission {
    let lane = pending.dispatch.lane;
    if !transfer.admits(pending.client, lane) {
        return RetainedWaitAdmission::RefusedNoEffect;
    }
    let Ok(reservation) = (&mut *core::ptr::addr_of_mut!(LPC_COMPONENT_WAITS)).reserve() else {
        return RetainedWaitAdmission::RefusedNoEffect;
    };
    let cancel = || {
        if (&mut *core::ptr::addr_of_mut!(LPC_COMPONENT_WAITS)).cancel(reservation).is_ok() {
            RetainedWaitAdmission::RefusedNoEffect
        } else {
            // A changed reservation may already belong to another effect owner. The caller
            // must retain and quarantine its original result, not reinsert it for replay.
            RetainedWaitAdmission::Indeterminate
        }
    };
    let Ok(return_target) = HostedReturnTarget::new(
        reply_cap, transfer.context(),
    ) else {
        return cancel();
    };
    let Some(owner) = lpc_wait_expected_owner(pending) else {
        return cancel();
    };
    let key = nt_component_suspension::SuspensionKey::lpc_request(pending.request.generation);
    let sequence = next_dispatcher_wait_sequence();
    let continuation = ComponentNativeContinuation::Hosted(HostedNativeContinuation {
        pending: PendingComponentDispatch::Lpc(pending),
        return_target,
        destination,
    });
    let Ok(binding) = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).binding(lane) else {
        return cancel();
    };
    let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
    let admitted = if let Some(token) = transfer.token() {
        lanes.transfer_external_to_suspension_running(
            lane,
            binding.reply_object,
            token,
            key,
            sequence,
            owner,
            continuation,
        )
    } else {
        lanes.admit_running(
            lane,
            binding.reply_object,
            key,
            sequence,
            owner,
            continuation,
        )
    };
    if admitted.is_err() {
        return cancel();
    }
    COMPONENT_WAIT_DISPATCH_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
    let _ = lpc_wait_begin_after_stack_admission(nt_handler, pending, key, reservation);
    RetainedWaitAdmission::Accepted
}

unsafe fn lpc_wait_admit_current(
    nt_handler: &mut ExecNtHandler,
    pending: win32k_glue::PendingLpcWaitDispatch,
    callback_transfer: Option<ComponentCallbackTransfer>,
    destination: HostedContinuationDestination,
) -> RetainedWaitAdmission {
    let active_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else {
        return RetainedWaitAdmission::RefusedNoEffect;
    };
    if active_reply == 0 {
        return RetainedWaitAdmission::RefusedNoEffect;
    }
    let admitted = lpc_wait_admit_retained(
        nt_handler,
        pending,
        active_reply,
        callback_transfer,
        destination,
    );
    if admitted != RetainedWaitAdmission::Accepted {
        return admitted;
    }
    if reply_park.try_commit().is_err() { RetainedWaitAdmission::Indeterminate }
    else { RetainedWaitAdmission::Accepted }
}

struct PendingWin32kHandoff {
    callback_suspended: bool,
    admitted_dispatch_id: u64,
    parked: bool,
    maintenance_ticket: Option<root_maintenance_owner::RootMaintenanceTicket>,
    retained_failure: bool,
}

fn trace_win32k_handoff_refusal(stage: &[u8]) {
    print_str(b"[win32k-handoff-refusal] stage=");
    print_str(stage);
    print_str(b"\n");
}

/// The physical nested parent already owns its Reply. Retain the independent root Call before
/// rotating the root Reply; no ordinary syscall result can be delivered from this handoff.
unsafe fn admit_pending_nested_restore_dispatch(
    destination: HostedContinuationDestination,
) -> Result<u64, ()> {
    let root_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    if root_reply == 0 {
        trace_win32k_handoff_refusal(b"nested-restore-root-reply");
        return Err(());
    }
    let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else {
        trace_win32k_handoff_refusal(b"nested-restore-reply-park-prepare");
        return Err(());
    };
    let Some(reservation) = nested_restore_owner::reserve_capacity() else {
        trace_win32k_handoff_refusal(b"nested-restore-capacity");
        return Err(());
    };
    let Some(pending) = win32k_glue::take_pending_nested_restore_dispatch() else {
        trace_win32k_handoff_refusal(b"nested-restore-pending-absent");
        return Err(());
    };
    trace_cursor_lookup_owner("handoff-kind:nested-restore", pending.snapshot.client,
        pending.snapshot.dispatch.ssn, pending.snapshot.dispatch.dispatch_id,
        Some(pending.snapshot.dispatch.lane), true, true, false);
    let dispatch_id = pending.snapshot.dispatch.dispatch_id;
    let ticket = match nested_restore_owner::retain(
        reservation, pending, root_reply, destination, false,
    ) {
        Ok(ticket) => ticket,
        Err(pending) => {
            let _ = win32k_glue::restore_pending_nested_restore_dispatch(pending);
            trace_win32k_handoff_refusal(b"nested-restore-retain");
            return Err(());
        }
    };
    if nested_restore_owner::park_root(ticket, reply_park).is_err()
        && !nested_restore_owner::retry_unparked_root(ticket)
    {
        // The retained frame still owns the original root Reply and physical parent. A refusal
        // cannot become a synthetic provider result or let the root receive reuse this Reply.
        trace_win32k_handoff_refusal(b"nested-restore-park-root");
        return Err(());
    }
    Ok(dispatch_id)
}

/// One authoritative transfer from a returned native pump to the retained execution owner.
/// Direct Win32k syscalls and early Ps process-create callouts use the same wait ordering.
/// Transfer an already parked initial-thread Reply when its later Win32k entry genuinely
/// suspends. A no-effect admission refusal restores the copied pending snapshot for redrive;
/// an uncertain transfer keeps the exact Reply fenced with its initial owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetainedInitialCalloutHandoff {
    Accepted,
    RetryNoEffect,
    Retained,
}

/// A retained initial syscall can run inside an active redirected callback. Its wait inherits
/// that exact lane token; it must not invent the staged context of a completed NtCallbackReturn.
fn retained_initial_callback_transfer(
    lane: nt_component_suspension::LaneHandle,
    token: Option<u64>,
) -> Option<NestedWaitTransfer> {
    use nt_user_host::process_create_callout::InitialCallbackTransfer;
    match nt_user_host::process_create_callout::initial_callback_transfer(lane, token)? {
        InitialCallbackTransfer::Root => Some(NestedWaitTransfer::None),
        InitialCallbackTransfer::InCallback { lane, token } =>
            Some(NestedWaitTransfer::InCallback { lane, token }),
    }
}

pub(crate) unsafe fn admit_retained_initial_win32k_dispatch(
    handler: &mut ExecNtHandler,
    origin: nt_user_host::process_create_callout::InitialThreadReplyOrigin<HostedThreadRole>,
    reply_cap: u64,
) -> RetainedInitialCalloutHandoff {
    use RetainedInitialCalloutHandoff::*;
    if reply_cap == 0 { return Retained; }
    if win32k_glue::pending_nested_restore_dispatch_is_some()
        || win32k_glue::pending_root_ingress_dispatch_is_some()
        || win32k_glue::pending_root_maintenance_dispatch_is_some()
    { return RetryNoEffect; }
    let destination = HostedContinuationDestination::InitialThread(origin);
    if let Some(pending) = win32k_glue::take_pending_receive_dispatch() {
        let Some(transfer) = retained_initial_callback_transfer(
            pending.snapshot.dispatch.lane, pending.snapshot.callback_token,
        ) else {
            return if win32k_glue::restore_pending_receive_dispatch(pending) {
                RetryNoEffect
            } else { Retained };
        };
        return match receive_admit_with_transfer(
            pending, reply_cap, transfer, destination,
        ) {
            RetainedWaitAdmission::Accepted => Accepted,
            RetainedWaitAdmission::RefusedNoEffect => {
                if win32k_glue::restore_pending_receive_dispatch(pending) { RetryNoEffect }
                else { Retained }
            }
            RetainedWaitAdmission::Indeterminate => Retained,
        };
    }
    if let Some(pending) = win32k_glue::take_pending_service_wait_dispatch() {
        let Some(transfer) = retained_initial_callback_transfer(
            pending.snapshot.dispatch.lane, pending.snapshot.callback_token,
        ) else {
            return if win32k_glue::restore_pending_service_wait_dispatch(pending) {
                RetryNoEffect
            } else { Retained };
        };
        return match service_wait_admit_with_transfer(
            pending, reply_cap, transfer, destination,
        ) {
            RetainedWaitAdmission::Accepted => Accepted,
            RetainedWaitAdmission::RefusedNoEffect => {
                if win32k_glue::restore_pending_service_wait_dispatch(pending) { RetryNoEffect }
                else { Retained }
            }
            RetainedWaitAdmission::Indeterminate => Retained,
        };
    }
    if let Some(pending) = win32k_glue::take_pending_provider_wait_dispatch() {
        let token = if pending.nested_user_callback {
            let Some(token) = win32k_glue::pending_callback_token_on_lane(
                pending.client, pending.dispatch.lane,
            ) else {
                return if win32k_glue::restore_pending_provider_wait_dispatch(pending) {
                    RetryNoEffect
                } else { Retained };
            };
            Some(token)
        } else { None };
        let Some(transfer) = retained_initial_callback_transfer(pending.dispatch.lane, token)
        else {
            return if win32k_glue::restore_pending_provider_wait_dispatch(pending) {
                RetryNoEffect
            } else { Retained };
        };
        return match provider_wait_admit_with_transfer(
            handler, pending, reply_cap, transfer, destination,
        ) {
            RetainedWaitAdmission::Accepted => Accepted,
            RetainedWaitAdmission::RefusedNoEffect => {
                if win32k_glue::restore_pending_provider_wait_dispatch(pending) { RetryNoEffect }
                else { Retained }
            }
            RetainedWaitAdmission::Indeterminate => Retained,
        };
    }
    if let Some(pending) = win32k_glue::take_pending_lpc_wait_dispatch() {
        let token = if pending.nested_user_callback {
            let Some(token) = win32k_glue::pending_callback_token_on_lane(
                pending.client, pending.dispatch.lane,
            ) else {
                return if win32k_glue::restore_pending_lpc_wait_dispatch(pending) {
                    RetryNoEffect
                } else { Retained };
            };
            Some(token)
        } else { None };
        let Some(transfer) = retained_initial_callback_transfer(pending.dispatch.lane, token)
        else {
            return if win32k_glue::restore_pending_lpc_wait_dispatch(pending) {
                RetryNoEffect
            } else { Retained };
        };
        return match lpc_wait_admit_with_transfer(
            handler, pending, reply_cap, transfer, destination,
        ) {
            RetainedWaitAdmission::Accepted => Accepted,
            RetainedWaitAdmission::RefusedNoEffect => {
                if win32k_glue::restore_pending_lpc_wait_dispatch(pending) { RetryNoEffect }
                else { Retained }
            }
            RetainedWaitAdmission::Indeterminate => Retained,
        };
    }
    Retained
}

/// A returned physical reply effect is never replayed when its receipt is uncertain.
pub(crate) unsafe fn reply_retained_initial_creation(reply_cap: u64, status: u32) -> bool {
    if !reply_parked_syscall(reply_cap, u64::from(status)) { return false; }
    release_reply_pool_cap(reply_cap);
    true
}

unsafe fn admit_pending_win32k_dispatch(
    handler: &mut ExecNtHandler,
    destination: HostedContinuationDestination,
) -> PendingWin32kHandoff {
    let callback_suspended = win32k_glue::take_user_callback_pump_suspended();
    let mut admitted_dispatch_id = 0;
    let mut parked = false;
    let mut maintenance_ticket = None;
    let mut retained_failure = false;
    if win32k_glue::pending_nested_restore_dispatch_is_some() {
        if callback_suspended {
            trace_win32k_handoff_refusal(b"nested-restore-callback-suspended");
            return PendingWin32kHandoff {
                callback_suspended, admitted_dispatch_id, parked,
                maintenance_ticket, retained_failure: true,
            };
        }
        match admit_pending_nested_restore_dispatch(destination) {
            Ok(dispatch_id) => {
                admitted_dispatch_id = dispatch_id;
                parked = true;
            }
            Err(()) => retained_failure = true,
        }
        return PendingWin32kHandoff {
            callback_suspended, admitted_dispatch_id, parked,
            maintenance_ticket, retained_failure,
        };
    }
    if win32k_glue::pending_root_ingress_dispatch_is_some() {
        if let Some((client, dispatch)) = win32k_glue::pending_root_ingress_dispatch_identity() {
            trace_cursor_lookup_owner("handoff-kind:root-ingress-refused", client,
                dispatch.ssn, dispatch.dispatch_id, Some(dispatch.lane), true, true, false);
        }
        // The distinct owner is retained in the Win32k pending slot, CALLS and PARENTS. This
        // dormant path must not import the child or rotate either Reply until the serialized
        // route preflight and undelivered-parent unwind are implemented together.
        trace_win32k_handoff_refusal(b"root-ingress-unimplemented");
        return PendingWin32kHandoff {
            callback_suspended, admitted_dispatch_id, parked,
            maintenance_ticket, retained_failure: true,
        };
    }
    if win32k_glue::pending_root_maintenance_dispatch_is_some() {
        // Initial-thread callouts cannot transfer this ordinary hosted syscall checkpoint.
        // Leave the pending snapshot in its global cell on every pre-effect refusal.
        if destination != HostedContinuationDestination::Win32k || callback_suspended {
            return PendingWin32kHandoff {
                callback_suspended, admitted_dispatch_id, parked,
                maintenance_ticket, retained_failure: true,
            };
        }
        let root_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
        if root_reply == 0 {
            return PendingWin32kHandoff {
                callback_suspended, admitted_dispatch_id, parked,
                maintenance_ticket, retained_failure: true,
            };
        }
        let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else {
            return PendingWin32kHandoff {
                callback_suspended, admitted_dispatch_id, parked,
                maintenance_ticket, retained_failure: true,
            };
        };
        let Some(reservation) = root_maintenance_owner::reserve_capacity() else {
            return PendingWin32kHandoff {
                callback_suspended, admitted_dispatch_id, parked,
                maintenance_ticket, retained_failure: true,
            };
        };
        let Some(pending) = win32k_glue::take_pending_root_maintenance_dispatch() else {
            root_maintenance_owner::cancel_reservation(reservation);
            return PendingWin32kHandoff {
                callback_suspended, admitted_dispatch_id, parked,
                maintenance_ticket, retained_failure: true,
            };
        };
        trace_cursor_lookup_owner("handoff-kind:maintenance", pending.snapshot.client,
            pending.snapshot.dispatch.ssn, pending.snapshot.dispatch.dispatch_id,
            Some(pending.snapshot.dispatch.lane), true, true, false);
        // The reservation makes this memory-only transfer allocation free. A defensive refusal
        // returns the snapshot to its pending cell before any physical effect can enter.
        let ticket = match root_maintenance_owner::retain(reservation, pending, root_reply) {
            Ok(ticket) => ticket,
            Err(pending) => {
                let _ = win32k_glue::restore_pending_root_maintenance_dispatch(pending);
                root_maintenance_owner::cancel_reservation(reservation);
                return PendingWin32kHandoff {
                    callback_suspended, admitted_dispatch_id, parked,
                    maintenance_ticket, retained_failure: true,
                };
            }
        };
        maintenance_ticket = Some(ticket);
        admitted_dispatch_id = pending.snapshot.dispatch.dispatch_id;
        let yielded = pending.yielded;
        let lane = yielded.dispatch.lane();
        let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
        let exact = root_reply != 0
            && pending.snapshot.callback_token.is_none()
            && pending.snapshot.pump.reply_cap == yielded.reply
            && pending.snapshot.dispatch.lane == lane
            && pending.snapshot.dispatch.dispatch_id == yielded.owner.dispatch_id
            && yielded.route.identity().lane == lane
            && lanes.is_dispatch_identity_active(yielded.dispatch)
            && lanes.phase(lane) == Ok(nt_component_suspension::LanePhase::Running)
            && lanes.binding(lane).is_ok_and(|binding| {
                binding.reply_object == yielded.reply
                    && binding.executor_id == pending.snapshot.channel.tcb
                    && binding.receive_endpoint == pending.snapshot.channel.fault_ep
            })
            && crate::spawn_hosts::shared_ingress::owner::runtime::dispatch(yielded.route)
                .is_ok_and(|dispatch| dispatch == yielded.dispatch)
            && crate::spawn_hosts::shared_ingress::owner::runtime::current_reply(yielded.route)
                .is_ok_and(|reply| reply == yielded.reply)
            && crate::spawn_hosts::shared_ingress::owner::runtime::channel_route(&pending.snapshot.channel)
                .is_ok_and(|route| route == Some(yielded.route))
            && win32k_glue::win32k_client_context_is_admitted(pending.snapshot.client)
            && crate::current_win32k_provider_domain().is_some_and(|provider| {
                provider.domain == yielded.owner.provider_domain
                    && provider.generation == yielded.owner.provider_generation
            });
        if !exact {
            return PendingWin32kHandoff {
                callback_suspended, admitted_dispatch_id, parked,
                maintenance_ticket, retained_failure: true,
            };
        }
        let Ok(return_target) = HostedReturnTarget::new(root_reply, None) else {
            return PendingWin32kHandoff {
                callback_suspended, admitted_dispatch_id, parked,
                maintenance_ticket, retained_failure: true,
            };
        };
        let continuation = ComponentNativeContinuation::Hosted(HostedNativeContinuation {
            pending: PendingComponentDispatch::RootMaintenance(pending),
            return_target,
            destination,
        });
        if !root_maintenance_owner::store_continuation(ticket, continuation) {
            return PendingWin32kHandoff {
                callback_suspended, admitted_dispatch_id, parked,
                maintenance_ticket, retained_failure: true,
            };
        }
        let acquired = root_maintenance_owner::with_physical(ticket, |physical| physical.acquire())
            .is_some_and(|result| result.is_ok());
        if !acquired {
            return PendingWin32kHandoff {
                callback_suspended, admitted_dispatch_id, parked,
                maintenance_ticket, retained_failure: true,
            };
        }
        let key = nt_component_suspension::SuspensionKey::root_maintenance(yielded.dispatch.epoch());
        let sequence = next_dispatcher_wait_sequence();
        let Some(continuation) = root_maintenance_owner::take_continuation(ticket) else {
            return PendingWin32kHandoff {
                callback_suspended, admitted_dispatch_id, parked,
                maintenance_ticket, retained_failure: true,
            };
        };
        let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
        if let Err((_, continuation)) = lanes.admit_root_maintenance_owned(
            lane, yielded.reply, yielded.dispatch, key, sequence, yielded.owner,
            yielded.captured_pass, continuation,
        ) {
            let _ = root_maintenance_owner::restore_continuation(ticket, continuation);
            return PendingWin32kHandoff {
                callback_suspended, admitted_dispatch_id, parked,
                maintenance_ticket, retained_failure: true,
            };
        }
        if !root_maintenance_owner::mark_admitted(ticket, key) {
            return PendingWin32kHandoff {
                callback_suspended, admitted_dispatch_id, parked,
                maintenance_ticket, retained_failure: true,
            };
        }
        if reply_park.try_commit().is_err() {
            return PendingWin32kHandoff {
                callback_suspended, admitted_dispatch_id, parked,
                maintenance_ticket, retained_failure: true,
            };
        }
        parked = true;
        return PendingWin32kHandoff {
            callback_suspended, admitted_dispatch_id, parked,
            maintenance_ticket, retained_failure,
        };
    }
    if let Some(pending) = win32k_glue::take_pending_receive_dispatch() {
        trace_cursor_lookup_owner("handoff-kind:receive", pending.snapshot.client,
            pending.snapshot.dispatch.ssn, pending.snapshot.dispatch.dispatch_id,
            Some(pending.snapshot.dispatch.lane), true, true, false);
        admitted_dispatch_id = pending.snapshot.dispatch.dispatch_id;
        parked = receive_admit_current(pending, destination);
        assert!(parked, "Receive retains parked parent and original client Reply");
    } else if let Some(pending) = win32k_glue::take_pending_service_wait_dispatch() {
        trace_cursor_lookup_owner("handoff-kind:service-wait", pending.snapshot.client,
            pending.snapshot.dispatch.ssn, pending.snapshot.dispatch.dispatch_id,
            Some(pending.snapshot.dispatch.lane), true, true, false);
        admitted_dispatch_id = pending.snapshot.dispatch.dispatch_id;
        match service_wait_admit_current(pending, destination) {
            RetainedWaitAdmission::Accepted => parked = true,
            RetainedWaitAdmission::RefusedNoEffect => {
                let restored = win32k_glue::restore_pending_service_wait_dispatch(pending);
                trace_win32k_handoff_refusal(if restored {
                    b"service-wait-refused-restored"
                } else { b"service-wait-refused-restore-failed" });
                retained_failure = true;
            }
            RetainedWaitAdmission::Indeterminate => {
                trace_win32k_handoff_refusal(b"service-wait-indeterminate");
                retained_failure = true;
            }
        }
    } else if let Some(pending) = win32k_glue::take_pending_provider_wait_dispatch() {
        trace_cursor_lookup_owner("handoff-kind:provider-wait", pending.client,
            pending.dispatch.ssn, pending.dispatch.dispatch_id,
            Some(pending.dispatch.lane), true, true, false);
        admitted_dispatch_id = pending.dispatch.dispatch_id;
        parked = provider_wait_admit_current(handler, pending, None, destination)
            == RetainedWaitAdmission::Accepted;
        assert!(parked, "provider wait could not reserve its native continuation");
    } else if let Some(pending) = win32k_glue::take_pending_lpc_wait_dispatch() {
        trace_cursor_lookup_owner("handoff-kind:lpc-wait", pending.client,
            pending.dispatch.ssn, pending.dispatch.dispatch_id,
            Some(pending.dispatch.lane), true, true, false);
        admitted_dispatch_id = pending.dispatch.dispatch_id;
        parked = lpc_wait_admit_current(handler, pending, None, destination)
            == RetainedWaitAdmission::Accepted;
        assert!(parked, "LPC wait could not reserve its native continuation");
    }
    assert!(!callback_suspended || !parked, "callback and provider wait cannot share one native yield");
    PendingWin32kHandoff {
        callback_suspended, admitted_dispatch_id, parked,
        maintenance_ticket, retained_failure,
    }
}

unsafe fn component_suspension_cancel_scope(
    nt_handler: &mut ExecNtHandler,
    scope: nt_component_suspension::SuspensionScope,
) -> bool {
    if !scope.is_valid() {
        return false;
    }
    if !(&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).contains_scope(scope) {
        return true;
    }
    if !component_return::prepare_abandoned_replies(scope) {
        return false;
    }
    while let Some((lane, wait_key)) =
        (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).next_cancellable_in_scope(scope)
    {
        let phase = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
            .frame(lane, wait_key)
            .ok()
            .flatten()
            .expect("provider wait cancellation target disappeared")
            .phase
            .clone();
        let external_cancelled = match wait_key.kind {
            nt_component_suspension::SuspensionKind::Receive
            | nt_component_suspension::SuspensionKind::RootIngress
            | nt_component_suspension::SuspensionKind::ServiceWait
            | nt_component_suspension::SuspensionKind::RootMaintenance
            | nt_component_suspension::SuspensionKind::NestedRestore => return false,
            nt_component_suspension::SuspensionKind::ProviderWait => {
                (&mut *core::ptr::addr_of_mut!(PROVIDER_WAIT_ARBITER))
                    .cancel(nt_handler, wait_key.id, 0xC000_0120u32 as i32)
                    .is_some()
            }
            nt_component_suspension::SuspensionKind::LpcRequest => {
                if let Some(wait) = lpc_component_wait_take(wait_key) {
                    lpc_client().is_some_and(|client| {
                        client
                            .cancel_request(
                                wait.identity.port_handle,
                                wait.identity.client_process,
                                wait.identity.client_thread,
                                wait.identity.message_id,
                            )
                            .is_ok()
                    })
                } else {
                    false
                }
            }
        };
        if matches!(phase, nt_component_suspension::SuspensionPhase::Waiting) && !external_cancelled
        {
            panic!("waiting component continuation has no readiness owner");
        }
        (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
            .cancel(
                wait_key,
                ComponentSuspensionCompletion::provider(0xC000_0120u32 as i32),
            )
            .expect("component teardown could not cancel its exact continuation");
        PROVIDER_WAIT_CANCELLATIONS.fetch_add(1, Ordering::Relaxed);
    }

    if nt_handler.loop_ctx.is_none() {
        return false;
    }
    let _ = component_resume::drain_hosted_ready(core::ptr::from_mut(nt_handler));
    !(&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).contains_scope(scope)
}

pub(crate) unsafe fn provider_wait_cancel_client_thread(
    nt_handler: &mut ExecNtHandler,
    tid: u64,
) -> bool {
    if (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).total_suspensions() == 0 {
        return true;
    }
    let source = (&*nt_handler.thread_runtime.table).entries.iter()
        .filter_map(|slot| slot.owner())
        .find(|runtime| runtime.binding().tid == tid)
        .map(|runtime| runtime.binding());
    let Some(source) = source else { return false; };
    if !component_return::prepare_abandoned_initial_source_replies(
        component_return::InitialSourceScope::Thread(source),
    ) { return false; }
    let Some(provider) = crate::current_win32k_provider_domain() else {
        return false;
    };
    let Some(pi) = nt_handler.hosted_thread_pi_for_tid(tid) else {
        return false;
    };
    let Some(client_generation) = nt_handler.hosted_process_generation(pi) else {
        return false;
    };
    let Some(client_badge) = nt_handler.hosted_thread_badge_for_tid(tid) else {
        return false;
    };
    component_suspension_cancel_scope(
        nt_handler,
        nt_component_suspension::SuspensionScope::Thread {
            domain: provider.domain,
            provider_generation: provider.generation,
            client_pi: pi as u32,
            client_generation,
            client_tid: tid,
            client_badge,
        },
    )
}

pub(crate) unsafe fn provider_wait_cancel_client_process(
    nt_handler: &mut ExecNtHandler,
    process_index: u8,
) -> bool {
    if (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).total_suspensions() == 0 {
        return true;
    }
    let Some(process) = nt_handler.capture_process_identity(process_index as usize) else {
        return false;
    };
    if !component_return::prepare_abandoned_initial_source_replies(
        component_return::InitialSourceScope::Process {
            pi: process_index as usize, process,
        },
    ) { return false; }
    let Some(provider) = crate::current_win32k_provider_domain() else {
        return false;
    };
    let Some(client_generation) = nt_handler.hosted_process_generation(process_index as usize)
    else {
        return false;
    };
    component_suspension_cancel_scope(
        nt_handler,
        nt_component_suspension::SuspensionScope::Process {
            domain: provider.domain,
            provider_generation: provider.generation,
            client_pi: process_index as u32,
            client_generation,
        },
    )
}

/// Pure final-VM admission query. Retained continuations block retirement across all provider
/// domains and phases, even after their user reply has been abandoned. PI-only legacy owners also
/// fence stale generations: process-slot reuse must not make those records refer to a new VM.
pub(crate) unsafe fn client_has_vm_continuations(pi: u32) -> bool {
    if (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).frames()
        .any(|(_, frame)| {
            frame.owner.hosted_client().is_some_and(|client| client.client_pi == pi)
        })
        || (&*core::ptr::addr_of!(DEFERRED_CALLBACK_RETURNS)).iter()
            .any(|entry| entry.used && entry.pi == pi)
        || (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS)).has_waiter_for_pi(pi)
    {
        return true;
    }
    let receives = &*core::ptr::addr_of!(LPC_RECEIVE_WAITS);
    let connects = &*core::ptr::addr_of!(LPC_CONNECT_WAITS);
    let requests = &*core::ptr::addr_of!(LPC_REQUEST_WAITS);
    receives.occupied_slots().any(|slot| receives.get(slot)
        .is_some_and(|wait| wait.continuation.pi == pi))
        || connects.occupied_slots().any(|slot| connects.get(slot)
            .is_some_and(|wait| wait.continuation.pi == pi))
        || requests.occupied_slots().any(|slot| requests.get(slot)
            .is_some_and(|wait| wait.continuation.pi == pi))
}

/// A process layout cannot retire while a Receive or Request wait still owns its exact Reply.
/// Indeterminate send/cancel phases remain visible in the same occupied rows.
pub(crate) unsafe fn lpc_wait_dependents_quiescent_exact(
    pi: usize,
    process: nt_user_host::process_identity::ProcessIdentity,
) -> bool {
    let receives = &*core::ptr::addr_of!(LPC_RECEIVE_WAITS);
    let requests = &*core::ptr::addr_of!(LPC_REQUEST_WAITS);
    !receives.occupied_slots().any(|slot| receives.get(slot).is_some_and(|wait| {
        wait.continuation.pi as usize == pi && wait.continuation.process == process
    })) && !requests.occupied_slots().any(|slot| requests.get(slot).is_some_and(|wait| {
        wait.continuation.pi as usize == pi && wait.continuation.process == process
    }))
}

fn component_suspension_owns_hosted_dispatch(dispatch_id: u64) -> bool {
    unsafe {
        (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
            .frames()
            .any(|(_, frame)| {
                frame.owner.hosted_client().is_some() && frame.owner.dispatch_id == dispatch_id
            })
    }
}

fn trace_deferred_user_callback_return_refusal(reason: &[u8]) {
    let n = USER_CALLBACK_DEFERRED_RETURNS_FULL.fetch_add(1, Ordering::Relaxed);
    if n < 16 {
        let (active_depth, continuation_depth) = win32k_glue::user_callback_stack_depths();
        print_str(b"[user-callback] deferred NtCallbackReturn refused: ");
        print_str(reason);
        print_str(b" active-depth=");
        print_u64(active_depth as u64);
        print_str(b" continuation-depth=");
        print_u64(continuation_depth as u64);
        let (reply_used, reply_live, reply_records, reply_cap, _, _, _, _) =
            wait_reply_pool_stats();
        print_str(b" reply-pool=");
        print_u64(reply_used);
        print_str(b"/");
        print_u64(reply_live);
        print_str(b"/");
        print_u64(reply_records);
        print_str(b"/");
        print_u64(reply_cap);
        print_str(b" active-reply=0x");
        print_hex_u64(REPLY_MAIN_SLOT.load(Ordering::Relaxed));
        print_str(b"\n");
    }
}

unsafe fn defer_user_callback_return(
    pi: u32,
    badge: u64,
    tid: u64,
    result_pointer: u64,
    result_length: u64,
    callback_status: u64,
    reply: nt_syscall_abi::ParkedSyscallReply,
) -> bool {
    let table = &mut *core::ptr::addr_of_mut!(DEFERRED_CALLBACK_RETURNS);
    let Some(slot) = (0..DEFERRED_CALLBACK_RETURN_N).find(|&index| !table[index].used) else {
        trace_deferred_user_callback_return_refusal(b"table-full");
        return false;
    };
    let Some(reply_cap) = steal_main_reply() else {
        trace_deferred_user_callback_return_refusal(b"reply-pool-empty");
        return false;
    };
    table[slot] = DeferredCallbackReturn {
        used: true,
        pi,
        badge,
        tid,
        result_pointer,
        result_length,
        callback_status,
        reply,
        reply_cap,
    };
    let count = USER_CALLBACK_DEFERRED_RETURNS_PARKED.fetch_add(1, Ordering::Relaxed) + 1;
    let n = USER_CALLBACK_DEFERRED_RETURNS_TRACE.fetch_add(1, Ordering::Relaxed);
    if n < 32 {
        let (active_depth, continuation_depth) = win32k_glue::user_callback_stack_depths();
        print_str(b"[user-callback] deferred out-of-order NtCallbackReturn #");
        print_u64(count);
        print_str(b" pi=");
        print_u64(pi as u64);
        print_str(b" badge=");
        print_u64(badge);
        print_str(b" tid=");
        print_u64(tid);
        print_str(b" result=0x");
        print_hex_u64(result_pointer);
        print_str(b" len=0x");
        print_hex_u64(result_length);
        print_str(b" status=0x");
        print_hex(callback_status as u32);
        print_str(b" depth=");
        print_u64(active_depth as u64);
        print_str(b"/");
        print_u64(continuation_depth as u64);
        print_str(b"\n");
    }
    true
}

unsafe fn take_ready_deferred_user_callback_return() -> Option<DeferredCallbackReturn> {
    let table = &mut *core::ptr::addr_of_mut!(DEFERRED_CALLBACK_RETURNS);
    for index in 0..DEFERRED_CALLBACK_RETURN_N {
        let item = table[index];
        if item.used
            && win32k_glue::user_callback_return_readiness(item.pi, item.badge, item.tid)
                == win32k_glue::UserCallbackReturnReadiness::Ready
        {
            table[index] = DeferredCallbackReturn::EMPTY;
            return Some(item);
        }
    }
    None
}

unsafe fn process_completed_user_callback_outer_dispatch(
    nt_handler: &mut ExecNtHandler,
    completion_pi: usize,
    completion_pml4: u64,
    completion_badge: u64,
    completion_tid: u64,
    mut dispatch: win32k_glue::CompletedWin32kDispatch,
    completion_filled_pages: &mut [u64; 512],
    completion_faults: usize,
    completion_scratch_base: u64,
) -> bool {
    if let Some(context) = dispatch.dispatch_context {
        let requester_generation = nt_handler.hosted_process_generation(completion_pi).unwrap_or(0);
        if !win32k_bulk_mapping::complete_dispatch(
            context, completion_pi as u32, requester_generation,
            dispatch.dispatch_return, dispatch.status,
        ) {
            return false;
        }
    }
    if let Some(claim) = dispatch.paint_output {
        if !copy_completed_paint_output(
            nt_handler,
            completion_pi,
            dispatch.ssn,
            claim,
            dispatch.provider_output_len,
            &dispatch.arg_snapshot,
            completion_scratch_base,
        ) {
            return false;
        }
    }
    if matches!(
        dispatch.ssn,
        nt_user_callback::NTUSER_GET_MESSAGE_SSN | nt_user_callback::NTUSER_PEEK_MESSAGE_SSN
    ) {
        let output_len = dispatch.provider_output_len as usize;
        if !nt_user_callback::message_dispatch_output_length_matches_result(
            dispatch.ssn,
            dispatch.status,
            dispatch.provider_output_len,
        ) {
            return false;
        }
        if output_len == 0 {
            if dispatch.arg_snapshot_len != 0 {
                return false;
            }
        } else if output_len != win32k_glue::COMPLETED_MSG_SNAPSHOT_BYTES
            || dispatch.arg_snapshot_len as usize != output_len
        {
            let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
            if failures < 8 {
                print_str(b"[win32k-svc] completed callback MSG metadata invalid pi=");
                print_u64(completion_pi as u64);
                print_str(b" ssn=0x");
                print_hex(dispatch.ssn as u32);
                print_str(b" published=");
                print_u64(dispatch.provider_output_len as u64);
                print_str(b" snapshot=");
                print_u64(dispatch.arg_snapshot_len as u64);
                print_str(b"\n");
            }
            return false;
        }
        let message = (output_len != 0)
            .then(|| u32::from_le_bytes(dispatch.arg_snapshot[8..12].try_into().unwrap()));
        if output_len != 0
            && !img_spawn::client_copyout_mapped(
                completion_pi as u64,
                dispatch.args[0],
                &dispatch.arg_snapshot[..output_len],
                completion_scratch_base,
            )
        {
            let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
            if failures < 8 {
                print_str(b"[win32k-svc] completed callback MSG copy-out failed pi=");
                print_u64(completion_pi as u64);
                print_str(b" buffer=0x");
                print_hex_u64(dispatch.args[0]);
                print_str(b"\n");
            }
            return false;
        }
        let trace = CALLBACK_MESSAGE_COMPLETION_TRACE.fetch_add(1, Ordering::Relaxed);
        if trace < 32 {
            let hwnd = (output_len != 0)
                .then(|| u64::from_le_bytes(dispatch.arg_snapshot[0..8].try_into().unwrap()))
                .unwrap_or(0);
            let wparam = (output_len != 0)
                .then(|| u64::from_le_bytes(dispatch.arg_snapshot[16..24].try_into().unwrap()))
                .unwrap_or(0);
            print_str(b"[win32k-callback-output] ssn=0x");
            print_hex(dispatch.ssn as u32);
            print_str(b" result=0x");
            print_hex_u64(dispatch.status);
            print_str(b" bytes=");
            print_u64(output_len as u64);
            print_str(b" hwnd=0x");
            print_hex_u64(hwnd);
            print_str(b" message=0x");
            print_hex(message.unwrap_or(0));
            print_str(b" wParam=0x");
            print_hex_u64(wparam);
            print_str(b"\n");
        }
        if completion_pi == 2
            && nt_user_callback::message_dispatch_returned_message(dispatch.ssn, dispatch.status)
        {
            let hwnd = u64::from_le_bytes(dispatch.arg_snapshot[0..8].try_into().unwrap());
            let wparam = u64::from_le_bytes(dispatch.arg_snapshot[16..24].try_into().unwrap());
            winlogon_credential_observe_retrieved(hwnd, message.unwrap_or(0), wparam);
        }
    }
    if dispatch.ssn == win32k_subsystem::SSN_NT_USER_INITIALIZE && dispatch.status == 0 {
        let blen = dispatch.args[2].min(win32k_subsystem::WIN32K_ARG_GENERAL_BYTES);
        if dispatch.arg_snapshot_len as u64 != blen {
            let failures = USERCONNECT_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
            if failures < 8 {
                print_str(
                    b"[win32k-svc] NtUserProcessConnect callback USERCONNECT snapshot missing pi=",
                );
                print_u64(completion_pi as u64);
                print_str(b" badge=");
                print_u64(completion_badge);
                print_str(b" tid=");
                print_u64(completion_tid);
                print_str(b" expected=");
                print_u64(blen);
                print_str(b" got=");
                print_u64(dispatch.arg_snapshot_len as u64);
                print_str(b"\n");
            }
            return false;
        }
        let userconnect = &mut dispatch.arg_snapshot[..blen as usize];
        if complete_ntuser_process_connect_copyout(
            nt_handler,
            completion_pi,
            completion_pml4,
            dispatch.args[1],
            userconnect,
            completion_scratch_base,
        ) {
            W32_CONNECTED_MASK.fetch_or(1u64 << completion_pi, Ordering::Relaxed);
        } else {
            return false;
        }
    }
    if completion_pi == 2 {
        observe_winlogon_completed_dispatch(
            dispatch,
            completion_scratch_base,
        );
        observe_completed_dialog_modal_dispatch(dispatch, completion_badge, completion_tid);
    }
    observe_completed_gdi_batch_flush(nt_handler, dispatch.logical_caller, dispatch.batch_records);
    observe_completed_desktop_dispatch(nt_handler, dispatch.logical_caller,
        dispatch.ssn, dispatch.args, dispatch.status, dispatch.dispatch_return);
    true
}

/// The provider publishes this count only after its real BatchFlushRoutine and original SSN
/// return on the same physical lane. Call here after the original Reply/output settlement so a
/// suspended prelude cannot become desktop evidence.
fn observe_completed_gdi_batch_flush(
    nt_handler: &mut ExecNtHandler,
    original_caller: Option<nt_user_host::provider_logical_caller::ProviderLogicalCaller>,
    records: u64,
) {
    if records == 0 { return; }
    let Some(caller) = original_caller else { return; };
    GDI_BATCH_FLUSHES.fetch_add(1, Ordering::Relaxed);
    GDI_BATCH_RECORDS_FLUSHED.fetch_add(records, Ordering::Relaxed);
    nt_handler.observe_desktop_gui_for(caller, DesktopGuiFact::BatchFlush, 1);
    nt_handler.observe_desktop_gui_for(caller, DesktopGuiFact::BatchRecords, records);
    let explorer = hosted_process_runtime_for_pi(caller.pi())
        .is_some_and(|runtime| {
            runtime.observation_role == nt_exe_image::HostedProcessRole::InteractiveShell
                && caller.process().generation
                    == nt_user_host::process_identity::ProcessGeneration::Hosted(runtime.generation)
        });
    if explorer {
        if EXPLORER_GDI_BATCH_FLUSHES.fetch_add(1, Ordering::Relaxed) == 0 {
            note_boot_progress(BootProgress::ExplorerGdiBatchObserved);
        }
        EXPLORER_GDI_BATCH_RECORDS.fetch_add(records, Ordering::Relaxed);
    }
}

/// Only settled provider output reaches this boundary, for inline and retained continuations.
fn observe_completed_desktop_dispatch(
    nt_handler: &mut ExecNtHandler,
    original_caller: Option<nt_user_host::provider_logical_caller::ProviderLogicalCaller>,
    ssn: u64,
    args: [u64; 4],
    status: u64,
    dispatch_return: Option<nt_user_callback::DispatchReturn>,
) {
    let Some(caller) = original_caller else { return; };
    if dispatch_return.and_then(|returned| returned.handler_value()) != Some(status) { return; }
    if status == 0 { return; }
    let fact = match ssn {
        0x1077 => Some(DesktopGuiFact::WindowCreated),
        0x1036 => Some(DesktopGuiFact::MessageRegistered),
        NTUSER_BEGIN_PAINT_SSN => Some(DesktopGuiFact::BeginPaint),
        NTUSER_END_PAINT_SSN => Some(DesktopGuiFact::EndPaint),
        0x105b | 0x1298 if args[1] as u32 == (-4i32) as u32 => Some(DesktopGuiFact::WndProcCompleted),
        NTGDI_BIT_BLT_SSN | NTGDI_STRETCH_BLT_SSN | NTGDI_LINE_TO_SSN | NTGDI_PAT_BLT_SSN
            | NTGDI_POLY_PAT_BLT_SSN | NTGDI_ALPHA_BLEND_SSN | NTGDI_STRETCH_DIBITS_INTERNAL_SSN
            | NTUSER_FILL_WINDOW_SSN | NTGDI_RECTANGLE_SSN | nt_user_callback::NTGDI_EXT_TEXT_OUT_W_SSN => Some(DesktopGuiFact::DirectDraw),
        _ => None,
    };
    if let Some(fact) = fact { nt_handler.observe_desktop_gui_for(caller, fact, 1); }
}

unsafe fn copy_completed_paint_output(
    nt_handler: &mut ExecNtHandler,
    pi: usize,
    ssn: u64,
    claim: nt_user_callback::PaintOutputClaim,
    published_len: u32,
    output: &[u8],
    scratch_base: u64,
) -> bool {
    let expected = match ssn {
        NTUSER_BEGIN_PAINT_SSN => WIN32K_PAINTSTRUCT_STAGE_BYTES,
        NTUSER_GET_UPDATE_RECT_SSN => WIN32K_RECT_STAGE_BYTES,
        _ => return false,
    };
    if published_len == 0 {
        return true;
    }
    if published_len as usize != expected || output.len() < expected {
        return false;
    }
    img_spawn::client_write_process_mapped_for(
        nt_handler,
        pi as u64,
        claim.process,
        claim.client_pointer,
        &output[..expected],
        scratch_base,
    )
}

unsafe fn sync_completed_user_callback_win32k_context(
    nt_handler: &mut ExecNtHandler,
    completion_pi: usize,
    completion_tid: u64,
) -> bool {
    let expected_pid = nt_handler.pm_pid_for_pi(completion_pi).unwrap_or(0) as u64;
    sync_win32k_context_to_process_manager(nt_handler, completion_pi, expected_pid, completion_tid)
}

unsafe fn drain_deferred_user_callback_returns(
    nt_handler: &mut ExecNtHandler,
    current_pi: usize,
    current_faults: usize,
    procs: &mut [ProcExec],
    pfilled: &mut [[u64; 512]],
    current_filled_pages: &mut [u64; 512],
) {
    while let Some(deferred) = take_ready_deferred_user_callback_return() {
        let completion = win32k_glue::complete_controlled_user_callback(
            deferred.pi,
            deferred.badge,
            deferred.tid,
            deferred.result_pointer,
            deferred.result_length,
            deferred.callback_status,
            deferred.reply.resume_ip(),
            deferred.reply.resume_sp(),
            deferred.reply.resume_flags(),
        );
        let mut effects_ok;
        let mut outer_dispatch_completed = false;
        let mut retained_reply = false;
        let mut staged_context = None;
        if let Some(completion) = completion {
            let completion_pi = deferred.pi as usize;
            effects_ok = completion_pi < MAX_PI;
            if effects_ok && !matches!(completion, win32k_glue::CompletedUserCallback::CaptureRefused { .. }) {
                effects_ok = sync_completed_user_callback_win32k_context(
                    nt_handler,
                    completion_pi,
                    deferred.tid,
                );
            }
            match completion {
                win32k_glue::CompletedUserCallback::CaptureRefused {
                    lane, callback_token, provider_reply_cap,
                } => {
                    let _ = provider_reply_cap; // The exact provider Reply, including zero, is retained as evidence.
                    assert!(win32k_glue::retain_callback_outer_reply(
                        lane, callback_token, deferred.reply_cap,
                    ), "refused callback lost its two exact Reply owners");
                    retained_reply = true;
                }
                win32k_glue::CompletedUserCallback::Completed { outer_dispatch, callback_context } => {
                    staged_context = Some(callback_context);
                    if let Some(dispatch) = outer_dispatch {
                        if effects_ok {
                            let completion_pml4 = procs[completion_pi].pml4;
                            let completion_scratch_base = procs[completion_pi].scratch_base;
                            let completion_faults = if completion_pi == current_pi {
                                current_faults
                            } else {
                                procs[completion_pi].faults as usize
                            };
                            effects_ok = if completion_pi == current_pi {
                                process_completed_user_callback_outer_dispatch(
                                    nt_handler,
                                    completion_pi,
                                    completion_pml4,
                                    deferred.badge,
                                    deferred.tid,
                                    dispatch,
                                    current_filled_pages,
                                    completion_faults,
                                    completion_scratch_base,
                                )
                            } else {
                                process_completed_user_callback_outer_dispatch(
                                    nt_handler,
                                    completion_pi,
                                    completion_pml4,
                                    deferred.badge,
                                    deferred.tid,
                                    dispatch,
                                    &mut pfilled[completion_pi],
                                    completion_faults,
                                    completion_scratch_base,
                                )
                            };
                            outer_dispatch_completed = effects_ok;
                        }
                    }
                }
                win32k_glue::CompletedUserCallback::ProviderWaitSuspended {
                    pending,
                    callback_token,
                    callback_context,
                } => {
                    assert!(provider_wait_admit_retained(
                        nt_handler,
                        pending,
                        deferred.reply_cap,
                        Some(ComponentCallbackTransfer {
                            token: callback_token,
                            context: callback_context,
                        }),
                        HostedContinuationDestination::Win32k,
                    ) == RetainedWaitAdmission::Accepted);
                    retained_reply = true;
                    let _ = component_resume::drain_hosted_ready(core::ptr::from_mut(nt_handler));
                }
                win32k_glue::CompletedUserCallback::LpcWaitSuspended {
                    pending,
                    callback_token,
                    callback_context,
                } => {
                    assert!(lpc_wait_admit_retained(
                        nt_handler,
                        pending,
                        deferred.reply_cap,
                        Some(ComponentCallbackTransfer {
                            token: callback_token,
                            context: callback_context,
                        }),
                        HostedContinuationDestination::Win32k,
                    ) == RetainedWaitAdmission::Accepted);
                    retained_reply = true;
                    let _ = component_resume::drain_hosted_ready(core::ptr::from_mut(nt_handler));
                }
                win32k_glue::CompletedUserCallback::ReceiveSuspended {
                    pending,
                    callback_token,
                    callback_context,
                } => {
                    assert!(receive_admit_retained(
                        pending,
                        deferred.reply_cap,
                        Some(ComponentCallbackTransfer {
                            token: callback_token,
                            context: callback_context,
                        }),
                        HostedContinuationDestination::Win32k,
                    ));
                    retained_reply = true;
                    let _ = component_resume::drain_hosted_ready(core::ptr::from_mut(nt_handler));
                }
                win32k_glue::CompletedUserCallback::ServiceWaitSuspended {
                    pending,
                    callback_token,
                    callback_context,
                } => {
                    assert!(service_wait_admit_retained(
                        pending,
                        deferred.reply_cap,
                        Some(ComponentCallbackTransfer {
                            token: callback_token,
                            context: callback_context,
                        }),
                        HostedContinuationDestination::Win32k,
                    ));
                    retained_reply = true;
                    let _ = component_resume::drain_hosted_ready(core::ptr::from_mut(nt_handler));
                }
            }
        } else {
            effects_ok = false;
        }
        if !effects_ok {
            print_str(b"[user-callback] deferred NtCallbackReturn drain completed with failed side effect pi=");
            print_u64(deferred.pi as u64);
            print_str(b" badge=");
            print_u64(deferred.badge);
            print_str(b" tid=");
            print_u64(deferred.tid);
            print_str(b"\n");
        } else if outer_dispatch_completed {
            pfilled[current_pi] = *current_filled_pages;
        }
        if !retained_reply {
            assert!(effects_ok, "failed deferred callback retains its bound Reply");
            let restarted = win32k_glue::restart_staged_user_callback_context(
                staged_context.expect("completed callback owns its installed context"),
                deferred.reply_cap,
            );
            assert!(restarted, "rejected deferred callback restart retains its bound Reply");
            release_reply_pool_cap(deferred.reply_cap);
            let n = USER_CALLBACK_DEFERRED_RETURNS_WOKEN.fetch_add(1, Ordering::Relaxed);
            if n < 32 {
                let (active_depth, continuation_depth) = win32k_glue::user_callback_stack_depths();
                print_str(b"[user-callback] drained deferred NtCallbackReturn #");
                print_u64(n + 1);
                print_str(b" pi=");
                print_u64(deferred.pi as u64);
                print_str(b" badge=");
                print_u64(deferred.badge);
                print_str(b" tid=");
                print_u64(deferred.tid);
                print_str(b" depth=");
                print_u64(active_depth as u64);
                print_str(b"/");
                print_u64(continuation_depth as u64);
                print_str(b"\n");
            }
        }
    }
}

fn win32k_callback_transport_idle() -> bool {
    let (active_depth, continuation_depth) = win32k_glue::user_callback_stack_depths();
    active_depth == 0
        && continuation_depth == 0
        && spawn_hosts::dispatch_depth() == 0
        && spawn_hosts::SUSPENDED_COMPONENT_OUTSTANDING.load(Ordering::Relaxed) == 0
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StallDeferralSnapshot {
    UserCallbacks {
        active_depth: u64,
        continuation_depth: u64,
        dispatch_depth: u64,
        suspended: u64,
    },
    HostedIpc {
        pi: usize,
        badge: u64,
        tid: u64,
        head: u64,
        tail: u64,
    },
    ExplorerChrome {
        pi: usize,
        generation: u64,
        owner: u64,
        register_messages: u64,
        begin_paints: u64,
        end_paints: u64,
        direct_draws: u64,
        batch_flushes: u64,
    },
}

fn defer_quiesce_for_active_user_callbacks(site: &[u8]) -> bool {
    if win32k_callback_transport_idle() {
        return false;
    }
    let n = USER_CALLBACK_QUIESCE_DEFER_TRACE.fetch_add(1, Ordering::Relaxed);
    if n < 16 {
        let (active_depth, continuation_depth) = win32k_glue::user_callback_stack_depths();
        print_str(b"[quiesce] deferring ");
        print_str(site);
        print_str(b": win32k callbacks active-depth=");
        print_u64(active_depth as u64);
        print_str(b" continuation-depth=");
        print_u64(continuation_depth as u64);
        print_str(b" dispatch-depth=");
        print_u64(spawn_hosts::dispatch_depth());
        print_str(b" suspended-outstanding=");
        print_u64(spawn_hosts::SUSPENDED_COMPONENT_OUTSTANDING.load(Ordering::Relaxed));
        print_str(b"\n");
    }
    true
}

unsafe fn pending_hosted_fault_endpoint_sender(
    nt_handler: &ExecNtHandler,
) -> Option<(usize, HostedThreadQuiesceRecord, u64, u64)> {
    const OWNER_THREAD_BADGE_SNAPSHOT: usize = 64;
    const EP_STATE_SEND: u64 = 1;

    for pi in 0..MAX_PI {
        if !hosted_process_pi_can_run(nt_handler, pi) {
            continue;
        }
        let mut threads = [HostedThreadQuiesceRecord::empty(); OWNER_THREAD_BADGE_SNAPSHOT];
        let (count, _) = nt_handler.hosted_thread_quiesce_records_for_pi(pi, &mut threads);
        for thread in threads[..count].iter().copied() {
            if matches!(
                thread.state,
                Some(nt_process::ThreadState::Initialized)
                    | Some(nt_process::ThreadState::Suspended)
                    | Some(nt_process::ThreadState::Terminated)
            ) {
                continue;
            }
            let Some(tcb) = nt_handler.hosted_thread_tcb_for_badge(thread.badge) else {
                continue;
            };
            let mut state = [0u64; win32k_glue::TCB_DEBUG_STATE_WORDS];
            win32k_glue::tcb_read_debug_state(tcb, 0, &mut state);
            if state[win32k_glue::TCB_DBG_FAULT_EP_STATE] == EP_STATE_SEND
                && state[win32k_glue::TCB_DBG_FAULT_EP_HEAD] != win32k_glue::TCB_DEBUG_NONE
            {
                return Some((
                    pi,
                    thread,
                    state[win32k_glue::TCB_DBG_FAULT_EP_HEAD],
                    state[win32k_glue::TCB_DBG_FAULT_EP_TAIL],
                ));
            }
        }
    }
    None
}

unsafe fn defer_quiesce_for_pending_hosted_ipc(nt_handler: &ExecNtHandler, site: &[u8]) -> bool {
    let Some((pi, thread, head, tail)) = pending_hosted_fault_endpoint_sender(nt_handler) else {
        return false;
    };
    let n = HOSTED_IPC_QUIESCE_DEFER_TRACE.fetch_add(1, Ordering::Relaxed);
    if n < 16 {
        print_str(b"[quiesce] deferring ");
        print_str(site);
        print_str(b": hosted fault endpoint has queued sender pi=");
        print_u64(pi as u64);
        print_str(b" badge=");
        print_u64(thread.badge);
        print_str(b" tid=");
        print_u64(thread.tid);
        print_str(b" head=");
        print_u64(head);
        print_str(b" tail=");
        print_u64(tail);
        print_str(b"\n");
    }
    true
}

unsafe fn progress_stall_deferral_snapshot(
    nt_handler: &ExecNtHandler,
    crash_parked: u64,
    wait_parked: u64,
) -> Option<StallDeferralSnapshot> {
    if !win32k_callback_transport_idle() {
        let (active_depth, continuation_depth) = win32k_glue::user_callback_stack_depths();
        return Some(StallDeferralSnapshot::UserCallbacks {
            active_depth: active_depth as u64,
            continuation_depth: continuation_depth as u64,
            dispatch_depth: spawn_hosts::dispatch_depth(),
            suspended: spawn_hosts::SUSPENDED_COMPONENT_OUTSTANDING.load(Ordering::Relaxed),
        });
    }
    if let Some((pi, thread, head, tail)) = pending_hosted_fault_endpoint_sender(nt_handler) {
        return Some(StallDeferralSnapshot::HostedIpc {
            pi,
            badge: thread.badge,
            tid: thread.tid,
            head,
            tail,
        });
    }
    if interactive_shell_chrome_frontier_pending(nt_handler, crash_parked, wait_parked) {
        let pi = live_hosted_pi_for_observation_role(
            nt_handler,
            nt_exe_image::HostedProcessRole::InteractiveShell,
        )?;
        return Some(StallDeferralSnapshot::ExplorerChrome {
            pi,
            generation: nt_handler.hosted_process_generation(pi).unwrap_or(0),
            owner: nt_handler.hosted_process_top_badge(pi).unwrap_or(u64::MAX),
            register_messages: EXPLORER_REGISTER_WINDOW_MESSAGE_CAPTURES.load(Ordering::Relaxed),
            begin_paints: EXPLORER_BEGIN_PAINTS.load(Ordering::Relaxed),
            end_paints: EXPLORER_END_PAINTS.load(Ordering::Relaxed),
            direct_draws: EXPLORER_DIRECT_GDI_DRAW_RETURNS.load(Ordering::Relaxed),
            batch_flushes: EXPLORER_GDI_BATCH_FLUSHES.load(Ordering::Relaxed),
        });
    }
    None
}

unsafe fn trace_progress_stall_deferral(
    snapshot: StallDeferralSnapshot,
    nt_handler: &ExecNtHandler,
    crash_parked: u64,
    wait_parked: u64,
) {
    match snapshot {
        StallDeferralSnapshot::UserCallbacks { .. } => {
            let _ = defer_quiesce_for_active_user_callbacks(b"progress-stall");
        }
        StallDeferralSnapshot::HostedIpc { .. } => {
            let _ = defer_quiesce_for_pending_hosted_ipc(nt_handler, b"progress-stall");
        }
        StallDeferralSnapshot::ExplorerChrome { .. } => {
            let _ =
                defer_quiesce_for_interactive_shell_chrome(nt_handler, crash_parked, wait_parked);
        }
    }
}

fn align_up_u64(value: u64, align: u64) -> Option<u64> {
    value.checked_add(align - 1).map(|v| v & !(align - 1))
}

fn win32k_client_label<'a>(nt_handler: &'a ExecNtHandler, pi: usize) -> &'a [u8] {
    nt_handler.hosted_process_leaf(pi).unwrap_or(b"client")
}

fn record_hosted_client_gdi_mapping(
    nt_handler: &mut ExecNtHandler, pi: usize, gdi_va: u64,
    caller: Option<nt_user_host::provider_logical_caller::ProviderLogicalCaller>,
) {
    if let Some(caller) = caller {
        nt_handler.observe_desktop_gui_for(caller, DesktopGuiFact::GdiMapped, 1);
    }
    let Some(image) = nt_handler.hosted_process_image(pi) else {
        return;
    };
    let first = match image.observation_role() {
        nt_exe_image::HostedProcessRole::InteractiveLogon => {
            WINLOGON_GDI_MAPPED.swap(1, Ordering::Relaxed) == 0
        }
        nt_exe_image::HostedProcessRole::InteractiveShellBootstrap => {
            USERINIT_GDI_MAPPED.swap(1, Ordering::Relaxed) == 0
        }
        nt_exe_image::HostedProcessRole::InteractiveShell => {
            EXPLORER_GDI_MAPPED.swap(1, Ordering::Relaxed) == 0
        }
        _ => false,
    };
    if first {
        print_str(b"[client-gdi] ");
        print_str(image.leaf);
        print_str(b" handle table alias @0x");
        print_hex((gdi_va >> 32) as u32);
        print_hex(gdi_va as u32);
        print_str(b" with live user attributes (PEB->GdiSharedHandleTable seeded pre-loader)\n");
    }
}

fn ntgdi_bitmap_format_rgb(bits: u32) -> u32 {
    if bits <= 1 {
        1
    } else if bits <= 4 {
        2
    } else if bits <= 8 {
        3
    } else if bits <= 16 {
        4
    } else if bits <= 24 {
        5
    } else if bits <= 32 {
        6
    } else {
        0
    }
}

fn ntgdi_bits_per_format(format: u32) -> Option<u64> {
    match format {
        1 => Some(1),
        2 => Some(4),
        3 => Some(8),
        4 => Some(16),
        5 => Some(24),
        6 => Some(32),
        _ => None,
    }
}

fn ntgdi_create_bitmap_bits_size(
    width: u64,
    height: u64,
    planes: u64,
    bits_pixel: u64,
) -> Option<usize> {
    let width = (width as u32) as i32;
    let height = (height as u32) as i32;
    let planes = planes as u32;
    let bits_pixel = bits_pixel as u32;
    let c_bits = planes.checked_mul(bits_pixel)?;
    let format = ntgdi_bitmap_format_rgb(c_bits);
    let real_bpp = ntgdi_bits_per_format(format)?;
    if width <= 0 || width >= 0x0800_0000 || height <= 0 || bits_pixel > 32 || planes > 32 {
        return None;
    }
    let row_bits = (width as u64).checked_mul(real_bpp)?;
    let row_bytes = row_bits.checked_add(15).map(|bits| (bits & !15) >> 3)?;
    let size = row_bytes.checked_mul(height as u64)?;
    if size >= 0x1_0000_0000 || size > usize::MAX as u64 {
        return None;
    }
    Some(size as usize)
}

fn sec_image_forward_policy() -> SecImageForwardPolicy {
    let slots_cap =
        ROOT_CSPACE_END.load(Ordering::Relaxed) - ROOT_CSPACE_START.load(Ordering::Relaxed);
    let slots_used = NEXT_SLOT.load(Ordering::Relaxed) - ROOT_CSPACE_START.load(Ordering::Relaxed);
    let slot_free = root_slot_available_count();
    let slot_soft = slots_cap != 0 && slot_free <= SEC_IMAGE_PREFETCH_SOFT_SLOT_HEADROOM;
    let slot_pressure = slots_cap != 0 && slot_free <= SEC_IMAGE_PREFETCH_LOW_SLOT_HEADROOM;
    let slot_critical = slots_cap != 0 && slot_free <= SEC_IMAGE_PREFETCH_CRITICAL_SLOT_HEADROOM;
    let frame_registry = client_frame_registry_stats();
    let untyped_total = UT_TOTAL_BYTES.load(Ordering::Relaxed);
    let untyped_free = untyped_total.saturating_sub(UT_RETYPE_LIVE_BYTES.load(Ordering::Relaxed));
    let untyped_soft = untyped_total != 0
        && untyped_free
            <= MIN_BOOT_UNTYPED_HEADROOM_BYTES + SEC_IMAGE_PREFETCH_SOFT_UNTYPED_MARGIN_BYTES;
    let untyped_low = untyped_total != 0
        && untyped_free
            <= MIN_BOOT_UNTYPED_HEADROOM_BYTES + SEC_IMAGE_PREFETCH_LOW_UNTYPED_MARGIN_BYTES;
    let untyped_critical = untyped_total != 0
        && untyped_free
            <= MIN_BOOT_UNTYPED_HEADROOM_BYTES + SEC_IMAGE_PREFETCH_CRITICAL_UNTYPED_MARGIN_BYTES;
    let batch_pages = if slot_pressure || untyped_low {
        SEC_IMAGE_PREFETCH_LOW_PAGES
    } else if slot_soft || untyped_soft {
        SEC_IMAGE_PREFETCH_SOFT_PAGES
    } else {
        SEC_IMAGE_PREFETCH_STEADY_PAGES
    };
    let private_neighbours = batch_pages == SEC_IMAGE_PREFETCH_STEADY_PAGES;
    if batch_pages != SEC_IMAGE_PREFETCH_STEADY_PAGES {
        if SEC_IMAGE_PREFETCH_THROTTLE_LOGGED.swap(1, Ordering::Relaxed) == 0 {
            print_str(b"[sec-image] forward prefetch throttled under pool pressure: cslots=");
            print_u64(slots_used);
            print_str(b"/");
            print_u64(slots_cap);
            print_str(b" slot-free=");
            print_u64(slot_free);
            print_str(b" frame-reg=");
            print_u64(frame_registry.records as u64);
            print_str(b"/");
            print_u64(frame_registry.capacity as u64);
            print_str(b" ut-free=");
            print_u64(untyped_free >> 10);
            print_str(b"KiB");
            print_str(b" critical=");
            print_u64((slot_critical || untyped_critical) as u64);
            print_str(b" batch=");
            print_u64(batch_pages);
            print_str(b" private-neighbours=");
            print_u64(private_neighbours as u64);
            print_str(b"\n");
        }
    }
    SecImageForwardPolicy {
        pages: batch_pages,
        private_neighbours,
    }
}

fn sec_image_clean_writecopy_shareable(
    pe: &nt_pe_loader::PeFile,
    rva: u32,
    image_base: u64,
) -> bool {
    match pe.loader_writable_page_state_at_base(rva, image_base) {
        Ok(nt_pe_loader::LoaderWritablePageState::Clean) => {
            SEC_IMAGE_CLEAN_WRITECOPY_SHARED.fetch_add(1, Ordering::Relaxed);
            true
        }
        Ok(nt_pe_loader::LoaderWritablePageState::Iat) => {
            SEC_IMAGE_WRITECOPY_PRIVATE_LOADER_STATE.fetch_add(1, Ordering::Relaxed);
            SEC_IMAGE_WRITECOPY_PRIVATE_IAT.fetch_add(1, Ordering::Relaxed);
            false
        }
        Ok(nt_pe_loader::LoaderWritablePageState::Relocation) => {
            SEC_IMAGE_WRITECOPY_PRIVATE_LOADER_STATE.fetch_add(1, Ordering::Relaxed);
            SEC_IMAGE_WRITECOPY_PRIVATE_RELOC.fetch_add(1, Ordering::Relaxed);
            false
        }
        Ok(nt_pe_loader::LoaderWritablePageState::SecurityCookie) => {
            SEC_IMAGE_WRITECOPY_PRIVATE_LOADER_STATE.fetch_add(1, Ordering::Relaxed);
            SEC_IMAGE_WRITECOPY_PRIVATE_COOKIE.fetch_add(1, Ordering::Relaxed);
            false
        }
        Ok(nt_pe_loader::LoaderWritablePageState::TlsIndex) => {
            SEC_IMAGE_WRITECOPY_PRIVATE_LOADER_STATE.fetch_add(1, Ordering::Relaxed);
            SEC_IMAGE_WRITECOPY_PRIVATE_TLS.fetch_add(1, Ordering::Relaxed);
            false
        }
        Err(nt_pe_loader::LoaderWritablePageError::Import(_)) => {
            SEC_IMAGE_WRITECOPY_PREDICATE_ERRORS.fetch_add(1, Ordering::Relaxed);
            SEC_IMAGE_WRITECOPY_PREDICATE_IMPORT_ERRORS.fetch_add(1, Ordering::Relaxed);
            false
        }
        Err(nt_pe_loader::LoaderWritablePageError::Relocation(_)) => {
            SEC_IMAGE_WRITECOPY_PREDICATE_ERRORS.fetch_add(1, Ordering::Relaxed);
            SEC_IMAGE_WRITECOPY_PREDICATE_RELOC_ERRORS.fetch_add(1, Ordering::Relaxed);
            false
        }
        Err(nt_pe_loader::LoaderWritablePageError::LoadConfig(_)) => {
            SEC_IMAGE_WRITECOPY_PREDICATE_ERRORS.fetch_add(1, Ordering::Relaxed);
            SEC_IMAGE_WRITECOPY_PREDICATE_LOAD_CONFIG_ERRORS.fetch_add(1, Ordering::Relaxed);
            false
        }
        Err(nt_pe_loader::LoaderWritablePageError::Tls(_)) => {
            SEC_IMAGE_WRITECOPY_PREDICATE_ERRORS.fetch_add(1, Ordering::Relaxed);
            SEC_IMAGE_WRITECOPY_PREDICATE_TLS_ERRORS.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

fn hosted_thread_tcb_or_zero(nt_handler: &ExecNtHandler, tid: u64) -> u64 {
    nt_handler.hosted_thread_tcb(tid).unwrap_or(0)
}

#[inline(never)]
unsafe fn reset_service_exe_images_work(
) -> &'static mut nt_exe_image::ImageTable<HOSTED_PROCESS_IMAGE_CAP> {
    let slot = core::ptr::addr_of_mut!(SERVICE_EXE_IMAGES_WORK);
    core::ptr::write(slot, nt_exe_image::ImageTable::new());
    &mut *slot
}

#[inline(never)]
unsafe fn reset_service_exe_image_catalog_work(
) -> &'static mut nt_exe_image::OwnedHostedImageCatalog<HOSTED_PROCESS_IMAGE_CAP> {
    let catalog = &mut *core::ptr::addr_of_mut!(SERVICE_EXE_IMAGE_CATALOG_WORK);
    catalog.clear();
    catalog
}

#[inline(never)]
unsafe fn reset_service_hosted_loaded_images_work() -> &'static mut HostedLoadedImageTable {
    let table = &mut *core::ptr::addr_of_mut!(SERVICE_HOSTED_LOADED_IMAGES_WORK);
    if !table.reset(MAX_PI) {
        panic!("hosted loaded image table allocation failed");
    }
    table
}

#[inline(never)]
unsafe fn reset_service_generic_sections_work() -> *mut GenericSectionTable {
    if SERVICE_GENERIC_SECTIONS_INITIALIZED.load(Ordering::Acquire) {
        // DriverEntry already populated this very table with canonical kernel Sections.
        // Preserve their identities and frames through the Ps/service handoff.
        return core::ptr::addr_of_mut!(SERVICE_GENERIC_SECTIONS_WORK);
    }
    SERVICE_GENERIC_SECTIONS_INITIALIZED.store(false, Ordering::Release);
    let slot = core::ptr::addr_of_mut!(SERVICE_GENERIC_SECTIONS_WORK);
    if !(*slot).reset() {
        panic!("generic section table allocation failed");
    }
    SERVICE_GENERIC_SECTIONS_INITIALIZED.store(true, Ordering::Release);
    slot
}

pub(crate) unsafe fn initialize_bootstrap_generic_sections_work() {
    let _durable = allocator::enter_durable();
    assert!(!SERVICE_GENERIC_SECTIONS_INITIALIZED.load(Ordering::Acquire));
    let _ = reset_service_generic_sections_work();
    BOOTSTRAP_SECTION_OWNER_ACTIVE.store(true, Ordering::Release);
}

/// DriverEntry's authenticated kernel Section lane uses the same table later adopted by the
/// service loop, but has no ExecNtHandler or process paging context.
pub(crate) fn bootstrap_section_table() -> Result<*mut GenericSectionTable, u32> {
    if !BOOTSTRAP_SECTION_OWNER_ACTIVE.load(Ordering::Acquire)
        || SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) != 0
        || !SERVICE_GENERIC_SECTIONS_INITIALIZED.load(Ordering::Acquire)
    { return Err(0xc000_00a3); }
    Ok(core::ptr::addr_of_mut!(SERVICE_GENERIC_SECTIONS_WORK))
}

/// The initialized canonical Section table is owned by the registered service handler even
/// while DriverEntry runs outside a per-process loop context. A stale handler or an unrelated
/// loop context cannot borrow it.
pub(crate) unsafe fn registered_section_table_for_handler(
    handler: *const ExecNtHandler,
) -> Result<*mut GenericSectionTable, u32> {
    let live = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire);
    if handler.is_null() || live == 0 || live != handler as u64
        || !SERVICE_GENERIC_SECTIONS_INITIALIZED.load(Ordering::Acquire)
    { return Err(0xc000_00a3); }
    let table = core::ptr::addr_of_mut!(SERVICE_GENERIC_SECTIONS_WORK);
    if (*handler).loop_ctx.is_some_and(|ctx| ctx.generic_sections != table) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    Ok(table)
}

pub(crate) fn service_generic_section_stats() -> GenericSectionTableStats {
    unsafe { (&*core::ptr::addr_of!(SERVICE_GENERIC_SECTIONS_WORK)).stats() }
}

pub(crate) fn service_hosted_loaded_images_stats() -> (usize, usize, usize, usize, u64) {
    unsafe { (&*core::ptr::addr_of!(SERVICE_HOSTED_LOADED_IMAGES_WORK)).store_stats() }
}

#[inline(never)]
unsafe fn reset_service_procs_work(slots: usize) -> Option<&'static mut [ProcExec]> {
    let procs = &mut *core::ptr::addr_of_mut!(SERVICE_PROCS_WORK);
    procs.clear();
    if procs.try_reserve(slots).is_err() {
        SERVICE_PROCS_ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    while procs.len() < slots {
        procs.push(ProcExec::empty());
    }
    Some(procs.as_mut_slice())
}

pub(crate) fn service_procs_work_stats() -> (usize, usize, u64) {
    unsafe {
        let procs = &*core::ptr::addr_of!(SERVICE_PROCS_WORK);
        (
            procs.len(),
            procs.capacity(),
            SERVICE_PROCS_ALLOCATION_FAILURES.load(Ordering::Relaxed),
        )
    }
}

#[inline(never)]
unsafe fn reset_service_dll_pe_store_work() -> &'static mut DllPeStore {
    let store = &mut *core::ptr::addr_of_mut!(SERVICE_DLL_PE_STORE_WORK);
    store.reset();
    store
}

pub(crate) fn service_dll_pe_store_stats() -> DllPeStoreStats {
    unsafe { (&*core::ptr::addr_of!(SERVICE_DLL_PE_STORE_WORK)).stats() }
}

/// Complete service-loop durability work before replying or receiving the next caller.
///
/// This boundary also progresses retained wait effects on timer-only activity, when no new user
/// syscall can arrive to drive a failed context write or capability retirement.
fn finalize_service_loop_state(nt_handler: &mut ExecNtHandler) -> u32 {
    let status = finalize_service_loop_work(nt_handler);
    // Include readiness created by any late post-action, on success and failure paths alike.
    unsafe { component_resume::reconcile(nt_handler) };
    if unsafe { driver_launch::hosted_scsi_receive_boundary_probe_due() } {
        let _message = unsafe { crate::ipc_message::SavedMessageBuffer::capture() };
        unsafe { driver_launch::trace_hosted_scsi_receive_boundary() };
    }
    unsafe { rearm_requested_mounted_native_timer(nt_handler) };
    status
}

fn report_service_finalize_failure(stage: &[u8], status: u32) -> u32 {
    print_str(b"[service-finalize] stage=");
    print_str(stage);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b"\n");
    status
}

const SYSTEM_WAL_FOLD_RETRY_INTERVAL_100NS: u64 = 5 * 10_000_000;
static SYSTEM_WAL_FIRST_DIRTY_100NS: AtomicU64 = AtomicU64::new(0);
static SYSTEM_WAL_USED_SECTORS: AtomicU64 = AtomicU64::new(0);
static SYSTEM_WAL_CAPACITY_SECTORS: AtomicU64 = AtomicU64::new(0);
// A timer scan records demand without entering CM or native snapshot I/O while its delivery
// gate and dispatcher borrows are live. The next safe service boundary owns the attempt.
static SYSTEM_WAL_FOLD_DUE: AtomicBool = AtomicBool::new(false);
// DUE keeps the retry deadline armed; READY grants one receive-boundary attempt.
static SYSTEM_WAL_FOLD_READY: AtomicBool = AtomicBool::new(false);
static SYSTEM_WAL_FOLD_RUNNING: AtomicBool = AtomicBool::new(false);
static SYSTEM_WAL_FOLD_RETRY_100NS: AtomicU64 = AtomicU64::new(0);

fn retire_system_wal_fold_demand() {
    SYSTEM_WAL_FOLD_READY.store(false, Ordering::Release);
    SYSTEM_WAL_FOLD_DUE.store(false, Ordering::Release);
    SYSTEM_WAL_FOLD_RETRY_100NS.store(0, Ordering::Release);
}

/// Called only after the exact WAL continuation and both anchored snapshot headers are
/// installed. All durable volume WAL users share this publication boundary.
pub(crate) fn note_durable_system_wal_mutation(used_sectors: u64, capacity_sectors: u64) {
    let now = monotonic_time_100ns().max(1);
    let _ = SYSTEM_WAL_FIRST_DIRTY_100NS.compare_exchange(
        0, now, Ordering::AcqRel, Ordering::Acquire,
    );
    SYSTEM_WAL_USED_SECTORS.store(used_sectors, Ordering::Release);
    SYSTEM_WAL_CAPACITY_SECTORS.store(capacity_sectors, Ordering::Release);
    let first_dirty = SYSTEM_WAL_FIRST_DIRTY_100NS.load(Ordering::Acquire);
    if crate::wal_fold_cadence::background_fold_due(
        first_dirty, now, used_sectors, capacity_sectors,
    ) {
        if !SYSTEM_WAL_FOLD_DUE.load(Ordering::Acquire) {
            SYSTEM_WAL_FOLD_RETRY_100NS.store(
                now.saturating_add(SYSTEM_WAL_FOLD_RETRY_INTERVAL_100NS), Ordering::Release,
            );
            if SYSTEM_WAL_FOLD_DUE.compare_exchange(
                false, true, Ordering::AcqRel, Ordering::Acquire,
            ).is_ok() {
                SYSTEM_WAL_FOLD_READY.store(true, Ordering::Release);
            }
        }
    }
    unsafe { rearm_registered_active_delay_timer() };
}

pub(crate) fn note_system_wal_fold_complete() {
    SYSTEM_WAL_FIRST_DIRTY_100NS.store(0, Ordering::Release);
    SYSTEM_WAL_USED_SECTORS.store(0, Ordering::Release);
    SYSTEM_WAL_CAPACITY_SECTORS.store(0, Ordering::Release);
    // An explicit or asynchronously completed fold bypasses maybe_fold_system_wal's success
    // branch. Its exact paired snapshot and CM ACK retire the pending timer demand as well.
    retire_system_wal_fold_demand();
}

pub(crate) fn system_wal_fold_next_deadline() -> Option<u64> {
    if SYSTEM_WAL_FOLD_DUE.load(Ordering::Acquire) {
        return Some(SYSTEM_WAL_FOLD_RETRY_100NS.load(Ordering::Acquire));
    }
    if !unsafe { crate::writable_fs::writable_fs_mounted() }
        || crate::writable_fs::legacy_snapshot_writes_allowed()
    {
        return None;
    }
    crate::wal_fold_cadence::next_background_fold_deadline(
        match SYSTEM_WAL_FIRST_DIRTY_100NS.load(Ordering::Acquire) {
            0 => None,
            at => Some(at),
        },
    )
}

/// Read-only receive-boundary diagnostic. Fields are sampled independently; the
/// timer selector remains the sole authority for choosing a wake deadline.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SystemWalFoldObservation {
    pub(crate) next_deadline: Option<u64>,
    pub(crate) due: bool,
    pub(crate) ready: bool,
    pub(crate) running: bool,
    pub(crate) retry_100ns: u64,
    pub(crate) first_dirty_100ns: u64,
}

pub(crate) fn system_wal_fold_observation() -> SystemWalFoldObservation {
    SystemWalFoldObservation {
        next_deadline: system_wal_fold_next_deadline(),
        due: SYSTEM_WAL_FOLD_DUE.load(Ordering::Acquire),
        ready: SYSTEM_WAL_FOLD_READY.load(Ordering::Acquire),
        running: SYSTEM_WAL_FOLD_RUNNING.load(Ordering::Acquire),
        retry_100ns: SYSTEM_WAL_FOLD_RETRY_100NS.load(Ordering::Acquire),
        first_dirty_100ns: SYSTEM_WAL_FIRST_DIRTY_100NS.load(Ordering::Acquire),
    }
}

pub(crate) fn record_due_system_wal_fold(now_100ns: u64) -> u64 {
    if !system_wal_fold_next_deadline().is_some_and(|deadline| deadline <= now_100ns) {
        return 0;
    }
    // If CM is still busy, keep a fixed future retry rather than minimum-arming the same
    // overdue shot. The WAL remains durable; this is only the background image fold.
    SYSTEM_WAL_FOLD_RETRY_100NS.store(
        now_100ns.saturating_add(SYSTEM_WAL_FOLD_RETRY_INTERVAL_100NS), Ordering::Release,
    );
    SYSTEM_WAL_FOLD_DUE.store(true, Ordering::Release);
    SYSTEM_WAL_FOLD_READY.store(true, Ordering::Release);
    1
}

pub(crate) fn system_wal_fold_work_pending() -> bool {
    SYSTEM_WAL_FOLD_DUE.load(Ordering::Acquire)
        && SYSTEM_WAL_FOLD_READY.load(Ordering::Acquire)
        && !SYSTEM_WAL_FOLD_RUNNING.load(Ordering::Acquire)
        && crate::config_manager_channel_idle()
}

/// Enter the same physical fold contract as the outer finalizer, but only after the nested
/// receiver has parked its exact parent. A busy native fold retains its owner and async work.
pub(crate) fn service_due_system_wal_fold() -> Result<bool, u32> {
    if !system_wal_fold_work_pending() {
        return Ok(false);
    }
    if SYSTEM_WAL_FOLD_RUNNING.swap(true, Ordering::AcqRel) {
        return Ok(false);
    }
    SYSTEM_WAL_FOLD_READY.store(false, Ordering::Release);
    let result = maybe_fold_system_wal();
    SYSTEM_WAL_FOLD_RUNNING.store(false, Ordering::Release);
    result?;
    Ok(!SYSTEM_WAL_FOLD_DUE.load(Ordering::Acquire))
}

/// Coalesce CM-owned SYSTEM mutations independently of ordinary file snapshot dirtiness.
/// A busy CM or reserve owner defers this background attempt; a physical uncertainty blocks
/// the mounted volume and must reach the service loop as a durability refusal.
fn maybe_fold_system_wal() -> Result<(), u32> {
    if !unsafe { crate::writable_fs::writable_fs_mounted() }
        || crate::writable_fs::legacy_snapshot_writes_allowed()
    {
        retire_system_wal_fold_demand();
        return Ok(());
    }
    let first_dirty = SYSTEM_WAL_FIRST_DIRTY_100NS.load(Ordering::Acquire);
    if first_dirty == 0 {
        // No epoch exists to fold. Retire stale timer demand without publishing a fold ACK.
        retire_system_wal_fold_demand();
        return Ok(());
    }
    let Some(now) = crate::wal_fold_cadence::background_fold_due_time_if_owned(
        Some(first_dirty),
        SYSTEM_WAL_USED_SECTORS.load(Ordering::Acquire),
        SYSTEM_WAL_CAPACITY_SECTORS.load(Ordering::Acquire),
        monotonic_time_100ns,
    ) else {
        return Ok(());
    };
    let _transient = allocator::enter_transient();
    let _alloc_ctx = allocator::enter_context(allocator::ALLOC_CTX_WRITABLE_SNAPSHOT);
    let result = unsafe { crate::writable_fs::fold_system_wal_if_dirty() };
    if result.is_ok() {
        SYSTEM_WAL_FOLD_DUE.store(false, Ordering::Release);
        SYSTEM_WAL_FOLD_RETRY_100NS.store(0, Ordering::Release);
    } else if !crate::writable_fs::system_wal_fold_blocked() {
        SYSTEM_WAL_FOLD_RETRY_100NS.store(
            now.saturating_add(SYSTEM_WAL_FOLD_RETRY_INTERVAL_100NS), Ordering::Release,
        );
        SYSTEM_WAL_FOLD_DUE.store(true, Ordering::Release);
    }
    unsafe { rearm_registered_active_delay_timer() };
    match result {
        Ok(_) => Ok(()),
        Err(_status) if crate::writable_fs::system_wal_fold_ack_pending() => Ok(()),
        Err(_status) if !crate::writable_fs::system_wal_fold_blocked() => Ok(()),
        Err(status) => Err(status),
    }
}

fn finalize_service_loop_work(nt_handler: &mut ExecNtHandler) -> u32 {
    if let Some(status) = redrive_service_loop_global_work(nt_handler) {
        return status;
    }
    checkpoint_service_loop_volume(nt_handler)
}

/// Advance retained service owners before attempting a mounted-volume checkpoint.
/// A pending fold ACK, journal volume owner, or section-retirement error can defer it.
fn redrive_service_loop_global_work(nt_handler: &mut ExecNtHandler) -> Option<u32> {
    // A native directory caller owns its original Reply until the exact Object Manager
    // request and local handle publication settle. Redrive before WAL early returns.
    {
        let _message = unsafe { crate::ipc_message::SavedMessageBuffer::capture() };
        unsafe { crate::native_directory_open_work::redrive(nt_handler) };
        unsafe { crate::native_file_target_open_work::redrive(nt_handler) };
        unsafe { crate::native_directory_effect_work::redrive_effects(nt_handler) };
        unsafe { crate::native_directory_effect_work::redrive_detached(nt_handler) };
    }
    nt_handler.sweep_directory_security_bodies();
    nt_handler.sweep_data_section_security();
    // A hosted import can consume its last object reference while its primary Call still owns
    // the Reply. The dynamic delete drain waits for that primary's exact ready receipt, then
    // invokes DeleteProcedure on a separate PASSIVE worker.
    unsafe { driver_launch::hosted_driver_dynamic_delete::drain(); }
    unsafe { driver_launch::hosted_provider_export_lane::drain(); }
    unsafe { spawn_hosts::shared_ingress::owner::runtime::nested::drain_abort(); }
    unsafe { win32k_glue::drain_win32k_startup_restores(); }
    if unsafe { driver_launch::hosted_driver_dynamic_delete::next_deadline() }.is_some() {
        unsafe { rearm_registered_active_delay_timer_with_handler(nt_handler) };
    }
    if unsafe { driver_launch::hosted_provider_export_lane::next_deadline() }.is_some() {
        unsafe { rearm_registered_active_delay_timer_with_handler(nt_handler) };
    }
    if spawn_hosts::shared_ingress::owner::runtime::nested::next_abort_deadline().is_some() {
        unsafe { rearm_registered_active_delay_timer_with_handler(nt_handler) };
    }
    if unsafe { win32k_glue::win32k_startup_restore_next_deadline() }.is_some() {
        unsafe { rearm_registered_active_delay_timer_with_handler(nt_handler) };
    }
    // A completed physical fold can be waiting only for its exact CM ACK. It still owns the
    // reserve, so redrive that receipt before any ordinary snapshot tries to acquire it.
    if crate::writable_fs::system_wal_fold_ack_pending() {
        if unsafe { crate::writable_fs::fold_system_wal_if_dirty() }.is_err() {
            // The completed fold is durable, but the CM ACK result is uncertain. Keep its
            // physical reserve and token, and let the next timer wake retry this exact ACK.
            // An ordinary checkpoint cannot acquire the reserve until that proof arrives.
            SYSTEM_WAL_FOLD_RETRY_100NS.store(
                monotonic_time_100ns().saturating_add(SYSTEM_WAL_FOLD_RETRY_INTERVAL_100NS),
                Ordering::Release,
            );
            SYSTEM_WAL_FOLD_DUE.store(true, Ordering::Release);
            unsafe { rearm_registered_active_delay_timer() };
            return Some(nt_fs::STATUS_SUCCESS);
        }
    }
    // The journal owns the mounted volume, including all dirty state, until its terminal proof.
    // Leave maintenance flags untouched; an unavailable volume is neither clean nor absent.
    if crate::writable_fs::registry_journal::owns_volume() {
        return Some(nt_fs::STATUS_SUCCESS);
    }
    unsafe { kernel_provider_activation::publish_runtime_waits(nt_handler) };
    unsafe { inline_file_retirement::redrive(nt_handler) };
    unsafe { crate::object_wait_apc::redrive(nt_handler) };
    unsafe { crate::object_wait_reply::redrive(nt_handler) };
    unsafe { crate::pending_file_apc::redrive(nt_handler) };
    unsafe { crate::current_apc::redrive(nt_handler) };
    if FILE_IO_DELIVERY_RETRY_PENDING.swap(false, Ordering::AcqRel) {
        // This boundary can follow receive, before the new caller's arguments are captured.
        // Retained cancellation must also converge when a timer delivers its only completion.
        let _message = unsafe { crate::ipc_message::SavedMessageBuffer::capture() };
        unsafe {
            let _ = pending_file_io_redrive_all(nt_handler);
            let _ = file_cleanup_redrive_all(nt_handler);
            let _ = driver_launch::pump_hosted_file_lifecycle();
            let _ = file_irp_drain_redrive_all(nt_handler);
        }
    }
    // Object Manager references can reach zero in handle, wait, debug, LPC, or teardown paths. The
    // serialized ownership barrier is the single convergence point for exact-generation final
    // process deletion; individual release sites may still make an eager attempt for low latency.
    let _ = nt_handler.drain_hosted_process_deletion_candidates();
    {
        let _message = unsafe { crate::ipc_message::SavedMessageBuffer::capture() };
        unsafe {
            nt_handler.retry_pending_section_view_rollbacks();
            let _ = lpc_connect_completion_drain(nt_handler);
        }
    }
    nt_handler.drain_native_process_images();
    if let Some(ctx) = nt_handler.loop_ctx {
        if let Err(status) = unsafe {
            service_drain_section_retirement_for_handler(&mut *ctx.generic_sections, nt_handler)
        } {
            return Some(report_service_finalize_failure(b"section-retirement", status));
        }
    }
    unsafe { crate::writable_fs::redrive_file_cleanup_work() };
    None
}

/// Claim dirty state and publish the mounted-volume checkpoint at the original service boundary.
fn checkpoint_service_loop_volume(nt_handler: &mut ExecNtHandler) -> u32 {
    let checkpoint_status = match publish_required_dirty_volume(nt_handler) {
        Ok(status) => status,
        Err(status) => return status,
    };
    if checkpoint_status == nt_fs::STATUS_SUCCESS {
        if let Err(status) = fold_background_system_wal(nt_handler) {
            return status;
        }
    }
    if checkpoint_status != nt_fs::STATUS_SUCCESS {
        return report_service_finalize_failure(b"volume-checkpoint", checkpoint_status);
    }
    checkpoint_status
}

/// Preserve dirty-state and commit requirements until the volume snapshot is durable.
fn publish_required_dirty_volume(nt_handler: &mut ExecNtHandler) -> Result<u32, u32> {
    let writable_fs_mount_dirty = crate::writable_fs::take_mount_dirty();
    let writable_fs_runtime_dirty = crate::writable_fs::take_runtime_dirty();
    let writable_fs_touched =
        nt_handler.writable_fs_dirty || writable_fs_mount_dirty || writable_fs_runtime_dirty;
    let mut checkpoint_status = nt_fs::STATUS_SUCCESS;
    if writable_fs_touched {
        let _alloc_scope = allocator::enter_scope(b"service-loop-writable-fs");
        nt_handler.writable_fs_dirty = false;
        if crate::writable_fs::snapshot_restore_seen() {
            if let Err(status) = nt_handler.refresh_boot_hive_checkpoints_from_writable_config() {
                nt_handler.writable_fs_dirty = true;
                return Err(report_service_finalize_failure(b"hive-refresh", status));
            }
        }
        if nt_handler.writable_fs_commit_required {
            let checkpoint_result = {
                let _transient = allocator::enter_transient();
                let _alloc_ctx = allocator::enter_context(allocator::ALLOC_CTX_WRITABLE_SNAPSHOT);
                unsafe { crate::writable_fs::checkpoint_dirty_volume() }
            };
            checkpoint_status = checkpoint_result.err().unwrap_or(nt_fs::STATUS_SUCCESS);
            if checkpoint_status != nt_fs::STATUS_SUCCESS {
                print_str(b"[writable-fs-snapshot] service-loop checkpoint status=0x");
                print_hex(checkpoint_status);
                print_str(b"\n");
            } else {
                if checkpoint_result == Ok(true) {
                    let _ = unsafe { crate::writable_fs::compact_unreferenced_blobs() };
                }
                nt_handler.complete_committed_mutable_hive_journal_snapshot(b"service-loop");
            }
        }
    }
    if checkpoint_status == nt_fs::STATUS_SUCCESS {
        nt_handler.writable_fs_commit_required = false;
    } else {
        // A failed checkpoint did not discharge the durable write. Keep both signals live so the
        // next ownership barrier retries the durable publication before a later success reply.
        nt_handler.writable_fs_dirty = true;
        nt_handler.writable_fs_commit_required = true;
    }
    Ok(checkpoint_status)
}

/// Background WAL folding follows a successful required checkpoint. Its current failure remains
/// a service-boundary refusal and retains both dirty retry signals.
fn fold_background_system_wal(nt_handler: &mut ExecNtHandler) -> Result<(), u32> {
    if let Err(status) = maybe_fold_system_wal() {
        nt_handler.writable_fs_dirty = true;
        nt_handler.writable_fs_commit_required = true;
        return Err(report_service_finalize_failure(b"system-wal-fold", status));
    }
    Ok(())
}

/// The native lookup owner has already parked its original Reply. Publish a pending canonical
/// CREATE with that saved capability, or cancel its unused File reservation after inline work.
pub(crate) unsafe fn finish_preparked_file_target_dispatch(
    handler: &mut ExecNtHandler,
    status: u32,
    reply: u64,
    native_call_transport: bool,
    resume_ip: u64,
    sp: u64,
    flags: u64,
) -> bool {
    if let Some(pending) = handler.pending_file_io_transfer.as_mut() {
        assert_eq!(status, nt_status::NtStatus::PENDING.raw() as u32);
        assert_ne!(reply, 0);
        assert_eq!(pending.reply_cap, 0);
        pending.reply_cap = reply;
        pending.reply_required = true;
        pending.native_call_transport = native_call_transport;
    }
    let handoff = file_dispatch_handoff::before_post_action(
        handler, ExecPostAction::None, native_call_transport, resume_ip, sp, flags,
    );
    if handoff.inline_retirement_needs_redrive() {
        inline_file_retirement::redrive(handler);
    }
    file_dispatch_handoff::finish_after_inline_retirement(handler, handoff).is_some()
}

fn checkpoint_boot_hives_at_quiesce(nt_handler: &mut ExecNtHandler) -> u32 {
    let legacy = crate::writable_fs::legacy_snapshot_writes_allowed();
    let dynamic_status = if legacy {
        nt_handler.checkpoint_dirty_dynamic_mutable_hives()
    } else {
        nt_fs::STATUS_SUCCESS
    };
    if dynamic_status != nt_fs::STATUS_SUCCESS {
        return dynamic_status;
    }
    if !unsafe { crate::writable_fs::writable_fs_mounted() } {
        return if legacy {
            nt_fs::STATUS_SUCCESS
        } else {
            nt_handler.verify_clean_dynamic_hives_at_quiesce()
        };
    }
    let dirty_cells = nt_handler.boot_mutable_hive_dirty_cells();
    let pending_journal_records = nt_handler.mutable_hive_journal_pending_records;
    if legacy && dirty_cells == 0 && pending_journal_records == 0
        && !nt_handler.writable_fs_commit_required
    {
        return nt_fs::STATUS_SUCCESS;
    }
    if legacy {
        print_str(b"[cm-flush] quiesce boot hive checkpoint dirty-cells=");
    } else {
        print_str(b"[cm-flush] quiesce v2 boot hive WAL proof dirty-cells=");
    }
    print_u64(dirty_cells as u64);
    print_str(b"\n");
    let status = if legacy {
        nt_handler.checkpoint_dirty_boot_mutable_hives_preserving_headroom()
    } else {
        nt_handler.verify_durable_v2_mutable_hives()
    };
    if status != nt_fs::STATUS_SUCCESS {
        print_str(b"[cm-flush] quiesce boot hive checkpoint failed status=0x");
        print_hex(status);
        print_str(b"\n");
        return status;
    }
    if !legacy {
        // The exact paired WAL and a clean snapshot were proven under the physical reserve.
        // Folding a WAL or launching a native checkpoint here would require replies from the
        // receive loop that has already terminated.
        return nt_fs::STATUS_SUCCESS;
    }
    if pending_journal_records != 0 {
        print_str(b"[cm-flush] quiesce mutable hive journal snapshot records=");
        print_u64(pending_journal_records as u64);
        print_str(b" dirty-cells=");
        print_u64(dirty_cells as u64);
        print_str(b"\n");
    }
    let snapshot_result = {
        let _transient = allocator::enter_transient();
        let _alloc_ctx = allocator::enter_context(allocator::ALLOC_CTX_WRITABLE_SNAPSHOT);
        unsafe { crate::writable_fs::checkpoint_dirty_volume() }
    };
    let snapshot_status = snapshot_result.err().unwrap_or(nt_fs::STATUS_SUCCESS);
    if snapshot_status == nt_fs::STATUS_SUCCESS {
        if snapshot_result == Ok(true) {
            let _ = unsafe { crate::writable_fs::compact_unreferenced_blobs() };
        }
        nt_handler.complete_committed_mutable_hive_journal_snapshot(b"quiesce");
        nt_handler.writable_fs_commit_required = false;
    } else {
        nt_handler.writable_fs_dirty = true;
        nt_handler.writable_fs_commit_required = true;
        print_str(b"[writable-fs-snapshot] quiesce checkpoint status=0x");
        print_hex(snapshot_status);
        print_str(b"\n");
    }
    snapshot_status
}

#[path = "service_section_pagein.rs"]
pub(crate) mod section_pagein;
pub(crate) use section_pagein::service_generic_section_frame;
pub(crate) use section_pagein::service_prepare_data_section_file;

fn generic_section_writes_back(section: GenericSection) -> bool {
    section.backing.kind == GENERIC_SECTION_BACKING_OVERLAY
}

fn generic_section_mark_dirty_if_backed(
    generic_sections: &mut GenericSectionTable,
    section_index: usize,
    section: GenericSection,
    page_index: u64,
) -> Result<(), u32> {
    if !generic_section_writes_back(section) {
        return Ok(());
    }
    if generic_sections.mark_page_dirty(section_index, page_index) {
        GENERIC_SECTION_DIRTY_MARKS.fetch_add(1, Ordering::Relaxed);
        Ok(())
    } else {
        Err(nt_address_space::STATUS_NOT_COMMITTED)
    }
}

#[path = "service_section_writeback.rs"]
mod section_writeback;
#[path = "service_section_scratch.rs"]
mod section_scratch;
pub(crate) use section_scratch::{service_read_file_coherent, service_resize_file_coherent, service_write_file_coherent};
pub(crate) use section_scratch::section_scratch_is_quiescent;
#[path = "service_section_retirement.rs"]
mod section_retirement;
pub(crate) use section_retirement::{service_drain_section_retirement, service_drain_section_retirement_for_handler, service_unmap_section_view_mappings};
pub(crate) use section_writeback::{
    service_generic_section_writeback_file, service_generic_section_writeback_plan,
    service_generic_section_writeback_view,
    service_generic_section_writeback_unpublished_selftest,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenericSectionFaultResult {
    Unmapped,
    Mapped,
    RoutedPageIn,
}

pub(crate) unsafe fn service_generic_section_fault(
    nt_handler: &mut ExecNtHandler,
    generic_sections: *mut GenericSectionTable,
    pi: usize,
    page: u64,
    pml4: u64,
    scratch_base: u64,
    fault_access: nt_address_space::FaultAccess,
    defer_routed: bool,
    routed_metadata_validated: bool,
) -> Result<GenericSectionFaultResult, u32> {
    let process = nt_handler
        .capture_process_identity(pi)
        .ok_or(nt_address_space::STATUS_ACCESS_VIOLATION)?;
    let lifetime = nt_memory_manager::MemoryLifetime::Process(process);
    hosted_thread_memory_access(pi as u64, page, 0x1000)?;
    let write_fault = fault_access == nt_address_space::FaultAccess::Write;
    let Some((section_index, view)) = (&*generic_sections).view_for_page(pi, page) else {
        return Ok(GenericSectionFaultResult::Unmapped);
    };
    if view.lifetime != lifetime {
        return Err(nt_address_space::STATUS_NOT_COMMITTED);
    }
    let Some(section) = (&*generic_sections).section(section_index) else {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    };
    let section_identity = (&*generic_sections)
        .section_identity(section_index)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let section_page_offset = view.section_offset + (page - view.base);
    let page_index = section_page_offset / 0x1000;
    let Some(view_info) = process_committed_mapping_basic_information(pi as u64, page) else {
        return Err(nt_address_space::STATUS_NOT_COMMITTED);
    };
    if view_info.type_ != nt_address_space::MEM_MAPPED {
        return Err(nt_address_space::STATUS_CONFLICTING_ADDRESSES);
    }
    nt_address_space::mapped_view_fault_access_status(view_info.protect, fault_access)?;
    if nt_handler.restore_process_pagefile_page(pi, page, pml4, scratch_base)? {
        return Ok(GenericSectionFaultResult::Mapped);
    }
    let resident = nt_memory_manager::admit_resident_reprotect(
        pi as u64,
        process,
        page,
        &*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY),
    )?;
    if resident.is_some() {
        if fault_access == nt_address_space::FaultAccess::Lock {
            return Ok(GenericSectionFaultResult::Mapped);
        }
        let fault_plan = nt_address_space::mapped_view_fault_plan(view_info.protect, write_fault);
        if write_fault && resident.is_some_and(|record| record.owns_frame) {
            let protection = nt_address_space::private_backing_protection(view_info.protect);
            vm_reprotect_private_page(pi, process, page, protection, protection, pml4)?;
            return Ok(GenericSectionFaultResult::Mapped);
        }
        if write_fault && fault_plan.copy_on_write {
            crate::win32k_glue::detach_attached_client_page_with_access(
                pi as u64,
                page,
                &crate::retirement_memory_access::Access::Process {
                    process,
                    handler: &*nt_handler,
                },
            )?;
            let old_protection =
                nt_address_space::mapped_view_fault_plan(view_info.protect, false).map_protection;
            vm_promote_mapped_cow_page(
                nt_handler,
                pi,
                page,
                0,
                old_protection,
                fault_plan.map_protection,
                pml4,
                scratch_base,
            )?;
            return Ok(GenericSectionFaultResult::Mapped);
        }
        if write_fault && fault_plan.mark_dirty {
            let old_protection =
                nt_address_space::mapped_view_fault_plan(view_info.protect, false).map_protection;
            generic_section_mark_dirty_if_backed(
                &mut *generic_sections,
                section_index,
                section,
                page_index,
            )?;
            vm_reprotect_private_page(
                pi,
                process,
                page,
                old_protection,
                view_info.protect,
                pml4,
            )?;
            return Ok(GenericSectionFaultResult::Mapped);
        }
        return Err(0xC000_0005); // STATUS_ACCESS_VIOLATION
    }
    nt_handler.ensure_process_working_set_admission(pi, page, scratch_base)?;
    let fault_plan = nt_address_space::mapped_view_fault_plan(view_info.protect, write_fault);
    if defer_routed
        && section.backing.kind == nt_memory_manager::GENERIC_SECTION_BACKING_ROUTED
        && (&*generic_sections).page_frame(section_index, page_index).is_none()
    {
        return Ok(GenericSectionFaultResult::RoutedPageIn);
    }
    let frame = service_generic_section_frame(
        generic_sections,
        section_index,
        section_identity,
        section,
        page_index,
        scratch_base,
        routed_metadata_validated,
    )?;
    if (&*generic_sections).view_for_page(pi, page) != Some((section_index, view))
        || process_committed_mapping_basic_information(pi as u64, page) != Some(view_info)
    {
        return Err(nt_address_space::STATUS_NOT_COMMITTED);
    }
    if fault_plan.copy_on_write {
        let old_protection =
            nt_address_space::mapped_view_fault_plan(view_info.protect, false).map_protection;
        vm_promote_mapped_cow_page(
            nt_handler,
            pi,
            page,
            frame,
            old_protection,
            fault_plan.map_protection,
            pml4,
            scratch_base,
        )?;
        return Ok(GenericSectionFaultResult::Mapped);
    }
    hosted_thread_memory_access(pi as u64, page, nt_address_space::PAGE_SIZE)?;
    ensure_process_user_page_table(nt_handler, pi, page, pml4)?;
    if fault_plan.mark_dirty {
        generic_section_mark_dirty_if_backed(&mut *generic_sections, section_index, section, page_index)?;
    }
    let (map_cap, copy_error) = copy_cap_r(frame);
    if copy_error != 0 {
        if map_cap != 0 {
            let _ = cnode_delete_recycle_r(map_cap);
        }
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    let map_error = page_map_r(
        map_cap,
        page,
        vm_page_rights(fault_plan.map_protection),
        pml4,
    );
    if map_error != 0 {
        let _ = cnode_delete_recycle_r(map_cap);
        if map_error == 8 && csrss_frame_get_exact(pi as u64, page).0 != 0 {
            return Ok(GenericSectionFaultResult::Mapped);
        }
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    let source_cap = csrss_frame_create_source_copy(map_cap, pi as u64, page, b"section-map");
    if source_cap == 0 || !csrss_frame_put_section_mapping(pi as u64, lifetime, page, map_cap, source_cap) {
        if source_cap != 0 {
            let _ = cnode_delete_recycle_r(source_cap);
        }
        let _ = page_unmap_r(map_cap);
        let _ = cnode_delete_recycle_r(map_cap);
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    let trace = GENERIC_SECTION_FAULT_TRACE.fetch_add(1, Ordering::Relaxed);
    if trace < 32 {
        print_str(b"[section] fault pi=");
        print_u64(pi as u64);
        print_str(b" page=0x");
        print_hex((page >> 32) as u32);
        print_hex(page as u32);
        print_str(b" sec-page=");
        print_u64(page_index);
        print_str(b" frame=0x");
        print_hex(frame as u32);
        print_str(b"\n");
    }
    Ok(GenericSectionFaultResult::Mapped)
}

fn sec_image_page_shareable(
    pe: &nt_pe_loader::PeFile,
    rva: u32,
    base: u64,
    main_image_base: u64,
    protection: u32,
    plan: nt_address_space::VmImageViewFaultPlan,
) -> bool {
    base != main_image_base
        && (nt_address_space::image_view_shared_cacheable(protection, plan.map_protection)
            || (!plan.copy_on_write
                && (protection & 0xff) == nt_address_space::PAGE_WRITECOPY
                && sec_image_clean_writecopy_shareable(pe, rva, base)))
}

unsafe fn discard_unpublished_image_backing(source: u64, faults: &mut u64) {
    if source != 0 {
        recycle_mapped_cap(source);
        *faults = faults.checked_sub(1).expect("unpublished image fill owns its scratch slot");
    }
}

/// Make one committed SEC_IMAGE page resident through the same cache, COW, fill, and registration
/// authorities used by a real user fault. `fault_observed` requests a remap when a retained private
/// source frame proves the page was previously filled but the user mapping faulted again.
pub(crate) unsafe fn service_image_page_residency(
    nt_handler: &mut ExecNtHandler,
    pi: usize,
    page: u64,
    base: u64,
    pe: &nt_pe_loader::PeFile,
    pml4: u64,
    scratch_base: u64,
    fault_access: nt_address_space::FaultAccess,
    fault_observed: bool,
    filled_pages: &mut [u64; 512],
    faults: &mut u64,
) -> Result<(), u32> {
    let process = nt_handler.capture_process_identity(pi)
        .ok_or(nt_address_space::STATUS_ACCESS_VIOLATION)?;
    let lifetime = nt_memory_manager::MemoryLifetime::Process(process);
    hosted_thread_memory_access(pi as u64, page, 0x1000)?;
    let info = process_committed_mapping_basic_information(pi as u64, page)
        .ok_or(nt_address_space::STATUS_NOT_COMMITTED)?;
    let residency = nt_address_space::vm_residency_page_plan(page, info)?;
    if residency.source != nt_address_space::VmResidencySource::Image {
        return Err(nt_address_space::STATUS_CONFLICTING_ADDRESSES);
    }
    nt_address_space::image_view_fault_access_status(info.protect, fault_access)?;
    if nt_handler.restore_process_pagefile_page(pi, page, pml4, scratch_base)? {
        return Ok(());
    }
    let resident = nt_memory_manager::admit_resident_reprotect(
        pi as u64,
        process,
        page,
        &*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY),
    )?;

    let write_fault = fault_access == nt_address_space::FaultAccess::Write;
    let fault_plan = nt_address_space::image_view_fault_plan(info.protect, write_fault);
    let rights = vm_page_rights(fault_plan.map_protection);
    if rights == 0 {
        return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
    }
    let rva = page
        .checked_sub(base)
        .and_then(|offset| u32::try_from(offset).ok())
        .ok_or(nt_address_space::STATUS_CONFLICTING_ADDRESSES)?;
    let shared_mapping_registered = shared_image_mapping_contains_for(pi as u64, process, page)?;

    if fault_plan.requires_private_backing()
        && (resident.is_some() || shared_mapping_registered)
    {
        let read_protection =
            nt_address_space::image_view_fault_plan(info.protect, false).map_protection;
        let prepared = nt_handler.prepare_private_mapping_backing(pi, page)?;
        vm_promote_image_cow_page(
            pi,
            lifetime,
            page,
            read_protection,
            fault_plan.map_protection,
            pml4,
            scratch_base,
        )?;
        nt_handler.commit_process_commit_charge(prepared);
        let filled_count = (*faults as usize).min(filled_pages.len());
        for filled_page in filled_pages.iter_mut().take(filled_count) {
            if *filled_page == page {
                *filled_page = 0;
            }
        }
        return Ok(());
    }

    let main_image_base = nt_handler.loop_ctx.and_then(|ctx| ctx.for_process(pi))
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?.img_base;
    let shareable = sec_image_page_shareable(pe, rva, base, main_image_base, info.protect, fault_plan);
    let cached = if shareable { dll_cache_get(page) } else { 0 };

    if !fault_observed
        && (resident.is_some() || shared_mapping_registered)
    {
        return Ok(());
    }

    nt_handler.ensure_process_working_set_admission(pi, page, scratch_base)?;

    let replacing_shared_mapping = shareable && fault_observed && shared_mapping_registered;
    if replacing_shared_mapping {
        let end = page
            .checked_add(0x1000)
            .ok_or(nt_address_space::STATUS_CONFLICTING_ADDRESSES)?;
        // Retire the old mapped cap before installing a sibling for the same physical frame.
        shared_image_mapping_unmap_range(pi as u64, process, page, end)?;
    }

    if !shareable {
        let resident = nt_memory_manager::admit_resident_reprotect(
            pi as u64,
            process,
            page,
            &*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY),
        )?;
        let existing = resident
            .map(|record| record.frame)
            .unwrap_or_else(|| dll_cache_get(page));
        if existing != 0 && existing != dll_cache_get(page) {
            if !fault_observed {
                return Ok(());
            }
            let (map_cap, copy_error) = copy_cap_r(existing);
            if copy_error != 0 {
                if map_cap != 0 {
                    let _ = cnode_delete_recycle_r(map_cap);
                }
                return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
            }
            let map_error = page_map_r(map_cap, page, rights, pml4);
            if map_error != 0 {
                let _ = cnode_delete_recycle_r(map_cap);
                return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
            }
            let trace = FIXUP_REMAP_N.fetch_add(1, Ordering::Relaxed);
            if trace < 16 {
                print_str(b"[fixup-remap] pi=");
                print_u64(pi as u64);
                print_str(b" page=0x");
                print_hex(page as u32);
                print_str(b" frame preserved\n");
            }
            return Ok(());
        }
    }

    let prepared = if fault_plan.requires_private_backing() {
        nt_handler.prepare_private_mapping_backing(pi, page)?
    } else {
        crate::exec_handler::PreparedProcessCommitCharge::default()
    };
    let (frame, private_alias, private_source_cap) = if cached != 0 {
        DLL_SHARED_HITS.fetch_add(1, Ordering::Relaxed);
        (cached, 0, 0)
    } else {
        if *faults >= SEC_IMAGE_FAULT_CAP {
            return Err(nt_address_space::STATUS_COMMITMENT_LIMIT);
        }
        let scratch = scratch_base
            .checked_add(
                faults
                    .checked_mul(0x1000)
                    .ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?,
            )
            .ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?;
        let (frame, frame_error) = alloc_frame_r();
        if frame_error != 0 {
            if frame != 0 {
                let _ = cnode_delete_recycle_r(frame);
            }
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        }
        if page_map_r(frame, scratch, RW_NX, CAP_INIT_THREAD_VSPACE) != 0 {
            let _ = cnode_delete_recycle_r(frame);
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        }
        let _ = fill_image_page(pe, rva, scratch);
        if shareable {
            if !dll_cache_put(page, frame) {
                let _ = page_unmap_r(frame);
                let _ = cnode_delete_recycle_r(frame);
                return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
            }
        }
        *faults += 1;
        (
            frame,
            if shareable { 0 } else { scratch },
            if shareable { 0 } else { frame },
        )
    };

    let (map_cap, copy_error) = copy_cap_r(frame);
    if copy_error != 0 {
        if map_cap != 0 {
            let _ = cnode_delete_recycle_r(map_cap);
        }
        discard_unpublished_image_backing(private_source_cap, faults);
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    let map_error = page_map_r(map_cap, page, rights, pml4);
    if map_error != 0 {
        let _ = cnode_delete_recycle_r(map_cap);
        discard_unpublished_image_backing(private_source_cap, faults);
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }

    if shareable {
        if !shared_image_mapping_put_banked(pi as u64, process, page, map_cap) {
            let _ = page_unmap_r(map_cap);
            let _ = cnode_delete_recycle_r(map_cap);
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        }
        if replacing_shared_mapping {
            IMAGE_MAP_CAP_REPLACEMENTS.fetch_add(1, Ordering::Relaxed);
        }
    } else if private_source_cap != 0 {
        if !csrss_frame_put_at_cap_source_backing(
            pi as u64,
            lifetime,
            page,
            map_cap,
            private_alias,
            private_source_cap,
            private_source_cap,
            fault_plan.requires_private_backing(),
            if fault_plan.requires_private_backing() { private_source_cap } else { 0 },
        ) {
            let _ = page_unmap_r(map_cap);
            let _ = cnode_delete_recycle_r(map_cap);
            discard_unpublished_image_backing(private_source_cap, faults);
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        }
        let filled_index = (*faults as usize).saturating_sub(1);
        nt_handler.commit_process_commit_charge(prepared);
        if filled_index < filled_pages.len() {
            filled_pages[filled_index] = if fault_plan.requires_private_backing() {
                0
            } else {
                page
            };
        }
    }
    note_boot_progress(BootProgress::PageMappingPublished);
    Ok(())
}

pub(crate) fn vm_fault_access_from_x86_error(error_code: u64) -> nt_address_space::FaultAccess {
    if error_code & 0x10 != 0 {
        nt_address_space::FaultAccess::Execute
    } else if error_code & 0x2 != 0 {
        nt_address_space::FaultAccess::Write
    } else {
        nt_address_space::FaultAccess::Read
    }
}

/// Serve the committed PE images owned by the hosted executable loader or DLL registry.
/// Native Section views are resolved first by callers; this path keeps the original PE
/// reader, process generation, VAD, and resident COW backing tied to the selected process.
pub(crate) unsafe fn service_legacy_image_page_residency(
    handler: &mut ExecNtHandler,
    pi: usize,
    page: u64,
    access: nt_address_space::FaultAccess,
    observation: nt_address_space::ImageFaultObservation,
) -> Result<(), u32> {
    let ctx = handler.loop_ctx.and_then(|ctx| ctx.for_process(pi))
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let target = (&*ctx.procs).get(pi).copied()
        .filter(|target| target.pml4 != 0 && target.scratch_base != 0)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let process = handler.capture_process_identity(pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let allocation = process_committed_image_allocation(pi as u64, page)
        .ok_or(nt_address_space::STATUS_NOT_COMMITTED)?;
    let base = allocation.allocation_base;
    let info = process_committed_mapping_basic_information(pi as u64, page)
        .ok_or(nt_address_space::STATUS_NOT_COMMITTED)?;
    let resident_mapping = if observation == nt_address_space::ImageFaultObservation::Protection {
        (&*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY))
            .get(pi as u64, page)
            .is_some_and(|record| record.is_resident()
                && record.lifetime == nt_memory_manager::MemoryLifetime::Process(process))
            || shared_image_mapping_contains_for(pi as u64, process, page)?
    } else {
        false
    };
    nt_address_space::legacy_image_receive_fault_status(
        info, base, access, observation, resident_mapping,
    )?;
    let _image_reader = if base == target.img_base {
        let _durable = crate::allocator::enter_durable();
        let image = (&*ctx.exe_image_catalog).get_by_pi(pi)
            .ok_or(nt_address_space::STATUS_CONFLICTING_ADDRESSES)?;
        Some(crate::hosted_loaded_images::HostedImageReadScope::capture(
            ctx.hosted_loaded_images, nt_exe_image::SpawnTarget::from_image(image),
        ).map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?)
    } else {
        None
    };
    let pe = if base == target.img_base {
        (&*ctx.hosted_loaded_images).pe_by_pi(pi)
            .ok_or(nt_address_space::STATUS_CONFLICTING_ADDRESSES)?
    } else if !ctx.ntdll_pe.is_null() && base == ctx.nt_base {
        &*ctx.ntdll_pe
    } else {
        let (index, _) = (&*ctx.reg).dll_for_page(pi, base)
            .ok_or(nt_address_space::STATUS_CONFLICTING_ADDRESSES)?;
        ctx.dll_pes().get(index).and_then(|slot| slot.as_ref())
            .ok_or(nt_address_space::STATUS_CONFLICTING_ADDRESSES)?
    };
    service_image_page_residency(
        handler, pi, page, base, pe, target.pml4, target.scratch_base,
        access, observation != nt_address_space::ImageFaultObservation::CopyAccess,
        &mut *ctx.filled_pages, &mut *ctx.faults,
    )
}

/// The outer boundary alone owns the handler and may service a retained Receive child.
unsafe fn service_receive_child_fault(
    handler: &mut ExecNtHandler,
    capture: crate::win32k_glue::ReceiveFaultCapture,
    binding: nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
    pml4: u64,
    scratch_base: u64,
) -> Result<(), u32> {
    match capture {
        crate::win32k_glue::ReceiveFaultCapture::Resident(resident) => {
            handler.service_captured_private_read_fault(resident, binding)
        }
        crate::win32k_glue::ReceiveFaultCapture::StackGuard(guard) => {
            if guard.child != binding
                || handler.capture_process_identity(binding.pi) != Some(binding.process)
            {
                return Err(nt_process::STATUS_INVALID_HANDLE);
            }
            let page = guard.address & !(nt_address_space::PAGE_SIZE - 1);
            let map = process_vm_region_map(binding.pi)
                .ok_or(nt_address_space::STATUS_ACCESS_VIOLATION)?;
            let extent = map.extent_at(page)
                .ok_or(nt_address_space::STATUS_ACCESS_VIOLATION)?;
            if extent.allocation_base != guard.allocation_base
                || extent.type_ != nt_address_space::MEM_PRIVATE
                || extent.state != nt_address_space::VmExtentState::Committed
                || map.protection_at(page) != Some(guard.protection)
            {
                return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
            }
            match crate::hosted_stack_growth::service_hosted_stack_growth(
                handler,
                binding.pi,
                binding.badge,
                guard.address,
                pml4,
                scratch_base,
                vm_fault_access_from_x86_error(guard.error_code),
            )? {
                Some(nt_thread_start::stack_vad::StackVadOutcome::Grown) => Ok(()),
                _ => Err(nt_address_space::STATUS_ACCESS_VIOLATION),
            }
        }
        crate::win32k_glue::ReceiveFaultCapture::NativeImage(image) => {
            if image.child != binding
                || handler.capture_process_identity(binding.pi) != Some(binding.process)
                || process_committed_mapping_basic_information(binding.pi as u64, image.page)
                    != Some(image.information)
            {
                return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
            }
            match handler.service_native_image_page_residency(
                binding.pi,
                image.page,
                image.access,
                image.observation,
            )? {
                Some(()) => Ok(()),
                None => service_legacy_image_page_residency(
                    handler, binding.pi, image.page, image.access, image.observation,
                ),
            }
        }
    }
}


unsafe fn service_private_guard_page_fault(
    nt_handler: &mut ExecNtHandler,
    pi: usize,
    badge: u64,
    page: u64,
    pml4: u64,
    scratch_base: u64,
    fault_access: nt_address_space::FaultAccess,
) -> Result<bool, u32> {
    hosted_thread_memory_access(pi as u64, page, nt_address_space::PAGE_SIZE)?;
    let process = nt_handler
        .capture_process_identity(pi)
        .ok_or(nt_address_space::STATUS_ACCESS_VIOLATION)?;
    let resident = nt_memory_manager::admit_resident_reprotect(
        pi as u64,
        process,
        page,
        &*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY),
    )?;
    let Some(vm_map) = process_vm_region_map_mut(pi) else {
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    };
    let before = &mut *core::ptr::addr_of_mut!(VM_MAP_BEFORE);
    let after = &mut *core::ptr::addr_of_mut!(VM_MAP_AFTER);
    *before = *vm_map;
    let Some(extent) = before.extent_at(page) else {
        return Ok(false);
    };
    if extent.state != nt_address_space::VmExtentState::Committed {
        return Ok(false);
    }
    let Some(old_protection) = before.protection_at(page) else {
        return Ok(false);
    };
    let Some(new_protection) =
        nt_address_space::private_guard_page_fault_plan(old_protection, fault_access)
    else {
        return Ok(false);
    };
    *after = *before;
    let plan = after.protect(page, nt_address_space::PAGE_SIZE, new_protection)?;
    let map_result = if resident.is_some() {
        vm_reprotect_private_page(
            pi,
            process,
            page,
            old_protection,
            plan.new_protection,
            pml4,
        )
    } else {
        vm_map_private_page(
            nt_handler,
            pi,
            page,
            plan.new_protection,
            pml4,
            scratch_base,
        )
    };
    map_result?;
    *vm_map = *after;

    let mut teb_write_ok = false;
    if nt_handler
        .hosted_thread_user_stack_for_badge(badge, pi)
        .is_some_and(|(allocation_base, stack_base, _)| {
            page >= allocation_base && page < stack_base
        })
    {
        if let Some(teb) = nt_handler.hosted_thread_teb_for_badge(badge) {
            teb_write_ok = img_spawn::client_copyout_mapped(
                pi as u64,
                teb + 0x10,
                &page.to_le_bytes(),
                scratch_base,
            );
        }
    }

    let trace = PRIVATE_GUARD_PAGE_TRACE.fetch_add(1, Ordering::Relaxed);
    if trace < 32 {
        print_str(b"[guard-page] pi=");
        print_u64(pi as u64);
        print_str(b" badge=");
        print_u64(badge);
        print_str(b" page=0x");
        print_hex((page >> 32) as u32);
        print_hex(page as u32);
        print_str(b" old=0x");
        print_hex(old_protection);
        print_str(b" new=0x");
        print_hex(plan.new_protection);
        print_str(b" teb=");
        print_u64(teb_write_ok as u64);
        print_str(b"\n");
    }
    Ok(true)
}

#[inline(never)]
pub(crate) unsafe fn initialize_service_delay_queue_work() -> Result<(), u32> {
    let storage = &mut *core::ptr::addr_of_mut!(SERVICE_DELAY_QUEUE_WORK);
    if storage.is_some() {
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }
    let _durable = allocator::enter_durable();
    let mut queue = nt_delay_execution::Queue::new();
    if !queue.reserve_capacity(DELAY_WAITER_INITIAL_RESERVE) {
        return Err(nt_process::STATUS_INSUFFICIENT_RESOURCES);
    }
    *storage = Some(queue);
    Ok(())
}

/// Bootstrap callers must prove phase ownership before borrowing this preallocated queue.
pub(crate) unsafe fn bootstrap_dispatcher_deadlines(
    timers: Option<&nt_provider_wait::ProviderTimerTable>,
    now: nt_time::TimeSnapshot,
) -> Result<nt_user_host::dispatcher_deadlines::DispatcherDeadlines, u32> {
    let queue = (&*core::ptr::addr_of!(SERVICE_DELAY_QUEUE_WORK))
        .as_ref()
        .ok_or(nt_process::STATUS_INVALID_PARAMETER)?;
    Ok(nt_user_host::dispatcher_deadlines::DispatcherDeadlines::collect(queue, timers, now))
}

pub(crate) fn service_delay_queue_stats() -> (usize, usize, usize, u64, u64) {
    unsafe {
        let Some(queue) = &*core::ptr::addr_of!(SERVICE_DELAY_QUEUE_WORK) else {
            return (0, 0, 0, 0, 0);
        };
        (
            queue.len(),
            queue.records(),
            queue.capacity(),
            queue.allocation_failures(),
            queue.store_failures(),
        )
    }
}

unsafe fn register_service_delay_drain_context(
    handler: &mut ExecNtHandler,
    queue: &mut nt_delay_execution::Queue,
) {
    BOOTSTRAP_SECTION_OWNER_ACTIVE.store(false, Ordering::Release);
    SERVICE_DELAY_DRAIN_HANDLER.store(handler as *mut ExecNtHandler as u64, Ordering::Release);
    SERVICE_DELAY_DRAIN_QUEUE.store(
        queue as *mut nt_delay_execution::Queue as u64,
        Ordering::Release,
    );
}

/// Resolve only a published live hosted binding. Shared ingress still queries the captured Reply
/// against this exact TCB; neither the badge nor a construction-time runtime is authority.
pub(crate) unsafe fn hosted_ingress_binding(
    badge: u64,
) -> Option<nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>> {
    let handler = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *const ExecNtHandler;
    if handler.is_null() { return None; }
    (&*handler).admit_hosted_thread_ingress(badge).ok().map(|runtime| runtime.binding())
}

/// Called only after a provider operation returned; no handler borrow crosses its execution.
pub(crate) unsafe fn service_observe_desktop_gui_for(
    caller: nt_user_host::provider_logical_caller::ProviderLogicalCaller,
    fact: DesktopGuiFact,
    amount: u64,
) {
    let pointer = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if !pointer.is_null() { (*pointer).observe_desktop_gui_for(caller, fact, amount); }
}

pub(crate) unsafe fn service_observe_desktop_callback_return(
    caller: nt_user_host::provider_logical_caller::ProviderLogicalCaller,
    api_index: u32,
    callback_status: u64,
) {
    if api_index != 0 {
        return;
    }
    let fact = if callback_status as i32 >= 0 {
        DesktopGuiFact::CallbackCompleted
    } else {
        DesktopGuiFact::CallbackFailed
    };
    service_observe_desktop_gui_for(caller, fact, 1);
}

unsafe fn clear_service_delay_drain_context() {
    SERVICE_DELAY_DRAIN_QUEUE.store(0, Ordering::Release);
    SERVICE_DELAY_DRAIN_HANDLER.store(0, Ordering::Release);
    W32_CLIENT_PI.store(u64::MAX, Ordering::Release);
    SERVICE_CRASH_PARKED_MASK.store(0, Ordering::Release);
}

/// Admission for kernel aliases of managed section views. The nested provider pump uses the
/// existing live handler and process epoch; legacy copybacks are serialized by the same owner.
/// `None` means this is not a data-section view, never that admission failed.
pub(crate) unsafe fn service_admit_section_alias(
    pi: u64,
    page: u64,
    write: bool,
    generation: Option<u64>,
) -> Result<Option<u64>, u32> {
    hosted_thread_memory_access(pi, page, 0x1000)?;
    if !process_committed_mapping_basic_information(pi, page)
        .is_some_and(|info| info.type_ == nt_address_space::MEM_MAPPED)
    {
        return Ok(None);
    }
    let pointer = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if pointer.is_null() { return Err(0xC000_00A3); } // STATUS_DEVICE_NOT_READY
    let pi = usize::try_from(pi).map_err(|_| nt_fs::STATUS_INVALID_HANDLE)?;
    let handler = &mut *pointer;
    if generation.is_some_and(|generation| generation == 0 || handler.hosted_process_generation(pi) != Some(generation)) {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    handler.prepare_mapped_section_alias(pi, page, write).map(Some)
}

#[inline]
fn service_watchdog_record_crash_parked(mask: u64) {
    SERVICE_CRASH_PARKED_MASK.store(mask, Ordering::Relaxed);
}

pub(crate) unsafe fn rearm_registered_delay_timer() -> nt_kernel_exec::TimerRearmOutcome {
    let handler_ptr = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    let queue_ptr =
        SERVICE_DELAY_DRAIN_QUEUE.load(Ordering::Acquire) as *mut nt_delay_execution::Queue;
    if handler_ptr.is_null() || queue_ptr.is_null() || !delay_timer_init() {
        return nt_kernel_exec::TimerRearmOutcome::Unavailable;
    }
    delay_timer_rearm(&*queue_ptr, &*handler_ptr)
}

/// Scheduler completion may rearm the live owner, but cannot initialize a bootstrap timer.
pub(crate) unsafe fn rearm_registered_active_delay_timer() {
    let handler = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *const ExecNtHandler;
    if !handler.is_null() {
        rearm_registered_active_delay_timer_with_handler(&*handler);
    }
}

/// Rearm from a native owner that already borrows the live handler. The broker must release
/// its mutable state before deadline selection reads that same state.
pub(crate) unsafe fn rearm_registered_active_delay_timer_with_handler(handler: &ExecNtHandler) {
    if DELAY_TIMER_HANDLER.load(Ordering::Relaxed) == 0
        || DELAY_TIMER_IRQ_STATE.load(Ordering::Acquire) != DELAY_TIMER_IRQ_ACTIVE
    {
        return;
    }
    let queue = SERVICE_DELAY_DRAIN_QUEUE.load(Ordering::Acquire) as *const nt_delay_execution::Queue;
    if !queue.is_null() {
        delay_timer_rearm(&*queue, handler);
    }
}

/// Backend dispatch only publishes a request. The live handler is read at an outer boundary,
/// after backend and mounted queue borrows have been released.
static MOUNTED_NATIVE_TIMER_REARM_DEMAND: nt_kernel_exec::TimerRearmDemand =
    nt_kernel_exec::TimerRearmDemand::new();

pub(crate) fn request_mounted_native_timer_rearm() {
    let now = monotonic_time_100ns();
    crate::driver_launch::publish_mounted_native_block_wake(now);
    request_mounted_native_timer_rearm_after_service();
}

pub(crate) fn request_mounted_native_timer_rearm_after_service() {
    MOUNTED_NATIVE_TIMER_REARM_DEMAND.publish();
}

unsafe fn rearm_requested_mounted_native_timer(handler: &ExecNtHandler) {
    if DELAY_TIMER_HANDLER.load(Ordering::Relaxed) == 0
        || DELAY_TIMER_IRQ_STATE.load(Ordering::Acquire) != DELAY_TIMER_IRQ_ACTIVE
        || SERVICE_DELAY_DRAIN_QUEUE.load(Ordering::Acquire) == 0
    {
        return;
    }
    let Some(attempt) = MOUNTED_NATIVE_TIMER_REARM_DEMAND
        .begin(crate::mounted_volume::mounted_sector_claimable()) else { return };
    let queue = SERVICE_DELAY_DRAIN_QUEUE.load(Ordering::Acquire) as *const nt_delay_execution::Queue;
    let outcome = delay_timer_rearm(&*queue, handler);
    let _ = attempt.finish(outcome);
}

/// Resolve the active process handle table for a win32k Event handle operation.
/// KeStackAttachProcess changes this table without changing the original IPC caller.
fn resolve_win32k_event_handle_pi(
    handler: &ExecNtHandler,
    channel: &spawn_hosts::PumpChannel,
    original_pi: usize,
) -> Result<usize, u32> {
    let invalid = nt_process::STATUS_INVALID_HANDLE;
    let logical = channel.logical_caller.ok_or(invalid)?;
    if !handler.validate_provider_logical_caller(logical)
        || logical.pi() != original_pi
        || logical.pi() as u64 != channel.client_pi
        || logical.process().generation !=
            nt_user_host::process_identity::ProcessGeneration::Hosted(channel.client_generation)
    {
        return Err(invalid);
    }
    let active = unsafe { crate::win32k_glue::current_query_process(logical, channel.pml4) }
        .ok_or(invalid)?;
    if handler.pm_pid_for_pi(active.pi) != Some(active.process.pid)
        || handler.hosted_process_generation(active.pi)
            != match active.process.generation {
                nt_user_host::process_identity::ProcessGeneration::Hosted(generation) => Some(generation),
                _ => None,
            }
    {
        return Err(invalid);
    }
    Ok(active.pi)
}

/// Route kernel Event requests through their retained activation; hosted requests use the live handler.
/// The nested component pump is serialized with native dispatch, so no second handler pointer or
/// lock domain is introduced. GUI redrive remains deferred until the outer dispatch can resume.
pub(crate) fn service_win32k_projected_event_set(
    handler: &mut ExecNtHandler,
    body: u64,
) -> (i32, u64, u64, u64) {
    match handler.provider_set_event(body) {
        Ok((previous, _id, index, _kind)) => {
            if !previous {
                let _ = unsafe { crate::wait_wake_event_set(index, handler) };
                let current = handler
                    .provider_read_event(body)
                    .expect("newly signalled provider Event lost its canonical identity");
                (0, u64::from(previous), u64::from(current), 0)
            } else {
                (0, 1, 1, 0)
            }
        }
        Err(status) => (status as i32, 0, 0, 0),
    }
}

pub(crate) fn service_win32k_projected_event_dereference(
    handler: &mut ExecNtHandler,
    body: u64,
) -> (i32, u64, u64, u64) {
    handler
        .provider_dereference_event(body)
        .map(|count| (0, count as u64, 0, 0))
        .unwrap_or_else(|status| (status as i32, 0, 0, 0))
}

pub(crate) fn service_win32k_projected_event_reclaim(
    handler: &mut ExecNtHandler,
    op: u64,
    first: u64,
    second: u64,
) -> (i32, u64, u64, u64) {
    match op {
        crate::win32k_subsystem::W32_EVENT_OP_DRAIN_RECLAIM => handler
            .pending_event_provider_reclaim()
            .map(|(id, body)| (0, id, body, 0))
            .unwrap_or((0, 0, 0, 0)),
        crate::win32k_subsystem::W32_EVENT_OP_ACK_RECLAIM => handler
            .complete_event_provider_reclaim(first, second)
            .map(|()| (0, 0, 0, 0))
            .unwrap_or_else(|status| (status as i32, 0, 0, 0)),
        _ => (nt_process::STATUS_INVALID_PARAMETER as i32, 0, 0, 0),
    }
}

pub(crate) unsafe fn service_win32k_event_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    message_info: u64,
    op: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> (i32, u64, u64, u64) {
    const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
    const STATUS_DEVICE_NOT_READY: i32 = 0xC000_00A3u32 as i32;
    if op == crate::win32k_subsystem::W32_EVENT_OP_CREATE_NAMED {
        return service_win32k_named_event_request(channel, reply_cap, badge, message_info,
            arg1, arg2, arg3);
    }
    if channel.kernel_caller.is_some() {
        return kernel_provider_activation::service_event(
            channel,
            nt_user_host::provider_kernel_activation::KernelProviderServiceEnvelope {
                badge,
                message_info,
                reply_cap,
            },
            op,
            arg1,
            arg2,
            arg3,
        );
    }
    let client_pi = channel.client_pi;
    let client_generation = channel.client_generation;
    let handler_ptr = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if handler_ptr.is_null() {
        return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
    }
    let handler = &mut *handler_ptr;
    let provider_scoped = matches!(
        op,
        crate::win32k_subsystem::W32_SYNC_OP_PUBLISH
            | crate::win32k_subsystem::W32_SYNC_OP_RELEASE_SEMAPHORE
            | crate::win32k_subsystem::W32_SYNC_OP_RELEASE_MUTANT
            | crate::win32k_subsystem::W32_SYNC_OP_RETIRE
            | crate::win32k_subsystem::W32_SYNC_OP_ACK_RETIREMENT
            | crate::win32k_subsystem::W32_SYNC_OP_QUERY
            |
        crate::win32k_subsystem::W32_EVENT_OP_PUBLISH_LOCAL
            | crate::win32k_subsystem::W32_EVENT_OP_RETIRE_LOCAL
            | crate::win32k_subsystem::W32_EVENT_OP_ACK_LOCAL_RETIREMENT
            | crate::win32k_subsystem::W32_EVENT_OP_SET_LOCAL
            | crate::win32k_subsystem::W32_EVENT_OP_RESET_LOCAL
            | crate::win32k_subsystem::W32_EVENT_OP_CLEAR_LOCAL
            | crate::win32k_subsystem::W32_EVENT_OP_PULSE_LOCAL
            | crate::win32k_subsystem::W32_EVENT_OP_READ_LOCAL
            | crate::win32k_subsystem::W32_TIMER_OP_PUBLISH_LOCAL
            | crate::win32k_subsystem::W32_TIMER_OP_RETIRE_LOCAL
            | crate::win32k_subsystem::W32_TIMER_OP_ACK_LOCAL_RETIREMENT
            | crate::win32k_subsystem::W32_TIMER_OP_SET_LOCAL
            | crate::win32k_subsystem::W32_TIMER_OP_CANCEL_LOCAL
            | crate::win32k_subsystem::W32_TIMER_OP_READ_LOCAL
    );
    let pi = if provider_scoped {
        0
    } else {
        let Ok(pi) = usize::try_from(client_pi) else {
            return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
        };
        if client_generation == 0
            || handler.pm_pid_for_pi(pi).is_none()
            || handler.hosted_process_generation(pi) != Some(client_generation)
        {
            return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
        }
        pi
    };
    match op {
        crate::win32k_subsystem::W32_SYNC_OP_PUBLISH
        | crate::win32k_subsystem::W32_SYNC_OP_RELEASE_SEMAPHORE
        | crate::win32k_subsystem::W32_SYNC_OP_RELEASE_MUTANT
        | crate::win32k_subsystem::W32_SYNC_OP_RETIRE
        | crate::win32k_subsystem::W32_SYNC_OP_ACK_RETIREMENT
        | crate::win32k_subsystem::W32_SYNC_OP_QUERY => {
            let Some(provider) = crate::current_win32k_provider_domain() else {
                return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
            };
            let owner = if op == crate::win32k_subsystem::W32_SYNC_OP_RELEASE_MUTANT {
                let Some(caller) = channel.logical_caller else {
                    return (STATUS_INVALID_PARAMETER, 0, 0, 0);
                };
                if !handler.validate_provider_logical_caller(caller)
                    || caller.pi() as u64 != channel.client_pi
                    || caller.process().generation !=
                        nt_user_host::process_identity::ProcessGeneration::Hosted(channel.client_generation)
                {
                    return (STATUS_INVALID_PARAMETER, 0, 0, 0);
                }
                Some(nt_provider_wait::ProviderWaitOwner {
                    provider_domain: provider.domain,
                    provider_generation: provider.generation,
                    dispatch_id: 1,
                    caller: nt_component_suspension::SuspensionCaller::Hosted(
                        nt_component_suspension::SuspensionHostedClient {
                            client_pi: caller.pi() as u32,
                            client_generation: channel.client_generation,
                            client_tid: u64::from(caller.thread().thread_id()),
                            client_badge: caller.badge(),
                        },
                    ),
                })
            } else {
                None
            };
            service_win32k_provider_sync_request(provider, owner, op, arg1, arg2, arg3)
        }
        crate::win32k_subsystem::W32_EVENT_OP_CREATE => handler
            .provider_create_event(pi, arg1 as u32, arg2 as u32, arg3 != 0)
            .map(|handle| (0, handle, 0, 0))
            .unwrap_or_else(|status| (status as i32, 0, 0, 0)),
        crate::win32k_subsystem::W32_EVENT_OP_REFERENCE =>
            resolve_win32k_event_handle_pi(handler, channel, pi)
            .and_then(|active_pi| handler.provider_reference_event(active_pi, arg1, arg3 as u32, arg2))
            .map(|(body, id, metadata, granted_access)| {
                (
                    0,
                    body,
                    id.0 .0,
                    (metadata << 32) | u64::from(granted_access),
                )
            })
            .unwrap_or_else(|status| (status as i32, 0, 0, 0)),
        crate::win32k_subsystem::W32_EVENT_OP_CLOSE =>
            resolve_win32k_event_handle_pi(handler, channel, pi)
            .and_then(|active_pi| handler.provider_close_event(active_pi, arg1))
            .map(|()| (0, 0, 0, 0))
            .unwrap_or_else(|status| (status as i32, 0, 0, 0)),
        crate::win32k_subsystem::W32_EVENT_OP_DEREFERENCE =>
            service_win32k_projected_event_dereference(handler, arg1),
        crate::win32k_subsystem::W32_EVENT_OP_DRAIN_RECLAIM
        | crate::win32k_subsystem::W32_EVENT_OP_ACK_RECLAIM =>
            service_win32k_projected_event_reclaim(handler, op, arg1, arg2),
        crate::win32k_subsystem::W32_EVENT_OP_RETAIN_POINTER => handler
            .provider_retain_event_pointer(arg1)
            .map(|count| (0, count as u64, 0, 0))
            .unwrap_or_else(|status| (status as i32, 0, 0, 0)),
        crate::win32k_subsystem::W32_EVENT_OP_SET =>
            service_win32k_projected_event_set(handler, arg1),
        crate::win32k_subsystem::W32_EVENT_OP_RESET => handler
            .provider_reset_event(arg1)
            .map(|previous| (0, u64::from(previous), 0, 0))
            .unwrap_or_else(|status| (status as i32, 0, 0, 0)),
        crate::win32k_subsystem::W32_EVENT_OP_CLEAR => handler
            .provider_clear_event(arg1)
            .map(|()| (0, 0, 0, 0))
            .unwrap_or_else(|status| (status as i32, 0, 0, 0)),
        crate::win32k_subsystem::W32_EVENT_OP_PULSE => match handler.provider_pulse_event(arg1) {
            Ok((previous, _id, index, _kind)) => {
                if previous {
                    handler
                        .provider_reset_event(arg1)
                        .expect("provider pulse lost its canonical Event identity");
                    (0, 1, 0, 0)
                } else {
                    let _ = crate::wait_wake_event_pulse(index, handler);
                    (0, 0, 0, 0)
                }
            }
            Err(status) => (status as i32, 0, 0, 0),
        },
        crate::win32k_subsystem::W32_EVENT_OP_READ => handler
            .provider_read_event(arg1)
            .map(|signaled| (0, u64::from(signaled), 0, 0))
            .unwrap_or_else(|status| (status as i32, 0, 0, 0)),
        crate::win32k_subsystem::W32_EVENT_OP_PUBLISH_LOCAL => {
            let Some(provider) = crate::current_win32k_provider_domain() else {
                return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
            };
            handler
                .provider_publish_local_event(provider, arg1, arg2 as u32, arg3 != 0)
                .map(|(id, metadata)| {
                    (
                        0,
                        id.0.slot().checked_add(1).unwrap_or(0),
                        u64::from(id.0.generation().0),
                        metadata,
                    )
                })
                .unwrap_or_else(|status| (status as i32, 0, 0, 0))
        }
        crate::win32k_subsystem::W32_EVENT_OP_RETIRE_LOCAL => {
            let Some(provider) = crate::current_win32k_provider_domain() else {
                return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
            };
            handler
                .provider_retire_local_event(provider, arg1)
                .map(|ready| match ready {
                    Some(id) => (
                        0,
                        id.0.slot().checked_add(1).unwrap_or(0),
                        u64::from(id.0.generation().0),
                        0,
                    ),
                    None => (0x0000_0103, 0, 0, 0),
                })
                .unwrap_or_else(|status| (status as i32, 0, 0, 0))
        }
        crate::win32k_subsystem::W32_EVENT_OP_ACK_LOCAL_RETIREMENT => {
            let Some(provider) = crate::current_win32k_provider_domain() else {
                return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
            };
            let Some(id) = nt_kernel_exec::EventObjectId::from_wire_parts(arg2, arg3) else {
                return (STATUS_INVALID_PARAMETER, 0, 0, 0);
            };
            handler
                .provider_ack_local_event_retirement(
                    provider,
                    arg1,
                    id,
                )
                .map(|()| (0, 0, 0, 0))
                .unwrap_or_else(|status| (status as i32, 0, 0, 0))
        }
        crate::win32k_subsystem::W32_EVENT_OP_SET_LOCAL
        | crate::win32k_subsystem::W32_EVENT_OP_PULSE_LOCAL => {
            let Some(provider) = crate::current_win32k_provider_domain() else {
                return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
            };
            use nt_user_host::provider_local_event_request::LocalEventRequest;
            let mode = match LocalEventRequest::decode(op, arg1, arg2, arg3) {
                Ok(LocalEventRequest::Set { .. }) => nt_kernel_exec::EventSignalMode::Set,
                Ok(LocalEventRequest::Pulse { .. }) => nt_kernel_exec::EventSignalMode::Pulse,
                Err(status) => return (status as i32, 0, 0, 0),
                _ => unreachable!("local signaling opcode decoded as another operation"),
            };
            crate::provider_local_event::signal(handler, provider, arg1, mode)
                .unwrap_or_else(|status| (status as i32, 0, 0, 0))
        }
        crate::win32k_subsystem::W32_EVENT_OP_RESET_LOCAL => {
            let Some(provider) = crate::current_win32k_provider_domain() else {
                return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
            };
            handler
                .provider_reset_local_event(provider, arg1)
                .and_then(|previous| handler.provider_read_local_event_with_sequence(provider, arg1)
                    .map(|(_, sequence)| (0, u64::from(previous), 0, sequence)))
                .unwrap_or_else(|status| (status as i32, 0, 0, 0))
        }
        crate::win32k_subsystem::W32_EVENT_OP_CLEAR_LOCAL => {
            let Some(provider) = crate::current_win32k_provider_domain() else {
                return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
            };
            handler
                .provider_clear_local_event(provider, arg1)
                .and_then(|()| handler.provider_read_local_event_with_sequence(provider, arg1)
                    .map(|(_, sequence)| (0, 0, 0, sequence)))
                .unwrap_or_else(|status| (status as i32, 0, 0, 0))
        }
        crate::win32k_subsystem::W32_EVENT_OP_READ_LOCAL => {
            let Some(provider) = crate::current_win32k_provider_domain() else {
                return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
            };
            handler
                .provider_read_local_event_with_sequence(provider, arg1)
                .map(|(signaled, sequence)| (0, u64::from(signaled), 0, sequence))
                .unwrap_or_else(|status| (status as i32, 0, 0, 0))
        }
        crate::win32k_subsystem::W32_TIMER_OP_PUBLISH_LOCAL
        | crate::win32k_subsystem::W32_TIMER_OP_RETIRE_LOCAL
        | crate::win32k_subsystem::W32_TIMER_OP_ACK_LOCAL_RETIREMENT
        | crate::win32k_subsystem::W32_TIMER_OP_SET_LOCAL
        | crate::win32k_subsystem::W32_TIMER_OP_CANCEL_LOCAL
        | crate::win32k_subsystem::W32_TIMER_OP_READ_LOCAL => {
            let Some(provider) = crate::current_win32k_provider_domain() else {
                return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
            };
            service_win32k_provider_timer_request(provider, op, arg1, arg2, arg3)
        }
        _ => (STATUS_INVALID_PARAMETER, 0, 0, 0),
    }
}

/// Capture the inline named-Event frame under the exact physical provider job before any
/// namespace or handle effect. The attached process is the target handle table.
unsafe fn service_win32k_named_event_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    name_len: u64,
    sd_len: u64,
    reserved: u64,
) -> (i32, u64, u64, u64) {
    let invalid = nt_process::STATUS_INVALID_HANDLE;
    if reserved != 0 || channel.kernel_caller.is_some() {
        return (nt_process::STATUS_INVALID_PARAMETER as i32, 0, 0, 0);
    }
    let (route, dispatch, caller) = match authenticate_win32k_service_request(
        channel, reply_cap, badge, mi,
        (crate::win32k_subsystem::W32_EVENT_LABEL << 12) | 4,
    ) {
        Ok(owner) => owner,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    let Some(logical) = channel.logical_caller else { return (invalid as i32, 0, 0, 0) };
    let Some(target) = crate::win32k_glue::current_query_process(logical, channel.pml4)
    else { return (invalid as i32, 0, 0, 0) };
    let capture = match crate::win32k_subsystem::named_event::read_owned(
        (route, dispatch, caller), name_len, sd_len,
    ) {
        Ok(capture) => capture,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    let handler = match registry_live_handler() {
        Ok(handler) => handler,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    if handler.pm_pid_for_pi(target.pi) != Some(target.process.pid)
        || handler.hosted_process_generation(target.pi)
            != match target.process.generation {
                nt_user_host::process_identity::ProcessGeneration::Hosted(generation) => Some(generation),
                _ => None,
            }
    {
        return (invalid as i32, 0, 0, 0);
    }
    handler.provider_create_named_event(target.pi, caller, &capture)
        .map(|(status, handle)| (status as i32, handle, 0, 0))
        .unwrap_or_else(|status| (status as i32, 0, 0, 0))
}

/// Authenticate at the entry adapter, then mutate one exact root-owned sync identity.
/// Release triggers the existing canonical waiter selector after the mutation is visible.
pub(crate) unsafe fn service_win32k_provider_sync_request(
    provider: nt_provider_wait::ProviderDomainIdentity,
    owner: Option<nt_provider_wait::ProviderWaitOwner>,
    op: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> (i32, u64, u64, u64) {
    use crate::win32k_subsystem::*;
    const INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
    let result: Result<(u64, u64, u64), u32> = match op {
        W32_SYNC_OP_PUBLISH => {
            let kind = match arg2 >> 32 {
                1 => nt_provider_wait::ProviderSyncKind::Semaphore {
                    initial_count: arg2 as u32 as i32,
                    limit: arg3 as u32 as i32,
                },
                2 if arg2 as u32 == 0 && arg3 == 0 => nt_provider_wait::ProviderSyncKind::Mutant,
                _ => return (INVALID_PARAMETER, 0, 0, 0),
            };
            crate::provider_dispatcher_backend::publish_sync(provider, arg1, kind)
                .map(|canonical| (canonical.object_id, canonical.object_generation, 0))
        }
        W32_SYNC_OP_RELEASE_SEMAPHORE if arg3 == 0 =>
            crate::provider_dispatcher_backend::release_sync_semaphore(provider, arg1, arg2 as u32 as i32)
                .map(|previous| (previous as u32 as u64, 0, 0)),
        W32_SYNC_OP_RELEASE_MUTANT if arg2 == 0 && arg3 == 0 =>
            owner.ok_or(INVALID_PARAMETER as u32).and_then(|owner|
                crate::provider_dispatcher_backend::release_sync_mutant(provider, arg1, owner))
                .map(|previous| (previous as u32 as u64, 0, 0)),
        W32_SYNC_OP_RETIRE if arg2 == 0 && arg3 == 0 =>
            crate::provider_dispatcher_backend::begin_retire_sync(provider, arg1)
                .map(|retirement| (retirement.canonical.object_id,
                    retirement.canonical.object_generation,
                    retirement.canonical.object_type as u64)),
        W32_SYNC_OP_ACK_RETIREMENT => {
            let kind = match arg3 >> 32 {
                2 => nt_provider_wait::ProviderWaitObjectType::Semaphore,
                7 => nt_provider_wait::ProviderWaitObjectType::Mutant,
                _ => return (INVALID_PARAMETER, 0, 0, 0),
            };
            let canonical = nt_provider_wait::ProviderWaitObject::new(kind, arg2, arg3 as u32 as u64);
            crate::provider_dispatcher_backend::ack_retire_sync(provider, arg1, canonical)
                .map(|()| (0, 0, 0))
        }
        W32_SYNC_OP_QUERY => {
            let kind = match arg3 >> 32 {
                2 => nt_provider_wait::ProviderWaitObjectType::Semaphore,
                7 => nt_provider_wait::ProviderWaitObjectType::Mutant,
                _ => return (INVALID_PARAMETER, 0, 0, 0),
            };
            let canonical = nt_provider_wait::ProviderWaitObject::new(kind, arg2, arg3 as u32 as u64);
            crate::provider_dispatcher_backend::snapshot_sync(provider, arg1, canonical)
                .and_then(|snapshot| match snapshot.mutant_owner {
                    None => Ok((snapshot.signal_state as u32 as u64, 0, 0)),
                    Some(nt_component_suspension::SuspensionCaller::Hosted(client)) =>
                        Ok((snapshot.signal_state as u32 as u64, client.client_tid, client.client_generation)),
                    Some(nt_component_suspension::SuspensionCaller::Kernel { .. }) =>
                        Err(INVALID_PARAMETER as u32),
                })
        }
        _ => Err(INVALID_PARAMETER as u32),
    };
    match result {
        Ok((out1, out2, out3)) => {
            if matches!(op, W32_SYNC_OP_RELEASE_SEMAPHORE | W32_SYNC_OP_RELEASE_MUTANT) {
                let handler = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
                if let Some(handler) = handler.as_mut() {
                    let mut objects = handler.dispatcher_objects(None);
                    let _ = provider_wait_select_ready(&mut objects);
                } else {
                    let _ = dispatcher_bootstrap::with_provider_objects(|mut objects| {
                        provider_wait_select_ready(&mut objects)
                    });
                }
            }
            (0, out1, out2, out3)
        }
        Err(status) => (status as i32, 0, 0, 0),
    }
}

pub(crate) unsafe fn service_win32k_provider_timer_request(
    provider: nt_provider_wait::ProviderDomainIdentity,
    op: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> (i32, u64, u64, u64) {
    let handler_ptr = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    let result = if let Some(handler) = handler_ptr.as_mut() {
        crate::provider_local_timer_request::dispatch(
            &mut handler.provider_timers, provider, op, arg1, arg2, arg3,
        )
    } else {
        match dispatcher_bootstrap::with_local_timers(|timers| {
            crate::provider_local_timer_request::dispatch(timers, provider, op, arg1, arg2, arg3)
        }) {
            Ok(result) => result,
            Err(status) => Err(status),
        }
    };
    match result {
        Ok(response) => {
            if matches!(
                op,
                crate::win32k_subsystem::W32_TIMER_OP_SET_LOCAL
                    | crate::win32k_subsystem::W32_TIMER_OP_CANCEL_LOCAL
            ) {
                let _ = rearm_registered_delay_timer();
            }
            response
        }
        Err(status) => (status as i32, 0, 0, 0),
    }
}

/// Revalidate retained routing metadata without holding any handler borrow across provider IPC.
pub(crate) unsafe fn validate_provider_logical_caller(
    caller: nt_user_host::provider_logical_caller::ProviderLogicalCaller,
) -> bool {
    let handler = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *const ExecNtHandler;
    handler.as_ref().is_some_and(|handler| handler.validate_provider_logical_caller(caller))
}

unsafe fn authenticate_win32k_service_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    expected_mi: u64,
) -> Result<(
    nt_component_suspension::peer_registry::PeerRoute,
    nt_component_suspension::LaneDispatchIdentity,
    nt_process::native_handle::NativeHandleCaller,
), u32> {
    let (route, dispatch) = crate::provider_service_ingress::authenticate(
        channel, reply_cap, badge, mi, expected_mi,
    )?;
    let caller = crate::provider_registry_caller::resolve(channel)?;
    Ok((route, dispatch, caller))
}

pub(crate) unsafe fn service_win32k_gdi_image_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    packet: u64,
    length: u64,
    spare: [u64; 2],
) -> crate::gdi_routed_image_work::SubmitResult {
    use crate::gdi_routed_image_work::SubmitResult;
    let rejected = |stage: &[u8], status: u32| {
        print_str(b"[gdi-image-ingress] rejected stage="); print_str(stage);
        print_str(b" status=0x"); print_hex(status);
        print_str(b" tcb=0x"); print_hex_u64(channel.tcb);
        print_str(b" packet=0x"); print_hex_u64(packet);
        print_str(b" length="); print_u64(length); print_str(b"\n");
        SubmitResult::Ready((status as i32, 0))
    };
    if spare != [0; 2] {
        return rejected(b"spare", nt_process::STATUS_INVALID_PARAMETER);
    }
    let (route, dispatch, caller) = match authenticate_win32k_service_request(
        channel, reply_cap, badge, mi,
        (crate::win32k_subsystem::W32_GDI_LOAD_LABEL << 12) | 4,
    ) {
        Ok(owner) => owner,
        Err(status) => return rejected(b"authentication", status),
    };
    if !matches!(crate::win32k_glue::win32k_physical_stack_route_for_channel(
        channel.tcb, channel.fault_ep, reply_cap,
    ), Some((physical_route, physical_dispatch, _, _))
        if physical_route == route && physical_dispatch == dispatch)
    {
        return rejected(b"physical-stack-route", nt_process::STATUS_INVALID_PARAMETER);
    }
    use spawn_hosts::shared_ingress::owner::runtime;
    let source = match runtime::physical_source(route) {
        Ok(source) => source,
        Err(_) => return rejected(b"physical-source", nt_process::STATUS_INVALID_PARAMETER),
    };
    if source.tcb != channel.tcb || source.pml4 != channel.pml4 {
        return rejected(b"physical-vspace", nt_process::STATUS_INVALID_PARAMETER);
    }
    let runtime::PhysicalDomain::Provider { catalog, domain } = source.domain else {
        return rejected(b"provider-kind", nt_process::STATUS_INVALID_PARAMETER);
    };
    if (&*core::ptr::addr_of!(crate::PROVIDER_WAIT_DOMAINS)).identity() != Some(catalog)
        || !crate::win32k_provider_domain_is_current(domain)
    {
        return rejected(b"provider-generation", nt_process::STATUS_INVALID_PARAMETER);
    }
    print_str(b"[gdi-image-ingress] admitted tcb=0x"); print_hex_u64(channel.tcb);
    print_str(b" packet=0x"); print_hex_u64(packet);
    print_str(b" length="); print_u64(length); print_str(b"\n");
    match crate::fs_loader::exec_fs_mount_identity().and_then(
        crate::fs_loader::exec_block_route_kind,
    ) {
        Some(nt_fs::BlockSourceKind::Boot) => SubmitResult::Ready(
            crate::driver_launch::service_win32k_gdi_image_request(packet, length, source),
        ),
        Some(nt_fs::BlockSourceKind::Native | nt_fs::BlockSourceKind::Draining) => {
            crate::gdi_routed_image_work::submit_routed_gdi_image(
                route, dispatch, reply_cap, caller, source, packet, length,
            )
        }
        None => rejected(b"mount-route", nt_fs::STATUS_DEVICE_NOT_READY),
    }
}

/// Directory-object requests carry only inline IPC words; all authority is reconstructed here.
pub(crate) unsafe fn service_win32k_directory_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    op: u64,
    m1: u64,
    m2: u64,
    m3: u64,
) -> crate::provider_directory_broker::SubmitResult {
    use crate::provider_directory_broker::SubmitResult;
    let (route, dispatch, caller) = match authenticate_win32k_service_request(
        channel, reply_cap, badge, mi, (crate::win32k_subsystem::W32_DIRECTORY_LABEL << 12) | 4,
    ) {
        Ok(owner) => owner,
        Err(status) => return SubmitResult::Ready((status as i32, 0, 0, 0)),
    };
    let pointer = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if pointer.is_null() {
        return SubmitResult::Ready((0xC000_00A3u32 as i32, 0, 0, 0));
    }
    crate::provider_directory_broker::dispatch(
        &mut *pointer, route, dispatch, caller, reply_cap, op, m1, m2, m3)
}

/// Create-only Section broker. The provider's packet is data, never caller authority.
pub(crate) unsafe fn service_win32k_section_create_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    op: u64,
    first: u64,
    second: u64,
    third: u64,
) -> crate::provider_section_broker::SubmitResult {
    use crate::provider_section_broker::SubmitResult;
    use nt_io_manager::win32k_mm_section_wire as mm_wire;
    if matches!(op, mm_wire::OP_DEREFERENCE | mm_wire::OP_UNMAP | mm_wire::OP_UNMAP_CLIENT) {
        return crate::provider_section_cleanup::service_win32k_section_cleanup_request(
            channel, reply_cap, badge, mi, op, first, second, third,
        );
    }
    let (route, dispatch, caller) = match authenticate_win32k_service_request(
        channel,
        reply_cap,
        badge,
        mi,
        (crate::win32k_subsystem::W32_SECTION_CREATE_LABEL << 12) | 4,
    ) {
        Ok(owner) => owner,
        Err(status) => {
            print_str(b"[kernel-section-service-failed] stage=authentication op=0x");
            print_hex_u64(op);
            print_str(b" first=0x"); print_hex_u64(first);
            print_str(b" tcb=0x"); print_hex_u64(channel.tcb);
            print_str(b" status=0x"); print_hex(status); print_str(b"\n");
            return SubmitResult::Ready((status as i32, 0, 0, 0));
        }
    };
    let handler = match registry_live_handler() {
        Ok(handler) if registered_section_table_for_handler(handler).is_ok() => handler,
        Ok(_) => return SubmitResult::Ready((0xC000_00A3u32 as i32, 0, 0, 0)),
        Err(_) => {
            if bootstrap_section_table().is_err() || op == mm_wire::OP_MAP_CLIENT
                || !crate::provider_section_broker::bootstrap_caller_admitted(caller)
            {
                return SubmitResult::Ready((0xC000_00A3u32 as i32, 0, 0, 0));
            }
            let physical = match crate::provider_service_ingress::physical_win32k_provider(
                channel, route, dispatch,
            ) {
                Ok(physical) => physical,
                Err(status) => return SubmitResult::Ready((status as i32, 0, 0, 0)),
            };
            if matches!(op, mm_wire::OP_REFERENCE | mm_wire::OP_MAP) {
                if third != 0 || (op == mm_wire::OP_REFERENCE && second != 0) {
                    return SubmitResult::Ready((nt_process::STATUS_INVALID_PARAMETER as i32, 0, 0, 0));
                }
                let result = match op {
                    mm_wire::OP_REFERENCE => crate::provider_mm_section_objects::reference(
                        core::ptr::null_mut(), first, physical).map(|count| (count, 0)),
                    mm_wire::OP_MAP => crate::provider_mm_section_objects::map(
                        core::ptr::null_mut(), first, physical, second, caller),
                    _ => unreachable!(),
                };
                return SubmitResult::Ready(match result {
                    Ok((first, second)) => (0, first, second, 0),
                    Err(status) => (status as i32, 0, 0, 0),
                });
            }
            return crate::provider_section_broker::submit_bootstrap(
                route, dispatch, caller, physical, op, first, second, third,
            );
        }
    };
    if matches!(op, mm_wire::OP_REFERENCE | mm_wire::OP_MAP | mm_wire::OP_MAP_CLIENT)
    {
        if (op != mm_wire::OP_MAP_CLIENT && third != 0)
            || (op == mm_wire::OP_REFERENCE && second != 0)
        {
            return SubmitResult::Ready((nt_process::STATUS_INVALID_PARAMETER as i32, 0, 0, 0));
        }
        let physical = match spawn_hosts::shared_ingress::owner::runtime::physical_source(route) {
            Ok(physical) => physical,
            Err(_) => {
                print_str(b"[kernel-section-service-failed] stage=physical-source op=0x");
                print_hex_u64(op);
                print_str(b" first=0x"); print_hex_u64(first); print_str(b"\n");
                return SubmitResult::Ready((nt_process::STATUS_INVALID_HANDLE as i32, 0, 0, 0));
            }
        };
        let handler = handler as *mut ExecNtHandler;
        if op == mm_wire::OP_MAP {
            return crate::provider_section_map_work::submit(
                &mut *handler, channel, route, dispatch, caller, physical, first, second);
        }
        let result = match op {
            mm_wire::OP_REFERENCE => crate::provider_mm_section_objects::reference(handler, first, physical)
                .map(|count| (count, 0)),
            mm_wire::OP_MAP_CLIENT => crate::provider_mm_section_objects::map_client(
                handler, first, physical, second, third >> 8, (third & 0xff) as u32),
            _ => unreachable!(),
        };
        return SubmitResult::Ready(match result {
            Ok((first, second)) => (0, first, second, 0),
            Err(status) => (status as i32, 0, 0, 0),
        });
    }
    crate::provider_section_broker::submit(
        handler, channel, route, dispatch, caller, op, first, second, third,
    )
}

pub(crate) unsafe fn service_win32k_section_map_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    op: u64,
    first: u64,
    second: u64,
    third: u64,
) -> (i32, u64, u64, u64) {
    let (route, dispatch, caller) = match authenticate_win32k_service_request(
        channel,
        reply_cap,
        badge,
        mi,
        (crate::win32k_subsystem::W32_SECTION_MAP_LABEL << 12) | 4,
    ) {
        Ok(owner) => owner,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    let handler = match registry_live_handler() {
        Ok(handler) if handler.loop_ctx.is_some() => handler,
        _ => return (0xC000_00A3u32 as i32, 0, 0, 0),
    };
    crate::provider_section_map_broker::dispatch(
        handler, route, dispatch, caller, op, first, second, third,
    )
}

pub(crate) unsafe fn service_win32k_section_unmap_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    op: u64,
    first: u64,
    second: u64,
    third: u64,
) -> (i32, u64, u64, u64) {
    let (route, dispatch, caller) = match authenticate_win32k_service_request(
        channel,
        reply_cap,
        badge,
        mi,
        (crate::win32k_subsystem::W32_SECTION_UNMAP_LABEL << 12) | 4,
    ) {
        Ok(owner) => owner,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    let handler = match registry_live_handler() {
        Ok(handler) if handler.loop_ctx.is_some() => handler,
        _ => return (0xC000_00A3u32 as i32, 0, 0, 0),
    };
    crate::provider_section_unmap_broker::dispatch(
        handler, route, dispatch, caller, op, first, second, third,
    )
}

/// Capture and release a canonical subject for one exact win32k Object Manager parse job.
pub(crate) unsafe fn service_win32k_subject_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    op: u64,
    first: u64,
    second: u64,
    third: u64,
) -> (i32, u64, u64, u64) {
    let (route, dispatch, caller) = match authenticate_win32k_service_request(
        channel,
        reply_cap,
        badge,
        mi,
        (crate::win32k_subsystem::W32_SUBJECT_LABEL << 12) | 4,
    ) {
        Ok(owner) => owner,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    let caller = if channel.logical_caller.is_some() {
        match with_provider_process_manager(|pm| {
            pm.capture_native_handle_caller(caller.original_thread(), nt_types::AccessMode::UserMode)
        }) {
            Ok(caller) => caller,
            Err(status) => return (status as i32, 0, 0, 0),
        }
    } else {
        caller
    };
    crate::provider_win32k_subject::dispatch(route, dispatch, caller, op, first, second, third)
}

pub(crate) unsafe fn service_win32k_file_close_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    handle: u64,
    spare: [u64; 3],
) -> crate::hosted_routed_file_close_work::SubmitResult {
    use crate::hosted_routed_file_close_work::SubmitResult;
    if spare != [0; 3] {
        return SubmitResult::Ready(nt_process::STATUS_INVALID_PARAMETER as i32);
    }
    let caller = match authenticate_win32k_service_request(
        channel, reply_cap, badge, mi, (crate::win32k_subsystem::W32_FILE_CLOSE_LABEL << 12) | 4,
    ) {
        Ok((_, _, caller)) => caller,
        Err(status) => return SubmitResult::Ready(status as i32),
    };
    if SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) == 0 {
        return SubmitResult::Ready(0xC000_00A3u32 as i32);
    }
    crate::hosted_routed_file_close_work::submit(channel, caller, handle)
}

pub(crate) unsafe fn service_win32k_section_close_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    handle: u64,
    previous_mode: u64,
    spare: [u64; 2],
) -> i32 {
    if previous_mode > 1 || spare != [0; 2] {
        return nt_process::STATUS_INVALID_PARAMETER as i32;
    }
    let (_, _, caller) = match authenticate_win32k_service_request(
        channel,
        reply_cap,
        badge,
        mi,
        (crate::win32k_subsystem::W32_SECTION_CLOSE_LABEL << 12) | 4,
    ) {
        Ok(owner) => owner,
        Err(status) => return status as i32,
    };
    let handler = match registry_live_handler() {
        Ok(handler) if handler.loop_ctx.is_some() => handler,
        _ => return 0xC000_00A3u32 as i32, // STATUS_DEVICE_NOT_READY
    };
    let caller = if previous_mode != 0 {
        if channel.logical_caller.is_none() {
            return nt_process::STATUS_INVALID_PARAMETER as i32;
        }
        match handler.pm.capture_native_handle_caller(
            caller.original_thread(),
            nt_types::AccessMode::UserMode,
        ) {
            Ok(caller) => caller,
            Err(status) => return status as i32,
        }
    } else {
        caller
    };
    if let Err(status) = handler.pm.lookup_native_section_handle(caller, handle) {
        return status as i32;
    }
    match handler.pm.close_native_handle(caller, handle) {
        Ok(closed) => {
            handler.release_handle_object(closed.into_object());
            0
        }
        Err(nt_process::native_handle::NativeCloseError::Status(status)) => status as i32,
        Err(nt_process::native_handle::NativeCloseError::BugCheck { code, parameters }) => {
            crate::provider_bugcheck::report(code, parameters)
        }
    }
}

pub(crate) unsafe fn service_win32k_file_create_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    packet: u64,
    length: u64,
    spare: [u64; 2],
) -> Option<nt_io_manager::io_create_file_reply::IoCreateFileReply> {
    use nt_io_manager::io_create_file_reply::IoCreateFileReply;
    let rejected = |status| Some(IoCreateFileReply::Rejected { status });
    if spare != [0; 2] {
        return rejected(nt_process::STATUS_INVALID_PARAMETER);
    }
    if let Err(status) = authenticate_win32k_service_request(
        channel, reply_cap, badge, mi, (crate::win32k_subsystem::W32_FILE_CREATE_LABEL << 12) | 4,
    ) {
        return rejected(status);
    }
    if SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) == 0 {
        return rejected(0xC000_00A3);
    }
    crate::driver_launch::service_win32k_io_create_file(channel, packet, length)
}

pub(crate) unsafe fn service_win32k_file_query_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    packet: u64,
    length: u64,
    handle: u64,
    spare: u64,
) -> Option<i32> {
    if let Err(status) = authenticate_win32k_service_request(
        channel, reply_cap, badge, mi, (crate::win32k_subsystem::W32_FILE_QUERY_LABEL << 12) | 4,
    ) {
        return Some(status as i32);
    }
    if SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) == 0 {
        return Some(0xC000_00A3u32 as i32);
    }
    crate::driver_launch::service_win32k_file_query(channel, packet, length, handle, spare)
}

pub(crate) unsafe fn service_win32k_file_read_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    packet: u64,
    length: u64,
    handle: u64,
    reserved: u64,
) -> Option<i32> {
    if reserved != 0 {
        return Some(nt_process::STATUS_INVALID_PARAMETER as i32);
    }
    if let Err(status) = authenticate_win32k_service_request(
        channel, reply_cap, badge, mi, (crate::win32k_subsystem::W32_FILE_READ_LABEL << 12) | 4,
    ) {
        return Some(status as i32);
    }
    if SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) == 0 {
        return Some(0xC000_00A3u32 as i32);
    }
    crate::driver_launch::service_win32k_file_read(channel, packet, length, handle)
}

pub(crate) unsafe fn service_win32k_file_read_completion(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    token: u64,
    handle: u64,
    reserved1: u64,
    reserved2: u64,
) -> i32 {
    if reserved1 != 0 || reserved2 != 0 {
        return nt_process::STATUS_INVALID_PARAMETER as i32;
    }
    if let Err(status) = authenticate_win32k_service_request(
        channel, reply_cap, badge, mi,
        (crate::win32k_subsystem::W32_FILE_READ_COMPLETION_LABEL << 12) | 4,
    ) {
        return status as i32;
    }
    crate::driver_launch::service_win32k_file_read_completion(channel, token, handle)
}

pub(crate) unsafe fn service_win32k_file_read_release(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    token: u64,
    handle: u64,
    reserved1: u64,
    reserved2: u64,
) -> i32 {
    if reserved1 != 0 || reserved2 != 0 {
        return nt_process::STATUS_INVALID_PARAMETER as i32;
    }
    if let Err(status) = authenticate_win32k_service_request(
        channel, reply_cap, badge, mi,
        (crate::win32k_subsystem::W32_FILE_READ_RELEASE_LABEL << 12) | 4,
    ) {
        return status as i32;
    }
    crate::driver_launch::service_win32k_file_read_release(channel, token, handle)
}

pub(crate) unsafe fn service_win32k_file_ioctl_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    packet: u64,
    length: u64,
    handle: u64,
    reserved: u64,
) -> Option<i32> {
    if reserved != 0 {
        return Some(nt_process::STATUS_INVALID_PARAMETER as i32);
    }
    if let Err(status) = authenticate_win32k_service_request(
        channel, reply_cap, badge, mi, (crate::win32k_subsystem::W32_FILE_IOCTL_LABEL << 12) | 4,
    ) {
        return Some(status as i32);
    }
    if SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) == 0 {
        return Some(0xC000_00A3u32 as i32);
    }
    crate::driver_launch::service_win32k_file_ioctl(channel, packet, length, handle)
}

pub(crate) unsafe fn service_win32k_file_ioctl_completion(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    token: u64,
    handle: u64,
    reserved1: u64,
    reserved2: u64,
) -> i32 {
    if reserved1 != 0 || reserved2 != 0 {
        return nt_process::STATUS_INVALID_PARAMETER as i32;
    }
    if let Err(status) = authenticate_win32k_service_request(
        channel, reply_cap, badge, mi,
        (crate::win32k_subsystem::W32_FILE_IOCTL_COMPLETION_LABEL << 12) | 4,
    ) {
        return status as i32;
    }
    crate::driver_launch::service_win32k_file_ioctl_completion(channel, token, handle)
}

pub(crate) unsafe fn service_win32k_file_ioctl_release(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    token: u64,
    handle: u64,
    reserved1: u64,
    reserved2: u64,
) -> i32 {
    if reserved1 != 0 || reserved2 != 0 {
        return nt_process::STATUS_INVALID_PARAMETER as i32;
    }
    if let Err(status) = authenticate_win32k_service_request(
        channel, reply_cap, badge, mi,
        (crate::win32k_subsystem::W32_FILE_IOCTL_RELEASE_LABEL << 12) | 4,
    ) {
        return status as i32;
    }
    crate::driver_launch::service_win32k_file_ioctl_release(channel, token, handle)
}

pub(crate) unsafe fn service_win32k_source_ioctl_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    packet: u64,
    length: u64,
    provider_stack_pointer: u64,
    reserved2: u64,
) -> Option<i32> {
    if provider_stack_pointer == 0 || reserved2 != 0 {
        return Some(nt_process::STATUS_INVALID_PARAMETER as i32);
    }
    if let Err(status) = authenticate_win32k_service_request(
        channel,
        reply_cap,
        badge,
        mi,
        (crate::win32k_subsystem::W32_SOURCE_IOCTL_LABEL << 12) | 4,
    ) {
        return Some(status as i32);
    }
    let handler = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if handler.is_null() {
        return Some(0xC000_00A3u32 as i32);
    }
    crate::driver_launch::service_win32k_source_ioctl(
        channel, reply_cap, packet, length, provider_stack_pointer, handler,
    )
}

pub(crate) unsafe fn service_win32k_source_pnp_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    packet: u64,
    length: u64,
    stack_pointer: u64,
    reserved: u64,
) -> Option<i32> {
    if reserved != 0 { return Some(nt_process::STATUS_INVALID_PARAMETER as i32); }
    if let Err(status) = authenticate_win32k_service_request(
        channel, reply_cap, badge, mi,
        (crate::win32k_subsystem::W32_SOURCE_PNP_LABEL << 12) | 4,
    ) { return Some(status as i32); }
    let handler = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if handler.is_null() { return Some(0xC000_00A3u32 as i32); }
    crate::driver_launch::service_win32k_source_pnp(
        channel, reply_cap, packet, length, stack_pointer, handler,
    )
}

pub(crate) unsafe fn service_win32k_source_fsd_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    packet: u64,
    length: u64,
    stack_pointer: u64,
    reserved: u64,
) -> Option<i32> {
    if reserved != 0 { return Some(nt_process::STATUS_INVALID_PARAMETER as i32); }
    if let Err(status) = authenticate_win32k_service_request(
        channel, reply_cap, badge, mi,
        (crate::win32k_subsystem::W32_SOURCE_FSD_LABEL << 12) | 4,
    ) { return Some(status as i32); }
    let handler = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if handler.is_null() { return Some(0xC000_00A3u32 as i32); }
    crate::driver_launch::service_win32k_source_fsd(
        channel, reply_cap, packet, length, stack_pointer, handler,
    )
}

pub(crate) unsafe fn service_win32k_source_armed_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    packet: u64,
    length: u64,
    spare: [u64; 2],
) -> i32 {
    if spare != [0; 2] {
        return nt_process::STATUS_INVALID_PARAMETER as i32;
    }
    if let Err(status) = authenticate_win32k_service_request(
        channel, reply_cap, badge, mi,
        (crate::win32k_subsystem::W32_SOURCE_ARMED_LABEL << 12) | 4,
    ) {
        return status as i32;
    }
    crate::driver_launch::service_win32k_source_armed(channel, packet, length)
}

pub(crate) unsafe fn service_win32k_file_query_delivered(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    packet: u64,
    handle: u64,
    spare: [u64; 2],
) -> i32 {
    if spare != [0; 2] {
        return nt_process::STATUS_INVALID_PARAMETER as i32;
    }
    if let Err(status) = authenticate_win32k_service_request(
        channel, reply_cap, badge, mi,
        (crate::win32k_subsystem::W32_FILE_QUERY_DELIVERED_LABEL << 12) | 4,
    ) {
        return status as i32;
    }
    let handler = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    crate::driver_launch::service_win32k_file_query_delivered(channel, packet, handle, handler)
}

pub(crate) unsafe fn service_win32k_file_cancel_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    handle: u64,
    reserved1: u64,
    reserved2: u64,
    reserved3: u64,
) -> Option<i32> {
    if let Err(status) = authenticate_win32k_service_request(
        channel, reply_cap, badge, mi, (crate::win32k_subsystem::W32_FILE_CANCEL_LABEL << 12) | 4,
    ) {
        return Some(status as i32);
    }
    if reserved1 != 0 || reserved2 != 0 || reserved3 != 0 {
        return Some(nt_process::STATUS_INVALID_PARAMETER as i32);
    }
    if SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) == 0 {
        return Some(0xC000_00A3u32 as i32);
    }
    crate::driver_launch::service_win32k_file_cancel(channel, handle)
}

/// The canonical shared-ingress completion owns final cleanup of unpublished stages.
pub(crate) unsafe fn retire_win32k_directory_route(
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
) {
    let pointer = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if pointer.is_null() {
        return;
    }
    crate::provider_directory_broker::retire_completed(&mut *pointer, route, dispatch);
}

pub(crate) unsafe fn retire_win32k_section_create_route(
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
) {
    let pointer = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if !pointer.is_null() {
        crate::provider_section_broker::retire_completed(&mut *pointer, route, dispatch);
    }
}

pub(crate) unsafe fn retire_win32k_section_map_route(
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
) {
    let pointer = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if !pointer.is_null() {
        crate::provider_section_map_broker::retire_completed(&mut *pointer, route, dispatch);
    }
}

pub(crate) unsafe fn retire_win32k_section_unmap_route(
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
) {
    crate::provider_section_unmap_broker::retire_completed(route, dispatch);
}

/// Service Ps queries issued by the win32k component against the canonical Process Manager.
/// Stable EPROCESS/ETHREAD projections cross this boundary; mutable Ps state does not.
pub(crate) unsafe fn service_win32k_ps_request(
    channel: &spawn_hosts::PumpChannel,
    op: u64,
    object: u64,
    value: u64,
) -> (i32, u64, u64, u64) {
    const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
    const STATUS_DEVICE_NOT_READY: i32 = 0xC000_00A3u32 as i32;

    let client_pi = channel.client_pi;
    let client_generation = channel.client_generation;
    let logical_caller = channel.logical_caller;
    if logical_caller.is_some() && channel.kernel_caller.is_some() {
        return (STATUS_INVALID_PARAMETER, 0, 0, 0);
    }
    if matches!(
        op,
        win32k_subsystem::W32_PS_OP_SET_OBJECT_HANDLE_FLAGS
            | win32k_subsystem::W32_PS_OP_QUERY_OBJECT_HANDLE_FLAGS
    ) {
        if (op == win32k_subsystem::W32_PS_OP_SET_OBJECT_HANDLE_FLAGS
            && value > u16::MAX as u64)
            || (op == win32k_subsystem::W32_PS_OP_QUERY_OBJECT_HANDLE_FLAGS && value != 0)
        {
            return (STATUS_INVALID_PARAMETER, 0, 0, 0);
        }
        if let Err(status) = provider_ps_projection::authenticated_target(channel) {
            return (status as i32, 0, 0, 0);
        }
        let caller = match provider_registry_caller::resolve(channel) {
            Ok(caller) => caller,
            Err(status) => return (status as i32, 0, 0, 0),
        };
        if op == win32k_subsystem::W32_PS_OP_QUERY_OBJECT_HANDLE_FLAGS {
            return match with_provider_process_manager(|pm| {
                pm.query_native_object_handle_flag_information(caller, object)
            }) {
                Ok(encoded) => (0, u16::from_le_bytes(encoded) as u64, 0, 0),
                Err(status) => (status as i32, 0, 0, 0),
            };
        }
        let encoded = (value as u16).to_le_bytes();
        let result = with_provider_process_manager(|pm| {
            pm.set_native_object_handle_flag_information(caller, object, &encoded)
        });
        return (result.err().unwrap_or(0) as i32, 0, 0, 0);
    }
    if let Some(caller) = channel.kernel_caller {
        return kernel_provider_activation::service_ps(channel, caller, op, object, value);
    }
    let target = match provider_ps_projection::authenticated_target(channel) {
        Ok(target) => target,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    let handler_ptr = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if handler_ptr.is_null() {
        return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
    }
    let handler = &mut *handler_ptr;
    let Ok(pi) = usize::try_from(client_pi) else {
        return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
    };
    if logical_caller.is_some_and(|caller| {
        caller.pi() != pi || !handler.validate_provider_logical_caller(caller)
    }) {
        return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
    }
    if client_generation == 0
        || handler.pm_pid_for_pi(pi).is_none()
        || handler.hosted_process_generation(pi) != Some(client_generation)
    {
        return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
    }
    if native_thread_priority::is_priority_effect_op(op) {
        return native_thread_priority::dispatch(handler, op, object, value);
    }
    if op == win32k_subsystem::W32_PS_OP_WAIT_THREAD_IDENTITY {
        if value != 0 { return (STATUS_INVALID_PARAMETER, 0, 0, 0); }
        return match provider_ps_wait::acquire(&mut handler.pm, target, object, client_pi, client_generation) {
            Ok((tid, generation, token)) => (0, tid, generation, token),
            Err(status) => (status as i32, 0, 0, 0),
        };
    }
    if op == win32k_subsystem::W32_PS_OP_RELEASE_THREAD_WAIT {
        if value != 0 { return (STATUS_INVALID_PARAMETER, 0, 0, 0); }
        return match provider_ps_wait::release(&mut handler.pm, target, object) {
            Ok(()) => (0, 0, 0, 0),
            Err(status) => (status as i32, 0, 0, 0),
        };
    }
    provider_ps::dispatch(
        &mut handler.pm,
        op,
        object,
        value,
        |pm, job| unsafe { crate::exec_handler::native_job_bodies::ensure(pm, job) },
        |pm, body| provider_ps_projection::grant(target, pm, body),
    )
}

/// Execute a hosted driver's checked thread-priority request against the same retained
/// PM/native TCB owner as win32k. The caller was authenticated by the driver ingress service.
pub(crate) unsafe fn service_hosted_driver_thread_priority(
    thread: u64,
    priority: i32,
) -> (i32, u64) {
    let handler = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if handler.is_null() {
        return (0xC000_00A3u32 as i32, 0);
    }
    let (status, previous, _, _) = native_thread_priority::dispatch(
        &mut *handler,
        win32k_subsystem::W32_PS_OP_SET_THREAD_PRIORITY,
        thread,
        priority as u32 as u64,
    );
    (status, previous)
}

/// Serialized memory-only ownership operation, across the bootstrap-to-live Ps store transfer.
/// No manager borrow may escape the callback or span IPC/reentrant dispatch.
pub(crate) unsafe fn with_provider_process_manager<R>(
    operation: impl FnOnce(&mut nt_process::ProcessManager) -> Result<R, u32>,
) -> Result<R, u32> {
    let handler = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if handler.is_null() {
        ps_bootstrap::with_process_manager(operation)
    } else {
        operation(&mut (*handler).pm)
    }
}

/// Memory-only paired-store operation. Neither borrow may span provider IPC.
pub(crate) unsafe fn with_provider_security_managers<R>(
    operation: impl FnOnce(&mut nt_process::ProcessManager, &mut nt_security::TokenStore) -> Result<R, u32>,
) -> Result<R, u32> {
    let handler = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if handler.is_null() {
        ps_bootstrap::with_security_managers(operation)
    } else {
        operation(&mut (*handler).pm, &mut (*handler).token_store)
    }
}

pub(crate) unsafe fn registry_live_handler() -> Result<&'static mut ExecNtHandler, u32> {
    registry_live_handler_pointer()?.as_mut().ok_or(0xc000_00a3)
}

/// Effectful adapters retain a raw execution owner, never a handler borrow across native IPC.
pub(crate) fn registry_live_handler_pointer() -> Result<*mut ExecNtHandler, u32> {
    let handler = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if handler.is_null() { Err(0xc000_00a3) } else { Ok(handler) }
}

/// Service `MmSecureVirtualMemory` for the authenticated hosted process generation. The returned
/// value is an opaque executive lease token and is meaningful only to the matching unsecure call.
pub(crate) unsafe fn service_win32k_mm_secure_request(
    client_pi: u64,
    client_generation: u64,
    op: u64,
    address_or_handle: u64,
    size: u64,
    protection: u64,
) -> (i32, u64) {
    const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
    const STATUS_DEVICE_NOT_READY: i32 = 0xC000_00A3u32 as i32;

    let handler_ptr = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if handler_ptr.is_null() {
        return (STATUS_DEVICE_NOT_READY, 0);
    }
    let handler = &mut *handler_ptr;
    let Ok(pi) = usize::try_from(client_pi) else {
        return (STATUS_DEVICE_NOT_READY, 0);
    };
    if client_generation == 0
        || handler.pm_pid_for_pi(pi).is_none()
        || handler.hosted_process_generation(pi) != Some(client_generation)
    {
        return (STATUS_DEVICE_NOT_READY, 0);
    }

    match op {
        crate::win32k_subsystem::W32_MM_SECURE_OP_SECURE => {
            let Ok(protection) = u32::try_from(protection) else {
                return (STATUS_INVALID_PARAMETER, 0);
            };
            handler
                .service_win32k_secure_virtual_memory(pi, address_or_handle, size, protection)
                .map(|handle| (0, handle))
                .unwrap_or_else(|status| (status as i32, 0))
        }
        crate::win32k_subsystem::W32_MM_SECURE_OP_UNSECURE => {
            if size != 0 || protection != 0 {
                return (STATUS_INVALID_PARAMETER, 0);
            }
            handler
                .service_win32k_unsecure_virtual_memory(pi, address_or_handle)
                .map(|()| (0, 0))
                .unwrap_or_else(|status| (status as i32, 0))
        }
        _ => (STATUS_INVALID_PARAMETER, 0),
    }
}

/// Service a bounded win32k global-atom request against the executive-lifetime native atom table.
pub(crate) unsafe fn service_win32k_atom_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    operation: u64,
    value: u64,
) -> (i32, u64) {
    const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
    const STATUS_DEVICE_NOT_READY: i32 = 0xC000_00A3u32 as i32;

    let (route, dispatch) = match crate::provider_service_ingress::authenticate(
        channel, reply_cap, badge, mi,
        (crate::win32k_subsystem::W32_ATOM_LABEL << 12) | 2,
    ) {
        Ok(owner) => owner,
        Err(status) => return (status as i32, 0),
    };
    if let Err(status) = crate::provider_service_ingress::physical_win32k_provider(
        channel, route, dispatch,
    ) {
        return (status as i32, 0);
    }
    let handler_ptr = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if handler_ptr.is_null() {
        // Before the runtime handler exists, only the exact root-issued kernel activation may
        // mutate the bootstrap owner. A hosted or absent caller needs live generation checks.
        if channel.kernel_caller.is_none() || channel.logical_caller.is_some() {
            return (STATUS_DEVICE_NOT_READY, 0);
        }
    }
    if channel.kernel_caller.is_none() {
        let handler = &mut *handler_ptr;
        let Some(caller) = channel.logical_caller else {
            return (STATUS_DEVICE_NOT_READY, 0);
        };
        if caller.pi() as u64 != channel.client_pi
            || caller.process().generation
                != nt_user_host::process_identity::ProcessGeneration::Hosted(
                    channel.client_generation,
                )
            || !crate::win32k_glue::registry_logical_caller_is_current(channel)
            || !handler.validate_provider_logical_caller(caller)
        {
            return (STATUS_DEVICE_NOT_READY, 0);
        }
        let Ok(pi) = usize::try_from(channel.client_pi) else {
            return (STATUS_DEVICE_NOT_READY, 0);
        };
        if channel.client_generation == 0
            || handler.pm_pid_for_pi(pi).is_none()
            || handler.hosted_process_generation(pi) != Some(channel.client_generation)
        {
            return (STATUS_DEVICE_NOT_READY, 0);
        }
    }

    let mut add_atom = |integer, name| {
        if handler_ptr.is_null() {
            crate::atom_bootstrap::add_kernel_atom(integer, name)
        } else {
            (&mut *handler_ptr).add_kernel_global_atom(integer, name)
        }
    };

    let result = match operation {
        crate::win32k_subsystem::W32_ATOM_OP_ADD_INTEGER => {
            if value > u16::MAX as u64 {
                return (STATUS_INVALID_PARAMETER, 0);
            }
            add_atom(Some(value as u16), &[])
        }
        crate::win32k_subsystem::W32_ATOM_OP_ADD_NAME => {
            let Ok(byte_length) = usize::try_from(value) else {
                return (STATUS_INVALID_PARAMETER, 0);
            };
            if byte_length > nt_kernel_exec::rtl_atom::NAME_CAP * 2 || byte_length & 1 != 0 {
                return (STATUS_INVALID_PARAMETER, 0);
            }
            let name = core::slice::from_raw_parts(
                (crate::win32k_subsystem::WIN32K_JOB_ATOM_VADDR
                    + crate::win32k_subsystem::WIN32K_JOB_ATOM_PAYLOAD_OFF)
                    as *const u16,
                byte_length / 2,
            );
            add_atom(None, name)
        }
        _ => return (STATUS_INVALID_PARAMETER, 0),
    };
    result
        .map(|atom| (0, u64::from(atom)))
        .unwrap_or_else(|status| (status as i32, 0))
}

unsafe fn delay_timer_rearm_after_park(
    queue: &mut nt_delay_execution::Queue,
    handler: &mut ExecNtHandler,
    has_deadline: bool,
) {
    if has_deadline {
        let _ = delay_timer_rearm_and_drain_overdue(queue, handler);
    } else {
        delay_timer_rearm(queue, handler);
    }
}

pub(crate) unsafe fn drain_nested_pump_timer_delivery() -> bool {
    if DELAY_TIMER_HANDLER.load(Ordering::Acquire) == 0 {
        return false;
    }
    let handler_ptr = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    let queue_ptr =
        SERVICE_DELAY_DRAIN_QUEUE.load(Ordering::Acquire) as *mut nt_delay_execution::Queue;
    if handler_ptr.is_null() || queue_ptr.is_null() {
        return false;
    }
    // Claim before consuming notifications or constructing references from published pointers.
    let Some(delivery) = TIMER_DELIVERY_GATE.try_enter() else {
        return false;
    };
    let ticks = DELAY_TIMER_TICKS_PENDING.swap(0, Ordering::Relaxed);
    if ticks == 0 {
        return false;
    }
    PUMP_TIMER_TICKS_DRAINED.fetch_add(ticks, Ordering::Relaxed);
    delay_timer_interrupt_claimed(&mut *queue_ptr, &mut *handler_ptr, &delivery);
    let n = SERVICE_DELAY_NESTED_DRAINS.fetch_add(1, Ordering::Relaxed);
    if n < 8 {
        print_str(b"[delay] nested pump drained timer ticks=");
        print_u64(ticks);
        print_str(b"\n");
    }
    true
}

/// A nested receive may ACK a one-shot while the root still owns the current
/// hosted Reply. Settle that deferred tick in place before using the Reply for
/// a new receive; the caller must not replay its current message or response.
unsafe fn prepare_service_receive(
    queue: &mut nt_delay_execution::Queue,
    handler: &mut ExecNtHandler,
) -> bool {
    loop {
        match component_resume::prepare_receive(handler) {
            component_resume::ReceivePreparation::Ready =>
                return delay_timer_arm_queued_work_receive_poll(queue, handler),
            component_resume::ReceivePreparation::PendingDelivery => {
                let ticks = DELAY_TIMER_TICKS_PENDING.swap(0, Ordering::AcqRel);
                if ticks == 0 { continue; }
                PUMP_TIMER_TICKS_DRAINED.fetch_add(ticks, Ordering::Relaxed);
                delay_timer_interrupt(queue, handler);
            }
        }
    }
}

/// CONNECT and HOOK own their source Replies and provider projections directly. Their nested
/// redrive does not borrow the File handler used by the other hosted work runners.
unsafe fn redrive_nested_hosted_input_work() -> bool {
    if crate::driver_launch::nested_hosted_start_fdo_ready()
        && crate::driver_launch::redrive_nested_hosted_start_fdo() { return true; }
    if crate::driver_launch::nested_hosted_connect_forward_ready()
        && crate::driver_launch::redrive_nested_hosted_connect_forward() { return true; }
    crate::driver_launch::nested_hosted_hook_forward_ready()
        && crate::driver_launch::redrive_nested_hosted_hook_forward()
}

/// Admit a nested pump only when a local runner can advance. Keep this gate beside the
/// runners; a later runner is rechecked after earlier work changes its readiness.
pub(crate) unsafe fn nested_hosted_file_work_ready() -> bool {
    let input = crate::driver_launch::nested_hosted_start_fdo_ready()
        || crate::driver_launch::nested_hosted_connect_forward_ready()
        || crate::driver_launch::nested_hosted_hook_forward_ready();
    if SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) == 0 {
        return input;
    }
    input
        || crate::spawn_hosts::shared_ingress::owner::runtime::nested::source_ioctl_parent_ready()
        || crate::driver_launch::nested_hosted_driver_create_ready()
        || crate::driver_launch::nested_hosted_query_path_ready()
        || crate::driver_launch::nested_hosted_internal_control_ready()
        || crate::driver_launch::nested_hosted_buffered_control_ready()
        || crate::driver_launch::nested_hosted_write_ready()
        || crate::driver_launch::nested_hosted_read_ready()
        || crate::driver_launch::nested_hosted_flush_ready()
        || crate::driver_launch::nested_hosted_query_information_ready()
        || crate::driver_launch::nested_hosted_lower_pnp_ready()
        || crate::driver_launch::nested_hosted_lower_file_ready()
        || crate::driver_launch::nested_hosted_kernel_file_read_query_ready()
        || crate::driver_launch::nested_hosted_win32k_async_read_ready()
        || crate::driver_launch::nested_hosted_file_lifecycle_work_ready()
        || crate::hosted_routed_file_close_work::nested_work_ready()
        || crate::driver_launch::nested_win32k_source_work_ready()
        || crate::provider_section_broker::nested_work_ready()
        || crate::provider_directory_broker::nested_work_ready()
}

// Read-only readiness census for an indeterminate nested child under a Pending CONNECT.
// Bits 0..2: StartFdo, CONNECT, HOOK; 3..19 follow the remaining runners in
// redrive_nested_hosted_file_work, from create through directory broker.
unsafe fn nested_child_ready_bits() -> u64 {
    macro_rules! bit { ($index:expr, $ready:expr) => { u64::from($ready) << $index }; }
    let input = bit!(0, crate::driver_launch::nested_hosted_start_fdo_ready())
        | bit!(1, crate::driver_launch::nested_hosted_connect_forward_ready())
        | bit!(2, crate::driver_launch::nested_hosted_hook_forward_ready());
    if SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) == 0 { return input; }
    input | bit!(3, crate::driver_launch::nested_hosted_driver_create_ready())
        | bit!(4, crate::driver_launch::nested_hosted_query_path_ready())
        | bit!(5, crate::driver_launch::nested_hosted_internal_control_ready())
        | bit!(6, crate::driver_launch::nested_hosted_buffered_control_ready())
        | bit!(7, crate::driver_launch::nested_hosted_write_ready())
        | bit!(8, crate::driver_launch::nested_hosted_read_ready())
        | bit!(9, crate::driver_launch::nested_hosted_flush_ready())
        | bit!(10, crate::driver_launch::nested_hosted_query_information_ready())
        | bit!(11, crate::driver_launch::nested_hosted_lower_pnp_ready())
        | bit!(12, crate::driver_launch::nested_hosted_lower_file_ready())
        | bit!(13, crate::driver_launch::nested_hosted_kernel_file_read_query_ready())
        | bit!(14, crate::driver_launch::nested_hosted_win32k_async_read_ready())
        | bit!(15, crate::driver_launch::nested_hosted_file_lifecycle_work_ready())
        | bit!(16, crate::hosted_routed_file_close_work::nested_work_ready())
        | bit!(17, crate::driver_launch::nested_win32k_source_work_ready())
        | bit!(18, crate::provider_section_broker::nested_work_ready())
        | bit!(19, crate::provider_directory_broker::nested_work_ready())
}

unsafe fn trace_nested_child_selection(stage: u64, detail: u64) {
    static COUNT: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    if !crate::driver_launch::hosted_connect_pending_reply_published()
        || COUNT.fetch_add(1, Ordering::Relaxed) >= 18 { return; }
    print_str(b"[connect-nested-child] stage/detail=");
    print_u64(stage); print_str(b"/"); print_hex_u64(detail); print_str(b"\n");
}

unsafe fn trace_nested_child_readiness(stage: u64) {
    if crate::driver_launch::hosted_connect_pending_reply_published() {
        trace_nested_child_selection(stage, nested_child_ready_bits());
    }
}

/// Evidence for one outer-loop child pass under a retained physical parent. A ready runner
/// that reports no progress may have made an uncertain native effect, so it cannot authorize
/// parent restoration. The no-ready case checks only owner readiness and enters no runner.
enum NestedChildStepOutcome {
    NoReady,
    Progressed,
    Indeterminate,
}

/// A one-use observation from the outer runner. Only this module can issue it after checking
/// readiness and, when ready, running one selected child. A copyable boolean is not authority
/// to resume a physically parked parent.
#[must_use = "retain until the exact child-work parent is restored or quarantined"]
pub(crate) struct NestedChildStep {
    outcome: NestedChildStepOutcome,
}

pub(crate) enum NestedChildStepDecision {
    RestoreParent,
    Quarantine,
}

impl NestedChildStep {
    pub(crate) fn ran_child(&self) -> bool {
        !matches!(self.outcome, NestedChildStepOutcome::NoReady)
    }

    pub(crate) fn into_decision(self) -> NestedChildStepDecision {
        match self.outcome {
            NestedChildStepOutcome::NoReady | NestedChildStepOutcome::Progressed =>
                NestedChildStepDecision::RestoreParent,
            NestedChildStepOutcome::Indeterminate => NestedChildStepDecision::Quarantine,
        }
    }
}

pub(crate) unsafe fn drive_one_nested_file_child_step() -> NestedChildStep {
    let ready = nested_hosted_file_work_ready();
    trace_nested_child_readiness(0);
    if !ready {
        return NestedChildStep { outcome: NestedChildStepOutcome::NoReady };
    }
    let progressed = redrive_nested_hosted_file_work();
    trace_nested_child_selection(1, u64::from(progressed));
    trace_nested_child_readiness(2);
    if progressed {
        NestedChildStep { outcome: NestedChildStepOutcome::Progressed }
    } else {
        NestedChildStep { outcome: NestedChildStepOutcome::Indeterminate }
    }
}

/// Run one locally ready retained child while the exact parent invocation is parked. A caller
/// can repeat the pass when more work is ready. Each runner checks and claims its retained
/// request before making a native effect.
pub(crate) unsafe fn redrive_nested_hosted_file_work() -> bool {
    let handler = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if handler.is_null() { return redrive_nested_hosted_input_work(); }
    // Check each owner immediately before entry. A runner may reserve a large Work frame even
    // when its row is not ready, so never enter a later runner after one has progressed.
    if crate::driver_launch::nested_hosted_driver_create_ready()
        && crate::driver_launch::redrive_nested_hosted_driver_create(handler) { return true; }
    if crate::driver_launch::nested_hosted_query_path_ready()
        && crate::driver_launch::redrive_nested_hosted_query_path(handler) { return true; }
    if crate::driver_launch::nested_hosted_internal_control_ready()
        && crate::driver_launch::redrive_nested_hosted_internal_control(handler) { return true; }
    if crate::driver_launch::nested_hosted_buffered_control_ready()
        && crate::driver_launch::redrive_nested_hosted_buffered_control(handler) { return true; }
    if crate::driver_launch::nested_hosted_write_ready()
        && crate::driver_launch::redrive_nested_hosted_write(handler) { return true; }
    if crate::driver_launch::nested_hosted_read_ready()
        && crate::driver_launch::redrive_nested_hosted_read(handler) { return true; }
    if crate::driver_launch::nested_hosted_flush_ready()
        && crate::driver_launch::redrive_nested_hosted_flush(handler) { return true; }
    if crate::driver_launch::nested_hosted_query_information_ready()
        && crate::driver_launch::redrive_nested_hosted_query_information(handler) { return true; }
    if crate::driver_launch::nested_hosted_lower_pnp_ready()
        && crate::driver_launch::redrive_nested_hosted_lower_pnp(handler) { return true; }
    if crate::driver_launch::nested_hosted_lower_file_ready()
        && crate::driver_launch::redrive_nested_hosted_lower_file(handler) { return true; }
    if redrive_nested_hosted_input_work() { return true; }
    if crate::driver_launch::nested_hosted_kernel_file_read_query_ready()
        && crate::driver_launch::redrive_nested_hosted_kernel_file_read_query(handler) { return true; }
    if crate::driver_launch::nested_hosted_win32k_async_read_ready()
        && crate::driver_launch::redrive_nested_hosted_win32k_async_read(handler) { return true; }
    if crate::driver_launch::nested_hosted_file_lifecycle_work_ready()
        && crate::driver_launch::redrive_nested_hosted_file_lifecycle_work() { return true; }
    if crate::hosted_routed_file_close_work::nested_work_ready()
        && crate::hosted_routed_file_close_work::redrive_nested_ready(handler) { return true; }
    if crate::spawn_hosts::shared_ingress::owner::runtime::nested::drain_source_ioctl_parent(handler) {
        return true;
    }
    if !crate::spawn_hosts::shared_ingress::owner::runtime::nested::source_ioctl_parent_retained()
        && crate::driver_launch::nested_win32k_source_work_ready()
        && crate::driver_launch::redrive_nested_win32k_source_work(handler) { return true; }
    if crate::provider_section_broker::nested_work_ready()
        && crate::provider_section_broker::redrive_nested_ready(handler) { return true; }
    if crate::provider_directory_broker::nested_work_ready()
        && crate::provider_directory_broker::redrive_nested_ready(handler) { return true; }
    crate::provider_mm_section_objects::redrive(handler);
    false
}

pub(crate) unsafe fn watchdog_defer_if_hosted_work_can_run(site: &[u8]) -> bool {
    if crate::WATCHDOG_TRIPPED.load(Ordering::Relaxed) != 1 {
        return false;
    }
    let handler_ptr = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *const ExecNtHandler;
    if handler_ptr.is_null() {
        return false;
    }
    let nt_handler = &*handler_ptr;
    let live = live_top_badges(nt_handler);
    let crash_parked = SERVICE_CRASH_PARKED_MASK.load(Ordering::Relaxed);
    let wait_parked = wait_parked_owner_mask(nt_handler);
    let runnable = live & !(crash_parked | wait_parked);
    if runnable == 0 {
        return false;
    }
    if !crate::watchdog_defer_runnable_silence() {
        return false;
    }
    let n = WATCHDOG_RUNNABLE_DEFER_TRACE.fetch_add(1, Ordering::Relaxed);
    if n < 16 {
        print_str(b"[deadman] deferred candidate at ");
        print_str(site);
        print_str(b": runnable-hosted=0x");
        print_hex_u64(runnable);
        print_str(b" live=0x");
        print_hex_u64(live);
        print_str(b" crash=0x");
        print_hex_u64(crash_parked);
        print_str(b" wait=0x");
        print_hex_u64(wait_parked);
        print_str(b"\n");
    }
    true
}

unsafe fn load_hosted_bootstrap_image(
    catalog: &mut nt_exe_image::OwnedHostedImageCatalog<HOSTED_PROCESS_IMAGE_CAP>,
    loaded_images: &mut HostedLoadedImageTable,
    index: usize,
    spec: HostedBootstrapLoadSpec,
) {
    let backing = crate::fs_loader::exec_fs()
        .and_then(|fs| crate::fs_loader::fat_open_path_metadata(&fs, spec.disk_path))
        .filter(|entry| !entry.metadata.is_directory)
        .and_then(|entry| crate::fs_loader::exec_fs_file_identity(entry.metadata.file_id));
    print_str(b"[sec-init] bootstrap-image item=");
    print_u64(index as u64);
    print_str(b" pi=");
    print_u64(spec.image.pi as u64);
    print_str(b" stem=");
    print_str(spec.stem);
    print_str(b" load-begin\n");
    let (pe, va) = load_dll_from_fs(spec.disk_path, spec.stem);
    if let Some(ref image_pe) = pe {
        print_str(b"[sec-init] bootstrap-image item=");
        print_u64(index as u64);
        print_str(b" relocate-begin\n");
        apply_relocations_to_buf(image_pe, va, PE_LOAD_BASE);
        let e_lfanew = core::ptr::read_volatile((va + 0x3c) as *const u32) as u64;
        core::ptr::write_volatile((va + e_lfanew + 0x30) as *mut u64, PE_LOAD_BASE);
        print_str(b"[sec-init] bootstrap-image item=");
        print_u64(index as u64);
        print_str(b" relocate-end\n");
    }
    let loaded = pe.is_some();
    print_str(b"[sec-init] bootstrap-image item=");
    print_u64(index as u64);
    print_str(b" catalog-begin loaded=");
    print_u64(loaded as u64);
    print_str(b" va=0x");
    print_hex((va >> 32) as u32);
    print_hex(va as u32);
    print_str(b"\n");
    register_loaded_hosted_image(catalog, spec.image, loaded)
        .expect("hosted bootstrap image metadata must register once when loaded");
    if loaded {
        let target = nt_exe_image::SpawnTarget::from_image(spec.image);
        catalog.bind_registered_backing(
            target,
            backing.expect("loaded bootstrap image retains its exact mounted File identity"),
        ).expect("bootstrap image File identity must bind its registered generation once");
        catalog.bind_registered_launch_policy(target, spec.allowed_creator)
            .expect("bootstrap creator policy must bind after its exact mounted File");
    }
    print_str(b"[sec-init] bootstrap-image item=");
    print_u64(index as u64);
    print_str(b" loaded-table-begin\n");
    loaded_images
        .register_if_loaded(spec.image, pe, va)
        .expect("loaded hosted executable PE metadata must register once");
    print_str(b"[sec-init] bootstrap-image item=");
    print_u64(index as u64);
    print_str(b" end\n");
}

#[derive(Clone, Copy)]
struct Win32kTokenContext {
    authentication_id: u64,
    user_sid: [u8; win32k_subsystem::WIN32K_TOKEN_USER_SID_MAX],
    user_sid_len: u32,
}

fn win32k_token_context(nt_handler: &ExecNtHandler, pi: usize) -> Win32kTokenContext {
    let authentication_id = nt_handler
        .primary_token_authentication_id_for_pi(pi)
        .map(|luid| luid.low as u64 | ((luid.high as u32 as u64) << 32))
        .unwrap_or(0);
    let mut user_sid = [0u8; win32k_subsystem::WIN32K_TOKEN_USER_SID_MAX];
    let user_sid_len = nt_handler
        .primary_token_user_sid_for_pi(pi, &mut user_sid)
        .unwrap_or(0) as u32;
    Win32kTokenContext {
        authentication_id,
        user_sid,
        user_sid_len,
    }
}

fn registered_gui_dispatch_client(handler: &ExecNtHandler, pi: usize, badge: u64, tid: u64) -> bool {
    let Some(runtime) = handler.thread_runtime.executable_by_badge(badge) else { return false; };
    let Some(thread) = handler.pm.thread_lifetime(tid as nt_process::ThreadId) else { return false; };
    runtime.pi == pi && runtime.tid == tid && !runtime.publication.is_busy()
        && handler.pm.validate_thread_lifetime(thread)
        && handler.capture_process_identity(pi) == Some(runtime.process)
        && runtime.process.pid == thread.process_id()
}

/// Memory-only observation of the exact retained logical caller while its provider callout runs.
/// A canonical body can already be published even before the PM mirror imports the dispatch.
pub(crate) fn callback_client_runtime(
    client: crate::spawn_hosts::UserCallbackClient,
) -> Option<(u64, bool)> {
    let caller = client.logical_caller?;
    let pointer = registry_live_handler_pointer().ok()?;
    let handler = unsafe { &*pointer };
    if !handler.validate_provider_logical_caller(caller)
        || caller.process().pid as u64 != client.pid
        || caller.thread().thread_id() as u64 != client.tid
        || caller.badge() != client.badge
        || handler.capture_process_identity(client.pi as usize) != Some(caller.process())
        || handler.hosted_process_generation(client.pi as usize) != Some(client.generation)
    { return None; }
    let runtime = handler.thread_runtime.executable_by_badge(client.badge)?;
    if runtime.pi != client.pi as usize || runtime.tcb != client.tcb
        || handler.pm.thread_teb(caller.thread().thread_id()) != Some(client.teb)
        || runtime.publication.is_busy()
    { return None; }
    let alias = handler.hosted_gui_thread_teb_alias_for(caller)?;
    let converted = crate::ps_object_backing::read_thread_win32(&handler.pm, caller.thread())
        .ok()? != 0;
    Some((alias, converted))
}

/// Publish the registered provider's GDI resources before real ClientThreadSetup caches the PEB.
/// This does not convert a thread or grant GUI-call authority.
pub(crate) unsafe fn prepare_callback_gdi_projection(
    client: crate::spawn_hosts::UserCallbackClient,
) -> bool {
    if callback_client_runtime(client).is_none() { return false; }
    let Some(caller) = client.logical_caller else { return false; };
    let Ok(pointer) = registry_live_handler_pointer() else { return false; };
    let pi = client.pi as usize;
    let pml4 = (&(*pointer).process_vspaces).get(pi).copied().unwrap_or(0);
    let Ok(process) = (*pointer).pm.query_process_basic(caller.process().pid, u64::MAX) else {
        return false;
    };
    let peb = process.peb_base_address;
    if pml4 == 0 || peb == 0 { return false; }
    let Some(field) = peb.checked_add(0xf8) else { return false; };
    let table = win32k_glue::map_gdi_shared_handle_table_into_client(&mut *pointer, pml4, pi);
    if table == 0 || callback_client_runtime(client).is_none()
        || (&(*pointer).process_vspaces).get(pi).copied() != Some(pml4)
    { return false; }
    if !win32k_glue::map_gdi_user_attributes_into_client(&mut *pointer, pml4, pi)
        || callback_client_runtime(client).is_none()
        || (&(*pointer).process_vspaces).get(pi).copied() != Some(pml4)
    { return false; }
    if (*pointer).process_memory_write_checked(pi, field, &table.to_le_bytes()).is_err()
        || callback_client_runtime(client).is_none()
        || (&(*pointer).process_vspaces).get(pi).copied() != Some(pml4)
    { return false; }
    record_hosted_client_gdi_mapping(&mut *pointer, pi, table, Some(caller));
    true
}

fn win32k_client_context_for_thread(
    nt_handler: &ExecNtHandler,
    pi: usize,
    badge: u64,
    tid: u64,
    tcb: u64,
    role: Option<HostedThreadRole>,
    teb: u64,
    peb_mirror: u64,
    scratch_base: u64,
) -> win32k_glue::Win32kClientContext {
    let pid = nt_handler.pm_pid_for_pi(pi).unwrap_or(0);
    let token = win32k_token_context(nt_handler, pi);
    win32k_glue::Win32kClientContext {
        logical_caller: nt_handler.capture_provider_logical_caller(pi, tid, badge, tcb),
        pi: pi as u32,
        generation: nt_handler
            .hosted_process_image(pi)
            .map(|image| image.generation)
            .unwrap_or(0),
        pid: pid as u64,
        badge,
        tid,
        tcb,
        eprocess: nt_handler.pm.process_kernel_object(pid).unwrap_or(0),
        ethread: nt_handler
            .pm
            .thread_kernel_object(tid as nt_process::ThreadId)
            .unwrap_or(0),
        role,
        process_role: nt_handler.hosted_process_role(pi),
        top_badge: nt_handler.hosted_process_top_badge(pi).unwrap_or(0),
        teb,
        peb_mirror,
        scratch_base,
        token_authentication_id: token.authentication_id,
        token_user_sid: token.user_sid,
        token_user_sid_len: token.user_sid_len,
    }
}

unsafe fn sync_win32k_context_to_process_manager(
    nt_handler: &mut ExecNtHandler,
    expected_pi: usize,
    expected_pid: u64,
    expected_tid: u64,
) -> bool {
    let captured = if expected_pi < MAX_PI {
        win32k_glue::take_suspended_published_win32k_context(
            expected_pi as u32,
            expected_pid,
            expected_tid,
        )
    } else {
        None
    };
    let published = match captured {
        Some(published) => published,
        None => {
            let Some(published) =
                win32k_glue::take_matching_published_win32k_context(expected_pid, expected_tid)
            else {
                return true;
            };
            published
        }
    };
    let pid = if published.pid != 0 {
        published.pid
    } else {
        expected_pid
    };
    let tid = if published.tid != 0 {
        published.tid
    } else {
        expected_tid
    };
    if expected_pid != 0 && pid != expected_pid {
        print_str(b"[win32k-context] ERROR: matched context identity mismatch expected-pid=");
        print_u64(expected_pid);
        print_str(b" actual=");
        print_u64(pid);
        print_str(b"\n");
        return false;
    }

    if pid != 0 && pid <= nt_process::ProcessId::MAX as u64 {
        let pid = pid as nt_process::ProcessId;
        if published.eprocess != 0 {
            if !nt_handler
                .pm
                .publish_process_kernel_object(pid, published.eprocess)
            {
                return false;
            }
        }
        if published.w32process != 0 {
            if !nt_handler.pm.set_process_win32(pid, published.w32process) {
                return false;
            }
            if let Err(status) =
                nt_handler.publish_process_win32_job_membership(pid, published.w32process)
            {
                print_str(b"[ps-job] failed to attach W32PROCESS pid=");
                print_u64(pid as u64);
                print_str(b" status=0x");
                print_hex(status);
                print_str(b"\n");
                return false;
            }
        }
    }
    if tid != 0 && tid <= nt_process::ThreadId::MAX as u64 {
        let tid = tid as nt_process::ThreadId;
        if pid != 0 {
            let Some(client_id) = nt_handler.pm.client_id(tid) else {
                let n = WIN32K_CONTEXT_IMPORT_TRACE.fetch_add(1, Ordering::Relaxed);
                if n < 32 {
                    print_str(b"[win32k-context] ERROR: published TID unknown tid=");
                    print_u64(tid as u64);
                    print_str(b" pid=");
                    print_u64(pid);
                    print_str(b"\n");
                }
                return false;
            };
            if client_id.unique_process as u64 != pid {
                let n = WIN32K_CONTEXT_IMPORT_TRACE.fetch_add(1, Ordering::Relaxed);
                if n < 32 {
                    print_str(b"[win32k-context] ERROR: published TID belongs to pid=");
                    print_u64(client_id.unique_process as u64);
                    print_str(b" expected-pid=");
                    print_u64(pid);
                    print_str(b" tid=");
                    print_u64(tid as u64);
                    print_str(b"\n");
                }
                return false;
            }
        }
        if expected_tid != 0 && tid as u64 != expected_tid {
            let n = WIN32K_CONTEXT_IMPORT_TRACE.fetch_add(1, Ordering::Relaxed);
            if n < 32 {
                print_str(b"[win32k-context] imported published thread expected-tid=");
                print_u64(expected_tid);
                print_str(b" actual-tid=");
                print_u64(tid as u64);
                print_str(b" pid=");
                print_u64(pid);
                print_str(b"\n");
            }
        }
        if published.ethread != 0 {
            if !nt_handler
                .pm
                .publish_thread_kernel_object(tid, published.ethread)
            {
                return false;
            }
        }
        if published.w32thread != 0 {
            let _ = nt_handler.pm.set_thread_win32(tid, published.w32thread);
        }
    }
    true
}

/// Consume the exact provider process-create publication before the initial loader can run.
/// The PM mirror then owns W32PROCESS and will issue the real process-exit callout before
/// provider object finalization. A missing or mismatched publication is an indeterminate
/// post-callout state; callers must retain the process and never invoke create again.
pub(crate) unsafe fn import_early_win32k_process_context(
    nt_handler: &mut ExecNtHandler,
    pi: usize,
    process: nt_types::ProcessIdentity,
    tid: u64,
) -> Option<u64> {
    if nt_handler.capture_process_identity(pi) != Some(process) { return None; }
    let pid = process.pid;
    let tid32 = nt_process::ThreadId::try_from(tid).ok()?;
    let published = win32k_glue::published_win32k_context();
    if published.pid != u64::from(pid) || published.tid != tid
        || published.eprocess == 0 || published.ethread == 0
        || published.eprocess != nt_handler.pm.process_kernel_object(pid).unwrap_or(0)
        || published.ethread != nt_handler.pm.thread_kernel_object(tid32).unwrap_or(0)
        || published.w32process == 0 || published.w32thread != 0
    { return None; }
    if !sync_win32k_context_to_process_manager(nt_handler, pi, u64::from(pid), tid)
        || nt_handler.capture_process_identity(pi) != Some(process)
        || nt_handler.pm.process_win32(pid) != Some(published.w32process)
    { return None; }
    Some(published.w32process)
}

unsafe fn dispatch_win32k_for_client(
    nt_handler: &mut ExecNtHandler,
    ssn: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    caller_sp: u64,
    stack_args: &[u64],
    client: win32k_glue::Win32kClientContext,
) -> (u64, bool) {
    let win32k_glue::Win32kDispatchOutcome::Known { value, completed } =
        win32k_glue::win32k_dispatch_wide(ssn, a0, a1, a2, a3, caller_sp, stack_args, client);
    if sync_win32k_context_to_process_manager(
        nt_handler,
        client.pi as usize,
        client.pid,
        client.tid,
    ) {
        (value, completed)
    } else {
        (0xC000_00A3u32 as u64, false)
    }
}

unsafe fn dispatch_win32k_for_client_with_completion_args(
    nt_handler: &mut ExecNtHandler,
    dispatch_id: u64,
    ssn: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    caller_sp: u64,
    stack_args: &[u64],
    completion_args: [u64; 4],
    output_stage: Option<nt_user_callback::DispatchOutputStage>,
    paint_output: Option<nt_user_callback::PaintOutputClaim>,
    client: win32k_glue::Win32kClientContext,
    dispatch_return: &mut Option<nt_user_callback::DispatchReturn>,
    dispatch_entered: &mut bool,
    dispatch_context: &mut Option<nt_user_callback::DispatchContext>,
) -> (u64, bool) {
    let result = win32k_glue::win32k_dispatch_wide_with_return_receipt(
        dispatch_id,
        ssn,
        a0,
        a1,
        a2,
        a3,
        caller_sp,
        stack_args,
        completion_args,
        output_stage,
        paint_output,
        client,
        dispatch_entered,
        dispatch_context,
    );
    *dispatch_return = result.dispatch_return;
    let win32k_glue::Win32kDispatchOutcome::Known { value, completed } = result.outcome;
    if sync_win32k_context_to_process_manager(
        nt_handler,
        client.pi as usize,
        client.pid,
        client.tid,
    ) {
        (value, completed)
    } else {
        (0xC000_00A3u32 as u64, false)
    }
}

unsafe fn post_winlogon_second_sas_after_welcome_drain(
    logical_caller: Option<nt_user_host::provider_logical_caller::ProviderLogicalCaller>,
    pi: usize,
    generation: u64,
    badge: u64,
    current_tid: u64,
    current_tcb: u64,
    current_role: Option<HostedThreadRole>,
    process_role: Option<nt_exe_image::HostedProcessRole>,
    top_badge: u64,
    main_tid: u64,
    pid: u64,
    client_teb: u64,
    peb_mirror: u64,
    scratch_base: u64,
    token: Win32kTokenContext,
) -> bool {
    let sas1 = WINLOGON_SAS1_RETRIEVED.load(Ordering::Relaxed);
    let sas2 = WINLOGON_SAS2_INJECTED.load(Ordering::Relaxed);
    let paint_now = win32k_glue::real_wm_paint_callback_returns();
    let paint_at_sas1 = WINLOGON_PAINT_RETURNS_AT_SAS1.load(Ordering::Relaxed);
    let paint_hwnd = win32k_glue::last_real_wm_paint_hwnd();
    let paint_pwnd = if paint_hwnd != 0 {
        winlogon_pwnd_for_hwnd(paint_hwnd)
    } else {
        0
    };
    if process_role != Some(nt_exe_image::HostedProcessRole::InteractiveLogon)
        || badge != top_badge
        || current_tid == 0
        || main_tid != current_tid
        || sas1 == 0
        || sas2 != 0
    {
        return false;
    }
    if paint_now <= paint_at_sas1 {
        return false;
    }
    if paint_pwnd == 0 {
        return false;
    }

    let session = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_SESSION) as *const u64,
    );
    let mut logon_state = 0u32;
    if session != 0 {
        const WLSESSION_LOGONSTATE_OFF: u64 = 0x118;
        let mut bytes = [0u8; 4];
        if img_spawn::smss_copyin(session + WLSESSION_LOGONSTATE_OFF, &mut bytes) {
            logon_state = u32::from_le_bytes(bytes);
        }
    }
    print_str(b"[wl-main] welcome queue drained after real paint; Session->LogonState=0x");
    print_hex(logon_state);
    print_str(b"\n");
    if logon_state != nt_user_callback::WINLOGON_STATE_LOGGED_OFF {
        return false;
    }

    WINLOGON_SAS_LOGONSTATE.store(logon_state as u64, Ordering::Relaxed);
    let _ = winlogon_dialog_observe_logged_off(session, logon_state);
    let hwnd = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_HWND) as *const u64,
    );
    if hwnd == 0 {
        return false;
    }
    WINLOGON_KEY_OPENED_AT_INJECT.store(
        WINLOGON_KEY_OPENED.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
    print_str(b"[wl-main] posting simulated Ctrl-Alt-Del through real NtUserPostMessage hwnd=0x");
    print_hex(hwnd as u32);
    print_str(b"\n");
    let win32k_glue::Win32kDispatchOutcome::Known { value: post_value, completed: post_completed } = win32k_glue::win32k_dispatch_wide(
        0x100e,
        hwnd,
        nt_user_callback::WLX_WM_SAS as u64,
        nt_user_callback::WLX_SAS_TYPE_CTRL_ALT_DEL,
        0,
        0,
        &[],
        win32k_glue::Win32kClientContext {
            logical_caller,
            pi: pi as u32,
            generation,
            pid,
            badge,
            tid: current_tid,
            tcb: current_tcb,
            eprocess: 0,
            ethread: 0,
            role: current_role,
            process_role,
            top_badge,
            teb: client_teb,
            peb_mirror,
            scratch_base,
            token_authentication_id: token.authentication_id,
            token_user_sid: token.user_sid,
            token_user_sid_len: token.user_sid_len,
        },
    );
    print_str(b"[wl-main] NtUserPostMessage(WLX_WM_SAS) -> ret=0x");
    print_hex(post_value as u32);
    print_str(b"\n");
    if post_completed && post_value != 0 {
        WINLOGON_SAS2_INJECTED.store(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

fn winlogon_second_sas_route_proven() -> bool {
    WINLOGON_SAS2_INJECTED.load(Ordering::Relaxed) != 0
        || WINLOGON_SAS2_RETRIEVED.load(Ordering::Relaxed) != 0
}

unsafe fn read_winlogon_session_logon_state() -> Option<(u64, u32)> {
    let session = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_SESSION) as *const u64,
    );
    if session == 0 {
        return None;
    }

    const WLSESSION_LOGONSTATE_OFF: u64 = 0x118;
    let mut bytes = [0u8; 4];
    img_spawn::smss_copyin(session + WLSESSION_LOGONSTATE_OFF, &mut bytes)
        .then(|| (session, u32::from_le_bytes(bytes)))
}

unsafe fn observe_winlogon_sas_logon_state() {
    if WINLOGON_SAS1_RETRIEVED.load(Ordering::Relaxed) == 0
        || WINLOGON_SAS_LOGONSTATE.load(Ordering::Relaxed) != 0
    {
        return;
    }
    let Some((session, logon_state)) = read_winlogon_session_logon_state() else {
        return;
    };
    if logon_state == 0 {
        return;
    }

    WINLOGON_SAS_LOGONSTATE.store(logon_state as u64, Ordering::Relaxed);
    if logon_state == nt_user_callback::WINLOGON_STATE_LOGGED_OFF {
        let _ = winlogon_dialog_observe_logged_off(session, logon_state);
    }
    print_str(b"[wl-main] observed post-SAS Session->LogonState=0x");
    print_hex(logon_state);
    print_str(b"\n");
}

fn hosted_top_badge_for_pi(nt_handler: &ExecNtHandler, pi: usize) -> u64 {
    nt_handler.hosted_process_top_badge(pi).unwrap_or(0)
}

fn hosted_top_badge_for_role(
    nt_handler: &ExecNtHandler,
    role: nt_exe_image::HostedProcessRole,
) -> Option<u64> {
    (0..MAX_PI).find_map(|pi| {
        (nt_handler.hosted_process_role(pi) == Some(role))
            .then(|| nt_handler.hosted_process_top_badge(pi))
            .flatten()
    })
}

fn hosted_pi_for_role(
    nt_handler: &ExecNtHandler,
    role: nt_exe_image::HostedProcessRole,
) -> Option<usize> {
    (0..MAX_PI).find(|&pi| {
        hosted_process_runtime_for_pi(pi).is_some()
            && nt_handler.hosted_process_role(pi) == Some(role)
    })
}

pub(crate) fn live_hosted_pi_for_observation_role(
    nt_handler: &ExecNtHandler,
    role: nt_exe_image::HostedProcessRole,
) -> Option<usize> {
    let mut selected = None;
    for pi in 0..MAX_PI {
        let Some(image) = nt_handler.hosted_process_image(pi) else {
            continue;
        };
        let Some(runtime) = hosted_process_runtime_for_pi(pi) else {
            continue;
        };
        if image.pi != pi
            || image.observation_role() != role
            || runtime.observation_role != role
            || runtime.pi != image.pi
            || runtime.generation != image.generation
            || !runtime
                .spawned
                .is_some_and(|spawned| spawned.load(Ordering::Relaxed) == 1)
        {
            continue;
        }
        let Some(mechanism) = nt_handler.process_mechanisms.get(pi) else {
            continue;
        };
        let Some(identity) = nt_handler.capture_process_identity(pi) else {
            continue;
        };
        if mechanism.pi != pi
            || mechanism.generation != image.generation
            || mechanism.top_badge != image.top_badge
            || identity.pid != mechanism.pid
            || identity.generation != nt_memory_manager::ProcessGeneration::Hosted(image.generation)
            || !nt_handler
                .pm
                .process(identity.pid)
                .is_some_and(|process| process.state == nt_process::ProcessState::Running)
        {
            continue;
        }
        if selected.is_some() {
            return None;
        }
        selected = Some(pi);
    }
    selected
}

fn hosted_pi_for_top_badge(nt_handler: &ExecNtHandler, badge: u64) -> Option<usize> {
    (0..MAX_PI).find(|&pi| {
        hosted_process_runtime_for_pi(pi).is_some()
            && nt_handler.hosted_process_top_badge(pi) == Some(badge)
    })
}

fn hosted_non_native_top_level_badge(nt_handler: &ExecNtHandler, badge: u64) -> bool {
    hosted_pi_for_top_badge(nt_handler, badge)
        .and_then(|pi| nt_handler.hosted_process_role(pi))
        .is_some_and(|role| role != nt_exe_image::HostedProcessRole::NativeSession)
}

fn hosted_pi_has_role(
    nt_handler: &ExecNtHandler,
    pi: usize,
    role: nt_exe_image::HostedProcessRole,
) -> bool {
    nt_handler.hosted_process_role(pi) == Some(role)
}

fn hosted_main_badge_has_role(
    nt_handler: &ExecNtHandler,
    badge: u64,
    role: nt_exe_image::HostedProcessRole,
) -> bool {
    hosted_pi_for_top_badge(nt_handler, badge)
        .is_some_and(|pi| hosted_pi_has_role(nt_handler, pi, role))
}

fn hosted_owner_has_role(
    nt_handler: &ExecNtHandler,
    badge: u64,
    role: nt_exe_image::HostedProcessRole,
) -> bool {
    owner_top_badge_for(nt_handler, badge)
        .is_some_and(|owner| hosted_main_badge_has_role(nt_handler, owner, role))
}

fn live_hosted_pi_for_role(
    nt_handler: &ExecNtHandler,
    role: nt_exe_image::HostedProcessRole,
) -> Option<usize> {
    for pi in 0..MAX_PI {
        if nt_handler.hosted_process_role(pi) != Some(role) {
            continue;
        }
        let Some(pid) = nt_handler.pm_pid_for_pi(pi) else {
            continue;
        };
        if nt_handler.pm.process(pid).is_some() {
            return Some(pi);
        }
    }
    None
}

fn hosted_leaf_for_fault_badge(nt_handler: &ExecNtHandler, badge: u64) -> Option<&[u8]> {
    let runtime = nt_handler.admit_hosted_thread_ingress(badge).ok()?;
    nt_handler.hosted_process_leaf(runtime.pi)
}

fn interactive_shell_frontier_pi(nt_handler: &ExecNtHandler) -> Option<usize> {
    let connected = W32_CONNECTED_MASK.load(Ordering::Relaxed);
    let create_window_attempted =
        INTERACTIVE_SHELL_CREATE_WINDOW_ATTEMPT_MASK.load(Ordering::Relaxed);
    for pi in 0..MAX_PI.min(64) {
        if nt_handler.hosted_process_observation_role(pi)
            != Some(nt_exe_image::HostedProcessRole::InteractiveShell)
        {
            continue;
        }
        if nt_handler.pm_pid_for_pi(pi).is_none() {
            continue;
        }
        let bit = 1u64 << pi;
        if connected & bit == 0 || create_window_attempted & bit != 0 {
            continue;
        }
        return Some(pi);
    }
    None
}

unsafe fn interactive_shell_chrome_frontier_pending(
    nt_handler: &ExecNtHandler,
    crash_parked: u64,
    wait_parked: u64,
) -> bool {
    if explorer_chrome_runtime_milestones_reached() {
        return false;
    }
    let Some(pi) = live_hosted_pi_for_observation_role(
        nt_handler,
        nt_exe_image::HostedProcessRole::InteractiveShell,
    ) else {
        return false;
    };
    let Some(owner) = nt_handler.hosted_process_top_badge(pi) else {
        return false;
    };
    if owner >= 64 {
        return false;
    }
    let owner_bit = 1u64 << owner;
    if crash_parked & owner_bit != 0 {
        return false;
    }
    owner_bit & !(crash_parked | wait_parked) != 0
}

unsafe fn defer_quiesce_for_interactive_shell_chrome(
    nt_handler: &ExecNtHandler,
    crash_parked: u64,
    wait_parked: u64,
) -> bool {
    if !interactive_shell_chrome_frontier_pending(nt_handler, crash_parked, wait_parked) {
        return false;
    }
    let n = SHELL_CHROME_QUIESCE_DEFER_TRACE.fetch_add(1, Ordering::Relaxed);
    if n < 8 {
        print_str(b"[quiesce] deferring while Explorer shell chrome frontier is live: register-window-messages=");
        print_u64(EXPLORER_REGISTER_WINDOW_MESSAGE_CAPTURES.load(Ordering::Relaxed));
        print_str(b" begin-paints=");
        print_u64(EXPLORER_BEGIN_PAINTS.load(Ordering::Relaxed));
        print_str(b" direct-gdi=");
        print_u64(EXPLORER_DIRECT_GDI_DRAW_RETURNS.load(Ordering::Relaxed));
        print_str(b" gdi-batches=");
        print_u64(EXPLORER_GDI_BATCH_FLUSHES.load(Ordering::Relaxed));
        print_str(b"\n");
    }
    true
}

unsafe fn pre_user_shell_frontier_pending(
    nt_handler: &ExecNtHandler,
    crash_parked: u64,
    wait_parked: u64,
    reason: &[u8],
) -> bool {
    if live_hosted_pi_for_observation_role(
        nt_handler,
        nt_exe_image::HostedProcessRole::InteractiveShellBootstrap,
    ).is_some()
        || live_hosted_pi_for_observation_role(
            nt_handler,
            nt_exe_image::HostedProcessRole::ServiceControlManager,
        ).is_none()
    {
        return false;
    }

    // Services may sit in normal finite NT waits while their idle worker loops poll IOCP/timeouts.
    // Those waiters are live, but they are not runnable work that should defer the interactive
    // login gate once the pre-user-shell path has otherwise gone idle.
    let mut runnable_owners = runnable_top_badges(nt_handler) & !(crash_parked | wait_parked);
    if let Some(winlogon_badge) = live_hosted_pi_for_observation_role(
        nt_handler,
        nt_exe_image::HostedProcessRole::InteractiveLogon,
    ).and_then(|pi| nt_handler.hosted_process_top_badge(pi))
    {
        if winlogon_badge < 64 {
            runnable_owners &= !(1u64 << winlogon_badge);
        }
    }
    if runnable_owners == 0 {
        return false;
    }

    let n = PRE_USER_SHELL_QUIESCE_DEFER_TRACE.fetch_add(1, Ordering::Relaxed);
    if n < 8 {
        print_str(b"[quiesce] ");
        print_str(reason);
        print_str(b": deferring gate while pre-user-shell hosted work is runnable: owners=0x");
        print_hex_u64(runnable_owners);
        print_str(b" services-events=");
        print_u64(SERVICES_NAMED_EVENTS.load(Ordering::Relaxed));
        print_str(b" query-dir=");
        print_u64(SERVICES_QUERY_DIR_OBJECT.load(Ordering::Relaxed));
        print_str(b" lsa-active=");
        print_u64(LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed));
        print_str(b" userinit=");
        print_u64(live_hosted_pi_for_observation_role(
            nt_handler,
            nt_exe_image::HostedProcessRole::InteractiveShellBootstrap,
        ).is_some() as u64);
        print_str(b"\n");
    }
    true
}

unsafe fn dump_shell_launch_quiesce(
    nt_handler: &ExecNtHandler,
    loaded_images: &HostedLoadedImageTable,
    reg: &nt_dll_registry::Registry,
    ntdll: (u64, &nt_pe_loader::PeFile),
    procs: &[ProcExec],
    pfilled: &[[u64; 512]],
) {
    let userinit_pi = live_hosted_pi_for_observation_role(
        nt_handler,
        nt_exe_image::HostedProcessRole::InteractiveShellBootstrap,
    );
    let explorer_pi = live_hosted_pi_for_observation_role(
        nt_handler,
        nt_exe_image::HostedProcessRole::InteractiveShell,
    );
    if userinit_pi.is_some()
        && USERINIT_SHELL_IMAGE_ATTEMPTS.load(Ordering::Relaxed) == 0
        && EXPLORER_IMAGE_OPEN_SUCCESSES.load(Ordering::Relaxed) == 0
    {
        if let Some(pi) = userinit_pi {
            if SHELL_LAUNCH_QUIESCE_DUMPED.fetch_or(1, Ordering::Relaxed) & 1 == 0 {
                print_str(b"[shell-launch] userinit spawned but no shell image open attempt; pi=");
                print_u64(pi as u64);
                print_str(b" spawned=");
                print_u64(1);
                print_str(b" shell-attempts=");
                print_u64(USERINIT_SHELL_IMAGE_ATTEMPTS.load(Ordering::Relaxed));
                print_str(b" explorer-opens=");
                print_u64(EXPLORER_IMAGE_OPEN_SUCCESSES.load(Ordering::Relaxed));
                print_str(b"\n");
                dump_hosted_main_thread_quiesce(
                    b"userinit-quiesce",
                    pi,
                    nt_handler,
                    loaded_images,
                    reg,
                    ntdll,
                    procs,
                    pfilled,
                );
            }
        }
    }

    if explorer_pi.is_some()
        && EXPLORER_CREATE_WINDOW_STRING_CAPTURES.load(Ordering::Relaxed) == 0
    {
        if let Some(pi) = explorer_pi {
            if SHELL_LAUNCH_QUIESCE_DUMPED.fetch_or(2, Ordering::Relaxed) & 2 == 0 {
                print_str(
                    b"[shell-launch] explorer spawned before first captured CreateWindow string; pi=",
                );
                print_u64(pi as u64);
                print_str(b" spawned=");
                print_u64(1);
                print_str(b" create-window-strings=");
                print_u64(EXPLORER_CREATE_WINDOW_STRING_CAPTURES.load(Ordering::Relaxed));
                print_str(b" connected-mask=0x");
                print_hex_u64(W32_CONNECTED_MASK.load(Ordering::Relaxed));
                print_str(b"\n");
                dump_hosted_main_thread_quiesce(
                    b"explorer-quiesce",
                    pi,
                    nt_handler,
                    loaded_images,
                    reg,
                    ntdll,
                    procs,
                    pfilled,
                );
            }
        }
    }

    if explorer_pi.is_some()
        && (EXPLORER_REGISTER_WINDOW_MESSAGE_CAPTURES.load(Ordering::Relaxed) == 0
            || EXPLORER_BEGIN_PAINTS.load(Ordering::Relaxed) == 0)
    {
        if let Some(pi) = explorer_pi {
            if SHELL_LAUNCH_QUIESCE_DUMPED.fetch_or(4, Ordering::Relaxed) & 4 == 0 {
                print_str(b"[shell-launch] explorer spawned before shell chrome milestones; pi=");
                print_u64(pi as u64);
                print_str(b" register-window-messages=");
                print_u64(EXPLORER_REGISTER_WINDOW_MESSAGE_CAPTURES.load(Ordering::Relaxed));
                print_str(b" begin-paints=");
                print_u64(EXPLORER_BEGIN_PAINTS.load(Ordering::Relaxed));
                print_str(b" direct-gdi=");
                print_u64(EXPLORER_DIRECT_GDI_DRAW_RETURNS.load(Ordering::Relaxed));
                print_str(b" gdi-batches=");
                print_u64(EXPLORER_GDI_BATCH_FLUSHES.load(Ordering::Relaxed));
                print_str(b"\n");
                dump_hosted_main_thread_quiesce(
                    b"explorer-chrome",
                    pi,
                    nt_handler,
                    loaded_images,
                    reg,
                    ntdll,
                    procs,
                    pfilled,
                );
            }
        }
    }
}

unsafe fn dump_lsa_readiness_quiesce(
    nt_handler: &ExecNtHandler,
    loaded_images: &HostedLoadedImageTable,
    reg: &nt_dll_registry::Registry,
    ntdll: (u64, &nt_pe_loader::PeFile),
    procs: &[ProcExec],
    pfilled: &[[u64; 512]],
) {
    if LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0 {
        return;
    }

    let services_pi = live_hosted_pi_for_observation_role(
        nt_handler,
        nt_exe_image::HostedProcessRole::ServiceControlManager,
    );
    let lsass_pi = live_hosted_pi_for_observation_role(
        nt_handler,
        nt_exe_image::HostedProcessRole::LocalSecurityAuthority,
    );
    if services_pi.is_none()
        && lsass_pi.is_none()
        && LSASS_SRM_CONNECTED.load(Ordering::Relaxed) == 0
    {
        return;
    }
    if LSA_READINESS_QUIESCE_DUMPED.fetch_or(1, Ordering::Relaxed) & 1 != 0 {
        return;
    }

    print_str(b"[lsa-readiness] no lsa_rpc_server_active before quiesce");
    print_str(b" services-pi=");
    match services_pi {
        Some(pi) => print_u64(pi as u64),
        None => print_str(b"none"),
    }
    print_str(b" lsass-pi=");
    match lsass_pi {
        Some(pi) => print_u64(pi as u64),
        None => print_str(b"none"),
    }
    print_str(b" services-spawned=");
    print_u64(services_pi.is_some() as u64);
    print_str(b" lsass-spawned=");
    print_u64(lsass_pi.is_some() as u64);
    print_str(b" srm-port=0x");
    print_hex_u64(SRM_COMMAND_PORT_OBJECT_HANDLE.load(Ordering::Relaxed));
    print_str(b" srm-connected=");
    print_u64(LSASS_SRM_CONNECTED.load(Ordering::Relaxed));
    print_str(b" named-events=");
    print_u64(SERVICES_NAMED_EVENTS.load(Ordering::Relaxed));
    print_str(b" query-dir=");
    print_u64(SERVICES_QUERY_DIR_OBJECT.load(Ordering::Relaxed));
    print_str(b"\n");

    print_str(b"[lsa-readiness] lpc auth-port=0x");
    print_hex_u64(LSA_AUTH_PORT_OBJECT_HANDLE.load(Ordering::Relaxed));
    print_str(b" delivered=");
    print_u64(LSA_CONNECT_DELIVERED.load(Ordering::Relaxed));
    print_str(b" completed=");
    print_u64(LSA_CONNECT_COMPLETED.load(Ordering::Relaxed));
    print_str(b" requests=");
    print_u64(LSA_REQUESTS_DELIVERED.load(Ordering::Relaxed));
    print_str(b" replies=");
    print_u64(LSA_REPLIES_DELIVERED.load(Ordering::Relaxed));
    print_str(b" rpc-clients=");
    print_u64(LSA_RPC_NEW_CLIENT_REQUESTS.load(Ordering::Relaxed));
    print_str(b" workers=");
    print_u64(LSA_RPC_EXTRA_WORKERS_CLAIMED.load(Ordering::Relaxed));
    print_str(b" worker-ssn=");
    print_u64(LSA_WORKER_SYSCALLS.load(Ordering::Relaxed));
    print_str(b"\n");

    if let Some(pi) = services_pi {
        dump_hosted_main_thread_quiesce(
            b"services-readiness",
            pi,
            nt_handler,
            loaded_images,
            reg,
            ntdll,
            procs,
            pfilled,
        );
    }
    if let Some(pi) = lsass_pi {
        dump_hosted_main_thread_quiesce(
            b"lsass-readiness",
            pi,
            nt_handler,
            loaded_images,
            reg,
            ntdll,
            procs,
            pfilled,
        );
    }
}

unsafe fn dump_services_start_quiesce(
    nt_handler: &ExecNtHandler,
    loaded_images: &HostedLoadedImageTable,
    reg: &nt_dll_registry::Registry,
    ntdll: (u64, &nt_pe_loader::PeFile),
    procs: &[ProcExec],
    pfilled: &[[u64; 512]],
) {
    let services_pi = live_hosted_pi_for_observation_role(
        nt_handler,
        nt_exe_image::HostedProcessRole::ServiceControlManager,
    );
    let userinit_pi = live_hosted_pi_for_observation_role(
        nt_handler,
        nt_exe_image::HostedProcessRole::InteractiveShellBootstrap,
    );
    let explorer_pi = live_hosted_pi_for_observation_role(
        nt_handler,
        nt_exe_image::HostedProcessRole::InteractiveShell,
    );
    if services_pi.is_none() || userinit_pi.is_some() || explorer_pi.is_some() {
        return;
    }
    if SERVICES_START_QUIESCE_DUMPED.fetch_or(1, Ordering::Relaxed) & 1 != 0 {
        return;
    }

    print_str(b"[services-quiesce] services spawned before user shell launch");
    print_str(b" pi=");
    match services_pi {
        Some(pi) => print_u64(pi as u64),
        None => print_str(b"none"),
    }
    print_str(b" named-events=");
    print_u64(SERVICES_NAMED_EVENTS.load(Ordering::Relaxed));
    print_str(b" query-dir=");
    print_u64(SERVICES_QUERY_DIR_OBJECT.load(Ordering::Relaxed));
    print_str(b" lsa-active=");
    print_u64(LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed));
    print_str(b" scm-worker-faults=");
    print_u64(SCM_WORKER_FAULTS.load(Ordering::Relaxed));
    print_str(b" userinit=");
    print_u64(userinit_pi.is_some() as u64);
    print_str(b" explorer=");
    print_u64(explorer_pi.is_some() as u64);
    print_str(b"\n");

    if let Some(pi) = services_pi {
        dump_hosted_main_thread_quiesce(
            b"services-quiesce",
            pi,
            nt_handler,
            loaded_images,
            reg,
            ntdll,
            procs,
            pfilled,
        );
    }
}

unsafe fn dump_interactive_shell_frontier_quiesce(
    nt_handler: &ExecNtHandler,
    loaded_images: &HostedLoadedImageTable,
    reg: &nt_dll_registry::Registry,
    ntdll: (u64, &nt_pe_loader::PeFile),
    procs: &[ProcExec],
    pfilled: &[[u64; 512]],
) {
    dump_shell_launch_quiesce(nt_handler, loaded_images, reg, ntdll, procs, pfilled);
    let Some(pi) = interactive_shell_frontier_pi(nt_handler) else {
        return;
    };
    print_str(
        b"[shell-frontier] no progress after NtUserProcessConnect before first NtUserCreateWindowEx; pi=",
    );
    print_u64(pi as u64);
    print_str(b" connected-mask=0x");
    print_hex_u64(W32_CONNECTED_MASK.load(Ordering::Relaxed));
    print_str(b" create-window-mask=0x");
    print_hex_u64(INTERACTIVE_SHELL_CREATE_WINDOW_ATTEMPT_MASK.load(Ordering::Relaxed));
    print_str(b"\n");
    dump_hosted_main_thread_quiesce(
        b"shell-quiesce",
        pi,
        nt_handler,
        loaded_images,
        reg,
        ntdll,
        procs,
        pfilled,
    );
}

struct HostedExeSpawn<'a> {
    image: nt_exe_image::HostedProcessImageRef<'a>,
    runtime: HostedProcessRuntime,
    pe: &'a nt_pe_loader::PeFile<'static>,
    layout: nt_exe_image::ProcessImageLayout,
    spawned: &'static AtomicU64,
    _image_reader: crate::hosted_loaded_images::HostedImageReadScope,
}

#[derive(Clone, Copy)]
enum HostedMultiplexedThreadSpawner {
    ServicesListener,
    LsassListener,
    LsassListener2,
    LsassListener3,
}

#[derive(Clone, Copy)]
struct HostedThreadSpawnSpec {
    owner_role: nt_exe_image::HostedProcessRole,
    badge: u64,
    role: HostedThreadRole,
    spawner: HostedMultiplexedThreadSpawner,
    spawn_prefix: &'static [u8],
    spawned_prefix: &'static [u8],
    spawned_suffix: &'static [u8],
}

fn hosted_multiplexed_thread_spawn_for(
    kind: HostedMultiplexedThreadKind,
) -> Option<HostedThreadSpawnSpec> {
    match kind {
        HostedMultiplexedThreadKind::ServicesListener => Some(HostedThreadSpawnSpec {
            owner_role: nt_exe_image::HostedProcessRole::ServiceControlManager,
            badge: SVC_LISTENER_BADGE,
            role: HostedThreadRole::ServicesListener,
            spawner: HostedMultiplexedThreadSpawner::ServicesListener,
            spawn_prefix: b"[svc-thread] spawning + RESUMING REAL RPC listener thread: entry=0x",
            spawned_prefix: b"[svc-thread] spawned + resumed tcb=0x",
            spawned_suffix: b" (runs into the main multiplex, badge 7)\n",
        }),
        HostedMultiplexedThreadKind::LsassListener { slot: 0 } => Some(HostedThreadSpawnSpec {
            owner_role: nt_exe_image::HostedProcessRole::LocalSecurityAuthority,
            badge: LSASS_LISTENER_BADGE,
            role: HostedThreadRole::LsassListener,
            spawner: HostedMultiplexedThreadSpawner::LsassListener,
            spawn_prefix: b"[lsass-thread] spawning + RESUMING REAL LSA server thread: entry=0x",
            spawned_prefix: b"[lsass-thread] spawned + resumed tcb=0x",
            spawned_suffix: b" (runs into the main multiplex, badge 9)\n",
        }),
        HostedMultiplexedThreadKind::LsassListener { slot: 1 } => Some(HostedThreadSpawnSpec {
            owner_role: nt_exe_image::HostedProcessRole::LocalSecurityAuthority,
            badge: LSASS_LISTENER2_BADGE,
            role: HostedThreadRole::LsassListener2,
            spawner: HostedMultiplexedThreadSpawner::LsassListener2,
            spawn_prefix: b"[lsass-thread2] spawning + RESUMING 2nd LSA server thread: entry=0x",
            spawned_prefix: b"[lsass-thread2] spawned + resumed tcb=0x",
            spawned_suffix: b" (runs into the main multiplex, badge 10)\n",
        }),
        HostedMultiplexedThreadKind::LsassListener { slot: 2 } => Some(HostedThreadSpawnSpec {
            owner_role: nt_exe_image::HostedProcessRole::LocalSecurityAuthority,
            badge: LSASS_LISTENER3_BADGE,
            role: HostedThreadRole::LsassListener3,
            spawner: HostedMultiplexedThreadSpawner::LsassListener3,
            spawn_prefix: b"[lsass-thread3] spawning + RESUMING 3rd LSA worker: entry=0x",
            spawned_prefix: b"[lsass-thread3] spawned + resumed tcb=0x",
            spawned_suffix: b" (runs into the main multiplex, badge 14)\n",
        }),
        _ => None,
    }
}

unsafe fn hosted_exe_spawn_for<'a>(
    request: nt_exe_image::SpawnRequest,
    catalog: &'a nt_exe_image::OwnedHostedImageCatalog<HOSTED_PROCESS_IMAGE_CAP>,
    loaded_images: *mut HostedLoadedImageTable,
) -> Option<HostedExeSpawn<'a>> {
    let target = request.target?;
    let image = catalog.get_by_pi(target.pi)?;
    if !image.leaf.eq_ignore_ascii_case(request.leaf())
        || nt_exe_image::SpawnTarget::from_image(image) != target
    {
        return None;
    }
    let runtime = hosted_process_runtime_for_pi(target.pi)?;
    let spawned = runtime.spawned?;
    let image_reader = {
        let _durable = allocator::enter_durable();
        unsafe { crate::hosted_loaded_images::HostedImageReadScope::capture(loaded_images, target).ok()? }
    };
    let pe = unsafe { (&*loaded_images).pe_by_pi(target.pi)? };
    let layout = (&*loaded_images).layout_by_pi(target.pi)?;
    Some(HostedExeSpawn {
        image,
        runtime,
        pe,
        layout,
        spawned,
        _image_reader: image_reader,
    })
}

/// Complete one already reserved image spawn before the syscall's original Reply is sent.
/// Both immediate and retained process-image paths use this same physical publication.
pub(crate) enum HostedExeSpawnError {
    Unentered(u32),
    Entered(u32),
    EnteredAbortable(u32),
}

pub(crate) unsafe fn publish_reserved_hosted_exe(
    request: nt_exe_image::SpawnRequest,
    catalog: &nt_exe_image::OwnedHostedImageCatalog<HOSTED_PROCESS_IMAGE_CAP>,
    loaded_images: *mut HostedLoadedImageTable,
    ntdll: (u64, &nt_pe_loader::PeFile),
    fault_ep: u64,
    procs: &mut [ProcExec],
    nt_handler: &mut ExecNtHandler,
    exe_images: &mut nt_exe_image::ImageTable<HOSTED_PROCESS_IMAGE_CAP>,
) -> Result<(u64, bool), HostedExeSpawnError> {
    let Some(spec) = hosted_exe_spawn_for(request, catalog, loaded_images) else {
        return Err(HostedExeSpawnError::Unentered(nt_process::STATUS_INVALID_PARAMETER));
    };
    if spec.spawned.load(Ordering::Relaxed) != 0 {
        return Err(HostedExeSpawnError::Unentered(nt_process::STATUS_INVALID_PARAMETER));
    }
    let is_csrss = spec.image.role == nt_exe_image::HostedProcessRole::Win32Subsystem;
    let handle = spawn_requested_hosted_exe(
        request, spec, ntdll, fault_ep, procs, nt_handler, exe_images,
    )?;
    Ok((handle, is_csrss))
}

unsafe fn spawn_requested_hosted_exe(
    request: nt_exe_image::SpawnRequest,
    spec: HostedExeSpawn<'_>,
    ntdll: (u64, &nt_pe_loader::PeFile),
    fault_ep: u64,
    procs: &mut [ProcExec],
    nt_handler: &mut ExecNtHandler,
    exe_images: &mut nt_exe_image::ImageTable<HOSTED_PROCESS_IMAGE_CAP>,
) -> Result<u64, HostedExeSpawnError> {
    let pi = spec.image.pi;
    let child_pid = nt_handler
        .pm_pid_for_pi(pi)
        .ok_or(HostedExeSpawnError::Unentered(nt_process::STATUS_INVALID_HANDLE))?;
    let child_tid = nt_handler
        .pm_main_tid_for_pi(pi)
        .ok_or(HostedExeSpawnError::Unentered(nt_process::STATUS_INVALID_HANDLE))?;
    let creator_pid = nt_handler
        .pm_pid_for_pi(request.creator_pi)
        .ok_or(HostedExeSpawnError::Unentered(nt_process::STATUS_INVALID_HANDLE))?;
    let initial_priority = native_thread_priority::initial_priority(&nt_handler.pm, u64::from(child_tid))
        .map_err(HostedExeSpawnError::Unentered)?;
    let identity = nt_handler.capture_process_identity(pi)
        .ok_or(HostedExeSpawnError::Unentered(nt_process::STATUS_INVALID_HANDLE))?;
    let fault_badge = mint_badged(fault_ep, spec.image.top_badge)
        .map_err(HostedExeSpawnError::Unentered)?;
    let child_spawn = spawn_hosted_sec_image_for_image(
        spec.image,
        nt_memory_manager::MemoryLifetime::Process(identity),
        spec.pe,
        spec.layout,
        fault_badge,
        Some(ntdll),
        true,
        false,
        0,
        child_pid as u64,
        child_tid as u64,
        initial_priority,
    ).map_err(|_| HostedExeSpawnError::Unentered(nt_process::STATUS_INVALID_HANDLE))?;
    procs[pi].pid = child_pid as u64;
    procs[pi].pml4 = child_spawn.pml4;
    nt_handler.publish_hosted_process_vspace(pi, child_spawn.vspace_caps)
        .map_err(HostedExeSpawnError::Entered)?;
    if !nt_handler.pm.set_peb_base(child_pid, SMSS_PEB_VA) {
        return Err(HostedExeSpawnError::Entered(nt_process::STATUS_INVALID_HANDLE));
    }
    nt_handler.register_main_thread_spawn(pi, child_spawn)
        .map_err(HostedExeSpawnError::Entered)?;
    hosted_debug_filter_process::install_hosted_user_alias(nt_handler, pi)
        .map_err(|error| if error.retained_uncertain {
            HostedExeSpawnError::Entered(error.status)
        } else {
            HostedExeSpawnError::EnteredAbortable(error.status)
        })?;
    procs[pi].img_base = spec.layout.base();
    procs[pi].img_end = spec.layout.end();
    procs[pi].scratch_base = spec.runtime.scratch_base;
    map_demand_scratch_pts(spec.runtime.scratch_base);

    let process_handle = match nt_handler.insert_process_handle(
        creator_pid,
        nt_process::HandleObject::Process(child_pid),
        nt_process::map_process_access(request.desired_access),
    ) {
        Ok(handle) => handle as u64,
        Err(status) => {
            return Err(HostedExeSpawnError::Entered(status));
        }
    };

    if !nt_handler.publish_created_process(request.process_handle_out, process_handle, SMSS_PEB_VA)
    {
        return Err(HostedExeSpawnError::Entered(0xC000_0005));
    }
    if exe_images.publish(request, process_handle).is_err() {
        return Err(HostedExeSpawnError::Entered(0xC000_000D));
    }
    spec.spawned.store(1, Ordering::Relaxed);

    print_str(b"[ntos-exec] NtCreateProcessEx: spawned ");
    print_str(spec.image.leaf);
    print_str(b" (badge ");
    print_u64(spec.image.top_badge);
    print_str(b") -> handle 0x");
    print_hex((process_handle >> 32) as u32);
    print_hex(process_handle as u32);
    if pi >= 5 {
        print_str(b"; initial thread awaits NtCreateThread\n");
    } else {
        print_str(b"; its ntdll loader now multiplexed into this loop\n");
    }
    Ok(process_handle)
}

/// Copyout is synchronous with the originating physical win32k lane. Its pool allocation and
/// desktop objects remain owned by that parked provider until the reply is acknowledged.
pub(crate) unsafe fn service_win32k_gui_client_info(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    packet_address: u64,
    packet_bytes: u64,
    reserved0: u64,
    reserved1: u64,
) -> i32 {
    hosted_gui_client_info::service(
        channel, reply_cap, badge, mi, packet_address, packet_bytes, reserved0, reserved1,
    )
}

fn log_refreshed_gui_thread_client_info(
    winlogon_gui_client: bool,
    pi: usize,
    tid: u64,
    teb_alias: u64,
    client_deskinfo: u64,
    pti: u64,
    delta: u64,
    client_pcti: u64,
    old_pti: u64,
) {
    if winlogon_gui_client {
        if WINLOGON_DESKHEAP_MAPPED.swap(1, Ordering::Relaxed) == 0 {
            print_str(
                b"[wl-main] winlogon CLIENTINFO seeded for client-side ValidateHwnd: pDeskInfo=0x",
            );
            print_hex((client_deskinfo >> 32) as u32);
            print_hex(client_deskinfo as u32);
            print_str(b" pti=0x");
            print_hex((pti >> 32) as u32);
            print_hex(pti as u32);
            print_str(b" ulClientDelta=0x");
            print_hex((delta >> 32) as u32);
            print_hex(delta as u32);
            print_str(b" pClientThreadInfo=0x");
            print_hex((client_pcti >> 32) as u32);
            print_hex(client_pcti as u32);
            print_str(b"\n");
        }
        return;
    }

    if old_pti == pti {
        return;
    }

    let n = GUI_CLIENTINFO_SEED_TRACE.fetch_add(1, Ordering::Relaxed);
    if n < 64 {
        print_str(b"[gui-clientinfo] pi=");
        print_u64(pi as u64);
        print_str(b" tid=");
        print_u64(tid);
        print_str(b" teb=0x");
        print_hex((teb_alias >> 32) as u32);
        print_hex(teb_alias as u32);
        print_str(b" CLIENTINFO seeded for client-side ValidateHwnd: old-pti=0x");
        print_hex((old_pti >> 32) as u32);
        print_hex(old_pti as u32);
        print_str(b" pDeskInfo=0x");
        print_hex((client_deskinfo >> 32) as u32);
        print_hex(client_deskinfo as u32);
        print_str(b" pti=0x");
        print_hex((pti >> 32) as u32);
        print_hex(pti as u32);
        print_str(b" ulClientDelta=0x");
        print_hex((delta >> 32) as u32);
        print_hex(delta as u32);
        print_str(b" pClientThreadInfo=0x");
        print_hex((client_pcti >> 32) as u32);
        print_hex(client_pcti as u32);
        print_str(b"\n");
    }
}

unsafe fn complete_ntuser_process_connect_copyout(
    nt_handler: &mut ExecNtHandler,
    pi: usize,
    pml4: u64,
    client_buffer: u64,
    buffer: &mut [u8],
    scratch_base: u64,
) -> bool {
    let blen = buffer.len();
    let min_sharedinfo_len = (win32k_subsystem::UC_SI_DELTA + 8) as usize;
    if client_buffer == 0 || blen == 0 || blen < min_sharedinfo_len {
        let failures = USERCONNECT_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtUserProcessConnect USERCONNECT copy-out invalid target pi=");
            print_u64(pi as u64);
            print_str(b" buffer=0x");
            print_hex_u64(client_buffer);
            print_str(b" bytes=");
            print_u64(blen as u64);
            print_str(b"\n");
        }
        return false;
    }

    // gSharedInfo CLIENT-MAPPING. win32k's NtUserProcessConnect handler filled the USERCONNECT's
    // siClient with pointers into its OWN session-space USER heap (gpsi / gHandleTable / the
    // handle-entry array). Map that USER heap into the GUI client and rewrite siClient to the
    // client-relative view before user32 resumes.
    let Some(delta) = win32k_glue::map_win32k_user_heap_into_client(nt_handler, pml4, pi) else {
        let failures = USERCONNECT_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtUserProcessConnect USER heap map failed pi=");
            print_u64(pi as u64);
            print_str(b"\n");
        }
        return false;
    };
    let heap_lo = win32k_subsystem::WIN32K_HEAP_VADDR;
    let heap_hi = heap_lo + win32k_subsystem::WIN32K_HEAP_FRAMES * 0x1000;
    let handler_delta = userconnect_read_u64(buffer, win32k_subsystem::UC_SI_DELTA);
    let psi_client = userconnect_read_u64(buffer, win32k_subsystem::UC_SI_PSI);
    let ahe_client = userconnect_read_u64(buffer, win32k_subsystem::UC_SI_AHELIST);
    let psi_server = psi_client.wrapping_add(handler_delta);
    let ahe_server = ahe_client.wrapping_add(handler_delta);
    if psi_client == 0
        || ahe_client == 0
        || psi_server < heap_lo
        || psi_server >= heap_hi
        || ahe_server < heap_lo
        || ahe_server >= heap_hi
    {
        let failures = USERCONNECT_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtUserProcessConnect incomplete SHAREDINFO pi=");
            print_u64(pi as u64);
            print_str(b" psi=0x");
            print_hex_u64(psi_client);
            print_str(b" ahe=0x");
            print_hex_u64(ahe_client);
            print_str(b" handler-delta=0x");
            print_hex_u64(handler_delta);
            print_str(b"\n");
        }
        return false;
    }

    core::ptr::write_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_AHELIST) as *mut u64,
        ahe_server,
    );
    userconnect_write_u64(
        buffer,
        win32k_subsystem::UC_SI_PSI,
        psi_server.wrapping_sub(delta),
    );
    userconnect_write_u64(
        buffer,
        win32k_subsystem::UC_SI_AHELIST,
        ahe_server.wrapping_sub(delta),
    );
    userconnect_write_u64(buffer, win32k_subsystem::UC_SI_DELTA, delta);
    userconnect_write_u64(buffer, win32k_subsystem::UC_SI_PDISPINFO, 0);

    if !img_spawn::client_write_mapped(
        pi as u64,
        client_buffer,
        buffer,
        scratch_base,
    ) {
        let failures = USERCONNECT_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] NtUserProcessConnect USERCONNECT copy-out failed pi=");
            print_u64(pi as u64);
            print_str(b" buffer=0x");
            print_hex_u64(client_buffer);
            print_str(b" bytes=");
            print_u64(blen as u64);
            print_str(b"\n");
        }
        return false;
    }

    true
}

fn userconnect_read_u64(buffer: &[u8], offset: u64) -> u64 {
    let offset = offset as usize;
    u64::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ])
}

fn userconnect_write_u64(buffer: &mut [u8], offset: u64, value: u64) {
    let offset = offset as usize;
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

unsafe fn observe_winlogon_completed_dispatch(
    dispatch: win32k_glue::CompletedWin32kDispatch,
    scratch_base: u64,
) {
    if dispatch.ssn != 0x1077 || dispatch.status == 0 {
        return;
    }
    let hwnd = dispatch.status as u32 as u64;
    let class = dispatch.args[1];
    let name = dispatch.args[3];
    let sas_hwnd = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_HWND) as *const u64,
    );
    if sas_hwnd != 0 && hwnd == sas_hwnd {
        if WINLOGON_SAS_MILESTONE.swap(1, Ordering::Relaxed) == 0 {
            print_str(
                b"[wl-main] winlogon created SAS window (completed NtUserCreateWindowEx -> HWND 0x",
            );
            print_hex(hwnd as u32);
            print_str(b")\n");
        }
        return;
    }
    if WINLOGON_SAS_MILESTONE.load(Ordering::Relaxed) == 0 {
        return;
    }

    if class != nt_user_callback::WC_DIALOG_ATOM {
        return;
    }
    WINLOGON_DIALOG_WINDOWS.fetch_add(1, Ordering::Relaxed);
    if !winlogon_second_sas_route_proven()
        || WINLOGON_KEY_OPENED.load(Ordering::Relaxed)
            <= WINLOGON_KEY_OPENED_AT_INJECT.load(Ordering::Relaxed)
        || name == 0
    {
        return;
    }

    let mut raw = [0u8; 16];
    let descriptor_read =
        img_spawn::client_copyin_mapped(2, name, &mut raw, scratch_base);
    let descriptor = descriptor_read
        .then(|| nt_user_callback::LargeUnicodeStringDescriptor::parse(&raw))
        .and_then(Result::ok);
    let raw_length = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let raw_maximum_and_ansi = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let raw_buffer = u64::from_le_bytes([
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
    ]);
    let source = if descriptor.is_some()
        && csrss_frame_get_exact_record(2, raw_buffer & !0xfff)
            .and_then(nt_memory_manager::ClientFrameRecord::mapped_alias)
            .is_some()
    {
        1
    } else if descriptor.is_some() && csrss_frame_get(2, raw_buffer & !0xfff) != 0 {
        3
    } else if descriptor.is_some() && client_copyin_frame_get(2, raw_buffer & !0xfff) != 0 {
        4
    } else {
        0
    };
    let mut bytes = [0u8; nt_user_callback::MAX_DIALOG_CAPTION_CODE_UNITS * 2];
    let mut units = [0u16; nt_user_callback::MAX_DIALOG_CAPTION_CODE_UNITS];
    let mut count = 0usize;
    let mut caption_read = false;
    if let Some(descriptor) = descriptor {
        let length = descriptor.length_bytes as usize;
        caption_read = img_spawn::client_copyin_mapped(
            2,
            descriptor.buffer,
            &mut bytes[..length],
            scratch_base,
        );
        if caption_read {
            count =
                nt_user_callback::decode_utf16le_bounded(&bytes[..length], &mut units).unwrap_or(0);
        }
    }
    let style = smss_stack_read(dispatch.caller_sp + 0x28) as u32;
    let top_level = style & 0x8000_0000 != 0 && style & 0x4000_0000 == 0;
    let caption_match = caption_read && units[..count] == nt_user_callback::IDD_LOGON_CAPTION;
    let session = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_SESSION) as *const u64,
    );
    let correlated = if caption_read {
        winlogon_dialog_capture_idd_logon(session, hwnd, class, &units[..count], top_level, true)
    } else {
        false
    };
    print_str(b"[dialog-caption] hwnd=0x");
    print_hex(hwnd as u32);
    print_str(b" descriptor-read=");
    print_u64(descriptor_read as u64);
    print_str(b" parse=");
    print_u64(descriptor.is_some() as u64);
    print_str(b" len=");
    print_u64(raw_length as u64);
    print_str(b" maxansi=0x");
    print_hex(raw_maximum_and_ansi);
    print_str(b" buf=0x");
    print_hex((raw_buffer >> 32) as u32);
    print_hex(raw_buffer as u32);
    print_str(b" source=");
    print_u64(source);
    print_str(b" caption-read=");
    print_u64(caption_read as u64);
    print_str(b" units=");
    print_u64(count as u64);
    print_str(b" Logon=");
    print_u64(caption_match as u64);
    print_str(b" top-level=");
    print_u64(top_level as u64);
    print_str(b" correlated=");
    print_u64(correlated as u64);
    print_str(b"\n");
}

unsafe fn observe_completed_dialog_modal_dispatch(
    dispatch: win32k_glue::CompletedWin32kDispatch,
    badge: u64,
    tid: u64,
) {
    if winlogon_dialog_modal_expected_ssn() != dispatch.ssn {
        return;
    }
    let owner_matches = if WINLOGON_DIALOG_MODAL_COMPLETED.load(Ordering::Relaxed) != 0 {
        winlogon_dialog_modal_thread_is_owner(badge, tid)
    } else {
        winlogon_dialog_modal_thread_matches(badge, tid, dispatch.args[0])
    };
    if !owner_matches {
        return;
    }
    let (hwnd, message) = if dispatch.ssn == nt_user_callback::NTUSER_DISPATCH_MESSAGE_SSN {
        if dispatch.arg_snapshot_len as usize >= 12 {
            (
                u64::from_le_bytes(dispatch.arg_snapshot[0..8].try_into().unwrap()),
                u32::from_le_bytes(dispatch.arg_snapshot[8..12].try_into().unwrap()),
            )
        } else {
            print_str(b"[dialog-pump] ERROR completed DispatchMessage snapshot missing\n");
            (0, 0)
        }
    } else {
        (
            smss_stack_read(dispatch.args[0]),
            smss_stack_read(dispatch.args[0] + 8) as u32,
        )
    };
    let _ = winlogon_dialog_modal_observe(dispatch.ssn, dispatch.status, hwnd, message);
}

/// Capture region inside the shared win32k ARG frame (4 pages, mapped in BOTH the executive and
/// win32k). SSN 0x10FA (`NtUserProcessConnect`) uses the frame from offset 0, so captures live in the
/// upper pages. Slots are handed out ROUND-ROBIN: window creation re-enters win32k through user-mode
/// callbacks (WM_NCCREATE/WM_CREATE ...), so a nested dispatch must not clobber an outer capture.
const RC_ARG_CAPTURE_BASE: u64 = 0x1000;
const RC_ARG_CAPTURE_SLOT: u64 = 0x0240;
const RC_ARG_CAPTURE_SLOTS: u64 = 0x0010;
const _: () = assert!(
    RC_ARG_CAPTURE_BASE + RC_ARG_CAPTURE_SLOT * RC_ARG_CAPTURE_SLOTS
        <= win32k_subsystem::WIN32K_ARG_GENERAL_BYTES
);
const RC_CLASS_MENU_DESC_OFF: u64 = 0x0080;
const RC_CLASS_MENU_BUF_OFF: u64 = 0x00A0;
const GET_ICON_INFO_ICONINFO_BYTES: usize = 32;
const GET_ICON_INFO_BPP_OFF: u64 = 0x20;
const GET_ICON_INFO_STRING_BUF_OFF: u64 = 0x20;
const GET_ICON_INFO_STRING_STAGE_CAP: u64 = RC_ARG_CAPTURE_SLOT - GET_ICON_INFO_STRING_BUF_OFF;
const DEVMODEW_DMSIZE_OFF: usize = 0x44;
const DEVMODEW_DMDRIVEREXTRA_OFF: usize = 0x46;
const DEVMODEW_MIN_BYTES: usize = 0x48;
/// Covers a MAX_PATH UTF-16 wallpaper name plus its terminator within one capture slot.
const RC_ARG_BUF_CAP: u64 = RC_ARG_CAPTURE_SLOT - 0x20;
const RC_WALLPAPER_MAX_BYTES: u64 = 260 * 2;
static RC_ARG_CAPTURE_NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
struct CapturedStringArg {
    desc: u64,
    length: u64,
    maximum: u64,
    buffer: u64,
    staged_buffer: u64,
    ansi: bool,
}

/// Capture a client counted-string argument (`UNICODE_STRING` when `large` is false, `LARGE_STRING`
/// when true) into the shared win32k ARG frame — the NT "probe and capture" contract applied at the
/// executive's cross-VSpace boundary. Both layouts put `Buffer` at +8; they differ only in the width
/// of the leading `Length` field and in `LARGE_STRING`'s `MaximumLength:31 | bAnsi:1` word.
///
/// Returns the ARG-frame VA of the captured descriptor, or `sp_va` UNCHANGED when capture is
/// impossible. Even `Length == 0` atom/resource forms are staged: win32k still probes the descriptor
/// before interpreting `Buffer` as the atom. For nonzero strings, both descriptor and bytes are copied
/// unconditionally when readable. Legacy callers leave the original pointer for the provider's
/// own probe when capture fails; exact-witness callers use `try_capture_client_string_arg_for`
/// and fail the request before provider dispatch instead.
unsafe fn capture_client_string_arg(
    pi: u64,
    sp_va: u64,
    large: bool,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> u64 {
    try_capture_client_string_arg(pi, sp_va, large, false, filled_pages, nfilled, scratch_base)
        .map(|capture| capture.desc)
        .unwrap_or(sp_va)
}

unsafe fn try_capture_client_string_arg(
    pi: u64,
    sp_va: u64,
    large: bool,
    capture_empty_buffer: bool,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<CapturedStringArg> {
    try_capture_client_string_arg_impl(
        pi, None, sp_va, large, capture_empty_buffer, scratch_base,
    )
}

unsafe fn try_capture_client_string_arg_for(
    pi: u64,
    process: nt_memory_manager::ProcessIdentity,
    sp_va: u64,
    large: bool,
    capture_empty_buffer: bool,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<CapturedStringArg> {
    try_capture_client_string_arg_impl(
        pi, Some(process), sp_va, large, capture_empty_buffer, scratch_base,
    )
}

unsafe fn copy_client_string_bytes(
    pi: u64,
    process: Option<nt_memory_manager::ProcessIdentity>,
    va: u64,
    dst: &mut [u8],
    scratch_base: u64,
) -> bool {
    match process {
        Some(process) => img_spawn::client_copyin_process_mapped_for(
            pi, process, va, dst, scratch_base,
        ),
        None => img_spawn::client_copyin_mapped(
            pi, va, dst, scratch_base,
        ),
    }
}

unsafe fn client_read_u64_for(
    pi: u64,
    process: nt_memory_manager::ProcessIdentity,
    va: u64,
    scratch_base: u64,
) -> Option<u64> {
    let mut bytes = [0u8; 8];
    img_spawn::client_copyin_process_mapped_for(
        pi, process, va, &mut bytes, scratch_base,
    )
    .then_some(u64::from_le_bytes(bytes))
}

unsafe fn try_capture_client_string_arg_impl(
    pi: u64,
    process: Option<nt_memory_manager::ProcessIdentity>,
    sp_va: u64,
    large: bool,
    capture_empty_buffer: bool,
    scratch_base: u64,
) -> Option<CapturedStringArg> {
    if sp_va == 0 {
        return None;
    }
    let mut sd = [0u8; 16];
    if !copy_client_string_bytes(pi, process, sp_va, &mut sd, scratch_base) {
        return None;
    }
    let (length, maximum, ansi, buffer) = if large {
        let input = nt_kernel_exec::user_string::large_string_input(&sd, RC_ARG_BUF_CAP)?;
        (input.length, input.maximum, input.ansi, input.buffer)
    } else {
        let input = nt_kernel_exec::user_string::unicode_string_input(&sd, RC_ARG_BUF_CAP)?;
        (input.length, input.maximum, false, input.buffer)
    };
    let terminator_bytes = if ansi { 1 } else { 2 };
    let stage_buffer = length != 0 || (capture_empty_buffer && buffer != 0);
    let slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let desc = rc_arg_slot_base(slot);
    let buf = desc + 0x20;
    let captured_buffer = if stage_buffer {
        let mut chars = [0u8; RC_ARG_BUF_CAP as usize];
        if length != 0
            && !copy_client_string_bytes(
                pi,
                process,
                buffer,
                &mut chars[..length as usize],
                scratch_base,
            )
        {
            return None;
        }
        core::ptr::write_bytes(desc as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
        if length != 0 {
            core::ptr::copy_nonoverlapping(chars.as_ptr(), buf as *mut u8, length as usize);
        }
        if ansi {
            core::ptr::write_volatile((buf + length) as *mut u8, 0);
        } else {
            core::ptr::write_volatile((buf + length) as *mut u16, 0);
        }
        buf
    } else {
        core::ptr::write_bytes(desc as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
        buffer
    };
    let staged_maximum = if stage_buffer || length != 0 {
        length + terminator_bytes
    } else {
        maximum
    };
    if large {
        // LARGE_STRING: Length(u32), MaximumLength:31|bAnsi:1 (u32), Buffer(u64). Preserve bAnsi.
        let ansi_bit = if ansi { 0x8000_0000 } else { 0 };
        core::ptr::write_volatile(desc as *mut u32, length as u32);
        core::ptr::write_volatile((desc + 4) as *mut u32, staged_maximum as u32 | ansi_bit);
    } else {
        core::ptr::write_volatile(desc as *mut u16, length as u16);
        core::ptr::write_volatile((desc + 2) as *mut u16, staged_maximum as u16);
        core::ptr::write_volatile((desc + 4) as *mut u32, 0); // explicit x64 padding
    }
    core::ptr::write_volatile((desc + 8) as *mut u64, captured_buffer);
    Some(CapturedStringArg {
        desc,
        length,
        maximum,
        buffer,
        staged_buffer: captured_buffer,
        ansi,
    })
}

unsafe fn capture_client_devmodew_arg(
    pi: u64,
    devmode: u64,
    scratch_base: u64,
) -> u64 {
    if devmode == 0 {
        return 0;
    }
    let mut header = [0u8; DEVMODEW_MIN_BYTES];
    if !img_spawn::client_copyin_mapped(
        pi,
        devmode,
        &mut header,
        scratch_base,
    ) {
        return devmode;
    }
    let dm_size = u16::from_le_bytes(
        header[DEVMODEW_DMSIZE_OFF..DEVMODEW_DMSIZE_OFF + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let dm_driver_extra = u16::from_le_bytes(
        header[DEVMODEW_DMDRIVEREXTRA_OFF..DEVMODEW_DMDRIVEREXTRA_OFF + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let Some(size) = dm_size.checked_add(dm_driver_extra) else {
        return devmode;
    };
    if !(DEVMODEW_MIN_BYTES..=RC_ARG_CAPTURE_SLOT as usize).contains(&size) {
        return devmode;
    }

    let slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let staged = rc_arg_slot_base(slot);
    core::ptr::write_bytes(staged as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
    let mut bytes = [0u8; RC_ARG_CAPTURE_SLOT as usize];
    if !img_spawn::client_copyin_mapped(
        pi,
        devmode,
        &mut bytes[..size],
        scratch_base,
    ) {
        return devmode;
    }
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), staged as *mut u8, size);
    staged
}

unsafe fn capture_required_client_unicode_string_arg(
    pi: u64,
    process: nt_memory_manager::ProcessIdentity,
    descriptor: u64,
    scratch_base: u64,
) -> Option<u64> {
    if descriptor == 0 {
        return None;
    }
    let mut sd = [0u8; 16];
    if !copy_client_string_bytes(
        pi, Some(process), descriptor, &mut sd, scratch_base,
    ) {
        return None;
    }
    let input = nt_kernel_exec::user_string::required_unicode_string(&sd, RC_ARG_BUF_CAP as usize)?;
    let length = input.length;
    let mut chars = [0u8; RC_ARG_BUF_CAP as usize];
    if !copy_client_string_bytes(
        pi, Some(process), input.buffer, &mut chars[..input.probe_length], scratch_base,
    ) {
        return None;
    }

    let slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let desc = rc_arg_slot_base(slot);
    let buf = desc + 0x20;
    core::ptr::write_bytes(desc as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
    if length != 0 {
        core::ptr::copy_nonoverlapping(chars.as_ptr(), buf as *mut u8, length);
    }
    core::ptr::write_volatile((buf + length as u64) as *mut u16, 0);
    core::ptr::write_volatile(desc as *mut u16, length as u16);
    core::ptr::write_volatile((desc + 2) as *mut u16, (length + 2) as u16);
    core::ptr::write_volatile((desc + 4) as *mut u32, 0);
    core::ptr::write_volatile((desc + 8) as *mut u64, buf);
    Some(desc)
}

unsafe fn stage_unicode_string_descriptor_for_win32k(
    pi: u64,
    process: Option<nt_memory_manager::ProcessIdentity>,
    descriptor: u64,
    desc_out: u64,
    buf_out: u64,
    buf_cap: u64,
    scratch_base: u64,
) -> bool {
    core::ptr::write_bytes(desc_out as *mut u8, 0, 16);
    if descriptor == 0 {
        return true;
    }
    let mut sd = [0u8; 16];
    if !copy_client_string_bytes(
        pi, process, descriptor, &mut sd, scratch_base,
    ) {
        return false;
    }
    let length = u16::from_le_bytes([sd[0], sd[1]]) as u64;
    let maximum = u16::from_le_bytes([sd[2], sd[3]]) as u64;
    let buffer = u64::from_le_bytes(sd[8..16].try_into().unwrap());
    if length & 1 != 0 {
        return false;
    }
    if length != 0 && (buffer == 0 || length > maximum || length + 2 > buf_cap) {
        return false;
    }
    core::ptr::copy_nonoverlapping(sd.as_ptr(), desc_out as *mut u8, sd.len());
    if length != 0 {
        let out = core::slice::from_raw_parts_mut(buf_out as *mut u8, length as usize);
        if !copy_client_string_bytes(
            pi, process, buffer, out, scratch_base,
        ) {
            return false;
        }
        core::ptr::write_volatile((buf_out + length) as *mut u16, 0);
        core::ptr::write_volatile((desc_out + 2) as *mut u16, (length + 2) as u16);
        core::ptr::write_volatile((desc_out + 8) as *mut u64, buf_out);
    }
    true
}

#[derive(Clone, Copy)]
struct CapturedGetClassInfo {
    wnd_client: u64,
    menu_client: u64,
    class_desc: u64,
    wnd_out: u64,
    menu_out: u64,
}

#[derive(Clone, Copy)]
struct CapturedGetClassName {
    desc_client: u64,
    buffer_client: u64,
    desc_out: u64,
    buffer_out: u64,
    maximum: u16,
}

#[derive(Clone, Copy)]
struct CapturedGetAtomName {
    process: nt_memory_manager::ProcessIdentity,
    buffer_client: u64,
    desc_out: u64,
    buffer_out: u64,
    maximum: u16,
}

#[derive(Clone, Copy)]
struct CapturedUnicodeStringOut {
    desc_client: u64,
    buffer_client: u64,
    maximum_client: u16,
    desc_out: u64,
    buffer_out: u64,
    buffer_cap: u16,
    original_desc: [u8; 16],
}

#[derive(Clone, Copy)]
struct CapturedGetIconInfo {
    iconinfo_client: u64,
    iconinfo_out: u64,
    bpp_client: u64,
    bpp_out: u64,
    module: Option<CapturedUnicodeStringOut>,
    resource: Option<CapturedUnicodeStringOut>,
}

impl CapturedGetIconInfo {
    const fn empty() -> Self {
        Self {
            iconinfo_client: 0,
            iconinfo_out: 0,
            bpp_client: 0,
            bpp_out: 0,
            module: None,
            resource: None,
        }
    }
}

fn rc_arg_slot_base(slot: u64) -> u64 {
    win32k_subsystem::WIN32K_ARG_VADDR + RC_ARG_CAPTURE_BASE + slot * RC_ARG_CAPTURE_SLOT
}

fn is_int_resource_value(value: u64) -> bool {
    value != 0 && value <= 0xffff
}

unsafe fn capture_get_class_info_graph(
    pi: u64,
    class_name: u64,
    wnd_class: u64,
    menu_name_ptr: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<CapturedGetClassInfo> {
    use nt_kernel_exec::user_class::WNDCLASSEXW_SIZE;

    if class_name == 0 || wnd_class == 0 {
        return None;
    }
    let class_slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let out_slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let class_base = rc_arg_slot_base(class_slot);
    let out_base = rc_arg_slot_base(out_slot);
    core::ptr::write_bytes(class_base as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
    core::ptr::write_bytes(out_base as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
    if !stage_unicode_string_descriptor_for_win32k(
        pi,
        None,
        class_name,
        class_base,
        class_base + 0x20,
        RC_ARG_CAPTURE_SLOT - 0x20,
        scratch_base,
    ) {
        return None;
    }

    let mut wnd = [0u8; WNDCLASSEXW_SIZE];
    // ReactOS preserves caller-owned fields such as cbSize and lpszClassName while populating the
    // remaining WNDCLASSEXW result. The isolation boundary must therefore capture the complete seed
    // and fail closed if any byte is inaccessible.
    if !img_spawn::client_copyin_mapped(
        pi,
        wnd_class,
        &mut wnd,
        scratch_base,
    ) {
        return None;
    }
    let wnd_out = out_base;
    let menu_out = out_base + WNDCLASSEXW_SIZE as u64;
    core::ptr::copy_nonoverlapping(wnd.as_ptr(), wnd_out as *mut u8, wnd.len());
    core::ptr::write_unaligned(menu_out as *mut u64, 0);
    Some(CapturedGetClassInfo {
        wnd_client: wnd_class,
        menu_client: menu_name_ptr,
        class_desc: class_base,
        wnd_out,
        menu_out,
    })
}

unsafe fn copy_back_get_class_info(
    pi: usize,
    capture: CapturedGetClassInfo,
    scratch_base: u64,
) -> bool {
    use nt_kernel_exec::user_class::WNDCLASSEXW_SIZE;

    let menu_value = core::ptr::read_unaligned(capture.menu_out as *const u64);
    let menu_ok = capture.menu_client == 0
        || img_spawn::client_write_mapped(
            pi as u64,
            capture.menu_client,
            &menu_value.to_le_bytes(),
            scratch_base,
        );
    let wnd_bytes = core::slice::from_raw_parts(capture.wnd_out as *const u8, WNDCLASSEXW_SIZE);
    menu_ok
        && img_spawn::client_write_mapped(
            pi as u64,
            capture.wnd_client,
            wnd_bytes,
            scratch_base,
        )
}

unsafe fn capture_get_class_name_out(
    pi: u64,
    class_name: u64,
    scratch_base: u64,
) -> Option<CapturedGetClassName> {
    if class_name == 0 {
        return None;
    }
    let mut raw = [0u8; 16];
    if !img_spawn::client_copyin_mapped(
        pi,
        class_name,
        &mut raw,
        scratch_base,
    ) {
        return None;
    }
    let length = u16::from_le_bytes([raw[0], raw[1]]);
    let maximum = u16::from_le_bytes([raw[2], raw[3]]);
    let buffer = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    if length & 1 != 0 || maximum < length || maximum == 0 || buffer == 0 {
        return None;
    }
    let staged_max = (maximum as u64).min(RC_ARG_BUF_CAP) as u16;
    if staged_max < 2 {
        return None;
    }

    let slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let desc_out = rc_arg_slot_base(slot);
    let buffer_out = desc_out + 0x20;
    core::ptr::write_bytes(desc_out as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
    raw[2..4].copy_from_slice(&staged_max.to_le_bytes());
    raw[8..16].copy_from_slice(&buffer_out.to_le_bytes());
    core::ptr::copy_nonoverlapping(raw.as_ptr(), desc_out as *mut u8, raw.len());
    Some(CapturedGetClassName {
        desc_client: class_name,
        buffer_client: buffer,
        desc_out,
        buffer_out,
        maximum,
    })
}

unsafe fn copy_back_get_class_name(
    pi: u64,
    capture: CapturedGetClassName,
    chars_returned: u64,
    scratch_base: u64,
) -> bool {
    let byte_len = chars_returned.saturating_mul(2).min(RC_ARG_BUF_CAP);
    let copy_len = (byte_len + 2)
        .min(capture.maximum as u64)
        .min(RC_ARG_BUF_CAP) as usize;
    let text = core::slice::from_raw_parts(capture.buffer_out as *const u8, copy_len);
    let text_ok = img_spawn::client_write_mapped(
        pi,
        capture.buffer_client,
        text,
        scratch_base,
    );

    let mut desc = [0u8; 16];
    core::ptr::copy_nonoverlapping(capture.desc_out as *const u8, desc.as_mut_ptr(), desc.len());
    desc[2..4].copy_from_slice(&capture.maximum.to_le_bytes());
    desc[8..16].copy_from_slice(&capture.buffer_client.to_le_bytes());
    let desc_ok = img_spawn::client_write_mapped(
        pi,
        capture.desc_client,
        &desc,
        scratch_base,
    );
    text_ok && desc_ok
}

unsafe fn capture_get_atom_name_out(
    pi: u64,
    process: nt_memory_manager::ProcessIdentity,
    atom_name: u64,
    scratch_base: u64,
) -> Option<CapturedGetAtomName> {
    if atom_name == 0 {
        return None;
    }
    let mut raw = [0u8; 16];
    if !copy_client_string_bytes(
        pi, Some(process), atom_name, &mut raw, scratch_base,
    ) {
        return None;
    }
    let maximum = u16::from_le_bytes([raw[2], raw[3]]);
    let buffer = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    if maximum < 2 || buffer == 0 {
        return None;
    }

    let staged_max = (maximum as u64).min(RC_ARG_BUF_CAP) as u16;
    let slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let desc_out = rc_arg_slot_base(slot);
    let buffer_out = desc_out + 0x20;
    core::ptr::write_bytes(desc_out as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
    raw[2..4].copy_from_slice(&staged_max.to_le_bytes());
    raw[8..16].copy_from_slice(&buffer_out.to_le_bytes());
    core::ptr::copy_nonoverlapping(raw.as_ptr(), desc_out as *mut u8, raw.len());
    Some(CapturedGetAtomName {
        process,
        buffer_client: buffer,
        desc_out,
        buffer_out,
        maximum,
    })
}

unsafe fn copy_back_get_atom_name(
    handler: &mut ExecNtHandler,
    pi: u64,
    capture: CapturedGetAtomName,
    chars_returned: u64,
    scratch_base: u64,
) -> bool {
    let byte_len = chars_returned.saturating_mul(2).min(RC_ARG_BUF_CAP);
    let copy_len = (byte_len + 2)
        .min(capture.maximum as u64)
        .min(RC_ARG_BUF_CAP) as usize;
    let text = core::slice::from_raw_parts(capture.buffer_out as *const u8, copy_len);
    img_spawn::client_write_process_mapped_for(
        handler,
        pi,
        capture.process,
        capture.buffer_client,
        text,
        scratch_base,
    )
}

unsafe fn stage_session_atom_name(
    nt_handler: &mut ExecNtHandler,
    atom: u16,
    capture: CapturedGetAtomName,
) -> Option<u64> {
    let mut units = [0u16; nt_kernel_exec::user_class::CLASS_ATOM_NAME_CAP];
    let len = nt_handler.lookup_class_atom_name(atom, &mut units)?;
    let byte_len = len.checked_mul(2)?;
    let total_len = byte_len.checked_add(2)?;
    let max = (capture.maximum as usize).min(RC_ARG_BUF_CAP as usize);
    if total_len > max {
        nt_handler.record_class_atom_name_serve(false);
        return None;
    }
    for (index, unit) in units[..len].iter().enumerate() {
        core::ptr::write_unaligned((capture.buffer_out + index as u64 * 2) as *mut u16, *unit);
    }
    core::ptr::write_unaligned((capture.buffer_out + byte_len as u64) as *mut u16, 0);
    core::ptr::write_unaligned(capture.desc_out as *mut u16, byte_len as u16);
    nt_handler.record_class_atom_name_serve(true);
    Some(len as u64)
}

unsafe fn stage_unicode_string_output_for_win32k(
    pi: u64,
    descriptor: u64,
    scratch_base: u64,
) -> Option<CapturedUnicodeStringOut> {
    if descriptor == 0 {
        return None;
    }

    let mut raw = [0u8; 16];
    if !img_spawn::client_copyin_mapped(
        pi,
        descriptor,
        &mut raw,
        scratch_base,
    ) {
        return None;
    }

    let maximum_client = u16::from_le_bytes([raw[2], raw[3]]);
    let buffer_client = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    let buffer_cap = (maximum_client as u64).min(GET_ICON_INFO_STRING_STAGE_CAP) as u16;
    if maximum_client != 0 && (buffer_client == 0 || buffer_cap < 2) {
        return None;
    }

    let slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let desc_out = rc_arg_slot_base(slot);
    let buffer_out = desc_out + GET_ICON_INFO_STRING_BUF_OFF;
    core::ptr::write_bytes(desc_out as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
    core::ptr::write_unaligned(desc_out as *mut u16, 0);
    core::ptr::write_unaligned((desc_out + 2) as *mut u16, buffer_cap);
    core::ptr::write_unaligned((desc_out + 4) as *mut u32, 0);
    core::ptr::write_unaligned(
        (desc_out + 8) as *mut u64,
        if buffer_cap != 0 { buffer_out } else { 0 },
    );

    Some(CapturedUnicodeStringOut {
        desc_client: descriptor,
        buffer_client,
        maximum_client,
        desc_out,
        buffer_out,
        buffer_cap,
        original_desc: raw,
    })
}

unsafe fn copy_back_unicode_string_output(
    pi: u64,
    capture: CapturedUnicodeStringOut,
    scratch_base: u64,
) -> bool {
    let mut staged = [0u8; 16];
    core::ptr::copy_nonoverlapping(
        capture.desc_out as *const u8,
        staged.as_mut_ptr(),
        staged.len(),
    );
    let length = u16::from_le_bytes([staged[0], staged[1]]);
    let maximum = u16::from_le_bytes([staged[2], staged[3]]);
    let staged_buffer = u64::from_le_bytes(staged[8..16].try_into().unwrap());

    let mut out_desc = capture.original_desc;
    out_desc[0..2].copy_from_slice(&length.to_le_bytes());
    let client_maximum =
        if staged_buffer == capture.buffer_out && length != 0 && maximum == capture.buffer_cap {
            capture.maximum_client
        } else {
            maximum
        };
    out_desc[2..4].copy_from_slice(&client_maximum.to_le_bytes());

    let (client_buffer, buffer_ok) = if staged_buffer == capture.buffer_out {
        if length == 0 {
            (capture.buffer_client, true)
        } else if capture.buffer_client == 0
            || length > capture.maximum_client
            || length > capture.buffer_cap
        {
            (capture.buffer_client, false)
        } else {
            (
                capture.buffer_client,
                img_spawn::client_copyout_mapped(
                    pi,
                    capture.buffer_client,
                    core::slice::from_raw_parts(capture.buffer_out as *const u8, length as usize),
                    scratch_base,
                ),
            )
        }
    } else if is_int_resource_value(staged_buffer) || staged_buffer == 0 {
        (staged_buffer, true)
    } else {
        (capture.buffer_client, false)
    };
    out_desc[8..16].copy_from_slice(&client_buffer.to_le_bytes());

    buffer_ok
        && img_spawn::client_write_mapped(
            pi,
            capture.desc_client,
            &out_desc,
            scratch_base,
        )
}

unsafe fn copy_back_get_icon_info(
    pi: u64,
    capture: CapturedGetIconInfo,
    scratch_base: u64,
) -> bool {
    let iconinfo_ok = capture.iconinfo_client == 0
        || img_spawn::client_copyout_mapped(
            pi,
            capture.iconinfo_client,
            core::slice::from_raw_parts(
                capture.iconinfo_out as *const u8,
                GET_ICON_INFO_ICONINFO_BYTES,
            ),
            scratch_base,
        );
    let bpp_ok = capture.bpp_client == 0
        || img_spawn::client_copyout_mapped(
            pi,
            capture.bpp_client,
            core::slice::from_raw_parts(capture.bpp_out as *const u8, 4),
            scratch_base,
        );
    let module_ok = capture.module.is_none_or(|module| {
        copy_back_unicode_string_output(pi, module, scratch_base)
    });
    let resource_ok = capture.resource.is_none_or(|resource| {
        copy_back_unicode_string_output(pi, resource, scratch_base)
    });
    iconinfo_ok && bpp_ok && module_ok && resource_ok
}

unsafe fn capture_register_class_graph(
    pi: u64,
    process: nt_memory_manager::ProcessIdentity,
    wnd_class: u64,
    class_menu: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<CapturedRegisterClassGraph> {
    use nt_kernel_exec::user_class::WNDCLASSEXW_SIZE;

    let mut wnd = [0u8; WNDCLASSEXW_SIZE];
    if wnd_class == 0
        || !copy_client_string_bytes(
            pi, Some(process), wnd_class, &mut wnd, scratch_base,
        )
    {
        return None;
    }
    let mut menu = [0u8; 24];
    if class_menu == 0
        || !copy_client_string_bytes(
            pi, Some(process), class_menu, &mut menu, scratch_base,
        )
    {
        return None;
    }

    let slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let base =
        win32k_subsystem::WIN32K_ARG_VADDR + RC_ARG_CAPTURE_BASE + slot * RC_ARG_CAPTURE_SLOT;
    let wnd_out = base;
    let menu_out = base + WNDCLASSEXW_SIZE as u64 + 0x10;
    let menu_desc_out = base + RC_CLASS_MENU_DESC_OFF;
    let menu_buf_out = base + RC_CLASS_MENU_BUF_OFF;
    let menu_buf_cap = RC_ARG_CAPTURE_SLOT - RC_CLASS_MENU_BUF_OFF;
    core::ptr::write_bytes(base as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
    core::ptr::copy_nonoverlapping(wnd.as_ptr(), wnd_out as *mut u8, wnd.len());

    let menu_descriptor = u64::from_le_bytes(menu[16..24].try_into().unwrap());
    if menu_descriptor == 0 {
        return None;
    }
    if !stage_unicode_string_descriptor_for_win32k(
        pi,
        Some(process),
        menu_descriptor,
        menu_desc_out,
        menu_buf_out,
        menu_buf_cap,
        scratch_base,
    ) {
        return None;
    }
    menu[16..24].copy_from_slice(&menu_desc_out.to_le_bytes());
    core::ptr::copy_nonoverlapping(menu.as_ptr(), menu_out as *mut u8, menu.len());
    Some(CapturedRegisterClassGraph {
        wnd: wnd_out,
        menu: menu_out,
        menu_desc: menu_desc_out,
        menu_buffer: menu_buf_out,
    })
}

#[derive(Clone, Copy)]
struct CapturedRegisterClassGraph {
    wnd: u64,
    menu: u64,
    menu_desc: u64,
    menu_buffer: u64,
}

enum CapturedCursorString {
    Atom(u16),
    Text(usize),
}

#[derive(Clone, Copy)]
struct CapturedClassAtomName {
    len: usize,
    units: [u16; nt_kernel_exec::user_class::CLASS_ATOM_NAME_CAP],
}

impl CapturedClassAtomName {
    fn as_slice(&self) -> &[u16] {
        &self.units[..self.len]
    }
}

/// Capture one `UNICODE_STRING` used by `NtUserFindExistingCursorIcon`. A zero-length resource is
/// the MAKEINTRESOURCE form: its Buffer field is the integer identity and is never dereferenced.
unsafe fn capture_cursor_counted_string(
    pi: u64,
    descriptor: u64,
    allow_atom: bool,
    units: &mut [u16; nt_kernel_exec::user_cursor::CURSOR_TEXT_CAP],
    scratch_base: u64,
) -> Option<CapturedCursorString> {
    use nt_kernel_exec::user_cursor::{
        decode_utf16, parse_string_descriptor, CursorStringDescriptor,
    };

    let mut raw = [0u8; 16];
    if descriptor == 0
        || !img_spawn::client_copyin_mapped(
            pi, descriptor, &mut raw, scratch_base,
        )
    {
        return None;
    }
    let (length, buffer) = match parse_string_descriptor(&raw, allow_atom)? {
        CursorStringDescriptor::Atom(atom) => return Some(CapturedCursorString::Atom(atom)),
        CursorStringDescriptor::Text { byte_len, buffer } => (byte_len, buffer),
    };
    let mut bytes = [0u8; nt_kernel_exec::user_cursor::CURSOR_TEXT_CAP * 2];
    if !img_spawn::client_copyin_mapped(
        pi, buffer, &mut bytes[..length], scratch_base,
    ) {
        return None;
    }
    decode_utf16(&bytes[..length], units).map(CapturedCursorString::Text)
}

unsafe fn staged_class_name_identity(
    descriptor: u64,
    staged_buffer: u64,
    buffer_cap: u64,
    allow_none: bool,
) -> Option<(
    nt_kernel_exec::user_class::ClassNameIdentity,
    Option<CapturedClassAtomName>,
)> {
    use nt_kernel_exec::user_class::{ClassNameIdentity, CLASS_ATOM_NAME_CAP};
    use nt_kernel_exec::user_cursor::{
        decode_utf16, parse_string_descriptor, CursorStringDescriptor, CURSOR_TEXT_CAP,
    };

    let mut raw = [0u8; 16];
    core::ptr::copy_nonoverlapping(descriptor as *const u8, raw.as_mut_ptr(), raw.len());
    let length = u16::from_le_bytes([raw[0], raw[1]]);
    let buffer = u64::from_le_bytes(raw[8..16].try_into().ok()?);
    if allow_none && length == 0 && buffer == 0 {
        return Some((ClassNameIdentity::none(), None));
    }
    match parse_string_descriptor(&raw, true)? {
        CursorStringDescriptor::Atom(atom) => Some((ClassNameIdentity::atom(atom), None)),
        CursorStringDescriptor::Text { byte_len, buffer } => {
            if buffer != staged_buffer || (byte_len as u64).checked_add(2)? > buffer_cap {
                return None;
            }
            let bytes = core::slice::from_raw_parts(buffer as *const u8, byte_len);
            let mut captured = [0u16; CURSOR_TEXT_CAP];
            let len = decode_utf16(bytes, &mut captured)?;
            let identity = ClassNameIdentity::name(&captured[..len])?;
            let atom_name = if len <= CLASS_ATOM_NAME_CAP {
                let mut units = [0u16; CLASS_ATOM_NAME_CAP];
                units[..len].copy_from_slice(&captured[..len]);
                Some(CapturedClassAtomName { len, units })
            } else {
                None
            };
            Some((identity, atom_name))
        }
    }
}

unsafe fn capture_cursor_identity_key(
    pi: u64,
    module_descriptor: u64,
    resource_descriptor: u64,
    icon_kind: u32,
    scratch_base: u64,
) -> Option<nt_kernel_exec::user_cursor::CursorLookupKey> {
    use nt_kernel_exec::user_cursor::{CursorLookupKey, CursorResource, CURSOR_TEXT_CAP};

    let mut module = [0u16; CURSOR_TEXT_CAP];
    let module_len = match capture_cursor_counted_string(
        pi,
        module_descriptor,
        false,
        &mut module,
        scratch_base,
    )? {
        CapturedCursorString::Text(len) => len,
        CapturedCursorString::Atom(_) => return None,
    };
    let mut resource_name = [0u16; CURSOR_TEXT_CAP];
    let resource = match capture_cursor_counted_string(
        pi,
        resource_descriptor,
        true,
        &mut resource_name,
        scratch_base,
    )? {
        CapturedCursorString::Atom(atom) => CursorResource::atom(atom),
        CapturedCursorString::Text(len) => CursorResource::name(&resource_name[..len])?,
    };
    CursorLookupKey::new(&module[..module_len], resource, icon_kind)
}

unsafe fn capture_find_existing_cursor_key(
    pi: u64,
    module_descriptor: u64,
    resource_descriptor: u64,
    parameter: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<nt_kernel_exec::user_cursor::CursorLookupKey> {
    if parameter == 0 {
        return None;
    }
    let mut params = [0u8; 12];
    if !img_spawn::client_copyin_mapped(
        pi,
        parameter,
        &mut params,
        scratch_base,
    ) {
        return None;
    }
    let icon_kind = (u32::from_le_bytes(params[0..4].try_into().ok()?) != 0) as u32;
    capture_cursor_identity_key(
        pi,
        module_descriptor,
        resource_descriptor,
        icon_kind,
        scratch_base,
    )
}

unsafe fn stage_cursor_lookup_args(
    pi: u64,
    module_descriptor: u64,
    resource_descriptor: u64,
    parameter: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<(u64, u64, u64)> {
    let module = try_capture_client_string_arg(
        pi,
        module_descriptor,
        false,
        false,
        filled_pages,
        nfilled,
        scratch_base,
    )?;
    let resource = try_capture_client_string_arg(
        pi,
        resource_descriptor,
        false,
        false,
        filled_pages,
        nfilled,
        scratch_base,
    )?;
    if parameter == 0 {
        return None;
    }
    let mut params = [0u8; 12];
    if !img_spawn::client_copyin_mapped(
        pi,
        parameter,
        &mut params,
        scratch_base,
    ) {
        return None;
    }

    let slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let param_out = rc_arg_slot_base(slot);
    core::ptr::write_bytes(param_out as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
    core::ptr::copy_nonoverlapping(params.as_ptr(), param_out as *mut u8, params.len());
    Some((module.desc, resource.desc, param_out))
}

/// Capture the identity assigned by a real `NtUserSetCursorIconData`. `CURSORDATA.rt` is RT_CURSOR
/// (1) or RT_ICON (3); normalize it to the canonical BOOL stored by a later lookup key.
unsafe fn capture_cursor_set_data_key(
    pi: u64,
    module_descriptor: u64,
    resource_descriptor: u64,
    cursor_data: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<nt_kernel_exec::user_cursor::CursorLookupKey> {
    let mut data_prefix = [0u8; 18];
    if cursor_data == 0
        || !img_spawn::client_copyin_mapped(
            pi,
            cursor_data,
            &mut data_prefix,
            scratch_base,
        )
    {
        return None;
    }
    let icon_kind = match u16::from_le_bytes([data_prefix[16], data_prefix[17]]) {
        1 => 0,
        3 => 1,
        _ => return None,
    };
    capture_cursor_identity_key(
        pi,
        module_descriptor,
        resource_descriptor,
        icon_kind,
        scratch_base,
    )
}

unsafe fn stage_optional_cursor_string_arg(
    pi: u64,
    descriptor: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<u64> {
    if descriptor == 0 {
        return Some(0);
    }
    try_capture_client_string_arg(
        pi,
        descriptor,
        false,
        false,
        filled_pages,
        nfilled,
        scratch_base,
    )
    .map(|capture| capture.desc)
}

/// Capture `NtUserSetCursorIconData`'s pointer graph before isolated win32k probes it. ReactOS first
/// copies the top-level `CURSORDATA`, then, for animated cursors, copies `aspcur`, `aicur`, and
/// `ajifRate` into kernel memory and rewrites the three pointers. The isolated provider needs the
/// same ownership boundary because the original pointers are process-private client VAs.
unsafe fn stage_cursor_icon_data_args(
    pi: u64,
    process_generation: u64,
    hcursor: u64,
    module_descriptor: u64,
    resource_descriptor: u64,
    cursor_data: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<(u64, u64, u64, win32k_bulk_mapping::BulkStage)> {
    let staged_module = stage_optional_cursor_string_arg(
        pi,
        module_descriptor,
        filled_pages,
        nfilled,
        scratch_base,
    )?;
    let staged_resource = stage_optional_cursor_string_arg(
        pi,
        resource_descriptor,
        filled_pages,
        nfilled,
        scratch_base,
    )?;

    let mut data = [0u8; CURSORDATA_BYTES];
    if cursor_data == 0
        || !img_spawn::client_copyin_mapped(
            pi,
            cursor_data,
            &mut data,
            scratch_base,
        )
    {
        return None;
    }

    let flags = u32::from_le_bytes(
        data[CURSORDATA_FLAGS_OFF..CURSORDATA_FLAGS_OFF + 4]
            .try_into()
            .unwrap(),
    );
    let rt = u16::from_le_bytes(data[0x10..0x12].try_into().unwrap());
    let cpcur = u32::from_le_bytes(
        data[CURSORDATA_CPCUR_OFF..CURSORDATA_CPCUR_OFF + 4]
            .try_into()
            .unwrap(),
    );
    let cicur = u32::from_le_bytes(
        data[CURSORDATA_CICUR_OFF..CURSORDATA_CICUR_OFF + 4]
            .try_into()
            .unwrap(),
    );
    let trace = SET_CURSOR_ICON_DATA_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
    if trace < 96 {
        print_str(b"[w32marshal] NtUserSetCursorIconData pi=");
        print_u64(pi);
        print_str(b" hcursor=0x");
        print_hex_u64(hcursor);
        print_str(b" rt=");
        print_u64(rt as u64);
        print_str(b" flags=0x");
        print_hex_u64(flags as u64);
        print_str(b" cpcur=");
        print_u64(cpcur as u64);
        print_str(b" cicur=");
        print_u64(cicur as u64);
    }

    if flags & CURSORF_ACON == 0 {
        let layout = nt_hosted_runtime::Win32kBulkLayout::flat(CURSORDATA_BYTES as u64)?;
        let stage = win32k_bulk_mapping::reserve(pi as u32, process_generation, layout)?;
        let base = stage.base();
        core::ptr::copy_nonoverlapping(data.as_ptr(), base as *mut u8, data.len());
        core::ptr::write_unaligned((base + CURSORDATA_ASPCUR_OFF as u64) as *mut u64, 0);
        core::ptr::write_unaligned((base + CURSORDATA_AICUR_OFF as u64) as *mut u64, 0);
        core::ptr::write_unaligned((base + CURSORDATA_AJIFRATE_OFF as u64) as *mut u64, 0);
        if trace < 96 {
            print_str(b" staged=0x");
            print_hex_u64(base);
            print_str(b" standard\n");
        }
        return Some((staged_module, staged_resource, base, stage));
    }

    if cpcur == 0 || cicur == 0 || cpcur > CURSORDATA_ACON_LIMIT || cicur > CURSORDATA_ACON_LIMIT {
        if trace < 96 {
            print_str(b" range-fail\n");
        }
        return None;
    }
    let aspcur_client = u64::from_le_bytes(
        data[CURSORDATA_ASPCUR_OFF..CURSORDATA_ASPCUR_OFF + 8]
            .try_into()
            .unwrap(),
    );
    let aicur_client = u64::from_le_bytes(
        data[CURSORDATA_AICUR_OFF..CURSORDATA_AICUR_OFF + 8]
            .try_into()
            .unwrap(),
    );
    let ajif_rate_client = u64::from_le_bytes(
        data[CURSORDATA_AJIFRATE_OFF..CURSORDATA_AJIFRATE_OFF + 8]
            .try_into()
            .unwrap(),
    );
    if aspcur_client == 0 || aicur_client == 0 || ajif_rate_client == 0 {
        if trace < 96 {
            print_str(b" null-acon-pointers aspcur=0x");
            print_hex_u64(aspcur_client);
            print_str(b" aicur=0x");
            print_hex_u64(aicur_client);
            print_str(b" ajif=0x");
            print_hex_u64(ajif_rate_client);
            print_str(b"\n");
        }
        return None;
    }

    let mut offset = align_up_u64(CURSORDATA_BYTES as u64, 8)?;
    let aspcur_bytes = (cpcur as u64).checked_mul(CURSORDATA_BYTES as u64)?;
    let aicur_bytes = (cicur as u64).checked_mul(4)?;
    let ajif_rate_bytes = (cicur as u64).checked_mul(4)?;

    let aspcur_offset = offset;
    offset = align_up_u64(offset.checked_add(aspcur_bytes)?, 8)?;
    let aicur_offset = offset;
    offset = align_up_u64(offset.checked_add(aicur_bytes)?, 4)?;
    let ajif_rate_offset = offset;
    offset = align_up_u64(offset.checked_add(ajif_rate_bytes)?, 4)?;
    let Some(layout) = nt_hosted_runtime::Win32kBulkLayout::flat(offset) else {
        if trace < 96 {
            print_str(b" layout-fail bytes=");
            print_u64(offset);
            print_str(b"\n");
        }
        return None;
    };
    let Some(stage) = win32k_bulk_mapping::reserve(pi as u32, process_generation, layout) else {
        if trace < 96 {
            print_str(b" stage-fail bytes=");
            print_u64(offset);
            print_str(b"\n");
        }
        return None;
    };
    let base = stage.base();
    let staged_aspcur = base + aspcur_offset;
    let staged_aicur = base + aicur_offset;
    let staged_ajif_rate = base + ajif_rate_offset;
    core::ptr::copy_nonoverlapping(data.as_ptr(), base as *mut u8, data.len());

    if !img_spawn::client_copyin_mapped(
        pi,
        aspcur_client,
        core::slice::from_raw_parts_mut(staged_aspcur as *mut u8, aspcur_bytes as usize),
        scratch_base,
    ) || !img_spawn::client_copyin_mapped(
        pi,
        aicur_client,
        core::slice::from_raw_parts_mut(staged_aicur as *mut u8, aicur_bytes as usize),
        scratch_base,
    ) || !img_spawn::client_copyin_mapped(
        pi,
        ajif_rate_client,
        core::slice::from_raw_parts_mut(staged_ajif_rate as *mut u8, ajif_rate_bytes as usize),
        scratch_base,
    ) {
        if trace < 96 {
            print_str(b" copy-fail aspcur=0x");
            print_hex_u64(aspcur_client);
            print_str(b" aicur=0x");
            print_hex_u64(aicur_client);
            print_str(b" ajif=0x");
            print_hex_u64(ajif_rate_client);
            print_str(b"\n");
        }
        if !win32k_bulk_mapping::settle(stage, false, false) {
            print_str(b"[win32k-bulk] cursor staging cancellation failed\n");
            park();
        }
        return None;
    }

    core::ptr::write_unaligned(
        (base + CURSORDATA_ASPCUR_OFF as u64) as *mut u64,
        staged_aspcur,
    );
    core::ptr::write_unaligned(
        (base + CURSORDATA_AICUR_OFF as u64) as *mut u64,
        staged_aicur,
    );
    core::ptr::write_unaligned(
        (base + CURSORDATA_AJIFRATE_OFF as u64) as *mut u64,
        staged_ajif_rate,
    );

    if trace < 96 {
        print_str(b" aspcur=0x");
        print_hex_u64(aspcur_client);
        print_str(b" aicur=0x");
        print_hex_u64(aicur_client);
        print_str(b" ajif=0x");
        print_hex_u64(ajif_rate_client);
        print_str(b" staged=0x");
        print_hex_u64(base);
        print_str(b" bytes=");
        print_u64(offset);
        print_str(b"\n");
    }

    Some((staged_module, staged_resource, base, stage))
}

unsafe fn capture_builtin_class_key(
    graph: CapturedRegisterClassGraph,
    class_name: CapturedStringArg,
    class_version: CapturedStringArg,
    fn_id: u32,
    flags: u32,
) -> Option<nt_kernel_exec::user_class::BuiltinClassKey> {
    use nt_kernel_exec::user_class::{BuiltinClassKey, WNDCLASSEXW_SIZE};

    let mut wnd = [0u8; WNDCLASSEXW_SIZE];
    core::ptr::copy_nonoverlapping(graph.wnd as *const u8, wnd.as_mut_ptr(), wnd.len());
    let class_name = staged_class_name_identity(
        class_name.desc, class_name.desc + 0x20, RC_ARG_BUF_CAP, false,
    )?.0;
    let class_version = staged_class_name_identity(
        class_version.desc, class_version.desc + 0x20, RC_ARG_BUF_CAP, false,
    )?.0;
    let menu_name = staged_class_name_identity(
        graph.menu_desc, graph.menu_buffer,
        RC_ARG_CAPTURE_SLOT - RC_CLASS_MENU_BUF_OFF, true,
    )?.0;
    BuiltinClassKey::decode(&wnd, class_name, class_version, menu_name, fn_id, flags)
}

/// Initialize the live executive once and service its hosted processes, starting with the primary
/// image and its ntdll. Generated SEC_IMAGE probes use `sec_image_diagnostic` instead.
pub(crate) unsafe fn service_sec_image(
    fault_ep: u64,
    primary_spawn: img_spawn::SecImageSpawn,
    primary_image: nt_exe_image::HostedProcessImageRef<'static>,
    pe: &nt_pe_loader::PeFile,
    scratch_base: u64,
    ntdll: (u64, &nt_pe_loader::PeFile),
    driver_starts: DriverStartBootstrap,
    boot_system_pnp_plan: &InlineDriverLaunchPlan,
    demand_pnp_plan: &InlineDriverLaunchPlan,
) -> (
    u64,
    u64,
    u64,
    u64,
    u64,
    BootDriverStartReports,
    NativeDriverLoadReport,
    LiveDeviceActionReport,
    StartDeviceCallReport,
    DesktopAcceptanceReport,
) {
    let pml4 = primary_spawn.pml4;
    let main_tcb = primary_spawn.main_tcb;
    loader_trace_clear();
    reset_deferred_user_callback_returns();
    let primary_layout = primary_spawn.layout;
    let img_base = primary_layout.base();
    let img_end = primary_layout.end();
    let nt_base = ntdll.0;
    let nt_end = nt_base + image_extent(ntdll.1);
    // Per-process demand-fault backstop (see the use sites). BATCH-22: raised from 2000 now that the
    // persistent scratch VA is decoupled from this count (bounded ≤256 slots) — it's a frame-budget /
    // runaway guard only, sized to let lsass's full LSA-init DLL tree page in within the frame pool.
    // Per-process fresh-fill ceiling. Each fresh fill consumes a UNIQUE monotonic scratch slot
    // (`scratch_base + faults*0x1000`), so this must stay under the per-process scratch window
    // (now 64 MiB = 16384 slots, see map_demand_scratch_pts). (A) EAGER IMAGE-MAP front-loads a
    // process's whole DLL tree, so raised 6000→15000 (headroom under 16384) to let lsass's full
    // LSA-init tree page in eagerly without hitting the cap. Runaway/frame-pool guard only.
    // page VA filled at each fault index → its persistent executive scratch is
    // scratch_base + index*0x1000. Lets a syscall handler copy OUT to any already-mapped image
    // page (e.g. an ntdll .data global), not just the stack (which has its own mirror).
    // Working buffer for the current pi's demand-filled page VAs — a STATIC (not a 4 KiB stack local)
    // so the 5th hosted process doesn't pressure the rootserver stack on the deep FS-walk call
    // chain (see FILLED_WORK). Loaded from / saved to `pfilled[pi]` around each dispatch below.
    let filled_pages: &mut [u64; 512] = &mut *core::ptr::addr_of_mut!(FILLED_WORK);
    // DIAG ring buffer of the last serviced SSNs, to locate the silent 0x80000005.
    let ssn_ring = &mut *core::ptr::addr_of_mut!(SERVICE_SSN_RING_WORK);
    ssn_ring.fill(0);
    let ssn_ring_badge = &mut *core::ptr::addr_of_mut!(SERVICE_SSN_RING_BADGE_WORK);
    ssn_ring_badge.fill(0);
    // winlogon-main-only ring (badge==WINLOGON_BADGE) — isolate winlogon's sequence from the
    // services (badge 6) noise that dominates the shared ring, to diagnose the StartLsass wall.
    let wl_ring = &mut *core::ptr::addr_of_mut!(SERVICE_WL_RING_WORK);
    wl_ring.fill(0);
    let wl_ri = 0usize;
    let ssn_ri = 0usize;
    // Generic owner-local file/section/spawn state for hosted executable images.
    let exe_images = reset_service_exe_images_work();
    let exe_image_catalog = reset_service_exe_image_catalog_work();
    let generic_sections = reset_service_generic_sections_work();
    register_loaded_hosted_image(exe_image_catalog, primary_image, !pe.bytes().is_empty())
        .expect("primary hosted image metadata must register once");
    let primary_backing = crate::fs_loader::exec_fs()
        .and_then(|fs| crate::fs_loader::fat_open_path_metadata(&fs, crate::installed_layout::SMSS))
        .filter(|entry| !entry.metadata.is_directory)
        .and_then(|entry| crate::fs_loader::exec_fs_file_identity(entry.metadata.file_id))
        .expect("primary SMSS image requires its exact mounted File identity");
    let primary_target = nt_exe_image::SpawnTarget::from_image(primary_image);
    exe_image_catalog.bind_registered_backing(primary_target, primary_backing)
        .expect("primary SMSS File identity must bind once");
    exe_image_catalog.bind_registered_launch_policy(
        primary_target, nt_exe_image::HostedProcessRole::NativeSession,
    ).expect("primary SMSS execution policy must bind once");
    let primary_pi = primary_image.pi;
    if let Some(runtime) = hosted_process_runtime_for_pi(primary_pi) {
        if let Some(spawned) = runtime.spawned {
            spawned.store(1, Ordering::Release);
        }
    }
    // csrss's loadable DLLs (csrsrv + the ServerDlls basesrv/winsrv) are tracked by the generic
    // nt-dll-registry, built below once their PEs are parsed. Each hosted VSpace gets its own
    // exact dynamic parent paging owner as images map; placement is not paging authority.
    // The bootstrap manifest supplies disk paths,
    // image identity, and runtime layout; each loaded PE is relocated to PE_LOAD_BASE and published
    // into the loaded-image registry below.
    let mut csrss_pi = usize::MAX;
    for index in 0..HOSTED_BOOTSTRAP_LOAD_COUNT {
        let spec = hosted_bootstrap_load_spec(index).expect("bootstrap load spec index is bounded");
        if spec.image.role == nt_exe_image::HostedProcessRole::Win32Subsystem {
            csrss_pi = spec.image.pi;
            break;
        }
    }
    assert!(
        csrss_pi != usize::MAX,
        "bootstrap manifest must include CSRSS"
    );
    let hosted_loaded_images = reset_service_hosted_loaded_images_work();
    // The primary image uses the same loaded-image authority as later child processes. Its
    // backing bytes remain valid throughout this service loop, like the supplied ntdll image.
    let primary_bytes = core::slice::from_raw_parts(pe.bytes().as_ptr(), pe.bytes().len());
    let primary_pe = nt_pe_loader::PeFile::parse(primary_bytes)
        .expect("the primary image has already passed PE validation");
    hosted_loaded_images
        .register_if_loaded(primary_image, Some(primary_pe), primary_bytes.as_ptr() as u64)
        .expect("primary executable backing must register once");
    let hosted_loaded_images_ptr = hosted_loaded_images as *mut HostedLoadedImageTable;
    print_str(b"[sec-init] bootstrap-image-load begin\n");
    for index in 0..HOSTED_BOOTSTRAP_LOAD_COUNT {
        let spec = hosted_bootstrap_load_spec(index).expect("bootstrap load spec index is bounded");
        load_hosted_bootstrap_image(
            exe_image_catalog,
            hosted_loaded_images,
            index,
            spec,
        );
    }
    print_str(b"[sec-init] bootstrap-image-load end\n");
    // Seeded Ps objects precede image loading. Admit each exact process only after its attached
    // executable has passed PE parsing; win32k Ps WOW64 queries must never infer x64 from a name.
    for pi in 0..HOSTED_PROCESS_MANAGER_SEED_COUNT {
        let image = exe_image_catalog
            .get_by_pi(pi)
            .expect("seeded Ps process retains its hosted image identity");
        let (validated_pe, _) = unsafe { hosted_loaded_images.pe_and_pool_for_image(image) }
            .expect("seeded Ps process needs its exact parsed executable");
        let cid = ps_bootstrap::hosted_main_client_id(pi)
            .expect("seeded Ps process retains its exact main client ID");
        unsafe { ps_bootstrap::with_process_manager(|pm| {
            pm.admit_validated_process_image(cid.unique_process, validated_pe)
        }) }
        .expect("seeded Ps process architecture admission failed");
    }
    // Retain the existing bootstrap DLL registry and its parsed pool-backed images for legacy
    // bootstrap consumers. Ordinary File opens do not populate this store: canonical SEC_IMAGE
    // admission captures the opened File, and image residency reads that retained source.
    const DLL_PINS: [(&[u8], &[u8]); DLL_PIN_COUNT] = [
        (b"csrsrv", crate::installed_layout::CSRSRV),
        (b"kernel32_vista", crate::installed_layout::KERNEL32_VISTA),
        (b"advapi32_vista", crate::installed_layout::ADVAPI32_VISTA),
        (b"ntdll_vista", crate::installed_layout::NTDLL_VISTA),
    ];
    // Bootstrap parsed-PE storage lives for the whole service loop.
    let dll_pe_store = reset_service_dll_pe_store_work();
    let mut reg = nt_dll_registry::Registry::new(DLL_ARENA_START, DLL_ARENA_END);
    print_str(b"[sec-init] pinned-dll-load begin\n");
    // Allocate metadata only for these loaded bootstrap images; csrsrv keeps slot 0 and its base.
    for (i, &(stem, path)) in DLL_PINS.iter().enumerate() {
        print_str(b"[sec-init] pinned-dll-load item=");
        print_u64(i as u64);
        print_str(b" stem=");
        print_str(stem);
        print_str(b"\n");
        let (pe, va) = load_dll_from_fs(path, stem);
        let (sz, ent) = pe
            .as_ref()
            .map(|p| (image_extent(p), p.entry_point_rva()))
            .unwrap_or((0, 0));
        let slot = reg.register(stem, sz, ent);
        if let Some(ref p) = pe {
            let base = reg.base(slot);
            apply_relocations_to_buf(p, va, base);
            let e_lfanew = core::ptr::read_volatile((va + 0x3c) as *const u32) as u64;
            core::ptr::write_volatile((va + e_lfanew + 0x30) as *mut u64, base);
        }
        if dll_pe_store.set(slot, pe).is_err() {
            print_str(b"[sec-init] dll-pe-store pin allocation failed slot=");
            print_u64(slot as u64);
            print_str(b"\n");
        }
    }
    print_str(b"[sec-init] pinned-dll-load end\n");
    // The real NT syscall path (seam): dispatch SSNs the handler implements; the remaining legacy
    // broker-owned SSNs continue through the broker match below.
    let nt_dispatcher = NativeSyscallDispatcher::new(build_nt_table());
    clear_service_delay_drain_context();
    // Bootstrap still owns Ps here. Drain provider CM work and its journal before moving Ps into
    // the handler, whose constructor runs setup with an exclusive mutable borrow.
    boot_registry_mutation_work::drain_boot_registry_before_handler_constructor()
        .expect("provider registry owner must quiesce before live setup");
    let mut nt_handler = initialize_exec_nt_handler_once(
        exe_image_catalog as *const nt_exe_image::OwnedHostedImageCatalog<HOSTED_PROCESS_IMAGE_CAP>,
        driver_starts,
    );
    print_str(b"[sec-init] handler-ready\n");
    nt_handler.register_main_thread_spawn(primary_pi, primary_spawn)
        .expect("primary runtime publication must precede first execution");
    nt_handler.seed_bootstrap_execution_role(primary_pi, primary_backing)
        .expect("primary execution root requires exact mounted File and live Ps identity");
    // Bootstrap and runtime retain one queue at the same address; registration cannot clear it.
    // Keep only the stable owner address across nested driver dispatch. Direct queue loans below
    // end at each call site; queue-taking helpers must return before the next nested rearm.
    let delay_queue = (&mut *core::ptr::addr_of_mut!(SERVICE_DELAY_QUEUE_WORK))
        .as_mut()
        .expect("delay wait queue must be initialized before providers") as *mut nt_delay_execution::Queue;
    nt_handler.global_atoms = Some(crate::atom_bootstrap::take());
    register_service_delay_drain_context(&mut nt_handler, &mut *delay_queue);
    // Bootstrap may already have armed the PIT. Reconcile the transferred deadlines
    // with the runtime owner before receiving; failed handoff must not strand work.
    let timer_handoff = rearm_registered_delay_timer();
    assert!(
        timer_handoff.owner_available(),
        "runtime timer ownership handoff failed: {:?}",
        timer_handoff,
    );
    publish_kuser_clocks();
    let alias = kuser_page_alias_get(0);
    if alias != 0 {
        KUSER_CLOCK_INITIAL_TICK.store(
            u64::from(nt_ntdll_layout::kuser::read_tick_count(alias as *const u8)),
            Ordering::Release,
        );
    }
    KUSER_CLOCK_INIT_OK.store(true, Ordering::Release);
    launch_live_pnp_plans(
        nt_handler as *mut ExecNtHandler,
        &[boot_system_pnp_plan, demand_pnp_plan],
    );
    // Per-hosted-process state, indexed by fault badge (0 = smss, 1 = csrss). The SINGLE service
    // loop multiplexes both: each thread faults through a fault-EP cap minted with its badge, so the
    // recv badge selects whose VSpace / image / scratch / fault-bookkeeping to use. Slot 1 (csrss)
    // is filled in when NtCreateProcess spawns it; until then only slot 0 (smss) is live. The `mut`
    // working locals (pml4/scratch_base/img_end/pe via shadowing, faults/first/ntfaults/filled_pages)
    // are LOADED from these at the top of each iteration and SAVED back before each recv, so the
    // ~30 body references stay unchanged.
    // Slots are EPROCESS-linked via the handler-owned process mechanism lookup. smss is live from
    // the initial recv; later hosted processes claim their pid on the native create-process path and
    // fill pml4/scratch/img_end when the service loop constructs their seL4 mechanism.
    let procs =
        reset_service_procs_work(MAX_PI).expect("service process scratch allocation failed");
    for (i, p) in procs.iter_mut().enumerate() {
        p.pid = nt_handler
            .pm_pid_for_pi(i)
            .map(|pid| pid as u64)
            .unwrap_or(0);
    }
    procs[primary_pi].pml4 = pml4;
    nt_handler
        .publish_hosted_process_vspace(primary_pi, primary_spawn.vspace_caps)
        .expect("primary VSpace publication requires a registered bootstrap process");
    procs[primary_pi].scratch_base = scratch_base;
    procs[primary_pi].img_end = img_end;
    procs[primary_pi].img_base = img_base;
    // Per-process demand-fill bookkeeping is kept out of the bounded rootserver stack. It is now a
    // heap-backed slice sized for the runtime process-index window instead of a fixed BSS matrix.
    let pfilled = reset_pfilled_work(MAX_PI).expect("process fault scratch allocation failed");
    if !reset_process_vm_region_maps(MAX_PI) {
        panic!("process VAD map allocation failed");
    }
    // Cooperative wait tables own durable state across syscall iterations. Reserve their expected
    // boot footprint up front; later growth remains valid through the tables' ordinary ownership.
    if !object_waiter_table_reset() {
        panic!("object wait table allocation failed");
    }
    if !io_completion_waiter_table_reset() {
        panic!("IO completion wait table allocation failed");
    }
    if !hosted_io_owner_tables_reset() {
        panic!("hosted I/O owner table allocation failed");
    }
    if !thread_wait_state_reset() {
        panic!("thread wait parked-state allocation failed");
    }
    if !keyed_wait_tables_reset() {
        panic!("keyed wait table allocation failed");
    }
    if !reset_lpc_receive_waits() {
        panic!("LPC receive waiter table allocation failed");
    }
    if !reset_lpc_connect_waits() {
        panic!("LPC connect waiter table allocation failed");
    }
    if !reset_lpc_request_waits() {
        panic!("LPC request waiter table allocation failed");
    }
    if !reset_lpc_component_waits() {
        panic!("component LPC readiness table allocation failed");
    }
    // Driver import catalogs are durable and may be consulted from later PnP or win32k loads.
    // Populate their expected boot footprint before entering the service loop.
    if !initialize_fsd_export_registry() {
        panic!("hosted driver export registry allocation failed");
    }
    #[cfg(not(feature = "mup-provider-kernel-only"))]
    if !win32k_subsystem::initialize_export_registry() {
        panic!("win32k export registry allocation failed");
    }
    if pending_driver_start_redrive_needed(&nt_handler) {
        let _ = pump_hosted_io_and_redrive_driver_starts(
            driver_launch::drain_hosted_driver_dpcs(),
            &mut nt_handler,
        );
    }
    #[cfg(feature = "source-irp-integration")]
    {
        // The live handler and source redrive context exist; SMSS is still suspended.
        let status = crate::win32k_glue::source_irp_integration::run_configured(nt_handler as *mut _);
        assert_eq!(status, 0, "native source IRP fixture did not prove completion");
    }
    nt_handler.capture_desktop_launch_contract();
    #[cfg(not(feature = "mup-provider-kernel-only"))]
    let primary_alias_activation = {
        let primary_alias_owner = nt_hosted_runtime::PrimaryAliasOwner {
            process_index: primary_pi,
            process_generation: nt_handler.hosted_process_generation(primary_pi)
                .expect("primary process retains its generation"),
            tcb: main_tcb,
        };
        let mut activation = nt_hosted_runtime::PrimaryAliasActivation::new(
            primary_alias_owner,
        ).expect("primary process retains its TCB and generation");
        PRIMARY_ALIAS_RETRY_DEADLINE.store(u64::MAX, Ordering::Release);
        PRIMARY_ALIAS_RETRY_WAKE_PENDING.store(false, Ordering::Release);
        attempt_primary_alias_activation(&mut nt_handler, &mut activation);
        activation
    };
    #[cfg(feature = "mup-provider-kernel-only")]
    print_str(b"[mup-provider-gate] SMSS remains suspended during native driver proof\n");
    // Fix (B): the INITIAL recv also binds REPLY_MAIN (r12) so the first caller's Call is captured
    // as a reply cap, matching every reply_recv_badge recv in the loop body.
    // The first blocking ingress rechecks retained work like every later one. This barrier
    // only programs wake demand; provider execution stays at the outer loop top.
    let msg = {
        assert!(prepare_service_receive(&mut *delay_queue, &mut nt_handler),
            "initial root receive lost its physical timer owner");
        let (badge, mi, m0, m1, m2, m3) =
            recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
        Message { badge, mi, m0, m1, m2, m3 }
    };
    // ★★ PARK + QUIESCE CONTRACT — see docs/n-threads-multiplex.md §1a for the authoritative catalog
    // of every park site + the quiesce predicate. Load-bearing: moving a park's location/condition or
    // changing the quiesce logic can hang the boot (never quiesce) or quiesce EARLY (miss specs / skip
    // the desktop paint). The two helpers below (`park_and_log!` crash parks, `mark_wait_parked!`
    // wakeable waits) + the `crash_parked`/`wait_parked` bitmasks ARE the unified park mechanism; the
    // remaining direct-`break` sites are per-process steady-state predicates (notably the
    // LSA_RPC_SERVER_ACTIVE_SIGNALLED paint-ordering guard) intentionally kept distinct.
    // ★ FAULT ISOLATION (generalized park-and-log). An UNHANDLED / UNRECOVERABLE fault in ONE hosted
    // process must PARK THAT PROCESS (with a clear one-line log) and let the shared loop CONTINUE
    // servicing the others — a process crash does not halt the kernel (fundamental OS fault isolation).
    // This replaces the recurring whack-a-mole of adding a bespoke park arm per new terminal wall
    // (smss-190, the listener-parks, the lsass-post-signal park, …). `crash_parked` is a bitmask of
    // top-level process badges (0/2/4/6/8, all < 64) that have hit an unrecoverable crash; a parked
    // process's further faults are re-parked WITHOUT re-logging (the `already` guard). QUIESCE
    // (break → gate) only when no live top-level process can make forward progress — every live one
    // is crash-parked (so `recv` would block forever). Cooperative parks (wait/delay/listener) are a
    // DIFFERENT, wakeable state and are left as-is; only a real crash sets a `crash_parked` bit.
    let crash_parked: u64 = 0;
    service_watchdog_record_crash_parked(crash_parked);
    // Boot-milestone watchdog state is wall-clock based (iteration counts are useless here:
    // each win32k dispatch is a whole-component TCG round-trip taking SECONDS, so the loop does only
    // ~1-2 iterations/sec and an iter-count stall never trips within the boot budget). `last_progress_t`
    // is the monotonic time (100ns units) at the last epoch bump (a new image/page publication,
    // finite credential/dialog or shell milestone, or committed registry mutation). An expired
    // milestone window requests bounded stall validation, not proof of a deadlock. Evaluate it
    // only without an owned client ingress: every accepted Call must reach dispatch and its
    // exact reply/park boundary before validation may stop the service loop.
    let progress_epoch = boot_progress_epoch;
    let last_progress_epoch = progress_epoch();
    let last_progress_t = monotonic_time_100ns();
    let stall_deferrals =
        nt_hosted_runtime::ProgressDeferralBudget::new(last_progress_epoch, 2);
    // FORWARD-PROGRESS CENSUS (see `print_progress_census`): attribute the wall-clock between two
    // consecutive loop tops to the badge that was serviced in between, and count the iterations.
    let census_prev_t = last_progress_t;
    let census_prev_badge = usize::MAX;
    // …and dump that census every `CENSUS_PERIOD_100NS`, so a boot that never quiesces (killed by
    // the harness at RUNEXIT=124, before the gate/final census ever runs) STILL says where its
    // wall-clock went. Successive dumps turn a runaway into a measurable RATE. The clock is a
    // STATIC because the win32k dispatch arm's nested pump ticks it too (see `w32_census_enter`).
    CENSUS_LAST_DUMP.store(last_progress_t, Ordering::Relaxed);
    let root_add_device_turn: Option<RootAddDeviceTurn> = None;
    let add_device_selection_evidence = nt_driver_start::AddDeviceSelectionEvidence::new(64);
    let root_queued_callback_turn: Vec<RootQueuedCallbackTurn> = Vec::new();
    let memory_context = ExecLoopCtx {
        owner_pi: primary_pi,
        owner_pid: nt_handler.capture_process_identity(primary_pi)
            .expect("primary process retains its mechanism identity").pid,
        owner_generation: primary_image.generation,
        live_paging: None,
        pml4,
        procs,
        pfilled,
        reg: &mut reg as *mut nt_dll_registry::Registry,
        hosted_loaded_images: hosted_loaded_images_ptr,
        exe_images: exe_images as *mut nt_exe_image::ImageTable<HOSTED_PROCESS_IMAGE_CAP>,
        exe_image_catalog: exe_image_catalog
            as *mut nt_exe_image::OwnedHostedImageCatalog<HOSTED_PROCESS_IMAGE_CAP>,
        filled_pages: &mut pfilled[primary_pi] as *mut [u64; 512],
        faults: &mut procs[primary_pi].faults as *mut u64,
        scratch_base,
        ntdll_pe: ntdll.1 as *const nt_pe_loader::PeFile as *const ()
            as *const nt_pe_loader::PeFile<'static>,
        img_end,
        img_base,
        nt_base,
        nt_end,
        dll_pe_store: dll_pe_store as *mut DllPeStore,
        generic_sections,
    };
    nt_handler.loop_ctx = Some(memory_context);
    receive_vspace::install(nt_handler.hosted_vspace_observer());
    let mut lp = LoopState {
        exit: LoopExit::new(),
        parks: Parks { crash_parked, crash_logged: 0, wait_parked: 0 },
        msg,
        ingress: Ingress {
            fault_ep,
            delay_queue,
            receive_boundary: None,
            root_add_device_turn,
            add_device_selection_evidence,
            root_queued_callback_turn,
            #[cfg(not(feature = "mup-provider-kernel-only"))]
            primary_alias_activation,
        },
        procs: Procs {
            procs,
            pfilled,
            filled_pages,
            primary_pi,
            csrss_process_handle: 0,
        },
        images: Images {
            exe_images,
            exe_image_catalog,
            generic_sections,
            hosted_loaded_images,
            hosted_loaded_images_ptr,
            dll_pe_store,
            reg: &mut reg,
            pe,
            ntdll,
            nt_base,
        },
        memory_context,
        handler: nt_handler,
        dispatcher: &nt_dispatcher,
        diag: Diag {
            ssn_ring,
            ssn_ring_badge,
            wl_ring,
            wl_ri,
            ssn_ri,
            progress_epoch,
            last_progress_epoch,
            last_progress_t,
            stall_deferrals,
            census_prev_t,
            census_prev_badge,
            alpc_create_ingress_trace: AtomicU64::new(0),
            alpc_send_ingress_trace: AtomicU64::new(0),
        },
    };
    'service_loop: loop {
        let (ingress, native_ingress_request) = match loop_maintenance::maintain(&mut lp) {
            ControlFlow::Continue(maintained) => maintained,
            ControlFlow::Break(Turn::Next) => continue 'service_loop,
            ControlFlow::Break(Turn::Exit) => break 'service_loop,
        };
        let ev = match loop_admission::admit(&mut lp, ingress, native_ingress_request) {
            ControlFlow::Continue(ev) => ev,
            ControlFlow::Break(Turn::Next) => continue 'service_loop,
            ControlFlow::Break(Turn::Exit) => break 'service_loop,
        };
        // A CPU exception (label 3). The DEBUG ntdll emits `int 0x2d` (DebugService/DPRINT),
        // which #GPs with no kernel debugger; emulate it as a no-op by skipping past the
        // `int 0x2d; int3` pair (echo the registers, advance the fault IP by 3, restart).
        if (lp.msg.mi >> 12) == 3 {
            match loop_exceptions::cpu_exception(&mut lp, &ev) {
                ControlFlow::Break(Turn::Next) => continue 'service_loop,
                ControlFlow::Break(Turn::Exit) => break 'service_loop,
            }
        }
        // DebugException (label 4 = seL4's #DB/#BP bucket). The microkernel payload is
        // m0=FaultIP, m1=ExceptionReason, m2=TriggerAddress, m3=BreakpointNumber. OUR ntdll's
        // `RtlRaiseException` / `RtlRaiseStatus` seams issue int3, so software-break requests also
        // decode WHAT exception the caller is raising: recover winlogon's full GPRs (RCX =
        // PEXCEPTION_RECORD arg, RSP), read the EXCEPTION_RECORD from its demand-faulted memory, and
        // walk the stack for the raise site.
        if (lp.msg.mi >> 12) == 4 {
            match loop_exceptions::debug_exception(&mut lp, &ev) {
                ControlFlow::Break(Turn::Next) => continue 'service_loop,
                ControlFlow::Break(Turn::Exit) => break 'service_loop,
            }
        }
        if (lp.msg.mi >> 12) == 6 {
            match loop_vm_fault::vm_fault(&mut lp, &ev) {
                ControlFlow::Break(Turn::Next) => continue 'service_loop,
                ControlFlow::Break(Turn::Exit) => break 'service_loop,
            }
        }
        // ntdll_plan Step 6.A — NATIVE seL4-Call transport. OUR ntdll (native-transport smss) does a
        // real seL4 `Call(CT_FAULT)` instead of a Windows-`syscall` UnknownSyscall trap. The request
        // carries MR0=SSN, MR1=caller RSP, and the complete argument vector in MR2 onward. We
        // NORMALIZE it into the fault-frame register slots the `(mi>>12)==2` arm reads, then re-label
        // the message as UnknownSyscall (2) so it flows through that arm's FULL servicing body
        // unchanged (dispatch + out-writes + spawn/park/delay post-actions). The reply is a NORMAL IPC
        // reply (the native caller has NO pending fault): `component_reply_recv!(..,result,..)` fans
        // result→MR0→the caller's r10, which our native stub reads as NTSTATUS.
        let native_call_transport = (lp.msg.mi >> 12) == nt_syscall_abi::NT_NATIVE_SYSCALL_LABEL;
        if native_call_transport {
            match loop_native_call::native_call(&mut lp, &ev) {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(Turn::Next) => continue 'service_loop,
                ControlFlow::Break(Turn::Exit) => break 'service_loop,
            }
        }
        if (lp.msg.mi >> 12) == 2 {
            match loop_syscall::syscall(&mut lp, &ev, native_call_transport) {
                ControlFlow::Break(Turn::Next) => continue 'service_loop,
                ControlFlow::Break(Turn::Exit) => break 'service_loop,
            }
        }
        // A non-VMFault, non-syscall fault (e.g. #GP) the loop can't service — unrecoverable. Park+log.
        match lp.park_and_log(ev.pi, b"other-fault", lp.msg.m1, lp.msg.m1) {
            Turn::Next => continue 'service_loop,
            Turn::Exit => break 'service_loop,
        }
    }
    if cfg!(feature = "mup-provider-kernel-only") {
        // This profile has no desktop verdict. Retain all live owners if its pump terminates.
        print_str(b"[mup-provider-gate] terminal service-loop failure\n");
        park();
    }
    let LoopState {
        exit: LoopExit { stop, stop_ssn, service_loop_exit_site, service_loop_exit_reason, iters, dbgsvc, .. },
        parks: Parks { crash_parked, wait_parked, .. },
        diag: Diag { ssn_ring, ssn_ring_badge, wl_ring, wl_ri, ssn_ri, .. },
        msg: Message { badge, mi, m0, m1, m3, .. },
        ingress: Ingress { root_add_device_turn, .. },
        procs: Procs { procs, pfilled, csrss_process_handle, .. },
        images: Images { hosted_loaded_images, .. },
        handler: mut nt_handler,
        ..
    } = lp;
    // One terminal receipt, before checkpointing can obscure the branch that ended the
    // serialized loop. Every field below is an observation; no owner or dirty bit is consumed.
    let ingress_hold = unsafe {
        crate::spawn_hosts::shared_ingress::owner::runtime::hold_snapshot()
    };
    let (callback_depth, continuation_depth) = win32k_glue::user_callback_stack_depths();
    print_str(b"[service-loop-exit] reason=");
    print_str(service_loop_exit_reason);
    print_str(b" site=");
    print_u64(service_loop_exit_site as u64);
    print_str(b" stop=");
    print_hex_u64(stop);
    print_str(b" stop-ssn=");
    print_u64(stop_ssn);
    print_str(b" badge/label/m0/reply=");
    print_u64(badge);
    print_str(b"/");
    print_u64(mi >> 12);
    print_str(b"/");
    print_hex_u64(m0);
    print_str(b"/");
    print_u64(REPLY_MAIN_SLOT.load(Ordering::Relaxed));
    print_str(b" child-pending=");
    print_u64(u64::from(crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending()));
    print_str(b" add-device-owner=");
    match root_add_device_turn.as_ref().map(|turn| turn.owner()) {
        Some(RootAddDeviceOwner::DriverStart(owner)) => {
            print_str(b"driver-start/");
            print_u64(owner.slot() as u64);
        }
        Some(RootAddDeviceOwner::PnpRebalance(owner)) => {
            print_str(b"pnp-rebalance/");
            print_u64(owner.slot() as u64);
        }
        None => print_str(b"none"),
    }
    print_str(b" callbacks/continuations/dispatch/suspended=");
    print_u64(callback_depth as u64);
    print_str(b"/");
    print_u64(continuation_depth as u64);
    print_str(b"/");
    print_u64(spawn_hosts::dispatch_depth());
    print_str(b"/");
    print_u64(spawn_hosts::SUSPENDED_COMPONENT_OUTSTANDING.load(Ordering::Relaxed));
    print_str(b" snapshot-dirty=");
    print_u64(u64::from(crate::writable_fs::snapshot_dirty_for_diagnostics()));
    print_str(b" live/crash/wait=");
    print_hex_u64(live_top_badges(&nt_handler));
    print_str(b"/");
    print_hex_u64(crash_parked);
    print_str(b"/");
    print_hex_u64(wait_parked);
    print_str(b"\n");
    if let Some(running) = ingress_hold.running {
        print_str(b"[service-loop-exit-owner] running lane/gen/epoch/route/executor/reply/tcb=");
        print_u64(running.lane.index as u64);
        print_str(b"/");
        print_u64(running.lane.generation);
        print_str(b"/");
        print_u64(running.dispatch.map_or(0, |dispatch| dispatch.epoch()));
        print_str(b"/");
        print_u64(running.route.map_or(0, |route| route.badge()));
        print_str(b"/");
        print_u64(running.binding.map_or(0, |binding| binding.executor_id));
        print_str(b"/");
        print_u64(running.binding.map_or(0, |binding| binding.reply_object));
        print_str(b"/");
        print_u64(running.physical.map_or(0, |source| source.tcb));
        print_str(b" quarantined=");
        print_u64(u64::from(running.quarantined.unwrap_or(false)));
        print_str(b"\n");
    }
    if let Some(oldest) = ingress_hold.oldest {
        print_str(b"[service-loop-exit-owner] oldest pi/pid/generation/tid/badge/reply/executor/admission=");
        print_u64(oldest.binding.pi as u64);
        print_str(b"/");
        print_u64(oldest.binding.process.pid as u64);
        print_str(b"/");
        match oldest.binding.process.generation {
            nt_types::ProcessGeneration::Hosted(generation) => {
                print_str(b"hosted:");
                print_u64(generation);
            }
            nt_types::ProcessGeneration::Temporary(generation) => {
                print_str(b"temporary:");
                print_u64(generation);
            }
        }
        print_str(b"/");
        print_u64(oldest.binding.tid);
        print_str(b"/");
        print_u64(oldest.binding.badge);
        print_str(b"/");
        print_u64(oldest.reply);
        print_str(b"/");
        print_u64(oldest.executor);
        print_str(b"/");
        print_u64(oldest.admission_sequence);
        print_str(b"\n");
    }
    nt_handler.loop_ctx = nt_handler.loop_ctx.map(|ctx| ctx.checkpoint_live());
    // Attribute a busy snapshot reserve before the terminal durability proof attempts to
    // acquire it. These owners are inspected once, after the serialized service loop exits.
    unsafe {
        crate::writable_fs::snapshot_storage::print_quiesce_header_owner();
        crate::writable_fs::print_quiesce_snapshot_owners();
        crate::registry_mutation_work::print_quiesce_owners();
        print_str(b"[quiesce-hive-journal] boot=");
        print_u64(u64::from(crate::writable_fs::hive_wal::has_retained_boot_hive_journal()));
        print_str(b" native=");
        print_u64(u64::from(crate::writable_fs::hive_wal::has_retained_native_hive_journal()));
        print_str(b"\n");
    }
    let quiesce_cm_status = checkpoint_boot_hives_at_quiesce(&mut nt_handler);
    if quiesce_cm_status != nt_fs::STATUS_SUCCESS {
        print_str(b"[cm-flush] shutdown hive durability refused status=0x");
        print_hex(quiesce_cm_status);
        print_str(b"\n");
        park();
    }
    dump_all_hosted_thread_quiesce(
        &nt_handler,
        &*hosted_loaded_images,
        &reg,
        ntdll,
        procs,
        pfilled,
    );
    dump_interactive_logon_quiesce(
        &nt_handler,
        &*hosted_loaded_images,
        &reg,
        ntdll,
        procs,
        pfilled,
    );
    dump_lsa_readiness_quiesce(
        &nt_handler,
        &*hosted_loaded_images,
        &reg,
        ntdll,
        procs,
        pfilled,
    );
    dump_services_start_quiesce(
        &nt_handler,
        &*hosted_loaded_images,
        &reg,
        ntdll,
        procs,
        pfilled,
    );
    dump_interactive_shell_frontier_quiesce(
        &nt_handler,
        &*hosted_loaded_images,
        &reg,
        ntdll,
        procs,
        pfilled,
    );
    dump_hot_hosted_thread_quiesce(
        &nt_handler,
        &*hosted_loaded_images,
        &reg,
        ntdll,
        procs,
        pfilled,
    );
    // ★ THE ESCAPE HATCH (unconditional, bounded). The service loop is done: release every reporter
    // still blocked on a debug event, so a debugger that attached, took an event and never continued
    // (or died holding one) can NEVER leave a target parked with its reply capability stranded. With
    // no debug object alive — every boot today — this returns on its first line and costs nothing.
    {
        let released = nt_handler.dbgk_release_all_blocked_reporters();
        if released != 0 {
            print_str(b"[dbgk] post-loop drain released ");
            print_u64(released as u64);
            print_str(b" blocked reporter(s)\n");
        }
    }
    // === PRIVATE-VM COMMIT/DECOMMIT/RE-COMMIT SELF-TEST (POST-QUIESCE). Runs on the real
    // `vm_map_private_page` path in a real hosted VSpace, at a VA above every placement the boot
    // makes, so it perturbs nothing. See `private_vm_unmap_selftest`. ===
    if let Some(logon_pi) = hosted_pi_for_role(
        &nt_handler,
        nt_exe_image::HostedProcessRole::InteractiveLogon,
    ) {
        crate::private_vm_unmap_selftest(
            &mut nt_handler,
            logon_pi,
            procs[logon_pi].pml4,
            procs[logon_pi].scratch_base,
        );
        crate::working_set_transition_selftest(
            &mut nt_handler,
            logon_pi,
            procs[logon_pi].pml4,
            procs[logon_pi].scratch_base,
        );
        crate::mapped_section_writeback_selftest(procs[logon_pi].scratch_base);
        crate::mapped_section_writecopy_cow_selftest(
            &mut nt_handler,
            logon_pi,
            procs[logon_pi].pml4,
            procs[logon_pi].scratch_base,
        );
        crate::image_writecopy_cow_selftest(
            &mut nt_handler,
            logon_pi,
            procs[logon_pi].pml4,
            procs[logon_pi].scratch_base,
        );
    } else {
        print_str(b"[private-vm] no runtime-registered interactive logon process -> skipped\n");
    }
    // === Path 2 lifecycle self-test (POST-LOOP: no more per-syscall heap reset follows, so these
    // durable pm allocations are safe). Proves NtOpenProcess + NtTerminateProcess route through pm.
    // The 3 HOSTED EPROCESSes are left untouched — terminate runs on a THROWAWAY process. ===
    {
        // NtOpenProcess: smss (pi 0) opens csrss by pid → a real Process(csrss_pid) handle in smss's
        // EPROCESS table.
        nt_handler.pi = 0;
        let mut open_ok = 0u64;
        if let (Some(smss_pid), Some(csrss_pid)) =
            (nt_handler.pm_pid_for_pi(0), nt_handler.pm_pid_for_pi(1))
        {
            let object_attributes = nt_ntdll_layout::ObjectAttributes::default();
            let client_id = nt_ntdll_layout::ClientId {
                unique_process: csrss_pid as u64,
                unique_thread: 0,
            };
            if let Ok((owner, _)) = nt_handler.open_process_captured(
                object_attributes,
                Some(client_id),
                0x0400, // PROCESS_QUERY_INFORMATION
            ) {
                let _ = owner;
                open_ok |= 1;
            }
            if nt_handler
                .pm
                .close_handle_by_object(smss_pid, nt_process::HandleObject::Process(csrss_pid))
            {
                open_ok |= 2; // the opened handle really is in smss's table
            }
        }
        PM_NTOPENPROCESS_OK.store(open_ok, Ordering::Relaxed);

        // NtTerminateProcess: build a throwaway EPROCESS + thread + handle, then run the same policy
        // teardown the handler drives, and verify the process/thread are signalled + wait-able + the
        // handle table closes. Also verify the handler's ProcessHandle resolve (NtCurrentProcess→self).
        let mut life_ok = 0u64;
        let parent = nt_handler.pm_pid_for_pi(0);
        let tpid = nt_handler
            .pm
            .create_process("lifecycle-test.exe", parent, None);
        if let Ok(ttid) = nt_handler.pm.create_thread(tpid, 0x1000, 0, false) {
            let th = nt_handler
                .pm
                .insert_handle(tpid, nt_process::HandleObject::Opaque(0xDEAD), 0)
                .ok();
            nt_handler.pi = 0;
            if nt_handler.resolve_process_handle(0xFFFF_FFFF_FFFF_FFFF)
                == nt_handler.pm_pid_for_pi(0)
            {
                life_ok |= 1; // NtCurrentProcess() resolves to the caller
            }
            if nt_handler.pm.terminate_process(tpid, 0x1234).is_ok() {
                life_ok |= 2;
            }
            if nt_handler.pm.is_process_signaled(tpid) {
                life_ok |= 4;
            }
            if nt_handler.pm.is_thread_signaled(ttid) {
                life_ok |= 8; // teardown signalled the process's threads
            }
            if nt_handler.pm.wait_process(tpid) == Some(0x1234) {
                life_ok |= 16; // exit status readable via wait
            }
            if th.is_some_and(|h| nt_handler.pm.close_handle(tpid, h).is_ok()) {
                life_ok |= 32; // handle-table teardown
            }
        }
        PM_LIFECYCLE_OK.store(life_ok, Ordering::Relaxed);

        // BATCH 39 — direct NtTerminateThread MECHANISM self-test (throwaway EPROCESS + threads).
        // Drives the exact terminate path the handler uses (`resolve_terminate_thread_handle` +
        // `terminate_thread`/`exit_thread` + `can_reclaim_thread`) WITHOUT depending on any live
        // hosted-thread self-exit. This replaces the batch-38 live-lifecycle terminate specs: with
        // the SCM RPC succeeding (route ON), the SCM worker/listener PERSIST as servers instead of
        // self-exiting, so a live self-exit COUNT is no longer a stable invariant. Runs post-loop on
        // throwaway processes/threads only -> the 6 hosted processes are untouched.
        {
            use nt_process::{HandleObject, ProcessState, ThreadState};
            const THREAD_TERMINATE: u32 = 0x0001;
            let mut term_ok = 0u64;
            let parent = nt_handler.pm_pid_for_pi(0);
            // Process A: two threads. `victim` is terminated via a typed Thread handle; `bystander`
            // must keep running (proves per-thread, not per-process, termination).
            let pa = nt_handler
                .pm
                .create_process("term-selftest-a.exe", parent, None);
            if let (Ok(victim), Ok(bystander)) = (
                nt_handler.pm.create_thread(pa, 0x2000, 0, false),
                nt_handler.pm.create_thread(pa, 0x3000, 0, false),
            ) {
                // A typed Thread handle with THREAD_TERMINATE resolves to the target tid.
                let hv = nt_handler
                    .pm
                    .insert_handle(pa, HandleObject::Thread(victim), THREAD_TERMINATE)
                    .ok();
                if let Some(hv) = hv {
                    if nt_handler.pm.resolve_terminate_thread_handle(
                        pa,
                        bystander,
                        hv as u64,
                        THREAD_TERMINATE,
                    ) == Ok(victim)
                    {
                        term_ok |= 0x01;
                    }
                }
                // A Thread handle WITHOUT THREAD_TERMINATE is rejected (access check enforced).
                if let Ok(hna) = nt_handler
                    .pm
                    .insert_handle(pa, HandleObject::Thread(victim), 0)
                {
                    if nt_handler
                        .pm
                        .resolve_terminate_thread_handle(
                            pa,
                            bystander,
                            hna as u64,
                            THREAD_TERMINATE,
                        )
                        .is_err()
                    {
                        term_ok |= 0x02;
                    }
                    let _ = nt_handler.pm.close_handle(pa, hna);
                }
                // The NULL/current pseudo-handle form (kernel32!ExitThread) resolves to the caller.
                if nt_handler
                    .pm
                    .resolve_terminate_thread_handle(pa, victim, 0, THREAD_TERMINATE)
                    == Ok(victim)
                {
                    term_ok |= 0x04;
                }
                // Terminate the victim: it becomes Terminated (signalled) with the exit status; the
                // bystander stays Ready and the EPROCESS is NOT cascaded (a live thread remains).
                if nt_handler.pm.terminate_thread(victim, 0xDEAD).is_ok()
                    && nt_handler.pm.thread(victim).is_some_and(|t| {
                        t.state == ThreadState::Terminated && t.exit_status == Some(0xDEAD)
                    })
                    && nt_handler.pm.is_thread_signaled(victim)
                    && nt_handler
                        .pm
                        .thread(bystander)
                        .is_some_and(|t| t.state != ThreadState::Terminated)
                    && nt_handler
                        .pm
                        .process(pa)
                        .is_some_and(|p| p.state == ProcessState::Running)
                {
                    term_ok |= 0x08;
                    term_ok |= 0x40; // the unrelated bystander thread continued
                }
                // TCB-reclaim gating: while a process handle still refers to the terminated victim it
                // must NOT be reclaimable (TID/slot aliasing hazard); after every such handle closes
                // it becomes reclaimable. Mirrors the handler's live TCB-reclaim guard.
                if let Some(hv) = hv {
                    let blocked = !nt_handler.pm.can_reclaim_thread(victim);
                    let _ = nt_handler.pm.close_handle(pa, hv);
                    if blocked && nt_handler.pm.can_reclaim_thread(victim) {
                        term_ok |= 0x10;
                    }
                }
            }
            // Process B: exercise the NO-CASCADE exit_thread path the handler uses for a process
            // whose OTHER threads keep it alive (the csrss "CSRSRV keeps us going" shape). The init
            // thread exits but a worker thread remains → the EPROCESS stays Running.
            let pb = nt_handler
                .pm
                .create_process("term-selftest-b.exe", parent, None);
            if let (Ok(init), Ok(_worker)) = (
                nt_handler.pm.create_thread(pb, 0x4000, 0, false),
                nt_handler.pm.create_thread(pb, 0x5000, 0, false),
            ) {
                if nt_handler.pm.exit_thread(init, 0x1).is_ok()
                    && nt_handler
                        .pm
                        .thread(init)
                        .is_some_and(|t| t.state == ThreadState::Terminated)
                    && nt_handler
                        .pm
                        .process(pb)
                        .is_some_and(|p| p.state == ProcessState::Running)
                {
                    term_ok |= 0x20;
                }
            }
            PM_TERMINATE_THREAD_SELFTEST.store(term_ok, Ordering::Relaxed);
        }

        // === Dbgk END-TO-END SELF-TEST (POST-LOOP) =================================================
        // Drives the REAL user-mode debugging plane the five native handlers dispatch into:
        // create a DEBUG_OBJECT, mint a TYPED handle for it in smss's REAL EPROCESS handle table and
        // resolve it through the handler's own `debug_object_for_handle` (access checks included),
        // attach it to a THROWAWAY debuggee, retrieve the fake create-process message with
        // NtWaitForDebugEvent's core (handles opened in the debugger's table + a rendered
        // DBGUI_WAIT_STATE_CHANGE), resolve it with NtDebugContinue, observe the thread-create /
        // thread-exit / process-exit EVENT SOURCES, then detach and prove the plane goes inert.
        // The 3 hosted EPROCESSes are otherwise untouched (only smss gains + loses handles).
        {
            use nt_process::dbgk;
            nt_handler.pi = 0;
            let mut dbg_ok = 0u64;
            let debugger_pid = nt_handler.pm_pid_for_pi(0);
            if let Some(debugger_pid) = debugger_pid {
                let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
                let bad_flags_rejected = nt_handler.pm.create_debug_object(0x8000)
                    == Err(nt_process::STATUS_INVALID_PARAMETER);
                if let Ok(object) = nt_handler
                    .pm
                    .create_debug_object(dbgk::DBGK_KILL_PROCESS_ON_EXIT)
                {
                    if bad_flags_rejected
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.kill_process_on_exit())
                    {
                        dbg_ok |= 0x0001;
                    }
                    // 0x1000 — the handler's typed-handle resolution + access enforcement, driven
                    // against smss's REAL per-process handle table.
                    let full = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::DebugObject(object),
                            dbgk::DEBUG_OBJECT_ALL_ACCESS,
                        )
                        .ok();
                    let no_access = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::DebugObject(object),
                            0,
                        )
                        .ok();
                    let wrong_type = nt_handler
                        .pm
                        .insert_handle(debugger_pid, nt_process::HandleObject::Opaque(0xDB6), 0)
                        .ok();
                    if full.is_some_and(|h| {
                        nt_handler.debug_object_for_handle(
                            h as u64,
                            dbgk::DEBUG_OBJECT_ADD_REMOVE_PROCESS,
                        ) == Ok(object)
                    }) && no_access.is_some_and(|h| {
                        nt_handler.debug_object_for_handle(
                            h as u64,
                            dbgk::DEBUG_OBJECT_ADD_REMOVE_PROCESS,
                        ) == Err(0xC000_0022)
                    }) && wrong_type.is_some_and(|h| {
                        nt_handler.debug_object_for_handle(h as u64, 0) == Err(0xC000_0024)
                    }) {
                        dbg_ok |= 0x1000;
                    }
                    for handle in [full, no_access, wrong_type].into_iter().flatten() {
                        let _ = nt_handler.pm.close_handle(debugger_pid, handle);
                    }

                    // A throwaway debuggee with a real image base + main thread.
                    let target = nt_handler
                        .pm
                        .create_process("dbgk-selftest.exe", None, None);
                    nt_handler.pm.set_image_base(target, 0x0000_0001_4000_0000);
                    if let Ok(main) = nt_handler.pm.create_thread(target, 0x2000, 0, false) {
                        let debugger = nt_process::ClientId {
                            unique_process: debugger_pid,
                            unique_thread: debugger_tid,
                        };
                        // 0x0002 — attach installs the port + PEB.BeingDebugged and posts + activates
                        // the fake DbgKmCreateProcessApi message.
                        if nt_handler.pm.debug_active_process(target, object, debugger) == Ok(1)
                            && nt_handler.pm.process_debug_port(target) == Some(object)
                            && nt_handler.pm.is_process_being_debugged(target)
                            && nt_handler
                                .pm
                                .debug_object(object)
                                .is_some_and(|o| o.len() == 1 && o.events_present())
                        {
                            dbg_ok |= 0x0002;
                        }
                        // 0x0004 — a self-attach is denied and a second attach is PORT_ALREADY_SET.
                        if let Ok(second) = nt_handler.pm.create_debug_object(0) {
                            if nt_handler
                                .pm
                                .debug_active_process(debugger_pid, second, debugger)
                                == Err(nt_process::STATUS_ACCESS_DENIED)
                                && nt_handler.pm.debug_active_process(target, second, debugger)
                                    == Err(dbgk::STATUS_PORT_ALREADY_SET)
                            {
                                dbg_ok |= 0x0004;
                            }
                            nt_handler.pm.destroy_debug_object(second);
                        }
                        // 0x0008 / 0x0010 — the wait retrieves it, with REAL handles opened in the
                        // debugger's table and the state change rendered around them.
                        if let Ok(Some(result)) =
                            nt_handler.pm.wait_for_debug_event(object, debugger_pid)
                        {
                            let sc = &result.state_change;
                            let u64_at = |o: usize| {
                                u64::from_le_bytes(sc[o..o + 8].try_into().unwrap_or([0; 8]))
                            };
                            if result.state == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                                && result.client_id.unique_process == target
                                && result.client_id.unique_thread == main
                                && u64_at(0x08) == target as u64
                                && u64_at(0x38) == 0x0000_0001_4000_0000
                                && u64_at(0x50) == 0x2000
                            {
                                dbg_ok |= 0x0008;
                            }
                            if result.handle_to_process != 0
                                && result.handle_to_thread != 0
                                && nt_handler
                                    .pm
                                    .lookup_handle(debugger_pid, result.handle_to_process)
                                    == Some(nt_process::HandleObject::Process(target))
                                && nt_handler
                                    .pm
                                    .lookup_handle(debugger_pid, result.handle_to_thread)
                                    == Some(nt_process::HandleObject::Thread(main))
                                && u64_at(0x18) == result.handle_to_process as u64
                                && u64_at(0x20) == result.handle_to_thread as u64
                            {
                                dbg_ok |= 0x0010;
                            }
                            let _ = nt_handler
                                .pm
                                .close_handle(debugger_pid, result.handle_to_process);
                            let _ = nt_handler
                                .pm
                                .close_handle(debugger_pid, result.handle_to_thread);
                            // 0x0020 — one outstanding event per debuggee process.
                            if matches!(
                                nt_handler.pm.wait_for_debug_event(object, debugger_pid),
                                Ok(None)
                            ) {
                                dbg_ok |= 0x0020;
                            }
                            // 0x0040 — continue validates its status and resolves the read event.
                            if nt_handler
                                .pm
                                .debug_continue(object, result.client_id, 0x1234)
                                == Err(nt_process::STATUS_INVALID_PARAMETER)
                                && nt_handler
                                    .pm
                                    .debug_continue(object, result.client_id, dbgk::DBG_CONTINUE)
                                    .is_ok()
                                && nt_handler
                                    .pm
                                    .debug_object(object)
                                    .is_some_and(|o| o.is_empty())
                            {
                                dbg_ok |= 0x0040;
                            }
                        }
                        // 0x0080 — EVENT SOURCE: thread create.
                        if let Ok(worker) = nt_handler.pm.create_thread(target, 0x3000, 0, false) {
                            if let Ok(Some(created)) =
                                nt_handler.pm.wait_for_debug_event(object, debugger_pid)
                            {
                                if created.state == dbgk::DBG_CREATE_THREAD_STATE_CHANGE
                                    && created.client_id.unique_thread == worker
                                    && u64::from_le_bytes(
                                        created.state_change[0x28..0x30]
                                            .try_into()
                                            .unwrap_or([0; 8]),
                                    ) == 0x3000
                                {
                                    dbg_ok |= 0x0080;
                                }
                                let _ = nt_handler
                                    .pm
                                    .close_handle(debugger_pid, created.handle_to_thread);
                                let _ = nt_handler.pm.debug_continue(
                                    object,
                                    created.client_id,
                                    dbgk::DBG_CONTINUE,
                                );
                            }
                            // 0x0100 — EVENT SOURCE: thread exit (no cascade: main still lives).
                            let _ = nt_handler.pm.exit_thread(worker, 0x1234);
                            if let Ok(Some(exited)) =
                                nt_handler.pm.wait_for_debug_event(object, debugger_pid)
                            {
                                if exited.state == dbgk::DBG_EXIT_THREAD_STATE_CHANGE
                                    && exited.client_id.unique_thread == worker
                                    && u32::from_le_bytes(
                                        exited.state_change[0x18..0x1c]
                                            .try_into()
                                            .unwrap_or([0; 4]),
                                    ) == 0x1234
                                {
                                    dbg_ok |= 0x0100;
                                }
                                let _ = nt_handler.pm.debug_continue(
                                    object,
                                    exited.client_id,
                                    dbgk::DBG_CONTINUE,
                                );
                            }
                        }
                        // 0x0200 — EVENT SOURCE: process exit.
                        let _ = nt_handler.pm.terminate_process(target, 0x99);
                        if let Ok(Some(dead)) =
                            nt_handler.pm.wait_for_debug_event(object, debugger_pid)
                        {
                            if dead.state == dbgk::DBG_EXIT_PROCESS_STATE_CHANGE
                                && u32::from_le_bytes(
                                    dead.state_change[0x18..0x1c].try_into().unwrap_or([0; 4]),
                                ) == 0x99
                            {
                                dbg_ok |= 0x0200;
                            }
                        }
                        // 0x0400 — detach clears the port + flushes; a second detach is PORT_NOT_SET.
                        let flushed = nt_handler.pm.remove_process_debug(target, object);
                        if flushed.is_ok()
                            && nt_handler.pm.process_debug_port(target).is_none()
                            && !nt_handler.pm.is_process_being_debugged(target)
                            && nt_handler
                                .pm
                                .debug_object(object)
                                .is_some_and(|o| o.is_empty())
                            && nt_handler.pm.remove_process_debug(target, object)
                                == Err(dbgk::STATUS_PORT_NOT_SET)
                        {
                            dbg_ok |= 0x0400;
                        }
                        // 0x0800 — a LIVE process that was attached then detached reports nothing
                        // further: attach a second throwaway debuggee, detach it, then create a
                        // thread in it and prove the plane stays inert.
                        let target2 =
                            nt_handler
                                .pm
                                .create_process("dbgk-selftest-b.exe", None, None);
                        if nt_handler
                            .pm
                            .create_thread(target2, 0x6000, 0, false)
                            .is_ok()
                        {
                            let attached = nt_handler
                                .pm
                                .debug_active_process(target2, object, debugger)
                                == Ok(1);
                            let detached =
                                nt_handler.pm.remove_process_debug(target2, object) == Ok(1);
                            let drained = nt_handler
                                .pm
                                .debug_object(object)
                                .is_some_and(|o| o.is_empty());
                            let _ = nt_handler.pm.create_thread(target2, 0x7000, 0, false);
                            if attached
                                && detached
                                && drained
                                && nt_handler
                                    .pm
                                    .debug_object(object)
                                    .is_some_and(|o| o.is_empty())
                                && matches!(
                                    nt_handler.pm.wait_for_debug_event(object, debugger_pid),
                                    Ok(None)
                                )
                            {
                                dbg_ok |= 0x0800;
                            }
                        }
                    }
                    nt_handler.pm.destroy_debug_object(object);
                }
            }
            DBGK_SELFTEST.store(dbg_ok, Ordering::Relaxed);
        }

        // === Dbgk SYSCALL-DISPATCH SELF-TEST (POST-LOOP) ===========================================
        // The block above drives the PLANE (ProcessManager + the pure `nt_process::dbgk` state
        // machine) directly; it proves nothing about the five NATIVE HANDLER ARMS. This block drives
        // those arms through the REAL dispatch route a hosted process uses —
        // `nt_dispatcher.dispatch(SSN, argv, origin, &mut nt_handler)`, the exact call the service
        // loop makes for every syscall — with REAL MARSHALLED ARGUMENTS living in CLIENT memory
        // (smss's mirrored stack). So the handler's own SSN→service resolution, typed-handle lookup,
        // `DbgkDebugObjectMapping` access checks, ProbeForWrite/copyin/copyout of the `*DebugHandle`,
        // `*Timeout`, `*CLIENT_ID` and `DBGUI_WAIT_STATE_CHANGE`, its counters and its wait-park
        // request all execute for real. Verified by the DBGK_* counters, which read 0 without it.
        {
            use nt_process::dbgk;
            const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
            const ST_TIMEOUT: u32 = 0x0000_0102;
            const ST_ACCESS_VIOLATION: u32 = 0xC000_0005;
            const ST_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
            const ST_INVALID_HANDLE: u32 = 0xC000_0008;
            const ST_INVALID_PARAMETER: u32 = 0xC000_000D;
            const ST_ACCESS_DENIED: u32 = 0xC000_0022;
            const ST_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
            // The client-side argument block: the DEEPEST (unused) end of smss's 16 KiB stack, which
            // is inside its mirrored range so the handler's copyin/copyout reach it exactly as they
            // reach a live caller's stack. smss is parked in its final syscall and the boot exits
            // right after the specs, so nothing ever reads these bytes back.
            const A_HANDLE: u64 = STACK_BASE + 0x80; // *DebugHandle out (8)
            const A_CLIENT_ID: u64 = STACK_BASE + 0x88; // CLIENT_ID in (16)
            const A_TIMEOUT: u64 = STACK_BASE + 0x98; // LARGE_INTEGER *Timeout in (8)
                                                      // DBGUI_WAIT_STATE_CHANGE out (0xB8).
            const A_STATE: u64 = STACK_BASE + 0xA0;
            // Handler-owned temporary slots let the specs exercise pid -> pi routing without
            // publishing throwaway processes as hosted launch topology.

            let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
            let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
            let saved_pi = nt_handler.pi;
            let saved_tid = nt_handler.current_tid;
            // Retain the process memory owner so syscall outputs use normal write admission.
            let saved_ctx = nt_handler.loop_ctx;
            crate::executor::local().client_pi.store(0, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(SMSS_SCRATCH_BASE, Ordering::Relaxed);
            nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(0));
            nt_handler.pi = 0;

            let mut sc_ok = 0u64;
            let dbg_origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
            // Every service below goes through THIS — the dispatcher, by SSN. An unregistered number
            // returns STATUS_INVALID_SYSTEM_SERVICE and never reaches a handler; a wrong argument
            // count returns STATUS_INVALID_PARAMETER before the handler.
            macro_rules! sysc {
                ($ssn:expr, $args:expr) => {
                    nt_dispatcher
                        .dispatch($ssn as u32, $args, &dbg_origin, &mut nt_handler)
                        .status
                };
            }

            // 0x0001 — the five services really are registered at the sysfuncs.lst-derived SSNs, with
            // their documented argument counts.
            if [
                (NativeService::NtCreateDebugObject, 35u32, 4u8),
                (NativeService::NtDebugActiveProcess, 59, 2),
                (NativeService::NtDebugContinue, 60, 3),
                (NativeService::NtRemoveProcessDebug, 199, 2),
                (NativeService::NtWaitForDebugEvent, 279, 4),
            ]
            .iter()
            .all(|&(service, ssn, argc)| {
                nt_dispatcher.table().number_of(service) == Some(ssn)
                    && nt_dispatcher.table().lookup(ssn).is_some_and(|entry| {
                        entry.service == service && entry.min_args == argc && entry.max_args == argc
                    })
            }) {
                sc_ok |= 0x0001;
            }

            let debugger_pid = nt_handler.pm_pid_for_pi(0).unwrap_or(0);
            let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
            nt_handler.current_tid = debugger_tid as u64;
            // Zero the client argument block through the mirror; if that fails the mirrors are not
            // usable and the whole test would be meaningless, so it stays 0 (=> FAIL) rather than
            // silently "passing".
            let client_args_ready = img_spawn::smss_copyout(A_HANDLE, &[0u8; 0x100]);
            if debugger_pid != 0 && client_args_ready {
                // --- NtCreateDebugObject (SSN 35): [*DebugHandle, DesiredAccess, *OA, Flags] ------
                let create = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[
                        A_HANDLE,
                        dbgk::DEBUG_OBJECT_ALL_ACCESS as u64,
                        0,
                        dbgk::DBGK_KILL_PROCESS_ON_EXIT as u64,
                    ]
                );
                // Read the handle back out of CLIENT memory the way the caller would — proof the
                // out-parameter was really marshalled, not just returned.
                let dbg_handle = smss_stack_read(A_HANDLE);
                let object = match nt_handler
                    .pm
                    .lookup_handle(debugger_pid, dbg_handle as nt_process::Handle)
                {
                    Some(nt_process::HandleObject::DebugObject(object)) => Some(object),
                    _ => None,
                };
                let host_event = object
                    .and_then(|object| nt_handler.pm.debug_object(object))
                    .map(|o| o.host_event)
                    .unwrap_or(0);
                let create_negatives = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[0, dbgk::DEBUG_OBJECT_ALL_ACCESS as u64, 0, 0]
                ) == ST_ACCESS_VIOLATION
                    && sysc!(
                        SSN_NT_CREATE_DEBUG_OBJECT,
                        &[A_HANDLE + 1, dbgk::DEBUG_OBJECT_ALL_ACCESS as u64, 0, 0]
                    ) == ST_DATATYPE_MISALIGNMENT
                    && sysc!(
                        SSN_NT_CREATE_DEBUG_OBJECT,
                        &[A_HANDLE, dbgk::DEBUG_OBJECT_ALL_ACCESS as u64, 0, 0x8000]
                    ) == ST_INVALID_PARAMETER;
                // 0x0002 — the handler created a real object, bound its EventsPresent dispatcher
                // event, minted a TYPED per-process handle and copied it out; its counter moved.
                if create == 0
                    && dbg_handle != 0
                    && object.is_some()
                    && host_event != 0
                    && DBGK_OBJECTS_CREATED.load(Ordering::Relaxed) >= 1
                    && create_negatives
                {
                    sc_ok |= 0x0002;
                }

                if let Some(object) = object {
                    // A throwaway debuggee with a real image base + main thread.
                    let target = nt_handler.pm.create_process("dbgk-syscall.exe", None, None);
                    nt_handler.pm.set_image_base(target, 0x0000_0001_5000_0000);
                    let main = nt_handler.pm.create_thread(target, 0x2100, 0, false).ok();
                    let target_claim = nt_handler.claim_temporary_process_slot(target, 0).ok();
                    let target_registered = target_claim.is_some();
                    let h_target = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(target),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let h_target_noaccess = nt_handler
                        .pm
                        .insert_handle(debugger_pid, nt_process::HandleObject::Process(target), 0)
                        .map(u64::from)
                        .unwrap_or(0);
                    let h_dbg_noaccess = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::DebugObject(object),
                            0,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let h_wrong_type = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Opaque(0xDB65),
                            dbgk::DEBUG_OBJECT_ALL_ACCESS,
                        )
                        .map(u64::from)
                        .unwrap_or(0);

                    // 0x0080 — the DEBUG-handle checks, all through the dispatch route: a handle
                    // without the required DbgkDebugObjectMapping access is ACCESS_DENIED on every
                    // service, a non-debug handle is OBJECT_TYPE_MISMATCH, and a NULL out/in pointer
                    // is ACCESS_VIOLATION.
                    if sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, h_dbg_noaccess])
                        == ST_ACCESS_DENIED
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[h_dbg_noaccess, 0, A_TIMEOUT, A_STATE]
                        ) == ST_ACCESS_DENIED
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[h_dbg_noaccess, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == ST_ACCESS_DENIED
                        && sysc!(SSN_NT_REMOVE_PROCESS_DEBUG, &[h_target, h_dbg_noaccess])
                            == ST_ACCESS_DENIED
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, h_wrong_type])
                            == ST_OBJECT_TYPE_MISMATCH
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[h_wrong_type, 0, A_TIMEOUT, A_STATE]
                        ) == ST_OBJECT_TYPE_MISMATCH
                        && sysc!(SSN_NT_WAIT_FOR_DEBUG_EVENT, &[dbg_handle, 0, A_TIMEOUT, 0])
                            == ST_ACCESS_VIOLATION
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, 0, dbgk::DBG_CONTINUE as u64]
                        ) == ST_ACCESS_VIOLATION
                    {
                        sc_ok |= 0x0080;
                    }
                    // 0x0200 — the PROCESS-handle side: a process handle lacking
                    // PROCESS_SUSPEND_RESUME is ACCESS_DENIED, an unknown one is INVALID_HANDLE, and
                    // detaching a process that was never attached is STATUS_PORT_NOT_SET.
                    if sysc!(
                        SSN_NT_DEBUG_ACTIVE_PROCESS,
                        &[h_target_noaccess, dbg_handle]
                    ) == ST_ACCESS_DENIED
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[0xDEAD_BEEF, dbg_handle])
                            == ST_INVALID_HANDLE
                        && sysc!(SSN_NT_REMOVE_PROCESS_DEBUG, &[h_target, dbg_handle])
                            == dbgk::STATUS_PORT_NOT_SET
                    {
                        sc_ok |= 0x0200;
                    }

                    // --- NtDebugActiveProcess (SSN 59): [ProcessHandle, DebugHandle] -------------
                    let attaches_before = DBGK_ATTACHES.load(Ordering::Relaxed);
                    let fake_before = DBGK_FAKE_MESSAGES.load(Ordering::Relaxed);
                    let attach = if target_registered {
                        sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle])
                    } else {
                        ST_INVALID_PARAMETER
                    };
                    // 0x0004 — the attach ran IN THE HANDLER (its counter moved), installed the port
                    // + PEB.BeingDebugged and posted the fake create message; a second one is
                    // STATUS_PORT_ALREADY_SET.
                    if attach == 0
                        && DBGK_ATTACHES.load(Ordering::Relaxed) == attaches_before + 1
                        && DBGK_FAKE_MESSAGES.load(Ordering::Relaxed) >= fake_before + 1
                        && nt_handler.pm.process_debug_port(target) == Some(object)
                        && nt_handler.pm.is_process_being_debugged(target)
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle])
                            == dbgk::STATUS_PORT_ALREADY_SET
                    {
                        sc_ok |= 0x0004;
                    }

                    // --- NtWaitForDebugEvent (SSN 279): [DebugHandle, Alertable, *Timeout,
                    //     *StateChange] — a REAL immediate timeout in client memory + a REAL
                    //     DBGUI_WAIT_STATE_CHANGE copied back out to client memory.
                    let timeout_written = img_spawn::smss_copyout(A_TIMEOUT, &0i64.to_le_bytes());
                    let waits_before = DBGK_WAITS_SERVED.load(Ordering::Relaxed);
                    let wait = sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    );
                    let mut sc = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];
                    let sc_read = img_spawn::smss_copyin(A_STATE, &mut sc);
                    let sc_u32 =
                        |o: usize| u32::from_le_bytes(sc[o..o + 4].try_into().unwrap_or([0; 4]));
                    let sc_u64 =
                        |o: usize| u64::from_le_bytes(sc[o..o + 8].try_into().unwrap_or([0; 8]));
                    let handle_to_process = sc_u64(0x18);
                    let handle_to_thread = sc_u64(0x20);
                    // 0x0008 — the handler served the wait and the OUT-PARAM LANDED IN CLIENT MEMORY:
                    // DbgCreateProcessStateChange for the right CLIENT_ID, carrying REAL process /
                    // thread handles opened in the debugger's own table, the image base and the
                    // initial thread's start address.
                    if wait == 0
                        && timeout_written
                        && sc_read
                        && DBGK_WAITS_SERVED.load(Ordering::Relaxed) == waits_before + 1
                        && sc_u32(0x00) == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                        && sc_u64(0x08) == target as u64
                        && main.is_some_and(|main| sc_u64(0x10) == main as u64)
                        && sc_u64(0x38) == 0x0000_0001_5000_0000
                        && sc_u64(0x50) == 0x2100
                        && handle_to_process != 0
                        && handle_to_thread != 0
                        && nt_handler
                            .pm
                            .lookup_handle(debugger_pid, handle_to_process as nt_process::Handle)
                            == Some(nt_process::HandleObject::Process(target))
                        && main.is_some_and(|main| {
                            nt_handler
                                .pm
                                .lookup_handle(debugger_pid, handle_to_thread as nt_process::Handle)
                                == Some(nt_process::HandleObject::Thread(main))
                        })
                    {
                        sc_ok |= 0x0008;
                    }
                    let _ = nt_handler
                        .pm
                        .close_handle(debugger_pid, handle_to_process as nt_process::Handle);
                    let _ = nt_handler
                        .pm
                        .close_handle(debugger_pid, handle_to_thread as nt_process::Handle);
                    // 0x0010 — nothing further is reportable for this debuggee (one outstanding event
                    // per process) and the *Timeout the handler READ from client memory is immediate
                    // ⇒ STATUS_TIMEOUT, with no park requested.
                    if sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    ) == ST_TIMEOUT
                        && nt_handler.wait_park_event < 0
                    {
                        sc_ok |= 0x0010;
                    }

                    // --- NtDebugContinue (SSN 60): [DebugHandle, *AppClientId, ContinueStatus] ---
                    let mut client_id = [0u8; 16];
                    client_id[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                    client_id[8..16].copy_from_slice(&(main.unwrap_or(0) as u64).to_le_bytes());
                    let client_id_written = img_spawn::smss_copyout(A_CLIENT_ID, &client_id);
                    let continues_before = DBGK_CONTINUES.load(Ordering::Relaxed);
                    // 0x0020 — the handler read the CLIENT_ID out of client memory, rejected an
                    // illegal continue status and resolved the read event; its counter moved.
                    if client_id_written
                        && sysc!(SSN_NT_DEBUG_CONTINUE, &[dbg_handle, A_CLIENT_ID, 0x1234])
                            == ST_INVALID_PARAMETER
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                        && DBGK_CONTINUES.load(Ordering::Relaxed) == continues_before + 1
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        sc_ok |= 0x0020;
                    }

                    // 0x0100 — WAIT-PARK / WAKE-SIGNAL. With the queue drained and a NULL (=
                    // infinite) *Timeout the handler must PARK: it binds `wait_park_event` to the
                    // debug object's EventsPresent dispatcher event — the same field the service loop
                    // consumes to steal the caller's reply cap — and that event is NOT ready. A later
                    // queue-side post through the same dispatch route (attaching a second debuggee)
                    // SETS that very dispatcher event, which is exactly what the loop's wake path
                    // consumes, and the re-issued wait then returns the new event.
                    // HONEST SCOPE: the reply-cap steal + thread resume itself is NOT exercised —
                    // post-loop there is no live client blocked inside the syscall.
                    nt_handler.wait_park_event = -1;
                    nt_handler.wait_timeout = PendingWaitTimeout::none();
                    let park_status =
                        sysc!(SSN_NT_WAIT_FOR_DEBUG_EVENT, &[dbg_handle, 0, 0, A_STATE]);
                    let park_index = nt_handler.wait_park_event;
                    let parked = park_status == ST_TIMEOUT
                        && park_index >= 0
                        && park_index as u64 + 1 == host_event
                        && !nt_handler.dispatcher_ready(park_index as usize)
                        && nt_handler.wait_timeout.is_none();
                    nt_handler.wait_park_event = -1;
                    let target2 = nt_handler
                        .pm
                        .create_process("dbgk-syscall-b.exe", None, None);
                    nt_handler.pm.set_image_base(target2, 0x0000_0001_6000_0000);
                    let _ = nt_handler.pm.create_thread(target2, 0x2200, 0, false);
                    let target2_claim = nt_handler.claim_temporary_process_slot(target2, 0).ok();
                    let target2_registered = target2_claim.is_some();
                    let h_target2 = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(target2),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let woke = target2_registered
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target2, dbg_handle]) == 0
                        && park_index >= 0
                        && nt_handler.dispatcher_ready(park_index as usize);
                    let redriven = sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    ) == 0;
                    let mut sc2 = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];
                    let redriven_payload = img_spawn::smss_copyin(A_STATE, &mut sc2)
                        && u32::from_le_bytes(sc2[0..4].try_into().unwrap_or([0; 4]))
                            == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                        && u64::from_le_bytes(sc2[8..16].try_into().unwrap_or([0; 8]))
                            == target2 as u64;
                    if parked && woke && redriven && redriven_payload {
                        sc_ok |= 0x0100;
                    }
                    nt_handler.wait_park_event = -1;
                    nt_handler.wait_timeout = PendingWaitTimeout::none();

                    // --- NtRemoveProcessDebug (SSN 199): [ProcessHandle, DebugHandle] ------------
                    let detaches_before = DBGK_DETACHES.load(Ordering::Relaxed);
                    // 0x0040 — the detach ran IN THE HANDLER (its counter moved), cleared the port +
                    // BeingDebugged, and a second detach is STATUS_PORT_NOT_SET.
                    if sysc!(SSN_NT_REMOVE_PROCESS_DEBUG, &[h_target, dbg_handle]) == 0
                        && DBGK_DETACHES.load(Ordering::Relaxed) == detaches_before + 1
                        && nt_handler.pm.process_debug_port(target).is_none()
                        && !nt_handler.pm.is_process_being_debugged(target)
                        && sysc!(SSN_NT_REMOVE_PROCESS_DEBUG, &[h_target, dbg_handle])
                            == dbgk::STATUS_PORT_NOT_SET
                    {
                        sc_ok |= 0x0040;
                    }
                    // 0x0400 — NtClose (SSN 27) on the last debug-object handle, through the same
                    // dispatch route, runs DbgkpCloseObject: the object is destroyed and the
                    // STILL-ATTACHED second debuggee is detached.
                    let aux_closed = h_dbg_noaccess == 0
                        || (sysc!(SSN_NT_CLOSE, &[h_dbg_noaccess]) == 0
                            && nt_handler.pm.debug_object(object).is_some());
                    if nt_handler.pm.process_debug_port(target2) == Some(object)
                        && aux_closed
                        && sysc!(SSN_NT_CLOSE, &[dbg_handle]) == 0
                        && nt_handler.pm.debug_object(object).is_none()
                        && nt_handler.pm.process_debug_port(target2).is_none()
                    {
                        sc_ok |= 0x0400;
                    }

                    if let Some(claim) = target_claim {
                        let _ = nt_handler.release_temporary_process_slot(claim);
                    }
                    if let Some(claim) = target2_claim {
                        let _ = nt_handler.release_temporary_process_slot(claim);
                    }
                    for handle in [
                        h_target,
                        h_target2,
                        h_target_noaccess,
                        h_dbg_noaccess,
                        h_wrong_type,
                    ] {
                        if handle != 0 {
                            let _ = nt_handler
                                .pm
                                .close_handle(debugger_pid, handle as nt_process::Handle);
                        }
                    }
                }
            }

            crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.loop_ctx = saved_ctx;
            nt_handler.wait_park_event = -1;
            nt_handler.wait_timeout = PendingWaitTimeout::none();
            DBGK_SYSCALL_SELFTEST.store(sc_ok, Ordering::Relaxed);
        }

        // ═══ Dbgk EXCEPTION-FORWARDING self-test (post-loop) ═══════════════════════════════════
        // `DbgkForwardException` — the debug-event source the previous batch left DEFERRED and the
        // load-bearing one (without it a debugger cannot see a crash or an `int3`).
        //
        // WHAT IS DRIVEN FOR REAL: the debugger side goes through the REAL dispatch route
        // (`nt_dispatcher.dispatch(SSN, …)`, arguments marshalled in CLIENT memory) exactly as a
        // hosted process's syscalls do, and the DEBUGGEE side goes through
        // `ExecNtHandler::dbgk_forward_exception` — *the very entry the live fault path calls* at
        // its `#PF` / `#GP` / int3 classification sites (`dbgk_forward_exception!`). Nothing here
        // reimplements the forward: the throwaway debuggee is registered in a handler-owned
        // temporary slot, so the pi -> pid -> `EPROCESS.DebugPort` resolution the fault path
        // performs is the same resolution performed here.
        {
            use nt_process::dbgk;
            const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
            const THREAD_TERMINATE: u32 = 0x0001;
            const ST_TIMEOUT: u32 = 0x0000_0102;
            const ST_INVALID_PARAMETER: u32 = 0xC000_000D;
            const A_HANDLE: u64 = STACK_BASE + 0x180;
            const A_CLIENT_ID: u64 = STACK_BASE + 0x188;
            const A_TIMEOUT: u64 = STACK_BASE + 0x198;
            const A_STATE: u64 = STACK_BASE + 0x1A0;
            // Temporary slots for the throwaway debuggees are claimed from identities with no live
            // process/thread mechanism, VSpace, worker reservation, or registered client frames.

            let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
            let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
            let saved_pi = nt_handler.pi;
            let saved_tid = nt_handler.current_tid;
            let saved_ctx = nt_handler.loop_ctx;
            crate::executor::local().client_pi.store(0, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(SMSS_SCRATCH_BASE, Ordering::Relaxed);
            nt_handler.pi = 0;

            let mut ex_ok = 0u64;
            nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(0));
            let dbg_origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
            macro_rules! sysc {
                ($ssn:expr, $args:expr) => {
                    nt_dispatcher
                        .dispatch($ssn as u32, $args, &dbg_origin, &mut nt_handler)
                        .status
                };
            }
            // Read a field back out of the DBGUI_WAIT_STATE_CHANGE the handler copied to CLIENT
            // memory — the bytes ntdll's `DbgUiWaitStateChange` would receive.
            let mut sc = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];

            let debugger_pid = nt_handler.pm_pid_for_pi(0).unwrap_or(0);
            let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
            nt_handler.current_tid = debugger_tid as u64;
            let client_args_ready = img_spawn::smss_copyout(A_HANDLE, &[0u8; 0x100])
                && img_spawn::smss_copyout(A_TIMEOUT, &0i64.to_le_bytes());
            if debugger_pid != 0 && client_args_ready {
                // --- setup: a real debug object + an attached throwaway debuggee, all by SSN ----
                let created = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[
                        A_HANDLE,
                        dbgk::DEBUG_OBJECT_ALL_ACCESS as u64,
                        0,
                        dbgk::DBGK_KILL_PROCESS_ON_EXIT as u64,
                    ]
                );
                let dbg_handle = smss_stack_read(A_HANDLE);
                let object = match nt_handler
                    .pm
                    .lookup_handle(debugger_pid, dbg_handle as nt_process::Handle)
                {
                    Some(nt_process::HandleObject::DebugObject(object)) => Some(object),
                    _ => None,
                };
                let host_event = object
                    .and_then(|object| nt_handler.pm.debug_object(object))
                    .map(|o| o.host_event)
                    .unwrap_or(0);
                if let (0, Some(object)) = (created, object) {
                    let target = nt_handler
                        .pm
                        .create_process("dbgk-exception.exe", None, None);
                    nt_handler.pm.set_image_base(target, 0x0000_0001_7000_0000);
                    let main = nt_handler.pm.create_thread(target, 0x3100, 0, false).ok();
                    // A second thread so terminating one (the lifecycle poster below) does not
                    // signal the process and tear its handles down.
                    let worker = nt_handler.pm.create_thread(target, 0x3200, 0, false).ok();
                    let target_claim = nt_handler.claim_temporary_process_slot(target, 0).ok();
                    let exc_test_pi = target_claim
                        .map(TemporaryProcessSlotClaim::pi)
                        .unwrap_or(MAX_PI);
                    let target_registered = target_claim.is_some();
                    // A NEVER-attached process in the OTHER free slot: the live-boot shape, the
                    // control for the no-debugger gate.
                    let plain = nt_handler.pm.create_process("dbgk-plain.exe", None, None);
                    let _ = nt_handler.pm.create_thread(plain, 0x3300, 0, false);
                    let plain_claim = nt_handler.claim_temporary_process_slot(plain, 0).ok();
                    let exc_test_pi2 = plain_claim
                        .map(TemporaryProcessSlotClaim::pi)
                        .unwrap_or(MAX_PI);
                    let plain_registered = plain_claim.is_some();
                    let h_target = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(target),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let h_worker = worker
                        .and_then(|worker| {
                            nt_handler
                                .pm
                                .insert_handle(
                                    debugger_pid,
                                    nt_process::HandleObject::Thread(worker),
                                    THREAD_TERMINATE,
                                )
                                .ok()
                        })
                        .map(u64::from)
                        .unwrap_or(0);
                    // Attach, then DRAIN every attach-time fake create message (one
                    // DbgKmCreateProcessApi for the first thread + a DbgKmCreateThreadApi for each
                    // other one) so the queue is empty and the exception below is unambiguously the
                    // outstanding event. Each drain step reads the reported CLIENT_ID straight back
                    // out of the state change in CLIENT memory and continues that exact thread.
                    let attached = target_registered
                        && h_target != 0
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle]) == 0
                        && nt_handler.pm.process_debug_port(target) == Some(object);
                    let mut drained = 0u64;
                    while drained < 8
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) == 0
                    {
                        let mut reported = [0u8; 16];
                        if !img_spawn::smss_copyin(A_STATE, &mut sc) {
                            break;
                        }
                        reported[0..8].copy_from_slice(&sc[0x08..0x10]);
                        reported[8..16].copy_from_slice(&sc[0x10..0x18]);
                        if !img_spawn::smss_copyout(A_CLIENT_ID, &reported)
                            || sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) != 0
                        {
                            break;
                        }
                        drained += 1;
                    }
                    // From here on the CLIENT_ID in client memory is the debuggee's MAIN thread —
                    // the thread every forwarded exception below reports for.
                    let mut client_id = [0u8; 16];
                    client_id[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                    client_id[8..16].copy_from_slice(&(main.unwrap_or(0) as u64).to_le_bytes());
                    let client_id_written = img_spawn::smss_copyout(A_CLIENT_ID, &client_id);
                    // 0x0001 — attached through the REAL dispatch route, with both fake create
                    // messages (two live threads) retrieved and continued by SSN, leaving the queue
                    // empty.
                    if attached
                        && client_id_written
                        && drained == 2
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        ex_ok |= 0x0001;
                    }

                    // --- THE FORWARD: the exact entry the live fault path calls ----------------
                    // A REAL page fault's record: STATUS_ACCESS_VIOLATION at RIP 0x0000_0001_7000_4321
                    // writing 0x0000_0000_0000_0018 — the shape `dbgk_forward_exception!` builds at
                    // the loop's null-deref / vmf-out sites from (m0, m3, addr).
                    const EXC_IP: u64 = 0x0000_0001_7000_4321;
                    const EXC_ADDR: u64 = 0x18;
                    let forwarded_before = DBGK_EXCEPTIONS_FORWARDED.load(Ordering::Relaxed);
                    let forwarded = nt_handler.dbgk_forward_exception(
                        exc_test_pi,
                        main.unwrap_or(0) as u64,
                        dbgk::ExceptionRecord::access_violation(EXC_IP, 1, EXC_ADDR),
                        true,
                    );
                    // 0x0002 — the forward ran: it resolved pi → pid → DebugPort, queued exactly one
                    // DbgKmExceptionApi event and moved the counter.
                    if forwarded
                        && DBGK_EXCEPTIONS_FORWARDED.load(Ordering::Relaxed) == forwarded_before + 1
                        && nt_handler.pm.debug_object(object).is_some_and(|o| {
                            o.len() == 1
                                && o.events()[0].message.api_number() == dbgk::DBGKM_EXCEPTION_API
                        })
                    {
                        ex_ok |= 0x0002;
                    }

                    // 0x0004 — the debugger retrieves it through the REAL NtWaitForDebugEvent arm
                    // and the WHOLE record lands in CLIENT memory: DbgExceptionStateChange for the
                    // faulting CLIENT_ID, exception code / address / both MmAccessFault parameters
                    // / FirstChance.
                    let waits_before = DBGK_WAITS_SERVED.load(Ordering::Relaxed);
                    let wait = sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    );
                    let sc_read = img_spawn::smss_copyin(A_STATE, &mut sc);
                    // Macros, not closures: the state-change buffer is re-filled by each later
                    // `smss_copyin`, so nothing may hold a borrow of it across the checks.
                    macro_rules! sc_u32 {
                        ($o:expr) => {
                            u32::from_le_bytes(sc[$o..$o + 4].try_into().unwrap_or([0; 4]))
                        };
                    }
                    macro_rules! sc_u64 {
                        ($o:expr) => {
                            u64::from_le_bytes(sc[$o..$o + 8].try_into().unwrap_or([0; 8]))
                        };
                    }
                    if wait == 0
                        && sc_read
                        && DBGK_WAITS_SERVED.load(Ordering::Relaxed) == waits_before + 1
                        && sc_u32!(0x00) == dbgk::DBG_EXCEPTION_STATE_CHANGE
                        && sc_u64!(0x08) == target as u64
                        && main.is_some_and(|main| sc_u64!(0x10) == main as u64)
                        && sc_u32!(0x18) == dbgk::STATUS_ACCESS_VIOLATION
                        && sc_u64!(0x28) == EXC_IP
                        && sc_u32!(0x30) == 2
                        && sc_u64!(0x38) == 1
                        && sc_u64!(0x40) == EXC_ADDR
                        && sc_u32!(0xb0) == 1
                    {
                        ex_ok |= 0x0004;
                    }

                    // 0x0008 — NtDebugContinue resolves the EXCEPTION event: an illegal continue
                    // status is rejected, DBG_CONTINUE (read from the CLIENT_ID in client memory)
                    // succeeds, the handler counter moves and the queue drains.
                    let continues_before = DBGK_CONTINUES.load(Ordering::Relaxed);
                    if sysc!(SSN_NT_DEBUG_CONTINUE, &[dbg_handle, A_CLIENT_ID, 0x4321])
                        == ST_INVALID_PARAMETER
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                        && DBGK_CONTINUES.load(Ordering::Relaxed) == continues_before + 1
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        ex_ok |= 0x0008;
                    }

                    // 0x0010 — BREAKPOINT/trap refinement. An `int3` forwarded exactly as the
                    // label-4 fault site forwards it reports as DbgBreakpointStateChange (not a
                    // plain exception), and the trap-vector → NTSTATUS map the label-3 site uses is
                    // the one `KiDispatchException` reports.
                    const BP_IP: u64 = 0x0000_0001_7000_1005;
                    if nt_handler.dbgk_forward_exception(
                        exc_test_pi,
                        main.unwrap_or(0) as u64,
                        dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, BP_IP),
                        true,
                    ) && sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    ) == 0
                        && img_spawn::smss_copyin(A_STATE, &mut sc)
                        && sc_u32!(0x00) == dbgk::DBG_BREAKPOINT_STATE_CHANGE
                        && sc_u32!(0x18) == dbgk::STATUS_BREAKPOINT
                        && sc_u64!(0x28) == BP_IP
                        && dbgk::exception_code_for_trap(3) == dbgk::STATUS_BREAKPOINT
                        && dbgk::exception_code_for_trap(6) == dbgk::STATUS_ILLEGAL_INSTRUCTION
                        && dbgk::exception_code_for_trap(14) == dbgk::STATUS_ACCESS_VIOLATION
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                    {
                        ex_ok |= 0x0010;
                    }

                    // 0x0020 — ★ THE NO-DEBUGGER GATE, the safety property the whole fault-path
                    // integration rests on: forwarding for a process with NO EPROCESS.DebugPort
                    // returns false, moves no counter and queues nothing. This is what EVERY fault
                    // on the live boot takes, which is why the fault path is byte-identical.
                    let quiet_before = DBGK_EXCEPTIONS_FORWARDED.load(Ordering::Relaxed);
                    let queued_before = nt_handler
                        .pm
                        .debug_object(object)
                        .map(|o| o.len())
                        .unwrap_or(0);
                    if plain_registered
                        && !nt_handler.dbgk_forward_exception(
                            exc_test_pi2,
                            0,
                            dbgk::ExceptionRecord::access_violation(0x1000, 0, 0x40),
                            true,
                        )
                        && !nt_handler.pm.is_process_being_debugged(plain)
                        && DBGK_EXCEPTIONS_FORWARDED.load(Ordering::Relaxed) == quiet_before
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .map(|o| o.len())
                            .unwrap_or(0)
                            == queued_before
                    {
                        ex_ok |= 0x0020;
                    }

                    // 0x0040 — ★ THE SIGNAL FIX, fault-path poster. Park the debugger on the
                    // object's EventsPresent dispatcher event (empty queue + NULL = infinite
                    // *Timeout), then forward an exception through the FAULT-PATH entry — which is
                    // not a syscall at all. Before this batch only the five dbgk syscall arms
                    // mirrored the modelled signal, so this post would have left the dispatcher
                    // event CLEAR and never woken the parked debugger.
                    nt_handler.wait_park_event = -1;
                    nt_handler.wait_timeout = PendingWaitTimeout::none();
                    let park_status =
                        sysc!(SSN_NT_WAIT_FOR_DEBUG_EVENT, &[dbg_handle, 0, 0, A_STATE]);
                    let park_index = nt_handler.wait_park_event;
                    let parked = park_status == ST_TIMEOUT
                        && park_index >= 0
                        && park_index as u64 + 1 == host_event
                        && !nt_handler.dispatcher_ready(park_index as usize);
                    nt_handler.wait_park_event = -1;
                    const FAULT_IP: u64 = 0x0000_0001_7000_9999;
                    let woke = nt_handler.dbgk_forward_exception(
                        exc_test_pi,
                        main.unwrap_or(0) as u64,
                        dbgk::ExceptionRecord::access_violation(FAULT_IP, 0, 0x88),
                        false,
                    ) && park_index >= 0
                        && nt_handler.dispatcher_ready(park_index as usize);
                    if parked
                        && woke
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) == 0
                        && img_spawn::smss_copyin(A_STATE, &mut sc)
                        && sc_u32!(0x00) == dbgk::DBG_EXCEPTION_STATE_CHANGE
                        && sc_u64!(0x28) == FAULT_IP
                        // SecondChance ⇒ FirstChance == 0, carried through faithfully.
                        && sc_u32!(0xb0) == 0
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_EXCEPTION_NOT_HANDLED as u64]
                        ) == 0
                    {
                        ex_ok |= 0x0040;
                    }
                    nt_handler.wait_park_event = -1;
                    nt_handler.wait_timeout = PendingWaitTimeout::none();

                    // 0x0080 — ★ THE SIGNAL FIX, NON-DBGK SYSCALL poster. The same park, then
                    // NtTerminateThread (SSN 267) on one of the debuggee's threads: a LIFECYCLE
                    // event source whose handler arm never mirrored the debug signal before this
                    // batch (it is now covered because the mirror runs at the ONE chokepoint every
                    // service passes through). The dispatcher event must be SET and the re-issued
                    // wait must return that thread's DbgExitThreadStateChange.
                    let park2_status =
                        sysc!(SSN_NT_WAIT_FOR_DEBUG_EVENT, &[dbg_handle, 0, 0, A_STATE]);
                    let park2_index = nt_handler.wait_park_event;
                    let parked2 = park2_status == ST_TIMEOUT
                        && park2_index >= 0
                        && !nt_handler.dispatcher_ready(park2_index as usize);
                    nt_handler.wait_park_event = -1;
                    let mut worker_client = [0u8; 16];
                    worker_client[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                    worker_client[8..16]
                        .copy_from_slice(&(worker.unwrap_or(0) as u64).to_le_bytes());
                    if parked2
                        && h_worker != 0
                        && img_spawn::smss_copyout(A_CLIENT_ID, &worker_client)
                        && sysc!(SSN_NT_TERMINATE_THREAD, &[h_worker, 0x1234]) == 0
                        && park2_index >= 0
                        && nt_handler.dispatcher_ready(park2_index as usize)
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) == 0
                        && img_spawn::smss_copyin(A_STATE, &mut sc)
                        && sc_u32!(0x00) == dbgk::DBG_EXIT_THREAD_STATE_CHANGE
                        && worker.is_some_and(|worker| sc_u64!(0x10) == worker as u64)
                        && sc_u32!(0x18) == 0x1234
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                    {
                        ex_ok |= 0x0080;
                    }
                    nt_handler.wait_park_event = -1;
                    nt_handler.wait_timeout = PendingWaitTimeout::none();

                    if let Some(claim) = target_claim {
                        let _ = nt_handler.release_temporary_process_slot(claim);
                    }
                    if let Some(claim) = plain_claim {
                        let _ = nt_handler.release_temporary_process_slot(claim);
                    }
                    for handle in [h_target, h_worker] {
                        if handle != 0 {
                            let _ = nt_handler
                                .pm
                                .close_handle(debugger_pid, handle as nt_process::Handle);
                        }
                    }
                    // DbgkpCloseObject through the real NtClose arm — leaves no debug object alive,
                    // so the gate's post-spec state matches a plain boot.
                    let _ = sysc!(SSN_NT_CLOSE, &[dbg_handle]);
                }
            }

            crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.loop_ctx = saved_ctx;
            nt_handler.wait_park_event = -1;
            nt_handler.wait_timeout = PendingWaitTimeout::none();
            DBGK_EXCEPTION_SELFTEST.store(ex_ok, Ordering::Relaxed);
        }

        // ═══ Dbgk MODULE LOAD/UNLOAD self-test (post-loop) ═════════════════════════════════════
        // `DbgkMapViewOfSection` / `DbgkUnMapViewOfSection` + `DbgkpPostFakeModuleMessages` — the
        // last of the deferred debug-event sources.
        //
        // WHAT IS DRIVEN FOR REAL: the DEBUGGER side goes through the REAL dispatch route
        // (`nt_dispatcher.dispatch(SSN, …)` with the arguments marshalled in CLIENT memory), and the
        // DEBUGGEE side goes through `ExecNtHandler::dbgk_module_load` / `dbgk_module_unload` —
        // *the very entries the live `NtMapViewOfSection` SEC_IMAGE branch and the
        // `NtUnmapViewOfSection` arm call*. Nothing is reimplemented for the test: each throwaway
        // process sits in a handler-owned temporary slot, so the pi -> pid ->
        // `EPROCESS.DebugPort` resolution is the same one the mapping path performs.
        {
            use nt_process::dbgk;
            const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
            const FILE_GENERIC_READ: u32 = 0x0012_0089;
            // Client argument block — past the exception self-test's 0x180..0x280 window.
            const A_HANDLE: u64 = STACK_BASE + 0x280;
            const A_CLIENT_ID: u64 = STACK_BASE + 0x288;
            const A_TIMEOUT: u64 = STACK_BASE + 0x298;
            const A_STATE: u64 = STACK_BASE + 0x2A0;
            // Temporary identities are claimed dynamically so admitted hosted images cannot collide
            // with this integration-only debug plane.
            // The debuggee's own image base + the IMAGE views this test maps into it.
            const TARGET_IMAGE_BASE: u64 = 0x0000_0001_8000_0000;
            const DLL_BASE: u64 = 0x0000_0000_7100_0000;
            const NOT_AN_IMAGE_BASE: u64 = 0x0000_0000_7200_0000;
            const PLAIN_IMAGE_BASE: u64 = 0x0000_0001_9000_0000;
            const PLAIN_PROBE_BASE: u64 = 0x0000_0000_7300_0000;
            const PLAIN_DLL_A: u64 = 0x0000_0000_7400_0000;
            const PLAIN_DLL_B: u64 = 0x0000_0000_7500_0000;
            const NAME_POINTER: u64 = SMSS_TEB_VA + 0x28; // NtTib.ArbitraryUserPointer
            const DBG_INFO: (u32, u32) = (0x0000_1234, 0x0000_0056);

            let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
            let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
            let saved_pi = nt_handler.pi;
            let saved_tid = nt_handler.current_tid;
            let saved_ctx = nt_handler.loop_ctx;
            crate::executor::local().client_pi.store(0, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(SMSS_SCRATCH_BASE, Ordering::Relaxed);
            nt_handler.pi = 0;

            let mut md_ok = 0u64;
            nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(0));
            let dbg_origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
            macro_rules! sysc {
                ($ssn:expr, $args:expr) => {
                    nt_dispatcher
                        .dispatch($ssn as u32, $args, &dbg_origin, &mut nt_handler)
                        .status
                };
            }
            let mut sc = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];
            macro_rules! sc_u32 {
                ($o:expr) => {
                    u32::from_le_bytes(sc[$o..$o + 4].try_into().unwrap_or([0; 4]))
                };
            }
            macro_rules! sc_u64 {
                ($o:expr) => {
                    u64::from_le_bytes(sc[$o..$o + 8].try_into().unwrap_or([0; 8]))
                };
            }

            let debugger_pid = nt_handler.pm_pid_for_pi(0).unwrap_or(0);
            let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
            nt_handler.current_tid = debugger_tid as u64;
            let client_args_ready = img_spawn::smss_copyout(A_HANDLE, &[0u8; 0x100])
                && img_spawn::smss_copyout(A_TIMEOUT, &0i64.to_le_bytes());
            if debugger_pid != 0 && client_args_ready {
                let created = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[
                        A_HANDLE,
                        dbgk::DEBUG_OBJECT_ALL_ACCESS as u64,
                        0,
                        dbgk::DBGK_KILL_PROCESS_ON_EXIT as u64,
                    ]
                );
                let dbg_handle = smss_stack_read(A_HANDLE);
                let object = match nt_handler
                    .pm
                    .lookup_handle(debugger_pid, dbg_handle as nt_process::Handle)
                {
                    Some(nt_process::HandleObject::DebugObject(object)) => Some(object),
                    _ => None,
                };
                if let (0, Some(object)) = (created, object) {
                    // The DEBUGGED throwaway debuggee.
                    let target = nt_handler.pm.create_process("dbgk-module.exe", None, None);
                    nt_handler.pm.set_image_base(target, TARGET_IMAGE_BASE);
                    let main = nt_handler.pm.create_thread(target, 0x4100, 0, false).ok();
                    let target_claim = nt_handler.claim_temporary_process_slot(target, 0).ok();
                    let mod_test_pi = target_claim
                        .map(TemporaryProcessSlotClaim::pi)
                        .unwrap_or(MAX_PI);
                    let target_registered = target_claim.is_some();
                    // The NEVER-attached control — the live-boot shape, and later the subject of the
                    // attach-time fake-module proof.
                    let plain = nt_handler
                        .pm
                        .create_process("dbgk-modplain.exe", None, None);
                    nt_handler.pm.set_image_base(plain, PLAIN_IMAGE_BASE);
                    let plain_main = nt_handler.pm.create_thread(plain, 0x4200, 0, false).ok();
                    let plain_claim = nt_handler.claim_temporary_process_slot(plain, 0).ok();
                    let mod_test_pi2 = plain_claim
                        .map(TemporaryProcessSlotClaim::pi)
                        .unwrap_or(MAX_PI);
                    let plain_registered = plain_claim.is_some();
                    let h_target = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(target),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let h_plain = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(plain),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    // The DEBUGGEE's own handle to the image file — the thing `DbgkpOpenHandles`
                    // duplicates. A real per-process handle in the debuggee's own table.
                    let debuggee_file = nt_handler
                        .pm
                        .insert_handle(
                            target,
                            nt_process::HandleObject::File(0xF11E_0001),
                            FILE_GENERIC_READ,
                        )
                        .map(u64::from)
                        .unwrap_or(0);

                    // --- 0x0001 setup: attach + drain the fake create message, all by SSN --------
                    let attached = target_registered
                        && h_target != 0
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle]) == 0
                        && nt_handler.pm.process_debug_port(target) == Some(object);
                    let mut client_id = [0u8; 16];
                    client_id[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                    client_id[8..16].copy_from_slice(&(main.unwrap_or(0) as u64).to_le_bytes());
                    let client_id_written = img_spawn::smss_copyout(A_CLIENT_ID, &client_id);
                    if attached
                        && client_id_written
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) == 0
                        && img_spawn::smss_copyin(A_STATE, &mut sc)
                        && sc_u32!(0x00) == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        md_ok |= 0x0001;
                    }

                    // --- THE LOAD: the exact entry the live SEC_IMAGE map branch calls -----------
                    // On the live path the mapping thread is the caller, so report as the debuggee's
                    // thread (what `self.current_tid` holds inside a serviced syscall).
                    nt_handler.current_tid = main.unwrap_or(0) as u64;
                    let loads_before = DBGK_MODULE_LOADS.load(Ordering::Relaxed);
                    let loaded = nt_handler.dbgk_module_load(
                        mod_test_pi,
                        DLL_BASE,
                        debuggee_file,
                        DBG_INFO,
                        NAME_POINTER,
                    );
                    nt_handler.current_tid = debugger_tid as u64;
                    // 0x0002 — the map-path entry queued exactly one DbgKmLoadDllApi, moved the
                    // counter, and tracked the view as a module of the debuggee.
                    if loaded
                        && DBGK_MODULE_LOADS.load(Ordering::Relaxed) == loads_before + 1
                        && nt_handler.pm.module_count(target) == 1
                        && nt_handler.pm.debug_object(object).is_some_and(|o| {
                            o.len() == 1
                                && o.events()[0].message.api_number() == dbgk::DBGKM_LOAD_DLL_API
                        })
                    {
                        md_ok |= 0x0002;
                    }

                    // 0x0004 — the debugger retrieves it through the REAL NtWaitForDebugEvent arm
                    // and the WHOLE payload lands in CLIENT memory, with the image FILE handle
                    // DUPLICATED into the debugger's own table (`DbgkpOpenHandles`).
                    let waits_before = DBGK_WAITS_SERVED.load(Ordering::Relaxed);
                    let wait = sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    );
                    let sc_read = img_spawn::smss_copyin(A_STATE, &mut sc);
                    let reported_file = sc_u64!(0x18);
                    if wait == 0
                        && sc_read
                        && DBGK_WAITS_SERVED.load(Ordering::Relaxed) == waits_before + 1
                        && sc_u32!(0x00) == dbgk::DBG_LOAD_DLL_STATE_CHANGE
                        && sc_u64!(0x08) == target as u64
                        && main.is_some_and(|main| sc_u64!(0x10) == main as u64)
                        && sc_u64!(0x20) == DLL_BASE
                        && sc_u32!(0x28) == DBG_INFO.0
                        && sc_u32!(0x2c) == DBG_INFO.1
                        && sc_u64!(0x30) == NAME_POINTER
                        // The duplicate is a DIFFERENT handle value in the DEBUGGER's table naming
                        // the SAME file object, with DUPLICATE_SAME_ACCESS.
                        && debuggee_file != 0
                        && reported_file != 0
                        && reported_file != debuggee_file
                        && nt_handler
                            .pm
                            .lookup_handle(debugger_pid, reported_file as nt_process::Handle)
                            == Some(nt_process::HandleObject::File(0xF11E_0001))
                        && nt_handler
                            .pm
                            .handle_access(debugger_pid, reported_file as nt_process::Handle)
                            == Some(FILE_GENERIC_READ)
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                    {
                        md_ok |= 0x0004;
                    }
                    let _ = nt_handler
                        .pm
                        .close_handle(debugger_pid, reported_file as nt_process::Handle);

                    // --- THE UNLOAD: the exact entry the live NtUnmapViewOfSection arm calls -----
                    nt_handler.current_tid = main.unwrap_or(0) as u64;
                    let unloads_before = DBGK_MODULE_UNLOADS.load(Ordering::Relaxed);
                    let unloaded = nt_handler.dbgk_module_unload(mod_test_pi, DLL_BASE);
                    nt_handler.current_tid = debugger_tid as u64;
                    // 0x0008 — DbgKmUnloadDllApi posted, retrieved as DbgUnloadDllStateChange with
                    // the right base, and the view is no longer tracked.
                    if unloaded
                        && DBGK_MODULE_UNLOADS.load(Ordering::Relaxed) == unloads_before + 1
                        && nt_handler.pm.module_count(target) == 0
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) == 0
                        && img_spawn::smss_copyin(A_STATE, &mut sc)
                        && sc_u32!(0x00) == dbgk::DBG_UNLOAD_DLL_STATE_CHANGE
                        && sc_u64!(0x18) == DLL_BASE
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                    {
                        md_ok |= 0x0008;
                    }

                    // 0x0010 — IMAGE-ONLY. Unmapping a base that was never an IMAGE view (a data or
                    // anonymous mapping — the CSR shared section and the NLS section on the live
                    // boot) posts nothing: `MmUnmapViewOfSection` only calls
                    // `DbgkUnMapViewOfSection` when the VAD it tore down was an image VAD. Same for
                    // re-unmapping the view already unmapped above.
                    let quiet_unloads = DBGK_MODULE_UNLOADS.load(Ordering::Relaxed);
                    nt_handler.current_tid = main.unwrap_or(0) as u64;
                    let image_only = !nt_handler.dbgk_module_unload(mod_test_pi, NOT_AN_IMAGE_BASE)
                        && !nt_handler.dbgk_module_unload(mod_test_pi, DLL_BASE);
                    nt_handler.current_tid = debugger_tid as u64;
                    if image_only
                        && DBGK_MODULE_UNLOADS.load(Ordering::Relaxed) == quiet_unloads
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        md_ok |= 0x0010;
                    }

                    // 0x0020 — ★ THE NO-DEBUGGER GATE, the safety property the whole mapping-path
                    // integration rests on: a map AND an unmap in a process with NO
                    // `EPROCESS.DebugPort` both return false, move no counter and queue nothing.
                    // This is the path EVERY DLL map on the live boot takes (and with no debug
                    // object alive at all, `dbgk_module_load` returns on its FIRST line, before any
                    // lookup — which is the state of every boot today).
                    let quiet_loads = DBGK_MODULE_LOADS.load(Ordering::Relaxed);
                    let quiet_unloads = DBGK_MODULE_UNLOADS.load(Ordering::Relaxed);
                    let queued_before = nt_handler
                        .pm
                        .debug_object(object)
                        .map(|o| o.len())
                        .unwrap_or(0);
                    nt_handler.current_tid = plain_main.unwrap_or(0) as u64;
                    let gated = plain_registered
                        && !nt_handler.dbgk_module_load(
                            mod_test_pi2,
                            PLAIN_PROBE_BASE,
                            0,
                            DBG_INFO,
                            NAME_POINTER,
                        )
                        && !nt_handler.dbgk_module_unload(mod_test_pi2, PLAIN_PROBE_BASE);
                    nt_handler.current_tid = debugger_tid as u64;
                    if gated
                        && !nt_handler.pm.is_process_being_debugged(plain)
                        && DBGK_MODULE_LOADS.load(Ordering::Relaxed) == quiet_loads
                        && DBGK_MODULE_UNLOADS.load(Ordering::Relaxed) == quiet_unloads
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .map(|o| o.len())
                            .unwrap_or(0)
                            == queued_before
                    {
                        md_ok |= 0x0020;
                    }

                    // --- 0x0040 — ATTACH-TIME FAKE MODULE MESSAGES -------------------------------
                    // Two DLLs + the process's OWN image map into the still-UNDEBUGGED control
                    // process (nothing posts — proven by the counter staying put), and only THEN is
                    // a debugger attached. `DbgkpPostFakeModuleMessages` must report the two DLLs as
                    // fake `DbgKmLoadDllApi` messages AFTER the create-process message, attributed
                    // to the first thread, with the EXE's own view NOT re-reported.
                    nt_handler.current_tid = plain_main.unwrap_or(0) as u64;
                    let premapped_loads = DBGK_MODULE_LOADS.load(Ordering::Relaxed);
                    for base in [PLAIN_DLL_A, PLAIN_DLL_B, PLAIN_IMAGE_BASE] {
                        nt_handler.dbgk_module_load(mod_test_pi2, base, 0, DBG_INFO, NAME_POINTER);
                    }
                    nt_handler.current_tid = debugger_tid as u64;
                    let premapped = DBGK_MODULE_LOADS.load(Ordering::Relaxed) == premapped_loads
                        && nt_handler.pm.module_count(plain) == 3;
                    let fake_before = DBGK_FAKE_MESSAGES.load(Ordering::Relaxed);
                    let attach_plain = plain_registered
                        && h_plain != 0
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_plain, dbg_handle]) == 0;
                    if premapped
                        && attach_plain
                        // 1 create-process + 2 load-dll fake messages (the EXE view is skipped).
                        && DBGK_FAKE_MESSAGES.load(Ordering::Relaxed) == fake_before + 3
                        && nt_handler.pm.debug_object(object).is_some_and(|o| {
                            o.len() == 3
                                && o.events()[0].message.api_number()
                                    == dbgk::DBGKM_CREATE_PROCESS_API
                                && o.events()[1].message.api_number() == dbgk::DBGKM_LOAD_DLL_API
                                && o.events()[2].message.api_number() == dbgk::DBGKM_LOAD_DLL_API
                                // The module messages ride the FIRST reported thread's CLIENT_ID …
                                && plain_main.is_some_and(|first| {
                                    o.events()[1].client_id.unique_thread == first
                                        && o.events()[2].client_id.unique_thread == first
                                })
                                // … are NOWAIT backout events, and only the create-process one was
                                // activated by DbgkpSetProcessDebugObject.
                                && o.events()[1].flags & dbgk::DEBUG_EVENT_NOWAIT != 0
                                && !o.events()[0].is_inactive()
                                && o.events()[1].is_inactive()
                                && o.events()[2].is_inactive()
                        })
                    {
                        md_ok |= 0x0040;
                    }

                    // 0x0080 — each of the three is retrieved through the REAL NtWaitForDebugEvent
                    // arm, in order, and continued by SSN: create-process, then the two
                    // DbgLoadDllStateChanges carrying the bases that were mapped before the attach.
                    let mut plain_client = [0u8; 16];
                    plain_client[0..8].copy_from_slice(&(plain as u64).to_le_bytes());
                    plain_client[8..16]
                        .copy_from_slice(&(plain_main.unwrap_or(0) as u64).to_le_bytes());
                    let mut drained_ok = img_spawn::smss_copyout(A_CLIENT_ID, &plain_client);
                    for (state, base) in [
                        (dbgk::DBG_CREATE_PROCESS_STATE_CHANGE, PLAIN_IMAGE_BASE),
                        (dbgk::DBG_LOAD_DLL_STATE_CHANGE, PLAIN_DLL_A),
                        (dbgk::DBG_LOAD_DLL_STATE_CHANGE, PLAIN_DLL_B),
                    ] {
                        let reported_base_offset = if state == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                        {
                            0x38 // CreateProcessInfo.NewProcess.BaseOfImage
                        } else {
                            0x20 // LoadDll.BaseOfDll
                        };
                        drained_ok = drained_ok
                            && sysc!(
                                SSN_NT_WAIT_FOR_DEBUG_EVENT,
                                &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                            ) == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == state
                            && sc_u64!(0x08) == plain as u64
                            && sc_u64!(reported_base_offset) == base
                            && sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) == 0;
                    }
                    if drained_ok
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        md_ok |= 0x0080;
                    }

                    if let Some(claim) = target_claim {
                        let _ = nt_handler.release_temporary_process_slot(claim);
                    }
                    if let Some(claim) = plain_claim {
                        let _ = nt_handler.release_temporary_process_slot(claim);
                    }
                    for handle in [h_target, h_plain] {
                        if handle != 0 {
                            let _ = nt_handler
                                .pm
                                .close_handle(debugger_pid, handle as nt_process::Handle);
                        }
                    }
                    // DbgkpCloseObject through the real NtClose arm — no debug object survives the
                    // spec, so the gate's post-spec state matches a plain boot.
                    let _ = sysc!(SSN_NT_CLOSE, &[dbg_handle]);
                }
            }

            crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.loop_ctx = saved_ctx;
            nt_handler.wait_park_event = -1;
            nt_handler.wait_timeout = PendingWaitTimeout::none();
            DBGK_MODULE_SELFTEST.store(md_ok, Ordering::Relaxed);
        }

        // The hosted receive loop is finished and has no delay waiter outstanding. Disable timer 0
        // and unbind its notification so a stale HPET signal cannot intercept later self-test recvs.
        delay_timer_shutdown(&mut *delay_queue, &nt_handler);
        clear_service_delay_drain_context();

        // === Dbgk TARGET-SIDE BLOCKING SELF-TEST (POST-LOOP) — the keystone deferred item ==========
        //
        // NT blocks the REPORTING thread inside `DbgkpQueueMessage` until `NtDebugContinue` runs
        // `DbgkpWakeTarget`, then applies the continue status to it. Proving that needs something no
        // model call can give: a LIVE thread genuinely blocked in-kernel on the Call that delivered
        // its fault, whose reply capability the executive holds. So this test stands up a REAL
        // throwaway CLIENT THREAD (`selftests::dbgk_client_spawn` — a fresh VSpace + code page +
        // hosted-syscalls TCB + SC, the same machinery as the ALPC cross-VSpace proof) that takes ONE
        // FAULT OF EACH FLAVOUR in order, writing a progress MARKER between them. The executive reads
        // that marker through its own window on the client's shared frame, so "the reporter blocked"
        // and "the continue resumed it" are OBSERVED, not inferred.
        //
        // The DEBUGGER side runs through the REAL dispatch route (`nt_dispatcher.dispatch(SSN, …)`
        // with the arguments marshalled in smss's CLIENT memory, the established idiom); the TARGET
        // side runs through `dbgk_forward_exception` / `dbgk_module_load` / `dbgk_block_reporter` -
        // the very entries the live fault loop and the live `NtMapViewOfSection` arm call.
        // Throwaway-only: a temporary handler slot, fresh caps, all reclaimed afterwards.
        {
            use nt_process::dbgk;
            const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
            const A_HANDLE: u64 = STACK_BASE + 0x180;
            const A_CLIENT_ID: u64 = STACK_BASE + 0x188;
            const A_TIMEOUT: u64 = STACK_BASE + 0x198;
            const A_STATE: u64 = STACK_BASE + 0x1A0;
            const A_CONTEXT: u64 = STACK_BASE + 0x280;
            const AMD64_CONTEXT_FLAGS_OFFSET: u64 = 0x30;
            const AMD64_CONTEXT_EFLAGS_OFFSET: u64 = 0x44;
            const CONTEXT_AMD64_CONTROL: u32 = 0x0010_0000 | 0x0000_0001;
            const CONTEXT_AMD64_DEBUG_REGISTERS: u32 = 0x0010_0000 | 0x0000_0010;
            const EFLAGS_TF: u32 = 0x0000_0100;
            const BLK_TEST_RUNTIME_BADGE: u64 = 0xDB6B_0001;
            const BLK_DEBUGGER_RUNTIME_BADGE: u64 = 0xDB6B_0002;
            const _: () = assert!(nt_component_suspension::badge::valid_endpoint_badge(
                BLK_DEBUGGER_RUNTIME_BADGE
            ));
            // Executive scratch VAs inside the SAME proven-resident 2 MiB page table the ALPC
            // cross-VSpace self-test uses (see its comment): base + 3000*0x1000, PT index 5.
            let write_scratch_t = SMSS_SCRATCH_BASE + 3010 * 0x1000;
            let write_scratch_d = SMSS_SCRATCH_BASE + 3011 * 0x1000;
            let marker_win_t = SMSS_SCRATCH_BASE + 3012 * 0x1000;
            let marker_win_d = SMSS_SCRATCH_BASE + 3013 * 0x1000;

            let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
            let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
            let saved_pi = nt_handler.pi;
            let saved_tid = nt_handler.current_tid;
            let saved_ctx = nt_handler.loop_ctx;
            crate::executor::local().client_pi.store(0, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(SMSS_SCRATCH_BASE, Ordering::Relaxed);
            nt_handler.pi = 0;

            let mut bk_ok = 0u64;
            nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(0));
            let dbg_origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
            macro_rules! sysc {
                ($ssn:expr, $args:expr) => {
                    nt_dispatcher
                        .dispatch($ssn as u32, $args, &dbg_origin, &mut nt_handler)
                        .status
                };
            }
            let mut sc = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];
            macro_rules! sc_u32 {
                ($o:expr) => {
                    u32::from_le_bytes(sc[$o..$o + 4].try_into().unwrap())
                };
            }
            macro_rules! sc_u64 {
                ($o:expr) => {
                    u64::from_le_bytes(sc[$o..$o + 8].try_into().unwrap())
                };
            }

            let debugger_pid = nt_handler.pm_pid_for_pi(0).unwrap_or(0);
            let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
            nt_handler.current_tid = debugger_tid as u64;
            let client_args_ready = img_spawn::smss_copyout(A_HANDLE, &[0u8; 0x100])
                && img_spawn::smss_copyout(A_CONTEXT, &[0u8; nt_thread_start::AMD64_CONTEXT_SIZE])
                && img_spawn::smss_copyout(A_TIMEOUT, &0i64.to_le_bytes());

            // Throwaway caps: the client's shared marker frame, the `#PF` fixup frame, the reply
            // objects each fault is received on, and a spare reply object for the escape-hatch probe.
            let mut slots = [0u64; 96];
            let mut nslots = 0usize;
            let mut make = |kind: u64, bits: u32| -> u64 {
                let s = alloc_slot();
                slots[nslots] = s;
                nslots += 1;
                let made = untyped_retype_r(CAP_INIT_UNTYPED, kind, bits, 1, s);
                if made != 0 {
                    print_str(b"[dbgk-blk] retype FAILED kind=");
                    print_u64(kind);
                    print_str(b" status=");
                    print_u64(made);
                    print_str(b"\n");
                }
                s
            };
            let shared_t = make(OBJ_X86_4K_PAGE, PAGING_BITS);
            let shared_d = make(OBJ_X86_4K_PAGE, PAGING_BITS);
            let fixup_frame = make(OBJ_X86_4K_PAGE, PAGING_BITS);
            let reply_a = make(OBJ_REPLY, 0);
            let reply_hw = make(OBJ_REPLY, 0);
            let reply_b = make(OBJ_REPLY, 0);
            let reply_step = make(OBJ_REPLY, 0);
            let reply_c = make(OBJ_REPLY, 0);
            let reply_d = make(OBJ_REPLY, 0);
            let reply_spare = make(OBJ_REPLY, 0);
            let reply_debugger_done = make(OBJ_REPLY, 0);
            // NOTE the ORDER below: each marker frame is mapped into its CLIENT'S VSpace FIRST (by
            // `dbgk_client_spawn`) and only then windowed into the executive through a `copy_cap`.
            // A frame capability carries its own mapping, and mapping a COPY first leaves the
            // ORIGINAL's map attempt failing with `seL4_DeleteFirst` — which is exactly how the
            // ALPC cross-VSpace self-test orders its shared frames too.
            if debugger_pid != 0 && client_args_ready {
                // --- a real DEBUG_OBJECT, by SSN ---------------------------------------------
                let created = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[
                        A_HANDLE,
                        dbgk::DEBUG_OBJECT_ALL_ACCESS as u64,
                        0,
                        dbgk::DBGK_KILL_PROCESS_ON_EXIT as u64,
                    ]
                );
                let dbg_handle = smss_stack_read(A_HANDLE);
                let object = match nt_handler
                    .pm
                    .lookup_handle(debugger_pid, dbg_handle as nt_process::Handle)
                {
                    Some(nt_process::HandleObject::DebugObject(object)) => Some(object),
                    _ => None,
                };
                if let (0, Some(object)) = (created, object) {
                    // The debuggee EPROCESS standing for the throwaway CLIENT THREAD, in a free
                    // temporary slot so pi -> pid -> DebugPort resolution is the real one. A second
                    // thread keeps the process alive when the first is terminated by DBG_TERMINATE.
                    let target = nt_handler.pm.create_process("dbgk-block.exe", None, None);
                    nt_handler.pm.set_image_base(target, 0x0000_0001_9000_0000);
                    let main = nt_handler.pm.create_thread(target, 0x5100, 0, false).ok();
                    let keepalive = nt_handler.pm.create_thread(target, 0x5200, 0, false).ok();
                    let target_claim = nt_handler.claim_temporary_process_slot(target, 0).ok();
                    let blk_test_pi = target_claim
                        .map(TemporaryProcessSlotClaim::pi)
                        .unwrap_or(MAX_PI);
                    let target_registered = target_claim.is_some();
                    let main_tid = main.unwrap_or(0);
                    let h_target = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(target),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let mut client_id = [0u8; 16];
                    client_id[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                    client_id[8..16].copy_from_slice(&(main_tid as u64).to_le_bytes());
                    let cid_written = img_spawn::smss_copyout(A_CLIENT_ID, &client_id);

                    // --- THE LIVE CLIENT THREAD ---------------------------------------------
                    let code = selftests::dbgk_target_client_code();
                    let (client_pml4, client_tcb, client_ep) = selftests::dbgk_client_spawn(
                        &code,
                        shared_t,
                        write_scratch_t,
                        0,
                        &mut slots,
                        &mut nslots,
                    );
                    let client_runtime_registered = main_tid != 0
                        && nt_handler.register_hosted_thread_tcb(
                            blk_test_pi,
                            main_tid as u64,
                            client_tcb,
                            BLK_TEST_RUNTIME_BADGE,
                            HostedThreadRole::DbgkSelftestTarget,
                        );
                    // 0x0001 — setup: attach BY SSN + drain the fake create message BY SSN. The
                    // FIRST recv also proves the client thread really ran (marker 1) and really
                    // faulted (its `#PF` on the deliberately-unmapped page).
                    let attach_ok = target_registered
                        && h_target != 0
                        && cid_written
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle]) == 0
                        && nt_handler.pm.process_debug_port(target) == Some(object);
                    // `DbgkpPostFakeProcessCreateMessages` posts one message per live thread — a
                    // `DbgKmCreateProcessApi` for the first and a `DbgKmCreateThreadApi` for the
                    // keep-alive one — so drain BOTH (each continued with ITS OWN CLIENT_ID) and
                    // leave the queue genuinely empty before the client's first fault is reported.
                    let mut drained = 0u64;
                    let mut first_state = 0u32;
                    let mut debuggee_thread_handle = 0u64;
                    while attach_ok && drained < 8 {
                        if sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) != 0
                            || !img_spawn::smss_copyin(A_STATE, &mut sc)
                        {
                            break;
                        }
                        if drained == 0 {
                            first_state = sc_u32!(0x00);
                            debuggee_thread_handle = sc_u64!(0x20);
                        }
                        let mut cid = [0u8; 16];
                        cid[0..8].copy_from_slice(&sc[0x08..0x10]);
                        cid[8..16].copy_from_slice(&sc[0x10..0x18]);
                        if !img_spawn::smss_copyout(A_CLIENT_ID, &cid)
                            || sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) != 0
                        {
                            break;
                        }
                        drained += 1;
                    }
                    // Restore the reporting thread's CLIENT_ID for the blocking continues below.
                    let cid_restored = img_spawn::smss_copyout(A_CLIENT_ID, &client_id);
                    let attached = attach_ok
                        && cid_restored
                        && drained == 2
                        && first_state == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty());
                    // ═══ FAULT 1 — VMFault (`#PF`), the flavour every page fault takes ═══════
                    // The executive's own window on the client's marker page (a copy_cap of the
                    // SAME physical frame the client writes — mapped only now that the client's own
                    // mapping is in place).
                    let win_t = {
                        let s = copy_cap(shared_t);
                        slots[nslots] = s;
                        nslots += 1;
                        s
                    };
                    let win_t_ok =
                        page_map_r(win_t, marker_win_t, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
                    let marker_t = || {
                        if win_t_ok {
                            core::ptr::read_volatile(marker_win_t as *const u64)
                        } else {
                            u64::MAX
                        }
                    };
                    // ★ Every stage below is GUARDED. A blocking `recv` on the client's endpoint is
                    // only ever issued once the previous continue is KNOWN to have resumed it, and
                    // any failure breaks out with the bits collected so far — a self-test that could
                    // block forever would be a boot wedge, which is exactly what this batch must not
                    // introduce. `loop { … break }` gives the early exits.
                    loop {
                        // ═══ FAULT 1 — VMFault (`#PF`), the flavour every page fault takes ═══
                        // The throwaway TCB can deliver an initial scheduler/startup fault before
                        // the target code reaches its marker write. That event is not the debuggee
                        // report this proof is about and, as a plain startup notification, does not
                        // leave `reply_a` bound to a blocked caller. Select the VMFault on FIXUP
                        // before parking the reporter so the later continue never replies to an
                        // unbound synthetic event.
                        let mut f1 = None;
                        let mut f1_guard = 0;
                        while f1_guard < 4 {
                            f1_guard += 1;
                            let (_fb, mi_r, m0_r, m1_r, _f1m2, _f1m3) =
                                recv_full_r12(client_ep, reply_a);
                            if (mi_r >> 12) == 6
                                && m1_r == selftests::DBGK_CLIENT_FIXUP
                                && marker_t() == 1
                            {
                                f1 = Some((mi_r, m0_r, m1_r));
                                dbgk_blk_trace(b"f1", mi_r, m0_r, m1_r, marker_t());
                                break;
                            }
                            dbgk_blk_trace(b"f1-foreign", mi_r, m0_r, m1_r, marker_t());
                        }
                        let Some((_f1_mi, f1_m0, f1_m1)) = f1 else {
                            break;
                        };
                        if attached && client_pml4 != 0 {
                            bk_ok |= 0x0001;
                        }
                        // 0x0002 — ★ THE BLOCK. Forward the fault through the entry the live loop
                        // uses, then PARK the reporting thread on the event it just queued.
                        // Observable: the block rides on the DEBUG_EVENT, the counter moves, and the
                        // client has NOT progressed (marker still 1) while the debugger holds it.
                        let blocked_before = DBGK_REPORTERS_BLOCKED.load(Ordering::Relaxed);
                        let forwarded = nt_handler.dbgk_forward_exception(
                            blk_test_pi,
                            main_tid as u64,
                            dbgk::ExceptionRecord::access_violation(f1_m0, 1, f1_m1),
                            true,
                        );
                        let parked = nt_handler.dbgk_block_reporter(
                            blk_test_pi,
                            main_tid as u64,
                            0,
                            dbgk::DBGK_BLOCK_VM_FAULT,
                            reply_a,
                            f1_m0,
                            0,
                            0,
                            0,
                        );
                        dbgk_blk_trace(
                            b"blk1",
                            0,
                            forwarded as u64,
                            parked as u64,
                            nt_handler.pm.blocked_reporter_count(object) as u64,
                        );
                        let no_progress1 = forwarded
                            && parked
                            && DBGK_REPORTERS_BLOCKED.load(Ordering::Relaxed) == blocked_before + 1
                            && nt_handler.pm.blocked_reporter_count(object) == 1
                            && marker_t() == 1;
                        if no_progress1 {
                            bk_ok |= 0x0002;
                        }
                        if !parked {
                            break; // nothing holds the client's reply cap — never recv again
                        }
                        // 0x0200 — real hardware breakpoint context path. Arm DR0 against the
                        // target's next `int3` address while the thread is parked on the page fault.
                        // Continuing the page fault should run marker 2 and then trap with a seL4
                        // instruction-breakpoint DebugException before the software int3 executes.
                        let hw_breakpoint_ip =
                            selftests::DBGK_CLIENT_CODE + selftests::DBGK_TARGET_INT3_OFFSET;
                        let hw_dr7 = nt_thread_start::AMD64_DR7_RESERVED_ONE | 1;
                        let hw_context_written = no_progress1
                            && client_runtime_registered
                            && debuggee_thread_handle != 0
                            && img_spawn::smss_copyout(
                                A_CONTEXT,
                                &[0u8; nt_thread_start::AMD64_CONTEXT_SIZE],
                            )
                            && img_spawn::smss_copyout(
                                A_CONTEXT + AMD64_CONTEXT_FLAGS_OFFSET,
                                &CONTEXT_AMD64_DEBUG_REGISTERS.to_le_bytes(),
                            )
                            && img_spawn::smss_copyout(
                                A_CONTEXT + nt_thread_start::CONTEXT_DR0_OFFSET,
                                &hw_breakpoint_ip.to_le_bytes(),
                            )
                            && img_spawn::smss_copyout(
                                A_CONTEXT + nt_thread_start::CONTEXT_DR7_OFFSET,
                                &hw_dr7.to_le_bytes(),
                            );
                        let setctx_hw = if hw_context_written {
                            sysc!(
                                SSN_NT_SET_CONTEXT_THREAD,
                                &[debuggee_thread_handle, A_CONTEXT]
                            )
                        } else {
                            u32::MAX
                        };
                        let getctx_hw_ready = setctx_hw == 0
                            && img_spawn::smss_copyout(
                                A_CONTEXT,
                                &[0u8; nt_thread_start::AMD64_CONTEXT_SIZE],
                            )
                            && img_spawn::smss_copyout(
                                A_CONTEXT + AMD64_CONTEXT_FLAGS_OFFSET,
                                &CONTEXT_AMD64_DEBUG_REGISTERS.to_le_bytes(),
                            );
                        let getctx_hw = if getctx_hw_ready {
                            sysc!(
                                SSN_NT_GET_CONTEXT_THREAD,
                                &[debuggee_thread_handle, A_CONTEXT]
                            )
                        } else {
                            u32::MAX
                        };
                        let mut hw_dr0_buf = [0u8; 8];
                        let mut hw_dr7_buf = [0u8; 8];
                        let hw_breakpoint_armed = getctx_hw == 0
                            && img_spawn::smss_copyin(
                                A_CONTEXT + nt_thread_start::CONTEXT_DR0_OFFSET,
                                &mut hw_dr0_buf,
                            )
                            && img_spawn::smss_copyin(
                                A_CONTEXT + nt_thread_start::CONTEXT_DR7_OFFSET,
                                &mut hw_dr7_buf,
                            )
                            && u64::from_le_bytes(hw_dr0_buf) == hw_breakpoint_ip
                            && u64::from_le_bytes(hw_dr7_buf) == hw_dr7;
                        // 0x0004 — ★ THE CONTINUE RESUMES IT. The debugger retrieves the exception,
                        // maps the page the client faulted on (a real debugger's fixup), and
                        // continues: `DbgkpWakeTarget` replies with the VMFault shape (length 0, no
                        // register transfer) so the faulting instruction is RETRIED — and now
                        // succeeds. Proof it resumed AND continued: its NEXT fault arrives with
                        // marker 2, i.e. the instruction after the `#PF` really executed.
                        let mapped = page_map_r(
                            fixup_frame,
                            selftests::DBGK_CLIENT_FIXUP,
                            RW_NX,
                            client_pml4,
                        ) == 0;
                        let resumed_before = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                        let wait1 = sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        );
                        let read1 = wait1 == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == dbgk::DBG_EXCEPTION_STATE_CHANGE;
                        let cont1 = if read1 {
                            sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            )
                        } else {
                            u32::MAX
                        };
                        let woke1 =
                            DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed) == resumed_before + 1;
                        dbgk_blk_trace(b"c1", 0, wait1 as u64, cont1 as u64, woke1 as u64);
                        if !woke1 {
                            // The reporter was never resumed — release it so nothing is stranded,
                            // and do NOT recv (the client can no longer produce an event).
                            let _ = nt_handler.dbgk_release_all_blocked_reporters();
                            break;
                        }
                        if hw_breakpoint_armed {
                            let (_fb, f2hw_mi, f2hw_m0, f2hw_m1, f2hw_m2, f2hw_m3) =
                                recv_full_r12(client_ep, reply_hw);
                            dbgk_blk_trace(b"f2hw", f2hw_mi, f2hw_m0, f2hw_m1, marker_t());
                            let hw_fault = mapped
                                && read1
                                && cont1 == 0
                                && (f2hw_mi >> 12) == 4
                                && f2hw_m0 == hw_breakpoint_ip
                                && f2hw_m1 == dbgk::SEL4_DEBUG_REASON_INSTRUCTION_BREAKPOINT
                                && f2hw_m2 == hw_breakpoint_ip
                                && f2hw_m3 == 0
                                && marker_t() == 2;
                            let forwarded_hw = hw_fault
                                && nt_handler.dbgk_forward_exception(
                                    blk_test_pi,
                                    main_tid as u64,
                                    dbgk::ExceptionRecord::new(dbgk::STATUS_SINGLE_STEP, f2hw_m0),
                                    true,
                                );
                            let blocked_hw = forwarded_hw
                                && nt_handler.dbgk_block_reporter(
                                    blk_test_pi,
                                    main_tid as u64,
                                    0,
                                    dbgk::DBGK_BLOCK_DEBUG_EXCEPTION,
                                    reply_hw,
                                    f2hw_m0,
                                    f2hw_m2,
                                    f2hw_m3,
                                    0,
                                );
                            let no_progress_hw = blocked_hw
                                && nt_handler.pm.blocked_reporter_count(object) == 1
                                && marker_t() == 2;
                            let resumed_before_hw = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                            let wait_hw = if blocked_hw {
                                sysc!(
                                    SSN_NT_WAIT_FOR_DEBUG_EVENT,
                                    &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                                )
                            } else {
                                u32::MAX
                            };
                            let read_hw = wait_hw == 0
                                && img_spawn::smss_copyin(A_STATE, &mut sc)
                                && sc_u32!(0x00) == dbgk::DBG_SINGLE_STEP_STATE_CHANGE;
                            let clear_hw_context_written = read_hw
                                && img_spawn::smss_copyout(
                                    A_CONTEXT,
                                    &[0u8; nt_thread_start::AMD64_CONTEXT_SIZE],
                                )
                                && img_spawn::smss_copyout(
                                    A_CONTEXT + AMD64_CONTEXT_FLAGS_OFFSET,
                                    &CONTEXT_AMD64_DEBUG_REGISTERS.to_le_bytes(),
                                );
                            let setctx_hw_clear = if clear_hw_context_written {
                                sysc!(
                                    SSN_NT_SET_CONTEXT_THREAD,
                                    &[debuggee_thread_handle, A_CONTEXT]
                                )
                            } else {
                                u32::MAX
                            };
                            let getctx_hw_clear_ready = setctx_hw_clear == 0
                                && img_spawn::smss_copyout(
                                    A_CONTEXT,
                                    &[0u8; nt_thread_start::AMD64_CONTEXT_SIZE],
                                )
                                && img_spawn::smss_copyout(
                                    A_CONTEXT + AMD64_CONTEXT_FLAGS_OFFSET,
                                    &CONTEXT_AMD64_DEBUG_REGISTERS.to_le_bytes(),
                                );
                            let getctx_hw_clear = if getctx_hw_clear_ready {
                                sysc!(
                                    SSN_NT_GET_CONTEXT_THREAD,
                                    &[debuggee_thread_handle, A_CONTEXT]
                                )
                            } else {
                                u32::MAX
                            };
                            let mut hw_clear_dr7_buf = [0u8; 8];
                            let hw_breakpoint_cleared = getctx_hw_clear == 0
                                && img_spawn::smss_copyin(
                                    A_CONTEXT + nt_thread_start::CONTEXT_DR7_OFFSET,
                                    &mut hw_clear_dr7_buf,
                                )
                                && u64::from_le_bytes(hw_clear_dr7_buf)
                                    == nt_thread_start::AMD64_DR7_RESERVED_ONE;
                            let cont_hw =
                                if read_hw && setctx_hw_clear == 0 && hw_breakpoint_cleared {
                                    sysc!(
                                        SSN_NT_DEBUG_CONTINUE,
                                        &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                                    )
                                } else {
                                    u32::MAX
                                };
                            let woke_hw = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed)
                                == resumed_before_hw + 1;
                            dbgk_blk_trace(
                                b"c2hw",
                                no_progress_hw as u64,
                                wait_hw as u64,
                                cont_hw as u64,
                                woke_hw as u64,
                            );
                            if hw_fault
                                && no_progress_hw
                                && read_hw
                                && hw_breakpoint_cleared
                                && cont_hw == 0
                                && woke_hw
                            {
                                bk_ok |= 0x0200;
                            }
                            if !woke_hw {
                                let _ = crate::win32k_glue::tcb_unset_breakpoint(client_tcb, 0);
                                if !blocked_hw {
                                    client_reply_on(reply_hw, 0, 0, 0, 0, 0);
                                }
                                let _ = nt_handler.dbgk_release_all_blocked_reporters();
                                break;
                            }
                        }
                        // ═══ FAULT 2 — DebugException (int3) ══════════════════════════════
                        let (_fb, f2_mi, f2_m0, f2_m1, _f2m2, _f2m3) =
                            recv_full_r12(client_ep, reply_b);
                        dbgk_blk_trace(b"f2", f2_mi, f2_m0, f2_m1, marker_t());
                        if mapped
                            && read1
                            && cont1 == 0
                            && nt_handler.pm.blocked_reporter_count(object) == 0
                            && (f2_mi >> 12) == 4
                            && f2_m1 == dbgk::SEL4_DEBUG_REASON_SOFTWARE_BREAK_REQUEST
                            && marker_t() == 2
                        {
                            bk_ok |= 0x0004;
                        }
                        // 0x0008 — the DebugException flavour: forward the int3, BLOCK its reporter,
                        // prove no progress, then let the debugger edit the real target context
                        // before continuing it.
                        let forwarded2 = nt_handler.dbgk_forward_exception(
                            blk_test_pi,
                            main_tid as u64,
                            dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, f2_m0),
                            true,
                        );
                        let blocked2 = nt_handler.dbgk_block_reporter(
                            blk_test_pi,
                            main_tid as u64,
                            0,
                            dbgk::DBGK_BLOCK_DEBUG_EXCEPTION,
                            reply_b,
                            f2_m0,
                            0,
                            0,
                            0,
                        );
                        let no_progress2 = forwarded2
                            && blocked2
                            && nt_handler.pm.blocked_reporter_count(object) == 1
                            && marker_t() == 2;
                        if !blocked2 {
                            break;
                        }
                        let resumed_before = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                        let wait2 = sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        );
                        let read2 = wait2 == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == dbgk::DBG_BREAKPOINT_STATE_CHANGE;
                        let tf_flags_written = read2
                            && no_progress2
                            && client_runtime_registered
                            && debuggee_thread_handle != 0
                            && img_spawn::smss_copyout(
                                A_CONTEXT + AMD64_CONTEXT_FLAGS_OFFSET,
                                &CONTEXT_AMD64_CONTROL.to_le_bytes(),
                            );
                        let getctx_tf = if tf_flags_written {
                            sysc!(
                                SSN_NT_GET_CONTEXT_THREAD,
                                &[debuggee_thread_handle, A_CONTEXT]
                            )
                        } else {
                            u32::MAX
                        };
                        let mut eflags_buf = [0u8; 4];
                        let eflags_read = getctx_tf == 0
                            && img_spawn::smss_copyin(
                                A_CONTEXT + AMD64_CONTEXT_EFLAGS_OFFSET,
                                &mut eflags_buf,
                            );
                        let original_eflags = if eflags_read {
                            u32::from_le_bytes(eflags_buf)
                        } else {
                            0
                        };
                        let tf_eflags = original_eflags | EFLAGS_TF;
                        let tf_eflags_written = eflags_read
                            && img_spawn::smss_copyout(
                                A_CONTEXT + AMD64_CONTEXT_EFLAGS_OFFSET,
                                &tf_eflags.to_le_bytes(),
                            );
                        let setctx_tf = if tf_eflags_written {
                            sysc!(
                                SSN_NT_SET_CONTEXT_THREAD,
                                &[debuggee_thread_handle, A_CONTEXT]
                            )
                        } else {
                            u32::MAX
                        };
                        let cont2 = if read2 && setctx_tf == 0 {
                            sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            )
                        } else {
                            u32::MAX
                        };
                        let woke2 =
                            DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed) == resumed_before + 1;
                        dbgk_blk_trace(
                            b"c2",
                            no_progress2 as u64,
                            wait2 as u64,
                            cont2 as u64,
                            woke2 as u64,
                        );
                        if !woke2 {
                            let _ = nt_handler.dbgk_release_all_blocked_reporters();
                            break;
                        }
                        // 0x0010 — context edit proof. The debugger-set TF must produce a real
                        // single-step `#DB` after the one-byte nop, before marker 3 is written.
                        let (_fb, f2s_mi, f2s_m0, f2s_m1, _f2s_m2, _f2s_m3) =
                            recv_full_r12(client_ep, reply_step);
                        dbgk_blk_trace(b"f2s", f2s_mi, f2s_m0, f2s_m1, marker_t());
                        let step_fault = no_progress2
                            && cont2 == 0
                            && setctx_tf == 0
                            && (f2s_mi >> 12) == 4
                            && f2s_m1 == dbgk::SEL4_DEBUG_REASON_SINGLE_STEP
                            && marker_t() == 2;
                        let forwarded_step = step_fault
                            && nt_handler.dbgk_forward_exception(
                                blk_test_pi,
                                main_tid as u64,
                                dbgk::ExceptionRecord::new(dbgk::STATUS_SINGLE_STEP, f2s_m0),
                                true,
                            );
                        let blocked_step = forwarded_step
                            && nt_handler.dbgk_block_reporter(
                                blk_test_pi,
                                main_tid as u64,
                                0,
                                dbgk::DBGK_BLOCK_DEBUG_EXCEPTION,
                                reply_step,
                                f2s_m0,
                                0,
                                0,
                                0,
                            );
                        let no_progress_step = blocked_step
                            && nt_handler.pm.blocked_reporter_count(object) == 1
                            && marker_t() == 2;
                        let resumed_before_step = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                        let wait_step = if blocked_step {
                            sysc!(
                                SSN_NT_WAIT_FOR_DEBUG_EVENT,
                                &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                            )
                        } else {
                            u32::MAX
                        };
                        let read_step = wait_step == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == dbgk::DBG_SINGLE_STEP_STATE_CHANGE;
                        let clear_flags_written = read_step
                            && img_spawn::smss_copyout(
                                A_CONTEXT + AMD64_CONTEXT_FLAGS_OFFSET,
                                &CONTEXT_AMD64_CONTROL.to_le_bytes(),
                            );
                        let getctx_clear = if clear_flags_written {
                            sysc!(
                                SSN_NT_GET_CONTEXT_THREAD,
                                &[debuggee_thread_handle, A_CONTEXT]
                            )
                        } else {
                            u32::MAX
                        };
                        let mut clear_buf = [0u8; 4];
                        let clear_read = getctx_clear == 0
                            && img_spawn::smss_copyin(
                                A_CONTEXT + AMD64_CONTEXT_EFLAGS_OFFSET,
                                &mut clear_buf,
                            );
                        let clear_eflags = if clear_read {
                            u32::from_le_bytes(clear_buf) & !EFLAGS_TF
                        } else {
                            0
                        };
                        let clear_written = clear_read
                            && img_spawn::smss_copyout(
                                A_CONTEXT + AMD64_CONTEXT_EFLAGS_OFFSET,
                                &clear_eflags.to_le_bytes(),
                            );
                        let setctx_clear = if clear_written {
                            sysc!(
                                SSN_NT_SET_CONTEXT_THREAD,
                                &[debuggee_thread_handle, A_CONTEXT]
                            )
                        } else {
                            u32::MAX
                        };
                        let cont_step = if read_step && setctx_clear == 0 {
                            sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            )
                        } else {
                            u32::MAX
                        };
                        let woke_step = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed)
                            == resumed_before_step + 1;
                        dbgk_blk_trace(
                            b"c2s",
                            no_progress_step as u64,
                            wait_step as u64,
                            cont_step as u64,
                            woke_step as u64,
                        );
                        if step_fault
                            && no_progress_step
                            && read_step
                            && setctx_clear == 0
                            && cont_step == 0
                            && woke_step
                        {
                            bk_ok |= 0x0010;
                        }
                        if !woke_step {
                            let _ = nt_handler.dbgk_release_all_blocked_reporters();
                            break;
                        }
                        // ═══ FAULT 3 — UnknownSyscall: the SYSCALL flavour ═══════════════
                        let (_fb, f3_mi, f3_m0, _f3_m1, f3_m2, _f3_m3) =
                            recv_full_r12(client_ep, reply_c);
                        // The service loop's own derivation: for an UnknownSyscall the resume IP is
                        // RCX (MR2) — the address `syscall` pushed — NOT the message's FaultIP slot.
                        let f3_ip = f3_m2;
                        let f3_sp = get_recv_mr(16);
                        let f3_flags = get_recv_mr(17);
                        dbgk_blk_trace(b"f3", f3_mi, f3_m0, 0, marker_t());
                        if no_progress2
                            && cont2 == 0
                            && woke_step
                            && (f3_mi >> 12) == 2
                            && f3_m0 == 0xDB
                            && marker_t() == 3
                        {
                            bk_ok |= 0x0008;
                        }
                        // 0x0020 — the SYSCALL flavour. A real `DbgkMapViewOfSection` load-dll event
                        // posted from a SYSCALL blocks its reporter (NT queues it with flags 0), and
                        // DBG_CONTINUE supplies only status in MR0, preserving the canonical
                        // continuation so the syscall returns and the client runs on.
                        nt_handler.current_tid = main_tid as u64;
                        let module_posted = nt_handler.dbgk_module_load(
                            blk_test_pi,
                            0x0000_0001_9100_0000,
                            0,
                            (0, 0),
                            0,
                        );
                        nt_handler.current_tid = debugger_tid as u64;
                        nt_handler.dbgk_block_request = false;
                        let blocked3 = nt_handler.dbgk_block_reporter(
                            blk_test_pi,
                            main_tid as u64,
                            0,
                            dbgk::DBGK_BLOCK_SYSCALL,
                            reply_c,
                            f3_ip,
                            f3_sp,
                            f3_flags,
                            0,
                        );
                        let no_progress3 = module_posted && blocked3 && marker_t() == 3;
                        if !blocked3 {
                            break;
                        }
                        let resumed_before = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                        let wait3 = sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        );
                        let read3 = wait3 == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == dbgk::DBG_LOAD_DLL_STATE_CHANGE;
                        let cont3 = if read3 {
                            sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            )
                        } else {
                            u32::MAX
                        };
                        let woke3 =
                            DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed) == resumed_before + 1;
                        dbgk_blk_trace(
                            b"c3",
                            no_progress3 as u64,
                            wait3 as u64,
                            cont3 as u64,
                            woke3 as u64,
                        );
                        if !woke3 {
                            let _ = nt_handler.dbgk_release_all_blocked_reporters();
                            break;
                        }
                        // ═══ FAULT 4 — UserException (`ud2`) ════════════════════════════
                        let (_fb, f4_mi, f4_m0, f4_m1, f4_m2, _f4m3) =
                            recv_full_r12(client_ep, reply_d);
                        dbgk_blk_trace(b"f4", f4_mi, f4_m0, 0, marker_t());
                        if no_progress3 && cont3 == 0 && (f4_mi >> 12) == 3 && marker_t() == 4 {
                            bk_ok |= 0x0020;
                        }
                        // 0x0040 — ★ DBG_TERMINATE_THREAD **ENFORCED**. Block the `ud2` reporter,
                        // then continue with DBG_TERMINATE_THREAD: the reporting ETHREAD is really
                        // terminated and it is NEVER resumed — the marker stays 4, i.e. the
                        // instruction after the `ud2` never executed. (Before this batch the status
                        // was recorded, not enforced.)
                        let forwarded4 = nt_handler.dbgk_forward_exception(
                            blk_test_pi,
                            main_tid as u64,
                            dbgk::ExceptionRecord::new(0xC000_001D, f4_m0),
                            true,
                        );
                        let blocked4 = nt_handler.dbgk_block_reporter(
                            blk_test_pi,
                            main_tid as u64,
                            0,
                            dbgk::DBGK_BLOCK_USER_EXCEPTION,
                            reply_d,
                            f4_m0,
                            f4_m1,
                            f4_m2,
                            0,
                        );
                        let terms_before = DBGK_TERMINATES_ENFORCED.load(Ordering::Relaxed);
                        let resumed_before = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                        let wait4 = sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        );
                        let terminated = forwarded4
                            && blocked4
                            && wait4 == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == dbgk::DBG_EXCEPTION_STATE_CHANGE
                            && sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_TERMINATE_THREAD as u64]
                            ) == 0;
                        dbgk_blk_trace(
                            b"term",
                            terminated as u64,
                            DBGK_TERMINATES_ENFORCED.load(Ordering::Relaxed),
                            DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed),
                            marker_t(),
                        );
                        if terminated
                            && DBGK_TERMINATES_ENFORCED.load(Ordering::Relaxed) == terms_before + 1
                            && DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed) == resumed_before
                            && nt_handler
                                .pm
                                .thread(main_tid)
                                .is_some_and(|t| t.state == nt_process::ThreadState::Terminated)
                            && marker_t() == 4
                        {
                            bk_ok |= 0x0040;
                        }
                        break;
                    }

                    // ═══ 0x0100 — ★ THE DEBUGGER-SIDE BLOCKING WAIT, with a LIVE CLIENT ═══════
                    // A second real client thread issues a syscall the test services as
                    // `NtWaitForDebugEvent` with an EMPTY queue. Its private fault endpoint is
                    // received with REPLY_MAIN, so the PRODUCTION
                    // `wait_park` steals its reply capability exactly as the service loop does. The
                    // client cannot progress until a queue-side post runs `wait_wake_dispatcher_set`.
                    let dphase_ready = target_registered && attached && keepalive.is_some();
                    let debugger_wait_tid = dphase_ready
                        .then(|| nt_handler.pm.create_thread(debugger_pid, selftests::DBGK_CLIENT_CODE, 0, false).ok())
                        .flatten();
                    let debugger_ep = alloc_slot();
                    slots[nslots] = debugger_ep;
                    nslots += 1;
                    let debugger_fault = alloc_slot();
                    slots[nslots] = debugger_fault;
                    nslots += 1;
                    let debugger_endpoint_ready = debugger_wait_tid.is_some()
                        && untyped_retype_r(CAP_INIT_UNTYPED, OBJ_ENDPOINT, 0, 1, debugger_ep) == 0
                        && cnode_mint_r(
                            CAP_INIT_THREAD_CNODE,
                            debugger_fault,
                            debugger_ep,
                            BLK_DEBUGGER_RUNTIME_BADGE,
                        ) == 0;
                    let (dbg_pml4, dbg_tcb, _dbg_ep) = if debugger_endpoint_ready {
                        let dcode = selftests::dbgk_debugger_client_code();
                        selftests::dbgk_client_spawn(
                            &dcode,
                            shared_d,
                            write_scratch_d,
                            debugger_fault,
                            &mut slots,
                            &mut nslots,
                        )
                    } else {
                        (0, 0, 0)
                    };
                    let debugger_runtime_registered = debugger_wait_tid.is_some_and(|tid| {
                        dbg_tcb != 0
                            && nt_handler.register_hosted_thread_tcb(
                                0,
                                u64::from(tid),
                                dbg_tcb,
                                BLK_DEBUGGER_RUNTIME_BADGE,
                                HostedThreadRole::DbgkSelftestTarget,
                            )
                    });
                    let win_d = if dphase_ready {
                        let s = copy_cap(shared_d);
                        slots[nslots] = s;
                        nslots += 1;
                        s
                    } else {
                        0
                    };
                    let win_d_ok = dphase_ready
                        && page_map_r(win_d, marker_win_d, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
                    let marker_d = || {
                        if win_d_ok {
                            core::ptr::read_volatile(marker_win_d as *const u64)
                        } else {
                            u64::MAX
                        }
                    };
                    // Drain anything still queued so the wait genuinely finds nothing to report.
                    let mut drain_guard = 0;
                    while dphase_ready && drain_guard < 16 {
                        drain_guard += 1;
                        if sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) != 0
                        {
                            break;
                        }
                        if !img_spawn::smss_copyin(A_STATE, &mut sc) {
                            break;
                        }
                        let mut cid = [0u8; 16];
                        cid[0..8].copy_from_slice(&sc[0x08..0x10]);
                        cid[8..16].copy_from_slice(&sc[0x10..0x18]);
                        if !img_spawn::smss_copyout(A_CLIENT_ID, &cid)
                            || sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) != 0
                        {
                            break;
                        }
                    }
                    // The root Reply slot is empty after the shared-ingress Call parks. This
                    // private endpoint needs its own pool-owned Reply for the live wait proof.
                    let private_reply = if debugger_runtime_registered
                        && REPLY_MAIN_SLOT.load(Ordering::Relaxed) == 0
                    {
                        wait_reply_pool_find_free().and_then(|(index, cap)| {
                            if !wait_reply_pool_mark_used(index) { return None; }
                            REPLY_MAIN_SLOT.store(cap, Ordering::Relaxed);
                            Some(cap)
                        })
                    } else {
                        None
                    };
                    // The private endpoint has exactly one registered sender. A mismatched fault
                    // fails this proof; no shared-endpoint caller is discarded or rebound.
                    let (w_badge, w_mi, w_m0, _, w_ip, _) = if let Some(reply) = private_reply {
                        recv_full_r12(debugger_ep, reply)
                    } else {
                        (0, 0, 0, 0, 0, 0)
                    };
                    let w_sp = get_recv_mr(16);
                    let w_flags = get_recv_mr(17);
                    let saved_wait_caller = (
                        nt_handler.current_tid,
                        nt_handler.current_badge,
                        nt_handler.current_resume_ip,
                        nt_handler.current_sp,
                        nt_handler.current_flags,
                        nt_handler.current_native_call_transport,
                    );
                    let debugger_wait_received = debugger_runtime_registered
                        && w_badge == BLK_DEBUGGER_RUNTIME_BADGE
                        && (w_mi >> 12) == 2
                        && w_m0 == 0xD1;
                    if debugger_wait_received {
                        nt_handler.current_tid = u64::from(debugger_wait_tid.unwrap());
                        nt_handler.current_badge = w_badge;
                        nt_handler.current_resume_ip = w_ip;
                        nt_handler.current_sp = w_sp;
                        nt_handler.current_flags = w_flags;
                        nt_handler.current_native_call_transport = false;
                    }
                    dbgk_blk_trace(b"dw1", w_mi, w_m0, 0, marker_d());
                    // The handler's own park REQUEST (NULL *Timeout, empty queue) — the exact arm a
                    // hosted debugger would take.
                    nt_handler.wait_park_event = -1;
                    let wait_status = if debugger_wait_received {
                        sysc!(SSN_NT_WAIT_FOR_DEBUG_EVENT, &[dbg_handle, 0, 0, A_STATE])
                    } else {
                        nt_process::STATUS_INSUFFICIENT_RESOURCES
                    };
                    let park_index = nt_handler.wait_park_event;
                    let live_parked = target_registered
                        && attached
                        && dbg_pml4 != 0
                        && debugger_wait_received
                        && wait_status == 0x102
                        && park_index >= 0
                        && wait_park(
                            &mut nt_handler,
                            WaitObject::dispatcher(park_index as usize),
                            false,
                            u64::from(debugger_wait_tid.unwrap()),
                            nt_delay_execution::Deadline::Infinite,
                        )
                        && marker_d() == 0;
                    // A queue-side post through the very entry the fault path uses SETS the
                    // object's EventsPresent dispatcher event and wakes the parked client.
                    let wake_posted = live_parked
                        && nt_handler.dbgk_forward_exception(
                            blk_test_pi,
                            keepalive.unwrap_or(0) as u64,
                            dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, 0x9999),
                            true,
                        );
                    // Only an acknowledged terminal delivery permits another blocking receive.
                    // A queued event alone cannot prove a failed Reply actually resumed the TCB.
                    if live_parked
                        && wake_posted
                        && !object_waiter_contains_tid(u64::from(debugger_wait_tid.unwrap()))
                    {
                        let (wb2, w2_mi, w2_m0, _x1, _x2, _x3) =
                            recv_full_r12(debugger_ep, reply_debugger_done);
                        dbgk_blk_trace(b"dw2", w2_mi, w2_m0, 0, marker_d());
                        if wb2 == BLK_DEBUGGER_RUNTIME_BADGE
                            && (w2_mi >> 12) == 2
                            && w2_m0 == 0xD2
                            && marker_d() == 1
                        {
                            bk_ok |= 0x0100;
                        }
                    } else if live_parked {
                        wait_cancel_thread(&mut nt_handler, u64::from(debugger_wait_tid.unwrap()));
                    } else if debugger_runtime_registered && w_mi >> 12 != 0 {
                        assert!(drop_current_hosted_reply(), "debugger proof failed to retire its received fault");
                    }
                    if private_reply.is_some() {
                        let replacement = REPLY_MAIN_SLOT.swap(0, Ordering::Relaxed);
                        let index = wait_reply_pool_find_cap(replacement)
                            .expect("debugger proof lost its private Reply replacement");
                        let identity = wait_reply_pool_ref().at(index)
                            .expect("debugger proof lost its private Reply identity");
                        assert_eq!(wait_reply_pool_ref().state(identity),
                            Ok(nt_component_suspension::RootReplySlotState::Used));
                        assert!(wait_reply_pool_mark_free(index));
                    }
                    (
                        nt_handler.current_tid,
                        nt_handler.current_badge,
                        nt_handler.current_resume_ip,
                        nt_handler.current_sp,
                        nt_handler.current_flags,
                        nt_handler.current_native_call_transport,
                    ) = saved_wait_caller;

                    // 0x0080 — ★ THE ESCAPE HATCH. Leave the live keepalive reporter blocked on
                    // the breakpoint event posted above, then destroy the debug object (`NtClose`
                    // → `DbgkpCloseObject`, i.e. the debugger died holding the event): every
                    // blocked target is RELEASED, so nothing can stay parked forever. The main
                    // reporter was deliberately terminated by the preceding phase and therefore
                    // cannot own another event.
                    let released_before = DBGK_REPORTERS_RELEASED.load(Ordering::Relaxed);
                    let escape_tid = keepalive.unwrap_or(0) as u64;
                    let stranded = nt_handler.dbgk_block_reporter(
                        blk_test_pi,
                        escape_tid,
                        0,
                        dbgk::DBGK_BLOCK_VM_FAULT,
                        reply_spare,
                        0x1000,
                        0,
                        0,
                        0,
                    );
                    if stranded
                        && nt_handler.pm.blocked_reporter_count(object) == 1
                        && sysc!(SSN_NT_CLOSE, &[dbg_handle]) == 0
                        && DBGK_REPORTERS_RELEASED.load(Ordering::Relaxed) == released_before + 1
                        && nt_handler.pm.debug_object(object).is_none()
                        && !nt_handler.pm.is_process_being_debugged(target)
                    {
                        bk_ok |= 0x0080;
                    }

                    // Reclaim private capabilities only after retained wait effects settle.
                    // An uncertain Send still owns the debugger TCB and all its runtime resources.
                    let _ = tcb_suspend_r(client_tcb);
                    if client_runtime_registered {
                        let _ = nt_handler.release_hosted_thread_runtime(main_tid as u64);
                    }
                    let mut debugger_resources_settled = true;
                    let mut debugger_tcb_owned = dbg_tcb != 0;
                    if let Some(tid) = debugger_wait_tid {
                        wait_cancel_thread(&mut nt_handler, u64::from(tid));
                        let _ = nt_handler.pm.terminate_thread(tid, 0);
                        crate::object_wait_reply::redrive(&mut nt_handler);
                        crate::object_wait_reply::redrive_terminated_runtimes(
                            &mut nt_handler,
                            &mut *delay_queue,
                        );
                        debugger_resources_settled = !object_waiter_contains_tid(u64::from(tid));
                        if debugger_runtime_registered
                            && nt_handler.thread_runtime.get_by_tid(u64::from(tid)).is_none()
                        {
                            // Retained termination reconciliation already deleted this TCB.
                            debugger_tcb_owned = false;
                        }
                        if debugger_resources_settled && debugger_runtime_registered {
                            let _ = nt_handler.release_hosted_thread_runtime(u64::from(tid));
                        }
                    }
                    if debugger_resources_settled {
                        if debugger_tcb_owned {
                            let _ = tcb_suspend_r(dbg_tcb);
                        }
                        for index in (0..nslots).rev() {
                            let s = slots[index];
                            if s == 0
                                || s == client_tcb
                                || s == dbg_tcb
                                || s == client_pml4
                                || s == dbg_pml4
                            {
                                continue;
                            }
                            let _ = cnode_delete_recycle_r(s);
                        }
                        let _ = cnode_delete_recycle_r(client_tcb);
                        if debugger_tcb_owned {
                            let _ = cnode_delete_recycle_r(dbg_tcb);
                        }
                        let _ = cnode_delete_recycle_r(client_pml4);
                        if dbg_pml4 != 0 {
                            let _ = cnode_delete_recycle_r(dbg_pml4);
                        }
                        if let Some(claim) = target_claim {
                            let _ = nt_handler.release_temporary_process_slot(claim);
                        }
                    } else {
                        bk_ok &= !0x0100;
                        print_str(b"[dbgk-blk] debugger teardown unsettled; private capabilities retained\n");
                    }
                }
            }

            print_str(b"[ntos-exec] dbgk target-block selftest bits=0x");
            print_hex(bk_ok as u32);
            print_str(b" blocked=");
            print_u64(DBGK_REPORTERS_BLOCKED.load(Ordering::Relaxed));
            print_str(b" resumed=");
            print_u64(DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed));
            print_str(b" terminated=");
            print_u64(DBGK_TERMINATES_ENFORCED.load(Ordering::Relaxed));
            print_str(b" released=");
            print_u64(DBGK_REPORTERS_RELEASED.load(Ordering::Relaxed));
            print_str(b"\n");

            crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.loop_ctx = saved_ctx;
            nt_handler.wait_park_event = -1;
            nt_handler.wait_timeout = PendingWaitTimeout::none();
            DBGK_BLOCK_SELFTEST.store(bk_ok, Ordering::Relaxed);
        }

        // === Dbgk REMOTE BREAK-IN SELF-TEST (POST-LOOP) — `DbgUiIssueRemoteBreakin`, end to end ===
        //
        // Three things had to become real together, because each is inert without the others:
        //   (1) CROSS-VSPACE THREAD CREATION — `NtCreateThread` with a FOREIGN `ProcessHandle` that
        //       really builds a thread (own stack + TEB + IPC buffer, caller-supplied entry AND
        //       parameter) inside the TARGET's address space (`create_remote_thread` →
        //       `rendezvous::spawn_slot_thread`).
        //   (2) `PEB->BeingDebugged` WRITE-THROUGH into the target's LIVE PEB page
        //       (`DbgkpMarkProcessPeb`) — without it `DbgUiRemoteBreakin` reads a zero byte, skips
        //       `DbgBreakPoint()` and exits silently, so the whole feature would be a no-op.
        //   (3) the `int3` → `DbgkForwardException` → `NtWaitForDebugEvent` → `NtDebugContinue`
        //       chain that batches 52 and 54 already built.
        //
        // The DEBUGGER side goes through the REAL dispatch route (`nt_dispatcher.dispatch(SSN, …)`
        // with the arguments marshalled in smss's CLIENT memory — the established idiom); the
        // TARGET side goes through `dbgk_forward_exception` / `dbgk_block_reporter`, the very
        // entries the live fault loop calls. The MECHANISM spawn calls `rendezvous::spawn_slot_thread`
        // — exactly what the loop's `spawn_requested_remote_thread` calls with the request the
        // handler produced — differing only in the two transport switches a target with no ntdll
        // mapped requires (direct entry instead of `LdrInitializeThunk`, hosted-syscalls instead of
        // the native Call) and a private endpoint, so the post-loop test can service it itself.
        if nt_handler.pm.has_process_exit_notify_registrations() {
            // This synthetic target has no ordinary provider create lifecycle. Do not inject its
            // exit into live providers from a post-loop diagnostic.
            print_str(b"[ntos-exec] dbgk remote-breakin selftest skipped: provider exit callbacks live\n");
            DBGK_BREAKIN_SELFTEST.store(0, Ordering::Relaxed);
        } else {
            use nt_process::dbgk;
            const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
            const PROCESS_CREATE_THREAD: u32 = 0x0002;
            const THREAD_ALL_ACCESS: u64 = 0x001F_03FF;
            const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
            // Argument scratch in smss's CLIENT memory (its stack mirror), clear of the block
            // self-test's window and of the live stack (which grows DOWN from the top).
            const A_HANDLE: u64 = STACK_BASE + 0x300;
            const A_CLIENT_ID: u64 = STACK_BASE + 0x308;
            const A_TIMEOUT: u64 = STACK_BASE + 0x318;
            const A_STATE: u64 = STACK_BASE + 0x320;
            // A_STATE holds a whole DBGUI_WAIT_STATE_CHANGE (0xB8) → 0x320..0x3D8; keep the
            // NtCreateThread argument block clear of it.
            const A_THREAD_HANDLE: u64 = STACK_BASE + 0x400;
            const A_CID_OUT: u64 = STACK_BASE + 0x408;
            const A_CALLER_SP: u64 = STACK_BASE + 0x420; // the "client stack" NtCreateThread reads
            const A_CONTEXT: u64 = STACK_BASE + 0x500; // the caller's CONTEXT record
            const A_INITIAL_TEB: u64 = STACK_BASE + 0xa00;
            const A_STACK_BASE: u64 = STACK_BASE + 0xa30;
            const A_STACK_SIZE: u64 = STACK_BASE + 0xa38;
            // Outside the fixed worker windows and the executive's automatic heap mirror.
            const CALLER_STACK_BASE: u64 = SMSS_ALLOC_VA + 0x0200_0000;
            const CALLER_STACK_SIZE: u64 = 0x1_0000;
                                                       // Executive scratch inside the SAME proven-resident 2 MiB page table the other post-loop
                                                       // self-tests use (SMSS_SCRATCH_BASE + 3000*0x1000, PT index 5).
            let write_scratch = SMSS_SCRATCH_BASE + 3020 * 0x1000;
            let mark_win = SMSS_SCRATCH_BASE + 3021 * 0x1000;
            let peb_win = SMSS_SCRATCH_BASE + 3022 * 0x1000;

            let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
            let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
            let saved_pi = nt_handler.pi;
            let saved_tid = nt_handler.current_tid;
            let saved_ctx = nt_handler.loop_ctx;
            crate::executor::local().client_pi.store(0, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(SMSS_SCRATCH_BASE, Ordering::Relaxed);
            nt_handler.pi = 0;

            let mut br_ok = 0u64;
            nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(0));
            let dbg_origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
            // Every dispatch through the real route, with the out-param write queue drained exactly
            // as the service loop drains it (`xas_write_u64` per queued write).
            macro_rules! sysc {
                ($ssn:expr, $args:expr) => {{
                    nt_handler.out_writes_n = 0;
                    let mut status = nt_dispatcher
                        .dispatch($ssn as u32, $args, &dbg_origin, &mut nt_handler)
                        .status;
                    for k in 0..nt_handler.out_writes_n {
                        let (ptr, val) = nt_handler.out_writes[k];
                        if !nt_handler.xas_write_u64(ptr, val) {
                            status = 0xC000_0005;
                        }
                    }
                    nt_handler.out_writes_n = 0;
                    status
                }};
            }
            let mut sc = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];
            macro_rules! sc_u32 {
                ($o:expr) => {
                    u32::from_le_bytes(sc[$o..$o + 4].try_into().unwrap())
                };
            }

            let debugger_pid = nt_handler.pm_pid_for_pi(0).unwrap_or(0);
            let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
            nt_handler.current_tid = debugger_tid as u64;

            let mut slots = [0u64; 64];
            let mut nslots = 0usize;
            // Macros (not closures) so the slot list stays freely usable alongside them.
            macro_rules! push_slot {
                ($cap:expr) => {{
                    let s = $cap;
                    slots[nslots] = s;
                    nslots += 1;
                    s
                }};
            }
            macro_rules! make {
                ($kind:expr, $bits:expr) => {{
                    let s = push_slot!(alloc_slot());
                    let made = untyped_retype_r(CAP_INIT_UNTYPED, $kind, $bits, 1, s);
                    if made != 0 {
                        print_str(b"[dbgk-brk] retype FAILED kind=");
                        print_u64($kind);
                        print_str(b" status=");
                        print_u64(made);
                        print_str(b"\n");
                    }
                    s
                }};
            }

            // ── The throwaway TARGET's address space ────────────────────────────────────────
            // A real hosted-process paging skeleton: the image PT, the hosted-client env PT
            // (PEB and test marker live in the dedicated env band), plus the WORK_CLUSTER PT that holds the
            // bounded thread-slot windows the remote thread's stack/TEB/IPC/trampoline land in.
            let target_pml4 = make!(OBJ_X86_PML4, PAGING_BITS);
            require_vspace_asid(target_pml4, b"dbgk-breakin-target");
            map_image_skeleton(target_pml4, 1);
            map_hosted_client_env_pt(target_pml4);
            map_tp_worker_target_lane_pts(target_pml4);
            let target = nt_handler.pm.create_process("dbgk-breakin.exe", None, None);
            nt_handler.pm.set_image_base(target, 0x0000_0001_A000_0000);
            let brk_test_claim = nt_handler
                .claim_temporary_process_slot(target, target_pml4)
                .ok();
            let test_pi = brk_test_claim
                .map(TemporaryProcessSlotClaim::pi)
                .unwrap_or(MAX_PI);
            // The real VM allocator consumes the target's ProcExec, not merely its Ps VSpace
            // lookup. Keep the previous empty slot until all caller VM ownership is retired.
            let saved_target_proc = if brk_test_claim.is_some() {
                nt_handler.loop_ctx.and_then(|ctx| {
                    let previous = (&*ctx.procs).get(test_pi).copied()?;
                    if previous.pid != 0 || previous.pml4 != 0
                        || !process_vm_region_map(test_pi).is_some_and(|map| map.extent_count() == 0)
                        || process_user_page_table_commit_bytes(test_pi) != 0
                    {
                        return None;
                    }
                    (&mut *ctx.procs)[test_pi] = ProcExec {
                        pid: u64::from(target),
                        pml4: target_pml4,
                        scratch_base: SMSS_SCRATCH_BASE + 3023 * 0x1000,
                        ..ProcExec::empty()
                    };
                    Some(previous)
                })
            } else {
                None
            };
            // The target's PEB page: mapped in ITS VSpace first, then windowed into the executive
            // (a frame capability carries its own mapping — map the original before any copy), and
            // registered with that window as its permanent alias, exactly as `spawn_sec_image`
            // registers a hosted process's PEB. That registration is what lets the general
            // client-memory writer reach it — `dbgk_mark_process_peb` invents no new mechanism.
            let peb_frame = make!(OBJ_X86_4K_PAGE, PAGING_BITS);
            let peb_mapped = page_map_r(peb_frame, SMSS_PEB_VA, RW_NX, target_pml4) == 0;
            let peb_alias = push_slot!(copy_cap(peb_frame));
            let peb_win_ok =
                peb_mapped && page_map_r(peb_alias, peb_win, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
            let peb_registered = peb_win_ok
                && brk_test_claim.is_some()
                && csrss_frame_put_at_cap(
                    test_pi as u64,
                    nt_memory_manager::MemoryLifetime::Process(brk_test_claim.unwrap().identity()),
                    SMSS_PEB_VA,
                    peb_frame,
                    peb_win,
                    peb_alias,
                );
            // The marker page (target-only) + the executive's window on the same frame.
            let mark_frame = make!(OBJ_X86_4K_PAGE, PAGING_BITS);
            let mark_mapped = page_map_r(
                mark_frame,
                selftests::DBGK_BREAKIN_MARK_VA,
                RW_NX,
                target_pml4,
            ) == 0;
            let mark_alias = push_slot!(copy_cap(mark_frame));
            let mark_win_ok =
                mark_mapped && page_map_r(mark_alias, mark_win, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
            let marker = |offset: u64| -> u64 {
                if mark_win_ok {
                    core::ptr::read_volatile((mark_win + offset) as *const u64)
                } else {
                    u64::MAX
                }
            };
            let peb_being_debugged = || -> u64 {
                if peb_win_ok {
                    core::ptr::read_volatile(
                        (peb_win + nt_ntdll_layout::PEB_BEING_DEBUGGED_OFFSET as u64) as *const u8,
                    ) as u64
                } else {
                    u64::MAX
                }
            };
            // `DbgUiRemoteBreakin`'s code page: written through an executive alias, mapped RX (W^X).
            let code = selftests::dbgk_breakin_thread_code();
            let code_frame = make!(OBJ_X86_4K_PAGE, PAGING_BITS);
            let code_written =
                page_map_r(code_frame, write_scratch, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
            if code_written {
                for (i, b) in code.iter().enumerate() {
                    core::ptr::write_volatile((write_scratch + i as u64) as *mut u8, *b);
                }
            }
            let code_copy = push_slot!(copy_cap(code_frame));
            let code_mapped = code_written
                && page_map_r(
                    code_copy,
                    selftests::DBGK_BREAKIN_CODE_VA,
                    /* RX */ 2,
                    target_pml4,
                ) == 0;

            let brk_ep = make!(OBJ_ENDPOINT, 0);
            let reply_a = make!(OBJ_REPLY, 0);
            let reply_b = make!(OBJ_REPLY, 0);

            // ── The throwaway TARGET process object ────────────────────────────────────────
            let target_main = nt_handler
                .pm
                .create_thread(target, selftests::DBGK_BREAKIN_CODE_VA, 0, false)
                .unwrap_or(0);
            let target_backing = if peb_registered && target_main != 0
                && nt_handler.pm.set_peb_base(target, SMSS_PEB_VA)
            {
                let scratch = crate::executor::local().scratch_base.load(Ordering::Relaxed);
                let lifetime = nt_handler.pm.thread_lifetime(target_main)
                    .expect("debugger target main thread has an exact lifetime");
                match ps_object_backing::prepare_process(&nt_handler.pm, target, scratch) {
                    Ok(process_body) => {
                        match ps_object_backing::prepare_thread(&nt_handler.pm, lifetime, scratch) {
                            Ok(_) => {
                                if ps_object_backing::publish_prepared_pair(
                                    &mut nt_handler.pm, lifetime,
                                ).is_ok() {
                                    true
                                } else {
                                    ps_object_backing::abort_prepared_thread(
                                        &nt_handler.pm, lifetime, scratch,
                                    ).expect("failed debugger target retains unpublished thread body");
                                    ps_object_backing::abort_unpublished(
                                        &nt_handler.pm, process_body, scratch,
                                    ).expect("failed debugger target retains unpublished process body");
                                    false
                                }
                            }
                            Err(_) => {
                                ps_object_backing::abort_prepared_thread(
                                    &nt_handler.pm, lifetime, scratch,
                                ).expect("failed debugger target retains unpublished thread body");
                                ps_object_backing::abort_unpublished(
                                    &nt_handler.pm, process_body, scratch,
                                ).expect("failed debugger target retains unpublished process body");
                                false
                            }
                        }
                    }
                    Err(_) => false,
                }
            } else {
                false
            };
            let target_registered = brk_test_claim.is_some();
            // This process HAS its initial thread, so a foreign-handle create is a genuine
            // ADDITIONAL thread — the real cross-VSpace path (exactly the live rule).
            if target_registered {
                let plan = nt_handler.pm.prepare_initial_thread_creation(target)
                    .expect("debugger fixture reserves its exact initial thread")
                    .expect("debugger fixture has a fresh initial thread");
                nt_handler.pm.commit_initial_thread_creation(&plan)
                    .expect("debugger fixture retains its published initial thread");
            }

            let h_target = nt_handler
                .pm
                .insert_handle(
                    debugger_pid,
                    nt_process::HandleObject::Process(target),
                    PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD | 0x0008, // PROCESS_VM_OPERATION
                )
                .map(u64::from)
                .unwrap_or(0);
            // The SAME process, through a handle that lacks PROCESS_CREATE_THREAD.
            let h_target_no_create = nt_handler
                .pm
                .insert_handle(
                    debugger_pid,
                    nt_process::HandleObject::Process(target),
                    PROCESS_SUSPEND_RESUME,
                )
                .map(u64::from)
                .unwrap_or(0);

            let args_ready = img_spawn::smss_copyout(A_HANDLE, &[0u8; 0x100])
                && img_spawn::smss_copyout(A_CONTEXT, &[0u8; nt_thread_start::AMD64_CONTEXT_SIZE])
                && img_spawn::smss_copyout(A_TIMEOUT, &0i64.to_le_bytes());
            let caller_stack_allocated = saved_target_proc.is_some()
                && args_ready
                && h_target != 0
                && img_spawn::smss_copyout(A_STACK_BASE, &CALLER_STACK_BASE.to_le_bytes())
                && img_spawn::smss_copyout(A_STACK_SIZE, &CALLER_STACK_SIZE.to_le_bytes())
                && sysc!(SSN_NT_ALLOCATE_VM, &[
                    h_target, A_STACK_BASE, 0, A_STACK_SIZE,
                    u64::from(nt_address_space::MEM_RESERVE | nt_address_space::MEM_COMMIT),
                    u64::from(nt_address_space::PAGE_READWRITE),
                ]) == 0;
            let setup_ok = peb_registered
                && mark_win_ok
                && code_mapped
                && target_main != 0
                && target_backing
                && target_registered
                && h_target != 0
                && h_target_no_create != 0
                && args_ready
                && caller_stack_allocated
                && smss_stack_read(A_STACK_BASE) == CALLER_STACK_BASE
                && smss_stack_read(A_STACK_SIZE) == CALLER_STACK_SIZE
                && debugger_pid != 0;

            let mut spawned_breakin_tid = 0u64;
            let mut breakin_runtime_tid = 0u64;
            if setup_ok {
                // ── 0x0001 — a real DEBUG_OBJECT + attach BY SSN, fake create messages drained ──
                let created = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[
                        A_HANDLE,
                        dbgk::DEBUG_OBJECT_ALL_ACCESS as u64,
                        0,
                        dbgk::DBGK_KILL_PROCESS_ON_EXIT as u64,
                    ]
                );
                let dbg_handle = smss_stack_read(A_HANDLE);
                let object = match nt_handler
                    .pm
                    .lookup_handle(debugger_pid, dbg_handle as nt_process::Handle)
                {
                    Some(nt_process::HandleObject::DebugObject(object)) => Some(object),
                    _ => None,
                };
                if let (0, Some(object)) = (created, object) {
                    let peb_before = peb_being_debugged();
                    let marks_before = DBGK_PEB_MARKS.load(Ordering::Relaxed);
                    let attached = sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle]) == 0
                        && nt_handler.pm.process_debug_port(target) == Some(object);
                    // Drain every fake thread/module message. Dormant pool identities are not live
                    // threads and therefore do not contribute to this cardinality.
                    let mut drained = 0u64;
                    while attached && drained < 8 {
                        if sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) != 0
                            || !img_spawn::smss_copyin(A_STATE, &mut sc)
                        {
                            break;
                        }
                        let mut cid = [0u8; 16];
                        cid[0..8].copy_from_slice(&sc[0x08..0x10]);
                        cid[8..16].copy_from_slice(&sc[0x10..0x18]);
                        if !img_spawn::smss_copyout(A_CLIENT_ID, &cid)
                            || sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) != 0
                        {
                            break;
                        }
                        drained += 1;
                    }
                    if attached
                        && drained != 0
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        br_ok |= 0x0001;
                    }
                    // ── 0x0002 — ★ `PEB->BeingDebugged` WRITTEN THROUGH, read back out of the
                    // TARGET's own PEB page (the very frame its VSpace maps at SMSS_PEB_VA).
                    if peb_before == 0
                        && peb_being_debugged() == 1
                        && DBGK_PEB_MARKS.load(Ordering::Relaxed) == marks_before + 1
                        && nt_handler.pm.is_process_being_debugged(target)
                    {
                        br_ok |= 0x0002;
                    }

                    // ── 0x0008 — ★ THE CROSS-VSPACE CREATE, BY SSN. Marshal NtCreateThread's
                    // stack-resident arguments (ClientId / ThreadContext / InitialTeb /
                    // CreateSuspended) in CLIENT memory and stage the caller stack pointer the
                    // handler reads them through, then issue SSN 55 with the TARGET's handle.
                    let mut context = [0u8; nt_thread_start::AMD64_CONTEXT_SIZE];
                    nt_thread_start::initialize_amd64_user_context(
                        &mut context,
                        selftests::DBGK_BREAKIN_CODE_VA,
                        selftests::DBGK_BREAKIN_PARAM,
                        CALLER_STACK_BASE + CALLER_STACK_SIZE,
                    );
                    let mut initial_teb = [0u8; nt_thread_start::INITIAL_TEB64_SIZE];
                    initial_teb[0x10..0x18].copy_from_slice(&(CALLER_STACK_BASE + CALLER_STACK_SIZE).to_le_bytes());
                    initial_teb[0x18..0x20].copy_from_slice(&CALLER_STACK_BASE.to_le_bytes());
                    initial_teb[0x20..0x28].copy_from_slice(&CALLER_STACK_BASE.to_le_bytes());
                    let ctx_ok = img_spawn::smss_copyout(A_CONTEXT, &context)
                        && img_spawn::smss_copyout(A_INITIAL_TEB, &initial_teb)
                        && img_spawn::smss_copyout(A_CALLER_SP + 0x28, &A_CID_OUT.to_le_bytes())
                            && img_spawn::smss_copyout(
                                A_CALLER_SP + 0x30,
                                &A_CONTEXT.to_le_bytes(),
                            )
                            && img_spawn::smss_copyout(A_CALLER_SP + 0x38, &A_INITIAL_TEB.to_le_bytes())
                            && img_spawn::smss_copyout(A_CALLER_SP + 0x40, &0u64.to_le_bytes())
                            && img_spawn::smss_copyout(A_THREAD_HANDLE, &0u64.to_le_bytes())
                            && img_spawn::smss_copyout(A_CID_OUT, &[0u8; 16]);
                    set_recv_mr(16, A_CALLER_SP);
                    // ★ The security negative FIRST (it must change nothing): the same target
                    // through a handle without PROCESS_CREATE_THREAD.
                    // NtCreateThread's full 8-argument shape (the dispatcher enforces argc):
                    // ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId,
                    // ThreadContext, InitialTeb, CreateSuspended — the last four also readable
                    // through the caller's stack, which is where the handler takes them from.
                    let denied = sysc!(
                        SSN_NT_CREATE_THREAD,
                        &[
                            A_THREAD_HANDLE,
                            THREAD_ALL_ACCESS,
                            0,
                            h_target_no_create,
                            A_CID_OUT,
                            A_CONTEXT,
                            A_INITIAL_TEB,
                            0,
                        ]
                    );
                    let created_before = PM_REMOTE_THREADS_CREATED.load(Ordering::Relaxed);
                    set_recv_mr(16, A_CALLER_SP);
                    let create_status = sysc!(
                        SSN_NT_CREATE_THREAD,
                        &[
                            A_THREAD_HANDLE,
                            THREAD_ALL_ACCESS,
                            0,
                            h_target,
                            A_CID_OUT,
                            A_CONTEXT,
                            A_INITIAL_TEB,
                            0,
                        ]
                    );
                    let request = nt_handler.remote_thread_request.take();
                    let publication_invisible = request.as_ref().is_some_and(|request| {
                        smss_stack_read(A_THREAD_HANDLE) == 0
                            && smss_stack_read(A_CID_OUT) == 0
                            && smss_stack_read(A_CID_OUT + 8) == 0
                            && nt_handler
                                .pm
                                .lookup_handle(
                                    debugger_pid,
                                    request.publication.handle() as nt_process::Handle,
                                )
                                .is_none()
                    });
                    let request_observation = request.as_ref().map(|request| (
                        request.target_pi, request.pml4, request.start.rip,
                        request.start.rcx, request.cid_thread,
                    ));

                    // ── 0x0010 — ★ THE REMOTE THREAD REALLY RUNS IN THE TARGET'S VSPACE.
                    // Build the mechanism through the same entry the loop uses; the thread's own
                    // stack/TEB/IPC buffer are mapped in the TARGET's pml4, and the marker it writes
                    // lands in a page that exists ONLY there.
                    let mut spawned_tcb = 0u64;
                    let mut breakin_runtime_slot = 0usize;
                    if let Some(request) = request {
                        breakin_runtime_slot = request.slot;
                        let runtime_publication = nt_handler.prepare_hosted_thread_runtime_publication(
                            test_pi, request.cid_thread, tp_worker_badge(test_pi, request.slot),
                            HostedThreadRole::TpWorker { slot: request.slot },
                        ).expect("debugger fixture owns its reserved runtime before construction");
                        let spawned = rendezvous::spawn_slot_thread(
                            &mut nt_handler,
                            &rendezvous::RemoteThreadSpawn {
                                target_pi: request.target_pi,
                                slot: request.slot,
                                pml4: request.pml4,
                                start: request.start,
                                initial_context: &request.initial_context,
                                stack_origin: request.stack_origin,
                                cid_proc: request.cid_proc,
                                cid_thread: request.cid_thread,
                                fault_ep: ThreadFaultEndpoint::Borrowed(brk_ep),
                                // The throwaway target has no ntdll mapped, so enter the start routine
                                // directly and keep the hosted-syscalls trap (its exit `syscall` is
                                // delivered here as an UnknownSyscall fault).
                                use_loader: false,
                                native: false,
                            },
                        );
                        match spawned {
                            Ok(spawned) => {
                                spawned_tcb = spawned.tcb();
                                nt_handler.finish_hosted_thread_publication(
                                    runtime_publication, spawned, request.publication, request.resume,
                                ).expect("debugger fixture activates before first resume and handle publication");
                                for k in 0..nt_handler.out_writes_n {
                                    let (ptr, val) = nt_handler.out_writes[k];
                                    assert!(nt_handler.xas_write_u64(ptr, val));
                                }
                                nt_handler.out_writes_n = 0;
                                spawned_breakin_tid = request.cid_thread;
                                PM_REMOTE_THREADS_SPAWNED.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(failure) => {
                                nt_handler.fail_hosted_thread_runtime_publication(runtime_publication, failure);
                                nt_handler.abort_unbuilt_hosted_thread_publication(
                                    request.publication, test_pi, tp_worker_badge(test_pi, request.slot),
                                    HostedThreadRole::TpWorker { slot: request.slot },
                                );
                            }
                        }
                    }
                    let thread_handle = smss_stack_read(A_THREAD_HANDLE);
                    let cid_proc = smss_stack_read(A_CID_OUT);
                    let breakin_tid = smss_stack_read(A_CID_OUT + 8);
                    breakin_runtime_tid = breakin_tid;
                    let handle_ok = matches!(
                        nt_handler
                            .pm
                            .lookup_handle(debugger_pid, thread_handle as nt_process::Handle),
                        Some(nt_process::HandleObject::Thread(t)) if t as u64 == breakin_tid
                    );
                    if publication_invisible
                        && ctx_ok
                        && denied == STATUS_ACCESS_DENIED
                        && create_status == 0
                        && PM_REMOTE_THREADS_CREATED.load(Ordering::Relaxed) == created_before + 1
                        && thread_handle != 0
                        && handle_ok
                        && cid_proc == target as u64
                        && breakin_tid != 0
                        && breakin_tid != target_main as u64
                        && request_observation.is_some_and(|(pi, pml4, rip, rcx, tid)| {
                            pi == test_pi
                                && pml4 == target_pml4
                                && rip == selftests::DBGK_BREAKIN_CODE_VA
                                && rcx == selftests::DBGK_BREAKIN_PARAM
                                && tid == breakin_tid
                        })
                    {
                        br_ok |= 0x0008;
                    }
                    print_str(b"[dbgk-brk] denied=0x");
                    print_hex(denied);
                    print_str(b" create=0x");
                    print_hex(create_status);
                    print_str(b" ctx_ok=");
                    print_u64(ctx_ok as u64);
                    print_str(b" invisible=");
                    print_u64(publication_invisible as u64);
                    print_str(b" h=0x");
                    print_hex(thread_handle as u32);
                    print_str(b" tid=");
                    print_u64(breakin_tid);
                    print_str(b" req=");
                    print_u64(request_observation.is_some() as u64);
                    print_str(b"\n");
                    if spawned_tcb != 0 {
                        // Its first fault: the `int3` if it read BeingDebugged = 1, else its exit
                        // syscall. Either way it must have RUN — the marker proves the thread
                        // executed in the target's address space with a correct TEB/PEB.
                        //
                        // Hosted TCB admission may emit a startup/scheduler notification before the
                        // thread reaches its entry trampoline. That notification is not the
                        // break-in thread's debuggee event, and treating it as such leaves the
                        // marker at zero. Select the first message after the marker page proves
                        // the break-in code has run; the private endpoint means any later selected
                        // message still belongs to this throwaway thread.
                        let mut f1 = None;
                        let mut saw_breakin_marker = false;
                        let mut f1_guard = 0;
                        while f1_guard < 8 {
                            f1_guard += 1;
                            let (_fb, mi_r, m0_r, m1_r, _m2_r, _m3_r) =
                                recv_full_r12(brk_ep, reply_a);
                            let ran = marker(0x00);
                            if ran == 0x11 || ran == 0x12 {
                                saw_breakin_marker = true;
                                let label = mi_r >> 12;
                                if label == 4 || label == 2 {
                                    dbgk_brk_trace(b"f1", mi_r, m0_r, m1_r, ran);
                                    f1 = Some((mi_r, m0_r));
                                    break;
                                }
                                dbgk_brk_trace(b"f1-wait", mi_r, m0_r, m1_r, ran);
                                continue;
                            }
                            dbgk_brk_trace(b"f1-foreign", mi_r, m0_r, m1_r, ran);
                        }
                        if saw_breakin_marker
                            && marker(0x00) == 0x11
                            && marker(0x08) == SMSS_PEB_VA
                            && marker(0x18) == selftests::DBGK_BREAKIN_PARAM
                        {
                            br_ok |= 0x0010;
                        }
                        if let Some((f1_mi, f1_m0)) = f1 {
                            // ── 0x0020 — ★ IT HIT THE BREAKPOINT, and the debugger sees it.
                            // The byte it read is the write-through; the `int3` (DebugException,
                            // label 4) is forwarded through the live fault-loop entry and its reporter
                            // parked. A real debugger may first receive the remote thread's
                            // DbgCreateThreadStateChange, because `NtCreateThread` queued it before
                            // the thread ran to `int3`; continue that lifecycle event, then retrieve
                            // the breakpoint BY SSN carrying the BREAK-IN THREAD's CLIENT_ID.
                            let is_breakpoint = (f1_mi >> 12) == 4 && marker(0x10) == 1;
                            let forwarded = is_breakpoint
                                && nt_handler.dbgk_forward_exception(
                                    test_pi,
                                    breakin_tid,
                                    dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, f1_m0),
                                    true,
                                );
                            let parked = forwarded
                                && nt_handler.dbgk_block_reporter(
                                    test_pi,
                                    breakin_tid,
                                    0,
                                    dbgk::DBGK_BLOCK_DEBUG_EXCEPTION,
                                    reply_a,
                                    f1_m0,
                                    0,
                                    0,
                                    0,
                                );
                            let mut waited = false;
                            if parked {
                                let first_wait = sysc!(
                                    SSN_NT_WAIT_FOR_DEBUG_EVENT,
                                    &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                                );
                                if first_wait == 0 && img_spawn::smss_copyin(A_STATE, &mut sc) {
                                    let selected_state = sc_u32!(0x00);
                                    let selected_tid =
                                        u64::from_le_bytes(sc[0x10..0x18].try_into().unwrap());
                                    if selected_state == dbgk::DBG_CREATE_THREAD_STATE_CHANGE
                                        && u64::from_le_bytes(sc[0x08..0x10].try_into().unwrap())
                                            == target as u64
                                        && selected_tid == breakin_tid
                                    {
                                        let mut lifecycle_cid = [0u8; 16];
                                        lifecycle_cid.copy_from_slice(&sc[0x08..0x18]);
                                        if img_spawn::smss_copyout(A_CLIENT_ID, &lifecycle_cid)
                                            && sysc!(
                                                SSN_NT_DEBUG_CONTINUE,
                                                &[
                                                    dbg_handle,
                                                    A_CLIENT_ID,
                                                    dbgk::DBG_CONTINUE as u64
                                                ]
                                            ) == 0
                                        {
                                            let second_wait = sysc!(
                                                SSN_NT_WAIT_FOR_DEBUG_EVENT,
                                                &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                                            );
                                            waited = second_wait == 0
                                                && img_spawn::smss_copyin(A_STATE, &mut sc);
                                        }
                                    } else {
                                        waited = true;
                                    }
                                }
                            }
                            let reported = waited
                                && sc_u32!(0x00) == dbgk::DBG_BREAKPOINT_STATE_CHANGE
                                && u64::from_le_bytes(sc[0x08..0x10].try_into().unwrap())
                                    == target as u64
                                && u64::from_le_bytes(sc[0x10..0x18].try_into().unwrap())
                                    == breakin_tid
                                && sc_u32!(0x18) == dbgk::STATUS_BREAKPOINT;
                            if reported {
                                br_ok |= 0x0020;
                            }
                            // ── 0x0040 — ★ CONTINUE RESUMES IT PAST THE int3 AND IT EXITS CLEANLY.
                            let resumed_before = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                            let mut cid = [0u8; 16];
                            cid[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                            cid[8..16].copy_from_slice(&breakin_tid.to_le_bytes());
                            let continued = reported
                                && img_spawn::smss_copyout(A_CLIENT_ID, &cid)
                                && sysc!(
                                    SSN_NT_DEBUG_CONTINUE,
                                    &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                                ) == 0
                                && DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed)
                                    == resumed_before + 1;
                            if continued {
                                // Its exit path: marker 0x12 (it really resumed past the breakpoint)
                                // then the `RtlExitUserThread` stand-in syscall arrives here.
                                let (_eb, e_mi, e_m0, _em1, _em2, _em3) =
                                    recv_full_r12(brk_ep, reply_b);
                                if (e_mi >> 12) == 2
                                    && e_m0 == selftests::DBGK_BREAKIN_EXIT_SSN
                                    && marker(0x00) == 0x12
                                {
                                    br_ok |= 0x0040;
                                }
                            } else if parked {
                                let _ = nt_handler.dbgk_release_all_blocked_reporters();
                            }
                        }
                    }

                    // ── 0x0004 — ★ DETACH CLEARS `PEB->BeingDebugged` in the LIVE PEB page.
                    let marks_before_detach = DBGK_PEB_MARKS.load(Ordering::Relaxed);
                    let detached = sysc!(SSN_NT_REMOVE_PROCESS_DEBUG, &[h_target, dbg_handle]) == 0;
                    if detached
                        && peb_being_debugged() == 0
                        && DBGK_PEB_MARKS.load(Ordering::Relaxed) == marks_before_detach + 1
                        && !nt_handler.pm.is_process_being_debugged(target)
                    {
                        br_ok |= 0x0004;
                    }
                    let _ = sysc!(SSN_NT_CLOSE, &[dbg_handle, 0, 0, 0]);
                    // Reclaim: suspend the remote thread, then drop every throwaway cap. Keep
                    // `target_pml4` out of the recycle path for now because its skeleton mappings are
                    // not tracked in this local slot list; all other slots here are local aliases,
                    // replies, endpoints, or throwaway frames.
                    let brk_tcb = nt_handler
                        .hosted_thread_tcb_for_role(
                            test_pi,
                            HostedThreadRole::TpWorker {
                                slot: breakin_runtime_slot,
                            },
                        )
                        .unwrap_or(0);
                    if brk_tcb > 1 {
                        assert_eq!(tcb_suspend_r(brk_tcb), 0,
                            "diagnostic caller stack remains owned until its TCB is suspended");
                    }
                }
            }
            print_str(b"[ntos-exec] dbgk remote-breakin selftest bits=0x");
            print_hex(br_ok as u32);
            print_str(b" peb-marks=");
            print_u64(DBGK_PEB_MARKS.load(Ordering::Relaxed));
            print_str(b" remote-created=");
            print_u64(PM_REMOTE_THREADS_CREATED.load(Ordering::Relaxed));
            print_str(b" remote-spawned=");
            print_u64(PM_REMOTE_THREADS_SPAWNED.load(Ordering::Relaxed));
            print_str(b" marker=0x");
            print_hex(if mark_win_ok {
                core::ptr::read_volatile(mark_win as *const u64) as u32
            } else {
                0xFFFF_FFFF
            });
            print_str(b"\n");
            for i in (0..nslots).rev() {
                let s = slots[i];
                if s != 0 && s != target_pml4 {
                    let _ = cnode_delete_recycle_r(s);
                }
            }
            if spawned_breakin_tid != 0 {
                breakin_runtime_tid = spawned_breakin_tid;
            }
            if breakin_runtime_tid != 0 {
                if let Some(runtime) = nt_handler.release_hosted_thread_runtime(breakin_runtime_tid)
                {
                    release_hosted_thread_resources(runtime.resources);
                    nt_handler.release_hosted_thread_commitment(runtime.resources);
                    release_hosted_thread_mechanism_cnodes(runtime);
                }
            }
            if caller_stack_allocated {
                assert!(img_spawn::smss_copyout(A_STACK_BASE, &CALLER_STACK_BASE.to_le_bytes())
                    && img_spawn::smss_copyout(A_STACK_SIZE, &0u64.to_le_bytes()));
                assert_eq!(sysc!(SSN_NT_FREE_VM, &[
                    h_target, A_STACK_BASE, A_STACK_SIZE, u64::from(nt_address_space::MEM_RELEASE),
                ]), 0, "diagnostic retains target context until real caller VAD release succeeds");
            }
            for handle in [h_target, h_target_no_create] {
                if handle != 0 && nt_handler.pm.lookup_handle(
                    debugger_pid, handle as nt_process::Handle,
                ).is_some() {
                    nt_handler.pm.close_handle(debugger_pid, handle as nt_process::Handle)
                        .expect("debugger fixture closes its target process handle");
                }
            }
            let breakin_pm_tid = u32::try_from(breakin_runtime_tid)
                .expect("debugger fixture runtime thread ID fits the process manager");
            for tid in [target_main, breakin_pm_tid] {
                while tid != 0 && nt_handler.pm.close_handle_by_object(
                    debugger_pid, nt_process::HandleObject::Thread(tid),
                ) {}
            }
            while nt_handler.pm.close_handle_by_object(
                debugger_pid, nt_process::HandleObject::Process(target),
            ) {}
            if saved_target_proc.is_some() {
                assert!(process_vm_region_map(test_pi).is_some_and(|map| map.extent_count() == 0));
                let (_, failed) = process_user_page_tables_release(test_pi, &mut nt_handler);
                assert_eq!(failed, 0, "diagnostic retains charged target page tables on failure");
            }
            if let Some(claim) = brk_test_claim {
                let _ = csrss_frame_take(test_pi as u64, SMSS_PEB_VA);
                assert!(nt_handler.release_temporary_process_slot(claim),
                    "debugger fixture releases its temporary process slot");
            }
            if let Some(previous) = saved_target_proc {
                if let Some(accounting) = nt_handler.process_commit.accounting(target) {
                    assert_eq!(accounting.current_bytes, 0);
                    assert_eq!(nt_handler.process_commit.unregister(target), Some(accounting));
                }
                let ctx = nt_handler.loop_ctx.expect("diagnostic target retains its paging context");
                assert_eq!((&*ctx.procs)[test_pi].pml4, target_pml4);
                (&mut *ctx.procs)[test_pi] = previous;
            }
            assert!(nt_handler.pm.process_debug_port(target).is_none(),
                "debugger fixture detaches before retiring target Ps bodies");
            nt_handler.pm.terminate_process(target, nt_process::STATUS_SUCCESS)
                .expect("debugger fixture terminates its throwaway target");
            crate::process_terminal_receipt::drain_hosted_process_exit_notifications(&mut nt_handler);
            let retirement = nt_handler.pm.withdraw_process_object_if_unreferenced(target)
                .expect("debugger fixture releases every target object reference");
            let backing = ps_object_backing::retire_withdrawn(
                &nt_handler.pm,
                &retirement,
                crate::executor::local().scratch_base.load(Ordering::Relaxed),
            ).expect("debugger fixture retires its canonical Ps bodies");
            let _deletion = nt_handler.pm.finish_process_object_retirement(retirement)
                .expect("debugger fixture finishes canonical Ps retirement");
            if ps_object_backing::release_retired_addresses(backing).is_err() {
                panic!("debugger fixture retains retired Ps address slots");
            }
            nt_handler.remote_thread_request = None;

            crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.loop_ctx = saved_ctx;
            nt_handler.wait_park_event = -1;
            nt_handler.wait_timeout = PendingWaitTimeout::none();
            DBGK_BREAKIN_SELFTEST.store(br_ok, Ordering::Relaxed);
        }

        // Path 1b COUNTED SPEC — process-local dense handle VALUES. Two DISTINCT live EPROCESSes each
        // allocate their first handle and BOTH get the SAME dense value (0x4), yet it refers to a
        // DIFFERENT object in each: proof of per-process handle namespaces (a global value scheme
        // could not hand out 0x4 twice). Runs post-loop on throwaway EPROCESSes (durable allocs are
        // safe — no reset follows), leaving the 3 hosted processes untouched.
        let pa = nt_handler.pm.create_process("hlocal-a.exe", None, None);
        let pb = nt_handler.pm.create_process("hlocal-b.exe", None, None);
        let ha = nt_handler
            .pm
            .insert_handle(pa, nt_process::HandleObject::Opaque(0xA11CE), 0);
        let hb = nt_handler
            .pm
            .insert_handle(pb, nt_process::HandleObject::Opaque(0xB0B), 0);
        let mut hl_ok = 0u64;
        if ha == Ok(4) && hb == Ok(4) {
            hl_ok |= 1; // both processes' FIRST handle is the same dense value 0x4
        }
        if nt_handler.pm.lookup_handle(pa, 4) == Some(nt_process::HandleObject::Opaque(0xA11CE))
            && nt_handler.pm.lookup_handle(pb, 4) == Some(nt_process::HandleObject::Opaque(0xB0B))
        {
            hl_ok |= 2; // the SAME value 0x4 resolves to a DIFFERENT object in each namespace
        }
        if nt_handler.pm.lookup_handle(pa, 4) != nt_handler.pm.lookup_handle(pb, 4) {
            hl_ok |= 4; // no cross-process aliasing
        }
        PM_HANDLE_LOCAL_OK.store(hl_ok, Ordering::Relaxed);

        // ITEM 2b — prove the seL4 MECHANISM-teardown (reclamation) on a THROWAWAY untyped/caps.
        // Runs here (post-loop, live boot only) alongside the other lifecycle self-tests; it touches
        // ONLY freshly-retyped throwaway caps + an unused scratch page, deletes everything it makes,
        // and never touches the 3 hosted processes' resources → byte-identical boot.
        PM_RECLAIM_OK.store(reclaim_mechanism_selftest(), Ordering::Relaxed);
        // ALPC last-mile item (b) — prove a REAL cross-address-space ALPC section view: two SEPARATE
        // throwaway endpoint VSpaces map the same port-section backing frames (copy_cap + page_map,
        // the CSRSS_ANON_BASE machinery), a hosted thread in one writes big data, a hosted thread in
        // the other reads it back through ITS OWN view mapping. Throwaway-only + reclaimed after →
        // the 3 live hosted processes are untouched (byte-identical boot).
        ALPC_XVIEW_OK.store(alpc_cross_vspace_selftest(), Ordering::Relaxed);
    }
    // Freeze hosted threads only after all post-quiesce active probes have run. The probes above
    // intentionally drive win32k callbacks, teardown, driver cancellation, and ALPC mappings; doing
    // a blanket TCB suspend before them corrupts the environment they are meant to prove.
    let (quiesce_suspended, quiesce_suspend_failures) =
        unsafe { nt_handler.suspend_hosted_threads_for_quiesce() };
    print_str(b"[quiesce-freeze] hosted-tcbs-suspended=");
    print_u64(quiesce_suspended as u64);
    print_str(b" failures=");
    print_u64(quiesce_suspend_failures as u64);
    print_str(b"\n");
    if csrss_process_handle != 0 {
        print_str(b"[sec-stop] csrss (badge 2) spawned, handle 0x");
        print_hex(csrss_process_handle as u32);
        print_str(b"; demand-paged ");
        print_u64(procs[csrss_pi].faults);
        print_str(b" page(s) (");
        print_u64(procs[csrss_pi].ntfaults);
        print_str(b" in ntdll), first fault=0x");
        print_hex((procs[csrss_pi].first >> 32) as u32);
        print_hex(procs[csrss_pi].first as u32);
        print_str(b"\n");
    }
    print_str(b"[sec-stop] NEXT_SLOT=");
    print_u64(NEXT_SLOT.load(Ordering::Relaxed));
    print_str(b" shared_frames=");
    print_u64(dll_cache_stats().0 as u64);
    print_str(b" shared_hits=");
    print_u64(DLL_SHARED_HITS.load(Ordering::Relaxed));
    print_str(b"\n[sec-stop] scratch-faults/pi=");
    for (pi, proc) in procs.iter().enumerate() {
        if pi != 0 {
            print_str(b",");
        }
        print_u64(pi as u64);
        print_str(b":");
        print_u64(proc.faults);
    }
    print_str(b" scratch-low-pts/pi=");
    for (pi, proc) in procs.iter().enumerate() {
        if pi != 0 {
            print_str(b",");
        }
        print_u64(pi as u64);
        print_str(b":");
        print_u64(proc.faults.saturating_add(511) / 512);
    }
    print_str(b"\n[sec-stop] badge=");
    print_u64(badge);
    print_str(b" (");
    print_str(hosted_leaf_for_fault_badge(&nt_handler, badge).unwrap_or(b"unknown"));
    print_str(b") label=");
    print_u64(mi >> 12);
    print_str(b" m0=0x");
    print_hex((m0 >> 32) as u32);
    print_hex(m0 as u32);
    print_str(b" m1=0x");
    print_hex((m1 >> 32) as u32);
    print_hex(m1 as u32);
    print_str(b" exc#=");
    print_u64(m3);
    print_str(b" code=0x");
    print_hex(get_recv_mr(4) as u32);
    print_str(b" iters=");
    print_u64(iters);
    print_str(b" dbgsvc=");
    print_u64(dbgsvc);
    print_str(b" stop_ssn=");
    print_u64(stop_ssn);
    // Dump the last serviced SSNs in chronological order (oldest first).
    print_str(b" ssns:");
    let ring_n = if ssn_ri < 32 { 0 } else { ssn_ri - 32 };
    for k in ring_n..ssn_ri {
        print_str(b" ");
        print_u64(ssn_ring_badge[k % 32] as u64);
        print_str(b":");
        print_u64(ssn_ring[k % 32] as u64);
    }
    // winlogon-main-only SSN sequence (badge 4), oldest first — isolates the StartLsass wall.
    print_str(b"\n[wl-ring]");
    let wl_n = if wl_ri < 48 { 0 } else { wl_ri - 48 };
    for k in wl_n..wl_ri {
        print_str(b" ");
        print_u64(wl_ring[k % 48] as u64);
    }
    // NtWriteVirtualMemory(287) diagnostic: dump the args + scan the caller's stack for smss/ntdll
    // return addresses to identify which routine issued it (RtlCreateUserProcess param-inject?).
    if stop_ssn == 287 {
        let sp = get_recv_mr(16);
        print_str(b"\n[287] proc=0x");
        print_hex(get_recv_mr(9) as u32); // R10 ProcessHandle
        print_str(b" base=0x");
        print_hex((m3 >> 32) as u32);
        print_hex(m3 as u32); // RDX BaseAddress
        print_str(b" buf=0x");
        print_hex((get_recv_mr(7) >> 32) as u32);
        print_hex(get_recv_mr(7) as u32); // R8 Buffer
        print_str(b" size=0x");
        print_hex(get_recv_mr(8) as u32); // R9 Size
        print_str(b" written*=0x");
        print_hex(smss_stack_read(sp + 0x28) as u32);
        print_str(b" chain:");
        let mut shown = 0;
        for i in 0..160u64 {
            let v = smss_stack_read(sp + i * 8);
            if v >= NTDLL_BASE && v < NTDLL_BASE + 0xf4000 {
                print_str(b" n+0x");
                print_hex((v - NTDLL_BASE) as u32);
                shown += 1;
            } else if v >= PE_LOAD_BASE && v < PE_LOAD_BASE + 0x40000 {
                // smss image
                print_str(b" s+0x");
                print_hex((v - PE_LOAD_BASE) as u32);
                shown += 1;
            }
            if shown >= 16 {
                break;
            }
        }
    }
    // NtRaiseHardError(190): decode the status (R10), Parameters[0], and the caller ([rsp]).
    // Guarded to this case — get_recv_mr(16)/(8) only hold a valid smss stack ptr here.
    if stop_ssn == 190 {
        print_str(b" r10=0x");
        print_hex((get_recv_mr(9) >> 32) as u32);
        print_hex(get_recv_mr(9) as u32);
        print_str(b" param0=0x");
        print_hex(smss_stack_read(get_recv_mr(8)) as u32);
        print_str(b" caller=0x");
        print_hex(smss_stack_read(get_recv_mr(16)) as u32);
        // Scan the stack for ntdll AND kernel32 return addresses to reconstruct the call chain that
        // produced the failure status (winlogon's CreateProcessW hard-error path is kernel32 code).
        let sp = get_recv_mr(16);
        print_str(b" chain:");
        let mut shown = 0;
        for i in 0..160u64 {
            let v = smss_stack_read(sp + i * 8);
            if v >= NTDLL_BASE && v < NTDLL_BASE + 0xf4000 {
                print_str(b" n+0x");
                print_hex((v - NTDLL_BASE) as u32);
                shown += 1;
            } else if v >= 0x803a0000 && v < 0x803a0000 + 0x2b0000 {
                print_str(b" k32+0x");
                print_hex((v - 0x803a0000) as u32);
                shown += 1;
            }
            if shown >= 20 {
                break;
            }
        }
    }
    print_str(b"\n");
    {
        loader_trace_dump(&reg);
    }
    if let Some(winlogon_pi) = live_hosted_pi_for_observation_role(
        &nt_handler,
        nt_exe_image::HostedProcessRole::InteractiveLogon,
    ) {
        WINLOGON_FAULTS.store(procs[winlogon_pi].faults, Ordering::Relaxed);
        print_str(b"[ntos-exec] winlogon (pi ");
        print_u64(winlogon_pi as u64);
        print_str(b") demand-faulted ");
        print_u64(procs[winlogon_pi].faults);
        print_str(b" page(s), first=0x");
        print_hex((procs[winlogon_pi].first >> 32) as u32);
        print_hex(procs[winlogon_pi].first as u32);
        print_str(b"\n");
    } else {
        WINLOGON_FAULTS.store(0, Ordering::Relaxed);
    }
    if let Some(services_pi) = live_hosted_pi_for_observation_role(
        &nt_handler,
        nt_exe_image::HostedProcessRole::ServiceControlManager,
    ) {
        SERVICES_FAULTS.store(procs[services_pi].faults, Ordering::Relaxed);
        print_str(b"[ntos-exec] services (pi ");
        print_u64(services_pi as u64);
        print_str(b") demand-faulted ");
        print_u64(procs[services_pi].faults);
        print_str(b" page(s), first=0x");
        print_hex((procs[services_pi].first >> 32) as u32);
        print_hex(procs[services_pi].first as u32);
        print_str(b"\n");
    } else {
        SERVICES_FAULTS.store(0, Ordering::Relaxed);
    }
    if let Some(lsass_pi) = live_hosted_pi_for_observation_role(
        &nt_handler,
        nt_exe_image::HostedProcessRole::LocalSecurityAuthority,
    ) {
        LSASS_FAULTS.store(procs[lsass_pi].faults, Ordering::Relaxed);
        print_str(b"[ntos-exec] lsass (pi ");
        print_u64(lsass_pi as u64);
        print_str(b") demand-faulted ");
        print_u64(procs[lsass_pi].faults);
        print_str(b" page(s), first=0x");
        print_hex((procs[lsass_pi].first >> 32) as u32);
        print_hex(procs[lsass_pi].first as u32);
        print_str(b"\n");
    } else {
        LSASS_FAULTS.store(0, Ordering::Relaxed);
    }
    // Path 3: record that each folded per-process ProcExec is EPROCESS-linked (live pml4 + its pid
    // matches the ProcessManager's pid for that pi). Read by `exec_eprocess_linked_mechanism`.
    let mut link_ok = 0u64;
    for (i, p) in procs.iter().enumerate() {
        if p.pml4 != 0
            && p.pid != 0
            && nt_handler.pm_pid_for_pi(i).map(|pid| pid as u64) == Some(p.pid)
        {
            link_ok |= 1 << i;
        }
    }
    PM_EXEC_LINK_OK.store(link_ok, Ordering::Relaxed);
    // Report the primary process's own fault stats regardless of which process stopped the loop.
    let boot_driver_start_reports = pending_driver_start_reports_snapshot(&nt_handler);
    let native_driver_load_report = nt_handler.native_driver_load_report;
    let live_device_action_report = print_live_device_action_report(&nt_handler);
    let start_device_call_report = print_start_device_call_report(&nt_handler);
    let desktop_acceptance_report = nt_handler.capture_desktop_acceptance_report();
    nt_handler.loop_ctx = None;
    (
        procs[primary_pi].faults,
        procs[primary_pi].first,
        stop,
        procs[primary_pi].ntfaults,
        stop_ssn,
        boot_driver_start_reports,
        native_driver_load_report,
        live_device_action_report,
        start_device_call_report,
        desktop_acceptance_report,
    )
}

#[inline(never)]
unsafe fn spawn_requested_multiplexed_thread(
    nt_handler: &mut ExecNtHandler,
    spec: HostedThreadSpawnSpec,
    procs: &[ProcExec],
    start: nt_thread_start::Amd64ThreadContext,
    initial_context: &nt_thread_start::amd64_context::InitialAmd64Context,
    initial_teb: nt_thread_start::InitialTeb64,
    publication: PreparedHostedThreadPublication,
    fault_ep: u64,
) -> Result<(), u32> {
    let (owner_pi, cid_proc, pml4) =
        live_process_context_for_role(nt_handler, procs, spec.owner_role)
            .expect("hosted EPROCESS missing before multiplexed thread spawn");
    let tid = publication.tid();
    if publication.pid() != cid_proc
        || nt_handler.hosted_thread_tid_for_role(owner_pi, spec.role) != Some(tid)
    {
        nt_handler.abort_unbuilt_hosted_thread_publication(
            publication, owner_pi, spec.badge, spec.role,
        );
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }

    let suspended = publication.create_suspended();
    let resume = !suspended;

    print_str(spec.spawn_prefix);
    print_hex_u64(start.rip);
    print_str(b" rcx=0x");
    print_hex_u64(start.rcx);
    print_str(b" rdx=0x");
    print_hex_u64(start.rdx);
    print_str(b" rsp=0x");
    print_hex_u64(start.rsp);
    print_str(b" tid=");
    print_u64(tid);
    print_str(b" stack=(");
    print_hex_u64(initial_teb.stack_base);
    print_str(b",");
    print_hex_u64(initial_teb.stack_limit);
    print_str(b",");
    print_hex_u64(initial_teb.allocated_stack_base);
    print_str(b") suspended=");
    print_u64(suspended as u64);
    print_str(b" resume=");
    print_u64(resume as u64);
    print_str(b"\n");

    let runtime_publication = match nt_handler.prepare_hosted_thread_runtime_publication(
        owner_pi, tid, spec.badge, spec.role,
    ) {
        Ok(prepared) => prepared,
        Err(status) => {
            nt_handler.abort_unbuilt_hosted_thread_publication(publication, owner_pi, spec.badge, spec.role);
            return Err(status);
        }
    };
    let spawned = match spec.spawner {
        HostedMultiplexedThreadSpawner::ServicesListener => spawn_svc_listener_thread(
            nt_handler,
            owner_pi,
            pml4,
            start,
            initial_context,
            initial_teb,
            cid_proc,
            tid,
            fault_ep,
        ),
        HostedMultiplexedThreadSpawner::LsassListener => spawn_lsass_listener_thread(
            nt_handler,
            owner_pi,
            pml4,
            start,
            initial_context,
            initial_teb,
            cid_proc,
            tid,
            fault_ep,
        ),
        HostedMultiplexedThreadSpawner::LsassListener2 => spawn_lsass_listener2_thread(
            nt_handler,
            owner_pi,
            pml4,
            start,
            initial_context,
            initial_teb,
            cid_proc,
            tid,
            fault_ep,
        ),
        HostedMultiplexedThreadSpawner::LsassListener3 => spawn_lsass_listener3_thread(
            nt_handler,
            owner_pi,
            pml4,
            start,
            initial_context,
            initial_teb,
            cid_proc,
            tid,
            fault_ep,
        ),
    };
    let spawned = match spawned {
        Ok(spawned) => spawned,
        Err(failure) => {
            nt_handler.fail_hosted_thread_runtime_publication(runtime_publication, failure);
            nt_handler.abort_unbuilt_hosted_thread_publication(publication, owner_pi, spec.badge, spec.role);
            return Err(nt_process::STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    let tcb = spawned.tcb();
    nt_handler.finish_hosted_thread_publication(runtime_publication, spawned, publication, resume)?;

    print_str(spec.spawned_prefix);
    print_hex(tcb as u32);
    print_str(b" stack-record=");
    print_u64(1);
    print_str(b" resume=");
    print_u64(resume as u64);
    print_str(spec.spawned_suffix);
    Ok(())
}

#[inline(never)]
unsafe fn dump_interactive_logon_quiesce(
    nt_handler: &ExecNtHandler,
    loaded_images: &HostedLoadedImageTable,
    reg: &nt_dll_registry::Registry,
    ntdll: (u64, &nt_pe_loader::PeFile),
    procs: &[ProcExec],
    pfilled: &[[u64; 512]],
) {
    let Some(pi) = live_hosted_pi_for_observation_role(
        nt_handler,
        nt_exe_image::HostedProcessRole::InteractiveLogon,
    ) else {
        print_str(b"[wl-quiesce] no runtime-registered interactive logon process\n");
        return;
    };
    dump_hosted_main_thread_quiesce(
        b"wl-quiesce",
        pi,
        nt_handler,
        loaded_images,
        reg,
        ntdll,
        procs,
        pfilled,
    );
}

unsafe fn dump_hot_hosted_thread_quiesce(
    nt_handler: &ExecNtHandler,
    loaded_images: &HostedLoadedImageTable,
    reg: &nt_dll_registry::Registry,
    ntdll: (u64, &nt_pe_loader::PeFile),
    procs: &[ProcExec],
    pfilled: &[[u64; 512]],
) {
    let mut hot_badge = u64::MAX;
    let mut hot_time = 0u64;
    let mut hot_events = 0u64;
    for badge in 0..36usize {
        let events = BADGE_EVENTS[badge].load(Ordering::Relaxed);
        if events == 0 {
            continue;
        }
        let time = BADGE_TIME_100NS[badge].load(Ordering::Relaxed);
        if time > hot_time || (time == hot_time && events > hot_events) {
            hot_badge = badge as u64;
            hot_time = time;
            hot_events = events;
        }
    }
    if hot_badge == u64::MAX {
        print_str(b"[hot-quiesce] no hosted badge census entries\n");
        return;
    }
    if HOT_HOSTED_QUIESCE_DUMPED.fetch_or(1, Ordering::Relaxed) & 1 != 0 {
        return;
    }

    let Some(pi) = nt_handler.hosted_thread_pi_for_badge(hot_badge) else {
        print_str(b"[hot-quiesce] hot badge has no hosted thread runtime badge=");
        print_u64(hot_badge);
        print_str(b" events=");
        print_u64(hot_events);
        print_str(b" ms=");
        print_u64(hot_time / 10_000);
        print_str(b"\n");
        return;
    };
    let Some(tid) = nt_handler.hosted_thread_tid_for_badge(hot_badge) else {
        print_str(b"[hot-quiesce] hot badge has no hosted tid badge=");
        print_u64(hot_badge);
        print_str(b" pi=");
        print_u64(pi as u64);
        print_str(b"\n");
        return;
    };
    let Some(tcb) = nt_handler.hosted_thread_tcb_for_badge(hot_badge) else {
        print_str(b"[hot-quiesce] hot badge has no hosted tcb badge=");
        print_u64(hot_badge);
        print_str(b" pi=");
        print_u64(pi as u64);
        print_str(b" tid=");
        print_u64(tid);
        print_str(b"\n");
        return;
    };

    print_str(b"[hot-quiesce] badge=");
    print_u64(hot_badge);
    print_str(b" pi=");
    print_u64(pi as u64);
    print_str(b" tid=");
    print_u64(tid);
    print_str(b" events=");
    print_u64(hot_events);
    print_str(b" ms=");
    print_u64(hot_time / 10_000);
    print_str(b"\n");
    dump_hosted_thread_quiesce(
        b"hot-quiesce",
        pi,
        tid,
        tcb,
        hot_badge,
        nt_handler,
        loaded_images,
        reg,
        ntdll,
        procs,
        pfilled,
    );
}

#[inline]
fn print_quiesce_tag(label: &[u8], suffix: &[u8]) {
    print_str(b"[");
    print_str(label);
    print_str(suffix);
    print_str(b"]");
}

#[inline(never)]
unsafe fn dump_hosted_quiesce_rip_mapping(label: &[u8], pi: usize, rip: u64) {
    let page = rip & !0xfff;
    print_quiesce_tag(label, b"-rip-map");
    print_str(b" page=0x");
    print_hex_u64(page);
    if let Some(info) = process_committed_mapping_basic_information(pi as u64, page) {
        print_str(b" base=0x");
        print_hex_u64(info.base_address);
        print_str(b" alloc=0x");
        print_hex_u64(info.allocation_base);
        print_str(b" size=0x");
        print_hex_u64(info.region_size);
        print_str(b" state=0x");
        print_hex(info.state);
        print_str(b" protect=0x");
        print_hex(info.protect);
        print_str(b" type=0x");
        print_hex(info.type_);
    } else {
        print_str(b" committed=none");
    }
    if let Some(image) = process_committed_image_allocation(pi as u64, page) {
        print_str(b" image=[0x");
        print_hex_u64(image.allocation_base);
        print_str(b"..0x");
        print_hex_u64(image.allocation_end);
        print_str(b")");
    } else {
        print_str(b" image=none");
    }
    if let Some(record) = csrss_frame_get_exact_record(pi as u64, page) {
        print_str(b" exact-frame=0x");
        print_hex(record.frame as u32);
        print_str(b" alias=0x");
        print_hex(record.alias as u32);
        print_str(b" source=0x");
        print_hex(record.source_cap as u32);
        print_str(b" owns=");
        print_u64(record.owns_frame as u64);
    } else {
        print_str(b" exact-frame=none");
    }
    match shared_image_mapping_debug(pi as u64, page) {
        Some(SharedImageMappingCap::Root(map_cap)) => {
            print_str(b" shared-map=0x");
            print_hex(map_cap as u32);
        }
        Some(SharedImageMappingCap::Bank { cnode, slot }) => {
            print_str(b" shared-map-bank=0x");
            print_hex(cnode as u32);
            print_str(b"/");
            print_u64(slot as u64);
        }
        None => print_str(b" shared-map=none"),
    }
    let shared_cache = dll_cache_get(page);
    print_str(b" shared-cache=0x");
    print_hex(shared_cache as u32);
    print_str(b"\n");
}

#[inline(never)]
unsafe fn dump_hosted_main_thread_quiesce(
    label: &[u8],
    pi: usize,
    nt_handler: &ExecNtHandler,
    loaded_images: &HostedLoadedImageTable,
    reg: &nt_dll_registry::Registry,
    ntdll: (u64, &nt_pe_loader::PeFile),
    procs: &[ProcExec],
    pfilled: &[[u64; 512]],
) {
    let Some((tid, tcb, badge)) =
        nt_handler.hosted_thread_identity_for_role(pi, HostedThreadRole::Main)
    else {
        print_quiesce_tag(label, b"");
        print_str(b" process has no live main-thread TCB pi=");
        print_u64(pi as u64);
        print_str(b"\n");
        return;
    };

    dump_hosted_thread_quiesce(
        label,
        pi,
        tid,
        tcb,
        badge,
        nt_handler,
        loaded_images,
        reg,
        ntdll,
        procs,
        pfilled,
    );
}

#[inline(never)]
unsafe fn dump_hosted_thread_quiesce(
    label: &[u8],
    pi: usize,
    tid: u64,
    tcb: u64,
    badge: u64,
    nt_handler: &ExecNtHandler,
    loaded_images: &HostedLoadedImageTable,
    reg: &nt_dll_registry::Registry,
    ntdll: (u64, &nt_pe_loader::PeFile),
    procs: &[ProcExec],
    pfilled: &[[u64; 512]],
) {
    let Some(caller) = hosted_quiesce::quiesce_caller(nt_handler, pi, tid, tcb, badge) else {
        print_quiesce_tag(label, b"-caller");
        print_str(b" unavailable (no exact current process/thread lifetime)\n");
        return;
    };
    let process = Some(caller.process());
    let wait = object_wait_snapshot_for_caller(caller);
    hosted_quiesce::print_wait_snapshot(label, wait);
    let reply = wait.filter(|wait| !wait.reply_sent).map_or(0, |wait| wait.reply_cap);
    if reply == 0 {
        print_quiesce_tag(label, b"-reply");
        print_str(b" unavailable (no exact unsent dispatcher-wait Reply)\n");
    }
    crate::win32k_glue::trace_hosted_tcb_debug_state(label, tcb, reply);
    let context = match crate::thread_context::LegacyThreadContext::read(tcb) {
        Ok(context) => context,
        Err(error) => {
            print_quiesce_tag(label, b"-registers");
            print_str(b" unavailable tcb=0x");
            print_hex_u64(tcb);
            print_str(b" error=0x");
            print_hex_u64(error);
            print_str(b"\n");
            return;
        }
    };
    let regs = context.registers;
    let rip = regs[nt_user_callback::USER_CONTEXT_RIP];
    let rsp = regs[nt_user_callback::USER_CONTEXT_RSP];
    let rax = regs[nt_user_callback::USER_CONTEXT_RAX];
    let rcx = regs[nt_user_callback::USER_CONTEXT_RCX];
    let rdx = regs[nt_user_callback::USER_CONTEXT_RDX];
    let r8 = regs[nt_user_callback::USER_CONTEXT_R8];
    let r9 = regs[nt_user_callback::USER_CONTEXT_R9];

    print_quiesce_tag(label, b"");
    print_str(b" pi=");
    print_u64(pi as u64);
    print_str(b" tid=");
    print_u64(tid);
    print_str(b" badge=");
    print_u64(badge);
    print_str(b" tcb=0x");
    print_hex(tcb as u32);
    print_str(b" state=");
    if tid <= nt_process::ThreadId::MAX as u64 {
        match nt_handler
            .pm
            .thread(tid as nt_process::ThreadId)
            .map(|thread| thread.state)
        {
            Some(nt_process::ThreadState::Initialized) => print_str(b"Initialized"),
            Some(nt_process::ThreadState::Ready) => print_str(b"Ready"),
            Some(nt_process::ThreadState::Running) => print_str(b"Running"),
            Some(nt_process::ThreadState::Waiting) => print_str(b"Waiting"),
            Some(nt_process::ThreadState::Suspended) => print_str(b"Suspended"),
            Some(nt_process::ThreadState::Terminated) => print_str(b"Terminated"),
            None => print_str(b"?"),
        }
    } else {
        print_str(b"?");
    }
    print_str(b" parked=");
    print_u64(thread_wait_state_badge_parked(badge) as u64);
    print_str(b" rip=");
    print_quiesce_addr(rip, pi, loaded_images, reg, ntdll);
    print_str(b" rsp=0x");
    print_hex_u64(rsp);
    print_str(b" rax=0x");
    print_hex_u64(rax);
    print_str(b" rcx=0x");
    print_hex_u64(rcx);
    print_str(b" rdx=0x");
    print_hex_u64(rdx);
    print_str(b" r8=0x");
    print_hex_u64(r8);
    print_str(b" r9=0x");
    print_hex_u64(r9);
    print_str(b"\n");

    dump_hosted_quiesce_rip_mapping(label, pi, rip);

    let mut threads = [HostedThreadQuiesceRecord::empty(); 32];
    let (count, overflow) = nt_handler.hosted_thread_quiesce_records_for_pi(pi, &mut threads);
    print_quiesce_tag(label, b"-threads");
    print_str(b" overflow=");
    print_u64(overflow as u64);
    print_str(b" threads=");
    for thread in threads[..count].iter().copied() {
        print_wait_snapshot_thread(thread);
    }
    print_str(b"\n");

    let Some((stack_base, stack_size, stack_mirror, _, _)) =
        mirror_ctx_for(nt_handler, badge, pi, tid)
    else {
        print_quiesce_tag(label, b"-runtime-retired");
        print_str(b"\n");
        return;
    };
    let mirror_stack_end = stack_base.checked_add(stack_size);
    let hosted_stack_range = nt_handler.hosted_thread_user_stack_for_badge(badge, pi);
    let rsp_has_qword =
        rsp.checked_add(8)
            .is_some_and(|end| match (mirror_stack_end, hosted_stack_range) {
                (Some(mirror_end), _) if rsp >= stack_base && end <= mirror_end => true,
                (_, Some((allocation_base, stack_base, _))) => {
                    rsp >= allocation_base && end <= stack_base
                }
                _ => false,
            });
    let read_wl = |va: u64| -> Option<u64> {
        unsafe {
            let end = va.checked_add(8)?;
            if mirror_stack_end.is_some_and(|mirror_end| va >= stack_base && end <= mirror_end) {
                return Some(core::ptr::read_volatile(
                    (stack_mirror + (va - stack_base)) as *const u64,
                ));
            }
            let mut bytes = [0u8; 8];
            quiesce_copyin_process_bytes(pi, process, va, &mut bytes, procs)
                .then(|| u64::from_le_bytes(bytes))
        }
    };

    print_quiesce_tag(label, b"-stack");
    print_str(b" rsp=0x");
    print_hex_u64(rsp);
    print_str(b" mirror=[0x");
    print_hex_u64(stack_base);
    print_str(b"..0x");
    if let Some(mirror_end) = mirror_stack_end {
        print_hex_u64(mirror_end);
    } else {
        print_str(b"overflow");
    }
    print_str(b") runtime=");
    if let Some((allocation_base, stack_base, _)) = hosted_stack_range {
        print_str(b"[0x");
        print_hex_u64(allocation_base);
        print_str(b"..0x");
        print_hex_u64(stack_base);
        print_str(b")");
    } else {
        print_str(b"none");
    }
    if !rsp_has_qword {
        print_str(b" invalid-stack-pointer -> stack walk skipped\n");
        print_quiesce_tag(label, b"-callers");
        print_str(b" skipped-invalid-rsp\n");
        return;
    }
    print_str(b" top:");
    for slot in 0..8u64 {
        print_str(b" +");
        print_u64(slot * 8);
        print_str(b"=");
        match rsp.checked_add(slot.saturating_mul(8)).and_then(&read_wl) {
            Some(value) => print_hex_u64(value),
            None => print_str(b"?"),
        }
    }
    print_str(b"\n");
    print_quiesce_tag(label, b"-callers");
    let mut shown = 0usize;
    let mut iat_shown = 0usize;
    for slot in 0..160u64 {
        let Some(value) = rsp.checked_add(slot.saturating_mul(8)).and_then(&read_wl) else {
            continue;
        };
        if !quiesce_addr_is_known(value, pi, loaded_images, reg, ntdll) {
            continue;
        }
        print_str(b" +");
        print_u64(slot * 8);
        print_str(b"=");
        print_quiesce_addr(value, pi, loaded_images, reg, ntdll);
        shown += 1;
        if iat_shown < 4
            && print_quiesce_iat_call_site(
                label,
                value,
                pi,
                process,
                loaded_images,
                reg,
                ntdll,
                procs,
            )
        {
            iat_shown += 1;
        }
        if shown >= 24 {
            break;
        }
    }
    if shown == 0 {
        print_str(b" <none>");
    }
    print_str(b"\n");
}

#[inline]
unsafe fn quiesce_copyin_process_bytes(
    pi: usize,
    process: Option<nt_memory_manager::ProcessIdentity>,
    va: u64,
    dst: &mut [u8],
    procs: &[ProcExec],
) -> bool {
    let Some(process) = process else {
        return false;
    };
    if pi >= MAX_PI {
        return false;
    }
    img_spawn::client_copyin_process_mapped_for(
        pi as u64,
        process,
        va,
        dst,
        procs[pi].scratch_base,
    )
}

#[inline]
unsafe fn print_quiesce_iat_call_site(
    label: &[u8],
    return_address: u64,
    pi: usize,
    process: Option<nt_memory_manager::ProcessIdentity>,
    loaded_images: &HostedLoadedImageTable,
    reg: &nt_dll_registry::Registry,
    ntdll: (u64, &nt_pe_loader::PeFile),
    procs: &[ProcExec],
) -> bool {
    let Some(insn_address) = return_address.checked_sub(6) else {
        return false;
    };
    let mut insn = [0u8; 6];
    if !quiesce_copyin_process_bytes(pi, process, insn_address, &mut insn, procs) {
        return false;
    }
    if insn[0] != 0xff || insn[1] != 0x15 {
        return false;
    }
    let disp = i32::from_le_bytes([insn[2], insn[3], insn[4], insn[5]]) as i64;
    let slot_address = if disp >= 0 {
        return_address.checked_add(disp as u64)
    } else {
        return_address.checked_sub(disp.unsigned_abs())
    };
    let Some(slot_address) = slot_address else {
        return false;
    };
    let mut target_bytes = [0u8; 8];
    let target =
        if quiesce_copyin_process_bytes(pi, process, slot_address, &mut target_bytes, procs) {
            Some(u64::from_le_bytes(target_bytes))
        } else {
            None
        };

    print_str(b"\n");
    print_quiesce_tag(label, b"-iat");
    print_str(b" ret=");
    print_quiesce_addr(return_address, pi, loaded_images, reg, ntdll);
    print_str(b" slot=0x");
    print_hex_u64(slot_address);
    print_str(b" target=");
    match target {
        Some(address) => print_quiesce_addr(address, pi, loaded_images, reg, ntdll),
        None => print_str(b"?"),
    }
    true
}

#[inline]
unsafe fn quiesce_addr_is_known(
    address: u64,
    pi: usize,
    loaded_images: &HostedLoadedImageTable,
    reg: &nt_dll_registry::Registry,
    ntdll: (u64, &nt_pe_loader::PeFile),
) -> bool {
    if let Some(layout) = loaded_images.layout_by_pi(pi) {
        if layout.rva(address).is_some() {
            return true;
        }
    }
    let (base, pe) = ntdll;
    if address >= base && address < base + image_extent(pe) {
        return true;
    }
    reg.dll_for_page(pi, address).is_some()
}

#[inline]
unsafe fn print_quiesce_addr(
    address: u64,
    pi: usize,
    loaded_images: &HostedLoadedImageTable,
    reg: &nt_dll_registry::Registry,
    ntdll: (u64, &nt_pe_loader::PeFile),
) {
    print_str(b"0x");
    print_hex_u64(address);
    print_str(b"(");
    if let Some(layout) = loaded_images.layout_by_pi(pi) {
        if let Some(rva) = layout.rva(address) {
            match loaded_images.get_by_pi(pi) {
                Some(image) => print_str(image.leaf()),
                None => print_str(b"exe"),
            }
            print_str(b"+0x");
            print_hex(rva as u32);
            print_str(b")");
            return;
        }
    }
    let (base, pe) = ntdll;
    if address >= base && address < base + image_extent(pe) {
        print_str(b"ntdll+0x");
        print_hex((address - base) as u32);
        print_str(b")");
        return;
    }
    if let Some((i, rva)) = reg.dll_for_page(pi, address) {
        let name = reg.name(i);
        if name.is_empty() {
            print_str(b"dll");
        } else {
            print_str(name);
        }
        print_str(b"+0x");
        print_hex(rva);
        print_str(b")");
        return;
    }
    print_str(b"unknown)");
}

#[inline]
fn live_process_context_for_role(
    nt_handler: &ExecNtHandler,
    procs: &[ProcExec],
    role: nt_exe_image::HostedProcessRole,
) -> Option<(usize, u64, u64)> {
    let pi = hosted_pi_for_role(nt_handler, role)?;
    let pid = nt_handler.pm_pid_for_pi(pi)?;
    nt_handler.pm.process(pid)?;
    Some((pi, pid as u64, procs[pi].pml4))
}

#[inline(never)]
unsafe fn spawn_requested_local_thread(
    nt_handler: &mut ExecNtHandler,
    request: HostedThreadSpawnRequest,
    procs: &[ProcExec],
    fault_ep: u64,
) -> Result<(), u32> {
    let (publication, start, stack_origin) = match &request {
        HostedThreadSpawnRequest::Multiplexed { publication, start, initial_teb, .. }
        | HostedThreadSpawnRequest::Winlogon { publication, start, initial_teb, .. } =>
            (publication, *start, ThreadStackOrigin::Caller(*initial_teb)),
        HostedThreadSpawnRequest::TpWorker { publication, start, stack_origin, .. } =>
            (publication, *start, *stack_origin),
    };
    if let ThreadStackOrigin::Caller(initial_teb) = stack_origin {
        if let Err(status) = nt_handler.validate_hosted_caller_stack(
            publication.owner_pi, start, initial_teb,
        ) {
            let publication = match request {
                HostedThreadSpawnRequest::Multiplexed { publication, .. }
                | HostedThreadSpawnRequest::Winlogon { publication, .. }
                | HostedThreadSpawnRequest::TpWorker { publication, .. } => publication,
            };
            nt_handler.abort_unbuilt_hosted_thread_request(publication);
            return Err(status);
        }
    }
    match request {
        HostedThreadSpawnRequest::Multiplexed {
            kind,
            start,
            initial_context,
            initial_teb,
            publication,
        } => {
            let Some(spec) = hosted_multiplexed_thread_spawn_for(kind) else {
                nt_handler.abort_unbuilt_hosted_thread_request(publication);
                return Err(nt_process::STATUS_INVALID_PARAMETER);
            };
            spawn_requested_multiplexed_thread(
                nt_handler,
                spec,
                procs,
                start,
                &initial_context,
                initial_teb,
                publication,
                fault_ep,
            )
        }
        HostedThreadSpawnRequest::Winlogon {
            slot,
            start,
            initial_context,
            initial_teb,
            publication,
        } => {
            let (role, badge, teb) = match slot {
                0 => (
                    HostedThreadRole::WinlogonListener,
                    WINLOGON_WORKER_BADGE,
                    WL_LISTENER_TEB_VA,
                ),
                1 => (
                    HostedThreadRole::WinlogonWorker { slot },
                    WINLOGON_WORKER2_BADGE,
                    WL_WORKER2_TEB_VA,
                ),
                2 => (
                    HostedThreadRole::WinlogonWorker { slot },
                    WINLOGON_WORKER3_BADGE,
                    WL_WORKER3_TEB_VA,
                ),
                _ => {
                    nt_handler.abort_unbuilt_hosted_thread_request(publication);
                    return Err(nt_process::STATUS_INVALID_PARAMETER);
                }
            };
            let (wl_pi, cid_proc, pml4) = live_process_context_for_role(
                nt_handler,
                procs,
                nt_exe_image::HostedProcessRole::InteractiveLogon,
            )
            .expect("winlogon EPROCESS missing before worker spawn");
            let tid = publication.tid();
            if publication.pid() != cid_proc
                || nt_handler.hosted_thread_tid_for_role(wl_pi, role) != Some(tid)
            {
                print_str(b"[wl-thread] missing reserved runtime role before spawn\n");
                nt_handler.abort_unbuilt_hosted_thread_publication(
                    publication, wl_pi, badge, role,
                );
                return Err(nt_process::STATUS_INVALID_PARAMETER);
            }
            print_str(b"[wl-thread] spawning REAL worker slot=");
            print_u64(slot as u64);
            print_str(b" (multiplexed): entry=0x");
            print_hex((start.rip >> 32) as u32);
            print_hex(start.rip as u32);
            print_str(b" arg0=0x");
            print_hex((start.rcx >> 32) as u32);
            print_hex(start.rcx as u32);
            print_str(b" arg1=0x");
            print_hex((start.rdx >> 32) as u32);
            print_hex(start.rdx as u32);
            print_str(b" tid=");
            print_u64(tid);
            print_str(b"\n");
            let suspended = publication.create_suspended();
            let runtime_publication = match nt_handler.prepare_hosted_thread_runtime_publication(wl_pi, tid, badge, role) {
                Ok(prepared) => prepared,
                Err(status) => {
                    nt_handler.abort_unbuilt_hosted_thread_publication(publication, wl_pi, badge, role);
                    return Err(status);
                }
            };
            let spawned = spawn_wl_listener_thread(
                nt_handler,
                wl_pi,
                slot,
                pml4,
                start,
                &initial_context,
                initial_teb,
                cid_proc,
                tid,
                fault_ep,
            );
            let spawned = match spawned {
                Ok(spawned) => spawned,
                Err(failure) => {
                    nt_handler.fail_hosted_thread_runtime_publication(runtime_publication, failure);
                    nt_handler.abort_unbuilt_hosted_thread_publication(publication, wl_pi, badge, role);
                    return Err(nt_process::STATUS_INSUFFICIENT_RESOURCES);
                }
            };
            let tcb = spawned.tcb();
            nt_handler.finish_hosted_thread_publication(runtime_publication, spawned, publication, !suspended)?;
            if slot == 0 {
                let mapped_low = initial_teb
                    .stack_limit
                    .checked_sub(nt_thread_start::USER_PAGE_SIZE)
                    .filter(|&low| {
                        initial_teb.allocated_stack_base & 0xfff == 0
                            && initial_teb.stack_base & 0xfff == 0
                            && initial_teb.allocated_stack_base <= low
                            && low < initial_teb.stack_base
                            && csrss_frame_get_exact(wl_pi as u64, low).0 != 0
                    })
                    .unwrap_or(0);
                if mapped_low != 0 {
                    WL_LISTENER_STACK_ALLOCATION_BASE
                        .store(initial_teb.allocated_stack_base, Ordering::Release);
                    WL_LISTENER_STACK_BASE_REAL.store(initial_teb.stack_base, Ordering::Release);
                    WL_LISTENER_STACK_MAPPED_LOW.store(mapped_low, Ordering::Release);
                } else {
                    WL_LISTENER_STACK_ALLOCATION_BASE.store(0, Ordering::Release);
                    WL_LISTENER_STACK_BASE_REAL.store(0, Ordering::Release);
                    WL_LISTENER_STACK_MAPPED_LOW.store(0, Ordering::Release);
                    print_str(b"[wl-thread] real stack reservation could not be armed\n");
                }
                WL_LISTENER_THREAD_MINTED.store(1, Ordering::Relaxed);
            }
            print_str(b"[wl-thread] spawned tcb=0x");
            print_hex(tcb as u32);
            print_str(b" TEB=0x");
            print_hex((teb >> 32) as u32);
            print_hex(teb as u32);
            print_str(if suspended {
                b" (SUSPENDED; NtResumeThread owns first run; real ETHREAD + TEB)\n"
            } else {
                b" (RESUMED into multiplex; real ETHREAD + TEB)\n"
            });
            Ok(())
        }
        HostedThreadSpawnRequest::TpWorker {
            pi,
            slot,
            start,
            initial_context,
            stack_origin,
            publication,
        } => {
            if pi < MAX_PI && slot < TP_WORKER_SLOT_COUNT {
                spawn_requested_tp_worker(
                    nt_handler,
                    pi,
                    slot,
                    procs[pi].pml4,
                    start,
                    &initial_context,
                    stack_origin,
                    publication,
                    fault_ep,
                )
            } else {
                nt_handler.release_unmapped_hosted_tp_worker_slot(pi, slot, publication.tid());
                nt_handler.abort_hosted_thread_publication(publication);
                Err(nt_process::STATUS_INVALID_PARAMETER)
            }
        }
    }
}

#[inline(never)]
unsafe fn spawn_requested_tp_worker(
    nt_handler: &mut ExecNtHandler,
    pi: usize,
    worker_slot: usize,
    pml4: u64,
    start: nt_thread_start::Amd64ThreadContext,
    initial_context: &nt_thread_start::amd64_context::InitialAmd64Context,
    stack_origin: ThreadStackOrigin,
    publication: PreparedHostedThreadPublication,
    fault_ep: u64,
) -> Result<(), u32> {
    let badge = tp_worker_badge(pi, worker_slot);
    if nt_handler.hosted_thread_tcb_for_badge(badge).is_some() {
        nt_handler.release_unmapped_hosted_tp_worker_slot(pi, worker_slot, publication.tid());
        nt_handler.abort_hosted_thread_publication(publication);
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }

    let tid = publication.tid();
    if nt_handler.hosted_thread_tid_for_badge(badge) != Some(tid) {
        nt_handler.release_unmapped_hosted_tp_worker_slot(pi, worker_slot, tid);
        nt_handler.abort_hosted_thread_publication(publication);
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }
    let role = nt_handler
        .hosted_thread_role_for_badge(badge)
        .unwrap_or(HostedThreadRole::TpWorker { slot: worker_slot });
    let cid_proc = nt_handler.pm_pid_for_pi(pi).unwrap_or(0) as u64;
    let suspended = publication.create_suspended();
    let rpc_worker = role.is_scm_rpc_worker() || role.is_lsa_rpc_worker();
    let runtime_publication = match nt_handler.prepare_hosted_thread_runtime_publication(pi, tid, badge, role) {
        Ok(prepared) => prepared,
        Err(status) => {
            nt_handler.abort_unbuilt_hosted_thread_publication(publication, pi, badge, role);
            return Err(status);
        }
    };
    let spawned = spawn_tp_worker_thread(
        nt_handler,
        pi,
        worker_slot,
        pml4,
        start,
        initial_context,
        stack_origin,
        cid_proc,
        tid,
        fault_ep,
    );
    let spawned = match spawned {
        Ok(spawned) => spawned,
        Err(failure) => {
            nt_handler.fail_hosted_thread_runtime_publication(runtime_publication, failure);
            nt_handler.abort_unbuilt_hosted_thread_publication(publication, pi, badge, role);
            return Err(nt_process::STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    let tcb = spawned.tcb();
    nt_handler.finish_hosted_thread_publication(runtime_publication, spawned, publication, !suspended)?;

    print_str(if rpc_worker {
        b"[rpc-worker] spawned pi="
    } else {
        b"[tp-worker] spawned pi="
    });
    print_u64(pi as u64);
    print_str(b" badge=");
    print_u64(badge);
    print_str(b" tid=");
    print_u64(tid);
    if pi == 0 {
        print_str(b" start_rcx=0x");
        print_hex_u64(start.rcx);
        print_str(b" start_rdx=0x");
        print_hex_u64(start.rdx);
    }
    print_str(b" tcb=0x");
    print_hex(tcb as u32);
    if let Some(kind) = role.rpc_worker_kind() {
        print_str(b" role=");
        print_str(kind.trace_role());
    }
    if worker_slot != 0 {
        print_str(b" slot=");
        print_u64(worker_slot as u64);
    }
    print_str(if suspended {
        b" suspended; NtResumeThread owns first run\n"
    } else {
        b" resumed into generic multiplex\n"
    });
    Ok(())
}

/// ★ Build the seL4 thread for a pending cross-VSpace `NtCreateThread`: the MECHANISM half of
/// `create_remote_thread`. The new thread's faults/syscalls arrive on the MAIN service endpoint
/// badged with its `(target pi, slot)` identity, so the loop's existing N-threads multiplex
/// (`tp_worker_identity_from_badge` → `mirror_ctx_for`) sub-selects it exactly like any other extra
/// thread of that process — a remote thread is not a special kind of thread once it exists.
///
/// Any hosted-process index under MAX_PI has a unique worker badge and mirror window.
pub(crate) unsafe fn spawn_requested_remote_thread(
    nt_handler: &mut ExecNtHandler,
    request: RemoteThreadRequest,
    fault_ep: u64,
) -> Result<u64, u32> {
    if request.target_pi >= MAX_PI || request.slot >= TP_WORKER_SLOT_COUNT {
        nt_handler.release_unmapped_hosted_tp_worker_slot(
            request.target_pi,
            request.slot,
            request.cid_thread,
        );
        nt_handler.abort_hosted_thread_publication(request.publication);
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }
    let badge = tp_worker_badge(request.target_pi, request.slot);
    let role = HostedThreadRole::TpWorker { slot: request.slot };
    if let ThreadStackOrigin::Caller(initial_teb) = request.stack_origin {
        if let Err(status) = nt_handler.validate_hosted_caller_stack(
            request.target_pi, request.start, initial_teb,
        ) {
            nt_handler.abort_unbuilt_hosted_thread_publication(
                request.publication, request.target_pi, badge, role,
            );
            return Err(status);
        }
    }
    let runtime_publication = match nt_handler.prepare_hosted_thread_runtime_publication(
        request.target_pi, request.cid_thread, badge, role,
    ) {
        Ok(prepared) => prepared,
        Err(status) => {
            nt_handler.abort_unbuilt_hosted_thread_publication(request.publication, request.target_pi, badge, role);
            return Err(status);
        }
    };
    let spawned = rendezvous::spawn_slot_thread(
        nt_handler,
        &rendezvous::RemoteThreadSpawn {
            target_pi: request.target_pi,
            slot: request.slot,
            pml4: request.pml4,
            start: request.start,
            initial_context: &request.initial_context,
            stack_origin: request.stack_origin,
            cid_proc: request.cid_proc,
            cid_thread: request.cid_thread,
            fault_ep: ThreadFaultEndpoint::Badged { source: fault_ep, badge },
            use_loader: true,
            native: true,
        },
    );
    let spawned = match spawned {
        Ok(spawned) => spawned,
        Err(failure) => {
            nt_handler.fail_hosted_thread_runtime_publication(runtime_publication, failure);
            nt_handler.abort_unbuilt_hosted_thread_publication(request.publication, request.target_pi, badge, role);
            return Err(nt_process::STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    let tcb = spawned.tcb();
    nt_handler.finish_hosted_thread_publication(runtime_publication, spawned, request.publication, request.resume)?;
    PM_REMOTE_THREADS_SPAWNED.fetch_add(1, Ordering::Relaxed);
    print_str(b"[remote-thread] spawned target_pi=");
    print_u64(request.target_pi as u64);
    print_str(b" slot=");
    print_u64(request.slot as u64);
    print_str(b" tid=");
    print_u64(request.cid_thread);
    print_str(b" tcb=0x");
    print_hex(tcb as u32);
    print_str(b"\n");
    Ok(tcb)
}

/// The active memory context for the thread identified by `badge`: stack base/size/mirror, process
/// heap mirror, and its demand scratch window. This is the same selection the main service
/// loop makes. Parked-I/O delivery temporarily switches to the parked thread's context.
#[inline]
fn mirror_ctx_for(
    handler: &ExecNtHandler, badge: u64, pi: usize, tid: u64,
) -> Option<(u64, u64, u64, u64, u64)> {
    let process = handler.capture_thread_process_identity(pi, tid)?;
    let runtime = match process.generation {
        nt_user_host::process_identity::ProcessGeneration::Hosted(generation) =>
            hosted_process_runtime_for_exact(pi, generation)?,
        nt_user_host::process_identity::ProcessGeneration::Temporary(_) =>
            hosted_process_runtime_for_pi(pi)?,
    };
    let (stack_base, stack_frames) =
        crate::hosted_thread_runtime::hosted_thread_fixed_stack_geometry(pi, badge);
    let stack_mirror =
        if let Some((tp_pi, tp_slot)) = tp_worker_identity_from_badge(badge) {
            debug_assert_eq!(tp_pi, pi);
            tp_worker_stack_mirror_va(tp_pi, tp_slot)
        } else {
            match badge {
                SVC_LISTENER_BADGE => SVC_LISTENER_STACK_MIRROR_VA,
                LSASS_LISTENER_BADGE => LSASS_LISTENER_STACK_MIRROR_VA,
                LSASS_LISTENER2_BADGE => LSASS_LISTENER2_STACK_MIRROR_VA,
                LSASS_LISTENER3_BADGE => LSASS_LISTENER3_STACK_MIRROR_VA,
                WINLOGON_WORKER2_BADGE => WINLOGON_WORKER2_STACK_MIRROR_VA,
                WINLOGON_WORKER3_BADGE => WINLOGON_WORKER3_STACK_MIRROR_VA,
                WINLOGON_WORKER_BADGE => WINLOGON_WORKER_STACK_MIRROR_VA,
                _ => {
                    // A top-level process MAIN thread — keyed by pi like the loop's default arm.
                    runtime.stack_mirror_va
                }
            }
        };
    Some((
        stack_base,
        stack_frames * 0x1000,
        stack_mirror,
        runtime.heap_mirror_va,
        runtime.scratch_base,
    ))
}

pub(crate) unsafe fn with_section_metadata_context<R>(
    handler: &mut ExecNtHandler,
    pi: usize,
    tid: u64,
    badge: u64,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
    service_number: u32,
    run: impl FnOnce(&mut ExecNtHandler) -> R,
) -> Option<R> {
    with_pagein_caller_target_context(handler, pi, pi, tid, badge, resume_ip, sp,
        flags, native_call_transport, service_number, run)
}

/// A foreign VM-lock page-in uses the caller's stack and thread authority while mapping
/// the independently captured target process. Never infer the caller from the target PI.
pub(crate) unsafe fn with_pagein_caller_target_context<R>(
    handler: &mut ExecNtHandler,
    caller_pi: usize,
    target_pi: usize,
    tid: u64,
    badge: u64,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    native_call_transport: bool,
    service_number: u32,
    run: impl FnOnce(&mut ExecNtHandler) -> R,
) -> Option<R> {
    let saved_ctx = handler.loop_ctx;
    let ctx = saved_ctx?.for_process(target_pi)?;
    let saved_client = (
        crate::executor::local().client_pi.load(Ordering::Relaxed),
        crate::executor::local().scratch_base.load(Ordering::Relaxed),
    );
    let saved_caller = (
        handler.pi, handler.current_tid, handler.current_badge,
        handler.current_resume_ip, handler.current_sp, handler.current_flags,
        handler.current_native_call_transport, handler.current_service_number,
    );
    // The caller's exact thread must still have a live memory context.
    mirror_ctx_for(handler, badge, caller_pi, tid)?;
    crate::executor::local().client_pi.store(caller_pi as u64, Ordering::Relaxed);
    crate::executor::local().scratch_base.store(ctx.scratch_base, Ordering::Relaxed);
    handler.loop_ctx = Some(ctx);
    handler.pi = caller_pi;
    handler.current_tid = tid;
    handler.current_badge = badge;
    handler.current_resume_ip = resume_ip;
    handler.current_sp = sp;
    handler.current_flags = flags;
    handler.current_native_call_transport = native_call_transport;
    handler.current_service_number = service_number;
    let result = run(handler);
    crate::executor::local().client_pi.store(saved_client.0, Ordering::Relaxed);
    crate::executor::local().scratch_base.store(saved_client.1, Ordering::Relaxed);
    handler.pi = saved_caller.0;
    handler.current_tid = saved_caller.1;
    handler.current_badge = saved_caller.2;
    handler.current_resume_ip = saved_caller.3;
    handler.current_sp = saved_caller.4;
    handler.current_flags = saved_caller.5;
    handler.current_native_call_transport = saved_caller.6;
    handler.current_service_number = saved_caller.7;
    handler.loop_ctx = saved_ctx;
    Some(result)
}

unsafe fn lpc_receive_wait_redrive_all(nt_handler: &mut ExecNtHandler) -> u64 {
    let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
    let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
    let saved_w32_client_pi = W32_CLIENT_PI.load(Ordering::Relaxed);
    let saved_pi = nt_handler.pi;
    let saved_tid = nt_handler.current_tid;
    let saved_badge = nt_handler.current_badge;
    let saved_user_memory = nt_handler.current_user_memory;
    let saved_ctx = nt_handler.loop_ctx;
    let mut woken = 0u64;

    let mut generation = 0u64;
    while let Some((slot, current_generation, wait)) = (&*core::ptr::addr_of!(LPC_RECEIVE_WAITS))
        .next_waiting_after(generation)
        .map(|(slot, generation, wait)| (slot, generation, *wait))
    {
        generation = current_generation;
        LPC_RECEIVE_WAIT_REDRIVES.fetch_add(1, Ordering::Relaxed);
        let receive = match lpc_client().map(|lpc| lpc.reply_wait_receive(wait.request.port_handle))
        {
            Some(Ok(received)) => Some(Ok(received)),
            Some(Err(status)) if status == nt_status::NtStatus::PENDING => None,
            Some(Err(status)) => Some(Err(status.raw() as u32)),
            None => Some(Err(nt_status::NtStatus::UNSUCCESSFUL.raw() as u32)),
        };
        let Some(receive) = receive else {
            continue;
        };

        let continuation = wait.continuation;
        let pi = continuation.pi as usize;
        let mirror = (pi < MAX_PI
            && nt_handler.capture_thread_process_identity(pi, continuation.tid)
                == Some(continuation.process)).then(||
            mirror_ctx_for(nt_handler, continuation.badge, pi, continuation.tid)).flatten();
        let status = if let Some((_, _, _, _, scratch_base)) = mirror {
            crate::executor::local().client_pi.store(pi as u64, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(scratch_base, Ordering::Relaxed);
            W32_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
            nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(pi));
            nt_handler.pi = pi;
            nt_handler.current_tid = continuation.tid;
            nt_handler.current_badge = continuation.badge;
            nt_handler.current_user_memory = continuation.memory;
            match receive {
                Ok(received) => nt_handler
                    .lpc_publish_received_message(pi, continuation.memory, wait.request, &received)
                    .map(|()| 0)
                    .unwrap_or_else(|status| status),
                Err(status) => status,
            }
        } else {
            nt_status::NtStatus::INVALID_HANDLE.raw() as u32
        };
        let Ok(ticket) = (&mut *core::ptr::addr_of_mut!(LPC_RECEIVE_WAITS))
            .begin_reply(slot, status) else {
            continue;
        };
        let replied = reply_parked_syscall(
            wait.continuation.reply_cap,
            status as u64,
        );
        let completed = (&mut *core::ptr::addr_of_mut!(LPC_RECEIVE_WAITS))
            .finish_reply(ticket, replied);
        if let Some(completed) = completed {
            release_reply_pool_cap(completed.continuation.reply_cap);
            thread_wait_state_clear_badge_ready(nt_handler, completed.continuation.badge);
            LPC_RECEIVE_WAIT_WOKEN.fetch_add(1, Ordering::Relaxed);
            woken += 1;
        } else {
            LPC_RECEIVE_WAIT_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
        print_str(b"[lpc-recv] WAKE pi=");
        print_u64(wait.continuation.pi as u64);
        print_str(b" badge=");
        print_u64(wait.continuation.badge);
        print_str(b" tid=");
        print_u64(wait.continuation.tid);
        print_str(b" port=0x");
        print_hex_u64(wait.request.port_handle);
        print_str(b" status=0x");
        print_hex(status);
        print_str(b" replied=");
        print_u64(replied as u64);
        print_str(b"\n");
    }

    crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
    crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
    W32_CLIENT_PI.store(saved_w32_client_pi, Ordering::Relaxed);
    nt_handler.pi = saved_pi;
    nt_handler.current_tid = saved_tid;
    nt_handler.current_badge = saved_badge;
    nt_handler.current_user_memory = saved_user_memory;
    nt_handler.loop_ctx = saved_ctx;
    woken
}

/// Drain broker progress into every typed LPC waiter. Producers that mutate the broker outside the
/// ordinary native-syscall dispatch phase call this at the mutation boundary so a parked server or
/// requester cannot remain asleep until an unrelated syscall happens to enter the service loop.
pub(crate) unsafe fn lpc_endpoint_redrive_all(nt_handler: &mut ExecNtHandler) -> u64 {
    if !nt_handler.lpc_endpoint_progress {
        return 0;
    }
    lpc_receive_wait_redrive_all(nt_handler) + lpc_request_wait_redrive_all(nt_handler)
}

unsafe fn lpc_request_wait_redrive_all(nt_handler: &mut ExecNtHandler) -> u64 {
    let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
    let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
    let saved_w32_client_pi = W32_CLIENT_PI.load(Ordering::Relaxed);
    let saved_pi = nt_handler.pi;
    let saved_tid = nt_handler.current_tid;
    let saved_badge = nt_handler.current_badge;
    let saved_user_memory = nt_handler.current_user_memory;
    let saved_ctx = nt_handler.loop_ctx;
    let mut woken = 0u64;

    let mut generation = 0u64;
    while let Some((slot, current_generation, wait)) = (&*core::ptr::addr_of!(LPC_REQUEST_WAITS))
        .next_waiting_after(generation)
        .map(|(slot, generation, wait)| (slot, generation, *wait))
    {
        generation = current_generation;
        LPC_REQUEST_WAIT_REDRIVES.fetch_add(1, Ordering::Relaxed);
        let completion = match lpc_client().map(|lpc| {
            lpc.receive_reply(
                wait.request.port_handle,
                wait.request.client_process,
                wait.request.client_thread,
                wait.request.message_id,
            )
        }) {
            Some(Ok(Some(reply))) => Some(Ok(reply)),
            Some(Ok(None)) => None,
            Some(Err(status)) => Some(Err(status.raw() as u32)),
            None => Some(Err(nt_status::NtStatus::UNSUCCESSFUL.raw() as u32)),
        };
        let Some(completion) = completion else {
            continue;
        };

        let continuation = wait.continuation;
        let pi = continuation.pi as usize;
        let completed_lsa_auth_request = pi < MAX_PI
            && nt_handler.lpc_connection_is(
                wait.request.port_handle,
                pi,
                b"\\LsaAuthenticationPort",
            );
        let lsa_reply_api_status = completed_lsa_auth_request
            .then(|| completion.as_ref().ok())
            .flatten()
            .and_then(|reply| {
                (reply.len() >= nt_lpc_abi::PORT_MESSAGE_HEADER_LEN + 8).then(|| {
                    let api_offset = nt_lpc_abi::PORT_MESSAGE_HEADER_LEN;
                    (
                        u32::from_le_bytes(reply[api_offset..api_offset + 4].try_into().unwrap()),
                        u32::from_le_bytes(
                            reply[api_offset + 4..api_offset + 8].try_into().unwrap(),
                        ),
                    )
                })
            });
        let mirror = (pi < MAX_PI
            && nt_handler.capture_thread_process_identity(pi, continuation.tid)
                == Some(continuation.process)).then(||
            mirror_ctx_for(nt_handler, continuation.badge, pi, continuation.tid)).flatten();
        let status = if let Some((_, _, _, _, scratch_base)) = mirror {
            crate::executor::local().client_pi.store(pi as u64, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(scratch_base, Ordering::Relaxed);
            W32_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
            nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(pi));
            nt_handler.pi = pi;
            nt_handler.current_tid = continuation.tid;
            nt_handler.current_badge = continuation.badge;
            nt_handler.current_user_memory = continuation.memory;
            match completion {
                Ok(reply) => nt_handler.lpc_publish_request_reply(
                    pi,
                    continuation.memory,
                    wait.request,
                    continuation.completion,
                    &reply,
                ),
                Err(status) => status,
            }
        } else {
            nt_status::NtStatus::INVALID_HANDLE.raw() as u32
        };
        let completed_csr_api_request = status == nt_syscall::STATUS_SUCCESS
            && pi < MAX_PI
            && nt_handler.lpc_connection_is(wait.request.port_handle, pi, b"\\windows\\apiport");

        let Ok(ticket) = (&mut *core::ptr::addr_of_mut!(LPC_REQUEST_WAITS))
            .begin_reply(slot, status) else {
            continue;
        };
        let replied = reply_parked_syscall(
            wait.continuation.reply_cap,
            status as u64,
        );
        let completed = (&mut *core::ptr::addr_of_mut!(LPC_REQUEST_WAITS))
            .finish_reply(ticket, replied);
        if let Some(completed) = completed {
            release_reply_pool_cap(completed.continuation.reply_cap);
            thread_wait_state_clear_badge_ready(nt_handler, completed.continuation.badge);
            LPC_REQUEST_WAIT_WOKEN.fetch_add(1, Ordering::Relaxed);
            if completed_csr_api_request {
                CSR_API_REAL_REPLIES.fetch_add(1, Ordering::Relaxed);
            }
            if status == nt_syscall::STATUS_SUCCESS && completed_lsa_auth_request {
                LSA_REPLIES_DELIVERED.fetch_add(1, Ordering::Relaxed);
                if let Some((api_number, api_status)) = lsa_reply_api_status {
                    match api_number {
                        2 => {
                            LSA_LOGON_REPLY_STATUS.store(api_status as u64, Ordering::Relaxed);
                            crate::latch_logon_dialog_evidence();
                        }
                        3 => {
                            LSA_LOOKUP_REPLY_STATUS.store(api_status as u64, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                }
                LSA_LOGON_IN_FLIGHT.store(0, Ordering::Relaxed);
            }
            woken += 1;
        } else {
            LPC_REQUEST_WAIT_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
        print_str(b"[lpc-request-wait] WAKE pi=");
        print_u64(wait.continuation.pi as u64);
        print_str(b" badge=");
        print_u64(wait.continuation.badge);
        print_str(b" tid=");
        print_u64(wait.continuation.tid);
        print_str(b" msgid=");
        print_u64(wait.request.message_id as u64);
        print_str(b" status=0x");
        print_hex(status);
        print_str(b" replied=");
        print_u64(replied as u64);
        print_str(b"\n");
    }

    crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
    crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
    W32_CLIENT_PI.store(saved_w32_client_pi, Ordering::Relaxed);
    nt_handler.pi = saved_pi;
    nt_handler.current_tid = saved_tid;
    nt_handler.current_badge = saved_badge;
    nt_handler.current_user_memory = saved_user_memory;
    nt_handler.loop_ctx = saved_ctx;
    woken
}

pub(crate) unsafe fn lpc_connect_completion_drain(nt_handler: &mut ExecNtHandler) -> usize {
    let mut delivered = 0;
    let pending = nt_handler.lpc_connect_completions.len();
    for _ in 0..pending {
        let Some(completion) = nt_handler.lpc_connect_completions.pop_front() else { break; };
        if lpc_connect_wait_complete(nt_handler, completion) { delivered += 1; }
    }
    delivered
}

unsafe fn lpc_connect_wait_complete(
    nt_handler: &mut ExecNtHandler,
    mut completion: PendingLpcConnectCompletion,
) -> bool {
    if completion.retained_refusal {
        nt_handler.queue_lpc_connect_completion(completion);
        return false;
    }
    let Some((_slot, wait)) = (&*core::ptr::addr_of!(LPC_CONNECT_WAITS))
        .find_connection(completion.connection_id)
        .map(|(slot, wait)| (slot, *wait))
    else {
        LPC_CONNECT_WAIT_FAILURES.fetch_add(1, Ordering::Relaxed);
        print_str(b"[lpc-connect-wait] terminal result has no connector conn=");
        print_u64(completion.connection_id);
        print_str(b" status=0x");
        print_hex(completion.status);
        print_str(b"\n");
        completion.retained_refusal = true;
        nt_handler.queue_lpc_connect_completion(completion);
        return false;
    };

    let ticket = match (&mut *core::ptr::addr_of_mut!(LPC_CONNECT_WAITS))
        .begin_completion(completion.connection_id, completion) {
        Ok(ticket) => ticket,
        Err((_, mut terminal)) => {
            terminal.retained_refusal = true;
            nt_handler.queue_lpc_connect_completion(terminal);
            LPC_CONNECT_WAIT_FAILURES.fetch_add(1, Ordering::Relaxed);
            return false;
        }
    };
    let completion = (&*core::ptr::addr_of!(LPC_CONNECT_WAITS)).completion(&ticket)
        .expect("exact completion admission retains terminal data").view();

    let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
    let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
    let saved_w32_client_pi = W32_CLIENT_PI.load(Ordering::Relaxed);
    let saved_pi = nt_handler.pi;
    let saved_tid = nt_handler.current_tid;
    let saved_badge = nt_handler.current_badge;
    let saved_user_memory = nt_handler.current_user_memory;
    let saved_ctx = nt_handler.loop_ctx;

    let continuation = wait.continuation;
    let pi = continuation.pi as usize;
    let connection_name = &continuation.name[..continuation.name_len as usize];
    let completed_csr_api_connect = completion.status == nt_syscall::STATUS_SUCCESS
        && matches!(
            wait.request.operation,
            nt_lpc_continuation::ConnectOperation::SecureConnect
        )
        && lpc_client()
            .and_then(|client| client.query_handle(completion.client_handle).ok())
            .is_some_and(|port| lpc_name_is(&port.name, b"\\Windows\\ApiPort"));
    let completed_lsa_auth_connect = completion.status == nt_syscall::STATUS_SUCCESS
        && lpc_name_is(connection_name, b"\\LsaAuthenticationPort");
    let mirror = (pi < MAX_PI).then(||
        mirror_ctx_for(nt_handler, continuation.badge, pi, continuation.tid)).flatten();
    let status = if let Some((_, _, _, _, scratch_base)) = mirror {
        crate::executor::local().client_pi.store(pi as u64, Ordering::Relaxed);
        crate::executor::local().scratch_base.store(scratch_base, Ordering::Relaxed);
        W32_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
        nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(pi));
        nt_handler.pi = pi;
        nt_handler.current_tid = continuation.tid;
        nt_handler.current_badge = continuation.badge;
        nt_handler.current_user_memory = continuation.memory;
        nt_handler.lpc_publish_connect_completion(
            pi,
            continuation.memory,
            wait.request,
            connection_name,
            &completion,
        )
    } else {
        nt_status::NtStatus::INVALID_HANDLE.raw() as u32
    };

    crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
    crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
    W32_CLIENT_PI.store(saved_w32_client_pi, Ordering::Relaxed);
    nt_handler.pi = saved_pi;
    nt_handler.current_tid = saved_tid;
    nt_handler.current_badge = saved_badge;
    nt_handler.current_user_memory = saved_user_memory;
    nt_handler.loop_ctx = saved_ctx;

    if (&mut *core::ptr::addr_of_mut!(LPC_CONNECT_WAITS)).begin_reply(&ticket, status).is_err() {
        LPC_CONNECT_WAIT_FAILURES.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let replied = reply_parked_syscall(
        wait.continuation.reply_cap,
        status as u64,
    );
    if replied {
        let Some((completed, completion)) = (&mut *core::ptr::addr_of_mut!(LPC_CONNECT_WAITS))
            .finish_reply(ticket, true) else {
            LPC_CONNECT_WAIT_FAILURES.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        release_reply_pool_cap(completed.continuation.reply_cap);
        thread_wait_state_clear_badge_ready(nt_handler, completed.continuation.badge);
        LPC_CONNECT_WAIT_WOKEN.fetch_add(1, Ordering::Relaxed);
        if status == nt_syscall::STATUS_SUCCESS && completed_csr_api_connect {
            CSR_AUTHENTIC_ACCEPTS.fetch_add(1, Ordering::Relaxed);
            CSR_AUTHENTIC_ACCEPT_MASK.fetch_or(1u64 << pi, Ordering::Relaxed);
            CSR_CONNECTED_MASK.fetch_or(1u64 << pi, Ordering::Relaxed);
            if nt_handler.hosted_process_role(pi)
                == Some(nt_exe_image::HostedProcessRole::InteractiveLogon)
            {
                WINLOGON_CSR_CONNECTED.store(1, Ordering::Relaxed);
            }
        }
        if status == nt_syscall::STATUS_SUCCESS && completed_lsa_auth_connect {
            LSA_CONNECT_COMPLETED.fetch_add(1, Ordering::Relaxed);
            let operational_mode = completion
                .connection_information
                .get(4..8)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()) as u64)
                .unwrap_or(0);
            LSA_OPERATIONAL_MODE.store(operational_mode, Ordering::Relaxed);
            if nt_handler.hosted_process_role(pi)
                == Some(nt_exe_image::HostedProcessRole::InteractiveLogon)
            {
                WINLOGON_LSA_PORT_HANDLE.store(completion.client_handle, Ordering::Relaxed);
                WINLOGON_LSA_CONNECTED.store(1, Ordering::Relaxed);
            }
        }
    } else {
        let _ = (&mut *core::ptr::addr_of_mut!(LPC_CONNECT_WAITS)).finish_reply(ticket, false);
        LPC_CONNECT_WAIT_FAILURES.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    print_str(b"[lpc-connect-wait] WAKE pi=");
    print_u64(wait.continuation.pi as u64);
    print_str(b" badge=");
    print_u64(wait.continuation.badge);
    print_str(b" tid=");
    print_u64(wait.continuation.tid);
    print_str(b" conn=");
    print_u64(wait.request.connection_id);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b" replied=");
    print_u64(replied as u64);
    print_str(b"\n");
    replied
}

pub(crate) unsafe fn lpc_receive_wait_abandon_thread(
    nt_handler: &mut ExecNtHandler,
    tid: u64,
) -> u64 {
    let table = &mut *core::ptr::addr_of_mut!(LPC_RECEIVE_WAITS);
    let mut abandoned = 0u64;
    for slot in 0..table.slot_count() {
        let Some(wait) = table.get(slot).copied() else {
            continue;
        };
        if wait.continuation.tid != tid {
            continue;
        }
        let cap = wait.continuation.reply_cap;
        let (ticket, reconcile_stop) = match table.begin_cancel(slot) {
            Ok(ticket) => (ticket, false),
            Err(_) if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(cap) => {
                let Ok(ticket) = table.begin_reconcile_stop(slot) else { continue; };
                (ticket, true)
            }
            Err(_) => continue,
        };
        let stopped = !reconcile_stop
            || spawn_hosts::shared_ingress::owner::runtime::stop_and_cancel_hosted(cap).is_ok();
        let cancelled = stopped && cancel_parked_reply_transport(cap);
        let removed = if reconcile_stop {
            table.finish_reconcile_stop(ticket, cancelled)
        } else {
            table.finish_cancel(ticket, cancelled)
        };
        let Some(removed) = removed else { continue; };
        release_reply_pool_cap(removed.continuation.reply_cap);
        abandoned += 1;
    }
    let still_owned = (0..table.slot_count()).any(|slot| {
        table.get(slot).is_some_and(|wait| wait.continuation.tid == tid)
    });
    if abandoned != 0 && !still_owned {
        thread_wait_state_clear_tid(nt_handler, tid);
    }
    abandoned
}

pub(crate) unsafe fn lpc_connect_wait_abandon_thread(
    nt_handler: &mut ExecNtHandler,
    tid: u64,
) -> u64 {
    let mut abandoned = 0u64;
    let slots = (&*core::ptr::addr_of!(LPC_CONNECT_WAITS)).slot_count();
    for slot in 0..slots {
        let Some(wait) = (&*core::ptr::addr_of!(LPC_CONNECT_WAITS)).get(slot).copied() else {
            continue;
        };
        if wait.continuation.tid != tid {
            continue;
        }
        let ticket = match (&mut *core::ptr::addr_of_mut!(LPC_CONNECT_WAITS)).begin_cancel(wait.request.connection_id) {
            Ok(ticket) => ticket,
            Err(_) => continue,
        };
        let cap = wait.continuation.reply_cap;
        let cancelled = cancel_parked_reply_transport(cap);
        let Some(removed) = (&mut *core::ptr::addr_of_mut!(LPC_CONNECT_WAITS)).finish_cancel(ticket, cancelled) else {
            continue;
        };
        if let Some(client) = lpc_client() {
            let _ = client.accept_connect(removed.request.connection_id, false, 0);
        }
        nt_handler.abort_lpc_connection_views(removed.request.connection_id);
        release_reply_pool_cap(cap);
        abandoned += 1;
    }
    let still_owned = (0..(&*core::ptr::addr_of!(LPC_CONNECT_WAITS)).slot_count()).any(|slot| {
        (&*core::ptr::addr_of!(LPC_CONNECT_WAITS)).get(slot)
            .is_some_and(|wait| wait.continuation.tid == tid)
    });
    if abandoned != 0 && !still_owned {
        thread_wait_state_clear_tid(nt_handler, tid);
    }
    abandoned
}

pub(crate) unsafe fn lpc_request_wait_abandon_thread(
    nt_handler: &mut ExecNtHandler,
    tid: u64,
) -> u64 {
    let table = &mut *core::ptr::addr_of_mut!(LPC_REQUEST_WAITS);
    let mut abandoned = 0u64;
    for slot in 0..table.slot_count() {
        let Some(wait) = table.get(slot).copied() else {
            continue;
        };
        if wait.continuation.tid != tid {
            continue;
        }
        let cap = wait.continuation.reply_cap;
        let (ticket, reconcile_stop) = match table.begin_cancel(slot) {
            Ok(ticket) => (ticket, false),
            Err(_) if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(cap) => {
                let Ok(ticket) = table.begin_reconcile_stop(slot) else { continue; };
                (ticket, true)
            }
            Err(_) => continue,
        };
        let broker_settled = lpc_client().is_some_and(|client| {
            client.cancel_request(
                wait.request.port_handle,
                wait.request.client_process,
                wait.request.client_thread,
                wait.request.message_id,
            ).is_ok()
        });
        let stopped = broker_settled && (!reconcile_stop
            || spawn_hosts::shared_ingress::owner::runtime::stop_and_cancel_hosted(cap).is_ok());
        let cancelled = stopped && cancel_parked_reply_transport(cap);
        let removed = if reconcile_stop {
            table.finish_reconcile_stop(ticket, cancelled)
        } else {
            table.finish_cancel(ticket, cancelled)
        };
        let Some(removed) = removed else {
            continue;
        };
        release_reply_pool_cap(removed.continuation.reply_cap);
        abandoned += 1;
    }
    let still_owned = (0..table.slot_count()).any(|slot| {
        table.get(slot).is_some_and(|wait| wait.continuation.tid == tid)
    });
    if abandoned != 0 && !still_owned {
        thread_wait_state_clear_tid(nt_handler, tid);
    }
    abandoned
}

unsafe fn io_completion_park(
    nt_handler: &mut ExecNtHandler,
    port_id: u32,
    key_context_out: u64,
    apc_context_out: u64,
    io_status_block_out: u64,
    deadline: nt_delay_execution::Deadline,
) -> bool {
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    if stolen == 0 {
        return false;
    }
    let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else {
        return false;
    };
    if nt_handler.io_completion_ports.retain(port_id).is_err() {
        return false;
    }
    let Some(process) = nt_handler.capture_thread_process_identity(
        nt_handler.pi, nt_handler.current_tid,
    ) else {
        nt_handler.release_io_completion_reference(port_id);
        return false;
    };
    let mut waiter = nt_io_completion::CompletionWaiter::default();
    waiter.port_id = port_id;
    waiter.process_index = nt_handler.pi as u8;
    waiter.process = Some(process);
    waiter.reply_cap = stolen;
    waiter.thread_id = nt_handler.current_tid;
    waiter.badge = nt_handler.current_badge;
    waiter.key_context_out = key_context_out;
    waiter.apc_context_out = apc_context_out;
    waiter.io_status_block_out = io_status_block_out;
    waiter.deadline = deadline;
    let waiters = unsafe { &mut *core::ptr::addr_of_mut!(IO_COMPLETION_WAITERS) };
    if waiters.insert(waiter).is_err() {
        nt_handler.release_io_completion_reference(port_id);
        return false;
    }
    reply_park.commit();
    IO_COMPLETION_PARKED_COUNT.fetch_add(1, Ordering::Relaxed);
    thread_wait_state_mark_badge_waiting(nt_handler, nt_handler.current_badge);
    true
}

unsafe fn io_completion_deliver(nt_handler: &mut ExecNtHandler) -> bool {
    let _ = io_completion_redrive_returned_packets(nt_handler);
    let mut delivered_any = false;
    let mut cursor = 0;
    while let Some((slot, waiter, packet)) =
        (&*core::ptr::addr_of!(IO_COMPLETION_WAITERS)).next_wake_from(cursor)
    {
    cursor = slot + 1;
    if nt_handler.capture_thread_process_identity(
        waiter.process_index as usize,
        waiter.thread_id,
    ) != waiter.process {
        continue;
    }
    // A retired process cannot accept copyout. The row still owns its packet, Reply and port.
    let Some((_, _, _, _, scratch_base)) =
        mirror_ctx_for(nt_handler, waiter.badge, waiter.process_index as usize,
            waiter.thread_id)
    else {
        continue;
    };
    let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
    let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
    let saved_pi = nt_handler.pi;
    let saved_ctx = nt_handler.loop_ctx;

    crate::executor::local().client_pi.store(waiter.process_index as u64, Ordering::Relaxed);
    crate::executor::local().scratch_base.store(scratch_base, Ordering::Relaxed);
    nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(waiter.process_index as usize));
    nt_handler.pi = waiter.process_index as usize;

    let copied = nt_handler
        .xas_try_write_buf(waiter.apc_context_out, &packet.apc_context.to_le_bytes())
        && nt_handler.xas_try_write_buf(waiter.key_context_out, &packet.key_context.to_le_bytes())
        && nt_handler.xas_try_write_buf(waiter.io_status_block_out, &packet.status.to_le_bytes())
        && nt_handler.xas_try_write_buf(
            waiter.io_status_block_out + 8,
            &packet.information.to_le_bytes(),
        );
    crate::exec_handler::trace_io_completion_packet(
        waiter.process_index as usize,
        if copied {
            b"deliver"
        } else {
            b"deliver-copy-failed"
        },
        waiter.port_id,
        nt_handler.io_completion_ports.depth(waiter.port_id).ok(),
        0,
        waiter.badge,
        packet,
    );

    crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
    crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
    nt_handler.pi = saved_pi;
    nt_handler.loop_ctx = saved_ctx;

    if !(&mut *core::ptr::addr_of_mut!(IO_COMPLETION_WAITERS))
        .begin_wake_reply_exact(waiter)
    {
        continue;
    }
    let delivered = reply_parked_syscall(
        waiter.reply_cap,
        if copied { 0 } else { 0xC000_0005 },
    );
    if !delivered {
        // The transport may have completed despite an uncertain receipt. Never replay it.
        continue;
    }
    let Some(waiter) = (&mut *core::ptr::addr_of_mut!(IO_COMPLETION_WAITERS))
        .finish_exact(waiter, delivered) else { continue; };
    release_reply_pool_cap(waiter.reply_cap);
    thread_wait_state_clear_badge_ready(nt_handler, waiter.badge);
    nt_handler.release_io_completion_reference(waiter.port_id);
    IO_COMPLETION_WOKEN_COUNT.fetch_add(1, Ordering::Relaxed);
    delivered_any = true;
    }
    delivered_any
}


/// Redirect one alertable pre-dispatch File acquisition waiter when its target
/// thread has a queued user APC.
unsafe fn reconcile_user_apc_file_acquisition_wait(
    nt_handler: &mut ExecNtHandler,
    tid: u64,
) -> bool {
    synchronous_file_apc::request(nt_handler, tid)
}

/// Reconcile a queued APC with either phase of an alertable synchronous File
/// wait. Pre-dispatch acquisition returns immediately; an in-flight IRP is
/// cancelled exactly and remains parked until terminal completion wins.
pub(crate) unsafe fn reconcile_user_apc_file_wait(
    nt_handler: &mut ExecNtHandler,
    tid: u64,
) -> bool {
    if reconcile_user_apc_file_acquisition_wait(nt_handler, tid) {
        return true;
    }
    crate::pending_file_apc::request(nt_handler, tid)
}

/// Reconcile every alertable wait class that can own a hosted thread continuation. Object/File
/// acquisition interruptions retain their exact owners through APC effects; in-flight I/O first
/// requests cancellation and stays owned until its real terminal completion wins the race.
pub(crate) unsafe fn reconcile_user_apc_waits(nt_handler: &mut ExecNtHandler, tid: u64) -> bool {
    crate::object_wait_apc::request(nt_handler, tid) || reconcile_user_apc_file_wait(nt_handler, tid)
}

/// Transfer one general File syscall into its exact pending-IRP delivery owner. Synchronous
/// operations also move the live syscall reply into that owner; asynchronous operations do not.
unsafe fn synchronous_file_wait_park(
    mut waiter: nt_io_manager::SynchronousFileWaiter,
    reservation: nt_io_manager::SynchronousFileWaitReservation,
) -> bool {
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    if stolen == 0 {
        return false;
    }
    let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else {
        return false;
    };
    waiter.reply_cap = stolen;
    let table = &mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS);
    if table.park_reserved(reservation, waiter).is_none() {
        return false;
    }
    reply_park.commit();
    true
}

/// Start the one canonical lifecycle owned by the transferred final-handle
/// reference. This is bookkeeping only: the retained lifecycle runner enters the
/// driver after this handler borrow ends, including from a held nested pump.
pub(crate) unsafe fn start_file_cleanup(nt_handler: &mut ExecNtHandler, file_id: u64) {
    let first_start = nt_handler
        .file_completion
        .mark_cleanup_lifecycle_started(file_id)
        .expect("File cleanup started without its Busy/reference owner");
    if !first_start {
        return;
    }

    // FsContext is mutable driver payload, so retire the auxiliary endpoint
    // indices only once cleanup actually owns its place behind ordinary I/O.
    if let Some((_, fs_context)) = driver_launch::hosted_file_route(file_id) {
        let server_context =
            nt_io_manager::pipe_server_file_id_for_endpoint(fs_context).unwrap_or(fs_context);
        crate::pipe_server_preconnected_forget(server_context);
        crate::pipe_fid_name_forget(fs_context);
    }
    driver_launch::release_hosted_file(file_id)
        .expect("canonical File cleanup was rejected before driver acceptance");
    // CLEANUP can complete retained reads/listens. Their ordinary completion
    // owners must publish and ACK before the manager is allowed to send CLOSE.
    nt_handler.pipe_endpoint_progress = true;
    FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
}

/// Retire manager-complete cleanup owners without allocating or manufacturing a
/// user completion. Synchronous Busy is released before the transferred File
/// reference, matching the FILE_OBJECT delete invariant.
unsafe fn file_cleanup_redrive_all(nt_handler: &mut ExecNtHandler) -> u64 {
    let mut cursor = 0usize;
    let mut completed = 0u64;
    while let Some((slot, file_id)) = nt_handler.file_completion.active_cleanup_from(cursor) {
        cursor = slot + 1;
        let cleanup_complete = driver_launch::io_manager_mut()
            .file(nt_io_manager::FileId(file_id))
            .is_none_or(|file| {
                matches!(
                    file.state,
                    nt_io_manager::FileState::CleanupComplete
                        | nt_io_manager::FileState::ClosePending
                        | nt_io_manager::FileState::Closed
                )
            });
        if !cleanup_complete {
            // start_file_cleanup transferred the final-handle owner once. The
            // manager and retained lifecycle row own every pending retry;
            // observing a nonterminal File does not grant another release.
            continue;
        }
        let continuation =
            (&mut *core::ptr::addr_of_mut!(PENDING_FILE_CLEANUP_WAITS)).take_file(file_id);
        if nt_handler
            .file_completion
            .io_mode(file_id)
            .expect("completed cleanup lost its File policy")
            .is_synchronous()
        {
            let release = nt_handler
                .file_completion
                .release_cleanup_io(file_id)
                .expect("completed cleanup lost synchronous Busy");
            assert_eq!(
                release.waiters, 0,
                "last-handle cleanup completed before ordinary File waiters"
            );
        }
        nt_handler.release_file_cleanup_reference(file_id);
        if let Some(pending) = continuation {
            let _ = reply_parked_syscall(pending.reply_cap, 0);
            release_reply_pool_cap(pending.reply_cap);
            thread_wait_state_clear_badge_ready(nt_handler, pending.badge);
        }
        completed += 1;
    }
    completed
}

/// Read only the exact parked continuation; the caller never takes its Reply.
pub(crate) fn file_cleanup_receive_owner_snapshot() -> Option<[u64; 6]> {
    let table = unsafe { &*core::ptr::addr_of!(PENDING_FILE_CLEANUP_WAITS) };
    let pending = table.parked().next()?;
    Some([
        pending.file_id, u64::from(pending.pi), pending.tid,
        pending.badge, pending.reply_cap, table.parked().count() as u64,
    ])
}

pub(crate) fn trace_file_cleanup_receive_owner_rows() {
    let table = unsafe { &*core::ptr::addr_of!(PENDING_FILE_CLEANUP_WAITS) };
    for pending in table.parked().take(4) {
        print_str(b"[retained-receive-cleanup] file/pi/tid/badge/reply=");
        for (index, value) in [pending.file_id, u64::from(pending.pi), pending.tid,
            pending.badge, pending.reply_cap].into_iter().enumerate() {
            if index != 0 { print_str(b"/"); }
            print_u64(value);
        }
        print_str(b"\n");
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn pending_driver_start_transfer(
    nt_handler: &mut ExecNtHandler,
    transfer: PendingDriverStartTransfer,
) {
    let PendingDriverStartTransfer {
        batch,
        reservation,
        request,
    } = transfer;
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(
        stolen, 0,
        "pending driver START Reply object disappeared after preflight"
    );
    let reply_park = root_reply_park::RootReplyPark::prepare()
        .expect("pending driver START Reply-pool claim disappeared after preflight");
    let reply = PendingPnpSyscallReply {
        tid: nt_handler.current_tid,
        badge: nt_handler.current_badge,
        reply_cap: stolen,
    };
    let owner = PendingDriverStartOwner::User {
        request: Some(request),
        reply: Some(reply),
    };
    nt_handler
        .pending_driver_starts
        .publish(reservation, PendingDriverStart {
            batch,
            reservation,
            bootstrap_predecessors: alloc::vec::Vec::new(),
            owner,
            observed_wait_stage: None,
        })
        .expect("reserved driver START continuation rejected its exact batch");
    reply_park.commit();
}

unsafe fn pending_pnp_operation_transfer(
    nt_handler: &mut ExecNtHandler,
    transfer: PendingPnpOperationTransfer,
) {
    let PendingPnpOperationTransfer {
        operation,
        reservation,
    } = transfer;
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(
        stolen, 0,
        "pending PnP operation Reply object disappeared after preflight"
    );
    let reply_park = root_reply_park::RootReplyPark::prepare()
        .expect("pending PnP operation Reply-pool claim disappeared after preflight");
    let reply = Some(PendingPnpSyscallReply {
        tid: nt_handler.current_tid,
        badge: nt_handler.current_badge,
        reply_cap: stolen,
    });
    nt_handler
        .pending_pnp_operations
        .publish(reservation, PendingPnpOperation { operation, reservation, reply })
        .expect("reserved PnP continuation rejected its exact operation");
    reply_park.commit();
}

unsafe fn pending_driver_start_reply_owner(
    nt_handler: &mut ExecNtHandler,
    cap: u64,
    badge: u64,
    status: u32,
) -> bool {
    let delivered = reply_parked_syscall(cap, status as u64);
    assert!(delivered, "driver START retains uncertain Reply completion");
    release_reply_pool_cap(cap);
    thread_wait_state_clear_badge_ready(nt_handler, badge);
    delivered
}

pub(crate) unsafe fn complete_registry_mutation_reply(
    handler: &mut ExecNtHandler,
    tid: u64,
    badge: u64,
    reply: u64,
    status: u32,
) -> bool {
    assert!(crate::registry_mutation_work::has_thread(tid));
    if !reply_parked_syscall(reply, status as u64) {
        return false;
    }
    let _ = (handler, badge);
    true
}

pub(crate) unsafe fn complete_mutable_hive_mutation_reply(
    _handler: &mut ExecNtHandler,
    tid: u64,
    reply: u64,
    status: u32,
) -> bool {
    assert!(crate::mutable_hive_mutation_work::has_thread(tid));
    reply_parked_syscall(reply, status as u64)
}

fn record_pending_start_result(
    nt_handler: &mut ExecNtHandler,
    request: nt_pnp_manager::StartDeviceRequestIdentity,
    batch: &mut OwnedHostedPnpStartBatch,
    status: u32,
) {
    let evidence = batch
        .take_single_start_evidence()
        .expect("pending live StartDevice batch did not own exactly one devnode");
    let result = match evidence {
        SingleStartEvidence::Consumed => {
            panic!("pending live StartDevice batch evidence was consumed twice")
        }
        SingleStartEvidence::NotDispatched => {
            if status == nt_status::NtStatus::SUCCESS.raw() as u32 {
                nt_handler
                    .pnp_start_device_calls
                    .complete_protocol_without_start_irp(request, status)
            } else {
                nt_handler
                    .pnp_start_device_calls
                    .complete_without_start_irp(request, status)
            }
        }
        SingleStartEvidence::Lifecycle { receipt } => nt_handler
            .pnp_start_device_calls
            .complete_lifecycle(request, receipt, status),
        SingleStartEvidence::Dispatched { irp_id } => nt_handler
            .pnp_start_device_calls
            .complete_protocol_ownership_lost(request, irp_id, None, status),
        SingleStartEvidence::OwnershipLost { irp_id, receipt } => nt_handler
            .pnp_start_device_calls
            .complete_protocol_ownership_lost(request, irp_id, receipt, status),
    };
    result.expect("pending StartDevice result lost its exact request");
}

fn record_pending_start_reply(
    nt_handler: &mut ExecNtHandler,
    request: nt_pnp_manager::StartDeviceRequestIdentity,
    status: u32,
    delivered: bool,
) {
    match nt_handler
        .pnp_start_device_calls
        .record_reply(request, status, delivered)
    {
        Ok(()) | Err(nt_pnp_manager::StartDeviceLedgerError::ReplyFailed) => {}
        Err(_) => panic!("pending StartDevice reply did not match its exact result"),
    }
}

fn trace_pending_driver_start_wait(
    slot: usize,
    pending: &mut PendingDriverStart,
    stage: hosted_pnp_start::HostedPnpWaitStage,
) {
    if pending.observed_wait_stage == Some(stage) {
        return;
    }
    pending.observed_wait_stage = Some(stage);
    print_str(b"[pnp-start-wait] slot=");
    print_u64(slot as u64);
    print_str(b" service=");
    print_str(pending.batch.service_name().as_bytes());
    print_str(b" stage=");
    print_str(stage.label());
    print_str(b"\n");
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RootAddDeviceOwner {
    DriverStart(nt_driver_start::PendingOperationReservation),
    PnpRebalance(nt_driver_start::PendingOperationReservation),
}
type RootAddDeviceTurn = nt_driver_start::AddDeviceRootTurn<
    RootAddDeviceOwner,
    crate::spawn_hosts::shared_ingress::owner::runtime::DeferredParkedIngress,
>;
type RootQueuedCallbackTurn = nt_component_suspension::RootChildTurn<
    crate::driver_launch::QueuedCallbackSelector,
    Vec<crate::spawn_hosts::shared_ingress::owner::runtime::DeferredParkedIngress>,
>;

/// This is a wake request only. The exact batch reservation remains the sole parent authority.
/// `u64::MAX` denotes no armed retry; the PIT remains one-shot and idle without retained work.
static ROOT_ADD_DEVICE_RETRY_DEADLINE: AtomicU64 = AtomicU64::new(u64::MAX);
static ROOT_ADD_DEVICE_EXCLUSIVE: AtomicBool = AtomicBool::new(false);

/// A root-owned callback is physically retained while its selected local child is absent.
/// The retry is only a wake request; neither the timer nor another Call may replace that owner.
static ROOT_QUEUED_CALLBACK_EXCLUSIVE: AtomicBool = AtomicBool::new(false);
static ROOT_QUEUED_CALLBACK_RETRY_DEADLINE: AtomicU64 = AtomicU64::new(u64::MAX);
static ROOT_QUEUED_CALLBACK_FAILURE_TRACE: AtomicU64 = AtomicU64::new(0);
static ROOT_QUEUED_CALLBACK_REFRESH_TRACE: AtomicU64 = AtomicU64::new(0);

/// A queue claim owns its root turn across every Reply its resumed parent refreshes. Follow
/// only the exact selector that claim's own row yields now; the turn keeps its deferred
/// ingress tickets, retry deadline, and single retirement watch. The bounded receipt records
/// each copied identity pair so a boot shows the transition that used to end the root loop.
unsafe fn refresh_queued_callback_turn_witness(turn: &mut RootQueuedCallbackTurn) -> bool {
    let retired = turn.owner();
    let Some(current) = crate::driver_launch::queued_callback_refreshed_selector(retired) else {
        return true;
    };
    if turn.advance_owner(retired, current).is_err() { return false; }
    if ROOT_QUEUED_CALLBACK_REFRESH_TRACE.fetch_add(1, Ordering::Relaxed) < 16 {
        use core::fmt::Write;
        let mut record = nt_printf::record::RecordBuffer::<768>::new();
        let _ = writeln!(record,
            "[queued-callback-root-refresh] retired={:?} current={:?} watch={}",
            retired.diagnostic_identity(), current.diagnostic_identity(),
            u8::from(crate::driver_launch::queued_callback_root_watch_present(current)));
        sel4_rt::print_record(record.bytes());
    }
    true
}

/// Failure-only root receipt. Selector snapshots are copied identities, never ACK authority.
unsafe fn trace_queued_callback_root_failure(
    stage: &str,
    current: &[RootQueuedCallbackTurn],
    permit: Option<&ParkedRootQueuedCallbackPermit>,
) {
    if ROOT_QUEUED_CALLBACK_FAILURE_TRACE.fetch_add(1, Ordering::Relaxed) >= 64 { return; }
    use core::fmt::Write;
    use crate::driver_launch::QueuedCallbackRootAction as Action;
    let action = crate::driver_launch::queued_callback_root_action().map(|action| match action {
        Action::NeedsChild(selector) => ("needs-child", selector.diagnostic_identity()),
        Action::ResumeRecordedStep(selector) => ("resume-step", selector.diagnostic_identity()),
        Action::RetryRestore(selector) => ("retry-restore", selector.diagnostic_identity()),
        Action::RetryTerminalAck(selector) => ("retry-ack", selector.diagnostic_identity()),
    });
    let top = current.last().map(|turn| turn.owner());
    let mut record = nt_printf::record::RecordBuffer::<1536>::new();
    let _ = writeln!(record,
        "[queued-callback-root-failure] stage={} depth={} permit={:?} permit-floor/watch={:?}/{:?} top={:?} top-retired={:?} selected={:?} unsettled={}",
        stage, current.len(), permit.map(|permit| permit.0.diagnostic_identity()),
        permit.map(|permit| crate::driver_launch::queued_callback_file_floor(permit.0).is_some()),
        permit.map(|permit| crate::driver_launch::queued_callback_root_watch_present(permit.0)),
        top.map(|selector| selector.diagnostic_identity()),
        top.map(|selector| crate::driver_launch::queued_callback_root_retired(selector)),
        action, u8::from(crate::driver_launch::unsettled_queued_callback()));
    sel4_rt::print_record(record.bytes());
}

pub(crate) fn root_queued_callback_exclusive_pending() -> bool {
    ROOT_QUEUED_CALLBACK_EXCLUSIVE.load(Ordering::Acquire)
}

pub(crate) fn root_queued_callback_retry_deadline() -> Option<u64> {
    let deadline = ROOT_QUEUED_CALLBACK_RETRY_DEADLINE.load(Ordering::Acquire);
    (deadline != u64::MAX).then_some(deadline)
}

pub(crate) fn root_queued_callback_retry_wake_due(now: u64) -> u64 {
    let Some(deadline) = root_queued_callback_retry_deadline() else { return 0 };
    if now < deadline { return 0 }
    u64::from(ROOT_QUEUED_CALLBACK_RETRY_DEADLINE.compare_exchange(
        deadline, u64::MAX, Ordering::AcqRel, Ordering::Acquire,
    ).is_ok())
}

pub(crate) fn root_add_device_exclusive_pending() -> bool {
    ROOT_ADD_DEVICE_EXCLUSIVE.load(Ordering::Acquire)
}

pub(crate) fn root_add_device_retry_deadline() -> Option<u64> {
    let deadline = ROOT_ADD_DEVICE_RETRY_DEADLINE.load(Ordering::Acquire);
    (deadline != u64::MAX).then_some(deadline)
}

pub(crate) fn root_add_device_retry_wake_due(now: u64) -> u64 {
    let Some(deadline) = root_add_device_retry_deadline() else { return 0 };
    if now < deadline { return 0 }
    u64::from(ROOT_ADD_DEVICE_RETRY_DEADLINE.compare_exchange(
        deadline, u64::MAX, Ordering::AcqRel, Ordering::Acquire,
    ).is_ok())
}

/// The parked parent owns an explicit PIT one-shot. General timer reconciliation may select an
/// unrelated overdue source whose callback writes this retained bank, so only the exact retry
/// shot is programmed until the parent has settled. Nested pump ticks are already ACKed there.
unsafe fn prepare_parked_add_device_receive(
    current: &mut Option<RootAddDeviceTurn>,
) -> bool {
    let Some(turn) = current.as_mut() else { return false };
    let owner = turn.owner();
    let pending = DELAY_TIMER_TICKS_PENDING.swap(0, Ordering::AcqRel);
    if pending != 0 {
        PUMP_TIMER_TICKS_DRAINED.fetch_add(pending, Ordering::Relaxed);
        let now = monotonic_time_100ns();
        let _ = root_add_device_retry_wake_due(now);
        if turn.observe_arrival(owner, nt_driver_start::RootArrival::Timer { now }).is_err() {
            return false;
        }
    }
    let now = monotonic_time_100ns();
    let deadline = match turn.retry_deadline(owner) {
        Ok(Some(deadline)) if deadline > now => deadline,
        Ok(_) => match turn.arm_retry(turn.owner(), now, 1_000_000) {
            Ok(deadline) => deadline,
            Err(_) => return false,
        },
        Err(_) => return false,
    };
    ROOT_ADD_DEVICE_RETRY_DEADLINE.store(deadline, Ordering::Release);
    delay_timer_program(deadline, DELAY_TIMER_SOURCE_ROOT_ADD_DEVICE_RETRY)
}

/// The queued callback's physical parent owns the root until its selected child or restore
/// completes. A short one-shot wakes the root without dispatching unrelated timer providers.
unsafe fn prepare_parked_queued_callback_receive(
    current: &mut Vec<RootQueuedCallbackTurn>,
) -> bool {
    let Some(turn) = current.last_mut() else { return false };
    if !refresh_queued_callback_turn_witness(turn) { return false; }
    let owner = turn.owner();
    use crate::driver_launch::QueuedCallbackRootAction as Action;
    if !matches!(crate::driver_launch::queued_callback_root_action(),
        Some(Action::NeedsChild(selector) | Action::RetryRestore(selector))
            if selector == owner)
    { return false; }
    let pending = DELAY_TIMER_TICKS_PENDING.swap(0, Ordering::AcqRel);
    if pending != 0 {
        PUMP_TIMER_TICKS_DRAINED.fetch_add(pending, Ordering::Relaxed);
        let now = monotonic_time_100ns();
        let _ = root_queued_callback_retry_wake_due(now);
        if turn.observe_arrival(owner, nt_driver_start::RootArrival::Timer { now }).is_err() {
            return false;
        }
    }
    let now = monotonic_time_100ns();
    let deadline = match turn.retry_deadline(owner) {
        Ok(Some(deadline)) if deadline > now => deadline,
        Ok(_) => match turn.arm_retry(owner, now, 1_000_000) {
            Ok(deadline) => deadline,
            Err(_) => return false,
        },
        Err(_) => return false,
    };
    ROOT_QUEUED_CALLBACK_RETRY_DEADLINE.store(deadline, Ordering::Release);
    delay_timer_program(deadline, DELAY_TIMER_SOURCE_ROOT_QUEUED_CALLBACK_RETRY)
}

unsafe fn service_parked_queued_callback_notification(
    badge: u64,
) -> Result<(), nt_status::NtStatus> {
    let _ = driver_launch::latch_hosted_irq_badge(badge);
    let _ = driver_launch::drain_pending_hosted_irqs();
    if badge_has_delay_timer(badge) {
        ack_parked_queued_callback_retry_timer()?;
    }
    Ok(())
}

unsafe fn service_parked_add_device_notification(
    badge: u64,
) -> Result<(), nt_status::NtStatus> {
    let _ = driver_launch::latch_hosted_irq_badge(badge);
    let _ = driver_launch::drain_pending_hosted_irqs();
    if badge_has_delay_timer(badge) {
        ack_parked_add_device_retry_timer()?;
    }
    Ok(())
}

pub(crate) struct ParkedRootAddDevicePermit(());

impl ParkedRootAddDevicePermit {
    fn for_exact(handler: &ExecNtHandler, owner: RootAddDeviceOwner) -> Option<Self> {
        root_add_device_still_parked(handler, owner).then_some(Self(()))
    }

}

/// Proof that the newest physical queue callback still needs a local child or a certified
/// no-effects restore retry. The selector includes queue generation and physical Reply identity;
/// it is reselected at every park because the Reply can be refreshed within one generation.
pub(crate) struct ParkedRootQueuedCallbackPermit(crate::driver_launch::QueuedCallbackSelector);

impl ParkedRootQueuedCallbackPermit {
    unsafe fn retained() -> Option<Self> {
        use crate::driver_launch::QueuedCallbackRootAction as Action;
        let selector = match crate::driver_launch::queued_callback_root_action()? {
            Action::NeedsChild(selector) | Action::ResumeRecordedStep(selector)
            | Action::RetryRestore(selector) | Action::RetryTerminalAck(selector) => selector,
        };
        crate::driver_launch::queued_callback_file_floor(selector)?;
        Some(Self(selector))
    }

    pub(crate) unsafe fn is_exact(&self) -> bool {
        use crate::driver_launch::QueuedCallbackRootAction as Action;
        matches!(crate::driver_launch::queued_callback_root_action(),
            Some(Action::NeedsChild(selector) | Action::ResumeRecordedStep(selector)
                | Action::RetryRestore(selector) | Action::RetryTerminalAck(selector))
                if selector == self.0)
            && crate::driver_launch::queued_callback_file_floor(self.0).is_some()
    }
}

/// Synchronize the retained parent stack to the newest exact queue action before any current
/// Call is returned to ingress. The same queue claim continues its turn under a refreshed
/// Reply; a newer callback must get its own root turn and ACK witness.
unsafe fn ensure_queued_callback_root_turn(
    current: &mut Vec<RootQueuedCallbackTurn>,
    permit: &ParkedRootQueuedCallbackPermit,
) -> bool {
    if !permit.is_exact() {
        trace_queued_callback_root_failure("permit-inexact", current, Some(permit));
        return false;
    }
    if !settle_parked_queued_callback_turn(current) {
        trace_queued_callback_root_failure("prior-turn-settlement", current, Some(permit));
        return false;
    }
    if current.last_mut().is_some_and(|turn| !refresh_queued_callback_turn_witness(turn)) {
        trace_queued_callback_root_failure("witness-refresh", current, Some(permit));
        return false;
    }
    if current.last().is_some_and(|turn| turn.owner() == permit.0) { return true; }
    if current.last().is_some_and(|turn|
        !crate::driver_launch::queued_callback_newer_root_child(turn.owner(), permit.0))
    {
        trace_queued_callback_root_failure("not-newer-child", current, Some(permit));
        return false;
    }
    if current.try_reserve(1).is_err() {
        trace_queued_callback_root_failure("reserve", current, Some(permit));
        return false;
    }
    let mut turn = RootQueuedCallbackTurn::new(permit.0);
    if turn.retain_ingress(permit.0, Vec::new()).is_err() {
        trace_queued_callback_root_failure("retain-ingress", current, Some(permit));
        return false;
    }
    if !crate::driver_launch::watch_queued_callback_root_retirement(permit.0) {
        trace_queued_callback_root_failure("watch-retirement", current, Some(permit));
        return false;
    }
    current.push(turn);
    ROOT_QUEUED_CALLBACK_EXCLUSIVE.store(true, Ordering::Release);
    true
}

/// Reserve before touching the physical ingress row. Every deferred Call stays owned by CALLS;
/// the root turn retains an exact ticket so no later Call can overtake it at release.
unsafe fn retain_parked_queued_callback_ingress(
    current: &mut Vec<RootQueuedCallbackTurn>,
    permit: &ParkedRootQueuedCallbackPermit,
    reply: u64,
    badge: u64,
) -> bool {
    if !ensure_queued_callback_root_turn(current, permit) { return false; }
    let Some(turn) = current.last_mut() else { return false };
    if turn.owner() != permit.0 { return false; }
    let owner = turn.owner();
    if turn.observe_arrival(owner, nt_driver_start::RootArrival::RetainedCall).is_err() {
        return false;
    }
    let Ok(Some(tickets)) = turn.retained_ingress_mut(owner) else { return false };
    if tickets.try_reserve(1).is_err() { return false; }
    let Ok(ticket) = crate::spawn_hosts::shared_ingress::owner::runtime::
        defer_hosted_delivery_for_queued_callback(reply, badge, permit)
    else { return false };
    tickets.push(ticket);
    true
}

unsafe fn transfer_selected_queued_callback_ingress(
    current: &mut Vec<RootQueuedCallbackTurn>,
) -> bool {
    for turn in current.iter_mut() {
        let owner = turn.owner();
        let Ok(Some(tickets)) = turn.retained_ingress_mut(owner) else { return false };
        tickets.retain(|ticket| unsafe {
            !crate::spawn_hosts::shared_ingress::owner::runtime::
                deferred_queued_ingress_selected(ticket)
        });
    }
    true
}

unsafe fn settle_parked_queued_callback_turn(
    current: &mut Vec<RootQueuedCallbackTurn>,
) -> bool {
    while let Some(turn) = current.last() {
        let owner = turn.owner();
        if !crate::driver_launch::queued_callback_root_retired(owner) { break; }
        let tickets = match turn.retained_ingress(owner) {
            Ok(Some(tickets)) => tickets,
            _ => {
                trace_queued_callback_root_failure("retired-ingress-missing", current, None);
                return false;
            }
        };
        if tickets.iter().any(|ticket|
            !crate::spawn_hosts::shared_ingress::owner::runtime::
                deferred_parked_ingress_is_exact(ticket))
        {
            trace_queued_callback_root_failure("retired-ticket-inexact", current, None);
            return false;
        }
        let turn = current.pop().expect("watched callback turn");
        if !crate::driver_launch::consume_queued_callback_root_retirement(owner) {
            current.push(turn);
            trace_queued_callback_root_failure("consume-retirement", current, None);
            return false;
        }
        if let Err(turn) = turn.settle(owner) {
            current.push(turn);
            trace_queued_callback_root_failure("settle-turn", current, None);
            return false;
        }
    }
    if !crate::driver_launch::unsettled_queued_callback() {
        if !current.is_empty() {
            trace_queued_callback_root_failure("orphaned-turn", current, None);
            return false;
        }
        ROOT_QUEUED_CALLBACK_RETRY_DEADLINE.store(u64::MAX, Ordering::Release);
        ROOT_QUEUED_CALLBACK_EXCLUSIVE.store(false, Ordering::Release);
    }
    true
}

fn ready_flat_root_add_device(
    handler: &ExecNtHandler,
) -> nt_driver_start::AddDeviceSelection<RootAddDeviceOwner> {
    use nt_driver_start::AddDeviceReadiness;
    let starts = &handler.pending_driver_starts;
    let driver_starts = starts.occupied_slots().filter_map(|slot| starts.get(slot)).map(|pending| {
        // A Ready boot batch can still be ordered behind an earlier enumerator. The
        // selected root pass must not repeatedly choose that row ahead of an eligible
        // sibling or rebalance restart. General redrive handles an uncertain predecessor.
        let behind_predecessor = pending.bootstrap_predecessors.iter().any(|predecessor| {
            starts.get_exact(*predecessor).is_some_and(|older| {
                matches!(&older.owner, PendingDriverStartOwner::Boot { .. })
            })
        });
        let readiness = if behind_predecessor {
            AddDeviceReadiness::NotReady
        } else {
            pending.batch.flat_root_add_device_readiness()
        };
        (RootAddDeviceOwner::DriverStart(pending.reservation), readiness)
    });
    let operations = &handler.pending_pnp_operations;
    let rebalances = operations.occupied_slots().filter_map(|slot| operations.get(slot))
        .filter_map(|pending| match &pending.operation {
            OwnedPendingPnpOperation::Rebalance(batch) => Some((
                RootAddDeviceOwner::PnpRebalance(pending.reservation),
                batch.flat_root_add_device_readiness(),
            )),
            OwnedPendingPnpOperation::Removal(_) => None,
        });
    nt_driver_start::select_add_device_row(driver_starts.chain(rebalances))
}

/// Bounded native evidence for a flat root selection that passed over, or stopped at, a row
/// whose bus PDO has not been reported. `selected=none` means no row could enter AddDevice.
fn trace_flat_root_add_device_selection(
    handler: &ExecNtHandler,
    selection: nt_driver_start::AddDeviceSelection<RootAddDeviceOwner>,
) {
    let (selected, awaiting) = match selection {
        nt_driver_start::AddDeviceSelection::Selected { owner, passed_over: Some(awaiting) } =>
            (Some(owner), awaiting),
        nt_driver_start::AddDeviceSelection::AwaitingBusRelations(awaiting) => (None, awaiting),
        _ => return,
    };
    print_str(b"[pnp-add-device-select] selected=");
    match selected {
        Some(owner) => print_root_add_device_owner(handler, owner),
        None => print_str(b"none"),
    }
    print_str(b" awaiting-bus-pdo=");
    print_u64(awaiting.rows as u64);
    print_str(b" first=");
    print_root_add_device_owner(handler, awaiting.first);
    print_str(b"\n");
}

fn print_root_add_device_owner(handler: &ExecNtHandler, owner: RootAddDeviceOwner) {
    let (kind, slot, identity) = match owner {
        RootAddDeviceOwner::DriverStart(reservation) => (
            b"start".as_slice(),
            reservation.slot(),
            handler.pending_driver_starts.get_exact(reservation)
                .map(|pending| pending.batch.next_devnode_identity()),
        ),
        RootAddDeviceOwner::PnpRebalance(reservation) => (
            b"rebalance".as_slice(),
            reservation.slot(),
            handler.pending_pnp_operations.get_exact(reservation)
                .and_then(|pending| match &pending.operation {
                    OwnedPendingPnpOperation::Rebalance(batch) =>
                        Some(batch.next_devnode_identity()),
                    OwnedPendingPnpOperation::Removal(_) => None,
                }),
        ),
    };
    print_str(kind);
    print_str(b" slot=");
    print_u64(slot as u64);
    if let Some((service, devnode)) = identity {
        print_str(b" service=");
        print_str(service.as_bytes());
        print_str(b" devnode=");
        print_str(devnode.unwrap_or("none").as_bytes());
    }
}

fn root_add_device_still_parked(handler: &ExecNtHandler, owner: RootAddDeviceOwner) -> bool {
    match owner {
        RootAddDeviceOwner::DriverStart(reservation) => handler.pending_driver_starts
            .get_exact(reservation).is_some_and(|pending|
                pending.batch.wait_stage() == hosted_pnp_start::HostedPnpWaitStage::AddDevice),
        RootAddDeviceOwner::PnpRebalance(reservation) => handler.pending_pnp_operations
            .get_exact(reservation).is_some_and(|pending| match &pending.operation {
                OwnedPendingPnpOperation::Rebalance(batch) => batch.add_device_wait_stage(),
                OwnedPendingPnpOperation::Removal(_) => false,
            }),
    }
}

fn root_add_device_owner_exact_present(
    handler: &ExecNtHandler,
    owner: RootAddDeviceOwner,
) -> bool {
    match owner {
        RootAddDeviceOwner::DriverStart(reservation) =>
            handler.pending_driver_starts.get_exact(reservation).is_some(),
        RootAddDeviceOwner::PnpRebalance(reservation) =>
            handler.pending_pnp_operations.get_exact(reservation).is_some(),
    }
}

fn root_add_device_retry_without_new_child(
    handler: &ExecNtHandler, owner: RootAddDeviceOwner,
) -> bool {
    match owner {
        RootAddDeviceOwner::DriverStart(reservation) => handler.pending_driver_starts
            .get_exact(reservation).is_some_and(|pending|
                pending.batch.retry_add_device_without_new_child()),
        RootAddDeviceOwner::PnpRebalance(reservation) => handler.pending_pnp_operations
            .get_exact(reservation).is_some_and(|pending| match &pending.operation {
                OwnedPendingPnpOperation::Rebalance(batch) =>
                    batch.retry_add_device_without_new_child(),
                OwnedPendingPnpOperation::Removal(_) => false,
            }),
    }
}

fn root_add_device_probe_bits(handler: &ExecNtHandler, owner: RootAddDeviceOwner) -> u64 {
    match owner {
        RootAddDeviceOwner::DriverStart(reservation) => handler.pending_driver_starts
            .get_exact(reservation).map_or(0, |pending|
                pending.batch.root_add_device_probe_bits()),
        RootAddDeviceOwner::PnpRebalance(reservation) => handler.pending_pnp_operations
            .get_exact(reservation).map_or(0, |pending| match &pending.operation {
                OwnedPendingPnpOperation::Rebalance(batch) => batch.root_add_device_probe_bits(),
                OwnedPendingPnpOperation::Removal(_) => 0,
            }),
    }
}

fn root_add_device_needs_child_step(
    handler: &ExecNtHandler, owner: RootAddDeviceOwner,
) -> bool {
    match owner {
        RootAddDeviceOwner::DriverStart(reservation) => handler.pending_driver_starts
            .get_exact(reservation).is_some_and(|pending|
                pending.batch.needs_add_device_child_step()),
        RootAddDeviceOwner::PnpRebalance(reservation) => handler.pending_pnp_operations
            .get_exact(reservation).is_some_and(|pending| match &pending.operation {
                OwnedPendingPnpOperation::Rebalance(batch) =>
                    batch.needs_add_device_child_step(),
                OwnedPendingPnpOperation::Removal(_) => false,
            }),
    }
}

unsafe fn redrive_flat_root_add_device_selected(
    handler: &mut ExecNtHandler, owner: RootAddDeviceOwner,
) -> u64 {
    match owner {
        RootAddDeviceOwner::DriverStart(reservation) =>
            pending_driver_start_redrive_flat_root_selected(handler, reservation),
        RootAddDeviceOwner::PnpRebalance(reservation) =>
            pending_pnp_operation_redrive_flat_root_selected(handler, reservation),
    }
}

/// Run at most one certified nested File step for an exact retained AddDevice batch. Its
/// Ready cursor cannot retire during this step: redrive waits until the receipt is deposited.
unsafe fn run_one_pending_add_device_child_step(
    handler: *mut ExecNtHandler,
) -> Result<Option<(RootAddDeviceOwner, bool)>, ()> {
    let selected = {
        let table = &(*handler).pending_driver_starts;
        table.occupied_slots().find_map(|slot| {
            let pending = table.get(slot)?;
            (pending.batch.wait_stage() == hosted_pnp_start::HostedPnpWaitStage::AddDevice)
                .then_some((slot, pending.reservation,
                    pending.batch.needs_add_device_child_step()))
        })
    };
    if let Some((slot, reservation, needs_child)) = selected {
        let owner = RootAddDeviceOwner::DriverStart(reservation);
        if !needs_child { return Ok(Some((owner, false))) }
        let step = drive_one_nested_file_child_step();
        let ran_child = step.ran_child();
        let pending = (*handler).pending_driver_starts.get_mut(slot)
            .filter(|pending| pending.reservation == reservation)
            .expect("selected AddDevice batch cannot retire before its child receipt is deposited");
        return match pending.batch.record_add_device_child_step(step) {
            Ok(crate::hosted_pnp_start::AddDeviceStepDeposit::Recorded) =>
                Ok(Some((owner, ran_child))),
            Ok(crate::hosted_pnp_start::AddDeviceStepDeposit::Quarantined) => Err(()),
            Err(_) => unreachable!("exact AddDevice batch refused its selected child receipt"),
        };
    }
    let selected = {
        let table = &(*handler).pending_pnp_operations;
        table.occupied_slots().find_map(|slot| {
            let pending = table.get(slot)?;
            let OwnedPendingPnpOperation::Rebalance(batch) = &pending.operation else {
                return None;
            };
            batch.add_device_wait_stage().then_some((slot, pending.reservation,
                batch.needs_add_device_child_step()))
        })
    };
    let Some((slot, reservation, needs_child)) = selected else { return Ok(None) };
    let owner = RootAddDeviceOwner::PnpRebalance(reservation);
    if !needs_child { return Ok(Some((owner, false))) }
    let step = drive_one_nested_file_child_step();
    let ran_child = step.ran_child();
    let pending = (*handler).pending_pnp_operations.get_mut(slot)
        .filter(|pending| pending.reservation == reservation)
        .expect("selected rebalance AddDevice cannot retire before its child receipt is deposited");
    let OwnedPendingPnpOperation::Rebalance(batch) = &mut pending.operation else {
        unreachable!("exact rebalance AddDevice changed operation kind");
    };
    match batch.record_add_device_child_step(step) {
        Ok(crate::hosted_pnp_start::AddDeviceStepDeposit::Recorded) =>
            Ok(Some((owner, ran_child))),
        Ok(crate::hosted_pnp_start::AddDeviceStepDeposit::Quarantined) => Err(()),
        Err(_) => unreachable!("exact rebalance AddDevice refused its selected child receipt"),
    }
}

/// Settle every inner CONNECT owner before an AddDevice parent or unrelated provider resumes.
/// Each selected child has one sealed observation. An empty local pass is retryable only after
/// the exact selector and its observation are deposited back in the CONNECT owner.
enum ConnectPumpSettlement {
    Settled,
    AwaitingLocalChild,
    /// A retryable physical restore or scheduler yield still owns its original Reply.
    RetryableRestore,
    Retained,
    Blocked,
}

/// Capped root checkpoint around CONNECT, queue, and Hook settlement. This reads only
/// owner readiness; no provider or shared-ring operation is issued by the probe.
/// Stages: 0 CONNECT redrive entry, 1 CONNECT redrive returned,
/// 2 CONNECT settled, 3 queue settled,
/// 4 Hook redrive entry, 5 Hook redrive returned. Settlement: 0 none,
/// 1 settled, 2 awaiting child, 3 retained, 4 blocked.
unsafe fn trace_connect_root_checkpoint(
    stage: u64, settlement: Option<&ConnectPumpSettlement>,
) {
    static ARMED: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    static COUNT: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    if !ARMED.load(core::sync::atomic::Ordering::Relaxed) {
        let connect_owner = crate::driver_launch::hosted_connect_pending_reply_published();
        if !connect_owner { return; }
        ARMED.store(true, core::sync::atomic::Ordering::Relaxed);
    }
    if COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed) >= 128 { return; }
    let settlement = match settlement {
        None => 0,
        Some(ConnectPumpSettlement::Settled) => 1,
        Some(ConnectPumpSettlement::AwaitingLocalChild) => 2,
        Some(ConnectPumpSettlement::RetryableRestore) => 5,
        Some(ConnectPumpSettlement::Retained) => 3,
        Some(ConnectPumpSettlement::Blocked) => 4,
    };
    print_str(b"[connect-root-checkpoint] stage/settlement/hook-ready/queue-held/file-held=");
    print_u64(stage); print_str(b"/");
    print_u64(settlement); print_str(b"/");
    print_u64(u64::from(crate::driver_launch::nested_hosted_hook_forward_ready()));
    print_str(b"/");
    print_u64(u64::from(crate::driver_launch::unsettled_queued_callback()));
    print_str(b"/");
    print_u64(u64::from(crate::driver_launch::generic_file_pump_unsettled()));
    print_str(b"\n");
}

// Stages: 1 recorded pump result (0 no work, 1 returned, 2 yielded,
// 3 retained, 4 blocked), 2 settlement (1 settled, 2 awaiting, 3 retained,
// 4 blocked), 3 AddDevice still-parked/awaiting-child/ran-child bits,
// 4 parked receive prepared, 5 native AddDevice continuation bits, 6 CONNECT
// origin bits. Phase comes from the live CONNECT owner.
unsafe fn trace_connect_add_device_boundary(stage: u64, detail: u64) {
    static COUNT: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    if !crate::driver_launch::hosted_connect_pending_reply_published() { return; }
    if COUNT.fetch_add(1, Ordering::Relaxed) >= 32 { return; }
    print_str(b"[connect-add-device] stage/detail/phase/unsettled=");
    print_u64(stage); print_str(b"/"); print_u64(detail); print_str(b"/");
    print_u64(crate::driver_launch::hosted_connect_root_probe_phase()); print_str(b"/");
    print_u64(u64::from(crate::driver_launch::unsettled_suspended_connect_pump()));
    print_str(b"\n");
}

unsafe fn trace_connect_pump_progress(progress: &crate::driver_launch::PortConnectPumpProgress) {
    use crate::driver_launch::PortConnectPumpProgress as Progress;
    let code = match progress {
        Progress::NoWork => 0, Progress::Returned => 1, Progress::Yielded => 2,
        Progress::Retained => 3, Progress::Blocked => 4,
    };
    trace_connect_add_device_boundary(1, code);
}

unsafe fn settle_suspended_connect_pumps() -> ConnectPumpSettlement {
    let result = settle_suspended_connect_pumps_inner();
    let code = match &result {
        ConnectPumpSettlement::Settled => 1,
        ConnectPumpSettlement::AwaitingLocalChild => 2,
        ConnectPumpSettlement::RetryableRestore => 5,
        ConnectPumpSettlement::Retained => 3,
        ConnectPumpSettlement::Blocked => 4,
    };
    trace_connect_add_device_boundary(2, code);
    result
}

unsafe fn settle_suspended_connect_pumps_inner() -> ConnectPumpSettlement {
    use crate::driver_launch::PortConnectPumpProgress as Progress;
    crate::driver_launch::trace_port_connect_root_probe(80, 0);
    loop {
        // A CONNECT child can enter a queued callback before its File/Hook source
        // publishes. That callback's physical Reply must settle first.
        match settle_queued_callbacks() {
            ConnectPumpSettlement::Settled => {}
            other => return other,
        }
        if let Some(selector) = crate::driver_launch::recorded_suspended_connect_pump() {
            match settle_suspended_file_pumps() {
                ConnectPumpSettlement::Settled => {}
                other => return other,
            }
            let progress = crate::driver_launch::redrive_recorded_connect_pump(selector);
            trace_connect_pump_progress(&progress);
            match progress {
                Progress::Blocked => return ConnectPumpSettlement::Blocked,
                Progress::Retained => return ConnectPumpSettlement::Retained,
                Progress::NoWork | Progress::Returned | Progress::Yielded => continue,
            }
        }
        match crate::driver_launch::redrive_retryable_connect_pump() {
            Progress::Blocked => return ConnectPumpSettlement::Blocked,
            Progress::Retained => return ConnectPumpSettlement::Retained,
            Progress::NoWork | Progress::Returned | Progress::Yielded => {}
        }
        let Some(selector) = crate::driver_launch::claim_suspended_port_connect_pump()
        else { break };
        crate::driver_launch::trace_port_connect_root_probe(81, 1);
        let step = drive_one_nested_file_child_step();
        let ran_child = step.ran_child();
        crate::driver_launch::trace_port_connect_root_probe(82, u64::from(ran_child));
        // The child receipt is move-only. The CONNECT Work must own it before any
        // inner Hook settlement can yield or refuse a root turn.
        match crate::driver_launch::record_suspended_connect_pump_child_step(selector, step) {
            Progress::Retained => {}
            Progress::Blocked => return ConnectPumpSettlement::Blocked,
            _ => return ConnectPumpSettlement::Retained,
        }
        // A reverse Hook can itself yield a nested File pump. Its exact invocation and
        // mutable Type3 input belong to that Hook owner, so settle it at the flat root
        // before restoring this CONNECT parent's physical Reply.
        let inner_settlement = settle_suspended_file_pumps();
        crate::driver_launch::trace_port_connect_root_probe(83, match inner_settlement {
            ConnectPumpSettlement::Settled => 0,
            ConnectPumpSettlement::AwaitingLocalChild => 1,
            ConnectPumpSettlement::RetryableRestore => 4,
            ConnectPumpSettlement::Retained => 2,
            ConnectPumpSettlement::Blocked => 3,
        });
        match inner_settlement {
            ConnectPumpSettlement::Settled => {}
            ConnectPumpSettlement::AwaitingLocalChild =>
                return ConnectPumpSettlement::AwaitingLocalChild,
            ConnectPumpSettlement::RetryableRestore =>
                return ConnectPumpSettlement::RetryableRestore,
            ConnectPumpSettlement::Retained => return ConnectPumpSettlement::Retained,
            ConnectPumpSettlement::Blocked => return ConnectPumpSettlement::Blocked,
        }
        let progress = crate::driver_launch::redrive_recorded_connect_pump(selector);
        trace_connect_pump_progress(&progress);
        match progress {
            Progress::Blocked => return ConnectPumpSettlement::Blocked,
            Progress::Retained => return ConnectPumpSettlement::Retained,
            Progress::Yielded if !ran_child => return ConnectPumpSettlement::AwaitingLocalChild,
            Progress::NoWork | Progress::Returned | Progress::Yielded => {}
        }
    }
    if crate::driver_launch::unsettled_suspended_connect_pump() {
        ConnectPumpSettlement::Retained
    } else {
        ConnectPumpSettlement::Settled
    }
}

/// Run every nested Hook File child after its caller's stack has unwound. A claimed parent
/// retains its one-use child observation while a newer Hook pump settles; retry resumes only
/// that recorded parent and never redispatches its original IRP.
fn trace_hook_root_boundary(stage: u64) {
    static COUNT: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    if COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed) >= 64 { return; }
    print_str(b"[hook-root-boundary] stage=");
    print_u64(stage);
    print_str(b"\n");
}

unsafe fn settle_suspended_file_pumps() -> ConnectPumpSettlement {
    // A queued callback may be the child of a File pump. Its receipt must settle before
    // the older File parent resumes. Recheck the newest exact queue row after every File
    // transition because that transition can itself create another callback.
    for _ in 0..512 {
        match settle_queued_callback_turn() {
            FilePumpTurn::Progressed => continue,
            FilePumpTurn::AwaitingLocalChild =>
                return ConnectPumpSettlement::AwaitingLocalChild,
            FilePumpTurn::RetryableRestore =>
                return ConnectPumpSettlement::RetryableRestore,
            FilePumpTurn::Retained => return ConnectPumpSettlement::Retained,
            FilePumpTurn::Blocked => return ConnectPumpSettlement::Blocked,
            FilePumpTurn::Settled => {}
        }
        match settle_one_generic_file_pump_after(0) {
            FilePumpTurn::Progressed => continue,
            FilePumpTurn::AwaitingLocalChild =>
                return ConnectPumpSettlement::AwaitingLocalChild,
            FilePumpTurn::RetryableRestore =>
                return ConnectPumpSettlement::RetryableRestore,
            FilePumpTurn::Retained => return ConnectPumpSettlement::Retained,
            FilePumpTurn::Blocked => return ConnectPumpSettlement::Blocked,
            FilePumpTurn::Settled => return if crate::driver_launch::hook_source_unsettled() {
                ConnectPumpSettlement::Retained
            } else {
                ConnectPumpSettlement::Settled
            },
        }
    }
    // Every owner and one-use receipt remains in its durable row; no provider is replayed
    // after this per-turn progress bound.
    ConnectPumpSettlement::Retained
}

enum FilePumpTurn {
    Progressed,
    Settled,
    AwaitingLocalChild,
    /// The selected callback is durable and may retry after a root timer/IRQ receive.
    RetryableRestore,
    Retained,
    Blocked,
}

/// Settle only one queued callback transition. Its File floor is captured before native
/// callback entry, so an older File parent stays parked until this callback completes.
unsafe fn settle_queued_callback_turn() -> FilePumpTurn {
    use crate::driver_launch::{QueuedCallbackProgress as Progress,
        QueuedCallbackRootAction as Action};
    let Some(action) = crate::driver_launch::queued_callback_root_action() else {
        return if crate::driver_launch::unsettled_queued_callback() {
            FilePumpTurn::Retained
        } else {
            FilePumpTurn::Settled
        };
    };
    let selector = match action {
        Action::NeedsChild(selector) => {
            let step = drive_one_nested_file_child_step();
            return match crate::driver_launch::record_queued_callback_child_step(selector, step) {
                Progress::RecordedStep => FilePumpTurn::Progressed,
                Progress::AwaitingLocalChild => FilePumpTurn::AwaitingLocalChild,
                Progress::Blocked => FilePumpTurn::Blocked,
                _ => FilePumpTurn::Retained,
            };
        }
        Action::ResumeRecordedStep(selector) | Action::RetryRestore(selector)
        | Action::RetryTerminalAck(selector) => selector,
    };
    let Some(floor) = crate::driver_launch::queued_callback_file_floor(selector) else {
        return FilePumpTurn::Retained;
    };
    match settle_one_generic_file_pump_after(floor) {
        FilePumpTurn::Progressed => return FilePumpTurn::Progressed,
        FilePumpTurn::Settled => {}
        other => return other,
    }
    // The File transition may have created a newer callback. Only the same exact row may
    // resume; a different selected row must first settle in physical LIFO order.
    if crate::driver_launch::queued_callback_root_action() != Some(action) {
        return FilePumpTurn::Progressed;
    }
    match crate::driver_launch::resume_queued_callback_after_file_settlement(selector) {
        Progress::Completed | Progress::TerminalFailure(_) | Progress::NeedsChild =>
            FilePumpTurn::Progressed,
        Progress::RecordedStep | Progress::InnerFilePending => FilePumpTurn::Retained,
        Progress::AwaitingLocalChild => FilePumpTurn::AwaitingLocalChild,
        Progress::PendingRestore => FilePumpTurn::RetryableRestore,
        Progress::PendingTerminalAck => FilePumpTurn::Retained,
        Progress::Blocked => FilePumpTurn::Blocked,
    }
}

/// A queue-only pass is used before ordinary CONNECT/Hook redrives. It does not inspect an
/// unrelated Hook source that can only finish after its own parent has resumed.
unsafe fn settle_queued_callbacks() -> ConnectPumpSettlement {
    for _ in 0..512 {
        match settle_queued_callback_turn() {
            FilePumpTurn::Progressed => continue,
            FilePumpTurn::Settled => return ConnectPumpSettlement::Settled,
            FilePumpTurn::AwaitingLocalChild =>
                return ConnectPumpSettlement::AwaitingLocalChild,
            FilePumpTurn::RetryableRestore => return ConnectPumpSettlement::RetryableRestore,
            FilePumpTurn::Retained => return ConnectPumpSettlement::Retained,
            FilePumpTurn::Blocked => return ConnectPumpSettlement::Blocked,
        }
    }
    ConnectPumpSettlement::Retained
}

/// Advance one generic File owner, then return to the queue selector before any other
/// File parent can resume. A selected child receipt is deposited before this function
/// returns, including when the child creates another queued callback.
unsafe fn settle_one_generic_file_pump_after(floor: u64) -> FilePumpTurn {
    use crate::driver_launch::GenericFilePumpDrive as Progress;
    {
        static COUNT: core::sync::atomic::AtomicU64 =
            core::sync::atomic::AtomicU64::new(0);
        let returned = crate::driver_launch::returned_hook_pump_ready();
        let generic = crate::driver_launch::generic_file_pump_unsettled();
        let source = crate::driver_launch::hook_source_unsettled();
        if crate::driver_launch::hosted_hook_port_waiting()
            && COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 256
        {
            print_str(b"[hook-root-settle] returned/generic/source=");
            print_u64(u64::from(returned)); print_str(b"/");
            print_u64(u64::from(generic)); print_str(b"/");
            print_u64(u64::from(source)); print_str(b"\n");
        }
    }
    // A queued callback's floor excludes its older File/Hook parent. Source rows keep
    // their exact File owner ID even after the File row retires.
    if crate::driver_launch::returned_hook_pump_ready_after(floor) {
        return if crate::driver_launch::redrive_returned_hook_pump_after(floor) {
            FilePumpTurn::Progressed
        } else {
            FilePumpTurn::Retained
        };
    }
    let (progress, deposited) = if let Some(selector) =
        crate::driver_launch::claim_suspended_generic_file_pump_after(floor)
    {
        let step = drive_one_nested_file_child_step();
        (crate::driver_launch::record_suspended_generic_file_pump_child_step(selector, step), true)
    } else if let Some(selector) =
        crate::driver_launch::recorded_suspended_generic_file_pump_after(floor)
    {
        (crate::driver_launch::redrive_recorded_generic_file_pump(selector), false)
    } else {
        (crate::driver_launch::redrive_retryable_generic_file_pump_after(floor), false)
    };
    match progress {
        Progress::NoWork if crate::driver_launch::generic_file_pump_unsettled_after(floor)
            || crate::driver_launch::hook_source_unsettled_after(floor) =>
            FilePumpTurn::Retained,
        Progress::NoWork => FilePumpTurn::Settled,
        Progress::Returned | Progress::Pending | Progress::Yielded => FilePumpTurn::Progressed,
        // A successful deposit returns Retained while the sealed receipt is held by the
        // row. It is progress, not a restore refusal.
        Progress::Retained if deposited => FilePumpTurn::Progressed,
        Progress::Retained => FilePumpTurn::Retained,
        Progress::AwaitingLocalChild => FilePumpTurn::AwaitingLocalChild,
        Progress::Blocked => FilePumpTurn::Blocked,
    }
}

unsafe fn pending_driver_start_redrive_all(nt_handler: &mut ExecNtHandler) -> u64 {
    pending_driver_start_redrive_selected(nt_handler, None, false)
}

unsafe fn pending_driver_start_redrive_flat_root_selected(
    nt_handler: &mut ExecNtHandler,
    reservation: nt_driver_start::PendingOperationReservation,
) -> u64 {
    pending_driver_start_redrive_selected(nt_handler, Some(reservation), true)
}

/// The root can settle only a selected parked AddDevice batch before any unrelated start row.
/// Ordinary completion redrive uses the same terminal publication logic with no selector.
unsafe fn pending_driver_start_redrive_selected(
    nt_handler: &mut ExecNtHandler,
    selected: Option<nt_driver_start::PendingOperationReservation>,
    flat_root_add_device_permit: bool,
) -> u64 {
    let mut completed = 0u64;
    for slot in 0..nt_handler.pending_driver_starts.slot_count() {
        if selected.is_some_and(|reservation| nt_handler.pending_driver_starts
            .get(slot).is_none_or(|pending| pending.reservation != reservation))
        {
            continue;
        }
        let bootstrap_barrier = {
            let table = &nt_handler.pending_driver_starts;
            let Some(pending) = table.get(slot) else {
                continue;
            };
            if selected.is_some()
                && pending.batch.wait_stage() == hosted_pnp_start::HostedPnpWaitStage::AddDevice
            {
                // This exact AddDevice has already entered native code. A predecessor may
                // affect later START policy, but cannot revoke its physical Reply owner.
                0u8
            } else if !matches!(&pending.owner, PendingDriverStartOwner::Boot { .. }) {
                0u8
            } else if pending.bootstrap_predecessors.iter().any(|predecessor| {
                table.get_exact(*predecessor).is_some_and(|older| {
                    matches!(
                        &older.owner,
                        PendingDriverStartOwner::Boot {
                            report_published: true,
                            ..
                        }
                    )
                })
            }) {
                // An uncertain predecessor keeps its exact slot and cannot publish a child PDO.
                2
            } else if pending.bootstrap_predecessors.iter().any(|predecessor| {
                table.get_exact(*predecessor).is_some_and(|older| {
                    matches!(&older.owner, PendingDriverStartOwner::Boot { .. })
                })
            }) {
                1
            } else {
                0
            }
        };
        if bootstrap_barrier == 1 {
            if let Some(pending) = nt_handler.pending_driver_starts.get_mut(slot) {
                trace_pending_driver_start_wait(
                    slot,
                    pending,
                    hosted_pnp_start::HostedPnpWaitStage::BootstrapPredecessor,
                );
            }
            continue;
        }
        let progress = {
            let Some(pending) = nt_handler.pending_driver_starts.get_mut(slot) else {
                continue;
            };
            if bootstrap_barrier == 2 {
                pending.batch.fail_unentered_bootstrap_barrier(
                    nt_status::NtStatus::INVALID_DEVICE_REQUEST,
                )
            } else {
                if flat_root_add_device_permit {
                    pending.batch.drive_flat_root_add_device()
                } else {
                    pending.batch.drive_after_completion_pump()
                }
            }
        };
        match progress {
            OwnedHostedPnpStartProgress::AwaitingCompletion => {
                if let Some(pending) = nt_handler.pending_driver_starts.get_mut(slot) {
                    let stage = pending.batch.wait_stage();
                    trace_pending_driver_start_wait(slot, pending, stage);
                }
            }
            OwnedHostedPnpStartProgress::Complete(result) => {
                let status = match result {
                    Ok(_) => nt_status::NtStatus::SUCCESS.raw() as u32,
                    Err(failure) => failure.status.raw() as u32,
                };
                let mut pending = nt_handler
                    .pending_driver_starts
                    .take(slot)
                    .expect("completed driver START continuation disappeared");
                match &mut pending.owner {
                    PendingDriverStartOwner::CriticalChild { claim } => {
                        if let Some(claim) = claim.take() {
                            driver_launch::complete_hosted_critical_child_start(claim, status);
                        }
                    }
                    PendingDriverStartOwner::Boot { target, .. } => nt_handler
                        .boot_driver_start_reports
                        .merge(*target, pending.batch.report()),
                    PendingDriverStartOwner::User { request, reply } => {
                        let request = request.take();
                        if let Some(request) = request {
                            record_pending_start_result(
                                nt_handler,
                                request,
                                &mut pending.batch,
                                status,
                            );
                        }
                        let reply = reply.take();
                        if let Some(reply) = reply {
                            let delivered = pending_driver_start_reply_owner(
                                nt_handler,
                                reply.reply_cap,
                                reply.badge,
                                status,
                            );
                            let request = request.expect(
                                "pending StartDevice reply survived after request retirement",
                            );
                            record_pending_start_reply(nt_handler, request, status, delivered);
                        }
                    }
                }
                completed += 1;
            }
            OwnedHostedPnpStartProgress::OwnershipLost(failure) => {
                let status = failure.status.raw() as u32;
                let mut boot_report = None;
                let user = {
                    let Some(pending) = nt_handler.pending_driver_starts.get_mut(slot) else {
                        continue;
                    };
                    match &mut pending.owner {
                        PendingDriverStartOwner::CriticalChild { claim } => {
                            if let Some(claim) = claim.take() {
                                driver_launch::quarantine_hosted_critical_child_start(claim);
                            }
                            None
                        }
                        PendingDriverStartOwner::Boot {
                            target,
                            report_published,
                        } => {
                            if !*report_published {
                                boot_report = Some((*target, pending.batch.report()));
                                *report_published = true;
                            }
                            None
                        }
                        PendingDriverStartOwner::User { request, reply } => Some((
                            request.take(),
                            reply.take(),
                            pending.batch.take_single_start_evidence(),
                        )),
                    }
                };
                if let Some((target, report)) = boot_report {
                    nt_handler.boot_driver_start_reports.merge(target, report);
                }
                if let Some((request, reply, evidence)) = user {
                    if let Some(request) = request {
                        let evidence = evidence
                            .expect("lost live StartDevice batch did not own exactly one devnode");
                        let result = match evidence {
                            SingleStartEvidence::Consumed => {
                                panic!("lost live StartDevice batch evidence was consumed twice")
                            }
                            SingleStartEvidence::NotDispatched => nt_handler
                                .pnp_start_device_calls
                                .complete_without_start_irp(request, status),
                            SingleStartEvidence::Lifecycle { receipt } => nt_handler
                                .pnp_start_device_calls
                                .complete_protocol_ownership_lost(
                                    request,
                                    receipt.dispatch().canonical_irp_id,
                                    Some(receipt),
                                    status,
                                ),
                            SingleStartEvidence::Dispatched { irp_id } => nt_handler
                                .pnp_start_device_calls
                                .complete_ownership_lost(request, irp_id, None, status),
                            SingleStartEvidence::OwnershipLost { irp_id, receipt } => nt_handler
                                .pnp_start_device_calls
                                .complete_ownership_lost(request, irp_id, receipt, status),
                        };
                        result.expect("lost StartDevice result lost its exact request");
                    }
                    if let Some(reply) = reply {
                        let request = request
                            .expect("lost StartDevice reply survived after request retirement");
                        let delivered = pending_driver_start_reply_owner(
                            nt_handler,
                            reply.reply_cap,
                            reply.badge,
                            status,
                        );
                        record_pending_start_reply(nt_handler, request, status, delivered);
                        completed += 1;
                    }
                }
            }
        }
    }
    completed
}

unsafe fn pending_pnp_operation_redrive_all(nt_handler: &mut ExecNtHandler) -> u64 {
    pending_pnp_operation_redrive_selected(nt_handler, None, false)
}

unsafe fn pending_pnp_operation_redrive_flat_root_selected(
    nt_handler: &mut ExecNtHandler,
    reservation: nt_driver_start::PendingOperationReservation,
) -> u64 {
    pending_pnp_operation_redrive_selected(nt_handler, Some(reservation), true)
}

unsafe fn pending_pnp_operation_redrive_selected(
    nt_handler: &mut ExecNtHandler,
    selected: Option<nt_driver_start::PendingOperationReservation>,
    flat_root_add_device_permit: bool,
) -> u64 {
    let mut completed = 0u64;
    for slot in 0..nt_handler.pending_pnp_operations.slot_count() {
        if selected.is_some_and(|reservation| nt_handler.pending_pnp_operations
            .get(slot).is_none_or(|pending| pending.reservation != reservation))
        {
            continue;
        }
        let progress = {
            let Some(pending) = nt_handler.pending_pnp_operations.get_mut(slot) else {
                continue;
            };
            if flat_root_add_device_permit {
                match &mut pending.operation {
                    OwnedPendingPnpOperation::Rebalance(batch) =>
                        match batch.drive_flat_root_add_device() {
                            OwnedHostedPnpRebalanceProgress::AwaitingCompletion =>
                                OwnedPendingPnpOperationProgress::AwaitingCompletion,
                            OwnedHostedPnpRebalanceProgress::Complete(result) =>
                                OwnedPendingPnpOperationProgress::Complete(match result {
                                    Ok(_) => nt_status::NtStatus::SUCCESS.raw() as u32,
                                    Err(failure) => failure.status.raw() as u32,
                                }),
                            OwnedHostedPnpRebalanceProgress::OwnershipLost(failure) =>
                                OwnedPendingPnpOperationProgress::OwnershipLost(
                                    failure.status.raw() as u32),
                        },
                    OwnedPendingPnpOperation::Removal(_) =>
                        unreachable!("flat root AddDevice selected removal"),
                }
            } else {
                pending.operation.drive_after_completion_pump()
            }
        };
        match progress {
            OwnedPendingPnpOperationProgress::AwaitingCompletion => {}
            OwnedPendingPnpOperationProgress::Complete(status) => {
                let mut pending = nt_handler
                    .pending_pnp_operations
                    .take(slot)
                    .expect("completed PnP operation continuation disappeared");
                if let Some(reply) = pending.reply.take() {
                    pending_driver_start_reply_owner(
                        nt_handler,
                        reply.reply_cap,
                        reply.badge,
                        status,
                    );
                }
                completed = completed.saturating_add(1);
            }
            OwnedPendingPnpOperationProgress::OwnershipLost(status) => {
                let reply = nt_handler
                    .pending_pnp_operations
                    .get_mut(slot)
                    .and_then(|pending| pending.reply.take());
                if let Some(reply) = reply {
                    pending_driver_start_reply_owner(
                        nt_handler,
                        reply.reply_cap,
                        reply.badge,
                        status,
                    );
                    completed = completed.saturating_add(1);
                }
            }
        }
    }
    completed
}

unsafe fn start_committed_critical_children(nt_handler: &mut ExecNtHandler) -> u64 {
    // A synchronous boot/config batch may reenter this pump between AddDevice and START,
    // before its continuation has been published in pending_driver_starts.
    if hosted_pnp_start::hosted_start_batch_drive_active() {
        return 0;
    }
    let Some(mount) = LIVE_CONFIG_MANAGER_SYSTEM_MOUNT else {
        return 0;
    };
    let mut progress = 0u64;
    for _ in 0..8 {
        // A terminal bus START can queue its initial relations during the redrive above or
        // during an earlier iteration. Admit no sibling START before that query dispatches.
        if driver_launch::hosted_bus_relation_pending() {
            break;
        }
        let claim = match driver_launch::claim_hosted_critical_child_start_ready(
            mount.identity_token(),
            |key, instance| !nt_handler.pending_driver_starts.occupied_slots().any(|slot| {
                nt_handler.pending_driver_starts.get(slot).is_some_and(|pending| {
                    pending.batch.owns_current_bus_child(instance, key.child().pdo_object_id())
                })
            }),
        ) {
            Ok(Some(claim)) => claim,
            Ok(None) => break,
            Err(nt_pnp_manager::CriticalChildStartError::StalePublication) => {
                progress += 1;
                continue;
            }
            Err(_) => break,
        };
        let instance = driver_launch::hosted_critical_child_instance_id(claim)
            .expect("critical child claim lost its instance identity");
        print_str(b"[pnp-critical-start] instance=");
        print_str(instance.as_bytes());
        print_str(b"\n");
        let state = driver_launch::hosted_pnp_device_state_for_instance(instance);
        match nt_pnp_manager::existing_device_start_disposition(state) {
            nt_pnp_manager::ExistingDeviceStartDisposition::AlreadyStarted => {
                driver_launch::complete_hosted_critical_child_start(claim, 0);
                progress += 1;
                continue;
            }
            nt_pnp_manager::ExistingDeviceStartDisposition::Busy => {
                driver_launch::complete_hosted_critical_child_start(
                    claim,
                    nt_status::NtStatus::DEVICE_BUSY.raw() as u32,
                );
                progress += 1;
                continue;
            }
            nt_pnp_manager::ExistingDeviceStartDisposition::NoSuchDevice => {
                driver_launch::complete_hosted_critical_child_start(claim, 0xC000_000E);
                progress += 1;
                continue;
            }
            nt_pnp_manager::ExistingDeviceStartDisposition::RequiresAction => {}
        }
        progress += 1;
        let spec = match live_config_existing_device_launch_spec(instance, SERVICE_DEMAND_START) {
            Ok(spec) if spec.class == driver_launch::DriverClass::Device && spec.devnodes.len() == 1 => spec,
            Ok(_) => {
                driver_launch::complete_hosted_critical_child_start(
                    claim,
                    nt_status::NtStatus::INVALID_PARAMETER.raw() as u32,
                );
                continue;
            }
            Err(status) => {
                driver_launch::complete_hosted_critical_child_start(claim, status as u32);
                continue;
            }
        };
        let reservation = match nt_handler.pending_driver_starts.reserve() {
            Ok(reservation) => reservation,
            Err(_) => {
                driver_launch::complete_hosted_critical_child_start(
                    claim,
                    nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw() as u32,
                );
                continue;
            }
        };
        let context = match driver_launch::loaded_driver_pnp_start_context(&spec.driver_object_path) {
            Some(context) => Ok(context),
            None if driver_launch::driver_id_by_name(&spec.driver_object_path).is_some() => {
                Err(nt_status::NtStatus::DEVICE_NOT_READY)
            }
            None => match exec_fs() {
                Some(fs) => driver_launch::load_driver(
                    &fs,
                    &spec.image_path,
                    spec.class,
                    &spec.driver_object_path,
                    initial_system_driver_caller(),
                )
                .and_then(|_| {
                    driver_launch::loaded_driver_pnp_start_context(&spec.driver_object_path)
                        .ok_or(nt_status::NtStatus::DEVICE_NOT_READY)
                }),
                None => Err(nt_status::NtStatus::OBJECT_NAME_NOT_FOUND),
            },
        };
        let (driver_id, ready_for_pnp) = match context {
            Ok(context) => context,
            Err(status) => {
                nt_handler.pending_driver_starts.cancel(reservation)
                    .expect("failed critical driver load lost its START reservation");
                driver_launch::complete_hosted_critical_child_start(claim, status.raw() as u32);
                continue;
            }
        };
        if !ready_for_pnp {
            nt_handler.pending_driver_starts.cancel(reservation)
                .expect("non-PnP critical driver lost its START reservation");
            driver_launch::complete_hosted_critical_child_start(
                claim,
                nt_status::NtStatus::DEVICE_NOT_READY.raw() as u32,
            );
            continue;
        }
        let mut batch = OwnedHostedPnpStartBatch::new_for_driver(
            driver_id,
            ready_for_pnp,
            spec,
            HostedPnpStartOptions::demand_start(),
        );
        match batch.drive() {
            OwnedHostedPnpStartProgress::Complete(result) => {
                nt_handler.pending_driver_starts.cancel(reservation)
                    .expect("completed critical START lost its continuation reservation");
                let status = result.map(|_| 0).unwrap_or_else(|failure| failure.status.raw() as u32);
                driver_launch::complete_hosted_critical_child_start(claim, status);
            }
            OwnedHostedPnpStartProgress::AwaitingCompletion => {
                nt_handler.pending_driver_starts.publish(
                    reservation,
                    PendingDriverStart {
                        batch,
                        reservation,
                        bootstrap_predecessors: alloc::vec::Vec::new(),
                        owner: PendingDriverStartOwner::CriticalChild { claim: Some(claim) },
                        observed_wait_stage: None,
                    },
                ).expect("pending critical START rejected its pre-reserved continuation");
            }
            OwnedHostedPnpStartProgress::OwnershipLost(_) => {
                driver_launch::quarantine_hosted_critical_child_start(claim);
                nt_handler.pending_driver_starts.publish(
                    reservation,
                    PendingDriverStart {
                        batch,
                        reservation,
                        bootstrap_predecessors: alloc::vec::Vec::new(),
                        owner: PendingDriverStartOwner::CriticalChild { claim: None },
                        observed_wait_stage: None,
                    },
                ).expect("uncertain critical START lost its retained continuation");
            }
        }
    }
    progress
}

/// An exact native settlement may resolve a mounted backend after its first service pass.
/// Admit one follow-up backend pass while all queue and provider borrows are released.
fn service_mounted_native_blocks_and_redrive_backends() -> u64 {
    let native_blocks = driver_launch::service_mounted_native_blocks() as u64;
    if native_blocks == 0 { return 0; }
    native_blocks.saturating_add(driver_launch::service_pending_file_backends() as u64)
}

/// Advance hosted I/O, driver, File, and LPC owners after the current syscall.
/// Keep the original ordering and retry-flag claim.
unsafe fn redrive_global_post_syscall_work(nt_handler: &mut ExecNtHandler) {
    let _ = driver_launch::pump_hosted_file_lifecycle();
    let hosted_io_progress = pump_hosted_io_and_redrive_driver_starts(
        driver_launch::drain_hosted_driver_dpcs(),
        nt_handler,
    );
    if hosted_io_progress != 0
        || FILE_IO_DELIVERY_RETRY_PENDING.swap(false, Ordering::AcqRel)
    {
        let _ = pending_file_io_redrive_all(nt_handler);
        let _ = file_cleanup_redrive_all(nt_handler);
        let _ = driver_launch::pump_hosted_file_lifecycle();
    }
    if nt_handler.pipe_endpoint_progress || hosted_io_progress != 0 {
        let _ = pending_file_io_redrive_all(nt_handler);
    }
    // Cancellation drains are ordered after the original IRP owners. A waiter becomes
    // runnable only once generic/LISTEN publication has ACKed and removed every exact
    // manager IRP for its File and requestor thread.
    let _ = file_irp_drain_redrive_all(nt_handler);
    if nt_handler.lpc_endpoint_progress {
        let _ = lpc_endpoint_redrive_all(nt_handler);
    }
    let _ = lpc_connect_completion_drain(nt_handler);
}

// Callers execute DPCs before borrowing the handler and pass only the completed work count.
unsafe fn pump_hosted_io_and_redrive_driver_starts(
    activated: u64,
    nt_handler: &mut ExecNtHandler,
) -> u64 {
    let retired = driver_launch::drain_hosted_file_retirements();
    let video_retired = crate::video_device::drain_video_file_retirements();
    let serviced = driver_launch::service_pending_file_backends() as u64;
    let native_blocks = service_mounted_native_blocks_and_redrive_backends();
    let pumped = driver_launch::pump_hosted_io_completions() as u64;
    if crate::config_manager_take_device_action_wake() {
        nt_handler.pnp_signal_pending_action();
    }
    let mut progress = activated
        .saturating_add(retired)
        .saturating_add(video_retired)
        .saturating_add(serviced)
        .saturating_add(native_blocks)
        .saturating_add(pumped)
        .saturating_add(pending_driver_start_redrive_all(nt_handler))
        .saturating_add(start_committed_critical_children(nt_handler))
        .saturating_add(pending_pnp_operation_redrive_all(nt_handler));
    // Deferred bus relations can load another boot-start driver after the initial plan loop.
    // Dispatch boot callbacks only at a turn with no relation or START admission in flight;
    // keep the boot phase open so a later exact registration is still owned and dispatched.
    if !hosted_pnp_start::hosted_start_batch_drive_active()
        && !driver_launch::hosted_bus_relation_pending()
        && !driver_launch::hosted_critical_child_start_pending()
        && nt_handler.pending_driver_starts.occupied_slots().next().is_none()
        && nt_handler.pending_pnp_operations.occupied_slots().next().is_none()
    {
        progress = progress.saturating_add(
            driver_launch::run_pending_boot_callbacks()
                .expect("boot driver reinitialization lost its exact callback terminal") as u64,
        );
        progress = progress.saturating_add(
            driver_launch::run_pending_ordinary_callbacks()
                .expect("driver reinitialization lost its exact callback terminal") as u64,
        );
    }
    if progress != 0 {
        FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
    }
    rearm_requested_mounted_native_timer(nt_handler);
    progress
}

fn pending_driver_start_redrive_needed(nt_handler: &ExecNtHandler) -> bool {
    let driver_start = nt_handler
        .pending_driver_starts
        .occupied_slots()
        .any(|slot| {
            nt_handler
                .pending_driver_starts
                .get(slot)
                .is_some_and(|pending| pending.batch.needs_completion_redrive())
        });
    driver_start
        || nt_handler
            .pending_pnp_operations
            .occupied_slots()
            .any(|slot| {
                nt_handler
                    .pending_pnp_operations
                    .get(slot)
                    .is_some_and(|pending| pending.operation.needs_completion_redrive())
            })
}

fn pending_driver_start_reports_snapshot(nt_handler: &ExecNtHandler) -> BootDriverStartReports {
    let mut reports = nt_handler.boot_driver_start_reports;
    for slot in nt_handler.pending_driver_starts.occupied_slots() {
        let Some(pending) = nt_handler.pending_driver_starts.get(slot) else {
            continue;
        };
        let PendingDriverStartOwner::Boot {
            target,
            report_published,
        } = &pending.owner
        else {
            continue;
        };
        if !*report_published {
            reports.merge(*target, pending.batch.report());
        }
    }
    reports
}

pub(crate) unsafe fn pending_driver_start_abandon_thread(
    nt_handler: &mut ExecNtHandler,
    tid: u64,
) -> u64 {
    let mut abandoned = 0u64;
    for slot in 0..nt_handler.pending_driver_starts.slot_count() {
        let matches = nt_handler
            .pending_driver_starts
            .get(slot)
            .is_some_and(|pending| {
                matches!(
                    &pending.owner,
                    PendingDriverStartOwner::User {
                        request: Some(_),
                        reply: Some(reply),
                    } if reply.tid == tid && reply.reply_cap != 0
                )
            });
        if !matches {
            continue;
        }
        let (request, reply) = {
            let pending = nt_handler
                .pending_driver_starts
                .get_mut(slot)
                .expect("matched StartDevice owner disappeared during abandonment");
            let PendingDriverStartOwner::User { request, reply } = &mut pending.owner else {
                unreachable!()
            };
            (
                request.expect("parked StartDevice reply lost its exact request"),
                reply
                    .take()
                    .expect("user START reply disappeared during abandonment"),
            )
        };
        nt_handler
            .pnp_start_device_calls
            .abandon(request)
            .expect("abandoned StartDevice reply did not match its pending request");
        let cap = reply.reply_cap;
        let cancelled = cancel_parked_reply_transport(cap);
        if cancelled {
            release_reply_pool_cap(cap);
        }
        thread_wait_state_clear_badge(reply.badge);
        abandoned += 1;
    }
    for slot in 0..nt_handler.pending_pnp_operations.slot_count() {
        let matches = nt_handler
            .pending_pnp_operations
            .get(slot)
            .and_then(|pending| pending.reply.as_ref())
            .is_some_and(|reply| reply.tid == tid && reply.reply_cap != 0);
        if !matches {
            continue;
        }
        let reply = nt_handler
            .pending_pnp_operations
            .get_mut(slot)
            .expect("PnP operation owner disappeared during abandonment")
            .reply
            .take()
            .expect("PnP operation reply disappeared during abandonment");
        let cap = reply.reply_cap;
        let cancelled = cancel_parked_reply_transport(cap);
        if cancelled {
            release_reply_pool_cap(cap);
        }
        thread_wait_state_clear_badge(reply.badge);
        abandoned = abandoned.saturating_add(1);
    }
    abandoned
}

pub(crate) fn print_pending_file_route(route: nt_io_manager::PendingFileRoute) {
    use nt_io_manager::{LocalFileObject, PendingFileRoute};
    match route {
        PendingFileRoute::Hosted(id) => {
            print_str(b"hosted/");
            print_u64(id);
        }
        PendingFileRoute::Local(LocalFileObject::ReadonlyFile(id)) => {
            print_str(b"readonly-file/");
            print_u64(u64::from(id));
        }
        PendingFileRoute::Local(LocalFileObject::ReadonlyDirectory(id)) => {
            print_str(b"readonly-directory/");
            print_u64(u64::from(id));
        }
        PendingFileRoute::Local(LocalFileObject::Overlay(id)) => {
            print_str(b"overlay/");
            print_u64(id);
        }
    }
}

unsafe fn pending_file_io_transfer(
    mut pending: nt_io_manager::PendingFileIo,
    wait_for_completion: bool,
    reservation: nt_io_manager::PendingFileIoReservation,
    native_call_transport: bool,
    resume_ip: u64,
    sp: u64,
    flags: u64,
) {
    fn commit_error_code(error: nt_io_manager::PendingFileIoParkError) -> u64 {
        match error {
            nt_io_manager::PendingFileIoParkError::StaleReservation => 1,
            nt_io_manager::PendingFileIoParkError::OccupiedReservation => 2,
            nt_io_manager::PendingFileIoParkError::InvalidRecord => 3,
            nt_io_manager::PendingFileIoParkError::DuplicateIrp => 4,
        }
    }

    unsafe fn commit_or_panic(
        table: &mut nt_io_manager::PendingFileIoTable,
        reservation: nt_io_manager::PendingFileIoReservation,
        pending: nt_io_manager::PendingFileIo,
        synchronous: bool,
    ) {
        let error = match table.park_reserved(reservation, pending) {
            Ok(_) => {
                crate::pending_file_caller::publish(reservation, pending);
                return;
            }
            Err(error) => error,
        };
        print_str(b"[pending-file-owner] commit rejected error/file/irp/major/pi/tid/badge/sync/reply=");
        print_u64(commit_error_code(error));
        print_str(b"/");
        print_pending_file_route(pending.route);
        print_str(b"/");
        print_u64(pending.irp_id);
        print_str(b"/");
        print_u64(pending.major as u64);
        print_str(b"/");
        print_u64(pending.pi as u64);
        print_str(b"/");
        print_u64(pending.tid);
        print_str(b"/");
        print_u64(pending.badge);
        print_str(b"/");
        print_u64(synchronous as u64);
        print_str(b"/");
        print_u64(pending.reply_required as u64);
        print_str(b" output/iosb/apc/iocp/event=0x");
        print_hex((pending.output_va >> 32) as u32);
        print_hex(pending.output_va as u32);
        print_str(b"/0x");
        print_hex((pending.iosb_va >> 32) as u32);
        print_hex(pending.iosb_va as u32);
        print_str(b"/0x");
        print_hex((pending.apc_routine >> 32) as u32);
        print_hex(pending.apc_routine as u32);
        print_str(b"/");
        print_u64(pending.publish_iocp as u64);
        print_str(b"/");
        print_u64(pending.event_obj_idx);
        print_str(b"\n");
        panic!("pre-dispatch pending File reservation rejected its exact IRP");
    }

    // A preparked Reply belongs to the original native caller, not the timer or ingress
    // event that happens to redrive its File CREATE.
    if pending.reply_cap == 0 {
        pending.native_call_transport = native_call_transport;
    }
    if !wait_for_completion {
        assert_eq!(pending.reply_cap, 0, "nonwaiting File transfer retained a parked Reply");
        let table = &mut *core::ptr::addr_of_mut!(PENDING_FILE_IO);
        return commit_or_panic(table, reservation, pending, false);
    }
    if pending.reply_cap != 0 {
        // The original caller already owns this saved Reply. A redriven CREATE must transfer
        // that exact capability to its reserved File owner, leaving the current ingress Reply
        // untouched. Validation also rejects an alias of the active main slot.
        parked_reply::validate_saved(pending.reply_cap)
            .expect("pending File transfer lost its preparked Reply");
        assert!(pending.reply_required);
        pending.resume_ip = resume_ip;
        pending.resume_sp = sp;
        pending.resume_flags = flags;
        let table = &mut *core::ptr::addr_of_mut!(PENDING_FILE_IO);
        commit_or_panic(table, reservation, pending, true);
        return;
    }
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(
        stolen, 0,
        "pending File reply cap disappeared after preflight"
    );
    let reply_park = root_reply_park::RootReplyPark::prepare()
        .expect("pending File reply-pool claim disappeared after preflight");
    pending.reply_cap = stolen;
    pending.reply_required = true;
    pending.resume_ip = resume_ip;
    pending.resume_sp = sp;
    pending.resume_flags = flags;
    let table = &mut *core::ptr::addr_of_mut!(PENDING_FILE_IO);
    commit_or_panic(table, reservation, pending, true);
    reply_park.commit();
}

unsafe fn file_irp_drain_transfer(
    mut pending: nt_io_manager::PendingFileIrpDrain,
    reservation: nt_io_manager::PendingFileIrpDrainReservation,
) {
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(
        stolen, 0,
        "File IRP drain reply cap disappeared after preflight"
    );
    let reply_park = root_reply_park::RootReplyPark::prepare()
        .expect("File IRP drain reply-pool claim disappeared after preflight");
    pending.reply_cap = stolen;
    (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IRP_DRAINS))
        .park_reserved(reservation, pending)
        .expect("reserved File IRP drain owner rejected its exact continuation");
    reply_park.commit();
}

/// Transfer the final-handle `NtClose` reply only when its canonical File lifecycle still exists.
/// Inline CLEANUP/CLOSE completion retires the policy before this tail and therefore needs no park.
unsafe fn file_cleanup_wait_transfer(
    nt_handler: &mut ExecNtHandler,
    mut pending: nt_io_manager::PendingFileCleanupWait,
    reservation: nt_io_manager::PendingFileCleanupWaitReservation,
) -> bool {
    let table = &mut *core::ptr::addr_of_mut!(PENDING_FILE_CLEANUP_WAITS);
    if nt_handler.file_completion.io_mode(pending.file_id).is_err() {
        assert!(
            table.cancel_reservation(reservation),
            "inline File cleanup left a stale continuation reservation"
        );
        return false;
    }
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(
        stolen, 0,
        "File cleanup reply cap disappeared after preflight"
    );
    let reply_park = root_reply_park::RootReplyPark::prepare()
        .expect("File cleanup reply-pool claim disappeared after preflight");
    pending.reply_cap = stolen;
    table
        .park_reserved(reservation, pending)
        .expect("reserved File cleanup owner rejected its exact continuation");
    reply_park.commit();
    true
}

unsafe fn pending_set_file_name_caller_is_live(
    handler: &ExecNtHandler,
    identity: nt_io_manager::PendingFileIoIdentity,
    pending: nt_io_manager::PendingFileIo,
) -> bool {
    (&*core::ptr::addr_of!(PENDING_FILE_IO))
        .get_exact(identity)
        .is_some_and(|live| live.irp_id == pending.irp_id && !live.consumer_abandoned)
        && crate::pending_file_caller::caller(identity, pending)
            .is_some_and(|caller| handler.set_file_name_caller_is_current(caller))
}

unsafe fn pending_file_native_caller(
    handler: &ExecNtHandler,
    identity: nt_io_manager::PendingFileIoIdentity,
    pending: nt_io_manager::PendingFileIo,
) -> Result<nt_process::native_handle::NativeHandleCaller, u32> {
    if !pending_set_file_name_caller_is_live(handler, identity, pending) {
        return Err(nt_status::NtStatus::CANCELLED.raw() as u32);
    }
    let caller = crate::pending_file_caller::caller(identity, pending)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    handler.pm.capture_native_handle_caller(caller.thread(), nt_types::AccessMode::KernelMode)
}

static NEXT_FILE_MODE_INPUT_PAGE_TOKEN: AtomicU64 = AtomicU64::new(1);

/// A routed page worker returns only to the exact FileMode input owner which admitted it.
/// The original Reply and File Busy remain in that row until normal terminal delivery.
pub(crate) unsafe fn file_mode_input_page_completed(
    identity: nt_io_manager::PendingFileIoIdentity, irp_id: u64, token: u64,
    pi: usize, page: u64, status: u32,
) -> bool {
    let table = &mut *core::ptr::addr_of_mut!(PENDING_FILE_IO);
    let exact = table.get_exact(identity).is_some_and(|pending| {
        pending.irp_id == irp_id && pending.pi as usize == pi
            && matches!(pending.operation,
                nt_io_manager::PendingFileIoOperation::OwnedModeInputCapture(input)
                if input.pending_token == token && input.pending_page == page)
    });
    if !exact || table.complete_mode_input_page_exact(identity, irp_id, page, token, status).is_none() {
        return false;
    }
    FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
    true
}

/// Return true only after input capture becomes terminal or mode precommit. The row was parked
/// before this function can run; no routed source work is submitted by the native syscall entry.
unsafe fn redrive_file_mode_input(
    handler: &mut ExecNtHandler,
    identity: nt_io_manager::PendingFileIoIdentity,
    pending: nt_io_manager::PendingFileIo,
) -> bool {
    use nt_io_manager::PendingFileIoOperation::OwnedModeInputCapture;
    let OwnedModeInputCapture(input) = pending.operation else { return true; };
    macro_rules! table { () => { &mut *core::ptr::addr_of_mut!(PENDING_FILE_IO) }; }
    if input.pending_token != 0 { return false; }
    if pending.consumer_abandoned || pending.reply_cap == 0 {
        return table!().fail_mode_input_exact(identity, pending.irp_id, nt_fs::STATUS_CANCELLED).is_some();
    }
    let pi = pending.pi as usize;
    let current = handler.capture_thread_process_identity(pi, pending.tid);
    let caller_live = crate::pending_file_caller::caller(identity, pending)
        .is_some_and(|caller| handler.validate_provider_logical_caller(caller));
    if current.is_none() || !caller_live {
        return table!().fail_mode_input_exact(identity, pending.irp_id, nt_fs::STATUS_INVALID_HANDLE).is_some();
    }
    let step = with_pagein_caller_target_context(
        handler, pi, pi, pending.tid, pending.badge,
        pending.resume_ip, pending.resume_sp, pending.resume_flags,
        pending.native_call_transport, 0,
        |handler| {
            if !input.signal_reset {
                let result = match pending.route {
                    nt_io_manager::PendingFileRoute::Hosted(file_id) =>
                        handler.file_completion.set_signaled(file_id, false),
                    nt_io_manager::PendingFileRoute::Local(
                        nt_io_manager::LocalFileObject::Overlay(file_object)) =>
                        crate::writable_fs::set_file_signaled(file_object, false),
                    _ => Err(nt_fs::STATUS_INVALID_HANDLE),
                };
                match result {
                    Ok(()) => {
                        if table!().mark_mode_input_signal_reset_exact(identity, pending.irp_id).is_none() {
                            return false;
                        }
                        FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                        return false;
                    }
                    Err(status) => return table!().fail_mode_input_exact(identity, pending.irp_id, status).is_some(),
                }
            }
            let Some(end) = input.input_va.checked_add(input.length as u64) else {
                return table!().fail_mode_input_exact(identity, pending.irp_id,
                    nt_address_space::STATUS_ACCESS_VIOLATION).is_some();
            };
            if input.next_page >= end {
                let captured = handler.capture_file_mode_resident_input(input.input_va, input.length);
                return match captured {
                    Ok(requested_mode) => table!().finish_mode_input_capture_exact(
                        identity, pending.irp_id, requested_mode).is_some(),
                    Err(status) => table!().fail_mode_input_exact(identity, pending.irp_id, status).is_some(),
                };
            }
            let page = input.next_page;
            match handler.copy_page_admission(pi, page, nt_address_space::FaultAccess::Read) {
                Ok(exec_handler::CopyPageAdmission::Resident) => {
                    if table!().complete_mode_input_page_exact(identity, pending.irp_id, page, 0, 0).is_none() {
                        return false;
                    }
                    FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                    false
                }
                Err(status) => table!().fail_mode_input_exact(identity, pending.irp_id, status).is_some(),
                Ok(exec_handler::CopyPageAdmission::NeedsRoutedPageIn) => {
                    let Some(token) = NEXT_FILE_MODE_INPUT_PAGE_TOKEN.try_update(
                        Ordering::AcqRel, Ordering::Acquire, |value| value.checked_add(1)
                    ).ok().filter(|token| *token != 0) else {
                        return table!().fail_mode_input_exact(identity, pending.irp_id,
                            nt_fs::STATUS_INSUFFICIENT_RESOURCES).is_some();
                    };
                    if table!().begin_mode_input_page_exact(identity, pending.irp_id, page, token).is_none() {
                        return false;
                    }
                    let info = handler.query_memory_basic_information(pi, page);
                    let result = match info.map(|info| info.type_) {
                        Ok(nt_address_space::MEM_MAPPED) =>
                            crate::section_pagein_work::submit_for_file_mode_input(
                                handler, pi, page, pending.reply_cap, identity, pending.irp_id, token)
                                .map(Some),
                        Ok(nt_address_space::MEM_IMAGE) =>
                            crate::native_image_pagein_work::submit_for_file_mode_input(
                                handler, pi, page, pending.reply_cap, identity, pending.irp_id, token),
                        Ok(_) => Err(nt_address_space::STATUS_CONFLICTING_ADDRESSES),
                        Err(status) => Err(status),
                    };
                    match result {
                        Ok(Some(_)) => false,
                        Ok(None) => {
                            if table!().abort_unentered_mode_input_page_exact(identity, pending.irp_id, page, token).is_some() {
                                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                            }
                            false
                        }
                        Err(status) => {
                            if table!().abort_unentered_mode_input_page_exact(identity, pending.irp_id, page, token).is_none() {
                                return false;
                            }
                            table!().fail_mode_input_exact(identity, pending.irp_id, status).is_some()
                        }
                    }
                }
            }
        });
    step.unwrap_or_else(|| table!().fail_mode_input_exact(identity, pending.irp_id,
        nt_fs::STATUS_INVALID_HANDLE).is_some())
}

/// Publish terminal results for general pending File IRPs in NT completion order. The backend
/// completion remains retained until every required surface and synchronous reply is visible.
unsafe fn pending_file_io_redrive_all(nt_handler: &mut ExecNtHandler) -> u64 {
    let (delivered, settled) = pending_file_io_redrive_pass(nt_handler, false);
    if settled == 0 {
        return delivered;
    }
    // Complete newly settled Busy owners before sleeping on the fault endpoint. This bounded
    // pass cannot create more release/wake work or require an unrelated syscall to deliver replies.
    delivered + pending_file_io_redrive_pass(nt_handler, true).0
}

unsafe fn pending_file_io_redrive_pass(
    nt_handler: &mut ExecNtHandler,
    finish_settled_busy_only: bool,
) -> (u64, usize) {
    if !finish_settled_busy_only {
        nt_handler.redrive_set_file_name_retirement();
        synchronous_file_retry::redrive_retirement(nt_handler);
        synchronous_file_cancellation::redrive(nt_handler);
        crate::pending_file_apc::redrive(nt_handler);
        nt_handler.publish_local_byte_lock_completions();
    }
    let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
    let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
    let saved_pi = nt_handler.pi;
    let saved_tid = nt_handler.current_tid;
    let saved_badge = nt_handler.current_badge;
    let saved_resume_ip = nt_handler.current_resume_ip;
    let saved_sp = nt_handler.current_sp;
    let saved_flags = nt_handler.current_flags;
    let saved_native_call_transport = nt_handler.current_native_call_transport;
    let saved_ctx = nt_handler.loop_ctx;
    macro_rules! restore_file_io_mirrors {
        () => {{
            crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.current_badge = saved_badge;
            nt_handler.current_resume_ip = saved_resume_ip;
            nt_handler.current_sp = saved_sp;
            nt_handler.current_flags = saved_flags;
            nt_handler.current_native_call_transport = saved_native_call_transport;
            nt_handler.loop_ctx = saved_ctx;
        }};
    }

    let mut snapshot: alloc::vec::Vec<_> = (&*core::ptr::addr_of!(PENDING_FILE_IO))
        .drain_exact()
        .filter(|(_, pending)| !finish_settled_busy_only
            || pending.busy.is_some_and(|busy| busy.is_settled()))
        .collect();
    // Publish provider CREATE metadata before transfers whose completion depends on that endpoint
    // transition. In particular, a client pipe CREATE records/consumes its exact server-instance
    // readiness before the accepted LISTEN exposes its completion event.
    snapshot.sort_by_key(|(_, pending)| {
        matches!(
            pending.operation,
            nt_io_manager::PendingFileIoOperation::Transfer
        )
    });
    let mut delivered = 0u64;
    for (identity, mut pending) in snapshot {
        let slot = identity.slot();
        let Some(live) = (&*core::ptr::addr_of!(PENDING_FILE_IO))
            .get_exact(identity).filter(|live| live.irp_id == pending.irp_id)
        else { continue; };
        pending = live;
        if matches!(pending.operation,
            nt_io_manager::PendingFileIoOperation::OwnedModeInputCapture(_))
        {
            if !redrive_file_mode_input(nt_handler, identity, pending) {
                continue;
            }
            let Some(live) = (&*core::ptr::addr_of!(PENDING_FILE_IO))
                .get_exact(identity).filter(|live| live.irp_id == pending.irp_id)
            else { continue; };
            pending = live;
        }
        if let nt_io_manager::PendingFileIoOperation::OwnedModePrecommit(operation) = pending.operation {
            // The original input, File reference, Busy and Reply already belong to this row.
            // Preparation is no-effect on Busy; never re-enter the syscall or read user input.
            let result = if pending.consumer_abandoned {
                Err(driver_launch::FileModePreparationError::Status(nt_fs::STATUS_CANCELLED))
            } else {
                nt_handler.commit_owned_file_mode_request(pending.route, operation.requested_mode, pending.tid)
            };
            let status = match result {
                Err(driver_launch::FileModePreparationError::Busy) => {
                    FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                    continue;
                }
                Err(driver_launch::FileModePreparationError::Status(status)) => status,
                Ok(()) => nt_fs::STATUS_SUCCESS,
            };
            (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                .commit_owned_mode_exact(identity, pending.irp_id, status)
                .expect("non-reentrant mode commit lost its retained precommit owner");
            // The transition is recorded before any fallible delivery operation.
            pending = (&*core::ptr::addr_of!(PENDING_FILE_IO)).get_exact(identity)
                .expect("committed mode lost its delivery row");
        }
        let Ok(delivery) = pending_file_delivery::Delivery::begin(identity, pending.irp_id)
        else { continue; };
        let hosted_file_id = pending.route.hosted_file_id();
        let local_file_object = pending.route.local_file_object();
        let set_file_name_id = match pending.operation {
            nt_io_manager::PendingFileIoOperation::SetFileName(operation) => {
                nt_io_manager::PendingSetFileNameId::from_raw(operation.transaction_id)
            }
            _ => None,
        };
        let transaction_terminal = set_file_name_id.and_then(|id| {
            (&*core::ptr::addr_of!(PENDING_SET_FILE_NAMES))
                .get(id)
                .and_then(|transaction| transaction.terminal_result())
        });
        let attribute_inline_terminal = match pending.operation {
            nt_io_manager::PendingFileIoOperation::AttributeQuery(operation) => operation.inline_terminal,
            _ => None,
        };
        // Once local output is committed, the I/O owner retains the terminal result even after
        // the FSD acknowledges its bytes. Later surface/reference retries must not re-query it.
        let local_terminal = if let Some(terminal) = pending.owned_terminal_result() {
            Some(terminal)
        } else if let nt_io_manager::PendingFileIoOperation::LocalDirectoryNotify(operation) = pending.operation {
            if pending.consumer_abandoned
                && nt_handler.cancel_local_directory_notify(
                    local_file_object.expect("local notify lost its File route"), operation.notify_id,
                ).is_err()
            {
                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                continue;
            }
            match nt_handler.local_directory_notify_terminal(
                local_file_object.expect("local notify lost its File route"), operation.notify_id, pending.irp_id,
            ) {
                Ok(terminal) => terminal.map(|(status, information)| (status, u64::from(information))),
                Err(_) => {
                    FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                    continue;
                }
            }
        } else {
            None
        };
        let mut completed = if pending.is_local()
            || matches!(pending.operation, nt_io_manager::PendingFileIoOperation::OwnedInline(_))
        {
            None
        } else {
            driver_launch::completed_irp_exact(pending.irp_id)
        };
        // Provider completion lookup may dispatch nested work and retire/reuse this slot.
        if !(&*core::ptr::addr_of!(PENDING_FILE_IO))
            .get_exact(identity).is_some_and(|live| live.irp_id == pending.irp_id)
        {
            continue;
        }
        if completed.is_none() && transaction_terminal.is_none()
            && attribute_inline_terminal.is_none() && local_terminal.is_none() {
            if !pending.is_local() && driver_launch::completed_irp_copy_requires_retry(pending.irp_id) {
                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
            }
            continue;
        }
        let is_pipe_transceive = !pending.is_local()
            && pending.major == nt_io_abi::major::IRP_MJ_FILE_SYSTEM_CONTROL
            && pending.control_code == crate::exec_handler::FSCTL_PIPE_TRANSCEIVE;
        if let Some(completed) = completed {
            if !(&*core::ptr::addr_of!(PENDING_FILE_IO)).matches_completion_exact(
                slot,
                pending.irp_id,
                completed.file_id,
                completed.requestor_tid,
                completed.major,
            ) {
                panic!("pending File completion identity mismatch");
            }
            if pending.major == nt_io_abi::major::IRP_MJ_WRITE {
                if let Some(file_id) = hosted_file_id {
                    let _ = nt_handler.complete_install_pipe_write(
                        pending.pi as usize, file_id, pending.irp_id,
                        completed.status, completed.information,
                    );
                    nt_handler.complete_rpc_op6_client_write(
                        pending.pi as usize, file_id, pending.irp_id,
                        completed.status, completed.information,
                    );
                }
            } else if is_pipe_transceive {
                if let Some(file_id) = hosted_file_id {
                    nt_handler.complete_rpc_op6_client_write(
                        pending.pi as usize, file_id, pending.irp_id,
                        completed.status, completed.information,
                    );
                }
            }
            pending_pipe_read_trace::terminal_observed(identity, pending.irp_id, completed.status);
            mounted_read_lifetime_trace::terminal_observed(identity, pending.irp_id,
                completed.status, completed.information);
            mounted_installer_file_trace::terminal(identity, pending.irp_id, completed.status);
            if pending.major == nt_io_abi::major::IRP_MJ_CREATE {
                mounted_create_owner_trace::terminal_exact(identity, pending.irp_id,
                    completed.file_id, completed.status);
            }
        }
        let is_pipe_listen = !pending.is_local()
            && pending.major == nt_io_abi::major::IRP_MJ_FILE_SYSTEM_CONTROL
            && pending.control_code == crate::exec_handler::FSCTL_PIPE_LISTEN;
        let pipe_listen_server_context = is_pipe_listen
            .then(|| hosted_file_id.and_then(driver_launch::hosted_file_route).map(|(_, context)| context))
            .flatten();
        if hosted_file_id.is_some_and(|id| nt_handler.hosted_file_is_named_pipe(id))
            && (matches!(
                pending.major,
                nt_io_abi::major::IRP_MJ_READ | nt_io_abi::major::IRP_MJ_WRITE
            ) || is_pipe_transceive)
        {
            nt_handler.pipe_endpoint_progress = true;
        }

        let Some(live) = (&*core::ptr::addr_of!(PENDING_FILE_IO))
            .get_exact(identity).filter(|live| live.irp_id == pending.irp_id)
        else { continue; };
        pending = live;
        let Some((_, _, _, _, scratch_base)) =
            mirror_ctx_for(nt_handler, pending.badge, pending.pi as usize, pending.tid)
        else {
            // Terminal provider output and the parked Reply remain owned by this exact row.
            // Do not acknowledge or publish either into a retired caller's address space.
            continue;
        };
        crate::executor::local().client_pi.store(pending.pi as u64, Ordering::Relaxed);
        crate::executor::local().scratch_base.store(scratch_base, Ordering::Relaxed);
        nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(pending.pi as usize));
        nt_handler.pi = pending.pi as usize;
        nt_handler.current_tid = pending.tid;
        nt_handler.current_badge = pending.badge;
        nt_handler.current_resume_ip = pending.resume_ip;
        nt_handler.current_sp = pending.resume_sp;
        nt_handler.current_flags = pending.resume_flags;
        nt_handler.current_native_call_transport = pending.native_call_transport;

        let mut delivery_state = pending.delivery_state;
        let mut terminal_status = transaction_terminal
            .map(|result| result.0)
            .or_else(|| attribute_inline_terminal.map(|result| result.0))
            .or_else(|| local_terminal.map(|result| result.0))
            .or_else(|| completed.map(|completion| completion.status))
            .expect("pending File owner has no terminal status");
        let mut terminal_information = transaction_terminal
            .map(|result| result.1)
            .or_else(|| attribute_inline_terminal.map(|result| result.1))
            .or_else(|| local_terminal.map(|result| result.1))
            .or_else(|| completed.map(|completion| completion.information))
            .expect("pending File owner has no terminal information");
        if let Some(file_id) = hosted_file_id {
            if matches!(pending.major, nt_io_abi::major::IRP_MJ_READ | nt_io_abi::major::IRP_MJ_WRITE) {
                let fs_context = driver_launch::hosted_file_route(file_id)
                    .map_or(0, |(_, context)| context);
                crate::exec_handler::trace_setup_scm_pipe_transition(
                    b"terminal-seen", pending.pi as usize, pending.badge, pending.tid,
                    None, file_id, fs_context, pending.irp_id, pending.major,
                    terminal_status, terminal_information, pending.delivery_state,
                    pending.reply_required,
                );
            }
        }
        let mut backend_ack_required = completed.is_some();
        if let nt_io_manager::PendingFileIoOperation::AttributeQuery(operation) = pending.operation {
            if pending.major == nt_io_abi::major::IRP_MJ_CREATE {
                let create = completed.expect("attribute CREATE lost its exact completion");
                if driver_launch::acknowledge_completed_irp(pending.irp_id).is_err() {
                    FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                    restore_file_io_mirrors!();
                    continue;
                }
                let file_id = hosted_file_id.expect("attribute CREATE lost its File");
                if (create.status as i32) < 0 {
                    (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                        .complete_attribute_query_inline_owner_exact(identity, pending.irp_id,
                            create.status, 0)
                        .expect("attribute CREATE terminal lost owner");
                } else {
                    let mut output = [0u8; 56];
                    let length = if operation.information_class == nt_fs::FILE_BASIC_INFORMATION {
                        40usize
                    } else { 56usize };
                    let query = pending_file_native_caller(nt_handler, identity, pending)
                        .and_then(|caller| driver_launch::dispatch_hosted_file_irp_result_exact(
                            file_id, nt_io_abi::major::IRP_MJ_QUERY_INFORMATION as u64,
                            operation.information_class as u64, caller, &[],
                            &mut output[..length], 0));
                    match query {
                        Ok((status, _, Some(irp_id), _)) if status == nt_status::NtStatus::PENDING.raw() => {
                            (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                                .retarget_attribute_query_owner_exact(identity, pending.irp_id,
                                    irp_id.raw())
                                .expect("attribute query lost CREATE owner");
                            crate::exec_handler::smss_attribute_probe_trace::trace_smss_attribute_retarget(
                                pending.pi, pending.tid, file_id, pending.irp_id, irp_id.raw(),
                            );
                        }
                        result => {
                            let (status, information) = match result {
                                Ok((status, information, None, _)) if status >= 0 => {
                                    if information != length as u64 {
                                        (nt_fs::STATUS_DATA_ERROR, 0)
                                    } else if nt_handler.xas_try_write_buf(pending.output_va,
                                        &output[..length]) {
                                        (status as u32, information)
                                    } else { (0xC000_0005, 0) }
                                }
                                Ok((status, _, _, _)) => (status as u32, 0),
                                Err(status) => (status, 0),
                            };
                            (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                                .complete_attribute_query_inline_owner_exact(identity, pending.irp_id,
                                    status, information)
                                .expect("inline attribute query lost CREATE owner");
                        }
                    }
                }
                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                restore_file_io_mirrors!();
                continue;
            }
            if pending.major == nt_io_abi::major::IRP_MJ_QUERY_INFORMATION
                && (terminal_status as i32) >= 0
                && terminal_information != u64::from(pending.output_len)
            {
                terminal_status = nt_fs::STATUS_DATA_ERROR;
                terminal_information = 0;
            }
        }
        if pending.major == nt_io_abi::major::IRP_MJ_QUERY_INFORMATION {
            if let Some(transaction_id) = set_file_name_id {
                let phase = (&*core::ptr::addr_of!(PENDING_SET_FILE_NAMES))
                    .get(transaction_id)
                    .expect("set-file-name source query lost its transaction")
                    .phase();
                assert_eq!(phase, nt_io_manager::PendingSetFileNamePhase::SourceQuery);
                // A late RootDirectory lookup must not consult a reused process/thread slot.
                if (terminal_status as i32) >= 0
                    && !pending_set_file_name_caller_is_live(nt_handler, identity, pending)
                {
                    terminal_status = nt_status::NtStatus::CANCELLED.raw() as u32;
                    terminal_information = 0;
                }
                if (terminal_status as i32) >= 0 {
                    const FILE_BASIC_INFORMATION_LEN: usize = 40;
                    let mut basic = [0u8; FILE_BASIC_INFORMATION_LEN];
                    if terminal_information < FILE_BASIC_INFORMATION_LEN as u64 {
                        terminal_status = nt_fs::STATUS_INFO_LENGTH_MISMATCH;
                        terminal_information = 0;
                    } else {
                        match driver_launch::copy_completed_irp_output_exact(
                            pending.irp_id,
                            0,
                            &mut basic,
                        ) {
                            Ok(FILE_BASIC_INFORMATION_LEN) => {}
                            Ok(_) => {
                                terminal_status = nt_fs::STATUS_INFO_LENGTH_MISMATCH;
                                terminal_information = 0;
                            }
                            Err(_) => {
                                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                                restore_file_io_mirrors!();
                                continue;
                            }
                        }
                        let source_is_directory =
                            match nt_fs::parse_file_basic_information_attributes(&basic) {
                                Ok(attributes) => attributes & nt_fs::FILE_ATTRIBUTE_DIRECTORY != 0,
                                Err(status) => {
                                    terminal_status = status;
                                    terminal_information = 0;
                                    false
                                }
                            };
                        if (terminal_status as i32) >= 0 {
                            if driver_launch::acknowledge_completed_irp(pending.irp_id).is_err() {
                                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                                restore_file_io_mirrors!();
                                continue;
                            }
                            backend_ack_required = false;
                            completed = None;
                            let mut transaction =
                                (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                                    .take_for_update(transaction_id)
                                    .expect("set-file-name query lost its captured buffers");
                            let create = pending_set_file_name_caller_is_live(nt_handler, identity, pending)
                                .then(|| crate::pending_file_caller::caller(identity, pending)).flatten()
                                .ok_or(nt_status::NtStatus::CANCELLED.raw() as u32)
                                .and_then(|caller| nt_handler.open_set_file_name_target(
                                    &mut transaction, source_is_directory, caller,
                                ));
                            let target_file_id = transaction.target_file_id;
                            match create {
                                Err(status) => {
                                    assert!(transaction.complete_inline(status, 0));
                                    terminal_status = status;
                                    terminal_information = 0;
                                }
                                Ok((status, create_information, create_irp, _)) => {
                                    let create_status = status as u32;
                                    if create_status == nt_status::NtStatus::PENDING.raw() as u32 {
                                        if let Some(create_irp) = create_irp {
                                            assert!((&mut *core::ptr::addr_of_mut!(
                                                PENDING_SET_FILE_NAMES
                                            ))
                                                .restore_update(transaction_id, transaction));
                                            (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                                                .retarget_set_file_name_query_owner_exact(
                                                    identity,
                                                    pending.irp_id,
                                                    create_irp.raw(),
                                                    nt_io_abi::major::IRP_MJ_CREATE,
                                                    target_file_id,
                                                )
                                                .expect("set-file-name query owner rejected target CREATE");
                                            FILE_IO_DELIVERY_RETRY_PENDING
                                                .store(true, Ordering::Release);
                                            restore_file_io_mirrors!();
                                            continue;
                                        }
                                        terminal_status = nt_fs::STATUS_INSUFFICIENT_RESOURCES;
                                        terminal_information = 0;
                                    } else if (create_status as i32) < 0 {
                                        terminal_status = create_status;
                                        terminal_information = create_information;
                                    } else if let Err(status) = transaction.validate_target_open(create_information, || {
                                        driver_launch::owned_hosted_files_share_related_device(transaction.source_file_id, target_file_id)
                                    }) {
                                        terminal_status = status.raw() as u32;
                                        terminal_information = 0;
                                    } else {
                                        let length =
                                            u32::try_from(transaction.set_information().len());
                                        let dispatch = if !pending_set_file_name_caller_is_live(nt_handler, identity, pending) {
                                            Err(nt_status::NtStatus::CANCELLED.raw() as u32)
                                        } else { match length {
                                            Ok(length) => pending_file_native_caller(nt_handler, identity, pending).and_then(|caller| driver_launch::dispatch_hosted_file_set_information_irp_result_exact(
                                                transaction.source_file_id,
                                                caller,
                                                nt_io_manager::SetInformationParameters {
                                                    info_class: transaction.information_class,
                                                    length,
                                                    target_file: Some(nt_io_manager::FileId(
                                                        target_file_id,
                                                    )),
                                                    control: transaction.control,
                                                },
                                                transaction.set_information(),
                                            )),
                                            Err(_) => Err(nt_fs::STATUS_INVALID_PARAMETER),
                                        }};
                                        match dispatch {
                                            Ok((status, _, Some(irp_id), _))
                                                if status == nt_status::NtStatus::PENDING.raw() =>
                                            {
                                                assert!(transaction.advance_to_source_set());
                                                assert!((&mut *core::ptr::addr_of_mut!(
                                                    PENDING_SET_FILE_NAMES
                                                ))
                                                    .restore_update(transaction_id, transaction));
                                                (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                                                    .retarget_set_file_name_query_owner_exact(
                                                        identity,
                                                        pending.irp_id,
                                                        irp_id.raw(),
                                                        nt_io_abi::major::IRP_MJ_SET_INFORMATION,
                                                        target_file_id,
                                                    )
                                                    .expect("set-file-name query owner rejected source SET");
                                                FILE_IO_DELIVERY_RETRY_PENDING
                                                    .store(true, Ordering::Release);
                                                restore_file_io_mirrors!();
                                                continue;
                                            }
                                            Ok((status, _, None, _))
                                                if status == nt_status::NtStatus::PENDING.raw() =>
                                            {
                                                terminal_status =
                                                    nt_fs::STATUS_INSUFFICIENT_RESOURCES;
                                                terminal_information = 0;
                                            }
                                            Ok((status, information, _, _)) => {
                                                terminal_status = status as u32;
                                                terminal_information = information;
                                            }
                                            Err(status) => {
                                                terminal_status = status;
                                                terminal_information = 0;
                                            }
                                        }
                                    }
                                    assert!(transaction
                                        .complete_inline(terminal_status, terminal_information,));
                                }
                            }
                            assert!((&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                                .restore_update(transaction_id, transaction));
                        }
                    }
                }
            }
        }
        if pending.major == nt_io_abi::major::IRP_MJ_CREATE {
            if let Some(transaction_id) = set_file_name_id {
                let phase = (&*core::ptr::addr_of!(PENDING_SET_FILE_NAMES))
                    .get(transaction_id)
                    .expect("set-file-name transaction disappeared")
                    .phase();
                if phase == nt_io_manager::PendingSetFileNamePhase::TargetCreate
                    && (terminal_status as i32) >= 0
                {
                    let mut transaction = (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                        .take_for_update(transaction_id)
                        .expect("set-file-name target CREATE lost its captured owner");
                    if let Err(status) = transaction.validate_target_open(terminal_information, || {
                        driver_launch::owned_hosted_files_share_related_device(transaction.source_file_id, transaction.target_file_id)
                    }) {
                        assert!(transaction.complete_inline(status.raw() as u32, 0));
                        assert!((&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                            .restore_update(transaction_id, transaction));
                        terminal_status = status.raw() as u32;
                        terminal_information = 0;
                    } else {
                        if driver_launch::acknowledge_completed_irp(pending.irp_id).is_err() {
                            assert!((&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                                .restore_update(transaction_id, transaction));
                            FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                            restore_file_io_mirrors!();
                            continue;
                        }
                        backend_ack_required = false;
                        completed = None;
                        let length = match u32::try_from(transaction.set_information().len()) {
                            Ok(length) => length,
                            Err(_) => {
                                assert!(
                                    transaction.complete_inline(nt_fs::STATUS_INVALID_PARAMETER, 0)
                                );
                                terminal_status = nt_fs::STATUS_INVALID_PARAMETER;
                                terminal_information = 0;
                                0
                            }
                        };
                        if transaction.phase()
                            == nt_io_manager::PendingSetFileNamePhase::TargetCreate
                        {
                            let dispatch = if !pending_set_file_name_caller_is_live(nt_handler, identity, pending) {
                                Err(nt_status::NtStatus::CANCELLED.raw() as u32)
                            } else { pending_file_native_caller(nt_handler, identity, pending).and_then(|caller| driver_launch::dispatch_hosted_file_set_information_irp_result_exact(
                                transaction.source_file_id,
                                caller,
                                nt_io_manager::SetInformationParameters {
                                    info_class: transaction.information_class,
                                    length,
                                    target_file: Some(nt_io_manager::FileId(
                                        transaction.target_file_id,
                                    )),
                                    control: transaction.control,
                                },
                                transaction.set_information(),
                            ))};
                            match dispatch {
                                Ok((status, _information, Some(irp_id), _))
                                    if status == nt_status::NtStatus::PENDING.raw() =>
                                {
                                    assert!(transaction.advance_to_source_set());
                                    assert!((&mut *core::ptr::addr_of_mut!(
                                        PENDING_SET_FILE_NAMES
                                    ))
                                        .restore_update(transaction_id, transaction));
                                    (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                                        .retarget_set_file_name_irp_owner_exact(
                                            identity,
                                            pending.irp_id,
                                            irp_id.raw(),
                                        )
                                        .expect("set-file-name owner rejected its source SET IRP");
                                    FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                                    restore_file_io_mirrors!();
                                    continue;
                                }
                                Ok((status, _, None, _))
                                    if status == nt_status::NtStatus::PENDING.raw() =>
                                {
                                    terminal_status = nt_fs::STATUS_INSUFFICIENT_RESOURCES;
                                    terminal_information = 0;
                                }
                                Ok((status, information, _, _)) => {
                                    terminal_status = status as u32;
                                    terminal_information = information;
                                }
                                Err(status) => {
                                    terminal_status = status;
                                    terminal_information = 0;
                                }
                            }
                            assert!(
                                transaction.complete_inline(terminal_status, terminal_information)
                            );
                            assert!((&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                                .restore_update(transaction_id, transaction));
                        } else {
                            assert!((&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                                .restore_update(transaction_id, transaction));
                        }
                    }
                }
            }
        }
        if let Some(server_context) = pipe_listen_server_context {
            // Successful accept consumes the one-shot connect-before-listen edge; cancellation
            // deliberately leaves that edge intact when a client already won the race.
            if terminal_status == nt_fs::STATUS_SUCCESS
                || terminal_status == nt_io_manager::STATUS_PIPE_CONNECTED.raw() as u32
            {
                crate::pipe_server_preconnected_forget(server_context);
            }
        }
        if let nt_io_manager::PendingFileIoOperation::Create(create) = pending.operation {
            let file_id = hosted_file_id.expect("provider CREATE lost its File route");
            let completed = completed.expect("pending process-visible CREATE has no completion");
            if delivery_state & nt_io_manager::IO_DELIVERY_CREATE_COMMITTED == 0 {
                let reservation = ExecNtHandler::pending_create_reservation(create);
                let publication = if (completed.status as i32) < 0 {
                    nt_handler.cancel_hosted_create_publication(file_id, reservation);
                    HostedCreatePublication {
                        status: completed.status,
                        information: completed.information,
                        handle: 0,
                        wake_server_fid: 0,
                    }
                } else {
                    match nt_handler.publish_registered_create(
                        pending.major,
                        file_id,
                        completed.file_context.unwrap_or(0),
                        reservation,
                        create.desired_access,
                        create.provider_context,
                        completed.status,
                        completed.information,
                    ) {
                        Ok(publication) => publication,
                        Err(status) => {
                            nt_handler
                                .cancel_hosted_create_publication(file_id, reservation);
                            HostedCreatePublication {
                                status,
                                information: 0,
                                handle: 0,
                                wake_server_fid: 0,
                            }
                        }
                    }
                };
                (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                    .commit_create_exact(
                        slot,
                        pending.irp_id,
                        publication.status,
                        publication.information,
                        publication.handle,
                    )
                    .expect("pending CREATE result could not be committed");
                if (publication.status as i32) >= 0 && publication.handle != 0 {
                    match pending.major {
                        nt_io_abi::major::IRP_MJ_CREATE_NAMED_PIPE => {
                            let _ = nt_handler.observe_install_pipe_server(pending.pi as usize, file_id);
                        }
                        nt_io_abi::major::IRP_MJ_CREATE => {
                            let _ = nt_handler.observe_install_pipe_child(pending.pi as usize, file_id);
                        }
                        _ => {}
                    }
                }
                if publication.wake_server_fid != 0 {
                    nt_handler.pipe_endpoint_progress = true;
                }
                delivery_state = (&*core::ptr::addr_of!(PENDING_FILE_IO))
                    .get_exact(identity)
                    .expect("committed pending CREATE owner disappeared")
                    .delivery_state;
            }
            pending = match crate::pending_file_create::deliver(nt_handler, identity) {
                Ok(pending) => pending,
                Err(()) => {
                    restore_file_io_mirrors!();
                    continue;
                }
            };
            let nt_io_manager::PendingFileIoOperation::Create(create) = pending.operation else {
                panic!("pending CREATE changed operation kind");
            };
            terminal_status = create.status;
            terminal_information = create.information;
            delivery_state = pending.delivery_state;
        }
        if matches!(pending.operation, nt_io_manager::PendingFileIoOperation::LocalBuffered(_)) {
            pending = match nt_handler.deliver_local_buffered_output(slot, pending) {
                Ok(pending) => pending,
                Err(()) => {
                    FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                    restore_file_io_mirrors!();
                    continue;
                }
            };
            // A definitive payload fault changes Status and may suppress inline surfaces.
            // Use the refreshed owner, never the pre-copy snapshot, for the remaining delivery.
            (terminal_status, terminal_information) = pending.owned_terminal_result()
                .expect("buffered local result disappeared during delivery");
            delivery_state = pending.delivery_state;
        } else if pending.output_va != 0
            && pending.output_len != 0
            && delivery_state & nt_io_manager::IO_DELIVERY_BUFFER_PUBLISHED == 0
        {
            let delivery_len = if !nt_io_completion::file_io_status_copies_output(terminal_status) {
                0
            } else {
                u32::try_from(terminal_information)
                    .ok()
                    .filter(|length| *length <= pending.output_len)
                    .expect("terminal File output exceeds delivery target")
            };
            let mut offset = (&*core::ptr::addr_of!(PENDING_FILE_IO))
                .get_exact(identity)
                .expect("pending File output owner disappeared")
                .output_offset;
            let mut copy_failed = false;
            while offset < delivery_len {
                let chunk = ((delivery_len - offset) as usize).min(4096);
                let work = &mut *core::ptr::addr_of_mut!(FILE_IO_COPY_WORK);
                let copy_result = match pending.operation {
                    nt_io_manager::PendingFileIoOperation::OwnedInline(_)
                    | nt_io_manager::PendingFileIoOperation::LocalBuffered(_)
                    | nt_io_manager::PendingFileIoOperation::LocalFlush(_) => {
                        Err(nt_fs::STATUS_INVALID_PARAMETER)
                    }
                    nt_io_manager::PendingFileIoOperation::LocalDirectoryNotify(operation) => {
                        nt_handler.copy_local_directory_notify_completion(
                            local_file_object.expect("local notify lost its File route"),
                            operation.notify_id, pending.irp_id,
                            offset as usize, &mut work[..chunk],
                        )
                    }
                    _ => driver_launch::copy_completed_irp_output_exact(
                        pending.irp_id, offset as u64, &mut work[..chunk],
                    ),
                };
                let copied = match copy_result {
                    Ok(copied) if copied != 0 => copied,
                    _ => {
                        copy_failed = true;
                        break;
                    }
                };
                if !nt_handler.xas_try_write_buf(pending.output_va + offset as u64, &work[..copied])
                {
                    copy_failed = true;
                    break;
                }
                if let Some(file_id) = hosted_file_id.filter(|_| pending.major == nt_io_abi::major::IRP_MJ_READ || is_pipe_transceive) {
                    nt_handler.observe_completed_npfs_read(
                        pending.pi as usize,
                        file_id,
                        pending.badge,
                        terminal_status,
                        terminal_information,
                        &work[..copied],
                        offset == 0,
                    );
                }
                offset = (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                    .advance_output_exact(slot, pending.irp_id, copied as u32, delivery_len)
                    .expect("pending File output progress lost");
            }
            if delivery_len == 0 {
                (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                    .advance_output_exact(slot, pending.irp_id, 0, 0)
                    .expect("pending File empty output owner disappeared");
            }
            if copy_failed {
                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                restore_file_io_mirrors!();
                continue;
            }
            delivery_state = (&*core::ptr::addr_of!(PENDING_FILE_IO))
                .get_exact(identity)
                .expect("published File output owner disappeared")
                .delivery_state;
        }

        if let nt_io_manager::PendingFileIoOperation::LocalDirectoryNotify(operation) = pending.operation {
            assert!((&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                .complete_local_directory_notify_exact(
                    pending.irp_id, operation.notify_id, terminal_status,
                    terminal_information as u32,
                    delivery_state & nt_io_manager::IO_DELIVERY_BUFFER_PUBLISHED != 0,
                ), "local directory completion lost its pending I/O owner");
        }

        if !matches!(pending.operation, nt_io_manager::PendingFileIoOperation::Create(_))
            && pending.iosb_va != 0
            && delivery_state
                & (nt_io_manager::IO_DELIVERY_IOSB_PUBLISHED | nt_io_manager::IO_DELIVERY_IOSB_FAULTED)
                == 0
        {
            let result = nt_handler.publish_file_io_status(
                pending.iosb_va, terminal_status, terminal_information,
            );
            let table = &mut *core::ptr::addr_of_mut!(PENDING_FILE_IO);
            delivery_state = match result {
                Ok(()) => table.mark_delivery_exact(
                    slot, pending.irp_id, nt_io_manager::IO_DELIVERY_IOSB_PUBLISHED,
                ),
                Err(nt_address_space::copy::MemoryCopyFailure::UserFault(status)) => {
                    if matches!(pending.operation, nt_io_manager::PendingFileIoOperation::LocalFlush(_)) {
                        table.mark_local_flush_iosb_faulted_exact(
                            slot, pending.irp_id, pending.iosb_va, status,
                        )
                    } else {
                        // Ordinary completion keeps its source result despite a permanent IOSB fault.
                        table.mark_iosb_faulted_exact(slot, pending.irp_id, pending.iosb_va)
                    }
                }
                Err(nt_address_space::copy::MemoryCopyFailure::Retry(_)) => {
                    FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                    restore_file_io_mirrors!();
                    continue;
                }
            }
            .expect("pending File IOSB owner disappeared");
            pending = table.get_exact(identity).expect("settled File IOSB owner disappeared");
        }

        if pending.event_obj_idx != u64::MAX
            && delivery_state & nt_io_manager::IO_DELIVERY_EVENT_PUBLISHED == 0
        {
            if nt_handler
                .events
                .set_existing(pending.event_obj_idx)
                .is_none()
            {
                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                restore_file_io_mirrors!();
                continue;
            }
            let _ = wait_wake_dispatcher_set(nt_handler);
            delivery_state = (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                .mark_delivery_exact(
                    slot,
                    pending.irp_id,
                    nt_io_manager::IO_DELIVERY_EVENT_PUBLISHED,
                )
                .expect("pending File event owner disappeared");
        }
        if pending.signal_file && delivery_state & nt_io_manager::IO_DELIVERY_FILE_PUBLISHED == 0 {
            let status = if pending.is_local() {
                nt_handler.signal_local_file_completion(local_file_object.expect("local completion lost its File route"))
            } else {
                nt_handler.signal_file_completion(hosted_file_id.expect("provider completion lost its File route"), terminal_status)
            };
            if status != nt_fs::STATUS_SUCCESS {
                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                restore_file_io_mirrors!();
                continue;
            }
            delivery_state = (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                .mark_delivery_exact(
                    slot,
                    pending.irp_id,
                    nt_io_manager::IO_DELIVERY_FILE_PUBLISHED,
                )
                .expect("pending File signal owner disappeared");
        }

        if pending.apc_routine != 0
            && delivery_state & nt_io_manager::IO_DELIVERY_APC_PUBLISHED == 0
        {
            let status = nt_handler.queue_file_user_apc(
                pending.tid,
                pending.apc_routine,
                pending.apc_context,
                pending.iosb_va,
            );
            if status != nt_fs::STATUS_SUCCESS && !nt_handler.file_apc_target_gone(pending.tid) {
                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                restore_file_io_mirrors!();
                continue;
            }
            delivery_state = (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                .mark_delivery_exact(
                    slot,
                    pending.irp_id,
                    nt_io_manager::IO_DELIVERY_APC_PUBLISHED,
                )
                .expect("pending File APC owner disappeared");
        } else if pending.apc_routine == 0
            && pending.publish_iocp
            && delivery_state & nt_io_manager::IO_DELIVERY_IOCP_PUBLISHED == 0
        {
            let status = nt_handler.post_file_completion_packet(
                hosted_file_id.expect("provider IOCP completion lost its File route"),
                pending.apc_context,
                terminal_status,
                terminal_information,
                false,
                pending.completion_port_suppressed,
            );
            if status != nt_fs::STATUS_SUCCESS {
                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                restore_file_io_mirrors!();
                continue;
            }
            let _ = io_completion_deliver(nt_handler);
            delivery_state = (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                .mark_delivery_exact(
                    slot,
                    pending.irp_id,
                    nt_io_manager::IO_DELIVERY_IOCP_PUBLISHED,
                )
                .expect("pending File IOCP owner disappeared");
        }

        if pending.busy.is_some_and(|busy| !busy.is_settled()) {
            pending_file_busy::release_if_ready(nt_handler, slot, pending);
            // Waking may enter provider cleanup and re-enter this loop. It runs only after the
            // snapshot walk, with a separate retained attempt; this owner cannot reply/ACK yet.
            restore_file_io_mirrors!();
            continue;
        }

        drop(delivery);
        if let Ok(view) = (&*core::ptr::addr_of!(PENDING_FILE_IO)).apc(identity) {
            if view.phase == nt_io_manager::PendingFileApcPhase::AwaitTerminal {
                (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                    .ready_apc_terminal(identity, pending.irp_id, terminal_status)
                    .expect("pending File APC reached staging before its terminal prefix settled");
            }
            crate::pending_file_apc::drive(nt_handler, identity);
            // The protocol retires the claim and Reply before normal backend ACK can resume.
            // Use a fresh row and delivery-state snapshot on the next completion visit.
            restore_file_io_mirrors!();
            continue;
        }

        if pending.reply_required
            && delivery_state & nt_io_manager::IO_DELIVERY_REPLY_PUBLISHED == 0
        {
            let cap = (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                .claim_reply_cap_exact(slot, pending.irp_id)
                .expect("pending File reply owner disappeared")
                .expect("pending File reply cap was claimed without publication");
            let replied = reply_parked_syscall(
                cap, pending.owned_syscall_status().unwrap_or(terminal_status) as u64,
            );
            if !replied {
                (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                    .restore_reply_cap_exact(slot, pending.irp_id, cap)
                    .expect("failed File reply lost its exact capability owner");
                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                restore_file_io_mirrors!();
                continue;
            }
            (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                .mark_reply_published_exact(slot, pending.irp_id)
                .expect("pending File reply publication owner disappeared");
            if pending.major == nt_io_abi::major::IRP_MJ_CREATE {
                if let Some(file) = hosted_file_id {
                    mounted_create_owner_trace::reply_exact(identity, pending.irp_id,
                        file, terminal_status);
                }
            }
            pending_pipe_read_trace::reply_delivered(identity, pending.irp_id);
            mounted_read_lifetime_trace::reply_delivered(identity, pending.irp_id);
            mounted_installer_file_trace::reply(identity, pending.irp_id);
            release_reply_pool_cap(cap);
            thread_wait_state_clear_badge_ready(nt_handler, pending.badge);
        }

        if !(&*core::ptr::addr_of!(PENDING_FILE_IO))
            .completion_surfaces_settled_exact(slot, pending.irp_id)
        {
            panic!("pending File completion reached ACK before required surfaces");
        }
        if delivery_state & nt_io_manager::IO_DELIVERY_BACKEND_ACKED == 0 {
            let acknowledged = match pending.operation {
                nt_io_manager::PendingFileIoOperation::LocalDirectoryNotify(operation) => {
                    nt_handler.acknowledge_local_directory_notify_completion(
                        local_file_object.expect("local notify lost its File route"), operation.notify_id, pending.irp_id,
                    )
                }
                _ if backend_ack_required => driver_launch::acknowledge_completed_irp(pending.irp_id),
                _ => Ok(()),
            };
            if acknowledged.is_err() {
                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                restore_file_io_mirrors!();
                continue;
            }
            delivery_state = (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                .mark_backend_acked_exact(slot, pending.irp_id)
                .expect("ACKed pending File owner disappeared");
            mounted_read_lifetime_trace::backend_acked(identity, pending.irp_id);
            mounted_installer_file_trace::ack(identity, pending.irp_id);
            if pending.major == nt_io_abi::major::IRP_MJ_CREATE {
                if let Some(file) = hosted_file_id {
                    mounted_create_owner_trace::ack_exact(identity, pending.irp_id,
                        file, terminal_status);
                }
            }
        }
        if (pending.is_local()
            || matches!(pending.operation, nt_io_manager::PendingFileIoOperation::OwnedInline(_)))
            && delivery_state & nt_io_manager::IO_DELIVERY_OWNED_REFERENCE_RELEASED == 0
        {
            let released = if let Some(file) = local_file_object {
                nt_handler.try_release_local_file_io_reference(file)
            } else {
                let receipt = (&*core::ptr::addr_of!(PENDING_FILE_IO))
                    .owned_reference_release_exact(identity, pending.irp_id);
                let receipt = match receipt {
                    Some(receipt) => Ok(receipt),
                    None => nt_handler.file_completion.release_file(
                        hosted_file_id.expect("Hosted-inline completion lost its File route"),
                    ).map(|receipt| {
                        (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                            .record_owned_reference_release_exact(identity, pending.irp_id, receipt)
                            .expect("consumed File reference lost its retained inline owner");
                        receipt
                    }),
                };
                receipt.and_then(|receipt| crate::file_reference_retirement::followup(nt_handler, receipt))
            };
            if released.is_err() {
                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                restore_file_io_mirrors!();
                continue;
            }
            (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                .mark_owned_reference_released_exact(slot, pending.irp_id)
                .expect("released owned File reference lost its pending owner");
        }
        assert!(
            !pending.operation.is_owned_mode_uncommitted(),
            "nonterminal mode preparation cannot retire its retained File owner",
        );
        if matches!(pending.operation, nt_io_manager::PendingFileIoOperation::AttributeQuery(_)) {
            if driver_launch::abandon_unpublished_hosted_file(
                hosted_file_id.expect("attribute query lost its File route")
            ).is_err() {
                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                restore_file_io_mirrors!();
                continue;
            }
            crate::exec_handler::smss_attribute_probe_trace::trace_smss_attribute_terminal(
                pending.pi, pending.tid, hosted_file_id, pending.irp_id,
                terminal_status, pending.owned_syscall_status().unwrap_or(terminal_status),
            );
        }
        let table = &mut *core::ptr::addr_of_mut!(PENDING_FILE_IO);
        let finished = table
            .finish_owner_exact(identity, pending.irp_id)
            .expect("completed pending File owner did not retire");
        pending_pipe_read_trace::retired(identity, pending.irp_id);
        mounted_read_lifetime_trace::retired(identity, pending.irp_id);
        mounted_installer_file_trace::retired(identity, pending.irp_id);
        if let Some(file_id) = finished.route.hosted_file_id() {
            if matches!(finished.major, nt_io_abi::major::IRP_MJ_READ | nt_io_abi::major::IRP_MJ_WRITE) {
                let fs_context = driver_launch::hosted_file_route(file_id)
                    .map_or(0, |(_, context)| context);
                crate::exec_handler::trace_setup_scm_pipe_transition(
                    b"owner-retired", finished.pi as usize, finished.badge, finished.tid,
                    None, file_id, fs_context, finished.irp_id, finished.major,
                    terminal_status, terminal_information, finished.delivery_state,
                    finished.reply_required,
                );
            }
        }
        crate::pending_file_caller::retire(identity);
        if let Some(event) = finished.transfer_event {
            assert!(finished.event_obj_idx == u64::MAX || finished.event_obj_idx == event.native_identity);
            nt_handler.release_transfer_event(event);
        }
        match finished.operation {
            nt_io_manager::PendingFileIoOperation::Transfer => {
                nt_handler.release_file_reference(finished.route.hosted_file_id().expect("provider completion lost its File route"));
            }
            nt_io_manager::PendingFileIoOperation::Create(create) => {
                if create.handle_value == 0 {
                    nt_handler.release_unpublished_hosted_create(finished);
                }
            }
            nt_io_manager::PendingFileIoOperation::SetFileName(operation) => {
                let transaction_id =
                    nt_io_manager::PendingSetFileNameId::from_raw(operation.transaction_id)
                        .expect("set-file-name completion lost its transaction generation");
                let transaction = (&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                    .take_for_update(transaction_id)
                    .expect("set-file-name completion lost its captured transaction");
                if transaction.target_file_id != 0
                    && driver_launch::abandon_unpublished_hosted_file(transaction.target_file_id).is_err()
                {
                    assert!((&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                        .restore_retirement(transaction_id, transaction));
                    FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                } else {
                    assert!((&mut *core::ptr::addr_of_mut!(PENDING_SET_FILE_NAMES))
                        .finish_update(transaction_id));
                }
                nt_handler.release_file_reference(finished.route.hosted_file_id().expect("provider rename lost its File route"));
            }
            nt_io_manager::PendingFileIoOperation::AttributeQuery(_) => {}
            nt_io_manager::PendingFileIoOperation::LocalByteLock(_)
            | nt_io_manager::PendingFileIoOperation::LocalDirectoryNotify(_)
            | nt_io_manager::PendingFileIoOperation::OwnedInline(_)
            | nt_io_manager::PendingFileIoOperation::LocalBuffered(_)
            | nt_io_manager::PendingFileIoOperation::LocalFlush(_) => {}
            nt_io_manager::PendingFileIoOperation::OwnedModeInputCapture(_)
            | nt_io_manager::PendingFileIoOperation::OwnedModePrecommit(_) => {
                unreachable!("finished File owner retained nonterminal mode preparation")
            }
        }
        delivered += 1;
        let trace_completion = FILE_IO_COMPLETION_TRACE.fetch_add(1, Ordering::Relaxed) < 32
            || (is_pipe_transceive
                && PIPE_TRANSCEIVE_COMPLETION_TRACE.fetch_add(1, Ordering::Relaxed) < 16);
        if trace_completion {
            print_str(b"[file-io-complete] irp=0x");
            print_hex_u64(pending.irp_id);
            print_str(b" file=");
            print_pending_file_route(pending.route);
            print_str(b" major=0x");
            print_hex(pending.major as u32);
            if pending.control_code != 0 {
                print_str(b" control=0x");
                print_hex(pending.control_code);
            }
            print_str(b" status=0x");
            print_hex(terminal_status);
            print_str(b" info=");
            print_u64(terminal_information);
            print_str(b"\n");
        }
    }
    restore_file_io_mirrors!();
    nt_handler.loop_ctx = saved_ctx;
    let settled = if finish_settled_busy_only {
        0
    } else {
        pending_file_busy::redrive_wakes(nt_handler)
    };
    restore_file_io_mirrors!();
    (delivered, settled)
}

/// Resume `NtCancelIoFile` only after every canonical IRP selected for its exact File/thread pair
/// has published through its original owner and been acknowledged. The cancellation syscall's own
/// IOSB is best effort, matching NT's guarded final write; a late invalidation cannot wedge drain.
unsafe fn file_irp_drain_redrive_all(nt_handler: &mut ExecNtHandler) -> u64 {
    if (&*core::ptr::addr_of!(PENDING_FILE_IRP_DRAINS)).is_empty() {
        return 0;
    }
    let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
    let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
    let saved_pi = nt_handler.pi;
    let saved_ctx = nt_handler.loop_ctx;
    let mut resumed = 0u64;
    let mut cursor = 0usize;
    while let Some((slot, pending)) =
        (&*core::ptr::addr_of!(PENDING_FILE_IRP_DRAINS)).next_from(cursor)
    {
        cursor = slot + 1;
        if !driver_launch::file_thread_io_drain_state(pending.file_id, pending.tid).is_drained() {
            continue;
        }
        if nt_handler.capture_thread_process_identity(pending.pi as usize, pending.tid)
            != pending.process
        {
            continue;
        }

        let Some((_, _, _, _, scratch_base)) =
            mirror_ctx_for(nt_handler, pending.badge, pending.pi as usize, pending.tid)
        else {
            // The drain row still owns the File reference and any unpublished Reply.
            continue;
        };
        crate::executor::local().client_pi.store(pending.pi as u64, Ordering::Relaxed);
        crate::executor::local().scratch_base.store(scratch_base, Ordering::Relaxed);
        nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(pending.pi as usize));
        nt_handler.pi = pending.pi as usize;

        let mut delivery_state = pending.delivery_state;
        if delivery_state & nt_io_manager::FILE_IRP_DRAIN_IOSB_PUBLISHED == 0 {
            let _ = nt_handler.xas_try_write_buf(pending.iosb_va, &0u32.to_le_bytes());
            let _ = nt_handler.xas_try_write_buf(pending.iosb_va + 8, &0u64.to_le_bytes());
            delivery_state = (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IRP_DRAINS))
                .mark_iosb_published_exact(slot, pending.file_id, pending.tid)
                .expect("File IRP drain IOSB owner disappeared");
        }
        if delivery_state & nt_io_manager::FILE_IRP_DRAIN_REPLY_PUBLISHED == 0 {
            let Some(cap) = (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IRP_DRAINS))
                .begin_reply_exact(slot, pending.file_id, pending.tid)
            else {
                // An entered Reply has an uncertain effect and must never be replayed.
                continue;
            };
            let replied = reply_parked_syscall(cap, 0);
            if !replied {
                // Keep the exact Reply and File owners until delivery can be reconciled.
                continue;
            }
            thread_wait_state_clear_badge_ready(nt_handler, pending.badge);
            (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IRP_DRAINS))
                .finish_reply_exact(slot, pending.file_id, pending.tid, true)
                .expect("File IRP drain reply publication owner disappeared");
        }
        let finished = (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IRP_DRAINS))
            .finish_exact(slot, pending.file_id, pending.tid)
            .expect("completed File IRP drain owner did not retire");
        release_reply_pool_cap(finished.reply_cap);
        nt_handler.release_file_reference(finished.file_id);
        resumed += 1;
    }
    crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
    crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
    nt_handler.pi = saved_pi;
    nt_handler.loop_ctx = saved_ctx;
    resumed
}

pub(crate) unsafe fn file_irp_drain_dependents_quiescent_exact(
    pi: u32,
    process: nt_user_host::process_identity::ProcessIdentity,
) -> bool {
    !(&*core::ptr::addr_of!(PENDING_FILE_IRP_DRAINS)).has_process_exact(pi, process)
}

unsafe fn ensure_client_copyin_dll_page(
    pi: u64,
    page: u64,
    scratch_base: u64,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[Option<nt_pe_loader::PeFile>],
) -> bool {
    if hosted_thread_memory_access(pi, page, nt_address_space::PAGE_SIZE).is_err() {
        return false;
    }
    if client_copyin_frame_retry_retirement(pi, page).is_err() {
        return false;
    }
    if csrss_frame_get(pi, page) != 0 || client_copyin_frame_get(pi, page) != 0 {
        return true;
    }
    let Some((i, rva)) = reg.dll_for_page(pi as usize, page) else {
        return false;
    };
    let Some(slot) = dll_pes.get(i) else {
        return false;
    };
    let Some(tpe) = slot.as_ref() else {
        return false;
    };
    client_copyin_frame_build(pi, page, scratch_base, tpe, rva).is_ok()
}

unsafe fn ensure_client_copyin_dll_page_for(
    pi: u64,
    process: nt_memory_manager::ProcessIdentity,
    page: u64,
    scratch_base: u64,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[Option<nt_pe_loader::PeFile>],
) -> bool {
    if hosted_thread_memory_access(pi, page, nt_address_space::PAGE_SIZE).is_err()
        || client_copyin_frame_retry_retirement_for(pi, process, page).is_err()
    {
        return false;
    }
    let Ok(prefetch) = client_copyin_frame_lookup_for(pi, process, page) else {
        return false;
    };
    let Ok(backing) = nt_memory_manager::admit_client_copy_backing(
        pi,
        process,
        page,
        &*core::ptr::addr_of!(CLIENT_FRAME_REGISTRY),
        shared_image_mapping_identity(pi, page),
    ) else {
        return false;
    };
    if backing.resident.is_some()
        || backing.shared_image
        || prefetch.is_some()
        || dll_cache_get(page) != 0
    {
        return true;
    }
    let Some((index, rva)) = reg.dll_for_page(pi as usize, page) else {
        return false;
    };
    let Some(pe) = dll_pes.get(index).and_then(Option::as_ref) else {
        return false;
    };
    client_copyin_frame_build_for(pi, process, page, scratch_base, pe, rva).is_ok()
}

unsafe fn prefill_client_copyin_dll_range_pages(
    pi: u64,
    va: u64,
    len: usize,
    scratch_base: u64,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[Option<nt_pe_loader::PeFile>],
) {
    if hosted_thread_memory_access(pi, va, len as u64).is_err() {
        return;
    }
    if len == 0 {
        return;
    }
    let Some(last) = va.checked_add(len as u64 - 1) else {
        return;
    };
    let mut page = va & !0xfffu64;
    let last_page = last & !0xfffu64;
    loop {
        let _ = ensure_client_copyin_dll_page(pi, page, scratch_base, reg, dll_pes);
        if page == last_page {
            break;
        }
        page += 0x1000;
    }
}

unsafe fn prefill_client_large_string_pages(
    pi: u64,
    descriptor_va: u64,
    scratch_base: u64,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[Option<nt_pe_loader::PeFile>],
) {
    let mut raw = [0u8; 16];
    if !img_spawn::client_copyin_mapped(
        pi,
        descriptor_va,
        &mut raw,
        scratch_base,
    ) {
        return;
    }
    let Ok(descriptor) = nt_user_callback::LargeUnicodeStringDescriptor::parse(&raw) else {
        return;
    };
    let mut offset = 0usize;
    let length = descriptor.length_bytes as usize;
    if hosted_thread_memory_access(pi, descriptor.buffer, length as u64).is_err() {
        return;
    }
    let mut last_page = u64::MAX;
    while offset < length {
        let current = descriptor.buffer + offset as u64;
        let page = current & !0xfffu64;
        if page != last_page {
            let _ = ensure_client_copyin_dll_page(pi, page, scratch_base, reg, dll_pes);
            last_page = page;
        }
        let page_remaining = 0x1000usize - (current as usize & 0xfff);
        offset += page_remaining.min(length - offset);
    }
}

unsafe fn prefill_client_large_string_pages_for(
    pi: u64,
    process: nt_memory_manager::ProcessIdentity,
    descriptor_va: u64,
    scratch_base: u64,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[Option<nt_pe_loader::PeFile>],
) {
    let mut raw = [0u8; 16];
    if !img_spawn::client_copyin_process_mapped_for(
        pi, process, descriptor_va, &mut raw, scratch_base,
    ) {
        return;
    }
    let Some(input) = nt_kernel_exec::user_string::large_string_input(&raw, RC_ARG_BUF_CAP) else {
        return;
    };
    if input.length == 0
        || hosted_thread_memory_access(pi, input.buffer, input.length).is_err()
    {
        return;
    }
    let mut page = input.buffer & !0xfffu64;
    let last_page = (input.buffer + input.length - 1) & !0xfffu64;
    loop {
        let _ = ensure_client_copyin_dll_page_for(pi, process, page, scratch_base, reg, dll_pes);
        if page == last_page {
            break;
        }
        page += 0x1000;
    }
}

/// Resolve an executable thread's current process owner without decoding a replacement identity.
#[inline]
fn owner_top_badge_for(nt_handler: &ExecNtHandler, badge: u64) -> Option<u64> {
    let runtime = nt_handler.admit_hosted_thread_ingress(badge).ok()?;
    nt_handler.hosted_process_top_badge(runtime.pi)
}

fn owner_bit_for_badge(nt_handler: &ExecNtHandler, badge: u64) -> u64 {
    owner_top_badge_for(nt_handler, badge)
        .and_then(|owner| u32::try_from(owner).ok())
        .and_then(|owner| 1u64.checked_shl(owner))
        .unwrap_or(0)
}

fn wait_parked_owner_mask(nt_handler: &ExecNtHandler) -> u64 {
    const OWNER_THREAD_BADGE_SNAPSHOT: usize = 64;
    let mut mask = 0u64;
    for pi in 0..MAX_PI {
        let mut threads = [HostedThreadQuiesceRecord::empty(); OWNER_THREAD_BADGE_SNAPSHOT];
        if let Some(snapshot) = hosted_process_wait_snapshot(nt_handler, pi, &mut threads) {
            if snapshot.all_parked {
                mask |= 1u64 << snapshot.owner;
            }
        }
    }
    mask
}

#[derive(Clone, Copy)]
struct HostedProcessWaitSnapshot {
    owner: u64,
    count: usize,
    live: bool,
    all_parked: bool,
    overflow: bool,
}

fn hosted_process_wait_snapshot(
    nt_handler: &ExecNtHandler,
    pi: usize,
    threads: &mut [HostedThreadQuiesceRecord],
) -> Option<HostedProcessWaitSnapshot> {
    if !hosted_process_pi_can_run(nt_handler, pi) {
        return None;
    }
    let owner = nt_handler.hosted_process_top_badge(pi)?;
    if owner >= 64 {
        return None;
    }
    let (count, overflow) = nt_handler.hosted_thread_quiesce_records_for_pi(pi, threads);
    let mut relevant = 0usize;
    let mut all_parked = true;
    for thread in threads[..count].iter().copied() {
        match thread.state {
            Some(nt_process::ThreadState::Ready) | Some(nt_process::ThreadState::Running) => {
                relevant += 1;
                all_parked = false;
            }
            Some(nt_process::ThreadState::Waiting) => {
                relevant += 1;
                if !thread_wait_state_badge_parked(thread.badge) {
                    all_parked = false;
                }
            }
            Some(nt_process::ThreadState::Initialized)
            | Some(nt_process::ThreadState::Suspended)
            | Some(nt_process::ThreadState::Terminated)
            | None => {}
        }
    }
    Some(HostedProcessWaitSnapshot {
        owner,
        count,
        live: overflow || relevant != 0,
        all_parked: !overflow && relevant != 0 && all_parked,
        overflow,
    })
}

fn hosted_process_pi_can_run(nt_handler: &ExecNtHandler, pi: usize) -> bool {
    if !hosted_process_pi_is_live(pi) {
        return false;
    }
    nt_handler
        .pm_pid_for_pi(pi)
        .is_none_or(|pid| !nt_handler.pm.is_process_signaled(pid))
}

fn trace_wait_owner_mask_after_mark(
    nt_handler: &ExecNtHandler,
    pi: usize,
    badge: u64,
    live: u64,
    crash_parked: u64,
    wait_parked: u64,
) {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    if n >= 320 {
        return;
    }
    const OWNER_THREAD_BADGE_SNAPSHOT: usize = 64;
    let mut threads = [HostedThreadQuiesceRecord::empty(); OWNER_THREAD_BADGE_SNAPSHOT];
    let snapshot = hosted_process_wait_snapshot(nt_handler, pi, &mut threads);
    print_str(b"[wait-owner] #");
    print_u64(n);
    print_str(b" pi=");
    print_u64(pi as u64);
    print_str(b" badge=");
    print_u64(badge);
    print_str(b" owner=");
    if let Some(snapshot) = snapshot {
        print_u64(snapshot.owner);
    } else {
        print_str(b"unknown");
    }
    print_str(b" live=0x");
    print_hex_u64(live);
    print_str(b" crash=0x");
    print_hex_u64(crash_parked);
    print_str(b" wait=0x");
    print_hex_u64(wait_parked);
    print_str(b" remaining=0x");
    print_hex_u64(live & !(crash_parked | wait_parked));
    let Some(snapshot) = snapshot else {
        print_str(b" snapshot=unavailable\n");
        return;
    };
    print_str(b" owner-bit=");
    print_u64(((snapshot.owner < 64) && (wait_parked & (1u64 << snapshot.owner)) != 0) as u64);
    print_str(b" snapshot-live=");
    print_u64(snapshot.live as u64);
    print_str(b" all-parked=");
    print_u64(snapshot.all_parked as u64);
    print_str(b" overflow=");
    print_u64(snapshot.overflow as u64);
    print_str(b" threads=");
    for thread in threads[..snapshot.count].iter().copied() {
        print_wait_snapshot_thread(thread);
    }
    print_str(b"\n");
}

fn print_wait_snapshot_thread(thread: HostedThreadQuiesceRecord) {
    print_u64(thread.badge);
    print_str(b":");
    match thread.state {
        Some(nt_process::ThreadState::Initialized) => print_str(b"I"),
        Some(nt_process::ThreadState::Ready) => print_str(b"Ready"),
        Some(nt_process::ThreadState::Running) => print_str(b"Run"),
        Some(nt_process::ThreadState::Waiting) => print_str(b"Wait"),
        Some(nt_process::ThreadState::Suspended) => print_str(b"S"),
        Some(nt_process::ThreadState::Terminated) => print_str(b"T"),
        None => print_str(b"?"),
    }
    print_str(if thread_wait_state_badge_parked(thread.badge) {
        b"/P "
    } else {
        b"/- "
    });
}

fn trace_smss_file_busy_wait(waiter: nt_io_manager::SynchronousFileWaiter) {
    static N: AtomicU64 = AtomicU64::new(0);
    if waiter.pi != 0 || N.fetch_add(1, Ordering::Relaxed) >= 24 { return; }
    print_str(b"[smss-file-busy] ssn=");
    print_u64(waiter.service_number as u64);
    print_str(b" handle=0x");
    print_hex_u64(waiter.handle as u64);
    print_str(b" tid=");
    print_u64(waiter.tid);
    print_str(b" file=0x");
    match waiter.route {
        nt_io_manager::FileIoWaitRoute::Hosted { file_id, .. } => print_hex_u64(file_id),
        nt_io_manager::FileIoWaitRoute::LocalOverlay { file_object } => print_hex_u64(file_object),
    }
    print_str(b"\n");
}

/// A DEADLINE-LESS wait park is the one park that can wedge the boot: the parked thread can only be
/// woken by another RUNNABLE thread, and if none is left the loop's next `recv` blocks forever —
/// past even the wall-clock stall watchdog, which lives at the loop top and therefore never runs.
/// Trace each indefinite park with the masks read by the quiesce test. The wait owner mask is derived
/// from live per-thread parked state, not from the current thread's role.
#[track_caller]
fn trace_indefinite_wait_park(
    nt_handler: &ExecNtHandler,
    badge: u64,
    live: u64,
    crash_parked: u64,
    wait_parked: u64,
) {
    static N: AtomicU64 = AtomicU64::new(0);
    if N.fetch_add(1, Ordering::Relaxed) >= 320 {
        return;
    }
    print_str(b"[wait-park] site=");
    print_u64(core::panic::Location::caller().line() as u64);
    print_str(b" pi=");
    print_u64(nt_handler.pi as u64);
    print_str(b" tid=");
    print_u64(nt_handler.current_tid);
    print_str(b" ssn=");
    print_u64(nt_handler.current_service_number as u64);
    print_str(b" badge=");
    print_u64(badge);
    print_str(b" owner=");
    match owner_top_badge_for(nt_handler, badge) {
        Some(owner) => print_u64(owner),
        None => print_str(b"unknown"),
    }
    print_str(b" top-level=");
    print_u64(pi_is_top_level(nt_handler, badge) as u64);
    print_str(b" live=0x");
    print_hex_u64(live);
    print_str(b" crash=0x");
    print_hex_u64(crash_parked);
    print_str(b" wait=0x");
    print_hex_u64(wait_parked);
    print_str(b"\n");
}

#[inline]
fn userinit_shell_frontier_pending(
    nt_handler: &ExecNtHandler,
    crash_parked: u64,
    wait_parked: u64,
) -> bool {
    if USERINIT_SHELL_IMAGE_ATTEMPTS.load(Ordering::Relaxed) != 0 {
        return false;
    }
    let Some(userinit_badge) = live_hosted_pi_for_observation_role(
        nt_handler,
        nt_exe_image::HostedProcessRole::InteractiveShellBootstrap,
    )
    .and_then(|pi| nt_handler.hosted_process_top_badge(pi))
    else {
        return false;
    };
    if userinit_badge >= 64 {
        return false;
    }
    let userinit_bit = 1u64 << userinit_badge;
    (crash_parked | wait_parked) & userinit_bit == 0
}

/// A top-level process badge is the process's main hosted thread, not a listener/worker sub-thread.
#[inline]
fn pi_is_top_level(nt_handler: &ExecNtHandler, badge: u64) -> bool {
    hosted_pi_for_top_badge(nt_handler, badge).is_some()
}

/// The bitmask of LIVE top-level process badges (smss is always live; the rest once SPAWNED).
/// Used by the quiesce test: the boot has no forward progress possible once every live top-level
/// process is crash-parked (so the loop's next `recv` would block on the fault-EP forever).
#[inline]
unsafe fn live_top_badges(nt_handler: &ExecNtHandler) -> u64 {
    const OWNER_THREAD_BADGE_SNAPSHOT: usize = 64;
    let mut mask = 0u64;
    for pi in 0..MAX_PI {
        let mut threads = [HostedThreadQuiesceRecord::empty(); OWNER_THREAD_BADGE_SNAPSHOT];
        if let Some(snapshot) = hosted_process_wait_snapshot(nt_handler, pi, &mut threads) {
            if snapshot.live {
                mask |= 1u64 << snapshot.owner;
            }
        }
    }
    mask
}

/// Top-level process owners that currently have at least one Ready/Running hosted thread.
#[inline]
unsafe fn runnable_top_badges(nt_handler: &ExecNtHandler) -> u64 {
    const OWNER_THREAD_BADGE_SNAPSHOT: usize = 64;
    let mut mask = 0u64;
    for pi in 0..MAX_PI {
        let mut threads = [HostedThreadQuiesceRecord::empty(); OWNER_THREAD_BADGE_SNAPSHOT];
        if hosted_process_wait_snapshot(nt_handler, pi, &mut threads).is_none() {
            continue;
        }
        let Some(owner) = nt_handler.hosted_process_top_badge(pi) else {
            continue;
        };
        if owner >= 64 {
            continue;
        }
        if threads.iter().any(|thread| {
            matches!(
                thread.state,
                Some(nt_process::ThreadState::Ready) | Some(nt_process::ThreadState::Running)
            )
        }) {
            mask |= 1u64 << owner;
        }
    }
    mask
}

/// One-line progress trace for the dbgk target-blocking self-test: which fault the throwaway client
/// took and what its progress MARKER read at that moment. Six lines per boot — they are the
/// human-readable record of "parked, not progressed" / "resumed, and continued".
unsafe fn dbgk_blk_trace(tag: &[u8], msginfo: u64, m0: u64, m1: u64, marker: u64) {
    print_str(b"[dbgk-blk] ");
    print_str(tag);
    print_str(b" label=");
    print_u64(msginfo >> 12);
    print_str(b" m0=0x");
    print_hex(m0 as u32);
    print_str(b" m1=0x");
    print_hex(m1 as u32);
    print_str(b" marker=");
    print_u64(marker);
    print_str(b"\n");
}

/// One-line progress trace for the DbgUiRemoteBreakin self-test. The marker is the remote target's
/// private proof page: zero means the selected event was admission noise, `0x11` means the break-in
/// thread reached its entry point, and `0x12` means it resumed past the breakpoint.
unsafe fn dbgk_brk_trace(tag: &[u8], msginfo: u64, m0: u64, m1: u64, marker: u64) {
    print_str(b"[dbgk-brk] ");
    print_str(tag);
    print_str(b" label=");
    print_u64(msginfo >> 12);
    print_str(b" m0=0x");
    print_hex(m0 as u32);
    print_str(b" m1=0x");
    print_hex(m1 as u32);
    print_str(b" marker=0x");
    print_hex(marker as u32);
    print_str(b"\n");
}
