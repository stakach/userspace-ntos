//! Outer-only execution and coalesced wake demand for selected component continuations.

use super::*;
use nt_component_suspension::{LaneResume, ResumeDemand, ResumePass, ResumeWake, SuspensionOwner};

#[path = "component_resume_execute.rs"]
mod execute;
pub(super) use execute::{run_hosted, run_receive};

#[path = "component_resume_maintenance.rs"]
mod maintenance;
pub(crate) use maintenance::{run_root_maintenance, RootMaintenanceResumeOutcome};

#[path = "component_resume_bootstrap.rs"]
mod bootstrap;
pub(crate) use bootstrap::{run_bootstrap_outer, BootstrapPassOutcome};

pub(crate) unsafe fn await_bootstrap_completion(
    target: nt_user_host::provider_kernel_activation::KernelProviderCaller,
) -> Result<bool, u32> {
    crate::bootstrap_receive::drive(target, || {
        match run_bootstrap_outer(target)? {
            BootstrapPassOutcome::TargetAcknowledged { initialized } => Ok(Some(initialized)),
            BootstrapPassOutcome::Deferred { .. }
            | BootstrapPassOutcome::NoReadyWork
            | BootstrapPassOutcome::PassFinished { .. } => Ok(None),
            _ => Err(nt_status::NtStatus::DEVICE_BUSY.raw() as u32),
        }
    })
}

// Scheduling latency/backoff, independent of the original NT wait's retained deadline.
static mut WAKE: ResumeWake = match ResumeWake::new(10_000, 160_000) {
    Ok(wake) => wake,
    Err(_) => panic!("invalid component resume pacing"),
};
static FAILURES: AtomicU64 = AtomicU64::new(0);

pub(super) struct Candidate {
    pub(super) resume: LaneResume<ComponentSuspensionCompletion>,
    pub(super) owner: SuspensionOwner,
    pub(super) sequence: u64,
    pub(super) continuation: ComponentNativeContinuation,
}

unsafe fn eligible(
    pm: &nt_process::ProcessManager,
    continuation: ComponentNativeContinuation,
) -> bool {
    match continuation {
        ComponentNativeContinuation::Hosted(hosted) => {
            if matches!(hosted.pending, PendingComponentDispatch::RootMaintenance(_)
                | PendingComponentDispatch::NestedRestore(_)) {
                return false;
            }
            let reply_ready = hosted.return_target.can_resume();
            let client_ready = win32k_glue::win32k_client_context_is_admitted(hosted.pending.client());
            if let HostedContinuationDestination::InitialThread(origin) = hosted.destination {
                let binding = origin.target();
                static INITIAL_RESUME_TRACE: AtomicU64 = AtomicU64::new(0);
                let count = INITIAL_RESUME_TRACE.fetch_add(1, Ordering::Relaxed);
                if count < 12 || count.is_power_of_two() {
                    print_str(b"[initial-provider-wait] stage=eligible pi/tid/reply/client=");
                    print_u64(binding.pi as u64);
                    print_str(b"/"); print_u64(binding.tid);
                    print_str(b"/"); print_u64(reply_ready as u64);
                    print_str(b"/"); print_u64(client_ready as u64);
                    print_str(b"\n");
                }
            }
            reply_ready && client_ready
        }
        ComponentNativeContinuation::Kernel(capture) => {
            kernel_provider_activation::wait_resume_is_eligible(pm, capture)
        }
    }
}

unsafe fn candidate(resume: LaneResume<ComponentSuspensionCompletion>) -> Option<Candidate> {
    let frame = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .frame(resume.lane, resume.suspension.key)
        .ok()??;
    Some(Candidate {
        owner: frame.owner,
        sequence: frame.admission_sequence,
        continuation: frame.continuation,
        resume,
    })
}

pub(super) unsafe fn next_ready(pm: &nt_process::ProcessManager) -> Option<Candidate> {
    let resume = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .next_resumable_if(|frame| eligible(pm, frame.continuation))?;
    candidate(resume)
}

unsafe fn next_in_pass(pm: &nt_process::ProcessManager, pass: &mut ResumePass) -> Option<Candidate> {
    let resume = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .next_resumable_in_pass(pass, |frame| eligible(pm, frame.continuation))?;
    candidate(resume)
}

/// ACK plus a retained next Call transfers the external service token to its
/// waiting syscall continuation. Neither observation alone authorizes resume.
unsafe fn select_ready_service_waits() {
    let waits: Vec<_> = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .frames()
        .filter_map(|(lane, frame)| {
            let ComponentNativeContinuation::Hosted(hosted) = frame.continuation else {
                return None;
            };
            let PendingComponentDispatch::ServiceWait(pending) = hosted.pending else {
                return None;
            };
            (pending.yielded.route.identity().lane == lane)
                .then_some((frame.key, frame.owner, pending))
        })
        .collect();
    for (key, owner, pending) in waits {
        let yielded = pending.yielded;
        let ready = crate::spawn_hosts::shared_ingress::owner::runtime::resume_service_component_wait(
            yielded.route, yielded.dispatch, yielded.reply, yielded.token, key, owner,
        );
        if matches!(ready, Ok(true)) {
            (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .select(key, ComponentSuspensionCompletion::receive_ready())
                .expect("ACKed service wait retains its typed continuation");
        }
    }
}

/// Finish currently selected hosted admissions before a caller reply, never fresh reparks.
/// Kernel continuations remain a barrier for the ordinary runtime/kernel owner.
pub(super) unsafe fn drain_hosted_ready(handler: *mut ExecNtHandler) -> u64 {
    if is_running()
        || crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending()
    {
        return 0;
    }
    let Some(ctx) = (*handler).loop_ctx else {
        return 0;
    };
    let _message = crate::ipc_message::SavedMessageBuffer::capture();
    let _durable = allocator::enter_durable();
    select_ready_service_waits();
    let mut pass = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).resume_pass();
    let mut drained = 0;
    loop {
        if crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending() {
            break;
        }
        drained += component_terminal::drain(&mut *handler, &mut *ctx.procs, &mut *ctx.pfilled);
        if crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending() {
            break;
        }
        if let Some(ticket) = root_maintenance_owner::next_returned_ticket()
            .or_else(|| root_maintenance_owner::next_ready_ticket()) {
            match run_root_maintenance(handler, ticket) {
                RootMaintenanceResumeOutcome::Parked | RootMaintenanceResumeOutcome::Terminal => {
                    continue;
                }
                RootMaintenanceResumeOutcome::DeferredRetry
                | RootMaintenanceResumeOutcome::RetainedFailure => break,
            }
        }
        let Some(candidate) = next_in_pass(&(*handler).pm, &mut pass) else {
            break;
        };
        if matches!(candidate.continuation, ComponentNativeContinuation::Kernel(_)) {
            break;
        }
        if run_hosted(handler, candidate).is_none() {
            break;
        }
    }
    if !crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending()
        && (*handler).lpc_endpoint_progress
    {
        let _ = lpc_endpoint_redrive_all(&mut *handler);
    }
    drained
}

pub(crate) unsafe fn is_running() -> bool {
    (&*core::ptr::addr_of!(WAKE)).is_running()
}

fn runtime_ready(handler: *const ExecNtHandler) -> bool {
    SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) == handler as u64
        && SERVICE_DELAY_DRAIN_QUEUE.load(Ordering::Acquire) != 0
        && DELAY_TIMER_HANDLER.load(Ordering::Relaxed) != 0
        && DELAY_TIMER_IRQ_STATE.load(Ordering::Acquire) == DELAY_TIMER_IRQ_ACTIVE
}

/// Timer callbacks only query this demand; they never claim or execute a selected continuation.
pub(crate) unsafe fn next_deadline(pm: &nt_process::ProcessManager) -> Option<u64> {
    let nested = nested_restore_owner::next_deadline();
    if component_execution_is_busy()
        && !kernel_provider_activation::has_stopped_wait_work(pm)
    {
        return nested;
    }
    match (nested, retained_deadline()) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
        (None, None) => None,
    }
}

/// Copy retained demand without runtime eligibility checks or claiming a continuation.
pub(crate) unsafe fn retained_deadline() -> Option<u64> {
    (&*core::ptr::addr_of!(WAKE)).next_deadline()
}

/// Count a scheduler wake as timer work without acknowledging demand or entering a provider.
pub(crate) unsafe fn wake_due(pm: &nt_process::ProcessManager, now: u64) -> u64 {
    u64::from(next_deadline(pm).is_some_and(|deadline| deadline <= now))
}

/// Memory-only observation. Do not run readiness validation while physical exclusion makes
/// its absence inconclusive; a stopped publication is distinct from an executing provider.
unsafe fn observe_demand(pm: &nt_process::ProcessManager) -> ResumeDemand {
    ResumeDemand::observe(
        component_execution_is_busy(),
        kernel_provider_activation::has_stopped_wait_work(pm),
        || {
            next_ready(pm).is_some()
                || root_maintenance_owner::next_returned_ticket().is_some()
                || (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).frames().any(|(_, frame)| {
                    frame.key.kind == nt_component_suspension::SuspensionKind::RootMaintenance
                        && matches!(frame.phase,
                            nt_component_suspension::SuspensionPhase::MaintenanceReady { .. })
                        && frame.continuation.hosted().is_some_and(|hosted| {
                            hosted.return_target.can_resume()
                        })
                })
                || kernel_provider_activation::has_ready_completions()
                || (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
                    .next_terminal_if(|_, terminal| {
                        terminal.frame.continuation.hosted().is_some_and(|hosted| {
                            hosted.return_target.can_resume()
                        })
                    })
                    .is_some()
        },
    )
}

unsafe fn reconcile_demand(pm: &nt_process::ProcessManager, now: u64) {
    let demand = observe_demand(pm);
    (&mut *core::ptr::addr_of_mut!(WAKE)).reconcile_demand(demand, now);
}

/// Every finalization barrier rechecks work before receiving. Physical exclusion suppresses
/// programming, not retained demand. Timer programming failure cannot acknowledge that demand.
pub(super) unsafe fn reconcile(handler: &mut ExecNtHandler) {
    // Nested finalization may defer; the outer receive boundary checks the live owner again.
    let _ = reconcile_runtime(handler);
}

/// A failed source may not silently strand deadlines in a blocking receive. Do not initialize
/// or replace hardware here: the existing fault path owns disabling and retiring that source.
pub(super) unsafe fn prepare_receive(handler: &mut ExecNtHandler) {
    let state = nt_kernel_exec::TimerReceiveState {
        registered: SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire)
            == core::ptr::from_ref(handler) as u64
            && SERVICE_DELAY_DRAIN_QUEUE.load(Ordering::Acquire) != 0,
        active: DELAY_TIMER_HANDLER.load(Ordering::Relaxed) != 0
            && DELAY_TIMER_IRQ_STATE.load(Ordering::Acquire) == DELAY_TIMER_IRQ_ACTIVE,
        delivery_running: TIMER_DELIVERY_GATE.is_active(),
        continuation_running: is_running(),
    };
    state
        .prepare(|| reconcile_runtime(handler))
        .expect("runtime timer ownership must permit blocking receive");
    super::mounted_create_owner_trace::receive_boundary_snapshot();
    trace_retained_receive_owners();
}

/// The final root receive boundary is the last point that can explain an all-HLT
/// guest. Keep separate budgets for changed and repeated states so early healthy
/// progress cannot consume every later sample. No Reply or timer owner changes.
fn trace_retained_receive_owners() {
    static LAST_KEY: AtomicU64 = AtomicU64::new(0);
    static REPEATS: AtomicU64 = AtomicU64::new(0);
    static CHANGES: AtomicU64 = AtomicU64::new(0);
    static CHANGE_PRINTS: AtomicU64 = AtomicU64::new(0);
    static REPEAT_PRINTS: AtomicU64 = AtomicU64::new(0);
    static URGENT_PRINTS: AtomicU64 = AtomicU64::new(0);
    static PRINTS: AtomicU64 = AtomicU64::new(0);
    let section = crate::section_metadata_work::receive_owner_snapshot();
    let cleanup = crate::service_sec_image::file_cleanup_receive_owner_snapshot();
    let lifecycle = driver_launch::hosted_file_lifecycle_receive_owner_snapshot();
    if section.is_none() && cleanup.is_none() && lifecycle.is_none() {
        return;
    }
    let mut key = 0xcbf2_9ce4_8422_2325u64;
    for value in section.into_iter().flatten()
        .chain(cleanup.into_iter().flatten())
        .chain(lifecycle.into_iter().flatten())
    {
        key = (key ^ value).wrapping_mul(0x100_0000_01b3);
    }
    let previous = LAST_KEY.swap(key, Ordering::Relaxed);
    let repeat = if previous == key {
        REPEATS.fetch_add(1, Ordering::Relaxed) + 1
    } else {
        REPEATS.store(0, Ordering::Relaxed);
        0
    };
    let now = monotonic_time_100ns();
    let armed = LAST_REARM_AUTHORITY.is_armed();
    let urgent = !armed || LAST_REARM_DEADLINE.load(Ordering::Relaxed) <= now;
    let urgent_selected = urgent && (repeat == 0 || repeat.is_power_of_two())
        && URGENT_PRINTS.fetch_add(1, Ordering::Relaxed) < 16;
    let selected = if urgent_selected {
        true
    } else if repeat == 0 {
        let change = CHANGES.fetch_add(1, Ordering::Relaxed) + 1;
        (change <= 8 || change.is_power_of_two() || change % 16 == 0)
            && CHANGE_PRINTS.fetch_add(1, Ordering::Relaxed) < 32
    } else {
        repeat.is_power_of_two() && REPEAT_PRINTS.fetch_add(1, Ordering::Relaxed) < 16
    };
    if !selected {
        return;
    }
    let sample = PRINTS.fetch_add(1, Ordering::Relaxed);
    if sample >= 64 {
        return;
    }
    print_str(b"[retained-receive] sample/repeat/now-ms=");
    print_u64(sample + 1);
    print_str(b"/"); print_u64(repeat);
    print_str(b"/"); print_u64(now / 10_000);
    print_str(b" section pi/tid/handle/file/phase/irp/reply/count=");
    print_receive_owner_fields(section);
    print_str(b" section-wake-ms=");
    match crate::section_metadata_work::next_deadline() {
        Some(deadline) => print_u64(deadline / 10_000),
        None => print_str(b"-"),
    }
    print_str(b" cleanup file/pi/tid/badge/reply/count=");
    print_receive_owner_fields(cleanup);
    print_str(b" lifecycle file/payload/blocked/retry-after/executing/count=");
    print_receive_owner_fields(lifecycle);
    print_str(b" timer source/deadline-ms/rearm-now-ms/armed/irq-state/tick-pending=");
    print_receive_owner_fields(Some([
        LAST_REARM_SOURCE.load(Ordering::Relaxed),
        LAST_REARM_DEADLINE.load(Ordering::Relaxed) / 10_000,
        LAST_REARM_NOW.load(Ordering::Relaxed) / 10_000,
        u64::from(LAST_REARM_AUTHORITY.is_armed()),
        DELAY_TIMER_IRQ_STATE.load(Ordering::Acquire),
        DELAY_TIMER_TICKS_PENDING.load(Ordering::Relaxed),
    ]));
    print_str(b"\n");
    if section.is_some_and(|owner| owner[7] > 1) {
        crate::section_metadata_work::trace_receive_owner_rows();
    }
    if cleanup.is_some_and(|owner| owner[5] > 1) {
        crate::service_sec_image::trace_file_cleanup_receive_owner_rows();
    }
    if lifecycle.is_some_and(|owner| owner[5] > 1) {
        driver_launch::trace_hosted_file_lifecycle_receive_owner_rows();
    }
}

fn print_receive_owner_fields<const N: usize>(fields: Option<[u64; N]>) {
    let Some(fields) = fields else {
        print_str(b"-");
        return;
    };
    for (index, value) in fields.into_iter().enumerate() {
        if index != 0 { print_str(b"/"); }
        print_u64(value);
    }
}

unsafe fn reconcile_runtime(handler: &mut ExecNtHandler) -> Option<nt_kernel_exec::TimerRearmOutcome> {
    if !runtime_ready(core::ptr::from_ref(handler)) || is_running() {
        return None;
    }
    let previous = (&*core::ptr::addr_of!(WAKE)).next_deadline();
    let now = monotonic_time_100ns();
    reconcile_demand(&handler.pm, now);
    let dpc_deadline = driver_launch::hosted_dpc_next_deadline(now);
    let acpi_deadline = driver_launch::hosted_acpi_pci_route_recovery_next_deadline(now);
    if previous.is_none()
        && (&*core::ptr::addr_of!(WAKE)).next_deadline().is_none()
        && nested_restore_owner::next_deadline().is_none()
        && dpc_deadline.is_none()
        && acpi_deadline.is_none()
        && driver_launch::hosted_irq_retry_next_deadline().is_none()
        && driver_launch::hosted_file_retry_deadline(now).is_none()
        && crate::registry_mutation_work::next_deadline().is_none()
        && crate::section_metadata_work::next_deadline().is_none()
        && crate::process_image_snapshot_work::next_deadline().is_none()
        && crate::provider_section_broker::next_deadline().is_none()
        && crate::gdi_routed_image_work::next_deadline().is_none()
    {
        return None;
    }
    let queue =
        SERVICE_DELAY_DRAIN_QUEUE.load(Ordering::Acquire) as *const nt_delay_execution::Queue;
    let _message = crate::ipc_message::SavedMessageBuffer::capture();
    Some(delay_timer_rearm(&*queue, handler))
}

unsafe fn drain_terminals(handler: *mut ExecNtHandler) -> bool {
    let ctx = (*handler).loop_ctx;
    let retired = if let Some(ctx) = ctx {
        component_terminal::drain(&mut *handler, &mut *ctx.procs, &mut *ctx.pfilled)
    } else {
        0
    };
    let kernel_progress = kernel_provider_activation::redrive_ready_completions();
    retired != 0 || kernel_progress
}

fn report_retained(status: u32) {
    if FAILURES.fetch_add(1, Ordering::Relaxed) < 16 {
        print_str(b"[component-resume] retained status=0x");
        print_hex(status);
        print_str(b"\n");
    }
}

/// The service-loop owner passes an address, never a borrowed helper parameter. All handler,
/// process, lane and activation borrows below are local to memory operations or terminal delivery;
/// none survives the selected driver pump. Received message registers survive the entire pass.
pub(super) unsafe fn run_outer(handler: *mut ExecNtHandler) {
    if !runtime_ready(handler)
        || is_running()
        || crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending()
    {
        return;
    }
    // A hosted terminal may own the shared execution fence while awaiting the separately
    // retained final Call. Settle that exact return before the ordinary busy-lane gate.
    let _ = component_terminal::drain_shared_returns();
    if let Some(ticket) = nested_restore_owner::next_retry() {
        let _message = crate::ipc_message::SavedMessageBuffer::capture();
        let _durable = allocator::enter_durable();
        if nested_restore_owner::run_one(ticket)
            == nested_restore_owner::NestedRestorePassOutcome::ResultRetained
        {
            let _ = nested_restore_owner::settle_result(ticket);
            if !nested_restore_owner::transfer_nested_repark(ticket)
                && !nested_restore_owner::transfer_genuine_wait(ticket, handler)
                && nested_restore_owner::transfer_callback_terminal(ticket).is_none()
            {
                let _ = nested_restore_owner::transfer_completed_terminal(ticket);
            }
        }
        nested_restore_owner::defer_retry(ticket);
        let _ = drain_terminals(handler);
    }
    if let Some(ticket) = root_maintenance_owner::next_returned_ticket() {
        let _message = crate::ipc_message::SavedMessageBuffer::capture();
        let _durable = allocator::enter_durable();
        match run_root_maintenance(handler, ticket) {
            RootMaintenanceResumeOutcome::Terminal => { let _ = drain_terminals(handler); }
            RootMaintenanceResumeOutcome::Parked => {}
            RootMaintenanceResumeOutcome::DeferredRetry => {}
            RootMaintenanceResumeOutcome::RetainedFailure =>
                report_retained(nt_process::STATUS_UNSUCCESSFUL),
        }
    }
    if component_execution_is_busy()
        && !kernel_provider_activation::has_stopped_wait_work(&(*handler).pm)
    {
        return;
    }
    let _message = crate::ipc_message::SavedMessageBuffer::capture();
    let _durable = allocator::enter_durable();
    select_ready_service_waits();
    reconcile(&mut *handler);
    let mut ticket = match (&mut *core::ptr::addr_of_mut!(WAKE)).begin_pass(monotonic_time_100ns())
    {
        Ok(Some(ticket)) => ticket,
        Ok(None) => return,
        Err(_) => {
            report_retained(nt_process::STATUS_INSUFFICIENT_RESOURCES);
            return;
        }
    };
    kernel_provider_activation::publish_runtime_waits(&mut *handler);
    let mut pass = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).resume_pass();
    let mut progressed = drain_terminals(handler);
    loop {
        if crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending() {
            break;
        }
        if let Some(ticket) = root_maintenance_owner::next_ready_ticket() {
            match run_root_maintenance(handler, ticket) {
                RootMaintenanceResumeOutcome::Parked | RootMaintenanceResumeOutcome::Terminal => {
                    progressed = true;
                    progressed |= drain_terminals(handler);
                    continue;
                }
                RootMaintenanceResumeOutcome::DeferredRetry => break,
                RootMaintenanceResumeOutcome::RetainedFailure => {
                    report_retained(nt_process::STATUS_UNSUCCESSFUL);
                    break;
                }
            }
        }
        let Some(candidate) = next_in_pass(&(*handler).pm, &mut pass) else {
            break;
        };
        match candidate.continuation {
            ComponentNativeContinuation::Hosted(_) => {
                progressed |= run_hosted(handler, candidate).is_some();
            }
            ComponentNativeContinuation::Kernel(capture) => {
                use kernel_provider_activation::resume::DriverEntryWaitOutcome;
                match kernel_provider_activation::resume::run_driver_entry_wait_resume(
                    capture.caller(),
                    capture,
                ) {
                    Ok(DriverEntryWaitOutcome::WaitCaptured(next)) => {
                        debug_assert_eq!(next.caller(), capture.caller());
                        progressed = true;
                    }
                    Ok(DriverEntryWaitOutcome::Returned(_terminal)) => progressed = true,
                    Ok(DriverEntryWaitOutcome::Stopped(_stop)) => {}
                    Err(status) => report_retained(status),
                }
                // A fresh wait owns its observed timeout origin and replaces the old frame
                // only after real lease acquisition. Refusal retains both original captures.
                kernel_provider_activation::publish_runtime_waits(&mut *handler);
            }
        }
        if crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending() {
            break;
        }
        progressed |= drain_terminals(handler);
    }
    if !crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending()
        && (*handler).lpc_endpoint_progress
    {
        // Component-originated LPC work bypasses the ordinary syscall post-action.
        let _ = lpc_endpoint_redrive_all(&mut *handler);
    }
    // A still-running physical owner is not evidence that its retained work disappeared.
    let has_work = component_execution_is_busy() || observe_demand(&(*handler).pm).retains_work();
    (&mut *core::ptr::addr_of_mut!(WAKE))
        .finish_pass(&mut ticket, monotonic_time_100ns(), has_work, progressed)
        .expect("runtime continuation pass must finish with its owned wake ticket");
    reconcile(&mut *handler);
}
