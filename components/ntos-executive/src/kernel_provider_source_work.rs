//! A kernel job stopped on its own inline source terminal.
//!
//! A hosted syscall leaves such a stop at the root as a service-wait yield and its hosted
//! Reply owner resumes it. A kernel job has no hosted Reply, so its retained activation owns
//! the same yielded receive half: the runner lends the singleton publication, the ordinary
//! source Work delivers the terminal into the provider, and the job continues exactly once.

use super::*;
use nt_user_host::provider_kernel_pump::KernelSourceTerminal;
use spawn_hosts::shared_ingress::owner::runtime as ingress;

/// The lent publication and the exact parked service wait it was lent for.
#[must_use = "a parked kernel job retains its lent publication until it is resumed"]
pub(super) struct ParkedSourceWork {
    wait: win32k_glue::ServiceWaitYield,
    page: win32k_glue::SharedResumeSnapshot,
}

impl ParkedSourceWork {
    /// The source Work is the only authority for its terminal. As for a hosted service wait,
    /// the job may continue only once that Work's service Reply is acknowledged and the
    /// provider's next Call is retained; the continued receive half then ends the wait itself.
    pub(super) unsafe fn terminal(&self) -> KernelSourceTerminal {
        let wait = self.wait;
        match driver_launch::win32k_source_ioctl_inline_terminal(
            wait.route, wait.dispatch, wait.reply, wait.token,
        ) {
            Some(KernelSourceTerminal::Indeterminate) => KernelSourceTerminal::Indeterminate,
            Some(KernelSourceTerminal::Unacknowledged) => KernelSourceTerminal::Unacknowledged,
            Some(KernelSourceTerminal::Acknowledged) | None => {
                match ingress::service_wait_resume_ready_exact(
                    wait.route, wait.dispatch, wait.reply, wait.token,
                ) {
                    Ok(true) => KernelSourceTerminal::Acknowledged,
                    Ok(false) => KernelSourceTerminal::Unacknowledged,
                    Err(_) => KernelSourceTerminal::Indeterminate,
                }
            }
        }
    }

    /// A long-parked job is visible at power-of-two passes; this never changes its state.
    pub(super) unsafe fn trace_waiting(&self, caller: KernelProviderCaller, passes: u64) {
        if passes >= 16 && passes.is_power_of_two() {
            trace_source_work(b"waiting", caller, self.wait, passes);
        }
    }
}

static SOURCE_WORK_TRACES: AtomicU64 = AtomicU64::new(0);

/// Bounded lifecycle evidence for one parked source-work stop. Read-only.
unsafe fn trace_source_work(
    stage: &[u8],
    caller: KernelProviderCaller,
    wait: win32k_glue::ServiceWaitYield,
    detail: u64,
) {
    trace_source_work_for(stage, caller, ps_target_tid(caller), wait, detail)
}

/// The Ps target's thread id, while the unfinished activation still retains its recipient.
unsafe fn ps_target_tid(caller: KernelProviderCaller) -> u64 {
    (&*core::ptr::addr_of!(ACTIVATIONS)).recipient(caller).ok()
        .and_then(KernelJobRecipient::ps_retirement)
        .map_or(0, |(_, target)| u64::from(target.thread().thread_id()))
}

unsafe fn trace_source_work_for(
    stage: &[u8],
    caller: KernelProviderCaller,
    tid: u64,
    wait: win32k_glue::ServiceWaitYield,
    detail: u64,
) {
    if SOURCE_WORK_TRACES.fetch_add(1, Ordering::Relaxed) >= 96 {
        return;
    }
    let terminal = match driver_launch::win32k_source_ioctl_inline_terminal(
        wait.route, wait.dispatch, wait.reply, wait.token,
    ) {
        None => 0,
        Some(KernelSourceTerminal::Unacknowledged) => 1,
        Some(KernelSourceTerminal::Acknowledged) => 2,
        Some(KernelSourceTerminal::Indeterminate) => 3,
    };
    print_str(b"[kernel-job-source-work] stage=");
    print_str(stage);
    print_str(b" dispatch/lane/lane-gen/epoch/reply/token/terminal/ps-tid/detail=");
    for value in [
        caller.owner().dispatch_id, u64::from(wait.dispatch.lane().index),
        wait.dispatch.lane().generation, wait.dispatch.epoch(), wait.reply, wait.token,
        terminal, tid, detail,
    ] {
        print_str(b"/");
        print_hex_u64(value);
    }
    print_str(b"\n");
}

/// Pump preflight without effects. Only an initial-origin Ps retirement job whose own service
/// Call is parked on a ready, unacknowledged inline source terminal yields: that terminal
/// must re-enter this provider, which the entered job's own publication forbids.
pub(crate) unsafe fn source_work_yield(
    channel: &spawn_hosts::PumpChannel,
) -> Option<win32k_glue::ServiceWaitYield> {
    let caller = channel.kernel_caller?;
    let recipient = (&*core::ptr::addr_of!(ACTIVATIONS)).recipient(caller).ok()?;
    if recipient.ps_retirement().is_none()
        || recipient.resumed_from_wait()
        || !recipient.matches(channel)
    {
        return None;
    }
    // An adopted service Call can change the canonical Reply inside this pump.
    let current = recipient.execution_channel(caller).ok()?;
    if authenticated_channel_caller(&current) != Ok(caller) {
        return None;
    }
    let route = ingress::channel_route(&current).ok().flatten()?;
    let dispatch = ingress::dispatch(route).ok()?;
    if dispatch != caller.dispatch() {
        return None;
    }
    let (reply, token) = ingress::parked_service_wait_identity(route, dispatch).ok().flatten()?;
    (driver_launch::win32k_source_ioctl_inline_terminal(route, dispatch, reply, token)
        == Some(KernelSourceTerminal::Unacknowledged))
        .then_some(win32k_glue::ServiceWaitYield { route, dispatch, reply, token })
}

/// Lend the publication of an observed source-work stop. A refusal has no effect: the stop
/// stays owned by its activation and is reported through the existing incomplete path.
pub(super) unsafe fn park(
    caller: KernelProviderCaller,
    publication: win32k_glue::KernelJobPublication,
) -> Result<ParkedSourceWork, u32> {
    let wait = (&*core::ptr::addr_of!(ACTIVATIONS))
        .recipient(caller)?
        .observation()
        .and_then(|pump| pump.service_wait_yield)
        .ok_or(nt_process::STATUS_INVALID_PARAMETER)?;
    let page = win32k_glue::park_kernel_job_publication(publication)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY.raw() as u32)?;
    trace_source_work(b"parked", caller, wait, 0);
    Ok(ParkedSourceWork { wait, page })
}

/// Continue the receive half once. The entry is claimed from the retained activation before
/// any restoration, so every later failure retains an uncertain pump and is never replayed.
pub(super) unsafe fn resume(
    caller: KernelProviderCaller,
    parked: ParkedSourceWork,
    publication: win32k_glue::KernelJobPublication,
) -> Result<KernelJobOutcome, u32> {
    let scope = driver_launch::ComponentSchedulerScope::enter();
    let terminal = parked.terminal();
    // A recorded return retires the recipient; keep its target for the final trace line.
    let tid = ps_target_tid(caller);
    let (channel, attempt, previous) = with_provider_process_manager(|pm| {
        let activations = &mut *core::ptr::addr_of_mut!(ACTIVATIONS);
        // The continued receive half retires the acknowledged service token itself, so the
        // lane is still suspended here and only retained authority can be checked.
        activations.validate_retained(
            caller,
            pm,
            &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
            &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS),
        )?;
        activations
            .recipient_mut(caller)?
            .begin_receive_after_source_work(caller, terminal)
    })?;
    // The target's effective attachment first, then the job's own page over whatever the
    // terminal and any other owner published while it was lent.
    if let Err(status) = restore_ps_retirement_window(caller, &channel) {
        return Err(retain_driver_entry_uncertain(caller, attempt, channel, None, None, status));
    }
    if !win32k_glue::restore_kernel_job_publication(publication, parked.page) {
        return Err(retain_driver_entry_uncertain(
            caller, attempt, channel, None, None, nt_process::STATUS_INVALID_PARAMETER,
        ));
    }
    trace_source_work(b"resuming", caller, parked.wait, 0);
    let mut attempt = attempt;
    // No coordinator, recipient or process-manager borrow crosses this real Recv.
    let result = match spawn_hosts::component_pump_continue_kernel_source_work(&channel, &previous) {
        Ok(result) => result,
        Err(status) => {
            return Err(retain_driver_entry_uncertain(caller, attempt, channel, None, None, status));
        }
    };
    if result.provider_wait_capture_refusal.is_some() {
        return Err(retain_driver_entry_capture_refusal(caller, attempt, channel, result, None));
    }
    if let Err(status) = observe_driver_entry_pump(&channel, &mut attempt, &result) {
        return Err(retain_driver_entry_uncertain(
            caller, attempt, channel, Some(result), None, status,
        ));
    }
    let outcome = finish_entered_kernel_job(&scope, caller, result)?;
    use nt_user_host::provider_kernel_wait::KernelProviderStoppedOutcome as Stop;
    let (stage, detail): (&[u8], u64) = match outcome.stop {
        Stop::Returned(status) => (b"returned", u64::from(status)),
        Stop::SourceWorkYielded => (b"yielded-again", 0),
        Stop::WaitCaptured(_) => (b"wait-captured", 0),
        _ => (b"stopped", 0),
    };
    trace_source_work_for(stage, caller, tid, parked.wait, detail);
    Ok(outcome)
}

static STOP_TRACES: AtomicU64 = AtomicU64::new(0);

/// Bounded evidence for a kernel job that leaves its runner without a return. Read-only.
pub(super) unsafe fn trace_stop(caller: KernelProviderCaller, stage: &[u8], status: u32) {
    use nt_user_host::provider_kernel_wait::KernelProviderStoppedOutcome as Stop;
    if STOP_TRACES.fetch_add(1, Ordering::Relaxed) >= 32 {
        return;
    }
    let recipient = (&*core::ptr::addr_of!(ACTIVATIONS)).recipient(caller).ok();
    let stop: &[u8] = match recipient.map(KernelJobRecipient::stopped_outcome) {
        Some(Ok(Stop::Returned(_))) => b"returned",
        Some(Ok(Stop::WaitCaptured(_))) => b"wait-captured",
        Some(Ok(Stop::Walled)) => b"walled",
        Some(Ok(Stop::CallbackSuspended)) => b"callback-suspended",
        Some(Ok(Stop::LpcWaitSuspended)) => b"lpc-wait-suspended",
        Some(Ok(Stop::SourceWorkYielded)) => b"source-work-yielded",
        Some(Err(_)) => b"unobserved",
        None => b"no-recipient",
    };
    let pump = recipient.and_then(KernelJobRecipient::observation);
    // completed/callback/provider-wait/lpc/scheduler/service-wait/nested-restore/refusal
    let flags = pump.map_or(u64::MAX, |pump| {
        u64::from(pump.completed)
            | u64::from(pump.callback_suspended) << 1
            | u64::from(pump.provider_wait_suspended()) << 2
            | u64::from(pump.lpc_wait_suspended) << 3
            | u64::from(pump.scheduler_yielded) << 4
            | u64::from(pump.service_wait_yield.is_some()) << 5
            | u64::from(pump.nested_restore_yield.is_some()
                || pump.nested_restore_quarantined.is_some()) << 6
            | u64::from(pump.provider_wait_capture_refusal.is_some()) << 7
    });
    let lane = caller.dispatch().lane();
    let phase = match (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).phase(lane) {
        Ok(nt_component_suspension::LanePhase::Running) => 1,
        Ok(nt_component_suspension::LanePhase::Suspended) => 2,
        Ok(nt_component_suspension::LanePhase::NestedExecution(_)) => 3,
        Ok(nt_component_suspension::LanePhase::Idle) => 4,
        Ok(_) => 5,
        Err(_) => 0,
    };
    let (pi, tid) = recipient
        .and_then(KernelJobRecipient::ps_retirement)
        .map_or((0, 0), |(pi, target)| (u64::from(pi), u64::from(target.thread().thread_id())));
    print_str(b"[kernel-job-stop] stage=");
    print_str(stage);
    print_str(b" stop=");
    print_str(stop);
    print_str(b" status/pump-flags/wall-label/wall-ip/lane/lane-gen/lane-phase/dispatch/ps-pi/ps-tid=");
    for value in [
        u64::from(status), flags,
        pump.map_or(0, |pump| pump.wall_label), pump.map_or(0, |pump| pump.wall_ip),
        u64::from(lane.index), lane.generation, phase, caller.owner().dispatch_id, pi, tid,
    ] {
        print_str(b"/");
        print_hex_u64(value);
    }
    print_str(b"\n");
}
