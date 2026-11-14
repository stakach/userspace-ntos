//! Ps exit callouts parked in a provider wait, retained for the retirement that issued them.
//!
//! A hosted syscall that blocks in a provider wait leaves root: its Reply owner is resumed
//! when the wait is granted. A Ps exit callout has no hosted Reply, so its runner used to stay
//! on root's stack until the callout returned, and the wait's owner could never run. The
//! callout now leaves root the same way. Runtime readiness resumes its captured wait from the
//! service loop, and the retirement that issued it comes back here for the real return.

use super::*;
use nt_user_host::provider_kernel_wait::KernelProviderStoppedOutcome as Stop;
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;
use nt_user_host::provider_ps_callout::{KernelJobWaitHeartbeat, PendingPsCallouts};
pub(crate) use nt_user_host::provider_ps_callout::PsCalloutState;
use spawn_hosts::shared_ingress::owner::runtime as ingress;

/// One retirement's callout: the provider command and the exact exiting thread it is for.
#[derive(Clone, Copy)]
struct PsCalloutKey {
    command: u64,
    logical: ProviderLogicalCaller,
}

impl PartialEq for PsCalloutKey {
    fn eq(&self, other: &Self) -> bool {
        self.command == other.command
            && self.logical.process() == other.logical.process()
            && self.logical.thread() == other.logical.thread()
    }
}

struct ParkedPsCallout {
    caller: KernelProviderCaller,
    result: KernelJobResult,
}

fn returned(job: &ParkedPsCallout) -> Option<u32> {
    job.result.returned()
}

static mut PENDING: PendingPsCallouts<PsCalloutKey, ParkedPsCallout> = PendingPsCallouts::new();
static REDRIVE_ACTIVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static TRACES: AtomicU64 = AtomicU64::new(0);
static HEARTBEATS: AtomicU64 = AtomicU64::new(0);

/// Lifecycle lines are capped. Heartbeats have their own budget: the first eight, then
/// power-of-two samples, so one stuck job cannot hide a later callout's lifecycle.
fn trace_admitted(heartbeat: bool) -> bool {
    if heartbeat {
        let sample = HEARTBEATS.fetch_add(1, Ordering::Relaxed) + 1;
        sample <= 8 || sample.is_power_of_two()
    } else {
        TRACES.fetch_add(1, Ordering::Relaxed) < 256
    }
}

fn stop_name(stop: Result<Stop, u32>) -> &'static [u8] {
    match stop {
        Ok(Stop::Returned(_)) => b"returned",
        Ok(Stop::WaitCaptured(_)) => b"wait-captured",
        Ok(Stop::Walled) => b"walled",
        Ok(Stop::CallbackSuspended) => b"callback-suspended",
        Ok(Stop::LpcWaitSuspended) => b"lpc-wait-suspended",
        Ok(Stop::SourceWorkYielded) => b"source-work-yielded",
        Err(_) => b"executing-or-unobserved",
    }
}

unsafe fn lane_phase(caller: KernelProviderCaller) -> u64 {
    match (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).phase(caller.dispatch().lane()) {
        Ok(nt_component_suspension::LanePhase::Running) => 1,
        Ok(nt_component_suspension::LanePhase::Suspended) => 2,
        Ok(nt_component_suspension::LanePhase::NestedExecution(_)) => 3,
        Ok(nt_component_suspension::LanePhase::Idle) => 4,
        Ok(_) => 5,
        Err(_) => 0,
    }
}

/// The provider-wait key the job is parked in, when it has one.
unsafe fn wait_id(caller: KernelProviderCaller) -> u64 {
    (&*core::ptr::addr_of!(ACTIVATIONS))
        .recipient(caller)
        .ok()
        .and_then(|recipient| match recipient.stopped_outcome() {
            Ok(Stop::WaitCaptured(capture)) => Some(capture.key().id),
            _ => None,
        })
        .unwrap_or(0)
}

/// Bounded lifecycle evidence for one parked callout. Read-only.
unsafe fn trace(stage: &[u8], key: PsCalloutKey, caller: KernelProviderCaller, detail: u64) {
    if !trace_admitted(stage == b"waiting") {
        return;
    }
    let stop = (&*core::ptr::addr_of!(ACTIVATIONS))
        .recipient(caller)
        .and_then(KernelJobRecipient::stopped_outcome);
    print_str(b"[kernel-job-wait] stage=");
    print_str(stage);
    print_str(b" stop=");
    print_str(stop_name(stop));
    print_str(b" command/dispatch/lane/lane-phase/wait-id/ps-pi/ps-tid/detail=");
    for value in [
        key.command, caller.owner().dispatch_id, u64::from(caller.dispatch().lane().index),
        lane_phase(caller), wait_id(caller), key.logical.pi() as u64,
        u64::from(key.logical.thread().thread_id()), detail,
    ] {
        print_str(b"/");
        print_hex_u64(value);
    }
    print_str(b"\n");
}

/// Keep a parked callout for the retirement that issued it. A refusal leaves the job retained
/// by its activation and reported; that retirement must not issue the callout again.
pub(crate) unsafe fn retain(
    caller: KernelProviderCaller,
    command: u64,
    logical: ProviderLogicalCaller,
    result: KernelJobResult,
) -> bool {
    let _durable = allocator::enter_durable();
    let key = PsCalloutKey { command, logical };
    let retained = (&mut *core::ptr::addr_of_mut!(PENDING))
        .retain(key, ParkedPsCallout { caller, result }, monotonic_time_100ns())
        .is_ok();
    trace(if retained { b"parked" } else { b"retain-refused" }, key, caller, 0);
    retained
}

/// The retirement asks for the callout it issued. A real return is handed over exactly once.
pub(crate) unsafe fn settle(command: u64, logical: ProviderLogicalCaller) -> PsCalloutState {
    let key = PsCalloutKey { command, logical };
    let pending = &mut *core::ptr::addr_of_mut!(PENDING);
    let caller = pending.job(&key).map(|job| job.caller);
    let state = pending.settle(&key, returned);
    if let (PsCalloutState::Returned(status), Some(caller)) = (state, caller) {
        trace(b"returned", key, caller, u64::from(status));
    }
    state
}

/// Service-loop pass. Bring each returned callout back to its retirement, which takes the
/// result through `settle`, and report callouts that are still waiting.
pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler, queue: &mut nt_delay_execution::Queue) {
    if (&*core::ptr::addr_of!(PENDING)).is_empty()
        || REDRIVE_ACTIVE.swap(true, Ordering::AcqRel)
    {
        return;
    }
    struct Active;
    impl Drop for Active {
        fn drop(&mut self) {
            REDRIVE_ACTIVE.store(false, Ordering::Release);
        }
    }
    let _active = Active;
    // One retirement attempt per returned callout per pass. A retirement still blocked by
    // another dependency leaves its result retained here for the next pass.
    let mut attempted = 0;
    while attempted < (&*core::ptr::addr_of!(PENDING)).len() {
        let Some(key) = (&*core::ptr::addr_of!(PENDING))
            .nth_returned(attempted, returned)
            .copied()
        else {
            break;
        };
        let before = (&*core::ptr::addr_of!(PENDING)).len();
        let retired = crate::hosted_termination::reconcile(handler, queue, key.logical);
        if retired {
            // The initiating syscall has already left without a Reply; finish the process
            // tail it would have run once its last mechanism was reclaimed.
            let _ = handler.try_delete_hosted_process_object(key.logical.process().pid);
            handler.refresh_process_manager_gates();
        }
        if (&*core::ptr::addr_of!(PENDING)).len() != before {
            continue;
        }
        if retired {
            // The retirement completed, or its thread is gone, without asking again. The
            // provider's return has no remaining consumer; release only this result slot.
            let caller = (&*core::ptr::addr_of!(PENDING)).job(&key).map(|job| job.caller);
            let _ = (&mut *core::ptr::addr_of_mut!(PENDING)).settle(&key, returned);
            if let Some(caller) = caller {
                trace(b"unclaimed", key, caller, 0);
            }
        } else {
            attempted += 1;
        }
    }
    let now = monotonic_time_100ns();
    loop {
        let pending = &mut *core::ptr::addr_of_mut!(PENDING);
        let Some((key, age)) = pending.next_heartbeat(now, returned).map(|(key, age)| (*key, age))
        else {
            break;
        };
        let Some(caller) = pending.job(&key).map(|job| job.caller) else { break };
        trace(b"waiting", key, caller, age / 10_000);
    }
}

/// Heartbeat of the runner's remaining nested wait loop: what stopped the job, which arrivals
/// the loop has seen and whether timer delivery is still alive.
pub(super) struct RunnerHeartbeat {
    pacing: KernelJobWaitHeartbeat,
    notifications: u64,
    calls: u64,
    hosted: u64,
}

impl RunnerHeartbeat {
    pub(super) fn new() -> Self {
        Self {
            pacing: KernelJobWaitHeartbeat::new(monotonic_time_100ns()),
            notifications: 0,
            calls: 0,
            hosted: 0,
        }
    }

    pub(super) fn arrived(&mut self, arrival: &ingress::Arrival) {
        match arrival {
            ingress::Arrival::Notification(_) => self.notifications += 1,
            ingress::Arrival::Call { .. } => self.calls += 1,
            ingress::Arrival::Hosted => self.hosted += 1,
        }
    }

    pub(super) unsafe fn report(&mut self, caller: KernelProviderCaller, stop: Stop) {
        let Some(age) = self.pacing.due(monotonic_time_100ns()) else { return };
        if !trace_admitted(true) {
            return;
        }
        print_str(b"[kernel-job-wait] stage=runner stop=");
        print_str(stop_name(Ok(stop)));
        print_str(b" dispatch/lane/lane-phase/wait-id/age-ms/notifications/calls/hosted/ticks-pending/timer-work=");
        for value in [
            caller.owner().dispatch_id, u64::from(caller.dispatch().lane().index),
            lane_phase(caller), wait_id(caller), age / 10_000,
            self.notifications, self.calls, self.hosted,
            DELAY_TIMER_TICKS_PENDING.load(Ordering::Acquire),
            u64::from(crate::dispatcher_bootstrap::timer_work_pending()),
        ] {
            print_str(b"/");
            print_hex_u64(value);
        }
        print_str(b"\n");
    }
}
