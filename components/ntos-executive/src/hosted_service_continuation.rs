//! Services whose inner pump stopped unfinished (#420).
//!
//! A service the running lane X called pumps another component. When that pump stops before
//! its dispatch finishes, the service has no result yet. The contract is
//! `nt_component_suspension::ServiceContinuations`:
//!
//! - With a lane X, the service registers its typed post-pump step and the kept pump, and X's
//!   parent stays parked (`ServiceAwait`). X's pump intercepts the reply it was about to send
//!   and yields that parent's restore to X's owner, whose retries are no-effect refusals
//!   until the service settles. The kept pump is driven at root boundaries; when it finishes,
//!   the step builds X's true reply, the parent is handed to X's owner, and the restore's
//!   receive continuation sends that reply first.
//! - At root level there is no X: the caller waits in a root progress loop and returns the
//!   true result itself.
//!
//! A fenced inner pump never runs its step and never replies; every resource stays held.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime::nested;
use nt_component_suspension::{PumpProgress, ServiceContinuations, SettledParent};

/// X's true reply. The intercepted envelope supplies its Reply object and, unless the step
/// names one, its message shape.
#[derive(Clone, Copy)]
pub(crate) struct ServiceReply {
    pub(crate) info: Option<u64>,
    pub(crate) words: [u64; 4],
}

impl ServiceReply {
    /// A one-word status reply, the shape of most service labels.
    pub(crate) fn status(status: i32) -> Self {
        Self { info: None, words: [status as u32 as u64, 0, 0, 0] }
    }
}

/// The post-pump half of one service, typed per family. It runs once on the true result.
pub(crate) enum ServiceStep {
    /// `ZwUnloadDriver` from a hosted driver: finish the unload and reply its status.
    ZwUnloadDriver(crate::driver_launch::hosted_zw_load_driver::PendingZwUnload),
}

impl ServiceStep {
    unsafe fn complete(self, result: crate::spawn_hosts::PumpResult) -> ServiceReply {
        match self {
            Self::ZwUnloadDriver(pending) => ServiceReply::status(pending.finish(result)),
        }
    }
}

type Services = ServiceContinuations<
    nested::NestedRestoreTicket, nested::ParkedParentHandle, ServiceStep, HostedPumpRestore,
    crate::spawn_hosts::DeferredReply, ServiceReply,
>;

static mut SERVICES: Services = ServiceContinuations::new();
/// Unfinished pumps whose caller already saw an uncertain result. The root still drives each
/// retryable one to the end of its dispatch, so its lanes and rows are released; nothing is
/// replayed, and a non-retryable one stays fenced with every resource.
static mut FENCED: Vec<HostedPumpRestore> = Vec::new();

fn services() -> &'static mut Services {
    unsafe { &mut *core::ptr::addr_of_mut!(SERVICES) }
}

/// An unfinished pump and the parked parent of the lane X whose service ran it. Only the
/// service that owns the whole post-pump state may register its step; every frame between
/// returns this upward without any effect.
#[must_use = "register the service's step, or fence the pump"]
pub(crate) struct KeptPump {
    pump: HostedPumpRestore,
    parent: nested::ParkedParentHandle,
}

/// How a service's pump ended for its caller.
#[must_use = "a kept pump is owed a registered step or a fence"]
pub(crate) enum ServicePump {
    /// The dispatch finished; this is its true result.
    Finished(crate::spawn_hosts::PumpResult),
    /// Unfinished while lane X is parked for it.
    Kept(KeptPump),
    /// Unfinished and nothing can own its continuation. It is fenced with every resource it
    /// holds; the caller sees an uncertain, never completed, result.
    Fenced(crate::spawn_hosts::PumpResult),
}

/// Settle a pump whose channel parked the running lane itself (`ReplyRequest`). At root
/// level, where there is no lane X, the caller waits here and receives the true result.
pub(in crate::driver_launch) unsafe fn settle(pump: HostedPumpRestore) -> ServicePump {
    match pump {
        HostedPumpRestore::Restored(result) | HostedPumpRestore::Unattributed(result) =>
            ServicePump::Finished(result),
        HostedPumpRestore::Retained { result, ticket, .. } => {
            // The dispatch finished; only the outer parent's restore is owed, and the running
            // lane's reply waits for it.
            crate::spawn_hosts::defer_reply_until_ticket_restored(ticket);
            ServicePump::Finished(result)
        }
        mut unfinished => match unfinished.take_outer_parent() {
            Some(parent) => ServicePump::Kept(KeptPump { pump: unfinished, parent }),
            None if !component_scheduler::is_active() => await_at_root(unfinished),
            None => ServicePump::Fenced(fence_pump(unfinished, b"scheduler-scope")),
        },
    }
}

impl KeptPump {
    /// Keep `step` instead of replying. X's pump intercepts its next reply and yields the
    /// parent; the step replies once the pump finishes. A refusal fences the pump and
    /// returns its uncertain result for the service to report.
    pub(crate) unsafe fn register(
        self, step: ServiceStep,
    ) -> Result<(), crate::spawn_hosts::PumpResult> {
        let Self { pump, parent } = self;
        if nested::await_service(&parent).is_err() {
            return Err(fence_with_parent(pump, parent, b"parent"));
        }
        let ticket = parent.ticket();
        match services().register(ticket, parent, step, pump) {
            Ok(()) => {
                trace(b"registered", ticket);
                Ok(())
            }
            Err(refused) => {
                // No row can reply to X: hand its parent back, and let X's reply wait for it.
                if let Ok(ticket) = nested::finish_service_await(refused.parent) {
                    crate::spawn_hosts::defer_reply_until_ticket_restored(ticket);
                }
                Err(fence_pump(refused.pump, b"capacity"))
            }
        }
    }

    /// A service with no step for this pump: fence it and release X with an uncertain result.
    pub(crate) unsafe fn fence(self) -> crate::spawn_hosts::PumpResult {
        fence_with_parent(self.pump, self.parent, b"no-step")
    }
}

/// X's parent is released for an uncertain reply: restored now, or its reply waits for it.
unsafe fn fence_with_parent(
    pump: HostedPumpRestore, parent: nested::ParkedParentHandle, reason: &[u8],
) -> crate::spawn_hosts::PumpResult {
    let mut parent = Some(parent);
    if nested::restore(&mut parent).is_err() {
        if let Some(parent) = parent {
            crate::spawn_hosts::defer_reply_until_restored(parent);
        }
    }
    fence_pump(pump, reason)
}

unsafe fn fence_pump(pump: HostedPumpRestore, reason: &[u8]) -> crate::spawn_hosts::PumpResult {
    let mut result = pump.result();
    result.completed = false;
    result.scheduler_yielded = false;
    result.nested_restore_yield = None;
    result.nested_restore_quarantined = None;
    result.nested_child_work = None;
    result.status = nt_status::NtStatus::DEVICE_BUSY.raw();
    print_str(b"[service-continuation] fenced reason=");
    print_str(reason);
    print_str(b"\n");
    // The pump keeps every row it holds. Without capacity its dropped handles hand those rows
    // to the root restore queue, which never replays an uncertain one.
    let fenced = &mut *core::ptr::addr_of_mut!(FENCED);
    if fenced.try_reserve(1).is_ok() { fenced.push(pump); }
    result
}

/// Root progress passes a runtime root waiter makes before it reports the pump uncertain.
const ROOT_WAIT_PASSES: usize = 64;

/// Root level only (no lane X, no scheduler scope): wait for the kept pump and return its true
/// result. Each pass services timer, IRQ and DPC work, retries the root-owned restores the pump
/// is usually waiting on, and continues the pump once. During boot the bootstrap receive owner
/// also receives between passes; at runtime the wait is bounded, and a pump that is still
/// unfinished keeps the fenced, uncertain outcome.
unsafe fn await_at_root(pump: HostedPumpRestore) -> ServicePump {
    if crate::dispatcher_bootstrap::is_owned() {
        let mut pump = Some(pump);
        let mut finished = None;
        let waited = crate::bootstrap_receive::drive((), || {
            match retry(pump.take().expect("kept root pump")) {
                PumpProgress::Finished(result) => { finished = Some(result); Ok(Some(true)) }
                PumpProgress::Unfinished(next) => { pump = Some(next); Ok(None) }
                PumpProgress::Fenced(next) => {
                    pump = Some(next);
                    Err(STATUS_UNSUCCESSFUL as u32)
                }
            }
        });
        return match (waited, finished) {
            (Ok(_), Some(result)) => { trace_root(b"boot-finished"); ServicePump::Finished(result) }
            _ => ServicePump::Fenced(fence_pump(pump.take().expect("unfinished root pump"),
                b"boot-wait")),
        };
    }
    let mut pump = pump;
    for _ in 0..ROOT_WAIT_PASSES {
        {
            let scope = component_scheduler::ComponentSchedulerScope::enter();
            drop(scope.service_irq_yield(0));
        }
        crate::service_sec_image::drain_root_restores();
        match retry(pump) {
            PumpProgress::Finished(result) => {
                trace_root(b"finished");
                return ServicePump::Finished(result);
            }
            PumpProgress::Unfinished(next) => pump = next,
            PumpProgress::Fenced(next) => return ServicePump::Fenced(fence_pump(next, b"root-fenced")),
        }
    }
    ServicePump::Fenced(fence_pump(pump, b"root-wait"))
}

fn trace_root(stage: &[u8]) {
    static TRACED: AtomicU64 = AtomicU64::new(0);
    let n = TRACED.fetch_add(1, Ordering::Relaxed) + 1;
    if n > 16 && !n.is_power_of_two() { return; }
    print_str(b"[service-continuation] root-wait n=");
    print_u64(n);
    print_str(b" stage=");
    print_str(stage);
    print_str(b"\n");
}

/// A caller with no continuation of its own: a root-level caller waits for the true result;
/// a lane caller's pump is fenced and the lane released with an uncertain result (#420 still
/// owes each such site a step).
pub(super) unsafe fn settle_without_step(pump: HostedPumpRestore) -> crate::spawn_hosts::PumpResult {
    match settle(pump) {
        ServicePump::Finished(result) | ServicePump::Fenced(result) => result,
        ServicePump::Kept(kept) => kept.fence(),
    }
}

/// Drive one kept pump once. Only a proven no-effect retry stays unfinished.
unsafe fn retry(pump: HostedPumpRestore) -> PumpProgress<HostedPumpRestore, crate::spawn_hosts::PumpResult> {
    if !pump.retryable_continuation() { return PumpProgress::Fenced(pump); }
    match component_scheduler::retry_child_work(pump) {
        HostedPumpRestore::Restored(result) | HostedPumpRestore::Unattributed(result) =>
            PumpProgress::Finished(result),
        unfinished if unfinished.retryable_continuation() => PumpProgress::Unfinished(unfinished),
        fenced => PumpProgress::Fenced(fenced),
    }
}

/// X's pump is about to reply on `ch`. A lane with a registered service sends nothing: its
/// envelope is kept and the parent whose restore X's owner now awaits is returned.
pub(crate) unsafe fn intercept(
    ch: &crate::spawn_hosts::PumpChannel, envelope: crate::spawn_hosts::DeferredReply,
) -> Option<nested::NestedRestoreTicket> {
    if services().is_empty() { return None; }
    let Ok(Some(route)) = crate::spawn_hosts::shared_ingress::owner::runtime::channel_route(ch)
    else { return None };
    let ticket = services()
        .intercept(|ticket| ticket.identity().route() == route, envelope).ok()?;
    trace(b"intercepted", ticket);
    Some(ticket)
}

/// After X's parent is restored: its service's reply, exactly once.
pub(crate) unsafe fn take_reply(
    ticket: nested::NestedRestoreTicket,
) -> Option<crate::spawn_hosts::DeferredReply> {
    let (envelope, reply) = services().take_reply(ticket)?;
    trace(b"replied", ticket);
    Some(envelope.with_words(reply.info, reply.words))
}

/// Root boundary only: drive each intercepted service's kept pump once, then each fenced one.
pub(crate) unsafe fn drive() -> usize {
    let mut finished = 0;
    if services().has_drivable() {
        // The pump and the step may reenter the registry (a nested service registers, a
        // nested lane replies), so drive from a snapshot and hold no borrow across either.
        let mut keys = Vec::new();
        if keys.try_reserve(services().drivable().count()).is_err() { return 0; }
        keys.extend(services().drivable());
        for key in keys {
            let settled = nt_component_suspension::drive_one(
                &mut (), |_| services(), key,
                |pump| retry(pump),
                |step, result| step.complete(result),
            );
            let Some(SettledParent { key, parent }) = settled else { continue };
            finished += 1;
            if nested::finish_service_await(parent).is_err() {
                trace(b"release-refused", key);
            } else {
                trace(b"settled", key);
            }
        }
    }
    let fenced = &mut *core::ptr::addr_of_mut!(FENCED);
    if fenced.iter().any(HostedPumpRestore::retryable_continuation) {
        for pump in core::mem::take(fenced) {
            match retry(pump) {
                PumpProgress::Finished(_) => finished += 1,
                PumpProgress::Unfinished(pump) | PumpProgress::Fenced(pump) =>
                    (&mut *core::ptr::addr_of_mut!(FENCED)).push(pump),
            }
        }
    }
    finished
}

fn trace(stage: &[u8], ticket: nested::NestedRestoreTicket) {
    static TRACED: AtomicU64 = AtomicU64::new(0);
    let n = TRACED.fetch_add(1, Ordering::Relaxed) + 1;
    if n > 32 && !n.is_power_of_two() { return; }
    print_str(b"[service-continuation] n=");
    print_u64(n);
    print_str(b" stage=");
    print_str(stage);
    print_str(b" lane=");
    print_u64(ticket.identity().dispatch().lane().index as u64);
    print_str(b"\n");
}
