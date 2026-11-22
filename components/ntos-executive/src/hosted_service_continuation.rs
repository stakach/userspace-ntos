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
use nt_component_suspension::{
    Completion, PumpProgress, ServiceContinuations, ServiceReservation, SettledParent,
};

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
    /// `ZwLoadDriver` from a hosted driver: the rest of DriverEntry's load (publication,
    /// reinitialization callbacks, rollback) and its status.
    ZwLoadDriver(crate::driver_launch::hosted_zw_load_driver::PendingZwLoad),
    /// A hosted dependent's provider export: the dispatch's finish and the export's tail.
    ProviderExport(crate::driver_launch::ProviderExportStep),
    /// A routed WDDM bridge call from win32k: the worker finish and the caller write-back.
    WddmBridge(crate::driver_launch::WddmBridgeStep),
    /// A provider's callback into a dependent: the target's finish, every adapter tail and
    /// the service's outer tail.
    ProviderCallback(crate::driver_launch::ProviderCallbackStep),
    /// A class driver's CONNECT forward: the kept alias or configure stage, the remaining
    /// stages and the tail that parks the class driver's Call.
    ConnectSubmit(crate::driver_launch::PendingConnectSubmit),
}

/// What a step owes X once its pump has returned: a reply, or (for a CONNECT submit whose
/// stages all returned) parking X's Call on its retained service, which only X's restored
/// receive may do.
pub(crate) enum ServiceAnswer {
    Reply(ServiceReply),
    ParkConnect(crate::driver_launch::ParkedConnect),
}

/// What X's restored receive does first.
pub(crate) enum ServiceDelivery {
    Reply(crate::spawn_hosts::DeferredReply),
    /// Park the Call, then reply the returned status if parking was refused.
    ParkConnect(crate::spawn_hosts::DeferredReply, crate::driver_launch::ParkedConnect),
}

impl ServiceStep {
    /// Run the step once at a root boundary, where X is parked: a CONNECT park is handed to
    /// X's restored receive instead of being made here.
    pub(crate) unsafe fn answer(self, result: crate::spawn_hosts::PumpResult) -> ServiceAnswer {
        if let Self::ZwLoadDriver(pending) = self {
            use crate::driver_launch::hosted_zw_load_driver::ZwLoadRun;
            return match pending.complete(result) {
                ZwLoadRun::Reply(status) => ServiceAnswer::Reply(ServiceReply::status(status)),
                // A reinitialization callback stopped unfinished: it continues this same row.
                ZwLoadRun::Kept(kept, pending) => match kept.register(
                    continuing_slot(), Self::ZwLoadDriver(pending),
                ) {
                    Ok(()) => ServiceAnswer::Reply(ServiceReply::status(nt_status::NtStatus::PENDING.raw())),
                    Err((uncertain, step)) => step.answer(uncertain),
                },
            };
        }
        let Self::ConnectSubmit(pending) = self else {
            return ServiceAnswer::Reply(self.complete(result));
        };
        use crate::driver_launch::SubmitRun;
        match pending.complete(result) {
            SubmitRun::Reply((status, accepted)) => ServiceAnswer::Reply(ServiceReply {
                info: None, words: [status as u32 as u64, u64::from(accepted), 0, 0],
            }),
            SubmitRun::Park(parked) => ServiceAnswer::ParkConnect(parked),
            // A later stage stopped unfinished: it continues this same row.
            SubmitRun::Kept(kept, pending) => match kept.register(
                continuing_slot(), Self::ConnectSubmit(pending),
            ) {
                Ok(()) => ServiceAnswer::Reply(ServiceReply::status(nt_status::NtStatus::PENDING.raw())),
                Err((uncertain, step)) => step.answer(uncertain),
            },
        }
    }

    /// Run the step once on its pump's result. A refused registration runs it at once on the
    /// uncertain result, so the service's own tail still releases what it holds.
    pub(crate) unsafe fn complete(self, result: crate::spawn_hosts::PumpResult) -> ServiceReply {
        match self {
            // Runs where the service runs, with X executing: a park is made at once.
            Self::ConnectSubmit(_) => match self.answer(result) {
                ServiceAnswer::Reply(reply) => reply,
                ServiceAnswer::ParkConnect(parked) => match parked.park() {
                    Some((status, accepted)) => ServiceReply {
                        info: None, words: [status as u32 as u64, u64::from(accepted), 0, 0],
                    },
                    None => ServiceReply::status(nt_status::NtStatus::PENDING.raw()),
                },
            },
            Self::ZwUnloadDriver(pending) => ServiceReply::status(pending.finish(result)),
            // Runs where the service runs: a further kept pump has no row of its own here, so
            // it is answered on the uncertain result through `answer`.
            Self::ZwLoadDriver(_) => match self.answer(result) {
                ServiceAnswer::Reply(reply) => reply,
                ServiceAnswer::ParkConnect(_) => unreachable!("a load never parks a CONNECT"),
            },
            Self::ProviderExport(step) => ServiceReply::status(step.complete(result) as u32 as i32),
            Self::ProviderCallback(step) =>
                ServiceReply { info: None, words: [step.complete(result), 0, 0, 0] },
            Self::WddmBridge(step) => {
                let (status, value) = step.complete(result);
                ServiceReply { info: None, words: [status as u32 as u64, value, 0, 0] }
            }
        }
    }
}

type Services = ServiceContinuations<
    nested::NestedRestoreTicket, nested::ParkedParentHandle, ServiceStep, HostedPumpRestore,
    crate::spawn_hosts::DeferredReply, ServiceAnswer,
>;

static mut SERVICES: Services = ServiceContinuations::new();
/// Unfinished pumps whose caller already saw an uncertain result. The root still drives each
/// retryable one to the end of its dispatch, so its lanes and rows are released; nothing is
/// replayed, and a non-retryable one stays fenced with every resource.
static mut FENCED: Vec<HostedPumpRestore> = Vec::new();

fn services() -> &'static mut Services {
    unsafe { &mut *core::ptr::addr_of_mut!(SERVICES) }
}

/// One continuation row's capacity, held by a lane's service from before it enters any
/// dispatch, so keeping its step can never be refused for capacity after an entered effect.
#[must_use = "hold the slot until the service has replied or registered its step"]
pub(crate) struct ServiceSlot(Option<ServiceReservation>);

impl ServiceSlot {
    fn take(&mut self) -> Option<ServiceReservation> { self.0.take() }
}

impl Drop for ServiceSlot {
    fn drop(&mut self) {
        if let Some(reservation) = self.0.take() { services().release(reservation); }
    }
}

/// A step's own tail keeping another pump continues the step's existing row; it needs no
/// capacity of its own.
pub(crate) fn continuing_slot() -> ServiceSlot { ServiceSlot(None) }

/// Reserve before the service enters anything; a refusal is a pre-entry resource failure.
pub(crate) unsafe fn reserve_slot() -> Result<ServiceSlot, i32> {
    let _durable = crate::allocator::enter_durable();
    services().reserve().map(|reservation| ServiceSlot(Some(reservation)))
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)
}

/// The service step currently running at a root boundary. A pump its tail enters that stops
/// unfinished is kept for the same parked parent ([`Completion::Again`]), never waited for.
static mut CONTINUING: Option<nested::NestedRestoreTicket> = None;
/// The remaining step and pump such a tail kept, collected when its step returns.
static mut CONTINUED: Option<(nested::NestedRestoreTicket, ServiceStep, HostedPumpRestore)> = None;

struct ContinuingScope(Option<nested::NestedRestoreTicket>);
impl ContinuingScope {
    unsafe fn enter(key: nested::NestedRestoreTicket) -> Self {
        Self(core::mem::replace(&mut *core::ptr::addr_of_mut!(CONTINUING), Some(key)))
    }
}
impl Drop for ContinuingScope {
    fn drop(&mut self) { unsafe { *core::ptr::addr_of_mut!(CONTINUING) = self.0; } }
}

/// Whether a service step is running at this root boundary (its pumps are its own).
pub(super) unsafe fn continuing_service() -> bool { continuing().is_some() }

unsafe fn continuing() -> Option<nested::NestedRestoreTicket> {
    // Only at the root boundary that runs the step; a nested scope has its own owner.
    if component_scheduler::is_active() { return None; }
    *core::ptr::addr_of!(CONTINUING)
}

/// Whose wait an unfinished pump's service is: lane X's parked parent, or the step of a
/// service already continuing for X.
enum KeptParent {
    Parked(nested::ParkedParentHandle),
    Continuing(nested::NestedRestoreTicket),
}

/// An unfinished pump and the parked parent of the lane X whose service ran it. Only the
/// service that owns the whole post-pump state may register its step; every frame between
/// returns this upward without any effect.
#[must_use = "register the service's step, or fence the pump"]
pub(crate) struct KeptPump {
    pump: HostedPumpRestore,
    parent: KeptParent,
}

/// How a service's pump ended for its caller.
#[must_use = "a kept pump is owed a registered step or a fence"]
pub(crate) enum ServicePump {
    /// The dispatch finished; this is its true result.
    Finished(crate::spawn_hosts::PumpResult),
    /// Unfinished while lane X is parked for it.
    Kept(KeptPump),
    /// Unfinished at root level inside a turn that may not block. The caller's own owner
    /// keeps it and the next root turn continues it ([`RootTurnPump`]).
    RootTurn(RootTurnPump),
    /// The pump entered an uncertain effect. It is fenced with every resource it holds; the
    /// caller sees an uncertain, never completed, result.
    Fenced(crate::spawn_hosts::PumpResult),
}

/// A root-level pump whose caller runs inside a turn that may not block (#420). Its owner
/// keeps it in a typed retained row and calls [`RootTurnPump::resume`] from a later root turn,
/// where the caller's result is finished with the true outcome.
#[must_use = "a root-turn pump is owed a retained owner"]
pub(crate) struct RootTurnPump {
    pump: HostedPumpRestore,
}

/// One root turn's attempt at a retained root pump.
pub(crate) enum RootTurnProgress {
    Finished(crate::spawn_hosts::PumpResult),
    Pending(RootTurnPump),
    /// The pump entered an uncertain effect.
    Fenced(crate::spawn_hosts::PumpResult),
}

impl RootTurnPump {
    /// Continue the pump once from a root turn; a frame that may block waits for it here.
    pub(crate) unsafe fn resume(self) -> RootTurnProgress {
        if crate::service_sec_image::root_wait_may_block() {
            return match await_at_root(self.pump) {
                ServicePump::Finished(result) => RootTurnProgress::Finished(result),
                ServicePump::RootTurn(pump) => RootTurnProgress::Pending(pump),
                ServicePump::Fenced(result) => RootTurnProgress::Fenced(result),
                ServicePump::Kept(kept) => RootTurnProgress::Fenced(kept.fence()),
            };
        }
        match retry(self.pump) {
            PumpProgress::Finished(result) => RootTurnProgress::Finished(result),
            PumpProgress::Unfinished(pump) => RootTurnProgress::Pending(Self { pump }),
            PumpProgress::Fenced(pump) => RootTurnProgress::Fenced(fence_pump(pump, b"root-turn")),
        }
    }

    /// Whether a root turn can continue it.
    pub(crate) fn retryable(&self) -> bool { self.pump.retryable_continuation() }

    /// A caller with no retained owner for a root turn: the pump is fenced and driven to the
    /// end of its dispatch, and the caller sees an uncertain result. Each such caller is still
    /// owed a typed retained row (#420); the marker names them.
    pub(crate) unsafe fn fence_unowned(self) -> crate::spawn_hosts::PumpResult {
        fence_pump(self.pump, b"root-turn-unowned")
    }
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
            Some(parent) =>
                ServicePump::Kept(KeptPump { pump: unfinished, parent: KeptParent::Parked(parent) }),
            None => match continuing() {
                Some(key) => ServicePump::Kept(KeptPump {
                    pump: unfinished, parent: KeptParent::Continuing(key),
                }),
                None => settle_parentless(unfinished),
            },
        },
    }
}

/// Settle a `RecvFirst` pump whose caller parked lane X itself (DriverEntry). An unfinished
/// pump keeps the caller's parent, which is therefore not restored early; a finished one
/// leaves the parent with the caller, which restores it as before.
pub(in crate::driver_launch) unsafe fn settle_parked(
    pump: HostedPumpRestore, parent: &mut Option<nested::ParkedParentHandle>,
) -> ServicePump {
    let unfinished = !matches!(pump, HostedPumpRestore::Restored(_)
        | HostedPumpRestore::Unattributed(_) | HostedPumpRestore::Retained { .. });
    match parent.take() {
        Some(handle) if unfinished =>
            ServicePump::Kept(KeptPump { pump, parent: KeptParent::Parked(handle) }),
        handle => {
            *parent = handle;
            settle(pump)
        }
    }
}

/// Settle an owned File dispatch's pump (#420). The File row is a real owner: a pump with no
/// lane X that cannot be waited for here (a root turn that may not block, a nested child step,
/// a scheduler service) is returned unfinished for the row to keep and a later root boundary
/// to resume. A root caller that may block still waits here for the true result.
pub(in crate::driver_launch) unsafe fn settle_for_file_owner(
    pump: HostedPumpRestore,
) -> HostedPumpRestore {
    let unfinished = !matches!(pump, HostedPumpRestore::Restored(_)
        | HostedPumpRestore::Unattributed(_) | HostedPumpRestore::Retained { .. });
    // A pump parked in its own wait is kept even where root could block: the root progress
    // loop delivers no hosted syscall, and its wake may need one (#420, #427 A).
    if unfinished && nt_component_suspension::settle_unfinished(
        matches!(pump, HostedPumpRestore::ParkedDispatchWait(_)),
        pump.has_outer_parent(),
        continuing().is_some(),
        component_scheduler::is_active(),
        crate::service_sec_image::root_wait_may_block(),
    ) == nt_component_suspension::UnfinishedSettle::Keep
    {
        trace_file_owner(b"retained");
        return pump;
    }
    match settle(pump) {
        ServicePump::Finished(result) | ServicePump::Fenced(result) =>
            HostedPumpRestore::Restored(result),
        ServicePump::RootTurn(turn) => turn.pump,
        // No File chain runs under a lane's service (call-context map); one that did has no
        // step for that lane's reply.
        ServicePump::Kept(kept) => HostedPumpRestore::Restored(kept.fence()),
    }
}

fn trace_file_owner(stage: &[u8]) {
    static TRACED: AtomicU64 = AtomicU64::new(0);
    let n = TRACED.fetch_add(1, Ordering::Relaxed) + 1;
    if n > 16 && !n.is_power_of_two() { return; }
    print_str(b"[service-continuation] file-owner n=");
    print_u64(n);
    print_str(b" stage=");
    print_str(stage);
    print_str(b"\n");
}

/// No lane X and no continuing step: root level waits; a nested scope has no owner yet.
unsafe fn settle_parentless(unfinished: HostedPumpRestore) -> ServicePump {
    if component_scheduler::is_active() {
        ServicePump::Fenced(fence_pump(unfinished, b"scheduler-scope"))
    } else {
        await_at_root(unfinished)
    }
}

impl KeptPump {
    /// Keep `step` instead of replying. X's pump intercepts its next reply and yields the
    /// parent; the step replies once the pump finishes. A refusal fences the pump and hands
    /// back the step with the uncertain result, so the service still runs its own tail.
    pub(crate) unsafe fn register(
        self, mut slot: ServiceSlot, step: ServiceStep,
    ) -> Result<(), (crate::spawn_hosts::PumpResult, ServiceStep)> {
        let Self { pump, parent } = self;
        let parent = match parent {
            KeptParent::Parked(parent) => parent,
            KeptParent::Continuing(key) => {
                // The running step collects this as its remaining continuation.
                let continued = &mut *core::ptr::addr_of_mut!(CONTINUED);
                if continued.is_some() {
                    return Err((fence_pump(pump, b"continued-twice"), step));
                }
                *continued = Some((key, step, pump));
                trace(b"continued", key);
                return Ok(());
            }
        };
        if nested::await_service(&parent).is_err() {
            return Err((fence_with_parent(pump, parent, b"parent"), step));
        }
        let ticket = parent.ticket();
        let Some(reservation) = slot.take() else {
            return Err((fence_with_parent(pump, parent, b"slot"), step));
        };
        match services().register_reserved(reservation, ticket, parent, step, pump) {
            Ok(()) => {
                trace(b"registered", ticket);
                Ok(())
            }
            Err(refused) => {
                // No row can reply to X: hand its parent back, and let X's reply wait for it.
                if let Ok(ticket) = nested::finish_service_await(refused.parent) {
                    crate::spawn_hosts::defer_reply_until_ticket_restored(ticket);
                }
                Err((fence_pump(refused.pump, b"duplicate"), refused.step))
            }
        }
    }

    /// A service with no step for this pump: fence it and release X with an uncertain result.
    pub(crate) unsafe fn fence(self) -> crate::spawn_hosts::PumpResult {
        match self.parent {
            KeptParent::Parked(parent) => fence_with_parent(self.pump, parent, b"no-step"),
            KeptParent::Continuing(_) => fence_pump(self.pump, b"no-step"),
        }
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

/// Root-level waiters currently driving a kept pump. Their held lane is their own execution,
/// not a busy component that would keep the bootstrap owner from receiving.
static ROOT_WAITS: AtomicU64 = AtomicU64::new(0);

/// Whether a root-level waiter owns the execution the bootstrap receive owner sees as busy.
pub(crate) fn root_wait_owns_execution() -> bool { ROOT_WAITS.load(Ordering::Acquire) != 0 }

struct RootWaitScope;
impl RootWaitScope {
    fn enter() -> Self { ROOT_WAITS.fetch_add(1, Ordering::AcqRel); Self }
}
impl Drop for RootWaitScope {
    fn drop(&mut self) { ROOT_WAITS.fetch_sub(1, Ordering::AcqRel); }
}

/// Root level only (no lane X, no scheduler scope): the caller owns the kept pump and waits
/// for its true result, driving it between passes of the root's own work. There is no pass
/// budget; only a pump that entered an uncertain effect ends the wait without a result.
/// During boot the bootstrap receive owner runs the passes; at runtime the root progress loop
/// does, wherever this frame may block. A frame that may not block (a timer delivery or a
/// component-resume pass is running above it) gets the pump back as a root-turn continuation.
unsafe fn await_at_root(pump: HostedPumpRestore) -> ServicePump {
    // The wait receives on the root thread inside a handler that may still read its own
    // delivered request from the buffer afterwards.
    crate::ipc_message::preserving_received(|| await_at_root_unguarded(pump))
}

unsafe fn await_at_root_unguarded(pump: HostedPumpRestore) -> ServicePump {
    let _waiting = RootWaitScope::enter();
    if crate::dispatcher_bootstrap::is_owned() {
        let mut pump = Some(pump);
        let mut finished = None;
        let mut fenced = false;
        let waited = crate::bootstrap_receive::drive((), || {
            match retry(pump.take().expect("kept root pump")) {
                PumpProgress::Finished(result) => { finished = Some(result); Ok(Some(true)) }
                PumpProgress::Unfinished(next) => { pump = Some(next); Ok(None) }
                PumpProgress::Fenced(next) => {
                    pump = Some(next);
                    fenced = true;
                    Err(STATUS_UNSUCCESSFUL as u32)
                }
            }
        });
        let pump = pump.take();
        return match (waited, finished, pump) {
            (Ok(_), Some(result), _) => { trace_root(b"boot-finished"); ServicePump::Finished(result) }
            (_, _, Some(pump)) if fenced => ServicePump::Fenced(fence_pump(pump, b"boot-uncertain")),
            // The bootstrap owner refused a receive transition: a refusal, not an effect. The
            // pump stays owned and unchanged for the caller's retained owner.
            (_, _, Some(pump)) => { trace_root(b"boot-refused"); ServicePump::RootTurn(RootTurnPump { pump }) }
            (_, Some(result), None) => ServicePump::Finished(result),
            (_, None, None) => unreachable!("a root wait always keeps its pump or its result"),
        };
    }
    if !crate::service_sec_image::root_wait_may_block() {
        trace_root(b"root-turn");
        return ServicePump::RootTurn(RootTurnPump { pump });
    }
    let waited = nt_component_suspension::await_root_pump_refusable(
        pump,
        || match crate::service_sec_image::root_progress_pass() {
            Ok(()) => nt_component_suspension::RootPass::Ran,
            Err(crate::service_sec_image::RootPassError::Transport) =>
                nt_component_suspension::RootPass::Refused,
        },
        |pump| retry(pump),
    );
    match waited {
        nt_component_suspension::RootPumpWait::Finished(result) => {
            trace_root(b"finished");
            ServicePump::Finished(result)
        }
        nt_component_suspension::RootPumpWait::Fenced(pump) =>
            ServicePump::Fenced(fence_pump(pump, b"root-uncertain")),
        // A root pass stopped before its receive; its owner keeps that step's entered state.
        nt_component_suspension::RootPumpWait::Retained(pump) => {
            trace_root(b"root-pass-refused");
            ServicePump::RootTurn(RootTurnPump { pump })
        }
    }
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
        // This caller has no retained owner for a root turn yet.
        ServicePump::RootTurn(turn) => turn.fence_unowned(),
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
pub(crate) unsafe fn take_reply(ticket: nested::NestedRestoreTicket) -> Option<ServiceDelivery> {
    let (envelope, answer) = services().take_reply(ticket)?;
    trace(b"replied", ticket);
    Some(match answer {
        ServiceAnswer::Reply(reply) =>
            ServiceDelivery::Reply(envelope.with_words(reply.info, reply.words)),
        ServiceAnswer::ParkConnect(parked) => ServiceDelivery::ParkConnect(envelope, parked),
    })
}

/// Root boundary only: drive each intercepted service's kept pump once, then each fenced one.
pub(crate) unsafe fn drive() -> usize {
    // Resuming a kept pump receives on the root thread. Whatever caller runs this may hold a
    // delivered, not yet captured request in the buffer; guard it here for every caller.
    crate::ipc_message::preserving_received(|| drive_unguarded())
}

unsafe fn drive_unguarded() -> usize {
    // Ordinary File rows own their kept pumps; their callers collect each return (#420).
    let mut finished = crate::driver_launch::redrive_plain_file_pumps();
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
                |step, result| {
                    let scope = ContinuingScope::enter(key);
                    let reply = step.answer(result);
                    drop(scope);
                    match (&mut *core::ptr::addr_of_mut!(CONTINUED)).take() {
                        Some((owner, step, pump)) if owner == key => Completion::Again(step, pump),
                        Some((_, _, pump)) => {
                            // Not this row's tail: it can never be continued.
                            let _ = fence_pump(pump, b"continued-foreign");
                            Completion::Reply(reply)
                        }
                        None => Completion::Reply(reply),
                    }
                },
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
