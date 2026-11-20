//! Provider callbacks whose dependent's pump stopped unfinished (#420).
//!
//! A provider lane X (NDIS, dxgkrnl) calls back into a dependent driver through
//! `FSD_SERVICE_PROVIDER_CALLBACK_LABEL`. Each callback signature has an adapter that marshals
//! the call, dispatches it, and then has a tail (copy-back, shadow refresh, alias rows). When
//! the dependent's pump stops unfinished, none of those tails may run yet. In keep mode, which
//! only the lane service enables, every tail is boxed before its dispatch and the capacity to
//! keep it is reserved too, so nothing can be refused after the dependent was entered:
//!
//! - the dispatcher keeps the pump in this module's chain and reports `Kept`;
//! - each adapter level pushes its boxed tail instead of running it;
//! - the service moves its own outer tail (IRQL, dispatch context, dependency lease) into a
//!   [`ProviderCallbackStep`] and registers it.
//!
//! When the kept pump finishes, the step runs the target's finish, the core resource refresh,
//! every tail innermost first, and the outer tail, on the true result. A tail that dispatches
//! again and is kept again becomes the step's remaining continuation for the same parent.

use super::*;
use component_scheduler::service_continuation::KeptPump;

/// The error value a kept dispatch propagates through every adapter's `Result<u64, i32>`.
/// Only meaningful while this module's chain holds a kept target; never replied.
pub(super) const CALLBACK_KEPT: i32 = 0x7F42_0420;

type CallbackTail = alloc::boxed::Box<
    dyn FnOnce(&mut HostedProviderCallbackDispatcher<'_>, Result<u64, i32>) -> Result<u64, i32>,
>;

/// Tail depth reserved before a keep-mode dispatch: adapter, signature helper and caller.
const TAIL_DEPTH: usize = 4;

/// The kept pump and how its receipt becomes the dispatch's result.
struct KeptTarget {
    kept: KeptPump,
    finish: TargetFinish,
}

/// What a kept pump was dispatching.
enum TargetFinish {
    /// A dependent's callback target, with `dispatch_dependent_provider_callback`'s finish.
    Component { instance_index: usize, shared: u64, core: Option<CoreTail> },
    /// A PDO projection created for a DXG AddDevice alias.
    PdoProjection { index: usize, shared: u64 },
}

impl TargetFinish {
    unsafe fn finish(self, pr: crate::spawn_hosts::PumpResult) -> Result<u64, i32> {
        match self {
            Self::Component { instance_index, shared, core } => {
                let target = finish_hosted_component_target(instance_index, shared, pr);
                match core {
                    Some(core) => core.finish(target),
                    None => match target {
                        Ok(value) => Ok(value),
                        Err(HostedComponentDispatchError::Status(status)) => Err(status),
                        Err(HostedComponentDispatchError::Wall(_)) => Err(STATUS_UNSUCCESSFUL),
                        Err(HostedComponentDispatchError::Kept) => Err(CALLBACK_KEPT),
                    },
                }
            }
            Self::PdoProjection { index, shared } =>
                finish_pdo_projection(finish_device_projection_control(index, shared, pr))
                    .map_err(|status| status.raw()),
        }
    }
}

/// `dispatch_dependent_provider_callback`'s own post-dispatch work.
#[derive(Clone, Copy)]
struct CoreTail {
    record: HostedProviderCallbackRecord,
    dependent_inst: DriverInstance,
    dependent_binding: Option<HostedDeviceBinding>,
    dependent_shared: u64,
}

impl CoreTail {
    unsafe fn finish(
        self, result: Result<u64, HostedComponentDispatchError>,
    ) -> Result<u64, i32> {
        let refresh = || if let Some(binding) = self.dependent_binding {
            refresh_hosted_device_resource_state(binding, self.dependent_shared);
        };
        match result {
            Ok(result) => { refresh(); Ok(result) }
            Err(HostedComponentDispatchError::Status(status)) => { refresh(); Err(status) }
            Err(HostedComponentDispatchError::Wall(pr)) => {
                trace_hosted_provider_callback_wall(self.record, self.dependent_inst, pr);
                Err(STATUS_UNSUCCESSFUL)
            }
            Err(HostedComponentDispatchError::Kept) => Err(CALLBACK_KEPT),
        }
    }
}

struct Chain {
    target: Option<KeptTarget>,
    tails: Vec<CallbackTail>,
    /// The scheduler depth of the service that owns this chain. A service nested inside a
    /// dependent's pump runs deeper and has its own owner, never this chain.
    depth: u64,
}

static mut CHAIN: Option<Chain> = None;

fn scheduler_depth() -> u64 {
    crate::executor::local().scheduler_depth.load(Ordering::Acquire)
}

fn chain() -> Option<&'static mut Chain> {
    unsafe { (&mut *core::ptr::addr_of_mut!(CHAIN)).as_mut() }
        .filter(|chain| chain.depth == scheduler_depth())
}

/// Keep mode for one provider-callback service: a dispatch that stops unfinished is kept,
/// never waited for or fenced. The previous mode is restored when the scope ends.
pub(super) struct KeepScope(Option<Option<Chain>>);

impl KeepScope {
    pub(super) unsafe fn enter(keeps: bool) -> Result<Self, i32> { Self::enter_reserving(keeps, 0) }

    /// Keep mode with room for `owed` more tails, so a step whose tail is kept again can keep
    /// every tail still owed without allocating after that dispatch was entered.
    unsafe fn enter_reserving(keeps: bool, owed: usize) -> Result<Self, i32> {
        let next = if keeps {
            let mut tails = Vec::new();
            let _durable = crate::allocator::enter_durable();
            tails.try_reserve(TAIL_DEPTH + owed).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            Some(Chain { target: None, tails, depth: scheduler_depth() })
        } else {
            None
        };
        Ok(Self(Some(core::mem::replace(&mut *core::ptr::addr_of_mut!(CHAIN), next))))
    }

    /// The kept target and the tails pushed above it, if this service's dispatch was kept.
    unsafe fn take_kept(&mut self) -> Option<(KeptTarget, Vec<CallbackTail>)> {
        let chain = chain()?;
        let target = chain.target.take()?;
        Some((target, core::mem::take(&mut chain.tails)))
    }
}

impl Drop for KeepScope {
    fn drop(&mut self) {
        if let Some(previous) = self.0.take() {
            unsafe { *core::ptr::addr_of_mut!(CHAIN) = previous; }
        }
    }
}

/// Whether this dispatch may be kept.
pub(super) fn keeps() -> bool { chain().is_some() }

/// The dispatcher kept the dependent's pump. Only keep mode calls this.
pub(super) unsafe fn keep_target(kept: KeptPump, instance_index: usize, shared: u64) -> bool {
    match chain() {
        Some(chain) if chain.target.is_none() => {
            chain.target = Some(KeptTarget {
                kept, finish: TargetFinish::Component { instance_index, shared, core: None },
            });
            true
        }
        _ => { let _ = kept.fence(); false }
    }
}

/// A PDO projection's pump was kept. Only keep mode calls this.
pub(super) unsafe fn keep_pdo_projection(kept: KeptPump, index: usize, shared: u64) -> bool {
    match chain() {
        Some(chain) if chain.target.is_none() => {
            chain.target = Some(KeptTarget {
                kept, finish: TargetFinish::PdoProjection { index, shared },
            });
            true
        }
        _ => { let _ = kept.fence(); false }
    }
}

/// Attach `dispatch_dependent_provider_callback`'s own finish to the kept target.
pub(super) unsafe fn attach_core(
    record: HostedProviderCallbackRecord, dependent_inst: DriverInstance,
    dependent_binding: Option<HostedDeviceBinding>, dependent_shared: u64,
) {
    if let Some(KeptTarget { finish: TargetFinish::Component { core, .. }, .. }) =
        chain().and_then(|chain| chain.target.as_mut())
    {
        if core.is_none() {
            *core = Some(CoreTail { record, dependent_inst, dependent_binding, dependent_shared });
        }
    }
}

/// Box `tail` without aborting on exhaustion.
unsafe fn try_box_tail<F>(tail: F) -> Result<CallbackTail, i32>
where
    F: FnOnce(&mut HostedProviderCallbackDispatcher<'_>, Result<u64, i32>) -> Result<u64, i32>
        + 'static,
{
    let layout = core::alloc::Layout::new::<F>();
    if layout.size() == 0 {
        return Ok(alloc::boxed::Box::new(tail));
    }
    let _durable = crate::allocator::enter_durable();
    let raw = alloc::alloc::alloc(layout) as *mut F;
    if raw.is_null() { return Err(STATUS_INSUFFICIENT_RESOURCES); }
    raw.write(tail);
    Ok(alloc::boxed::Box::from_raw(raw))
}

enum HeldTail<F> {
    Inline(F),
    Boxed(CallbackTail),
}

/// Run `body`, then `tail` on its result. In keep mode the tail is boxed and its slot reserved
/// before `body` can enter anything; a kept body pushes the tail instead of running it.
pub(super) unsafe fn with_tail<F>(
    dispatch: &mut HostedProviderCallbackDispatcher<'_>,
    body: impl FnOnce(&mut HostedProviderCallbackDispatcher<'_>) -> Result<u64, i32>,
    tail: F,
) -> Result<u64, i32>
where
    F: FnOnce(&mut HostedProviderCallbackDispatcher<'_>, Result<u64, i32>) -> Result<u64, i32>
        + 'static,
{
    let held = match chain() {
        Some(chain) => {
            if chain.tails.len() == chain.tails.capacity() {
                let _durable = crate::allocator::enter_durable();
                chain.tails.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            }
            HeldTail::Boxed(try_box_tail(tail)?)
        }
        None => HeldTail::Inline(tail),
    };
    let result = body(dispatch);
    let kept = result == Err(CALLBACK_KEPT)
        && chain().is_some_and(|chain| chain.target.is_some());
    match held {
        HeldTail::Boxed(tail) if kept => {
            let chain = chain().expect("kept chain");
            debug_assert!(chain.tails.len() < chain.tails.capacity());
            chain.tails.push(tail);
            Err(CALLBACK_KEPT)
        }
        HeldTail::Boxed(tail) => tail(dispatch, result),
        HeldTail::Inline(tail) => tail(dispatch, result),
    }
}

/// `_with_dispatch`'s own work after its adapter returns.
pub(super) struct OuterTail {
    pub(super) record: HostedProviderCallbackRecord,
    pub(super) callback_args: [u64; 4],
    pub(super) provider_stack: [u64; 8],
    pub(super) dependent_shared: u64,
    pub(super) saved_dependent_irql: Option<u8>,
    pub(super) _device_dispatch_context: Option<HostedDeviceDispatchContextGuard>,
    pub(super) _dependency_lease: HostedProviderDependencyDispatchLease,
}

impl OuterTail {
    /// Restore the dependent's IRQL, count the completion and encode the reply word.
    pub(super) unsafe fn finish(self, result: Result<u64, i32>) -> u64 {
        if let Some(saved) = self.saved_dependent_irql {
            write_volatile((self.dependent_shared + SH_HOSTED_CURRENT_IRQL) as *mut u8, saved);
        }
        if result.is_ok() {
            record_provider_protocol_receive_completion(self.record);
        }
        HOSTED_PROVIDER_CALLBACK_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
        trace_hosted_provider_callback(
            b"done", self.record, self.callback_args, &self.provider_stack, result);
        match result {
            Ok(value) => value,
            Err(status) => hosted_provider_callback_failure(status),
        }
    }
}

/// How a provider-callback service ended.
pub(super) enum CallbackService {
    Replied(u64),
    /// The dependent is still running; the service's step owes the reply.
    Kept(PendingCallback),
}

#[must_use = "a kept provider callback is owed its service step"]
pub(super) struct PendingCallback {
    target: KeptTarget,
    tails: Vec<CallbackTail>,
    outer: OuterTail,
}

impl PendingCallback {
    /// After the adapter returned: the kept target and its tails, if it was kept.
    pub(super) unsafe fn from_scope(
        scope: &mut KeepScope, result: Result<u64, i32>, outer: OuterTail,
    ) -> CallbackService {
        if result == Err(CALLBACK_KEPT) {
            if let Some((target, tails)) = scope.take_kept() {
                return CallbackService::Kept(Self { target, tails, outer });
            }
        }
        CallbackService::Replied(outer.finish(result))
    }

    pub(super) fn into_step(
        self, caller: nt_process::native_handle::NativeHandleCaller,
    ) -> (KeptPump, ProviderCallbackStep) {
        let Self { target, tails, outer } = self;
        let KeptTarget { kept, finish } = target;
        (kept, ProviderCallbackStep { finish, tails, outer, caller })
    }
}

/// The service step of a provider callback whose dependent had not returned (#420).
pub(crate) struct ProviderCallbackStep {
    finish: TargetFinish,
    tails: Vec<CallbackTail>,
    outer: OuterTail,
    caller: nt_process::native_handle::NativeHandleCaller,
}

impl ProviderCallbackStep {
    /// The callback's reply word once the dependent has really returned (or walled).
    pub(crate) unsafe fn complete(self, pr: crate::spawn_hosts::PumpResult) -> u64 {
        let Self { finish, tails, outer, caller } = self;
        let mut result = finish.finish(pr);
        let mut dispatch = callback_dispatcher(caller);
        let owed = tails.len();
        let end = nt_component_suspension::run_tails(
            tails, result, || Err(STATUS_INSUFFICIENT_RESOURCES),
            |tail, result| {
                // A tail that dispatches again may be kept again.
                let Ok(mut scope) = KeepScope::enter_reserving(true, owed) else {
                    // No keep capacity: the tail runs on the refusal before entering anything.
                    return nt_component_suspension::TailRun::Done(
                        tail(&mut dispatch, Err(STATUS_INSUFFICIENT_RESOURCES)));
                };
                let next = tail(&mut dispatch, result);
                match (next == Err(CALLBACK_KEPT)).then(|| scope.take_kept()).flatten() {
                    Some((target, inner)) => nt_component_suspension::TailRun::Kept(target, inner),
                    None => nt_component_suspension::TailRun::Done(next),
                }
            },
        );
        result = match end {
            nt_component_suspension::ChainEnd::Finished(result) => result,
            nt_component_suspension::ChainEnd::Refused(target, result) => {
                let _ = target.kept.fence();
                result
            }
            nt_component_suspension::ChainEnd::Kept(target, tails) => {
                // The step's remaining continuation for the same parked provider lane.
                let (kept, step) = PendingCallback { target, tails, outer }.into_step(caller);
                return match kept.register(
                    component_scheduler::service_continuation::continuing_slot(),
                    ServiceStep::ProviderCallback(step),
                ) {
                    // This step's reply is replaced by its continuation's.
                    Ok(()) => nt_status::NtStatus::PENDING.raw() as u32 as u64,
                    Err((uncertain, ServiceStep::ProviderCallback(step))) =>
                        step.complete(uncertain),
                    Err(_) => unreachable!("provider callback step"),
                };
            }
        };
        outer.finish(result)
    }
}

/// The lane service's dispatcher, rebuilt for a step that runs at a root boundary.
pub(super) fn callback_dispatcher(
    caller: nt_process::native_handle::NativeHandleCaller,
) -> impl FnMut(
    HostedProviderCallbackRecord, DriverInstance, u64, [u64; 4],
    [u64; PROVIDER_CALLBACK_STACK_QWORDS],
) -> Result<u64, HostedComponentDispatchError> {
    move |record, dependent_inst, exec_code_va, args, stack_args| unsafe {
        dispatch_hosted_component_target(
            record.dependent_instance, dependent_inst, exec_code_va, record.target, args,
            stack_args, caller,
        )
    }
}
