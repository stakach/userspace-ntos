//! A kernel job whose scheduler service could not hand its lane back (#333).
//!
//! The job's recipient row keeps the receive attempt, the yielded pump and the owed step, so
//! the same receive continues once the exact parent is restored; the job is never entered
//! again and an uncertain restore is never replayed. Exactly one owner drives each row:
//! - an initial entry by its runner (`run_kernel_job`, or `await_initial` at boot), which
//!   needs the classified outcome;
//! - a selected-wait resume by the outer resume passes, through [`redrive_waits`].
//!
//! A timer wake paces the retries, so a held lane never depends on unrelated traffic.

use super::*;
pub(super) use super::bootstrap::RetainedKernelYield as RetainedYield;
use nt_time::CoalescedRetryWake;

const RETRY_100NS: u64 = 1_600_000;
static WAKE: CoalescedRetryWake = CoalescedRetryWake::new();
/// The jobs with a retained yield. The recipient row is the authority; this only lists them.
static mut RETAINED: alloc::vec::Vec<KernelProviderCaller> = alloc::vec::Vec::new();

pub(super) enum YieldsEnd {
    Received(spawn_hosts::PumpResult),
    /// The recipient row now owns the receive; its owner continues it.
    Retained,
}

/// How a retried yield finished, by the kind of entry that owns it.
pub(super) enum Resumed {
    Initial(KernelJobOutcome),
    Wait(resume::DriverEntryWaitOutcome),
}

/// Move a reserved receive whose service kept the lane held into the job's recipient row.
pub(super) unsafe fn retain(
    caller: KernelProviderCaller,
    attempt: KernelProviderPumpAttempt,
    channel: spawn_hosts::PumpChannel,
    previous: spawn_hosts::PumpResult,
    step: driver_launch::SchedulerYieldStep,
    capture: Option<nt_user_host::provider_kernel_activation::KernelProviderWaitCapture>,
) -> Result<YieldsEnd, u32> {
    (&mut *core::ptr::addr_of_mut!(ACTIVATIONS))
        .recipient_mut(caller)
        .expect("entered kernel activation must retain its scheduler yield")
        .retain_scheduler_yield(caller, attempt, channel, previous, step, capture);
    let retained = &mut *core::ptr::addr_of_mut!(RETAINED);
    if !retained.contains(&caller) {
        retained.try_reserve(1).map_err(|_| nt_process::STATUS_INSUFFICIENT_RESOURCES)?;
        retained.push(caller);
    }
    WAKE.publish(crate::monotonic_time_100ns().saturating_add(RETRY_100NS));
    trace(b"retained", caller, step.retryable());
    Ok(YieldsEnd::Retained)
}

unsafe fn retryable(caller: KernelProviderCaller, wait: bool) -> bool {
    (&*core::ptr::addr_of!(ACTIVATIONS)).recipient(caller).ok()
        .and_then(KernelJobRecipient::retained_yield)
        .is_some_and(|(retryable, is_wait)| retryable && is_wait == wait)
}

unsafe fn has_work() -> bool {
    (&*core::ptr::addr_of!(RETAINED)).iter().any(|caller| {
        (&*core::ptr::addr_of!(ACTIVATIONS)).recipient(*caller).ok()
            .and_then(KernelJobRecipient::retained_yield)
            .is_some_and(|(retryable, _)| retryable)
    })
}

pub(crate) unsafe fn next_deadline() -> Option<u64> { WAKE.next_deadline(has_work()) }

pub(crate) unsafe fn wake_due(now_100ns: u64) -> u64 {
    u64::from(WAKE.wake_due(now_100ns, has_work()))
}

/// Retry one job's retained yield once. `None` while it is still owed: the row keeps it.
pub(super) unsafe fn resume(caller: KernelProviderCaller) -> Result<Option<Resumed>, u32> {
    // The retained receive owns this job's lane. Another lane running here would be a parent
    // nothing parked for this slice, so it waits for a boundary without one.
    if spawn_hosts::shared_ingress::owner::runtime::running_lane().is_some() {
        return Ok(None);
    }
    let recipient = (&mut *core::ptr::addr_of_mut!(ACTIVATIONS)).recipient_mut(caller)?;
    let Some(mut retained) = recipient.take_scheduler_yield(caller) else { return Ok(None) };
    let _message = crate::ipc_message::SavedMessageBuffer::capture();
    let _durable = allocator::enter_durable();
    retained.step = driver_launch::retry_scheduler_yield_restore(retained.step);
    if !matches!(retained.step, driver_launch::SchedulerYieldStep::Service
        | driver_launch::SchedulerYieldStep::Receive)
    {
        trace(b"refused", caller, retained.step.retryable());
        (&mut *core::ptr::addr_of_mut!(ACTIVATIONS)).recipient_mut(caller)?
            .return_scheduler_yield(retained);
        WAKE.publish(crate::monotonic_time_100ns().saturating_add(RETRY_100NS));
        return Ok(None);
    }
    trace(b"resumed", caller, true);
    let capture = retained.capture;
    let previous = retained.previous;
    let scope = driver_launch::ComponentSchedulerScope::enter();
    let end = receive_driver_entry_yields(&scope, caller, capture, previous, Some(retained))
        .inspect_err(|_| forget(caller))?;
    let YieldsEnd::Received(result) = end else { return Ok(None) };
    forget(caller);
    Ok(Some(match capture {
        None => Resumed::Initial(classify_entered_kernel_job(caller, result)?),
        Some(capture) => Resumed::Wait(resume::finish_stopped_wait(caller, capture, result)?),
    }))
}

unsafe fn forget(caller: KernelProviderCaller) {
    (&mut *core::ptr::addr_of_mut!(RETAINED)).retain(|retained| *retained != caller);
}

/// Boot owner of an initial DriverEntry yield: the bootstrap receive loop services IRQ, timer
/// and ingress work between retries until the same receive continues.
pub(super) unsafe fn await_initial(caller: KernelProviderCaller) -> Result<KernelJobOutcome, u32> {
    let mut outcome = None;
    crate::bootstrap_receive::drive(caller, || {
        if !retryable(caller, false) {
            return Err(nt_process::STATUS_UNSUCCESSFUL);
        }
        match resume(caller)? {
            Some(Resumed::Initial(resumed)) => { outcome = Some(resumed); Ok(Some(true)) }
            Some(Resumed::Wait(_)) => Err(nt_process::STATUS_INVALID_PARAMETER),
            None => Ok(None),
        }
    })?;
    outcome.ok_or(nt_process::STATUS_INVALID_PARAMETER)
}

/// Whether a retained yield owns the execution the bootstrap receive owner observes as busy.
pub(crate) unsafe fn owns_execution() -> bool { has_work() }

/// Outer resume passes only: continue each selected-wait yield whose retry is due. Returns
/// whether any made progress. Initial-entry yields belong to their runner.
pub(crate) unsafe fn redrive_waits() -> bool {
    let Some((attempt, now)) = WAKE.begin_redrive_with_clock(
        (&*core::ptr::addr_of!(RETAINED)).iter().any(|caller| retryable(*caller, true)),
        crate::monotonic_time_100ns,
    ) else { return false };
    let _ = attempt.retry_at(now.saturating_add(RETRY_100NS));
    let callers: alloc::vec::Vec<KernelProviderCaller> = (&*core::ptr::addr_of!(RETAINED))
        .iter().copied().filter(|caller| retryable(*caller, true)).collect();
    let mut progressed = false;
    for caller in callers {
        match resume(caller) {
            Ok(Some(Resumed::Wait(resume::DriverEntryWaitOutcome::WaitCaptured(_)
                | resume::DriverEntryWaitOutcome::Returned(_)))) => progressed = true,
            Ok(_) => {}
            Err(status) => trace(b"retained-failure", caller, status == 0),
        }
    }
    progressed
}

fn trace(stage: &[u8], caller: KernelProviderCaller, retryable: bool) {
    static TRACED: AtomicU64 = AtomicU64::new(0);
    let n = TRACED.fetch_add(1, Ordering::Relaxed) + 1;
    if n > 16 && !n.is_power_of_two() { return; }
    print_str(b"[kernel-yield-retry] n=");
    print_u64(n);
    print_str(b" stage=");
    print_str(stage);
    print_str(b" executor=");
    print_u64(caller.executor_id());
    print_str(b" retryable=");
    print_u64(u64::from(retryable));
    print_str(b"\n");
}
