//! Outer-only execution and coalesced wake demand for selected component continuations.

use super::*;
use nt_component_suspension::{LaneResume, ResumePass, ResumeWake, SuspensionOwner};

#[path = "component_resume_execute.rs"]
mod execute;
pub(super) use execute::run_hosted;

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

unsafe fn eligible(handler: &ExecNtHandler, continuation: ComponentNativeContinuation) -> bool {
    match continuation {
        ComponentNativeContinuation::Hosted(hosted) => {
            hosted.return_target.can_resume()
                && win32k_glue::win32k_client_context_is_admitted(hosted.pending.client())
        }
        ComponentNativeContinuation::Kernel(capture) => {
            kernel_provider_activation::wait_resume_is_eligible(&handler.pm, capture)
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

pub(super) unsafe fn next_ready(handler: &ExecNtHandler) -> Option<Candidate> {
    let resume = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .next_resumable_if(|frame| eligible(handler, frame.continuation))?;
    candidate(resume)
}

unsafe fn next_in_pass(handler: &ExecNtHandler, pass: &mut ResumePass) -> Option<Candidate> {
    let resume = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .next_resumable_in_pass(pass, |frame| eligible(handler, frame.continuation))?;
    candidate(resume)
}

pub(super) unsafe fn is_running() -> bool {
    (&*core::ptr::addr_of!(WAKE)).is_running()
}

fn runtime_ready(handler: *const ExecNtHandler) -> bool {
    SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) == handler as u64
        && SERVICE_DELAY_DRAIN_QUEUE.load(Ordering::Acquire) != 0
        && DELAY_TIMER_HANDLER.load(Ordering::Relaxed) != 0
        && DELAY_TIMER_IRQ_STATE.load(Ordering::Acquire) == DELAY_TIMER_IRQ_ACTIVE
}

/// Timer callbacks only query this demand; they never claim or execute a selected continuation.
pub(crate) unsafe fn next_deadline(handler: &ExecNtHandler) -> Option<u64> {
    if component_execution_is_busy()
        && !kernel_provider_activation::has_stopped_wait_work(&handler.pm)
    {
        return None;
    }
    (&*core::ptr::addr_of!(WAKE)).next_deadline()
}

/// Count a scheduler wake as timer work without acknowledging demand or entering a provider.
pub(crate) unsafe fn wake_due(handler: &ExecNtHandler, now: u64) -> u64 {
    u64::from(next_deadline(handler).is_some_and(|deadline| deadline <= now))
}

/// Every finalization barrier rechecks work before receiving. Physical exclusion suppresses
/// programming, not retained demand. Timer programming failure cannot acknowledge that demand.
pub(super) unsafe fn reconcile(handler: &mut ExecNtHandler) {
    if !runtime_ready(core::ptr::from_ref(handler)) || is_running() {
        return;
    }
    let previous = (&*core::ptr::addr_of!(WAKE)).next_deadline();
    let stopped_wait = kernel_provider_activation::has_stopped_wait_work(&handler.pm);
    if !component_execution_is_busy() || stopped_wait {
        let has_work = stopped_wait || next_ready(handler).is_some();
        (&mut *core::ptr::addr_of_mut!(WAKE)).reconcile(has_work, monotonic_time_100ns());
    }
    let dpc_deadline = driver_launch::hosted_dpc_next_deadline(monotonic_time_100ns());
    if previous.is_none()
        && (&*core::ptr::addr_of!(WAKE)).next_deadline().is_none()
        && dpc_deadline.is_none()
    {
        return;
    }
    let queue =
        SERVICE_DELAY_DRAIN_QUEUE.load(Ordering::Acquire) as *const nt_delay_execution::Queue;
    let _message = crate::ipc_message::SavedMessageBuffer::capture();
    delay_timer_rearm(&*queue, handler);
}

unsafe fn drain_terminals(handler: *mut ExecNtHandler) -> u64 {
    let ctx = (*handler).loop_ctx;
    let retired = if let Some(ctx) = ctx {
        component_terminal::drain(&mut *handler, &mut *ctx.procs, &mut *ctx.pfilled)
    } else {
        0
    };
    kernel_provider_activation::redrive_ready_completions();
    retired
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
    if !runtime_ready(handler) || is_running() {
        return;
    }
    if component_execution_is_busy()
        && !kernel_provider_activation::has_stopped_wait_work(&(*handler).pm)
    {
        return;
    }
    let _message = crate::ipc_message::SavedMessageBuffer::capture();
    let _durable = allocator::enter_durable();
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
    let mut progressed = drain_terminals(handler) != 0;
    while let Some(candidate) = next_in_pass(&*handler, &mut pass) {
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
        progressed |= drain_terminals(handler) != 0;
    }
    if (*handler).lpc_endpoint_progress {
        // Component-originated LPC work bypasses the ordinary syscall post-action.
        let _ = lpc_endpoint_redrive_all(&mut *handler);
    }
    // A still-running physical owner is not evidence that its retained work disappeared.
    let has_work = component_execution_is_busy()
        || kernel_provider_activation::has_stopped_wait_work(&(*handler).pm)
        || next_ready(&*handler).is_some();
    if (&mut *core::ptr::addr_of_mut!(WAKE))
        .finish_pass(&mut ticket, monotonic_time_100ns(), has_work, progressed)
        .is_err()
    {
        report_retained(nt_process::STATUS_INSUFFICIENT_RESOURCES);
    }
    reconcile(&mut *handler);
}
