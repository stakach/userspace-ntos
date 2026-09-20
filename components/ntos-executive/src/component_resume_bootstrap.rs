//! Bounded kernel-only continuation service before ownership moves into the runtime handler.

use super::*;
use nt_user_host::provider_kernel_activation::KernelProviderCaller;

/// Scheduling observations only. None of these grants authority to receive on a parked Reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootstrapPassOutcome {
    TargetAcknowledged {
        initialized: bool,
    },
    OwnershipUnavailable,
    InvocationActive,
    TimerDeliveryActive,
    PassActive,
    PhysicalExecutionBlocked,
    /// The original pacing deadline is retained; no continuation was executed by this call.
    Deferred {
        deadline: u64,
    },
    /// No schedulable demand was observed. Parked jobs may still await external signals.
    NoReadyWork,
    /// A bounded pass ended. Its next scheduling deadline is not the complete timer deadline set.
    PassFinished {
        next_deadline: Option<u64>,
    },
}

unsafe fn observe_kernel_demand(pm: &nt_process::ProcessManager) -> ResumeDemand {
    ResumeDemand::observe(
        component_execution_is_busy(),
        kernel_provider_activation::has_stopped_wait_work(pm),
        || {
            (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
                .next_resumable_if(|frame| {
                    matches!(frame.continuation, ComponentNativeContinuation::Kernel(_))
                        && eligible(pm, frame.continuation)
                })
                .is_some()
                || kernel_provider_activation::has_ready_completions()
        },
    )
}

unsafe fn drain_completions(target: KernelProviderCaller, acknowledged: &mut Option<bool>) -> bool {
    kernel_provider_activation::redrive_ready_completions_observed(|receipt, initialized| {
        if receipt.caller() == target {
            assert!(acknowledged.replace(initialized).is_none());
        }
    })
}

unsafe fn next_kernel_in_pass(pass: &mut ResumePass) -> Option<Candidate> {
    ps_bootstrap::with_process_manager(|pm| {
        let resume =
            (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).next_resumable_in_pass(pass, |frame| {
                matches!(frame.continuation, ComponentNativeContinuation::Kernel(_))
                    && eligible(pm, frame.continuation)
            });
        Ok(resume.and_then(|resume| candidate(resume)))
    })
    .expect("bootstrap continuation pass must retain its process owner")
}

/// Called only after the initial physical DriverEntry scope has returned. This is one bounded
/// scheduling pass, not a receive loop, and does not admit otherwise unsupported blocking waits.
pub(crate) unsafe fn run_bootstrap_outer(
    target: KernelProviderCaller,
) -> Result<BootstrapPassOutcome, u32> {
    if SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) != 0 || !dispatcher_bootstrap::is_owned()
    {
        return Ok(BootstrapPassOutcome::OwnershipUnavailable);
    }
    if driver_launch::hosted_component_dispatch_active() {
        return Ok(BootstrapPassOutcome::InvocationActive);
    }
    if TIMER_DELIVERY_GATE.is_active() {
        return Ok(BootstrapPassOutcome::TimerDeliveryActive);
    }
    if is_running() {
        return Ok(BootstrapPassOutcome::PassActive);
    }
    let can_schedule = ps_bootstrap::with_process_manager(|pm| {
        let demand = observe_kernel_demand(pm);
        (&mut *core::ptr::addr_of_mut!(WAKE)).reconcile_demand(demand, monotonic_time_100ns());
        Ok(demand.can_schedule())
    })?;
    if !can_schedule {
        return Ok(BootstrapPassOutcome::PhysicalExecutionBlocked);
    }
    let _message = crate::ipc_message::SavedMessageBuffer::capture();
    let _durable = allocator::enter_durable();
    let mut acknowledged = None;
    let mut ran_pass = false;
    if let Some(mut ticket) = (&mut *core::ptr::addr_of_mut!(WAKE))
        .begin_pass(monotonic_time_100ns())
        .map_err(|_| nt_process::STATUS_INSUFFICIENT_RESOURCES)?
    {
        ran_pass = true;
        let mut progressed = kernel_provider_activation::publish_bootstrap_waits()
            .expect("bootstrap continuation pass must retain its dispatcher owner");
        let mut pass = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).resume_pass();
        progressed |= drain_completions(target, &mut acknowledged);
        while let Some(candidate) = next_kernel_in_pass(&mut pass) {
            let ComponentNativeContinuation::Kernel(capture) = candidate.continuation else {
                unreachable!("bootstrap selection admits only kernel continuations");
            };
            use kernel_provider_activation::resume::DriverEntryWaitOutcome;
            match kernel_provider_activation::resume::run_driver_entry_wait_resume(
                capture.caller(),
                capture,
            ) {
                Ok(DriverEntryWaitOutcome::WaitCaptured(next)) => {
                    debug_assert_eq!(next.caller(), capture.caller());
                    progressed = true;
                }
                Ok(DriverEntryWaitOutcome::Returned(_)) => progressed = true,
                Ok(DriverEntryWaitOutcome::Stopped(_)) => {}
                Err(status) => report_retained(status),
            }
            progressed |= kernel_provider_activation::publish_bootstrap_waits()
                .expect("bootstrap continuation pass must retain its dispatcher owner");
            progressed |= drain_completions(target, &mut acknowledged);
        }
        let has_work = ps_bootstrap::with_process_manager(|pm| {
            Ok(component_execution_is_busy() || observe_kernel_demand(pm).retains_work())
        })
        .expect("bootstrap continuation pass must retain its process owner");
        (&mut *core::ptr::addr_of_mut!(WAKE))
            .finish_pass(&mut ticket, monotonic_time_100ns(), has_work, progressed)
            .expect("bootstrap continuation pass must finish with its owned wake ticket");
    }
    assert!(dispatcher_bootstrap::request_receive_checkpoint());
    dispatcher_bootstrap::prepare_receive()?;
    if let Some(initialized) = acknowledged {
        return Ok(BootstrapPassOutcome::TargetAcknowledged { initialized });
    }
    if component_execution_is_busy() {
        return Ok(BootstrapPassOutcome::PhysicalExecutionBlocked);
    }
    let next_deadline = retained_deadline();
    if !ran_pass {
        return Ok(match next_deadline {
            Some(deadline) => BootstrapPassOutcome::Deferred { deadline },
            None => BootstrapPassOutcome::NoReadyWork,
        });
    }
    Ok(BootstrapPassOutcome::PassFinished { next_deadline })
}
