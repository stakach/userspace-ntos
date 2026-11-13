//! Execute an already selected kernel wait without borrowing hosted-client return machinery.

use super::*;
use nt_user_host::provider_kernel_activation::KernelProviderWaitCapture;

/// The owned ticket leaves all canonical borrows before any native mechanism is invoked.
unsafe fn claim_driver_entry_wait_resume(
    caller: KernelProviderCaller,
    capture: KernelProviderWaitCapture,
) -> Result<
    (
        spawn_hosts::PumpChannel,
        nt_user_host::provider_kernel_wait::KernelProviderWaitResume<ComponentSuspensionCompletion>,
    ),
    u32,
> {
    let _durable = allocator::enter_durable();
    let channel = (&*core::ptr::addr_of!(ACTIVATIONS))
        .recipient(caller)?
        .execution_channel(caller)?;
    if authenticated_channel_caller(&channel)? != caller {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    restore_ps_retirement_window(caller, &channel)?;
    let ticket = with_provider_process_manager(|pm| {
        (&mut *core::ptr::addr_of_mut!(ACTIVATIONS))
            .begin_wait_resume(
                caller,
                pm,
                &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
                &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS),
                capture,
            )
            .map_err(|error| {
                use nt_user_host::provider_kernel_activation::KernelProviderResumeError;
                match error {
                    KernelProviderResumeError::Authority(status) => status,
                    KernelProviderResumeError::Pump(
                        nt_user_host::provider_kernel_pump::PumpProgressError::IdentityExhausted,
                    )
                    | KernelProviderResumeError::Lane(
                        nt_component_suspension::LaneError::NoCapacity,
                    ) => nt_process::STATUS_INSUFFICIENT_RESOURCES,
                    KernelProviderResumeError::Lane(nt_component_suspension::LaneError::Busy) => {
                        nt_status::NtStatus::DEVICE_BUSY.raw() as u32
                    }
                    _ => nt_process::STATUS_INVALID_PARAMETER,
                }
            })
    })?;
    Ok((channel, ticket))
}

/// A physical stop is retained by the activation and its existing canonical frame. None of
/// these outcomes releases that ownership or makes the stopped lane eligible for fresh work.
#[must_use = "the retained physical stop still needs its readiness or terminal owner"]
pub(crate) enum DriverEntryWaitOutcome {
    WaitCaptured(KernelProviderWaitCapture),
    Returned(nt_component_suspension::TerminalIdentity),
    Stopped(spawn_hosts::PumpResult),
}

/// Readiness selects the real typed frame before this entry. The outer bootstrap receive owner
/// retains the target while this invocation runs, reparks, or publishes terminal completion.
pub(crate) unsafe fn run_driver_entry_wait_resume(
    caller: KernelProviderCaller,
    capture: KernelProviderWaitCapture,
) -> Result<DriverEntryWaitOutcome, u32> {
    let _durable = allocator::enter_durable();
    let scope = driver_launch::ComponentSchedulerScope::enter();
    let (mut channel, ticket) = claim_driver_entry_wait_resume(caller, capture)?;
    let (capture, mut attempt, selection) = ticket.into_parts();
    channel.initial = spawn_hosts::InitialAction::ReplyRequest;
    let reservation = (&mut *core::ptr::addr_of_mut!(ACTIVATIONS))
        .recipient_mut(caller)?
        .reserve_capture_refusal(caller, &channel);
    if let Err(status) = reservation {
        return Err(retain_driver_entry_uncertain(
            caller, attempt, channel, None,
            Some(KernelResumeAuthority { capture, selection: Some(selection) }), status,
        ));
    }
    if let Err(status) = validate_driver_entry_execution(caller, Some(capture), &attempt) {
        return Err(retain_driver_entry_uncertain(
            caller, attempt, channel, None,
            Some(KernelResumeAuthority { capture, selection: Some(selection) }), status,
        ));
    }
    let previous = match (&*core::ptr::addr_of!(ACTIVATIONS))
        .recipient(caller).ok().and_then(KernelJobRecipient::observation)
    {
        Some(previous) => previous,
        None => return Err(retain_driver_entry_uncertain(
            caller, attempt, channel, None,
            Some(KernelResumeAuthority { capture, selection: Some(selection) }),
            nt_process::STATUS_INVALID_PARAMETER,
        )),
    };
    let page = match win32k_glue::provider_wait_page_for_channel(&channel) {
        Some(page) => page,
        None => return Err(retain_driver_entry_uncertain(
            caller, attempt, channel, None,
            Some(KernelResumeAuthority { capture, selection: Some(selection) }),
            nt_process::STATUS_INVALID_HANDLE,
        )),
    };
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*page).result),
        nt_provider_wait::ProviderWaitResult::completed(
            capture.key().id,
            selection.completion.status,
        ),
    );
    // No coordinator, recipient or process-manager borrow crosses this real Reply/Recv.
    let result = match spawn_hosts::component_pump_resume_kernel_provider_wait(&channel, &previous) {
        Ok(result) => result,
        Err(status) => return Err(retain_driver_entry_uncertain(
            caller, attempt, channel, None,
            Some(KernelResumeAuthority { capture, selection: Some(selection) }), status,
        )),
    };
    if result.provider_wait_capture_refusal.is_some() {
        return Err(retain_driver_entry_capture_refusal(
            caller, attempt, channel, result,
            Some(KernelResumeAuthority { capture, selection: Some(selection) }),
        ));
    }
    if let Err(status) = observe_driver_entry_pump(&channel, &mut attempt, &result) {
        return Err(retain_driver_entry_uncertain(
            caller, attempt, channel, Some(result),
            Some(KernelResumeAuthority { capture, selection: Some(selection) }), status,
        ));
    }
    let result = receive_driver_entry_yields(&scope, caller, Some(capture), result)?;
    finish_stopped_wait(caller, capture, result)
}

unsafe fn finish_stopped_wait(
    caller: KernelProviderCaller,
    previous: KernelProviderWaitCapture,
    result: spawn_hosts::PumpResult,
) -> Result<DriverEntryWaitOutcome, u32> {
    use nt_user_host::provider_kernel_wait::KernelProviderStoppedOutcome;
    let stop = (&*core::ptr::addr_of!(ACTIVATIONS))
        .recipient(caller)?
        .stopped_outcome()?;
    let status = match stop {
        KernelProviderStoppedOutcome::WaitCaptured(next) => {
            // The old Resuming frame remains until the next wait acquires dispatcher leases.
            return Ok(DriverEntryWaitOutcome::WaitCaptured(next));
        }
        KernelProviderStoppedOutcome::Returned(status) => status,
        // A wait-resumed job never yields source work: its return belongs to this frame's
        // terminal owner, so the pump preflight leaves that stop to the existing path.
        KernelProviderStoppedOutcome::Walled
        | KernelProviderStoppedOutcome::CallbackSuspended
        | KernelProviderStoppedOutcome::LpcWaitSuspended
        | KernelProviderStoppedOutcome::SourceWorkYielded => {
            return Ok(DriverEntryWaitOutcome::Stopped(result));
        }
    };
    let terminal = with_provider_process_manager(|pm| {
        (&mut *core::ptr::addr_of_mut!(ACTIVATIONS))
            .retain_terminal_completion(
                caller,
                pm,
                &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
                &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS),
                previous.key(),
                component_terminal::NativeTerminal::kernel_return(caller, status),
                status,
            )
            .map_err(|(status, _payload)| status)
    })?;
    Ok(DriverEntryWaitOutcome::Returned(terminal))
}
