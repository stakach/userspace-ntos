//! Canonical caller references for kernel-originated physical provider jobs.

use super::*;
use nt_component_suspension::{LaneBinding, LaneHandle};
use nt_user_host::provider_kernel_activation::{
    KernelProviderActivations, KernelProviderCaller, KernelProviderCompletionReceipt,
};
use nt_user_host::provider_kernel_pump::{KernelProviderPumpAttempt, KernelProviderPumpFacts};

#[path = "kernel_bootstrap.rs"]
mod bootstrap;
#[path = "kernel_provider_event.rs"]
mod event;
#[path = "kernel_provider_resume.rs"]
pub(super) mod resume;
#[path = "kernel_provider_terminal.rs"]
mod terminal;
#[path = "kernel_provider_wait_work.rs"]
mod wait_work;
pub(super) use wait_work::publish_runtime_waits;
use bootstrap::{DriverEntryCompletion, DriverEntryRecipient};

static mut ACTIVATIONS: KernelProviderActivations<DriverEntryRecipient> =
    KernelProviderActivations::new();

pub(super) unsafe fn wait_resume_is_eligible(
    pm: &nt_process::ProcessManager,
    capture: nt_user_host::provider_kernel_activation::KernelProviderWaitCapture,
) -> bool {
    (&mut *core::ptr::addr_of_mut!(ACTIVATIONS))
        .validate_wait_resume(
            capture.caller(), pm,
            &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
            &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS), capture,
        )
        .is_ok()
}

pub(super) unsafe fn has_stopped_wait_work(pm: &nt_process::ProcessManager) -> bool {
    let activations = &mut *core::ptr::addr_of_mut!(ACTIVATIONS);
    let mut cursor = activations.wait_work_cursor();
    while let Some((_, work)) = activations.next_wait_work(
        &mut cursor, pm,
        &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
        &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS),
    ) {
        if work.is_ok() {
            return true;
        }
    }
    false
}

fn channel_binding(channel: &spawn_hosts::PumpChannel) -> LaneBinding {
    LaneBinding {
        executor_id: channel.tcb,
        receive_endpoint: channel.fault_ep,
        reply_object: channel.reply_cap,
    }
}

fn kernel_channel(channel: &spawn_hosts::PumpChannel) -> bool {
    channel.logical_caller.is_none()
        && channel.client_pi == 0
        && channel.client_generation == 0
        && channel.caps.kind == spawn_hosts::ReqKind::Syscall
}

fn authenticated_channel_caller(
    channel: &spawn_hosts::PumpChannel,
) -> Result<KernelProviderCaller, u32> {
    let caller = channel
        .kernel_caller
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    if !kernel_channel(channel)
        || channel.shared_va != win32k_subsystem::WIN32K_SHARED_VADDR
        || channel.dispatch_label != win32k_subsystem::W32_DISPATCH_LABEL
        || caller.binding() != channel_binding(channel)
        || !unsafe { (&*core::ptr::addr_of!(ACTIVATIONS)).recipient(caller) }
            .is_ok_and(|recipient| recipient.matches(channel))
        || current_win32k_provider_domain().is_none_or(|provider| {
            caller.owner().provider_domain != provider.domain
                || caller.owner().provider_generation != provider.generation
        })
    {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    Ok(caller)
}

/// The component blocks in this request before DriverEntry. Capture may occur after its TCB was
/// started, but the reply cannot publish an owner until the root has retained the real activation.
pub(crate) unsafe fn publish(channel: &spawn_hosts::PumpChannel) -> u32 {
    let descriptor = (|| {
        let caller = authenticated_channel_caller(channel)?;
        with_provider_process_manager(|pm| {
            (&*core::ptr::addr_of!(ACTIVATIONS)).validate(
                caller,
                pm,
                &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
                &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS),
            )?;
            nt_provider_wait::KernelProviderActivationDescriptor::new(caller.owner())
                .map_err(|_| nt_process::STATUS_INVALID_PARAMETER)
        })
    })();
    match descriptor {
        Ok(descriptor) => {
            let page = win32k_subsystem::WIN32K_PROVIDER_WAIT_VADDR
                as *mut nt_provider_wait::ProviderWaitSharedPage;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*page).kernel_activation),
                descriptor,
            );
            nt_process::STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// DriverEntry is the first native consumer. Its bootstrap designation is authenticated before
/// capturing a general kernel activation; subsequent uses require the retained row, not System.
pub(crate) unsafe fn capture_win32k_initial_system(
    channel: &spawn_hosts::PumpChannel,
    lane: LaneHandle,
    system: nt_process::InitialSystemIdentity,
) -> Result<KernelProviderCaller, u32> {
    if !kernel_channel(channel) || channel.kernel_caller.is_some() {
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }
    let provider = current_win32k_provider_domain().ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
    if lanes.binding(lane) != Ok(channel_binding(channel)) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let recipient = DriverEntryRecipient::new(*channel)?;
    with_provider_process_manager(|pm| {
        if !pm.validate_initial_system_caller(system) {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        let native =
            pm.capture_native_handle_caller(system.thread(), nt_types::AccessMode::KernelMode)?;
        let _durable = allocator::enter_durable();
        (&mut *core::ptr::addr_of_mut!(ACTIVATIONS))
            .capture_with_recipient(
                pm,
                &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
                lanes,
                provider,
                lane,
                native,
                recipient,
            )
            .map_err(|(status, _recipient)| status)
    })
}

#[must_use = "a stopped activation retains its readiness or completion owner"]
pub(crate) struct InitialDriverEntryOutcome {
    pub observation: spawn_hosts::PumpResult,
    pub stop: nt_user_host::provider_kernel_wait::KernelProviderStoppedOutcome,
    pub receipt: Option<KernelProviderCompletionReceipt>,
}

/// Claim the first pump once, then only genuine IRQ-yield receive continuations. The provider
/// retains its Running lane throughout; walls and typed waits do not enter this scheduler path.
pub(crate) unsafe fn run_initial_driver_entry(
    caller: KernelProviderCaller,
) -> Result<InitialDriverEntryOutcome, u32> {
    let scope = driver_launch::ComponentSchedulerScope::enter();
    let (channel, mut attempt) = with_provider_process_manager(|pm| {
        let activations = &mut *core::ptr::addr_of_mut!(ACTIVATIONS);
        activations.validate(
            caller,
            pm,
            &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
            &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS),
        )?;
        activations.recipient_mut(caller)?.begin_initial(caller)
    })?;
    let result = spawn_hosts::component_pump(&channel);
    observe_driver_entry_pump(&channel, &mut attempt, &result)?;
    let result = receive_driver_entry_yields(&scope, caller, None, result)?;
    use nt_user_host::provider_kernel_wait::KernelProviderStoppedOutcome;
    let stop = (&*core::ptr::addr_of!(ACTIVATIONS))
        .recipient(caller)?
        .stopped_outcome()?;
    let receipt = if matches!(stop, KernelProviderStoppedOutcome::Returned(_)) {
        Some(
            finish_observed_driver_entry_return(caller)?
                .ok_or(nt_process::STATUS_INVALID_PARAMETER)?,
        )
    } else {
        None
    };
    Ok(InitialDriverEntryOutcome {
        observation: result,
        stop,
        receipt,
    })
}

unsafe fn validate_driver_entry_execution(
    caller: KernelProviderCaller,
    capture: Option<nt_user_host::provider_kernel_activation::KernelProviderWaitCapture>,
    attempt: &KernelProviderPumpAttempt,
) -> Result<(), u32> {
    with_provider_process_manager(|pm| {
        let activations = &mut *core::ptr::addr_of_mut!(ACTIVATIONS);
        let catalog = &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS);
        let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
        if let Some(capture) = capture {
            activations.validate_wait_execution(caller, pm, catalog, lanes, capture, attempt)
        } else {
            activations.validate(caller, pm, catalog, lanes)
        }
    })
}

/// Both initial entry and selected waits retain the same channel and bank through IRQ work.
/// Receiving after a yield must never retransmit the initial request or a wait-result reply.
unsafe fn receive_driver_entry_yields(
    scope: &driver_launch::ComponentSchedulerScope,
    caller: KernelProviderCaller,
    capture: Option<nt_user_host::provider_kernel_activation::KernelProviderWaitCapture>,
    mut result: spawn_hosts::PumpResult,
) -> Result<spawn_hosts::PumpResult, u32> {
    while result.scheduler_yielded {
        let (receiving, mut receive_attempt, previous) = with_provider_process_manager(|pm| {
            let activations = &mut *core::ptr::addr_of_mut!(ACTIVATIONS);
            activations.validate(
                caller,
                pm,
                &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
                &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS),
            )?;
            activations
                .recipient_mut(caller)?
                .begin_receive_after_yield(caller)
        })?;
        validate_driver_entry_execution(caller, capture, &receive_attempt)?;
        scope.service_irq_yield(receiving.shared_va);
        // Dedicated IRQ workers can perform nested IPC. Recheck authority after those effects,
        // without minting another attempt or permitting a failed entered continuation to replay.
        validate_driver_entry_execution(caller, capture, &receive_attempt)?;
        result = spawn_hosts::component_pump_continue_receive(&receiving, &previous)?;
        observe_driver_entry_pump(&receiving, &mut receive_attempt, &result)?;
    }
    Ok(result)
}

pub(super) unsafe fn service_ps(
    channel: &spawn_hosts::PumpChannel,
    caller: KernelProviderCaller,
    op: u64,
    object: u64,
    value: u64,
) -> (i32, u64, u64, u64) {
    if authenticated_channel_caller(channel) != Ok(caller) {
        return (nt_process::STATUS_INVALID_HANDLE as i32, 0, 0, 0);
    }
    match with_provider_process_manager(|pm| {
        (&*core::ptr::addr_of!(ACTIVATIONS)).validate(
            caller,
            pm,
            &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
            &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS),
        )?;
        Ok(provider_ps::dispatch(pm, op, object, value))
    }) {
        Ok(result) => result,
        Err(status) => (status as i32, 0, 0, 0),
    }
}

pub(super) unsafe fn service_event(
    channel: &spawn_hosts::PumpChannel,
    envelope: nt_user_host::provider_kernel_activation::KernelProviderServiceEnvelope,
    op: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> (i32, u64, u64, u64) {
    let result = (|| {
        let caller = authenticated_channel_caller(channel)?;
        with_provider_process_manager(|pm| {
            (&*core::ptr::addr_of!(ACTIVATIONS)).validate_service_call(
                caller,
                pm,
                &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
                &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS),
                envelope,
                (win32k_subsystem::W32_EVENT_LABEL << 12) | 4,
            )
        })?;
        let request = nt_user_host::provider_local_event_request::LocalEventRequest::decode(
            op, arg1, arg2, arg3,
        )?;
        let owner = caller.owner();
        event::dispatch(
            nt_provider_wait::ProviderDomainIdentity {
                domain: owner.provider_domain,
                generation: owner.provider_generation,
            },
            request,
        )
    })();
    result.unwrap_or_else(|status| (status as i32, 0, 0, 0))
}

/// Authenticate the current bound call while borrowing dispatcher state. Polling retains the
/// Running activation and cannot publish a suspension or deliver another lane's continuation.
pub(super) unsafe fn service_event_poll(
    channel: &spawn_hosts::PumpChannel,
    envelope: nt_user_host::provider_kernel_activation::KernelProviderServiceEnvelope,
    request: &nt_provider_wait::ProviderWaitRequest,
) -> i32 {
    let result = (|| {
        let caller = authenticated_channel_caller(channel)?;
        event::with_dispatcher(|pm, state| {
            (&*core::ptr::addr_of!(ACTIVATIONS)).validate_event_poll(
                caller,
                pm,
                &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
                &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS),
                envelope,
                win32k_subsystem::W32_PROVIDER_WAIT_LABEL << 12,
                request,
            )?;
            state.poll(&*core::ptr::addr_of!(PROVIDER_WAIT_ARBITER), request, caller.owner())
        })
    })();
    result.unwrap_or_else(|status| status as i32)
}

/// Capture the real initialization return before the shared page or physical lane is reused.
/// A wall, scheduler yield or parked wait is not completion and retains the activation unchanged.
unsafe fn observe_driver_entry_pump(
    channel: &spawn_hosts::PumpChannel,
    attempt: &mut KernelProviderPumpAttempt,
    result: &spawn_hosts::PumpResult,
) -> Result<(), u32> {
    let caller = authenticated_channel_caller(channel)?;
    let facts = KernelProviderPumpFacts {
        observed_at: nt_time_snapshot(),
        reply_cap: result.reply_cap,
        completed: result.completed,
        callback_suspended: result.callback_suspended,
        provider_wait_suspended: result.provider_wait_suspended,
        lpc_wait_suspended: result.lpc_wait_suspended,
        scheduler_yielded: result.scheduler_yielded,
    };
    let status = facts.is_return(channel.reply_cap).then(|| {
        core::ptr::read_volatile((channel.shared_va + win32k_subsystem::SH_DE_STATUS) as *const u32)
    });
    (&mut *core::ptr::addr_of_mut!(ACTIVATIONS))
        .recipient_mut(caller)?
        .observe(attempt, *result, facts, status)?;
    if result.provider_wait_suspended {
        let page = win32k_subsystem::WIN32K_PROVIDER_WAIT_VADDR
            as *const nt_provider_wait::ProviderWaitSharedPage;
        let request = core::ptr::read_volatile(core::ptr::addr_of!((*page).request));
        // No mechanism call or bank release separates observation, capture and retention.
        // Keep the lane Running and exclusive until owned runtime readiness admission.
        with_provider_process_manager(|pm| {
            let activations = &mut *core::ptr::addr_of_mut!(ACTIVATIONS);
            let capture = activations.capture_provider_wait(
                caller,
                pm,
                &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
                &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS),
                result.reply_cap,
                activations.recipient(caller)?.progress(),
                request,
            );
            activations
                .recipient_mut(caller)?
                .retain_provider_wait(request, capture)
        })?;
    }
    Ok(())
}

/// Retry local completion recording from retained evidence only. This never repumps a stopped
/// component, rereads its shared bank, or repeats return-side cleanup after publication.
pub(crate) unsafe fn finish_observed_driver_entry_return(
    caller: KernelProviderCaller,
) -> Result<Option<KernelProviderCompletionReceipt>, u32> {
    if let Ok(receipt) = (&*core::ptr::addr_of!(ACTIVATIONS)).completion(caller) {
        return Ok(Some(receipt));
    }
    let Some(status) = (&*core::ptr::addr_of!(ACTIVATIONS))
        .recipient(caller)?
        .observed_return()
    else {
        return Ok(None);
    };
    let receipt = with_provider_process_manager(|pm| {
        (&mut *core::ptr::addr_of_mut!(ACTIVATIONS)).record_completion(
            caller,
            pm,
            &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
            &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS),
            status,
        )
    })?;
    crate::driver_launch::win32k_device_properties::retire_completed_transfers();
    Ok(Some(receipt))
}

/// Only the initiating kernel recipient acknowledges its retained result. The exact receipt and
/// both Ps references survive a failed acknowledgment; shared bytes are never read again here.
unsafe fn accept_driver_entry_completion(
    receipt: KernelProviderCompletionReceipt,
) -> Result<DriverEntryCompletion, u32> {
    with_provider_process_manager(|pm| {
        (&mut *core::ptr::addr_of_mut!(ACTIVATIONS))
            .acknowledge_completion_with_recipient(receipt, pm)
            .map(|(status, recipient)| DriverEntryCompletion::new(status, recipient))
    })
}

static DELIVERY_ACTIVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static DELIVERY_FAILURES: AtomicU64 = AtomicU64::new(0);

struct CompletionDeliveryPass {
    _message: crate::ipc_message::SavedMessageBuffer,
}

impl CompletionDeliveryPass {
    unsafe fn enter() -> Result<Self, u32> {
        if component_execution_is_busy()
            || DELIVERY_ACTIVE
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(nt_status::NtStatus::DEVICE_BUSY.raw() as u32);
        }
        Ok(Self {
            _message: crate::ipc_message::SavedMessageBuffer::capture(),
        })
    }

    unsafe fn deliver(&self, receipt: KernelProviderCompletionReceipt) -> Result<bool, u32> {
        if component_execution_is_busy() {
            return Err(nt_status::NtStatus::DEVICE_BUSY.raw() as u32);
        }
        // Cleanup of a failed DriverEntry needs no new execution. Successful delayed readiness
        // still requires the original live provider and idle physical lane before releasing refs.
        if (receipt.status() as i32) >= 0
            && !(&*core::ptr::addr_of!(ACTIVATIONS))
                .recipient(receipt.caller())?
                .can_initialize(receipt.caller())
        {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        let completion = accept_driver_entry_completion(receipt)?;
        // Neither an activation nor a Ps-manager borrow crosses readiness's nested IPC.
        Ok(completion.initialize())
    }
}

impl Drop for CompletionDeliveryPass {
    fn drop(&mut self) {
        DELIVERY_ACTIVE.store(false, Ordering::Release);
    }
}

fn report_deferred(receipt: KernelProviderCompletionReceipt, status: u32) {
    if DELIVERY_FAILURES.fetch_add(1, Ordering::Relaxed) < 16 {
        print_str(b"[kernel-bootstrap] completion retained provider=");
        print_u64(receipt.caller().owner().provider_domain);
        print_str(b" status=0x");
        print_hex(status);
        print_str(b"\n");
    }
}

/// Eager bootstrap uses exactly the same guarded delivery as the outer-loop retry boundary.
pub(crate) unsafe fn deliver_driver_entry_completion(
    receipt: KernelProviderCompletionReceipt,
) -> Result<bool, u32> {
    let _durable = allocator::enter_durable();
    match CompletionDeliveryPass::enter() {
        Ok(pass) => {
            let result = pass.deliver(receipt);
            if let Err(status) = result {
                report_deferred(receipt, status);
            }
            result
        }
        Err(status) => Err(status),
    }
}

/// Observe canonical retry demand without acquiring a delivery attempt or releasing references.
pub(super) unsafe fn has_ready_completions() -> bool {
    (&*core::ptr::addr_of!(ACTIVATIONS)).has_ready_completion() || terminal::has_ready()
}

/// Deliver retained kernel terminals and genuine Ready receipts, once per bounded pass.
/// Return acknowledged ownership progress, not DriverEntry success. Never invoke from a nested
/// pump timer hook or with handler/PM borrows alive: initialization belongs to the outer scheduler.
pub(super) unsafe fn redrive_ready_completions() -> bool {
    if !has_ready_completions() {
        return false;
    }
    let Ok(pass) = CompletionDeliveryPass::enter() else {
        return false;
    };
    let _durable = allocator::enter_durable();
    let mut progressed = terminal::drain();
    // Terminal retirement can publish an older activation than the initial readiness probe.
    let mut cursor = (&*core::ptr::addr_of!(ACTIVATIONS)).completion_cursor();
    let Some(mut receipt) = (&*core::ptr::addr_of!(ACTIVATIONS)).next_ready_completion(&mut cursor)
    else {
        return progressed;
    };
    loop {
        if let Err(status) = pass.deliver(receipt) {
            report_deferred(receipt, status);
        } else {
            // Ok(false) still acknowledged the result and released the canonical Ps pair.
            progressed = true;
        }
        let Some(next) = (&*core::ptr::addr_of!(ACTIVATIONS)).next_ready_completion(&mut cursor)
        else {
            break;
        };
        receipt = next;
    }
    progressed
}
