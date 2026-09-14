//! Canonical caller references for kernel-originated physical provider jobs.

use super::*;
use nt_component_suspension::{LaneBinding, LaneHandle};
use nt_user_host::provider_kernel_activation::{
    KernelProviderActivations, KernelProviderCaller, KernelProviderCompletionReceipt,
};

static mut ACTIVATIONS: KernelProviderActivations = KernelProviderActivations::new();

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
    with_provider_process_manager(|pm| {
        if !pm.validate_initial_system_caller(system) {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        let native =
            pm.capture_native_handle_caller(system.thread(), nt_types::AccessMode::KernelMode)?;
        (&mut *core::ptr::addr_of_mut!(ACTIVATIONS)).capture(
            pm,
            &*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS),
            lanes,
            provider,
            lane,
            native,
        )
    })
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

/// Capture the real initialization return before the shared page or physical lane is reused.
/// A wall, scheduler yield or parked wait is not completion and retains the activation unchanged.
pub(crate) unsafe fn record_driver_entry_return(
    channel: &spawn_hosts::PumpChannel,
    result: &spawn_hosts::PumpResult,
) -> Result<KernelProviderCompletionReceipt, u32> {
    let caller = authenticated_channel_caller(channel)?;
    if !result.completed
        || result.callback_suspended
        || result.provider_wait_suspended
        || result.lpc_wait_suspended
        || result.scheduler_yielded
        || result.reply_cap != channel.reply_cap
    {
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }
    let status = core::ptr::read_volatile(
        (channel.shared_va + win32k_subsystem::SH_DE_STATUS) as *const u32,
    );
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
    Ok(receipt)
}

/// Only the initiating kernel recipient acknowledges its retained result. The exact receipt and
/// both Ps references survive a failed acknowledgment; shared bytes are never read again here.
pub(crate) unsafe fn acknowledge_completion(
    receipt: KernelProviderCompletionReceipt,
) -> Result<u32, u32> {
    with_provider_process_manager(|pm| {
        (&mut *core::ptr::addr_of_mut!(ACTIVATIONS)).acknowledge_completion(receipt, pm)
    })
}
