//! Canonical caller references for kernel-originated physical provider jobs.

use super::*;
use nt_component_suspension::{LaneBinding, LaneHandle};
use nt_user_host::provider_kernel_activation::{KernelProviderActivations, KernelProviderCaller};

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
    if !kernel_channel(channel)
        || channel.kernel_caller != Some(caller)
        || caller.binding() != channel_binding(channel)
        || current_win32k_provider_domain().is_none_or(|provider| {
            caller.owner().provider_domain != provider.domain
                || caller.owner().provider_generation != provider.generation
        })
    {
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

/// Only the observed completion sentinel may retire DriverEntry. A wall or uncertain reply keeps
/// the row and both references; future terminal/cancellation wiring must retire those explicitly.
pub(crate) unsafe fn release_completed(caller: KernelProviderCaller) -> Result<(), u32> {
    let nt_component_suspension::SuspensionCaller::Kernel { lane } = caller.owner().caller else {
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    };
    if !component_execution_lane_is_idle(lane) {
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }
    with_provider_process_manager(|pm| {
        (&mut *core::ptr::addr_of_mut!(ACTIVATIONS)).release(caller, pm)
    })
}
