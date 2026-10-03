//! Exact retained service invocation, independent of authority to open native handles.

use super::*;
use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use spawn_hosts::shared_ingress::owner::runtime;

pub(crate) unsafe fn authenticate(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    expected_mi: u64,
) -> Result<(PeerRoute, LaneDispatchIdentity), u32> {
    let invalid = nt_process::STATUS_INVALID_PARAMETER;
    if channel.caps.kind != spawn_hosts::ReqKind::Syscall
        || mi != expected_mi
        || reply_cap != channel.reply_cap
    {
        return Err(invalid);
    }
    let route = runtime::channel_route(channel)
        .map_err(|_| invalid)?
        .ok_or(invalid)?;
    if route.badge() != badge || runtime::current_reply(route).map_err(|_| invalid)? != reply_cap {
        return Err(invalid);
    }
    let dispatch = runtime::dispatch(route).map_err(|_| invalid)?;
    if channel.logical_caller.is_some() && channel.kernel_caller.is_some() {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    if channel.kernel_caller.is_some() {
        let envelope = nt_user_host::provider_kernel_activation::KernelProviderServiceEnvelope {
            badge,
            message_info: mi,
            reply_cap,
        };
        service_sec_image::kernel_provider_activation::validate_win32k_service_call(
            channel,
            envelope,
            expected_mi,
        )?;
    }
    Ok((route, dispatch))
}

/// The source is a physical provider execution owner, not the logical requestor's handle scope.
pub(crate) unsafe fn physical_win32k_provider(
    channel: &spawn_hosts::PumpChannel,
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
) -> Result<runtime::PhysicalSource, u32> {
    let invalid = nt_process::STATUS_INVALID_HANDLE;
    let source = runtime::physical_source(route).map_err(|_| invalid)?;
    if source.tcb != channel.tcb
        || source.pml4 != channel.pml4
        || runtime::dispatch(route).map_err(|_| invalid)? != dispatch
        || runtime::current_reply(route).map_err(|_| invalid)? != channel.reply_cap
        || win32k_glue::win32k_physical_lane_for_channel(
            channel.tcb,
            channel.fault_ep,
            channel.reply_cap,
        ) != Some(route.identity().lane)
    {
        return Err(invalid);
    }
    let runtime::PhysicalDomain::Provider { catalog, domain } = source.domain else {
        return Err(invalid);
    };
    if (&*core::ptr::addr_of!(PROVIDER_WAIT_DOMAINS)).identity() != Some(catalog)
        || current_win32k_provider_domain() != Some(domain)
        || !win32k_provider_domain_is_current(domain)
    {
        return Err(invalid);
    }
    Ok(source)
}
