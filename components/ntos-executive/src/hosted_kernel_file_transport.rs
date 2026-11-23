//! Exact retained File transport validation for hosted driver lanes.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;

/// Resolve the exact still-running physical lane before publishing a retained File terminal.
/// The component packet lives in the instance's pool, but its completion belongs to the bank
/// that issued this service. A bank address or instance ID alone is never sufficient authority.
pub(super) unsafe fn live_instance(
    channel: &crate::spawn_hosts::PumpChannel,
    captured: nt_io_manager::HostedTransportIdentity,
    retained: DriverInstance,
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
) -> Option<DriverInstance> {
    if runtime::channel_route(channel).ok()?? != route
        || runtime::dispatch(route).ok()? != dispatch
        || runtime::current_reply(route).ok()? != reply
    {
        return None;
    }
    let (index, live) = instance_by_shared_va(channel.shared_va)
        .or_else(|| hosted_source_completion_lane::instance_for_shared(channel.shared_va))
        .or_else(|| hosted_class_irp_lane::instance_for_shared(channel.shared_va))
        .or_else(|| hosted_provider_export_lane::instance_for_shared(channel.shared_va))?;
    let primary = channel.shared_va == live.exec_shared_va
        && channel.fault_ep == live.fault_ep
        && channel.tcb == live.tcb;
    let worker = hosted_source_completion_lane::matches_channel(index, live, channel)
        || hosted_class_irp_lane::matches_channel(index, live, channel)
        || hosted_provider_export_lane::matches_channel(index, live, channel);
    if !primary && !worker {
        return None;
    }
    let live_domain = instance_domain_identity(live)?;
    let live_transport = nt_io_manager::HostedTransportIdentity {
        domain: live_domain,
        endpoint: channel.fault_ep,
        vspace: live.pml4,
        shared: channel.shared_va,
    };
    (captured.matches_live(live_transport)
        && live_domain == instance_domain_identity(retained)?
        && live.driver_id == retained.driver_id
        && live.exec_pool_va == retained.exec_pool_va)
        .then_some(live)
}
