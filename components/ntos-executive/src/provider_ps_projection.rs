//! Ps pointer publication requires the executing provider's acknowledged canonical alias.

use super::*;
use spawn_hosts::shared_ingress::owner::runtime;

/// The enclosing Ps service has authenticated its logical caller or kernel activation. This
/// independently binds the mapping to its retained physical source, not ambient caller state.
/// No component IPC may be pumped while the canonical manager and page owner are borrowed.
pub(crate) unsafe fn grant(
    channel: &spawn_hosts::PumpChannel,
    pm: &nt_process::ProcessManager,
    body: u64,
) -> Result<(), u32> {
    let invalid = nt_process::STATUS_INVALID_HANDLE;
    let route = runtime::channel_route(channel)
        .map_err(|_| invalid)?
        .ok_or(invalid)?;
    let source = runtime::physical_source(route).map_err(|_| invalid)?;
    runtime::dispatch(route).map_err(|_| invalid)?;
    if runtime::current_reply(route).map_err(|_| invalid)? != channel.reply_cap
        || channel.caps.kind != spawn_hosts::ReqKind::Syscall
        || source.pml4 != channel.pml4
        || source.tcb != channel.tcb
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
    if current_win32k_provider_domain() != Some(domain) {
        return Err(invalid);
    }
    let target = ps_object_provider::ProviderRoot::new(catalog, domain, source.pml4)?;
    ps_object_backing::grant_referenced_body(
        pm,
        body,
        target,
        ACTIVE_SCRATCH_BASE.load(Ordering::Relaxed),
    )
}
