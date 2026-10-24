//! Exact system-context cookie projection beneath a live miniport device.

use super::*;
use nt_hosted_runtime::{DxgContextAliasKey, DxgContextCookieRetirement,
    DxgCreateContextLayout};

pub(super) struct DxgContextAlias {
    request_guard: Option<DxgQueryOutputGuard>,
    kmd_guard: Option<StartOutputGuard>,
    key: Option<DxgContextAliasKey>,
    free_route: Option<nt_component_suspension::peer_registry::PeerRoute>,
    retirement: Option<DxgContextCookieRetirement>,
    destroy_entered: bool,
}

pub(crate) unsafe fn create(
    dispatch: &mut HostedProviderCallbackDispatcher<'_>,
    marshal_window: HostedProviderMarshalWindow,
    provider_inst: DriverInstance,
    record: HostedProviderCallbackRecord,
    dependent_inst: DriverInstance,
    exec_code_va: u64,
    kmd_device: u64,
    provider_request: u64,
) -> Result<u64, i32> {
    if kmd_device == 0 { return Err(STATUS_INVALID_PARAMETER); }
    let owner = hosted_provider_object_owner_for_pair(
        record.provider_instance, record.dependent_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let (alias_index, device_index) = {
        let mut found = None;
        for (alias_index, alias) in pdo_aliases_mut().iter().enumerate() {
            if alias.provider_instance != record.provider_instance
                || alias.dependent_instance != record.dependent_instance
                || alias.provider_domain != record.provider_domain
                || alias.dependent_domain != record.dependent_domain
                || alias.provider_publication_cookie != record.provider_publication_cookie
                || !alias.start_succeeded || alias.blocked || alias.pointer_retired
            { continue; }
            let Some(authority) = alias.authority else { continue; };
            for (device_index, device) in alias.devices.iter().enumerate() {
                let Some(guard) = device.kmd_guard.as_ref() else { continue; };
                if !device.destroy_entered && device.key.is_some_and(|key|
                    key.matches_destroy(authority, kmd_device,
                        guard.allocation.pool_generation)) {
                    if found.replace((alias_index, device_index)).is_some() {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                }
            }
        }
        found.ok_or(STATUS_INVALID_PARAMETER)?
    };
    let alias = &pdo_aliases_mut()[alias_index];
    let dependent_pdo = alias.dependent_alias.ok_or(STATUS_INVALID_PARAMETER)?;
    let context_allocation = alias.context_allocation.ok_or(STATUS_INVALID_PARAMETER)?;
    let authority = alias.authority.ok_or(STATUS_INVALID_PARAMETER)?;
    let device_key = alias.devices[device_index].key.ok_or(STATUS_INVALID_PARAMETER)?;
    let device_guard = alias.devices[device_index].kmd_guard.as_ref().unwrap();
    if instance_domain_identity(provider_inst) != Some(record.provider_domain)
        || instance_domain_identity(dependent_inst) != Some(record.dependent_domain)
        || hosted_device_allocations::capture_allocation(dependent_inst, alias.context).ok()
            != Some(context_allocation)
        || io_manager_mut().hosted_device_pointer_registration(
            record.provider_domain, alias.provider_pdo.address()) != Some(alias.provider_pdo)
        || io_manager_mut().hosted_device_pointer_registration(
            record.dependent_domain, dependent_pdo.address()) != Some(dependent_pdo)
        || !authority.matches(owner, record.provider_publication_cookie,
            alias.provider_pdo.device_id().raw(), alias.provider_pdo.address(),
            alias.provider_pdo.generation(), dependent_pdo.address(), dependent_pdo.generation())
        || !device_guard.live(dependent_inst, record.dependent_domain)
    { return Err(STATUS_INVALID_PARAMETER); }
    provider_callback_marshal_window(marshal_window, 0x48, 0)?;
    let request_guard = DxgQueryOutputGuard::capture(provider_inst, record.provider_domain,
        provider_request, 0x48, alias.provider_fdo_allocation, alias.provider_fdo)?;
    let request_exec = component_to_exec_va_for_instance(record.provider_instance,
        provider_inst, provider_request, 0x48).ok_or(STATUS_INVALID_PARAMETER)?;
    if !request_guard.live(provider_inst, record.provider_domain) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let request = core::slice::from_raw_parts(request_exec as *const u8, 0x48);
    let layout = DxgCreateContextLayout::parse(record.callback_version,
        request, marshal_window.capacity).ok_or(STATUS_NOT_SUPPORTED)?;
    let mut original = [0u8; 0x48];
    original.copy_from_slice(request);
    copy_bytes(marshal_window.exec_base, request_exec, 0x48);
    let dependent_request = core::slice::from_raw_parts_mut(
        marshal_window.exec_base as *mut u8, 0x48);
    dependent_request[..8].fill(0);
    dependent_request[0x24..0x44].fill(0);
    pdo_aliases_mut()[alias_index].devices[device_index].contexts.try_reserve(1)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    pdo_aliases_mut()[alias_index].devices[device_index].contexts.push(DxgContextAlias {
        request_guard: Some(request_guard), kmd_guard: None, key: None,
        free_route: None, retirement: None, destroy_entered: false,
    });
    pdo_aliases_mut()[alias_index].blocked = true;
    let context_index = pdo_aliases_mut()[alias_index].devices[device_index].contexts.len() - 1;
    let outcome = dispatch_dependent_provider_callback(dispatch, record, dependent_inst,
        exec_code_va, [kmd_device, marshal_window.component_base, 0, 0],
        [0; PROVIDER_CALLBACK_STACK_QWORDS]);
    let result = match outcome {
        Ok(result) => result,
        Err(status) => {
            pdo_aliases_mut()[alias_index].devices[device_index].contexts[context_index]
                .request_guard.as_ref().unwrap().retain_uncertain();
            return Err(status);
        }
    };
    if (result as u32 as i32) < 0 {
        pdo_aliases_mut()[alias_index].devices[device_index].contexts[context_index]
            .request_guard.as_ref().unwrap().retain_uncertain();
        return Ok(result);
    }
    let returned = core::slice::from_raw_parts(marshal_window.exec_base as *const u8, 0x48);
    let kmd_context = read_unaligned(marshal_window.exec_base as *const u64);
    if kmd_context == 0 { return Err(STATUS_INVALID_PARAMETER); }
    let kmd_guard = StartOutputGuard::capture(dependent_inst, record.dependent_domain,
        kmd_context, 1, alias.provider_fdo_allocation, alias.provider_fdo)?;
    let key = DxgContextAliasKey::new(device_key, layout.runtime_context(), 0,
        kmd_context, kmd_guard.allocation.pool_generation)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    pdo_aliases_mut()[alias_index].devices[device_index].contexts[context_index]
        .kmd_guard = Some(kmd_guard);
    pdo_aliases_mut()[alias_index].devices[device_index].contexts[context_index]
        .key = Some(key);
    if pdo_aliases_mut().iter().enumerate().any(|(other_alias, alias)| {
        alias.dependent_domain == record.dependent_domain
            && alias.devices.iter().enumerate().any(|(other_device, device)| {
                device.contexts.iter().enumerate().any(|(other_context, context)| {
                    (other_alias, other_device, other_context)
                        != (alias_index, device_index, context_index)
                        && context.key.is_some_and(|other| other.cookie_address_conflicts(key))
                })
            })
    }) {
        let context = &pdo_aliases_mut()[alias_index].devices[device_index]
            .contexts[context_index];
        context.request_guard.as_ref().unwrap().retain_uncertain();
        context.kmd_guard.as_ref().unwrap().retain_uncertain();
        return Err(STATUS_INVALID_PARAMETER);
    }
    if !layout.copyback(&mut original, returned) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let context = &mut pdo_aliases_mut()[alias_index].devices[device_index]
        .contexts[context_index];
    if let Err(status) = context.request_guard.as_ref().unwrap().write_bytes(
        record.provider_instance, provider_inst, record.provider_domain, &original) {
        context.request_guard.as_ref().unwrap().retain_uncertain();
        context.kmd_guard.as_ref().unwrap().retain_uncertain();
        return Err(status);
    }
    context.request_guard.as_mut().unwrap().release()?;
    context.request_guard = None;
    pdo_aliases_mut()[alias_index].blocked = false;
    Ok(result)
}

pub(crate) unsafe fn destroy(
    dispatch: &mut HostedProviderCallbackDispatcher<'_>,
    provider_inst: DriverInstance,
    record: HostedProviderCallbackRecord,
    dependent_inst: DriverInstance,
    exec_code_va: u64,
    kmd_context: u64,
) -> Result<u64, i32> {
    if kmd_context == 0 { return Err(STATUS_INVALID_PARAMETER); }
    let owner = hosted_provider_object_owner_for_pair(
        record.provider_instance, record.dependent_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let (alias_index, device_index, context_index) = {
        let mut found = None;
        for (alias_index, alias) in pdo_aliases_mut().iter().enumerate() {
            if alias.provider_instance != record.provider_instance
                || alias.dependent_instance != record.dependent_instance
                || alias.provider_domain != record.provider_domain
                || alias.dependent_domain != record.dependent_domain
                || alias.provider_publication_cookie != record.provider_publication_cookie
                || !alias.start_succeeded || alias.blocked || alias.pointer_retired
            { continue; }
            let Some(authority) = alias.authority else { continue; };
            for (device_index, device) in alias.devices.iter().enumerate() {
                let Some(device_guard) = device.kmd_guard.as_ref() else { continue; };
                let Some(device_key) = device.key else { continue; };
                if device.destroy_entered || !device_key.matches_destroy(authority,
                    device_guard.address, device_guard.allocation.pool_generation)
                { continue; }
                for (context_index, context) in device.contexts.iter().enumerate() {
                    let Some(guard) = context.kmd_guard.as_ref() else { continue; };
                    if !context.destroy_entered && context.key.is_some_and(|key|
                        key.matches_destroy(device_key, kmd_context,
                            guard.allocation.pool_generation)) {
                        if found.replace((alias_index, device_index, context_index)).is_some() {
                            return Err(STATUS_INVALID_PARAMETER);
                        }
                    }
                }
            }
        }
        found.ok_or(STATUS_INVALID_PARAMETER)?
    };
    let alias = &pdo_aliases_mut()[alias_index];
    let dependent_pdo = alias.dependent_alias.ok_or(STATUS_INVALID_PARAMETER)?;
    let context_allocation = alias.context_allocation.ok_or(STATUS_INVALID_PARAMETER)?;
    if instance_domain_identity(provider_inst) != Some(record.provider_domain)
        || instance_domain_identity(dependent_inst) != Some(record.dependent_domain)
        || hosted_device_allocations::capture_allocation(dependent_inst, alias.context).ok()
            != Some(context_allocation)
        || io_manager_mut().hosted_device_pointer_registration(
            record.provider_domain, alias.provider_pdo.address()) != Some(alias.provider_pdo)
        || io_manager_mut().hosted_device_pointer_registration(
            record.dependent_domain, dependent_pdo.address()) != Some(dependent_pdo)
        || !alias.authority.unwrap().matches(owner, record.provider_publication_cookie,
            alias.provider_pdo.device_id().raw(), alias.provider_pdo.address(),
            alias.provider_pdo.generation(), dependent_pdo.address(), dependent_pdo.generation())
        || !alias.devices[device_index].kmd_guard.as_ref().unwrap()
            .live(dependent_inst, record.dependent_domain)
        || !alias.devices[device_index].contexts[context_index]
            .kmd_guard.as_ref().unwrap().live(dependent_inst, record.dependent_domain)
    { return Err(STATUS_INVALID_PARAMETER); }
    let route = hosted_ingress_sources::primary_route(record.dependent_instance)
        .ok_or(STATUS_DEVICE_NOT_READY)?;
    if route.identity().executor != dependent_inst.tcb
        || route.endpoint() != dependent_inst.fault_ep
    { return Err(STATUS_INVALID_PARAMETER); }
    let route_identity = process::free_route_identity(record.dependent_domain, route)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let key = alias.devices[device_index].contexts[context_index]
        .key.ok_or(STATUS_INVALID_PARAMETER)?;
    let retirement = DxgContextCookieRetirement::new(key, route_identity)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let context = &mut pdo_aliases_mut()[alias_index].devices[device_index]
        .contexts[context_index];
    context.destroy_entered = true;
    context.free_route = Some(route);
    context.retirement = Some(retirement);
    pdo_aliases_mut()[alias_index].blocked = true;
    let outcome = dispatch_dependent_provider_callback(dispatch, record, dependent_inst,
        exec_code_va, [kmd_context, 0, 0, 0],
        [0; PROVIDER_CALLBACK_STACK_QWORDS]);
    pdo_aliases_mut()[alias_index].devices[device_index].contexts[context_index]
        .retirement.as_mut().unwrap().close_callback_interval();
    let result = outcome?;
    if (result as u32 as i32) < 0 { return Ok(result); }
    let context = &mut pdo_aliases_mut()[alias_index].devices[device_index]
        .contexts[context_index];
    let retirement = context.retirement.as_mut().unwrap();
    let guard = context.kmd_guard.as_mut().unwrap();
    if retirement.free_requested() {
        if !retirement.complete(true, true) { return Err(STATUS_INVALID_PARAMETER); }
        guard.complete_deferred_free()?;
    } else {
        if !retirement.release_without_free(true, true) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        guard.release()?;
    }
    pdo_aliases_mut()[alias_index].devices[device_index].contexts.remove(context_index);
    pdo_aliases_mut()[alias_index].blocked = false;
    Ok(result)
}

pub(crate) unsafe fn defer_cookie_free(
    channel: &crate::spawn_hosts::PumpChannel,
    instance_index: usize,
    inst: DriverInstance,
    domain: HostedDomainIdentity,
    address: u64,
    caller_badge: u64,
    active_reply_cap: u64,
) -> Option<i32> {
    if address == 0 || active_reply_cap == 0
        || instance_domain_identity(inst) != Some(domain)
        || instance_for_pump_channel(channel, active_reply_cap)?.0 != instance_index
        || hosted_driver_pump_caller_tcb(channel, active_reply_cap, caller_badge)? != channel.tcb
    { return None; }
    let route = channel.ingress_route?;
    if route.badge() != caller_badge || route.identity().executor != channel.tcb
        || hosted_ingress_sources::primary_route(instance_index) != Some(route)
    { return None; }
    let route_identity = process::free_route_identity(domain, route)?;
    let mut found = None;
    for (alias_index, alias) in pdo_aliases_mut().iter().enumerate() {
        if alias.dependent_instance != instance_index || alias.dependent_domain != domain
            || !alias.blocked
        { continue; }
        for (device_index, device) in alias.devices.iter().enumerate() {
            for (context_index, context) in device.contexts.iter().enumerate() {
                if !context.destroy_entered || context.free_route != Some(route)
                    || context.kmd_guard.as_ref().is_none_or(|guard|
                        guard.address != address || guard.allocation.component_address != address
                            || !guard.live(inst, domain))
                    || context.retirement.is_none()
                { continue; }
                if found.replace((alias_index, device_index, context_index)).is_some() {
                    return None;
                }
            }
        }
    }
    let (alias_index, device_index, context_index) = found?;
    let context = &mut pdo_aliases_mut()[alias_index].devices[device_index]
        .contexts[context_index];
    let guard = context.kmd_guard.as_ref()?;
    if !context.retirement.as_mut()?.request_free(context.key?, route_identity,
        address, guard.allocation.pool_generation)
    { return None; }
    Some(nt_status::NtStatus::PENDING.raw())
}
