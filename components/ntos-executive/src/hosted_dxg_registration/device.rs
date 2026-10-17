//! Generation-bound WDDM miniport device cookies for the pinned x64 ABI.

use super::*;
use nt_hosted_runtime::{DxgCreateDeviceLayout, DxgDeviceAliasKey,
    DxgDeviceCookieRetirement};

pub(super) struct DxgDeviceAlias {
    request_guard: Option<DxgQueryOutputGuard>,
    kmd_guard: Option<StartOutputGuard>,
    key: Option<DxgDeviceAliasKey>,
    free_route: Option<nt_component_suspension::peer_registry::PeerRoute>,
    retirement: Option<DxgDeviceCookieRetirement>,
    destroy_entered: bool,
}

impl DxgDeviceAlias {
    pub(super) fn linked_process(&self, cookie: u64) -> bool {
        self.key.is_some_and(|key| key.kmd_process() == cookie)
    }
}

pub(super) unsafe fn create(
    dispatch: &mut HostedProviderCallbackDispatcher<'_>,
    marshal_window: HostedProviderMarshalWindow,
    provider_inst: DriverInstance,
    record: HostedProviderCallbackRecord,
    dependent_inst: DriverInstance,
    exec_code_va: u64,
    provider_context: u64,
    provider_request: u64,
) -> Result<u64, i32> {
    let owner = hosted_provider_object_owner_for_pair(
        record.provider_instance, record.dependent_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let alias_index = pdo_aliases_mut().iter().position(|alias| {
        alias.provider_instance == record.provider_instance
            && alias.dependent_instance == record.dependent_instance
            && alias.provider_domain == record.provider_domain
            && alias.dependent_domain == record.dependent_domain
            && alias.provider_publication_cookie == record.provider_publication_cookie
            && alias.context == provider_context && alias.context_allocation.is_some()
            && alias.start_entered && alias.start_succeeded && !alias.start_callback_active
            && !alias.blocked && !alias.pointer_retired && alias.interface_handle != 0
            && alias.authority.is_some()
    }).ok_or(STATUS_INVALID_PARAMETER)?;
    let alias = &pdo_aliases_mut()[alias_index];
    let authority = alias.authority.ok_or(STATUS_INVALID_PARAMETER)?;
    let dependent_pdo = alias.dependent_alias.ok_or(STATUS_INVALID_PARAMETER)?;
    let context_allocation = alias.context_allocation.ok_or(STATUS_INVALID_PARAMETER)?;
    let provider_pdo = alias.provider_pdo;
    let provider_fdo_allocation = alias.provider_fdo_allocation;
    let provider_fdo = alias.provider_fdo;
    if instance_domain_identity(provider_inst) != Some(record.provider_domain)
        || instance_domain_identity(dependent_inst) != Some(record.dependent_domain)
        || hosted_device_allocations::capture_allocation(dependent_inst, provider_context).ok()
            != Some(context_allocation)
        || io_manager_mut().hosted_device_pointer_registration(
            record.provider_domain, provider_pdo.address()) != Some(provider_pdo)
        || io_manager_mut().hosted_device_pointer_registration(
            record.dependent_domain, dependent_pdo.address()) != Some(dependent_pdo)
        || !authority.matches(owner, record.provider_publication_cookie,
            provider_pdo.device_id().raw(), provider_pdo.address(),
            provider_pdo.generation(), dependent_pdo.address(), dependent_pdo.generation())
    { return Err(STATUS_INVALID_PARAMETER); }
    provider_callback_marshal_window(marshal_window, 0x20, 0)?;
    let request_guard = DxgQueryOutputGuard::capture(provider_inst, record.provider_domain,
        provider_request, 0x20, provider_fdo_allocation, provider_fdo)?;
    let request_exec = component_to_exec_va_for_instance(
        record.provider_instance, provider_inst, provider_request, 0x20)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if !request_guard.live(provider_inst, record.provider_domain) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let request = core::slice::from_raw_parts(request_exec as *const u8, 0x20);
    let layout = DxgCreateDeviceLayout::parse(
        record.callback_version, request, marshal_window.capacity)
        .ok_or(STATUS_NOT_SUPPORTED)?;
    let kmd_process = layout.kmd_process();
    let process_generation = if kmd_process == 0 {
        if alias.null_process_credits.is_none_or(|credits| credits.count() == 0) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        0
    } else {
        let mut generation = None;
        for process in alias.processes.iter() {
            if let Some(found) = process.live_kmd_cookie(
                dependent_inst, record.dependent_domain, kmd_process) {
                if generation.replace(found).is_some() { return Err(STATUS_INVALID_PARAMETER); }
            }
        }
        generation.ok_or(STATUS_INVALID_PARAMETER)?
    };
    let mut original = [0u8; 0x20];
    original.copy_from_slice(request);
    copy_bytes(marshal_window.exec_base, request_exec, 0x20);
    pdo_aliases_mut()[alias_index].devices.try_reserve(1)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    pdo_aliases_mut()[alias_index].devices.push(DxgDeviceAlias {
        request_guard: Some(request_guard), kmd_guard: None, key: None,
        free_route: None, retirement: None, destroy_entered: false,
    });
    pdo_aliases_mut()[alias_index].blocked = true;
    let device_index = pdo_aliases_mut()[alias_index].devices.len() - 1;
    let outcome = dispatch_dependent_provider_callback(dispatch, record,
        dependent_inst, exec_code_va,
        [provider_context, marshal_window.component_base, 0, 0],
        [0; PROVIDER_CALLBACK_STACK_QWORDS]);
    let result = match outcome {
        Ok(result) => result,
        Err(status) => {
            pdo_aliases_mut()[alias_index].devices[device_index]
                .request_guard.as_ref().unwrap().retain_uncertain();
            return Err(status);
        }
    };
    if (result as u32 as i32) < 0 {
        pdo_aliases_mut()[alias_index].devices[device_index]
            .request_guard.as_ref().unwrap().retain_uncertain();
        return Ok(result);
    }
    let kmd_device = read_unaligned(marshal_window.exec_base as *const u64);
    if kmd_device == 0 { return Err(STATUS_INVALID_PARAMETER); }
    let kmd_guard = StartOutputGuard::capture(dependent_inst, record.dependent_domain,
        kmd_device, 1, provider_fdo_allocation, provider_fdo)?;
    let key = DxgDeviceAliasKey::new(authority, provider_context,
        context_allocation.pool_generation, kmd_process, process_generation,
        kmd_device, kmd_guard.allocation.pool_generation)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    pdo_aliases_mut()[alias_index].devices[device_index].kmd_guard = Some(kmd_guard);
    pdo_aliases_mut()[alias_index].devices[device_index].key = Some(key);
    if pdo_aliases_mut().iter().enumerate().any(|(other_alias, alias)| {
        alias.dependent_domain == record.dependent_domain
            && alias.devices.iter().enumerate().any(|(other_device, device)| {
                (other_alias, other_device) != (alias_index, device_index)
                    && device.key.is_some_and(|other| other.cookie_address_conflicts(key))
            })
    }) {
        let device = &pdo_aliases_mut()[alias_index].devices[device_index];
        device.request_guard.as_ref().unwrap().retain_uncertain();
        device.kmd_guard.as_ref().unwrap().retain_uncertain();
        return Err(STATUS_INVALID_PARAMETER);
    }
    if !layout.copyback_device(&mut original, kmd_device) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let device = &mut pdo_aliases_mut()[alias_index].devices[device_index];
    if let Err(status) = device.request_guard.as_ref().unwrap().write_bytes(
        record.provider_instance, provider_inst, record.provider_domain, &original) {
        device.request_guard.as_ref().unwrap().retain_uncertain();
        device.kmd_guard.as_ref().unwrap().retain_uncertain();
        return Err(status);
    }
    device.request_guard.as_mut().unwrap().release()?;
    device.request_guard = None;
    pdo_aliases_mut()[alias_index].blocked = false;
    Ok(result)
}

pub(super) unsafe fn destroy(
    dispatch: &mut HostedProviderCallbackDispatcher<'_>,
    provider_inst: DriverInstance,
    record: HostedProviderCallbackRecord,
    dependent_inst: DriverInstance,
    exec_code_va: u64,
    kmd_device: u64,
) -> Result<u64, i32> {
    if kmd_device == 0 { return Err(STATUS_INVALID_PARAMETER); }
    let owner = hosted_provider_object_owner_for_pair(
        record.provider_instance, record.dependent_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let (alias_index, device_index) = {
        let mut match_row = None;
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
                if device.destroy_entered { continue; }
                let Some(guard) = device.kmd_guard.as_ref() else { continue; };
                if device.key.is_some_and(|key| key.matches_destroy(authority,
                    kmd_device, guard.allocation.pool_generation)) {
                    if match_row.replace((alias_index, device_index)).is_some() {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                }
            }
        }
        match_row.ok_or(STATUS_INVALID_PARAMETER)?
    };
    let alias = &pdo_aliases_mut()[alias_index];
    let dependent_pdo = alias.dependent_alias.ok_or(STATUS_INVALID_PARAMETER)?;
    let authority = alias.authority.ok_or(STATUS_INVALID_PARAMETER)?;
    let context_allocation = alias.context_allocation.ok_or(STATUS_INVALID_PARAMETER)?;
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
        || !alias.devices[device_index].kmd_guard.as_ref().unwrap()
            .live(dependent_inst, record.dependent_domain)
    { return Err(STATUS_INVALID_PARAMETER); }
    let route = hosted_ingress_sources::primary_route(record.dependent_instance)
        .ok_or(STATUS_DEVICE_NOT_READY)?;
    if route.identity().executor != dependent_inst.tcb
        || route.endpoint() != dependent_inst.fault_ep
    { return Err(STATUS_INVALID_PARAMETER); }
    let route_identity = process::free_route_identity(record.dependent_domain, route)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let key = alias.devices[device_index].key.ok_or(STATUS_INVALID_PARAMETER)?;
    let retirement = DxgDeviceCookieRetirement::new(key, route_identity)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let device = &mut pdo_aliases_mut()[alias_index].devices[device_index];
    device.destroy_entered = true;
    device.free_route = Some(route);
    device.retirement = Some(retirement);
    pdo_aliases_mut()[alias_index].blocked = true;
    let outcome = dispatch_dependent_provider_callback(dispatch, record, dependent_inst,
        exec_code_va, [kmd_device, 0, 0, 0],
        [0; PROVIDER_CALLBACK_STACK_QWORDS]);
    pdo_aliases_mut()[alias_index].devices[device_index].retirement
        .as_mut().unwrap().close_callback_interval();
    let result = outcome?;
    if (result as u32 as i32) < 0 { return Ok(result); }
    let device = &mut pdo_aliases_mut()[alias_index].devices[device_index];
    let retirement = device.retirement.as_mut().unwrap();
    let guard = device.kmd_guard.as_mut().unwrap();
    if retirement.free_requested() {
        if !retirement.complete(true, true) { return Err(STATUS_INVALID_PARAMETER); }
        guard.complete_deferred_free()?;
    } else {
        if !retirement.release_without_free(true, true) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        guard.release()?;
    }
    pdo_aliases_mut()[alias_index].devices.remove(device_index);
    pdo_aliases_mut()[alias_index].blocked = false;
    Ok(result)
}

pub(super) unsafe fn defer_cookie_free(
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
    let mut match_row = None;
    for (alias_index, alias) in pdo_aliases_mut().iter().enumerate() {
        if alias.dependent_instance != instance_index || alias.dependent_domain != domain
            || !alias.blocked
        { continue; }
        for (device_index, device) in alias.devices.iter().enumerate() {
            if !device.destroy_entered || device.free_route != Some(route)
                || device.kmd_guard.as_ref().is_none_or(|guard|
                    guard.address != address || guard.allocation.component_address != address
                        || !guard.live(inst, domain))
                || device.retirement.is_none()
            { continue; }
            if match_row.replace((alias_index, device_index)).is_some() { return None; }
        }
    }
    let (alias_index, device_index) = match_row?;
    let device = &mut pdo_aliases_mut()[alias_index].devices[device_index];
    let guard = device.kmd_guard.as_ref()?;
    if !device.retirement.as_mut()?.request_free(device.key?, route_identity,
        address, guard.allocation.pool_generation)
    { return None; }
    Some(nt_status::NtStatus::PENDING.raw())
}
