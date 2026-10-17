//! WDDM process cookie projection for the pinned LiberNT Dxg/SoftGpu pair.
//! Each row is owned by the started adapter alias before miniport entry.

use super::*;
use nt_hosted_runtime::{
    DxgCreateProcessLayout, DxgProcessAliasKey, DxgProcessCookieRetirement,
    DxgProcessFreeRoute,
};

pub(super) struct DxgProcessAlias {
    dxg_process: u64,
    source_guard: StartOutputGuard,
    request_guard: Option<DxgQueryOutputGuard>,
    kmd_guard: Option<StartOutputGuard>,
    key: Option<DxgProcessAliasKey>,
    free_route: Option<nt_component_suspension::peer_registry::PeerRoute>,
    retirement: Option<DxgProcessCookieRetirement>,
    destroy_entered: bool,
}

fn free_route_identity(domain: HostedDomainIdentity,
    route: nt_component_suspension::peer_registry::PeerRoute) -> Option<DxgProcessFreeRoute>
{
    DxgProcessFreeRoute::new(domain.domain_id.raw(), domain.cookie,
        route.endpoint(), route.badge(), route.identity().domain_generation,
        route.identity().executor)
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
            provider_pdo.generation(), dependent_pdo.address(),
            dependent_pdo.generation())
    { return Err(STATUS_INVALID_PARAMETER); }
    let expected = match record.callback_version {
        0x5022 | 0x5023 => 0x20u64,
        0x11007 => 0x38,
        _ => return Err(STATUS_NOT_SUPPORTED),
    };
    provider_callback_marshal_window(marshal_window, expected, 0)?;
    let request_guard = DxgQueryOutputGuard::capture(provider_inst, record.provider_domain,
        provider_request, expected, provider_fdo_allocation, provider_fdo)?;
    let request_exec = component_to_exec_va_for_instance(
        record.provider_instance, provider_inst, provider_request, expected)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if !request_guard.live(provider_inst, record.provider_domain) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let request = core::slice::from_raw_parts(request_exec as *const u8, expected as usize);
    let layout = DxgCreateProcessLayout::parse(
        record.callback_version, request, marshal_window.capacity)
        .ok_or(STATUS_NOT_SUPPORTED)?;
    if pdo_aliases_mut()[alias_index].processes.iter()
        .any(|process| process.dxg_process == layout.dxg_process()) {
        return Err(nt_status::NtStatus::DEVICE_BUSY.raw());
    }
    let source_guard = StartOutputGuard::capture(provider_inst, record.provider_domain,
        layout.dxg_process(), 1, provider_fdo_allocation, provider_fdo)?;
    let mut original = [0u8; 0x38];
    original[..expected as usize].copy_from_slice(request);
    copy_bytes(marshal_window.exec_base, request_exec, expected);
    pdo_aliases_mut()[alias_index].processes.try_reserve(1)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    pdo_aliases_mut()[alias_index].processes.push(DxgProcessAlias {
        dxg_process: layout.dxg_process(), source_guard,
        request_guard: Some(request_guard), kmd_guard: None, key: None,
        free_route: None, retirement: None,
        destroy_entered: false,
    });
    pdo_aliases_mut()[alias_index].blocked = true;
    let process_index = pdo_aliases_mut()[alias_index].processes.len() - 1;
    let result = match dispatch_dependent_provider_callback(
        dispatch, record, dependent_inst, exec_code_va,
        [provider_context, marshal_window.component_base, 0, 0],
        [0; PROVIDER_CALLBACK_STACK_QWORDS],
    ) {
        Ok(result) => result,
        Err(status) => {
            let process = &pdo_aliases_mut()[alias_index].processes[process_index];
            process.source_guard.retain_uncertain();
            process.request_guard.as_ref().unwrap().retain_uncertain();
            return Err(status);
        }
    };
    if (result as u32 as i32) < 0 {
        // A negative DDI status does not prove that the miniport left no
        // effects. Keep the exact process owner and its allocation pins until
        // retirement has an explicit, generation-bound completion contract.
        let process = &pdo_aliases_mut()[alias_index].processes[process_index];
        process.source_guard.retain_uncertain();
        process.request_guard.as_ref().unwrap().retain_uncertain();
        return Ok(result);
    }
    let kmd_process = read_unaligned((marshal_window.exec_base + 8) as *const u64);
    let kmd_guard = if kmd_process != 0 {
        Some(StartOutputGuard::capture(dependent_inst, record.dependent_domain,
            kmd_process, 1, provider_fdo_allocation, provider_fdo)?)
    } else { None };
    let kmd_generation = kmd_guard.as_ref()
        .map_or(0, |guard| guard.allocation.pool_generation);
    let key = DxgProcessAliasKey::new(authority, provider_context,
        context_allocation.pool_generation,
        layout.dxg_process(),
        pdo_aliases_mut()[alias_index].processes[process_index].source_guard
            .allocation.pool_generation,
        kmd_process, kmd_generation)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    pdo_aliases_mut()[alias_index].processes[process_index].kmd_guard = kmd_guard;
    pdo_aliases_mut()[alias_index].processes[process_index].key = Some(key);
    if kmd_process != 0 && pdo_aliases_mut().iter().enumerate().any(|(other_alias, alias)| {
        alias.dependent_domain == record.dependent_domain
            && alias.processes.iter().enumerate().any(|(other_process, process)| {
                (other_alias, other_process) != (alias_index, process_index)
                    && process.key.is_some_and(|other| other.cookie_address_conflicts(key))
            })
    }) {
        let process = &pdo_aliases_mut()[alias_index].processes[process_index];
        process.source_guard.retain_uncertain();
        process.request_guard.as_ref().unwrap().retain_uncertain();
        process.kmd_guard.as_ref().unwrap().retain_uncertain();
        return Err(STATUS_INVALID_PARAMETER);
    }
    if !layout.copyback_kmd_process(&mut original[..expected as usize], kmd_process) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    pdo_aliases_mut()[alias_index].processes[process_index].request_guard
        .as_ref().unwrap().write_bytes(record.provider_instance, provider_inst,
            record.provider_domain, &original[..expected as usize])?;
    pdo_aliases_mut()[alias_index].processes[process_index].request_guard
        .as_mut().unwrap().release()?;
    pdo_aliases_mut()[alias_index].processes[process_index].request_guard = None;
    if kmd_process == 0 {
        let alias = &mut pdo_aliases_mut()[alias_index];
        if alias.null_process_credits.is_none() {
            alias.null_process_credits = Some(
                nt_hosted_runtime::DxgNullProcessCredits::new(
                    authority, provider_context, context_allocation.pool_generation)
                    .ok_or(STATUS_INVALID_PARAMETER)?);
        }
        if !alias.null_process_credits.as_mut().unwrap().record_create(
            authority, provider_context, context_allocation.pool_generation, true, true)
        { return Err(STATUS_INVALID_PARAMETER); }
        alias.processes[process_index].source_guard.release()?;
        alias.processes.remove(process_index);
    }
    pdo_aliases_mut()[alias_index].blocked = false;
    Ok(result)
}

pub(super) unsafe fn destroy(
    dispatch: &mut HostedProviderCallbackDispatcher<'_>,
    provider_inst: DriverInstance,
    record: HostedProviderCallbackRecord,
    dependent_inst: DriverInstance,
    exec_code_va: u64,
    provider_context: u64,
    kmd_process: u64,
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
            && alias.start_succeeded && !alias.blocked && !alias.pointer_retired
    }).ok_or(STATUS_INVALID_PARAMETER)?;
    let alias = &pdo_aliases_mut()[alias_index];
    let authority = alias.authority.ok_or(STATUS_INVALID_PARAMETER)?;
    let dependent_pdo = alias.dependent_alias.ok_or(STATUS_INVALID_PARAMETER)?;
    if instance_domain_identity(provider_inst) != Some(record.provider_domain)
        || instance_domain_identity(dependent_inst) != Some(record.dependent_domain)
        || hosted_device_allocations::capture_allocation(dependent_inst, provider_context).ok()
            != alias.context_allocation
        || io_manager_mut().hosted_device_pointer_registration(
            record.provider_domain, alias.provider_pdo.address()) != Some(alias.provider_pdo)
        || io_manager_mut().hosted_device_pointer_registration(
            record.dependent_domain, dependent_pdo.address()) != Some(dependent_pdo)
        || !authority.matches(owner, record.provider_publication_cookie,
            alias.provider_pdo.device_id().raw(), alias.provider_pdo.address(),
            alias.provider_pdo.generation(), dependent_pdo.address(),
            dependent_pdo.generation())
    { return Err(STATUS_INVALID_PARAMETER); }
    let context_generation = alias.context_allocation.unwrap().pool_generation;
    let route = hosted_ingress_sources::primary_route(record.dependent_instance)
        .ok_or(STATUS_DEVICE_NOT_READY)?;
    if route.identity().executor != dependent_inst.tcb
        || route.endpoint() != dependent_inst.fault_ep
    { return Err(STATUS_INVALID_PARAMETER); }
    if kmd_process == 0 {
        let credits = pdo_aliases_mut()[alias_index].null_process_credits.as_mut()
            .ok_or(STATUS_INVALID_PARAMETER)?;
        if !credits.begin_destroy(authority, provider_context, context_generation) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        pdo_aliases_mut()[alias_index].blocked = true;
        let result = dispatch_dependent_provider_callback(dispatch, record, dependent_inst,
            exec_code_va, [provider_context, 0, 0, 0],
            [0; PROVIDER_CALLBACK_STACK_QWORDS])?;
        if (result as u32 as i32) >= 0 {
            if !pdo_aliases_mut()[alias_index].null_process_credits.as_mut().unwrap()
                .finish_destroy(true, true)
            { return Err(STATUS_INVALID_PARAMETER); }
            pdo_aliases_mut()[alias_index].blocked = false;
        }
        return Ok(result);
    }
    let process_index = alias.processes.iter().position(|process| {
        !process.destroy_entered && process.key.is_some_and(|key| {
            key.matches_destroy(authority, provider_context,
                alias.context_allocation.unwrap().pool_generation,
                kmd_process, process.kmd_guard.as_ref()
                    .map_or(0, |guard| guard.allocation.pool_generation))
        })
    }).ok_or(STATUS_INVALID_PARAMETER)?;
    let process = &alias.processes[process_index];
    if !process.source_guard.live(provider_inst, record.provider_domain)
        || process.kmd_guard.as_ref().is_some_and(|guard|
            !guard.live(dependent_inst, record.dependent_domain))
    { return Err(STATUS_INVALID_PARAMETER); }
    let retirement = if kmd_process != 0 {
        let key = process.key.ok_or(STATUS_INVALID_PARAMETER)?;
        let route_identity = free_route_identity(record.dependent_domain, route)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        Some(DxgProcessCookieRetirement::new(key, route_identity)
            .ok_or(STATUS_INVALID_PARAMETER)?)
    } else { None };
    pdo_aliases_mut()[alias_index].processes[process_index].destroy_entered = true;
    pdo_aliases_mut()[alias_index].processes[process_index].free_route = Some(route);
    pdo_aliases_mut()[alias_index].processes[process_index].retirement = retirement;
    pdo_aliases_mut()[alias_index].blocked = true;
    let outcome = dispatch_dependent_provider_callback(dispatch, record, dependent_inst,
        exec_code_va, [provider_context, kmd_process, 0, 0],
        [0; PROVIDER_CALLBACK_STACK_QWORDS]);
    pdo_aliases_mut()[alias_index].processes[process_index].retirement
        .as_mut().unwrap().close_callback_interval();
    let result = outcome?;
    if (result as u32 as i32) < 0 { return Ok(result); }
    let process = &mut pdo_aliases_mut()[alias_index].processes[process_index];
    if let Some(retirement) = process.retirement.as_mut() {
        let guard = process.kmd_guard.as_mut().ok_or(STATUS_INVALID_PARAMETER)?;
        if retirement.free_requested() {
            // The miniport's ExFreePool request is held until its callback
            // and Reply complete; no address reuse is possible meanwhile.
            if !retirement.complete(true, true) { return Err(STATUS_INVALID_PARAMETER); }
            guard.complete_deferred_free()?;
        } else {
            // A successful DDI may retain an opaque cookie and release it
            // later. Callback ownership has ended, so drop our pin now.
            if !retirement.release_without_free(true, true) {
                return Err(STATUS_INVALID_PARAMETER);
            }
            guard.release()?;
        }
    }
    process.source_guard.release()?;
    pdo_aliases_mut()[alias_index].processes.remove(process_index);
    pdo_aliases_mut()[alias_index].blocked = false;
    Ok(result)
}

/// Called only from the authenticated dependent pool-retirement service.
/// A matching free is recorded while its allocation stays pinned; the real
/// free happens after the matching Destroy callback and Reply finish.
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
    if route.badge() != caller_badge
        || route.identity().executor != channel.tcb
        || hosted_ingress_sources::primary_route(instance_index) != Some(route)
    { return None; }
    let route_identity = free_route_identity(domain, route)?;
    let mut match_row = None;
    for (alias_index, alias) in pdo_aliases_mut().iter().enumerate() {
        if alias.dependent_instance != instance_index || alias.dependent_domain != domain
            || !alias.blocked
        { continue; }
        for (process_index, process) in alias.processes.iter().enumerate() {
            if !process.destroy_entered || process.free_route != Some(route)
                || process.kmd_guard.as_ref().is_none_or(|guard|
                    guard.address != address || guard.allocation.component_address != address
                        || !guard.live(inst, domain))
                || process.retirement.is_none()
            { continue; }
            if match_row.replace((alias_index, process_index)).is_some() { return None; }
        }
    }
    let (alias_index, process_index) = match_row?;
    let process = &mut pdo_aliases_mut()[alias_index].processes[process_index];
    let guard = process.kmd_guard.as_ref()?;
    let key = process.key?;
    if !process.retirement.as_mut()?.request_free(key, route_identity,
        address, guard.allocation.pool_generation)
    { return None; }
    Some(nt_status::NtStatus::PENDING.raw())
}
