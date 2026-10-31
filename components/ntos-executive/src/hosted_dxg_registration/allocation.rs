//! Bounded one-allocation WDDM CreateAllocation callback and KMD cookie owner.

use super::*;
use nt_hosted_runtime::{DxgAllocationAliasKey, DxgAllocationCallbackDisposition,
    DxgAllocationCookieRetirement,
    DxgCreateAllocationLayout, DxgDestroyAllocationLayout};

pub(super) struct DxgAllocationAlias {
    request: Option<DxgQueryOutputGuard>,
    info: Option<DxgQueryOutputGuard>,
    request_private: Option<DxgQueryOutputGuard>,
    allocation_private: Option<DxgQueryOutputGuard>,
    cookie: Option<StartOutputGuard>,
    key: Option<DxgAllocationAliasKey>,
    destroy_request: Option<DxgQueryOutputGuard>,
    destroy_list: Option<DxgQueryOutputGuard>,
    free_route: Option<nt_component_suspension::peer_registry::PeerRoute>,
    retirement: Option<DxgAllocationCookieRetirement>,
    destroy_entered: bool,
    create_callback_active: bool,
}

impl DxgAllocationAlias {
    pub(super) fn create_in_flight(&self) -> bool {
        self.create_callback_active
    }

    fn retain_uncertain(&self) {
        if let Some(guard) = &self.request { guard.retain_uncertain(); }
        if let Some(guard) = &self.info { guard.retain_uncertain(); }
        if let Some(guard) = &self.request_private { guard.retain_uncertain(); }
        if let Some(guard) = &self.allocation_private { guard.retain_uncertain(); }
        if let Some(guard) = &self.cookie { guard.retain_uncertain(); }
        if let Some(guard) = &self.destroy_request { guard.retain_uncertain(); }
        if let Some(guard) = &self.destroy_list { guard.retain_uncertain(); }
    }

    unsafe fn release_inputs(&mut self) -> Result<(), i32> {
        if let Some(guard) = &mut self.allocation_private { guard.release()?; }
        if let Some(guard) = &mut self.request_private { guard.release()?; }
        if let Some(guard) = &mut self.info { guard.release()?; }
        if let Some(guard) = &mut self.request { guard.release()?; }
        self.allocation_private = None;
        self.request_private = None;
        self.info = None;
        self.request = None;
        Ok(())
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
    let provider_fdo_allocation = alias.provider_fdo_allocation;
    let provider_fdo = alias.provider_fdo;
    if instance_domain_identity(provider_inst) != Some(record.provider_domain)
        || instance_domain_identity(dependent_inst) != Some(record.dependent_domain)
        || hosted_device_allocations::capture_allocation(dependent_inst, provider_context).ok()
            != Some(context_allocation)
        || io_manager_mut().hosted_device_pointer_registration(
            record.provider_domain, alias.provider_pdo.address()) != Some(alias.provider_pdo)
        || io_manager_mut().hosted_device_pointer_registration(
            record.dependent_domain, dependent_pdo.address()) != Some(dependent_pdo)
        || !authority.matches(owner, record.provider_publication_cookie,
            alias.provider_pdo.device_id().raw(), alias.provider_pdo.address(),
            alias.provider_pdo.generation(), dependent_pdo.address(),
            dependent_pdo.generation())
    { return Err(STATUS_INVALID_PARAMETER); }

    // Capture the provider's stack/pool identity before reading its nested
    // request. No miniport effect occurs until every input is pinned.
    let request_guard = DxgQueryOutputGuard::capture(provider_inst, record.provider_domain,
        provider_request, 0x28, provider_fdo_allocation, provider_fdo)?;
    let request_exec = component_to_exec_va_for_instance(record.provider_instance,
        provider_inst, provider_request, 0x28).ok_or(STATUS_INVALID_PARAMETER)?;
    let mut original_request = [0u8; 0x28];
    original_request.copy_from_slice(core::slice::from_raw_parts(
        request_exec as *const u8, 0x28));
    let info_address = u64::from_le_bytes(original_request[16..24].try_into().unwrap());
    let info_guard = DxgQueryOutputGuard::capture(provider_inst, record.provider_domain,
        info_address, 0x58, provider_fdo_allocation, provider_fdo)?;
    let info_exec = component_to_exec_va_for_instance(record.provider_instance,
        provider_inst, info_address, 0x58).ok_or(STATUS_INVALID_PARAMETER)?;
    let mut original_info = [0u8; 0x58];
    original_info.copy_from_slice(core::slice::from_raw_parts(info_exec as *const u8, 0x58));
    let layout = DxgCreateAllocationLayout::parse(record.callback_version,
        provider_request, &original_request, &original_info, marshal_window.capacity)
        .ok_or(STATUS_NOT_SUPPORTED)?;
    provider_callback_marshal_window(marshal_window, layout.marshal_bytes(), 0)?;
    let (request_private_address, request_private_len) = layout.request_private();
    let (allocation_private_address, allocation_private_len) = layout.private_driver_data();
    let request_private = if request_private_len != 0 {
        Some(DxgQueryOutputGuard::capture(provider_inst, record.provider_domain,
            request_private_address, request_private_len as u64,
            provider_fdo_allocation, provider_fdo)?)
    } else { None };
    let allocation_private = if allocation_private_len != 0 {
        Some(DxgQueryOutputGuard::capture(provider_inst, record.provider_domain,
            allocation_private_address, allocation_private_len as u64,
            provider_fdo_allocation, provider_fdo)?)
    } else { None };

    copy_bytes(marshal_window.exec_base, original_request.as_ptr() as u64, 0x28);
    copy_bytes(marshal_window.exec_base + layout.info_offset(),
        original_info.as_ptr() as u64, 0x58);
    if request_private_len != 0 {
        let source = component_to_exec_va_for_instance(record.provider_instance,
            provider_inst, request_private_address, request_private_len as u64)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        copy_bytes(marshal_window.exec_base + layout.private_offset(),
            source, request_private_len as u64);
    }
    if allocation_private_len != 0 {
        let source = component_to_exec_va_for_instance(record.provider_instance,
            provider_inst, allocation_private_address, allocation_private_len as u64)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        copy_bytes(marshal_window.exec_base + layout.allocation_private_offset(),
            source, allocation_private_len as u64);
    }
    let projected_info = marshal_window.component_base + layout.info_offset();
    let projected_request_private = if request_private_len != 0 {
        marshal_window.component_base + layout.private_offset()
    } else { 0 };
    let projected_allocation_private = if allocation_private_len != 0 {
        marshal_window.component_base + layout.allocation_private_offset()
    } else { 0 };
    write_unaligned((marshal_window.exec_base + 0x10) as *mut u64, projected_info);
    write_unaligned(marshal_window.exec_base as *mut u64, projected_request_private);
    write_unaligned((marshal_window.exec_base + layout.info_offset()) as *mut u64,
        projected_allocation_private);
    let mut projected_request = [0u8; 0x28];
    projected_request.copy_from_slice(core::slice::from_raw_parts(
        marshal_window.exec_base as *const u8, 0x28));

    pdo_aliases_mut()[alias_index].allocations.try_reserve(1)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    pdo_aliases_mut()[alias_index].allocations.push(DxgAllocationAlias {
        request: Some(request_guard), info: Some(info_guard),
        request_private, allocation_private, cookie: None, key: None,
        destroy_request: None, destroy_list: None,
        free_route: None, retirement: None, destroy_entered: false,
        create_callback_active: false,
    });
    pdo_aliases_mut()[alias_index].blocked = true;
    let allocation_index = pdo_aliases_mut()[alias_index].allocations.len() - 1;
    pdo_aliases_mut()[alias_index].allocations[allocation_index].create_callback_active = true;
    let dispatch_result = dispatch_dependent_provider_callback(dispatch, record,
        dependent_inst, exec_code_va,
        [provider_context, marshal_window.component_base, 0, 0],
        [0; PROVIDER_CALLBACK_STACK_QWORDS]);
    pdo_aliases_mut()[alias_index].allocations[allocation_index].create_callback_active = false;
    let result = match dispatch_result {
        Ok(result) => result,
        Err(status) => {
            pdo_aliases_mut()[alias_index].allocations[allocation_index].retain_uncertain();
            return Err(status);
        }
    };
    let returned_request = core::slice::from_raw_parts(
        marshal_window.exec_base as *const u8, 0x28);
    let returned_info = core::slice::from_raw_parts(
        (marshal_window.exec_base + layout.info_offset()) as *const u8, 0x58);
    let kmd_allocation = read_unaligned(returned_info.as_ptr().add(0x38) as *const u64);
    match DxgAllocationCallbackDisposition::create(
        true, result as u32 as i32, kmd_allocation) {
        DxgAllocationCallbackDisposition::ReleaseProvisional => {
            pdo_aliases_mut()[alias_index].allocations[allocation_index].release_inputs()?;
            pdo_aliases_mut()[alias_index].allocations.remove(allocation_index);
            pdo_aliases_mut()[alias_index].blocked = false;
            return Ok(result);
        }
        DxgAllocationCallbackDisposition::Retain => {
            pdo_aliases_mut()[alias_index].allocations[allocation_index].retain_uncertain();
            if (result as u32 as i32) < 0 { return Ok(result); }
            return Err(STATUS_INVALID_PARAMETER);
        }
        DxgAllocationCallbackDisposition::Publish => {}
        _ => return Err(STATUS_INVALID_PARAMETER),
    }
    if returned_request != projected_request
        || read_unaligned(returned_info.as_ptr() as *const u64)
            != projected_allocation_private
        || returned_info[8..12] != original_info[8..12]
        || read_unaligned(returned_info.as_ptr().add(0x48) as *const u64) != 0
    {
        pdo_aliases_mut()[alias_index].allocations[allocation_index].retain_uncertain();
        return Err(STATUS_INVALID_PARAMETER);
    }
    let cookie_guard = match StartOutputGuard::capture(dependent_inst,
        record.dependent_domain, kmd_allocation, 1,
        provider_fdo_allocation, provider_fdo) {
        Ok(guard) => guard,
        Err(status) => {
            pdo_aliases_mut()[alias_index].allocations[allocation_index].retain_uncertain();
            return Err(status);
        }
    };
    let cookie_generation = cookie_guard.allocation.pool_generation;
    pdo_aliases_mut()[alias_index].allocations[allocation_index].cookie = Some(cookie_guard);
    let Some(key) = DxgAllocationAliasKey::new(authority, provider_context,
        context_allocation.pool_generation, kmd_allocation,
        cookie_generation) else {
        pdo_aliases_mut()[alias_index].allocations[allocation_index].retain_uncertain();
        return Err(STATUS_INVALID_PARAMETER);
    };
    pdo_aliases_mut()[alias_index].allocations[allocation_index].key = Some(key);
    if pdo_aliases_mut().iter().enumerate().any(|(other_alias, alias)| {
        alias.dependent_domain == record.dependent_domain
            && alias.allocations.iter().enumerate().any(|(other_allocation, allocation)| {
                (other_alias, other_allocation) != (alias_index, allocation_index)
                    && allocation.key.is_some_and(|other|
                        other.cookie_address_conflicts(key))
            })
    }) {
        pdo_aliases_mut()[alias_index].allocations[allocation_index].retain_uncertain();
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut output_info = [0u8; 0x58];
    output_info.copy_from_slice(returned_info);
    output_info[..8].copy_from_slice(&allocation_private_address.to_le_bytes());
    let allocation = &pdo_aliases_mut()[alias_index].allocations[allocation_index];
    if let Err(status) = allocation.info.as_ref().unwrap().write_bytes(
        record.provider_instance, provider_inst, record.provider_domain, &output_info) {
        allocation.retain_uncertain();
        return Err(status);
    }
    pdo_aliases_mut()[alias_index].allocations[allocation_index].release_inputs()?;
    pdo_aliases_mut()[alias_index].blocked = false;
    Ok(result)
}

pub(super) unsafe fn destroy(
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
    let provider_fdo_allocation = alias.provider_fdo_allocation;
    let provider_fdo = alias.provider_fdo;
    if instance_domain_identity(provider_inst) != Some(record.provider_domain)
        || instance_domain_identity(dependent_inst) != Some(record.dependent_domain)
        || hosted_device_allocations::capture_allocation(dependent_inst, provider_context).ok()
            != Some(context_allocation)
        || io_manager_mut().hosted_device_pointer_registration(
            record.provider_domain, alias.provider_pdo.address()) != Some(alias.provider_pdo)
        || io_manager_mut().hosted_device_pointer_registration(
            record.dependent_domain, dependent_pdo.address()) != Some(dependent_pdo)
        || !authority.matches(owner, record.provider_publication_cookie,
            alias.provider_pdo.device_id().raw(), alias.provider_pdo.address(),
            alias.provider_pdo.generation(), dependent_pdo.address(),
            dependent_pdo.generation())
    { return Err(STATUS_INVALID_PARAMETER); }

    let request_guard = DxgQueryOutputGuard::capture(provider_inst, record.provider_domain,
        provider_request, 0x20, provider_fdo_allocation, provider_fdo)?;
    let request_exec = component_to_exec_va_for_instance(record.provider_instance,
        provider_inst, provider_request, 0x20).ok_or(STATUS_INVALID_PARAMETER)?;
    let mut original_request = [0u8; 0x20];
    original_request.copy_from_slice(core::slice::from_raw_parts(
        request_exec as *const u8, 0x20));
    let list_address = u64::from_le_bytes(original_request[8..16].try_into().unwrap());
    let list_guard = DxgQueryOutputGuard::capture(provider_inst, record.provider_domain,
        list_address, 8, provider_fdo_allocation, provider_fdo)?;
    let list_exec = component_to_exec_va_for_instance(record.provider_instance,
        provider_inst, list_address, 8).ok_or(STATUS_INVALID_PARAMETER)?;
    let kmd_allocation = read_unaligned(list_exec as *const u64);
    let layout = DxgDestroyAllocationLayout::parse(record.callback_version,
        provider_request, &original_request, kmd_allocation, marshal_window.capacity)
        .ok_or(STATUS_NOT_SUPPORTED)?;
    let allocation_index = {
        let mut found = None;
        for (index, allocation) in alias.allocations.iter().enumerate() {
            let Some(cookie) = allocation.cookie.as_ref() else { continue; };
            if allocation.destroy_entered || allocation.key.is_none_or(|key|
                !key.matches_destroy(authority, kmd_allocation,
                    cookie.allocation.pool_generation))
                || !cookie.live(dependent_inst, record.dependent_domain)
            { continue; }
            if found.replace(index).is_some() { return Err(STATUS_INVALID_PARAMETER); }
        }
        found.ok_or(STATUS_INVALID_PARAMETER)?
    };
    let route = hosted_ingress_sources::primary_route(record.dependent_instance)
        .ok_or(STATUS_DEVICE_NOT_READY)?;
    if route.identity().executor != dependent_inst.tcb
        || route.endpoint() != dependent_inst.fault_ep
    { return Err(STATUS_INVALID_PARAMETER); }
    let route_identity = process::free_route_identity(record.dependent_domain, route)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let key = alias.allocations[allocation_index].key.ok_or(STATUS_INVALID_PARAMETER)?;
    let retirement = DxgAllocationCookieRetirement::new(key, route_identity)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    provider_callback_marshal_window(marshal_window, layout.marshal_bytes(), 0)?;
    copy_bytes(marshal_window.exec_base, original_request.as_ptr() as u64, 0x20);
    write_unaligned((marshal_window.exec_base + 0x20) as *mut u64, kmd_allocation);
    write_unaligned((marshal_window.exec_base + 8) as *mut u64,
        marshal_window.component_base + 0x20);
    let allocation = &mut pdo_aliases_mut()[alias_index].allocations[allocation_index];
    allocation.destroy_request = Some(request_guard);
    allocation.destroy_list = Some(list_guard);
    allocation.free_route = Some(route);
    allocation.retirement = Some(retirement);
    allocation.destroy_entered = true;
    pdo_aliases_mut()[alias_index].blocked = true;
    let outcome = dispatch_dependent_provider_callback(dispatch, record,
        dependent_inst, exec_code_va,
        [provider_context, marshal_window.component_base, 0, 0],
        [0; PROVIDER_CALLBACK_STACK_QWORDS]);
    pdo_aliases_mut()[alias_index].allocations[allocation_index].retirement
        .as_mut().unwrap().close_callback_interval();
    let result = match outcome {
        Ok(result) => result,
        Err(status) => {
            pdo_aliases_mut()[alias_index].allocations[allocation_index].retain_uncertain();
            return Err(status);
        }
    };
    let free_requested = pdo_aliases_mut()[alias_index].allocations[allocation_index]
        .retirement.as_ref().unwrap().free_requested();
    match DxgAllocationCallbackDisposition::destroy(
        true, result as u32 as i32, free_requested) {
        DxgAllocationCallbackDisposition::RetryWithCookie => {
            let allocation = &mut pdo_aliases_mut()[alias_index].allocations[allocation_index];
            if !allocation.cookie.as_ref().unwrap().live(dependent_inst, record.dependent_domain) {
                allocation.retain_uncertain();
                return Err(STATUS_INVALID_PARAMETER);
            }
            allocation.destroy_list.as_mut().unwrap().release()?;
            allocation.destroy_request.as_mut().unwrap().release()?;
            allocation.destroy_list = None;
            allocation.destroy_request = None;
            allocation.free_route = None;
            allocation.retirement = None;
            allocation.destroy_entered = false;
            pdo_aliases_mut()[alias_index].blocked = false;
            return Ok(result);
        }
        DxgAllocationCallbackDisposition::Retain => {
            pdo_aliases_mut()[alias_index].allocations[allocation_index].retain_uncertain();
            if (result as u32 as i32) < 0 { return Ok(result); }
            return Err(STATUS_INVALID_PARAMETER);
        }
        DxgAllocationCallbackDisposition::RetireCookie => {}
        _ => return Err(STATUS_INVALID_PARAMETER),
    }
    let allocation = &mut pdo_aliases_mut()[alias_index].allocations[allocation_index];
    let retirement = allocation.retirement.as_mut().unwrap();
    let cookie = allocation.cookie.as_mut().unwrap();
    if !retirement.complete(true, true) { return Err(STATUS_INVALID_PARAMETER); }
    cookie.complete_deferred_free()?;
    allocation.destroy_list.as_mut().unwrap().release()?;
    allocation.destroy_request.as_mut().unwrap().release()?;
    pdo_aliases_mut()[alias_index].allocations.remove(allocation_index);
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
    let mut found = None;
    for (alias_index, alias) in pdo_aliases_mut().iter().enumerate() {
        if alias.dependent_instance != instance_index || alias.dependent_domain != domain
            || !alias.blocked
        { continue; }
        for (allocation_index, allocation) in alias.allocations.iter().enumerate() {
            if !allocation.destroy_entered || allocation.free_route != Some(route)
                || allocation.cookie.as_ref().is_none_or(|cookie|
                    cookie.address != address || cookie.allocation.component_address != address
                        || !cookie.live(inst, domain))
                || allocation.retirement.is_none()
            { continue; }
            if found.replace((alias_index, allocation_index)).is_some() { return None; }
        }
    }
    let (alias_index, allocation_index) = found?;
    let allocation = &mut pdo_aliases_mut()[alias_index].allocations[allocation_index];
    let cookie = allocation.cookie.as_ref()?;
    if !allocation.retirement.as_mut()?.request_free(allocation.key?, route_identity,
        address, cookie.allocation.pool_generation)
    { return None; }
    Some(nt_status::NtStatus::PENDING.raw())
}
