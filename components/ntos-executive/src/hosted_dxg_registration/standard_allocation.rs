//! Two-phase full-WDDM standard-allocation query with exact provider buffers.

use super::*;
use nt_hosted_runtime::DxgStandardAllocationLayout;

pub(super) struct StandardAllocationInFlight {
    request: DxgQueryOutputGuard,
    surface: DxgQueryOutputGuard,
    allocation: Option<DxgQueryOutputGuard>,
    resource: Option<DxgQueryOutputGuard>,
}

impl StandardAllocationInFlight {
    fn retain_uncertain(&self) {
        self.request.retain_uncertain();
        self.surface.retain_uncertain();
        if let Some(guard) = &self.allocation { guard.retain_uncertain(); }
        if let Some(guard) = &self.resource { guard.retain_uncertain(); }
    }

    unsafe fn release(&mut self) -> Result<(), i32> {
        if let Some(guard) = &mut self.resource { guard.release()?; }
        if let Some(guard) = &mut self.allocation { guard.release()?; }
        self.surface.release()?;
        self.request.release()?;
        Ok(())
    }
}

pub(super) unsafe fn query(
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
            && alias.standard_allocation.is_none()
    }).ok_or(STATUS_INVALID_PARAMETER)?;
    let alias = &pdo_aliases_mut()[alias_index];
    let dependent_pdo = alias.dependent_alias.ok_or(STATUS_INVALID_PARAMETER)?;
    let authority = alias.authority.ok_or(STATUS_INVALID_PARAMETER)?;
    if instance_domain_identity(provider_inst) != Some(record.provider_domain)
        || instance_domain_identity(dependent_inst) != Some(record.dependent_domain)
        || hosted_device_allocations::capture_allocation(dependent_inst, provider_context)
            .ok() != alias.context_allocation
        || io_manager_mut().hosted_device_pointer_registration(
            record.provider_domain, alias.provider_pdo.address()) != Some(alias.provider_pdo)
        || io_manager_mut().hosted_device_pointer_registration(
            record.dependent_domain, dependent_pdo.address()) != Some(dependent_pdo)
        || !authority.matches(owner, record.provider_publication_cookie,
            alias.provider_pdo.device_id().raw(), alias.provider_pdo.address(),
            alias.provider_pdo.generation(), dependent_pdo.address(),
            dependent_pdo.generation())
    { return Err(STATUS_INVALID_PARAMETER); }

    // Pin before reading any provider-owned request bytes. The provider is parked
    // on its Reply, and pool-backed nested outputs retain exact allocation pins.
    let request_guard = DxgQueryOutputGuard::capture(provider_inst, record.provider_domain,
        provider_request, 0x30, alias.provider_fdo_allocation, alias.provider_fdo)?;
    let request_exec = component_to_exec_va_for_instance(record.provider_instance,
        provider_inst, provider_request, 0x30).ok_or(STATUS_INVALID_PARAMETER)?;
    let request_bytes = core::slice::from_raw_parts(request_exec as *const u8, 0x30);
    let layout = DxgStandardAllocationLayout::parse(record.callback_version,
        request_bytes, marshal_window.capacity).ok_or(STATUS_NOT_SUPPORTED)?;
    let (allocation_address, allocation_len) = layout.allocation_private();
    let (resource_address, resource_len) = layout.resource_private();
    let surface_address = layout.surface_address();
    let surface_len = layout.surface_bytes();
    for (address, len) in [(surface_address, surface_len),
        (allocation_address, allocation_len as u64),
        (resource_address, resource_len as u64)] {
        if !nt_hosted_runtime::dxg_query_output_regions_disjoint(
            provider_request, 0x30, address, len) {
            return Err(STATUS_INVALID_PARAMETER);
        }
    }
    provider_callback_marshal_window(marshal_window, layout.marshal_bytes(), 0)?;
    let surface_guard = DxgQueryOutputGuard::capture(provider_inst, record.provider_domain,
        surface_address, surface_len, alias.provider_fdo_allocation, alias.provider_fdo)?;
    let allocation_guard = if allocation_len != 0 {
        Some(DxgQueryOutputGuard::capture(provider_inst, record.provider_domain,
            allocation_address, allocation_len as u64,
            alias.provider_fdo_allocation, alias.provider_fdo)?)
    } else { None };
    let resource_guard = if resource_len != 0 {
        Some(DxgQueryOutputGuard::capture(provider_inst, record.provider_domain,
            resource_address, resource_len as u64,
            alias.provider_fdo_allocation, alias.provider_fdo)?)
    } else { None };
    let surface_exec = component_to_exec_va_for_instance(record.provider_instance,
        provider_inst, surface_address, surface_len).ok_or(STATUS_INVALID_PARAMETER)?;
    let mut original_request = [0u8; 0x30];
    original_request.copy_from_slice(request_bytes);
    let mut original_surface = [0u8; 0x18];
    original_surface[..surface_len as usize].copy_from_slice(
        core::slice::from_raw_parts(surface_exec as *const u8, surface_len as usize));

    copy_bytes(marshal_window.exec_base, request_exec, 0x30);
    copy_bytes(marshal_window.exec_base + layout.surface_offset(), surface_exec, surface_len);
    if allocation_len != 0 {
        core::ptr::write_bytes((marshal_window.exec_base + layout.allocation_offset()) as *mut u8,
            0, allocation_len as usize);
    }
    if resource_len != 0 {
        core::ptr::write_bytes((marshal_window.exec_base + layout.resource_offset()) as *mut u8,
            0, resource_len as usize);
    }
    let surface_projected = marshal_window.component_base + layout.surface_offset();
    let allocation_projected = if allocation_len != 0 {
        marshal_window.component_base + layout.allocation_offset()
    } else { 0 };
    let resource_projected = if resource_len != 0 {
        marshal_window.component_base + layout.resource_offset()
    } else { 0 };
    write_unaligned((marshal_window.exec_base + 8) as *mut u64, surface_projected);
    write_unaligned((marshal_window.exec_base + 0x10) as *mut u64, allocation_projected);
    write_unaligned((marshal_window.exec_base + 0x20) as *mut u64, resource_projected);

    pdo_aliases_mut()[alias_index].standard_allocation = Some(StandardAllocationInFlight {
        request: request_guard, surface: surface_guard,
        allocation: allocation_guard, resource: resource_guard,
    });
    pdo_aliases_mut()[alias_index].blocked = true;
    let result = match dispatch_dependent_provider_callback(dispatch, record,
        dependent_inst, exec_code_va,
        [provider_context, marshal_window.component_base, 0, 0],
        [0; PROVIDER_CALLBACK_STACK_QWORDS]) {
        Ok(result) => result,
        Err(status) => {
            pdo_aliases_mut()[alias_index].standard_allocation.as_ref().unwrap()
                .retain_uncertain();
            return Err(status);
        }
    };
    let status = result as u32 as i32;
    if status < 0 {
        pdo_aliases_mut()[alias_index].standard_allocation.as_mut().unwrap().release()?;
        pdo_aliases_mut()[alias_index].standard_allocation = None;
        pdo_aliases_mut()[alias_index].blocked = false;
        return Ok(result);
    }
    let returned = core::slice::from_raw_parts(
        marshal_window.exec_base as *const u8, 0x30);
    if read_unaligned(returned.as_ptr().add(8) as *const u64) != surface_projected
        || read_unaligned(returned.as_ptr().add(0x10) as *const u64) != allocation_projected
        || read_unaligned(returned.as_ptr().add(0x20) as *const u64) != resource_projected
    {
        pdo_aliases_mut()[alias_index].standard_allocation.as_ref().unwrap()
            .retain_uncertain();
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut returned_request = [0u8; 0x30];
    returned_request.copy_from_slice(returned);
    returned_request[8..16].copy_from_slice(&surface_address.to_le_bytes());
    returned_request[0x10..0x18].copy_from_slice(&allocation_address.to_le_bytes());
    returned_request[0x20..0x28].copy_from_slice(&resource_address.to_le_bytes());
    if !layout.copyback_sizes(&mut original_request, &returned_request) {
        pdo_aliases_mut()[alias_index].standard_allocation.as_ref().unwrap()
            .retain_uncertain();
        return Err(STATUS_INVALID_PARAMETER);
    }
    let reported_allocation = u32::from_le_bytes(
        original_request[0x18..0x1c].try_into().unwrap());
    let reported_resource = u32::from_le_bytes(
        original_request[0x28..0x2c].try_into().unwrap());
    if (allocation_len != 0 && reported_allocation > allocation_len)
        || (resource_len != 0 && reported_resource > resource_len)
    {
        pdo_aliases_mut()[alias_index].standard_allocation.as_ref().unwrap()
            .retain_uncertain();
        return Err(STATUS_INVALID_PARAMETER);
    }
    let in_flight = pdo_aliases_mut()[alias_index].standard_allocation.as_ref().unwrap();
    let projected_surface = core::slice::from_raw_parts(
        (marshal_window.exec_base + layout.surface_offset()) as *const u8,
        surface_len as usize);
    let immutable = if layout.kind() == 2 { 12 } else { surface_len as usize };
    if projected_surface[..immutable] != original_surface[..immutable] {
        in_flight.retain_uncertain();
        return Err(STATUS_INVALID_PARAMETER);
    }
    if allocation_len != 0 {
        let bytes = core::slice::from_raw_parts(
            (marshal_window.exec_base + layout.allocation_offset()) as *const u8,
            allocation_len as usize);
        if let Err(error) = in_flight.allocation.as_ref().unwrap().write_bytes(
            record.provider_instance, provider_inst, record.provider_domain, bytes) {
            in_flight.retain_uncertain();
            return Err(error);
        }
    }
    if resource_len != 0 {
        let bytes = core::slice::from_raw_parts(
            (marshal_window.exec_base + layout.resource_offset()) as *const u8,
            resource_len as usize);
        if let Err(error) = in_flight.resource.as_ref().unwrap().write_bytes(
            record.provider_instance, provider_inst, record.provider_domain, bytes) {
            in_flight.retain_uncertain();
            return Err(error);
        }
    }
    if layout.kind() == 2 {
        if let Err(error) = in_flight.surface.write_bytes(record.provider_instance,
            provider_inst, record.provider_domain, projected_surface) {
            in_flight.retain_uncertain();
            return Err(error);
        }
    }
    if let Err(error) = pdo_aliases_mut()[alias_index].standard_allocation.as_ref().unwrap()
        .request.write_bytes(record.provider_instance, provider_inst,
            record.provider_domain, &original_request) {
        pdo_aliases_mut()[alias_index].standard_allocation.as_ref().unwrap().retain_uncertain();
        return Err(error);
    }
    pdo_aliases_mut()[alias_index].standard_allocation.as_mut().unwrap().release()?;
    pdo_aliases_mut()[alias_index].standard_allocation = None;
    pdo_aliases_mut()[alias_index].blocked = false;
    Ok(result)
}
