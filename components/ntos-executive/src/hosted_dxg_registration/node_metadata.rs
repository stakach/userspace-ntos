//! Exact WDDM node metadata output projection across the Dxg/miniport domains.

use super::*;
use nt_hosted_runtime::DxgNodeMetadataLayout;

pub(super) unsafe fn query(
    dispatch: &mut HostedProviderCallbackDispatcher<'_>,
    marshal_window: HostedProviderMarshalWindow,
    provider_inst: DriverInstance,
    record: HostedProviderCallbackRecord,
    dependent_inst: DriverInstance,
    exec_code_va: u64,
    provider_context: u64,
    node_ordinal: u64,
    provider_output: u64,
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
            && alias.node_metadata_output.is_none() && alias.authority.is_some()
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
    let layout = DxgNodeMetadataLayout::new(record.callback_version,
        node_ordinal, provider_output, marshal_window.capacity)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    provider_callback_marshal_window(marshal_window, layout.bytes(), 0)?;
    let output_guard = DxgQueryOutputGuard::capture(provider_inst,
        record.provider_domain, provider_output, layout.bytes(),
        provider_fdo_allocation, provider_fdo)?;
    if !output_guard.live(provider_inst, record.provider_domain) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let dependent_output = core::slice::from_raw_parts_mut(
        marshal_window.exec_base as *mut u8, layout.bytes() as usize);
    if !layout.initialize_output(dependent_output) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    pdo_aliases_mut()[alias_index].node_metadata_output = Some(output_guard);
    pdo_aliases_mut()[alias_index].blocked = true;
    let result = match dispatch_dependent_provider_callback(dispatch, record,
        dependent_inst, exec_code_va,
        [provider_context, layout.node_ordinal() as u64,
            marshal_window.component_base, 0],
        [0; PROVIDER_CALLBACK_STACK_QWORDS]) {
        Ok(result) => result,
        Err(status) => {
            pdo_aliases_mut()[alias_index].node_metadata_output.as_ref().unwrap()
                .retain_uncertain();
            return Err(status);
        }
    };
    if (result as u32 as i32) >= 0 {
        let returned = core::slice::from_raw_parts(marshal_window.exec_base as *const u8,
            layout.bytes() as usize);
        let mut output = [0u8; 0x4a];
        if !layout.copyback(&mut output, returned) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if let Err(status) = pdo_aliases_mut()[alias_index].node_metadata_output.as_ref()
            .unwrap().write_bytes(record.provider_instance, provider_inst,
                record.provider_domain, &output)
        {
            pdo_aliases_mut()[alias_index].node_metadata_output.as_ref().unwrap()
                .retain_uncertain();
            return Err(status);
        }
    }
    pdo_aliases_mut()[alias_index].node_metadata_output.as_mut().unwrap().release()?;
    pdo_aliases_mut()[alias_index].node_metadata_output = None;
    pdo_aliases_mut()[alias_index].blocked = false;
    Ok(result)
}
