//! Const visibility request for one exact started display miniport.
//!
//! A failed provider result can follow a scanout state change, so it is
//! returned verbatim while the request owner remains blocked and retained.

use super::*;
use nt_hosted_runtime::DxgSourceVisibilityRequest;

pub(in crate::driver_launch) unsafe fn service_visibility_callback(
    dispatch: &mut HostedProviderCallbackDispatcher<'_>,
    marshal_window: HostedProviderMarshalWindow,
    provider_inst: DriverInstance,
    record: HostedProviderCallbackRecord,
    dependent_inst: DriverInstance,
    exec_code_va: u64,
    provider_context: u64,
    provider_request: u64,
) -> Result<u64, i32> {
    let alias_index = admit_callback_alias(provider_inst, record,
        dependent_inst, provider_context)?;
    let alias = &pdo_aliases_mut()[alias_index];
    let request_len = DxgSourceVisibilityRequest::BYTES as u64;
    provider_callback_marshal_window(marshal_window, request_len, 0)?;
    let request_guard = DxgQueryOutputGuard::capture(provider_inst,
        record.provider_domain, provider_request, request_len,
        alias.provider_fdo_allocation, alias.provider_fdo)?;
    let request_exec = component_to_exec_va_for_instance(record.provider_instance,
        provider_inst, provider_request, request_len).ok_or(STATUS_INVALID_PARAMETER)?;
    let request_bytes = core::slice::from_raw_parts(
        request_exec as *const u8, DxgSourceVisibilityRequest::BYTES);
    DxgSourceVisibilityRequest::parse(request_bytes).ok_or(STATUS_INVALID_PARAMETER)?;
    copy_bytes(marshal_window.exec_base, request_exec, request_len);
    let mut expected = [0u8; 5];
    expected.copy_from_slice(&request_bytes[..5]);
    pdo_aliases_mut()[alias_index].vidpn = Some(VidPnInFlight {
        request: request_guard,
        vidpn: None,
        provider_vidpn: 0,
        timing_results: None,
        timing_paths: None,
        dependent_instance: record.dependent_instance,
        dependent_domain: record.dependent_domain,
        topology_handle: None,
        topology_allocation: None,
        mode_sets: Vec::new(),
        mode_objects: Vec::new(),
        paths: Vec::new(),
        terminal: false,
        nested_uncertain: false,
        interfaces: Vec::new(),
    });
    pdo_aliases_mut()[alias_index].blocked = true;
    let result = match dispatch_dependent_provider_callback(
        dispatch, record, dependent_inst, exec_code_va,
        [provider_context, marshal_window.component_base, 0, 0],
        [0; PROVIDER_CALLBACK_STACK_QWORDS],
    ) {
        Ok(value) => value,
        Err(status) => {
            pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().retain_uncertain();
            return Err(status);
        }
    };
    let held = pdo_aliases_mut()[alias_index].vidpn.as_ref().unwrap();
    let returned = core::slice::from_raw_parts(
        marshal_window.exec_base as *const u8, DxgSourceVisibilityRequest::BYTES);
    if returned[..5] != expected || !held.live(provider_inst, record.provider_domain)
        || held.nested_uncertain
    {
        pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().retain_uncertain();
        return Err(STATUS_DEVICE_NOT_READY);
    }
    if (result as u32 as i32) < 0 {
        pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().retain_uncertain();
        return Ok(result);
    }
    pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().terminal = true;
    pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().release()?;
    pdo_aliases_mut()[alias_index].vidpn = None;
    pdo_aliases_mut()[alias_index].blocked = false;
    Ok(result)
}
