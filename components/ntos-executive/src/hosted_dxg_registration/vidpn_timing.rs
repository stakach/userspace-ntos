//! WDDM timing transaction across the provider and miniport address spaces.
//!
//! The request contains two caller-owned nested buffers. Keep exact pins for
//! both until the miniport returns, and project only documented output fields
//! back into the provider's path records.

use super::*;
use nt_hosted_runtime::DxgSetTimingsRequest;

const RESULTS_OFFSET: u64 = DxgSetTimingsRequest::BYTES as u64;
const PATHS_OFFSET: u64 = 0x30;
const MAX_PATH_BYTES: usize =
    DxgSetTimingsRequest::MAX_PATHS * DxgSetTimingsRequest::PATH_BYTES;

pub(in crate::driver_launch) unsafe fn service_set_timings_callback(
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

    let request_len = DxgSetTimingsRequest::BYTES as u64;
    let request_guard = DxgQueryOutputGuard::capture(provider_inst,
        record.provider_domain, provider_request, request_len,
        alias.provider_fdo_allocation, alias.provider_fdo)?;
    let request_exec = component_to_exec_va_for_instance(record.provider_instance,
        provider_inst, provider_request, request_len).ok_or(STATUS_INVALID_PARAMETER)?;
    let request_bytes = core::slice::from_raw_parts(
        request_exec as *const u8, DxgSetTimingsRequest::BYTES);
    let request = DxgSetTimingsRequest::parse(request_bytes).ok_or(STATUS_INVALID_PARAMETER)?;
    let used = PATHS_OFFSET.checked_add(request.path_bytes() as u64)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    provider_callback_marshal_window(marshal_window, used, 0)?;
    let results_guard = DxgQueryOutputGuard::capture(provider_inst,
        record.provider_domain, request.results(), 4,
        alias.provider_fdo_allocation, alias.provider_fdo)?;
    let results_exec = component_to_exec_va_for_instance(record.provider_instance,
        provider_inst, request.results(), 4).ok_or(STATUS_INVALID_PARAMETER)?;
    let (paths_guard, paths_exec) = if request.path_count() == 0 {
        (None, 0)
    } else {
        let bytes = request.path_bytes() as u64;
        (Some(DxgQueryOutputGuard::capture(provider_inst,
            record.provider_domain, request.paths(), bytes,
            alias.provider_fdo_allocation, alias.provider_fdo)?),
        component_to_exec_va_for_instance(record.provider_instance,
            provider_inst, request.paths(), bytes).ok_or(STATUS_INVALID_PARAMETER)?)
    };
    let vidpn_guard = if request.vidpn() == 0 { None } else {
        Some(StartOutputGuard::capture(provider_inst,
            record.provider_domain, request.vidpn(), 8,
            alias.provider_fdo_allocation, alias.provider_fdo)?)
    };
    copy_bytes(marshal_window.exec_base, request_exec, request_len);
    copy_bytes(marshal_window.exec_base + RESULTS_OFFSET, results_exec, 4);
    let mut original_paths = [0u8; MAX_PATH_BYTES];
    if request.path_count() != 0 {
        let path_bytes = request.path_bytes();
        let source = core::slice::from_raw_parts(paths_exec as *const u8, path_bytes);
        original_paths[..path_bytes].copy_from_slice(source);
        copy_bytes(marshal_window.exec_base + PATHS_OFFSET, paths_exec,
            path_bytes as u64);
    }
    // Only the dependent's local request receives cross-space pointers.
    write_unaligned((marshal_window.exec_base + 16) as *mut u64,
        marshal_window.component_base + RESULTS_OFFSET);
    write_unaligned((marshal_window.exec_base + 32) as *mut u64,
        if request.path_count() == 0 { 0 } else {
            marshal_window.component_base + PATHS_OFFSET
        });
    let mut expected_request = [0u8; DxgSetTimingsRequest::BYTES];
    expected_request.copy_from_slice(core::slice::from_raw_parts(
        marshal_window.exec_base as *const u8, DxgSetTimingsRequest::BYTES));

    pdo_aliases_mut()[alias_index].vidpn = Some(VidPnInFlight {
        request: request_guard,
        vidpn: vidpn_guard,
        provider_vidpn: request.vidpn(),
        timing_results: Some(results_guard),
        timing_paths: paths_guard,
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
    let returned_request = core::slice::from_raw_parts(
        marshal_window.exec_base as *const u8, DxgSetTimingsRequest::BYTES);
    if returned_request != expected_request || !held.live(provider_inst, record.provider_domain)
        || held.nested_uncertain
    {
        pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().retain_uncertain();
        return Err(STATUS_DEVICE_NOT_READY);
    }
    if (result as u32 as i32) < 0 {
        // A timing failure can follow a hardware side effect. Preserve the
        // provider's status and all receipts; retrying the native DDI would
        // be unsafe until the exact outcome is reconciled.
        pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().retain_uncertain();
        return Ok(result);
    }
    let results = core::slice::from_raw_parts(
        (marshal_window.exec_base + RESULTS_OFFSET) as *const u8, 4);
    if let Err(status) = held.timing_results.as_ref().unwrap().write_bytes(
        record.provider_instance, provider_inst, record.provider_domain, results)
    {
        pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().retain_uncertain();
        return Err(status);
    }
    if request.path_count() != 0 {
        let returned_paths = core::slice::from_raw_parts(
            (marshal_window.exec_base + PATHS_OFFSET) as *const u8,
            request.path_bytes());
        if request.merge_path_outputs(&mut original_paths[..request.path_bytes()],
            returned_paths).is_none()
        {
            pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().retain_uncertain();
            return Err(STATUS_INVALID_PARAMETER);
        }
        if let Err(status) = held.timing_paths.as_ref().unwrap().write_bytes(
            record.provider_instance, provider_inst, record.provider_domain,
            &original_paths[..request.path_bytes()])
        {
            pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().retain_uncertain();
            return Err(status);
        }
    }
    pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().terminal = true;
    pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().release()?;
    pdo_aliases_mut()[alias_index].vidpn = None;
    pdo_aliases_mut()[alias_index].blocked = false;
    Ok(result)
}
