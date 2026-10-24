//! The no-recommendation half of the full miniport VidPN protocol.
//!
//! A VidPN is owned by dxgkrnl's VSpace. Its handle remains opaque to the
//! miniport, and its allocation is pinned across the callback. A successful
//! recommendation would require a separate VIDPN_MGR mutation projection;
//! it is fenced until that contract exists. The released SoftGpu miniport
//! returns the precise no-recommendation status for both callbacks, allowing
//! dxgkrnl to build its own connected path.

use super::*;
use nt_hosted_runtime::{DxgDdiSignature, DxgRecommendationRequest};

const MAX_REQUEST_AND_TARGETS: usize = 48 + 16 * 4;

pub(super) struct RecommendationInFlight {
    request: DxgQueryOutputGuard,
    vidpn: StartOutputGuard,
    targets: Option<DxgQueryOutputGuard>,
    terminal_no_mutation: bool,
}

impl RecommendationInFlight {
    pub(super) fn may_settle(&self) -> bool { self.terminal_no_mutation }

    unsafe fn live(&self, inst: DriverInstance, domain: HostedDomainIdentity) -> bool {
        self.request.live(inst, domain)
            && self.vidpn.live(inst, domain)
            && self.targets.as_ref().is_none_or(|target| target.live(inst, domain))
    }

    fn retain_uncertain(&self) {
        self.request.retain_uncertain();
        self.vidpn.retain_uncertain();
        if let Some(targets) = self.targets.as_ref() { targets.retain_uncertain(); }
    }

    pub(super) unsafe fn release(&mut self) -> Result<(), i32> {
        self.request.release()?;
        self.vidpn.release()?;
        if let Some(targets) = self.targets.as_mut() { targets.release()?; }
        Ok(())
    }
}

pub(in crate::driver_launch) unsafe fn service_recommendation_callback(
    dispatch: &mut HostedProviderCallbackDispatcher<'_>,
    marshal_window: HostedProviderMarshalWindow,
    provider_inst: DriverInstance,
    record: HostedProviderCallbackRecord,
    dependent_inst: DriverInstance,
    exec_code_va: u64,
    provider_context: u64,
    provider_request: u64,
    signature: DxgDdiSignature,
) -> Result<u64, i32> {
    let request_len = DxgRecommendationRequest::request_bytes(signature)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let owner = hosted_provider_object_owner_for_pair(
        record.provider_instance, record.dependent_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let alias_index = pdo_aliases_mut().iter().position(|alias| {
        alias.provider_instance == record.provider_instance
            && alias.dependent_instance == record.dependent_instance
            && alias.provider_domain == record.provider_domain
            && alias.dependent_domain == record.dependent_domain
            && alias.provider_publication_cookie == record.provider_publication_cookie
            && alias.context == provider_context && alias.context_allocation.is_some()
            && alias.start_entered && alias.start_succeeded
            && !alias.start_callback_active && !alias.blocked && !alias.pointer_retired
            && alias.interface_handle != 0 && alias.recommendation.is_none()
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

    // Only after the exact adapter/context pair is admitted may the parked
    // provider's request be read. Capture its allocation before parsing the
    // opaque VidPN handle and the optional target vector it names.
    let request_guard = DxgQueryOutputGuard::capture(provider_inst,
        record.provider_domain, provider_request, request_len,
        alias.provider_fdo_allocation, alias.provider_fdo)?;
    let request_exec = component_to_exec_va_for_instance(
        record.provider_instance, provider_inst, provider_request, request_len,
    ).ok_or(STATUS_INVALID_PARAMETER)?;
    let request_data = core::slice::from_raw_parts(request_exec as *const u8, request_len as usize);
    let request = DxgRecommendationRequest::parse(signature, request_data,
        marshal_window.capacity).ok_or(STATUS_INVALID_PARAMETER)?;
    let targets_len = request.target_bytes();
    let payload_len = request_len.checked_add(targets_len).ok_or(STATUS_INVALID_PARAMETER)?;
    provider_callback_marshal_window(marshal_window, payload_len, 0)?;
    let vidpn_guard = StartOutputGuard::capture(provider_inst,
        record.provider_domain, request.vidpn(), 8,
        alias.provider_fdo_allocation, alias.provider_fdo)?;
    let targets_guard = if targets_len == 0 { None } else {
        Some(DxgQueryOutputGuard::capture(provider_inst,
            record.provider_domain, request.targets(), targets_len,
            alias.provider_fdo_allocation, alias.provider_fdo)?)
    };
    copy_bytes(marshal_window.exec_base, request_exec, request_len);
    if targets_len != 0 {
        let targets_exec = component_to_exec_va_for_instance(
            record.provider_instance, provider_inst, request.targets(), targets_len,
        ).ok_or(STATUS_INVALID_PARAMETER)?;
        copy_bytes(marshal_window.exec_base + request_len, targets_exec, targets_len);
        write_unaligned((marshal_window.exec_base + 8) as *mut u64,
            marshal_window.component_base + request_len);
    }
    let mut expected = [0u8; MAX_REQUEST_AND_TARGETS];
    expected[..payload_len as usize].copy_from_slice(core::slice::from_raw_parts(
        marshal_window.exec_base as *const u8, payload_len as usize));
    pdo_aliases_mut()[alias_index].recommendation = Some(RecommendationInFlight {
        request: request_guard, vidpn: vidpn_guard, targets: targets_guard,
        terminal_no_mutation: false,
    });
    pdo_aliases_mut()[alias_index].blocked = true;
    let result = match dispatch_dependent_provider_callback(
        dispatch, record, dependent_inst, exec_code_va,
        [provider_context, marshal_window.component_base, 0, 0],
        [0; PROVIDER_CALLBACK_STACK_QWORDS],
    ) {
        Ok(value) => value,
        Err(status) => {
            pdo_aliases_mut()[alias_index].recommendation.as_ref().unwrap().retain_uncertain();
            return Err(status);
        }
    };
    let in_flight = pdo_aliases_mut()[alias_index].recommendation.as_ref().unwrap();
    let unchanged = core::slice::from_raw_parts(
        marshal_window.exec_base as *const u8, payload_len as usize)
        == &expected[..payload_len as usize];
    let owner_live = in_flight.live(provider_inst, record.provider_domain);
    if !nt_hosted_runtime::dxg_recommendation_settle_admitted(
        true, result as u32 as i32, unchanged, owner_live)
    {
        in_flight.retain_uncertain();
        return Err(STATUS_NOT_SUPPORTED);
    }
    pdo_aliases_mut()[alias_index].recommendation.as_mut().unwrap()
        .terminal_no_mutation = true;
    // The miniport's actual negative result is returned to dxgkrnl. In
    // particular, its two no-recommendation codes trigger the OS default path.
    pdo_aliases_mut()[alias_index].recommendation.as_mut().unwrap().release()?;
    pdo_aliases_mut()[alias_index].recommendation = None;
    pdo_aliases_mut()[alias_index].blocked = false;
    Ok(result)
}
