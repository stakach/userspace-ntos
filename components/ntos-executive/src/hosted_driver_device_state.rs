//! Deferred `IoInvalidateDeviceState` for a canonical hosted PDO incarnation.

use super::*;

enum QueryOwner {
    Queued,
    InFlight,
    Retained(nt_io_manager::RetainedExternalPnp),
    RetainedIndeterminate(nt_io_manager::RetainedExternalPnp),
    DispatchReturned(nt_io_manager::ExternalPnpReturn),
    AckReturned(nt_io_manager::ExternalPnpCompletionReturn),
    Indeterminate,
}

struct StateQuery {
    domain: HostedDomainIdentity,
    pdo: nt_io_manager::DeviceId,
    identity: nt_pnp_manager::DevnodeIdentity,
    irp: Option<IrpId>,
    origin_driver: Option<DriverId>,
    completion_driver: Option<DriverId>,
    completion_device: Option<nt_io_manager::DeviceId>,
    owner: QueryOwner,
}

static mut QUERIES: Option<Vec<StateQuery>> = None;

unsafe fn queries() -> &'static mut Vec<StateQuery> {
    let slot = &mut *core::ptr::addr_of_mut!(QUERIES);
    if slot.is_none() { *slot = Some(Vec::new()); }
    slot.as_mut().unwrap()
}

/// Void WDM import. A rejected authority or failed durable enqueue is a provider contract fault.
pub(super) extern "win64" fn invalidate(pdo: u64) {
    let (words, raw, a, b, c) = unsafe {
        call_on4_raw((FSD_SERVICE_DEVICE_LABEL << 12) | 4,
            HOSTED_DEVICE_OP_INVALIDATE_STATE, pdo, 0, 0)
    };
    if words != 4 || a != 0 || b != 0 || c != 0
        || raw as u32 as i32 != STATUS_SUCCESS
    {
        unsafe { crate::provider_bugcheck::report(0xc4,
            [HOSTED_DEVICE_OP_INVALIDATE_STATE, pdo, words, raw]); }
    }
}

/// The authenticated service only queues work. The component is still blocked on its Call here.
pub(super) fn enqueue(
    ch: &crate::spawn_hosts::PumpChannel,
    pdo_object: u64,
    active_reply_cap: u64,
) -> i32 {
    let (_, inst, pdo) = match authenticated_hosted_pdo(ch, pdo_object, active_reply_cap) {
        Ok(value) => value,
        Err(status) => return status.raw(),
    };
    let Some(domain) = instance_domain_identity(inst) else { return STATUS_ACCESS_DENIED; };
    let Some(identity) = (unsafe { hosted_pnp_manager_mut().devnode_identity_for_pdo(pdo.raw()) })
    else { return STATUS_INVALID_DEVICE_REQUEST; };
    if !unsafe { hosted_pnp_manager_mut().devnode_identity_is_started(identity) } {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    let rows = unsafe { queries() };
    if rows.iter().any(|row| row.domain == domain && row.pdo == pdo && row.identity == identity) {
        return STATUS_SUCCESS; // Coalesced with an already owned query of this exact incarnation.
    }
    if rows.try_reserve(1).is_err() { return STATUS_INSUFFICIENT_RESOURCES; }
    rows.push(StateQuery {
        domain, pdo, identity, irp: None, origin_driver: None,
        completion_driver: None, completion_device: None, owner: QueryOwner::Queued,
    });
    STATUS_SUCCESS
}

fn exact_receipt(row: &StateQuery, receipt: &nt_io_manager::ExternalPnpTerminalReceipt) -> bool {
    Some(receipt.irp_id()) == row.irp
        && Some(receipt.origin_driver_id()) == row.origin_driver
        && receipt.origin_device_id() == row.pdo
        && Some(receipt.completion_driver_id()) == row.completion_driver
        && Some(receipt.completion_device_id()) == row.completion_device
        && receipt.minor() == nt_pnp_abi::IRP_MN_QUERY_PNP_DEVICE_STATE
        && receipt.relation_type().is_none()
}

fn state_bits(status: nt_status::NtStatus, information: u64) -> Option<u32> {
    if !status.is_success() { return None; }
    let bits = u32::try_from(information).ok()?;
    (bits & !nt_pnp_abi::PNP_DEVICE_STATE_KNOWN_MASK == 0).then_some(bits)
}

unsafe fn commit(index: usize, receipt: &nt_io_manager::ExternalPnpTerminalReceipt) -> bool {
    let row = &queries()[index];
    if !exact_receipt(row, receipt) { return false; }
    if !receipt.status().is_success() { return true; }
    let Some(bits) = state_bits(receipt.status(), receipt.information()) else { return false; };
    let address = io_manager_mut().hosted_device_address_by_identity(row.domain, row.pdo);
    if io_manager_mut().hosted_domain_identity(row.domain.domain_id) != Some(row.domain)
        || !address.is_some_and(|address|
            io_manager_mut().hosted_device_by_identity(row.domain, address) == Some(row.pdo))
    { return false; }
    hosted_pnp_manager_mut().set_queried_pnp_device_state(row.identity, bits).is_ok()
}

unsafe fn begin(index: usize) -> bool {
    let (domain, pdo, identity) = {
        let row = &queries()[index]; (row.domain, row.pdo, row.identity)
    };
    if hosted_pnp_manager_mut().devnode_identity_for_pdo(pdo.raw()) != Some(identity)
        || !hosted_pnp_manager_mut().devnode_identity_is_started(identity)
        || io_manager_mut().hosted_domain_identity(domain.domain_id) != Some(domain)
    { queries()[index].owner = QueryOwner::Indeterminate; return true; }
    let parameters = PnpParameters::query_information(nt_pnp_abi::IRP_MN_QUERY_PNP_DEVICE_STATE)
        .expect("device-state query is a scalar PnP query");
    let prepared = match io_manager_mut().prepare_external_pnp_to_device(
        ClientId(IO_MANAGER_COMPONENT_ID), pdo, 0, parameters, &[]) {
        Ok(prepared) => prepared,
        Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES) => return false,
        Err(_) => { queries()[index].owner = QueryOwner::Indeterminate; return true; }
    };
    let irp = prepared.irp_id();
    let identities = io_manager_mut().irp(irp).and_then(|record| {
        let stack = record.current_stack()?;
        Some((record.origin_driver_id, stack.driver_id, stack.device_id))
    });
    let Some((origin, completion_driver, completion_device)) = identities else {
        io_manager_mut().discard_prepared_external_pnp(prepared)
            .expect("unissued state query must be discardable");
        queries()[index].owner = QueryOwner::Indeterminate;
        return true;
    };
    {
        let row = &mut queries()[index];
        row.irp = Some(irp);
        row.origin_driver = Some(origin);
        row.completion_driver = Some(completion_driver);
        row.completion_device = Some(completion_device);
        row.owner = QueryOwner::InFlight;
    }
    let invocation = match io_manager_mut().begin_prepared_external_pnp(prepared) {
        Ok(invocation) => invocation,
        Err(rejection) => {
            let (_, prepared) = rejection.into_parts();
            io_manager_mut().discard_prepared_external_pnp(prepared)
                .expect("unissued state query must be discardable");
            queries()[index].owner = QueryOwner::Indeterminate;
            return true;
        }
    };
    let returned = invocation.invoke(|context, projection| {
        let Some((provider, inst)) = instance_by_driver_id(projection.driver_id.raw()) else {
            return PnpBackendDispatch::NotDispatched {
                status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
            };
        };
        if !inst.ready || instance_domain_identity(inst).is_none() {
            return PnpBackendDispatch::NotDispatched {
                status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
            };
        }
        HostedDriverBackend { instance: provider }.dispatch_pnp_irp(context, projection)
    });
    let finished = match io_manager_mut().finish_external_pnp(returned) {
        Ok(finished) => finished,
        Err(rejection) => {
            // A rejected return still owns the foreign effect. Retain it as an exact barrier.
            queries()[index].owner = QueryOwner::DispatchReturned(rejection.into_owner());
            return true;
        }
    };
    match finished {
        nt_io_manager::ExternalPnpFinishResult::Terminal(
            ExternalPnpDispatchResult::Returned { receipt, .. }) => {
            if commit(index, &receipt) { queries().remove(index); }
            else { queries()[index].owner = QueryOwner::Indeterminate; }
        }
        nt_io_manager::ExternalPnpFinishResult::Retained(owner) => {
            let pending = matches!(owner.outcome(), ExternalPnpDispatchResult::Pending { .. });
            queries()[index].owner = if pending { QueryOwner::Retained(owner) } else {
                QueryOwner::RetainedIndeterminate(owner)
            };
        }
        _ => queries()[index].owner = QueryOwner::Indeterminate,
    }
    true
}

unsafe fn complete(index: usize) -> bool {
    let Some(irp) = queries()[index].irp else { return false; };
    let Some(completion) = io_manager_mut().completed_irp(irp) else { return false; };
    let valid = completion.id == irp
        && completion.client_id == ClientId(IO_MANAGER_COMPONENT_ID)
        && completion.file_id.is_none()
        && Some(completion.driver_id) == queries()[index].origin_driver
        && completion.device_id == queries()[index].pdo
        && completion.major == major::IRP_MJ_PNP
        && completion.minor == nt_pnp_abi::IRP_MN_QUERY_PNP_DEVICE_STATE
        && Some(completion.completion_driver_id) == queries()[index].completion_driver
        && Some(completion.completion_device_id) == queries()[index].completion_device
        && completion.user_data == 0 && completion.requestor_tid == 0
        && completion.completion_origin == IrpCompletionOrigin::Driver
        && (!completion.status.is_success()
            || state_bits(completion.status, completion.information).is_some());
    if !valid {
        let owner = core::mem::replace(&mut queries()[index].owner, QueryOwner::InFlight);
        let QueryOwner::Retained(owner) = owner else { unreachable!() };
        queries()[index].owner = QueryOwner::RetainedIndeterminate(owner);
        return true;
    }
    let Some((provider, inst)) = queries()[index].completion_driver
        .and_then(|driver| instance_by_driver_id(driver.raw())) else {
            let owner = core::mem::replace(&mut queries()[index].owner, QueryOwner::InFlight);
            let QueryOwner::Retained(owner) = owner else { unreachable!() };
            queries()[index].owner = QueryOwner::RetainedIndeterminate(owner);
            return true;
        };
    if !inst.ready {
        let owner = core::mem::replace(&mut queries()[index].owner, QueryOwner::InFlight);
        let QueryOwner::Retained(owner) = owner else { unreachable!() };
        queries()[index].owner = QueryOwner::RetainedIndeterminate(owner);
        return true;
    }
    let owner = core::mem::replace(&mut queries()[index].owner, QueryOwner::InFlight);
    let QueryOwner::Retained(owner) = owner else { unreachable!() };
    let invocation = match io_manager_mut().prepare_external_pnp_completion(owner) {
        Ok(invocation) => invocation,
        Err(rejection) => {
            queries()[index].owner = QueryOwner::Retained(rejection.into_owner());
            return false;
        }
    };
    let returned = invocation.invoke(|_| {
        hosted_file_dispatch::acknowledgement_result(hosted_file_dispatch::control(
            provider, irp, FSD_DISPATCH_ACK_COMPLETION, 0, &mut []))
    });
    match io_manager_mut().finish_external_pnp_completion(returned) {
        Ok((receipt, payload)) if payload.is_empty() => {
            if commit(index, &receipt) { queries().remove(index); }
            else { queries()[index].owner = QueryOwner::Indeterminate; }
        }
        Ok(_) => queries()[index].owner = QueryOwner::Indeterminate,
        Err(rejection) => queries()[index].owner = QueryOwner::AckReturned(rejection.into_owner()),
    }
    true
}

pub(super) unsafe fn drain() -> usize {
    let mut index = 0;
    let mut progress = 0usize;
    while index < queries().len() {
        let before = queries().len();
        let advanced = if matches!(&queries()[index].owner, QueryOwner::Queued) {
            begin(index)
        } else if matches!(&queries()[index].owner, QueryOwner::Retained(_)) {
            complete(index)
        } else { false };
        progress += usize::from(advanced);
        if queries().len() == before { index += 1; }
    }
    progress
}

/// No domain may retire while one of its effects or ACKs remains unresolved.
pub(super) unsafe fn retire_domain(domain: HostedDomainIdentity) -> bool {
    queries().iter().all(|row| row.domain != domain)
}
