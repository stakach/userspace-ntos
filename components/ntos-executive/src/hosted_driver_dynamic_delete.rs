//! Final reference and DeleteProcedure delivery for hosted dynamic object types.
//!
//! The registry row is the durable queue. A callback is claimed only after its original driver
//! has acknowledged the primary Reply and an independent PASSIVE worker is ready. A wall retains
//! the in-flight row and body; it never permits callback replay or address reuse.

use super::*;
use nt_object_manager::hosted_dynamic_type::DynamicHandleOwner;

pub(super) const DEREFERENCE_LABEL: u64 = 0x7cd;

/// Release one typed borrowed reference from the physical driver that owns the object body.
/// A body outside this exact driver incarnation is reported as absent so ordinary Obf paths may
/// continue; a live body with no borrowed reference is an invalid release, never a fake success.
pub(crate) fn release_reference_service(
    channel: &crate::spawn_hosts::PumpChannel,
    body: u64,
    reserved0: u64,
    reserved1: u64,
    reserved2: u64,
    caller_badge: u64,
    active_reply_cap: u64,
) -> (i32, u64) {
    if body == 0 || reserved0 != 0 || reserved1 != 0 || reserved2 != 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let Some((index, inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return (STATUS_INVALID_HANDLE, 0);
    };
    if hosted_driver_caller(index, inst, caller_badge).is_none() {
        return (STATUS_INVALID_HANDLE, 0);
    }
    let caller = match unsafe { crate::provider_registry_caller::resolve(channel) } {
        Ok(caller) => caller,
        Err(status) => return (status as i32, 0),
    };
    if let Err(status) = unsafe { crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.validate_native_handle_caller(caller)
    }) } { return (status as i32, 0); }
    unsafe {
        let Some(lease) = hosted_driver_dynamic_type::registry_mut()
            .and_then(|registry| registry.lease_for_live_body(body)) else {
            return (STATUS_INVALID_HANDLE, 0);
        };
        let Some((bound_index, bound_inst, _)) =
            hosted_driver_dynamic_type::pending_delete_binding(lease)
        else { return (STATUS_INVALID_HANDLE, 0); };
        if bound_index != index || bound_inst.hosted_domain_cookie != inst.hosted_domain_cookie
            || hosted_instance_pool_allocation_exec_if_live(inst, body, 1).is_none()
        { return (STATUS_INVALID_HANDLE, 0); }
        let Some(registry) = hosted_driver_dynamic_type::registry_mut() else {
            return (STATUS_INVALID_HANDLE, 0);
        };
        match registry.dereference_object(lease) {
            Ok(()) => (STATUS_SUCCESS, registry.borrowed_references(lease).unwrap_or(0)),
            Err(status) => (status.raw(), 0),
        }
    }
}

pub(crate) unsafe fn close_native_handle(
    pm: &nt_process::ProcessManager,
    table_owner: nt_process::ProcessId,
    handle: nt_process::Handle,
    body: u64,
    generation: u64,
) -> Result<(), u32> {
    let process = pm.process_kernel_object(table_owner).ok_or(STATUS_INVALID_HANDLE as u32)?;
    let owner = DynamicHandleOwner {
        process_id: table_owner,
        creation_sequence: pm.process_sequence_for_kernel_process_object(process)?,
    };
    let registry = hosted_driver_dynamic_type::registry_mut()
        .ok_or(STATUS_INVALID_HANDLE as u32)?;
    let lease = registry.object_for_body(body, generation)
        .ok_or(STATUS_INVALID_HANDLE as u32)?;
    if registry.object_for_handle(owner, u64::from(handle)) != Some(lease) {
        return Err(STATUS_INVALID_HANDLE as u32);
    }
    // The canonical close supplied the exact table owner and handle. Only this matching ledger
    // row may lose its handle reference; another process's equal numeric handle is irrelevant.
    registry.close_handle(owner, u64::from(handle))
        .map_err(|status| status.raw() as u32)?;
    assert_eq!(lease.body(), body);
    Ok(())
}

pub(crate) unsafe fn close_removed_object(body: u64, generation: u64) -> Result<(), u32> {
    let registry = hosted_driver_dynamic_type::registry_mut()
        .ok_or(STATUS_INVALID_HANDLE as u32)?;
    let lease = registry.object_for_body(body, generation)
        .ok_or(STATUS_INVALID_HANDLE as u32)?;
    registry.close_removed_object(lease).map_err(|status| status.raw() as u32)
}

/// Called only at the outer service-loop boundary. The primary must have reached its receive
/// continuation, proving that a component import returned and any local reply guard was dropped.
pub(crate) unsafe fn drain() -> usize {
    let mut completed = 0;
    loop {
        let Some(lease) = hosted_driver_dynamic_type::registry_mut()
            .and_then(|registry| registry.next_ready_delete())
        else { break; };
        let Some((index, inst, callback)) =
            hosted_driver_dynamic_type::pending_delete_binding(lease)
        else { break; };
        let Some(primary) = hosted_ingress_sources::primary_route(index) else { break; };
        if !matches!(crate::spawn_hosts::shared_ingress::owner::runtime::ready_for_admission(primary), Ok(true)) {
            break;
        }
        if hosted_class_irp_lane::prepare(index).is_err() { break; }
        let Some(selection) = hosted_class_irp_lane::select_callback(index) else { break; };
        // Worker construction may have nested through the service loop. Revalidate both physical
        // primary receipt and exact object allocation before claiming the one-shot callback.
        if !matches!(crate::spawn_hosts::shared_ingress::owner::runtime::ready_for_admission(primary), Ok(true))
            || hosted_instance_pool_allocation_exec_if_live(inst, lease.body(), 1).is_none()
        { break; }
        let Some(ticket) = hosted_driver_dynamic_type::registry_mut()
            .and_then(|registry| registry.take_delete(lease))
        else { break; };
        if ticket.callback != callback
            || !hosted_class_irp_lane::dispatch_callback(index, &selection, callback, ticket.object)
        {
            // The ticket is now in flight. A wall or uncertain acknowledgement cannot authorize
            // a second DeleteProcedure call or pool reuse.
            break;
        }
        if hosted_driver_dynamic_type::registry_mut()
            .is_none_or(|registry| registry.complete_delete(ticket).is_err())
        { break; }
        if !hosted_instance_pool_free(inst, ticket.object) {
            // The callback and ledger retirement are definite. A failed free retains the pool
            // allocation as a leak; it cannot justify repeating the callback.
            break;
        }
        completed += 1;
    }
    completed
}
