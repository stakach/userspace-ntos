//! Primary-driver KPCR projections owned by exact physical invocations.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_process::{native_handle::NativeHandleCaller, STATUS_INVALID_HANDLE};
use nt_user_host::provider_thread_projection::{ProjectionOwners, ThreadProjection};

static mut OWNERS: ProjectionOwners<PeerRoute, LaneDispatchIdentity> = ProjectionOwners::new();

unsafe fn primary(route: PeerRoute) -> Result<Option<(usize, DriverInstance)>, u32> {
    let source = runtime::physical_source(route).map_err(|_| STATUS_INVALID_HANDLE)?;
    let runtime::PhysicalDomain::Hosted(domain) = source.domain else { return Ok(None); };
    if source.kind != runtime::PhysicalSourceKind::Primary { return Ok(None); }
    let (index, inst) = driver_instances().and_then(|rows| rows.iter().copied().enumerate()
        .find(|(_, inst)| instance_domain_identity(*inst) == Some(domain)
            && inst.tcb == source.tcb && inst.pml4 == source.pml4))
        .ok_or(STATUS_INVALID_HANDLE)?;
    Ok(Some((index, inst)))
}

unsafe fn projection(route: PeerRoute, caller: NativeHandleCaller)
    -> Result<Option<ThreadProjection>, u32> {
    let Some((index, inst)) = primary(route)? else { return Ok(None); };
    let (_, _, _, thread_body, _) = driver_ps_context::project(inst, caller)?;
    let window = ExecVaWindow::try_for_instance(index).ok_or(STATUS_INVALID_HANDLE)?;
    Ok(Some(ThreadProjection { executor: inst.tcb, address_space: inst.pml4,
        component_kpcr: FSD_KPCR_VA, executive_kpcr: window.data_va + 0x1000,
        thread_body }))
}

unsafe fn write(projection: ThreadProjection) {
    write_volatile((projection.executive_kpcr + 0x18) as *mut u64, projection.component_kpcr);
    write_volatile((projection.executive_kpcr + 0x20) as *mut u64, projection.component_kpcr + 0x180);
    write_volatile((projection.executive_kpcr + 0x188) as *mut u64, projection.thread_body);
}

/// The freshly enrolled primary TCB is still suspended. Retain before its first Resume.
pub(crate) unsafe fn bootstrap(route: PeerRoute, caller: NativeHandleCaller) -> Result<(), u32> {
    let _durable = crate::allocator::enter_durable();
    let projection = projection(route, caller)?.ok_or(STATUS_INVALID_HANDLE)?;
    crate::service_sec_image::with_provider_process_manager(|pm| {
        (&mut *core::ptr::addr_of_mut!(OWNERS)).capture(pm, route, None, caller, projection)
    })?;
    write(projection);
    Ok(())
}

/// Admission owns the exact blocked Call; no driver code runs before the pump releases it.
pub(crate) unsafe fn enter(channel: &crate::spawn_hosts::PumpChannel,
    caller: Option<NativeHandleCaller>) -> Result<(), u32> {
    let route = runtime::channel_route(channel).map_err(|_| STATUS_INVALID_HANDLE)?;
    let Some(route) = route else { return Ok(()); };
    if primary(route)?.is_none() { return Ok(()); }
    let caller = match caller { Some(caller) => caller,
        None => crate::provider_registry_caller::resolve(channel)? };
    let dispatch = runtime::dispatch(route).map_err(|_| STATUS_INVALID_HANDLE)?;
    let _durable = crate::allocator::enter_durable();
    let projection = projection(route, caller)?.ok_or(STATUS_INVALID_HANDLE)?;
    let initialized = crate::service_sec_image::with_provider_process_manager(|pm| {
        let owners = &mut *core::ptr::addr_of_mut!(OWNERS);
        if owners.contains_dispatch(route, dispatch) || owners.has_bootstrap(route) {
            owners.bind(pm, route, dispatch, caller, projection)?;
            Ok(false)
        } else {
            if channel.initial != crate::spawn_hosts::InitialAction::ReplyRequest {
                return Err(STATUS_INVALID_HANDLE);
            }
            owners.capture(pm, route, Some(dispatch), caller, projection)?;
            Ok(true)
        }
    })?;
    if initialized { write(projection); }
    Ok(())
}

/// Called after the exact parent's physical execution hold was acquired.
pub(crate) unsafe fn hold(route: PeerRoute, dispatch: LaneDispatchIdentity) -> Result<(), u32> {
    if primary(route)?.is_none() { return Ok(()); }
    if !(&mut *core::ptr::addr_of_mut!(OWNERS)).hold(route, dispatch)? {
        return Err(STATUS_INVALID_HANDLE);
    }
    Ok(())
}

pub(crate) unsafe fn restore(route: PeerRoute, dispatch: LaneDispatchIdentity) -> Result<(), u32> {
    let projection = crate::service_sec_image::with_provider_process_manager(|pm| {
        (&mut *core::ptr::addr_of_mut!(OWNERS)).begin_restore(pm, route, dispatch)
    })?;
    if let Some(projection) = projection { write(projection); }
    Ok(())
}

pub(crate) unsafe fn restored(route: PeerRoute, dispatch: LaneDispatchIdentity) -> Result<(), u32> {
    (&mut *core::ptr::addr_of_mut!(OWNERS)).restored(route, dispatch)
}

/// The canonical completion keeps the driver blocked in its final Call. Clear its pointer
/// before releasing references; an uncertain pump return never reaches this hook.
pub(crate) unsafe fn complete(route: PeerRoute, dispatch: LaneDispatchIdentity) -> Result<(), u32> {
    let owners = &mut *core::ptr::addr_of_mut!(OWNERS);
    if let Some(projection) = owners.completing(route, dispatch)? {
        write_volatile((projection.executive_kpcr + 0x188) as *mut u64, 0);
    }
    crate::service_sec_image::with_provider_process_manager(|pm| owners.retire(pm, route, dispatch))
}

/// Primary retirement has already stopped the exact TCB and drained its canonical ingress.
pub(crate) unsafe fn retire_stopped(route: PeerRoute, inst: DriverInstance) -> Result<(), u32> {
    let owners = &mut *core::ptr::addr_of_mut!(OWNERS);
    if let Some(projection) = owners.stopped_projection(route, inst.tcb, inst.pml4)? {
        write_volatile((projection.executive_kpcr + 0x188) as *mut u64, 0);
    }
    crate::service_sec_image::with_provider_process_manager(|pm| {
        owners.retire_stopped(pm, route, inst.tcb, inst.pml4)
    })
}
