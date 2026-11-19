//! Root owner of the WDDM bridge interface's cross-domain routes from win32k into its provider.
//!
//! `IOCTL_WDDM_BRIDGE_QUERY_INTERFACE` returns provider function pointers. Before that output
//! leaves the root, [`project_query_interface`] proves every pointer is code of the provider
//! that owns the target device, rewrites each to a win32k-domain entry
//! (`win32k_subsystem::wddm_bridge`), and records one binding for win32k's exact domain identity.
//! A routed entry reaches [`service`], which calls the recorded provider RVA on a provider export
//! worker owned by the (provider, win32k) pair. Caller pointers are staged in that worker's marshal
//! window and copied back only after a reusable completion.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_component_suspension::peer_registry::PeerRoute;
use nt_hosted_runtime::{
    classify_hosted_caller_arguments, hosted_wddm_bridge_send_ioctl_marshal_policy,
    HostedCallerArgument,
};
use nt_io_manager::wddm_bridge_interface::{
    project_bridge_interface, BridgeBindings, BridgeCallerIdentity, BridgeProjectionError,
    BridgeProviderIdentity, BridgeResolveError, WDDM_BRIDGE_SEND_IOCTL_SLOT,
};

/// Root-only: win32k reaches these rows only through [`service`].
static mut BINDINGS: BridgeBindings = BridgeBindings::new();
static TRACES: AtomicU64 = AtomicU64::new(0);
const TRACE_LIMIT: u64 = 64;

unsafe fn bindings() -> &'static mut BridgeBindings {
    &mut *core::ptr::addr_of_mut!(BINDINGS)
}

pub(in crate::driver_launch) enum ProjectionResult {
    Projected,
    /// No room for the binding; nothing was rewritten.
    Retry,
    /// The query completes with this status and no output.
    Refused(i32),
}

fn caller_identity(route: PeerRoute) -> Option<BridgeCallerIdentity> {
    let source = unsafe { runtime::physical_source(route) }.ok()?;
    let runtime::PhysicalDomain::Provider { domain, .. } = source.domain else { return None };
    (crate::current_win32k_provider_domain() == Some(domain))
        .then_some(BridgeCallerIdentity { domain: domain.domain, generation: domain.generation })
}

unsafe fn provider_identity(singleton: HostedProviderSingleton) -> BridgeProviderIdentity {
    BridgeProviderIdentity {
        instance: singleton.instance,
        domain_id: singleton.owner_domain.domain_id.raw(),
        domain_cookie: singleton.owner_domain.cookie,
        publication_cookie: singleton.provider_publication_cookie,
    }
}

/// The live singleton for a recorded provider publication, or none once it has retired.
unsafe fn live_singleton(provider: BridgeProviderIdentity) -> Option<HostedProviderSingleton> {
    let (_, singleton) = find_hosted_provider_singleton_by_cookie(provider.publication_cookie)?;
    (provider_identity(singleton) == provider).then_some(singleton)
}

/// Project a successful query for the win32k lane `route`. `device_id` is the IOCTL's target.
pub(in crate::driver_launch) unsafe fn project_query_interface(
    route: PeerRoute,
    device_id: u64,
    output: &mut [u8],
) -> ProjectionResult {
    let refuse = |stage: &[u8], status: i32| {
        print_str(b"[wddm-bridge] refused stage=");
        print_str(stage);
        print_str(b" status=0x");
        print_hex(status as u32);
        print_str(b"\n");
        ProjectionResult::Refused(status)
    };
    let Some(caller) = caller_identity(route) else {
        return refuse(b"caller", STATUS_INVALID_HANDLE);
    };
    let Some((instance_index, inst, _)) = hosted_driver_device_route_by_device_id(device_id)
    else {
        return refuse(b"device", STATUS_DEVICE_NOT_READY);
    };
    let domain = instance_domain_identity(inst);
    let Some(singleton) = hosted_provider_singletons().and_then(|rows| {
        rows.iter().copied().find(|row| {
            row.present && row.instance == instance_index && Some(row.owner_domain) == domain
        })
    }) else {
        return refuse(b"provider", STATUS_NOT_SUPPORTED);
    };
    if !matches!(
        plan_hosted_provider_import_binding(Some(hosted_provider_domain_descriptor(singleton)), 0),
        Ok(HostedProviderImportBinding::ProviderDomainCall(_))
    ) {
        return refuse(b"provider-domain", STATUS_NOT_SUPPORTED);
    }
    if bindings().reserve().is_err() {
        return ProjectionResult::Retry;
    }
    let projection = match project_bridge_interface(
        output,
        singleton.run_va,
        singleton.image_len as u64,
        |rva| executable_extent(singleton, rva).is_some(),
        crate::win32k_subsystem::wddm_bridge::entry,
    ) {
        Ok(projection) => projection,
        Err(BridgeProjectionError::Length) => return refuse(b"length", STATUS_INVALID_PARAMETER),
        Err(BridgeProjectionError::SlotOutsideProvider { slot }) => {
            print_str(b"[wddm-bridge] slot outside provider code slot=");
            print_u64(slot as u64);
            print_str(b"\n");
            return refuse(b"slot", STATUS_INVALID_PARAMETER);
        }
    };
    if bindings().publish(caller, provider_identity(singleton), projection).is_err() {
        // Room was reserved above.
        crate::provider_bugcheck::report(0xc4, [0x5744_444d, device_id, 0, 1]);
    }
    print_str(b"[wddm-bridge] projected provider=");
    print_str(singleton.provider.as_bytes());
    print_str(b" cookie=");
    print_u64(singleton.provider_publication_cookie);
    print_str(b" slots=");
    print_u64(projection.present_slots() as u64);
    print_str(b" send-ioctl-rva=0x");
    print_hex(projection.provider_rva(WDDM_BRIDGE_SEND_IOCTL_SLOT).unwrap_or(0) as u32);
    print_str(b"\n");
    ProjectionResult::Projected
}

/// A provider publication is retiring: its routes are gone before its domain can be reused.
pub(in crate::driver_launch) unsafe fn retire_provider(domain: HostedDomainIdentity) {
    let dropped = bindings().retire_provider(domain.domain_id.raw(), domain.cookie);
    if dropped != 0 {
        print_str(b"[wddm-bridge] retired bindings=");
        print_u64(dropped as u64);
        print_str(b"\n");
    }
}

unsafe fn trace(phase: &[u8], slot: u64, rva: u64, args: &[u64], result: u64) {
    if TRACES.fetch_add(1, Ordering::Relaxed) >= TRACE_LIMIT {
        return;
    }
    print_str(b"[provider-export] ");
    print_str(phase);
    print_str(b" dependent=win32k slot=");
    print_u64(slot);
    print_str(b" rva=0x");
    print_hex(rva as u32);
    print_str(b" args=");
    for (index, arg) in args.iter().enumerate() {
        if index != 0 {
            print_str(b",");
        }
        print_hex64(*arg);
    }
    if phase == b"done" {
        print_str(b" result=0x");
        print_hex64(result);
    }
    print_str(b"\n");
}

unsafe fn reject(stage: &[u8], slot: u64, status: i32) -> (i32, u64) {
    if TRACES.fetch_add(1, Ordering::Relaxed) < TRACE_LIMIT {
        print_str(b"[provider-export] reject dependent=win32k slot=");
        print_u64(slot);
        print_str(b" stage=");
        print_str(stage);
        print_str(b" status=0x");
        print_hex(status as u32);
        print_str(b"\n");
    }
    (status, 0)
}

/// One routed bridge call from the exact physical win32k lane: `(status, provider result)`.
/// `entry_rsp` is the entry's stack pointer; the caller's arguments start at `entry_rsp + 8`.
pub(crate) unsafe fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    [slot, entry_rsp, spare0, spare1]: [u64; 4],
) -> (i32, u64) {
    let expected_mi = (crate::win32k_subsystem::W32_WDDM_BRIDGE_LABEL << 12) | 4;
    let (route, dispatch, caller) = match crate::service_sec_image::
        authenticate_win32k_service_request(ch, reply_cap, badge, mi, expected_mi)
    {
        Ok(authenticated) => authenticated,
        Err(status) => return reject(b"authentication", slot, status as i32),
    };
    if crate::provider_service_ingress::physical_win32k_provider(ch, route, dispatch).is_err() {
        return reject(b"physical-lane", slot, STATUS_INVALID_HANDLE);
    }
    if spare0 != 0 || spare1 != 0 {
        return reject(b"spare", slot, STATUS_INVALID_PARAMETER);
    }
    let Some(win32k) = caller_identity(route) else {
        return reject(b"caller", slot, STATUS_INVALID_HANDLE);
    };
    let Ok(slot_index) = usize::try_from(slot) else {
        return reject(b"slot", slot, STATUS_INVALID_PARAMETER);
    };
    let not_connected = nt_status::NtStatus::DEVICE_NOT_CONNECTED.raw();
    let target = match bindings().resolve(win32k, slot_index,
        |provider| live_singleton(provider).is_some())
    {
        Ok(target) => target,
        Err(BridgeResolveError::NoBinding) => return reject(b"binding", slot, not_connected),
        Err(BridgeResolveError::ProviderRetired) => return reject(b"retired", slot, not_connected),
        Err(BridgeResolveError::Unrouted) => return reject(b"unrouted", slot, STATUS_NOT_SUPPORTED),
        Err(BridgeResolveError::AbsentSlot) => {
            return reject(b"absent", slot, STATUS_INVALID_PARAMETER)
        }
    };
    let policy = match slot_index {
        WDDM_BRIDGE_SEND_IOCTL_SLOT => hosted_wddm_bridge_send_ioctl_marshal_policy(),
        _ => return reject(b"policy-slot", slot, STATUS_NOT_SUPPORTED),
    };
    let Some(singleton) = live_singleton(target.provider) else {
        return reject(b"singleton", slot, not_connected);
    };
    if !matches!(
        plan_hosted_provider_import_binding(Some(hosted_provider_domain_descriptor(singleton)),
            target.provider_rva),
        Ok(HostedProviderImportBinding::ProviderDomainCall(_))
    ) {
        return reject(b"provider-domain", slot, STATUS_DEVICE_NOT_READY);
    }
    let Some(provider_inst) = instance(singleton.instance) else {
        return reject(b"provider-instance", slot, STATUS_DEVICE_NOT_READY);
    };

    // Every argument is in the caller frame: the entry spilled rcx/rdx/r8/r9 into its home space.
    let argument_bytes = policy.argument_count as u64 * 8;
    let Some(frame) = entry_rsp.checked_add(8).and_then(|frame| {
        crate::win32k_glue::win32k_stack_alias_for_route(route, frame, argument_bytes)
    }) else {
        return reject(b"frame", slot, STATUS_ACCESS_VIOLATION);
    };
    let mut args = [0u64; HOSTED_PROVIDER_EXPORT_ARG_CAP];
    for (index, arg) in args.iter_mut().take(policy.argument_count as usize).enumerate() {
        *arg = read_volatile((frame + index as u64 * 8) as *const u64);
    }
    let classified = match classify_hosted_caller_arguments(policy, &args) {
        Ok(classified) => classified,
        Err(_) => return reject(b"policy", slot, STATUS_NOT_SUPPORTED),
    };

    let Some(owner) = HostedProviderObjectOwner::new(
        singleton.owner_domain.domain_id.raw(), singleton.owner_domain.cookie,
        win32k.domain, win32k.generation)
    else {
        return reject(b"owner", slot, STATUS_INVALID_HANDLE);
    };
    let dependent = hosted_provider_export_lane::Dependent::Win32k(
        nt_provider_wait::ProviderDomainIdentity { domain: win32k.domain, generation: win32k.generation });
    if let Err(status) = hosted_provider_export_lane::prepare(
        singleton.instance, dependent, owner, singleton.provider_publication_cookie)
    {
        return reject(b"worker-prepare", slot, status.raw());
    }
    let Some(selection) = hosted_provider_export_lane::select(
        singleton.instance, dependent, owner, singleton.provider_publication_cookie)
    else {
        return reject(b"worker-select", slot, nt_status::NtStatus::DEVICE_BUSY.raw());
    };
    let Some(window) = HostedProviderMarshalWindow::new(
        selection.component_shared.checked_add(SH_PROVIDER_EXPORT_MARSHAL_BASE).unwrap_or(0),
        selection.executive_shared.checked_add(SH_PROVIDER_EXPORT_MARSHAL_BASE).unwrap_or(0),
        SH_PROVIDER_EXPORT_MARSHAL_BYTES,
    ) else {
        return reject(b"window", slot, STATUS_INVALID_PARAMETER);
    };

    // Stage caller ranges. A write-back target is captured with its exact backing and must still
    // be that backing after the call.
    let mut state = ProviderMarshalState::empty();
    let mut targets: [Option<(super::hosted_kernel_win32k_source_ioctl::Target, u64)>;
        HOSTED_PROVIDER_EXPORT_ARG_CAP] = Default::default();
    let caller_args = args;
    for (index, argument) in classified.iter().enumerate() {
        args[index] = match *argument {
            HostedCallerArgument::Scalar(value) => value,
            HostedCallerArgument::Null => 0,
            // A non-NULL empty range: the provider receives a non-NULL address it may not touch.
            HostedCallerArgument::Buffer { bytes: 0, .. } => window.component_base,
            HostedCallerArgument::Buffer { address, bytes, copy_in, copy_out } => {
                let Some(target) =
                    super::hosted_kernel_win32k_source_ioctl::Target::capture(route, address, bytes)
                else {
                    return reject(b"caller-range", slot, STATUS_ACCESS_VIOLATION);
                };
                let Some(caller_exec) = target.address_if_live(route).filter(|va| *va != 0) else {
                    return reject(b"caller-range-live", slot, STATUS_ACCESS_VIOLATION);
                };
                let Some((provider_component, provider_exec)) =
                    provider_marshal_alloc(&mut state, window, bytes)
                else {
                    return reject(b"window-capacity", slot, STATUS_INSUFFICIENT_RESOURCES);
                };
                if copy_in {
                    copy_bytes(provider_exec, caller_exec, bytes);
                }
                if copy_out {
                    if provider_marshal_add_copyout(&mut state, caller_exec, provider_exec, bytes)
                        .is_none()
                    {
                        return reject(b"copyouts", slot, STATUS_INSUFFICIENT_RESOURCES);
                    }
                    targets[index] = Some((target, caller_exec));
                }
                provider_component
            }
        };
    }

    let argument_count = policy.argument_count as usize;
    trace(b"enter", slot, target.provider_rva, &caller_args[..argument_count], 0);
    let mut result = match hosted_provider_export_lane::dispatch(
        selection, target.provider_rva, &args, entry_rsp, caller)
    {
        Ok(result) => result,
        // The provider may have run. Nothing is copied back and the call is never replayed;
        // the worker stays retained as uncertain.
        Err(status) => return reject(b"dispatch", slot, status),
    };
    if targets.iter().flatten().any(|(target, exec)| target.address_if_live(route) != Some(*exec)) {
        return reject(b"caller-range-retired", slot, STATUS_ACCESS_VIOLATION);
    }
    complete_provider_export_marshal(policy, &state, singleton.instance, provider_inst,
        &mut result, false);
    trace(b"done", slot, target.provider_rva, &caller_args[..argument_count], result);
    (STATUS_SUCCESS, result)
}
