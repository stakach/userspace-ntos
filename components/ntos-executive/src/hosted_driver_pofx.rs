//! Root-owned PoFx registration and component activation for hosted WDM drivers.

use super::*;
use nt_power_manager::pofx::{ComponentEvent, PofxHandle, PofxManager};
use nt_power_types::pofx::{PoFxComponentIdleState, PoFxComponentV2, PoFxDeviceV3, PO_FX_VERSION_V3};

pub(super) const LABEL: u64 = 0x7D0;
const BEGIN: u64 = 1;
const COMPONENT: u64 = 2;
const COMMIT: u64 = 3;
const ABORT: u64 = 4;
const ACTIVATE: u64 = 5;
const IDLE: u64 = 6;
const UNREGISTER: u64 = 7;
const SET_LATENCY: u64 = 8;
const SET_RESIDENCY: u64 = 9;
const COMPLETE_IDLE_CONDITION: u64 = 10;
const COMPLETE_IDLE_STATE: u64 = 11;
const COMPLETE_POWER_NOT_REQUIRED: u64 = 12;
const REPORT_POWERED_ON: u64 = 13;
const POWER_CONTROL: u64 = 14;
const MAX_COMPONENTS: u32 = 0xffff;
const MAX_IDLE_STATES: u32 = 64;
const MAX_PROVIDERS: u32 = 64;
const VALID_COMPONENT_FLAGS: u64 = 0x7;
const ARG_COMPONENT: u64 = 0;
const ARG_IDLE: u64 = 56;
const ARG_PROVIDERS: u64 = ARG_IDLE + MAX_IDLE_STATES as u64 * 24;
const _: () = assert!(ARG_PROVIDERS + MAX_PROVIDERS as u64 * 4 <= FSD_ARG_BYTES);

#[derive(Clone, Copy)]
struct Callbacks {
    active: u64,
    idle: u64,
    idle_state: u64,
    power_required: u64,
    power_not_required: u64,
    power_control: u64,
    directed_up: u64,
    directed_down: u64,
    context: u64,
}

struct ComponentDescription {
    raw: PoFxComponentV2,
    idle_states: Vec<PoFxComponentIdleState>,
    providers: Vec<u32>,
    latency: u64,
    residency: u64,
}

struct Registration {
    cookie: u64,
    domain: HostedDomainIdentity,
    instance: usize,
    driver_id: u64,
    pdo: u64,
    count: u32,
    // Retained only as registration metadata. This broker never invokes a
    // callback: pinned dxgkrnl does not start PoFx runtime management, so no
    // component condition or device-level transition is issued. If runtime
    // start is added, each callback needs a root-owned ticket before dispatch.
    callbacks: Callbacks,
    components: Vec<Option<ComponentDescription>>,
    core: Option<PofxHandle>,
}

static NEXT_COOKIE: AtomicU64 = AtomicU64::new(0);
static mut REGISTRATIONS: Vec<Registration> = Vec::new();
static mut MANAGER: Option<PofxManager> = None;

unsafe fn manager() -> &'static mut PofxManager {
    let slot = &mut *core::ptr::addr_of_mut!(MANAGER);
    if slot.is_none() { *slot = Some(PofxManager::new()); }
    slot.as_mut().unwrap()
}

unsafe fn shared<T: Copy>(offset: u64) -> T {
    read_unaligned((FSD_ARG_VADDR + offset) as *const T)
}

unsafe fn write_shared<T: Copy>(offset: u64, value: T) {
    write_unaligned((FSD_ARG_VADDR + offset) as *mut T, value);
}

fn call(op: u64, a: u64, b: u64, c: u64) -> Result<u64, i32> {
    let (info, status, result, _, _) = unsafe {
        call_on4_raw((LABEL << 12) | 4, op, a, b, c)
    };
    if info != 2 {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, op, info, status]); }
    }
    let status = status as u32 as i32;
    if status == STATUS_SUCCESS { Ok(result) } else { Err(status) }
}

fn must_complete(op: u64, handle: u64, component: u64, value: u64) {
    if let Err(status) = call(op, handle, component, value) {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, op, handle, status as u32 as u64]); }
    }
}

pub(super) extern "win64" fn register_device(pdo: u64, description: u64, output: u64) -> i32 {
    if pdo == 0 || description == 0 || output == 0 { return STATUS_INVALID_PARAMETER; }
    let header: PoFxDeviceV3 = unsafe { read_unaligned(description as *const _) };
    if header.version != PO_FX_VERSION_V3 || header.component_count == 0
        || header.component_count > MAX_COMPONENTS || header.flags != 0
    { return STATUS_INVALID_PARAMETER; }
    let Some(bytes) = (header.component_count as u64)
        .checked_mul(core::mem::size_of::<PoFxComponentV2>() as u64)
        .and_then(|n| description.checked_add(104)?.checked_add(n))
    else { return STATUS_INVALID_PARAMETER; };
    let _ = bytes;
    unsafe { write_unaligned(output as *mut u64, 0); }
    unsafe {
        let _guard = component_device_reply_lock();
        write_shared(0, header);
        let cookie = match call(BEGIN, pdo, header.component_count as u64, 0) {
            Ok(cookie) if cookie != 0 => cookie,
            Ok(_) => crate::provider_bugcheck::report(0xc4, [LABEL, BEGIN, pdo, 0]),
            Err(status) => return status,
        };
        for index in 0..header.component_count {
            let address = description + 104 + index as u64 * 56;
            let component: PoFxComponentV2 = read_unaligned(address as *const _);
            if component.idle_state_count == 0 || component.idle_state_count > MAX_IDLE_STATES
                || component.provider_count > MAX_PROVIDERS
                || component.idle_states == 0
                || (component.provider_count != 0 && component.providers == 0)
            {
                must_complete(ABORT, cookie, 0, 0);
                return STATUS_INVALID_PARAMETER;
            }
            if component.idle_states.checked_add(component.idle_state_count as u64 * 24).is_none()
                || component.providers.checked_add(component.provider_count as u64 * 4).is_none()
            {
                must_complete(ABORT, cookie, 0, 0);
                return STATUS_INVALID_PARAMETER;
            }
            write_shared(ARG_COMPONENT, component);
            for state in 0..component.idle_state_count {
                let value: PoFxComponentIdleState = read_unaligned(
                    (component.idle_states + state as u64 * 24) as *const _);
                write_shared(ARG_IDLE + state as u64 * 24, value);
            }
            for provider in 0..component.provider_count {
                let value: u32 = read_unaligned(
                    (component.providers + provider as u64 * 4) as *const _);
                write_shared(ARG_PROVIDERS + provider as u64 * 4, value);
            }
            if let Err(status) = call(COMPONENT, cookie, index as u64, 0) {
                must_complete(ABORT, cookie, 0, 0);
                return status;
            }
        }
        match call(COMMIT, cookie, 0, 0) {
            Ok(handle) if handle != 0 => {
                write_unaligned(output as *mut u64, handle);
                STATUS_SUCCESS
            }
            Ok(_) => crate::provider_bugcheck::report(0xc4, [LABEL, COMMIT, cookie, 0]),
            Err(status) => { must_complete(ABORT, cookie, 0, 0); status }
        }
    }
}

pub(super) extern "win64" fn activate(handle: u64, component: u32, flags: u32) {
    if flags != 0 { unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, ACTIVATE, handle, flags as u64]); } }
    must_complete(ACTIVATE, handle, component as u64, flags as u64);
}

pub(super) extern "win64" fn idle(handle: u64, component: u32, flags: u32) {
    if flags != 0 { unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, IDLE, handle, flags as u64]); } }
    must_complete(IDLE, handle, component as u64, flags as u64);
}

pub(super) extern "win64" fn unregister_device(handle: u64) {
    must_complete(UNREGISTER, handle, 0, 0);
}

pub(super) extern "win64" fn set_latency(handle: u64, component: u32, latency: u64) {
    must_complete(SET_LATENCY, handle, component as u64, latency);
}

pub(super) extern "win64" fn set_residency(handle: u64, component: u32, residency: u64) {
    must_complete(SET_RESIDENCY, handle, component as u64, residency);
}

pub(super) extern "win64" fn complete_idle_condition(handle: u64, component: u32) {
    must_complete(COMPLETE_IDLE_CONDITION, handle, component as u64, 0);
}

pub(super) extern "win64" fn complete_idle_state(handle: u64, component: u32) {
    must_complete(COMPLETE_IDLE_STATE, handle, component as u64, 0);
}

pub(super) extern "win64" fn complete_device_power_not_required(handle: u64) {
    must_complete(COMPLETE_POWER_NOT_REQUIRED, handle, 0, 0);
}

pub(super) extern "win64" fn report_device_powered_on(handle: u64) {
    must_complete(REPORT_POWERED_ON, handle, 0, 0);
}

pub(super) extern "win64" fn power_control(
    handle: u64,
    code: u64,
    input: u64,
    input_len: u64,
    output: u64,
    output_len: u64,
    bytes_returned: u64,
) -> i32 {
    if code == 0 || (input_len != 0 && input == 0) || (output_len != 0 && output == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if bytes_returned != 0 { unsafe { write_unaligned(bytes_returned as *mut u64, 0); } }
    match call(POWER_CONTROL, handle, 0, 0) {
        Ok(_) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

fn callbacks(header: PoFxDeviceV3) -> Callbacks {
    Callbacks {
        active: header.component_active_condition_callback,
        idle: header.component_idle_condition_callback,
        idle_state: header.component_idle_state_callback,
        power_required: header.device_power_required_callback,
        power_not_required: header.device_power_not_required_callback,
        power_control: header.power_control_callback,
        directed_up: header.directed_power_up_callback,
        directed_down: header.directed_power_down_callback,
        context: header.device_context,
    }
}

fn callback_in_image(instance_index: usize, domain: HostedDomainIdentity, callback: u64) -> bool {
    if callback == 0 { return true; }
    let Some(singleton) = (unsafe { hosted_provider_singletons() })
        .and_then(|rows| rows.iter().find(|row| row.present
            && row.instance == instance_index && row.owner_domain == domain))
    else { return false; };
    singleton.run_va.checked_add(singleton.image_len as u64)
        .is_some_and(|end| callback >= singleton.run_va && callback < end)
}

/// The WDK limits provider dependency depth to four and forbids cycles.
/// Bounded recursion here cannot consume an unbounded native stack.
fn provider_path_valid(
    components: &[Option<ComponentDescription>],
    index: u32,
    depth: usize,
    path: &mut [u32; 5],
) -> bool {
    if depth > 4 || path[..depth].contains(&index) { return false; }
    path[depth] = index;
    let Some(component) = components[index as usize].as_ref() else { return false; };
    component.providers.iter().all(|&provider| {
        provider_path_valid(components, provider, depth + 1, path)
    })
}

fn registration_metadata_valid(row: &Registration) -> bool {
    let needs_callbacks = row.components.iter().flatten().any(|component| {
        component.raw.idle_state_count > 1
    });
    if needs_callbacks && (row.callbacks.active == 0 || row.callbacks.idle == 0
        || row.callbacks.idle_state == 0) { return false; }
    (0..row.count).all(|index| {
        provider_path_valid(&row.components, index, 0, &mut [u32::MAX; 5])
    })
}

pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    op: u64,
    a: u64,
    b: u64,
    c: u64,
    badge: u64,
    reply_cap: u64,
) -> (i32, u64) {
    let Some((index, inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return (STATUS_ACCESS_DENIED, 0);
    };
    let Some(domain) = instance_domain_identity(inst) else { return (STATUS_ACCESS_DENIED, 0); };
    if hosted_driver_caller(index, inst, badge).is_none() { return (STATUS_ACCESS_DENIED, 0); }
    let rows = unsafe { &mut *core::ptr::addr_of_mut!(REGISTRATIONS) };
    if op == BEGIN {
        let (_, _, pdo_id) = match authenticated_hosted_pdo(ch, a, reply_cap) {
            Ok(result) => result,
            Err(status) => return (status.raw(), 0),
        };
        if unsafe { crate::power_manager::started_device_state(pdo_id.raw()) }
            != Ok(nt_power_manager::DevicePowerState::D0)
        { return (STATUS_DEVICE_NOT_READY, 0); }
        if inst.exec_arg_va == 0 || b == 0 || b > MAX_COMPONENTS as u64 {
            return (STATUS_INVALID_PARAMETER, 0);
        }
        let header: PoFxDeviceV3 = unsafe { read_unaligned(inst.exec_arg_va as *const _) };
        if header.version != PO_FX_VERSION_V3 || header.flags != 0 || header.component_count as u64 != b
            || rows.iter().any(|row| row.pdo == pdo_id.raw() && row.domain == domain)
        { return (STATUS_INVALID_PARAMETER, 0); }
        let callbacks = callbacks(header);
        for callback in [callbacks.active, callbacks.idle, callbacks.idle_state,
            callbacks.power_required, callbacks.power_not_required, callbacks.power_control,
            callbacks.directed_up, callbacks.directed_down] {
            if !callback_in_image(index, domain, callback) { return (STATUS_INVALID_PARAMETER, 0); }
        }
        let mut components = Vec::new();
        if components.try_reserve_exact(b as usize).is_err() || rows.try_reserve(1).is_err() {
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        components.resize_with(b as usize, || None);
        let cookie = match NEXT_COOKIE.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |last| last.checked_add(1)) {
            Ok(last) => last + 1,
            Err(_) => return (STATUS_INSUFFICIENT_RESOURCES, 0),
        };
        rows.push(Registration { cookie, domain, instance: index, driver_id: inst.driver_id,
            pdo: pdo_id.raw(), count: b as u32, callbacks, components, core: None });
        return (STATUS_SUCCESS, cookie);
    }
    let Some(position) = rows.iter().position(|row| row.cookie == a && row.domain == domain
        && row.instance == index && row.driver_id == inst.driver_id)
    else { return (STATUS_INVALID_PARAMETER, 0); };
    if op == ABORT {
        if rows[position].core.is_some() { return (STATUS_INVALID_PARAMETER, 0); }
        rows.remove(position);
        return (STATUS_SUCCESS, 0);
    }
    if op == COMPONENT {
        let row = &mut rows[position];
        if row.core.is_some() || b >= row.count as u64 || inst.exec_arg_va == 0
            || row.components[b as usize].is_some() { return (STATUS_INVALID_PARAMETER, 0); }
        let mut raw: PoFxComponentV2 = unsafe { read_unaligned(inst.exec_arg_va as *const _) };
        if raw.idle_state_count == 0 || raw.idle_state_count > MAX_IDLE_STATES
            || raw.provider_count > MAX_PROVIDERS || raw.flags & !VALID_COMPONENT_FLAGS != 0
        { return (STATUS_INVALID_PARAMETER, 0); }
        let mut idle_states: Vec<PoFxComponentIdleState> = Vec::new();
        let mut providers: Vec<u32> = Vec::new();
        if idle_states.try_reserve_exact(raw.idle_state_count as usize).is_err()
            || providers.try_reserve_exact(raw.provider_count as usize).is_err()
        { return (STATUS_INSUFFICIENT_RESOURCES, 0); }
        for state in 0..raw.idle_state_count {
            idle_states.push(unsafe { read_unaligned((inst.exec_arg_va + ARG_IDLE + state as u64 * 24) as *const _) });
        }
        for provider in 0..raw.provider_count {
            let index: u32 = unsafe { read_unaligned((inst.exec_arg_va + ARG_PROVIDERS + provider as u64 * 4) as *const _) };
            if index >= row.count || index == b as u32 || providers.contains(&index) {
                return (STATUS_INVALID_PARAMETER, 0);
            }
            providers.push(index);
        }
        if raw.deepest_wakeable_idle_state >= raw.idle_state_count {
            return (STATUS_INVALID_PARAMETER, 0);
        }
        if idle_states[0].transition_latency != 0
            || idle_states[0].residency_requirement != 0
        { return (STATUS_INVALID_PARAMETER, 0); }
        // Pointer fields belong to the caller's temporary allocation. Retain
        // only the copied arrays in this root-owned registration.
        raw.idle_states = 0;
        raw.providers = 0;
        row.components[b as usize] = Some(ComponentDescription {
            raw, idle_states, providers, latency: 0, residency: 0,
        });
        return (STATUS_SUCCESS, 0);
    }
    if op == COMMIT {
        let row = &mut rows[position];
        if row.core.is_some() || row.components.iter().any(Option::is_none)
            || !registration_metadata_valid(row) {
            return (STATUS_INVALID_PARAMETER, 0);
        }
        let core = match unsafe { manager() }.register(row.cookie, row.pdo, row.count) {
            Ok(handle) => handle,
            Err(_) => return (STATUS_INSUFFICIENT_RESOURCES, 0),
        };
        row.core = Some(core);
        return (STATUS_SUCCESS, row.cookie);
    }
    let row = &mut rows[position];
    let Some(core) = row.core else { return (STATUS_INVALID_PARAMETER, 0); };
    if op == UNREGISTER {
        if unsafe { manager() }.unregister(row.cookie, core).is_err() {
            return (STATUS_INVALID_PARAMETER, 0);
        }
        rows.remove(position);
        return (STATUS_SUCCESS, 0);
    }
    if op == POWER_CONTROL {
        // No platform extension has registered a power-control provider.
        // The request has no effect and must not report synthetic success.
        return (STATUS_NOT_SUPPORTED, 0);
    }
    if matches!(op, COMPLETE_POWER_NOT_REQUIRED | REPORT_POWERED_ON) {
        // No device-level power transition was issued by this broker.
        return (STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    if b >= row.count as u64 { return (STATUS_INVALID_PARAMETER, 0); }
    if matches!(op, ACTIVATE | IDLE)
        && unsafe { manager() }.started(row.cookie, core) != Ok(false)
    {
        // No runtime-start export is bound for the pinned dxgkrnl image.
        // A future starter must add callback tickets before any count edge.
        return (STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    match op {
        ACTIVATE => match unsafe { manager() }.activate(row.cookie, core, b as u32) {
            Ok(ComponentEvent::None) => (STATUS_SUCCESS, 0),
            _ => (STATUS_INVALID_DEVICE_REQUEST, 0),
        },
        IDLE => match unsafe { manager() }.idle(row.cookie, core, b as u32) {
            Ok(ComponentEvent::None) => (STATUS_SUCCESS, 0),
            _ => (STATUS_INVALID_DEVICE_REQUEST, 0),
        },
        SET_LATENCY => {
            row.components[b as usize].as_mut().unwrap().latency = c;
            (STATUS_SUCCESS, 0)
        }
        SET_RESIDENCY => {
            row.components[b as usize].as_mut().unwrap().residency = c;
            (STATUS_SUCCESS, 0)
        }
        COMPLETE_IDLE_CONDITION | COMPLETE_IDLE_STATE => {
            // A completion without a retained callback request is invalid.
            (STATUS_INVALID_DEVICE_REQUEST, 0)
        }
        _ => (STATUS_INVALID_PARAMETER, 0),
    }
}

pub(crate) unsafe fn quiesced(domain: HostedDomainIdentity) -> bool {
    // A live registration alone does not block teardown. Exact callback
    // tickets do, including uncertain dispatches. No callback is dispatched
    // by the pinned dxgkrnl path, but query the core rather than assuming it.
    let rows = &*core::ptr::addr_of!(REGISTRATIONS);
    rows.iter().filter(|row| row.domain == domain).all(|row| {
        row.core.is_none_or(|handle| {
            manager().callback_quiesced(row.cookie, handle) == Ok(true)
        })
    })
}

pub(crate) unsafe fn retire_domain(domain: HostedDomainIdentity) {
    let rows = &mut *core::ptr::addr_of_mut!(REGISTRATIONS);
    let manager = manager();
    for row in rows.iter().filter(|row| row.domain == domain) {
        if let Some(handle) = row.core {
            assert!(manager.unregister(row.cookie, handle).is_ok(),
                "PoFx registration and core owner diverged during retirement");
        }
    }
    rows.retain(|row| row.domain != domain);
}
