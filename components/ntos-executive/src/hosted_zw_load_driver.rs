//! Kernel-mode ZwLoadDriver/ZwUnloadDriver from a hosted driver into the live CM and loader.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;

const STATUS_INVALID_HANDLE_LOCAL: i32 = 0xC000_0008u32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND_LOCAL: i32 = 0xC000_0034u32 as i32;
const STATUS_INSUFFICIENT_RESOURCES_LOCAL: i32 = 0xC000_009Au32 as i32;
const STATUS_IMAGE_ALREADY_LOADED_LOCAL: i32 = 0xC000_010Eu32 as i32;

/// A Zw call is from KernelMode, so no user token privilege check applies. The executive must
/// still authenticate the physical hosted sender before it reads either caller pointer.
pub(super) extern "win64" fn s_zw_load_driver(service_name: u64) -> i32 {
    let (label, status, _, _, _) = unsafe {
        call_on4(
            (FSD_SERVICE_ZW_LOAD_DRIVER_LABEL << 12) | 1,
            service_name,
            0,
            0,
            0,
        )
    };
    if label != 0 {
        unsafe {
            crate::provider_bugcheck::report(
                0xC4,
                [
                    FSD_SERVICE_ZW_LOAD_DRIVER_LABEL,
                    service_name,
                    label,
                    status,
                ],
            );
        }
    }
    status as u32 as i32
}

pub(super) extern "win64" fn s_zw_unload_driver(service_name: u64) -> i32 {
    let (label, status, _, _, _) = unsafe {
        call_on4(
            (FSD_SERVICE_ZW_UNLOAD_DRIVER_LABEL << 12) | 1,
            service_name,
            0,
            0,
            0,
        )
    };
    if label != 0 {
        unsafe {
            crate::provider_bugcheck::report(0xC4, [FSD_SERVICE_ZW_UNLOAD_DRIVER_LABEL, label, status, 0]);
        }
    }
    status as u32 as i32
}

static mut ACTIVE_DRIVER_TRANSITIONS: Vec<alloc::string::String> = Vec::new();

struct DriverTransitionReservation {
    path: alloc::string::String,
}

fn source_reply_unchanged(
    channel: &crate::spawn_hosts::PumpChannel,
    instance_index: usize,
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply_cap: u64,
) -> bool {
    unsafe {
        runtime::dispatch(route).ok() == Some(dispatch)
            && runtime::current_reply(route).ok() == Some(reply_cap)
            && instance_for_pump_channel(channel, reply_cap)
                .is_some_and(|(index, _)| index == instance_index)
    }
}

struct CapturedDriverCall {
    instance_index: usize,
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    path: alloc::string::String,
}

/// Authenticate the exact physical caller before dereferencing its UNICODE_STRING or buffer.
unsafe fn capture_driver_call(
    channel: &crate::spawn_hosts::PumpChannel,
    service_name: u64,
    badge: u64,
    reply_cap: u64,
) -> Result<CapturedDriverCall, i32> {
    let (instance_index, inst) = instance_for_pump_channel(channel, reply_cap)
        .ok_or(STATUS_INVALID_HANDLE_LOCAL)?;
    let caller = hosted_driver_caller(instance_index, inst, badge)
        .ok_or(STATUS_INVALID_HANDLE_LOCAL)?;
    if caller.route.endpoint() != channel.fault_ep
        || caller.runtime.map_or(inst.tcb, |worker| worker.tcb) != channel.tcb
    {
        return Err(STATUS_INVALID_HANDLE_LOCAL);
    }
    let route = caller.route;
    let dispatch = runtime::dispatch(route).map_err(|_| STATUS_INVALID_HANDLE_LOCAL)?;
    if runtime::current_reply(route).ok() != Some(reply_cap) {
        return Err(STATUS_INVALID_HANDLE_LOCAL);
    }
    let path = nt_config_client::capture_driver_service_name(service_name, |va, output| {
        let Some(exec_va) =
            hosted_driver_component_object_exec_va(instance_index, inst, va, output.len() as u64)
        else {
            return false;
        };
        unsafe {
            core::ptr::copy_nonoverlapping(exec_va as *const u8, output.as_mut_ptr(), output.len());
        }
        true
    })?;
    if !source_reply_unchanged(channel, instance_index, route, dispatch, reply_cap) {
        panic!("Zw driver control source Reply or dispatch changed during name capture");
    }
    Ok(CapturedDriverCall { instance_index, route, dispatch, path })
}

impl DriverTransitionReservation {
    unsafe fn acquire(path: &str) -> Result<Self, i32> {
        let active = &mut *core::ptr::addr_of_mut!(ACTIVE_DRIVER_TRANSITIONS);
        if active
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(path))
        {
            return Err(nt_status::NtStatus::DEVICE_BUSY.raw());
        }
        let mut owned = alloc::string::String::new();
        owned
            .try_reserve_exact(path.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES_LOCAL)?;
        owned.push_str(path);
        let mut guard_path = alloc::string::String::new();
        guard_path
            .try_reserve_exact(path.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES_LOCAL)?;
        guard_path.push_str(path);
        active
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES_LOCAL)?;
        active.push(owned);
        Ok(Self { path: guard_path })
    }
}

impl Drop for DriverTransitionReservation {
    fn drop(&mut self) {
        unsafe {
            let active = &mut *core::ptr::addr_of_mut!(ACTIVE_DRIVER_TRANSITIONS);
            let index = active
                .iter()
                .position(|existing| existing.eq_ignore_ascii_case(&self.path))
                .expect("hosted driver transition reservation disappeared");
            active.swap_remove(index);
        }
    }
}

pub(super) unsafe fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    service_name: u64,
    badge: u64,
    reply_cap: u64,
) -> i32 {
    let _durable = crate::allocator::enter_durable();
    let call = match capture_driver_call(channel, service_name, badge, reply_cap) {
        Ok(call) => call,
        Err(status) => return status,
    };
    let selected = crate::live_config_driver_service_launch_spec_from_registry_path(
        &call.path,
        nt_config_manager::SERVICE_DEMAND_START,
    );
    if !source_reply_unchanged(channel, call.instance_index, call.route, call.dispatch, reply_cap) {
        panic!("ZwLoadDriver source Reply or dispatch changed during CM lookup");
    }
    let spec = match selected {
        Ok(spec) => spec,
        Err(status) => return status,
    };
    if driver_id_by_name(&spec.driver_object_path).is_some() {
        return STATUS_IMAGE_ALREADY_LOADED_LOCAL;
    }
    let _reservation = match DriverTransitionReservation::acquire(&spec.driver_object_path) {
        Ok(reservation) => reservation,
        Err(status) => return status,
    };
    let Some(fs) = crate::exec_fs() else {
        return STATUS_OBJECT_NAME_NOT_FOUND_LOCAL;
    };
    // Hold the continuation row before DriverEntry can be entered (#420).
    let slot = match crate::driver_launch::reserve_service_slot() {
        Ok(slot) => slot,
        Err(status) => return status,
    };
    let system_caller = crate::initial_system_driver_caller();
    let outcome = begin_load_driver(
        &fs,
        &spec.image_path,
        spec.class,
        &spec.driver_object_path,
        system_caller,
    );
    let source = SourceCall {
        channel: *channel, instance_index: call.instance_index, route: call.route,
        dispatch: call.dispatch, reply_cap,
    };
    let pending = match outcome {
        DriverLoad::Done(outcome) => return finish_load(source, &spec.driver_object_path, outcome),
        DriverLoad::Kept(pending) => pending,
    };
    // DriverEntry (or a reinitialization callback) is still running: this lane stays parked,
    // and the load's own finish replies with its true status. The reservation stays held.
    let step = PendingZwLoad {
        rest: pending.rest, source, driver_object_path: spec.driver_object_path,
        _reservation,
    };
    match pending.kept.register(slot, crate::driver_launch::ServiceStep::ZwLoadDriver(step)) {
        // The reply this returns is intercepted and never sent.
        Ok(()) => nt_status::NtStatus::PENDING.raw(),
        Err((uncertain, step)) => step.complete(uncertain).words[0] as u32 as i32,
    }
}

/// The calling lane's exact parked dispatch, checked again before the load's status is
/// published. A nested DriverEntry may run another provider pump.
#[derive(Clone, Copy)]
struct SourceCall {
    channel: crate::spawn_hosts::PumpChannel,
    instance_index: usize,
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply_cap: u64,
}

unsafe fn finish_load(
    source: SourceCall, driver_object_path: &str,
    outcome: Result<DriverComponent, nt_status::NtStatus>,
) -> i32 {
    if !source_reply_unchanged(&source.channel, source.instance_index, source.route,
        source.dispatch, source.reply_cap)
    {
        panic!("ZwLoadDriver source Reply or dispatch changed during nested launch");
    }
    match outcome {
        Ok(loaded) if driver_id_by_name(driver_object_path) == Some(loaded.driver_id) => 0,
        Ok(_) => panic!("ZwLoadDriver succeeded without publishing exact driver identity"),
        Err(status) => status.raw(),
    }
}

/// The rest of a `ZwLoadDriver` whose DriverEntry or reinitialization had not finished (#420).
pub(crate) struct PendingZwLoad {
    rest: PendingLoadRest,
    source: SourceCall,
    driver_object_path: alloc::string::String,
    _reservation: DriverTransitionReservation,
}

/// A load step's next act after its kept pump returned.
pub(crate) enum ZwLoadRun {
    Reply(i32),
    /// Another pump of the same load stopped unfinished; it continues the same parked lane.
    Kept(crate::driver_launch::component_scheduler::service_continuation::KeptPump, PendingZwLoad),
}

impl PendingZwLoad {
    pub(crate) unsafe fn complete(self, pr: crate::spawn_hosts::PumpResult) -> ZwLoadRun {
        let _durable = crate::allocator::enter_durable();
        let Self { rest, source, driver_object_path, _reservation } = self;
        match rest.finish(pr) {
            DriverLoad::Done(outcome) =>
                ZwLoadRun::Reply(finish_load(source, &driver_object_path, outcome)),
            DriverLoad::Kept(pending) => ZwLoadRun::Kept(pending.kept, Self {
                rest: pending.rest, source, driver_object_path, _reservation,
            }),
        }
    }
}

pub(super) unsafe fn service_unload(
    channel: &crate::spawn_hosts::PumpChannel,
    service_name: u64,
    badge: u64,
    reply_cap: u64,
) -> i32 {
    let _durable = crate::allocator::enter_durable();
    let call = match capture_driver_call(channel, service_name, badge, reply_cap) {
        Ok(call) => call,
        Err(status) => return status,
    };
    // Hold the continuation row before DriverUnload can be entered (#420).
    let slot = match crate::driver_launch::reserve_service_slot() {
        Ok(slot) => slot,
        Err(status) => return status,
    };
    let selected = crate::live_config_driver_service_launch_spec_from_registry_path(
        &call.path,
        nt_config_manager::SERVICE_DEMAND_START,
    );
    if !source_reply_unchanged(channel, call.instance_index, call.route, call.dispatch, reply_cap) {
        panic!("ZwUnloadDriver source Reply or dispatch changed during CM lookup");
    }
    let spec = match selected {
        Ok(spec) => spec,
        Err(status) => return status,
    };
    let Some(target_driver_id) = driver_id_by_name(&spec.driver_object_path) else {
        return STATUS_OBJECT_NAME_NOT_FOUND_LOCAL;
    };
    if instance_by_driver_id(target_driver_id).is_some_and(|(index, _)| index == call.instance_index) {
        return nt_status::NtStatus::DEVICE_BUSY.raw();
    }
    let _reservation = match DriverTransitionReservation::acquire(&spec.driver_object_path) {
        Ok(reservation) => reservation,
        Err(status) => return status,
    };
    let outcome = begin_driver_unload(&spec.driver_object_path);
    if !source_reply_unchanged(channel, call.instance_index, call.route, call.dispatch, reply_cap) {
        panic!("ZwUnloadDriver source Reply or dispatch changed during nested unload");
    }
    let pending = match outcome {
        DriverUnload::Done(Ok(())) => return 0,
        DriverUnload::Done(Err(status)) => return status.raw(),
        DriverUnload::Kept(pending) => pending,
    };
    // DriverUnload is still running: this lane stays parked, and the stop's finish replies
    // with the true status. The reservation stays held until then.
    let step = PendingZwUnload { finish: pending.finish, _reservation: _reservation };
    match pending.kept.register(slot, crate::driver_launch::ServiceStep::ZwUnloadDriver(step)) {
        // The reply this returns is intercepted and never sent.
        Ok(()) => nt_status::NtStatus::PENDING.raw(),
        Err((uncertain, step)) => step.complete(uncertain).words[0] as u32 as i32,
    }
}

/// The rest of a `ZwUnloadDriver` whose `DriverUnload` had not finished (#420).
pub(crate) struct PendingZwUnload {
    finish: DriverUnloadFinish,
    _reservation: DriverTransitionReservation,
}

impl PendingZwUnload {
    /// The stop's true status once `DriverUnload` has returned. The reservation drops here.
    pub(crate) unsafe fn finish(self, pr: crate::spawn_hosts::PumpResult) -> i32 {
        let _durable = crate::allocator::enter_durable();
        match self.finish.after_callback(pr) {
            Ok(()) => 0,
            Err(status) => status.raw(),
        }
    }
}
