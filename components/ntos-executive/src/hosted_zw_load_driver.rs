//! Kernel-mode ZwLoadDriver from a hosted driver into the live CM and driver loader.

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

static mut ACTIVE_LAUNCHES: Vec<alloc::string::String> = Vec::new();

struct LaunchReservation {
    path: alloc::string::String,
}

fn source_reply_unchanged(
    channel: &crate::spawn_hosts::PumpChannel,
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply_cap: u64,
) -> bool {
    unsafe {
        runtime::dispatch(route).ok() == Some(dispatch)
            && runtime::current_reply(route).ok() == Some(reply_cap)
            && instance_for_pump_channel(channel, reply_cap).is_some()
    }
}

impl LaunchReservation {
    unsafe fn acquire(path: &str) -> Result<Self, i32> {
        let active = &mut *core::ptr::addr_of_mut!(ACTIVE_LAUNCHES);
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

impl Drop for LaunchReservation {
    fn drop(&mut self) {
        unsafe {
            let active = &mut *core::ptr::addr_of_mut!(ACTIVE_LAUNCHES);
            let index = active
                .iter()
                .position(|existing| existing.eq_ignore_ascii_case(&self.path))
                .expect("hosted ZwLoadDriver reservation disappeared");
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
    let Some((instance_index, inst)) = instance_for_pump_channel(channel, reply_cap) else {
        return STATUS_INVALID_HANDLE_LOCAL;
    };
    let Some(caller) = hosted_driver_caller(instance_index, inst, badge) else {
        return STATUS_INVALID_HANDLE_LOCAL;
    };
    if caller.route.endpoint() != channel.fault_ep
        || caller.runtime.map_or(inst.tcb, |worker| worker.tcb) != channel.tcb
    {
        return STATUS_INVALID_HANDLE_LOCAL;
    }
    let route = caller.route;
    let Ok(dispatch) = runtime::dispatch(route) else {
        return STATUS_INVALID_HANDLE_LOCAL;
    };
    if runtime::current_reply(route).ok() != Some(reply_cap) {
        return STATUS_INVALID_HANDLE_LOCAL;
    }
    let path = match nt_config_client::capture_driver_service_name(service_name, |va, output| {
        let Some(exec_va) =
            hosted_driver_component_object_exec_va(instance_index, inst, va, output.len() as u64)
        else {
            return false;
        };
        unsafe {
            core::ptr::copy_nonoverlapping(exec_va as *const u8, output.as_mut_ptr(), output.len());
        }
        true
    }) {
        Ok(path) => path,
        Err(status) => return status,
    };
    let selected = crate::live_config_driver_service_launch_spec_from_registry_path(
        &path,
        nt_config_manager::SERVICE_DEMAND_START,
    );
    if !source_reply_unchanged(channel, route, dispatch, reply_cap) {
        panic!("ZwLoadDriver source Reply or dispatch changed during CM lookup");
    }
    let spec = match selected {
        Ok(spec) => spec,
        Err(status) => return status,
    };
    if driver_id_by_name(&spec.driver_object_path).is_some() {
        return STATUS_IMAGE_ALREADY_LOADED_LOCAL;
    }
    let _reservation = match LaunchReservation::acquire(&spec.driver_object_path) {
        Ok(reservation) => reservation,
        Err(status) => return status,
    };
    let Some(fs) = crate::exec_fs() else {
        return STATUS_OBJECT_NAME_NOT_FOUND_LOCAL;
    };
    let system_caller = crate::initial_system_driver_caller();
    let outcome = load_driver(
        &fs,
        &spec.image_path,
        spec.class,
        &spec.driver_object_path,
        system_caller,
    );
    // A nested DriverEntry may run another provider pump. The original caller must still own the
    // exact parked dispatch and Reply before we publish the terminal result.
    if !source_reply_unchanged(channel, route, dispatch, reply_cap) {
        panic!("ZwLoadDriver source Reply or dispatch changed during nested launch");
    }
    match outcome {
        Ok(loaded) if driver_id_by_name(&spec.driver_object_path) == Some(loaded.driver_id) => 0,
        Ok(_) => panic!("ZwLoadDriver succeeded without publishing exact driver identity"),
        Err(status) => status.raw(),
    }
}
