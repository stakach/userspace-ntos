//! Executive ownership boundary for the NT Power Manager.
//!
//! Device-stack discovery remains in `driver_launch`, but policy state lives here. This keeps one
//! component-neutral authority for per-devnode power and per-thread execution-state accounting.

static mut POWER_MANAGER: Option<nt_power_manager::PowerManager> = None;

unsafe fn manager_mut() -> &'static mut nt_power_manager::PowerManager {
    let slot = &mut *core::ptr::addr_of_mut!(POWER_MANAGER);
    if slot.is_none() {
        *slot = Some(nt_power_manager::PowerManager::new());
    }
    slot.as_mut().unwrap()
}

pub(crate) fn status(error: nt_power_manager::PowerError) -> nt_status::NtStatus {
    match error {
        nt_power_manager::PowerError::InsufficientResources => {
            nt_status::NtStatus::INSUFFICIENT_RESOURCES
        }
        nt_power_manager::PowerError::NotRegistered | nt_power_manager::PowerError::NotStarted => {
            nt_status::NtStatus::DEVICE_NOT_READY
        }
        nt_power_manager::PowerError::Removed => nt_status::NtStatus::DELETE_PENDING,
        nt_power_manager::PowerError::Busy => nt_status::NtStatus::DEVICE_BUSY,
        nt_power_manager::PowerError::InvalidState => nt_status::NtStatus::INVALID_PARAMETER,
    }
}

pub(crate) unsafe fn prepare_device(devnode_id: u64) -> Result<(), nt_status::NtStatus> {
    manager_mut().prepare_device(devnode_id).map_err(status)
}

pub(crate) unsafe fn complete_start(devnode_id: u64) -> Result<(), nt_status::NtStatus> {
    manager_mut().complete_start(devnode_id).map_err(status)
}

pub(crate) unsafe fn unregister_device(devnode_id: u64) {
    if let Some(manager) = (*core::ptr::addr_of_mut!(POWER_MANAGER)).as_mut() {
        manager.unregister_device(devnode_id);
    }
}

pub(crate) unsafe fn report_device_state(
    devnode_id: u64,
    state: nt_power_manager::DevicePowerState,
) -> Result<nt_power_manager::DevicePowerState, nt_status::NtStatus> {
    manager_mut()
        .report_device_state(devnode_id, state)
        .map_err(status)
}

pub(crate) unsafe fn report_system_state(
    devnode_id: u64,
    state: nt_power_manager::SystemPowerState,
) -> Result<nt_power_manager::SystemPowerState, nt_status::NtStatus> {
    manager_mut()
        .report_system_state(devnode_id, state)
        .map_err(status)
}

pub(crate) unsafe fn started_device_state(
    devnode_id: u64,
) -> Result<nt_power_manager::DevicePowerState, nt_status::NtStatus> {
    let manager = (*core::ptr::addr_of!(POWER_MANAGER))
        .as_ref()
        .ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    manager
        .started_device_state(devnode_id)
        .ok_or(nt_status::NtStatus::DEVICE_NOT_READY)
}

pub(crate) unsafe fn set_thread_execution_state(
    thread_id: u64,
    requested_flags: u32,
) -> Result<u32, nt_status::NtStatus> {
    manager_mut()
        .set_thread_execution_state(thread_id, requested_flags)
        .map_err(status)
}

pub(crate) unsafe fn remove_thread_execution_state(thread_id: u64) -> bool {
    (*core::ptr::addr_of_mut!(POWER_MANAGER))
        .as_mut()
        .is_some_and(|manager| manager.remove_thread_execution_state(thread_id))
}
