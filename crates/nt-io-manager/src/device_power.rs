//! DeviceObjectExtension power reports belong to the exact canonical device, not its stack.

use crate::{DeviceId, IoManager};
use nt_status::NtStatus;
pub use nt_power_types::{DevicePowerState, SystemPowerState};

impl<P> IoManager<P> {
    pub fn device_power_state(&self, id: DeviceId) -> Result<DevicePowerState, NtStatus> {
        let device = self.device(id).ok_or(NtStatus::INVALID_PARAMETER)?;
        if device.delete_pending { return Err(NtStatus::DELETE_PENDING); }
        Ok(device.device_power_state)
    }

    pub fn system_power_state(&self, id: DeviceId) -> Result<SystemPowerState, NtStatus> {
        let device = self.device(id).ok_or(NtStatus::INVALID_PARAMETER)?;
        if device.delete_pending { return Err(NtStatus::DELETE_PENDING); }
        Ok(device.system_power_state)
    }

    /// Store the requested state and return this object's previous state. No IRP is required.
    pub fn report_device_power_state(
        &mut self, id: DeviceId, state: DevicePowerState,
    ) -> Result<DevicePowerState, NtStatus> {
        if state == DevicePowerState::Maximum { return Err(NtStatus::INVALID_PARAMETER); }
        let device = self.device_mut(id).ok_or(NtStatus::INVALID_PARAMETER)?;
        if device.delete_pending { return Err(NtStatus::DELETE_PENDING); }
        Ok(core::mem::replace(&mut device.device_power_state, state))
    }

    pub fn report_system_power_state(
        &mut self, id: DeviceId, state: SystemPowerState,
    ) -> Result<SystemPowerState, NtStatus> {
        if state == SystemPowerState::Maximum { return Err(NtStatus::INVALID_PARAMETER); }
        let device = self.device_mut(id).ok_or(NtStatus::INVALID_PARAMETER)?;
        if device.delete_pending { return Err(NtStatus::DELETE_PENDING); }
        Ok(core::mem::replace(&mut device.system_power_state, state))
    }
}
