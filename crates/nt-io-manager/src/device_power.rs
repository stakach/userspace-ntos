//! DeviceObjectExtension power reports belong to the exact canonical device, not its stack.

use crate::{DeviceId, HostedDomainIdentity, IoManager};
use nt_status::NtStatus;
pub use nt_power_types::{DevicePowerState, SystemPowerState};

impl<P> IoManager<P> {
    /// A producer and an upper stack may independently hold projections of the same PDO.
    /// Only the exact live registration anchor, not a selected stack route, grants admission.
    pub fn hosted_power_report_target(
        &self, domain: HostedDomainIdentity, address: u64,
    ) -> Result<DeviceId, NtStatus> {
        let registration = self.hosted_device_pointer_registration(domain, address)
            .ok_or(NtStatus::ACCESS_DENIED)?;
        let id = registration.device_id();
        let device = self.device(id).ok_or(NtStatus::ACCESS_DENIED)?;
        if device.delete_pending { return Err(NtStatus::DELETE_PENDING); }
        Ok(id)
    }

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
