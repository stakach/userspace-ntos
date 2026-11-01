//! Exact canonical admission for an upper filter's post-AddDevice device type.
//!
//! This check is separate from physical `DEVICE_OBJECT` validation. The native
//! adapter must finish its immutable-pointer checks before committing a type.

use crate::{DeviceType, HostedDevicePointerRegistration, IoManager};
use nt_status::NtStatus;

impl<P> IoManager<P> {
    /// Check the reported type of an attached upper FDO against its exact live
    /// class-domain projections and canonical stack. This first contract keeps
    /// the preexisting strict type match; admitting lower-type inheritance is a
    /// separate behavior change requiring a live regression.
    pub fn admitted_hosted_upper_filter_device_type(
        &self,
        source: HostedDevicePointerRegistration,
        pdo: HostedDevicePointerRegistration,
        lower: HostedDevicePointerRegistration,
        observed: DeviceType,
    ) -> Result<DeviceType, NtStatus> {
        let domain = source.domain();
        if domain != pdo.domain() || domain != lower.domain()
            || self.hosted_domain_identity(domain.domain_id) != Some(domain)
            || [source, pdo, lower].into_iter().any(|registration| {
                self.hosted_device_pointer_registration(domain, registration.address())
                    != Some(registration)
            })
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let source_device = self.device(source.device_id()).ok_or(NtStatus::INVALID_PARAMETER)?;
        let pdo_device = self.device(pdo.device_id()).ok_or(NtStatus::INVALID_PARAMETER)?;
        let lower_device = self.device(lower.device_id()).ok_or(NtStatus::INVALID_PARAMETER)?;
        if source_device.delete_pending || pdo_device.delete_pending || lower_device.delete_pending
            || pdo_device.attached_to.is_some()
            || source_device.attached_to != Some(lower.device_id())
            || self.top_of_device_stack(pdo.device_id()) != Ok(source.device_id())
            || self.hosted_driver_address_by_identity(domain, source_device.driver_id).is_none()
            || observed != source_device.device_type
        {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        Ok(observed)
    }
}
