//! Admit a provider's completed PDO to a bus relation.

use crate::{DeviceFlags, HostedDomainIdentity, IoManager};
use nt_io_abi::{DeviceId, DriverId};
use nt_status::NtStatus;

impl<P> IoManager<P> {
    /// The native broker has already validated and synchronized the exact provider allocation.
    /// The relation may publish it only after the provider clears DO_DEVICE_INITIALIZING.
    pub fn validate_hosted_bus_pdo_publication(
        &self,
        domain: HostedDomainIdentity,
        address: u64,
        device_id: DeviceId,
        driver_id: DriverId,
    ) -> Result<(), NtStatus> {
        let registration = self
            .hosted_device_pointer_registration(domain, address)
            .ok_or(NtStatus::INVALID_DEVICE_REQUEST)?;
        if registration.device_id() != device_id
            || self.hosted_driver_address_by_identity(domain, driver_id).is_none()
        {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        let device = self
            .device(device_id)
            .ok_or(NtStatus::INVALID_DEVICE_REQUEST)?;
        if device.driver_id != driver_id
            || device.delete_pending
            || device.top_of_stack != device_id
            || device.flags.contains(DeviceFlags::DEVICE_INITIALIZING)
        {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceCharacteristics, DeviceType, DriverBackendId, DriverRecord, MajorFunctionTable};
    use nt_types::{NtPath, ObjectId};

    #[test]
    fn bus_pdo_requires_exact_live_provider_and_completed_native_initialization() {
        let mut io = IoManager::new(crate::MockObjectPort::new());
        let provider = io.register_driver(DriverRecord::new(
            ObjectId::NULL,
            NtPath::parse_str("\\Driver\\AcpiProvider").unwrap(),
            DriverBackendId(1),
            MajorFunctionTable::new(),
        ));
        let other = io.register_driver(DriverRecord::new(
            ObjectId::NULL,
            NtPath::parse_str("\\Driver\\OtherProvider").unwrap(),
            DriverBackendId(2),
            MajorFunctionTable::new(),
        ));
        let pdo = io.create_device(
            provider,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::DEVICE_INITIALIZING,
            0,
        ).unwrap();
        let domain = io.register_hosted_domain();
        io.bind_hosted_driver_identity(domain, 0x1000, provider).unwrap();
        io.bind_hosted_device_pointer(domain, 0x2000, pdo).unwrap();

        assert_eq!(
            io.validate_hosted_bus_pdo_publication(domain, 0x2000, pdo, provider),
            Err(NtStatus::INVALID_DEVICE_REQUEST),
        );
        io.device_mut(pdo).unwrap().flags.remove(DeviceFlags::DEVICE_INITIALIZING);
        assert_eq!(
            io.validate_hosted_bus_pdo_publication(domain, 0x3000, pdo, provider),
            Err(NtStatus::INVALID_DEVICE_REQUEST),
        );
        assert_eq!(
            io.validate_hosted_bus_pdo_publication(domain, 0x2000, pdo, other),
            Err(NtStatus::INVALID_DEVICE_REQUEST),
        );
        assert_eq!(
            io.validate_hosted_bus_pdo_publication(domain, 0x2000, pdo, provider),
            Ok(()),
        );
        io.device_mut(pdo).unwrap().delete_pending = true;
        assert_eq!(
            io.validate_hosted_bus_pdo_publication(domain, 0x2000, pdo, provider),
            Err(NtStatus::INVALID_DEVICE_REQUEST),
        );
    }
}
