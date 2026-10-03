//! Referenced top-of-stack lookup for an admitted hosted DEVICE_OBJECT.
//!
//! The I/O database lock in NT protects both the attachment walk and the object reference.
//! `IoManager`'s exclusive borrow provides the equivalent transaction for canonical records.

use crate::{HostedDomainIdentity, IoManager};
use nt_status::NtStatus;

impl<P> IoManager<P> {
    /// Resolve the live top of `device_object`'s stack and retain its exact projection in the
    /// caller's domain. The caller must release the returned pointer through
    /// `dereference_hosted_device_pointer`, including when the topology changes afterward.
    ///
    /// A foreign top without a projection in this domain cannot be returned: a raw address from
    /// the foreign driver would not denote a valid object in the caller's address space.
    pub fn reference_hosted_attached_device(
        &mut self,
        domain: HostedDomainIdentity,
        device_object: u64,
    ) -> Result<u64, NtStatus> {
        let input = self
            .hosted_device_pointer_registration(domain, device_object)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let top = self.top_of_device_stack(input.device_id())?;
        let top_address = self
            .hosted_device_address_by_identity(domain, top)
            .ok_or(NtStatus::INVALID_DEVICE_REQUEST)?;
        let top_registration = self
            .hosted_device_pointer_registration(domain, top_address)
            .filter(|registration| registration.device_id() == top)
            .ok_or(NtStatus::INVALID_DEVICE_REQUEST)?;
        self.reference_hosted_device_pointer(top_registration)?;
        Ok(top_address)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        DeviceCharacteristics, DeviceFlags, DeviceId, DeviceRecord, DeviceType, DriverBackendId,
        DriverId, DriverRecord, IoManager, MajorFunctionTable, MockObjectPort,
    };
    use nt_status::NtStatus;
    use nt_types::{NtPath, ObjectId};

    fn add_device(io: &mut IoManager<MockObjectPort>, driver: DriverId) -> DeviceId {
        io.add_device(DeviceRecord::new(
            ObjectId::NULL,
            driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::empty(),
            0,
        ))
    }

    #[test]
    fn selects_current_top_and_retains_exact_returned_projection() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.register_driver(DriverRecord::new(
            ObjectId::NULL,
            NtPath::parse_str("\\Driver\\AttachedReference").unwrap(),
            DriverBackendId(1),
            MajorFunctionTable::new(),
        ));
        let lower = add_device(&mut io, driver);
        let first = add_device(&mut io, driver);
        let second = add_device(&mut io, driver);
        let domain = io.register_hosted_domain();
        let lower_ptr = io.bind_hosted_device_pointer(domain, 0x1000, lower).unwrap();
        let first_ptr = io.bind_hosted_device_pointer(domain, 0x2000, first).unwrap();
        let second_ptr = io.bind_hosted_device_pointer(domain, 0x3000, second).unwrap();

        assert_eq!(io.reference_hosted_attached_device(domain, 0x1000), Ok(0x1000));
        assert_eq!(io.hosted_device_pointer_count(lower_ptr), Ok(1));
        io.dereference_hosted_device_pointer(lower_ptr).unwrap();

        io.attach_device_to_stack(first, lower).unwrap();
        assert_eq!(io.reference_hosted_attached_device(domain, 0x1000), Ok(0x2000));
        assert_eq!(io.hosted_device_pointer_count(first_ptr), Ok(1));
        io.attach_device_to_stack(second, lower).unwrap();
        assert_eq!(io.reference_hosted_attached_device(domain, 0x1000), Ok(0x3000));
        assert_eq!(io.hosted_device_pointer_count(second_ptr), Ok(1));

        io.detach_device_from_stack(second).unwrap();
        assert_eq!(io.reference_hosted_attached_device(domain, 0x1000), Ok(0x2000));
        assert_eq!(io.hosted_device_pointer_count(first_ptr), Ok(2));
        assert_eq!(io.retire_hosted_device_pointer(first_ptr), Err(NtStatus::DEVICE_BUSY));
        io.dereference_hosted_device_pointer(second_ptr).unwrap();
        io.dereference_hosted_device_pointer(first_ptr).unwrap();
        io.dereference_hosted_device_pointer(first_ptr).unwrap();
        assert_eq!(io.hosted_device_pointer_count(first_ptr), Ok(0));
        io.detach_device_from_stack(first).unwrap();
        io.retire_hosted_device_pointer(first_ptr).unwrap();
    }

    #[test]
    fn refuses_foreign_or_unregistered_top_without_retaining_anything() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.register_driver(DriverRecord::new(
            ObjectId::NULL,
            NtPath::parse_str("\\Driver\\AttachedForeign").unwrap(),
            DriverBackendId(1),
            MajorFunctionTable::new(),
        ));
        let lower = add_device(&mut io, driver);
        let upper = add_device(&mut io, driver);
        let caller = io.register_hosted_domain();
        let foreign = io.register_hosted_domain();
        let lower_ptr = io.bind_hosted_device_pointer(caller, 0x1000, lower).unwrap();
        let upper_ptr = io.bind_hosted_device_pointer(foreign, 0x2000, upper).unwrap();
        io.attach_device_to_stack(upper, lower).unwrap();

        assert_eq!(
            io.reference_hosted_attached_device(caller, 0x1000),
            Err(NtStatus::INVALID_DEVICE_REQUEST)
        );
        assert_eq!(io.hosted_device_pointer_count(lower_ptr), Ok(0));
        assert_eq!(io.hosted_device_pointer_count(upper_ptr), Ok(0));
        assert_eq!(
            io.reference_hosted_attached_device(foreign, 0x1000),
            Err(NtStatus::INVALID_PARAMETER)
        );

        let caller_upper = io.bind_hosted_device_pointer(caller, 0x3000, upper).unwrap();
        assert_eq!(io.reference_hosted_attached_device(caller, 0x1000), Ok(0x3000));
        assert_eq!(io.hosted_device_pointer_count(caller_upper), Ok(1));
        io.dereference_hosted_device_pointer(caller_upper).unwrap();
    }
}
