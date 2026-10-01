//! Canonical half of `IoAttachDeviceToDeviceStackSafe` for hosted drivers.

use crate::{DeviceFlags, HostedDomainIdentity, IoManager};
use nt_status::NtStatus;

const STATUS_NO_SUCH_DEVICE: NtStatus = NtStatus(0xC000_000Eu32 as i32);

impl<P> IoManager<P> {
    /// Native broker variant: compare the caller's observed lower projection before mutation.
    /// This prevents an obsolete local attachment walk from committing a different canonical
    /// edge after another stack change.
    pub fn attach_hosted_device_to_stack_safe_checked(
        &mut self,
        domain: HostedDomainIdentity,
        source_address: u64,
        target_address: u64,
        expected_lower_address: u64,
    ) -> Result<u64, NtStatus> {
        let target = self
            .hosted_device_pointer_registration(domain, target_address)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let current_top = self
            .top_of_device_stack(target.device_id())
            .map_err(attach_status)?;
        let lower = self
            .hosted_device_pointer_registration(domain, expected_lower_address)
            .ok_or(NtStatus::INVALID_DEVICE_REQUEST)?;
        if lower.device_id() != current_top {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        self.attach_hosted_device_to_stack_safe(domain, source_address, target_address)
    }

    /// Attach `source` above the current top of `target` and return the exact lower projection in
    /// their caller domain. The attachment edge, not a new caller object reference, protects the
    /// lower device until `IoDetachDevice` removes that edge.
    ///
    /// All pointer and topology checks precede mutation under one exclusive I/O Manager borrow.
    /// An upper device in a foreign domain must have an admitted projection in this domain; its
    /// foreign pointer is never returned as a substitute.
    pub fn attach_hosted_device_to_stack_safe(
        &mut self,
        domain: HostedDomainIdentity,
        source_address: u64,
        target_address: u64,
    ) -> Result<u64, NtStatus> {
        let source = self
            .hosted_device_pointer_registration(domain, source_address)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let target = self
            .hosted_device_pointer_registration(domain, target_address)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let expected_lower_id = self
            .top_of_device_stack(target.device_id())
            .map_err(attach_status)?;
        if self
            .device(expected_lower_id)
            .is_some_and(|device| device.flags.contains(DeviceFlags::DEVICE_INITIALIZING))
        {
            return Err(STATUS_NO_SUCH_DEVICE);
        }
        let expected_lower_address = self
            .hosted_device_address_by_identity(domain, expected_lower_id)
            .ok_or(NtStatus::INVALID_DEVICE_REQUEST)?;
        let expected_lower = self
            .hosted_device_pointer_registration(domain, expected_lower_address)
            .filter(|registration| registration.device_id() == expected_lower_id)
            .ok_or(NtStatus::INVALID_DEVICE_REQUEST)?;
        let lower = self
            .attach_device_to_stack(source.device_id(), target.device_id())
            .map_err(attach_status)?;
        // Both selection operations are guarded by the same exclusive borrow. If this ever
        // diverges, the canonical transaction has violated its own topology contract.
        assert_eq!(lower, expected_lower.device_id());
        Ok(expected_lower.address())
    }

    /// Undo an attachment whose lower pointer could not be published to the caller. This checks
    /// the exact edge before mutation so a later attachment cannot be removed accidentally.
    pub fn rollback_hosted_safe_attach(
        &mut self,
        domain: HostedDomainIdentity,
        source_address: u64,
        lower_address: u64,
    ) -> Result<(), NtStatus> {
        let source = self
            .hosted_device_pointer_registration(domain, source_address)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let lower = self
            .hosted_device_pointer_registration(domain, lower_address)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let current_lower = self
            .device(source.device_id())
            .and_then(|device| device.attached_to)
            .ok_or(NtStatus::INVALID_DEVICE_REQUEST)?;
        if current_lower != lower.device_id() {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        let detached = self.detach_device_from_stack(source.device_id())?;
        assert_eq!(detached, lower.device_id());
        Ok(())
    }
}

fn attach_status(status: NtStatus) -> NtStatus {
    if status == NtStatus::DELETE_PENDING {
        STATUS_NO_SUCH_DEVICE
    } else {
        status
    }
}

#[cfg(test)]
mod tests {
    use super::STATUS_NO_SUCH_DEVICE;
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
    fn returns_current_lower_without_creating_caller_reference() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.register_driver(DriverRecord::new(
            ObjectId::NULL,
            NtPath::parse_str("\\Driver\\SafeAttach").unwrap(),
            DriverBackendId(1),
            MajorFunctionTable::new(),
        ));
        let pdo = add_device(&mut io, driver);
        let first = add_device(&mut io, driver);
        let second = add_device(&mut io, driver);
        let domain = io.register_hosted_domain();
        let pdo_ptr = io.bind_hosted_device_pointer(domain, 0x1000, pdo).unwrap();
        let first_ptr = io
            .bind_hosted_device_pointer(domain, 0x2000, first)
            .unwrap();
        io.bind_hosted_device_pointer(domain, 0x3000, second)
            .unwrap();

        assert_eq!(
            io.attach_hosted_device_to_stack_safe(domain, 0x2000, 0x1000),
            Ok(0x1000)
        );
        assert_eq!(io.device_reference_count(pdo), 1);
        assert_eq!(io.hosted_device_pointer_count(pdo_ptr), Ok(0));
        assert_eq!(
            io.attach_hosted_device_to_stack_safe(domain, 0x3000, 0x1000),
            Ok(0x2000)
        );
        assert_eq!(io.hosted_device_pointer_count(first_ptr), Ok(0));
        assert_eq!(io.top_of_device_stack(pdo), Ok(second));
        assert_eq!(
            io.destroy_device(first).err(),
            Some(NtStatus::DELETE_PENDING)
        );
    }

    #[test]
    fn foreign_top_projection_rejects_before_attaching() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.register_driver(DriverRecord::new(
            ObjectId::NULL,
            NtPath::parse_str("\\Driver\\SafeAttachForeign").unwrap(),
            DriverBackendId(1),
            MajorFunctionTable::new(),
        ));
        let pdo = add_device(&mut io, driver);
        let foreign_top = add_device(&mut io, driver);
        let source = add_device(&mut io, driver);
        let caller = io.register_hosted_domain();
        let foreign = io.register_hosted_domain();
        io.bind_hosted_device_pointer(caller, 0x1000, pdo).unwrap();
        io.bind_hosted_device_pointer(caller, 0x3000, source)
            .unwrap();
        io.bind_hosted_device_pointer(foreign, 0x2000, foreign_top)
            .unwrap();
        io.attach_device_to_stack(foreign_top, pdo).unwrap();

        assert_eq!(
            io.attach_hosted_device_to_stack_safe(caller, 0x3000, 0x1000),
            Err(NtStatus::INVALID_DEVICE_REQUEST)
        );
        assert_eq!(io.device(source).unwrap().attached_to, None);
        io.bind_hosted_device_pointer(caller, 0x4000, foreign_top)
            .unwrap();
        assert_eq!(
            io.attach_hosted_device_to_stack_safe(caller, 0x3000, 0x1000),
            Ok(0x4000)
        );
        assert_eq!(io.device(source).unwrap().attached_to, Some(foreign_top));
    }

    #[test]
    fn checked_lower_rejects_stale_local_walk_before_mutation() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.register_driver(DriverRecord::new(
            ObjectId::NULL,
            NtPath::parse_str("\\Driver\\SafeAttachChecked").unwrap(),
            DriverBackendId(1),
            MajorFunctionTable::new(),
        ));
        let pdo = add_device(&mut io, driver);
        let upper = add_device(&mut io, driver);
        let source = add_device(&mut io, driver);
        let domain = io.register_hosted_domain();
        io.bind_hosted_device_pointer(domain, 0x1000, pdo).unwrap();
        io.bind_hosted_device_pointer(domain, 0x2000, upper)
            .unwrap();
        io.bind_hosted_device_pointer(domain, 0x3000, source)
            .unwrap();
        io.attach_device_to_stack(upper, pdo).unwrap();

        assert_eq!(
            io.attach_hosted_device_to_stack_safe_checked(domain, 0x3000, 0x1000, 0x1000),
            Err(NtStatus::INVALID_DEVICE_REQUEST)
        );
        assert_eq!(io.device(source).unwrap().attached_to, None);
        assert_eq!(
            io.attach_hosted_device_to_stack_safe_checked(domain, 0x3000, 0x1000, 0x2000),
            Ok(0x2000)
        );
    }

    #[test]
    fn publication_rollback_only_detaches_original_edge() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.register_driver(DriverRecord::new(
            ObjectId::NULL,
            NtPath::parse_str("\\Driver\\SafeAttachRollback").unwrap(),
            DriverBackendId(1),
            MajorFunctionTable::new(),
        ));
        let pdo = add_device(&mut io, driver);
        let source = add_device(&mut io, driver);
        let domain = io.register_hosted_domain();
        io.bind_hosted_device_pointer(domain, 0x1000, pdo).unwrap();
        io.bind_hosted_device_pointer(domain, 0x2000, source)
            .unwrap();

        assert_eq!(
            io.attach_hosted_device_to_stack_safe(domain, 0x2000, 0x1000),
            Ok(0x1000)
        );
        assert_eq!(
            io.rollback_hosted_safe_attach(domain, 0x2000, 0x2000),
            Err(NtStatus::INVALID_DEVICE_REQUEST)
        );
        assert_eq!(io.device(source).unwrap().attached_to, Some(pdo));
        assert_eq!(
            io.rollback_hosted_safe_attach(domain, 0x2000, 0x1000),
            Ok(())
        );
        assert_eq!(io.device(source).unwrap().attached_to, None);
    }

    #[test]
    fn initializing_top_rejects_without_mutation() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.register_driver(DriverRecord::new(
            ObjectId::NULL,
            NtPath::parse_str("\\Driver\\SafeAttachInitializing").unwrap(),
            DriverBackendId(1),
            MajorFunctionTable::new(),
        ));
        let pdo = add_device(&mut io, driver);
        let source = add_device(&mut io, driver);
        io.device_mut(pdo)
            .unwrap()
            .flags
            .insert(DeviceFlags::DEVICE_INITIALIZING);
        let domain = io.register_hosted_domain();
        io.bind_hosted_device_pointer(domain, 0x1000, pdo).unwrap();
        io.bind_hosted_device_pointer(domain, 0x2000, source)
            .unwrap();

        assert_eq!(
            io.attach_hosted_device_to_stack_safe(domain, 0x2000, 0x1000),
            Err(STATUS_NO_SUCH_DEVICE)
        );
        assert_eq!(io.device(source).unwrap().attached_to, None);
    }
}
