//! Hosted file-system registration queues and their device lifetime anchors.

use crate::{
    DeviceFlags, DeviceId, DeviceReference, DeviceType, HostedDevicePointerRegistration,
    HostedDomainIdentity, IoManager,
};
use alloc::vec::Vec;
use nt_status::NtStatus;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileSystemClass {
    Disk,
    Network,
    CdRom,
    Tape,
    Other,
}

impl FileSystemClass {
    fn for_device_type(device_type: DeviceType) -> Self {
        match device_type {
            DeviceType::DISK_FILE_SYSTEM => Self::Disk,
            DeviceType::NETWORK_FILE_SYSTEM => Self::Network,
            DeviceType::CD_ROM_FILE_SYSTEM => Self::CdRom,
            DeviceType::TAPE_FILE_SYSTEM => Self::Tape,
            _ => Self::Other,
        }
    }
}

struct Registration {
    pointer: HostedDevicePointerRegistration,
    reference: DeviceReference,
    class: FileSystemClass,
    low_priority: bool,
}

#[derive(Default)]
pub(crate) struct HostedFileSystemRegistry {
    rows: Vec<Registration>,
    operations: u64,
}

impl HostedFileSystemRegistry {
    pub(crate) fn retains_registration(&self, pointer: HostedDevicePointerRegistration) -> bool {
        self.rows.iter().any(|row| row.pointer == pointer)
    }
    pub(crate) fn retains_domain(&self, domain: HostedDomainIdentity) -> bool {
        self.rows.iter().any(|row| row.pointer.domain() == domain)
    }
}

impl<P> IoManager<P> {
    /// Register a projected file system. The exact pointer registration is authority, while an
    /// independent canonical reference protects the device until explicit unregister. A driver's
    /// current low-priority flag is captured because it may be set after `IoCreateDevice`.
    pub fn register_hosted_file_system(
        &mut self,
        domain: HostedDomainIdentity,
        address: u64,
        low_priority: bool,
    ) -> Result<(), NtStatus> {
        let pointer = self
            .hosted_device_pointer_registration(domain, address)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if self
            .hosted_file_systems
            .rows
            .iter()
            .any(|row| row.pointer.device_id() == pointer.device_id())
        {
            return Err(NtStatus::OBJECT_NAME_COLLISION);
        }
        let class = FileSystemClass::for_device_type(
            self.device(pointer.device_id())
                .ok_or(NtStatus::INVALID_PARAMETER)?
                .device_type,
        );
        let next_operations = self
            .hosted_file_systems
            .operations
            .checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        self.hosted_file_systems
            .rows
            .try_reserve(1)
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        let reference = self.retain_device_reference(pointer.device_id())?;
        let index = if low_priority {
            self.hosted_file_systems
                .rows
                .iter()
                .rposition(|row| row.class == class)
                .map_or(self.hosted_file_systems.rows.len(), |index| index + 1)
        } else {
            self.hosted_file_systems
                .rows
                .iter()
                .position(|row| row.class == class)
                .unwrap_or(self.hosted_file_systems.rows.len())
        };
        self.hosted_file_systems.rows.insert(
            index,
            Registration {
                pointer,
                reference,
                class,
                low_priority,
            },
        );
        let device = self
            .device_mut(pointer.device_id())
            .expect("referenced file system device disappeared");
        device.flags.remove(DeviceFlags::DEVICE_INITIALIZING);
        device
            .flags
            .set(DeviceFlags::LOW_PRIORITY_FILESYSTEM, low_priority);
        self.hosted_file_systems.operations = next_operations;
        Ok(())
    }

    /// Remove only the exact registration made by this domain and pointer generation. Failure
    /// leaves the registration and its device reference intact.
    pub fn unregister_hosted_file_system(
        &mut self,
        domain: HostedDomainIdentity,
        address: u64,
    ) -> Result<(), NtStatus> {
        let pointer = self
            .hosted_device_pointer_registration(domain, address)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let index = self
            .hosted_file_systems
            .rows
            .iter()
            .position(|row| row.pointer == pointer)
            .ok_or(NtStatus::INVALID_DEVICE_REQUEST)?;
        let next_operations = self
            .hosted_file_systems
            .operations
            .checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        let mut registration = self.hosted_file_systems.rows.remove(index);
        if let Err(status) = self.release_device_reference(&mut registration.reference) {
            self.hosted_file_systems.rows.insert(index, registration);
            return Err(status);
        }
        self.hosted_file_systems.operations = next_operations;
        Ok(())
    }

    pub fn registered_file_systems(
        &self,
        class: FileSystemClass,
    ) -> impl Iterator<Item = (DeviceId, bool)> + '_ {
        self.hosted_file_systems
            .rows
            .iter()
            .filter(move |row| row.class == class)
            .map(|row| (row.pointer.device_id(), row.low_priority))
    }

    pub fn file_system_registration_operations(&self) -> u64 {
        self.hosted_file_systems.operations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeviceCharacteristics, DeviceRecord, DriverBackendId, DriverId, DriverRecord,
        MajorFunctionTable, MockObjectPort,
    };
    use nt_types::{NtPath, ObjectId};

    fn setup() -> (IoManager<MockObjectPort>, DriverId, HostedDomainIdentity) {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.register_driver(DriverRecord::new(
            ObjectId::NULL,
            NtPath::parse_str("\\Driver\\FsRegistry").unwrap(),
            DriverBackendId(1),
            MajorFunctionTable::new(),
        ));
        let domain = io.register_hosted_domain();
        (io, driver, domain)
    }

    fn device(
        io: &mut IoManager<MockObjectPort>,
        driver: DriverId,
        domain: HostedDomainIdentity,
        address: u64,
        device_type: DeviceType,
    ) -> DeviceId {
        let device = io.add_device(DeviceRecord::new(
            ObjectId::NULL,
            driver,
            None,
            device_type,
            DeviceCharacteristics::empty(),
            DeviceFlags::DEVICE_INITIALIZING,
            0,
        ));
        io.bind_hosted_device_pointer(domain, address, device)
            .unwrap();
        device
    }

    #[test]
    fn register_orders_by_priority_and_releases_exact_lifetime() {
        let (mut io, driver, domain) = setup();
        let low = device(
            &mut io,
            driver,
            domain,
            0x1000,
            DeviceType::DISK_FILE_SYSTEM,
        );
        let normal = device(
            &mut io,
            driver,
            domain,
            0x2000,
            DeviceType::DISK_FILE_SYSTEM,
        );
        let cd = device(
            &mut io,
            driver,
            domain,
            0x3000,
            DeviceType::CD_ROM_FILE_SYSTEM,
        );
        assert_eq!(io.device_reference_count(low), 1);
        io.register_hosted_file_system(domain, 0x1000, true)
            .unwrap();
        io.register_hosted_file_system(domain, 0x2000, false)
            .unwrap();
        io.register_hosted_file_system(domain, 0x3000, false)
            .unwrap();
        assert_eq!(
            io.registered_file_systems(FileSystemClass::Disk)
                .collect::<Vec<_>>(),
            [(normal, false), (low, true)]
        );
        assert_eq!(
            io.registered_file_systems(FileSystemClass::CdRom)
                .collect::<Vec<_>>(),
            [(cd, false)]
        );
        assert_eq!(io.device_reference_count(low), 2);
        assert!(!io
            .device(low)
            .unwrap()
            .flags
            .contains(DeviceFlags::DEVICE_INITIALIZING));
        assert_eq!(io.file_system_registration_operations(), 3);
        let registration = io
            .hosted_device_pointer_registration(domain, 0x1000)
            .unwrap();
        assert_eq!(
            io.retire_hosted_device_pointer(registration),
            Err(NtStatus::DEVICE_BUSY)
        );
        io.unregister_hosted_file_system(domain, 0x1000).unwrap();
        assert_eq!(io.device_reference_count(low), 1);
        assert_eq!(io.file_system_registration_operations(), 4);
        io.retire_hosted_device_pointer(registration).unwrap();
    }

    #[test]
    fn duplicate_or_foreign_unregistration_preserves_reference() {
        let (mut io, driver, domain) = setup();
        let fs = device(
            &mut io,
            driver,
            domain,
            0x1000,
            DeviceType::NETWORK_FILE_SYSTEM,
        );
        let foreign = io.register_hosted_domain();
        io.bind_hosted_device_pointer(foreign, 0x2000, fs).unwrap();
        io.register_hosted_file_system(domain, 0x1000, false)
            .unwrap();
        assert_eq!(
            io.register_hosted_file_system(foreign, 0x2000, false),
            Err(NtStatus::OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            io.unregister_hosted_file_system(foreign, 0x2000),
            Err(NtStatus::INVALID_DEVICE_REQUEST)
        );
        assert_eq!(io.device_reference_count(fs), 3);
        assert_eq!(io.file_system_registration_operations(), 1);
        io.unregister_hosted_file_system(domain, 0x1000).unwrap();
        assert_eq!(io.device_reference_count(fs), 2);
    }
}
