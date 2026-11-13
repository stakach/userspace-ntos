use nt_io_manager::{
    DeviceCharacteristics, DeviceFlags, DeviceRecord, DeviceType, DriverBackendId, DriverRecord,
    IoManager, MajorFunctionTable, MockObjectPort,
};
use nt_status::NtStatus;
use nt_types::{NtPath, ObjectId};

fn setup() -> (IoManager<MockObjectPort>, nt_io_manager::DeviceId, nt_io_manager::HostedDomainIdentity) {
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io.register_driver(DriverRecord::new(
        ObjectId::NULL,
        NtPath::parse_str("\\Driver\\ClassPnpObjectReference").unwrap(),
        DriverBackendId(1),
        MajorFunctionTable::new(),
    ));
    let device = io.add_device(DeviceRecord::new(
        ObjectId::NULL,
        driver,
        None,
        DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(),
        DeviceFlags::empty(),
        0,
    ));
    let domain = io.register_hosted_domain();
    (io, device, domain)
}

#[test]
fn reference_by_pointer_checks_exact_registration_type_and_lifetime_before_mutation() {
    const DEVICE_OBJECT_TYPE: u64 = 0x5000;
    let (mut io, device, domain) = setup();
    let registration = io.bind_hosted_device_pointer(domain, 0x1000, device).unwrap();
    let foreign = io.register_hosted_domain();
    let foreign_registration = io.bind_hosted_device_pointer(foreign, 0x2000, device).unwrap();

    assert_eq!(
        io.reference_hosted_device_object_by_pointer(domain, registration, None, DEVICE_OBJECT_TYPE),
        Ok(1)
    );
    assert_eq!(
        io.reference_hosted_device_object_by_pointer(
            domain,
            registration,
            Some(DEVICE_OBJECT_TYPE),
            DEVICE_OBJECT_TYPE,
        ),
        Ok(2)
    );
    assert_eq!(io.hosted_device_pointer_count(registration), Ok(2));
    assert_eq!(
        io.reference_hosted_device_object_by_pointer(domain, registration, Some(0x6000), DEVICE_OBJECT_TYPE),
        Err(NtStatus::OBJECT_TYPE_MISMATCH)
    );
    assert_eq!(io.hosted_device_pointer_count(registration), Ok(2));

    // The caller's authenticated domain must match the exact registration, including generation.
    assert_eq!(
        io.reference_hosted_device_object_by_pointer(
            domain,
            foreign_registration,
            None,
            DEVICE_OBJECT_TYPE,
        ),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(io.hosted_device_pointer_count(foreign_registration), Ok(0));

    io.dereference_hosted_device_pointer(registration).unwrap();
    io.dereference_hosted_device_pointer(registration).unwrap();
    io.retire_hosted_device_pointer(registration).unwrap();
    let replacement = io.bind_hosted_device_pointer(domain, 0x1000, device).unwrap();
    assert_ne!(registration.generation(), replacement.generation());
    assert_eq!(
        io.reference_hosted_device_object_by_pointer(
            domain,
            registration,
            None,
            DEVICE_OBJECT_TYPE,
        ),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(io.hosted_device_pointer_count(replacement), Ok(0));
}
