use super::*;
use crate::{
    DeviceCharacteristics, DeviceFlags, DeviceRecord, DeviceType, DriverBackendId, DriverRecord,
    IoManager, MajorFunctionTable, MockObjectPort,
};
use nt_types::{NtPath, ObjectId};

fn fixture() -> (IoManager<MockObjectPort>, HostedProviderChildRouteEvidence) {
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io.register_driver(DriverRecord::new(
        ObjectId::NULL,
        NtPath::parse_str("\\Driver\\Miniport").unwrap(),
        DriverBackendId(7),
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
    let dependent_domain = io.register_hosted_domain();
    let provider_domain = io.register_hosted_domain();
    let provider_driver_object = 0x8000;
    io.bind_hosted_driver_identity(provider_domain, provider_driver_object, driver)
        .unwrap();
    let registration = io
        .bind_hosted_device_pointer(provider_domain, 0x1000, device)
        .unwrap();
    (
        io,
        HostedProviderChildRouteEvidence {
            device_id: device,
            driver_id: driver,
            dependent_domain,
            provider_domain,
            provider_publication_cookie: 42,
            provider_driver_object,
            registration,
            allocation: SourcePoolAllocationIdentity {
                component_address: 0x1000,
                capacity: 0x300,
                pool_generation: 17,
            },
        },
    )
}

#[test]
fn child_registration_belongs_to_provider_domain_while_driver_remains_canonical() {
    let (mut io, evidence) = fixture();
    assert!(evidence.is_well_formed());
    assert_eq!(io.device(evidence.device_id).unwrap().driver_id, evidence.driver_id);
    assert_eq!(io.hosted_device_address_by_identity(evidence.dependent_domain, evidence.device_id), None);
    assert_eq!(
        io.hosted_device_pointer_registration(evidence.provider_domain, evidence.registration.address()),
        Some(evidence.registration),
    );

    io.retire_hosted_device_pointer(evidence.registration).unwrap();
    assert_eq!(
        io.hosted_device_pointer_registration(evidence.provider_domain, evidence.registration.address()),
        None,
    );
    let replacement = io.bind_hosted_device_pointer(
        evidence.provider_domain,
        evidence.registration.address(),
        evidence.device_id,
    ).unwrap();
    assert_ne!(replacement, evidence.registration);
}

#[test]
fn child_route_requires_matching_identity_and_physical_allocation() {
    let (_, evidence) = fixture();
    let mut same_domain = evidence;
    same_domain.dependent_domain = evidence.provider_domain;
    assert!(!same_domain.is_well_formed());
    let mut wrong_device = evidence;
    wrong_device.device_id = DeviceId(evidence.device_id.raw() + 1);
    assert!(!wrong_device.is_well_formed());
    let mut wrong_domain = evidence;
    wrong_domain.provider_domain = evidence.dependent_domain;
    assert!(!wrong_domain.is_well_formed());
    let mut wrong_address = evidence;
    wrong_address.allocation.component_address += 0x100;
    assert!(!wrong_address.is_well_formed());
    let mut missing_generation = evidence;
    missing_generation.allocation.pool_generation = 0;
    assert!(!missing_generation.is_well_formed());
}
