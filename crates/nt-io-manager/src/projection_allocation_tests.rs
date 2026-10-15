use super::*;
use crate::{
    DeviceCharacteristics, DeviceFlags, DeviceRecord, DeviceType, DriverBackendId, DriverRecord,
    IoManager, MajorFunctionTable, MockObjectPort,
};
use nt_types::{NtPath, ObjectId};

fn setup() -> (HostedDomainIdentity, HostedDevicePointerRegistration) {
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io.register_driver(DriverRecord::new(
        ObjectId::NULL,
        NtPath::parse_str("\\Driver\\PhysicalProjection").unwrap(),
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
    let physical = io.register_hosted_domain();
    let logical = io.register_hosted_domain();
    (
        physical,
        io.bind_hosted_device_pointer(logical, 0x1000, device)
            .unwrap(),
    )
}

fn allocation() -> SourcePoolAllocationIdentity {
    SourcePoolAllocationIdentity {
        component_address: 0x1000,
        capacity: 0x1a0,
        pool_generation: 7,
    }
}

#[test]
fn physical_protection_precedes_logical_publication_and_survives_uncertainty() {
    let (physical, registration) = setup();
    assert_ne!(physical, registration.domain());
    let mut ledger = ProjectionAllocationLedger::new();
    let mut owner = ledger.stage(physical, allocation()).unwrap();
    assert!(ledger.protects_address(physical, 0x1000));
    ledger.attach_registration(&owner, registration).unwrap();
    ledger
        .begin_retirement(&owner, physical, allocation(), Some(registration))
        .unwrap();
    assert!(ledger.protects_address(physical, 0x1000));
    assert!(ledger
        .begin_retirement(&owner, physical, allocation(), Some(registration))
        .is_err());
    assert!(ledger.stage(physical, allocation()).is_err());
    ledger.acknowledge_free(&mut owner).unwrap();
    assert!(!owner.is_held());
    assert!(!ledger.protects_address(physical, 0x1000));
    assert!(ledger.acknowledge_free(&mut owner).is_err());
}

#[test]
fn stale_generation_capacity_and_foreign_ledger_cannot_retire_owner() {
    let (physical, registration) = setup();
    let mut ledger = ProjectionAllocationLedger::new();
    let owner = ledger.stage(physical, allocation()).unwrap();
    ledger.attach_registration(&owner, registration).unwrap();
    let mut stale = allocation();
    stale.pool_generation += 1;
    assert!(ledger
        .begin_retirement(&owner, physical, stale, Some(registration))
        .is_err());
    stale = allocation();
    stale.capacity += 16;
    assert!(ledger
        .begin_retirement(&owner, physical, stale, Some(registration))
        .is_err());
    assert!(ledger
        .begin_retirement(&owner, physical, allocation(), None)
        .is_err());
    assert!(ledger
        .begin_retirement(
            &owner,
            registration.domain(),
            allocation(),
            Some(registration)
        )
        .is_err());
    let mut foreign = ProjectionAllocationLedger::new();
    let _foreign_owner = foreign.stage(physical, allocation()).unwrap();
    assert!(foreign.attach_registration(&owner, registration).is_err());
    assert!(foreign
        .begin_retirement(&owner, physical, allocation(), Some(registration))
        .is_err());
    assert!(ledger.protects_address(physical, 0x1000));
}

#[test]
fn failed_bind_cleanup_requires_exact_unpublished_owner_and_native_ack() {
    let (physical, _) = setup();
    let mut ledger = ProjectionAllocationLedger::new();
    let mut owner = ledger.stage(physical, allocation()).unwrap();
    assert!(ledger.acknowledge_free(&mut owner).is_err());
    ledger
        .begin_retirement(&owner, physical, allocation(), None)
        .unwrap();
    assert!(owner.is_held());
    ledger.acknowledge_free(&mut owner).unwrap();
    let mut reused = allocation();
    reused.pool_generation += 1;
    let next = ledger.stage(physical, reused).unwrap();
    assert!(ledger
        .begin_retirement(&owner, physical, reused, None)
        .is_err());
    assert!(next.is_held());
}

#[test]
fn physical_domain_and_registration_address_are_not_interchangeable() {
    let (physical, registration) = setup();
    let mut ledger = ProjectionAllocationLedger::new();
    let owner = ledger.stage(physical, allocation()).unwrap();
    assert!(!ledger.protects_address(registration.domain(), 0x1000));
    let mut other = allocation();
    other.component_address += 0x1000;
    let other_owner = ledger.stage(physical, other).unwrap();
    assert!(ledger
        .attach_registration(&other_owner, registration)
        .is_err());
    ledger.attach_registration(&owner, registration).unwrap();
    assert!(ledger.attach_registration(&owner, registration).is_err());
}

#[test]
fn invalid_physical_identity_is_refused_before_publication() {
    let (physical, _) = setup();
    let mut ledger = ProjectionAllocationLedger::new();
    for bad in [
        SourcePoolAllocationIdentity {
            pool_generation: 0,
            ..allocation()
        },
        SourcePoolAllocationIdentity {
            capacity: 0,
            ..allocation()
        },
        SourcePoolAllocationIdentity {
            component_address: 0,
            ..allocation()
        },
    ] {
        assert!(ledger.stage(physical, bad).is_err());
    }
    assert!(!ledger.protects_address(physical, 0x1000));
    assert!(ledger
        .stage(HostedDomainIdentity::default(), allocation())
        .is_err());
}

#[test]
fn registration_and_acknowledgement_cannot_cross_owners() {
    let (physical, registration) = setup();
    let (_, foreign_registration) = setup();
    let mut ledger = ProjectionAllocationLedger::new();
    let mut owner = ledger.stage(physical, allocation()).unwrap();
    ledger.attach_registration(&owner, registration).unwrap();
    assert!(ledger
        .begin_retirement(&owner, physical, allocation(), Some(foreign_registration))
        .is_err());
    ledger
        .begin_retirement(&owner, physical, allocation(), Some(registration))
        .unwrap();
    let mut foreign = ProjectionAllocationLedger::new();
    let _foreign_owner = foreign.stage(physical, allocation()).unwrap();
    assert!(foreign.acknowledge_free(&mut owner).is_err());
    assert!(owner.is_held());
    assert!(ledger.protects_address(physical, 0x1000));
    ledger.acknowledge_free(&mut owner).unwrap();
}

#[test]
fn physical_publication_rejects_overlapping_ranges_but_not_foreign_pool_addresses() {
    let (physical, registration) = setup();
    let mut ledger = ProjectionAllocationLedger::new();
    let _owner = ledger.stage(physical, allocation()).unwrap();
    assert!(ledger.protects_address(physical, 0x1000));
    assert!(ledger.protects_address(physical, 0x1010));
    assert!(ledger.protects_address(physical, 0x119f));
    assert!(!ledger.protects_address(physical, 0x0fff));
    assert!(!ledger.protects_address(physical, 0x11a0));
    let interior = SourcePoolAllocationIdentity {
        component_address: 0x1010,
        capacity: 16,
        pool_generation: 8,
    };
    assert!(ledger.stage(physical, interior).is_err());
    let enclosing = SourcePoolAllocationIdentity {
        component_address: 0x0ff0,
        capacity: 0x1c0,
        pool_generation: 9,
    };
    assert!(ledger.stage(physical, enclosing).is_err());
    let adjacent = SourcePoolAllocationIdentity {
        component_address: 0x11a0,
        capacity: 16,
        pool_generation: 10,
    };
    assert!(ledger.stage(physical, adjacent).is_ok());
    assert!(ledger.stage(registration.domain(), allocation()).is_ok());
}
