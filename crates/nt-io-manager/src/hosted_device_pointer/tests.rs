use super::*;
use crate::{
    DeviceCharacteristics, DeviceFlags, DeviceRecord, DeviceType, DriverBackendId, DriverId,
    DriverRecord, MajorFunctionTable, MockObjectPort,
};
use nt_types::{NtPath, ObjectId};

fn setup() -> (
    IoManager<MockObjectPort>,
    DriverId,
    DeviceId,
    HostedDomainIdentity,
) {
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io.register_driver(DriverRecord::new(
        ObjectId::NULL,
        NtPath::parse_str("\\Driver\\PointerTest").unwrap(),
        DriverBackendId(1),
        MajorFunctionTable::new(),
    ));
    let device = add_device(&mut io, driver);
    let domain = io.register_hosted_domain();
    io.bind_hosted_device_identity(domain, 0x1000, device)
        .unwrap();
    (io, driver, device, domain)
}

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
fn admission_anchor_and_repeated_callers_have_separate_counts() {
    let (mut io, _, device, domain) = setup();
    let registration = io.register_hosted_device_pointer(domain, 0x1000).unwrap();
    assert_eq!(
        io.register_hosted_device_pointer(domain, 0x1000),
        Ok(registration)
    );
    assert_eq!(io.device_reference_count(device), 1);
    assert_eq!(io.hosted_device_pointer_count(registration), Ok(0));
    let capacity = io.hosted_device_pointers.rows.capacity();
    for _ in 0..64 {
        assert_eq!(io.reference_hosted_device_pointer(registration), Ok(1));
        assert_eq!(io.reference_hosted_device_pointer(registration), Ok(2));
        assert_eq!(io.device_reference_count(device), 3);
        assert_eq!(io.dereference_hosted_device_pointer(registration), Ok(1));
        assert_eq!(io.dereference_hosted_device_pointer(registration), Ok(0));
    }
    assert_eq!(io.hosted_device_pointers.rows.capacity(), capacity);
    assert_eq!(
        io.dereference_hosted_device_pointer(registration),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(io.device_reference_count(device), 1);
}

#[test]
fn callers_and_registration_block_unbind_and_domain_retirement() {
    let (mut io, _, device, domain) = setup();
    let registration = io.register_hosted_device_pointer(domain, 0x1000).unwrap();
    io.reference_hosted_device_pointer(registration).unwrap();
    assert_eq!(
        io.unregister_hosted_device_pointer(registration),
        Err(NtStatus::DEVICE_BUSY)
    );
    assert!(!io.unbind_hosted_device_identity(domain, 0x1000, device));
    assert_eq!(
        io.unregister_hosted_domain(domain),
        Err(NtStatus::DEVICE_BUSY)
    );
    io.dereference_hosted_device_pointer(registration).unwrap();
    assert!(!io.unbind_hosted_device_identity(domain, 0x1000, device));
    io.unregister_hosted_device_pointer(registration).unwrap();
    assert!(io.unbind_hosted_device_identity(domain, 0x1000, device));
    io.unregister_hosted_domain(domain).unwrap();
    assert_eq!(io.device_reference_count(device), 0);
}

#[test]
fn source_to_destination_transfer_conserves_actual_references() {
    let (mut io, _, device, domain) = setup();
    let target_domain = io.register_hosted_domain();
    io.bind_hosted_device_identity(target_domain, 0x2000, device)
        .unwrap();
    let source = io.register_hosted_device_pointer(domain, 0x1000).unwrap();
    let target = io
        .register_hosted_device_pointer(target_domain, 0x2000)
        .unwrap();
    io.reference_hosted_device_pointer(source).unwrap();
    let mut owner = io.take_hosted_device_pointer_reference(source).unwrap();
    assert!(owner.is_held());
    assert_eq!(io.device_reference_count(device), 3);
    assert_eq!(io.hosted_device_pointer_count(source), Ok(0));
    assert_eq!(
        io.adopt_hosted_device_pointer_reference(target, &mut owner),
        Ok(1)
    );
    assert!(!owner.is_held());
    assert_eq!(io.device_reference_count(device), 3);
    assert_eq!(
        io.adopt_hosted_device_pointer_reference(target, &mut owner),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(owner.release(&mut io), Err(NtStatus::INVALID_PARAMETER));
    io.dereference_hosted_device_pointer(target).unwrap();
    io.unregister_hosted_device_pointer(source).unwrap();
    io.unregister_hosted_device_pointer(target).unwrap();
    assert_eq!(io.device_reference_count(device), 0);
}

#[test]
fn failed_destination_admission_preserves_transfer_owner() {
    let (mut io, driver, device, domain) = setup();
    let other = add_device(&mut io, driver);
    io.bind_hosted_device_identity(domain, 0x2000, other)
        .unwrap();
    let source = io.register_hosted_device_pointer(domain, 0x1000).unwrap();
    let target = io.register_hosted_device_pointer(domain, 0x2000).unwrap();
    io.reference_hosted_device_pointer(source).unwrap();
    let mut owner = io.take_hosted_device_pointer_reference(source).unwrap();
    assert_eq!(
        io.adopt_hosted_device_pointer_reference(target, &mut owner),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert!(owner.is_held());
    assert_eq!(io.device_reference_count(device), 2);
    assert_eq!(io.device_reference_count(other), 1);
    assert_eq!(
        io.adopt_hosted_device_pointer_reference(source, &mut owner),
        Ok(1)
    );
    assert!(!owner.is_held());
}

#[test]
fn transferred_reference_survives_source_domain_retirement() {
    let (mut io, _, device, domain) = setup();
    let source = io.register_hosted_device_pointer(domain, 0x1000).unwrap();
    io.reference_hosted_device_pointer(source).unwrap();
    let mut owner = io.take_hosted_device_pointer_reference(source).unwrap();
    io.unregister_hosted_device_pointer(source).unwrap();
    assert!(io.unbind_hosted_device_identity(domain, 0x1000, device));
    io.unregister_hosted_domain(domain).unwrap();
    assert_eq!(io.device_reference_count(device), 1);
    assert_eq!(io.can_delete_device(device), Err(NtStatus::DELETE_PENDING));
    owner.release(&mut io).unwrap();
    assert_eq!(io.device_reference_count(device), 0);
}

#[test]
fn stale_registration_cannot_mutate_reused_address() {
    let (mut io, _, device, domain) = setup();
    let old = io.register_hosted_device_pointer(domain, 0x1000).unwrap();
    io.unregister_hosted_device_pointer(old).unwrap();
    let new = io.register_hosted_device_pointer(domain, 0x1000).unwrap();
    assert_ne!(old, new);
    assert_eq!(
        io.reference_hosted_device_pointer(old),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        io.unregister_hosted_device_pointer(old),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(io.hosted_device_pointer_count(new), Ok(0));
    assert_eq!(io.device_reference_count(device), 1);
}

#[test]
fn matching_numeric_ids_from_other_manager_have_no_authority() {
    let (mut first, _, first_device, first_domain) = setup();
    let (mut second, _, second_device, second_domain) = setup();
    assert_eq!(first_device, second_device);
    assert_eq!(first_domain, second_domain);
    let source = first
        .register_hosted_device_pointer(first_domain, 0x1000)
        .unwrap();
    let target = second
        .register_hosted_device_pointer(second_domain, 0x1000)
        .unwrap();
    assert_eq!(
        second.reference_hosted_device_pointer(source),
        Err(NtStatus::INVALID_PARAMETER)
    );
    first.reference_hosted_device_pointer(source).unwrap();
    let mut owner = first.take_hosted_device_pointer_reference(source).unwrap();
    assert_eq!(
        second.adopt_hosted_device_pointer_reference(target, &mut owner),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(owner.release(&mut second), Err(NtStatus::INVALID_PARAMETER));
    assert!(owner.is_held());
    assert_eq!(first.device_reference_count(first_device), 2);
    assert_eq!(second.device_reference_count(second_device), 1);
    owner.release(&mut first).unwrap();
}

#[test]
fn invalid_bindings_and_exhausted_sequence_acquire_nothing() {
    let (mut io, _, device, domain) = setup();
    let invalid = HostedDomainIdentity {
        cookie: domain.cookie + 1,
        ..domain
    };
    assert_eq!(
        io.register_hosted_device_pointer(invalid, 0x1000),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        io.register_hosted_device_pointer(domain, 0),
        Err(NtStatus::INVALID_PARAMETER)
    );
    io.hosted_device_pointers.sequence = u64::MAX;
    assert_eq!(
        io.register_hosted_device_pointer(domain, 0x1000),
        Err(NtStatus::INSUFFICIENT_RESOURCES)
    );
    assert!(io.hosted_device_pointers.rows.is_empty());
    assert_eq!(io.device_reference_count(device), 0);
}

#[test]
fn deletion_pending_keeps_existing_pointer_lifetime_but_rejects_new_registration() {
    let (mut io, _, device, domain) = setup();
    let registration = io.register_hosted_device_pointer(domain, 0x1000).unwrap();
    assert_eq!(
        io.delete_device(device).err(),
        Some(NtStatus::DELETE_PENDING)
    );
    assert_eq!(io.reference_hosted_device_pointer(registration), Ok(1));
    let new_domain = io.register_hosted_domain();
    io.bind_hosted_device_identity(new_domain, 0x2000, device)
        .unwrap();
    assert_eq!(
        io.register_hosted_device_pointer(new_domain, 0x2000),
        Err(NtStatus::DELETE_PENDING)
    );
    io.dereference_hosted_device_pointer(registration).unwrap();
    io.unregister_hosted_device_pointer(registration).unwrap();
    assert_eq!(io.device_reference_count(device), 0);
}

#[test]
fn atomic_publication_and_retirement_preserve_exact_registration_generation() {
    let (mut io, _, device, domain) = setup();
    assert!(io.unbind_hosted_device_identity(domain, 0x1000, device));
    assert_eq!(io.hosted_device_pointer_registration(domain, 0x1000), None);
    let first = io
        .bind_hosted_device_pointer(domain, 0x1000, device)
        .unwrap();
    assert_eq!(io.hosted_device_by_identity(domain, 0x1000), Some(device));
    assert_eq!(
        io.hosted_device_pointer_registration(domain, 0x1000),
        Some(first)
    );
    assert_eq!(
        io.bind_hosted_device_pointer(domain, 0x1000, device),
        Ok(first)
    );
    assert_eq!(io.device_reference_count(device), 1);
    io.retire_hosted_device_pointer(first).unwrap();
    assert_eq!(io.hosted_device_by_identity(domain, 0x1000), None);
    assert_eq!(io.hosted_device_pointer_registration(domain, 0x1000), None);
    assert_eq!(io.device_reference_count(device), 0);
    let second = io
        .bind_hosted_device_pointer(domain, 0x1000, device)
        .unwrap();
    assert_ne!(first, second);
    assert_eq!(
        io.retire_hosted_device_pointer(first),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        io.hosted_device_pointer_registration(domain, 0x1000),
        Some(second)
    );
    assert_eq!(io.device_reference_count(device), 1);
    io.retire_hosted_device_pointer(second).unwrap();
    io.unregister_hosted_domain(domain).unwrap();
}

#[test]
fn failed_atomic_registration_rolls_back_only_its_new_binding() {
    let (mut io, driver, existing_device, domain) = setup();
    let new_device = add_device(&mut io, driver);
    io.hosted_device_pointers.sequence = u64::MAX;
    assert_eq!(
        io.bind_hosted_device_pointer(domain, 0x2000, new_device),
        Err(NtStatus::INSUFFICIENT_RESOURCES)
    );
    assert_eq!(io.hosted_device_by_identity(domain, 0x2000), None);
    assert_eq!(io.hosted_device_pointer_registration(domain, 0x2000), None);
    assert_eq!(io.device_reference_count(new_device), 0);
    assert_eq!(
        io.bind_hosted_device_pointer(domain, 0x1000, existing_device),
        Err(NtStatus::INSUFFICIENT_RESOURCES)
    );
    assert_eq!(
        io.hosted_device_by_identity(domain, 0x1000),
        Some(existing_device)
    );
    assert_eq!(io.device_reference_count(existing_device), 0);
    assert_eq!(
        io.hosted_domain(domain.domain_id)
            .unwrap()
            .device_binding_count(),
        1
    );
}

#[test]
fn failed_anchor_acquisition_rolls_back_new_binding_and_preserves_existing_owner() {
    let (mut io, _, device, domain) = setup();
    let existing = io
        .bind_hosted_device_pointer(domain, 0x1000, device)
        .unwrap();
    assert_eq!(
        io.delete_device(device).err(),
        Some(NtStatus::DELETE_PENDING)
    );
    let other_domain = io.register_hosted_domain();
    assert_eq!(
        io.bind_hosted_device_pointer(other_domain, 0x2000, device),
        Err(NtStatus::DELETE_PENDING)
    );
    assert_eq!(io.hosted_device_by_identity(other_domain, 0x2000), None);
    assert_eq!(io.device_reference_count(device), 1);
    assert_eq!(
        io.bind_hosted_device_pointer(domain, 0x1000, device),
        Ok(existing)
    );
    io.unregister_hosted_domain(other_domain).unwrap();
    io.retire_hosted_device_pointer(existing).unwrap();
    assert!(io.delete_device(device).is_ok());
}

#[test]
fn caller_references_block_atomic_retirement_and_device_destruction() {
    let (mut io, _, device, domain) = setup();
    let registration = io
        .bind_hosted_device_pointer(domain, 0x1000, device)
        .unwrap();
    io.reference_hosted_device_pointer(registration).unwrap();
    assert_eq!(
        io.retire_hosted_device_pointer(registration),
        Err(NtStatus::DEVICE_BUSY)
    );
    assert_eq!(
        io.hosted_device_pointer_registration(domain, 0x1000),
        Some(registration)
    );
    assert_eq!(io.hosted_device_by_identity(domain, 0x1000), Some(device));
    assert_eq!(io.device_reference_count(device), 2);
    assert_eq!(io.can_delete_device(device), Err(NtStatus::DELETE_PENDING));
    let mut detached = io
        .take_hosted_device_pointer_reference(registration)
        .unwrap();
    io.retire_hosted_device_pointer(registration).unwrap();
    io.unregister_hosted_domain(domain).unwrap();
    assert_eq!(io.device_reference_count(device), 1);
    assert_eq!(io.can_delete_device(device), Err(NtStatus::DELETE_PENDING));
    detached.release(&mut io).unwrap();
    assert!(io.delete_device(device).is_ok());
}

#[test]
fn atomic_publication_rejects_collisions_and_stale_domains_without_mutation() {
    let (mut io, driver, device, domain) = setup();
    let registration = io
        .bind_hosted_device_pointer(domain, 0x1000, device)
        .unwrap();
    let other = add_device(&mut io, driver);
    for (address, target) in [(0x1000, other), (0x2000, device)] {
        assert_eq!(
            io.bind_hosted_device_pointer(domain, address, target),
            Err(NtStatus::OBJECT_NAME_COLLISION)
        );
    }
    assert_eq!(
        io.bind_hosted_device_pointer(domain, 0, other),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        io.bind_hosted_device_pointer(domain, 0x2000, DeviceId::NULL),
        Err(NtStatus::INVALID_PARAMETER)
    );
    let stale = HostedDomainIdentity {
        cookie: domain.cookie + 1,
        ..domain
    };
    assert_eq!(io.hosted_device_pointer_registration(stale, 0x1000), None);
    assert_eq!(
        io.bind_hosted_device_pointer(stale, 0x2000, other),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        io.hosted_device_pointer_registration(domain, 0x1000),
        Some(registration)
    );
    assert_eq!(
        io.hosted_domain(domain.domain_id)
            .unwrap()
            .device_binding_count(),
        1
    );
    assert_eq!(io.device_reference_count(device), 1);
    assert_eq!(io.device_reference_count(other), 0);
}

#[test]
fn provider_registrations_at_matching_addresses_retire_independently() {
    let (mut io, _, device, first_domain) = setup();
    let second_domain = io.register_hosted_domain();
    let first = io
        .bind_hosted_device_pointer(first_domain, 0x1000, device)
        .unwrap();
    let second = io
        .bind_hosted_device_pointer(second_domain, 0x1000, device)
        .unwrap();
    io.reference_hosted_device_pointer(second).unwrap();
    assert_eq!(io.device_reference_count(device), 3);
    io.retire_hosted_device_pointer(first).unwrap();
    io.unregister_hosted_domain(first_domain).unwrap();
    assert_eq!(
        io.hosted_device_pointer_registration(first_domain, 0x1000),
        None
    );
    assert_eq!(
        io.hosted_device_pointer_registration(second_domain, 0x1000),
        Some(second)
    );
    assert_eq!(io.device_reference_count(device), 2);
    io.dereference_hosted_device_pointer(second).unwrap();
    io.retire_hosted_device_pointer(second).unwrap();
    io.unregister_hosted_domain(second_domain).unwrap();
    assert_eq!(io.device_reference_count(device), 0);
}

#[test]
fn multi_device_rollback_detaches_all_owned_edges_before_destroying_lower_device() {
    let (mut io, driver, pdo, domain) = setup();
    let lower = add_device(&mut io, driver);
    let upper = add_device(&mut io, driver);
    let lower_pointer = io
        .bind_hosted_device_pointer(domain, 0x2000, lower)
        .unwrap();
    let upper_pointer = io
        .bind_hosted_device_pointer(domain, 0x3000, upper)
        .unwrap();
    assert_eq!(io.attach_device_to_stack(lower, pdo), Ok(pdo));
    assert_eq!(io.attach_device_to_stack(upper, pdo), Ok(lower));

    io.detach_device_from_stack(lower).unwrap();
    io.retire_hosted_device_pointer(lower_pointer).unwrap();
    assert_eq!(
        io.destroy_device(lower).err(),
        Some(NtStatus::DELETE_PENDING)
    );
    assert!(io.device(lower).is_some());

    // The next owned attachment must make progress even while lower deletion is pending.
    io.detach_device_from_stack(upper).unwrap();
    io.retire_hosted_device_pointer(upper_pointer).unwrap();
    io.destroy_device(lower).unwrap();
    io.destroy_device(upper).unwrap();
    assert_eq!(io.device(pdo).unwrap().top_of_stack, pdo);
    assert_eq!(io.hosted_device_by_identity(domain, 0x1000), Some(pdo));
    assert_eq!(io.device_reference_count(pdo), 0);
}
