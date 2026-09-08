use super::*;
use crate::{
    DeviceCharacteristics, DeviceFlags, DeviceRecord, DeviceType, DriverBackendId, DriverRecord,
    MajorFunctionTable, MockObjectPort,
};
use nt_types::{NtPath, ObjectId};

fn setup(default: bool) -> (IoManager<MockObjectPort>, DriverId, DeviceId) {
    let mut io = if default {
        IoManager::default()
    } else {
        IoManager::new(MockObjectPort::new())
    };
    let driver = io.register_driver(DriverRecord::new(
        ObjectId::NULL,
        NtPath::parse_str("\\Driver\\ReferenceTest").unwrap(),
        DriverBackendId(1),
        MajorFunctionTable::new(),
    ));
    let device = add_device(&mut io, driver);
    (io, driver, device)
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
fn references_prevent_normal_and_raw_device_deletion() {
    let (mut io, _, device) = setup(false);
    let mut first = io.retain_device_reference(device).unwrap();
    let mut second = io.retain_device_reference(device).unwrap();
    assert_eq!(first.device_id(), device);
    assert!(first.is_held());
    assert_eq!(io.device_reference_count(device), 2);
    assert_eq!(io.can_delete_device(device), Err(NtStatus::DELETE_PENDING));
    assert_eq!(
        io.delete_device(device).err(),
        Some(NtStatus::DELETE_PENDING)
    );
    assert!(io.device(device).unwrap().delete_pending);
    assert!(io.remove_device(device).is_none());
    io.release_device_reference(&mut first).unwrap();
    assert!(!first.is_held());
    assert_eq!(io.device_reference_count(device), 1);
    assert!(io.remove_device(device).is_none());
    io.release_device_reference(&mut second).unwrap();
    assert_eq!(io.device_reference_count(device), 0);
    assert!(io.delete_device(device).is_ok());
}

#[test]
fn references_block_driver_unload_destroy_and_raw_removal() {
    let (mut io, driver, device) = setup(false);
    let mut reference = io.retain_device_reference(device).unwrap();
    assert_eq!(
        io.can_begin_driver_unload(driver),
        Err(NtStatus::DELETE_PENDING)
    );
    assert_eq!(io.can_destroy_driver(driver), Err(NtStatus::DELETE_PENDING));
    assert_eq!(
        io.destroy_driver(driver).err(),
        Some(NtStatus::DELETE_PENDING)
    );
    assert!(io.remove_driver(driver).is_none());
    assert!(io.driver(driver).is_some());
    assert!(io.device(device).is_some());
    io.release_device_reference(&mut reference).unwrap();
    assert!(io.destroy_driver(driver).is_ok());
    assert!(io.driver(driver).is_none());
    assert!(io.device(device).is_none());
}

#[test]
fn default_and_new_managers_have_distinct_lazy_reference_identity() {
    let (mut first, _, first_device) = setup(false);
    let (mut second, _, second_device) = setup(true);
    assert_eq!(first.device_references.manager_identity, 0);
    assert_eq!(second.device_references.manager_identity, 0);
    assert_eq!(first_device, second_device);
    let mut first_ref = first.retain_device_reference(first_device).unwrap();
    let mut second_ref = second.retain_device_reference(second_device).unwrap();
    assert_ne!(first_ref.manager_identity, second_ref.manager_identity);
    assert_eq!(
        second.release_device_reference(&mut first_ref),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert!(first_ref.is_held());
    assert_eq!(first.device_reference_count(first_device), 1);
    assert_eq!(second.device_reference_count(second_device), 1);
    first.release_device_reference(&mut first_ref).unwrap();
    second.release_device_reference(&mut second_ref).unwrap();
}

#[test]
fn moving_manager_preserves_reference_authority() {
    let (mut io, _, device) = setup(false);
    let mut reference = io.retain_device_reference(device).unwrap();
    let mut moved = io;
    moved.release_device_reference(&mut reference).unwrap();
    assert!(!reference.is_held());
    assert_eq!(moved.can_delete_device(device), Ok(()));
}

#[test]
fn double_release_is_rejected_without_stealing_another_reference() {
    let (mut io, _, device) = setup(false);
    let mut first = io.retain_device_reference(device).unwrap();
    let mut second = io.retain_device_reference(device).unwrap();
    io.release_device_reference(&mut first).unwrap();
    assert_eq!(
        io.release_device_reference(&mut first),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(io.device_reference_count(device), 1);
    assert!(second.is_held());
    io.release_device_reference(&mut second).unwrap();
}

#[test]
fn reference_count_overflow_is_failure_atomic() {
    let (mut io, _, device) = setup(false);
    let mut reference = io.retain_device_reference(device).unwrap();
    io.device_references.counts[0].count = u64::MAX;
    assert_eq!(
        io.retain_device_reference(device).err(),
        Some(NtStatus::INSUFFICIENT_RESOURCES)
    );
    assert_eq!(io.device_reference_count(device), u64::MAX);
    assert!(reference.is_held());
    io.device_references.counts[0].count = 1;
    io.release_device_reference(&mut reference).unwrap();
}

#[test]
fn manager_identity_exhaustion_cannot_wrap() {
    for start in [0, u64::MAX] {
        let counter = AtomicU64::new(start);
        assert_eq!(
            allocate_manager_identity(&counter),
            Err(NtStatus::INSUFFICIENT_RESOURCES)
        );
        assert_eq!(counter.load(Ordering::Relaxed), start);
    }
    let counter = AtomicU64::new(u64::MAX - 1);
    assert_eq!(allocate_manager_identity(&counter), Ok(u64::MAX - 1));
    assert_eq!(
        allocate_manager_identity(&counter),
        Err(NtStatus::INSUFFICIENT_RESOURCES)
    );
}

#[test]
fn absent_deleted_and_delete_pending_devices_cannot_be_newly_retained() {
    let (mut io, _, device) = setup(false);
    assert_eq!(
        io.retain_device_reference(DeviceId::NULL).err(),
        Some(NtStatus::INVALID_PARAMETER)
    );
    io.device_mut(device).unwrap().delete_pending = true;
    assert_eq!(
        io.retain_device_reference(device).err(),
        Some(NtStatus::DELETE_PENDING)
    );
    assert_eq!(io.device_reference_count(device), 0);
    assert!(io.remove_device(device).is_some());
    assert_eq!(
        io.retain_device_reference(device).err(),
        Some(NtStatus::INVALID_PARAMETER)
    );
}

#[test]
fn unloading_driver_cannot_acquire_new_device_references() {
    let (mut io, driver, device) = setup(false);
    io.driver_mut(driver).unwrap().unload_state = DriverUnloadState::UnloadRequested;
    assert_eq!(
        io.retain_device_reference(device).err(),
        Some(NtStatus::DELETE_PENDING)
    );
    assert_eq!(io.device_reference_count(device), 0);
}

#[test]
fn separate_devices_and_consumers_keep_separate_counts() {
    let (mut io, driver, first_device) = setup(false);
    let second_device = add_device(&mut io, driver);
    let mut first = io.retain_device_reference(first_device).unwrap();
    let mut second = io.retain_device_reference(second_device).unwrap();
    io.release_device_reference(&mut first).unwrap();
    assert_eq!(io.can_delete_device(first_device), Ok(()));
    assert_eq!(
        io.can_delete_device(second_device),
        Err(NtStatus::DELETE_PENDING)
    );
    assert_eq!(io.can_destroy_driver(driver), Err(NtStatus::DELETE_PENDING));
    io.release_device_reference(&mut second).unwrap();
    assert_eq!(io.can_destroy_driver(driver), Ok(()));
}

#[test]
fn hosted_binding_is_not_a_reference_and_unbind_does_not_release_one() {
    let (mut io, _, device) = setup(false);
    let domain = io.register_hosted_domain();
    io.bind_hosted_device_identity(domain, 0x1000, device)
        .unwrap();
    assert_eq!(io.device_reference_count(device), 0);
    assert_eq!(io.can_delete_device(device), Ok(()));
    let mut reference = io.retain_hosted_device_reference(domain, 0x1000).unwrap();
    assert_eq!(io.can_delete_device(device), Err(NtStatus::DELETE_PENDING));
    assert!(io.unbind_hosted_device_identity(domain, 0x1000, device));
    io.unregister_hosted_domain(domain).unwrap();
    assert_eq!(
        io.retain_hosted_device_reference(domain, 0x1000).err(),
        Some(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(io.device_reference_count(device), 1);
    io.release_device_reference(&mut reference).unwrap();
    assert_eq!(io.can_delete_device(device), Ok(()));
}

#[test]
fn stale_domain_cookie_cannot_mint_a_reference() {
    let (mut io, _, device) = setup(false);
    let domain = io.register_hosted_domain();
    io.bind_hosted_device_identity(domain, 0x1000, device)
        .unwrap();
    let stale = HostedDomainIdentity {
        cookie: domain.cookie ^ 1,
        ..domain
    };
    assert_eq!(
        io.retain_hosted_device_reference(stale, 0x1000).err(),
        Some(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(io.device_reference_count(device), 0);
}

#[test]
fn failed_release_preserves_token_and_count_for_retry() {
    let (mut io, _, device) = setup(false);
    let mut reference = io.retain_device_reference(device).unwrap();
    io.device_references.counts[0].count = 0;
    assert_eq!(
        io.release_device_reference(&mut reference),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert!(reference.is_held());
    assert_eq!(io.device_reference_count(device), 0);
    io.device_references.counts[0].count = 1;
    io.release_device_reference(&mut reference).unwrap();
    assert!(!reference.is_held());
}

#[test]
fn stale_device_generation_cannot_release_a_replacement() {
    let (mut io, driver, device) = setup(false);
    let mut old = io.retain_device_reference(device).unwrap();
    // Deliberately bypass the guarded API to test failure against an inconsistent external state.
    assert!(io.devices.remove(device).is_some());
    let replacement = add_device(&mut io, driver);
    assert_ne!(device, replacement);
    let mut current = io.retain_device_reference(replacement).unwrap();
    assert_eq!(
        io.release_device_reference(&mut old),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert!(old.is_held());
    assert_eq!(io.device_reference_count(device), 1);
    assert_eq!(io.device_reference_count(replacement), 1);
    io.release_device_reference(&mut current).unwrap();
}

#[test]
fn device_record_updates_cannot_reset_private_reference_count() {
    let (mut io, driver, device) = setup(false);
    let mut reference = io.retain_device_reference(device).unwrap();
    let mut record = DeviceRecord::new(
        ObjectId::NULL,
        driver,
        None,
        DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(),
        DeviceFlags::empty(),
        0,
    );
    record.id = device;
    record.top_of_stack = device;
    *io.device_mut(device).unwrap() = record;
    assert_eq!(io.can_delete_device(device), Err(NtStatus::DELETE_PENDING));
    assert_eq!(io.device_reference_count(device), 1);
    io.release_device_reference(&mut reference).unwrap();
}

#[test]
fn counted_owner_releases_one_or_all_without_retiring_other_owners() {
    let (mut io, _, device) = setup(false);
    let mut counted = io.retain_device_reference(device).unwrap();
    let mut independent = io.retain_device_reference(device).unwrap();
    io.retain_device_reference_owned(&mut counted).unwrap();
    io.retain_device_reference_owned(&mut counted).unwrap();
    assert_eq!(counted.count(), 3);
    assert_eq!(io.device_reference_count(device), 4);
    io.release_device_reference_one(&mut counted).unwrap();
    assert_eq!(counted.count(), 2);
    assert_eq!(io.device_reference_count(device), 3);
    io.release_device_reference(&mut counted).unwrap();
    assert_eq!(counted.count(), 0);
    assert!(!counted.is_held());
    assert_eq!(io.device_reference_count(device), 1);
    assert_eq!(io.can_delete_device(device), Err(NtStatus::DELETE_PENDING));
    io.release_device_reference_one(&mut independent).unwrap();
    assert_eq!(io.device_reference_count(device), 0);
    assert_eq!(io.can_delete_device(device), Ok(()));
}

#[test]
fn existing_owner_can_grow_after_delete_and_unload_requests_without_allocation() {
    let (mut io, driver, device) = setup(false);
    let mut reference = io.retain_device_reference(device).unwrap();
    let pointer = io.device_references.counts.as_ptr();
    let capacity = io.device_references.counts.capacity();
    io.device_mut(device).unwrap().delete_pending = true;
    io.driver_mut(driver).unwrap().unload_state = DriverUnloadState::UnloadRequested;
    assert_eq!(
        io.retain_device_reference(device).err(),
        Some(NtStatus::DELETE_PENDING)
    );
    for _ in 0..100 {
        io.retain_device_reference_owned(&mut reference).unwrap();
    }
    assert_eq!(reference.count(), 101);
    assert_eq!(io.device_reference_count(device), 101);
    assert_eq!(io.device_references.counts.as_ptr(), pointer);
    assert_eq!(io.device_references.counts.capacity(), capacity);
    assert!(io.remove_device(device).is_none());
    assert!(io.remove_driver(driver).is_none());
    io.release_device_reference_one(&mut reference).unwrap();
    assert!(io.remove_device(device).is_none());
    io.release_device_reference(&mut reference).unwrap();
    assert_eq!(io.device_reference_count(device), 0);
}

#[test]
fn split_and_merge_transfer_counts_without_changing_canonical_ownership() {
    let (mut io, _, device) = setup(false);
    let mut source = io.retain_device_reference(device).unwrap();
    io.retain_device_reference_owned(&mut source).unwrap();
    let mut transfer = io.split_device_reference_one(&mut source).unwrap();
    assert_eq!(source.count(), 1);
    assert_eq!(transfer.count(), 1);
    assert_eq!(io.device_reference_count(device), 2);
    io.merge_device_references(&mut source, &mut transfer)
        .unwrap();
    assert_eq!(source.count(), 2);
    assert_eq!(transfer.count(), 0);
    assert_eq!(io.device_reference_count(device), 2);
    assert_eq!(
        io.release_device_reference_one(&mut transfer),
        Err(NtStatus::INVALID_PARAMETER)
    );
    io.release_device_reference(&mut source).unwrap();
    assert_eq!(io.device_reference_count(device), 0);
}

#[test]
fn splitting_last_reference_preserves_device_and_empty_owner_cannot_resurrect() {
    let (mut io, _, device) = setup(false);
    let mut source = io.retain_device_reference(device).unwrap();
    let mut transfer = io.split_device_reference_one(&mut source).unwrap();
    assert!(!source.is_held());
    assert_eq!(io.device_reference_count(device), 1);
    assert_eq!(io.can_delete_device(device), Err(NtStatus::DELETE_PENDING));
    assert_eq!(
        io.retain_device_reference_owned(&mut source),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        io.split_device_reference_one(&mut source).err(),
        Some(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        io.merge_device_references(&mut source, &mut transfer),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(transfer.count(), 1);
    io.release_device_reference(&mut transfer).unwrap();
    assert_eq!(io.can_delete_device(device), Ok(()));
}

#[test]
fn counted_operations_reject_foreign_manager_and_different_device_atomically() {
    let (mut io, driver, device) = setup(false);
    let second_device = add_device(&mut io, driver);
    let mut first = io.retain_device_reference(device).unwrap();
    let mut second = io.retain_device_reference(second_device).unwrap();
    let (mut foreign, _, foreign_device) = setup(false);
    let mut foreign_reference = foreign.retain_device_reference(foreign_device).unwrap();
    assert_eq!(device, foreign_device);
    assert_eq!(
        foreign.retain_device_reference_owned(&mut first),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        foreign.release_device_reference_one(&mut first),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        foreign.split_device_reference_one(&mut first).err(),
        Some(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        foreign.merge_device_references(&mut foreign_reference, &mut first),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        io.merge_device_references(&mut first, &mut second),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(first.count(), 1);
    assert_eq!(second.count(), 1);
    assert_eq!(foreign_reference.count(), 1);
    assert_eq!(io.device_reference_count(device), 1);
    assert_eq!(io.device_reference_count(second_device), 1);
    assert_eq!(foreign.device_reference_count(foreign_device), 1);
    io.release_device_reference(&mut first).unwrap();
    io.release_device_reference(&mut second).unwrap();
    foreign
        .release_device_reference(&mut foreign_reference)
        .unwrap();
}

#[test]
fn counted_increment_and_merge_overflow_preserve_every_owner() {
    let (mut io, _, device) = setup(false);
    let mut first = io.retain_device_reference(device).unwrap();
    let mut second = io.retain_device_reference(device).unwrap();
    io.device_references.counts[0].count = u64::MAX;
    assert_eq!(
        io.retain_device_reference_owned(&mut first),
        Err(NtStatus::INSUFFICIENT_RESOURCES)
    );
    assert_eq!(first.count(), 1);
    first.count = u64::MAX;
    assert_eq!(
        io.retain_device_reference_owned(&mut first),
        Err(NtStatus::INSUFFICIENT_RESOURCES)
    );
    assert_eq!(
        io.merge_device_references(&mut first, &mut second),
        Err(NtStatus::INSUFFICIENT_RESOURCES)
    );
    assert_eq!(first.count(), u64::MAX);
    assert_eq!(second.count(), 1);
    assert_eq!(io.device_reference_count(device), u64::MAX);
    first.count = 1;
    io.device_references.counts[0].count = 2;
    io.release_device_reference(&mut first).unwrap();
    io.release_device_reference(&mut second).unwrap();
}

#[test]
fn inconsistent_canonical_counts_do_not_allow_partial_release_or_transfer() {
    let (mut io, _, device) = setup(false);
    let mut first = io.retain_device_reference(device).unwrap();
    io.retain_device_reference_owned(&mut first).unwrap();
    let mut second = io.retain_device_reference(device).unwrap();
    io.device_references.counts[0].count = 1;
    assert_eq!(
        io.release_device_reference_one(&mut first),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        io.release_device_reference(&mut first),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        io.split_device_reference_one(&mut first).err(),
        Some(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(first.count(), 2);
    io.device_references.counts[0].count = 2;
    assert_eq!(
        io.merge_device_references(&mut first, &mut second),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(first.count(), 2);
    assert_eq!(second.count(), 1);
    assert_eq!(io.device_reference_count(device), 2);
    io.device_references.counts[0].count = 3;
    io.release_device_reference(&mut first).unwrap();
    io.release_device_reference(&mut second).unwrap();
}

#[test]
fn counted_owner_survives_manager_move_and_domain_unbinding() {
    let (mut io, _, device) = setup(false);
    let domain = io.register_hosted_domain();
    io.bind_hosted_device_identity(domain, 0x1000, device)
        .unwrap();
    let mut owner = io.retain_hosted_device_reference(domain, 0x1000).unwrap();
    io.retain_device_reference_owned(&mut owner).unwrap();
    assert!(io.unbind_hosted_device_identity(domain, 0x1000, device));
    io.unregister_hosted_domain(domain).unwrap();
    let mut moved = io;
    let mut transfer = moved.split_device_reference_one(&mut owner).unwrap();
    moved.release_device_reference(&mut owner).unwrap();
    assert_eq!(moved.device_reference_count(device), 1);
    moved.release_device_reference(&mut transfer).unwrap();
    assert_eq!(moved.device_reference_count(device), 0);
}
