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
