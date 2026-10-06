use super::*;
use crate::{
    CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceType, MockDriverBackend,
    MockObjectPort, ShareAccess,
};
use alloc::boxed::Box;
use nt_types::{AccessMask, NtPath};

fn fixture() -> (
    IoManager<MockObjectPort>,
    HostedDevicePointerRegistration,
    [FileId; 2],
) {
    let mut io = IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let driver = io
        .create_driver(
            &NtPath::parse_str(r"\Driver\SharedConsumer").unwrap(),
            Box::new(MockDriverBackend::new()),
        )
        .unwrap();
    let path = NtPath::parse_str(r"\Device\SharedConsumer").unwrap();
    let device = io
        .create_device(
            driver,
            Some(&path),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
    let mut files = [FileId(0); 2];
    for file in &mut files {
        let handle = io
            .open(
                client,
                &path,
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::empty(),
                0,
            )
            .unwrap();
        *file = io
            .reference_open_file(client, handle, AccessMask::empty())
            .unwrap()
            .0;
    }
    assert_ne!(files[0], files[1]);
    let domain = io.register_hosted_domain();
    let registration = io
        .bind_hosted_device_pointer(domain, 0x6000, device)
        .unwrap();
    (io, registration, files)
}

#[test]
fn sibling_file_retirement_preserves_exact_device_until_last_lease() {
    let (mut io, registration, files) = fixture();
    let mut owner = ConsumerDeviceProjection::new(&io, registration).unwrap();
    let mut first = owner.acquire(&mut io, files[0]).unwrap();
    let mut second = owner.acquire(&mut io, files[1]).unwrap();
    assert_eq!(owner.lease_count(), 2);
    assert_eq!(owner.begin_retirement(&mut io), Err(NtStatus::DEVICE_BUSY));
    owner.release(&mut io, &mut first).unwrap();
    assert!(!first.is_held());
    assert_eq!(
        owner.release(&mut io, &mut first),
        Err(NtStatus::INVALID_HANDLE)
    );
    assert_eq!(
        io.hosted_device_pointer_registration(registration.domain(), registration.address()),
        Some(registration)
    );
    assert_eq!(owner.begin_retirement(&mut io), Err(NtStatus::DEVICE_BUSY));
    owner.release(&mut io, &mut second).unwrap();
    owner.begin_retirement(&mut io).unwrap();
    assert!(owner.is_retired());
    assert_eq!(
        io.hosted_device_pointer_registration(registration.domain(), registration.address()),
        None
    );
    assert!(matches!(
        owner.acquire(&mut io, files[0]),
        Err(NtStatus::DELETE_PENDING)
    ));
}

#[test]
fn stale_registration_and_foreign_lease_cannot_mutate_new_owner() {
    let (mut io, registration, files) = fixture();
    let mut old = ConsumerDeviceProjection::new(&io, registration).unwrap();
    let mut lease = old.acquire(&mut io, files[0]).unwrap();
    let mut other = ConsumerDeviceProjection::new(&io, registration).unwrap();
    let mut other_lease = other.acquire(&mut io, files[0]).unwrap();
    assert_eq!(
        other.release(&mut io, &mut lease),
        Err(NtStatus::INVALID_HANDLE)
    );
    assert!(lease.is_held());
    assert_eq!(other.lease_count(), 1);
    other.release(&mut io, &mut other_lease).unwrap();
    assert_eq!(other.begin_retirement(&mut io), Err(NtStatus::DEVICE_BUSY));
    assert_eq!(io.hosted_device_pointer_count(registration), Ok(1));
    old.release(&mut io, &mut lease).unwrap();
    old.begin_retirement(&mut io).unwrap();
    let current = io
        .bind_hosted_device_pointer(
            registration.domain(),
            registration.address(),
            registration.device_id(),
        )
        .unwrap();
    assert_ne!(registration, current);
    assert!(matches!(
        ConsumerDeviceProjection::new(&io, registration),
        Err(NtStatus::INVALID_HANDLE)
    ));
    let mut owner = ConsumerDeviceProjection::new(&io, current).unwrap();
    assert_eq!(
        owner.release(&mut io, &mut lease),
        Err(NtStatus::INVALID_HANDLE)
    );
    assert_eq!(owner.lease_count(), 0);
    let mut current_lease = owner.acquire(&mut io, files[1]).unwrap();
    assert_eq!(io.hosted_device_pointer_count(current), Ok(1));
    owner.release(&mut io, &mut current_lease).unwrap();
    owner.begin_retirement(&mut io).unwrap();
}

#[test]
fn foreign_canonical_file_device_is_rejected_without_reference_effect() {
    let (mut io, registration, _) = fixture();
    let driver = io.device(registration.device_id()).unwrap().driver_id;
    let path = NtPath::parse_str(r"\Device\OtherConsumer").unwrap();
    io.create_device(
        driver,
        Some(&path),
        DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(),
        DeviceFlags::BUFFERED_IO,
        0,
    )
    .unwrap();
    let client = io.register_client();
    let handle = io
        .open(
            client,
            &path,
            AccessMask::GENERIC_READ,
            ShareAccess::READ,
            CreateOptions::empty(),
            0,
        )
        .unwrap();
    let foreign = io
        .reference_open_file(client, handle, AccessMask::empty())
        .unwrap()
        .0;
    let mut owner = ConsumerDeviceProjection::new(&io, registration).unwrap();
    assert!(matches!(
        owner.acquire(&mut io, foreign),
        Err(NtStatus::INVALID_HANDLE)
    ));
    assert_eq!(owner.lease_count(), 0);
    assert_eq!(io.hosted_device_pointer_count(registration), Ok(0));
    owner.begin_retirement(&mut io).unwrap();
}

#[test]
fn acknowledged_retirement_denies_replay_or_rejoin() {
    let (mut io, registration, files) = fixture();
    let mut owner = ConsumerDeviceProjection::new(&io, registration).unwrap();
    owner.begin_retirement(&mut io).unwrap();
    assert_eq!(
        owner.begin_retirement(&mut io),
        Err(NtStatus::DELETE_PENDING)
    );
    assert!(matches!(
        owner.acquire(&mut io, files[0]),
        Err(NtStatus::DELETE_PENDING)
    ));
    assert_eq!(owner.lease_count(), 0);
}

#[test]
fn known_busy_unregistration_allows_exact_live_rejoin() {
    let (mut io, registration, files) = fixture();
    let mut owner = ConsumerDeviceProjection::new(&io, registration).unwrap();
    let mut first = owner.acquire(&mut io, files[0]).unwrap();
    io.reference_hosted_device_pointer(registration).unwrap();
    owner.release(&mut io, &mut first).unwrap();
    assert_eq!(owner.begin_retirement(&mut io), Err(NtStatus::DEVICE_BUSY));
    assert!(!owner.is_retired());
    let mut second = owner.acquire(&mut io, files[1]).unwrap();
    assert_eq!(second.registration(), registration);
    io.dereference_hosted_device_pointer(registration).unwrap();
    assert_eq!(owner.begin_retirement(&mut io), Err(NtStatus::DEVICE_BUSY));
    owner.release(&mut io, &mut second).unwrap();
    owner.begin_retirement(&mut io).unwrap();
}
