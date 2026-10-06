use super::*;
use crate::{
    DeviceCharacteristics, DeviceFlags, DeviceRecord, DeviceType, DriverBackendId, DriverRecord,
    MajorFunctionTable, MockObjectPort,
};
use nt_types::{NtPath, ObjectId};

fn setup() -> (
    IoManager<MockObjectPort>,
    DeviceId,
    HostedDomainIdentity,
    HostedDevicePointerRegistration,
) {
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io.register_driver(DriverRecord::new(
        ObjectId::NULL,
        NtPath::parse_str("\\Driver\\ProjectionTest").unwrap(),
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
    let registration = io
        .bind_hosted_device_pointer(domain, 0x1000, device)
        .unwrap();
    (io, device, domain, registration)
}

#[test]
fn projection_owner_blocks_retirement_until_every_pin_is_released() {
    let (mut io, device, domain, registration) = setup();
    let mut first = io
        .retain_hosted_device_projection_reference(registration)
        .unwrap();
    let mut second = io
        .retain_hosted_device_projection_reference(registration)
        .unwrap();
    assert_eq!(first.registration(), registration);
    assert_eq!(io.device_reference_count(device), 3);
    assert_eq!(io.hosted_device_pointer_count(registration), Ok(0));
    assert_eq!(
        io.unregister_hosted_device_pointer(registration),
        Err(NtStatus::DEVICE_BUSY)
    );
    assert_eq!(
        io.retire_hosted_device_pointer(registration),
        Err(NtStatus::DEVICE_BUSY)
    );
    assert_eq!(
        io.hosted_device_pointer_registration(domain, 0x1000),
        Some(registration)
    );
    assert!(!io.unbind_hosted_device_identity(domain, 0x1000, device));
    first.release(&mut io).unwrap();
    assert!(!first.is_held());
    assert!(first.release(&mut io).is_err());
    assert_eq!(io.device_reference_count(device), 2);
    assert_eq!(
        io.unregister_hosted_device_pointer(registration),
        Err(NtStatus::DEVICE_BUSY)
    );
    second.release(&mut io).unwrap();
    io.retire_hosted_device_pointer(registration).unwrap();
    assert_eq!(io.device_reference_count(device), 0);
    assert_eq!(io.hosted_device_pointer_registration(domain, 0x1000), None);
}

#[test]
fn projection_owner_move_and_foreign_release_preserve_exact_owner() {
    let (mut io, device, _, registration) = setup();
    let owner = io
        .retain_hosted_device_projection_reference(registration)
        .unwrap();
    let mut moved = owner;
    let (mut foreign, other_device, _, _) = setup();
    assert!(foreign
        .retain_hosted_device_projection_reference(registration)
        .is_err());
    assert!(moved.release(&mut foreign).is_err());
    assert!(moved.is_held());
    assert_eq!(io.device_reference_count(device), 2);
    assert_eq!(foreign.device_reference_count(other_device), 1);
    moved.release(&mut io).unwrap();
    assert_eq!(io.device_reference_count(device), 1);
}

#[test]
fn stale_projection_generation_cannot_pin_replacement() {
    let (mut io, device, domain, registration) = setup();
    io.retire_hosted_device_pointer(registration).unwrap();
    let replacement = io
        .bind_hosted_device_pointer(domain, 0x1000, device)
        .unwrap();
    assert_ne!(registration.generation(), replacement.generation());
    assert!(io
        .retain_hosted_device_projection_reference(registration)
        .is_err());
    assert_eq!(io.device_reference_count(device), 1);
    for wrong in [
        HostedDevicePointerRegistration {
            address: 0x2000,
            ..replacement
        },
        HostedDevicePointerRegistration {
            domain: io.register_hosted_domain(),
            ..replacement
        },
        HostedDevicePointerRegistration {
            device: DeviceId(device.raw() + 1),
            ..replacement
        },
    ] {
        assert!(io.retain_hosted_device_projection_reference(wrong).is_err());
    }
    assert_eq!(io.device_reference_count(device), 1);
}

#[test]
fn projection_pin_domain_retirement_and_detached_legacy_owner_are_distinct() {
    let (mut io, device, domain, registration) = setup();
    let mut projection = io
        .retain_hosted_device_projection_reference(registration)
        .unwrap();
    let mut detached = io
        .retain_hosted_device_pointer_reference(registration)
        .unwrap();
    assert!(io.unregister_hosted_domain(domain).is_err());
    assert_eq!(
        io.retire_hosted_device_pointer(registration),
        Err(NtStatus::DEVICE_BUSY)
    );
    projection.release(&mut io).unwrap();
    io.retire_hosted_device_pointer(registration).unwrap();
    io.unregister_hosted_domain(domain).unwrap();
    assert!(detached.is_held());
    assert_eq!(io.device_reference_count(device), 1);
    detached.release(&mut io).unwrap();
    assert_eq!(io.device_reference_count(device), 0);
}

#[test]
fn release_refusal_preserves_projection_pin_and_counts() {
    let (mut io, device, _, registration) = setup();
    let mut owner = io
        .retain_hosted_device_projection_reference(registration)
        .unwrap();
    owner.registration.sequence += 1;
    assert!(owner.release(&mut io).is_err());
    assert!(owner.is_held());
    assert_eq!(io.device_reference_count(device), 2);
    assert_eq!(
        io.unregister_hosted_device_pointer(registration),
        Err(NtStatus::DEVICE_BUSY)
    );
    owner.registration = registration;
    owner.release(&mut io).unwrap();
    assert_eq!(io.device_reference_count(device), 1);
}

#[test]
fn projection_count_overflow_and_pending_delete_refuse_before_acquisition() {
    let (mut io, device, _, registration) = setup();
    let index = io.pointer_row_index(registration).unwrap();
    io.hosted_device_pointers.rows[index].projection_references = u64::MAX;
    assert!(matches!(
        io.retain_hosted_device_projection_reference(registration),
        Err(NtStatus::INSUFFICIENT_RESOURCES)
    ));
    assert_eq!(io.device_reference_count(device), 1);
    io.hosted_device_pointers.rows[index].projection_references = 0;
    let mut owner = io
        .retain_hosted_device_projection_reference(registration)
        .unwrap();
    assert_eq!(
        io.delete_device(device).err(),
        Some(NtStatus::DELETE_PENDING)
    );
    assert!(matches!(
        io.retain_hosted_device_projection_reference(registration),
        Err(NtStatus::DELETE_PENDING)
    ));
    assert_eq!(io.device_reference_count(device), 2);
    owner.release(&mut io).unwrap();
    io.retire_hosted_device_pointer(registration).unwrap();
}

#[test]
fn native_projection_retirement_retries_busy_before_freeing_projection() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../components/ntos-executive/src/driver_launch.rs"
    ));
    let start = source
        .find("unsafe fn drain_hosted_device_retirements()")
        .unwrap();
    let function = &source[start..];
    let end = function
        .find("\nfn clear_hosted_device_bindings_for_instance")
        .unwrap();
    let function = &function[..end];
    let retire = function
        .find("retire_hosted_device_pointer(registration)")
        .unwrap();
    let free = function
        .find("retire_hosted_device_projection(")
        .unwrap();
    let retry = function[retire..free]
        .find("Err(nt_status::NtStatus::DEVICE_BUSY)")
        .unwrap();
    let retry_body = &function[retire + retry..];
    let retry_end = retry_body.find("Err(status)").unwrap();
    assert!(retire < free);
    assert!(retry_body[..retry_end].contains("continue;"));
    assert!(!retry_body[..retry_end].contains("barrier_status"));
}
