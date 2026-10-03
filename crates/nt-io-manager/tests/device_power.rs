use nt_io_manager::{DeviceCharacteristics, DeviceFlags, DeviceId, DeviceType, DriverId,
    IoManager, MockDriverBackend, MockObjectPort};
use nt_io_manager::device_power::{DevicePowerState, SystemPowerState};
use nt_status::NtStatus;
use nt_types::NtPath;

fn fixture() -> (IoManager<MockObjectPort>, DriverId) {
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io.create_driver(&NtPath::parse_str(r"\Driver\Power").unwrap(),
        Box::new(MockDriverBackend::new())).unwrap();
    (io, driver)
}

fn device(io: &mut IoManager<MockObjectPort>, driver: DriverId) -> DeviceId {
    io.create_device(driver, None, DeviceType::UNKNOWN, DeviceCharacteristics::empty(),
        DeviceFlags::empty(), 0).unwrap()
}

#[test]
fn object_states_initialize_unspecified_and_return_exact_old_values_without_irps() {
    let (mut io, driver) = fixture();
    let object = device(&mut io, driver);
    assert_eq!(io.device_power_state(object), Ok(DevicePowerState::Unspecified));
    assert_eq!(io.system_power_state(object), Ok(SystemPowerState::Unspecified));
    assert_eq!(io.report_device_power_state(object, DevicePowerState::D3),
        Ok(DevicePowerState::Unspecified));
    assert_eq!(io.report_device_power_state(object, DevicePowerState::D0), Ok(DevicePowerState::D3));
    assert_eq!(io.report_device_power_state(object, DevicePowerState::D0), Ok(DevicePowerState::D0));
    assert_eq!(io.report_system_power_state(object, SystemPowerState::Sleeping3),
        Ok(SystemPowerState::Unspecified));
    assert_eq!(io.report_system_power_state(object, SystemPowerState::Working),
        Ok(SystemPowerState::Sleeping3));
    assert_eq!(io.device_power_state(object), Ok(DevicePowerState::D0));
}

#[test]
fn attached_objects_do_not_share_reported_power_states() {
    let (mut io, driver) = fixture();
    let pdo = device(&mut io, driver);
    let fdo = device(&mut io, driver);
    io.attach_device_to_stack(fdo, pdo).unwrap();
    assert_eq!(io.report_device_power_state(pdo, DevicePowerState::D0),
        Ok(DevicePowerState::Unspecified));
    assert_eq!(io.report_device_power_state(fdo, DevicePowerState::D3),
        Ok(DevicePowerState::Unspecified));
    assert_eq!(io.device_power_state(pdo), Ok(DevicePowerState::D0));
    assert_eq!(io.device_power_state(fdo), Ok(DevicePowerState::D3));
    io.report_system_power_state(pdo, SystemPowerState::Working).unwrap();
    assert_eq!(io.system_power_state(fdo), Ok(SystemPowerState::Unspecified));
}

#[test]
fn invalid_and_retiring_targets_have_no_state_effect() {
    let (mut io, driver) = fixture();
    let object = device(&mut io, driver);
    assert_eq!(io.report_device_power_state(object, DevicePowerState::Maximum),
        Err(NtStatus::INVALID_PARAMETER));
    assert_eq!(io.report_system_power_state(object, SystemPowerState::Maximum),
        Err(NtStatus::INVALID_PARAMETER));
    assert_eq!(io.device_power_state(object), Ok(DevicePowerState::Unspecified));
    io.device_mut(object).unwrap().delete_pending = true;
    assert_eq!(io.report_device_power_state(object, DevicePowerState::D0),
        Err(NtStatus::DELETE_PENDING));
    assert_eq!(io.report_system_power_state(object, SystemPowerState::Working),
        Err(NtStatus::DELETE_PENDING));
}

#[test]
fn deletion_and_slot_reuse_do_not_inherit_a_previous_object_state() {
    let (mut io, driver) = fixture();
    let old = device(&mut io, driver);
    io.report_device_power_state(old, DevicePowerState::D2).unwrap();
    io.delete_device(old).unwrap();
    let new = device(&mut io, driver);
    assert_ne!(old, new);
    assert_eq!(io.report_device_power_state(old, DevicePowerState::D0),
        Err(NtStatus::INVALID_PARAMETER));
    assert_eq!(io.device_power_state(new), Ok(DevicePowerState::Unspecified));
    assert_eq!(io.report_device_power_state(new, DevicePowerState::D1),
        Ok(DevicePowerState::Unspecified));
}

#[test]
fn producer_and_upper_stack_projections_share_only_the_exact_pdo_state() {
    let (mut io, driver) = fixture();
    let pdo = device(&mut io, driver);
    let fdo = device(&mut io, driver);
    io.attach_device_to_stack(fdo, pdo).unwrap();
    let producer = io.register_hosted_domain();
    let upper = io.register_hosted_domain();
    io.bind_hosted_device_pointer(producer, 0x1000, pdo).unwrap();
    io.bind_hosted_device_pointer(upper, 0x2000, pdo).unwrap();
    io.bind_hosted_device_pointer(upper, 0x3000, fdo).unwrap();
    assert_eq!(io.hosted_power_report_target(producer, 0x1000), Ok(pdo));
    assert_eq!(io.hosted_power_report_target(upper, 0x2000), Ok(pdo));
    let target = io.hosted_power_report_target(producer, 0x1000).unwrap();
    assert_eq!(io.report_device_power_state(target, DevicePowerState::D0),
        Ok(DevicePowerState::Unspecified));
    let target = io.hosted_power_report_target(upper, 0x2000).unwrap();
    assert_eq!(io.report_device_power_state(target, DevicePowerState::D3), Ok(DevicePowerState::D0));
    assert_eq!(io.device_power_state(fdo), Ok(DevicePowerState::Unspecified));
}

#[test]
fn power_projection_requires_a_live_exact_registration_and_device() {
    let (mut io, driver) = fixture();
    let object = device(&mut io, driver);
    let domain = io.register_hosted_domain();
    io.bind_hosted_device_identity(domain, 0x1000, object).unwrap();
    assert_eq!(io.hosted_power_report_target(domain, 0x1000), Err(NtStatus::ACCESS_DENIED));
    let registration = io.register_hosted_device_pointer(domain, 0x1000).unwrap();
    assert_eq!(io.hosted_power_report_target(domain, 0x1000), Ok(object));
    let stale = nt_io_manager::HostedDomainIdentity { cookie: domain.cookie + 1, ..domain };
    assert_eq!(io.hosted_power_report_target(stale, 0x1000), Err(NtStatus::ACCESS_DENIED));
    assert_eq!(io.hosted_power_report_target(domain, 0x2000), Err(NtStatus::ACCESS_DENIED));
    io.device_mut(object).unwrap().delete_pending = true;
    assert_eq!(io.hosted_power_report_target(domain, 0x1000), Err(NtStatus::DELETE_PENDING));
    io.device_mut(object).unwrap().delete_pending = false;
    io.unregister_hosted_device_pointer(registration).unwrap();
    assert_eq!(io.hosted_power_report_target(domain, 0x1000), Err(NtStatus::ACCESS_DENIED));
}
