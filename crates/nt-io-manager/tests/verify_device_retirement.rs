use nt_io_manager::verify_device_retirement::{ThreadVerifyIdentity, VerifyDeviceBindings};
use nt_io_manager::{
    DeviceCharacteristics, DeviceFlags, DeviceType, IoManager, MockDriverBackend, MockObjectPort,
};
use nt_types::NtPath;

fn path(value: &str) -> NtPath { NtPath::parse_str(value).unwrap() }

#[test]
fn verify_device_ledger_clears_only_the_exact_registration_and_thread_incarnation() {
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io.create_driver(&path("\\Driver\\Verify"), Box::new(MockDriverBackend::new())).unwrap();
    let one = io.create_device(driver, Some(&path("\\Device\\One")), DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(), DeviceFlags::BUFFERED_IO, 0).unwrap();
    let two = io.create_device(driver, Some(&path("\\Device\\Two")), DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(), DeviceFlags::BUFFERED_IO, 0).unwrap();
    let first_domain = io.register_hosted_domain();
    let second_domain = io.register_hosted_domain();
    let first = io.bind_hosted_device_pointer(first_domain, 0x4000, one).unwrap();
    let second = io.bind_hosted_device_pointer(second_domain, 0x4000, two).unwrap();
    let thread = ThreadVerifyIdentity { body: 0x3000, process_id: 1, thread_id: 2, generation: 7 };
    let other = ThreadVerifyIdentity { body: 0x5000, process_id: 1, thread_id: 3, generation: 9 };
    let mut bindings = VerifyDeviceBindings::new();
    bindings.reserve_write(thread, Some(first)).unwrap();
    bindings.commit_write(thread, Some(first));
    bindings.reserve_write(other, Some(second)).unwrap();
    bindings.commit_write(other, Some(second));
    assert_eq!(bindings.next_for_retirement(first), Some(thread));
    assert_eq!(bindings.next_for_retirement(second), Some(other));
    assert!(!bindings.forget_exact(thread, second));
    assert!(bindings.forget_exact(thread, first));
    assert_eq!(bindings.next_for_retirement(first), None);
    assert_eq!(bindings.next_for_retirement(second), Some(other));

    // A new activation at the same ETHREAD address cannot inherit a former device binding.
    let next = ThreadVerifyIdentity { generation: 8, ..thread };
    bindings.reserve_write(next, Some(second)).unwrap();
    bindings.commit_write(next, Some(second));
    assert_eq!(bindings.next_for_retirement(second), Some(other));
    assert!(!bindings.forget_exact(thread, first));
    bindings.forget_thread(next);
    assert_eq!(bindings.next_for_retirement(second), Some(other));
    assert!(bindings.forget_exact(other, second));
    assert_eq!(bindings.next_for_retirement(second), None);
}
