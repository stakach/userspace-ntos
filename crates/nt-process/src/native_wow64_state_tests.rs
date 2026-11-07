use crate::{ProcessManager, STATUS_INVALID_HANDLE, STATUS_INVALID_IMAGE_FORMAT};
use nt_driver_test_fixtures::{minimal_pe, DEFAULT_IMAGE_BASE};
use nt_pe_loader::PeFile;

#[test]
fn wow64_pointer_requires_validated_image_and_exact_live_process_body() {
    let image = minimal_pe();
    let parsed = PeFile::parse(&image).unwrap();
    let mut manager = ProcessManager::new();
    let first = manager.create_process("first.exe", None, None);
    let second = manager.create_process("second.exe", None, None);
    assert!(manager.publish_process_kernel_object(first, 0x1000));
    assert!(manager.publish_process_kernel_object(second, 0x2000));

    assert_eq!(manager.process_wow64_pointer(first), Err(STATUS_INVALID_IMAGE_FORMAT));
    assert_eq!(
        manager.wow64_pointer_for_kernel_process_object(0x1000),
        Err(STATUS_INVALID_IMAGE_FORMAT)
    );
    assert_eq!(
        manager.wow64_pointer_for_kernel_process_object(0xDEAD),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(manager.admit_validated_process_image(first, &parsed), Ok(()));
    assert_eq!(manager.process_wow64_pointer(first), Ok(0));
    assert_eq!(manager.wow64_pointer_for_kernel_process_object(0x1000), Ok(0));
    assert_eq!(manager.process_wow64_pointer(second), Err(STATUS_INVALID_IMAGE_FORMAT));
    assert_eq!(
        manager.wow64_pointer_for_kernel_process_object(0x2000),
        Err(STATUS_INVALID_IMAGE_FORMAT)
    );
    assert_eq!(manager.admit_validated_process_image(first, &parsed), Ok(()));
    assert_eq!(manager.admit_validated_process_image(9999, &parsed), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn image_section_process_inherits_validated_amd64_machine_proof() {
    let image = minimal_pe();
    let mut manager = ProcessManager::new();
    let section = manager
        .create_image_section("section.exe", &image, DEFAULT_IMAGE_BASE)
        .unwrap();
    let process = manager.create_process("section.exe", None, Some(section));
    assert_eq!(manager.process_wow64_pointer(process), Ok(0));
}

#[test]
fn designated_initial_system_has_native_kernel_architecture_proof() {
    let mut manager = ProcessManager::new();
    let system = manager.create_process("System", None, None);
    let thread = manager.create_thread(system, 0, 0, true).unwrap();
    assert_eq!(manager.process_wow64_pointer(system), Err(STATUS_INVALID_IMAGE_FORMAT));
    manager.designate_initial_system(system, thread).unwrap();
    assert_eq!(manager.process_wow64_pointer(system), Ok(0));
}
