use crate::{ProcessManager, STATUS_INVALID_HANDLE, STATUS_INVALID_IMAGE_FORMAT};
use nt_driver_test_fixtures::minimal_pe;
use nt_pe_loader::PeFile;

#[test]
fn process_peb_queries_require_exact_published_body_and_peb32_architecture_proof() {
    let image = minimal_pe();
    let parsed = PeFile::parse(&image).unwrap();
    let mut manager = ProcessManager::new();
    let first = manager.create_process("first.exe", None, None);
    let second = manager.create_process("second.exe", None, None);
    assert!(manager.set_peb_base(first, 0x70_0000));
    assert!(manager.set_peb_base(second, 0x80_0000));
    assert!(manager.publish_process_kernel_object(first, 0x1000));
    assert!(manager.publish_process_kernel_object(second, 0x2000));

    assert_eq!(manager.peb_for_kernel_process_object(0x1000), Ok(0x70_0000));
    assert_eq!(manager.peb_for_kernel_process_object(0x2000), Ok(0x80_0000));
    assert_eq!(manager.peb_for_kernel_process_object(0xDEAD), Err(STATUS_INVALID_HANDLE));
    assert_eq!(manager.peb32_for_kernel_process_object(0x1000), Err(STATUS_INVALID_IMAGE_FORMAT));
    assert_eq!(manager.admit_validated_process_image(first, &parsed), Ok(()));
    assert_eq!(manager.peb32_for_kernel_process_object(0x1000), Ok(0));
    assert_eq!(manager.peb32_for_kernel_process_object(0x2000), Err(STATUS_INVALID_IMAGE_FORMAT));
    assert_eq!(manager.peb32_for_kernel_process_object(0xDEAD), Err(STATUS_INVALID_HANDLE));

    let mut bootstrap = ProcessManager::new();
    let system = bootstrap.create_process("System", None, None);
    let thread = bootstrap.create_thread(system, 0, 0, true).unwrap();
    bootstrap.designate_initial_system(system, thread).unwrap();
    assert!(bootstrap.publish_process_kernel_object(system, 0x3000));
    assert_eq!(bootstrap.peb_for_kernel_process_object(0x3000), Ok(0));
    assert_eq!(bootstrap.peb32_for_kernel_process_object(0x3000), Ok(0));
}
