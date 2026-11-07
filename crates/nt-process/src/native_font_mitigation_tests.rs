use crate::{ProcessManager, STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS};

#[test]
fn font_mitigation_flags_require_exact_process_body_and_selector_nine() {
    let mut manager = ProcessManager::new();
    let first = manager.create_process("first.exe", None, None);
    let second = manager.create_process("second.exe", None, None);
    assert!(manager.publish_process_kernel_object(first, 0x1000));
    assert!(manager.publish_process_kernel_object(second, 0x2000));

    // Neither process supplied an accepted ProcessFontDisablePolicy input at creation.
    assert_eq!(manager.process_mitigation_policy_flags_by_kernel_object(0x1000, 9), Ok(0));
    assert_eq!(manager.process_mitigation_policy_flags_by_kernel_object(0x2000, 9), Ok(0));
    assert_eq!(
        manager.process_mitigation_policy_flags_by_kernel_object(0x1000, 8),
        Err(STATUS_INVALID_INFO_CLASS)
    );
    assert_eq!(
        manager.process_mitigation_policy_flags_by_kernel_object(0xDEAD, 9),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        manager.process_mitigation_policy_flags_by_kernel_object(0, 9),
        Err(STATUS_INVALID_HANDLE)
    );
}
