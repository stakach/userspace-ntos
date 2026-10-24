use nt_process::{
    ProcessManager, PROCESS_PRIORITY_CLASS_HIGH, PROCESS_PRIORITY_CLASS_NORMAL,
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
};

#[test]
fn native_priority_class_uses_exact_live_process_body_and_changes_class_only() {
    let mut pm = ProcessManager::new();
    let first = pm.create_process("first.exe", None, None);
    let second = pm.create_process("second.exe", None, None);
    assert!(pm.publish_process_kernel_object(first, 0x1000));
    assert!(pm.publish_process_kernel_object(second, 0x2000));
    let original_base_priority = pm.process(first).unwrap().base_priority();

    assert_eq!(pm.priority_class_for_kernel_process_object(0x1000), Ok(PROCESS_PRIORITY_CLASS_NORMAL));
    assert_eq!(pm.priority_class_for_kernel_process_object(0x2000), Ok(PROCESS_PRIORITY_CLASS_NORMAL));
    assert_eq!(pm.set_priority_class_for_kernel_process_object(0x1000, PROCESS_PRIORITY_CLASS_HIGH), Ok(()));
    assert_eq!(pm.priority_class_for_kernel_process_object(0x1000), Ok(PROCESS_PRIORITY_CLASS_HIGH));
    assert_eq!(pm.priority_class_for_kernel_process_object(0x2000), Ok(PROCESS_PRIORITY_CLASS_NORMAL));
    assert_eq!(pm.process(first).unwrap().base_priority(), original_base_priority);
    assert!(!pm.process(first).unwrap().foreground());

    assert_eq!(pm.set_priority_class_for_kernel_process_object(0x1000, u8::MAX), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(pm.priority_class_for_kernel_process_object(0x1000), Ok(PROCESS_PRIORITY_CLASS_HIGH));
    assert_eq!(pm.priority_class_for_kernel_process_object(0xDEAD), Err(STATUS_INVALID_HANDLE));
    assert_eq!(pm.set_priority_class_for_kernel_process_object(0xDEAD, PROCESS_PRIORITY_CLASS_HIGH), Err(STATUS_INVALID_HANDLE));

    assert!(pm.abort_process_creation(first).is_some());
    assert_eq!(pm.priority_class_for_kernel_process_object(0x1000), Err(STATUS_INVALID_HANDLE));
    assert_eq!(pm.set_priority_class_for_kernel_process_object(0x1000, PROCESS_PRIORITY_CLASS_HIGH), Err(STATUS_INVALID_HANDLE));
}
