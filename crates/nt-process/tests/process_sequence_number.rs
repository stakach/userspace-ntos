use nt_process::{ProcessManager, STATUS_INVALID_HANDLE};

#[test]
fn sequence_numbers_follow_creation_and_remain_stable_through_thread_creation() {
    let mut pm = ProcessManager::new();
    let first = pm.create_process("first.exe", None, None);
    let second = pm.create_process("second.exe", None, None);
    assert!(pm.publish_process_kernel_object(first, 0x1000));
    assert!(pm.publish_process_kernel_object(second, 0x2000));

    let first_sequence = pm.process_sequence_for_kernel_process_object(0x1000).unwrap();
    let second_sequence = pm.process_sequence_for_kernel_process_object(0x2000).unwrap();
    assert!(first_sequence != 0 && first_sequence < second_sequence);

    pm.create_thread(first, 0x4000, 0, false).unwrap();
    assert_eq!(
        pm.process_sequence_for_kernel_process_object(0x1000),
        Ok(first_sequence)
    );
    assert_eq!(
        pm.process_sequence_for_kernel_process_object(0x2000),
        Ok(second_sequence)
    );
    assert_eq!(
        pm.process_sequence_for_kernel_process_object(u64::from(first)),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.process_sequence_for_kernel_process_object(0),
        Err(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn withdrawn_eprocess_cannot_expose_or_reuse_its_creation_sequence() {
    let mut pm = ProcessManager::new();
    let withdrawn = pm.create_process("withdrawn.exe", None, None);
    assert!(pm.publish_process_kernel_object(withdrawn, 0x3000));
    let old_sequence = pm.process_sequence_for_kernel_process_object(0x3000).unwrap();

    assert!(pm.abort_process_creation(withdrawn).is_some());
    assert_eq!(
        pm.process_sequence_for_kernel_process_object(0x3000),
        Err(STATUS_INVALID_HANDLE)
    );

    let next = pm.create_process("next.exe", None, None);
    assert!(pm.publish_process_kernel_object(next, 0x3000));
    let next_sequence = pm.process_sequence_for_kernel_process_object(0x3000).unwrap();
    assert!(next_sequence > old_sequence);
}
