use super::*;

fn objects() -> (ProcessManager, [ProcessId; 2], [ThreadId; 2]) {
    let mut pm = ProcessManager::new();
    let first = pm.create_process("first.exe", None, None);
    let second = pm.create_process("second.exe", None, None);
    let first_thread = pm.create_thread(first, 0x1000, 0, false).unwrap();
    let second_thread = pm.create_thread(second, 0x2000, 0, false).unwrap();
    (pm, [first, second], [first_thread, second_thread])
}

#[test]
fn distinct_processes_cannot_publish_the_same_body() {
    let (mut pm, [first, second], _) = objects();
    assert!(pm.publish_process_kernel_object(first, 0x1000));
    assert!(pm.publish_process_kernel_object(first, 0x1000));
    assert!(!pm.publish_process_kernel_object(second, 0x1000));
    assert_eq!(pm.process_kernel_object(second), None);
    assert_eq!(pm.pid_for_kernel_process_object(0x1000), Some(first));
    assert_eq!(pm.lookup_kernel_process_by_id(first), Ok((0x1000, 1)));
    assert_eq!(pm.process(first).unwrap().kernel_pointer_references, 1);
    assert_eq!(pm.process(second).unwrap().kernel_pointer_references, 0);
    assert!(pm.publish_process_kernel_object(second, 0x2000));
    assert!(!pm.publish_process_kernel_object(second, 0x1000));
    assert_eq!(pm.process_kernel_object(second), Some(0x2000));
}

#[test]
fn distinct_threads_cannot_publish_the_same_body() {
    let (mut pm, _, [first, second]) = objects();
    assert!(pm.publish_thread_kernel_object(first, 0x1000));
    assert!(pm.publish_thread_kernel_object(first, 0x1000));
    assert!(!pm.publish_thread_kernel_object(second, 0x1000));
    assert_eq!(pm.thread_kernel_object(second), None);
    assert_eq!(pm.tid_for_kernel_thread_object(0x1000), Some(first));
    assert_eq!(pm.lookup_kernel_thread_by_id(first), Ok((0x1000, 1)));
    assert_eq!(pm.thread(first).unwrap().kernel_pointer_references, 1);
    assert_eq!(pm.thread(second).unwrap().kernel_pointer_references, 0);
    assert!(pm.publish_thread_kernel_object(second, 0x2000));
    assert!(!pm.publish_thread_kernel_object(second, 0x1000));
    assert_eq!(pm.thread_kernel_object(second), Some(0x2000));
}

#[test]
fn process_and_thread_bodies_share_one_pointer_namespace() {
    let (mut pm, [first, second], [first_thread, second_thread]) = objects();
    assert!(pm.publish_process_kernel_object(first, 0x1000));
    assert!(!pm.publish_thread_kernel_object(first_thread, 0x1000));
    assert!(!pm.publish_thread_kernel_object(second_thread, 0x1000));
    assert!(pm.publish_thread_kernel_object(first_thread, 0x2000));
    assert!(!pm.publish_process_kernel_object(second, 0x2000));
    assert!(!pm.publish_process_kernel_object(first, 0x2000));
    assert_eq!(pm.tid_for_kernel_thread_object(0x1000), None);
    assert_eq!(pm.pid_for_kernel_process_object(0x2000), None);
    assert_eq!(pm.retain_kernel_object_pointer(0x1000), Ok(1));
    assert_eq!(pm.retain_kernel_object_pointer(0x2000), Ok(1));
    assert_eq!(pm.process_kernel_object(second), None);
    assert_eq!(pm.thread_kernel_object(second_thread), None);
}

#[test]
fn terminated_referenced_objects_keep_body_ownership_until_actual_deletion() {
    let (mut pm, [first, second], [first_thread, second_thread]) = objects();
    assert!(pm.publish_process_kernel_object(first, 0x1000));
    assert!(pm.publish_thread_kernel_object(first_thread, 0x2000));
    pm.retain_kernel_object_pointer(0x1000).unwrap();
    pm.terminate_process(first, 0).unwrap();
    assert!(!pm.publish_process_kernel_object(second, 0x1000));
    assert!(!pm.publish_thread_kernel_object(second_thread, 0x2000));
    assert!(pm.delete_process_object_if_unreferenced(first).is_none());
    assert_eq!(pm.release_kernel_object_pointer(0x1000), Ok(0));
    assert!(pm.delete_process_object_if_unreferenced(first).is_some());
    assert!(pm.publish_process_kernel_object(second, 0x1000));
    assert!(pm.publish_thread_kernel_object(second_thread, 0x2000));
    assert_eq!(pm.pid_for_kernel_process_object(0x1000), Some(second));
    assert_eq!(pm.tid_for_kernel_thread_object(0x2000), Some(second_thread));
}

#[test]
fn initial_system_body_cannot_be_alias_published_by_other_objects() {
    let (mut pm, [first, second], [first_thread, second_thread]) = objects();
    pm.threads.get_mut(&first_thread).unwrap().is_system_thread = true;
    let identity = pm.designate_initial_system(first, first_thread).unwrap();
    assert!(pm.publish_process_kernel_object(first, 0x1000));
    assert!(pm.publish_thread_kernel_object(first_thread, 0x2000));
    assert!(!pm.publish_process_kernel_object(second, 0x1000));
    assert!(!pm.publish_process_kernel_object(second, 0x2000));
    assert!(!pm.publish_thread_kernel_object(second_thread, 0x1000));
    assert!(!pm.publish_thread_kernel_object(second_thread, 0x2000));
    assert_eq!(pm.initial_system_identity(), Some(identity));
    assert!(pm.is_initial_system_process(pm.pid_for_kernel_process_object(0x1000).unwrap()));
    assert_eq!(
        pm.release_kernel_object_pointer(0x1000),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.release_kernel_object_pointer(0x2000),
        Err(STATUS_INVALID_PARAMETER)
    );
}
