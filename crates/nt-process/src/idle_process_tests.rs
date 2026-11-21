use super::*;

fn idle_manager(processors: u64) -> ProcessManager {
    let mut pm = ProcessManager::new_with_active_processor_count(processors).unwrap();
    pm.create_idle_process().unwrap();
    pm
}

#[test]
fn idle_process_is_pid_zero_named_idle_with_one_thread_per_processor() {
    let pm = idle_manager(3);
    assert_eq!(pm.active_processor_count(), 3);
    let idle = pm.idle_process().unwrap();
    assert_eq!(idle.process_id(), 0);
    assert_eq!(idle.image_file_name(), "Idle");
    assert_eq!(idle.session_id(), 0);
    assert_eq!(idle.thread_count(), 3);
    assert_eq!(idle.kernel_object(), None);
    let threads: Vec<_> = pm.idle_threads().collect();
    assert_eq!(threads.len(), 3);
    for (processor, thread) in threads.iter().enumerate() {
        // KPRCB->IdleThread never receives a CID, on any processor.
        assert_eq!(thread.processor(), processor as u32);
        assert_eq!((thread.process_id(), thread.thread_id()), (0, 0));
        assert_eq!(thread.teb_base(), 0);
        assert_eq!(pm.idle_thread(processor as u32), Some(*thread));
    }
    assert_eq!(pm.idle_thread(3), None);
}

#[test]
fn default_manager_has_one_processor_and_idle_is_created_once() {
    let mut pm = ProcessManager::new();
    assert_eq!(pm.active_processor_count(), 1);
    assert!(pm.idle_process().is_none());
    assert_eq!(pm.idle_threads().count(), 0);
    pm.create_idle_process().unwrap();
    assert_eq!(pm.idle_process().unwrap().thread_count(), 1);
    assert_eq!(pm.create_idle_process(), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(pm.idle_process().unwrap().thread_count(), 1);
}

#[test]
fn idle_objects_are_outside_the_cid_table_and_cannot_be_scheduled_or_terminated() {
    let mut pm = idle_manager(2);
    let system = pm.create_process("System", None, None);
    let system_thread = pm.create_thread(system, 0x1000, 0, true).unwrap();
    // Allocated CIDs never collide with the Idle process's unallocated zero.
    assert_ne!(system, 0);
    assert_ne!(system_thread, 0);
    assert_eq!(pm.process_count(), 1);
    assert!(pm.process(0).is_none());
    assert!(pm.thread(0).is_none());
    assert_eq!(pm.set_thread_state(0, ThreadState::Running), Err(STATUS_INVALID_HANDLE));
    assert!(pm.suspend_thread(0).is_err());
    assert!(pm.terminate_thread(0, 1).is_err());
    assert!(pm.terminate_process(0, 1).is_err());
    assert!(pm.lookup_kernel_process_by_id(0).is_err());
    assert!(pm.lookup_kernel_thread_by_id(0).is_err());
    let open_process = ClientId { unique_process: 0, unique_thread: 0 };
    assert!(pm.open_process_by_client_id(system, open_process, PROCESS_ALL_ACCESS).is_err());
    assert!(pm.open_thread_by_client_id(system, open_process, THREAD_ALL_ACCESS).is_err());
    assert_eq!(pm.idle_process().unwrap().thread_count(), 2);
}

#[test]
fn idle_bodies_publish_atomically_once_and_own_their_addresses() {
    let mut pm = idle_manager(2);
    let process = pm.create_process("first.exe", None, None);
    let thread = pm.create_thread(process, 0x1000, 0, false).unwrap();
    assert!(pm.publish_process_kernel_object(process, 0x9000));
    // A count, duplicate, zero or foreign body is refused with nothing published.
    for threads in [&[0x2000][..], &[0x2000, 0x2000], &[0x2000, 0], &[0x2000, 0x9000],
        &[0x1000, 0x2000], &[0x2000, 0x3000, 0x4000]]
    {
        assert!(!pm.publish_idle_kernel_objects(0x1000, threads), "{threads:x?}");
        assert_eq!(pm.idle_process().unwrap().kernel_object(), None);
        assert!(pm.idle_threads().all(|thread| thread.kernel_object().is_none()));
    }
    assert!(!pm.publish_idle_kernel_objects(0x9000, &[0x2000, 0x3000]));
    assert!(!pm.publish_idle_kernel_objects(0, &[0x2000, 0x3000]));
    assert!(pm.publish_idle_kernel_objects(0x1000, &[0x2000, 0x3000]));
    assert!(pm.publish_idle_kernel_objects(0x1000, &[0x2000, 0x3000]), "identical is idempotent");
    assert!(!pm.publish_idle_kernel_objects(0x1000, &[0x3000, 0x2000]));
    assert_eq!(pm.idle_process().unwrap().kernel_object(), Some(0x1000));
    assert_eq!(pm.idle_thread(0).unwrap().kernel_object(), Some(0x2000));
    assert_eq!(pm.idle_thread(1).unwrap().kernel_object(), Some(0x3000));
    for body in [0x1000, 0x2000, 0x3000] {
        assert!(pm.is_idle_kernel_object(body));
        assert!(!pm.publish_thread_kernel_object(thread, body));
        assert!(!pm.publish_process_kernel_object(process, body));
    }
    assert!(!pm.is_idle_kernel_object(0x9000));
    assert!(!pm.is_idle_kernel_object(0));
    // Idle bodies are not CID-table objects: no reverse map, no counted pointer references.
    assert_eq!(pm.pid_for_kernel_process_object(0x1000), None);
    assert_eq!(pm.tid_for_kernel_thread_object(0x2000), None);
}

#[test]
fn idle_bodies_cannot_be_published_before_the_idle_process_exists() {
    let mut pm = ProcessManager::new();
    assert!(!pm.publish_idle_kernel_objects(0x1000, &[0x2000]));
}
