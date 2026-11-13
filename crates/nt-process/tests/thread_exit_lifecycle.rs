use nt_process::{ClientId, HandleObject, ProcessManager, ProcessState, ThreadState, THREAD_ALL_ACCESS};

#[test]
fn undelivered_system_thread_handle_can_close_without_terminating_worker() {
    let mut pm = ProcessManager::new();
    let system = pm.create_process("System", None, None);
    let creator = pm.create_process("driver-host", None, None);
    let tid = pm.create_thread(system, 0x1000, 0, true).unwrap();
    let handle = pm.open_thread_by_client_id(
        creator,
        ClientId { unique_process: system, unique_thread: tid },
        THREAD_ALL_ACCESS,
    ).unwrap();
    assert_eq!(pm.lookup_handle(creator, handle), Some(HandleObject::Thread(tid)));
    pm.close_handle(creator, handle).unwrap();
    assert_eq!(pm.lookup_handle(creator, handle), None);
    assert!(!pm.is_thread_signaled(tid));
    pm.terminate_thread(tid, 0x1234).unwrap();
    assert!(pm.is_thread_signaled(tid));
}

#[test]
fn accepted_suspended_peer_keeps_process_alive_after_initial_thread_exit() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("arbitrary.exe", None, None);
    let initial = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let peer = pm.create_thread(pid, 0x2000, 0, false).unwrap();
    pm.suspend_thread(peer).unwrap();
    assert_eq!(pm.thread(peer).unwrap().state, ThreadState::Suspended);
    pm.terminate_thread_at(initial, 0x1234, 100).unwrap();
    assert!(pm.is_thread_signaled(initial));
    assert!(!pm.is_process_signaled(pid));
    assert_eq!(pm.process(pid).unwrap().state, ProcessState::Running);
    pm.terminate_thread_at(peer, 0x5678, 200).unwrap();
    assert!(pm.is_process_signaled(pid));
    assert_eq!(pm.wait_process(pid), Some(0x5678));
}

#[test]
fn unadmitted_dormant_pool_identity_does_not_prevent_last_active_thread_exit() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("arbitrary.exe", None, None);
    let active = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let dormant = pm.create_dormant_thread(pid).unwrap();
    assert_eq!(pm.thread(dormant).unwrap().state, ThreadState::Initialized);
    pm.terminate_thread_at(active, 0x1234, 100).unwrap();
    assert!(pm.is_process_signaled(pid));
    assert!(pm.is_thread_signaled(dormant));
}
