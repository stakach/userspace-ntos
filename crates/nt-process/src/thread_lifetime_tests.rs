use super::*;

fn dormant() -> (ProcessManager, ProcessId, ThreadId) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("host.exe", None, None);
    pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let tid = pm.create_dormant_thread(pid).unwrap();
    (pm, pid, tid)
}

fn prepare(pm: &ProcessManager, tid: ThreadId) -> Result<ThreadActivationPlan, u32> {
    pm.prepare_thread_activation(tid, 0x4000, 0x55, true, 0x7000, 123, true)
}

#[test]
fn snapshot_is_read_only_and_distinguishes_threads_and_processes() {
    let (mut pm, pid, tid) = dormant();
    let snapshot = pm.thread_lifetime(tid).unwrap();
    assert_eq!(snapshot.thread_id(), tid);
    assert_eq!(snapshot.process_id(), pid);
    assert_eq!(snapshot.generation(), 1);
    assert!(pm.validate_thread_lifetime(snapshot));
    assert_eq!(pm.thread_lifetime(0), None);
    assert_eq!(pm.thread_lifetime(u32::MAX), None);
    let second = pm.create_dormant_thread(pid).unwrap();
    let other_pid = pm.create_process("other.exe", None, None);
    let other = pm.create_thread(other_pid, 0x1000, 0, false).unwrap();
    assert_ne!(pm.thread_lifetime(second), Some(snapshot));
    assert_ne!(pm.thread_lifetime(other), Some(snapshot));
    assert!(!pm.validate_thread_lifetime(ThreadLifetime {
        process_id: other_pid,
        ..snapshot
    }));
    let _ = prepare(&pm, tid).unwrap();
    assert_eq!(pm.thread_lifetime(tid), Some(snapshot));
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Initialized);
}

#[test]
fn activation_invalidates_prior_snapshot_without_changing_ethread_identity() {
    let (mut pm, _, tid) = dormant();
    let dormant = pm.thread_lifetime(tid).unwrap();
    let first = prepare(&pm, tid).unwrap();
    pm.commit_thread_activation(first).unwrap();
    let activated = pm.thread_lifetime(tid).unwrap();
    assert_eq!(activated.thread_id(), dormant.thread_id());
    assert_eq!(activated.process_id(), dormant.process_id());
    assert_eq!(activated.generation(), 2);
    assert!(!pm.validate_thread_lifetime(dormant));
    assert!(pm.validate_thread_lifetime(activated));
    pm.terminate_thread(tid, 0x1234).unwrap();
    assert!(pm.validate_thread_lifetime(activated));
    let second = prepare(&pm, tid).unwrap();
    pm.commit_thread_activation(second).unwrap();
    assert_eq!(pm.thread_lifetime(tid).unwrap().generation(), 3);
    assert!(!pm.validate_thread_lifetime(activated));
    assert_eq!(pm.commit_thread_activation(first), Err(STATUS_INVALID_PARAMETER));
}

#[test]
fn ordinary_thread_state_changes_do_not_change_lifetime() {
    let (mut pm, _, tid) = dormant();
    let plan = prepare(&pm, tid).unwrap();
    pm.commit_thread_activation(plan).unwrap();
    let snapshot = pm.thread_lifetime(tid).unwrap();
    pm.set_thread_state(tid, ThreadState::Waiting).unwrap();
    pm.set_thread_state(tid, ThreadState::Running).unwrap();
    assert!(pm.validate_thread_lifetime(snapshot));
    pm.terminate_thread(tid, 0).unwrap();
    assert!(pm.validate_thread_lifetime(snapshot));
}

#[test]
fn removed_thread_snapshot_is_stale_and_new_thread_does_not_reuse_it() {
    let (mut pm, pid, tid) = dormant();
    let snapshot = pm.thread_lifetime(tid).unwrap();
    assert!(pm.abort_process_creation(pid).is_some());
    assert!(!pm.validate_thread_lifetime(snapshot));
    assert_eq!(pm.thread_lifetime(tid), None);
    let new_pid = pm.create_process("replacement.exe", None, None);
    let new_tid = pm.create_thread(new_pid, 0x1000, 0, false).unwrap();
    assert_ne!(new_tid, tid);
    assert_ne!(pm.thread_lifetime(new_tid), Some(snapshot));
}

#[test]
fn generation_exhaustion_rejects_prepare_and_commit_before_any_publication() {
    let (mut pm, _, tid) = dormant();
    let mut plan = prepare(&pm, tid).unwrap();
    pm.threads.get_mut(&tid).unwrap().activation_generation = u64::MAX;
    plan.generation = u64::MAX;
    let before = pm.thread_lifetime(tid).unwrap();
    let descriptor = pm.thread(tid).unwrap().security_descriptor.clone();
    let descriptor_pointer = pm.thread(tid).unwrap().security_descriptor.as_ptr();
    assert_eq!(prepare(&pm, tid), Err(STATUS_INSUFFICIENT_RESOURCES));
    assert_eq!(
        pm.commit_thread_activation(plan),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(pm.thread_lifetime(tid), Some(before));
    let thread = pm.thread(tid).unwrap();
    assert_eq!(thread.state, ThreadState::Initialized);
    assert_eq!(thread.start_address, 0);
    assert_eq!(thread.parameter, 0);
    assert_eq!(thread.teb_base, 0);
    assert_eq!(thread.create_time_100ns, 0);
    assert_eq!(thread.suspend_count, 0);
    assert!(!thread.hide_from_debugger);
    assert_eq!(thread.security_descriptor, descriptor);
    assert_eq!(thread.security_descriptor.as_ptr(), descriptor_pointer);
}

#[test]
fn final_generation_can_be_published_but_never_wraps_on_later_activation() {
    let (mut pm, _, tid) = dormant();
    pm.threads.get_mut(&tid).unwrap().activation_generation = u64::MAX - 1;
    let before = pm.thread_lifetime(tid).unwrap();
    let plan = prepare(&pm, tid).unwrap();
    pm.commit_thread_activation(plan).unwrap();
    let final_lifetime = pm.thread_lifetime(tid).unwrap();
    assert_eq!(final_lifetime.generation(), u64::MAX);
    assert!(!pm.validate_thread_lifetime(before));
    pm.terminate_thread(tid, 0x1234).unwrap();
    assert_eq!(prepare(&pm, tid), Err(STATUS_INSUFFICIENT_RESOURCES));
    assert_eq!(pm.thread_lifetime(tid), Some(final_lifetime));
    assert_eq!(pm.thread(tid).unwrap().exit_status, Some(0x1234));
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Terminated);
}

#[test]
fn activation_rejection_preserves_lifetime_and_prepared_plan() {
    let (mut pm, pid, tid) = dormant();
    let before = pm.thread_lifetime(tid).unwrap();
    let plan = prepare(&pm, tid).unwrap();
    let handle = pm.insert_handle(pid, HandleObject::Thread(tid), THREAD_ALL_ACCESS).unwrap();
    assert_eq!(pm.commit_thread_activation(plan), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(pm.thread_lifetime(tid), Some(before));
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Initialized);
    pm.close_handle(pid, handle).unwrap();
    pm.commit_thread_activation(plan).unwrap();
    assert!(!pm.validate_thread_lifetime(before));
}
