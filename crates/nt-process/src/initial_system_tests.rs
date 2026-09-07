use super::*;

fn bootstrap_objects() -> (ProcessManager, ProcessId, ThreadId) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("bootstrap-root", None, None);
    let tid = pm.create_thread(pid, 0, 0, true).unwrap();
    (pm, pid, tid)
}

fn references(pm: &ProcessManager, pid: ProcessId, tid: ThreadId) -> (u32, u32) {
    (
        pm.process(pid).unwrap().kernel_pointer_references,
        pm.thread(tid).unwrap().kernel_pointer_references,
    )
}

#[test]
fn designation_is_explicit_and_not_a_fixed_pid_name_or_token_subject() {
    let mut pm = ProcessManager::new();
    let named = pm.create_process("System", None, None);
    let named_thread = pm.create_thread(named, 0, 0, false).unwrap();
    let mut tokens = nt_security::TokenStore::new();
    let system_token = tokens.insert(nt_security::AccessToken::system());
    pm.replace_process_primary_token(named, Some(system_token))
        .unwrap();
    assert_eq!(pm.initial_system_identity(), None);
    assert!(!pm.is_initial_system_process(named));
    assert_eq!(
        pm.designate_initial_system(named, named_thread),
        Err(STATUS_INVALID_PARAMETER)
    );

    let pid = pm.create_process("kernel-bootstrap", None, None);
    let tid = pm.create_thread(pid, 0, 0, true).unwrap();
    let identity = pm.designate_initial_system(pid, tid).unwrap();
    assert_ne!(pid, crate::FIRST_CLIENT_ID);
    assert_eq!(identity.process_id(), pid);
    assert_eq!(identity.thread_id(), tid);
    assert_eq!(identity.thread(), pm.thread_lifetime(tid).unwrap());
    assert_eq!(pm.initial_system_identity(), Some(identity));
    assert!(pm.is_initial_system_process(pid));
    assert!(!pm.is_initial_system_process(named));
    assert_eq!(references(&pm, pid, tid), (1, 1));
    assert_eq!(pm.process(pid).unwrap().kernel_process_object, None);
    assert_eq!(pm.thread(tid).unwrap().kernel_thread_object, None);
    assert_eq!(pm.process(pid).unwrap().peb_base_address, 0);
    assert_eq!(pm.thread(tid).unwrap().teb_base, 0);
}

#[test]
fn repeated_designation_preserves_existing_identity_counts_and_allocation_state() {
    let (mut pm, pid, tid) = bootstrap_objects();
    let identity = pm.designate_initial_system(pid, tid).unwrap();
    let other_pid = pm.create_process("another", None, None);
    let other_tid = pm.create_thread(other_pid, 0, 0, true).unwrap();
    let next = pm.next_cid;
    for (requested_pid, requested_tid) in [(pid, tid), (other_pid, other_tid), (0, 0)] {
        assert_eq!(
            pm.designate_initial_system(requested_pid, requested_tid),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(pm.initial_system_identity(), Some(identity));
        assert_eq!(references(&pm, pid, tid), (1, 1));
        assert_eq!(references(&pm, other_pid, other_tid), (0, 0));
        assert_eq!(pm.next_cid, next);
    }
}

#[test]
fn moving_manager_preserves_designation_and_root_references() {
    let (mut pm, pid, tid) = bootstrap_objects();
    let identity = pm.designate_initial_system(pid, tid).unwrap();
    let mut moved = alloc::boxed::Box::new(pm);
    assert_eq!(moved.initial_system_identity(), Some(identity));
    assert_eq!(references(&moved, pid, tid), (1, 1));
    moved.release_initial_system_references(identity).unwrap();
    assert_eq!(references(&moved, pid, tid), (0, 0));
    assert!(!moved.initial_system_references_held());
}

#[test]
fn colliding_ids_in_another_manager_do_not_authorize_reference_release() {
    let (mut first, pid, tid) = bootstrap_objects();
    let (mut second, other_pid, other_tid) = bootstrap_objects();
    let first_identity = first.designate_initial_system(pid, tid).unwrap();
    let second_identity = second
        .designate_initial_system(other_pid, other_tid)
        .unwrap();
    assert_eq!(first_identity.thread(), second_identity.thread());
    assert_ne!(first_identity, second_identity);
    assert_eq!(
        second.release_initial_system_references(first_identity),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        first.release_initial_system_references(second_identity),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(references(&first, pid, tid), (1, 1));
    assert_eq!(references(&second, other_pid, other_tid), (1, 1));
    assert!(first.initial_system_references_held());
    assert!(second.initial_system_references_held());
}

#[test]
fn root_references_block_normal_deletion_until_explicit_release() {
    let (mut pm, pid, tid) = bootstrap_objects();
    let identity = pm.designate_initial_system(pid, tid).unwrap();
    assert!(pm.abort_process_creation(pid).is_none());
    pm.terminate_process(pid, 0).unwrap();
    let blockers = pm.process_object_delete_blockers(pid).unwrap();
    assert_eq!(blockers.process_kernel_pointer_references, 1);
    assert_eq!(blockers.thread_kernel_pointer_references, 1);
    assert!(!pm.can_reclaim_thread(tid));
    assert!(pm.delete_process_object_if_unreferenced(pid).is_none());
    assert_eq!(pm.initial_system_identity(), Some(identity));
    pm.release_initial_system_references(identity).unwrap();
    assert!(pm.can_reclaim_thread(tid));
    assert!(pm.delete_process_object_if_unreferenced(pid).is_some());
    assert_eq!(pm.initial_system_identity(), None);
    assert!(!pm.is_initial_system_process(pid));
    assert_eq!(
        pm.release_initial_system_references(identity),
        Err(STATUS_INVALID_PARAMETER)
    );
    let replacement = pm.create_process("System", None, None);
    let replacement_thread = pm.create_thread(replacement, 0, 0, true).unwrap();
    assert_eq!(
        pm.designate_initial_system(replacement, replacement_thread),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn pointer_releases_cannot_consume_bootstrap_ownership() {
    let (mut pm, pid, tid) = bootstrap_objects();
    let identity = pm.designate_initial_system(pid, tid).unwrap();
    assert!(pm.publish_process_kernel_object(pid, 0x1000));
    assert!(pm.publish_thread_kernel_object(tid, 0x2000));
    assert_eq!(
        pm.release_kernel_object_pointer(0x1000),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.release_kernel_object_pointer(0x2000),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(pm.lookup_kernel_process_by_id(pid), Ok((0x1000, 2)));
    assert_eq!(pm.lookup_kernel_thread_by_id(tid), Ok((0x2000, 2)));
    assert_eq!(pm.release_kernel_object_pointer(0x1000), Ok(1));
    assert_eq!(pm.release_kernel_object_pointer(0x2000), Ok(1));
    assert_eq!(references(&pm, pid, tid), (1, 1));
    pm.lookup_kernel_process_by_id(pid).unwrap();
    pm.lookup_kernel_thread_by_id(tid).unwrap();
    pm.release_initial_system_references(identity).unwrap();
    assert_eq!(references(&pm, pid, tid), (1, 1));
    assert_eq!(pm.release_kernel_object_pointer(0x1000), Ok(0));
    assert_eq!(pm.release_kernel_object_pointer(0x2000), Ok(0));
    assert_eq!(
        pm.release_kernel_object_pointer(0x1000),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.release_initial_system_references(identity),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn invalid_role_owner_and_user_environment_do_not_partially_designate() {
    let (mut pm, pid, tid) = bootstrap_objects();
    let other_pid = pm.create_process("other", None, None);
    let other_tid = pm.create_thread(other_pid, 0, 0, true).unwrap();
    assert_eq!(
        pm.designate_initial_system(pid, other_tid),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.designate_initial_system(0, tid),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.designate_initial_system(pid, 0),
        Err(STATUS_INVALID_HANDLE)
    );
    pm.processes.get_mut(&pid).unwrap().peb_base_address = 0x4000;
    assert_eq!(
        pm.designate_initial_system(pid, tid),
        Err(STATUS_INVALID_PARAMETER)
    );
    pm.processes.get_mut(&pid).unwrap().peb_base_address = 0;
    pm.threads.get_mut(&tid).unwrap().teb_base = 0x7000;
    assert_eq!(
        pm.designate_initial_system(pid, tid),
        Err(STATUS_INVALID_PARAMETER)
    );
    pm.threads.get_mut(&tid).unwrap().teb_base = 0;
    pm.threads.get_mut(&tid).unwrap().is_system_thread = false;
    assert_eq!(
        pm.designate_initial_system(pid, tid),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(pm.initial_system_identity(), None);
    assert_eq!(references(&pm, pid, tid), (0, 0));
    assert_eq!(references(&pm, other_pid, other_tid), (0, 0));
}

#[test]
fn reference_overflow_preflights_both_objects_before_publication() {
    let (mut pm, pid, tid) = bootstrap_objects();
    for (process_refs, thread_refs) in [(u32::MAX, 0), (0, u32::MAX)] {
        pm.processes
            .get_mut(&pid)
            .unwrap()
            .kernel_pointer_references = process_refs;
        pm.threads.get_mut(&tid).unwrap().kernel_pointer_references = thread_refs;
        assert_eq!(
            pm.designate_initial_system(pid, tid),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(references(&pm, pid, tid), (process_refs, thread_refs));
        assert_eq!(pm.initial_system_identity(), None);
        assert!(!pm.initial_system_references_held());
    }
    pm.threads.get_mut(&tid).unwrap().kernel_pointer_references = 0;
    assert!(pm.designate_initial_system(pid, tid).is_ok());
}

#[test]
fn designation_nonce_exhaustion_does_not_publish_or_take_references() {
    let (mut pm, pid, tid) = bootstrap_objects();
    for value in [0, u64::MAX] {
        let counter = AtomicU64::new(value);
        assert_eq!(
            pm.designate_initial_system_with_counter(pid, tid, &counter),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(counter.load(Ordering::Relaxed), value);
        assert_eq!(references(&pm, pid, tid), (0, 0));
        assert_eq!(pm.initial_system_identity(), None);
    }
    assert!(pm.designate_initial_system(pid, tid).is_ok());
}

#[test]
fn release_validation_failure_leaves_both_reference_owners_untouched() {
    let (mut pm, pid, tid) = bootstrap_objects();
    let identity = pm.designate_initial_system(pid, tid).unwrap();
    pm.threads.get_mut(&tid).unwrap().kernel_pointer_references = 0;
    assert_eq!(
        pm.release_initial_system_references(identity),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(references(&pm, pid, tid), (1, 0));
    assert!(pm.initial_system_references_held());
    pm.threads.get_mut(&tid).unwrap().kernel_pointer_references = 1;
    pm.release_initial_system_references(identity).unwrap();
    assert_eq!(references(&pm, pid, tid), (0, 0));
}

#[test]
fn caller_validation_preserves_identity_across_move_and_live_thread_states() {
    let (mut pm, pid, tid) = bootstrap_objects();
    let identity = pm.designate_initial_system(pid, tid).unwrap();
    let mut moved = alloc::boxed::Box::new(pm);
    for state in [
        ThreadState::Ready,
        ThreadState::Running,
        ThreadState::Waiting,
        ThreadState::Suspended,
    ] {
        moved.set_thread_state(tid, state).unwrap();
        assert!(moved.validate_initial_system_caller(identity));
        assert_eq!(moved.initial_system_identity(), Some(identity));
        assert_eq!(references(&moved, pid, tid), (1, 1));
    }
}

#[test]
fn caller_validation_rejects_foreign_designation_and_released_bootstrap_references() {
    let (mut pm, pid, tid) = bootstrap_objects();
    let (mut other, other_pid, other_tid) = bootstrap_objects();
    let identity = pm.designate_initial_system(pid, tid).unwrap();
    let foreign = other
        .designate_initial_system(other_pid, other_tid)
        .unwrap();
    assert_eq!(identity.thread(), foreign.thread());
    assert!(!pm.validate_initial_system_caller(foreign));
    assert!(pm.validate_initial_system_caller(identity));
    pm.release_initial_system_references(identity).unwrap();
    assert_eq!(pm.initial_system_identity(), Some(identity));
    assert!(!pm.validate_initial_system_caller(identity));
    assert_eq!(references(&pm, pid, tid), (0, 0));
}

#[test]
fn caller_validation_rejects_exit_and_non_system_state_without_mutation() {
    let (mut pm, pid, tid) = bootstrap_objects();
    let identity = pm.designate_initial_system(pid, tid).unwrap();
    for state in [
        ProcessState::Created,
        ProcessState::LoadingImage,
        ProcessState::Ready,
        ProcessState::Exiting,
        ProcessState::Terminated,
    ] {
        pm.processes.get_mut(&pid).unwrap().state = state;
        assert!(!pm.validate_initial_system_caller(identity));
        assert_eq!(pm.process(pid).unwrap().state, state);
        assert_eq!(references(&pm, pid, tid), (1, 1));
    }
    pm.processes.get_mut(&pid).unwrap().state = ProcessState::Running;
    pm.processes.get_mut(&pid).unwrap().exit_status = Some(0);
    assert!(!pm.validate_initial_system_caller(identity));
    pm.processes.get_mut(&pid).unwrap().exit_status = None;
    for state in [ThreadState::Initialized, ThreadState::Terminated] {
        pm.threads.get_mut(&tid).unwrap().state = state;
        assert!(!pm.validate_initial_system_caller(identity));
        assert_eq!(pm.thread(tid).unwrap().state, state);
    }
    pm.threads.get_mut(&tid).unwrap().state = ThreadState::Running;
    pm.threads.get_mut(&tid).unwrap().exit_status = Some(0);
    assert!(!pm.validate_initial_system_caller(identity));
    pm.threads.get_mut(&tid).unwrap().exit_status = None;
    pm.threads.get_mut(&tid).unwrap().is_system_thread = false;
    assert!(!pm.validate_initial_system_caller(identity));
    pm.threads.get_mut(&tid).unwrap().is_system_thread = true;
    assert!(pm.validate_initial_system_caller(identity));
    assert_eq!(references(&pm, pid, tid), (1, 1));
}
