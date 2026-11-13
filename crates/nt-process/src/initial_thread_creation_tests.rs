use super::*;

fn fresh() -> (ProcessManager, ProcessId, ThreadId) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("ordinary.exe", None, None);
    let tid = pm.create_thread(pid, 0, 0, false).unwrap();
    (pm, pid, tid)
}

#[test]
fn abandoned_unstarted_process_waits_for_its_final_external_handle() {
    let mut pm = ProcessManager::new();
    let creator = pm.create_process("creator.exe", None, None);
    let child = pm.create_process("child.exe", Some(creator), None);
    let main = pm.create_thread(child, 0, 0, false).unwrap();
    assert!(pm.publish_process_kernel_object(child, 0x3000));
    assert!(pm.publish_thread_kernel_object(main, 0x4000));
    let first = pm.insert_handle(creator, HandleObject::Process(child), 0).unwrap();
    let last = pm.insert_handle(creator, HandleObject::Process(child), 0).unwrap();

    assert!(!pm.should_terminate_unstarted_process(child),
        "a visible creator handle still owns initial-thread admission");
    pm.close_handle(creator, first).unwrap();
    assert!(!pm.should_terminate_unstarted_process(child),
        "closing one of several handles cannot abandon the child");
    pm.close_handle(creator, last).unwrap();
    assert_eq!(pm.retain_kernel_object_pointer(0x3000), Ok(1));
    assert!(!pm.should_terminate_unstarted_process(child),
        "a native process-pointer owner can still admit the initial thread");
    assert_eq!(pm.release_kernel_object_pointer(0x3000), Ok(0));
    assert_eq!(pm.retain_kernel_object_pointer(0x4000), Ok(1));
    assert!(!pm.should_terminate_unstarted_process(child),
        "a native main-thread pointer also keeps creation authority alive");
    assert_eq!(pm.release_kernel_object_pointer(0x4000), Ok(0));
    assert!(pm.should_terminate_unstarted_process(child),
        "the last close must make a never-started process eligible for normal retirement");
    pm.terminate_process(child, STATUS_INVALID_PARAMETER).unwrap();
    assert!(pm.is_process_signaled(child));
    assert!(!pm.should_terminate_unstarted_process(child),
        "a signaled process must not be terminated again");
}

#[test]
fn final_close_receipt_waits_for_pointer_owner_before_retirement() {
    let mut pm = ProcessManager::new();
    let creator = pm.create_process("creator.exe", None, None);
    let child = pm.create_process("child.exe", Some(creator), None);
    let main = pm.create_thread(child, 0, 0, false).unwrap();
    assert!(pm.publish_process_kernel_object(child, 0x7000));
    assert!(pm.publish_thread_kernel_object(main, 0x8000));
    let handle = pm.insert_handle(creator, HandleObject::Process(child), 0).unwrap();
    assert_eq!(pm.retain_kernel_object_pointer(0x7000), Ok(1));
    pm.close_handle(creator, handle).unwrap();
    assert!(pm.request_unstarted_process_abandonment(child),
        "the real final close must be recorded despite a temporary native pointer owner");
    assert!(!pm.unstarted_process_abandonment_pending(child));
    assert_eq!(pm.release_kernel_object_pointer(0x7000), Ok(0));
    assert!(pm.unstarted_process_abandonment_pending(child),
        "the retained close receipt becomes eligible after the pointer owner releases");
}

#[test]
fn pending_or_committed_initial_thread_prevents_abandoned_process_cleanup() {
    let (mut pm, child, main) = fresh();
    assert!(pm.publish_process_kernel_object(child, 0x5000));
    assert!(pm.publish_thread_kernel_object(main, 0x6000));
    assert!(pm.should_terminate_unstarted_process(child));
    let plan = pm.prepare_initial_thread_creation(child).unwrap().unwrap();
    assert!(!pm.should_terminate_unstarted_process(child),
        "a retained native creation attempt owns the process even without handles");
    pm.cancel_initial_thread_creation(&plan).unwrap();
    assert!(pm.should_terminate_unstarted_process(child),
        "proven no-effect cancellation restores abandonment eligibility");
    let plan = pm.prepare_initial_thread_creation(child).unwrap().unwrap();
    pm.commit_initial_thread_creation(&plan).unwrap();
    assert!(!pm.should_terminate_unstarted_process(child),
        "a committed main thread remains the execution owner after handles close");
}

#[test]
fn fresh_main_reserves_then_commits_exact_creation_once() {
    let (mut pm, pid, tid) = fresh();
    let lifetime = pm.thread_lifetime(tid).unwrap();
    let state = pm.thread(tid).unwrap().state;
    let plan = pm.prepare_initial_thread_creation(pid).unwrap().unwrap();
    assert_eq!(plan.lifetime(), lifetime);
    assert_eq!(
        pm.prepare_initial_thread_creation(pid),
        Err(STATUS_DEVICE_BUSY)
    );
    pm.commit_initial_thread_creation(&plan).unwrap();
    assert_eq!(pm.prepare_initial_thread_creation(pid), Ok(None));
    assert_eq!(pm.thread_lifetime(tid), Some(lifetime));
    assert_eq!(pm.thread(tid).unwrap().state, state);
    assert_eq!(
        pm.commit_initial_thread_creation(&plan),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.cancel_initial_thread_creation(&plan),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn suspended_creation_commit_does_not_resume_or_change_count() {
    let (mut pm, pid, tid) = fresh();
    pm.suspend_thread(tid).unwrap();
    let plan = pm.prepare_initial_thread_creation(pid).unwrap().unwrap();
    pm.commit_initial_thread_creation(&plan).unwrap();
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Suspended);
    assert_eq!(pm.thread(tid).unwrap().suspend_count, 1);
}

#[test]
fn runtime_metadata_publication_does_not_commit_initial_creation() {
    let (mut pm, pid, tid) = fresh();
    let lifetime = pm.thread_lifetime(tid).unwrap();
    pm.publish_initial_thread_runtime(lifetime, 0x4000, 0x7000, 5)
        .unwrap();
    assert!(pm.prepare_initial_thread_creation(pid).unwrap().is_some());
}

#[test]
fn existing_additional_threads_do_not_replace_main_receipt() {
    let (mut pm, pid, main) = fresh();
    let extra = pm.create_thread(pid, 0x4000, 0, false).unwrap();
    let plan = pm.prepare_initial_thread_creation(pid).unwrap().unwrap();
    assert_eq!(plan.lifetime().thread_id(), main);
    pm.commit_initial_thread_creation(&plan).unwrap();
    assert_eq!(pm.prepare_initial_thread_creation(pid), Ok(None));
    assert_eq!(pm.thread(extra).unwrap().state, ThreadState::Ready);
}

#[test]
fn cancel_known_unentered_creation_issues_new_nonce_and_rejects_old_plan() {
    let (mut pm, pid, _) = fresh();
    let old = pm.prepare_initial_thread_creation(pid).unwrap().unwrap();
    pm.cancel_initial_thread_creation(&old).unwrap();
    let current = pm.prepare_initial_thread_creation(pid).unwrap().unwrap();
    assert_ne!(old.nonce, current.nonce);
    assert_eq!(
        pm.commit_initial_thread_creation(&old),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.cancel_initial_thread_creation(&old),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.prepare_initial_thread_creation(pid),
        Err(STATUS_DEVICE_BUSY)
    );
    pm.commit_initial_thread_creation(&current).unwrap();
}

#[test]
fn independent_managers_with_equal_lifetimes_cannot_import_plan() {
    let (mut first, pid, _) = fresh();
    let (mut second, other_pid, _) = fresh();
    let a = first.prepare_initial_thread_creation(pid).unwrap().unwrap();
    let b = second
        .prepare_initial_thread_creation(other_pid)
        .unwrap()
        .unwrap();
    assert_eq!(a.lifetime(), b.lifetime());
    assert_eq!(
        second.commit_initial_thread_creation(&a),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        second.cancel_initial_thread_creation(&a),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        second.prepare_initial_thread_creation(other_pid),
        Err(STATUS_DEVICE_BUSY)
    );
    second.commit_initial_thread_creation(&b).unwrap();
    first.commit_initial_thread_creation(&a).unwrap();
}

#[test]
fn altered_generation_cannot_settle_reservation() {
    let (mut pm, pid, _) = fresh();
    let plan = pm.prepare_initial_thread_creation(pid).unwrap().unwrap();
    let mut wrong = InitialThreadCreationPlan {
        nonce: plan.nonce,
        lifetime: plan.lifetime,
    };
    wrong.lifetime.generation += 1;
    assert_eq!(
        pm.commit_initial_thread_creation(&wrong),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.cancel_initial_thread_creation(&wrong),
        Err(STATUS_INVALID_PARAMETER)
    );
    pm.commit_initial_thread_creation(&plan).unwrap();
}

#[test]
fn pending_creation_blocks_exit_termination_abort_and_reclamation() {
    let (mut pm, pid, tid) = fresh();
    let plan = pm.prepare_initial_thread_creation(pid).unwrap().unwrap();
    assert_eq!(pm.exit_thread(tid, 0), Err(STATUS_DEVICE_BUSY));
    assert_eq!(pm.terminate_thread(tid, 0), Err(STATUS_DEVICE_BUSY));
    assert_eq!(pm.terminate_process(pid, 0), Err(STATUS_DEVICE_BUSY));
    assert!(pm.abort_process_creation(pid).is_none());
    assert!(!pm.process_object_delete_ready(pid));
    assert!(!pm.can_reclaim_thread(tid));
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Ready);
    pm.cancel_initial_thread_creation(&plan).unwrap();
    pm.terminate_process(pid, 0).unwrap();
}

#[test]
fn committed_main_exit_and_reactivation_never_reset_initial_creation() {
    let (mut pm, pid, tid) = fresh();
    let worker = pm.create_thread(pid, 0x5000, 0, false).unwrap();
    let plan = pm.prepare_initial_thread_creation(pid).unwrap().unwrap();
    pm.commit_initial_thread_creation(&plan).unwrap();
    pm.exit_thread(tid, 0).unwrap();
    assert_eq!(pm.thread(worker).unwrap().state, ThreadState::Ready);
    assert!(pm.can_reclaim_thread(tid));
    assert_eq!(pm.prepare_initial_thread_creation(pid), Ok(None));
    let activation = pm
        .prepare_thread_activation(tid, 0x4000, 0, false, 0x7000, 0, false)
        .unwrap();
    pm.commit_thread_activation(activation).unwrap();
    assert_ne!(pm.thread_lifetime(tid), Some(plan.lifetime()));
    assert_eq!(pm.prepare_initial_thread_creation(pid), Ok(None));
    assert_eq!(
        pm.commit_initial_thread_creation(&plan),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn committed_process_history_survives_structural_main_row_withdrawal() {
    let (mut pm, pid, main) = fresh();
    let worker = pm.create_thread(pid, 0x5000, 0, false).unwrap();
    let plan = pm.prepare_initial_thread_creation(pid).unwrap().unwrap();
    pm.commit_initial_thread_creation(&plan).unwrap();
    pm.exit_thread(main, 0).unwrap();
    assert!(pm.can_reclaim_thread(main));
    // There is no public single-ETHREAD withdrawal API today. Model the exact row withdrawal
    // directly to prove that the historical creation receipt belongs to the surviving process.
    assert!(pm.threads.remove(&main).is_some());
    pm.processes
        .get_mut(&pid)
        .unwrap()
        .threads
        .entries
        .retain(|&tid| tid != main);
    assert_eq!(pm.thread(worker).unwrap().state, ThreadState::Ready);
    assert_eq!(pm.prepare_initial_thread_creation(pid), Ok(None));
    assert_eq!(
        pm.commit_initial_thread_creation(&plan),
        Err(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn pending_main_does_not_block_unrelated_worker_exit_but_prevents_main_activation() {
    let (mut pm, pid, main) = fresh();
    let worker = pm.create_thread(pid, 0x5000, 0, false).unwrap();
    let plan = pm.prepare_initial_thread_creation(pid).unwrap().unwrap();
    pm.exit_thread(worker, 0).unwrap();
    assert_eq!(
        pm.prepare_thread_activation(main, 0x4000, 0, false, 0x7000, 0, false),
        Err(STATUS_DEVICE_BUSY)
    );
    assert_eq!(
        pm.terminate_process_other_threads_at(pid, worker, 0, 0),
        Err(STATUS_DEVICE_BUSY)
    );
    assert_eq!(pm.thread(main).unwrap().state, ThreadState::Ready);
    pm.cancel_initial_thread_creation(&plan).unwrap();
}

#[test]
fn uncommitted_dead_main_cannot_be_initially_created_again() {
    let (mut pm, pid, tid) = fresh();
    pm.exit_thread(tid, 0).unwrap();
    assert_eq!(
        pm.prepare_initial_thread_creation(pid),
        Err(STATUS_THREAD_IS_TERMINATING)
    );
    let activation = pm
        .prepare_thread_activation(tid, 0x4000, 0, false, 0x7000, 0, false)
        .unwrap();
    pm.commit_thread_activation(activation).unwrap();
    assert_eq!(
        pm.prepare_initial_thread_creation(pid),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn aborted_process_plan_does_not_apply_to_next_process() {
    let (mut pm, pid, _) = fresh();
    let old = pm.prepare_initial_thread_creation(pid).unwrap().unwrap();
    pm.cancel_initial_thread_creation(&old).unwrap();
    assert!(pm.abort_process_creation(pid).is_some());
    let next_pid = pm.create_process("next.exe", None, None);
    pm.create_thread(next_pid, 0, 0, false).unwrap();
    let next = pm
        .prepare_initial_thread_creation(next_pid)
        .unwrap()
        .unwrap();
    assert_ne!(pid, next_pid);
    assert_eq!(
        pm.commit_initial_thread_creation(&old),
        Err(STATUS_INVALID_HANDLE)
    );
    pm.commit_initial_thread_creation(&next).unwrap();
}

#[test]
fn missing_main_and_terminated_process_refuse_before_reservation() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("empty.exe", None, None);
    assert_eq!(
        pm.prepare_initial_thread_creation(pid),
        Err(STATUS_INVALID_PARAMETER)
    );
    pm.create_thread(pid, 0, 0, false).unwrap();
    pm.terminate_process(pid, 0).unwrap();
    assert_eq!(
        pm.prepare_initial_thread_creation(pid),
        Err(STATUS_PROCESS_IS_TERMINATING)
    );
    assert_eq!(
        pm.prepare_initial_thread_creation(0),
        Err(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn pending_creation_cannot_be_invalidated_by_raw_state_setter() {
    let (mut pm, pid, tid) = fresh();
    let plan = pm.prepare_initial_thread_creation(pid).unwrap().unwrap();
    for state in [ThreadState::Initialized, ThreadState::Terminated] {
        assert_eq!(pm.set_thread_state(tid, state), Err(STATUS_DEVICE_BUSY));
        assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Ready);
        assert_eq!(pm.thread(tid).unwrap().suspend_count, 0);
    }
    pm.commit_initial_thread_creation(&plan).unwrap();
}
