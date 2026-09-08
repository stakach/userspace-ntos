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
fn activation_plan_exposes_expected_lifetime_and_intended_teb_without_mutation() {
    let (mut pm, _, tid) = dormant();
    let lifetime = pm.thread_lifetime(tid).unwrap();
    let before_teb = pm.thread(tid).unwrap().teb_base;
    let plan = prepare(&pm, tid).unwrap();
    assert_eq!(plan.expected_lifetime(), lifetime);
    assert_eq!(plan.teb_base(), 0x7000);
    assert_eq!(pm.thread(tid).unwrap().teb_base, before_teb);
    assert_eq!(pm.thread_lifetime(tid), Some(lifetime));
    pm.commit_thread_activation(plan).unwrap();
    assert_eq!(pm.thread(tid).unwrap().teb_base, plan.teb_base());
    assert_ne!(pm.thread_lifetime(tid), Some(plan.expected_lifetime()));
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

#[test]
fn failed_first_resume_retires_unpublished_activation_without_rewinding_identity() {
    let (mut pm, pid, tid) = dormant();
    let main_tid = pm.process(pid).unwrap().main_thread.unwrap();
    pm.exit_thread_at(main_tid, 0, 100).unwrap();
    let body = 0x20_0000;
    assert!(pm.publish_thread_kernel_object(tid, body));
    assert!(!pm.thread(tid).unwrap().is_system_thread);
    let dormant_lifetime = pm.thread_lifetime(tid).unwrap();
    let plan = pm
        .prepare_thread_activation(tid, 0x4000, 0x55, false, 0x7000, 123, true)
        .unwrap();
    let reservation = pm.try_reserve_handle_slot(pid).unwrap();
    pm.bind_reserved_handle(reservation, HandleObject::Thread(tid), THREAD_ALL_ACCESS)
        .unwrap();
    pm.commit_thread_activation_with_handle(plan, reservation)
        .unwrap();
    let failed_lifetime = pm.thread_lifetime(tid).unwrap();
    assert_eq!(failed_lifetime.generation(), dormant_lifetime.generation() + 1);
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Running);
    assert_eq!(pm.thread_kernel_object(tid), Some(body));
    assert_eq!(pm.lookup_handle(pid, reservation.handle), None);
    assert_eq!(pm.handle_count(pid), 0);
    assert_eq!(pm.handle_reservation_count(pid), 1);

    // The first native resume failed after the PM commit. Exit only this activation,
    // even though it is the process's last live thread, and retain the bound handle owner.
    pm.exit_thread_at(tid, STATUS_INSUFFICIENT_RESOURCES, 456)
        .unwrap();
    assert_eq!(pm.process(pid).unwrap().state, ProcessState::Running);
    assert_eq!(pm.process(pid).unwrap().exit_status, None);
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Terminated);
    assert_eq!(pm.thread(tid).unwrap().exit_status, Some(STATUS_INSUFFICIENT_RESOURCES));
    assert_eq!(pm.thread(tid).unwrap().exit_time_100ns, 456);
    assert_eq!(pm.thread_lifetime(tid), Some(failed_lifetime));
    assert_eq!(pm.thread_kernel_object(tid), Some(body));
    assert!(!pm.can_reclaim_thread(tid));
    assert_eq!(prepare(&pm, tid), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(pm.lookup_handle(pid, reservation.handle), None);

    assert_eq!(pm.cancel_bound_handle(reservation), Ok(HandleObject::Thread(tid)));
    assert_eq!(pm.handle_reservation_count(pid), 0);
    assert!(pm.can_reclaim_thread(tid));
    assert_eq!(pm.thread_lifetime(tid), Some(failed_lifetime));
    assert_eq!(pm.commit_thread_activation(plan), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(pm.thread_lifetime(tid), Some(failed_lifetime));
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Terminated);

    let next_plan = prepare(&pm, tid).unwrap();
    let next_reservation = pm.try_reserve_handle_slot(pid).unwrap();
    pm.bind_reserved_handle(next_reservation, HandleObject::Thread(tid), THREAD_ALL_ACCESS)
        .unwrap();
    pm.commit_thread_activation_with_handle(next_plan, next_reservation)
        .unwrap();
    assert_eq!(pm.thread_lifetime(tid).unwrap().generation(), failed_lifetime.generation() + 1);
    assert!(!pm.validate_thread_lifetime(failed_lifetime));
    assert_eq!(pm.thread_kernel_object(tid), Some(body));
    assert_eq!(pm.tid_for_kernel_thread_object(body), Some(tid));
    assert_eq!(pm.thread(tid).unwrap().exit_status, None);
    assert_eq!(pm.thread(tid).unwrap().exit_time_100ns, 0);
    assert_eq!(pm.lookup_handle(pid, next_reservation.handle), None);
    let handle = pm.publish_reserved_handle(next_reservation).unwrap();
    assert_eq!(pm.lookup_handle(pid, handle), Some(HandleObject::Thread(tid)));
    pm.close_handle(pid, handle).unwrap();
}
