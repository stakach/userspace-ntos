use super::*;

fn setup() -> (ProcessManager, ProcessId, ThreadId) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("suspend.exe", None, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    (pm, pid, tid)
}

fn prepare(
    pm: &mut ProcessManager,
    tid: ThreadId,
    operation: ThreadSuspendOperation,
) -> ThreadSuspendPlan {
    let lifetime = pm.thread_lifetime(tid).unwrap();
    pm.prepare_thread_suspend_control(lifetime, operation)
        .unwrap()
}

#[test]
fn suspension_preserves_waiting_ready_and_unstarted_states() {
    for state in [
        ThreadState::Ready,
        ThreadState::Running,
        ThreadState::Waiting,
        ThreadState::Initialized,
    ] {
        let (mut pm, _, tid) = setup();
        pm.set_thread_state(tid, state).unwrap();
        assert_eq!(pm.suspend_thread(tid), Ok(0));
        assert_eq!(pm.suspend_thread(tid), Ok(1));
        assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Suspended);
        assert!(!pm.has_yield_candidate(u32::MAX));
        assert_eq!(pm.resume_thread(tid), Ok(2));
        assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Suspended);
        assert_eq!(pm.resume_thread(tid), Ok(1));
        let expected = if state == ThreadState::Running {
            ThreadState::Ready
        } else {
            state
        };
        assert_eq!(pm.thread(tid).unwrap().state, expected);
        assert_eq!(pm.resume_thread(tid), Ok(0));
        assert_eq!(pm.thread(tid).unwrap().state, expected);
    }
}

#[test]
fn suspension_projection_survives_wait_and_run_updates() {
    let (mut pm, _, tid) = setup();
    pm.suspend_thread(tid).unwrap();
    for state in [
        ThreadState::Waiting,
        ThreadState::Ready,
        ThreadState::Running,
        ThreadState::Waiting,
    ] {
        pm.set_thread_state(tid, state).unwrap();
        assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Suspended);
        assert_eq!(pm.thread(tid).unwrap().suspend_count, 1);
    }
    pm.resume_thread(tid).unwrap();
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Waiting);
    assert_eq!(
        pm.set_thread_state(tid, ThreadState::Suspended),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn plans_preserve_wait_completion_on_both_physical_boundaries() {
    let (mut pm, _, tid) = setup();
    pm.set_thread_state(tid, ThreadState::Waiting).unwrap();
    let acquire = prepare(&mut pm, tid, ThreadSuspendOperation::Suspend);
    assert_eq!(acquire.transition(), ThreadSuspendTransition::AcquireHold);
    assert_eq!((acquire.previous_count(), acquire.next_count()), (0, 1));
    assert_eq!(pm.thread(tid).unwrap().suspend_count, 0);
    pm.set_thread_state(tid, ThreadState::Ready).unwrap();
    assert_eq!(pm.commit_thread_suspend_control(&acquire), Ok(0));
    pm.set_thread_state(tid, ThreadState::Waiting).unwrap();
    let release = prepare(&mut pm, tid, ThreadSuspendOperation::Resume);
    assert_eq!(release.transition(), ThreadSuspendTransition::ReleaseHold);
    assert_eq!((release.previous_count(), release.next_count()), (1, 0));
    pm.set_thread_state(tid, ThreadState::Ready).unwrap();
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Suspended);
    assert_eq!(pm.commit_thread_suspend_control(&release), Ok(1));
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Ready);
}

#[test]
fn only_zero_crossings_require_physical_transitions() {
    let (mut pm, _, tid) = setup();
    for (op, previous, transition) in [
        (
            ThreadSuspendOperation::Resume,
            0,
            ThreadSuspendTransition::None,
        ),
        (
            ThreadSuspendOperation::Suspend,
            0,
            ThreadSuspendTransition::AcquireHold,
        ),
        (
            ThreadSuspendOperation::Suspend,
            1,
            ThreadSuspendTransition::None,
        ),
        (
            ThreadSuspendOperation::Resume,
            2,
            ThreadSuspendTransition::None,
        ),
        (
            ThreadSuspendOperation::Resume,
            1,
            ThreadSuspendTransition::ReleaseHold,
        ),
    ] {
        let plan = prepare(&mut pm, tid, op);
        assert_eq!(plan.operation(), op);
        assert_eq!(plan.transition(), transition);
        assert_eq!(pm.commit_thread_suspend_control(&plan), Ok(previous));
        assert_eq!(
            pm.commit_thread_suspend_control(&plan),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            pm.cancel_thread_suspend_control(&plan),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
}

#[test]
fn pending_plan_is_exclusive_and_cancellation_preserves_current_wait() {
    let (mut pm, pid, tid) = setup();
    let plan = prepare(&mut pm, tid, ThreadSuspendOperation::Suspend);
    assert!(pm.has_thread_suspend_control(tid));
    assert!(pm.has_process_suspend_control(pid));
    assert_eq!(pm.suspend_thread(tid), Err(STATUS_DEVICE_BUSY));
    assert_eq!(pm.resume_thread(tid), Err(STATUS_DEVICE_BUSY));
    pm.set_thread_state(tid, ThreadState::Waiting).unwrap();
    pm.cancel_thread_suspend_control(&plan).unwrap();
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Waiting);
    assert_eq!(pm.thread(tid).unwrap().suspend_count, 0);
    assert!(!pm.has_process_suspend_control(pid));
    let next = prepare(&mut pm, tid, ThreadSuspendOperation::Suspend);
    assert_ne!(next.identity(), plan.identity());
    assert_eq!(
        pm.commit_thread_suspend_control(&plan),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.cancel_thread_suspend_control(&plan),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert!(pm.has_thread_suspend_control(tid));
    pm.commit_thread_suspend_control(&next).unwrap();
}

#[test]
fn plan_namespace_is_manager_scoped_and_move_stable() {
    let (mut first, _, tid) = setup();
    let (mut second, _, other_tid) = setup();
    let first_plan = prepare(&mut first, tid, ThreadSuspendOperation::Suspend);
    let second_plan = prepare(&mut second, other_tid, ThreadSuspendOperation::Suspend);
    assert_eq!(first_plan.lifetime(), second_plan.lifetime());
    assert_ne!(first_plan.identity(), second_plan.identity());
    assert_eq!(
        second.commit_thread_suspend_control(&first_plan),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        second.cancel_thread_suspend_control(&first_plan),
        Err(STATUS_INVALID_HANDLE)
    );
    assert!(second.has_thread_suspend_control(other_tid));
    let mut moved = alloc::boxed::Box::new(first);
    assert_eq!(moved.commit_thread_suspend_control(&first_plan), Ok(0));
    assert_eq!(second.commit_thread_suspend_control(&second_plan), Ok(0));
}

#[test]
fn dropped_plan_retains_lifecycle_barriers() {
    let (mut pm, pid, tid) = setup();
    drop(prepare(&mut pm, tid, ThreadSuspendOperation::Suspend));
    assert_eq!(pm.suspend_thread(tid), Err(STATUS_DEVICE_BUSY));
    assert_eq!(
        pm.set_thread_state(tid, ThreadState::Initialized),
        Err(STATUS_DEVICE_BUSY)
    );
    assert_eq!(
        pm.set_thread_state(tid, ThreadState::Terminated),
        Err(STATUS_DEVICE_BUSY)
    );
    assert_eq!(pm.exit_thread(tid, 5), Err(STATUS_DEVICE_BUSY));
    assert_eq!(pm.terminate_thread(tid, 5), Err(STATUS_DEVICE_BUSY));
    assert_eq!(pm.terminate_process(pid, 5), Err(STATUS_DEVICE_BUSY));
    assert!(pm.abort_process_creation(pid).is_none());
    assert!(!pm.can_reclaim_thread(tid));
    assert!(!pm.process_object_delete_ready(pid));
    assert!(pm.delete_process_object_if_unreferenced(pid).is_none());
    assert_eq!(pm.thread(tid).unwrap().exit_status, None);
    assert_eq!(pm.process(pid).unwrap().exit_status, None);
}

#[test]
fn pending_system_peer_blocks_last_user_exit_before_any_exit_publication() {
    let (mut pm, pid, tid) = setup();
    let system = pm.create_thread(pid, 0x2000, 0, true).unwrap();
    let plan = prepare(&mut pm, system, ThreadSuspendOperation::Suspend);
    assert_eq!(pm.terminate_thread(tid, 7), Err(STATUS_DEVICE_BUSY));
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Ready);
    assert_eq!(pm.thread(tid).unwrap().exit_status, None);
    pm.cancel_thread_suspend_control(&plan).unwrap();
    pm.terminate_thread(tid, 7).unwrap();
    assert_eq!(pm.thread(system).unwrap().state, ThreadState::Terminated);
}

#[test]
fn pending_dormant_control_blocks_prepared_and_new_activation() {
    let (mut pm, pid, _) = setup();
    let tid = pm.create_dormant_thread(pid).unwrap();
    let activation = pm
        .prepare_thread_activation(tid, 0x2000, 0, true, 0x7000, 0, false)
        .unwrap();
    let plan = prepare(&mut pm, tid, ThreadSuspendOperation::Resume);
    assert_eq!(
        pm.prepare_thread_activation(tid, 0x2000, 0, true, 0x7000, 0, false),
        Err(STATUS_DEVICE_BUSY)
    );
    assert_eq!(
        pm.commit_thread_activation(activation),
        Err(STATUS_DEVICE_BUSY)
    );
    pm.cancel_thread_suspend_control(&plan).unwrap();
    let activation = pm
        .prepare_thread_activation(tid, 0x2000, 0, true, 0x7000, 0, false)
        .unwrap();
    pm.commit_thread_activation(activation).unwrap();
    assert_eq!(
        pm.validate_thread_suspend_control(&plan),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Suspended);
    assert_eq!(pm.resume_thread(tid), Ok(1));
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Ready);
}

#[test]
fn count_limit_and_revision_exhaustion_refuse_without_reservation_or_mutation() {
    let (mut pm, _, tid) = setup();
    for expected in 0..MAXIMUM_SUSPEND_COUNT {
        assert_eq!(pm.suspend_thread(tid), Ok(expected));
    }
    let revision = pm.thread(tid).unwrap().suspend_revision;
    assert_eq!(pm.suspend_thread(tid), Err(STATUS_SUSPEND_COUNT_EXCEEDED));
    assert_eq!(pm.thread(tid).unwrap().suspend_revision, revision);
    assert_eq!(pm.thread(tid).unwrap().suspend_count, MAXIMUM_SUSPEND_COUNT);
    assert!(!pm.has_thread_suspend_control(tid));
    pm.threads.get_mut(&tid).unwrap().suspend_revision = u64::MAX;
    assert_eq!(pm.resume_thread(tid), Err(STATUS_INSUFFICIENT_RESOURCES));
    assert_eq!(pm.thread(tid).unwrap().suspend_count, MAXIMUM_SUSPEND_COUNT);
    assert!(!pm.has_thread_suspend_control(tid));
}

#[test]
fn forged_expected_count_or_lifetime_cannot_consume_pending_admission() {
    let (mut pm, _, tid) = setup();
    let mut plan = prepare(&mut pm, tid, ThreadSuspendOperation::Suspend);
    plan.previous = 7;
    assert_eq!(
        pm.commit_thread_suspend_control(&plan),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.cancel_thread_suspend_control(&plan),
        Err(STATUS_INVALID_PARAMETER)
    );
    plan.previous = 0;
    plan.lifetime.generation += 1;
    assert_eq!(
        pm.commit_thread_suspend_control(&plan),
        Err(STATUS_INVALID_HANDLE)
    );
    plan.lifetime.generation -= 1;
    assert!(pm.has_thread_suspend_control(tid));
    assert_eq!(pm.commit_thread_suspend_control(&plan), Ok(0));
}
