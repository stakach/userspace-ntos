use super::*;

fn fixture() -> (ProcessManager, NativeHandleCaller) {
    let mut pm = ProcessManager::new();
    let system_pid = pm.create_process("System", None, None);
    let system_tid = pm.create_thread(system_pid, 0, 0, true).unwrap();
    pm.designate_initial_system(system_pid, system_tid).unwrap();
    assert!(pm.publish_process_kernel_object(system_pid, 0x1000));
    assert!(pm.publish_thread_kernel_object(system_tid, 0x2000));
    let pid = pm.create_process("requestor", None, None);
    let tid = pm.create_thread(pid, 0x5000, 0, false).unwrap();
    assert!(pm.publish_process_kernel_object(pid, 0x3000));
    assert!(pm.publish_thread_kernel_object(tid, 0x4000));
    let caller = pm
        .capture_native_handle_caller(pm.thread_lifetime(tid).unwrap(), AccessMode::KernelMode)
        .unwrap();
    (pm, caller)
}

fn counts(pm: &ProcessManager, caller: NativeHandleCaller) -> (u32, u32) {
    let lifetime = caller.original_thread();
    (
        pm.process(lifetime.process_id())
            .unwrap()
            .kernel_pointer_references,
        pm.thread(lifetime.thread_id())
            .unwrap()
            .kernel_pointer_references,
    )
}

#[test]
fn original_thread_and_process_are_retained_and_released_atomically() {
    let (mut pm, caller) = fixture();
    let mut owner = pm.reference_native_requestor(caller).unwrap();
    assert_eq!(owner.thread_lifetime(), caller.original_thread());
    assert_eq!(owner.process_body(), Some(0x3000));
    assert_eq!(owner.thread_body(), Some(0x4000));
    assert_eq!(counts(&pm, caller), (1, 1));
    owner.release(&mut pm).unwrap();
    assert_eq!(counts(&pm, caller), (0, 0));
    assert!(!owner.is_held());
    assert_eq!(owner.process_body(), None);
    assert_eq!(owner.thread_body(), None);
    assert_eq!(owner.release(&mut pm), Err(STATUS_INVALID_HANDLE));
    assert_eq!(counts(&pm, caller), (0, 0));
}

#[test]
fn absent_or_null_either_body_never_takes_first_reference() {
    for missing_thread in [false, true] {
        for missing in [None, Some(0)] {
            let (mut pm, caller) = fixture();
            let lifetime = caller.original_thread();
            if missing_thread {
                pm.threads
                    .get_mut(&lifetime.thread_id())
                    .unwrap()
                    .kernel_thread_object = missing;
            } else {
                pm.processes
                    .get_mut(&lifetime.process_id())
                    .unwrap()
                    .kernel_process_object = missing;
            }
            assert_eq!(
                pm.reference_native_requestor(caller).unwrap_err(),
                STATUS_INVALID_HANDLE
            );
            assert_eq!(counts(&pm, caller), (0, 0));
        }
    }
}

#[test]
fn either_counter_overflow_preserves_both_counts() {
    for overflow_thread in [false, true] {
        let (mut pm, caller) = fixture();
        let lifetime = caller.original_thread();
        if overflow_thread {
            pm.threads
                .get_mut(&lifetime.thread_id())
                .unwrap()
                .kernel_pointer_references = u32::MAX;
        } else {
            pm.processes
                .get_mut(&lifetime.process_id())
                .unwrap()
                .kernel_pointer_references = u32::MAX;
        }
        let before = counts(&pm, caller);
        assert_eq!(
            pm.reference_native_requestor(caller).unwrap_err(),
            crate::STATUS_INSUFFICIENT_RESOURCES
        );
        assert_eq!(counts(&pm, caller), before);
    }
}

#[test]
fn foreign_manager_and_user_mode_cannot_capture_or_release_pair() {
    let (mut pm, caller) = fixture();
    let (mut foreign, foreign_caller) = fixture();
    assert_eq!(
        foreign.reference_native_requestor(caller).unwrap_err(),
        STATUS_INVALID_HANDLE
    );
    let user = pm
        .capture_native_handle_caller(caller.original_thread(), AccessMode::UserMode)
        .unwrap();
    assert_eq!(
        pm.reference_native_requestor(user).unwrap_err(),
        STATUS_ACCESS_DENIED
    );
    let mut owner = pm.reference_native_requestor(caller).unwrap();
    assert_eq!(owner.release(&mut foreign), Err(STATUS_INVALID_HANDLE));
    assert!(owner.is_held());
    assert_eq!(counts(&pm, caller), (1, 1));
    assert_eq!(counts(&foreign, foreign_caller), (0, 0));
    owner.release(&mut pm).unwrap();
}

#[test]
fn release_validates_both_bodies_before_changing_either_count() {
    for changed_thread in [false, true] {
        let (mut pm, caller) = fixture();
        let mut owner = pm.reference_native_requestor(caller).unwrap();
        let lifetime = caller.original_thread();
        if changed_thread {
            pm.threads
                .get_mut(&lifetime.thread_id())
                .unwrap()
                .kernel_thread_object = Some(0x9000);
        } else {
            pm.processes
                .get_mut(&lifetime.process_id())
                .unwrap()
                .kernel_process_object = Some(0x9000);
        }
        assert_eq!(owner.release(&mut pm), Err(STATUS_INVALID_HANDLE));
        assert_eq!(counts(&pm, caller), (1, 1));
        assert!(owner.is_held());
        if changed_thread {
            pm.threads
                .get_mut(&lifetime.thread_id())
                .unwrap()
                .kernel_thread_object = Some(0x4000);
        } else {
            pm.processes
                .get_mut(&lifetime.process_id())
                .unwrap()
                .kernel_process_object = Some(0x3000);
        }
        owner.release(&mut pm).unwrap();
        assert_eq!(counts(&pm, caller), (0, 0));
    }
}

#[test]
fn release_checks_both_floors_before_mutating_pair() {
    for depleted_thread in [false, true] {
        let (mut pm, caller) = fixture();
        let mut owner = pm.reference_native_requestor(caller).unwrap();
        let lifetime = caller.original_thread();
        if depleted_thread {
            pm.threads
                .get_mut(&lifetime.thread_id())
                .unwrap()
                .kernel_pointer_references = 0;
        } else {
            pm.processes
                .get_mut(&lifetime.process_id())
                .unwrap()
                .kernel_pointer_references = 0;
        }
        let before = counts(&pm, caller);
        assert_eq!(owner.release(&mut pm), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(counts(&pm, caller), before);
        assert!(owner.is_held());
        if depleted_thread {
            pm.threads
                .get_mut(&lifetime.thread_id())
                .unwrap()
                .kernel_pointer_references = 1;
        } else {
            pm.processes
                .get_mut(&lifetime.process_id())
                .unwrap()
                .kernel_pointer_references = 1;
        }
        owner.release(&mut pm).unwrap();
    }
}

#[test]
fn initial_system_pair_preserves_both_bootstrap_floors() {
    let (mut pm, _) = fixture();
    let identity = pm.initial_system_identity().unwrap();
    let caller = pm
        .capture_native_handle_caller(identity.thread(), AccessMode::KernelMode)
        .unwrap();
    let before = counts(&pm, caller);
    let mut owner = pm.reference_native_requestor(caller).unwrap();
    assert_eq!(owner.process_body(), Some(0x1000));
    assert_eq!(owner.thread_body(), Some(0x2000));
    assert_eq!(counts(&pm, caller), (before.0 + 1, before.1 + 1));
    owner.release(&mut pm).unwrap();
    assert_eq!(counts(&pm, caller), before);
    assert!(pm.validate_initial_system_caller(identity));
}

#[test]
fn exited_thread_remains_releasable_but_cannot_reactivate_while_pair_held() {
    let (mut pm, caller) = fixture();
    pm.create_thread(caller.original_thread().process_id(), 0x5100, 0, false)
        .unwrap();
    let mut owner = pm.reference_native_requestor(caller).unwrap();
    let tid = caller.original_thread().thread_id();
    pm.terminate_thread(tid, 0).unwrap();
    assert!(pm.reference_native_requestor(caller).is_err());
    assert!(!pm.can_reclaim_thread(tid));
    assert!(pm
        .prepare_thread_activation(tid, 0x6000, 0, false, 0x7000, 123, false)
        .is_err());
    owner.release(&mut pm).unwrap();
    let plan = pm
        .prepare_thread_activation(tid, 0x6000, 0, false, 0x7000, 123, false)
        .unwrap();
    pm.commit_thread_activation(plan).unwrap();
    assert_ne!(pm.thread_lifetime(tid), Some(caller.original_thread()));
    assert_eq!(pm.thread_kernel_object(tid), Some(0x4000));
    assert!(pm.reference_native_requestor(caller).is_err());
    let current = pm
        .capture_native_handle_caller(pm.thread_lifetime(tid).unwrap(), AccessMode::KernelMode)
        .unwrap();
    let mut replacement = pm.reference_native_requestor(current).unwrap();
    assert!(owner.release(&mut pm).is_err());
    assert_eq!(counts(&pm, current), (1, 1));
    replacement.release(&mut pm).unwrap();
}

#[test]
fn pair_blocks_process_deletion_until_both_owners_return() {
    let (mut pm, caller) = fixture();
    let mut owner = pm.reference_native_requestor(caller).unwrap();
    let pid = caller.original_thread().process_id();
    pm.terminate_process(pid, 0).unwrap();
    assert!(!pm.process_object_delete_ready(pid));
    assert!(pm.abort_process_creation(pid).is_none());
    owner.release(&mut pm).unwrap();
    assert!(pm.abort_process_creation(pid).is_some());
}
