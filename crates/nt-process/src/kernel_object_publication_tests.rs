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

#[test]
fn pair_publication_is_atomic_idempotent_and_does_not_acquire_references() {
    let (mut pm, [pid, _], [tid, _]) = objects();
    let lifetime = pm.thread_lifetime(tid).unwrap();
    assert!(pm.publish_kernel_object_pair(lifetime, 0x1000, 0x2000));
    assert!(pm.publish_kernel_object_pair(lifetime, 0x1000, 0x2000));
    assert_eq!(pm.process_kernel_object(pid), Some(0x1000));
    assert_eq!(pm.thread_kernel_object(tid), Some(0x2000));
    assert_eq!(pm.pid_for_kernel_process_object(0x1000), Some(pid));
    assert_eq!(pm.tid_for_kernel_thread_object(0x2000), Some(tid));
    assert_eq!(pm.process(pid).unwrap().kernel_pointer_references, 0);
    assert_eq!(pm.thread(tid).unwrap().kernel_pointer_references, 0);
    assert_eq!(pm.thread_lifetime(tid), Some(lifetime));
}

#[test]
fn pair_rejects_null_or_identical_addresses_without_partial_publication() {
    for (process, thread) in [(0, 0), (0, 0x2000), (0x1000, 0), (0x1000, 0x1000)] {
        let (mut pm, [pid, _], [tid, _]) = objects();
        let lifetime = pm.thread_lifetime(tid).unwrap();
        assert!(!pm.publish_kernel_object_pair(lifetime, process, thread));
        assert_eq!(pm.process_kernel_object(pid), None);
        assert_eq!(pm.thread_kernel_object(tid), None);
    }
}

#[test]
fn pair_requires_exact_thread_lifetime_and_owning_process_membership() {
    let (mut pm, [pid, other], [tid, _]) = objects();
    let lifetime = pm.thread_lifetime(tid).unwrap();
    for invalid in [
        ThreadLifetime { process_id: other, ..lifetime },
        ThreadLifetime { process_id: u32::MAX, ..lifetime },
        ThreadLifetime { thread_id: u32::MAX, ..lifetime },
        ThreadLifetime { generation: lifetime.generation + 1, ..lifetime },
    ] {
        assert!(!pm.publish_kernel_object_pair(invalid, 0x1000, 0x2000));
        assert_eq!(pm.process_kernel_object(pid), None);
        assert_eq!(pm.process_kernel_object(other), None);
        assert_eq!(pm.thread_kernel_object(tid), None);
    }
    pm.processes.get_mut(&pid).unwrap().threads.entries.clear();
    assert!(!pm.publish_kernel_object_pair(lifetime, 0x1000, 0x2000));
    pm.processes.get_mut(&pid).unwrap().threads.entries.extend_from_slice(&[tid, tid]);
    assert!(!pm.publish_kernel_object_pair(lifetime, 0x1000, 0x2000));
    assert_eq!(pm.process_kernel_object(pid), None);
    assert_eq!(pm.thread_kernel_object(tid), None);
}

#[test]
fn pair_rejects_snapshot_from_before_real_thread_activation() {
    let (mut pm, [pid, _], _) = objects();
    let tid = pm.create_dormant_thread(pid).unwrap();
    let before = pm.thread_lifetime(tid).unwrap();
    let activation = pm.prepare_thread_activation(tid, 0x3000, 0, false, 0x7000, 1, false).unwrap();
    pm.commit_thread_activation(activation).unwrap();
    assert!(!pm.publish_kernel_object_pair(before, 0x1000, 0x2000));
    assert_eq!(pm.process_kernel_object(pid), None);
    assert_eq!(pm.thread_kernel_object(tid), None);
    let current = pm.thread_lifetime(tid).unwrap();
    assert!(pm.publish_kernel_object_pair(current, 0x1000, 0x2000));
    assert!(!pm.publish_kernel_object_pair(before, 0x1000, 0x2000));
}

#[test]
fn pair_checks_both_sides_against_the_shared_live_body_namespace() {
    for (process, thread) in [
        (0x1000, 0x4000), (0x2000, 0x4000),
        (0x3000, 0x1000), (0x3000, 0x2000),
    ] {
        let (mut pm, [first, second], [first_tid, second_tid]) = objects();
        assert!(pm.publish_process_kernel_object(first, 0x1000));
        assert!(pm.publish_thread_kernel_object(first_tid, 0x2000));
        let lifetime = pm.thread_lifetime(second_tid).unwrap();
        assert!(!pm.publish_kernel_object_pair(lifetime, process, thread));
        assert_eq!(pm.process_kernel_object(first), Some(0x1000));
        assert_eq!(pm.thread_kernel_object(first_tid), Some(0x2000));
        assert_eq!(pm.process_kernel_object(second), None);
        assert_eq!(pm.thread_kernel_object(second_tid), None);
    }
}

#[test]
fn pair_rejects_replacement_without_publishing_the_missing_partner() {
    let (mut pm, [first, second], [first_tid, second_tid]) = objects();
    assert!(pm.publish_process_kernel_object(first, 0x1000));
    let first_lifetime = pm.thread_lifetime(first_tid).unwrap();
    assert!(!pm.publish_kernel_object_pair(first_lifetime, 0x3000, 0x4000));
    assert_eq!(pm.process_kernel_object(first), Some(0x1000));
    assert_eq!(pm.thread_kernel_object(first_tid), None);
    assert!(pm.publish_thread_kernel_object(second_tid, 0x2000));
    let second_lifetime = pm.thread_lifetime(second_tid).unwrap();
    assert!(!pm.publish_kernel_object_pair(second_lifetime, 0x3000, 0x4000));
    assert_eq!(pm.process_kernel_object(second), None);
    assert_eq!(pm.thread_kernel_object(second_tid), Some(0x2000));
    assert!(pm.publish_kernel_object_pair(first_lifetime, 0x1000, 0x4000));
    assert!(pm.publish_kernel_object_pair(second_lifetime, 0x3000, 0x2000));
}

#[test]
fn pair_cannot_republish_withdrawn_objects_or_reuse_their_reserved_bodies() {
    let (mut pm, [system_pid, pid], [system_tid, tid]) = objects();
    pm.threads.get_mut(&system_tid).unwrap().is_system_thread = true;
    pm.designate_initial_system(system_pid, system_tid).unwrap();
    let lifetime = pm.thread_lifetime(tid).unwrap();
    assert!(pm.publish_kernel_object_pair(lifetime, 0x1000, 0x2000));
    pm.terminate_process(pid, 0).unwrap();
    let retirement = pm.withdraw_process_object_if_unreferenced(pid).unwrap();
    assert!(!pm.publish_kernel_object_pair(lifetime, 0x1000, 0x2000));
    let next_pid = pm.create_process("next.exe", None, None);
    let next_tid = pm.create_thread(next_pid, 0x3000, 0, false).unwrap();
    let next = pm.thread_lifetime(next_tid).unwrap();
    for (process, thread) in [
        (0x1000, 0x4000), (0x2000, 0x4000),
        (0x3000, 0x1000), (0x3000, 0x2000),
    ] {
        assert!(!pm.publish_kernel_object_pair(next, process, thread));
        assert_eq!(pm.process_kernel_object(next_pid), None);
        assert_eq!(pm.thread_kernel_object(next_tid), None);
    }
    pm.finish_process_object_retirement(retirement).unwrap();
    assert!(pm.publish_kernel_object_pair(next, 0x1000, 0x2000));
}
