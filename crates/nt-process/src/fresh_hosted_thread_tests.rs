use super::*;

fn process() -> (ProcessManager, ProcessId) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("host", None, None);
    pm.create_thread(pid, 0x1000, 0, false).unwrap();
    (pm, pid)
}

#[test]
fn fresh_identity_preserves_retained_terminated_thread() {
    let (mut pm, pid) = process();
    let old = pm.create_thread(pid, 0x2000, 0, false).unwrap();
    assert!(pm.publish_thread_kernel_object(old, 0x8000));
    let handle = pm
        .insert_handle(pid, HandleObject::Thread(old), 0x1f_ffff)
        .unwrap();
    pm.terminate_thread(old, 0x1234).unwrap();
    let old_lifetime = pm.thread_lifetime(old).unwrap();
    assert!(!pm.can_reclaim_thread(old));
    let fresh = pm.prepare_fresh_hosted_thread(pid).unwrap();
    let tid = fresh.lifetime().thread_id;
    assert_ne!(old, tid);
    let activation = pm
        .prepare_thread_activation(tid, 0x3000, 0, true, 0x7000, 0, false)
        .unwrap();
    pm.commit_thread_activation(activation).unwrap();
    assert_eq!(pm.thread_lifetime(old), Some(old_lifetime));
    assert_eq!(pm.thread(old).unwrap().exit_status, Some(0x1234));
    assert!(pm.is_thread_signaled(old));
    assert_eq!(pm.thread_kernel_object(old), Some(0x8000));
    assert_eq!(
        pm.handle_object_reference_count(HandleObject::Thread(old)),
        1
    );
    assert_eq!(
        pm.resolve_thread_handle(
            pid,
            pm.process(pid).unwrap().main_thread.unwrap(),
            u64::from(handle),
            0
        ),
        Ok(old)
    );
    assert!(pm.cancel_fresh_hosted_thread(&fresh).is_err());
}

#[test]
fn unborn_cancel_removes_only_exact_identity_and_never_reuses_cid() {
    let (mut pm, pid) = process();
    let before = pm.process(pid).unwrap().threads.len();
    let fresh = pm.prepare_fresh_hosted_thread(pid).unwrap();
    let tid = fresh.lifetime().thread_id;
    pm.cancel_fresh_hosted_thread(&fresh).unwrap();
    assert!(pm.thread(tid).is_none());
    assert_eq!(pm.process(pid).unwrap().threads.len(), before);
    assert!(pm.cancel_fresh_hosted_thread(&fresh).is_err());
    assert_ne!(
        pm.prepare_fresh_hosted_thread(pid)
            .unwrap()
            .lifetime()
            .thread_id,
        tid
    );
}

#[test]
fn unborn_cancel_refuses_body_and_bound_or_published_handles() {
    let (mut pm, pid) = process();
    let fresh = pm.prepare_fresh_hosted_thread(pid).unwrap();
    let tid = fresh.lifetime().thread_id;
    let reservation = pm.try_reserve_handle_slot(pid).unwrap();
    pm.bind_reserved_handle(reservation, HandleObject::Thread(tid), 0)
        .unwrap();
    assert_eq!(
        pm.cancel_fresh_hosted_thread(&fresh),
        Err(STATUS_DEVICE_BUSY)
    );
    pm.cancel_bound_handle(reservation).unwrap();
    let handle = pm.insert_handle(pid, HandleObject::Thread(tid), 0).unwrap();
    assert_eq!(
        pm.cancel_fresh_hosted_thread(&fresh),
        Err(STATUS_DEVICE_BUSY)
    );
    pm.close_handle(pid, handle).unwrap();
    assert!(pm.publish_thread_kernel_object(tid, 0x9000));
    assert_eq!(
        pm.cancel_fresh_hosted_thread(&fresh),
        Err(STATUS_DEVICE_BUSY)
    );
    assert!(pm.thread(tid).is_some());
}

#[test]
fn foreign_manager_cannot_cancel_matching_numeric_identity() {
    let (mut first, pid) = process();
    let (mut second, other_pid) = process();
    let fresh = first.prepare_fresh_hosted_thread(pid).unwrap();
    let other = second.prepare_fresh_hosted_thread(other_pid).unwrap();
    assert_eq!(fresh.lifetime(), other.lifetime());
    assert_eq!(
        second.cancel_fresh_hosted_thread(&fresh),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert!(second.thread(other.lifetime().thread_id).is_some());
}

#[test]
fn exhausted_cid_preparation_does_not_mutate_process_or_threads() {
    let (mut pm, pid) = process();
    let count = pm.threads.len();
    let members = pm.process(pid).unwrap().threads.len();
    pm.next_cid = u32::MAX - 3;
    assert_eq!(
        pm.prepare_fresh_hosted_thread(pid),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(pm.threads.len(), count);
    assert_eq!(pm.process(pid).unwrap().threads.len(), members);
    assert_eq!(pm.next_cid, u32::MAX - 3);
}

#[test]
fn real_table_allocation_refusal_keeps_preparation_unpublished() {
    let (mut pm, pid) = process();
    let count = pm.threads.len();
    let members = pm.process(pid).unwrap().threads.len();
    let next = pm.next_cid;
    assert_eq!(
        pm.prepare_fresh_hosted_thread_with_reserve(pid, usize::MAX),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(pm.threads.len(), count);
    assert_eq!(pm.process(pid).unwrap().threads.len(), members);
    assert_eq!(pm.next_cid, next);
    let fresh = pm.prepare_fresh_hosted_thread(pid).unwrap();
    assert_eq!(fresh.lifetime().thread_id, next);
}

#[test]
fn unborn_wait_reference_blocks_cancel_until_exact_release() {
    let (mut pm, pid) = process();
    let fresh = pm.prepare_fresh_hosted_thread(pid).unwrap();
    let tid = fresh.lifetime().thread_id;
    pm.retain_thread_wait_reference(tid).unwrap();
    assert_eq!(
        pm.cancel_fresh_hosted_thread(&fresh),
        Err(STATUS_DEVICE_BUSY)
    );
    pm.release_thread_wait_reference(tid).unwrap();
    pm.cancel_fresh_hosted_thread(&fresh).unwrap();
}
