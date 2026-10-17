use nt_process::{ProcessManager, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER};

#[test]
fn kernel_thread_priority_plan_commits_only_for_exact_unchanged_activation() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("thread.exe", None, None);
    let tid = pm.create_thread(pid, 0, 0, false).unwrap();
    assert!(pm.publish_thread_kernel_object(tid, 0x2000));
    let original = pm.thread_scheduling_state(tid).unwrap().priority;

    let plan = pm.prepare_kernel_thread_priority(0x2000, 12).unwrap();
    assert_eq!(plan.lifetime(), pm.thread_lifetime(tid).unwrap());
    assert_eq!((plan.previous(), plan.next()), (original, 12));
    assert_eq!(pm.thread_scheduling_state(tid).unwrap().priority, original);
    assert_eq!(pm.commit_kernel_thread_priority(plan), Ok(original));
    assert_eq!(pm.thread_scheduling_state(tid).unwrap().priority, 12);

    let stale = pm.prepare_kernel_thread_priority(0x2000, 13).unwrap();
    pm.set_kernel_thread_priority(0x2000, 10).unwrap();
    assert_eq!(pm.commit_kernel_thread_priority(stale), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(pm.thread_scheduling_state(tid).unwrap().priority, 10);
    assert_eq!(pm.prepare_kernel_thread_priority(0xdead, 13).err(), Some(STATUS_INVALID_HANDLE));
}

#[test]
fn hosted_system_worker_priority_plan_cannot_target_its_requestor() {
    let mut pm = ProcessManager::new();
    let system = pm.create_process("System", None, None);
    let requestor = pm.create_thread(system, 0x1000, 0, true).unwrap();
    let worker = pm.create_thread(system, 0x2000, 0, true).unwrap();
    assert!(pm.publish_thread_kernel_object(requestor, 0x4000));
    assert!(pm.publish_thread_kernel_object(worker, 0x5000));
    let requestor_before = pm.thread_scheduling_state(requestor).unwrap().priority;
    let worker_before = pm.thread_scheduling_state(worker).unwrap().priority;

    let plan = pm.prepare_kernel_thread_priority(0x5000, 16).unwrap();
    assert_eq!(plan.lifetime(), pm.thread_lifetime(worker).unwrap());
    assert_eq!(plan.previous(), worker_before);
    assert_eq!(pm.thread_scheduling_state(worker).unwrap().priority, worker_before);
    assert_eq!(pm.commit_kernel_thread_priority_retained(&plan), Ok(worker_before));
    assert_eq!(pm.thread_scheduling_state(worker).unwrap().priority, 16);
    assert_eq!(pm.thread_scheduling_state(requestor).unwrap().priority, requestor_before);
}
