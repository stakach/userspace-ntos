use nt_process::{
    ProcessManager, ProcessPriorityQuantumPolicy, PROCESS_PRIORITY_CLASS_HIGH,
    PROCESS_PRIORITY_CLASS_IDLE, PROCESS_PRIORITY_CLASS_REALTIME, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER,
};

fn policy() -> ProcessPriorityQuantumPolicy {
    // An explicit, admitted policy input keeps host tests independent of boot registry state.
    ProcessPriorityQuantumPolicy {
        foreground_quantums: [12, 18, 24],
        priority_separation: 2,
        use_job_scheduling_classes: false,
    }
}

#[test]
fn by_class_applies_exact_mode_priority_quantum_memory_and_thread_delta() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("gui.exe", None, None);
    pm.set_process_base_priority(pid, 8).unwrap();
    let tid = pm.create_thread(pid, 0, 0, false).unwrap();
    assert!(pm.publish_process_kernel_object(pid, 0x1000));
    assert!(pm.publish_thread_kernel_object(tid, 0x2000));
    assert_eq!(pm.set_kernel_thread_priority(0x2000, 10), Ok(8));

    // ReactOS computes memory priority before KeSetPriorityAndQuantumProcess. If the computed
    // base is unchanged, Ke returns before updating quantum or any thread priority.
    let initial_process = pm.process_scheduling_state_for_kernel_object(0x1000).unwrap();
    let initial_thread = pm.thread_scheduling_state(tid).unwrap();
    assert_eq!(pm.set_process_priority_by_class_for_kernel_object(0x1000, 0, policy()), Ok(()));
    let same_base = pm.process_scheduling_state_for_kernel_object(0x1000).unwrap();
    assert_eq!(same_base.base_priority, 8);
    assert_eq!(same_base.memory_priority, 2);
    assert_eq!(same_base.quantum_reset, initial_process.quantum_reset);
    assert_eq!(pm.thread_scheduling_state(tid).unwrap(), initial_thread);

    // Class mutation alone changes only EPROCESS.PriorityClass. ByClass then computes the
    // foreground quantum and propagates the base-priority delta to the live thread.
    assert_eq!(pm.set_priority_class_for_kernel_process_object(0x1000, PROCESS_PRIORITY_CLASS_HIGH), Ok(()));
    assert_eq!(pm.process_scheduling_state_for_kernel_object(0x1000).unwrap().base_priority, 8);
    assert_eq!(pm.set_process_priority_by_class_for_kernel_object(0x1000, 0, policy()), Ok(()));
    let foreground = pm.process_scheduling_state_for_kernel_object(0x1000).unwrap();
    assert_eq!(foreground.priority_class, PROCESS_PRIORITY_CLASS_HIGH);
    assert_eq!(foreground.base_priority, 13);
    assert_eq!(foreground.quantum_reset, 24);
    assert_eq!(foreground.memory_priority, 2);
    let thread = pm.thread_scheduling_state(tid).unwrap();
    assert_eq!((thread.base_priority, thread.priority, thread.quantum_reset), (13, 13, 24));

    assert_eq!(pm.set_priority_class_for_kernel_process_object(0x1000, PROCESS_PRIORITY_CLASS_IDLE), Ok(()));
    assert_eq!(pm.set_process_priority_by_class_for_kernel_object(0x1000, 1, policy()), Ok(()));
    let background = pm.process_scheduling_state_for_kernel_object(0x1000).unwrap();
    assert_eq!((background.priority_class, background.base_priority, background.quantum_reset, background.memory_priority),
        (PROCESS_PRIORITY_CLASS_IDLE, 4, 6, 0));
    let thread = pm.thread_scheduling_state(tid).unwrap();
    assert_eq!((thread.base_priority, thread.priority, thread.quantum_reset), (4, 4, 6));

    // Spinning uses the background quantum but preserves the prior memory priority.
    assert_eq!(pm.set_priority_class_for_kernel_process_object(0x1000, PROCESS_PRIORITY_CLASS_REALTIME), Ok(()));
    assert_eq!(pm.set_process_priority_by_class_for_kernel_object(0x1000, 2, policy()), Ok(()));
    let spinning = pm.process_scheduling_state_for_kernel_object(0x1000).unwrap();
    assert_eq!((spinning.priority_class, spinning.base_priority, spinning.quantum_reset, spinning.memory_priority),
        (PROCESS_PRIORITY_CLASS_REALTIME, 24, 12, 0));
    let thread = pm.thread_scheduling_state(tid).unwrap();
    assert_eq!((thread.base_priority, thread.priority, thread.quantum_reset), (24, 24, 12));

    let before = (spinning, thread);
    assert_eq!(pm.set_process_priority_by_class_for_kernel_object(0x1000, 3, policy()), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(pm.process_scheduling_state_for_kernel_object(0x1000).unwrap(), before.0);
    assert_eq!(pm.thread_scheduling_state(tid).unwrap(), before.1);
    assert_eq!(pm.set_process_priority_by_class_for_kernel_object(0xDEAD, 0, policy()), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn by_class_refuses_withdrawn_eprocess_without_changing_other_process() {
    let mut pm = ProcessManager::new();
    let retired = pm.create_process("retired.exe", None, None);
    let live = pm.create_process("live.exe", None, None);
    assert!(pm.publish_process_kernel_object(retired, 0x3000));
    assert!(pm.publish_process_kernel_object(live, 0x4000));
    assert!(pm.abort_process_creation(retired).is_some());
    let before = pm.process_scheduling_state_for_kernel_object(0x4000).unwrap();
    assert_eq!(pm.set_process_priority_by_class_for_kernel_object(0x3000, 0, policy()), Err(STATUS_INVALID_HANDLE));
    assert_eq!(pm.process_scheduling_state_for_kernel_object(0x4000).unwrap(), before);
}

#[test]
fn prepared_by_class_plan_refuses_stale_process_or_thread_without_partial_commit() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("planned.exe", None, None);
    pm.set_process_base_priority(pid, 8).unwrap();
    let tid = pm.create_thread(pid, 0, 0, false).unwrap();
    assert!(pm.publish_process_kernel_object(pid, 0x5000));
    assert!(pm.publish_thread_kernel_object(tid, 0x6000));
    pm.set_priority_class_for_kernel_process_object(0x5000, PROCESS_PRIORITY_CLASS_HIGH).unwrap();

    let process_plan = pm.prepare_process_priority_by_class_for_kernel_object(0x5000, 0, policy()).unwrap();
    pm.set_priority_class_for_kernel_process_object(0x5000, PROCESS_PRIORITY_CLASS_IDLE).unwrap();
    let process_before = pm.process_scheduling_state_for_kernel_object(0x5000).unwrap();
    let thread_before = pm.thread_scheduling_state(tid).unwrap();
    assert_eq!(pm.commit_process_priority_by_class(process_plan), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(pm.process_scheduling_state_for_kernel_object(0x5000).unwrap(), process_before);
    assert_eq!(pm.thread_scheduling_state(tid).unwrap(), thread_before);

    let thread_plan = pm.prepare_process_priority_by_class_for_kernel_object(0x5000, 1, policy()).unwrap();
    assert_eq!(pm.set_kernel_thread_priority(0x6000, 10), Ok(8));
    let process_before = pm.process_scheduling_state_for_kernel_object(0x5000).unwrap();
    let thread_before = pm.thread_scheduling_state(tid).unwrap();
    assert_eq!(pm.commit_process_priority_by_class(thread_plan), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(pm.process_scheduling_state_for_kernel_object(0x5000).unwrap(), process_before);
    assert_eq!(pm.thread_scheduling_state(tid).unwrap(), thread_before);
}
