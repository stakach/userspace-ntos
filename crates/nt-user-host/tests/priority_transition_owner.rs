use nt_process::{ProcessManager, ThreadLifetime};
use nt_types::{ProcessGeneration, ProcessIdentity};
use nt_user_host::thread_binding::ThreadBinding;
use nt_user_host::thread_priority_transition::{
    PriorityEffect, PriorityTransitionError, PriorityTransitionOutcome,
    PriorityTransitionOwner,
};

fn bindings() -> (ThreadBinding<u8>, ThreadLifetime, ThreadBinding<u8>, ThreadLifetime) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("priority.exe", None, None);
    let first = pm.create_thread(pid, 0, 0, false).unwrap();
    let second = pm.create_thread(pid, 0, 0, false).unwrap();
    let process = ProcessIdentity {
        pid,
        generation: ProcessGeneration::Hosted(7),
    };
    let make = |tid, tcb| ThreadBinding {
        pi: 2,
        process,
        tid: u64::from(tid),
        badge: u64::from(tid) + 0x100,
        role: 1,
        tcb,
        reservations: None,
    };
    (make(first, 0x40), pm.thread_lifetime(first).unwrap(),
     make(second, 0x41), pm.thread_lifetime(second).unwrap())
}

#[test]
fn exact_bindings_apply_serially_and_only_acknowledged_effects_release_plan() {
    let (first, first_lifetime, second, second_lifetime) = bindings();
    let mut owner = PriorityTransitionOwner::new(
        "canonical PM plan",
        vec![
            PriorityEffect::new(first, first_lifetime, 72, 77),
            PriorityEffect::new(second, second_lifetime, 72, 81),
        ],
    ).unwrap();
    assert_eq!(owner.finish(), Err(PriorityTransitionError::NotComplete));
    assert_eq!(owner.begin(ThreadBinding { tcb: 0x99, ..first }, first_lifetime),
               Err(PriorityTransitionError::OwnerChanged));
    let first_call = owner.begin(first, first_lifetime).unwrap();
    assert_eq!((first_call.tcb(), first_call.previous(), first_call.next()), (0x40, 72, 77));
    assert_eq!(owner.begin(second, second_lifetime), Err(PriorityTransitionError::Busy));
    owner.complete(first_call, PriorityTransitionOutcome::Acknowledged).unwrap();
    assert_eq!(owner.finish(), Err(PriorityTransitionError::NotComplete));
    let second_call = owner.begin(second, second_lifetime).unwrap();
    assert_eq!((second_call.tcb(), second_call.previous(), second_call.next()), (0x41, 72, 81));
    owner.complete(second_call, PriorityTransitionOutcome::Acknowledged).unwrap();
    assert_eq!(owner.finish(), Ok("canonical PM plan"));
}

#[test]
fn uncertain_native_result_retains_binding_and_refuses_replay_or_commit() {
    let (first, first_lifetime, _, _) = bindings();
    let mut owner = PriorityTransitionOwner::new(
        13u32,
        vec![PriorityEffect::new(first, first_lifetime, 72, 77)],
    ).unwrap();
    let call = owner.begin(first, first_lifetime).unwrap();
    assert_eq!(owner.complete(call, PriorityTransitionOutcome::Indeterminate(0xc000_0001)),
               Err(PriorityTransitionError::Indeterminate(0xc000_0001)));
    assert_eq!(owner.begin(first, first_lifetime), Err(PriorityTransitionError::Busy));
    assert_eq!(owner.finish(), Err(PriorityTransitionError::NotComplete));
    assert_eq!(owner.retained_binding(), Some(first));
}

#[test]
fn duplicate_tcb_or_stale_thread_generation_is_refused_before_any_effect() {
    let (first, first_lifetime, second, second_lifetime) = bindings();
    assert_eq!(
        PriorityTransitionOwner::new((), vec![
            PriorityEffect::new(first, first_lifetime, 72, 77),
            PriorityEffect::new(ThreadBinding { tcb: first.tcb, ..second }, second_lifetime, 72, 81),
        ]).err(),
        Some(PriorityTransitionError::DuplicateOwner),
    );
    let mut owner = PriorityTransitionOwner::new(
        (), vec![PriorityEffect::new(first, first_lifetime, 72, 77)],
    ).unwrap();
    assert_eq!(owner.begin(first, second_lifetime), Err(PriorityTransitionError::OwnerChanged));
    assert_eq!(owner.finish(), Err(PriorityTransitionError::NotComplete));
}

#[test]
fn stale_pm_after_tcb_ack_refuses_commit_while_owner_retains_the_plan() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("stale.exe", None, None);
    let tid = pm.create_thread(pid, 0, 0, false).unwrap();
    assert!(pm.publish_thread_kernel_object(tid, 0x2000));
    let lifetime = pm.thread_lifetime(tid).unwrap();
    let binding = ThreadBinding {
        pi: 2,
        process: ProcessIdentity { pid, generation: ProcessGeneration::Hosted(7) },
        tid: u64::from(tid), badge: 0x100, role: 1u8, tcb: 0x40,
        reservations: None,
    };
    let plan = pm.prepare_kernel_thread_priority(0x2000, 12).unwrap();
    let mut owner = PriorityTransitionOwner::new(
        plan, vec![PriorityEffect::new(binding, lifetime, 77, 76)],
    ).unwrap();
    let call = owner.begin(binding, lifetime).unwrap();
    owner.complete(call, PriorityTransitionOutcome::Acknowledged).unwrap();
    pm.set_kernel_thread_priority(0x2000, 10).unwrap();
    assert_eq!(pm.commit_kernel_thread_priority_retained(owner.acknowledged_payload().unwrap()),
               Err(nt_process::STATUS_INVALID_PARAMETER));
    assert!(owner.acknowledged_payload().is_ok());
    assert_eq!(pm.thread_scheduling_state(tid).unwrap().priority, 10);
}
