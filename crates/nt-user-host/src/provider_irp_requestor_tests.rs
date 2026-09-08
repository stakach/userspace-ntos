use super::*;
use crate::process_identity::{ProcessGeneration, ProcessIdentity};

fn fixture() -> (ProcessManager, ThreadBinding<()>, ProviderLogicalCaller) {
    let mut pm = ProcessManager::new();
    let system_pid = pm.create_process("kernel", None, None);
    let system_tid = pm.create_thread(system_pid, 0, 0, true).unwrap();
    pm.designate_initial_system(system_pid, system_tid).unwrap();
    assert!(pm.publish_process_kernel_object(system_pid, 0x1000));
    assert!(pm.publish_thread_kernel_object(system_tid, 0x2000));
    let pid = pm.create_process("requestor", None, None);
    let tid = pm.create_thread(pid, 0x5000, 0, false).unwrap();
    assert!(pm.publish_process_kernel_object(pid, 0x3000));
    assert!(pm.publish_thread_kernel_object(tid, 0x4000));
    let binding = ThreadBinding {
        pi: 2,
        process: ProcessIdentity {
            pid,
            generation: ProcessGeneration::Hosted(3),
        },
        tid: u64::from(tid),
        badge: 7,
        role: (),
        tcb: 9,
        reservations: None,
    };
    let caller = ProviderLogicalCaller::capture(binding, pm.thread_lifetime(tid).unwrap()).unwrap();
    (pm, binding, caller)
}

fn references(pm: &ProcessManager, caller: ProviderLogicalCaller) -> u32 {
    pm.process_object_delete_blockers(caller.process().pid)
        .unwrap()
        .thread_kernel_pointer_references
}

fn process_references(pm: &ProcessManager, caller: ProviderLogicalCaller) -> u32 {
    pm.process_object_delete_blockers(caller.process().pid)
        .unwrap()
        .process_kernel_pointer_references
}

#[test]
fn hosted_capture_retains_the_real_thread_not_its_process_or_executor() {
    let (mut pm, binding, caller) = fixture();
    let mut owner = ProviderIrpRequestor::capture_hosted(caller, Some(binding), &mut pm).unwrap();
    assert_eq!(owner.thread_lifetime(), caller.thread());
    assert_eq!(owner.requestor_tid(), binding.tid);
    assert_eq!(owner.thread_body(), Some(0x4000));
    assert_eq!(owner.process_body(), Some(0x3000));
    assert_eq!(owner.requestor_pid(), u64::from(caller.process().pid));
    assert_ne!(
        owner.thread_body(),
        pm.process_kernel_object(caller.process().pid)
    );
    assert_ne!(owner.thread_body(), Some(binding.tcb));
    assert_eq!(references(&pm, caller), 1);
    assert_eq!(process_references(&pm, caller), 1);
    owner.release(&mut pm).unwrap();
    assert_eq!(references(&pm, caller), 0);
    assert_eq!(process_references(&pm, caller), 0);
    assert!(!owner.is_held());
    assert_eq!(owner.thread_body(), None);
    assert_eq!(owner.process_body(), None);
    assert!(owner.release(&mut pm).is_err());
    assert_eq!(references(&pm, caller), 0);
}

#[test]
fn initial_system_capture_is_explicit_and_preserves_the_bootstrap_reference_floor() {
    let (mut pm, _, _) = fixture();
    let identity = pm.initial_system_identity().unwrap();
    let before = pm
        .process_object_delete_blockers(identity.process_id())
        .unwrap()
        .thread_kernel_pointer_references;
    let process_before = pm
        .process_object_delete_blockers(identity.process_id())
        .unwrap()
        .process_kernel_pointer_references;
    let mut owner = ProviderIrpRequestor::capture_initial_system(identity, &mut pm).unwrap();
    assert_eq!(owner.thread_body(), Some(0x2000));
    assert_eq!(owner.process_body(), Some(0x1000));
    assert_eq!(owner.thread_lifetime(), identity.thread());
    assert_eq!(owner.requestor_tid(), u64::from(identity.thread_id()));
    assert_eq!(
        pm.process_object_delete_blockers(identity.process_id())
            .unwrap()
            .thread_kernel_pointer_references,
        before + 1
    );
    assert_eq!(
        pm.process_object_delete_blockers(identity.process_id())
            .unwrap()
            .process_kernel_pointer_references,
        process_before + 1
    );
    owner.release(&mut pm).unwrap();
    assert_eq!(
        pm.process_object_delete_blockers(identity.process_id())
            .unwrap()
            .thread_kernel_pointer_references,
        before
    );
    assert_eq!(
        pm.process_object_delete_blockers(identity.process_id())
            .unwrap()
            .process_kernel_pointer_references,
        process_before
    );
    assert!(pm.validate_initial_system_caller(identity));
}

#[test]
fn missing_or_changed_admission_never_acquires_a_reference() {
    let (mut pm, binding, caller) = fixture();
    assert!(matches!(
        ProviderIrpRequestor::capture_hosted::<()>(caller, None, &mut pm),
        Err(ProviderIrpRequestorError::Caller(
            ProviderCallerError::MissingRuntime
        ))
    ));
    for variant in 0..5 {
        let mut changed = binding;
        match variant {
            0 => changed.pi += 1,
            1 => changed.process.generation = ProcessGeneration::Hosted(4),
            2 => changed.tid += 1,
            3 => changed.badge += 1,
            _ => changed.tcb += 1,
        }
        assert!(ProviderIrpRequestor::capture_hosted(caller, Some(changed), &mut pm).is_err());
        assert_eq!(references(&pm, caller), 0);
        assert_eq!(process_references(&pm, caller), 0);
    }
}

#[test]
fn foreign_initial_designation_and_release_do_not_touch_colliding_ps_objects() {
    let (mut pm, binding, caller) = fixture();
    let (mut foreign, _, foreign_caller) = fixture();
    assert!(matches!(
        ProviderIrpRequestor::capture_initial_system(
            foreign.initial_system_identity().unwrap(),
            &mut pm
        ),
        Err(ProviderIrpRequestorError::InvalidInitialSystem)
    ));
    let mut owner = ProviderIrpRequestor::capture_hosted(caller, Some(binding), &mut pm).unwrap();
    assert!(owner.release(&mut foreign).is_err());
    assert!(owner.is_held());
    assert_eq!(owner.thread_body(), Some(0x4000));
    assert_eq!(references(&pm, caller), 1);
    assert_eq!(references(&foreign, foreign_caller), 0);
    assert_eq!(process_references(&foreign, foreign_caller), 0);
    assert_eq!(process_references(&pm, caller), 1);
    owner.release(&mut pm).unwrap();
    assert_eq!(references(&pm, caller), 0);
}

#[test]
fn caller_exit_prevents_new_capture_but_retained_requestor_remains_releasable() {
    let (mut pm, binding, caller) = fixture();
    let mut owner = ProviderIrpRequestor::capture_hosted(caller, Some(binding), &mut pm).unwrap();
    pm.terminate_thread(caller.thread().thread_id(), 0).unwrap();
    assert!(ProviderIrpRequestor::capture_hosted(caller, Some(binding), &mut pm).is_err());
    assert!(!pm.can_reclaim_thread(caller.thread().thread_id()));
    assert_eq!(references(&pm, caller), 1);
    owner.release(&mut pm).unwrap();
    assert!(pm.can_reclaim_thread(caller.thread().thread_id()));
}

#[test]
fn process_retirement_cannot_remove_an_irps_requestor_thread() {
    let (mut pm, binding, caller) = fixture();
    let mut owner = ProviderIrpRequestor::capture_hosted(caller, Some(binding), &mut pm).unwrap();
    let pid = caller.process().pid;
    pm.terminate_process(pid, 0).unwrap();
    assert!(pm.abort_process_creation(pid).is_none());
    assert!(pm.thread(caller.thread().thread_id()).is_some());
    assert_eq!(owner.thread_body(), Some(0x4000));
    assert_eq!(owner.process_body(), Some(0x3000));
    owner.release(&mut pm).unwrap();
    assert!(pm.abort_process_creation(pid).is_some());
    assert!(pm.thread(caller.thread().thread_id()).is_none());
}

#[test]
fn missing_projection_fails_before_reference_acquisition() {
    let (mut pm, _, _) = fixture();
    let pid = pm.create_process("no-body", None, None);
    let tid = pm.create_thread(pid, 0x5000, 0, false).unwrap();
    let binding = ThreadBinding {
        pi: 3,
        process: ProcessIdentity {
            pid,
            generation: ProcessGeneration::Hosted(1),
        },
        tid: u64::from(tid),
        badge: 11,
        role: (),
        tcb: 12,
        reservations: None,
    };
    let caller = ProviderLogicalCaller::capture(binding, pm.thread_lifetime(tid).unwrap()).unwrap();
    assert!(ProviderIrpRequestor::capture_hosted(caller, Some(binding), &mut pm).is_err());
    assert_eq!(references(&pm, caller), 0);
    assert_eq!(process_references(&pm, caller), 0);
}

#[test]
fn a_single_published_body_cannot_leave_half_a_requestor_reference() {
    for publish_thread in [false, true] {
        let (mut pm, _, _) = fixture();
        let pid = pm.create_process("partial-body", None, None);
        let tid = pm.create_thread(pid, 0x5000, 0, false).unwrap();
        if publish_thread {
            assert!(pm.publish_thread_kernel_object(tid, 0x6000));
        } else {
            assert!(pm.publish_process_kernel_object(pid, 0x5000));
        }
        let binding = ThreadBinding {
            pi: 3,
            process: ProcessIdentity {
                pid,
                generation: ProcessGeneration::Hosted(1),
            },
            tid: u64::from(tid),
            badge: 11,
            role: (),
            tcb: 12,
            reservations: None,
        };
        let caller =
            ProviderLogicalCaller::capture(binding, pm.thread_lifetime(tid).unwrap()).unwrap();
        assert!(ProviderIrpRequestor::capture_hosted(caller, Some(binding), &mut pm).is_err());
        assert_eq!(references(&pm, caller), 0);
        assert_eq!(process_references(&pm, caller), 0);
    }
}

#[test]
fn dropping_owner_does_not_pretend_to_release_an_external_reference() {
    let (mut pm, binding, caller) = fixture();
    let owner = ProviderIrpRequestor::capture_hosted(caller, Some(binding), &mut pm).unwrap();
    drop(owner);
    assert_eq!(references(&pm, caller), 1);
    assert_eq!(process_references(&pm, caller), 1);
    assert!(pm.abort_process_creation(caller.process().pid).is_none());
}
