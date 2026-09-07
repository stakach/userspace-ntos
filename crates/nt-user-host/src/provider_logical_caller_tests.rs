use super::*;
use crate::process_identity::ProcessGeneration;
use nt_process::{ProcessManager, ThreadState};

fn caller() -> (ProcessManager, ThreadBinding<()>, ProviderLogicalCaller) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("host.exe", None, None);
    pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let tid = pm.create_thread(pid, 0x2000, 0, false).unwrap();
    let binding = ThreadBinding {
        pi: 2,
        process: ProcessIdentity {
            pid,
            generation: ProcessGeneration::Hosted(3),
        },
        tid: u64::from(tid),
        badge: 4,
        role: (),
        tcb: 8,
        reservations: None,
    };
    let caller = ProviderLogicalCaller::capture(binding, pm.thread_lifetime(tid).unwrap()).unwrap();
    (pm, binding, caller)
}

#[test]
fn captures_exact_logical_identity_and_validates_without_mutation() {
    let (pm, binding, caller) = caller();
    assert_eq!(caller.pi(), binding.pi);
    assert_eq!(caller.process(), binding.process);
    assert_eq!(caller.thread().thread_id() as u64, binding.tid);
    assert_eq!(caller.badge(), binding.badge);
    assert_eq!(caller.tcb(), binding.tcb);
    let before = caller;
    assert_eq!(
        caller.validate(Some(binding), pm.thread_lifetime(binding.tid as u32)),
        Ok(())
    );
    assert_eq!(caller, before);
}

#[test]
fn zero_badge_and_zero_process_slot_are_valid_when_real_identity_is_admitted() {
    let (pm, mut binding, _) = caller();
    binding.pi = 0;
    binding.badge = 0;
    let thread = pm.thread_lifetime(binding.tid as u32).unwrap();
    let caller = ProviderLogicalCaller::capture(binding, thread).unwrap();
    assert_eq!(caller.validate(Some(binding), Some(thread)), Ok(()));
    assert_eq!(caller.pi(), 0);
    assert_eq!(caller.badge(), 0);
}

#[test]
fn absent_runtime_or_thread_cannot_acquire_startup_authority() {
    let (pm, binding, caller) = caller();
    let thread = pm.thread_lifetime(binding.tid as u32);
    assert_eq!(
        caller.validate::<()>(None, thread),
        Err(ProviderCallerError::MissingRuntime)
    );
    assert_eq!(
        caller.validate(Some(binding), None),
        Err(ProviderCallerError::MissingThread)
    );
    for tcb in [0, 1] {
        assert_eq!(
            ProviderLogicalCaller::capture(ThreadBinding { tcb, ..binding }, thread.unwrap()),
            Err(ProviderCallerError::InvalidBinding)
        );
    }
    assert_eq!(
        ProviderLogicalCaller::capture(
            ThreadBinding {
                process: ProcessIdentity::empty(),
                ..binding
            },
            thread.unwrap()
        ),
        Err(ProviderCallerError::InvalidBinding)
    );
}

#[test]
fn capture_rejects_wrong_thread_process_and_truncated_tid() {
    let (mut pm, binding, _) = caller();
    let thread = pm.thread_lifetime(binding.tid as u32).unwrap();
    let other_pid = pm.create_process("other.exe", None, None);
    let other_tid = pm.create_thread(other_pid, 0x1000, 0, false).unwrap();
    assert_eq!(
        ProviderLogicalCaller::capture(binding, pm.thread_lifetime(other_tid).unwrap()),
        Err(ProviderCallerError::ThreadMismatch)
    );
    assert_eq!(
        ProviderLogicalCaller::capture(
            ThreadBinding {
                tid: binding.tid | (1u64 << 32),
                ..binding
            },
            thread
        ),
        Err(ProviderCallerError::ThreadMismatch)
    );
    assert_eq!(
        ProviderLogicalCaller::capture(
            ThreadBinding {
                process: ProcessIdentity {
                    pid: other_pid,
                    ..binding.process
                },
                ..binding
            },
            thread
        ),
        Err(ProviderCallerError::ThreadMismatch)
    );
    assert_eq!(
        ProviderLogicalCaller::capture(ThreadBinding { tid: 0, ..binding }, thread),
        Err(ProviderCallerError::InvalidBinding)
    );
}

#[test]
fn same_tid_badge_and_tcb_after_reactivation_do_not_validate_old_job() {
    let (mut pm, binding, caller) = caller();
    let tid = binding.tid as u32;
    pm.terminate_thread(tid, 0).unwrap();
    let plan = pm
        .prepare_thread_activation(tid, 0x3000, 0, false, 0x7000, 0, false)
        .unwrap();
    pm.commit_thread_activation(plan).unwrap();
    let fresh = pm.thread_lifetime(tid).unwrap();
    assert_eq!(
        caller.validate(Some(binding), Some(fresh)),
        Err(ProviderCallerError::LifetimeChanged)
    );
    assert_ne!(caller.thread(), fresh);
    let new_job = ProviderLogicalCaller::capture(binding, fresh).unwrap();
    assert_eq!(new_job.validate(Some(binding), Some(fresh)), Ok(()));
    assert_ne!(new_job, caller);
}

#[test]
fn changed_process_generation_domain_badge_tcb_and_pi_are_rejected() {
    let (pm, binding, caller) = caller();
    let thread = pm.thread_lifetime(binding.tid as u32);
    for changed in [
        ThreadBinding {
            pi: binding.pi + 1,
            ..binding
        },
        ThreadBinding {
            badge: binding.badge + 1,
            ..binding
        },
        ThreadBinding {
            tcb: binding.tcb + 1,
            ..binding
        },
        ThreadBinding {
            process: ProcessIdentity {
                generation: ProcessGeneration::Hosted(4),
                ..binding.process
            },
            ..binding
        },
        ThreadBinding {
            process: ProcessIdentity {
                generation: ProcessGeneration::Temporary(3),
                ..binding.process
            },
            ..binding
        },
    ] {
        assert_eq!(
            caller.validate(Some(changed), thread),
            Err(ProviderCallerError::BindingChanged)
        );
    }
}

#[test]
fn nested_unrelated_caller_cannot_replace_outer_authority() {
    let (mut pm, binding, outer) = caller();
    let other_tid = pm
        .create_thread(binding.process.pid, 0x3000, 0, false)
        .unwrap();
    let inner_binding = ThreadBinding {
        tid: other_tid as u64,
        badge: 9,
        tcb: 10,
        ..binding
    };
    let inner_thread = pm.thread_lifetime(other_tid).unwrap();
    let inner = ProviderLogicalCaller::capture(inner_binding, inner_thread).unwrap();
    assert_eq!(
        outer.validate(Some(inner_binding), Some(inner_thread)),
        Err(ProviderCallerError::BindingChanged)
    );
    assert_eq!(
        inner.validate(Some(inner_binding), Some(inner_thread)),
        Ok(())
    );
    assert_eq!(
        outer.validate(Some(binding), pm.thread_lifetime(binding.tid as u32)),
        Ok(())
    );
}

#[test]
fn waiting_state_does_not_invalidate_identity_but_failed_admission_does() {
    let (mut pm, binding, caller) = caller();
    pm.set_thread_state(binding.tid as u32, ThreadState::Waiting)
        .unwrap();
    let thread = pm.thread_lifetime(binding.tid as u32);
    assert_eq!(caller.validate(Some(binding), thread), Ok(()));
    // The adapter excludes terminal/pending runtime rows instead of passing an ownership snapshot.
    pm.terminate_thread(binding.tid as u32, 0).unwrap();
    assert_eq!(
        caller.validate::<()>(None, thread),
        Err(ProviderCallerError::MissingRuntime)
    );
}
