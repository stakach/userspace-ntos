use super::*;
use crate::process_identity::ProcessGeneration;
use crate::thread_binding::ThreadBinding;
use nt_process::ProcessManager;

#[test]
fn foreign_vm_lock_keeps_caller_reply_separate_from_target_generation() {
    let mut pm = ProcessManager::new();
    let caller_pid = pm.create_process("caller.exe", None, None);
    let target_pid = pm.create_process("target.exe", None, None);
    let tid = pm.create_thread(caller_pid, 0x1000, 0, false).unwrap();
    let binding = ThreadBinding {
        pi: 2, process: ProcessIdentity { pid: caller_pid, generation: ProcessGeneration::Hosted(7) },
        tid: u64::from(tid), badge: 11, role: (), tcb: 13, reservations: None,
    };
    let caller = ProviderLogicalCaller::capture(binding, pm.thread_lifetime(tid).unwrap()).unwrap();
    let target = ProcessIdentity { pid: target_pid, generation: ProcessGeneration::Hosted(17) };
    let owner = VmLockInvocationOwner::capture(caller, 5, target, 19)
        .expect("foreign target must retain its own process generation");
    assert!(owner.matches(caller, 5, target, 19));
    assert!(!owner.matches(caller, 5, ProcessIdentity {
        generation: ProcessGeneration::Hosted(18), ..target
    }, 19));
    assert!(!owner.matches(caller, 2, target, 19));
    assert!(!owner.matches(caller, 5, target, 20));
    let changed_binding = ThreadBinding { tcb: 14, ..binding };
    let changed = ProviderLogicalCaller::capture(changed_binding, pm.thread_lifetime(tid).unwrap()).unwrap();
    assert!(!owner.matches(changed, 5, target, 19));
}
