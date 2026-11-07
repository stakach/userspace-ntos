//! A startup diagnostic may read registers only from the exact current main
//! thread, at a bounded cadence. Observing it never grants execution rights.

use crate::process_identity::{ProcessGeneration, ProcessIdentity};
use crate::startup_thread_sample::{StartupThreadSampleGate, StartupThreadSampleRoster};
use crate::thread_binding::ThreadBinding;
use nt_process::ProcessManager;

fn captured() -> (ProcessManager, ThreadBinding<()>, nt_process::ThreadLifetime) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("csrss.exe", None, None);
    // Keep the process's initial thread live while recycling a separate
    // activated ETHREAD identity. Last-thread exit would terminate the process.
    pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let tid = pm.create_dormant_thread(pid).unwrap();
    let plan = pm.prepare_thread_activation(tid, 0x2000, 0, false, 0x7000, 0, false).unwrap();
    pm.commit_thread_activation(plan).unwrap();
    let binding = ThreadBinding {
        pi: 1,
        process: ProcessIdentity { pid, generation: ProcessGeneration::Hosted(7) },
        tid: u64::from(tid),
        badge: 29,
        role: (),
        tcb: 138,
        reservations: None,
    };
    let lifetime = pm.thread_lifetime(tid).unwrap();
    (pm, binding, lifetime)
}

#[test]
fn startup_tcb_sample_is_generation_exact_and_does_not_spend_budget_on_stale_rows() {
    let (mut pm, binding, lifetime) = captured();
    let mut gate = StartupThreadSampleGate::new(binding, lifetime, 50_000_000, 3).unwrap();
    let first = 100_000_000;
    assert_eq!(gate.claim_sample(Some(binding), Some(lifetime), first), Some(1));

    let stale_process = ThreadBinding {
        process: ProcessIdentity {
            generation: ProcessGeneration::Hosted(8), ..binding.process
        },
        ..binding
    };
    assert_eq!(gate.claim_sample(Some(stale_process), Some(lifetime), first + 50_000_000), None);
    let reused_tcb = ThreadBinding { tcb: binding.tcb + 1, ..binding };
    assert_eq!(gate.claim_sample(Some(reused_tcb), Some(lifetime), first + 50_000_000), None);

    let tid = binding.tid as u32;
    pm.terminate_thread(tid, 0).unwrap();
    let plan = pm.prepare_thread_activation(tid, 0x3000, 0, false, 0x7000, 0, false).unwrap();
    pm.commit_thread_activation(plan).unwrap();
    let fresh_lifetime = pm.thread_lifetime(tid).unwrap();
    assert_ne!(lifetime, fresh_lifetime);
    assert_eq!(gate.claim_sample(Some(binding), Some(fresh_lifetime), first + 50_000_000), None,
        "same badge, TID, and TCB cannot adopt an old thread generation");
    assert_eq!(gate.claim_sample(Some(binding), Some(lifetime), first + 50_000_000), Some(2),
        "stale observations must not spend the old owner's finite diagnostic budget");
}

#[test]
fn startup_tcb_sample_obeys_interval_and_finite_cap() {
    let (_, binding, lifetime) = captured();
    let mut gate = StartupThreadSampleGate::new(binding, lifetime, 100_000_000, 2).unwrap();
    assert_eq!(gate.claim_sample(Some(binding), Some(lifetime), 1_000_000_000), Some(1));
    assert_eq!(gate.claim_sample(Some(binding), Some(lifetime), 1_000_000_000), None);
    assert_eq!(gate.claim_sample(Some(binding), Some(lifetime), 1_099_999_999), None);
    assert_eq!(gate.claim_sample(None, Some(lifetime), 1_100_000_000), None);
    assert_eq!(gate.claim_sample(Some(binding), None, 1_100_000_000), None);
    assert_eq!(gate.claim_sample(Some(binding), Some(lifetime), 1_100_000_000), Some(2));
    assert_eq!(gate.claim_sample(Some(binding), Some(lifetime), 1_200_000_000), None);
    assert!(StartupThreadSampleGate::new(binding, lifetime, 0, 2).is_none());
    assert!(StartupThreadSampleGate::new(binding, lifetime, 100_000_000, 0).is_none());
    assert!(StartupThreadSampleGate::new(
        ThreadBinding { tcb: 1, ..binding }, lifetime, 100_000_000, 2
    ).is_none());
}

#[test]
fn startup_roles_keep_independent_generation_exact_budgets() {
    let (_, binding, lifetime) = captured();
    let mut roster = StartupThreadSampleRoster::<(), 3>::new(100, 2).unwrap();
    assert_eq!(roster.claim(0, Some(binding), Some(lifetime), 1000), Some(1));
    assert_eq!(roster.claim(1, Some(binding), Some(lifetime), 1000), Some(1));
    assert_eq!(roster.claim(0, Some(binding), Some(lifetime), 1050), None);
    let recycled = ThreadBinding {
        process: ProcessIdentity {
            generation: ProcessGeneration::Hosted(8), ..binding.process
        },
        ..binding
    };
    assert_eq!(roster.claim(0, Some(recycled), Some(lifetime), 1100), Some(2));
    assert_eq!(roster.claim(0, Some(recycled), Some(lifetime), 1200), None);
    assert_eq!(roster.claim(1, Some(binding), Some(lifetime), 1100), Some(2));
    assert_eq!(roster.claim(2, Some(binding), Some(lifetime), 1100), Some(1));
    assert_eq!(roster.claim(3, Some(binding), Some(lifetime), 1100), None);
}
