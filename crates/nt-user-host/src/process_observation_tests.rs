use super::*;
use crate::process_identity::ProcessGeneration;
use crate::thread_binding::ThreadBinding;
use nt_process::ProcessManager;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Bootstrap,
    Shell,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fact {
    Window,
    Draw,
}
type Observations = ProcessObservations<Role, u64, Fact>;

fn fixture() -> (
    ProcessManager,
    ThreadBinding<()>,
    ProviderLogicalCaller,
    ObservationKey,
) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("observer.exe", None, None);
    pm.create_thread(pid, 0x3000, 0, false).unwrap();
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let binding = ThreadBinding {
        pi: 7,
        process: ProcessIdentity {
            pid,
            generation: ProcessGeneration::Hosted(2),
        },
        tid: u64::from(tid),
        badge: 614,
        role: (),
        tcb: 12,
        reservations: None,
    };
    let caller = ProviderLogicalCaller::capture(binding, pm.thread_lifetime(tid).unwrap()).unwrap();
    let key = ObservationKey {
        pi: binding.pi,
        process: binding.process,
    };
    (pm, binding, caller, key)
}

#[test]
fn publication_phases_are_independent_and_exact_duplicate_acks_are_idempotent() {
    let (_, _, caller, key) = fixture();
    let mut observations = Observations::new();
    assert_eq!(
        observations.register(key, Role::Shell, 42),
        Ok(ObservationAck::Recorded)
    );
    assert_eq!(
        observations.record_main_publication(key, caller, caller.thread()),
        Ok(ObservationAck::Recorded)
    );
    let snapshot = observations.historical_snapshot(key).unwrap();
    assert!(!snapshot.fully_published());
    assert!(!snapshot.publication(PublicationFact::VSpace));
    assert!(!snapshot.publication(PublicationFact::ProcessCatalog));
    assert_eq!(
        observations.record_publication(key, PublicationFact::VSpace),
        Ok(ObservationAck::Recorded)
    );
    assert!(!observations
        .historical_snapshot(key)
        .unwrap()
        .fully_published());
    assert_eq!(
        observations.record_publication(key, PublicationFact::ProcessCatalog),
        Ok(ObservationAck::Recorded)
    );
    assert!(observations
        .historical_snapshot(key)
        .unwrap()
        .fully_published());
    assert_eq!(
        observations.record_publication(key, PublicationFact::VSpace),
        Ok(ObservationAck::Duplicate)
    );
    assert_eq!(
        observations.record_main_publication(key, caller, caller.thread()),
        Ok(ObservationAck::Duplicate)
    );
    assert_eq!(
        observations.register(key, Role::Shell, 42),
        Ok(ObservationAck::Duplicate)
    );
    assert_eq!(
        observations.register(key, Role::Shell, 43),
        Err(ObservationError::ConflictingRegistration)
    );
    assert_eq!(
        observations.register(key, Role::Bootstrap, 42),
        Err(ObservationError::ConflictingRegistration)
    );
}

#[test]
fn foreign_generation_and_conflicting_main_receipt_cannot_borrow_observation() {
    let (pm, binding, caller, key) = fixture();
    let mut observations = Observations::new();
    observations.register(key, Role::Shell, 42).unwrap();
    observations
        .record_main_publication(key, caller, caller.thread())
        .unwrap();
    let foreign = ProviderLogicalCaller::capture(
        ThreadBinding {
            process: ProcessIdentity {
                generation: ProcessGeneration::Hosted(3),
                ..binding.process
            },
            ..binding
        },
        caller.thread(),
    )
    .unwrap();
    assert_eq!(
        observations.record_worker_activation(key, foreign, caller.thread()),
        Err(ObservationError::StaleCaller)
    );
    let other = ProviderLogicalCaller::capture(
        ThreadBinding { tcb: 13, ..binding },
        pm.thread_lifetime(binding.tid as u32).unwrap(),
    )
    .unwrap();
    assert_eq!(
        observations.record_main_publication(key, other, other.thread()),
        Err(ObservationError::ConflictingReceipt)
    );
    assert_eq!(
        observations
            .historical_snapshot(key)
            .unwrap()
            .main_publication(),
        Some(caller)
    );
}

#[test]
fn same_worker_lifetime_with_changed_physical_receipt_is_conflicting() {
    let (_, binding, caller, key) = fixture();
    let mut observations = Observations::new();
    observations.register(key, Role::Shell, 42).unwrap();
    observations
        .record_worker_activation(key, caller, caller.thread())
        .unwrap();
    for changed in [
        ThreadBinding { tcb: 13, ..binding },
        ThreadBinding {
            badge: binding.badge + 1,
            ..binding
        },
    ] {
        let conflicting = ProviderLogicalCaller::capture(changed, caller.thread()).unwrap();
        assert_eq!(
            observations.record_worker_activation(key, conflicting, conflicting.thread()),
            Err(ObservationError::ConflictingReceipt)
        );
        assert_eq!(
            observations
                .historical_snapshot(key)
                .unwrap()
                .worker_activations(),
            &[caller]
        );
    }
}

#[test]
fn reused_thread_generation_requires_fresh_activation_and_gui_caller_receipt() {
    let (mut pm, binding, caller, key) = fixture();
    let mut observations = Observations::new();
    observations.register(key, Role::Shell, 42).unwrap();
    observations
        .record_worker_activation(key, caller, caller.thread())
        .unwrap();
    assert_eq!(
        observations.record_worker_activation(key, caller, caller.thread()),
        Ok(ObservationAck::Duplicate)
    );
    pm.terminate_thread(binding.tid as u32, 0).unwrap();
    let plan = pm
        .prepare_thread_activation(binding.tid as u32, 0x2000, 0, false, 0x7000, 0, false)
        .unwrap();
    pm.commit_thread_activation(plan).unwrap();
    let current = pm.thread_lifetime(binding.tid as u32).unwrap();
    assert_ne!(current, caller.thread());
    assert_eq!(
        observations.record_worker_activation(key, caller, current),
        Err(ObservationError::StaleCaller)
    );
    assert_eq!(
        observations.record_gui_fact(key, caller, current, Fact::Draw, 1),
        Err(ObservationError::StaleCaller)
    );
    let fresh = ProviderLogicalCaller::capture(binding, current).unwrap();
    assert_eq!(
        observations.record_gui_fact(key, fresh, current, Fact::Draw, 1),
        Err(ObservationError::UnacknowledgedCaller)
    );
    observations
        .record_worker_activation(key, fresh, current)
        .unwrap();
    assert_eq!(
        observations.record_gui_fact(key, fresh, current, Fact::Draw, 1),
        Ok(1)
    );
    assert_eq!(
        observations
            .historical_snapshot(key)
            .unwrap()
            .worker_activations()
            .len(),
        2
    );
}

#[test]
fn gui_counts_are_per_kind_and_overflow_refuses_before_mutation() {
    let (_, _, caller, key) = fixture();
    let mut observations = Observations::new();
    observations.register(key, Role::Shell, 42).unwrap();
    assert_eq!(
        observations.record_gui_fact(key, caller, caller.thread(), Fact::Window, 1),
        Err(ObservationError::UnacknowledgedCaller)
    );
    observations
        .record_main_publication(key, caller, caller.thread())
        .unwrap();
    assert_eq!(
        observations.record_gui_fact(key, caller, caller.thread(), Fact::Window, 2),
        Ok(2)
    );
    assert_eq!(
        observations.record_gui_fact(key, caller, caller.thread(), Fact::Draw, u64::MAX),
        Ok(u64::MAX)
    );
    assert_eq!(
        observations.record_gui_fact(key, caller, caller.thread(), Fact::Draw, 1),
        Err(ObservationError::CountOverflow)
    );
    assert_eq!(
        observations.record_gui_fact(key, caller, caller.thread(), Fact::Window, 0),
        Err(ObservationError::InvalidCount)
    );
    let snapshot = observations.historical_snapshot(key).unwrap();
    assert_eq!(snapshot.gui_count(Fact::Draw), u64::MAX);
    assert_eq!(snapshot.gui_count(Fact::Window), 2);
    assert_eq!(snapshot.gui_fact_kinds(), 2, "no per-draw event log");
}

#[test]
fn immutable_terminal_and_retired_history_never_count_as_current_live() {
    let (_, _, caller, key) = fixture();
    let mut observations = Observations::new();
    observations.register(key, Role::Bootstrap, 42).unwrap();
    observations
        .record_main_publication(key, caller, caller.thread())
        .unwrap();
    observations
        .record_gui_fact(key, caller, caller.thread(), Fact::Window, 1)
        .unwrap();
    assert_eq!(
        observations.retire(key),
        Err(ObservationError::TerminalRequired)
    );
    assert!(observations.current_live_snapshot(key, key).is_some());
    assert_eq!(
        observations.record_terminal(key, 0),
        Ok(ObservationAck::Recorded)
    );
    assert_eq!(
        observations.record_terminal(key, 0),
        Ok(ObservationAck::Duplicate)
    );
    assert_eq!(
        observations.record_terminal(key, 0xc0000001),
        Err(ObservationError::ConflictingReceipt)
    );
    assert!(observations.current_live_snapshot(key, key).is_none());
    assert_eq!(observations.retire(key), Ok(ObservationAck::Recorded));
    assert_eq!(observations.retire(key), Ok(ObservationAck::Duplicate));
    let snapshot = observations.historical_snapshot(key).unwrap();
    assert_eq!(snapshot.terminal_status(), Some(0));
    assert!(snapshot.is_retired());
    assert_eq!(snapshot.gui_count(Fact::Window), 1);
    assert_eq!(
        observations.record_gui_fact(key, caller, caller.thread(), Fact::Draw, 1),
        Err(ObservationError::Inactive)
    );
}

#[test]
fn pi_and_pid_reuse_preserves_history_without_lending_facts_to_new_key() {
    let (_, binding, caller, key) = fixture();
    let mut observations = Observations::new();
    observations.register(key, Role::Bootstrap, 42).unwrap();
    observations
        .record_main_publication(key, caller, caller.thread())
        .unwrap();
    observations.record_terminal(key, 0).unwrap();
    observations.retire(key).unwrap();
    let fresh_key = ObservationKey {
        process: ProcessIdentity {
            generation: ProcessGeneration::Hosted(3),
            ..binding.process
        },
        ..key
    };
    observations.register(fresh_key, Role::Shell, 43).unwrap();
    let fresh = observations
        .current_live_snapshot(fresh_key, fresh_key)
        .unwrap();
    assert_eq!(fresh.image(), &43);
    assert_eq!(fresh.main_publication(), None);
    assert_eq!(fresh.gui_count(Fact::Window), 0);
    assert!(!fresh.fully_published());
    assert!(observations.current_live_snapshot(key, fresh_key).is_none());
    assert_eq!(
        observations.record_main_publication(fresh_key, caller, caller.thread()),
        Err(ObservationError::StaleCaller)
    );
    assert!(observations.historical_snapshot(key).unwrap().is_retired());
}

#[test]
fn role_selection_refuses_ambiguity_and_uses_only_supplied_current_keys() {
    let (_, _, _, key) = fixture();
    let second = ObservationKey {
        pi: key.pi + 1,
        process: ProcessIdentity {
            pid: key.process.pid + 1,
            generation: ProcessGeneration::Hosted(9),
        },
    };
    let mut observations = Observations::new();
    observations.register(key, Role::Shell, 42).unwrap();
    observations.register(second, Role::Shell, 43).unwrap();
    assert_eq!(
        observations
            .live_for_role(Role::Shell, &[key, second])
            .err(),
        Some(ObservationError::AmbiguousRole)
    );
    assert_eq!(
        observations
            .live_for_role(Role::Shell, &[second])
            .unwrap()
            .unwrap()
            .key(),
        second
    );
    assert!(observations
        .live_for_role(Role::Bootstrap, &[key, second])
        .unwrap()
        .is_none());
    observations.record_terminal(second, 0).unwrap();
    observations.retire(second).unwrap();
    assert_eq!(
        observations
            .live_for_role(Role::Shell, &[key, second])
            .unwrap()
            .unwrap()
            .key(),
        key
    );
    assert!(observations
        .live_for_role(Role::Shell, &[])
        .unwrap()
        .is_none());
}
