use nt_user_host::initial_creation_progress::{InitialCreationProgress, InitialCreationStep};

#[test]
fn physical_start_survives_ps_commit_failure_without_replay_or_cancellation() {
    let mut progress = InitialCreationProgress::new();
    assert_eq!(progress.next_step(), InitialCreationStep::StartPhysical);
    assert!(progress.may_cancel_no_effects());
    progress.physical_started().unwrap();
    assert_eq!(progress.next_step(), InitialCreationStep::CommitPs);
    assert!(!progress.may_cancel_no_effects());
    // A failed Ps commit does not mutate the owner. Redrive must retry only Ps.
    assert_eq!(progress.next_step(), InitialCreationStep::CommitPs);
    assert!(progress.physical_started().is_err());
}

#[test]
fn ps_commit_survives_handle_delivery_failure_without_replaying_start_or_ps() {
    let mut progress = InitialCreationProgress::new();
    progress.physical_started().unwrap();
    progress.ps_committed().unwrap();
    assert_eq!(progress.next_step(), InitialCreationStep::PublishHandle);
    assert!(!progress.may_cancel_no_effects());
    // Handle publication can fail and retry while both prior effects remain committed.
    assert_eq!(progress.next_step(), InitialCreationStep::PublishHandle);
    assert!(progress.physical_started().is_err());
    assert!(progress.ps_committed().is_err());
}

#[test]
fn certified_no_effects_after_uncertainty_reopens_cancellation() {
    let mut progress = InitialCreationProgress::new();
    progress.physical_indeterminate().unwrap();
    progress.physical_refused_no_effects().unwrap();
    assert_eq!(progress.next_step(), InitialCreationStep::StartPhysical);
    assert!(progress.may_cancel_no_effects());
}

#[test]
fn uncertain_physical_effect_retains_owner_and_forbids_replay_or_cancellation() {
    let mut progress = InitialCreationProgress::new();
    progress.physical_indeterminate().unwrap();
    assert_eq!(progress.next_step(), InitialCreationStep::PhysicalIndeterminate);
    assert!(!progress.may_cancel_no_effects());
    assert!(progress.physical_started().is_err());
    assert!(progress.ps_committed().is_err());
    progress.physical_resolved().unwrap();
    assert_eq!(progress.next_step(), InitialCreationStep::CommitPs);
    assert!(!progress.may_cancel_no_effects());
}
