use nt_hosted_runtime::{PrimaryAliasActivation, PrimaryAliasOwner, PrimaryAliasPhase};

#[test]
fn permanent_mapping_conflict_does_not_schedule_a_primary_retry() {
    use nt_hosted_runtime::{classify_alias_registration_status, AliasRetryDisposition};
    assert_eq!(
        classify_alias_registration_status(0xC000_0018),
        AliasRetryDisposition::Retain,
    );
    assert_eq!(
        classify_alias_registration_status(0xC000_009A),
        AliasRetryDisposition::Retry,
    );
}

const OWNER: PrimaryAliasOwner = PrimaryAliasOwner {
    process_index: 0, process_generation: 17, tcb: 0x1234,
};

#[test]
fn definitive_failure_schedules_one_due_retry_for_exact_owner() {
    let mut activation = PrimaryAliasActivation::new(OWNER).unwrap();
    assert!(activation.ready(OWNER));
    assert_eq!(activation.fail_definitive(OWNER, 100, 10), Some(110));
    assert_eq!(activation.phase(), PrimaryAliasPhase::RetryAt(110));
    assert_eq!(activation.next_deadline(), Some(110));
    assert!(!activation.ready(OWNER));
    assert_eq!(activation.fail_definitive(OWNER, 101, 10), None);
    assert!(!activation.wake_due(OWNER, 109));
    assert!(activation.wake_due(OWNER, 110));
    assert!(!activation.wake_due(OWNER, 110));
    assert_eq!(activation.next_deadline(), None);
    assert!(activation.ready(OWNER));
    assert_eq!(activation.fail_definitive(OWNER, 120, 10), Some(130));
}

#[test]
fn uncertain_effect_parks_without_replay_or_start() {
    let mut activation = PrimaryAliasActivation::new(OWNER).unwrap();
    assert!(activation.fail_uncertain(OWNER));
    assert_eq!(activation.phase(), PrimaryAliasPhase::ParkedUncertain);
    assert_eq!(activation.next_deadline(), None);
    assert!(!activation.ready(OWNER));
    assert!(!activation.wake_due(OWNER, u64::MAX));
    assert_eq!(activation.fail_definitive(OWNER, 200, 10), None);
    assert!(!activation.start(OWNER));
}

#[test]
fn stale_identity_cannot_wake_resume_or_replace_primary() {
    let mut activation = PrimaryAliasActivation::new(OWNER).unwrap();
    let stale = PrimaryAliasOwner { process_generation: 16, ..OWNER };
    let other_tcb = PrimaryAliasOwner { tcb: 0x5678, ..OWNER };
    assert!(!activation.ready(stale));
    assert_eq!(activation.fail_definitive(stale, 100, 10), None);
    assert!(!activation.fail_uncertain(other_tcb));
    assert!(!activation.start(other_tcb));
    assert_eq!(activation.phase(), PrimaryAliasPhase::Ready);
    assert!(activation.start(OWNER));
    assert_eq!(activation.phase(), PrimaryAliasPhase::Started);
    assert!(!activation.ready(OWNER));
    assert_eq!(activation.fail_definitive(OWNER, 200, 10), None);
    assert!(!activation.fail_uncertain(OWNER));
    assert!(!activation.start(OWNER));
    assert!(PrimaryAliasActivation::new(PrimaryAliasOwner { tcb: 0, ..OWNER }).is_none());
}
