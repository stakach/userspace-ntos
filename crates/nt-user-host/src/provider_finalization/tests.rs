use super::*;

#[test]
fn required_finalization_marks_invoking_before_any_result() {
    let mut owner = ProviderFinalization::new(true);
    assert_eq!(owner.phase(), ProviderFinalizationPhase::Pending);
    assert!(!owner.ready());
    owner.begin().unwrap();
    assert_eq!(owner.phase(), ProviderFinalizationPhase::Invoking);
    assert!(!owner.ready());
    assert_eq!(owner.begin(), Err(ProviderFinalizationError::InvalidPhase));
    assert_eq!(owner.phase(), ProviderFinalizationPhase::Invoking);
}

#[test]
fn accepted_finalization_cannot_be_replayed() {
    let mut owner = ProviderFinalization::new(true);
    owner.begin().unwrap();
    owner
        .record(ProviderFinalizationResult::Returned(0))
        .unwrap();
    assert!(owner.ready());
    assert_eq!(owner.begin(), Err(ProviderFinalizationError::InvalidPhase));
    assert_eq!(
        owner.record(ProviderFinalizationResult::NotEntered(1)),
        Err(ProviderFinalizationError::InvalidPhase)
    );
    assert_eq!(owner.phase(), ProviderFinalizationPhase::Accepted);
}

#[test]
fn no_provider_destructor_is_ready_without_invocation() {
    let mut owner = ProviderFinalization::new(false);
    assert!(owner.ready());
    assert_eq!(owner.begin(), Err(ProviderFinalizationError::InvalidPhase));
    assert_eq!(
        owner.record(ProviderFinalizationResult::Returned(0)),
        Err(ProviderFinalizationError::InvalidPhase)
    );
    assert!(owner.ready());
}

#[test]
fn ambiguous_completion_retains_status_without_replay() {
    for status in [0, 1, 0x103, 0xc000_0001, u32::MAX] {
        let mut owner = ProviderFinalization::new(true);
        owner.begin().unwrap();
        owner
            .record(ProviderFinalizationResult::Indeterminate(status))
            .unwrap();
        assert_eq!(
            owner.phase(),
            ProviderFinalizationPhase::Indeterminate(status)
        );
        assert!(!owner.ready());
        assert_eq!(owner.begin(), Err(ProviderFinalizationError::InvalidPhase));
        assert_eq!(
            owner.record(ProviderFinalizationResult::Returned(0)),
            Err(ProviderFinalizationError::InvalidPhase)
        );
        assert_eq!(
            owner.phase(),
            ProviderFinalizationPhase::Indeterminate(status)
        );
    }
}

#[test]
fn preentry_failure_allows_one_new_invocation() {
    let mut owner = ProviderFinalization::new(true);
    owner.begin().unwrap();
    owner
        .record(ProviderFinalizationResult::NotEntered(0xc000_009a))
        .unwrap();
    assert_eq!(owner.phase(), ProviderFinalizationPhase::Pending);
    assert!(!owner.ready());
    owner.begin().unwrap();
    owner
        .record(ProviderFinalizationResult::Returned(0))
        .unwrap();
    assert!(owner.ready());
}

#[test]
fn returned_failure_is_retryable_but_positive_status_is_not_completion() {
    for status in [0x8000_0000, 0xc000_0001, u32::MAX] {
        let mut owner = ProviderFinalization::new(true);
        owner.begin().unwrap();
        owner
            .record(ProviderFinalizationResult::Returned(status))
            .unwrap();
        assert_eq!(owner.phase(), ProviderFinalizationPhase::Pending);
        owner.begin().unwrap();
    }
    for status in [1, 0x103, 0x4000_0000, 0x7fff_ffff] {
        let mut owner = ProviderFinalization::new(true);
        owner.begin().unwrap();
        owner
            .record(ProviderFinalizationResult::Returned(status))
            .unwrap();
        assert_eq!(
            owner.phase(),
            ProviderFinalizationPhase::Indeterminate(status)
        );
        assert_eq!(owner.begin(), Err(ProviderFinalizationError::InvalidPhase));
        assert!(!owner.ready());
    }
}

#[test]
fn every_result_rejects_wrong_phase_without_mutation() {
    for phase in [
        ProviderFinalizationPhase::Pending,
        ProviderFinalizationPhase::Accepted,
        ProviderFinalizationPhase::Indeterminate(0xc000_0001),
    ] {
        for result in [
            ProviderFinalizationResult::NotEntered(0xc000_009a),
            ProviderFinalizationResult::Returned(0),
            ProviderFinalizationResult::Returned(0xc000_0001),
            ProviderFinalizationResult::Indeterminate(0x103),
        ] {
            let mut owner = ProviderFinalization { phase };
            assert_eq!(
                owner.record(result),
                Err(ProviderFinalizationError::InvalidPhase)
            );
            assert_eq!(owner.phase(), phase);
        }
    }
}

#[test]
fn moving_owner_preserves_inflight_acknowledgement() {
    let mut original = ProviderFinalization::new(true);
    original.begin().unwrap();
    let mut moved = original;
    assert_eq!(moved.begin(), Err(ProviderFinalizationError::InvalidPhase));
    moved
        .record(ProviderFinalizationResult::Returned(0))
        .unwrap();
    assert!(moved.ready());
}
