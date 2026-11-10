use super::*;
use crate::ProcessDeletionPhase;

fn child(generation: u64) -> ProcessMechanism {
    ProcessMechanism {
        pi: 7,
        pid: 42,
        main_tid: 43,
        top_badge: 0x711,
        generation,
    }
}

fn retired(child: ProcessMechanism) -> ProcessDeletionCandidate {
    let mut candidate = ProcessDeletionCandidate::from_mechanism(child, true);
    candidate.phase = ProcessDeletionPhase::AwaitingReferences;
    candidate
}

#[test]
fn definite_alias_error_retires_child_before_one_original_reply_and_releases_refs_after_ack() {
    let child = child(9);
    let status = 0xc000_009a;
    let mut abort = EnteredSpawnAbort::begin(child, AliasFailure::Definite(status)).unwrap();
    assert_eq!(abort.phase(), AbortPhase::TerminateChild);
    assert!(abort.blocks_child_teardown());
    assert!(abort.blocks_creator_teardown());
    assert_eq!(abort.enter_reply(child), Err(AbortError::OutOfOrder));
    assert_eq!(
        abort.record_execution_retired(retired(child)),
        Err(AbortError::OutOfOrder)
    );

    abort.record_child_terminated(child).unwrap();
    assert!(!abort.blocks_child_teardown());
    assert!(abort.blocks_creator_teardown());
    assert_eq!(abort.phase(), AbortPhase::RetireExecution);
    abort.record_execution_retired(retired(child)).unwrap();
    assert_eq!(abort.phase(), AbortPhase::ReplyReady);
    assert_eq!(abort.enter_reply(child), Ok(status));
    assert_eq!(abort.phase(), AbortPhase::ReplyEntered);
    assert_eq!(abort.enter_reply(child), Err(AbortError::OutOfOrder));
    assert_eq!(abort.release_references(child), Err(AbortError::OutOfOrder));
    abort.acknowledge_reply(child).unwrap();
    assert_eq!(abort.phase(), AbortPhase::ReplyAcknowledged);
    abort.release_references(child).unwrap();
    assert_eq!(abort.phase(), AbortPhase::Complete);
    assert!(!abort.blocks_creator_teardown());
    assert_eq!(abort.release_references(child), Err(AbortError::OutOfOrder));
}

#[test]
fn uncertain_effect_never_admits_the_abort_path() {
    assert!(matches!(
        EnteredSpawnAbort::begin(child(9), AliasFailure::Uncertain(0xc000_009a)),
        Err(AbortError::UncertainEffect)
    ));
}

#[test]
fn stale_generation_and_mismatched_mechanism_cannot_advance_or_release_owner() {
    let child = child(9);
    let mut abort = EnteredSpawnAbort::begin(child, AliasFailure::Definite(0xc000_009a)).unwrap();
    let stale = ProcessMechanism {
        generation: 10,
        ..child
    };
    assert_eq!(
        abort.record_child_terminated(stale),
        Err(AbortError::StaleIdentity)
    );
    abort.record_child_terminated(child).unwrap();
    assert_eq!(
        abort.record_execution_retired(retired(stale)),
        Err(AbortError::StaleIdentity)
    );
    let mut candidate = retired(child);
    candidate.phase = ProcessDeletionPhase::RetiringExecution;
    assert_eq!(
        abort.record_execution_retired(candidate),
        Err(AbortError::OutOfOrder)
    );
    abort.record_execution_retired(retired(child)).unwrap();
    assert_eq!(abort.enter_reply(stale), Err(AbortError::StaleIdentity));
    assert_eq!(abort.enter_reply(child), Ok(0xc000_009a));
    assert_eq!(
        abort.acknowledge_reply(stale),
        Err(AbortError::StaleIdentity)
    );
    abort.acknowledge_reply(child).unwrap();
    assert_eq!(
        abort.release_references(stale),
        Err(AbortError::StaleIdentity)
    );
    abort.release_references(child).unwrap();
}

#[test]
fn invalid_identity_is_not_an_abort_authority() {
    let mut missing_generation = child(0);
    assert!(matches!(
        EnteredSpawnAbort::begin(missing_generation, AliasFailure::Definite(5)),
        Err(AbortError::InvalidIdentity)
    ));
    missing_generation = child(9);
    missing_generation.main_tid = 0;
    assert!(matches!(
        EnteredSpawnAbort::begin(missing_generation, AliasFailure::Definite(5)),
        Err(AbortError::InvalidIdentity)
    ));
    assert!(matches!(
        EnteredSpawnAbort::begin(child(9), AliasFailure::Definite(0)),
        Err(AbortError::InvalidStatus)
    ));
}

#[test]
fn cancelled_original_reply_releases_child_only_after_exact_revocation_reconciliation() {
    let stale = child(10);
    let child = child(9);
    let mut abort = EnteredSpawnAbort::begin(child, AliasFailure::Definite(0xc000_009a)).unwrap();
    assert_eq!(abort.enter_revoke(child, ReplyCancellation::ExactReceipt), Err(AbortError::OutOfOrder));
    abort.record_child_terminated(child).unwrap();
    abort.record_execution_retired(retired(child)).unwrap();
    assert_eq!(abort.enter_revoke(stale, ReplyCancellation::ExactReceipt), Err(AbortError::StaleIdentity));
    abort.enter_revoke(child, ReplyCancellation::ExactReceipt).unwrap();
    assert_eq!(abort.phase(), AbortPhase::RevokeEntered);
    assert_eq!(abort.enter_reply(child), Err(AbortError::OutOfOrder));
    assert_eq!(abort.release_references(child), Err(AbortError::OutOfOrder));
    assert_eq!(abort.acknowledge_revoke(stale), Err(AbortError::StaleIdentity));
    abort.acknowledge_revoke(child).unwrap();
    assert_eq!(abort.phase(), AbortPhase::RevokeAcknowledged);
    assert!(!abort.blocks_creator_teardown());
    assert_eq!(abort.release_references(child), Err(AbortError::OutOfOrder));
    assert_eq!(abort.record_revoke_runtime_reconciled(stale), Err(AbortError::StaleIdentity));
    abort.record_revoke_runtime_reconciled(child).unwrap();
    assert_eq!(abort.phase(), AbortPhase::RevokeReconciled);
    abort.release_references(child).unwrap();
    assert_eq!(abort.phase(), AbortPhase::Complete);
}

#[test]
fn creator_termination_without_reply_receipt_cannot_revoke_entered_reply() {
    let child = child(9);
    let mut abort = EnteredSpawnAbort::begin(child, AliasFailure::Definite(0xc000_009a)).unwrap();
    abort.record_child_terminated(child).unwrap();
    abort.record_execution_retired(retired(child)).unwrap();
    abort.enter_reply(child).unwrap();
    assert_eq!(
        abort.enter_revoke(child, ReplyCancellation::OwnerTerminated),
        Err(AbortError::OutOfOrder),
    );
    assert_eq!(abort.phase(), AbortPhase::ReplyEntered);
    abort.enter_revoke(child, ReplyCancellation::ExactReceipt).unwrap();
}
