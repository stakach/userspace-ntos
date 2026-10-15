use super::*;

fn queued() -> (ProcessDeletionCandidateTable<2>, ProcessDeletionCandidate) {
    let candidate = ProcessDeletionCandidate::from_mechanism(
        ProcessMechanism {
            pi: 1,
            pid: 12,
            main_tid: 20,
            top_badge: 2,
            generation: 7,
        },
        true,
    );
    let mut table = ProcessDeletionCandidateTable::new();
    table.queue(candidate).unwrap();
    (table, candidate)
}

#[test]
fn acknowledged_rundown_is_once_only_and_cannot_be_discarded_or_reset() {
    let (mut table, initial) = queued();
    let acknowledged = table.acknowledge_lpc_rundown_exact(initial).unwrap();
    assert_eq!(
        acknowledged,
        ProcessDeletionCandidate {
            lpc_rundown_acknowledged: true,
            ..initial
        }
    );
    assert_eq!(
        table.acknowledge_lpc_rundown_exact(initial),
        Err(MechanismError::StaleIdentity)
    );
    assert_eq!(
        table.acknowledge_lpc_rundown_exact(acknowledged),
        Err(MechanismError::InvalidIdentity)
    );
    assert_eq!(table.queue(initial), Ok(false));
    assert_eq!(
        table.remove_exact(acknowledged),
        Err(MechanismError::InvalidIdentity)
    );
    assert_eq!(table.get(initial.pi), Some(acknowledged));
    assert_eq!(
        table.advance_exact(initial),
        Err(MechanismError::StaleIdentity)
    );
}

#[test]
fn rundown_acknowledgement_requires_exact_candidate_and_initial_phase() {
    let (mut table, initial) = queued();
    for forged in [
        ProcessDeletionCandidate { pid: 13, ..initial },
        ProcessDeletionCandidate {
            generation: 8,
            ..initial
        },
        ProcessDeletionCandidate {
            provider_objects: false,
            ..initial
        },
        ProcessDeletionCandidate {
            lpc_rundown_acknowledged: true,
            ..initial
        },
        ProcessDeletionCandidate {
            pending_exception_port: 9,
            ..initial
        },
        ProcessDeletionCandidate {
            phase: ProcessDeletionPhase::ReclaimingVm,
            ..initial
        },
    ] {
        assert_eq!(
            table.acknowledge_lpc_rundown_exact(forged),
            Err(MechanismError::StaleIdentity)
        );
        assert_eq!(table.get(initial.pi), Some(initial));
    }
    assert_eq!(
        table.acknowledge_lpc_rundown_exact(ProcessDeletionCandidate { pi: 2, ..initial }),
        Err(MechanismError::SlotOutOfRange)
    );
    let mut empty = ProcessDeletionCandidateTable::<2>::new();
    assert_eq!(
        empty.queue(ProcessDeletionCandidate {
            lpc_rundown_acknowledged: true,
            ..initial
        }),
        Err(MechanismError::InvalidIdentity)
    );
    assert_eq!(empty.live_len(), 0);
    let advanced = table.advance_exact(initial).unwrap();
    assert_eq!(
        table.acknowledge_lpc_rundown_exact(advanced),
        Err(MechanismError::InvalidIdentity)
    );
    assert_eq!(table.get(initial.pi), Some(advanced));
}

#[test]
fn rundown_acknowledgement_survives_all_retirement_transitions_not_slot_reuse() {
    let (mut table, initial) = queued();
    let acknowledged = table.acknowledge_lpc_rundown_exact(initial).unwrap();
    let reclaiming = table.advance_exact(acknowledged).unwrap();
    let deleting = table.advance_exact(reclaiming).unwrap();
    let withdrawn = table
        .record_process_object_withdrawal_exact(deleting)
        .unwrap();
    let releasing = table
        .record_process_object_deletion_exact(withdrawn, 9, 17, 2)
        .unwrap();
    let token_released = table.release_primary_token_exact(releasing).unwrap();
    let port_released = table.release_exception_port_exact(token_released).unwrap();
    let retired = table.advance_exact(port_released).unwrap();
    for snapshot in [
        reclaiming,
        deleting,
        withdrawn,
        releasing,
        token_released,
        port_released,
        retired,
    ] {
        assert!(snapshot.lpc_rundown_acknowledged);
        assert!(snapshot.same_identity(initial));
    }
    assert_eq!(table.remove_exact(retired), Ok(retired));
    let replacement = ProcessDeletionCandidate {
        pid: 13,
        generation: 8,
        ..initial
    };
    assert_eq!(table.queue(replacement), Ok(true));
    assert!(!table.get(replacement.pi).unwrap().lpc_rundown_acknowledged);
    assert_eq!(
        table.acknowledge_lpc_rundown_exact(initial),
        Err(MechanismError::StaleIdentity)
    );
    assert_eq!(table.get(replacement.pi), Some(replacement));
}
