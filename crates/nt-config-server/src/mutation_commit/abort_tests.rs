use super::test_support::*;
use super::*;

#[test]
fn abort_releases_only_exact_preparation_without_changing_live_hive() {
    let mut server = server();
    let mut request = prepare(&mut server, "Child");
    request.operation = operation::ABORT;
    // Cleanup uses captured identity, not current authority. A stale preparation must be releasable.
    server.system_hive.as_mut().unwrap().generation = 7;
    let before = nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive);
    let pending_events = server.device_action_journal.pending_len();
    let receipt = exchange(&mut server, request).unwrap();
    assert_eq!(receipt.disposition, disposition::ABORTED);
    assert_eq!(receipt.next_generation, 0);
    assert_eq!(receipt.has_pending_device_action, 0);
    assert!(server.prepared_system_mutation.is_none());
    assert_eq!(server.system_hive.as_ref().unwrap().generation, 7);
    assert_eq!(
        nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive),
        before
    );
    assert_eq!(server.device_action_journal.pending_len(), pending_events);
    assert_eq!(exchange(&mut server, request), Ok(receipt));
    server.system_hive = None;
    assert_eq!(exchange(&mut server, request), Ok(receipt));
    exchange(&mut server, ack(receipt)).unwrap();
    assert!(exchange(&mut server, request).is_err());
}

#[test]
fn alternating_abort_commit_receipts_preserve_terminal_kind_and_ack_order() {
    let mut server = server();
    let mut previous: Option<CmHiveMutationCommitReply> = None;
    for (index, op) in [
        operation::ABORT,
        operation::COMMIT,
        operation::ABORT,
        operation::COMMIT,
    ]
    .into_iter()
    .enumerate()
    {
        let mut request = prepare(&mut server, &alloc::format!("Child{index}"));
        request.operation = op;
        let generation = server.system_hive.as_ref().unwrap().generation;
        let receipt = exchange(&mut server, request).unwrap();
        assert_eq!(
            server.system_hive.as_ref().unwrap().generation,
            generation + u64::from(op == operation::COMMIT)
        );
        let opposite = CmHiveMutationCommitRequest {
            operation: if op == operation::ABORT {
                operation::COMMIT
            } else {
                operation::ABORT
            },
            ..request
        };
        assert_eq!(
            exchange(&mut server, opposite),
            Err(STATUS_INVALID_PARAMETER)
        );
        if let Some(old) = previous {
            assert_eq!(receipt.receipt_generation, old.receipt_generation + 1);
            assert_eq!(
                exchange(&mut server, ack(old)).unwrap().disposition,
                disposition::ALREADY_ACKNOWLEDGED
            );
            assert!(server.system_mutation_outcomes.is_pending());
        }
        assert_eq!(exchange(&mut server, request), Ok(receipt));
        exchange(&mut server, ack(receipt)).unwrap();
        let next = prepare(&mut server, "Unpublished");
        assert!(exchange(&mut server, request).is_err());
        assert_eq!(
            server.prepared_system_mutation.as_ref().unwrap().token,
            next.mutation_token
        );
        server.prepared_system_mutation = None;
        // Receipt generations count terminal outcomes, not abandoned upload identities.
        let token = server
            .system_mutation_leases
            .begin(server.system_hive.as_ref().unwrap().generation, 1)
            .unwrap();
        assert!(server.system_mutation_leases.abort(
            token,
            server.system_hive.as_ref().unwrap().generation,
            1
        ));
        previous = Some(receipt);
    }
}

#[test]
fn malformed_abort_and_receipt_exhaustion_do_not_release_preparation() {
    let mut server = server();
    let mut good = prepare(&mut server, "Child");
    good.operation = operation::ABORT;
    let mut invalid = [good; 10];
    invalid[0].abi_size -= 1;
    invalid[1].abi_version += 1;
    invalid[2].mount = 0;
    invalid[3].reserved = 1;
    invalid[4].mutation_token += 1;
    invalid[5].expected_generation += 1;
    invalid[6].semantic_journal_len += 1;
    invalid[7].receipt_bank = 1;
    invalid[8].receipt_generation = 1;
    invalid[9].operation = 99;
    for request in invalid {
        assert_eq!(
            exchange(&mut server, request),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert!(server.prepared_system_mutation.is_some());
    }
    let mut output = [0; 56];
    assert_eq!(
        server
            .op_system_hive_mutation_commit(good.as_bytes(), &mut output[..55])
            .status,
        STATUS_BUFFER_TOO_SMALL
    );
    assert!(server.prepared_system_mutation.is_some());
    assert!(!server.system_mutation_outcomes.is_pending());
    server.system_mutation_outcomes.acknowledged = u64::MAX;
    assert_eq!(
        exchange(&mut server, good),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert!(server.prepared_system_mutation.is_some());
    server.system_mutation_outcomes = MutationOutcomeJournal::default();
    server.identities.next_sequence.set(0);
    assert_eq!(
        exchange(&mut server, good),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert!(server.prepared_system_mutation.is_some());
    assert_eq!(server.system_hive.as_ref().unwrap().generation, 1);
}
