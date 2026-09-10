use super::test_support::{ack, exchange, prepare, server};
use super::*;
use nt_config_abi::{hive_mutation_kind, CmHiveMutationRecord};

fn cancellation_for_upload(
    server: &mut CmServer,
    bytes: &[u8],
    received: usize,
) -> CmHiveMutationCommitRequest {
    let expected = server.system_hive.as_ref().unwrap().generation;
    let token = server
        .system_mutation_leases
        .begin(expected, bytes.len())
        .unwrap();
    if received != 0 {
        server
            .system_mutation_leases
            .append(token, expected, bytes.len(), 0, &bytes[..received])
            .unwrap();
    }
    CmHiveMutationCommitRequest {
        abi_size: core::mem::size_of::<CmHiveMutationCommitRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        mount: hive_mount::SYSTEM,
        operation: operation::ABORT_UNPUBLISHED,
        mutation_token: token,
        expected_generation: expected,
        semantic_journal_len: bytes.len() as u32,
        ..CmHiveMutationCommitRequest::default()
    }
}

fn create_record() -> Vec<u8> {
    let path: Vec<u8> = r"\Registry\Machine\System\CurrentControlSet\Services\Child"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let record = CmHiveMutationRecord {
        kind: hive_mutation_kind::CREATE_KEY,
        path_len_bytes: path.len() as u32,
        ..CmHiveMutationRecord::default()
    };
    let mut bytes = record.as_bytes().to_vec();
    bytes.extend_from_slice(&path);
    bytes
}

fn owns(server: &CmServer, request: CmHiveMutationCommitRequest) -> bool {
    server
        .validate_unpublished_system_mutation(
            request.mutation_token,
            request.expected_generation,
            request.semantic_journal_len as usize,
        )
        .is_ok()
}

#[test]
fn cancellation_resolves_upload_or_uncertain_prepare_without_publishing() {
    for received in [0, 1, 2] {
        for prepare_ran in [false, true] {
            if prepare_ran && received != 2 {
                continue;
            }
            let mut server = server();
            let bytes = create_record();
            let count = if received == 2 { bytes.len() } else { received };
            let request = cancellation_for_upload(&mut server, &bytes, count);
            if prepare_ran {
                let transfer = CmHiveMutationRequest {
                    abi_size: core::mem::size_of::<CmHiveMutationRequest>() as u16,
                    abi_version: CM_ABI_VERSION,
                    operation: hive_mutation_transfer::PREPARE,
                    mount: hive_mount::SYSTEM,
                    expected_generation: request.expected_generation,
                    lease_token: request.mutation_token,
                    journal_len_bytes: request.semantic_journal_len,
                    journal_offset: request.semantic_journal_len,
                    ..CmHiveMutationRequest::default()
                };
                // The client did not observe this real successful PREPARE reply.
                assert_eq!(
                    server
                        .op_mutate_system_hive(transfer.as_bytes(), &mut [])
                        .status,
                    STATUS_SUCCESS
                );
                assert!(server.prepared_system_mutation.is_some());
            }
            let before = nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive);
            let receipt = exchange(&mut server, request).unwrap();
            assert_eq!(receipt.disposition, disposition::UNPUBLISHED_ABORTED);
            assert_eq!(receipt.next_generation, 0);
            assert_eq!(receipt.has_pending_device_action, 0);
            assert!(!server.system_mutation_leases.is_busy());
            assert!(server.prepared_system_mutation.is_none());
            assert_eq!(server.system_hive.as_ref().unwrap().generation, 1);
            assert_eq!(server.device_action_journal.pending_len(), 0);
            assert_eq!(
                nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive),
                before
            );
            assert_eq!(exchange(&mut server, request), Ok(receipt));
            server.system_hive = None;
            assert_eq!(exchange(&mut server, request), Ok(receipt));
            exchange(&mut server, ack(receipt)).unwrap();
            assert!(exchange(&mut server, request).is_err());
        }
    }
}

#[test]
fn cancellation_requires_discovery_ack_before_releasing_upload() {
    use nt_config_abi::mutation_begin::Request;
    let mut server = server();
    let authority = server
        .system_mutation_begins
        .grant(19, 1, &server.identities)
        .unwrap();
    let begin = Request {
        expected_mount: server.system_hive.as_ref().unwrap().identity,
        server_nonce: authority,
        requester_nonce: 19,
        request_generation: 1,
        expected_generation: 1,
        semantic_journal_len: 4,
        ..Request::default()
    };
    let (slot, _) = server.system_mutation_begins.claim(&begin).unwrap();
    let mount = server.system_hive.as_ref().unwrap().identity;
    let token = server.acquire_system_mutation_upload(mount, 1, 4).unwrap();
    server.system_mutation_begins.finish(slot, Ok(token));
    let request = CmHiveMutationCommitRequest {
        abi_size: core::mem::size_of::<CmHiveMutationCommitRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        mount: hive_mount::SYSTEM,
        operation: operation::ABORT_UNPUBLISHED,
        mutation_token: token,
        expected_generation: 1,
        semantic_journal_len: 4,
        ..CmHiveMutationCommitRequest::default()
    };
    assert_eq!(exchange(&mut server, request), Err(STATUS_DEVICE_BUSY));
    assert!(owns(&server, request));
    assert!(!server.system_mutation_outcomes.is_pending());
    server
        .system_mutation_begins
        .acknowledge(&Request {
            mutation_token: token,
            expected_mount: 0,
            expected_generation: 0,
            semantic_journal_len: 0,
            ..begin
        })
        .unwrap();
    let receipt = exchange(&mut server, request).unwrap();
    assert_eq!(receipt.disposition, disposition::UNPUBLISHED_ABORTED);
    assert!(!owns(&server, request));
}

#[test]
fn malformed_identity_and_receipt_exhaustion_preserve_either_owner() {
    for prepared in [false, true] {
        let mut server = server();
        let mut request = if prepared {
            prepare(&mut server, "Child")
        } else {
            cancellation_for_upload(&mut server, b"bytes", 1)
        };
        request.operation = operation::ABORT_UNPUBLISHED;
        // Cleanup remains bound to the original identity even after authority moves.
        server.system_hive.as_mut().unwrap().generation = 7;
        for field in 0..7 {
            let mut wrong = request;
            match field {
                0 => wrong.mutation_token += 1,
                1 => wrong.expected_generation += 1,
                2 => wrong.semantic_journal_len += 1,
                3 => wrong.receipt_bank = 1,
                4 => wrong.receipt_generation = 1,
                5 => wrong.reserved = 1,
                _ => wrong.mount = 0,
            }
            assert_eq!(exchange(&mut server, wrong), Err(STATUS_INVALID_PARAMETER));
            assert!(owns(&server, request));
        }
        let mut output = [0; 55];
        assert_eq!(
            server
                .op_system_hive_mutation_commit(request.as_bytes(), &mut output)
                .status,
            STATUS_BUFFER_TOO_SMALL
        );
        assert!(owns(&server, request));
        server.system_mutation_outcomes.acknowledged = u64::MAX;
        assert_eq!(
            exchange(&mut server, request),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert!(owns(&server, request));
        server.system_mutation_outcomes = MutationOutcomeJournal::default();
        server.identities.next_sequence.set(0);
        assert_eq!(
            exchange(&mut server, request),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert!(owns(&server, request));
        server.identities.next_sequence.set(100);
        let receipt = exchange(&mut server, request).unwrap();
        assert_eq!(receipt.expected_generation, request.expected_generation);
        assert_eq!(server.system_hive.as_ref().unwrap().generation, 7);
    }
}

#[test]
fn cancellation_cannot_change_terminal_kind_or_release_later_work() {
    let mut server = server();
    let request = cancellation_for_upload(&mut server, b"bytes", 1);
    assert!(exchange(
        &mut server,
        CmHiveMutationCommitRequest {
            operation: operation::ABORT,
            ..request
        }
    )
    .is_err());
    let cancelled = exchange(&mut server, request).unwrap();
    for operation in [operation::ABORT, operation::COMMIT] {
        assert_eq!(
            exchange(
                &mut server,
                CmHiveMutationCommitRequest {
                    operation,
                    ..request
                }
            ),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
    exchange(&mut server, ack(cancelled)).unwrap();
    let committed_request = prepare(&mut server, "Committed");
    let committed = exchange(&mut server, committed_request).unwrap();
    let cancel_committed = CmHiveMutationCommitRequest {
        operation: operation::ABORT_UNPUBLISHED,
        ..committed_request
    };
    assert_eq!(
        exchange(&mut server, cancel_committed),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        exchange(&mut server, ack(cancelled)).unwrap().disposition,
        disposition::ALREADY_ACKNOWLEDGED
    );
    assert_eq!(exchange(&mut server, committed_request), Ok(committed));
    exchange(&mut server, ack(committed)).unwrap();
    let aborted_request = CmHiveMutationCommitRequest {
        operation: operation::ABORT,
        ..prepare(&mut server, "Aborted")
    };
    let aborted = exchange(&mut server, aborted_request).unwrap();
    assert_eq!(
        exchange(
            &mut server,
            CmHiveMutationCommitRequest {
                operation: operation::ABORT_UNPUBLISHED,
                ..aborted_request
            }
        ),
        Err(STATUS_INVALID_PARAMETER)
    );
    exchange(&mut server, ack(aborted)).unwrap();
    let next = cancellation_for_upload(&mut server, b"other", 0);
    assert!(exchange(&mut server, request).is_err());
    assert!(exchange(&mut server, cancel_committed).is_err());
    assert!(owns(&server, next));
    let receipt = exchange(&mut server, next).unwrap();
    assert_eq!(
        exchange(&mut server, ack(committed)).unwrap().disposition,
        disposition::ALREADY_ACKNOWLEDGED
    );
    assert_eq!(exchange(&mut server, next), Ok(receipt));
}
