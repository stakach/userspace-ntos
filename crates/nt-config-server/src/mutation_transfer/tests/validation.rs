use super::*;

fn prepared(server: &mut CmServer) -> (CmHiveMutationRequest, CmHiveMutationRequest) {
    let bytes = record(
        kind::CREATE_KEY,
        &alloc::format!("{SERVICES}\\Child"),
        "",
        0,
        &[],
    );
    let transfer = upload(server, &bytes);
    let result = call(server, transfer, &[]);
    assert_eq!(result.status, STATUS_SUCCESS);
    let validation = CmHiveMutationRequest {
        operation: hive_mutation_transfer::VALIDATE_PREPARED,
        expected_mount: server.system_hive.as_ref().unwrap().identity,
        journal_offset: result.information,
        ..transfer
    };
    (transfer, validation)
}

fn validate(server: &mut CmServer, request: CmHiveMutationRequest, extra: &[u8]) -> CmReply {
    let mut input = request.as_bytes().to_vec();
    input.extend_from_slice(extra);
    let mut output = [0xa5; 32];
    let result = server.dispatch(opcode::CM_OP_MUTATE_SYSTEM_HIVE, &input, &mut output);
    assert_eq!(output, [0xa5; 32]);
    assert_eq!(result.information, 0);
    result
}

#[test]
fn exact_prepared_admission_is_read_only_and_replayable() {
    let mut server = server();
    let (transfer, request) = prepared(&mut server);
    let hive = nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive);
    let journal = server
        .prepared_system_mutation
        .as_ref()
        .unwrap()
        .durable_journal
        .clone();
    let identity_sequence = server.identities.next_sequence.get();
    for _ in 0..3 {
        let result = validate(&mut server, request, &[]);
        assert_eq!(result.status, STATUS_SUCCESS);
        assert_eq!(result.detail0, request.expected_generation + 1);
        assert_eq!(result.detail1, request.lease_token);
        assert_eq!(server.identities.next_sequence.get(), identity_sequence);
        assert!(!server.system_mutation_outcomes.is_pending());
        assert_eq!(server.device_action_journal.pending_len(), 0);
        assert_eq!(
            server.system_hive.as_ref().unwrap().generation,
            request.expected_generation
        );
        assert_eq!(
            nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive),
            hive
        );
        assert_eq!(
            server
                .prepared_system_mutation
                .as_ref()
                .unwrap()
                .durable_journal,
            journal
        );
    }
    assert_eq!(call(&mut server, transfer, &[]).status, STATUS_SUCCESS);
}

#[test]
fn malformed_or_foreign_admission_preserves_the_real_preparation() {
    let mut server = server();
    let (_, request) = prepared(&mut server);
    let cases = [
        CmHiveMutationRequest {
            abi_size: request.abi_size - 1,
            ..request
        },
        CmHiveMutationRequest {
            abi_version: request.abi_version + 1,
            ..request
        },
        CmHiveMutationRequest {
            mount: 0,
            ..request
        },
        CmHiveMutationRequest {
            expected_mount: 0,
            ..request
        },
        CmHiveMutationRequest {
            expected_mount: request.expected_mount + 1,
            ..request
        },
        CmHiveMutationRequest {
            lease_token: 0,
            ..request
        },
        CmHiveMutationRequest {
            lease_token: request.lease_token + 1,
            ..request
        },
        CmHiveMutationRequest {
            expected_generation: 0,
            ..request
        },
        CmHiveMutationRequest {
            expected_generation: request.expected_generation + 1,
            ..request
        },
        CmHiveMutationRequest {
            journal_len_bytes: 0,
            ..request
        },
        CmHiveMutationRequest {
            journal_len_bytes: request.journal_len_bytes + 1,
            ..request
        },
        CmHiveMutationRequest {
            journal_offset: request.journal_offset + 1,
            ..request
        },
        CmHiveMutationRequest {
            chunk_offset: 1,
            ..request
        },
        CmHiveMutationRequest {
            chunk_len_bytes: 1,
            ..request
        },
    ];
    let identity_sequence = server.identities.next_sequence.get();
    for invalid in cases {
        assert_ne!(validate(&mut server, invalid, &[]).status, STATUS_SUCCESS);
        assert_eq!(validate(&mut server, request, &[]).status, STATUS_SUCCESS);
        assert_eq!(server.identities.next_sequence.get(), identity_sequence);
        assert!(!server.system_mutation_outcomes.is_pending());
        assert_eq!(server.device_action_journal.pending_len(), 0);
    }
    assert_eq!(
        validate(&mut server, request, &[0]).status,
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(validate(&mut server, request, &[]).status, STATUS_SUCCESS);
}

#[test]
fn validation_does_not_prepare_a_complete_upload() {
    let mut server = server();
    let bytes = record(
        kind::CREATE_KEY,
        &alloc::format!("{SERVICES}\\Child"),
        "",
        0,
        &[],
    );
    let transfer = upload(&mut server, &bytes);
    let request = CmHiveMutationRequest {
        operation: hive_mutation_transfer::VALIDATE_PREPARED,
        expected_mount: server.system_hive.as_ref().unwrap().identity,
        journal_offset: 0,
        ..transfer
    };
    for _ in 0..2 {
        assert_eq!(
            validate(&mut server, request, &[]).status,
            STATUS_INVALID_PARAMETER
        );
        assert_upload(&server, transfer, &bytes);
        assert!(!server.system_mutation_outcomes.is_pending());
    }
    assert_eq!(call(&mut server, transfer, &[]).status, STATUS_SUCCESS);
}

#[test]
fn aborted_and_published_tokens_have_no_prepared_admission() {
    for operation in [
        hive_mutation_transfer::ABORT,
        hive_mutation_transfer::COMMIT,
    ] {
        let mut server = server();
        let (transfer, request) = prepared(&mut server);
        let terminal = CmHiveMutationRequest {
            operation,
            journal_offset: if operation == hive_mutation_transfer::ABORT {
                0
            } else {
                transfer.journal_len_bytes
            },
            ..transfer
        };
        assert_eq!(call(&mut server, terminal, &[]).status, STATUS_SUCCESS);
        assert!(server.prepared_system_mutation.is_none());
        assert_ne!(validate(&mut server, request, &[]).status, STATUS_SUCCESS);
        assert!(server.prepared_system_mutation.is_none());
        assert!(!server.system_mutation_leases.is_busy());
    }
}

#[test]
fn replaced_mount_and_stale_generation_reject_existing_preparation() {
    let mut server = server();
    let (_, request) = prepared(&mut server);
    server.system_hive.as_mut().unwrap().identity += 1;
    assert_eq!(
        validate(&mut server, request, &[]).status,
        STATUS_INVALID_HANDLE
    );
    server.system_hive.as_mut().unwrap().identity = request.expected_mount;
    server.system_hive.as_mut().unwrap().generation += 1;
    assert_eq!(
        validate(&mut server, request, &[]).status,
        STATUS_REVISION_MISMATCH
    );
    assert!(server.prepared_system_mutation.is_some());
    server.system_hive.as_mut().unwrap().generation = request.expected_generation;
    assert_eq!(validate(&mut server, request, &[]).status, STATUS_SUCCESS);
}

#[test]
fn validation_requires_the_exact_next_generation() {
    let mut server = server();
    let (_, request) = prepared(&mut server);
    server
        .prepared_system_mutation
        .as_mut()
        .unwrap()
        .next_generation += 1;
    assert_eq!(
        validate(&mut server, request, &[]).status,
        STATUS_INVALID_PARAMETER
    );
    server
        .prepared_system_mutation
        .as_mut()
        .unwrap()
        .next_generation -= 1;
    assert_eq!(validate(&mut server, request, &[]).status, STATUS_SUCCESS);
}

#[test]
fn zero_durable_length_is_valid_for_a_real_noop_preparation() {
    let mut server = server();
    let bytes = record(kind::CREATE_KEY, SERVICES, "", 0, &[]);
    let transfer = upload(&mut server, &bytes);
    let result = call(&mut server, transfer, &[]);
    assert_eq!(result.status, STATUS_SUCCESS);
    assert_eq!(result.information, 0);
    let request = CmHiveMutationRequest {
        operation: hive_mutation_transfer::VALIDATE_PREPARED,
        expected_mount: server.system_hive.as_ref().unwrap().identity,
        journal_offset: 0,
        ..transfer
    };
    assert_eq!(validate(&mut server, request, &[]).status, STATUS_SUCCESS);
    assert!(server
        .prepared_system_mutation
        .as_ref()
        .unwrap()
        .durable_journal
        .is_empty());
}
