use super::*;
use crate::mutation_commit::test_support::server;

fn exchange(server: &mut CmServer, request: Request) -> Result<Reply, i32> {
    let mut out = [0u8; 72];
    let reply = server.dispatch(
        opcode::CM_OP_SYSTEM_HIVE_MUTATION_BEGIN,
        request.as_bytes(),
        &mut out,
    );
    if reply.status != STATUS_SUCCESS {
        return Err(reply.status);
    }
    assert_eq!(reply.information, 72);
    let body = Reply::from_bytes(&out).unwrap();
    assert_eq!(reply.detail0, body.server_nonce);
    assert_eq!(reply.detail1, body.request_generation);
    assert_eq!(body.abi_size, 72);
    assert_eq!(body.abi_version, CM_ABI_VERSION);
    assert_eq!(body.mount, hive_mount::SYSTEM);
    assert_eq!(body.reserved, 0);
    Ok(body)
}

fn query(requester: u64, slots: u32) -> Request {
    Request {
        abi_size: 64,
        abi_version: CM_ABI_VERSION,
        mount: hive_mount::SYSTEM,
        operation: operation::QUERY,
        requester_nonce: requester,
        slot_count: slots,
        ..Request::default()
    }
}

fn register(server: &mut CmServer, requester: u64, slots: u32) -> Request {
    let query = query(requester, slots);
    let grant = exchange(server, query).unwrap();
    assert_eq!(grant.disposition, disposition::AUTHORITY);
    assert_eq!(grant.slot_count, slots);
    assert_eq!(exchange(server, query), Ok(grant));
    Request {
        operation: operation::BEGIN,
        server_nonce: grant.server_nonce,
        slot_count: 0,
        request_generation: 1,
        expected_generation: 1,
        semantic_journal_len: 4,
        ..query
    }
}

fn ack(request: Request, token: u64) -> Request {
    Request {
        operation: operation::ACKNOWLEDGE,
        expected_generation: 0,
        semantic_journal_len: 0,
        mutation_token: token,
        ..request
    }
}

fn transfer(server: &mut CmServer, request: Request, token: u64, operation: u16) -> CmReply {
    let mut header = CmHiveMutationRequest {
        abi_size: core::mem::size_of::<CmHiveMutationRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        mount: hive_mount::SYSTEM,
        operation,
        lease_token: token,
        expected_generation: request.expected_generation,
        journal_len_bytes: request.semantic_journal_len,
        ..CmHiveMutationRequest::default()
    };
    let bytes = [1, 2, 3, 4];
    if operation == hive_mutation_transfer::APPEND {
        header.chunk_offset = header.abi_size as u32;
        header.chunk_len_bytes = bytes.len() as u32;
    } else if operation == hive_mutation_transfer::PREPARE {
        header.journal_offset = request.semantic_journal_len;
    }
    let mut input = header.as_bytes().to_vec();
    if operation == hive_mutation_transfer::APPEND {
        input.extend_from_slice(&bytes);
    }
    server.op_mutate_system_hive(&input, &mut [])
}

#[test]
fn exact_begin_replay_and_ack_handoff_preserve_live_upload() {
    let mut server = server();
    let request = register(&mut server, 1, 2);
    let outcome = exchange(&mut server, request).unwrap();
    assert_eq!(outcome.disposition, disposition::OUTCOME);
    assert_eq!(outcome.outcome_status, STATUS_SUCCESS);
    assert_ne!(outcome.mutation_token, 0);
    for _ in 0..3 {
        assert_eq!(exchange(&mut server, request), Ok(outcome));
    }
    for operation in [
        hive_mutation_transfer::APPEND,
        hive_mutation_transfer::PREPARE,
        hive_mutation_transfer::ABORT,
    ] {
        assert_eq!(
            transfer(&mut server, request, outcome.mutation_token, operation).status,
            STATUS_DEVICE_BUSY
        );
    }
    assert_eq!(
        exchange(&mut server, ack(request, outcome.mutation_token + 1)),
        Err(STATUS_INVALID_HANDLE)
    );
    let acknowledged = exchange(&mut server, ack(request, outcome.mutation_token)).unwrap();
    assert_eq!(acknowledged.disposition, disposition::ACKNOWLEDGED);
    assert_eq!(acknowledged.mutation_token, 0);
    assert_eq!(acknowledged.expected_generation, 0);
    assert_eq!(acknowledged.semantic_journal_len, 0);
    assert_eq!(exchange(&mut server, request), Err(STATUS_INVALID_HANDLE));
    assert_eq!(
        transfer(
            &mut server,
            request,
            outcome.mutation_token,
            hive_mutation_transfer::APPEND
        )
        .status,
        STATUS_SUCCESS
    );
    assert_eq!(
        server
            .system_mutation_leases
            .complete_bytes(outcome.mutation_token, 1, 4)
            .unwrap(),
        [1, 2, 3, 4]
    );
    let old_ack = ack(request, outcome.mutation_token);
    assert_eq!(
        exchange(&mut server, old_ack).unwrap().disposition,
        disposition::ALREADY_ACKNOWLEDGED
    );
    assert!(server.system_mutation_leases.is_busy());
    assert_eq!(
        transfer(
            &mut server,
            request,
            outcome.mutation_token,
            hive_mutation_transfer::ABORT
        )
        .status,
        STATUS_SUCCESS
    );
    let next = Request {
        request_generation: 2,
        ..request
    };
    let fresh = exchange(&mut server, next).unwrap();
    assert_ne!(fresh.mutation_token, outcome.mutation_token);
    assert_eq!(
        exchange(&mut server, old_ack).unwrap().disposition,
        disposition::ALREADY_ACKNOWLEDGED
    );
    assert_eq!(exchange(&mut server, next), Ok(fresh));
}

#[test]
fn busy_and_stale_outcomes_are_cached_until_ack_not_re_evaluated() {
    let mut server = server();
    let first = register(&mut server, 1, 1);
    let second = register(&mut server, 2, 1);
    let acquired = exchange(&mut server, first).unwrap();
    let busy = exchange(&mut server, second).unwrap();
    assert_eq!(busy.outcome_status, STATUS_DEVICE_BUSY);
    assert_eq!(busy.mutation_token, 0);
    exchange(&mut server, ack(first, acquired.mutation_token)).unwrap();
    assert_eq!(
        transfer(
            &mut server,
            first,
            acquired.mutation_token,
            hive_mutation_transfer::ABORT
        )
        .status,
        STATUS_SUCCESS
    );
    assert_eq!(exchange(&mut server, second), Ok(busy));
    assert_eq!(
        exchange(&mut server, ack(second, 99)),
        Err(STATUS_INVALID_HANDLE)
    );
    exchange(&mut server, ack(second, 0)).unwrap();
    let stale = Request {
        request_generation: 2,
        expected_generation: 2,
        ..second
    };
    let failed = exchange(&mut server, stale).unwrap();
    assert_eq!(failed.outcome_status, STATUS_REVISION_MISMATCH);
    server.system_hive.as_mut().unwrap().generation = 2;
    assert_eq!(exchange(&mut server, stale), Ok(failed));
    assert!(!server.system_mutation_leases.is_busy());
    exchange(&mut server, ack(stale, 0)).unwrap();
    let next = Request {
        request_generation: 3,
        ..stale
    };
    assert_eq!(
        exchange(&mut server, next).unwrap().outcome_status,
        STATUS_SUCCESS
    );
}

#[test]
fn malformed_frames_and_changed_attempts_do_not_change_acquisition() {
    let mut server = server();
    let request = register(&mut server, 1, 1);
    let mut short = [0; 71];
    assert_eq!(
        server
            .op_system_hive_mutation_begin(request.as_bytes(), &mut short)
            .status,
        STATUS_BUFFER_TOO_SMALL
    );
    assert!(!server.system_mutation_leases.is_busy());
    assert_eq!(
        exchange(&mut server, ack(request, 0)),
        Err(STATUS_INVALID_HANDLE)
    );
    for field in 0..8 {
        let mut invalid = request;
        match field {
            0 => invalid.abi_size -= 1,
            1 => invalid.abi_version += 1,
            2 => invalid.mount = 0,
            3 => invalid.operation = 99,
            4 => invalid.slot_count = 1,
            5 => invalid.mutation_token = 1,
            6 => invalid.semantic_journal_len = 0,
            _ => invalid.expected_generation = 0,
        }
        assert_eq!(
            exchange(&mut server, invalid),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert!(!server.system_mutation_leases.is_busy());
    }
    let original = exchange(&mut server, request).unwrap();
    for field in 0..6 {
        let mut changed = request;
        match field {
            0 => changed.server_nonce += 1,
            1 => changed.requester_nonce += 1,
            2 => changed.request_slot = 1,
            3 => changed.request_generation = 2,
            4 => changed.expected_generation += 1,
            _ => changed.semantic_journal_len += 1,
        }
        assert!(exchange(&mut server, changed).is_err());
        assert_eq!(exchange(&mut server, request), Ok(original));
    }
    let ack = ack(request, original.mutation_token);
    assert_eq!(
        server
            .op_system_hive_mutation_begin(ack.as_bytes(), &mut short)
            .status,
        STATUS_BUFFER_TOO_SMALL
    );
    assert_eq!(exchange(&mut server, request), Ok(original));
}

#[test]
fn registration_capacity_and_incarnation_do_not_replace_live_grants() {
    let mut server = server();
    let request = register(&mut server, 1, MAX_SLOTS as u32);
    assert_eq!(
        exchange(&mut server, query(2, 1)),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(
        exchange(&mut server, query(1, 1)),
        Err(STATUS_INVALID_PARAMETER)
    );
    let outcome = exchange(&mut server, request).unwrap();
    let mut restarted = CmServer::new_for_incarnation(NonZeroU32::new(2).unwrap());
    let replacement = register(&mut restarted, 1, 1);
    assert_ne!(replacement.server_nonce, request.server_nonce);
    assert_eq!(
        exchange(&mut restarted, request),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        exchange(&mut restarted, ack(request, outcome.mutation_token)),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(exchange(&mut server, request), Ok(outcome));
}

#[test]
fn exhausted_authority_or_upload_identity_never_invents_ownership() {
    let mut server = server();
    server.identities.next_sequence.set(0);
    assert_eq!(
        exchange(&mut server, query(1, 1)),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert!(!server.system_mutation_leases.is_busy());
    server.identities.next_sequence.set(1);
    let request = register(&mut server, 1, 1);
    server.identities.next_sequence.set(0);
    let failed = exchange(&mut server, request).unwrap();
    assert_eq!(failed.outcome_status, STATUS_INSUFFICIENT_RESOURCES);
    assert_eq!(failed.mutation_token, 0);
    assert!(!server.system_mutation_leases.is_busy());
    server.identities.next_sequence.set(2);
    assert_eq!(exchange(&mut server, request), Ok(failed));
    exchange(&mut server, ack(request, 0)).unwrap();
    let next = Request {
        request_generation: 2,
        ..request
    };
    assert_eq!(
        exchange(&mut server, next).unwrap().outcome_status,
        STATUS_SUCCESS
    );
}

#[test]
fn imports_cannot_invalidate_upload_before_or_after_begin_ack() {
    let mut server = server();
    let image = nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive);
    let mut import = CmHiveImportRequest {
        abi_size: core::mem::size_of::<CmHiveImportRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        mount: hive_mount::SYSTEM,
        operation: hive_import_transfer::BEGIN,
        total_len_bytes: image.len() as u32,
        ..CmHiveImportRequest::default()
    };
    let opened = server.op_import_hive(import.as_bytes());
    assert_eq!(opened.status, STATUS_SUCCESS);
    import.transfer_token = opened.detail1;
    for (index, chunk) in image.chunks(CM_HIVE_IMPORT_CHUNK_BYTES).enumerate() {
        let push = CmHiveImportRequest {
            operation: hive_import_transfer::PUSH,
            value_offset: (index * CM_HIVE_IMPORT_CHUNK_BYTES) as u32,
            chunk_offset: import.abi_size as u32,
            chunk_len_bytes: chunk.len() as u32,
            ..import
        };
        let mut bytes = push.as_bytes().to_vec();
        bytes.extend_from_slice(chunk);
        assert_eq!(server.op_import_hive(&bytes).status, STATUS_SUCCESS);
    }
    let request = register(&mut server, 1, 1);
    let outcome = exchange(&mut server, request).unwrap();
    let commit = CmHiveImportRequest {
        operation: hive_import_transfer::COMMIT,
        value_offset: image.len() as u32,
        ..import
    };
    for acknowledged in [false, true] {
        if acknowledged {
            exchange(&mut server, ack(request, outcome.mutation_token)).unwrap();
        }
        let begin = CmHiveImportRequest {
            transfer_token: 0,
            ..import
        };
        assert_eq!(
            server.op_import_hive(begin.as_bytes()).status,
            STATUS_DEVICE_BUSY
        );
        assert_eq!(
            server.op_import_hive(commit.as_bytes()).status,
            STATUS_DEVICE_BUSY
        );
        assert!(server.system_mutation_leases.is_busy());
    }
    assert_eq!(
        transfer(
            &mut server,
            request,
            outcome.mutation_token,
            hive_mutation_transfer::ABORT
        )
        .status,
        STATUS_SUCCESS
    );
    assert_eq!(
        server.op_import_hive(commit.as_bytes()).status,
        STATUS_SUCCESS
    );
    assert_eq!(server.system_hive.as_ref().unwrap().generation, 2);
}
