use super::*;
use crate::mutation_commit::test_support::server;
use nt_config_abi::{hive_mutation_kind as kind, CmHiveMutationRecord};

const SERVICES: &str = r"\Registry\Machine\System\CurrentControlSet\Services";

fn record(kind: u16, path: &str, name: &str, ty: u32, data: &[u8]) -> Vec<u8> {
    let path: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let header = CmHiveMutationRecord {
        kind,
        path_len_bytes: path.len() as u32,
        name_len_bytes: name.len() as u32,
        data_len_bytes: data.len() as u32,
        value_type: ty,
        ..CmHiveMutationRecord::default()
    };
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(&path);
    bytes.extend_from_slice(&name);
    bytes.extend_from_slice(data);
    bytes
}

fn call(server: &mut CmServer, request: CmHiveMutationRequest, data: &[u8]) -> CmReply {
    let mut input = request.as_bytes().to_vec();
    input.extend_from_slice(data);
    server.dispatch(opcode::CM_OP_MUTATE_SYSTEM_HIVE, &input, &mut [])
}

fn begin(server: &mut CmServer, len: usize) -> CmHiveMutationRequest {
    let mut request = CmHiveMutationRequest {
        abi_size: core::mem::size_of::<CmHiveMutationRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        mount: hive_mount::SYSTEM,
        operation: hive_mutation_transfer::BEGIN,
        expected_generation: server.system_hive.as_ref().unwrap().generation,
        expected_mount: server.system_hive.as_ref().unwrap().identity,
        journal_len_bytes: len as u32,
        ..CmHiveMutationRequest::default()
    };
    let reply = call(server, request, &[]);
    assert_eq!(reply.status, STATUS_SUCCESS);
    assert_eq!(reply.information, 0);
    request.lease_token = reply.detail1;
    request.expected_mount = 0;
    request.operation = hive_mutation_transfer::PREPARE;
    request.journal_offset = len as u32;
    request
}

fn append(
    server: &mut CmServer,
    request: CmHiveMutationRequest,
    offset: usize,
    data: &[u8],
) -> CmReply {
    call(
        server,
        CmHiveMutationRequest {
            operation: hive_mutation_transfer::APPEND,
            journal_offset: offset as u32,
            chunk_offset: request.abi_size as u32,
            chunk_len_bytes: data.len() as u32,
            ..request
        },
        data,
    )
}

fn upload(server: &mut CmServer, data: &[u8]) -> CmHiveMutationRequest {
    let request = begin(server, data.len());
    for (index, bytes) in data.chunks(31).enumerate() {
        let reply = append(server, request, index * 31, bytes);
        assert_eq!(reply.status, STATUS_SUCCESS);
        assert_eq!(append(server, request, index * 31, bytes), reply);
    }
    request
}

fn assert_upload(server: &CmServer, request: CmHiveMutationRequest, expected: &[u8]) {
    assert_eq!(
        server
            .system_mutation_leases
            .complete_bytes(
                request.lease_token,
                request.expected_generation,
                request.journal_len_bytes as usize
            )
            .unwrap(),
        expected
    );
    assert!(server.prepared_system_mutation.is_none());
}

fn assert_pull_rejected(server: &mut CmServer, request: CmHiveMutationRequest) {
    let pull = CmHiveMutationRequest {
        operation: hive_mutation_transfer::PULL,
        journal_offset: 0,
        chunk_len_bytes: 1,
        ..request
    };
    let mut output = [0xa5];
    assert_ne!(
        server
            .op_mutate_system_hive(pull.as_bytes(), &mut output)
            .status,
        STATUS_SUCCESS
    );
    assert_eq!(output, [0xa5]);
}

#[test]
fn stale_foreign_requests_and_incomplete_prepare_do_not_retire_upload() {
    let mut server = server();
    let bytes = record(
        kind::CREATE_KEY,
        &alloc::format!("{SERVICES}\\Child"),
        "",
        0,
        &[],
    );
    let request = begin(&mut server, bytes.len());
    assert_eq!(
        append(&mut server, request, 0, &bytes[..31]).status,
        STATUS_SUCCESS
    );
    assert_eq!(
        call(&mut server, request, &[]).status,
        STATUS_INVALID_PARAMETER
    );
    for (token, generation) in [
        (request.lease_token, 2),
        (request.lease_token + 1, 2),
        (request.lease_token + 1, 1),
    ] {
        let foreign = CmHiveMutationRequest {
            lease_token: token,
            expected_generation: generation,
            ..request
        };
        assert_ne!(
            append(&mut server, foreign, 31, &bytes[31..]).status,
            STATUS_SUCCESS
        );
        assert_ne!(call(&mut server, foreign, &[]).status, STATUS_SUCCESS);
        assert!(server.system_mutation_leases.is_busy());
    }
    assert_eq!(
        append(&mut server, request, 31, &bytes[31..]).status,
        STATUS_SUCCESS
    );
    assert_upload(&server, request, &bytes);
    let prepared = call(&mut server, request, &[]);
    assert_eq!(prepared.status, STATUS_SUCCESS);
    assert_eq!(call(&mut server, request, &[]), prepared);
}

#[test]
fn malformed_path_validation_and_generation_failures_retain_original_bytes() {
    let cases = [
        (alloc::vec![0xff; 25], 1),
        (
            record(
                kind::CREATE_KEY,
                r"\Registry\Machine\Software\Child",
                "",
                0,
                &[],
            ),
            1,
        ),
        (
            record(
                kind::DELETE_KEY,
                &alloc::format!("{SERVICES}\\Absent"),
                "",
                0,
                &[],
            ),
            1,
        ),
        (
            record(
                kind::CREATE_KEY,
                &alloc::format!("{SERVICES}\\Child"),
                "",
                0,
                &[],
            ),
            u64::MAX,
        ),
    ];
    for (bytes, generation) in cases {
        let mut server = server();
        server.system_hive.as_mut().unwrap().generation = generation;
        let before = nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive);
        let request = upload(&mut server, &bytes);
        let failure = call(&mut server, request, &[]);
        assert_ne!(failure.status, STATUS_SUCCESS);
        assert_eq!(call(&mut server, request, &[]), failure);
        assert_upload(&server, request, &bytes);
        assert_eq!(
            nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive),
            before
        );
        assert_eq!(server.device_action_journal.pending_len(), 0);
        let abort = CmHiveMutationRequest {
            operation: hive_mutation_transfer::ABORT,
            journal_offset: 0,
            ..request
        };
        assert_eq!(call(&mut server, abort, &[]).status, STATUS_SUCCESS);
        assert!(!server.system_mutation_leases.is_busy());
    }
}

#[test]
fn late_projection_failure_rolls_back_validation_and_retries_same_upload() {
    let mut server = server();
    let services = server.cm.registry().open_key(SERVICES).unwrap();
    assert!(server.cm.registry_mut().delete_key(services, false));
    let before = nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive);
    // SET_VALUE requires the missing semantic key before CREATE_KEY could recreate its parent.
    let mut bytes = record(
        kind::SET_VALUE,
        SERVICES,
        "Value",
        RegistryValueType::Dword as u32,
        &1u32.to_le_bytes(),
    );
    bytes.extend_from_slice(&record(
        kind::CREATE_KEY,
        &alloc::format!("{SERVICES}\\Child"),
        "",
        0,
        &[],
    ));
    let request = upload(&mut server, &bytes);
    for _ in 0..2 {
        assert_eq!(
            call(&mut server, request, &[]).status,
            STATUS_REGISTRY_CORRUPT
        );
        assert_upload(&server, request, &bytes);
        assert_eq!(
            nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive),
            before
        );
    }
    let mounted = server.system_hive.as_ref().unwrap();
    server.cm = config_manager_from_system_hive(&mounted.hive, &mounted.current_control_set);
    assert_eq!(call(&mut server, request, &[]).status, STATUS_SUCCESS);
    assert!(!server.system_mutation_leases.is_busy());
    assert_eq!(
        nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive),
        before
    );
    assert_eq!(server.system_hive.as_ref().unwrap().generation, 1);
}

#[test]
fn prepare_and_pull_replay_captured_result_without_revalidation() {
    let mut server = server();
    let bytes = record(
        kind::CREATE_KEY,
        &alloc::format!("{SERVICES}\\Child"),
        "",
        0,
        &[],
    );
    let request = upload(&mut server, &bytes);
    let first = call(&mut server, request, &[]);
    assert_eq!(first.status, STATUS_SUCCESS);
    assert_eq!(
        append(&mut server, request, 0, &bytes[..31]).status,
        STATUS_INVALID_PARAMETER
    );
    let prepared = server.prepared_system_mutation.as_ref().unwrap();
    let expected = prepared.durable_journal.clone();
    let address = prepared.durable_journal.as_ptr();
    // New authority cannot change already captured bytes or their generation.
    server.system_hive.as_mut().unwrap().generation = 7;
    assert_eq!(call(&mut server, request, &[]), first);
    assert_eq!(
        server
            .prepared_system_mutation
            .as_ref()
            .unwrap()
            .durable_journal
            .as_ptr(),
        address
    );
    for offset in 0..expected.len() {
        let pull = CmHiveMutationRequest {
            operation: hive_mutation_transfer::PULL,
            journal_offset: offset as u32,
            chunk_len_bytes: 13,
            ..request
        };
        let mut out = [0; 13];
        let reply = server.op_mutate_system_hive(pull.as_bytes(), &mut out);
        assert_eq!(reply.status, STATUS_SUCCESS);
        let end = core::cmp::min(offset + 13, expected.len());
        assert_eq!(reply.information as usize, end - offset);
        assert_eq!(reply.detail0 as usize, expected.len());
        assert_eq!(reply.detail1, request.lease_token);
        assert_eq!(&out[..end - offset], &expected[offset..end]);
    }
    for field in 0..6 {
        let mut wrong = request;
        match field {
            0 => wrong.lease_token += 1,
            1 => wrong.expected_generation += 1,
            2 => {
                wrong.journal_len_bytes += 1;
                wrong.journal_offset += 1;
            }
            3 => wrong.journal_offset -= 1,
            4 => wrong.chunk_offset = wrong.abi_size as u32,
            _ => wrong.chunk_len_bytes = 1,
        }
        assert_eq!(
            call(&mut server, wrong, &[]).status,
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(call(&mut server, request, &[]), first);
    }
    assert_eq!(server.system_hive.as_ref().unwrap().generation, 7);
    assert!(server
        .system_hive
        .as_ref()
        .unwrap()
        .hive
        .open_key(r"ControlSet001\Services\Child")
        .is_none());
}

#[test]
fn begin_is_not_deduplicated_by_equal_length_or_generation() {
    let mut server = server();
    let request = begin(&mut server, 4);
    let repeat = CmHiveMutationRequest {
        operation: hive_mutation_transfer::BEGIN,
        lease_token: 0,
        expected_mount: server.system_hive.as_ref().unwrap().identity,
        journal_offset: 0,
        ..request
    };
    assert_eq!(call(&mut server, repeat, &[]).status, STATUS_DEVICE_BUSY);
    assert_eq!(
        append(&mut server, request, 0, &[1, 2, 3, 4]).status,
        STATUS_SUCCESS
    );
    assert_upload(&server, request, &[1, 2, 3, 4]);
}

#[test]
fn begin_requires_exact_mount_and_transfer_cannot_rebind_it() {
    let mut server = server();
    let mounted = server.system_hive.as_ref().unwrap();
    let request = CmHiveMutationRequest {
        abi_size: core::mem::size_of::<CmHiveMutationRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        mount: hive_mount::SYSTEM,
        operation: hive_mutation_transfer::BEGIN,
        expected_generation: mounted.generation,
        expected_mount: mounted.identity,
        journal_len_bytes: 4,
        ..CmHiveMutationRequest::default()
    };
    for (identity, status) in [
        (0, STATUS_INVALID_PARAMETER),
        (request.expected_mount + 1, STATUS_INVALID_HANDLE),
    ] {
        assert_eq!(
            call(
                &mut server,
                CmHiveMutationRequest {
                    expected_mount: identity,
                    ..request
                },
                &[]
            )
            .status,
            status
        );
        assert!(!server.system_mutation_leases.is_busy());
    }
    let acquired = call(&mut server, request, &[]);
    assert_eq!(acquired.status, STATUS_SUCCESS);
    let transfer = CmHiveMutationRequest {
        operation: hive_mutation_transfer::APPEND,
        lease_token: acquired.detail1,
        chunk_offset: request.abi_size as u32,
        chunk_len_bytes: 4,
        ..request
    };
    assert_eq!(
        call(&mut server, transfer, &[1, 2, 3, 4]).status,
        STATUS_INVALID_PARAMETER
    );
    let transfer = CmHiveMutationRequest {
        expected_mount: 0,
        ..transfer
    };
    assert_eq!(
        call(&mut server, transfer, &[1, 2, 3, 4]).status,
        STATUS_SUCCESS
    );
    assert_upload(&server, transfer, &[1, 2, 3, 4]);
}

#[test]
fn another_cm_incarnation_cannot_consume_an_admitted_upload() {
    let mut original = server();
    let first = begin(&mut original, 4);
    let mut replacement = CmServer::new_for_incarnation(NonZeroU32::new(2).unwrap());
    replacement.system_hive = server().system_hive.take();
    replacement.system_hive.as_mut().unwrap().identity = replacement.identities.take().unwrap();
    let second = begin(&mut replacement, 4);
    assert_ne!(first.lease_token, second.lease_token);
    assert_eq!(
        append(&mut replacement, first, 0, &[1, 2, 3, 4]).status,
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        append(&mut original, second, 0, &[1, 2, 3, 4]).status,
        STATUS_INVALID_PARAMETER
    );
    let foreign_abort = CmHiveMutationRequest {
        operation: hive_mutation_transfer::ABORT,
        journal_offset: 0,
        ..first
    };
    assert_eq!(
        call(&mut replacement, foreign_abort, &[]).status,
        STATUS_INVALID_PARAMETER
    );
    assert!(original.system_mutation_leases.is_busy());
    assert!(replacement.system_mutation_leases.is_busy());
    assert_eq!(
        append(&mut original, first, 0, &[1, 2, 3, 4]).status,
        STATUS_SUCCESS
    );
    assert_eq!(
        append(&mut replacement, second, 0, &[5, 6, 7, 8]).status,
        STATUS_SUCCESS
    );
    assert_upload(&original, first, &[1, 2, 3, 4]);
    assert_upload(&replacement, second, &[5, 6, 7, 8]);
}

#[test]
fn live_generation_drift_preserves_upload_until_exact_cleanup() {
    let mut server = server();
    let bytes = record(
        kind::CREATE_KEY,
        &alloc::format!("{SERVICES}\\Child"),
        "",
        0,
        &[],
    );
    let request = upload(&mut server, &bytes);
    server.system_hive.as_mut().unwrap().generation = 2;
    assert_eq!(
        append(&mut server, request, 0, &bytes[..31]).status,
        STATUS_REVISION_MISMATCH
    );
    assert_eq!(
        call(&mut server, request, &[]).status,
        STATUS_REVISION_MISMATCH
    );
    assert_upload(&server, request, &bytes);
    let abort = CmHiveMutationRequest {
        operation: hive_mutation_transfer::ABORT,
        journal_offset: 0,
        ..request
    };
    assert_eq!(call(&mut server, abort, &[]).status, STATUS_SUCCESS);
    assert!(!server.system_mutation_leases.is_busy());
}

#[test]
fn old_prepare_never_resurrects_after_commit_or_abort() {
    use nt_config_abi::{hive_mutation_commit_operation as operation, CmHiveMutationCommitRequest};
    for operation in [operation::COMMIT, operation::ABORT] {
        let mut server = server();
        let bytes = record(
            kind::CREATE_KEY,
            &alloc::format!("{SERVICES}\\Child"),
            "",
            0,
            &[],
        );
        let request = upload(&mut server, &bytes);
        assert_eq!(call(&mut server, request, &[]).status, STATUS_SUCCESS);
        let terminal = CmHiveMutationCommitRequest {
            abi_size: core::mem::size_of::<CmHiveMutationCommitRequest>() as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            mount: hive_mount::SYSTEM,
            mutation_token: request.lease_token,
            expected_generation: request.expected_generation,
            semantic_journal_len: request.journal_len_bytes,
            ..CmHiveMutationCommitRequest::default()
        };
        let mut output = [0; 56];
        let receipt = server.op_system_hive_mutation_commit(terminal.as_bytes(), &mut output);
        assert_eq!(receipt.status, STATUS_SUCCESS);
        for _ in 0..2 {
            assert_ne!(call(&mut server, request, &[]).status, STATUS_SUCCESS);
            assert_pull_rejected(&mut server, request);
            assert!(server.prepared_system_mutation.is_none());
            assert!(!server.system_mutation_leases.is_busy());
            let mut retry = [0; 56];
            assert_eq!(
                server.op_system_hive_mutation_commit(terminal.as_bytes(), &mut retry),
                receipt
            );
            assert_eq!(retry, output);
        }
        let ack = CmHiveMutationCommitRequest {
            operation: operation::ACKNOWLEDGE,
            receipt_bank: receipt.detail0,
            receipt_generation: receipt.detail1,
            mutation_token: 0,
            expected_generation: 0,
            semantic_journal_len: 0,
            ..terminal
        };
        assert_eq!(
            server
                .op_system_hive_mutation_commit(ack.as_bytes(), &mut output)
                .status,
            STATUS_SUCCESS
        );
        let next_bytes = record(
            kind::CREATE_KEY,
            &alloc::format!("{SERVICES}\\Next"),
            "",
            0,
            &[],
        );
        let next = upload(&mut server, &next_bytes);
        assert_ne!(call(&mut server, request, &[]).status, STATUS_SUCCESS);
        assert_pull_rejected(&mut server, request);
        assert_upload(&server, next, &next_bytes);
        let new_prepared = call(&mut server, next, &[]);
        assert_eq!(new_prepared.status, STATUS_SUCCESS);
        assert_eq!(
            call(&mut server, request, &[]).status,
            STATUS_INVALID_PARAMETER
        );
        assert_pull_rejected(&mut server, request);
        assert_eq!(call(&mut server, next, &[]), new_prepared);
    }
}
