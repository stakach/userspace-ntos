use crate::*;
use nt_config_abi::{hive_mutation_kind, CmHiveMutationRecord, CmSystemHiveMountRequest};

fn request(generation: u64, identity: u64) -> CmSystemHiveMountRequest {
    CmSystemHiveMountRequest {
        abi_size: core::mem::size_of::<CmSystemHiveMountRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        mount: hive_mount::SYSTEM,
        _reserved: 0,
        expected_generation: generation,
        expected_identity: identity,
    }
}

fn query(server: &mut CmServer, generation: u64, identity: u64) -> CmReply {
    let mut output = [0xa5; 32];
    let result = server.dispatch(
        opcode::CM_OP_QUERY_SYSTEM_HIVE_MOUNT,
        request(generation, identity).as_bytes(),
        &mut output,
    );
    assert_eq!(result.information, 0);
    assert_eq!(output, [0xa5; 32]);
    result
}

fn rejected(reply: CmReply, status: i32) {
    assert_eq!(reply.status, status);
    assert_eq!((reply.information, reply.detail0, reply.detail1), (0, 0, 0));
}

fn image() -> Vec<u8> {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    hive.create_key(r"ControlSet001\Services");
    let devnode = hive.create_key(r"ControlSet001\Enum\ROOT\MOUNT\0000");
    hive.set_value(
        devnode,
        "PdoName",
        RegistryValueType::Sz,
        nt_config_manager::encode_sz(r"\Device\MountIdentityTest"),
    );
    hive.finish_clean_import();
    nt_hive_core::encode_image(&hive)
}

fn import_call(
    server: &mut CmServer,
    operation: u16,
    token: u64,
    offset: usize,
    length: usize,
    chunk: &[u8],
) -> CmReply {
    let size = core::mem::size_of::<CmHiveImportRequest>();
    let header = CmHiveImportRequest {
        abi_size: size as u16,
        abi_version: CM_ABI_VERSION,
        operation,
        mount: hive_mount::SYSTEM,
        value_offset: offset as u32,
        chunk_offset: if chunk.is_empty() { 0 } else { size as u32 },
        chunk_len_bytes: chunk.len() as u32,
        total_len_bytes: length as u32,
        transfer_token: token,
    };
    let mut input = header.as_bytes().to_vec();
    input.extend_from_slice(chunk);
    server.dispatch(opcode::CM_OP_IMPORT_HIVE, &input, &mut [])
}

fn upload(server: &mut CmServer, bytes: &[u8]) -> u64 {
    let begin = import_call(server, hive_import_transfer::BEGIN, 0, 0, bytes.len(), &[]);
    assert_eq!(begin.status, STATUS_SUCCESS);
    assert_ne!(begin.detail1, 0);
    let mut offset = 0;
    for chunk in bytes.chunks(CM_HIVE_IMPORT_CHUNK_BYTES) {
        let result = import_call(
            server,
            hive_import_transfer::PUSH,
            begin.detail1,
            offset,
            bytes.len(),
            chunk,
        );
        assert_eq!(result.status, STATUS_SUCCESS);
        offset += chunk.len();
        assert_eq!(result.detail0, offset as u64);
    }
    begin.detail1
}

fn publish(server: &mut CmServer, bytes: &[u8]) -> u64 {
    let token = upload(server, bytes);
    let result = import_call(
        server,
        hive_import_transfer::COMMIT,
        token,
        bytes.len(),
        bytes.len(),
        &[],
    );
    assert_eq!(result.status, STATUS_SUCCESS);
    assert_eq!(result.detail1, token);
    result.detail0
}

#[test]
fn absent_and_malformed_queries_never_disclose_authority_or_touch_output() {
    let mut server = CmServer::new_for_incarnation(NonZeroU32::MIN);
    rejected(query(&mut server, 1, 0), STATUS_DEVICE_NOT_READY);
    assert_eq!(publish(&mut server, &image()), 1);
    let before = query(&mut server, 1, 0);
    assert_eq!(before.status, STATUS_SUCCESS);
    assert_ne!(before.detail1, 0);
    for field in 0..6 {
        let mut malformed = request(1, 0);
        match field {
            0 => malformed.abi_size -= 1,
            1 => malformed.abi_size += 1,
            2 => malformed.abi_version += 1,
            3 => malformed.mount = 0,
            4 => malformed._reserved = 1,
            _ => malformed.expected_generation = 0,
        }
        let mut out = [0xa5; 32];
        rejected(
            server.dispatch(
                opcode::CM_OP_QUERY_SYSTEM_HIVE_MOUNT,
                malformed.as_bytes(),
                &mut out,
            ),
            STATUS_INVALID_PARAMETER,
        );
        assert_eq!(out, [0xa5; 32]);
    }
    let valid = request(1, 0);
    for length in 0..valid.as_bytes().len() {
        rejected(
            server.dispatch(
                opcode::CM_OP_QUERY_SYSTEM_HIVE_MOUNT,
                &valid.as_bytes()[..length],
                &mut [],
            ),
            STATUS_INVALID_PARAMETER,
        );
    }
    let mut too_long = valid.as_bytes().to_vec();
    too_long.push(0);
    rejected(
        server.dispatch(opcode::CM_OP_QUERY_SYSTEM_HIVE_MOUNT, &too_long, &mut []),
        STATUS_INVALID_PARAMETER,
    );
    assert_eq!(query(&mut server, 1, 0), before);
}

#[test]
fn exact_generation_and_incarnation_queries_are_read_only() {
    let mut server = CmServer::new_for_incarnation(NonZeroU32::MIN);
    publish(&mut server, &image());
    let first = query(&mut server, 1, 0);
    assert_eq!(first.status, STATUS_SUCCESS);
    assert_eq!(first.detail0, 1);
    let before = nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive);
    let pending = server.device_action_journal.pending_len();
    let next = server.identities.next_sequence.get();
    for _ in 0..3 {
        assert_eq!(query(&mut server, 1, first.detail1), first);
        rejected(
            query(&mut server, 2, first.detail1),
            STATUS_REVISION_MISMATCH,
        );
        rejected(
            query(&mut server, 1, first.detail1 + 1),
            STATUS_REVISION_MISMATCH,
        );
    }
    assert_eq!(
        nt_hive_core::encode_image(&server.system_hive.as_ref().unwrap().hive),
        before
    );
    assert_eq!(server.device_action_journal.pending_len(), pending);
    assert_eq!(server.identities.next_sequence.get(), next);
    assert_eq!(server.hive_imports.len(), 0);
    assert!(!server.system_mutation_leases.is_busy());
    assert!(server.prepared_system_mutation.is_none());
    assert!(server.prepared_system_checkpoint.is_none());
}

#[test]
fn reimport_and_reconstructed_server_never_reuse_mount_incarnation() {
    let source = Rc::new(CmIdentitySource::new(NonZeroU32::MIN));
    let bytes = image();
    let mut first = CmServer::new_with_identity_source(Rc::clone(&source));
    assert_eq!(publish(&mut first, &bytes), 1);
    let old = query(&mut first, 1, 0).detail1;
    assert_eq!(publish(&mut first, &bytes), 2);
    let replacement = query(&mut first, 2, 0).detail1;
    assert_ne!(replacement, old);
    rejected(query(&mut first, 2, old), STATUS_REVISION_MISMATCH);
    rejected(query(&mut first, 1, replacement), STATUS_REVISION_MISMATCH);
    drop(first);
    let mut restarted = CmServer::new_with_identity_source(source);
    assert_eq!(publish(&mut restarted, &bytes), 1);
    let new = query(&mut restarted, 1, 0).detail1;
    assert_ne!(new, old);
    assert_ne!(new, replacement);
    rejected(query(&mut restarted, 1, old), STATUS_REVISION_MISMATCH);
    rejected(
        query(&mut restarted, 1, replacement),
        STATUS_REVISION_MISMATCH,
    );
}

#[test]
fn identity_exhaustion_keeps_import_pending_and_preserves_publication_state() {
    for existing in [false, true] {
        let mut server = CmServer::new_for_incarnation(NonZeroU32::MIN);
        let bytes = image();
        let before = if existing {
            publish(&mut server, &bytes);
            Some(query(&mut server, 1, 0))
        } else {
            None
        };
        let token = upload(&mut server, &bytes);
        let pending = server.device_action_journal.pending_len();
        let restore_sequence = server.identities.next_sequence.get();
        server.identities.next_sequence.set(0);
        let result = import_call(
            &mut server,
            hive_import_transfer::COMMIT,
            token,
            bytes.len(),
            bytes.len(),
            &[],
        );
        assert_eq!(result.status, STATUS_INSUFFICIENT_RESOURCES);
        assert_eq!(server.hive_imports.len(), 1);
        assert_eq!(server.device_action_journal.pending_len(), pending);
        assert_eq!(server.system_hive.is_some(), existing);
        if let Some(before) = before {
            assert_eq!(query(&mut server, 1, before.detail1), before);
        } else {
            assert_eq!(pending, 0);
            assert!(server.config().devnode(r"ROOT\MOUNT\0000").is_none());
        }
        server.identities.next_sequence.set(restore_sequence);
        assert_eq!(
            import_call(
                &mut server,
                hive_import_transfer::COMMIT,
                token,
                bytes.len(),
                bytes.len(),
                &[]
            )
            .status,
            STATUS_SUCCESS
        );
        assert!(server.config().devnode(r"ROOT\MOUNT\0000").is_some());
        // Initial import seeds known topology, not synthetic arrivals. Successful retry above
        // also proves the failed first import did not seed it (which would reject reseeding).
        assert_eq!(server.device_action_journal.pending_len(), 0);
        assert_eq!(server.hive_imports.len(), 0);
    }
}

#[test]
fn mutation_and_checkpoint_preserve_mount_identity() {
    let mut server = CmServer::new_for_incarnation(NonZeroU32::MIN);
    publish(&mut server, &image());
    let identity = query(&mut server, 1, 0).detail1;
    let path: Vec<u8> = r"\Registry\Machine\System\CurrentControlSet\Services\Child"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let header = CmHiveMutationRecord {
        kind: hive_mutation_kind::CREATE_KEY,
        path_len_bytes: path.len() as u32,
        ..CmHiveMutationRecord::default()
    };
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(&path);
    let mut request = CmHiveMutationRequest {
        abi_size: core::mem::size_of::<CmHiveMutationRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        operation: hive_mutation_transfer::BEGIN,
        mount: hive_mount::SYSTEM,
        journal_len_bytes: bytes.len() as u32,
        expected_generation: 1,
        expected_mount: identity,
        ..CmHiveMutationRequest::default()
    };
    let begin = server.dispatch(
        opcode::CM_OP_MUTATE_SYSTEM_HIVE,
        request.as_bytes(),
        &mut [],
    );
    assert_eq!(begin.status, STATUS_SUCCESS);
    request.lease_token = begin.detail1;
    request.expected_mount = 0;
    request.operation = hive_mutation_transfer::APPEND;
    request.chunk_offset = request.abi_size as u32;
    request.chunk_len_bytes = bytes.len() as u32;
    let mut input = request.as_bytes().to_vec();
    input.extend_from_slice(&bytes);
    assert_eq!(
        server
            .dispatch(opcode::CM_OP_MUTATE_SYSTEM_HIVE, &input, &mut [])
            .status,
        STATUS_SUCCESS
    );
    request.journal_offset = bytes.len() as u32;
    request.chunk_offset = 0;
    request.chunk_len_bytes = 0;
    for operation in [
        hive_mutation_transfer::PREPARE,
        hive_mutation_transfer::COMMIT,
    ] {
        request.operation = operation;
        assert_eq!(
            server
                .dispatch(
                    opcode::CM_OP_MUTATE_SYSTEM_HIVE,
                    request.as_bytes(),
                    &mut []
                )
                .status,
            STATUS_SUCCESS
        );
    }
    let after = query(&mut server, 2, identity);
    assert_eq!(after.status, STATUS_SUCCESS);
    assert_eq!((after.detail0, after.detail1), (2, identity));
    rejected(query(&mut server, 1, identity), STATUS_REVISION_MISMATCH);
    let mut checkpoint = CmHiveCheckpointRequest {
        abi_size: core::mem::size_of::<CmHiveCheckpointRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        operation: hive_checkpoint_transfer::BEGIN,
        mount: hive_mount::SYSTEM,
        expected_generation: 2,
        chunk_capacity: CM_HIVE_CHECKPOINT_CHUNK_BYTES as u32,
        ..CmHiveCheckpointRequest::default()
    };
    let mut output = [0; CM_HIVE_CHECKPOINT_CHUNK_BYTES];
    let begin = server.dispatch(
        opcode::CM_OP_CHECKPOINT_SYSTEM_HIVE,
        checkpoint.as_bytes(),
        &mut output,
    );
    assert_eq!(begin.status, STATUS_SUCCESS);
    assert_ne!(begin.detail1, 0);
    checkpoint.transfer_token = begin.detail1;
    checkpoint.value_offset = begin.information;
    checkpoint.operation = hive_checkpoint_transfer::PULL;
    while u64::from(checkpoint.value_offset) < begin.detail0 {
        let pulled = server.dispatch(
            opcode::CM_OP_CHECKPOINT_SYSTEM_HIVE,
            checkpoint.as_bytes(),
            &mut output,
        );
        assert_eq!(pulled.status, STATUS_SUCCESS);
        assert_ne!(pulled.information, 0);
        checkpoint.value_offset += pulled.information;
    }
    checkpoint.operation = hive_checkpoint_transfer::ACK;
    checkpoint.chunk_capacity = 0;
    assert_eq!(
        server
            .dispatch(
                opcode::CM_OP_CHECKPOINT_SYSTEM_HIVE,
                checkpoint.as_bytes(),
                &mut []
            )
            .status,
        STATUS_SUCCESS
    );
    assert_eq!(server.system_hive.as_ref().unwrap().hive.dirty_count(), 0);
    assert_eq!(query(&mut server, 2, identity), after);
}
