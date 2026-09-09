use super::*;
use nt_config_manager::encode_sz;

const PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Services\Device";

fn server(incarnation: u32) -> CmServer {
    let mut server = CmServer::new_for_incarnation(NonZeroU32::new(incarnation).unwrap());
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    let key = hive.create_key(r"ControlSet001\Services\Device");
    hive.set_dword(key, "Type", 1);
    hive.set_dword(key, "Start", 3);
    hive.set_value(
        key,
        "ImagePath",
        RegistryValueType::Sz,
        encode_sz(r"system32\drivers\real.sys"),
    );
    hive.finish_clean_import();
    server.system_hive = Some(MountedSystemHive {
        hardware_profile: nt_hive_core::HardwareProfileAlias::capture(
            &hive, &hive.current_control_set().unwrap(),
        ).unwrap(),
        current_control_set: hive.current_control_set().unwrap(),
        hive,
        generation: 1,
    });
    server
}

fn request(operation: u16) -> CmRetainedSnapshotRequest {
    CmRetainedSnapshotRequest {
        abi_size: 56,
        abi_version: CM_ABI_VERSION,
        operation,
        ..CmRetainedSnapshotRequest::default()
    }
}

fn execute(server: &mut CmServer, bytes: &[u8]) -> (CmReply, CmRetainedSnapshotReply, Vec<u8>) {
    let mut output = [0; 4096];
    let reply = server.dispatch(opcode::CM_OP_RETAINED_SNAPSHOT, bytes, &mut output);
    let body = CmRetainedSnapshotReply::from_bytes(&output).unwrap();
    if reply.status == STATUS_SUCCESS {
        assert_eq!(body.abi_size, 64);
        assert_eq!(body.abi_version, CM_ABI_VERSION);
        assert_eq!(body._reserved, 0);
        assert_eq!(reply.information, 64 + body.chunk_bytes);
        assert_eq!(reply.detail0, body.server_nonce);
        assert_eq!(reply.detail1, body.request_generation);
        (reply, body, output[64..reply.information as usize].to_vec())
    } else {
        (reply, body, Vec::new())
    }
}

fn registration(requester: u64, slots: u32) -> CmRetainedSnapshotRequest {
    CmRetainedSnapshotRequest {
        requester_nonce: requester,
        chunk_capacity: slots,
        ..request(operation::QUERY)
    }
}

fn grant(server: &mut CmServer, requester: u64, slots: u32) -> u64 {
    let (reply, body, _) = execute(server, registration(requester, slots).as_bytes());
    assert_eq!(reply.status, STATUS_SUCCESS);
    assert_eq!(body.disposition, disposition::AUTHORITY);
    assert_eq!(body.requester_nonce, requester);
    assert_eq!(body.total_bytes, slots);
    body.server_nonce
}

fn identity(
    nonce: u64,
    requester: u64,
    slot: u64,
    generation: u64,
    operation: u16,
) -> CmRetainedSnapshotRequest {
    CmRetainedSnapshotRequest {
        server_nonce: nonce,
        requester_nonce: requester,
        request_slot: slot,
        request_generation: generation,
        query_kind: kind::ACTIVE_DRIVER_SERVICE,
        ..request(operation)
    }
}

fn begin(identity: CmRetainedSnapshotRequest, path: &str) -> Vec<u8> {
    let header = CmRetainedSnapshotRequest {
        operation: operation::BEGIN,
        request_offset: 56,
        request_len_bytes: (path.encode_utf16().count() * 2) as u32,
        ..identity
    };
    let mut bytes = header.as_bytes().to_vec();
    for unit in path.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn ack(
    server: &mut CmServer,
    identity: CmRetainedSnapshotRequest,
) -> (CmReply, CmRetainedSnapshotReply) {
    let request = CmRetainedSnapshotRequest {
        operation: operation::ACKNOWLEDGE,
        ..identity
    };
    let (reply, body, _) = execute(server, request.as_bytes());
    (reply, body)
}

fn pull(
    server: &mut CmServer,
    identity: CmRetainedSnapshotRequest,
    offset: u32,
    capacity: u32,
) -> (CmReply, CmRetainedSnapshotReply, Vec<u8>) {
    execute(
        server,
        CmRetainedSnapshotRequest {
            operation: operation::PULL,
            value_offset: offset,
            chunk_capacity: capacity,
            ..identity
        }
        .as_bytes(),
    )
}

fn collect(server: &mut CmServer, identity: CmRetainedSnapshotRequest, size: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    while bytes.len() < size as usize {
        let (reply, body, chunk) = pull(server, identity, bytes.len() as u32, 31);
        assert_eq!(reply.status, STATUS_SUCCESS);
        assert_eq!(body.disposition, disposition::CHUNK);
        assert_eq!(body.value_offset, bytes.len() as u32);
        assert_eq!(body.total_bytes, size);
        assert!(!chunk.is_empty());
        bytes.extend_from_slice(&chunk);
    }
    bytes
}

#[test]
fn lost_registration_reply_replays_the_same_preallocated_bank() {
    let mut server = server(1);
    let first = execute(&mut server, registration(9, 2).as_bytes());
    let second = execute(&mut server, registration(9, 2).as_bytes());
    assert_eq!(first, second);
    assert_eq!(server.retained_snapshots.granted_slots, 2);
    assert_eq!(server.retained_snapshots.requesters.len(), 1);
    assert_eq!(
        execute(&mut server, registration(9, 3).as_bytes()).0.status,
        STATUS_INVALID_PARAMETER
    );
    server.retained_snapshots.max_slots = 2;
    assert_eq!(
        execute(&mut server, registration(10, 1).as_bytes())
            .0
            .status,
        STATUS_INSUFFICIENT_RESOURCES
    );
    let identity = identity(first.1.server_nonce, 9, 1, 1, operation::ACKNOWLEDGE);
    assert_eq!(
        ack(&mut server, identity).1.disposition,
        disposition::ACKNOWLEDGED
    );
}

#[test]
fn begin_replay_is_exact_and_does_not_recapture_mutated_hive() {
    let mut server = server(1);
    let nonce = grant(&mut server, 9, 2);
    let identity = identity(nonce, 9, 0, 1, operation::BEGIN);
    let input = begin(identity, PATH);
    let first = execute(&mut server, &input);
    assert_eq!(first.0.status, STATUS_SUCCESS);
    assert_eq!(first.1.disposition, disposition::OUTCOME);
    assert_eq!(first.1.outcome_status, STATUS_SUCCESS);
    let original = collect(&mut server, identity, first.1.total_bytes);
    let retained = server.retained_snapshots.retained_bytes;
    let mounted = server.system_hive.as_mut().unwrap();
    let key = mounted
        .hive
        .open_key(r"ControlSet001\Services\Device")
        .unwrap();
    mounted.hive.set_value(
        key,
        "ImagePath",
        RegistryValueType::Sz,
        encode_sz("changed.sys"),
    );
    mounted.generation += 1;
    assert_eq!(execute(&mut server, &input), first);
    assert_eq!(
        collect(&mut server, identity, first.1.total_bytes),
        original
    );
    assert_eq!(server.retained_snapshots.retained_bytes, retained);
    assert_eq!(
        execute(&mut server, &begin(identity, &PATH.to_ascii_lowercase()))
            .0
            .status,
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(ack(&mut server, identity).0.status, STATUS_SUCCESS);
    assert_eq!(server.retained_snapshots.retained_bytes, 0);
}

#[test]
fn final_pull_is_replayable_and_only_ack_releases_bytes() {
    let mut server = server(1);
    let nonce = grant(&mut server, 9, 1);
    let identity = identity(nonce, 9, 0, 1, operation::BEGIN);
    let outcome = execute(&mut server, &begin(identity, PATH)).1;
    let final_offset = outcome.total_bytes - 7;
    let first = pull(&mut server, identity, final_offset, 31);
    assert_eq!(first.2.len(), 7);
    assert_eq!(pull(&mut server, identity, final_offset, 31), first);
    assert!(server.retained_snapshots.retained_bytes > 0);
    assert_eq!(
        pull(&mut server, identity, outcome.total_bytes + 1, 1)
            .0
            .status,
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        pull(&mut server, identity, outcome.total_bytes, 1)
            .1
            .chunk_bytes,
        0
    );
    assert_eq!(
        ack(&mut server, identity).1.disposition,
        disposition::ACKNOWLEDGED
    );
    assert_eq!(
        ack(&mut server, identity).1.disposition,
        disposition::ALREADY_ACKNOWLEDGED
    );
    assert_eq!(
        pull(&mut server, identity, 0, 1).0.status,
        STATUS_INVALID_HANDLE
    );
}

#[test]
fn cleanup_fences_unexecuted_begin_without_allocating_or_consuming_new_identity() {
    let mut server = server(1);
    let nonce = grant(&mut server, 9, 1);
    let identity = identity(nonce, 9, 0, 1, operation::BEGIN);
    server.identities.next_sequence.set(0);
    server.retained_snapshots.max_slots = 0;
    server.retained_snapshots.max_bytes = 0;
    assert_eq!(
        ack(&mut server, identity).1.disposition,
        disposition::ACKNOWLEDGED
    );
    assert_eq!(
        execute(&mut server, &begin(identity, PATH)).0.status,
        STATUS_INVALID_HANDLE
    );
    assert_eq!(
        ack(&mut server, identity).1.disposition,
        disposition::ALREADY_ACKNOWLEDGED
    );
    let future = CmRetainedSnapshotRequest {
        request_generation: 3,
        ..identity
    };
    assert_eq!(ack(&mut server, future).0.status, STATUS_INVALID_HANDLE);
    let next = CmRetainedSnapshotRequest {
        request_generation: 2,
        ..identity
    };
    assert_eq!(
        ack(&mut server, next).1.disposition,
        disposition::ACKNOWLEDGED
    );
}

#[test]
fn failed_outcomes_are_cached_until_acknowledged() {
    let mut server = server(1);
    let nonce = grant(&mut server, 9, 1);
    let identity = identity(nonce, 9, 0, 1, operation::BEGIN);
    let mounted = server.system_hive.take();
    let first = execute(&mut server, &begin(identity, PATH));
    assert_eq!(first.0.status, STATUS_SUCCESS);
    assert_eq!(first.1.outcome_status, STATUS_DEVICE_NOT_READY);
    assert_eq!(first.1.total_bytes, 0);
    server.system_hive = mounted;
    assert_eq!(execute(&mut server, &begin(identity, PATH)), first);
    assert_eq!(ack(&mut server, identity).0.status, STATUS_SUCCESS);
    let next = CmRetainedSnapshotRequest {
        request_generation: 2,
        ..identity
    };
    assert_eq!(
        execute(&mut server, &begin(next, PATH)).1.outcome_status,
        STATUS_SUCCESS
    );
}

#[test]
fn byte_budget_failure_is_cached_without_evicting_another_reader() {
    let mut server = server(1);
    let nonce = grant(&mut server, 9, 2);
    let a = identity(nonce, 9, 0, 1, operation::BEGIN);
    let b = identity(nonce, 9, 1, 1, operation::BEGIN);
    let a_outcome = execute(&mut server, &begin(a, PATH)).1;
    let original = collect(&mut server, a, a_outcome.total_bytes);
    server.retained_snapshots.max_bytes = server.retained_snapshots.retained_bytes;
    let failed = execute(&mut server, &begin(b, PATH));
    assert_eq!(failed.1.outcome_status, STATUS_INSUFFICIENT_RESOURCES);
    assert_eq!(collect(&mut server, a, a_outcome.total_bytes), original);
    assert_eq!(ack(&mut server, a).0.status, STATUS_SUCCESS);
    assert_eq!(execute(&mut server, &begin(b, PATH)), failed);
    assert_eq!(ack(&mut server, b).0.status, STATUS_SUCCESS);
    let next = CmRetainedSnapshotRequest {
        request_generation: 2,
        ..b
    };
    assert_eq!(
        execute(&mut server, &begin(next, PATH)).1.outcome_status,
        STATUS_SUCCESS
    );
}

#[test]
fn old_ack_cannot_release_a_later_generation_in_the_same_slot() {
    let mut server = server(1);
    let nonce = grant(&mut server, 9, 1);
    let first = identity(nonce, 9, 0, 1, operation::BEGIN);
    execute(&mut server, &begin(first, PATH));
    assert_eq!(ack(&mut server, first).0.status, STATUS_SUCCESS);
    let second = CmRetainedSnapshotRequest {
        request_generation: 2,
        ..first
    };
    let outcome = execute(&mut server, &begin(second, PATH)).1;
    let retained = server.retained_snapshots.retained_bytes;
    assert_eq!(
        ack(&mut server, first).1.disposition,
        disposition::ALREADY_ACKNOWLEDGED
    );
    assert_eq!(server.retained_snapshots.retained_bytes, retained);
    assert_eq!(
        collect(&mut server, second, outcome.total_bytes).len(),
        outcome.total_bytes as usize
    );
    assert_eq!(
        execute(&mut server, &begin(first, PATH)).0.status,
        STATUS_INVALID_HANDLE
    );
}

#[test]
fn independent_registered_banks_and_slots_do_not_replace_each_other() {
    let mut server = server(1);
    let nonce = grant(&mut server, 9, 2);
    assert_eq!(grant(&mut server, 10, 1), nonce);
    let a = identity(nonce, 9, 0, 1, operation::BEGIN);
    let b = identity(nonce, 10, 0, 1, operation::BEGIN);
    let a_outcome = execute(&mut server, &begin(a, PATH)).1;
    let b_outcome = execute(&mut server, &begin(b, PATH)).1;
    assert_eq!(ack(&mut server, a).0.status, STATUS_SUCCESS);
    assert_eq!(
        collect(&mut server, b, b_outcome.total_bytes).len(),
        a_outcome.total_bytes as usize
    );
}

#[test]
fn restart_and_reconstruction_do_not_admit_stale_requests() {
    let mut first = server(1);
    let nonce = grant(&mut first, 9, 1);
    let old = identity(nonce, 9, 0, 1, operation::BEGIN);
    execute(&mut first, &begin(old, PATH));
    let mut second = server(2);
    let second_nonce = grant(&mut second, 9, 1);
    assert_ne!(second_nonce, nonce);
    assert_eq!(ack(&mut second, old).0.status, STATUS_INVALID_HANDLE);
    let mut reconstructed = CmServer::new_with_identity_source(first.identities.clone());
    assert_ne!(grant(&mut reconstructed, 9, 1), nonce);
    assert_eq!(
        execute(&mut reconstructed, &begin(old, PATH)).0.status,
        STATUS_INVALID_HANDLE
    );
    let mut moved = first;
    assert_eq!(ack(&mut moved, old).0.status, STATUS_SUCCESS);
}

#[test]
fn frame_validation_and_output_capacity_precede_journal_mutation() {
    let mut server = server(1);
    assert_eq!(
        server
            .dispatch(
                opcode::CM_OP_RETAINED_SNAPSHOT,
                registration(9, 1).as_bytes(),
                &mut [0; 63]
            )
            .status,
        STATUS_BUFFER_TOO_SMALL
    );
    assert_eq!(server.retained_snapshots.granted_slots, 0);
    let nonce = grant(&mut server, 9, 1);
    let identity = identity(nonce, 9, 0, 1, operation::BEGIN);
    let mut bad = begin(identity, PATH);
    bad.push(0);
    assert_eq!(
        execute(&mut server, &bad).0.status,
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        execute(&mut server, &begin(identity, "\0")).0.status,
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        server
            .dispatch(
                opcode::CM_OP_RETAINED_SNAPSHOT,
                &begin(identity, PATH),
                &mut [0; 63]
            )
            .status,
        STATUS_BUFFER_TOO_SMALL
    );
    assert!(server.retained_snapshots.requesters[0].slots[0]
        .pending
        .is_none());
    assert_eq!(ack(&mut server, identity).0.status, STATUS_SUCCESS);
    assert_eq!(
        server.dispatch(0x21ff, &[], &mut []).status,
        STATUS_INVALID_SYSTEM_SERVICE
    );
}

#[test]
fn foreign_identity_and_exhausted_slot_generation_fail_closed() {
    let mut server = server(1);
    let nonce = grant(&mut server, 9, 1);
    let valid = identity(nonce, 9, 0, 1, operation::BEGIN);
    for invalid in [
        CmRetainedSnapshotRequest {
            server_nonce: nonce + 1,
            ..valid
        },
        CmRetainedSnapshotRequest {
            requester_nonce: 10,
            ..valid
        },
        CmRetainedSnapshotRequest {
            request_slot: 1,
            ..valid
        },
        CmRetainedSnapshotRequest {
            request_generation: 2,
            ..valid
        },
    ] {
        assert_eq!(ack(&mut server, invalid).0.status, STATUS_INVALID_HANDLE);
    }
    server.retained_snapshots.requesters[0].slots[0].acknowledged = u64::MAX - 1;
    let last = CmRetainedSnapshotRequest {
        request_generation: u64::MAX,
        ..valid
    };
    assert_eq!(
        execute(&mut server, &begin(last, PATH)).1.outcome_status,
        STATUS_SUCCESS
    );
    assert_eq!(
        ack(&mut server, last).1.disposition,
        disposition::ACKNOWLEDGED
    );
    assert_eq!(
        ack(&mut server, last).1.disposition,
        disposition::ALREADY_ACKNOWLEDGED
    );
    let wrapped = CmRetainedSnapshotRequest {
        request_generation: 0,
        ..valid
    };
    assert_eq!(
        execute(&mut server, &begin(wrapped, PATH)).0.status,
        STATUS_INVALID_HANDLE
    );
}

#[test]
fn exhausted_server_authority_cannot_publish_a_bank() {
    let mut server = server(1);
    server.identities.next_sequence.set(0);
    assert_eq!(
        execute(&mut server, registration(9, 1).as_bytes()).0.status,
        STATUS_INSUFFICIENT_RESOURCES
    );
    assert_eq!(server.retained_snapshots.granted_slots, 0);
    assert!(server.retained_snapshots.requesters.is_empty());
}
