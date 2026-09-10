use super::*;
use core::num::NonZeroU32;

fn server() -> CmServer {
    server_with_source(Rc::new(CmIdentitySource::new(NonZeroU32::MIN)))
}

fn server_with_source(source: Rc<CmIdentitySource>) -> CmServer {
    let mut server = CmServer::new_with_identity_source(source);
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    hive.create_key("ControlSet001\\Services\\Device");
    hive.finish_clean_import();
    server.system_hive = Some(MountedSystemHive {
        identity: server.identities.take().unwrap(),
        hardware_profile: nt_hive_core::HardwareProfileAlias::capture(
            &hive, &hive.current_control_set().unwrap(),
        ).unwrap(),
        current_control_set: hive.current_control_set().unwrap(),
        hive,
        generation: 1,
    });
    server
}

fn request(operation: u16) -> CmHiveKeyOpenRequest {
    CmHiveKeyOpenRequest {
        abi_size: core::mem::size_of::<CmHiveKeyOpenRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        operation,
        mount: hive_mount::SYSTEM,
        ..CmHiveKeyOpenRequest::default()
    }
}

fn run(server: &mut CmServer, input: &[u8]) -> (CmReply, CmHiveKeyOpenReply, Vec<u8>) {
    let mut output = [0; CM_HIVE_KEY_OPEN_REPLY_MAX_BYTES];
    let reply = server.dispatch(opcode::CM_OP_SYSTEM_HIVE_KEY_OPEN, input, &mut output);
    let body = CmHiveKeyOpenReply::from_bytes(&output).unwrap();
    let payload = if reply.status == STATUS_SUCCESS {
        output[..reply.information as usize].to_vec()
    } else {
        Vec::new()
    };
    (reply, body, payload)
}

fn authority(server: &mut CmServer) -> u64 {
    let (reply, body, _) = run(server, request(operation::QUERY).as_bytes());
    assert_eq!(reply.status, STATUS_SUCCESS);
    assert_eq!(body.disposition, disposition::AUTHORITY);
    assert_eq!(body.server_nonce, reply.detail0);
    assert_ne!(body.server_nonce, 0);
    body.server_nonce
}

fn begin(nonce: u64, slot: u64, generation: u64, path: &str) -> Vec<u8> {
    let mut request = request(operation::BEGIN);
    request.server_nonce = nonce;
    request.requester_nonce = 41;
    request.request_slot = slot;
    request.request_generation = generation;
    request.path_offset = core::mem::size_of::<CmHiveKeyOpenRequest>() as u32;
    request.path_len_bytes = (path.encode_utf16().count() * 2) as u32;
    let mut input = request.as_bytes().to_vec();
    for unit in path.encode_utf16() {
        input.extend_from_slice(&unit.to_le_bytes());
    }
    input
}

fn ack(outcome: CmHiveKeyOpenReply) -> CmHiveKeyOpenRequest {
    CmHiveKeyOpenRequest {
        server_nonce: outcome.server_nonce,
        requester_nonce: outcome.requester_nonce,
        request_slot: outcome.request_slot,
        request_generation: outcome.request_generation,
        ..request(operation::ACKNOWLEDGE)
    }
}

const DEVICE: &str = r"\Registry\Machine\System\CurrentControlSet\Services\Device";

#[test]
fn lost_open_reply_replays_the_exact_single_acquisition() {
    let mut server = server();
    let nonce = authority(&mut server);
    let input = begin(nonce, 0, 1, DEVICE);
    let (reply, body, original) = run(&mut server, &input);
    assert_eq!(reply.status, STATUS_SUCCESS);
    assert_eq!(body.outcome_status, STATUS_SUCCESS);
    assert_eq!(body.opened_generation, 1);
    assert_ne!(body.lease_token, 0);
    assert_eq!(server.system_key_leases.outstanding_count(), 1);
    for _ in 0..4 {
        assert_eq!(run(&mut server, &input).2, original);
        assert_eq!(server.system_key_leases.outstanding_count(), 1);
    }
    assert_eq!(
        server
            .system_key_leases
            .get(body.lease_token)
            .unwrap()
            .physical_path,
        r"\Registry\Machine\System\ControlSet001\Services\Device"
    );
}

#[test]
fn changed_payload_and_future_attempt_cannot_replace_a_pending_outcome() {
    let mut server = server();
    let nonce = authority(&mut server);
    let input = begin(nonce, 7, 1, DEVICE);
    let (_, body, original) = run(&mut server, &input);
    assert_eq!(
        run(
            &mut server,
            &begin(nonce, 7, 1, r"\Registry\Machine\System")
        )
        .0
        .status,
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        run(&mut server, &begin(nonce, 7, 2, DEVICE)).0.status,
        STATUS_INVALID_HANDLE
    );
    assert_eq!(run(&mut server, &input).2, original);
    assert!(server.system_key_leases.get(body.lease_token).is_some());
    assert_eq!(server.system_key_leases.outstanding_count(), 1);
}

#[test]
fn lost_ack_reply_and_slot_reuse_do_not_reopen_or_ack_another_attempt() {
    let mut server = server();
    let nonce = authority(&mut server);
    let input = begin(nonce, 0, 1, DEVICE);
    let (_, first, _) = run(&mut server, &input);
    let ack = ack(first);
    assert_eq!(
        run(&mut server, ack.as_bytes()).1.disposition,
        disposition::ACKNOWLEDGED
    );
    assert_eq!(run(&mut server, &input).0.status, STATUS_INVALID_HANDLE);
    assert_eq!(
        run(&mut server, ack.as_bytes()).1.disposition,
        disposition::ALREADY_ACKNOWLEDGED
    );
    let input = begin(nonce, 0, 2, DEVICE);
    let (_, second, original) = run(&mut server, &input);
    assert_ne!(second.lease_token, first.lease_token);
    assert_eq!(
        run(&mut server, ack.as_bytes()).1.disposition,
        disposition::ALREADY_ACKNOWLEDGED
    );
    assert_eq!(run(&mut server, &input).2, original);
    assert_eq!(server.system_key_opens.slots.len(), 1);
    assert_eq!(server.system_key_leases.outstanding_count(), 2);
}

#[test]
fn failure_outcome_is_cached_until_ack_even_if_namespace_changes() {
    let mut server = server();
    let nonce = authority(&mut server);
    let path = r"\Registry\Machine\System\CurrentControlSet\Services\Later";
    let input = begin(nonce, 1, 1, path);
    let (reply, body, original) = run(&mut server, &input);
    assert_eq!(reply.status, STATUS_SUCCESS);
    assert_eq!(body.outcome_status, STATUS_OBJECT_NAME_NOT_FOUND);
    assert_eq!(
        (
            body.lease_token,
            body.opened_generation,
            body.path_len_bytes
        ),
        (0, 0, 0)
    );
    server
        .system_hive
        .as_mut()
        .unwrap()
        .hive
        .create_key("ControlSet001\\Services\\Later");
    assert_eq!(run(&mut server, &input).2, original);
    assert_eq!(server.system_key_leases.outstanding_count(), 0);
    run(&mut server, ack(body).as_bytes());
    assert_eq!(
        run(&mut server, &begin(nonce, 1, 2, path)).1.outcome_status,
        STATUS_SUCCESS
    );
}

#[test]
fn authority_nonce_survives_move_and_rejects_replacement_server() {
    let mut first = server();
    let mut second =
        server_with_source(Rc::new(CmIdentitySource::new(NonZeroU32::new(2).unwrap())));
    let nonce = authority(&mut first);
    assert_eq!(authority(&mut first), nonce);
    assert_ne!(authority(&mut second), nonce);
    let input = begin(nonce, 0, 1, DEVICE);
    assert_eq!(run(&mut second, &input).0.status, STATUS_INVALID_HANDLE);
    assert_eq!(second.system_key_leases.outstanding_count(), 0);
    assert!(second.system_key_opens.slots.is_empty());
    let mut moved = first;
    let (_, body, _) = run(&mut moved, &input);
    assert_eq!(body.outcome_status, STATUS_SUCCESS);
    assert_eq!(
        run(&mut second, ack(body).as_bytes()).0.status,
        STATUS_INVALID_HANDLE
    );
}

#[test]
fn malformed_and_short_reply_banks_fail_before_acquisition() {
    let mut server = server();
    let nonce = authority(&mut server);
    let valid = begin(nonce, 0, 1, DEVICE);
    let mut output = [0; CM_HIVE_KEY_OPEN_REPLY_MAX_BYTES - 1];
    assert_eq!(
        server.op_system_hive_key_open(&valid, &mut output).status,
        STATUS_BUFFER_TOO_SMALL
    );
    assert!(server.system_key_opens.slots.is_empty());
    assert_eq!(server.system_key_leases.outstanding_count(), 0);
    let mut bad = valid.clone();
    bad.push(0);
    assert_eq!(run(&mut server, &bad).0.status, STATUS_INVALID_PARAMETER);
    let mut bad = valid.clone();
    bad.pop();
    assert_eq!(run(&mut server, &bad).0.status, STATUS_INVALID_PARAMETER);
    let mut bad = begin(nonce, 0, 1, "x");
    bad[48..50].copy_from_slice(&0xd800u16.to_le_bytes());
    assert_eq!(run(&mut server, &bad).0.status, STATUS_INVALID_PARAMETER);
    let bad = begin(nonce, 0, 1, "nul\0path");
    assert_eq!(run(&mut server, &bad).0.status, STATUS_INVALID_PARAMETER);
    assert!(server.system_key_opens.slots.is_empty());
    assert_eq!(server.system_key_leases.outstanding_count(), 0);
}

#[test]
fn unicode_identity_and_close_receipt_cleanup_survive_mount_retirement() {
    let mut server = server();
    let nonce = authority(&mut server);
    let leaf = "ControlSet001\\Services\\\u{4e2d}\u{1f4c4}";
    server.system_hive.as_mut().unwrap().hive.create_key(leaf);
    let path = alloc::format!("\\Registry\\Machine\\System\\{leaf}");
    let input = begin(nonce, 0, 1, &path);
    let (_, body, original) = run(&mut server, &input);
    assert_eq!(body.outcome_status, STATUS_SUCCESS);
    assert_eq!(
        &original[CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES..],
        path.as_bytes()
    );
    server.system_key_leases.invalidate();
    server.system_hive = None;
    assert!(server.system_key_leases.get(body.lease_token).is_none());
    assert_eq!(run(&mut server, &input).2, original);
    let close = server
        .system_key_leases
        .prepare_close(body.lease_token)
        .unwrap();
    assert_eq!(
        run(&mut server, ack(body).as_bytes()).1.disposition,
        disposition::ACKNOWLEDGED
    );
    server
        .system_key_leases
        .acknowledge_close(close.bank, close.slot, close.generation)
        .unwrap();
    assert_eq!(server.system_key_leases.outstanding_count(), 0);
    assert_eq!(run(&mut server, &input).0.status, STATUS_INVALID_HANDLE);
}

#[test]
fn journal_capacity_and_nonce_exhaustion_do_not_admit_an_attempt() {
    let mut journal = OpenJournal::new();
    let source = CmIdentitySource::new(NonZeroU32::MIN);
    source.next_sequence.set(0);
    assert_eq!(
        journal.authority(&source),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(journal.nonce, 0);
    source.next_sequence.set(1);
    let nonce = journal.authority(&source).unwrap();
    let bytes = begin(nonce, 0, 1, DEVICE);
    let request = CmHiveKeyOpenRequest::from_bytes(&bytes).unwrap();
    assert_eq!(
        journal.claim(&request, &[1, 2], 0),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert!(journal.slots.is_empty());
    let (index, _) = journal.claim(&request, &[1, 2], 1).unwrap();
    journal.finish(index, OpenOutcome::failed(STATUS_OBJECT_NAME_NOT_FOUND));
    journal.acknowledge(&request).unwrap();
    journal.slots[index].acknowledged = u64::MAX;
    assert_eq!(
        journal.claim(&request, &[1, 2], 1),
        Err(STATUS_INVALID_HANDLE)
    );
    assert!(journal.slots[index].pending.is_none());
}

#[test]
fn reconstructed_server_shares_source_without_reusing_any_open_or_lease_identity() {
    let source = Rc::new(CmIdentitySource::new(NonZeroU32::new(42).unwrap()));
    let mut first = server_with_source(source.clone());
    let nonce = authority(&mut first);
    let input = begin(nonce, 0, 1, DEVICE);
    let (_, old, _) = run(&mut first, &input);
    let close = first
        .system_key_leases
        .prepare_close(old.lease_token)
        .unwrap();
    let mut next = server_with_source(source);
    let next_nonce = authority(&mut next);
    assert_ne!(next_nonce, nonce);
    assert_eq!(run(&mut next, &input).0.status, STATUS_INVALID_HANDLE);
    let (_, local, _) = run(&mut next, &begin(next_nonce, 0, 1, DEVICE));
    assert_ne!(local.lease_token, old.lease_token);
    assert_eq!(
        next.system_key_leases.prepare_close(old.lease_token),
        Err(SystemKeyLeaseError::Invalid)
    );
    let local_close = next
        .system_key_leases
        .prepare_close(local.lease_token)
        .unwrap();
    assert_ne!(local_close.bank, close.bank);
    assert_eq!(
        next.system_key_leases
            .acknowledge_close(close.bank, close.slot, close.generation),
        Err(SystemKeyLeaseError::Invalid)
    );
}
