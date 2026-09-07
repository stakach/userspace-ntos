use super::*;
use nt_config_abi::{CmHiveKeyCloseReply, CmHiveKeyCloseRequest, hive_key_close_operation,
    hive_key_close_disposition};

fn response(exchange: &SystemHiveKeyOpenExchange, status: i32, token: u64, generation: u64, path: &[u8]) -> SystemHiveKeyOpenResponse {
    let request = CmHiveKeyOpenRequest::from_bytes(&exchange.bytes[..exchange.len]).unwrap();
    let body = CmHiveKeyOpenReply {
        abi_size: CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES as u16, abi_version: CM_ABI_VERSION,
        disposition: match exchange.operation {
            SystemHiveKeyOpenOperation::Query => disposition::AUTHORITY,
            SystemHiveKeyOpenOperation::Begin => disposition::OUTCOME,
            SystemHiveKeyOpenOperation::Acknowledge => disposition::ACKNOWLEDGED,
        }, reserved: 0, server_nonce: 19,
        requester_nonce: request.requester_nonce, request_slot: request.request_slot,
        request_generation: request.request_generation,
        outcome_status: status, path_len_bytes: path.len() as u32,
        lease_token: token, opened_generation: generation,
    };
    let mut bytes = [0; CM_HIVE_KEY_OPEN_REPLY_MAX_BYTES];
    bytes[..CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES].copy_from_slice(body.as_bytes());
    bytes[CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES..CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES + path.len()].copy_from_slice(path);
    SystemHiveKeyOpenResponse { reply: CmReply { status: STATUS_SUCCESS,
        information: (CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES + path.len()) as u32,
        detail0: 19, detail1: request.request_generation }, bytes }
}

fn mutate_body(response: &mut SystemHiveKeyOpenResponse, mutate: impl FnOnce(&mut CmHiveKeyOpenReply)) {
    let mut body = CmHiveKeyOpenReply::from_bytes(&response.bytes).unwrap();
    mutate(&mut body);
    response.bytes[..CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES].copy_from_slice(body.as_bytes());
}

fn query(manager: &SystemHiveKeyOpenAttempts, attempt: &mut SystemHiveKeyOpenAttempt) {
    let mut exchange = manager.begin_exchange(attempt, SystemHiveKeyOpenOperation::Query).unwrap();
    let reply = response(&exchange, 0, 0, 0, &[]);
    manager.complete_exchange(attempt, &mut exchange, reply).unwrap();
}

fn opened(manager: &SystemHiveKeyOpenAttempts, attempt: &mut SystemHiveKeyOpenAttempt) {
    query(manager, attempt);
    let mut exchange = manager.begin_exchange(attempt, SystemHiveKeyOpenOperation::Begin).unwrap();
    let reply = response(&exchange, 0, 77, 8, b"\\Registry\\Machine\\System");
    manager.complete_exchange(attempt, &mut exchange, reply).unwrap();
}

fn acknowledge(manager: &SystemHiveKeyOpenAttempts, attempt: &mut SystemHiveKeyOpenAttempt) {
    let mut exchange = manager.begin_exchange(attempt, SystemHiveKeyOpenOperation::Acknowledge).unwrap();
    let reply = response(&exchange, 0, 0, 0, &[]);
    manager.complete_exchange(attempt, &mut exchange, reply).unwrap();
}

struct CloseBackend;
impl Backend for CloseBackend {
    fn call(&mut self, _: u16, input: &[u8], output: &mut [u8]) -> CmReply {
        let request = CmHiveKeyCloseRequest::from_bytes(input).unwrap();
        let preparing = request.operation == hive_key_close_operation::PREPARE;
        let body = CmHiveKeyCloseReply {
            abi_size: core::mem::size_of::<CmHiveKeyCloseReply>() as u16, abi_version: CM_ABI_VERSION,
            disposition: if preparing { hive_key_close_disposition::RETAINED } else { hive_key_close_disposition::ACKNOWLEDGED },
            reserved: 0, lease_token: if preparing { request.lease_token } else { 0 },
            receipt_bank: 51,
            receipt_slot: if preparing { request.lease_token } else { request.receipt_slot },
            receipt_generation: 1,
        };
        output[..body.as_bytes().len()].copy_from_slice(body.as_bytes());
        CmReply { status: STATUS_SUCCESS, information: body.as_bytes().len() as u32, detail0: 51, detail1: 1 }
    }
}

#[test]
fn success_transfers_acknowledged_lease_once_without_reallocating_path() {
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut attempt = manager.reserve(r"\Registry\Machine\System").unwrap();
    let pointer = attempt.physical_path.as_ptr();
    let capacity = attempt.physical_path.capacity();
    opened(&manager, &mut attempt);
    assert_eq!(attempt.physical_path.as_ptr(), pointer);
    assert_eq!(attempt.physical_path.capacity(), capacity);
    assert!(manager.take_validated(&mut attempt, 8).is_err());
    assert!(manager.release(&mut attempt).is_err());
    acknowledge(&manager, &mut attempt);
    let result = manager.take_validated(&mut attempt, 8).unwrap();
    assert_eq!(result.lease.token, 77);
    assert_eq!(result.physical_path, r"\Registry\Machine\System");
    assert_eq!(result.physical_path.as_ptr(), pointer);
    assert!(attempt.known_lease().is_none());
    assert!(attempt.is_transferred());
    assert!(manager.take_validated(&mut attempt, 8).is_err());
    manager.release(&mut attempt).unwrap();
    assert!(attempt.is_released());
}

#[test]
fn lost_begin_reply_retries_identical_identity_and_does_not_release_ambiguity() {
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut attempt = manager.reserve("key").unwrap();
    query(&manager, &mut attempt);
    let mut first = manager.begin_exchange(&mut attempt, SystemHiveKeyOpenOperation::Begin).unwrap();
    assert_eq!(manager.complete_exchange(&mut attempt, &mut first, SystemHiveKeyOpenResponse::transport_error(STATUS_DEVICE_NOT_READY)), Err(STATUS_DEVICE_NOT_READY));
    assert!(attempt.was_submitted());
    assert!(!attempt.is_inflight());
    assert!(!attempt.has_outcome());
    assert!(manager.release(&mut attempt).is_err());
    let mut retry = manager.begin_exchange(&mut attempt, SystemHiveKeyOpenOperation::Begin).unwrap();
    assert_eq!(first.bytes[..first.len], retry.bytes[..retry.len]);
    let reply = response(&retry, 0, 77, 8, b"key");
    manager.complete_exchange(&mut attempt, &mut retry, reply).unwrap();
    assert_eq!(attempt.known_lease().unwrap().token, 77);
}

#[test]
fn lost_ack_retry_retains_lease_and_accepts_only_explicit_acknowledgment() {
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut attempt = manager.reserve("key").unwrap();
    opened(&manager, &mut attempt);
    let mut first = manager.begin_exchange(&mut attempt, SystemHiveKeyOpenOperation::Acknowledge).unwrap();
    assert!(manager.complete_exchange(&mut attempt, &mut first, SystemHiveKeyOpenResponse::transport_error(STATUS_DEVICE_NOT_READY)).is_err());
    assert!(!attempt.is_acknowledged());
    assert!(attempt.known_lease().is_some());
    let mut retry = manager.begin_exchange(&mut attempt, SystemHiveKeyOpenOperation::Acknowledge).unwrap();
    assert_eq!(first.bytes[..first.len], retry.bytes[..retry.len]);
    let mut reply = response(&retry, 0, 0, 0, &[]);
    mutate_body(&mut reply, |body| body.disposition = disposition::ALREADY_ACKNOWLEDGED);
    manager.complete_exchange(&mut attempt, &mut retry, reply).unwrap();
    assert!(attempt.is_acknowledged());
}

#[test]
fn malformed_path_or_generation_retains_lease_before_validation() {
    for (generation, path) in [(0, &b"key"[..]), (8, &b"bad\0key"[..]), (8, &b"\xff"[..]), (8, &b""[..])] {
        let mut manager = SystemHiveKeyOpenAttempts::new();
        let mut attempt = manager.reserve("key").unwrap();
        query(&manager, &mut attempt);
        let mut exchange = manager.begin_exchange(&mut attempt, SystemHiveKeyOpenOperation::Begin).unwrap();
        let reply = response(&exchange, 0, 77, generation, path);
        assert_eq!(manager.complete_exchange(&mut attempt, &mut exchange, reply), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(attempt.known_lease(), Some(SystemHiveKeyLease { token: 77, opened_generation: generation }));
        assert!(attempt.has_outcome());
        assert!(manager.begin_exchange(&mut attempt, SystemHiveKeyOpenOperation::Acknowledge).is_err());
        assert!(manager.release(&mut attempt).is_err());
    }
}

#[test]
fn malformed_outcome_is_closed_then_acknowledged_without_publishing() {
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut attempt = manager.reserve("key").unwrap();
    query(&manager, &mut attempt);
    let mut exchange = manager.begin_exchange(&mut attempt, SystemHiveKeyOpenOperation::Begin).unwrap();
    let reply = response(&exchange, 0, 77, 0, b"key");
    assert!(manager.complete_exchange(&mut attempt, &mut exchange, reply).is_err());
    let mut client = ConfigClient::new(CloseBackend);
    let receipt = client.prepare_system_hive_key_close(attempt.known_lease().unwrap()).unwrap();
    manager.record_close_receipt(&mut attempt, receipt).unwrap();
    assert_eq!(attempt.close_receipt(), Some(receipt));
    assert!(manager.begin_exchange(&mut attempt, SystemHiveKeyOpenOperation::Begin).is_err());
    let ack = client.acknowledge_system_hive_key_close(receipt).unwrap();
    manager.mark_lease_closed(&mut attempt, ack).unwrap();
    assert!(manager.release(&mut attempt).is_err());
    acknowledge(&manager, &mut attempt);
    assert!(manager.take_validated(&mut attempt, 8).is_err());
    manager.release(&mut attempt).unwrap();
}

#[test]
fn foreign_close_acknowledgment_cannot_retire_known_lease() {
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut attempt = manager.reserve("key").unwrap();
    opened(&manager, &mut attempt);
    let mut client = ConfigClient::new(CloseBackend);
    let own = client.prepare_system_hive_key_close(attempt.known_lease().unwrap()).unwrap();
    let foreign = client.prepare_system_hive_key_close(SystemHiveKeyLease { token: 99, opened_generation: 8 }).unwrap();
    assert!(manager.record_close_receipt(&mut attempt, foreign).is_err());
    manager.record_close_receipt(&mut attempt, own).unwrap();
    let foreign_ack = client.acknowledge_system_hive_key_close(foreign).unwrap();
    assert!(manager.mark_lease_closed(&mut attempt, foreign_ack).is_err());
    assert!(!attempt.is_lease_closed());
    assert_eq!(attempt.known_lease().unwrap().token, 77);
}

#[test]
fn failed_operation_outcome_requires_ack_but_never_allocates_a_lease() {
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut attempt = manager.reserve("missing").unwrap();
    query(&manager, &mut attempt);
    let mut exchange = manager.begin_exchange(&mut attempt, SystemHiveKeyOpenOperation::Begin).unwrap();
    let reply = response(&exchange, STATUS_DEVICE_NOT_READY, 0, 0, &[]);
    manager.complete_exchange(&mut attempt, &mut exchange, reply).unwrap();
    assert_eq!(attempt.outcome_status(), Some(STATUS_DEVICE_NOT_READY));
    assert_eq!(attempt.validation_status(), Some(STATUS_SUCCESS));
    assert!(attempt.known_lease().is_none());
    assert!(manager.release(&mut attempt).is_err());
    acknowledge(&manager, &mut attempt);
    assert_eq!(manager.take_validated(&mut attempt, 8), Err(STATUS_DEVICE_NOT_READY));
    manager.release(&mut attempt).unwrap();
}

#[test]
fn actual_reply_length_and_identity_must_authenticate_acquisition_evidence() {
    for variant in 0..6 {
        let mut manager = SystemHiveKeyOpenAttempts::new();
        let mut attempt = manager.reserve("key").unwrap();
        query(&manager, &mut attempt);
        let mut exchange = manager.begin_exchange(&mut attempt, SystemHiveKeyOpenOperation::Begin).unwrap();
        let mut reply = response(&exchange, 0, 77, 8, b"key");
        match variant {
            0 => reply.reply.information = 0,
            1 => mutate_body(&mut reply, |body| body.requester_nonce += 1),
            2 => mutate_body(&mut reply, |body| body.request_slot += 1),
            3 => mutate_body(&mut reply, |body| body.request_generation += 1),
            4 => mutate_body(&mut reply, |body| body.reserved = 1),
            _ => reply.reply.detail0 += 1,
        }
        assert!(manager.complete_exchange(&mut attempt, &mut exchange, reply).is_err());
        assert!(!attempt.has_outcome());
        assert!(attempt.known_lease().is_none());
        assert!(manager.release(&mut attempt).is_err());
    }
}

#[test]
fn authenticated_error_envelope_preserves_acquisition_for_cleanup() {
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut attempt = manager.reserve("key").unwrap();
    query(&manager, &mut attempt);
    let mut exchange = manager.begin_exchange(&mut attempt, SystemHiveKeyOpenOperation::Begin).unwrap();
    let mut reply = response(&exchange, STATUS_DEVICE_NOT_READY, 77, 8, b"key");
    reply.reply.status = STATUS_DEVICE_NOT_READY;
    assert_eq!(manager.complete_exchange(&mut attempt, &mut exchange, reply), Err(STATUS_DEVICE_NOT_READY));
    assert_eq!(attempt.known_lease().unwrap().token, 77);
    assert!(attempt.has_outcome());
}

#[test]
fn retries_cannot_rewrite_known_lease_generation_token_or_validated_outcome() {
    for variant in 0..4 {
        let mut manager = SystemHiveKeyOpenAttempts::new();
        let mut attempt = manager.reserve("key").unwrap();
        opened(&manager, &mut attempt);
        let mut exchange = manager.begin_exchange(&mut attempt, SystemHiveKeyOpenOperation::Begin).unwrap();
        let mut reply = response(&exchange, 0, 77, 8, b"\\Registry\\Machine\\System");
        match variant {
            0 => mutate_body(&mut reply, |body| body.opened_generation = 9),
            1 => mutate_body(&mut reply, |body| body.lease_token = 99),
            2 => mutate_body(&mut reply, |body| body.outcome_status = STATUS_DEVICE_NOT_READY),
            _ => reply.bytes[CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES] = b'X',
        }
        assert!(manager.complete_exchange(&mut attempt, &mut exchange, reply).is_err());
        assert_eq!(attempt.known_lease(), Some(SystemHiveKeyLease { token: 77, opened_generation: 8 }));
        assert_eq!(attempt.outcome_status(), Some(STATUS_SUCCESS));
        assert_eq!(attempt.validation_status(), Some(STATUS_SUCCESS));
        assert_eq!(attempt.physical_path, r"\Registry\Machine\System");
    }
}

#[test]
fn expected_generation_mismatch_keeps_acknowledged_lease_owned() {
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut attempt = manager.reserve("key").unwrap();
    opened(&manager, &mut attempt);
    acknowledge(&manager, &mut attempt);
    assert_eq!(manager.take_validated(&mut attempt, 9), Err(STATUS_DEVICE_NOT_READY));
    assert!(attempt.known_lease().is_some());
    assert!(!attempt.is_transferred());
    assert!(manager.release(&mut attempt).is_err());
}

#[test]
fn cancelled_unsubmitted_reservation_does_not_skip_server_generation() {
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut cancelled = manager.reserve("key").unwrap();
    let identity = cancelled.identity;
    query(&manager, &mut cancelled);
    manager.release(&mut cancelled).unwrap();
    let mut next = manager.reserve("key").unwrap();
    assert!(next.identity == identity);
    query(&manager, &mut next);
    let exchange = manager.begin_exchange(&mut next, SystemHiveKeyOpenOperation::Begin).unwrap();
    assert_eq!(CmHiveKeyOpenRequest::from_bytes(&exchange.bytes[..exchange.len]).unwrap().request_generation, 1);
    assert!(manager.begin_exchange(&mut cancelled, SystemHiveKeyOpenOperation::Query).is_err());
}

#[test]
fn acknowledged_slot_reuse_advances_sequence_and_rejects_old_attempt() {
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut old = manager.reserve("key").unwrap();
    opened(&manager, &mut old);
    acknowledge(&manager, &mut old);
    manager.take_validated(&mut old, 8).unwrap();
    manager.release(&mut old).unwrap();
    let next = manager.reserve("key").unwrap();
    assert_eq!(next.identity.slot, old.identity.slot);
    assert_eq!(next.identity.sequence, old.identity.sequence + 1);
    assert_eq!(manager.slots.len(), 1);
    assert!(manager.release(&mut old).is_err());
}

#[test]
fn foreign_or_stale_exchange_cannot_complete_other_owner() {
    let mut first = SystemHiveKeyOpenAttempts::new();
    let mut second = SystemHiveKeyOpenAttempts::new();
    let mut a = first.reserve("key").unwrap();
    let mut b = second.reserve("key").unwrap();
    let mut ticket = first.begin_exchange(&mut a, SystemHiveKeyOpenOperation::Query).unwrap();
    let reply = response(&ticket, 0, 0, 0, &[]);
    assert!(second.complete_exchange(&mut b, &mut ticket, reply).is_err());
    assert!(ticket.live);
    let reply = response(&ticket, 0, 0, 0, &[]);
    first.complete_exchange(&mut a, &mut ticket, reply).unwrap();
    let reply = response(&ticket, 0, 0, 0, &[]);
    assert!(first.complete_exchange(&mut a, &mut ticket, reply).is_err());
}

#[test]
fn epoch_exhaustion_and_invalid_paths_fail_before_submission() {
    let mut manager = SystemHiveKeyOpenAttempts::new();
    assert!(manager.reserve("").is_err());
    assert!(manager.reserve("bad\0key").is_err());
    assert!(manager.slots.is_empty());
    let mut attempt = manager.reserve("key").unwrap();
    query(&manager, &mut attempt);
    attempt.epoch = u64::MAX;
    assert!(manager.begin_exchange(&mut attempt, SystemHiveKeyOpenOperation::Begin).is_err());
    assert!(!attempt.was_submitted());
    assert!(!attempt.is_inflight());
    manager.release(&mut attempt).unwrap();
}
