use super::*;
use crate::active_driver_service::tests::snapshot;

const PATH: &str = r"\Registry\Machine\System\ControlSet002\Services\Stable";

fn response(exchange: &CmSnapshotExchange, status: i32, total: u32, chunk: &[u8]) -> CmSnapshotResponse {
    let query = exchange.operation == CmSnapshotOperation::Query;
    let body = CmRetainedSnapshotReply {
        abi_size: CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES as u16, abi_version: CM_ABI_VERSION,
        disposition: match exchange.operation { CmSnapshotOperation::Query => disposition::AUTHORITY,
            CmSnapshotOperation::Begin => disposition::OUTCOME, CmSnapshotOperation::Pull => disposition::CHUNK,
            CmSnapshotOperation::Acknowledge => disposition::ACKNOWLEDGED },
        query_kind: if query { 0 } else { kind::ACTIVE_DRIVER_SERVICE },
        server_nonce: 19, requester_nonce: exchange.identity.requester,
        request_slot: if query { 0 } else { exchange.identity.slot },
        request_generation: if query { 0 } else { exchange.identity.sequence },
        outcome_status: status, total_bytes: if query { exchange.capacity } else { total },
        value_offset: exchange.offset, chunk_bytes: chunk.len() as u32, _reserved: 0,
    };
    let mut bytes = [0; REPLY_MAX];
    bytes[..CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES].copy_from_slice(body.as_bytes());
    bytes[CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES..CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES + chunk.len()].copy_from_slice(chunk);
    CmSnapshotResponse { reply: CmReply { status: STATUS_SUCCESS,
        information: (CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES + chunk.len()) as u32,
        detail0: body.server_nonce, detail1: body.request_generation }, bytes }
}

fn mutate(reply: &mut CmSnapshotResponse, change: impl FnOnce(&mut CmRetainedSnapshotReply)) {
    let mut body = CmRetainedSnapshotReply::from_bytes(&reply.bytes).unwrap();
    change(&mut body);
    reply.bytes[..CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES].copy_from_slice(body.as_bytes());
}

fn bind(manager: &mut CmSnapshotAttempts, attempt: &mut CmSnapshotAttempt) {
    if attempt.server_nonce().is_some() { return; }
    let mut exchange = manager.begin_exchange(attempt, CmSnapshotOperation::Query).unwrap();
    let reply = response(&exchange, 0, 0, &[]);
    manager.complete_exchange(attempt, &mut exchange, reply).unwrap();
}

fn manifest(manager: &mut CmSnapshotAttempts, attempt: &mut CmSnapshotAttempt, total: u32) {
    bind(manager, attempt);
    let mut exchange = manager.begin_exchange(attempt, CmSnapshotOperation::Begin).unwrap();
    let reply = response(&exchange, 0, total, &[]);
    manager.complete_exchange(attempt, &mut exchange, reply).unwrap();
}

fn ack(manager: &mut CmSnapshotAttempts, attempt: &mut CmSnapshotAttempt) {
    let mut exchange = manager.begin_exchange(attempt, CmSnapshotOperation::Acknowledge).unwrap();
    let reply = response(&exchange, 0, 0, &[]);
    manager.complete_exchange(attempt, &mut exchange, reply).unwrap();
}

#[test]
fn complete_result_requires_ack_and_transfers_once_across_many_banks() {
    let mut manager = CmSnapshotAttempts::new();
    let mut attempt = manager.reserve_active_driver_service(PATH).unwrap();
    let bytes = snapshot(PATH, 73);
    manifest(&mut manager, &mut attempt, bytes.len() as u32);
    let address = attempt.bytes.as_ptr();
    let capacity = attempt.bytes.capacity();
    while !attempt.is_complete() {
        let mut exchange = manager.begin_exchange(&mut attempt, CmSnapshotOperation::Pull).unwrap();
        let offset = exchange.offset as usize;
        let end = core::cmp::min(offset + 97, bytes.len());
        let reply = response(&exchange, 0, bytes.len() as u32, &bytes[offset..end]);
        manager.complete_exchange(&mut attempt, &mut exchange, reply).unwrap();
    }
    assert_eq!(attempt.bytes.as_ptr(), address);
    assert_eq!(attempt.bytes.capacity(), capacity);
    assert!(manager.take_active_driver_service(&mut attempt, 7).is_err());
    assert!(manager.release(&mut attempt).is_err());
    ack(&mut manager, &mut attempt);
    let result = manager.take_active_driver_service(&mut attempt, 7).unwrap();
    assert_eq!(result.binding.devnodes.len(), 73);
    assert_eq!(result.physical_path, PATH);
    assert!(manager.take_active_driver_service(&mut attempt, 7).is_err());
    manager.release(&mut attempt).unwrap();
}

#[test]
fn unknown_begin_can_be_abandoned_and_acknowledged_without_recovering_outcome() {
    let mut manager = CmSnapshotAttempts::new();
    let mut attempt = manager.reserve_active_driver_service(PATH).unwrap();
    bind(&mut manager, &mut attempt);
    let mut begin = manager.begin_exchange(&mut attempt, CmSnapshotOperation::Begin).unwrap();
    assert_eq!(manager.complete_exchange(&mut attempt, &mut begin, CmSnapshotResponse::transport_error(STATUS_DEVICE_NOT_READY)), Err(STATUS_DEVICE_NOT_READY));
    assert!(attempt.outcome_status().is_none());
    assert!(manager.release(&mut attempt).is_err());
    manager.abandon(&mut attempt).unwrap();
    assert!(manager.begin_exchange(&mut attempt, CmSnapshotOperation::Begin).is_err());
    ack(&mut manager, &mut attempt);
    assert!(manager.take_active_driver_service(&mut attempt, 7).is_err());
    manager.release(&mut attempt).unwrap();
}

#[test]
fn abandoned_inflight_begin_does_not_allocate_or_publish_late_result() {
    let mut manager = CmSnapshotAttempts::new();
    let mut attempt = manager.reserve_active_driver_service(PATH).unwrap();
    bind(&mut manager, &mut attempt);
    let mut begin = manager.begin_exchange(&mut attempt, CmSnapshotOperation::Begin).unwrap();
    manager.abandon(&mut attempt).unwrap();
    let reply = response(&begin, 0, 100, &[]);
    manager.complete_exchange_with_reserve(&mut attempt, &mut begin, reply, |_, _| panic!("late result allocated")).unwrap();
    assert_eq!(attempt.bytes.capacity(), 0);
    assert!(manager.begin_exchange(&mut attempt, CmSnapshotOperation::Pull).is_err());
    ack(&mut manager, &mut attempt);
    assert!(manager.take_active_driver_service(&mut attempt, 7).is_err());
    manager.release(&mut attempt).unwrap();
}

#[test]
fn allocation_failure_keeps_manifest_and_exact_ack_cleanup_available() {
    let mut manager = CmSnapshotAttempts::new();
    let mut attempt = manager.reserve_active_driver_service(PATH).unwrap();
    bind(&mut manager, &mut attempt);
    let mut begin = manager.begin_exchange(&mut attempt, CmSnapshotOperation::Begin).unwrap();
    let reply = response(&begin, 0, 100, &[]);
    assert_eq!(manager.complete_exchange_with_reserve(&mut attempt, &mut begin, reply, |_, _| Err(STATUS_INSUFFICIENT_RESOURCES)), Err(STATUS_INSUFFICIENT_RESOURCES));
    assert_eq!(attempt.total_len(), Some(100));
    assert_eq!(attempt.outcome_status(), Some(STATUS_SUCCESS));
    assert!(manager.begin_exchange(&mut attempt, CmSnapshotOperation::Pull).is_err());
    manager.abandon(&mut attempt).unwrap();
    ack(&mut manager, &mut attempt);
    manager.release(&mut attempt).unwrap();
}

#[test]
fn lost_final_pull_and_ack_retry_use_exact_request_bytes() {
    let mut manager = CmSnapshotAttempts::new();
    let mut attempt = manager.reserve_active_driver_service(PATH).unwrap();
    manifest(&mut manager, &mut attempt, 3);
    let mut first = manager.begin_exchange(&mut attempt, CmSnapshotOperation::Pull).unwrap();
    assert!(manager.complete_exchange(&mut attempt, &mut first, CmSnapshotResponse::transport_error(STATUS_DEVICE_NOT_READY)).is_err());
    assert_eq!(attempt.collected_len(), 0);
    let mut retry = manager.begin_exchange(&mut attempt, CmSnapshotOperation::Pull).unwrap();
    assert_eq!(first.bytes[..first.len], retry.bytes[..retry.len]);
    let reply = response(&retry, 0, 3, &[1, 2, 3]);
    manager.complete_exchange(&mut attempt, &mut retry, reply).unwrap();
    assert!(attempt.is_complete());
    let mut first = manager.begin_exchange(&mut attempt, CmSnapshotOperation::Acknowledge).unwrap();
    assert!(manager.complete_exchange(&mut attempt, &mut first, CmSnapshotResponse::transport_error(STATUS_DEVICE_NOT_READY)).is_err());
    let mut retry = manager.begin_exchange(&mut attempt, CmSnapshotOperation::Acknowledge).unwrap();
    assert_eq!(first.bytes[..first.len], retry.bytes[..retry.len]);
    let mut reply = response(&retry, 0, 0, &[]);
    mutate(&mut reply, |body| body.disposition = disposition::ALREADY_ACKNOWLEDGED);
    manager.complete_exchange(&mut attempt, &mut retry, reply).unwrap();
    manager.release(&mut attempt).unwrap();
}

#[test]
fn malformed_pull_never_appends_any_bytes_and_remains_abandonable() {
    for variant in 0..9 {
        let mut manager = CmSnapshotAttempts::new();
        let mut attempt = manager.reserve_active_driver_service(PATH).unwrap();
        manifest(&mut manager, &mut attempt, 3);
        let mut pull = manager.begin_exchange(&mut attempt, CmSnapshotOperation::Pull).unwrap();
        let mut reply = response(&pull, 0, 3, &[1, 2, 3]);
        match variant {
            0 => mutate(&mut reply, |body| body.total_bytes = 4),
            1 => mutate(&mut reply, |body| body.value_offset = 1),
            2 => mutate(&mut reply, |body| body.chunk_bytes = 0),
            3 => mutate(&mut reply, |body| body.chunk_bytes = 4),
            4 => mutate(&mut reply, |body| body.request_generation += 1),
            5 => mutate(&mut reply, |body| body._reserved = 1),
            6 => reply.reply.information -= 1,
            7 => reply.reply.information = 0,
            _ => reply.reply.detail0 += 1,
        }
        assert!(manager.complete_exchange(&mut attempt, &mut pull, reply).is_err());
        assert_eq!(attempt.collected_len(), 0);
        manager.abandon(&mut attempt).unwrap();
        ack(&mut manager, &mut attempt);
        manager.release(&mut attempt).unwrap();
    }
}

#[test]
fn malformed_or_excessive_manifest_never_allocates_and_can_be_cancelled() {
    for variant in 0..5 {
        let mut manager = CmSnapshotAttempts::new();
        let mut attempt = manager.reserve_active_driver_service(PATH).unwrap();
        bind(&mut manager, &mut attempt);
        let mut begin = manager.begin_exchange(&mut attempt, CmSnapshotOperation::Begin).unwrap();
        let mut reply = response(&begin, 0, 3, &[]);
        match variant {
            0 => mutate(&mut reply, |body| body.total_bytes = CM_RETAINED_SNAPSHOT_MAX_BYTES as u32 + 1),
            1 => mutate(&mut reply, |body| body.value_offset = 1),
            2 => mutate(&mut reply, |body| body.chunk_bytes = 1),
            3 => mutate(&mut reply, |body| body.outcome_status = STATUS_DEVICE_NOT_READY),
            _ => mutate(&mut reply, |body| body.query_kind = 99),
        }
        assert!(manager.complete_exchange_with_reserve(&mut attempt, &mut begin, reply, |_, _| panic!("malformed manifest allocated")).is_err());
        assert_eq!(attempt.bytes.capacity(), 0);
        manager.abandon(&mut attempt).unwrap();
        ack(&mut manager, &mut attempt);
        manager.release(&mut attempt).unwrap();
    }
}

#[test]
fn failed_outcome_still_requires_ack_and_returns_genuine_status() {
    let mut manager = CmSnapshotAttempts::new();
    let mut attempt = manager.reserve_active_driver_service(PATH).unwrap();
    bind(&mut manager, &mut attempt);
    let mut begin = manager.begin_exchange(&mut attempt, CmSnapshotOperation::Begin).unwrap();
    let reply = response(&begin, STATUS_DEVICE_NOT_READY, 0, &[]);
    manager.complete_exchange(&mut attempt, &mut begin, reply).unwrap();
    assert!(attempt.is_complete());
    assert!(manager.release(&mut attempt).is_err());
    ack(&mut manager, &mut attempt);
    assert_eq!(manager.take_active_driver_service(&mut attempt, 7), Err(STATUS_DEVICE_NOT_READY));
    manager.release(&mut attempt).unwrap();
}

#[test]
fn registration_grant_and_cached_incarnation_are_strict() {
    let mut manager = CmSnapshotAttempts::new();
    let mut a = manager.reserve_active_driver_service(PATH).unwrap();
    let mut b = manager.reserve_active_driver_service(PATH).unwrap();
    let mut first = manager.begin_exchange(&mut a, CmSnapshotOperation::Query).unwrap();
    let mut second = manager.begin_exchange(&mut b, CmSnapshotOperation::Query).unwrap();
    let reply = response(&first, 0, 0, &[]);
    manager.complete_exchange(&mut a, &mut first, reply).unwrap();
    let mut reply = response(&second, 0, 0, &[]);
    mutate(&mut reply, |body| body.server_nonce = 20);
    reply.reply.detail0 = 20;
    assert!(manager.complete_exchange(&mut b, &mut second, reply).is_err());
    assert_eq!(manager.server, Some(19));
    assert!(b.server_nonce().is_none());
    let mut retry = manager.begin_exchange(&mut b, CmSnapshotOperation::Query).unwrap();
    let mut reply = response(&retry, 0, 0, &[]);
    mutate(&mut reply, |body| body.total_bytes -= 1);
    assert!(manager.complete_exchange(&mut b, &mut retry, reply).is_err());
    bind(&mut manager, &mut b);
    assert_eq!(b.server_nonce(), Some(19));
    manager.release(&mut a).unwrap();
    manager.release(&mut b).unwrap();
}

#[test]
fn query_loss_cancellation_reuses_same_bank_and_unsubmitted_sequence() {
    let mut manager = CmSnapshotAttempts::new();
    let mut old = manager.reserve_active_driver_service(PATH).unwrap();
    let identity = old.identity;
    let mut query = manager.begin_exchange(&mut old, CmSnapshotOperation::Query).unwrap();
    assert!(manager.complete_exchange(&mut old, &mut query, CmSnapshotResponse::transport_error(STATUS_DEVICE_NOT_READY)).is_err());
    manager.abandon(&mut old).unwrap();
    manager.release(&mut old).unwrap();
    let mut next = manager.reserve_active_driver_service(PATH).unwrap();
    assert_eq!(identity, next.identity);
    let retry = manager.begin_exchange(&mut next, CmSnapshotOperation::Query).unwrap();
    assert_eq!(query.bytes[..query.len], retry.bytes[..retry.len]);
    assert!(manager.begin_exchange(&mut old, CmSnapshotOperation::Query).is_err());
}

#[test]
fn foreign_tickets_and_ack_fields_cannot_release_another_attempt() {
    let mut manager = CmSnapshotAttempts::new();
    let mut a = manager.reserve_active_driver_service(PATH).unwrap();
    let mut b = manager.reserve_active_driver_service(PATH).unwrap();
    bind(&mut manager, &mut a);
    bind(&mut manager, &mut b);
    let mut begin = manager.begin_exchange(&mut a, CmSnapshotOperation::Begin).unwrap();
    let reply = response(&begin, 0, 0, &[]);
    assert!(manager.complete_exchange(&mut b, &mut begin, reply).is_err());
    assert!(begin.live);
    let reply = response(&begin, 0, 0, &[]);
    manager.complete_exchange(&mut a, &mut begin, reply).unwrap();
    let mut exchange = manager.begin_exchange(&mut a, CmSnapshotOperation::Acknowledge).unwrap();
    let mut reply = response(&exchange, 0, 0, &[]);
    mutate(&mut reply, |body| body.request_slot += 1);
    assert!(manager.complete_exchange(&mut a, &mut exchange, reply).is_err());
    assert!(!a.is_acknowledged());
    assert!(manager.release(&mut a).is_err());
    ack(&mut manager, &mut a);
    manager.release(&mut a).unwrap();
}

#[test]
fn slot_budget_and_epoch_exhaustion_precede_submission() {
    assert!(CmSnapshotAttempts::with_slot_limit(0).is_err());
    assert!(CmSnapshotAttempts::with_slot_limit(CM_RETAINED_SNAPSHOT_MAX_SLOTS + 1).is_err());
    let mut manager = CmSnapshotAttempts::with_slot_limit(1).unwrap();
    assert!(manager.reserve_active_driver_service("").is_err());
    assert!(manager.reserve_active_driver_service("bad\0key").is_err());
    let mut attempt = manager.reserve_active_driver_service(PATH).unwrap();
    assert!(manager.reserve_active_driver_service(PATH).is_err());
    bind(&mut manager, &mut attempt);
    attempt.epoch = u64::MAX;
    assert!(manager.begin_exchange(&mut attempt, CmSnapshotOperation::Begin).is_err());
    assert!(!attempt.was_submitted());
    assert!(!attempt.is_inflight());
    manager.release(&mut attempt).unwrap();
    assert!(manager.reserve_active_driver_service(PATH).is_ok());
}

#[test]
fn dropped_exchange_never_makes_an_inflight_slot_reusable() {
    let mut manager = CmSnapshotAttempts::with_slot_limit(1).unwrap();
    let mut attempt = manager.reserve_active_driver_service(PATH).unwrap();
    drop(manager.begin_exchange(&mut attempt, CmSnapshotOperation::Query).unwrap());
    manager.abandon(&mut attempt).unwrap();
    assert!(manager.release(&mut attempt).is_err());
    assert!(manager.reserve_active_driver_service(PATH).is_err());
}
