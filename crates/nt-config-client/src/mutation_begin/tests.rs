extern crate std;

use super::*;
use crate::STATUS_DEVICE_NOT_READY;
use core::num::NonZeroU32;
use nt_config_abi::hive_mutation_transfer;
use nt_config_server::CmServer;
use nt_hive_core::{encode_image, Hive, HiveKind};

const PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Services\Device";
const BUSY: i32 = 0x8000_0011u32 as i32;

fn reserve<C>(manager: &mut CmMutationBeginAttempts, caller: C) -> CmMutationBeginAttempt<C> {
    reserve_on(manager, &mut client(), caller)
}

fn mount() -> SystemHiveMount {
    client().query_system_hive_mount(1).unwrap().mount()
}

fn reserve_on<C>(
    manager: &mut CmMutationBeginAttempts,
    client: &mut ConfigClient<Direct>,
    caller: C,
) -> CmMutationBeginAttempt<C> {
    let mount = client.query_system_hive_mount(1).unwrap().mount();
    match manager.reserve(
        mount,
        1,
        &[SystemHiveMutation::CreateKey { path: PATH }],
        caller,
    ) {
        Ok(attempt) => attempt,
        Err((status, _)) => panic!("reserve failed: {status:x}"),
    }
}

fn response(
    exchange: &CmMutationBeginExchange,
    status: i32,
    token: u64,
) -> CmMutationBeginResponse {
    let request = Request::from_bytes(&exchange.bytes).unwrap();
    let query = exchange.operation == CmMutationBeginOperation::Query;
    let begin = exchange.operation == CmMutationBeginOperation::Begin;
    let body = Reply {
        abi_size: REPLY_BYTES as u16,
        abi_version: CM_ABI_VERSION,
        mount: hive_mount::SYSTEM,
        disposition: match exchange.operation {
            CmMutationBeginOperation::Query => disposition::AUTHORITY,
            CmMutationBeginOperation::Begin => disposition::OUTCOME,
            CmMutationBeginOperation::Acknowledge => disposition::ACKNOWLEDGED,
        },
        server_nonce: 19,
        requester_nonce: request.requester_nonce,
        slot_count: if query { request.slot_count } else { 0 },
        request_slot: request.request_slot,
        request_generation: request.request_generation,
        outcome_status: if begin { status } else { 0 },
        expected_generation: if begin {
            request.expected_generation
        } else {
            0
        },
        semantic_journal_len: if begin {
            request.semantic_journal_len
        } else {
            0
        },
        mutation_token: if begin { token } else { 0 },
        expected_mount: if begin { request.expected_mount } else { 0 },
        reserved: 0,
    };
    let mut bytes = [0; REPLY_BYTES];
    bytes.copy_from_slice(body.as_bytes());
    CmMutationBeginResponse {
        reply: CmReply {
            status: STATUS_SUCCESS,
            information: REPLY_BYTES as u32,
            detail0: body.server_nonce,
            detail1: body.request_generation,
        },
        bytes,
    }
}

fn mutate(response: &mut CmMutationBeginResponse, change: impl FnOnce(&mut Reply)) {
    let mut body = Reply::from_bytes(&response.bytes).unwrap();
    change(&mut body);
    response.bytes.copy_from_slice(body.as_bytes());
}

fn complete<C>(
    manager: &mut CmMutationBeginAttempts,
    attempt: &mut CmMutationBeginAttempt<C>,
    operation: CmMutationBeginOperation,
    status: i32,
    token: u64,
) {
    let mut ticket = manager.begin_exchange(attempt, operation).unwrap();
    let response = response(&ticket, status, token);
    manager
        .complete_exchange(attempt, &mut ticket, response)
        .unwrap();
}

#[test]
fn successful_ack_moves_original_bytes_and_caller_once_without_exposing_writer() {
    let mut manager = CmMutationBeginAttempts::with_slot_limit(1).unwrap();
    let mut attempt = reserve(&mut manager, alloc::string::String::from("whole caller"));
    let pointer = attempt.journal().as_ptr();
    let identity = attempt.identity;
    assert!(manager.take_upload(&mut attempt).is_err());
    complete(
        &mut manager,
        &mut attempt,
        CmMutationBeginOperation::Query,
        0,
        0,
    );
    complete(
        &mut manager,
        &mut attempt,
        CmMutationBeginOperation::Begin,
        0,
        31,
    );
    assert!(manager.take_upload(&mut attempt).is_err());
    assert!(manager.take_failure(&mut attempt).is_err());
    assert!(manager
        .reserve(
            mount(),
            1,
            &[SystemHiveMutation::CreateKey { path: PATH }],
            ()
        )
        .is_err());
    complete(
        &mut manager,
        &mut attempt,
        CmMutationBeginOperation::Acknowledge,
        0,
        0,
    );
    assert!(manager.take_failure(&mut attempt).is_err());
    let upload = manager.take_upload(&mut attempt).unwrap();
    assert_eq!(upload.journal().as_ptr(), pointer);
    assert_eq!(upload.continuation(), "whole caller");
    assert_eq!(upload.expected_generation(), 1);
    assert_eq!(upload.mount(), attempt.mount());
    assert_eq!(upload.mutation_token, 31);
    assert_eq!(upload.server, 19);
    assert_eq!(upload.identity, identity);
    assert!(attempt.continuation().is_none());
    assert!(attempt.journal().is_empty());
    assert!(attempt.is_released());
    assert!(manager.take_upload(&mut attempt).is_err());
    assert!(manager.take_failure(&mut attempt).is_err());
    let next = reserve(&mut manager, ());
    assert_eq!(next.identity.slot, identity.slot);
    assert_eq!(next.identity.sequence, identity.sequence + 1);
    assert_eq!(next.server_nonce(), Some(19));
}

#[test]
fn failure_requires_exact_ack_and_returns_caller_once() {
    let mut manager = CmMutationBeginAttempts::with_slot_limit(1).unwrap();
    let mut attempt = reserve(&mut manager, 42);
    complete(
        &mut manager,
        &mut attempt,
        CmMutationBeginOperation::Query,
        0,
        0,
    );
    complete(
        &mut manager,
        &mut attempt,
        CmMutationBeginOperation::Begin,
        BUSY,
        0,
    );
    assert!(manager.take_failure(&mut attempt).is_err());
    assert!(manager
        .begin_exchange(&mut attempt, CmMutationBeginOperation::Begin)
        .is_err());
    let mut ack = manager
        .begin_exchange(&mut attempt, CmMutationBeginOperation::Acknowledge)
        .unwrap();
    let request = Request::from_bytes(&ack.bytes).unwrap();
    assert_eq!(request.mutation_token, 0);
    assert_eq!(request.expected_generation, 0);
    assert_eq!(request.semantic_journal_len, 0);
    assert_eq!(request.slot_count, 0);
    let response = response(&ack, 0, 0);
    manager
        .complete_exchange(&mut attempt, &mut ack, response)
        .unwrap();
    assert!(manager.take_upload(&mut attempt).is_err());
    assert_eq!(manager.take_failure(&mut attempt), Ok((BUSY, 42)));
    assert!(manager.take_failure(&mut attempt).is_err());
    assert_eq!(reserve(&mut manager, ()).identity.sequence, 2);
}

#[test]
fn transport_errors_retain_exact_input_and_ack_retries() {
    let mut manager = CmMutationBeginAttempts::new();
    let mut attempt = reserve(&mut manager, 73);
    for operation in [
        CmMutationBeginOperation::Query,
        CmMutationBeginOperation::Begin,
        CmMutationBeginOperation::Acknowledge,
    ] {
        let mut first = manager.begin_exchange(&mut attempt, operation).unwrap();
        assert_eq!(
            manager.complete_exchange(
                &mut attempt,
                &mut first,
                CmMutationBeginResponse::transport_error(STATUS_DEVICE_NOT_READY)
            ),
            Err(STATUS_DEVICE_NOT_READY)
        );
        assert_eq!(attempt.continuation(), Some(&73));
        assert!(manager.take_upload(&mut attempt).is_err());
        let mut retry = manager.begin_exchange(&mut attempt, operation).unwrap();
        assert_eq!(first.bytes, retry.bytes);
        assert_ne!(first.epoch, retry.epoch);
        let mut reply = response(&retry, 0, 31);
        if operation == CmMutationBeginOperation::Acknowledge {
            mutate(&mut reply, |body| {
                body.disposition = disposition::ALREADY_ACKNOWLEDGED
            });
        }
        manager
            .complete_exchange(&mut attempt, &mut retry, reply)
            .unwrap();
    }
    assert_eq!(
        manager.take_upload(&mut attempt).unwrap().continuation(),
        &73
    );
}

#[test]
fn malformed_begin_never_adopts_an_outcome_or_authorizes_ack() {
    for variant in 0..22 {
        let mut manager = CmMutationBeginAttempts::new();
        let mut attempt = reserve(&mut manager, 42);
        complete(
            &mut manager,
            &mut attempt,
            CmMutationBeginOperation::Query,
            0,
            0,
        );
        let mut ticket = manager
            .begin_exchange(&mut attempt, CmMutationBeginOperation::Begin)
            .unwrap();
        let mut reply = response(&ticket, 0, 31);
        match variant {
            0 => reply.reply.information -= 1,
            1 => reply.reply.information += 1,
            2 => reply.reply.detail0 += 1,
            3 => reply.reply.detail1 += 1,
            4 => mutate(&mut reply, |body| body.abi_size -= 1),
            5 => mutate(&mut reply, |body| body.abi_version += 1),
            6 => mutate(&mut reply, |body| body.reserved = 1),
            7 => mutate(&mut reply, |body| body.mount = 0),
            8 => mutate(&mut reply, |body| body.server_nonce = 0),
            9 => mutate(&mut reply, |body| body.requester_nonce += 1),
            10 => mutate(&mut reply, |body| body.request_slot += 1),
            11 => mutate(&mut reply, |body| body.request_generation += 1),
            12 => mutate(&mut reply, |body| body.slot_count = 1),
            13 => mutate(&mut reply, |body| {
                body.disposition = disposition::ACKNOWLEDGED
            }),
            14 => mutate(&mut reply, |body| body.expected_generation += 1),
            15 => mutate(&mut reply, |body| body.semantic_journal_len += 1),
            16 => mutate(&mut reply, |body| body.mutation_token = 0),
            17 => mutate(&mut reply, |body| body.outcome_status = BUSY),
            18 => {
                mutate(&mut reply, |body| body.server_nonce = 20);
                reply.reply.detail0 = 20;
            }
            19 => mutate(&mut reply, |body| {
                body.outcome_status = 0x103;
                body.mutation_token = 0;
            }),
            20 => mutate(&mut reply, |body| body.expected_mount = 0),
            21 => mutate(&mut reply, |body| body.expected_mount += 1),
            _ => unreachable!(),
        }
        assert_eq!(
            manager.complete_exchange(&mut attempt, &mut ticket, reply),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(attempt.outcome_status(), None);
        assert_eq!(attempt.mutation_token, None);
        assert_eq!(attempt.continuation(), Some(&42));
        assert!(manager
            .begin_exchange(&mut attempt, CmMutationBeginOperation::Acknowledge)
            .is_err());
        complete(
            &mut manager,
            &mut attempt,
            CmMutationBeginOperation::Begin,
            0,
            31,
        );
    }
}

#[test]
fn malformed_query_and_ack_preserve_the_owned_phase() {
    for op in [
        CmMutationBeginOperation::Query,
        CmMutationBeginOperation::Acknowledge,
    ] {
        for variant in 0..8 {
            let mut manager = CmMutationBeginAttempts::new();
            let mut attempt = reserve(&mut manager, 7);
            if op == CmMutationBeginOperation::Acknowledge {
                complete(
                    &mut manager,
                    &mut attempt,
                    CmMutationBeginOperation::Query,
                    0,
                    0,
                );
                complete(
                    &mut manager,
                    &mut attempt,
                    CmMutationBeginOperation::Begin,
                    0,
                    31,
                );
            }
            let mut ticket = manager.begin_exchange(&mut attempt, op).unwrap();
            let mut reply = response(&ticket, 0, 0);
            match variant {
                0 => mutate(&mut reply, |body| body.slot_count ^= 1),
                1 => mutate(&mut reply, |body| body.expected_generation = 1),
                2 => mutate(&mut reply, |body| body.semantic_journal_len = 1),
                3 => mutate(&mut reply, |body| body.mutation_token = 31),
                4 => mutate(&mut reply, |body| body.outcome_status = BUSY),
                5 => mutate(&mut reply, |body| body.disposition = disposition::OUTCOME),
                6 => mutate(&mut reply, |body| body.request_slot += 1),
                7 => mutate(&mut reply, |body| body.expected_mount = 1),
                _ => unreachable!(),
            }
            assert_eq!(
                manager.complete_exchange(&mut attempt, &mut ticket, reply),
                Err(STATUS_INVALID_PARAMETER)
            );
            assert!(!attempt.is_acknowledged());
            assert!(manager.take_upload(&mut attempt).is_err());
            if op == CmMutationBeginOperation::Query {
                assert_eq!(attempt.server_nonce(), None);
            }
            complete(&mut manager, &mut attempt, op, 0, 0);
        }
    }
}

#[test]
fn dropped_wrong_manager_and_stale_tickets_never_release_an_inflight_attempt() {
    let mut manager = CmMutationBeginAttempts::new();
    let mut other = CmMutationBeginAttempts::new();
    let mut attempt = reserve(&mut manager, 7);
    let _other_attempt = reserve(&mut other, 8);
    let mut first = manager
        .begin_exchange(&mut attempt, CmMutationBeginOperation::Query)
        .unwrap();
    let reply = response(&first, 0, 0);
    assert_eq!(
        other.complete_exchange(&mut attempt, &mut first, reply),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert!(first.live);
    assert!(attempt.is_inflight());
    assert!(manager
        .complete_exchange(
            &mut attempt,
            &mut first,
            CmMutationBeginResponse::transport_error(STATUS_DEVICE_NOT_READY)
        )
        .is_err());
    let second = manager
        .begin_exchange(&mut attempt, CmMutationBeginOperation::Query)
        .unwrap();
    let reply = response(&first, 0, 0);
    assert_eq!(
        manager.complete_exchange(&mut attempt, &mut first, reply),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert!(attempt.is_inflight());
    drop(second);
    assert!(manager
        .begin_exchange(&mut attempt, CmMutationBeginOperation::Query)
        .is_err());
    assert!(manager.take_upload(&mut attempt).is_err());
    assert!(manager.take_failure(&mut attempt).is_err());
}

#[test]
fn admission_errors_return_caller_without_allocating_a_request_identity() {
    let mut manager = CmMutationBeginAttempts::with_slot_limit(1).unwrap();
    assert!(matches!(
        manager.reserve(mount(), 0, &[], 7),
        Err((STATUS_INVALID_PARAMETER, 7))
    ));
    assert_eq!(manager.requester, 0);
    assert!(manager.slots.is_empty());
    assert!(matches!(
        manager.reserve(mount(), 1, &[], 8),
        Err((STATUS_INVALID_PARAMETER, 8))
    ));
    let _attempt = reserve(&mut manager, 9);
    assert!(matches!(
        manager.reserve(
            mount(),
            1,
            &[SystemHiveMutation::CreateKey { path: PATH }],
            10
        ),
        Err((STATUS_INSUFFICIENT_RESOURCES, 10))
    ));
    assert!(CmMutationBeginAttempts::with_slot_limit(0).is_err());
    assert!(CmMutationBeginAttempts::with_slot_limit(MAX_SLOTS + 1).is_err());
}

#[test]
fn caller_drops_only_with_its_current_owner_and_dropped_attempt_does_not_reuse_slot() {
    use alloc::rc::Rc;
    use core::cell::Cell;
    struct Caller(Rc<Cell<usize>>);
    impl Drop for Caller {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Rc::new(Cell::new(0));
    let mut manager = CmMutationBeginAttempts::with_slot_limit(1).unwrap();
    let failed = manager.reserve(mount(), 0, &[], Caller(drops.clone()));
    assert_eq!(drops.get(), 0);
    drop(failed);
    assert_eq!(drops.get(), 1);
    let mut attempt = reserve(&mut manager, Caller(drops.clone()));
    complete(
        &mut manager,
        &mut attempt,
        CmMutationBeginOperation::Query,
        0,
        0,
    );
    complete(
        &mut manager,
        &mut attempt,
        CmMutationBeginOperation::Begin,
        0,
        31,
    );
    complete(
        &mut manager,
        &mut attempt,
        CmMutationBeginOperation::Acknowledge,
        0,
        0,
    );
    let upload = manager.take_upload(&mut attempt).unwrap();
    drop(attempt);
    assert_eq!(drops.get(), 1);
    drop(upload);
    assert_eq!(drops.get(), 2);
    let attempt = reserve(&mut manager, Caller(drops.clone()));
    drop(attempt);
    assert_eq!(drops.get(), 3);
    assert!(manager
        .reserve(
            mount(),
            1,
            &[SystemHiveMutation::CreateKey { path: PATH }],
            ()
        )
        .is_err());
}

#[test]
fn manager_rejects_replacement_authority_on_another_unsubmitted_attempt() {
    let mut manager = CmMutationBeginAttempts::new();
    let mut first = reserve(&mut manager, 1);
    let mut second = reserve(&mut manager, 2);
    complete(
        &mut manager,
        &mut first,
        CmMutationBeginOperation::Query,
        0,
        0,
    );
    let mut query = manager
        .begin_exchange(&mut second, CmMutationBeginOperation::Query)
        .unwrap();
    let mut reply = response(&query, 0, 0);
    mutate(&mut reply, |body| body.server_nonce = 20);
    reply.reply.detail0 = 20;
    assert_eq!(
        manager.complete_exchange(&mut second, &mut query, reply),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(manager.server, Some(19));
    assert_eq!(second.server_nonce(), None);
    complete(
        &mut manager,
        &mut second,
        CmMutationBeginOperation::Query,
        0,
        0,
    );
    assert_eq!(second.server_nonce(), Some(19));
}

struct Direct {
    server: CmServer,
    lose: Option<u16>,
    panic_after: Option<u16>,
    requests: Vec<Request>,
    tokens: Vec<u64>,
}

impl Backend for Direct {
    fn call(&mut self, op: u16, input: &[u8], output: &mut [u8]) -> CmReply {
        let reply = self.server.dispatch(op, input, output);
        if op != opcode::CM_OP_SYSTEM_HIVE_MUTATION_BEGIN {
            return reply;
        }
        let request = Request::from_bytes(input).unwrap();
        self.requests.push(request);
        if reply.status == STATUS_SUCCESS && request.operation == operation::BEGIN {
            self.tokens
                .push(Reply::from_bytes(output).unwrap().mutation_token);
        }
        if self.panic_after == Some(request.operation) {
            self.panic_after = None;
            panic!("injected unwind after real server effect");
        }
        if self.lose == Some(request.operation) {
            self.lose = None;
            output.fill(0);
            return CmReply {
                status: STATUS_DEVICE_NOT_READY,
                information: 0,
                detail0: 0,
                detail1: 0,
            };
        }
        reply
    }
}

fn client() -> ConfigClient<Direct> {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    hive.create_key(r"ControlSet001\Services");
    hive.finish_clean_import();
    let mut client = ConfigClient::new(Direct {
        server: CmServer::new_for_incarnation(NonZeroU32::MIN),
        lose: None,
        panic_after: None,
        requests: Vec::new(),
        tokens: Vec::new(),
    });
    client.import_system_hive(&encode_image(&hive)).unwrap();
    client
}

fn exchange<C>(
    manager: &mut CmMutationBeginAttempts,
    attempt: &mut CmMutationBeginAttempt<C>,
    client: &mut ConfigClient<Direct>,
    operation: CmMutationBeginOperation,
) -> Result<(), i32> {
    let mut ticket = manager.begin_exchange(attempt, operation)?;
    let response = client.exchange_system_hive_mutation_begin(&ticket);
    manager.complete_exchange(attempt, &mut ticket, response)
}

#[test]
fn real_server_lost_begin_and_ack_transfer_one_still_live_upload() {
    let mut client = client();
    let mut manager = CmMutationBeginAttempts::with_slot_limit(1).unwrap();
    let mut attempt = reserve_on(&mut manager, &mut client, 42);
    for (op, wire) in [
        (CmMutationBeginOperation::Query, operation::QUERY),
        (CmMutationBeginOperation::Begin, operation::BEGIN),
        (
            CmMutationBeginOperation::Acknowledge,
            operation::ACKNOWLEDGE,
        ),
    ] {
        client.backend.lose = Some(wire);
        assert_eq!(
            exchange(&mut manager, &mut attempt, &mut client, op),
            Err(STATUS_DEVICE_NOT_READY)
        );
        assert!(manager.take_upload(&mut attempt).is_err());
        exchange(&mut manager, &mut attempt, &mut client, op).unwrap();
        let requests = &client.backend.requests;
        assert_eq!(requests[requests.len() - 1], requests[requests.len() - 2]);
    }
    assert_eq!(client.backend.tokens.len(), 2);
    assert_ne!(client.backend.tokens[0], 0);
    assert_eq!(client.backend.tokens[0], client.backend.tokens[1]);
    let upload = manager.take_upload(&mut attempt).unwrap();
    assert_eq!(upload.mutation_token, client.backend.tokens[0]);
    assert_eq!(upload.continuation(), &42);
    let mut competitor = reserve_on(&mut manager, &mut client, 9);
    exchange(
        &mut manager,
        &mut competitor,
        &mut client,
        CmMutationBeginOperation::Begin,
    )
    .unwrap();
    assert_eq!(competitor.outcome_status(), Some(BUSY));
    // Test-only use of the opaque token proves BEGIN ACK did not release the upload.
    let appended = client
        .hive_mutation_call(
            hive_mutation_transfer::APPEND,
            0,
            upload.mutation_token,
            upload.expected_generation,
            0,
            upload.journal.len() as u32,
            &upload.journal,
        )
        .unwrap();
    assert_eq!(appended.status, STATUS_SUCCESS);
    let aborted = client
        .hive_mutation_call(
            hive_mutation_transfer::ABORT,
            0,
            upload.mutation_token,
            upload.expected_generation,
            0,
            upload.journal.len() as u32,
            &[],
        )
        .unwrap();
    assert_eq!(aborted.status, STATUS_SUCCESS);
    exchange(
        &mut manager,
        &mut competitor,
        &mut client,
        CmMutationBeginOperation::Acknowledge,
    )
    .unwrap();
    assert_eq!(manager.take_failure(&mut competitor), Ok((BUSY, 9)));
}

#[test]
fn real_server_lost_busy_outcome_remains_failed_after_writer_is_released() {
    let mut client = client();
    let mut manager = CmMutationBeginAttempts::with_slot_limit(2).unwrap();
    let mut first = reserve_on(&mut manager, &mut client, 1);
    exchange(
        &mut manager,
        &mut first,
        &mut client,
        CmMutationBeginOperation::Query,
    )
    .unwrap();
    exchange(
        &mut manager,
        &mut first,
        &mut client,
        CmMutationBeginOperation::Begin,
    )
    .unwrap();
    exchange(
        &mut manager,
        &mut first,
        &mut client,
        CmMutationBeginOperation::Acknowledge,
    )
    .unwrap();
    let upload = manager.take_upload(&mut first).unwrap();
    let mut failed = reserve_on(&mut manager, &mut client, 2);
    client.backend.lose = Some(operation::BEGIN);
    assert_eq!(
        exchange(
            &mut manager,
            &mut failed,
            &mut client,
            CmMutationBeginOperation::Begin
        ),
        Err(STATUS_DEVICE_NOT_READY)
    );
    assert_eq!(failed.outcome_status(), None);
    assert!(manager
        .begin_exchange(&mut failed, CmMutationBeginOperation::Acknowledge)
        .is_err());
    let aborted = client
        .hive_mutation_call(
            hive_mutation_transfer::ABORT,
            0,
            upload.mutation_token,
            upload.expected_generation,
            0,
            upload.journal.len() as u32,
            &[],
        )
        .unwrap();
    assert_eq!(aborted.status, STATUS_SUCCESS);
    exchange(
        &mut manager,
        &mut failed,
        &mut client,
        CmMutationBeginOperation::Begin,
    )
    .unwrap();
    assert_eq!(failed.outcome_status(), Some(BUSY));
    exchange(
        &mut manager,
        &mut failed,
        &mut client,
        CmMutationBeginOperation::Acknowledge,
    )
    .unwrap();
    assert_eq!(manager.take_failure(&mut failed), Ok((BUSY, 2)));
    let mut next = reserve_on(&mut manager, &mut client, 3);
    exchange(
        &mut manager,
        &mut next,
        &mut client,
        CmMutationBeginOperation::Begin,
    )
    .unwrap();
    assert_eq!(next.outcome_status(), Some(STATUS_SUCCESS));
}

#[test]
fn real_server_unwind_after_begin_keeps_epoch_busy_and_caller_owned() {
    let mut client = client();
    let mut manager = CmMutationBeginAttempts::new();
    let mut attempt = reserve_on(&mut manager, &mut client, 42);
    exchange(
        &mut manager,
        &mut attempt,
        &mut client,
        CmMutationBeginOperation::Query,
    )
    .unwrap();
    client.backend.panic_after = Some(operation::BEGIN);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ticket = manager
            .begin_exchange(&mut attempt, CmMutationBeginOperation::Begin)
            .unwrap();
        let _ = client.exchange_system_hive_mutation_begin(&ticket);
    }));
    assert!(result.is_err());
    assert!(attempt.is_inflight());
    assert_eq!(attempt.continuation(), Some(&42));
    assert!(attempt.outcome_status().is_none());
    assert!(manager
        .begin_exchange(&mut attempt, CmMutationBeginOperation::Begin)
        .is_err());
    assert!(manager
        .begin_exchange(&mut attempt, CmMutationBeginOperation::Acknowledge)
        .is_err());
    assert!(manager.take_upload(&mut attempt).is_err());
}
