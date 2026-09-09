extern crate std;

use super::*;
use crate::mutation_commit::test_support::{image, PARENT};
use crate::{
    Backend, CmMutationBeginAttempts, CmMutationBeginOperation, ConfigClient, SystemHiveMutation,
    STATUS_DEVICE_NOT_READY, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use alloc::{vec, vec::Vec};
use core::num::NonZeroU32;
use nt_config_abi::{
    hive_mutation_commit_disposition as commit_disposition,
    hive_mutation_commit_operation as commit_op, hive_mutation_transfer, opcode,
    CmHiveMutationCommitReply, CmHiveMutationCommitRequest, CmHiveMutationRequest, CmReply,
};
use nt_config_server::CmServer;

type Op = CmMutationPreparationOperation;
type Phase = CmMutationPreparationPhase;

#[derive(Clone, Copy)]
enum Fault {
    Lose,
    Cqe(u8),
    Body(u8),
    Panic,
}

struct Direct {
    server: CmServer,
    fault: Option<(Op, Fault)>,
    requests: Vec<(Op, Vec<u8>)>,
}

impl Backend for Direct {
    fn call(&mut self, op: u16, input: &[u8], output: &mut [u8]) -> CmReply {
        let mut reply = self.server.dispatch(op, input, output);
        let operation = match op {
            opcode::CM_OP_MUTATE_SYSTEM_HIVE => {
                match CmHiveMutationRequest::from_bytes(input).unwrap().operation {
                    hive_mutation_transfer::APPEND => Op::Append,
                    hive_mutation_transfer::PREPARE => Op::Prepare,
                    hive_mutation_transfer::PULL => Op::Pull,
                    _ => return reply,
                }
            }
            opcode::CM_OP_SYSTEM_HIVE_MUTATION_COMMIT => {
                match CmHiveMutationCommitRequest::from_bytes(input)
                    .unwrap()
                    .operation
                {
                    commit_op::ABORT_UNPUBLISHED => Op::Cancel,
                    commit_op::ACKNOWLEDGE => Op::AcknowledgeCancellation,
                    _ => return reply,
                }
            }
            _ => return reply,
        };
        self.requests.push((operation, input.to_vec()));
        let Some((target, fault)) = self.fault else {
            return reply;
        };
        if target != operation {
            return reply;
        }
        self.fault = None;
        assert_eq!(
            reply.status, STATUS_SUCCESS,
            "fault injection follows a real successful effect"
        );
        match fault {
            Fault::Lose => {
                output.fill(0);
                return CmReply {
                    status: STATUS_DEVICE_NOT_READY,
                    information: 0,
                    detail0: 0,
                    detail1: 0,
                };
            }
            Fault::Panic => panic!("unwind after real CM effect"),
            Fault::Cqe(variant) => match variant {
                0 => reply.information = reply.information.saturating_sub(1),
                1 => reply.information += 1,
                2 => reply.detail0 ^= 1,
                3 => reply.detail1 ^= 1,
                4 => reply.status = 0x103,
                _ => unreachable!(),
            },
            Fault::Body(variant) => {
                let mut body = CmHiveMutationCommitReply::from_bytes(output).unwrap();
                match variant {
                    0 => body.abi_size -= 1,
                    1 => body.abi_version += 1,
                    2 => body.reserved = 1,
                    3 => body.mutation_token ^= 1,
                    4 => body.expected_generation ^= 1,
                    5 => body.semantic_journal_len ^= 1,
                    6 => body.next_generation = 1,
                    7 => body.has_pending_device_action = 1,
                    8 => {
                        body.receipt_bank = 0;
                        reply.detail0 = 0;
                    }
                    9 => {
                        body.receipt_generation = 0;
                        reply.detail1 = 0;
                    }
                    10 => body.disposition = commit_disposition::ABORTED,
                    11 => body.disposition = commit_disposition::RETAINED,
                    12 => {
                        body.receipt_bank += 1;
                        reply.detail0 = body.receipt_bank;
                    }
                    13 => {
                        body.receipt_generation += 1;
                        reply.detail1 = body.receipt_generation;
                    }
                    _ => unreachable!(),
                }
                output[..core::mem::size_of::<CmHiveMutationCommitReply>()]
                    .copy_from_slice(body.as_bytes());
            }
        }
        reply
    }
}

fn client() -> ConfigClient<Direct> {
    let mut client = ConfigClient::new(Direct {
        server: CmServer::new_for_incarnation(NonZeroU32::MIN),
        fault: None,
        requests: Vec::new(),
    });
    client.import_system_hive(&image()).unwrap();
    client
}

fn preparation<C>(
    client: &mut ConfigClient<Direct>,
    mutations: &[SystemHiveMutation<'_>],
    caller: C,
) -> SystemHiveMutationPreparation<C> {
    let mut manager = CmMutationBeginAttempts::new();
    let mut attempt = match manager.reserve(1, mutations, caller) {
        Ok(attempt) => attempt,
        Err((status, _)) => panic!("reserve failed: {status:x}"),
    };
    for op in [
        CmMutationBeginOperation::Query,
        CmMutationBeginOperation::Begin,
        CmMutationBeginOperation::Acknowledge,
    ] {
        let mut ticket = manager.begin_exchange(&mut attempt, op).unwrap();
        let response = client.exchange_system_hive_mutation_begin(&ticket);
        manager
            .complete_exchange(&mut attempt, &mut ticket, response)
            .unwrap();
    }
    let upload = manager.take_upload(&mut attempt).unwrap();
    let pointer = upload.journal().as_ptr();
    let owner = upload.into_preparation();
    assert_eq!(owner.upload.as_ref().unwrap().journal().as_ptr(), pointer);
    owner
}

fn standard<C>(client: &mut ConfigClient<Direct>, caller: C) -> SystemHiveMutationPreparation<C> {
    let data = vec![0x5a; 9000];
    preparation(
        client,
        &[SystemHiveMutation::SetValue {
            path: PARENT,
            name: "Large",
            value_type: 3,
            data: &data,
        }],
        caller,
    )
}

fn exchange<C>(
    client: &mut ConfigClient<Direct>,
    owner: &mut SystemHiveMutationPreparation<C>,
    op: Op,
) -> Result<(), i32> {
    let mut ticket = owner.begin_exchange(op)?;
    let response = client.exchange_system_hive_mutation_preparation(&ticket);
    owner.complete_exchange(&mut ticket, response)
}

fn append_all<C>(client: &mut ConfigClient<Direct>, owner: &mut SystemHiveMutationPreparation<C>) {
    while owner.phase() == Phase::Appending {
        exchange(client, owner, Op::Append).unwrap();
    }
    assert_eq!(owner.phase(), Phase::Preparing);
}

fn prepare_and_allocate<C>(
    client: &mut ConfigClient<Direct>,
    owner: &mut SystemHiveMutationPreparation<C>,
) {
    append_all(client, owner);
    exchange(client, owner, Op::Prepare).unwrap();
    if owner.phase() == Phase::Allocating {
        owner.allocate_journal().unwrap();
    }
}

fn cancel<C>(client: &mut ConfigClient<Direct>, owner: &mut SystemHiveMutationPreparation<C>) {
    exchange(client, owner, Op::Cancel).unwrap();
    assert_eq!(owner.phase(), Phase::AcknowledgingCancellation);
    exchange(client, owner, Op::AcknowledgeCancellation).unwrap();
    assert_eq!(owner.phase(), Phase::Cancelled);
}

#[test]
fn real_server_lost_append_prepare_and_pull_keep_exact_offsets_and_move_once() {
    let mut client = client();
    let mut owner = standard(&mut client, 42);
    let semantic_len = owner.upload.as_ref().unwrap().journal().len();
    for op in [Op::Append, Op::Prepare, Op::Pull] {
        if op == Op::Prepare {
            append_all(&mut client, &mut owner);
        }
        if op == Op::Pull {
            owner.allocate_journal().unwrap();
        }
        let uploaded = owner.uploaded_len();
        let collected = owner.collected_len();
        client.backend.fault = Some((op, Fault::Lose));
        assert_eq!(
            exchange(&mut client, &mut owner, op),
            Err(STATUS_DEVICE_NOT_READY)
        );
        assert_eq!(owner.uploaded_len(), uploaded);
        assert_eq!(owner.collected_len(), collected);
        assert_eq!(owner.continuation(), Some(&42));
        assert!(owner.take_prepared().is_err());
        exchange(&mut client, &mut owner, op).unwrap();
        let calls = &client.backend.requests;
        assert_eq!(calls[calls.len() - 1], calls[calls.len() - 2]);
    }
    assert_eq!(owner.uploaded_len(), semantic_len);
    let pointer = owner.durable.as_ptr();
    while owner.phase() == Phase::Pulling {
        exchange(&mut client, &mut owner, Op::Pull).unwrap();
    }
    assert_eq!(owner.phase(), Phase::Prepared);
    assert!(owner.collected_len() > 9000);
    assert_eq!(owner.durable.as_ptr(), pointer);
    let (prepared, caller) = owner.take_prepared().unwrap();
    assert_eq!(caller, 42);
    assert_eq!(prepared.expected_generation(), 1);
    assert_eq!(prepared.next_generation(), 2);
    assert_eq!(prepared.durable_journal().as_ptr(), pointer);
    assert_eq!(prepared.semantic_journal_len as usize, semantic_len);
    assert_eq!(owner.phase(), Phase::Taken);
    assert!(owner.continuation().is_none());
    assert!(owner.take_prepared().is_err());
    assert!(owner.take_cancelled().is_err());
    assert!(owner.begin_exchange(Op::Cancel).is_err());
    // This test has no durable storage/publication; clean up the transferred preparation exactly.
    let receipt = client
        .abort_prepared_system_hive_mutation_retained(&prepared)
        .unwrap();
    let _ = client
        .acknowledge_system_hive_mutation_abort(receipt)
        .unwrap();
}

#[test]
fn real_noop_preparation_has_zero_journal_and_never_issues_pull() {
    let mut client = client();
    let mut owner = preparation(
        &mut client,
        &[SystemHiveMutation::CreateKey { path: PARENT }],
        7,
    );
    prepare_and_allocate(&mut client, &mut owner);
    assert_eq!(owner.durable_len, Some(0));
    assert_eq!(owner.phase(), Phase::Prepared);
    assert_eq!(owner.collected_len(), 0);
    assert!(owner.begin_exchange(Op::Pull).is_err());
    let (prepared, caller) = owner.take_prepared().unwrap();
    assert_eq!(caller, 7);
    assert!(prepared.durable_journal().is_empty());
    assert!(client
        .backend
        .requests
        .iter()
        .all(|(op, _)| *op != Op::Pull));
    let receipt = client
        .abort_prepared_system_hive_mutation_retained(&prepared)
        .unwrap();
    let _ = client
        .acknowledge_system_hive_mutation_abort(receipt)
        .unwrap();
}

#[test]
fn allocation_failure_retains_validated_manifest_and_can_retry_without_another_prepare() {
    let mut client = client();
    let mut owner = standard(&mut client, 42);
    append_all(&mut client, &mut owner);
    exchange(&mut client, &mut owner, Op::Prepare).unwrap();
    let total = owner.durable_len.unwrap();
    let calls = client.backend.requests.len();
    assert_eq!(
        owner.allocate_journal_with_reserve(|_, requested| {
            assert_eq!(requested, total as usize);
            Err(crate::STATUS_INSUFFICIENT_RESOURCES)
        }),
        Err(crate::STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(owner.phase(), Phase::Allocating);
    assert_eq!(owner.durable_len, Some(total));
    assert_eq!(owner.continuation(), Some(&42));
    assert_eq!(owner.collected_len(), 0);
    assert!(owner.begin_exchange(Op::Prepare).is_err());
    assert!(owner.begin_exchange(Op::Pull).is_err());
    assert!(owner.take_prepared().is_err());
    assert_eq!(
        owner.allocate_journal_with_reserve(|_, _| Ok(())),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(owner.phase(), Phase::Allocating);
    owner.allocate_journal().unwrap();
    assert_eq!(owner.phase(), Phase::Pulling);
    assert_eq!(client.backend.requests.len(), calls);
    cancel(&mut client, &mut owner);
    assert_eq!(owner.take_cancelled(), Ok(42));
}

#[test]
fn allocation_failure_can_cancel_without_allocating_or_collecting_the_journal() {
    let mut client = client();
    let mut owner = standard(&mut client, 42);
    append_all(&mut client, &mut owner);
    exchange(&mut client, &mut owner, Op::Prepare).unwrap();
    assert!(owner
        .allocate_journal_with_reserve(|_, _| Err(crate::STATUS_INSUFFICIENT_RESOURCES))
        .is_err());
    assert_eq!(owner.durable.capacity(), 0);
    cancel(&mut client, &mut owner);
    assert_eq!(owner.durable.capacity(), 0);
    assert_eq!(owner.take_cancelled(), Ok(42));
}

#[test]
fn caller_drops_once_after_acknowledged_cancellation_not_on_protocol_failure() {
    use alloc::rc::Rc;
    use core::cell::Cell;
    struct Caller(Rc<Cell<usize>>);
    impl Drop for Caller {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Rc::new(Cell::new(0));
    let mut client = client();
    let mut owner = standard(&mut client, Caller(drops.clone()));
    client.backend.fault = Some((Op::Append, Fault::Lose));
    assert!(exchange(&mut client, &mut owner, Op::Append).is_err());
    assert_eq!(drops.get(), 0);
    cancel(&mut client, &mut owner);
    let caller = owner.take_cancelled().unwrap();
    drop(owner);
    assert_eq!(drops.get(), 0);
    drop(caller);
    assert_eq!(drops.get(), 1);
}

#[test]
fn malformed_append_does_not_advance_and_replays_identical_bytes() {
    for variant in 0..5 {
        let mut client = client();
        let mut owner = standard(&mut client, 42);
        client.backend.fault = Some((Op::Append, Fault::Cqe(variant)));
        assert!(exchange(&mut client, &mut owner, Op::Append).is_err());
        assert_eq!(owner.uploaded_len(), 0);
        assert_eq!(owner.phase(), Phase::Appending);
        assert!(owner.begin_exchange(Op::Prepare).is_err());
        exchange(&mut client, &mut owner, Op::Append).unwrap();
        assert!(owner.uploaded_len() > 0);
        assert_eq!(client.backend.requests[0], client.backend.requests[1]);
        cancel(&mut client, &mut owner);
        assert_eq!(owner.take_cancelled(), Ok(42));
    }
}

#[test]
fn malformed_prepare_identity_retains_uncertain_preparation_for_retry_or_cancel() {
    for variant in 2..5 {
        let mut client = client();
        let mut owner = standard(&mut client, 42);
        append_all(&mut client, &mut owner);
        client.backend.fault = Some((Op::Prepare, Fault::Cqe(variant)));
        assert!(exchange(&mut client, &mut owner, Op::Prepare).is_err());
        assert_eq!(owner.phase(), Phase::Preparing);
        assert_eq!(owner.durable_len, None);
        assert!(owner.allocate_journal().is_err());
        assert!(owner.begin_exchange(Op::Pull).is_err());
        assert!(owner.take_prepared().is_err());
        if variant == 2 {
            exchange(&mut client, &mut owner, Op::Prepare).unwrap();
            assert_eq!(owner.phase(), Phase::Allocating);
        }
        cancel(&mut client, &mut owner);
        assert_eq!(owner.take_cancelled(), Ok(42));
    }
}

#[test]
fn malformed_pull_length_total_or_token_never_appends_bytes() {
    for variant in 0..5 {
        let mut client = client();
        let mut owner = standard(&mut client, 42);
        prepare_and_allocate(&mut client, &mut owner);
        client.backend.fault = Some((Op::Pull, Fault::Cqe(variant)));
        assert!(exchange(&mut client, &mut owner, Op::Pull).is_err());
        assert_eq!(owner.collected_len(), 0);
        assert_eq!(owner.phase(), Phase::Pulling);
        exchange(&mut client, &mut owner, Op::Pull).unwrap();
        assert!(owner.collected_len() > 0);
        let calls = &client.backend.requests;
        assert_eq!(calls[calls.len() - 1], calls[calls.len() - 2]);
        cancel(&mut client, &mut owner);
        assert_eq!(owner.take_cancelled(), Ok(42));
    }
}

#[test]
fn uncertain_prepare_cancels_exact_server_preparation_and_acknowledges_once() {
    let mut client = client();
    let mut owner = standard(&mut client, 42);
    append_all(&mut client, &mut owner);
    client.backend.fault = Some((Op::Prepare, Fault::Lose));
    assert!(exchange(&mut client, &mut owner, Op::Prepare).is_err());
    for op in [Op::Cancel, Op::AcknowledgeCancellation] {
        client.backend.fault = Some((op, Fault::Lose));
        assert_eq!(
            exchange(&mut client, &mut owner, op),
            Err(STATUS_DEVICE_NOT_READY)
        );
        assert!(!owner.is_inflight());
        assert_eq!(owner.continuation(), Some(&42));
        assert!(owner.take_cancelled().is_err());
        assert!(owner.take_prepared().is_err());
        for progress in [Op::Append, Op::Prepare, Op::Pull] {
            assert!(owner.begin_exchange(progress).is_err());
        }
        assert!(owner.allocate_journal().is_err());
        exchange(&mut client, &mut owner, op).unwrap();
        let calls = &client.backend.requests;
        assert_eq!(calls[calls.len() - 1], calls[calls.len() - 2]);
    }
    assert_eq!(owner.take_cancelled(), Ok(42));
    assert_eq!(owner.phase(), Phase::Taken);
    assert!(owner.take_cancelled().is_err());
    assert!(owner.begin_exchange(Op::Cancel).is_err());
    let mut next = standard(&mut client, 9);
    cancel(&mut client, &mut next);
    assert_eq!(next.take_cancelled(), Ok(9));
}

#[test]
fn cancellation_is_available_from_every_unpublished_quiescent_phase() {
    for stage in 0..5 {
        let mut client = client();
        let mut owner = standard(&mut client, stage);
        if stage >= 1 {
            append_all(&mut client, &mut owner);
        }
        if stage >= 2 {
            exchange(&mut client, &mut owner, Op::Prepare).unwrap();
        }
        if stage >= 3 {
            owner.allocate_journal().unwrap();
        }
        if stage >= 4 {
            while owner.phase() == Phase::Pulling {
                exchange(&mut client, &mut owner, Op::Pull).unwrap();
            }
            assert_eq!(owner.phase(), Phase::Prepared);
        }
        cancel(&mut client, &mut owner);
        assert_eq!(owner.take_cancelled(), Ok(stage));
    }
}

#[test]
fn malformed_cancellation_receipt_never_authorizes_ack_or_progress() {
    for variant in 0..12 {
        let mut client = client();
        let mut owner = standard(&mut client, 42);
        client.backend.fault = Some((Op::Cancel, Fault::Body(variant)));
        assert!(exchange(&mut client, &mut owner, Op::Cancel).is_err());
        assert_eq!(owner.phase(), Phase::Cancelling);
        assert!(owner.cancel_receipt.is_none());
        assert!(owner.begin_exchange(Op::AcknowledgeCancellation).is_err());
        assert!(owner.begin_exchange(Op::Append).is_err());
        assert!(owner.take_cancelled().is_err());
        cancel(&mut client, &mut owner);
        assert_eq!(owner.take_cancelled(), Ok(42));
    }
}

#[test]
fn malformed_cancel_ack_retains_receipt_and_retries_after_server_watermark_advanced() {
    for variant in 0..14 {
        let mut client = client();
        let mut owner = standard(&mut client, 42);
        exchange(&mut client, &mut owner, Op::Cancel).unwrap();
        let bank = owner.cancel_receipt.as_ref().unwrap().bank;
        let generation = owner.cancel_receipt.as_ref().unwrap().generation;
        client.backend.fault = Some((Op::AcknowledgeCancellation, Fault::Body(variant)));
        assert!(exchange(&mut client, &mut owner, Op::AcknowledgeCancellation).is_err());
        assert_eq!(owner.phase(), Phase::AcknowledgingCancellation);
        assert_eq!(owner.cancel_receipt.as_ref().unwrap().bank, bank);
        assert_eq!(
            owner.cancel_receipt.as_ref().unwrap().generation,
            generation
        );
        assert!(owner.take_cancelled().is_err());
        assert!(owner.begin_exchange(Op::Cancel).is_err());
        // Another complete cancellation may reuse the server receipt slot, not this receipt identity.
        let mut next = standard(&mut client, 9);
        cancel(&mut client, &mut next);
        assert_eq!(next.take_cancelled(), Ok(9));
        exchange(&mut client, &mut owner, Op::AcknowledgeCancellation).unwrap();
        assert_eq!(owner.take_cancelled(), Ok(42));
    }
}

#[test]
fn dropped_and_stale_exchange_tickets_cannot_clear_current_epoch() {
    let mut client = client();
    let mut owner = standard(&mut client, 42);
    let mut old = owner.begin_exchange(Op::Append).unwrap();
    assert!(owner
        .complete_exchange(
            &mut old,
            CmMutationPreparationResponse::transport_error(STATUS_DEVICE_NOT_READY)
        )
        .is_err());
    let current = owner.begin_exchange(Op::Append).unwrap();
    assert_eq!(
        owner.complete_exchange(
            &mut old,
            CmMutationPreparationResponse::transport_error(STATUS_DEVICE_NOT_READY)
        ),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert!(owner.is_inflight());
    assert!(owner.begin_exchange(Op::Cancel).is_err());
    assert!(owner.take_prepared().is_err());
    drop(current);
    assert!(owner.is_inflight());
    assert!(owner.begin_exchange(Op::Append).is_err());
}

#[test]
fn wrong_owner_ticket_does_not_consume_either_inflight_exchange() {
    let mut client = client();
    let mut owner = standard(&mut client, 42);
    let mut second_client = self::client();
    let mut second = standard(&mut second_client, 9);
    let mut ticket = owner.begin_exchange(Op::Append).unwrap();
    let reply = client.exchange_system_hive_mutation_preparation(&ticket);
    assert_eq!(
        second.complete_exchange(&mut ticket, reply),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert!(owner.is_inflight());
    assert!(ticket.live);
    let reply = client.exchange_system_hive_mutation_preparation(&ticket);
    owner.complete_exchange(&mut ticket, reply).unwrap();
    assert!(owner.uploaded_len() > 0);
    cancel(&mut client, &mut owner);
    cancel(&mut second_client, &mut second);
}

fn reject_stale_equal_sized_chunk_response(op: Op) {
    let mut client = client();
    let mut owner = standard(&mut client, 42);
    if op == Op::Pull {
        prepare_and_allocate(&mut client, &mut owner);
    }
    let mut first = owner.begin_exchange(op).unwrap();
    let first_request = CmHiveMutationRequest::from_bytes(&first.bytes).unwrap();
    assert_eq!(
        first_request.chunk_len_bytes as usize,
        nt_config_abi::CM_HIVE_MUTATION_CHUNK_BYTES
    );
    let response = client.exchange_system_hive_mutation_preparation(&first);
    let stale = client.exchange_system_hive_mutation_preparation(&first);
    owner.complete_exchange(&mut first, response).unwrap();
    let uploaded = owner.uploaded_len();
    let collected = owner.collected_len();

    let mut second = owner.begin_exchange(op).unwrap();
    let second_request = CmHiveMutationRequest::from_bytes(&second.bytes).unwrap();
    assert_eq!(
        first_request.chunk_len_bytes,
        second_request.chunk_len_bytes
    );
    assert_ne!(first_request.journal_offset, second_request.journal_offset);
    assert_eq!(
        owner.complete_exchange(&mut second, stale),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert!(second.live);
    assert!(owner.is_inflight());
    assert_eq!(owner.uploaded_len(), uploaded);
    assert_eq!(owner.collected_len(), collected);
    assert_eq!(owner.continuation(), Some(&42));
    assert!(owner.begin_exchange(Op::Cancel).is_err());

    let response = client.exchange_system_hive_mutation_preparation(&second);
    owner.complete_exchange(&mut second, response).unwrap();
    assert!(!owner.is_inflight());
    assert!(!second.live);
    if op == Op::Append {
        assert_eq!(
            owner.uploaded_len(),
            uploaded + second_request.chunk_len_bytes as usize
        );
        assert_eq!(owner.collected_len(), collected);
    } else {
        assert_eq!(owner.uploaded_len(), uploaded);
        assert_eq!(
            owner.collected_len(),
            collected + second_request.chunk_len_bytes as usize
        );
    }
    cancel(&mut client, &mut owner);
    assert_eq!(owner.take_cancelled(), Ok(42));
}

#[test]
fn stale_append_response_cannot_advance_a_later_equal_sized_chunk() {
    reject_stale_equal_sized_chunk_response(Op::Append);
}

#[test]
fn stale_pull_response_cannot_append_a_later_equal_sized_chunk() {
    reject_stale_equal_sized_chunk_response(Op::Pull);
}

#[test]
fn unwind_after_each_server_effect_keeps_caller_and_inflight_authority() {
    for op in [
        Op::Append,
        Op::Prepare,
        Op::Pull,
        Op::Cancel,
        Op::AcknowledgeCancellation,
    ] {
        let mut client = client();
        let mut owner = standard(&mut client, 42);
        match op {
            Op::Prepare => append_all(&mut client, &mut owner),
            Op::Pull => prepare_and_allocate(&mut client, &mut owner),
            Op::AcknowledgeCancellation => {
                exchange(&mut client, &mut owner, Op::Cancel).unwrap();
            }
            _ => {}
        }
        client.backend.fault = Some((op, Fault::Panic));
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let ticket = owner.begin_exchange(op).unwrap();
            let _ = client.exchange_system_hive_mutation_preparation(&ticket);
        }));
        assert!(unwind.is_err());
        assert!(owner.is_inflight());
        assert_eq!(owner.continuation(), Some(&42));
        assert!(owner.take_prepared().is_err());
        assert!(owner.take_cancelled().is_err());
        for retry in [
            Op::Append,
            Op::Prepare,
            Op::Pull,
            Op::Cancel,
            Op::AcknowledgeCancellation,
        ] {
            assert!(owner.begin_exchange(retry).is_err());
        }
    }
}
