//! End-to-end loss and cancellation tests through the real CM dispatcher.

use super::*;
use core::num::NonZeroU32;
use nt_config_abi::{
    retained_snapshot_operation as operation, CmRetainedSnapshotReply, CmRetainedSnapshotRequest,
    CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES,
};
use nt_config_server::CmServer;
use nt_hive_core::{encode_image, Hive, HiveKind};

const PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Services\Device";
const INVALID_HANDLE: i32 = 0xc000_0008u32 as i32;
const NOT_READY: i32 = 0xc000_00a3u32 as i32;

#[derive(Clone, Copy)]
enum Loss {
    Before(u16),
    After(u16),
    CorruptChunk,
}

struct Direct {
    server: CmServer,
    loss: Option<Loss>,
    last_query: Vec<u8>,
    last_begin: Vec<u8>,
    last_pull: Vec<u8>,
    begin_calls: usize,
}

fn lost(output: &mut [u8]) -> CmReply {
    output.fill(0);
    CmReply {
        status: NOT_READY,
        information: 0,
        detail0: 0,
        detail1: 0,
    }
}

impl Backend for Direct {
    fn call(&mut self, opcode: u16, input: &[u8], output: &mut [u8]) -> CmReply {
        if opcode != opcode::CM_OP_RETAINED_SNAPSHOT {
            return self.server.dispatch(opcode, input, output);
        }
        let request = CmRetainedSnapshotRequest::from_bytes(input).unwrap();
        match request.operation {
            operation::QUERY => self.last_query = input.into(),
            operation::BEGIN => {
                self.last_begin = input.into();
                self.begin_calls += 1;
            }
            operation::PULL => self.last_pull = input.into(),
            _ => {}
        }
        if matches!(self.loss, Some(Loss::Before(op)) if op == request.operation) {
            self.loss = None;
            return lost(output);
        }
        let reply = self.server.dispatch(opcode, input, output);
        if matches!(self.loss, Some(Loss::After(op)) if op == request.operation) {
            self.loss = None;
            return lost(output);
        }
        if matches!(self.loss, Some(Loss::CorruptChunk)) && request.operation == operation::PULL {
            self.loss = None;
            let mut body = CmRetainedSnapshotReply::from_bytes(output).unwrap();
            body.value_offset = body.value_offset.saturating_add(1);
            output[..CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES].copy_from_slice(body.as_bytes());
        }
        reply
    }
}

fn image(image_path: &str, devices: usize) -> Vec<u8> {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    let service = hive.create_key("ControlSet001\\Services\\Device");
    hive.set_dword(service, "Type", 1);
    hive.set_dword(service, "Start", 3);
    hive.set_value(
        service,
        "ImagePath",
        nt_config_manager::RegistryValueType::Sz,
        nt_config_manager::encode_sz(image_path),
    );
    for index in 0..devices {
        let key = hive.create_key(&alloc::format!(
            "ControlSet001\\Enum\\ROOT\\DEVICE\\{:04}",
            index
        ));
        hive.set_value(
            key,
            "Service",
            nt_config_manager::RegistryValueType::Sz,
            nt_config_manager::encode_sz("Device"),
        );
        hive.set_value(
            key,
            "HardwareID",
            nt_config_manager::RegistryValueType::MultiSz,
            nt_config_manager::encode_multi_sz(&["ROOT\\DEVICE"]),
        );
    }
    hive.finish_clean_import();
    encode_image(&hive)
}

fn client(devices: usize) -> ConfigClient<Direct> {
    let mut client = ConfigClient::new(Direct {
        server: CmServer::new_for_incarnation(NonZeroU32::MIN),
        loss: None,
        last_query: Vec::new(),
        last_begin: Vec::new(),
        last_pull: Vec::new(),
        begin_calls: 0,
    });
    client
        .import_system_hive(&image(r"system32\drivers\original.sys", devices))
        .unwrap();
    client
}

fn exchange(
    manager: &mut CmSnapshotAttempts,
    attempt: &mut CmSnapshotAttempt,
    client: &mut ConfigClient<Direct>,
    operation: CmSnapshotOperation,
) -> Result<(), i32> {
    let mut ticket = manager.begin_exchange(attempt, operation)?;
    let response = client.exchange_retained_snapshot(&ticket);
    manager.complete_exchange(attempt, &mut ticket, response)
}

fn query(
    manager: &mut CmSnapshotAttempts,
    attempt: &mut CmSnapshotAttempt,
    client: &mut ConfigClient<Direct>,
) {
    if attempt.server_nonce().is_none() {
        exchange(manager, attempt, client, CmSnapshotOperation::Query).unwrap();
    }
}

fn abandon(
    manager: &mut CmSnapshotAttempts,
    attempt: &mut CmSnapshotAttempt,
    client: &mut ConfigClient<Direct>,
) {
    manager.abandon(attempt).unwrap();
    exchange(manager, attempt, client, CmSnapshotOperation::Acknowledge).unwrap();
    manager.release(attempt).unwrap();
}

fn replay(client: &mut ConfigClient<Direct>, request: &[u8]) -> CmReply {
    client
        .backend
        .server
        .dispatch(opcode::CM_OP_RETAINED_SNAPSHOT, request, &mut [0; 4096])
}

#[test]
fn lost_begin_is_abandoned_without_learning_a_reply_token_or_reacquiring() {
    let mut client = client(2);
    let mut manager = CmSnapshotAttempts::new();
    let mut attempt = manager.reserve_active_driver_service(PATH).unwrap();
    query(&mut manager, &mut attempt, &mut client);
    client.backend.loss = Some(Loss::After(operation::BEGIN));
    assert_eq!(
        exchange(
            &mut manager,
            &mut attempt,
            &mut client,
            CmSnapshotOperation::Begin
        ),
        Err(NOT_READY)
    );
    assert!(attempt.outcome_status().is_none());
    let original = client.backend.last_begin.clone();
    abandon(&mut manager, &mut attempt, &mut client);
    assert_eq!(client.backend.begin_calls, 1);
    assert_eq!(replay(&mut client, &original).status, INVALID_HANDLE);
    let mut next = manager.reserve_active_driver_service(PATH).unwrap();
    query(&mut manager, &mut next, &mut client);
    exchange(
        &mut manager,
        &mut next,
        &mut client,
        CmSnapshotOperation::Begin,
    )
    .unwrap();
    abandon(&mut manager, &mut next, &mut client);
}

#[test]
fn cancellation_before_begin_delivery_fences_the_delayed_request() {
    let mut client = client(1);
    let mut manager = CmSnapshotAttempts::new();
    let mut attempt = manager.reserve_active_driver_service(PATH).unwrap();
    query(&mut manager, &mut attempt, &mut client);
    client.backend.loss = Some(Loss::Before(operation::BEGIN));
    assert!(exchange(
        &mut manager,
        &mut attempt,
        &mut client,
        CmSnapshotOperation::Begin
    )
    .is_err());
    let delayed = client.backend.last_begin.clone();
    abandon(&mut manager, &mut attempt, &mut client);
    assert_eq!(replay(&mut client, &delayed).status, INVALID_HANDLE);
}

#[test]
fn lost_final_pull_replays_immutable_bytes_and_lost_ack_still_transfers_once() {
    let mut client = client(1);
    let mut manager = CmSnapshotAttempts::new();
    let mut attempt = manager.reserve_active_driver_service(PATH).unwrap();
    query(&mut manager, &mut attempt, &mut client);
    exchange(
        &mut manager,
        &mut attempt,
        &mut client,
        CmSnapshotOperation::Begin,
    )
    .unwrap();
    client.backend.loss = Some(Loss::After(operation::PULL));
    assert_eq!(
        exchange(
            &mut manager,
            &mut attempt,
            &mut client,
            CmSnapshotOperation::Pull
        ),
        Err(NOT_READY)
    );
    assert_eq!(attempt.collected_len(), 0);
    let final_pull = client.backend.last_pull.clone();
    client
        .import_system_hive(&image(r"system32\drivers\changed.sys", 1))
        .unwrap();
    exchange(
        &mut manager,
        &mut attempt,
        &mut client,
        CmSnapshotOperation::Pull,
    )
    .unwrap();
    assert!(attempt.is_complete());
    assert_eq!(client.backend.last_pull, final_pull);
    assert_eq!(replay(&mut client, &final_pull).status, STATUS_SUCCESS);
    client.backend.loss = Some(Loss::After(operation::ACKNOWLEDGE));
    assert!(exchange(
        &mut manager,
        &mut attempt,
        &mut client,
        CmSnapshotOperation::Acknowledge
    )
    .is_err());
    exchange(
        &mut manager,
        &mut attempt,
        &mut client,
        CmSnapshotOperation::Acknowledge,
    )
    .unwrap();
    let result = manager.take_active_driver_service(&mut attempt, 1).unwrap();
    assert_eq!(result.binding.image_path, r"system32\drivers\original.sys");
    assert_eq!(result.binding.devnodes.len(), 1);
    assert!(manager.take_active_driver_service(&mut attempt, 1).is_err());
    manager.release(&mut attempt).unwrap();
    assert_eq!(replay(&mut client, &final_pull).status, INVALID_HANDLE);
}

#[test]
fn concurrent_multichunk_readers_remain_independent_and_malformed_chunk_is_not_appended() {
    let mut client = client(96);
    let mut manager = CmSnapshotAttempts::new();
    let mut first = manager.reserve_active_driver_service(PATH).unwrap();
    query(&mut manager, &mut first, &mut client);
    let mut second = manager.reserve_active_driver_service(PATH).unwrap();
    query(&mut manager, &mut second, &mut client);
    exchange(
        &mut manager,
        &mut first,
        &mut client,
        CmSnapshotOperation::Begin,
    )
    .unwrap();
    exchange(
        &mut manager,
        &mut second,
        &mut client,
        CmSnapshotOperation::Begin,
    )
    .unwrap();
    client.backend.loss = Some(Loss::CorruptChunk);
    assert!(exchange(
        &mut manager,
        &mut first,
        &mut client,
        CmSnapshotOperation::Pull
    )
    .is_err());
    assert_eq!(first.collected_len(), 0);
    abandon(&mut manager, &mut first, &mut client);
    let mut chunks = 0;
    while !second.is_complete() {
        exchange(
            &mut manager,
            &mut second,
            &mut client,
            CmSnapshotOperation::Pull,
        )
        .unwrap();
        chunks += 1;
    }
    assert!(chunks > 1);
    exchange(
        &mut manager,
        &mut second,
        &mut client,
        CmSnapshotOperation::Acknowledge,
    )
    .unwrap();
    assert_eq!(
        manager
            .take_active_driver_service(&mut second, 1)
            .unwrap()
            .binding
            .devnodes
            .len(),
        96
    );
    manager.release(&mut second).unwrap();
}

#[test]
fn lost_query_registration_reuses_its_grant_and_local_cancellation_preserves_sequence() {
    let mut client = client(1);
    let mut manager = CmSnapshotAttempts::new();
    let mut first = manager.reserve_active_driver_service(PATH).unwrap();
    client.backend.loss = Some(Loss::After(operation::QUERY));
    assert_eq!(
        exchange(
            &mut manager,
            &mut first,
            &mut client,
            CmSnapshotOperation::Query
        ),
        Err(NOT_READY)
    );
    let registration = client.backend.last_query.clone();
    manager.abandon(&mut first).unwrap();
    manager.release(&mut first).unwrap();
    for _ in 0..16 {
        assert_eq!(replay(&mut client, &registration).status, STATUS_SUCCESS);
    }
    let mut next = manager.reserve_active_driver_service(PATH).unwrap();
    query(&mut manager, &mut next, &mut client);
    assert_eq!(client.backend.last_query, registration);
    exchange(
        &mut manager,
        &mut next,
        &mut client,
        CmSnapshotOperation::Begin,
    )
    .unwrap();
    abandon(&mut manager, &mut next, &mut client);
}

#[test]
fn restarted_server_cannot_acknowledge_an_old_ambiguous_request() {
    let mut client = client(1);
    let mut manager = CmSnapshotAttempts::new();
    let mut attempt = manager.reserve_active_driver_service(PATH).unwrap();
    query(&mut manager, &mut attempt, &mut client);
    client.backend.loss = Some(Loss::After(operation::BEGIN));
    assert!(exchange(
        &mut manager,
        &mut attempt,
        &mut client,
        CmSnapshotOperation::Begin
    )
    .is_err());
    client.backend.server = CmServer::new_for_incarnation(NonZeroU32::new(2).unwrap());
    manager.abandon(&mut attempt).unwrap();
    assert_eq!(
        exchange(
            &mut manager,
            &mut attempt,
            &mut client,
            CmSnapshotOperation::Acknowledge
        ),
        Err(INVALID_HANDLE)
    );
    assert!(manager.release(&mut attempt).is_err());
}

#[test]
fn negative_outcome_lost_ack_is_retired_before_request_slot_reuse() {
    let mut client = client(1);
    let mut manager = CmSnapshotAttempts::new();
    let mut missing = manager
        .reserve_active_driver_service(
            r"\Registry\Machine\System\CurrentControlSet\Services\Missing",
        )
        .unwrap();
    query(&mut manager, &mut missing, &mut client);
    exchange(
        &mut manager,
        &mut missing,
        &mut client,
        CmSnapshotOperation::Begin,
    )
    .unwrap();
    assert_eq!(missing.outcome_status(), Some(0xc000_0034u32 as i32));
    assert!(missing.is_complete());
    assert_eq!(missing.collected_len(), 0);
    let old_begin = client.backend.last_begin.clone();
    manager.abandon(&mut missing).unwrap();
    client.backend.loss = Some(Loss::After(operation::ACKNOWLEDGE));
    assert_eq!(
        exchange(
            &mut manager,
            &mut missing,
            &mut client,
            CmSnapshotOperation::Acknowledge,
        ),
        Err(NOT_READY)
    );
    assert!(!missing.is_acknowledged());
    assert!(manager.release(&mut missing).is_err());
    exchange(
        &mut manager,
        &mut missing,
        &mut client,
        CmSnapshotOperation::Acknowledge,
    )
    .unwrap();
    manager.release(&mut missing).unwrap();
    assert_eq!(replay(&mut client, &old_begin).status, INVALID_HANDLE);

    let mut next = manager.reserve_active_driver_service(PATH).unwrap();
    query(&mut manager, &mut next, &mut client);
    exchange(
        &mut manager,
        &mut next,
        &mut client,
        CmSnapshotOperation::Begin,
    )
    .unwrap();
    let old = CmRetainedSnapshotRequest::from_bytes(&old_begin).unwrap();
    let new = CmRetainedSnapshotRequest::from_bytes(&client.backend.last_begin).unwrap();
    assert_eq!(old.request_slot, new.request_slot);
    assert_eq!(
        old.request_generation.checked_add(1),
        Some(new.request_generation)
    );
    assert_eq!(next.outcome_status(), Some(STATUS_SUCCESS));
    abandon(&mut manager, &mut next, &mut client);
}

#[test]
fn acknowledged_stale_generation_is_unpublished_and_releases_its_local_slot() {
    let mut client = client(1);
    let mut manager = CmSnapshotAttempts::new();
    let mut old = manager.reserve_active_driver_service(PATH).unwrap();
    query(&mut manager, &mut old, &mut client);
    exchange(
        &mut manager,
        &mut old,
        &mut client,
        CmSnapshotOperation::Begin,
    )
    .unwrap();
    while !old.is_complete() {
        exchange(
            &mut manager,
            &mut old,
            &mut client,
            CmSnapshotOperation::Pull,
        )
        .unwrap();
    }
    let old_begin = client.backend.last_begin.clone();
    let current_generation = client
        .import_system_hive(&image(r"system32\drivers\replacement.sys", 2))
        .unwrap();
    assert_eq!(current_generation, 2);
    exchange(
        &mut manager,
        &mut old,
        &mut client,
        CmSnapshotOperation::Acknowledge,
    )
    .unwrap();
    assert_eq!(
        manager.take_active_driver_service(&mut old, current_generation),
        Err(NOT_READY)
    );
    assert!(!old.is_transferred());
    manager.abandon(&mut old).unwrap();
    manager.release(&mut old).unwrap();
    assert_eq!(replay(&mut client, &old_begin).status, INVALID_HANDLE);

    let mut fresh = manager.reserve_active_driver_service(PATH).unwrap();
    query(&mut manager, &mut fresh, &mut client);
    exchange(
        &mut manager,
        &mut fresh,
        &mut client,
        CmSnapshotOperation::Begin,
    )
    .unwrap();
    while !fresh.is_complete() {
        exchange(
            &mut manager,
            &mut fresh,
            &mut client,
            CmSnapshotOperation::Pull,
        )
        .unwrap();
    }
    exchange(
        &mut manager,
        &mut fresh,
        &mut client,
        CmSnapshotOperation::Acknowledge,
    )
    .unwrap();
    let result = manager
        .take_active_driver_service(&mut fresh, current_generation)
        .unwrap();
    assert_eq!(result.mount_generation, current_generation);
    assert_eq!(result.binding.image_path, r"system32\drivers\replacement.sys");
    assert_eq!(result.binding.devnodes.len(), 2);
    manager.release(&mut fresh).unwrap();
}
