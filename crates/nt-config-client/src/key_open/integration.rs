use super::*;
use core::num::NonZeroU32;
use nt_config_server::CmServer;
use nt_hive_core::{encode_image, Hive, HiveKind};

const PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Services\Device";
const INVALID_HANDLE: i32 = 0xc000_0008u32 as i32;
const NOT_FOUND: i32 = 0xc000_0034u32 as i32;

#[derive(Clone, Copy)]
enum Corrupt {
    Lose(u16),
    Path,
}

struct Direct {
    server: CmServer,
    corrupt: Option<Corrupt>,
    acquired: Vec<u64>,
}

impl Backend for Direct {
    fn call(&mut self, opcode: u16, input: &[u8], output: &mut [u8]) -> CmReply {
        let reply = self.server.dispatch(opcode, input, output);
        if opcode != opcode::CM_OP_SYSTEM_HIVE_KEY_OPEN {
            return reply;
        }
        let request = CmHiveKeyOpenRequest::from_bytes(input).unwrap();
        if request.operation == operation::BEGIN && reply.status == STATUS_SUCCESS {
            let body = CmHiveKeyOpenReply::from_bytes(output).unwrap();
            if body.lease_token != 0 {
                self.acquired.push(body.lease_token);
            }
        }
        match self.corrupt {
            Some(Corrupt::Lose(op)) if op == request.operation => {
                self.corrupt = None;
                output.fill(0);
                CmReply {
                    status: STATUS_DEVICE_NOT_READY,
                    information: 0,
                    detail0: 0,
                    detail1: 0,
                }
            }
            Some(Corrupt::Path) if request.operation == operation::BEGIN => {
                self.corrupt = None;
                output[CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES] = 0xff;
                reply
            }
            _ => reply,
        }
    }
}

fn image(with_device: bool) -> Vec<u8> {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    hive.create_key("ControlSet001\\Services");
    if with_device {
        hive.create_key("ControlSet001\\Services\\Device");
    }
    hive.finish_clean_import();
    encode_image(&hive)
}

fn client(with_device: bool) -> ConfigClient<Direct> {
    let mut client = ConfigClient::new(Direct {
        server: CmServer::new_for_incarnation(NonZeroU32::MIN),
        corrupt: None,
        acquired: Vec::new(),
    });
    client.import_system_hive(&image(with_device)).unwrap();
    client
}

fn exchange(
    manager: &SystemHiveKeyOpenAttempts,
    attempt: &mut SystemHiveKeyOpenAttempt,
    client: &mut ConfigClient<Direct>,
    operation: SystemHiveKeyOpenOperation,
) -> Result<(), i32> {
    let mut ticket = manager.begin_exchange(attempt, operation)?;
    let response = client.exchange_system_hive_key_open(&ticket);
    manager.complete_exchange(attempt, &mut ticket, response)
}

fn close_owned(
    manager: &SystemHiveKeyOpenAttempts,
    attempt: &mut SystemHiveKeyOpenAttempt,
    client: &mut ConfigClient<Direct>,
) {
    let receipt = client
        .prepare_system_hive_key_close(attempt.known_lease().unwrap())
        .unwrap();
    manager.record_close_receipt(attempt, receipt).unwrap();
    let acknowledged = client.acknowledge_system_hive_key_close(receipt).unwrap();
    manager.mark_lease_closed(attempt, acknowledged).unwrap();
}

#[test]
fn real_server_lost_open_and_ack_replies_transfer_exactly_one_lease() {
    let mut client = client(true);
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut attempt = manager.reserve(PATH).unwrap();
    exchange(
        &manager,
        &mut attempt,
        &mut client,
        SystemHiveKeyOpenOperation::Query,
    )
    .unwrap();
    client.backend.corrupt = Some(Corrupt::Lose(operation::BEGIN));
    assert_eq!(
        exchange(
            &manager,
            &mut attempt,
            &mut client,
            SystemHiveKeyOpenOperation::Begin
        ),
        Err(STATUS_DEVICE_NOT_READY)
    );
    assert!(attempt.known_lease().is_none());
    assert!(manager.release(&mut attempt).is_err());
    exchange(
        &manager,
        &mut attempt,
        &mut client,
        SystemHiveKeyOpenOperation::Begin,
    )
    .unwrap();
    assert_eq!(client.backend.acquired.len(), 2);
    assert_eq!(client.backend.acquired[0], client.backend.acquired[1]);
    client.backend.corrupt = Some(Corrupt::Lose(operation::ACKNOWLEDGE));
    assert!(exchange(
        &manager,
        &mut attempt,
        &mut client,
        SystemHiveKeyOpenOperation::Acknowledge
    )
    .is_err());
    exchange(
        &manager,
        &mut attempt,
        &mut client,
        SystemHiveKeyOpenOperation::Acknowledge,
    )
    .unwrap();
    let opened = manager.take_validated(&mut attempt, 1).unwrap();
    manager.release(&mut attempt).unwrap();
    assert_eq!(opened.lease.token, client.backend.acquired[0]);
    assert_eq!(
        opened.physical_path,
        r"\Registry\Machine\System\ControlSet001\Services\Device"
    );
    assert!(client
        .query_leased_system_hive_key_information(opened.lease)
        .is_ok());
    let receipt = client.prepare_system_hive_key_close(opened.lease).unwrap();
    client.acknowledge_system_hive_key_close(receipt).unwrap();
}

#[test]
fn real_server_malformed_path_closes_known_lease_before_open_ack() {
    let mut client = client(true);
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut attempt = manager.reserve(PATH).unwrap();
    exchange(
        &manager,
        &mut attempt,
        &mut client,
        SystemHiveKeyOpenOperation::Query,
    )
    .unwrap();
    client.backend.corrupt = Some(Corrupt::Path);
    assert_eq!(
        exchange(
            &manager,
            &mut attempt,
            &mut client,
            SystemHiveKeyOpenOperation::Begin
        ),
        Err(STATUS_INVALID_PARAMETER)
    );
    let lease = attempt.known_lease().unwrap();
    assert!(manager
        .begin_exchange(&mut attempt, SystemHiveKeyOpenOperation::Acknowledge)
        .is_err());
    close_owned(&manager, &mut attempt, &mut client);
    exchange(
        &manager,
        &mut attempt,
        &mut client,
        SystemHiveKeyOpenOperation::Acknowledge,
    )
    .unwrap();
    manager.release(&mut attempt).unwrap();
    assert_eq!(
        client.query_leased_system_hive_key_information(lease),
        Err(INVALID_HANDLE)
    );
}

#[test]
fn real_server_cached_failure_does_not_become_success_after_hive_replacement() {
    let mut client = client(false);
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut attempt = manager.reserve(PATH).unwrap();
    exchange(
        &manager,
        &mut attempt,
        &mut client,
        SystemHiveKeyOpenOperation::Query,
    )
    .unwrap();
    client.backend.corrupt = Some(Corrupt::Lose(operation::BEGIN));
    assert!(exchange(
        &manager,
        &mut attempt,
        &mut client,
        SystemHiveKeyOpenOperation::Begin
    )
    .is_err());
    client.import_system_hive(&image(true)).unwrap();
    exchange(
        &manager,
        &mut attempt,
        &mut client,
        SystemHiveKeyOpenOperation::Begin,
    )
    .unwrap();
    assert_eq!(attempt.outcome_status(), Some(NOT_FOUND));
    assert!(attempt.known_lease().is_none());
    exchange(
        &manager,
        &mut attempt,
        &mut client,
        SystemHiveKeyOpenOperation::Acknowledge,
    )
    .unwrap();
    assert_eq!(manager.take_validated(&mut attempt, 2), Err(NOT_FOUND));
    manager.release(&mut attempt).unwrap();
    let mut next = manager.reserve(PATH).unwrap();
    exchange(
        &manager,
        &mut next,
        &mut client,
        SystemHiveKeyOpenOperation::Query,
    )
    .unwrap();
    exchange(
        &manager,
        &mut next,
        &mut client,
        SystemHiveKeyOpenOperation::Begin,
    )
    .unwrap();
    close_owned(&manager, &mut next, &mut client);
    exchange(
        &manager,
        &mut next,
        &mut client,
        SystemHiveKeyOpenOperation::Acknowledge,
    )
    .unwrap();
    manager.release(&mut next).unwrap();
}

#[test]
fn real_server_query_only_cancellation_does_not_skip_slot_generation() {
    let mut client = client(true);
    let mut manager = SystemHiveKeyOpenAttempts::new();
    for _ in 0..3 {
        let mut cancelled = manager.reserve(PATH).unwrap();
        exchange(
            &manager,
            &mut cancelled,
            &mut client,
            SystemHiveKeyOpenOperation::Query,
        )
        .unwrap();
        manager.release(&mut cancelled).unwrap();
    }
    let mut attempt = manager.reserve(PATH).unwrap();
    exchange(
        &manager,
        &mut attempt,
        &mut client,
        SystemHiveKeyOpenOperation::Query,
    )
    .unwrap();
    exchange(
        &manager,
        &mut attempt,
        &mut client,
        SystemHiveKeyOpenOperation::Begin,
    )
    .unwrap();
    close_owned(&manager, &mut attempt, &mut client);
    exchange(
        &manager,
        &mut attempt,
        &mut client,
        SystemHiveKeyOpenOperation::Acknowledge,
    )
    .unwrap();
    manager.release(&mut attempt).unwrap();
}

#[test]
fn real_server_restart_cannot_reinterpret_an_ambiguous_open_request() {
    let mut client = client(true);
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut attempt = manager.reserve(PATH).unwrap();
    exchange(
        &manager,
        &mut attempt,
        &mut client,
        SystemHiveKeyOpenOperation::Query,
    )
    .unwrap();
    client.backend.corrupt = Some(Corrupt::Lose(operation::BEGIN));
    assert!(exchange(
        &manager,
        &mut attempt,
        &mut client,
        SystemHiveKeyOpenOperation::Begin
    )
    .is_err());
    client.backend.server = CmServer::new_for_incarnation(NonZeroU32::new(2).unwrap());
    client.import_system_hive(&image(true)).unwrap();
    assert_eq!(
        exchange(
            &manager,
            &mut attempt,
            &mut client,
            SystemHiveKeyOpenOperation::Begin
        ),
        Err(INVALID_HANDLE)
    );
    assert_eq!(client.backend.acquired.len(), 1);
    assert!(manager.release(&mut attempt).is_err());
}
