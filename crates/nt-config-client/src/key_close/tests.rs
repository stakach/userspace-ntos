use super::*;
use core::num::NonZeroU32;
use nt_config_abi::CmReply;
use nt_config_server::CmServer;
use nt_hive_core::{encode_image, Hive, HiveKind};

const INVALID_HANDLE: i32 = 0xc000_0008u32 as i32;

struct Direct {
    server: CmServer,
    corrupt: Option<(u16, u8)>,
    calls: usize,
}

impl Backend for Direct {
    fn call(&mut self, opcode: u16, input: &[u8], output: &mut [u8]) -> CmReply {
        self.calls += 1;
        let mut response = self.server.dispatch(opcode, input, output);
        if opcode != opcode::CM_OP_SYSTEM_HIVE_KEY_CLOSE {
            return response;
        }
        let request = CmHiveKeyCloseRequest::from_bytes(input).unwrap();
        if let Some((operation, corruption)) = self.corrupt {
            if operation != request.operation {
                return response;
            }
            self.corrupt = None;
            if corruption == 0 {
                response.status = STATUS_INVALID_PARAMETER;
            } else if corruption == 1 {
                response.information -= 1;
            } else {
                let mut body = CmHiveKeyCloseReply::from_bytes(output).unwrap();
                match corruption {
                    2 => body.abi_size -= 1,
                    3 => body.abi_version += 1,
                    4 => body.reserved = 1,
                    5 => body.lease_token ^= 1,
                    6 => body.receipt_bank = 0,
                    7 => body.receipt_generation = 0,
                    8 => body.disposition = 99,
                    9 => response.detail1 ^= 1,
                    _ => unreachable!(),
                }
                output.copy_from_slice(body.as_bytes());
            }
        }
        response
    }
}

fn image() -> alloc::vec::Vec<u8> {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    hive.create_key("ControlSet001\\Services\\Device");
    hive.finish_clean_import();
    encode_image(&hive)
}

fn client() -> ConfigClient<Direct> {
    client_for_incarnation(NonZeroU32::MIN)
}

fn client_for_incarnation(incarnation: NonZeroU32) -> ConfigClient<Direct> {
    let mut client = ConfigClient::new(Direct {
        server: CmServer::new_for_incarnation(incarnation),
        corrupt: None,
        calls: 0,
    });
    client.import_system_hive(&image()).unwrap();
    client
}

fn open(client: &mut ConfigClient<Direct>) -> SystemHiveKeyLease {
    client
        .open_system_hive_key(r"\Registry\Machine\System\CurrentControlSet\Services\Device")
        .unwrap()
}

#[test]
fn uncertain_prepare_and_ack_replies_recover_without_invalid_handle_fallback() {
    let mut client = client();
    let lease = open(&mut client);
    client.backend.corrupt = Some((operation::PREPARE, 0));
    assert_eq!(
        client.prepare_system_hive_key_close(lease),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        client.query_leased_system_hive_key_information(lease),
        Err(INVALID_HANDLE)
    );
    let receipt = client.prepare_system_hive_key_close(lease).unwrap();
    assert_eq!(receipt.lease_token(), lease.token);
    assert_eq!(client.prepare_system_hive_key_close(lease), Ok(receipt));
    client.backend.corrupt = Some((operation::ACKNOWLEDGE, 1));
    assert_eq!(
        client
            .acknowledge_system_hive_key_close(receipt)
            .map(SystemHiveKeyCloseAcknowledgement::disposition),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        client
            .acknowledge_system_hive_key_close(receipt)
            .map(SystemHiveKeyCloseAcknowledgement::disposition),
        Ok(SystemHiveKeyCloseAcknowledgementDisposition::AlreadyAcknowledged)
    );
    assert_eq!(
        client.prepare_system_hive_key_close(lease),
        Err(INVALID_HANDLE)
    );
    let next = open(&mut client);
    let next = client.prepare_system_hive_key_close(next).unwrap();
    assert_eq!(next.slot, receipt.slot);
    assert_eq!(next.generation, receipt.generation + 1);
    assert_eq!(
        client
            .acknowledge_system_hive_key_close(receipt)
            .map(SystemHiveKeyCloseAcknowledgement::disposition),
        Ok(SystemHiveKeyCloseAcknowledgementDisposition::AlreadyAcknowledged)
    );
    assert_eq!(
        client
            .acknowledge_system_hive_key_close(next)
            .map(SystemHiveKeyCloseAcknowledgement::disposition),
        Ok(SystemHiveKeyCloseAcknowledgementDisposition::Acknowledged)
    );
}

#[test]
fn every_malformed_success_preserves_retryable_server_receipt() {
    let mut client = client();
    let lease = open(&mut client);
    for corruption in 1..=9 {
        client.backend.corrupt = Some((operation::PREPARE, corruption));
        assert_eq!(
            client.prepare_system_hive_key_close(lease),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
    let receipt = client.prepare_system_hive_key_close(lease).unwrap();
    client
        .acknowledge_system_hive_key_close(receipt)
        .unwrap();
}

#[test]
fn replaced_mount_retains_exact_close_authority_but_not_key_access() {
    let mut client = client();
    let lease = open(&mut client);
    let legacy = open(&mut client);
    client.import_system_hive(&image()).unwrap();
    assert_eq!(
        client.query_leased_system_hive_key_information(lease),
        Err(INVALID_HANDLE)
    );
    assert_eq!(
        client.query_leased_system_hive_key_information(legacy),
        Err(INVALID_HANDLE)
    );
    assert_eq!(client.close_system_hive_key(legacy), Ok(2));
    assert_eq!(client.close_system_hive_key(legacy), Err(INVALID_HANDLE));
    assert_eq!(
        client.prepare_system_hive_key_close(legacy),
        Err(INVALID_HANDLE)
    );
    let receipt = client.prepare_system_hive_key_close(lease).unwrap();
    assert_eq!(
        client
            .acknowledge_system_hive_key_close(receipt)
            .map(SystemHiveKeyCloseAcknowledgement::disposition),
        Ok(SystemHiveKeyCloseAcknowledgementDisposition::Acknowledged)
    );
}

#[test]
fn foreign_server_lease_and_receipt_cannot_close_local_owners() {
    let mut first = client();
    let mut second = client_for_incarnation(NonZeroU32::new(2).unwrap());
    let a = open(&mut first);
    let b = open(&mut second);
    assert_ne!(a.token, b.token);
    assert_eq!(second.prepare_system_hive_key_close(a), Err(INVALID_HANDLE));
    let receipt = first.prepare_system_hive_key_close(a).unwrap();
    let local = second.prepare_system_hive_key_close(b).unwrap();
    assert_eq!(
        second
            .acknowledge_system_hive_key_close(receipt)
            .map(SystemHiveKeyCloseAcknowledgement::disposition),
        Err(INVALID_HANDLE)
    );
    assert_eq!(
        second
            .acknowledge_system_hive_key_close(local)
            .map(SystemHiveKeyCloseAcknowledgement::disposition),
        Ok(SystemHiveKeyCloseAcknowledgementDisposition::Acknowledged)
    );
    first
        .acknowledge_system_hive_key_close(receipt)
        .unwrap();
}

#[test]
fn legacy_close_and_zero_token_keep_their_original_contracts() {
    let mut client = client();
    let before = client.backend.calls;
    assert_eq!(
        client.prepare_system_hive_key_close(SystemHiveKeyLease {
            token: 0,
            opened_generation: 1,
        }),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(client.backend.calls, before);
    let lease = open(&mut client);
    assert_eq!(client.close_system_hive_key(lease), Ok(1));
    assert_eq!(
        client.prepare_system_hive_key_close(lease),
        Err(INVALID_HANDLE)
    );
}
