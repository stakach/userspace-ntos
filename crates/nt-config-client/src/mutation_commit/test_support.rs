use super::*;
use crate::SystemHiveMutation;
use alloc::vec::Vec;
use core::num::NonZeroU32;
use nt_config_abi::CmReply;
use nt_config_server::CmServer;
use nt_hive_core::{encode_image, Hive, HiveKind};

pub(crate) const PARENT: &str = r"\Registry\Machine\System\CurrentControlSet\Services";
pub(crate) const BUSY: i32 = 0x8000_0011u32 as i32;
pub(crate) const INVALID_HANDLE: i32 = 0xc000_0008u32 as i32;

pub(crate) struct Direct {
    pub(crate) server: CmServer,
    pub(crate) corrupt: Option<(u16, u8)>,
    pub(crate) calls: usize,
}

impl Backend for Direct {
    fn call(&mut self, opcode: u16, input: &[u8], output: &mut [u8]) -> CmReply {
        self.calls += 1;
        let mut response = self.server.dispatch(opcode, input, output);
        if opcode != opcode::CM_OP_SYSTEM_HIVE_MUTATION_COMMIT {
            return response;
        }
        let request = CmHiveMutationCommitRequest::from_bytes(input).unwrap();
        if let Some((operation, corruption)) = self.corrupt {
            if operation != request.operation {
                return response;
            }
            self.corrupt = None;
            // Fault injection happens AFTER the real server side effect.
            assert_eq!(response.status, STATUS_SUCCESS);
            if corruption == 17 {
                panic!("injected unwind after server effect");
            } else if corruption == 0 {
                response.status = STATUS_INVALID_PARAMETER;
            } else if corruption == 1 {
                response.information -= 1;
            } else {
                let mut body = CmHiveMutationCommitReply::from_bytes(output).unwrap();
                match corruption {
                    2 => body.abi_size -= 1,
                    3 => body.abi_version += 1,
                    4 => body.reserved = 1,
                    5 => body.mutation_token ^= 1,
                    6 => body.expected_generation ^= 1,
                    7 => body.next_generation ^= 1,
                    8 => body.semantic_journal_len ^= 1,
                    9 => body.has_pending_device_action = 2,
                    10 => body.receipt_bank = 0,
                    11 => body.receipt_generation = 0,
                    12 => body.disposition = 99,
                    13 => response.detail0 ^= 1,
                    14 => response.detail1 ^= 1,
                    15 => {
                        body.receipt_bank ^= 1;
                        response.detail0 = body.receipt_bank;
                    }
                    16 => {
                        body.receipt_generation += 1;
                        response.detail1 = body.receipt_generation;
                    }
                    18 => body.disposition = disposition::RETAINED,
                    19 => body.disposition = disposition::ABORTED,
                    _ => unreachable!(),
                }
                output.copy_from_slice(body.as_bytes());
            }
        }
        response
    }
}

pub(crate) fn image() -> Vec<u8> {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    hive.create_key(r"ControlSet001\Services");
    hive.finish_clean_import();
    encode_image(&hive)
}

pub(crate) fn client(incarnation: u32) -> ConfigClient<Direct> {
    let mut client = ConfigClient::new(Direct {
        server: CmServer::new_for_incarnation(NonZeroU32::new(incarnation).unwrap()),
        corrupt: None,
        calls: 0,
    });
    client.import_system_hive(&image()).unwrap();
    client
}

pub(crate) fn prepare(
    client: &mut ConfigClient<Direct>,
    generation: u64,
    name: &str,
) -> PreparedSystemHiveMutation {
    client
        .prepare_system_hive_mutation(
            generation,
            &[SystemHiveMutation::CreateChild {
                parent: PARENT,
                name,
                class_name: Some("class"),
                descriptor: b"security",
            }],
        )
        .unwrap()
}
