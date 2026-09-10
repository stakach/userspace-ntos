use super::*;
use crate::{SystemHiveMutation, STATUS_DEVICE_NOT_READY};
use alloc::{rc::Rc, vec::Vec};
use core::num::NonZeroU32;
use nt_config_abi::CmReply;
use nt_config_server::{CmIdentitySource, CmServer};
use nt_hive_core::{encode_image, Hive, HiveKind, RegistryValueType};

const STALE: i32 = 0xC000_0059u32 as i32;

struct Local(CmServer);
impl Backend for Local {
    fn call(&mut self, opcode: u16, input: &[u8], output: &mut [u8]) -> CmReply {
        self.0.dispatch(opcode, input, output)
    }
}

fn client(source: Rc<CmIdentitySource>) -> ConfigClient<Local> {
    ConfigClient::new(Local(CmServer::new_with_identity_source(source)))
}

fn source() -> Rc<CmIdentitySource> {
    Rc::new(CmIdentitySource::new(NonZeroU32::new(712).unwrap()))
}

fn image() -> Vec<u8> {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    hive.create_key(r"ControlSet001\Services\Stable");
    hive.finish_clean_import();
    encode_image(&hive)
}

#[test]
fn observation_requires_an_existing_exact_generation() {
    let mut client = client(source());
    assert_eq!(
        client.query_system_hive_mount(1),
        Err(STATUS_DEVICE_NOT_READY)
    );
    assert_eq!(client.import_system_hive(&image()), Ok(1));
    let first = client.query_system_hive_mount(1).unwrap();
    assert_eq!(first.generation(), 1);
    assert_eq!(
        client.validate_system_hive_mount(first.mount(), 1),
        Ok(first)
    );
    assert_eq!(client.query_system_hive_mount(2), Err(STALE));
    assert_eq!(
        client.validate_system_hive_mount(first.mount(), 2),
        Err(STALE)
    );
}

#[test]
fn remount_and_same_generation_reconstruction_cannot_reuse_identity() {
    let source = source();
    let mut first_client = client(source.clone());
    first_client.import_system_hive(&image()).unwrap();
    let first = first_client.query_system_hive_mount(1).unwrap();
    assert_eq!(first_client.import_system_hive(&image()), Ok(2));
    let remounted = first_client.query_system_hive_mount(2).unwrap();
    assert_ne!(remounted.mount(), first.mount());
    assert_eq!(
        first_client.validate_system_hive_mount(first.mount(), 2),
        Err(STALE)
    );

    let mut replacement = client(source);
    replacement.import_system_hive(&image()).unwrap();
    let reconstructed = replacement.query_system_hive_mount(1).unwrap();
    assert_ne!(reconstructed.mount(), first.mount());
    assert_ne!(reconstructed.mount(), remounted.mount());
    assert_eq!(
        replacement.validate_system_hive_mount(first.mount(), 1),
        Err(STALE)
    );
}

#[test]
fn ordinary_publication_and_checkpoint_preserve_mount_identity() {
    let mut client = client(source());
    client.import_system_hive(&image()).unwrap();
    let first = client.query_system_hive_mount(1).unwrap();
    let prepared = client
        .prepare_system_hive_mutation(
            1,
            &[SystemHiveMutation::SetValue {
                path: r"\Registry\Machine\System\ControlSet001\Services\Stable",
                name: "Value",
                value_type: RegistryValueType::Dword as u32,
                data: &7u32.to_le_bytes(),
            }],
        )
        .unwrap();
    assert_eq!(
        client.validate_system_hive_mount(first.mount(), 1),
        Ok(first)
    );
    assert_eq!(
        client
            .publish_system_hive_mutation(&prepared)
            .unwrap()
            .generation,
        2
    );
    let second = client.validate_system_hive_mount(first.mount(), 2).unwrap();
    assert_eq!(second.mount(), first.mount());
    assert_eq!(second.generation(), 2);
    assert_eq!(
        client.validate_system_hive_mount(first.mount(), 1),
        Err(STALE)
    );

    let checkpoint = client.prepare_system_hive_checkpoint(2).unwrap().unwrap();
    assert_eq!(
        client.validate_system_hive_mount(first.mount(), 2),
        Ok(second)
    );
    // The in-process CM protocol fixture does not claim storage durability.
    client
        .acknowledge_system_hive_checkpoint(&checkpoint)
        .unwrap();
    assert_eq!(
        client.validate_system_hive_mount(first.mount(), 2),
        Ok(second)
    );
}

#[test]
fn failed_import_does_not_replace_a_mount() {
    let mut client = client(source());
    client.import_system_hive(&image()).unwrap();
    let first = client.query_system_hive_mount(1).unwrap();
    assert!(client.import_system_hive(b"not a hive").is_err());
    assert_eq!(
        client.validate_system_hive_mount(first.mount(), 1),
        Ok(first)
    );
}

struct ReplyBackend {
    response: CmReply,
    calls: usize,
    last: Option<CmSystemHiveMountRequest>,
}
impl Backend for ReplyBackend {
    fn call(&mut self, opcode: u16, input: &[u8], output: &mut [u8]) -> CmReply {
        assert_eq!(opcode, opcode::CM_OP_QUERY_SYSTEM_HIVE_MOUNT);
        assert!(output.is_empty());
        assert_eq!(input.len(), 24);
        self.calls += 1;
        self.last = CmSystemHiveMountRequest::from_bytes(input);
        self.response
    }
}

fn replying() -> ConfigClient<ReplyBackend> {
    ConfigClient::new(ReplyBackend {
        response: CmReply {
            status: 0,
            information: 0,
            detail0: 3,
            detail1: 9,
        },
        calls: 0,
        last: None,
    })
}

#[test]
fn zero_generation_never_reaches_transport() {
    let mut client = replying();
    let mount = client.query_system_hive_mount(3).unwrap().mount();
    assert_eq!(
        client.query_system_hive_mount(0),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        client.validate_system_hive_mount(mount, 0),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(client.backend.calls, 1);
}

#[test]
fn exact_wire_request_distinguishes_discovery_and_revalidation() {
    let mut client = replying();
    let first = client.query_system_hive_mount(3).unwrap();
    let discovery = client.backend.last.unwrap();
    assert_eq!(
        discovery,
        CmSystemHiveMountRequest {
            abi_size: 24,
            abi_version: CM_ABI_VERSION,
            mount: hive_mount::SYSTEM,
            _reserved: 0,
            expected_generation: 3,
            expected_identity: 0,
        }
    );
    client.backend.response.detail0 = 4;
    client.validate_system_hive_mount(first.mount(), 4).unwrap();
    assert_eq!(
        client.backend.last.unwrap(),
        CmSystemHiveMountRequest {
            expected_generation: 4,
            expected_identity: 9,
            ..discovery
        }
    );
}

#[test]
fn malformed_success_never_mints_or_substitutes_identity() {
    for field in 0..4 {
        let mut client = replying();
        let first = client.query_system_hive_mount(3).unwrap();
        match field {
            0 => client.backend.response.information = 1,
            1 => client.backend.response.detail0 = 2,
            2 => client.backend.response.detail1 = 0,
            3 => client.backend.response.detail1 = 10,
            _ => unreachable!(),
        }
        assert_eq!(
            client.validate_system_hive_mount(first.mount(), 3),
            Err(STATUS_INVALID_PARAMETER)
        );
        if field != 3 {
            assert_eq!(
                client.query_system_hive_mount(3),
                Err(STATUS_INVALID_PARAMETER)
            );
        }
    }
}

#[test]
fn failure_and_pending_replies_never_publish_mount_state() {
    for status in [STALE, STATUS_DEVICE_NOT_READY, 0x103] {
        let mut client = replying();
        let first = client.query_system_hive_mount(3).unwrap();
        client.backend.response.status = status;
        assert_eq!(client.query_system_hive_mount(3), Err(status));
        assert_eq!(
            client.validate_system_hive_mount(first.mount(), 3),
            Err(status)
        );
    }
}
