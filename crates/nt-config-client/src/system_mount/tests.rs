use super::*;
use crate::{SystemHiveMutation, STATUS_DEVICE_BUSY, STATUS_DEVICE_NOT_READY};
use alloc::{rc::Rc, vec::Vec};
use core::num::NonZeroU32;
use nt_config_abi::CmReply;
use nt_config_server::{CmIdentitySource, CmServer};
use nt_hive_core::{decode_image, encode_image, Hive, HiveKind, RegistryValueType};

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
    crate::tests::secure_fixture_hive(&mut hive);
    hive.finish_clean_import();
    encode_image(&hive)
}

#[test]
fn restored_system_wal_fold_prepares_the_exact_clean_cm_generation() {
    let original = image();
    let original_hive = decode_image(&original).unwrap();
    let mut client = client(source());
    assert_eq!(client.import_system_hive(&original), Ok(1));
    assert_eq!(client.prepare_system_hive_checkpoint(1), Ok(None));

    let prepared = client.prepare_system_hive_checkpoint_for_restored_wal(1).unwrap();
    let folded = decode_image(&prepared.image).unwrap();
    assert_eq!(prepared.mount_generation, 1);
    assert_eq!(prepared.hive_sequence, original_hive.sequence);
    assert_eq!(folded.sequence, original_hive.sequence);
    assert_eq!(prepared.image_generation, original_hive.generation + 1);
    assert_eq!(folded.generation, prepared.image_generation);
    assert!(folded.open_key(r"ControlSet001\Services\Stable").is_some());

    // The same token excludes a new checkpoint or mutation until the image is durable.
    assert_eq!(client.prepare_system_hive_checkpoint(1), Err(STATUS_DEVICE_BUSY));
    assert_eq!(client.prepare_system_hive_checkpoint_for_restored_wal(2), Err(STALE));
    // The local fixture stands in for the paired durable publication before this ACK.
    client.acknowledge_system_hive_checkpoint(&prepared).unwrap();
    client.acknowledge_system_hive_checkpoint(&prepared).unwrap();
    assert_eq!(client.prepare_system_hive_checkpoint(1), Ok(None));
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
    assert_eq!(prepared.mount(), first.mount());
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
fn leased_key_revalidation_accepts_new_revision_only_on_the_same_mount() {
    let mut client = client(source());
    client.import_system_hive(&image()).unwrap();
    let first = client.query_system_hive_mount(1).unwrap();
    let path = r"\Registry\Machine\System\ControlSet001\Services\Stable";
    let lease = crate::retained_test_keys::open(&mut client, path).lease;
    let prepared = client.prepare_system_hive_mutation(1, &[
        SystemHiveMutation::SetValue {
            path,
            name: "Start",
            value_type: RegistryValueType::Dword as u32,
            data: &2u32.to_le_bytes(),
        },
    ]).unwrap();
    assert_eq!(client.publish_system_hive_mutation(&prepared).unwrap().generation, 2);

    assert_eq!(
        client.query_leased_system_hive_key_at_exact_mount(lease, first.mount(), 1),
        Err(STATUS_DEVICE_BUSY),
    );
    let rebased = client.query_leased_system_hive_key_at_exact_mount(
        lease, first.mount(), 2,
    ).unwrap();
    assert_eq!(rebased.mount_generation, 2);
    assert_eq!(rebased.path.to_ascii_lowercase(), path.to_ascii_lowercase());

    assert_eq!(client.import_system_hive(&image()), Ok(3));
    let replacement = crate::retained_test_keys::open(&mut client, path).lease;
    assert_eq!(
        client.query_leased_system_hive_key_at_exact_mount(replacement, first.mount(), 3),
        Err(STALE),
    );
}

#[test]
fn hive_log_sequence_observation_requires_exact_mount_and_published_generation() {
    let image = image();
    let initial_sequence = decode_image(&image).unwrap().sequence;
    let mut client = client(source());
    assert_eq!(client.import_system_hive(&image), Ok(1));
    let mount = client.query_system_hive_mount(1).unwrap().mount();
    assert_eq!(
        client.query_system_hive_sequence_at_mount(mount, 1),
        Ok(initial_sequence),
    );

    let path = r"\Registry\Machine\System\ControlSet001\Services\Stable";
    let prepared = client.prepare_system_hive_mutation(1, &[
        SystemHiveMutation::SetValue {
            path,
            name: "Start",
            value_type: RegistryValueType::Dword as u32,
            data: &2u32.to_le_bytes(),
        },
    ]).unwrap();
    assert!(!prepared.durable_journal().is_empty());
    assert_eq!(client.publish_system_hive_mutation(&prepared).unwrap().generation, 2);
    let written_sequence = client.query_system_hive_sequence_at_mount(mount, 2).unwrap();
    assert!(written_sequence > initial_sequence);
    assert_eq!(client.query_system_hive_sequence_at_mount(mount, 1), Err(STALE));

    let unchanged = client.prepare_system_hive_mutation(2, &[
        SystemHiveMutation::CreateKey { path },
    ]).unwrap();
    assert!(unchanged.durable_journal().is_empty());
    assert_eq!(client.publish_system_hive_mutation(&unchanged).unwrap().generation, 3);
    assert_eq!(
        client.query_system_hive_sequence_at_mount(mount, 3),
        Ok(written_sequence),
        "an empty journal advances CM generation without consuming an HLR1 sequence",
    );

    assert_eq!(client.import_system_hive(&image), Ok(4));
    assert_eq!(client.query_system_hive_sequence_at_mount(mount, 4), Err(STALE));
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

#[test]
fn explicit_preparation_never_rediscovers_a_foreign_mount() {
    let source = source();
    let mut first = client(source.clone());
    let mut second = client(source);
    first.import_system_hive(&image()).unwrap();
    second.import_system_hive(&image()).unwrap();
    let first_mount = first.query_system_hive_mount(1).unwrap().mount();
    let second_mount = second.query_system_hive_mount(1).unwrap().mount();
    let mutations = [SystemHiveMutation::CreateKey {
        path: r"\Registry\Machine\System\ControlSet001\Services\Child",
    }];
    assert_eq!(
        second.prepare_system_hive_mutation_for_mount(first_mount, 1, &mutations),
        Err(0xC000_0008u32 as i32),
    );
    let prepared = second
        .prepare_system_hive_mutation_for_mount(second_mount, 1, &mutations)
        .unwrap();
    assert_eq!(prepared.mount(), second_mount);
    // A token admitted on this mount cannot publish on another service at the same generation.
    assert!(first.publish_system_hive_mutation(&prepared).is_err());
    assert_eq!(
        second
            .publish_system_hive_mutation(&prepared)
            .unwrap()
            .generation,
        2
    );
}

struct ReplaceAfterObservation {
    active: CmServer,
    replacement: Option<CmServer>,
}

impl Backend for ReplaceAfterObservation {
    fn call(&mut self, opcode: u16, input: &[u8], output: &mut [u8]) -> CmReply {
        let response = self.active.dispatch(opcode, input, output);
        if opcode == opcode::CM_OP_QUERY_SYSTEM_HIVE_MOUNT {
            if let Some(replacement) = self.replacement.take() {
                self.active = replacement;
            }
        }
        response
    }
}

#[test]
fn replacement_between_discovery_and_begin_cannot_acquire_a_writer() {
    let source = source();
    let mut first = client(source.clone());
    let mut second = client(source);
    first.import_system_hive(&image()).unwrap();
    second.import_system_hive(&image()).unwrap();
    let new_mount = second.query_system_hive_mount(1).unwrap().mount();
    let mut client = ConfigClient::new(ReplaceAfterObservation {
        active: first.backend.0,
        replacement: Some(second.backend.0),
    });
    let mutations = [SystemHiveMutation::CreateKey {
        path: r"\Registry\Machine\System\ControlSet001\Services\Child",
    }];
    assert_eq!(
        client.prepare_system_hive_mutation(1, &mutations),
        Err(0xC000_0008u32 as i32),
    );
    // Rejected stale admission left the replacement's writer available for a fresh operation.
    let prepared = client
        .prepare_system_hive_mutation_for_mount(new_mount, 1, &mutations)
        .unwrap();
    assert_eq!(prepared.mount(), new_mount);
    assert_eq!(
        client
            .publish_system_hive_mutation(&prepared)
            .unwrap()
            .generation,
        2
    );
}
