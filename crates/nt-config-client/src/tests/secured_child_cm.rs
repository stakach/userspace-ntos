use super::*;
use nt_security::{
    AccessToken, CapturedSubjectContext, KeyCreationAudit, ProcessorMode, SecurityAssignmentAudit,
    TokenStore,
};

const SERVICES: &str = r"\Registry\Machine\System\CurrentControlSet\Services";
const CHILD: &str = r"\Registry\Machine\System\CurrentControlSet\Services\Child";
const PROFILE: &str = r"\Registry\Machine\System\CurrentControlSet\Hardware Profiles\Current";
const STATUS_REVISION_MISMATCH: i32 = 0xc000_0059u32 as i32;

fn hive() -> Hive {
    let mut tokens = TokenStore::new();
    let primary = tokens.insert(AccessToken::system());
    let mut capture = CapturedSubjectContext::capture(&mut tokens, primary, None, 0).unwrap();
    let security = nt_security::assign_registry_root_security(
        &capture.resolve(&tokens).unwrap(),
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    capture.release(&mut tokens).unwrap();
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    let services = hive.create_key(r"ControlSet001\Services");
    hive.set_key_security_descriptor(services, &security);
    let config = hive.create_key(r"ControlSet001\Control\IDConfigDB");
    hive.set_dword(config, "CurrentConfig", 7);
    hive.create_key(r"ControlSet001\Hardware Profiles\0007");
    hive.create_key(r"ControlSet001\Hardware Profiles\0009");
    hive.finish_clean_import();
    hive
}

fn create<'a>(
    parent: &'a str,
    name: &'a str,
    class: Option<&'a str>,
    sd: &'a [u8],
) -> SystemHiveMutation<'a> {
    SystemHiveMutation::CreateChild {
        parent,
        name,
        class_name: class,
        descriptor: sd,
    }
}

#[test]
fn captured_parent_authorization_streams_metadata_and_publishes_one_secured_child() {
    let original = hive();
    let mut client = ConfigClient::new(Framed {
        server: fresh_server(),
    });
    client.import_system_hive(&encode_image(&original)).unwrap();
    let parent = retained_test_keys::open(&mut client, SERVICES);
    let info = client
        .query_leased_system_hive_key_information(parent.lease)
        .unwrap();
    let mut tokens = TokenStore::new();
    let primary = tokens.insert(AccessToken::admin(123));
    let mut capture = CapturedSubjectContext::capture(&mut tokens, primary, None, 0).unwrap();
    let mut audit = KeyCreationAudit::default();
    // A valid large creator DACL exercises multiple frames without exceeding class-name limits.
    let mut creator = vec![
        1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0,
    ];
    creator.extend_from_slice(&[2, 0]);
    creator.extend_from_slice(&4808u16.to_le_bytes());
    creator.extend_from_slice(&[200, 0, 0, 0]);
    for _ in 0..200 {
        creator.extend_from_slice(&[0, 2, 24, 0]);
        creator.extend_from_slice(&0xf003fu32.to_le_bytes());
        creator.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]);
    }
    let security = nt_security::prepare_key_creation_security(
        &capture.resolve(&tokens).unwrap(),
        info.security_descriptor.as_deref().unwrap(),
        Some(&creator),
        2,
        ProcessorMode::UserMode,
        &mut audit,
    )
    .unwrap();
    let class = "C".repeat(300);
    let prepared = client
        .prepare_system_hive_mutation(
            info.mount_generation,
            &[create(
                &info.path,
                "Child",
                Some(&class),
                &security.descriptor,
            )],
        )
        .unwrap();
    assert!(prepared.durable_journal.len() > CM_HIVE_MUTATION_CHUNK_BYTES);
    assert_eq!(
        client.query_system_hive_key(CHILD),
        Err(STATUS_OBJECT_NAME_NOT_FOUND)
    );
    assert_eq!(
        client.import_system_hive(&encode_image(&original)),
        Err(STATUS_DEVICE_BUSY)
    );
    assert_eq!(
        client
            .prepare_system_hive_mutation(
                info.mount_generation,
                &[create(&info.path, "Other", None, b"security")]
            )
            .unwrap_err(),
        STATUS_DEVICE_BUSY
    );
    assert_eq!(
        client
            .query_leased_system_hive_key_information(parent.lease)
            .unwrap(),
        info
    );
    let result = client.publish_system_hive_mutation(&prepared).unwrap();
    assert_eq!(result.generation, info.mount_generation + 1);
    let child = retained_test_keys::open(&mut client, CHILD);
    let child_info = client
        .query_leased_system_hive_key_information(child.lease)
        .unwrap();
    assert_eq!(child_info.class_name.as_deref(), Some(class.as_str()));
    assert_eq!(
        child_info.security_descriptor.as_deref(),
        Some(security.descriptor.as_slice())
    );
    assert!(client
        .backend
        .server
        .config()
        .registry()
        .open_key(CHILD)
        .is_some());
    let mut replayed = original.clone();
    try_replay_log(&mut replayed, &prepared.durable_journal, original.sequence).unwrap();
    let key = replayed.open_key(r"ControlSet001\Services\Child").unwrap();
    assert_eq!(
        replayed.key_security_descriptor(key),
        Some(security.descriptor.as_slice())
    );
    assert_eq!(replayed.key_class(key), Some(class.as_str()));
    retained_test_keys::close(&mut client, child.lease).unwrap();
    retained_test_keys::close(&mut client, parent.lease).unwrap();
    capture.release(&mut tokens).unwrap();
    assert_eq!(tokens.reference_count(primary), Some(1));
}

#[test]
fn changed_parent_security_rejects_stale_authorization_even_though_lease_is_live() {
    let mut client = client();
    client.import_system_hive(&encode_image(&hive())).unwrap();
    let parent = retained_test_keys::open(&mut client, SERVICES);
    let captured = client
        .query_leased_system_hive_key_information(parent.lease)
        .unwrap();
    let change = client
        .prepare_system_hive_mutation(
            captured.mount_generation,
            &[SystemHiveMutation::SetKeySecurity {
                path: &captured.path,
                descriptor: b"replacement",
            }],
        )
        .unwrap();
    client.publish_system_hive_mutation(&change).unwrap();
    let current = client
        .query_leased_system_hive_key_information(parent.lease)
        .unwrap();
    assert_eq!(parent.lease.opened_generation, 1);
    assert_eq!(current.mount_generation, 2);
    assert_eq!(
        client
            .prepare_system_hive_mutation(
                captured.mount_generation,
                &[create(&captured.path, "Child", None, b"assigned")]
            )
            .unwrap_err(),
        STATUS_REVISION_MISMATCH
    );
    assert_eq!(
        client.query_system_hive_key(CHILD),
        Err(STATUS_OBJECT_NAME_NOT_FOUND)
    );
    assert_eq!(
        client
            .query_system_hive_key(SERVICES)
            .unwrap()
            .mount_generation,
        2
    );
    retained_test_keys::close(&mut client, parent.lease).unwrap();
}

#[test]
fn failure_after_child_validation_rolls_back_and_abort_preserves_generation() {
    let mut client = client();
    client.import_system_hive(&encode_image(&hive())).unwrap();
    let parent_before = client.query_system_hive_key(SERVICES).unwrap();
    assert_eq!(
        client
            .prepare_system_hive_mutation(
                1,
                &[
                    create(SERVICES, "Child", Some("test"), b"security"),
                    SystemHiveMutation::SetValue {
                        path: r"\Registry\Machine\System\Missing",
                        name: "x",
                        value_type: 4,
                        data: &[1, 0, 0, 0]
                    },
                ]
            )
            .unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(
        client.query_system_hive_key(SERVICES).unwrap(),
        parent_before
    );
    assert_eq!(
        client.query_system_hive_key(CHILD),
        Err(STATUS_OBJECT_NAME_NOT_FOUND)
    );
    let prepared = client
        .prepare_system_hive_mutation(1, &[create(SERVICES, "Child", Some(""), b"security")])
        .unwrap();
    client.abort_prepared_system_hive_mutation(&prepared);
    assert_eq!(
        client.query_system_hive_key(SERVICES).unwrap(),
        parent_before
    );
    let prepared = client
        .prepare_system_hive_mutation(1, &[create(SERVICES, "Child", Some(""), b"security")])
        .unwrap();
    client.publish_system_hive_mutation(&prepared).unwrap();
    assert_eq!(
        client
            .query_system_hive_key(CHILD)
            .unwrap()
            .class_name
            .as_deref(),
        Some("")
    );
}

#[test]
fn invalid_child_requests_do_not_create_parents_or_replace_existing_keys() {
    let mut client = client();
    client.import_system_hive(&encode_image(&hive())).unwrap();
    for (parent, name, sd, status) in [
        (SERVICES, "", &b"s"[..], STATUS_INVALID_PARAMETER),
        (SERVICES, "a\\b", &b"s"[..], STATUS_INVALID_PARAMETER),
        (SERVICES, "Child", &b""[..], STATUS_INVALID_PARAMETER),
        (
            r"\Registry\Machine\System\Missing",
            "Child",
            &b"s"[..],
            STATUS_OBJECT_NAME_NOT_FOUND,
        ),
        (
            r"\Registry\Machine\System\CurrentControlSet",
            "Services",
            &b"s"[..],
            0xc0000035u32 as i32,
        ),
    ] {
        assert_eq!(
            client
                .prepare_system_hive_mutation(1, &[create(parent, name, None, sd)])
                .unwrap_err(),
            status
        );
        assert_eq!(
            client
                .query_system_hive_key(SERVICES)
                .unwrap()
                .mount_generation,
            1
        );
        assert_eq!(
            client.query_system_hive_key(CHILD),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }
}

#[test]
fn prepared_profile_child_logs_physical_parent_and_torn_recovery_never_exposes_child() {
    let original = hive();
    let mut client = client();
    client.import_system_hive(&encode_image(&original)).unwrap();
    let prepared = client
        .prepare_system_hive_mutation(1, &[create(PROFILE, "Child", None, b"assigned")])
        .unwrap();
    for end in 0..prepared.durable_journal.len() {
        let mut replayed = original.clone();
        try_replay_log(
            &mut replayed,
            &prepared.durable_journal[..end],
            original.sequence,
        )
        .unwrap();
        assert_eq!(encode_image(&replayed), encode_image(&original));
    }
    let mut replayed = original.clone();
    try_replay_log(&mut replayed, &prepared.durable_journal, original.sequence).unwrap();
    assert!(replayed
        .open_key(r"ControlSet001\Hardware Profiles\0007\Child")
        .is_some());
    assert!(replayed
        .open_key(r"ControlSet001\Hardware Profiles\Current")
        .is_none());
    assert!(replayed
        .open_key(r"ControlSet001\Hardware Profiles\0009\Child")
        .is_none());
    client.publish_system_hive_mutation(&prepared).unwrap();
    assert_eq!(
        client
            .query_system_hive_key(&format!(r"{PROFILE}\Child"))
            .unwrap()
            .security_descriptor
            .as_deref(),
        Some(&b"assigned"[..])
    );
}

#[test]
fn complete_physical_path_limit_is_checked_after_alias_resolution() {
    let mut client = client();
    client.import_system_hive(&encode_image(&hive())).unwrap();
    let physical = client
        .resolve_system_hive_path(SERVICES)
        .unwrap()
        .physical_path;
    let units = CM_MAX_HIVE_PATH_UNITS - physical.encode_utf16().count() - 1;
    let too_long = "x".repeat(units + 1);
    assert_eq!(
        client
            .prepare_system_hive_mutation(1, &[create(SERVICES, &too_long, None, b"security")])
            .unwrap_err(),
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        client
            .query_system_hive_key(SERVICES)
            .unwrap()
            .mount_generation,
        1
    );
    let mut at_limit = "\u{1f600}".repeat(units / 2);
    if units % 2 != 0 {
        at_limit.push('x');
    }
    let prepared = client
        .prepare_system_hive_mutation(1, &[create(SERVICES, &at_limit, None, b"security")])
        .unwrap();
    client.publish_system_hive_mutation(&prepared).unwrap();
    let path = format!(r"{physical}\{at_limit}");
    assert_eq!(path.encode_utf16().count(), CM_MAX_HIVE_PATH_UNITS);
    let opened = retained_test_keys::open(&mut client, &path);
    assert_eq!(
        client
            .query_leased_system_hive_key_information(opened.lease)
            .unwrap()
            .security_descriptor
            .as_deref(),
        Some(&b"security"[..])
    );
    retained_test_keys::close(&mut client, opened.lease).unwrap();
}
