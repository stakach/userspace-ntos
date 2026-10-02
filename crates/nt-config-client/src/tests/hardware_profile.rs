use super::*;

const CURRENT: &str = r"\Registry\Machine\System\CurrentControlSet\Hardware Profiles\Current";
const CONFIG: &str = r"\Registry\Machine\System\CurrentControlSet\Control\IDConfigDB";
const PHYSICAL: &str = r"\Registry\Machine\System\ControlSet001\Hardware Profiles\0007";

fn hive() -> Hive {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    for control_set in ["ControlSet001", "ControlSet002"] {
        let config = hive.create_key(&format!(r"{control_set}\Control\IDConfigDB"));
        hive.set_dword(config, "CurrentConfig", 7);
        for profile in [7, 9] {
            let key = hive.create_key(&format!(r"{control_set}\Hardware Profiles\{profile:04}"));
            hive.set_dword(key, "Identity", profile);
        }
    }
    secure_fixture_hive(&mut hive);
    hive.finish_clean_import();
    hive
}

fn mutate(
    client: &mut ConfigClient<Direct>,
    generation: u64,
    mutations: &[SystemHiveMutation<'_>],
) -> PreparedSystemHiveMutation {
    let prepared = client
        .prepare_system_hive_mutation(generation, mutations)
        .unwrap();
    let outcome = client.publish_system_hive_mutation(&prepared).unwrap();
    assert_eq!(outcome.generation, prepared.next_generation);
    prepared
}

#[test]
fn mounted_alias_agrees_across_path_snapshot_and_retained_lease() {
    let mut client = client();
    client.import_system_hive(&encode_image(&hive())).unwrap();
    let resolved = client.resolve_system_hive_path(CURRENT).unwrap();
    assert_eq!(resolved.physical_path, PHYSICAL);
    let snapshot = client.query_system_hive_key(CURRENT).unwrap();
    let physical = client.query_system_hive_key(PHYSICAL).unwrap();
    assert_eq!(snapshot.values, physical.values);
    let opened = retained_test_keys::open(&mut client, CURRENT);
    assert_eq!(opened.physical_path, PHYSICAL);
    let value = client
        .query_leased_system_hive_value(opened.lease, "Identity")
        .unwrap();
    assert_eq!(value.data, 7u32.to_le_bytes());
    retained_test_keys::close(&mut client, opened.lease).unwrap();
}

#[test]
fn ordinary_current_enumerated_child_keeps_exact_relative_open_authority() {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    let config = hive.create_key(r"ControlSet001\Control\IDConfigDB");
    hive.set_dword(config, "CurrentConfig", 0);
    hive.create_key(r"ControlSet001\Control\IDConfigDB\Hardware Profiles\0000");
    let fonts = hive.create_key(r"ControlSet001\Hardware Profiles\Current\Software\Fonts");
    hive.set_dword(fonts, "LogPixels", 96);
    assert!(hive.open_key(r"ControlSet001\Hardware Profiles\0000").is_none());
    secure_fixture_hive(&mut hive);
    hive.finish_clean_import();

    let mut client = client();
    client.import_system_hive(&encode_image(&hive)).unwrap();
    let parent = retained_test_keys::open(
        &mut client,
        r"\Registry\Machine\System\ControlSet001\Hardware Profiles",
    );
    let child = client.enumerate_leased_system_hive_subkey(parent.lease, 0).unwrap();
    assert_eq!(child.name, "Current");
    assert_eq!(
        client.enumerate_leased_system_hive_subkey(parent.lease, 1),
        Err(STATUS_NO_MORE_ENTRIES)
    );

    let mut open_relative = |root, path: &str| {
        let mut manager = SystemHiveKeyOpenAttempts::new();
        let mut attempt = manager.reserve_relative(root, path).unwrap();
        for operation in [
            SystemHiveKeyOpenOperation::Query,
            SystemHiveKeyOpenOperation::Begin,
            SystemHiveKeyOpenOperation::Acknowledge,
        ] {
            let mut exchange = manager.begin_exchange(&mut attempt, operation).unwrap();
            let response = client.exchange_system_hive_key_open(&exchange);
            manager.complete_exchange(&mut attempt, &mut exchange, response).unwrap();
        }
        assert_eq!(attempt.outcome_status(), Some(0), "relative OPEN must admit the enumerated ordinary key");
        let generation = attempt.known_lease().unwrap().opened_generation;
        let opened = manager.take_validated(&mut attempt, generation).unwrap();
        manager.release(&mut attempt).unwrap();
        opened
    };
    let current = open_relative(parent.lease, &child.name);
    let fonts = open_relative(current.lease, r"Software\Fonts");
    assert_eq!(
        current.physical_path,
        r"\Registry\Machine\System\ControlSet001\Hardware Profiles\Current"
    );
    assert_eq!(
        fonts.physical_path,
        r"\Registry\Machine\System\ControlSet001\Hardware Profiles\Current\Software\Fonts"
    );
    let value = client.query_leased_system_hive_value(fonts.lease, "LogPixels").unwrap();
    assert_eq!(value.value_type, RegistryValueType::Dword as u32);
    assert_eq!(value.data, 96u32.to_le_bytes());
    let physical = retained_test_keys::open(&mut client, &fonts.physical_path);
    assert_eq!(
        client.query_leased_system_hive_key_information(fonts.lease).unwrap(),
        client.query_leased_system_hive_key_information(physical.lease).unwrap()
    );
    for lease in [physical.lease, fonts.lease, current.lease, parent.lease] {
        retained_test_keys::close(&mut client, lease).unwrap();
    }
}

#[test]
fn actual_current_link_uses_its_target_not_the_profile_selector() {
    let mut hive = hive();
    let target = r"\Registry\Machine\System\ControlSet001\Hardware Profiles\0009";
    let child = hive.create_key(r"ControlSet001\Hardware Profiles\0009\Software\Fonts");
    hive.set_dword(child, "LogPixels", 144);
    let link = hive.create_key(r"ControlSet001\Hardware Profiles\Current");
    assert!(hive.set_key_kind(link, nt_hive_core::KeyKind::SymbolicLink));
    hive.set_value(
        link,
        "SymbolicLinkValue",
        RegistryValueType::Link,
        target.encode_utf16().flat_map(u16::to_le_bytes).collect(),
    );
    secure_fixture_hive(&mut hive);
    hive.finish_clean_import();

    let mut client = client();
    client.import_system_hive(&encode_image(&hive)).unwrap();
    let opened = retained_test_keys::open(&mut client, CURRENT);
    assert_eq!(opened.physical_path, target);
    assert_eq!(
        client.query_leased_system_hive_value(opened.lease, "Identity").unwrap().data,
        9u32.to_le_bytes()
    );
    let fonts_path = format!(r"{CURRENT}\Software\Fonts");
    let fonts = retained_test_keys::open(&mut client, &fonts_path);
    assert_eq!(fonts.physical_path, format!(r"{target}\Software\Fonts"));
    let physical = retained_test_keys::open(&mut client, &fonts.physical_path);
    assert_eq!(
        client.query_leased_system_hive_key_information(fonts.lease).unwrap(),
        client.query_leased_system_hive_key_information(physical.lease).unwrap()
    );
    let selector_change = mutate(
        &mut client,
        1,
        &[SystemHiveMutation::SetValue {
            path: CONFIG,
            name: "CurrentConfig",
            value_type: RegistryValueType::Dword as u32,
            data: &0u32.to_le_bytes(),
        }],
    );
    assert_eq!(selector_change.next_generation, 2);
    assert_eq!(client.resolve_system_hive_path(CURRENT).unwrap().physical_path, target);
    assert_eq!(
        client.query_leased_system_hive_value(fonts.lease, "LogPixels").unwrap().data,
        144u32.to_le_bytes()
    );
    assert_eq!(client.query_system_hive_key(&fonts_path).unwrap().values[0].data, 144u32.to_le_bytes());
    for lease in [physical.lease, fonts.lease, opened.lease] {
        retained_test_keys::close(&mut client, lease).unwrap();
    }
}

#[test]
fn selector_write_does_not_move_alias_and_mutation_log_is_physical() {
    let mut original = hive();
    let mut client = client();
    client.import_system_hive(&encode_image(&original)).unwrap();
    let child = format!(r"{CURRENT}\Enum\PCI\Device");
    let prepared = mutate(
        &mut client,
        1,
        &[
            SystemHiveMutation::SetValue {
                path: CONFIG,
                name: "CurrentConfig",
                value_type: RegistryValueType::Dword as u32,
                data: &9u32.to_le_bytes(),
            },
            SystemHiveMutation::CreateKey { path: &child },
            SystemHiveMutation::SetValue {
                path: &child,
                name: "Marker",
                value_type: RegistryValueType::Dword as u32,
                data: &42u32.to_le_bytes(),
            },
        ],
    );
    assert_eq!(
        client
            .resolve_system_hive_path(CURRENT)
            .unwrap()
            .physical_path,
        PHYSICAL
    );
    let base = original.sequence;
    try_replay_log(&mut original, &prepared.durable_journal, base).unwrap();
    let physical_child = r"ControlSet001\Hardware Profiles\0007\Enum\PCI\Device";
    assert!(original.open_key(physical_child).is_some());
    assert!(original
        .open_key(r"ControlSet001\Hardware Profiles\Current")
        .is_none());
    assert!(original
        .open_key(r"ControlSet001\Hardware Profiles\0009\Enum")
        .is_none());
    assert_eq!(
        client.query_system_hive_key(&child).unwrap().values[0].data,
        42u32.to_le_bytes()
    );
}

#[test]
fn replacement_mount_recaptures_profile_and_invalidates_old_leases() {
    let mut hive = hive();
    let mut client = client();
    client.import_system_hive(&encode_image(&hive)).unwrap();
    let opened = retained_test_keys::open(&mut client, CURRENT);
    let config = hive.open_key(r"ControlSet001\Control\IDConfigDB").unwrap();
    hive.set_dword(config, "CurrentConfig", 9);
    assert_eq!(client.import_system_hive(&encode_image(&hive)), Ok(2));
    assert!(client
        .query_leased_system_hive_value(opened.lease, "Identity")
        .is_err());
    assert_eq!(
        client
            .resolve_system_hive_path(CURRENT)
            .unwrap()
            .physical_path,
        r"\Registry\Machine\System\ControlSet001\Hardware Profiles\0009"
    );
    retained_test_keys::close(&mut client, opened.lease).unwrap();
}

#[test]
fn unavailable_alias_without_an_ordinary_key_never_uses_a_default_profile() {
    for invalid in [
        None,
        Some((RegistryValueType::Sz, vec![7, 0, 0, 0])),
        Some((RegistryValueType::Dword, vec![7, 0, 0])),
    ] {
        let mut hive = hive();
        let config = hive.open_key(r"ControlSet001\Control\IDConfigDB").unwrap();
        hive.delete_value(config, "CurrentConfig");
        if let Some((kind, bytes)) = invalid {
            hive.set_value(config, "CurrentConfig", kind, bytes);
        }
        let mut client = client();
        assert_eq!(client.import_system_hive(&encode_image(&hive)), Ok(1));
        assert_eq!(
            client.resolve_system_hive_path(CURRENT),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            client.query_system_hive_key(CURRENT),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert!(client.query_system_hive_key(PHYSICAL).is_ok());
        assert_eq!(
            client
                .prepare_system_hive_mutation(
                    1,
                    &[SystemHiveMutation::CreateKey {
                        path: &format!(r"{CURRENT}\MustNotExist"),
                    }]
                )
                .err(),
            Some(STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }
}

#[test]
fn deleted_profile_remains_selected_without_retargeting() {
    let mut client = client();
    client.import_system_hive(&encode_image(&hive())).unwrap();
    let deletion = mutate(
        &mut client,
        1,
        &[SystemHiveMutation::DeleteKey { path: CURRENT }],
    );
    assert_eq!(deletion.next_generation, 2);
    assert_eq!(
        client
            .resolve_system_hive_path(CURRENT)
            .unwrap()
            .physical_path,
        PHYSICAL
    );
    assert_eq!(
        client.query_system_hive_key(CURRENT),
        Err(STATUS_OBJECT_NAME_NOT_FOUND)
    );
}

#[test]
fn control_set_selection_does_not_transplant_the_profile_alias() {
    let mut client = client();
    client.import_system_hive(&encode_image(&hive())).unwrap();
    let selector_change = mutate(
        &mut client,
        1,
        &[SystemHiveMutation::SetValue {
            path: r"\Registry\Machine\System\Select",
            name: "Current",
            value_type: RegistryValueType::Dword as u32,
            data: &2u32.to_le_bytes(),
        }],
    );
    assert_eq!(selector_change.next_generation, 2);
    assert_eq!(
        client.query_system_hive_key(CURRENT),
        Err(STATUS_OBJECT_NAME_NOT_FOUND)
    );
    assert_eq!(
        client
            .resolve_system_hive_path(
                r"\Registry\Machine\System\ControlSet001\Hardware Profiles\Current"
            )
            .unwrap()
            .physical_path,
        PHYSICAL
    );
}

#[test]
fn device_key_policy_resolves_through_cm_and_persists_new_parameters_security() {
    use nt_io_manager::device_registry::DeviceRegistryKeyType;
    let mut client = client();
    client.import_system_hive(&encode_image(&hive())).unwrap();
    let instance: Vec<u16> = r"PCI\VEN_1234\0".encode_utf16().collect();
    let driver: Vec<u16> = r"{1234}\0002".encode_utf16().collect();
    for flags in [1, 2, 5, 6] {
        let plan = DeviceRegistryKeyType::from_flags(flags)
            .unwrap()
            .plan(&instance, Some(&driver), 0x20019)
            .unwrap();
        let logical = String::from_utf16(&plan.absolute_path().unwrap()).unwrap();
        let path = client
            .resolve_system_hive_path(&logical)
            .unwrap()
            .physical_path;
        let profile = if flags & 4 != 0 {
            r"\Hardware Profiles\0007\System\CurrentControlSet"
        } else {
            ""
        };
        let tail = match flags {
            1 => r"Enum\PCI\VEN_1234\0\Device Parameters",
            5 => r"Enum\PCI\VEN_1234\0",
            _ => r"Control\Class\{1234}\0002",
        };
        assert_eq!(
            path,
            format!(r"\Registry\Machine\System\ControlSet001{profile}\{tail}")
        );
    }

    // This is a privileged host fixture transaction, not proof of native parent authorization.
    // Exercise the actual CM mutation/log/lease path with the prepared security bytes.
    let plan = DeviceRegistryKeyType::Device
        .plan(&instance, None, 0x20019)
        .unwrap();
    let path = String::from_utf16(&plan.absolute_path().unwrap()).unwrap();
    let sd = nt_security::prepare_device_parameters_security(
        &nt_security::DEFAULT_KEY_SECURITY_DESCRIPTOR,
    )
    .unwrap();
    let prepared = mutate(
        &mut client,
        1,
        &[
            SystemHiveMutation::CreateKey { path: &path },
            SystemHiveMutation::SetKeySecurity {
                path: &path,
                descriptor: &sd,
            },
        ],
    );
    let opened = retained_test_keys::open(&mut client, &path);
    let info = client
        .query_leased_system_hive_key_information(opened.lease)
        .unwrap();
    assert_eq!(info.security_descriptor.as_deref(), Some(sd.as_slice()));
    retained_test_keys::close(&mut client, opened.lease).unwrap();
    let mut replayed = hive();
    let base = replayed.sequence;
    try_replay_log(&mut replayed, &prepared.durable_journal, base).unwrap();
    let key = replayed
        .open_key(r"ControlSet001\Enum\PCI\VEN_1234\0\Device Parameters")
        .unwrap();
    assert_eq!(replayed.key_security_descriptor(key), Some(sd.as_slice()));
}
