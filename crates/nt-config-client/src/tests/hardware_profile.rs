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
fn unavailable_alias_never_uses_a_literal_current_key_or_default_profile() {
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
        hive.create_key(r"ControlSet001\Hardware Profiles\Current");
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
    mutate(
        &mut client,
        1,
        &[SystemHiveMutation::DeleteKey { path: CURRENT }],
    );
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
    mutate(
        &mut client,
        1,
        &[SystemHiveMutation::SetValue {
            path: r"\Registry\Machine\System\Select",
            name: "Current",
            value_type: RegistryValueType::Dword as u32,
            data: &2u32.to_le_bytes(),
        }],
    );
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
