use super::*;

const SERVICES: &str = r"\Registry\Machine\System\CurrentControlSet\Services";
const DEVICE: &str = r"\Registry\Machine\System\CurrentControlSet\Services\Device";
const REVISION_MISMATCH: i32 = 0xc000_0059u32 as i32;

fn client() -> ConfigClient<Framed> {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    let device = hive.create_key(r"ControlSet001\Services\Device");
    hive.set_key_security_descriptor(device, b"original security");
    hive.set_dword(device, "Value", 1);
    hive.finish_clean_import();
    let mut client = ConfigClient::new(Framed {
        server: fresh_server(),
    });
    client.import_system_hive(&encode_image(&hive)).unwrap();
    client
}

fn publish(
    client: &mut ConfigClient<Framed>,
    generation: u64,
    mutations: &[SystemHiveMutation<'_>],
) -> u64 {
    let prepared = client
        .prepare_system_hive_mutation(generation, mutations)
        .unwrap();
    let receipt = client
        .commit_system_hive_mutation_retained(&prepared)
        .unwrap();
    let _ = client
        .acknowledge_system_hive_mutation_commit(receipt)
        .unwrap();
    receipt.outcome().generation
}

#[test]
fn stale_descriptor_decision_is_not_rebased_onto_a_new_generation() {
    let mut client = client();
    let opened = retained_test_keys::open(&mut client, DEVICE);
    let before = client
        .query_leased_system_hive_key_information(opened.lease)
        .unwrap();
    let next = publish(
        &mut client,
        before.mount_generation,
        &[SystemHiveMutation::SetKeySecurity {
            path: &before.path,
            descriptor: b"concurrent security",
        }],
    );
    let stale = client.prepare_system_hive_mutation(
        before.mount_generation,
        &[SystemHiveMutation::SetKeySecurity {
            path: &before.path,
            descriptor: b"stale merged security",
        }],
    );
    assert_eq!(stale.unwrap_err(), REVISION_MISMATCH);
    let after = client
        .query_leased_system_hive_key_information(opened.lease)
        .unwrap();
    assert_eq!(after.mount_generation, next);
    assert_eq!(
        after.security_descriptor.as_deref(),
        Some(b"concurrent security".as_slice())
    );
    retained_test_keys::close(&mut client, opened.lease).unwrap();
}

#[test]
fn absence_based_creation_and_setup_batch_keep_the_original_read_generation() {
    let mut client = client();
    let child = alloc::format!("{SERVICES}\\New");
    let resolved = client.resolve_system_hive_path(&child).unwrap();
    assert_eq!(
        client.query_system_hive_key(&child),
        Err(STATUS_OBJECT_NAME_NOT_FOUND)
    );
    let next = publish(
        &mut client,
        resolved.mount_generation,
        &[SystemHiveMutation::CreateChild {
            parent: SERVICES,
            name: "New",
            class_name: Some("winner"),
            descriptor: b"winner security",
        }],
    );
    // The legacy composite uses CreateKey followed by metadata operations. Rebasing its generation
    // would modify the competing creator's key, even though our decision was "absent".
    assert_eq!(
        client
            .prepare_system_hive_mutation(
                resolved.mount_generation,
                &[
                    SystemHiveMutation::CreateKey {
                        path: &resolved.physical_path
                    },
                    SystemHiveMutation::SetKeyClass {
                        path: &resolved.physical_path,
                        class_name: Some("stale")
                    },
                    SystemHiveMutation::SetValue {
                        path: DEVICE,
                        name: "Value",
                        value_type: 4,
                        data: &9u32.to_le_bytes()
                    },
                ]
            )
            .unwrap_err(),
        REVISION_MISMATCH
    );
    let winner = retained_test_keys::open(&mut client, &child);
    let information = client
        .query_leased_system_hive_key_information(winner.lease)
        .unwrap();
    assert_eq!(information.mount_generation, next);
    assert_eq!(information.class_name.as_deref(), Some("winner"));
    let device = retained_test_keys::open(&mut client, DEVICE);
    assert_eq!(
        client
            .query_leased_system_hive_value(device.lease, "Value")
            .unwrap()
            .data,
        1u32.to_le_bytes()
    );
    retained_test_keys::close(&mut client, device.lease).unwrap();
    retained_test_keys::close(&mut client, winner.lease).unwrap();
}

#[test]
fn opaque_upload_uses_final_exact_lease_validation_not_begin_generation() {
    let mut client = client();
    let device = retained_test_keys::open(&mut client, DEVICE);
    let begin = client
        .query_leased_system_hive_key_information(device.lease)
        .unwrap();
    let mut upload = SystemHiveValueUpload::new(4).unwrap();
    upload.append(0, &[7, 0]).unwrap();
    let next = publish(
        &mut client,
        begin.mount_generation,
        &[SystemHiveMutation::CreateChild {
            parent: SERVICES,
            name: "Unrelated",
            class_name: None,
            descriptor: b"security",
        }],
    );
    upload.append(2, &[0, 0]).unwrap();
    let final_information = client
        .query_leased_system_hive_key_information(device.lease)
        .unwrap();
    assert_eq!(final_information.mount_generation, next);
    publish(
        &mut client,
        final_information.mount_generation,
        &[SystemHiveMutation::SetValue {
            path: &final_information.path,
            name: "Value",
            value_type: 4,
            data: upload.complete_data().unwrap(),
        }],
    );
    assert_eq!(
        client
            .query_leased_system_hive_value(device.lease, "Value")
            .unwrap()
            .data,
        [7, 0, 0, 0]
    );
    retained_test_keys::close(&mut client, device.lease).unwrap();
}

#[test]
fn deleted_and_recreated_path_cannot_replace_an_uploads_original_lease() {
    let mut client = client();
    let device = retained_test_keys::open(&mut client, DEVICE);
    let before = client
        .query_leased_system_hive_key_information(device.lease)
        .unwrap();
    let mut upload = SystemHiveValueUpload::new(1).unwrap();
    upload.append(0, &[7]).unwrap();
    let next = publish(
        &mut client,
        before.mount_generation,
        &[
            SystemHiveMutation::DeleteKey { path: &before.path },
            SystemHiveMutation::CreateChild {
                parent: SERVICES,
                name: "Device",
                class_name: None,
                descriptor: b"replacement",
            },
        ],
    );
    assert!(client
        .query_leased_system_hive_key_information(device.lease)
        .is_err());
    let replacement = retained_test_keys::open(&mut client, DEVICE);
    assert_ne!(replacement.lease.token, device.lease.token);
    let information = client
        .query_leased_system_hive_key_information(replacement.lease)
        .unwrap();
    assert_eq!(information.mount_generation, next);
    assert_eq!(
        client.query_leased_system_hive_value(replacement.lease, "Value"),
        Err(STATUS_OBJECT_NAME_NOT_FOUND)
    );
    retained_test_keys::close(&mut client, device.lease).unwrap();
    retained_test_keys::close(&mut client, replacement.lease).unwrap();
}
