use super::*;
use nt_config_manager::{
    device_property, encode_sz, ConfigManager, DevPropKey, PropertyValue, RegistryValueType,
};

/// Build the spec §21 fixture configuration.
fn fixture() -> ConfigManager {
    let mut cm = ConfigManager::new();
    cm.register_service(
        "KmdfInterfaceRegistryTest",
        "x.sys",
        Some("System"),
        Some("{4d36e97d-...}"),
        3,
        1,
    );
    cm.set_service_parameter(
        "KmdfInterfaceRegistryTest",
        "Answer",
        RegistryValueType::Dword,
        42u32.to_le_bytes().to_vec(),
    );
    cm.set_service_parameter(
        "KmdfInterfaceRegistryTest",
        "Greeting",
        RegistryValueType::Sz,
        encode_sz("hello registry"),
    );
    let dn = cm.register_devnode(
        r"Root\KmdfInterfaceRegistryTest\0000",
        Some("KmdfInterfaceRegistryTest"),
        Some(r"\Device\NTPNP_ROOT_0004"),
        &[r"Root\KmdfInterfaceRegistryTest"],
        &[r"Root\USERSPLACE"],
    );
    cm.register_interface(dn, "{9a7b0b24-6e57-4c51-ad3c-6d9f5f0e0001}", "", true);
    cm.set_legacy_property(
        dn,
        device_property::FRIENDLY_NAME,
        PropertyValue::string("Test Device"),
    );
    cm.assign_devprop(
        dn,
        DevPropKey {
            fmtid: [0xAB; 16],
            pid: 2,
        },
        PropertyValue::uint32(42),
    );
    cm
}

/// Assert the reconstructed config matches the fixture's observable state.
fn assert_fixture(cm: &ConfigManager) {
    let params = cm
        .service_parameters_key("KmdfInterfaceRegistryTest")
        .unwrap();
    assert_eq!(cm.registry().query_dword(params, "Answer"), Some(42));
    assert_eq!(
        cm.registry().query_string(params, "Greeting").as_deref(),
        Some("hello registry")
    );
    let devnodes = cm.devnodes_for_service("KmdfInterfaceRegistryTest");
    assert_eq!(devnodes.len(), 1);
    assert_eq!(
        devnodes[0].hardware_ids,
        alloc::vec![alloc::string::String::from(
            r"Root\KmdfInterfaceRegistryTest"
        )]
    );
    assert_eq!(
        cm.interfaces_by_guid("{9a7b0b24-6e57-4c51-ad3c-6d9f5f0e0001}", true)
            .len(),
        1
    );
    let dn = cm
        .devnode(r"Root\KmdfInterfaceRegistryTest\0000")
        .unwrap()
        .id;
    assert_eq!(
        cm.query_legacy_property(dn, device_property::FRIENDLY_NAME)
            .and_then(|v| v.as_string())
            .as_deref(),
        Some("Test Device")
    );
    assert_eq!(
        cm.query_devprop(
            dn,
            &DevPropKey {
                fmtid: [0xAB; 16],
                pid: 2
            }
        )
        .and_then(|v| v.as_uint32()),
        Some(42)
    );
}

#[test]
fn snapshot_roundtrip() {
    let cm = fixture();
    let bytes = snapshot::encode(&cm, 1, 0);
    let info = snapshot::parse_header(&bytes).unwrap();
    assert_eq!(info.generation, 1);
    assert!(info.record_count > 5);
    let restored = snapshot::decode(&bytes).unwrap();
    assert_fixture(&restored);
}

#[test]
fn snapshot_checksum_rejects_corruption() {
    let cm = fixture();
    let mut bytes = snapshot::encode(&cm, 1, 0);
    // Flip a byte in the payload → payload CRC mismatch.
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    assert_eq!(
        snapshot::parse_header(&bytes),
        Err(DecodeError::BadChecksum)
    );
    // A truncated buffer is rejected, not panicked.
    assert!(snapshot::decode(&bytes[..20]).is_err());
    // Wrong magic.
    let mut m = snapshot::encode(&cm, 1, 0);
    m[0] = b'X';
    assert_eq!(snapshot::parse_header(&m), Err(DecodeError::BadMagic));
}

#[test]
fn boot_replays_journal_after_snapshot() {
    // Compact a snapshot, then journal a runtime write, then boot → the write is present.
    let store = MemoryStore::new();
    let mut p = Persistence::new(store);
    let mut cm = fixture();
    p.compact(&cm).unwrap();
    // A running driver writes SeenByDriver=1 to its Parameters (journaled).
    p.mutate(
        &mut cm,
        journal::Mutation::SetValue {
            path: r"\Registry\Machine\System\CurrentControlSet\Services\KmdfInterfaceRegistryTest\Parameters",
            name: "SeenByDriver",
            value_type: RegistryValueType::Dword,
            data: &1u32.to_le_bytes(),
        },
    )
    .unwrap();
    // Simulate a restart: a fresh Persistence over the same store.
    let store = p.store_mut();
    store.crash();
    // (Re-open by moving the store into a new engine.)
    let mut p2 = Persistence::new(core::mem::take(store));
    let booted = p2.boot().unwrap();
    assert_fixture(&booted);
    let params = booted
        .service_parameters_key("KmdfInterfaceRegistryTest")
        .unwrap();
    assert_eq!(
        booted.registry().query_dword(params, "SeenByDriver"),
        Some(1)
    );
}

#[test]
fn compaction_truncates_journal() {
    let mut p = Persistence::new(MemoryStore::new());
    let mut cm = fixture();
    p.compact(&cm).unwrap();
    let params = cm
        .service_parameters_key("KmdfInterfaceRegistryTest")
        .unwrap();
    let key_path =
        r"\Registry\Machine\System\CurrentControlSet\Services\KmdfInterfaceRegistryTest\Parameters";
    let _ = params;
    p.mutate(
        &mut cm,
        journal::Mutation::SetValue {
            path: key_path,
            name: "V",
            value_type: RegistryValueType::Dword,
            data: &7u32.to_le_bytes(),
        },
    )
    .unwrap();
    assert!(!p.store_mut().read_journal().unwrap().is_empty());
    // Compaction folds the journal into a new snapshot + truncates it.
    p.compact(&cm).unwrap();
    assert!(p.store_mut().read_journal().unwrap().is_empty());
    let booted = Persistence::new(core::mem::take(p.store_mut()))
        .boot()
        .unwrap();
    assert_eq!(
        booted
            .registry()
            .query_dword(booted.registry().open_key(key_path).unwrap(), "V"),
        Some(7)
    );
}

#[test]
fn idempotent_replay() {
    // Replaying the same journal twice yields the same state (spec §10.5).
    let mut cm = fixture();
    let rec = journal::encode_record(
        &journal::Mutation::SetValue {
            path: r"\Registry\Machine\Test",
            name: "N",
            value_type: RegistryValueType::Dword,
            data: &5u32.to_le_bytes(),
        },
        1,
    );
    journal::replay(&mut cm, &rec, 0);
    journal::replay(&mut cm, &rec, 0); // re-apply
    let key = cm.registry().open_key(r"\Registry\Machine\Test").unwrap();
    assert_eq!(cm.registry().query_dword(key, "N"), Some(5));
    // With base_sequence >= the record's sequence, replay skips it.
    let mut cm2 = fixture();
    assert_eq!(journal::replay(&mut cm2, &rec, 1), 1); // sequence 1 <= base 1 → skipped
    assert!(cm2.registry().open_key(r"\Registry\Machine\Test").is_none());
}

#[test]
fn torn_journal_record_is_ignored() {
    // A crash mid-append leaves a torn final record; replay stops cleanly before it (spec §21.2).
    let mut cm = fixture();
    let good = journal::encode_record(
        &journal::Mutation::SetValue {
            path: r"\Registry\Machine\A",
            name: "G",
            value_type: RegistryValueType::Dword,
            data: &1u32.to_le_bytes(),
        },
        1,
    );
    let torn = journal::encode_record(
        &journal::Mutation::SetValue {
            path: r"\Registry\Machine\B",
            name: "T",
            value_type: RegistryValueType::Dword,
            data: &2u32.to_le_bytes(),
        },
        2,
    );
    let mut bytes = good.clone();
    bytes.extend_from_slice(&torn[..torn.len() - 5]); // truncate the second record
    let last = journal::replay(&mut cm, &bytes, 0);
    assert_eq!(last, 1); // only the intact record applied
    assert_eq!(
        cm.registry()
            .query_dword(cm.registry().open_key(r"\Registry\Machine\A").unwrap(), "G"),
        Some(1)
    );
    assert!(cm.registry().open_key(r"\Registry\Machine\B").is_none());
}

#[test]
fn fault_on_snapshot_write_preserves_previous() {
    // A failed atomic snapshot write leaves the previously-committed snapshot intact (spec §7.3):
    // the store is set to fail its 2nd snapshot write.
    let mut p = Persistence::new(FaultStore::new().fail_after(2, None));
    let mut cm = fixture();
    p.compact(&cm).unwrap(); // write #1 commits the snapshot
                             // A journaled mutation the second compact would fold in.
    p.mutate(
        &mut cm,
        journal::Mutation::CreateKey {
            path: r"\Registry\Machine\Late",
        },
    )
    .unwrap();
    // The second compact's snapshot write faults → the previous snapshot + journal survive.
    assert_eq!(p.compact(&cm), Err(StoreError::Io));
    let booted = Persistence::new(core::mem::take(p.store_mut()))
        .boot()
        .unwrap();
    assert_fixture(&booted); // recovered from snapshot #1 + replayed journal
    assert!(booted
        .registry()
        .open_key(r"\Registry\Machine\Late")
        .is_some());
}
