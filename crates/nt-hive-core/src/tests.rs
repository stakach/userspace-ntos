use super::*;
use alloc::string::String;

#[test]
fn hive_create_open_set_query() {
    let mut h = Hive::new(HiveKind::System);
    let key = h.create_key(r"CurrentControlSet\Services\Test\Parameters");
    assert_eq!(h.open_key(r"currentcontrolset\services\test\parameters"), Some(key)); // case-insensitive
    h.set_dword(key, "Answer", 42);
    h.set_value(key, "Greeting", RegistryValueType::Sz, alloc::vec![1, 0]);
    assert_eq!(h.query_dword(key, "answer"), Some(42));
    assert!(h.query_value(key, "Greeting").is_some());
    assert_eq!(h.key_path(key).as_deref(), Some(r"\CurrentControlSet\Services\Test\Parameters"));
    assert!(h.dirty_count() > 0);
}

#[test]
fn mount_table_currentcontrolset_resolver() {
    let mut mt = HiveMountTable::new();
    mt.mount(SYSTEM_HIVE_PATH, 1);
    mt.mount(r"\Registry\Machine\Software", 2);
    // Services path resolves through CurrentControlSet → ControlSet001 (spec §8, M2 success).
    let (hive, rel) = mt
        .resolve(r"\Registry\Machine\System\CurrentControlSet\Services\Foo")
        .unwrap();
    assert_eq!(hive, 1);
    assert_eq!(rel, r"\ControlSet001\Services\Foo");
    // Longest-mount-root wins.
    assert_eq!(mt.resolve(r"\Registry\Machine\Software\X").unwrap().0, 2);
    // Unmounted path → None.
    assert!(mt.resolve(r"\Registry\User\Foo").is_none());
}

#[test]
fn image_roundtrips_registry_tree() {
    let mut h = Hive::new(HiveKind::System);
    let a = h.create_key(r"ControlSet001\Services\A");
    h.set_dword(a, "Start", 3);
    let b = h.create_key(r"ControlSet001\Services\B\Parameters");
    h.set_value(b, "Name", RegistryValueType::Sz, alloc::vec![0x41, 0, 0, 0]);
    let bytes = encode_image(&h);
    let restored = decode_image(&bytes).unwrap();
    let a2 = restored.open_key(r"ControlSet001\Services\A").unwrap();
    assert_eq!(restored.query_dword(a2, "Start"), Some(3));
    let b2 = restored.open_key(r"ControlSet001\Services\B\Parameters").unwrap();
    assert!(restored.query_value(b2, "Name").is_some());
    let mut subs = restored.enum_subkeys(restored.open_key("ControlSet001\\Services").unwrap());
    subs.sort();
    assert_eq!(subs, alloc::vec![String::from("A"), String::from("B")]);
}

#[test]
fn image_checksum_rejects_corruption() {
    let h = Hive::new(HiveKind::System);
    let mut bytes = encode_image(&h);
    // Corrupt a byte in the (non-empty: root cell) payload → payload CRC mismatch.
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    assert!(matches!(decode_image(&bytes), Err(HiveDecodeError::BadChecksum)));
    let mut m = encode_image(&Hive::new(HiveKind::System));
    m[0] = b'X';
    assert!(matches!(decode_image(&m), Err(HiveDecodeError::BadMagic)));
    assert!(decode_image(&[0u8; 4]).is_err());
}

#[test]
fn manager_boot_mutate_flush_survives_restart() {
    let mut mgr = HiveManager::new(MemoryHiveIoProvider::new());
    let mut hive = mgr.boot(HiveKind::System).unwrap(); // fresh
    // Seed via mutations (journaled).
    mgr.mutate(&mut hive, HiveLogOp::CreateKey { path: r"ControlSet001\Services\Svc\Parameters" }).unwrap();
    mgr.mutate(&mut hive, HiveLogOp::SetValue {
        path: r"ControlSet001\Services\Svc\Parameters",
        name: "Answer",
        value_type: RegistryValueType::Dword,
        data: &42u32.to_le_bytes(),
    }).unwrap();
    // Checkpoint into an image + truncate log.
    mgr.flush(&mut hive).unwrap();
    // A further journaled write after the checkpoint.
    mgr.mutate(&mut hive, HiveLogOp::SetValue {
        path: r"ControlSet001\Services\Svc\Parameters",
        name: "SeenByDriver",
        value_type: RegistryValueType::Dword,
        data: &1u32.to_le_bytes(),
    }).unwrap();
    // Crash + reboot: fresh manager over the same provider (image + replayed log).
    mgr.provider_mut().crash();
    let provider = mgr.into_provider();
    let mut mgr2 = HiveManager::new(provider);
    let booted = mgr2.boot(HiveKind::System).unwrap();
    let key = booted.open_key(r"ControlSet001\Services\Svc\Parameters").unwrap();
    assert_eq!(booted.query_dword(key, "Answer"), Some(42)); // from the image
    assert_eq!(booted.query_dword(key, "SeenByDriver"), Some(1)); // from the replayed log
}

#[test]
fn log_replay_idempotent_and_torn() {
    let mut h = Hive::new(HiveKind::System);
    let rec = encode_log_record(&HiveLogOp::SetValue {
        path: r"ControlSet001\X",
        name: "N",
        value_type: RegistryValueType::Dword,
        data: &5u32.to_le_bytes(),
    }, 1);
    replay_log(&mut h, &rec, 0);
    replay_log(&mut h, &rec, 0); // idempotent re-apply
    let key = h.open_key(r"ControlSet001\X").unwrap();
    assert_eq!(h.query_dword(key, "N"), Some(5));
    // A torn trailing record is ignored.
    let good = encode_log_record(&HiveLogOp::CreateKey { path: r"ControlSet001\A" }, 2);
    let torn = encode_log_record(&HiveLogOp::CreateKey { path: r"ControlSet001\B" }, 3);
    let mut bytes = good.clone();
    bytes.extend_from_slice(&torn[..torn.len() - 4]);
    let mut h2 = Hive::new(HiveKind::System);
    let last = replay_log(&mut h2, &bytes, 0);
    assert_eq!(last, 2);
    assert!(h2.open_key(r"ControlSet001\A").is_some());
    assert!(h2.open_key(r"ControlSet001\B").is_none());
}

#[test]
fn fault_on_image_write_preserves_previous() {
    // The second image write faults → the previous image + log survive (spec §18.1).
    let mut mgr = HiveManager::new(FaultInjectionHiveIoProvider::new().fail_image_write_after(2));
    let mut hive = mgr.boot(HiveKind::System).unwrap();
    mgr.mutate(&mut hive, HiveLogOp::SetValue {
        path: r"ControlSet001\X", name: "A", value_type: RegistryValueType::Dword, data: &1u32.to_le_bytes(),
    }).unwrap();
    mgr.flush(&mut hive).unwrap(); // image write #1 ok
    mgr.mutate(&mut hive, HiveLogOp::SetValue {
        path: r"ControlSet001\X", name: "B", value_type: RegistryValueType::Dword, data: &2u32.to_le_bytes(),
    }).unwrap();
    assert_eq!(mgr.flush(&mut hive), Err(HiveIoError::Io)); // image write #2 faults
    let provider = mgr.into_provider();
    let booted = HiveManager::new(provider).boot(HiveKind::System).unwrap();
    let key = booted.open_key(r"ControlSet001\X").unwrap();
    assert_eq!(booted.query_dword(key, "A"), Some(1)); // image #1
    assert_eq!(booted.query_dword(key, "B"), Some(2)); // replayed log survived
}

#[test]
fn ntfile_provider_is_not_supported_yet() {
    let mut p = NtFileHiveIoProvider;
    assert_eq!(p.provider_kind(), HiveIoProviderKind::NtFile);
    assert_eq!(p.read_primary_image(), Err(HiveIoError::NotSupported));
}
