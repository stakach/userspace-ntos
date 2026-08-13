use super::*;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::hive::{Cell, KeyCell, ValueCell};

#[test]
fn hive_create_open_set_query() {
    let mut h = Hive::new(HiveKind::System);
    let key = h.create_key(r"CurrentControlSet\Services\Test\Parameters");
    assert_eq!(
        h.open_key(r"currentcontrolset\services\test\parameters"),
        Some(key)
    ); // case-insensitive
    h.set_dword(key, "Answer", 42);
    h.set_value(key, "Greeting", RegistryValueType::Sz, alloc::vec![1, 0]);
    assert_eq!(h.query_dword(key, "answer"), Some(42));
    assert!(h.query_value(key, "Greeting").is_some());
    assert!(h.set_key_class(key, Some("Service Parameters")));
    assert_eq!(h.key_class(key), Some("Service Parameters"));
    assert_eq!(
        h.subkey_class_by_index(h.open_key(r"CurrentControlSet\Services\Test").unwrap(), 0),
        Some("Service Parameters")
    );
    let descriptor =
        b"\x01\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    assert!(h.set_key_security_descriptor(key, descriptor));
    assert_eq!(h.key_security_descriptor(key), Some(&descriptor[..]));
    assert!(h.delete_value(key, "greeting"));
    assert_eq!(h.query_value(key, "Greeting"), None);
    assert!(!h.delete_value(key, "greeting"));
    assert_eq!(
        h.key_path(key).as_deref(),
        Some(r"\CurrentControlSet\Services\Test\Parameters")
    );
    assert!(h.dirty_count() > 0);
}

#[test]
fn hive_class_metadata_roundtrips_in_image() {
    let mut h = Hive::new(HiveKind::Software);
    let key = h.create_key(r"Classes\Sample");
    assert!(h.set_key_class(key, Some("Sample Class")));
    let descriptor =
        b"\x01\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    assert!(h.set_key_security_descriptor(key, descriptor));

    let image = encode_image(&h);
    let decoded = decode_image(&image).expect("decode hive image");
    let decoded_key = decoded.open_key(r"Classes\Sample").unwrap();
    assert_eq!(decoded.key_class(decoded_key), Some("Sample Class"));
    assert_eq!(
        decoded.key_security_descriptor(decoded_key),
        Some(&descriptor[..])
    );
}

#[test]
fn security_hive_lsa_policy_paths_roundtrip_in_image() {
    let mut hive = Hive::new(HiveKind::Security);
    let account_secret = hive.create_key(r"Policy\Accounts\S");
    hive.set_value(
        account_secret,
        "SecDesc",
        RegistryValueType::Binary,
        b"account-secret-descriptor".to_vec(),
    );
    let account_domain = hive.create_key(r"Policy\PolAcDmS");
    let domain_sid = [
        1u8, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0x47, 0xb1, 0xa6, 0x49, 0x9c, 0x8f, 0x77, 0x1f,
        0xf3, 0xce, 0x43, 0x7e,
    ];
    hive.set_value(
        account_domain,
        "",
        RegistryValueType::Binary,
        domain_sid.to_vec(),
    );

    let image = encode_image(&hive);
    assert_eq!(encoded_image_len(&hive), Ok(image.len()));
    assert_eq!(
        image_value_len_if_valid(&image, r"Policy\PolAcDmS", ""),
        Ok(domain_sid.len())
    );
    assert_eq!(
        image_value_len_if_valid(&image, r"policy\accounts\s", "secdesc"),
        Ok(b"account-secret-descriptor".len())
    );
    assert_eq!(
        image_value_len_if_valid(&image, r"Policy\Missing", ""),
        Ok(0)
    );

    let decoded = decode_image(&image).expect("decode security hive image");
    assert_eq!(decoded.kind, HiveKind::Security);
    assert_eq!(decoded.dirty_count(), 0);

    let decoded_secret = decoded
        .open_key(r"policy\accounts\s")
        .expect("Accounts\\S key");
    assert_eq!(
        decoded.query_value(decoded_secret, "SecDesc"),
        Some((
            RegistryValueType::Binary,
            b"account-secret-descriptor".as_slice()
        ))
    );
    let decoded_domain = decoded.open_key(r"Policy\PolAcDmS").expect("PolAcDmS key");
    assert_eq!(
        decoded.query_value(decoded_domain, ""),
        Some((RegistryValueType::Binary, domain_sid.as_slice()))
    );
}

#[test]
fn hive_borrowed_indexed_enumeration_preserves_names_and_data() {
    let mut h = Hive::new(HiveKind::System);
    let services = h.create_key(r"ControlSet001\Services");
    h.create_key(r"ControlSet001\Services\Afd");
    h.create_key(r"ControlSet001\Services\EventLog");
    h.set_value(
        services,
        "DisplayName",
        RegistryValueType::Sz,
        b"S\0C\0M\0\0\0".to_vec(),
    );
    h.set_dword(services, "Start", 2);

    assert_eq!(h.subkey_count(services), 2);
    assert_eq!(h.subkey_name_by_index(services, 0), Some("Afd"));
    assert_eq!(h.subkey_name_by_index(services, 1), Some("EventLog"));
    assert_eq!(h.subkey_name_by_index(services, 2), None);

    assert_eq!(h.value_count(services), 2);
    let (name, ty, data) = h.value_by_index(services, 0).unwrap();
    assert_eq!(name, "DisplayName");
    assert_eq!(ty, RegistryValueType::Sz);
    assert_eq!(data, b"S\0C\0M\0\0\0");
    let (name, ty, data) = h.value_by_index(services, 1).unwrap();
    assert_eq!(name, "Start");
    assert_eq!(ty, RegistryValueType::Dword);
    assert_eq!(data, &2u32.to_le_bytes());
    assert!(h.value_by_index(services, 2).is_none());
}

#[test]
fn hive_delete_key_removes_only_leaf_keys() {
    let mut h = Hive::new(HiveKind::Software);
    let parent = h.create_key(r"Classes\CLSID");
    let child = h.create_key(r"Classes\CLSID\{11111111-2222-3333-4444-555555555555}");
    h.set_value(child, "", RegistryValueType::Sz, b"C\0l\0s\0\0\0".to_vec());

    assert_eq!(h.delete_key(h.root()), Err(DeleteKeyError::CannotDelete));
    assert_eq!(h.delete_key(parent), Err(DeleteKeyError::CannotDelete));
    assert_eq!(h.subkey_count(parent), 1);

    assert_eq!(h.delete_key(child), Ok(()));
    assert_eq!(
        h.open_key(r"Classes\CLSID\{11111111-2222-3333-4444-555555555555}"),
        None
    );
    assert_eq!(h.subkey_count(parent), 0);
    assert_eq!(h.query_value(child, ""), None);
    assert_eq!(h.delete_key(child), Err(DeleteKeyError::NotFound));
    assert!(h.dirty_count() >= 3);
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
    assert!(mt.owns_path(r"\Registry\Machine\Software\Missing"));
    // Unmounted path → None.
    assert!(mt.resolve(r"\Registry\User\Foo").is_none());
    assert!(!mt.owns_path(r"\Registry\User\Foo"));
}

#[test]
fn mutable_hive_set_resolves_mutates_and_unmounts_hives() {
    let mut system = Hive::new(HiveKind::System);
    system.create_key(r"ControlSet001\Services");
    let mut software = Hive::new(HiveKind::Software);
    software.create_key(r"Microsoft");

    let mut set = MutableHiveSet::new();
    set.mount(SYSTEM_HIVE_PATH, 1, system);
    set.mount(r"\Registry\Machine\Software", 2, software);
    assert!(set.clear_hive_dirty(1));
    assert_eq!(set.hive(1).unwrap().dirty_count(), 0);

    let svc = set
        .create_key(r"\Registry\Machine\System\CurrentControlSet\Services\RpcSs")
        .expect("create service key");
    assert_eq!(svc.hive, 1);
    assert_eq!(
        set.hive(svc.hive)
            .and_then(|hive| hive.key_path(svc.key))
            .as_deref(),
        Some(r"\ControlSet001\Services\RpcSs")
    );
    assert!(set.set_value(
        svc,
        "Start",
        RegistryValueType::Dword,
        2u32.to_le_bytes().to_vec()
    ));
    assert_eq!(
        set.query_value(svc, "start")
            .map(|(ty, data)| (ty, data.to_vec())),
        Some((RegistryValueType::Dword, 2u32.to_le_bytes().to_vec()))
    );
    assert!(set.hive(1).unwrap().dirty_count() > 0);
    assert!(set.clear_hive_dirty(1));
    assert_eq!(set.hive(1).unwrap().dirty_count(), 0);
    assert!(set.owns_path(r"\Registry\Machine\System\CurrentControlSet\Services\Missing"));
    assert!(set.delete_value(svc, "Start"));
    assert!(set.query_value(svc, "start").is_none());
    assert!(!set.delete_value(svc, "Start"));
    assert!(set.set_key_class(svc, Some("Service")));
    assert_eq!(set.key_class(svc), Some("Service"));
    let descriptor =
        b"\x01\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    assert!(set.set_key_security_descriptor(svc, descriptor));
    assert_eq!(set.key_security_descriptor(svc), Some(&descriptor[..]));

    let transient = set
        .create_key(r"\Registry\Machine\System\CurrentControlSet\Services\RpcSs\Parameters")
        .expect("create transient service child");
    assert_eq!(set.delete_key(svc), Err(DeleteKeyError::CannotDelete));
    assert_eq!(set.delete_key(transient), Ok(()));
    assert!(set
        .resolve_key(r"\Registry\Machine\System\CurrentControlSet\Services\RpcSs\Parameters")
        .is_none());

    let opened = set
        .resolve_key(r"\registry\machine\system\controlset001\services\rpcss")
        .expect("open through canonical control set");
    assert_eq!(opened, svc);

    let parent = set
        .resolve_key(r"\Registry\Machine\System\CurrentControlSet\Services")
        .expect("resolve services parent");
    let child = set
        .create_subkey(parent, "EventLog")
        .expect("create child from resolved parent");
    assert_eq!(
        set.resolve_key(r"\Registry\Machine\System\ControlSet001\Services\EventLog"),
        Some(child)
    );
    assert!(set.create_subkey(parent, r"Bad\Name").is_none());

    let sw = set
        .create_key(r"\Registry\Machine\Software\Microsoft\Windows")
        .expect("create software key");
    assert_eq!(sw.hive, 2);
    assert_eq!(
        set.hive(sw.hive)
            .and_then(|hive| hive.key_path(sw.key))
            .as_deref(),
        Some(r"\Microsoft\Windows")
    );

    let removed = set
        .unmount(r"\Registry\Machine\Software")
        .expect("unmount software hive");
    assert_eq!(removed.kind, HiveKind::Software);
    assert!(set
        .resolve_key(r"\Registry\Machine\Software\Microsoft")
        .is_none());
    assert!(set
        .resolve_key(r"\Registry\Machine\System\CurrentControlSet\Services\RpcSs")
        .is_some());
}

#[test]
fn set_value_replaces_existing_value_atomically() {
    let mut hive = Hive::new(HiveKind::System);
    let key = hive.create_key(r"ControlSet001\Services\Large");
    let mut original = alloc::vec::Vec::new();
    original.resize(1024, 0x5a);
    assert!(hive.set_value(key, "Blob", RegistryValueType::Binary, original));

    let mut replacement = alloc::vec::Vec::new();
    replacement.resize(768, 1);
    replacement[256..].fill(2);
    assert!(hive.set_value(key, "Blob", RegistryValueType::Binary, replacement));
    assert_eq!(hive.query_value(key, "Blob").unwrap().1[0], 1);
    assert_eq!(hive.query_value(key, "Blob").unwrap().1[256], 2);
    assert_eq!(hive.query_value(key, "Blob").unwrap().1.len(), 768);
}

#[test]
fn same_hive_value_copy_shares_payload_until_replacement() {
    let mut hive = Hive::new(HiveKind::System);
    let source_key = hive.create_key(r"ControlSet001\Enum\PCI\VEN_8086");
    let destination_key = hive.create_key(r"ControlSet002\Enum\PCI\VEN_8086");
    let mut large = alloc::vec::Vec::new();
    large.resize(128 * 1024, 0x37);
    large[0] = 0x11;
    let last = large.len() - 1;
    large[last] = 0xee;
    assert!(hive.set_value(
        source_key,
        "AllocConfig",
        RegistryValueType::ResourceList,
        large
    ));

    let (source_value, _, _, source_data) = hive.value_ref_by_index(source_key, 0).unwrap();
    assert_eq!(source_data[0], 0x11);
    assert_eq!(source_data[source_data.len() - 1], 0xee);
    let source_ptr = source_data.as_ptr();
    let source_len = source_data.len();

    assert!(hive.set_value_from_existing_value(
        destination_key,
        "AllocConfig",
        RegistryValueType::ResourceList,
        source_value
    ));
    let source_data = hive.query_value(source_key, "AllocConfig").unwrap().1;
    let destination_data = hive.query_value(destination_key, "allocconfig").unwrap().1;
    assert_eq!(source_data.len(), source_len);
    assert_eq!(destination_data, source_data);
    assert_eq!(destination_data.as_ptr(), source_ptr);

    assert!(hive.set_value(
        destination_key,
        "AllocConfig",
        RegistryValueType::ResourceList,
        alloc::vec![1, 2, 3]
    ));
    assert_eq!(
        hive.query_value(destination_key, "AllocConfig").unwrap().1,
        &[1, 2, 3]
    );
    assert_eq!(
        hive.query_value(source_key, "AllocConfig").unwrap().1[0],
        0x11
    );
    assert_eq!(
        hive.query_value(source_key, "AllocConfig")
            .unwrap()
            .1
            .as_ptr(),
        source_ptr
    );
}

#[test]
fn mutable_hive_set_replaces_mounted_value() {
    let mut system = Hive::new(HiveKind::System);
    system.create_key(r"ControlSet001\Services");
    let mut set = MutableHiveSet::new();
    set.mount(SYSTEM_HIVE_PATH, 1, system);
    let key = set
        .create_key(r"\Registry\Machine\System\CurrentControlSet\Services\Large")
        .expect("large key");
    assert!(set.set_value(key, "Blob", RegistryValueType::Binary, alloc::vec![1, 2, 3]));
    assert_eq!(
        set.query_value(key, "Blob"),
        Some((RegistryValueType::Binary, &[1, 2, 3][..]))
    );
}

#[test]
fn mutable_hive_set_cross_hive_copy_shares_payload_until_replacement() {
    let mut system = Hive::new(HiveKind::System);
    let system_key = system.create_key(r"ControlSet001\Setup");
    let mut large = alloc::vec::Vec::new();
    large.resize(128 * 1024, 0x42);
    large[0] = 0x10;
    let last = large.len() - 1;
    large[last] = 0x90;
    assert!(system.set_value(system_key, "BigValue", RegistryValueType::Binary, large));

    let mut software = Hive::new(HiveKind::Software);
    software.create_key(r"Microsoft\SetupCopy");

    let mut set = MutableHiveSet::new();
    set.mount(SYSTEM_HIVE_PATH, 1, system);
    set.mount(r"\Registry\Machine\Software", 2, software);
    let source_key = set
        .resolve_key(r"\Registry\Machine\System\CurrentControlSet\Setup")
        .expect("source key");
    let (source, _, _, source_data) = set.value_ref_by_index(source_key, 0).expect("source value");
    let source_ptr = source_data.as_ptr();
    let dest_key = set
        .resolve_key(r"\Registry\Machine\Software\Microsoft\SetupCopy")
        .expect("destination key");
    assert!(set.set_value_from_existing_value(
        dest_key,
        "BigValue",
        RegistryValueType::Binary,
        source
    ));
    let dest_data = set.query_value(dest_key, "BigValue").unwrap().1;
    assert_eq!(dest_data.as_ptr(), source_ptr);
    assert_eq!(dest_data[0], 0x10);
    assert_eq!(dest_data[dest_data.len() - 1], 0x90);

    assert!(set.set_value(
        dest_key,
        "BigValue",
        RegistryValueType::Binary,
        alloc::vec![1, 2, 3]
    ));
    assert_eq!(set.query_value(dest_key, "BigValue").unwrap().1, &[1, 2, 3]);
    assert_eq!(
        set.query_value(source_key, "BigValue").unwrap().1.as_ptr(),
        source_ptr
    );
}

#[test]
fn value_copy_provenance_is_per_thread() {
    let source_a = ResolvedHiveValue {
        hive: 1,
        value: CellId(10),
    };
    let source_b = ResolvedHiveValue {
        hive: 1,
        value: CellId(20),
    };
    let mut table = RegistryValueCopyProvenanceTable::with_capacity(1);

    assert!(table.record(RegistryValueCopyProvenance::new(
        source_a, 3, 100, 0x5000, 128, 3,
    )));
    assert!(table.record(RegistryValueCopyProvenance::new(
        source_b, 4, 200, 0x6000, 256, 4,
    )));

    assert_eq!(
        table.source_for_user_data(3, 100, 0x5000, 128, 3),
        Some(source_a)
    );
    assert_eq!(
        table.source_for_user_data(4, 200, 0x6000, 256, 4),
        Some(source_b)
    );
    assert_eq!(table.source_for_user_data(3, 100, 0x5000, 129, 3), None);

    table.clear_for_thread(3, 100);
    assert_eq!(table.source_for_user_data(3, 100, 0x5000, 128, 3), None);
    assert_eq!(
        table.source_for_user_data(4, 200, 0x6000, 256, 4),
        Some(source_b)
    );
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
    let b2 = restored
        .open_key(r"ControlSet001\Services\B\Parameters")
        .unwrap();
    assert!(restored.query_value(b2, "Name").is_some());
    let mut subs = restored.enum_subkeys(restored.open_key("ControlSet001\\Services").unwrap());
    subs.sort();
    assert_eq!(subs, alloc::vec![String::from("A"), String::from("B")]);
}

#[test]
fn imports_control_set_services_into_config_manager() {
    let mut h = Hive::new(HiveKind::System);
    let svc = h.create_key(r"ControlSet001\Services\RpcSs");
    h.set_value(
        svc,
        "ImagePath",
        RegistryValueType::ExpandSz,
        utf16le_sz(r"%SystemRoot%\system32\svchost.exe -k rpcss"),
    );
    h.set_dword(svc, "Type", nt_config_manager::SERVICE_WIN32_SHARE_PROCESS);
    h.set_dword(svc, "Start", nt_config_manager::SERVICE_AUTO_START);
    h.set_dword(svc, "ErrorControl", 1);
    h.set_value(
        svc,
        "DependOnService",
        RegistryValueType::MultiSz,
        nt_config_manager::encode_multi_sz(&["DcomLaunch", "RpcEptMapper"]),
    );
    let params = h.create_key(r"ControlSet001\Services\RpcSs\Parameters");
    h.set_value(
        params,
        "ServiceDll",
        RegistryValueType::ExpandSz,
        utf16le_sz(r"%SystemRoot%\system32\rpcss.dll"),
    );

    let mut cm = nt_config_manager::ConfigManager::new();
    assert_eq!(
        import_control_set_services_into_config_manager(&h, &mut cm, "ControlSet001"),
        1
    );

    let auto = cm.auto_start_win32_service_candidates();
    assert_eq!(auto.len(), 1);
    assert_eq!(auto[0].name, "RpcSs");
    assert_eq!(
        auto[0].dependencies,
        alloc::vec![String::from("DcomLaunch"), String::from("RpcEptMapper")]
    );
    let service_dll = cm
        .registry()
        .open_key(r"\Registry\Machine\System\CurrentControlSet\Services\RpcSs\Parameters")
        .and_then(|key| cm.registry().query_string(key, "ServiceDll"));
    assert_eq!(
        service_dll.as_deref(),
        Some(r"%SystemRoot%\system32\rpcss.dll")
    );
}

#[test]
fn imports_service_group_order_for_service_database_order() {
    let mut h = Hive::new(HiveKind::System);
    let group_key = h.create_key(r"ControlSet001\Control\ServiceGroupOrder");
    h.set_value(
        group_key,
        "List",
        RegistryValueType::MultiSz,
        nt_config_manager::encode_multi_sz(&["Event Log", "NetworkProvider"]),
    );

    let dcom = h.create_key(r"ControlSet001\Services\DcomLaunch");
    h.set_value(
        dcom,
        "ImagePath",
        RegistryValueType::ExpandSz,
        utf16le_sz(r"%SystemRoot%\system32\svchost.exe -k DcomLaunch"),
    );
    h.set_dword(dcom, "Type", nt_config_manager::SERVICE_WIN32_SHARE_PROCESS);
    h.set_dword(dcom, "Start", nt_config_manager::SERVICE_AUTO_START);
    h.set_dword(dcom, "ErrorControl", 1);
    h.set_value(
        dcom,
        "Group",
        RegistryValueType::Sz,
        utf16le_sz("Event log"),
    );

    let eventlog = h.create_key(r"ControlSet001\Services\EventLog");
    h.set_value(
        eventlog,
        "ImagePath",
        RegistryValueType::ExpandSz,
        utf16le_sz(r"%SystemRoot%\system32\eventlog.exe"),
    );
    h.set_dword(
        eventlog,
        "Type",
        nt_config_manager::SERVICE_WIN32_OWN_PROCESS,
    );
    h.set_dword(eventlog, "Start", nt_config_manager::SERVICE_AUTO_START);
    h.set_dword(eventlog, "ErrorControl", 0);
    h.set_value(
        eventlog,
        "Group",
        RegistryValueType::Sz,
        utf16le_sz("Event Log"),
    );

    let mut cm = nt_config_manager::ConfigManager::new();
    assert_eq!(
        import_control_set_services_into_config_manager(&h, &mut cm, "ControlSet001"),
        2
    );
    assert_eq!(
        import_control_set_service_group_order_into_config_manager(&h, &mut cm, "ControlSet001"),
        1
    );
    assert_eq!(
        cm.service_group_order(),
        alloc::vec![String::from("Event Log"), String::from("NetworkProvider")]
    );
    assert_eq!(
        cm.service_database_ordered_names(),
        alloc::vec![String::from("EventLog"), String::from("DcomLaunch")]
    );
}

#[test]
fn imports_control_set_enum_into_config_manager() {
    let mut h = Hive::new(HiveKind::System);
    let dn = h.create_key(r"ControlSet001\Enum\PCI\VEN_8086&DEV_100E\3&11583659&0&18");
    h.set_value(dn, "Service", RegistryValueType::Sz, utf16le_sz("E1000"));
    h.set_value(
        dn,
        "PdoName",
        RegistryValueType::Sz,
        utf16le_sz(r"\Device\NTPNP_PCI0001"),
    );
    h.set_value(
        dn,
        "HardwareID",
        RegistryValueType::MultiSz,
        nt_config_manager::encode_multi_sz(&[r"PCI\VEN_8086&DEV_100E", r"PCI\VEN_8086"]),
    );

    let mut cm = nt_config_manager::ConfigManager::new();
    assert_eq!(
        import_control_set_enum_into_config_manager(&h, &mut cm, "ControlSet001"),
        1
    );

    let indexed = cm
        .devnode(r"PCI\VEN_8086&DEV_100E\3&11583659&0&18")
        .unwrap();
    assert_eq!(indexed.service.as_deref(), Some("E1000"));
    assert_eq!(indexed.pdo_name.as_deref(), Some(r"\Device\NTPNP_PCI0001"));
    assert_eq!(
        indexed.hardware_ids,
        alloc::vec![
            String::from(r"PCI\VEN_8086&DEV_100E"),
            String::from(r"PCI\VEN_8086"),
        ]
    );
    assert_eq!(cm.devnodes_for_service("e1000").len(), 1);
}

#[test]
fn image_checksum_rejects_corruption() {
    let h = Hive::new(HiveKind::System);
    let mut bytes = encode_image(&h);
    // Corrupt a byte in the (non-empty: root cell) payload → payload CRC mismatch.
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    assert!(matches!(
        decode_image(&bytes),
        Err(HiveDecodeError::BadChecksum)
    ));
    let mut m = encode_image(&Hive::new(HiveKind::System));
    m[0] = b'X';
    assert!(matches!(decode_image(&m), Err(HiveDecodeError::BadMagic)));
    assert!(decode_image(&[0u8; 4]).is_err());
}

#[test]
fn image_len_validation_checks_header_without_decoding_cells() {
    let mut h = Hive::new(HiveKind::Software);
    let key = h.create_key(r"Microsoft\Windows NT\CurrentVersion\ProfileList");
    h.set_value(
        key,
        "ProfileImagePath",
        RegistryValueType::ExpandSz,
        b"C:\\Profiles\\Administrator\0".to_vec(),
    );

    let mut bytes = encode_image(&h);
    assert_eq!(image_len_if_valid(&bytes), Ok(bytes.len()));

    let last = bytes.len() - 1;
    bytes[last] ^= 0x55;
    assert_eq!(
        image_len_if_valid(&bytes),
        Err(HiveDecodeError::BadChecksum)
    );
}

#[test]
fn hive_image_compacts_sparse_cell_ids_on_decode() {
    let mut h = Hive {
        cells: Vec::new(),
        value_blobs: alloc::vec![Rc::new(b"service".to_vec())],
        root: CellId(64),
        next_id: 2048,
        kind: HiveKind::System,
        generation: 7,
        sequence: 9,
        clean_sequence: 9,
    };
    h.cells.resize_with(1025, || None);
    h.cells[64] = Some(Cell::Key(KeyCell {
        id: CellId(64),
        parent: None,
        name: String::new(),
        subkeys: alloc::vec![CellId(512)],
        values: Vec::new(),
        class_name: None,
        security_descriptor: None,
        last_write_sequence: 1,
    }));
    h.cells[512] = Some(Cell::Key(KeyCell {
        id: CellId(512),
        parent: Some(CellId(64)),
        name: String::from("Services"),
        subkeys: Vec::new(),
        values: alloc::vec![CellId(1024)],
        class_name: None,
        security_descriptor: None,
        last_write_sequence: 2,
    }));
    h.cells[1024] = Some(Cell::Value(ValueCell {
        id: CellId(1024),
        parent_key: CellId(512),
        name: String::from("Name"),
        value_type: RegistryValueType::Sz,
        data_blob: 0,
        last_write_sequence: 3,
    }));

    assert_eq!(h.cell_count(), 3);
    assert_eq!(h.cells.len(), 1025);

    let decoded = decode_image(&encode_image(&h)).expect("decode compacted hive image");
    assert_eq!(decoded.root(), CellId(0));
    assert_eq!(decoded.cell_count(), 3);
    assert_eq!(decoded.cells.len(), 3);
    let key = decoded.open_key("Services").unwrap();
    assert_eq!(decoded.query_value(key, "Name").unwrap().1, b"service");
}

#[test]
fn manager_boot_mutate_flush_survives_restart() {
    let mut mgr = HiveManager::new(MemoryHiveIoProvider::new());
    let mut hive = mgr.boot(HiveKind::System).unwrap(); // fresh
                                                        // Seed via mutations (journaled).
    mgr.mutate(
        &mut hive,
        HiveLogOp::CreateKey {
            path: r"ControlSet001\Services\Svc\Parameters",
        },
    )
    .unwrap();
    mgr.mutate(
        &mut hive,
        HiveLogOp::SetValue {
            path: r"ControlSet001\Services\Svc\Parameters",
            name: "Answer",
            value_type: RegistryValueType::Dword,
            data: &42u32.to_le_bytes(),
        },
    )
    .unwrap();
    // Checkpoint into an image + truncate log.
    mgr.flush(&mut hive).unwrap();
    // A further journaled write after the checkpoint.
    mgr.mutate(
        &mut hive,
        HiveLogOp::SetValue {
            path: r"ControlSet001\Services\Svc\Parameters",
            name: "SeenByDriver",
            value_type: RegistryValueType::Dword,
            data: &1u32.to_le_bytes(),
        },
    )
    .unwrap();
    // Crash + reboot: fresh manager over the same provider (image + replayed log).
    mgr.provider_mut().crash();
    let provider = mgr.into_provider();
    let mut mgr2 = HiveManager::new(provider);
    let booted = mgr2.boot(HiveKind::System).unwrap();
    let key = booted
        .open_key(r"ControlSet001\Services\Svc\Parameters")
        .unwrap();
    assert_eq!(booted.query_dword(key, "Answer"), Some(42)); // from the image
    assert_eq!(booted.query_dword(key, "SeenByDriver"), Some(1)); // from the replayed log
}

#[test]
fn manager_replays_deletes_and_key_metadata_after_checkpoint() {
    let mut mgr = HiveManager::new(MemoryHiveIoProvider::new());
    let mut hive = mgr.boot(HiveKind::Software).unwrap();
    mgr.mutate(
        &mut hive,
        HiveLogOp::SetValue {
            path: r"Classes\CLSID\{00000000-0000-0000-0000-000000000001}",
            name: "Stale",
            value_type: RegistryValueType::Sz,
            data: b"remove-me",
        },
    )
    .unwrap();
    mgr.mutate(
        &mut hive,
        HiveLogOp::SetValue {
            path: r"Classes\DeleteMe",
            name: "Payload",
            value_type: RegistryValueType::Binary,
            data: b"gone",
        },
    )
    .unwrap();
    mgr.flush(&mut hive).unwrap();

    mgr.mutate(
        &mut hive,
        HiveLogOp::DeleteValue {
            path: r"Classes\CLSID\{00000000-0000-0000-0000-000000000001}",
            name: "Stale",
        },
    )
    .unwrap();
    mgr.mutate(
        &mut hive,
        HiveLogOp::SetKeyClass {
            path: r"Classes\CLSID\{00000000-0000-0000-0000-000000000001}",
            class_name: Some("OleServer"),
        },
    )
    .unwrap();
    mgr.mutate(
        &mut hive,
        HiveLogOp::SetKeySecurityDescriptor {
            path: r"Classes\CLSID\{00000000-0000-0000-0000-000000000001}",
            descriptor: b"sd",
        },
    )
    .unwrap();
    mgr.mutate(
        &mut hive,
        HiveLogOp::DeleteKey {
            path: r"Classes\DeleteMe",
        },
    )
    .unwrap();

    mgr.provider_mut().crash();
    let provider = mgr.into_provider();
    let booted = HiveManager::new(provider).boot(HiveKind::Software).unwrap();
    let clsid = booted
        .open_key(r"Classes\CLSID\{00000000-0000-0000-0000-000000000001}")
        .unwrap();
    assert!(booted.query_value(clsid, "Stale").is_none());
    assert_eq!(booted.key_class(clsid), Some("OleServer"));
    assert_eq!(booted.key_security_descriptor(clsid), Some(&b"sd"[..]));
    assert!(booted.open_key(r"Classes\DeleteMe").is_none());
}

#[test]
fn log_replay_idempotent_and_torn() {
    let mut h = Hive::new(HiveKind::System);
    let rec = encode_log_record(
        &HiveLogOp::SetValue {
            path: r"ControlSet001\X",
            name: "N",
            value_type: RegistryValueType::Dword,
            data: &5u32.to_le_bytes(),
        },
        1,
    );
    replay_log(&mut h, &rec, 0);
    replay_log(&mut h, &rec, 0); // idempotent re-apply
    let key = h.open_key(r"ControlSet001\X").unwrap();
    assert_eq!(h.query_dword(key, "N"), Some(5));
    // A torn trailing record is ignored.
    let good = encode_log_record(
        &HiveLogOp::CreateKey {
            path: r"ControlSet001\A",
        },
        2,
    );
    let torn = encode_log_record(
        &HiveLogOp::CreateKey {
            path: r"ControlSet001\B",
        },
        3,
    );
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
    mgr.mutate(
        &mut hive,
        HiveLogOp::SetValue {
            path: r"ControlSet001\X",
            name: "A",
            value_type: RegistryValueType::Dword,
            data: &1u32.to_le_bytes(),
        },
    )
    .unwrap();
    mgr.flush(&mut hive).unwrap(); // image write #1 ok
    mgr.mutate(
        &mut hive,
        HiveLogOp::SetValue {
            path: r"ControlSet001\X",
            name: "B",
            value_type: RegistryValueType::Dword,
            data: &2u32.to_le_bytes(),
        },
    )
    .unwrap();
    assert_eq!(mgr.flush(&mut hive), Err(HiveIoError::Io)); // image write #2 faults
    let provider = mgr.into_provider();
    let booted = HiveManager::new(provider).boot(HiveKind::System).unwrap();
    let key = booted.open_key(r"ControlSet001\X").unwrap();
    assert_eq!(booted.query_dword(key, "A"), Some(1)); // image #1
    assert_eq!(booted.query_dword(key, "B"), Some(2)); // replayed log survived
}
