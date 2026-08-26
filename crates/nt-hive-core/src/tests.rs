use super::*;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::hive::{Cell, KeyCell, ValueCell};

fn mountable_system_hive() -> Hive {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    hive.create_key("ControlSet001");
    hive
}

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
fn hive_key_path_rejects_cyclic_parent_chain() {
    let mut h = Hive::new(HiveKind::System);
    let parent = h.create_key(r"ControlSet001\Services\Loop");
    let child = h.create_key(r"ControlSet001\Services\Loop\Child");
    if let Some(Cell::Key(key)) = h
        .cells
        .get_mut(parent.0 as usize)
        .and_then(|cell| cell.as_mut())
    {
        key.parent = Some(child);
    }

    assert_eq!(h.key_path(parent), None);
    assert_eq!(h.key_path(child), None);
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
    assert_eq!(image_root_subkey_count_if_valid(&image), Ok(1));
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
fn image_root_subkey_count_validates_without_materialising_hive() {
    let root_only = Hive::new(HiveKind::Default);
    let root_only_image = encode_image(&root_only);
    assert_eq!(image_root_subkey_count_if_valid(&root_only_image), Ok(0));

    let mut with_children = Hive::new(HiveKind::Default);
    with_children.create_key(r"Control Panel\International");
    with_children.create_key(r"Software\ReactOS");
    let image = encode_image(&with_children);
    assert_eq!(image_root_subkey_count_if_valid(&image), Ok(2));

    let mut corrupted = image.clone();
    corrupted[20] ^= 0x5a;
    assert_eq!(
        image_root_subkey_count_if_valid(&corrupted),
        Err(HiveDecodeError::BadChecksum)
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
fn hive_overlay_composes_setup_state_without_losing_persistent_state() {
    let mut persistent = Hive::new(HiveKind::System);
    let services = persistent.create_key(r"ControlSet001\Services");
    assert!(persistent.set_key_class(services, Some("Persistent services")));
    let persistent_descriptor = b"persistent-security-descriptor";
    assert!(persistent.set_key_security_descriptor(services, persistent_descriptor));
    persistent.set_dword(services, "BaseOnly", 11);
    persistent.set_dword(services, "ReplaceMe", 12);
    let persistent_driver = persistent.create_key(r"ControlSet001\Services\DriverA");
    persistent.set_dword(persistent_driver, "Start", 3);
    persistent.finish_clean_import();

    let mut overlay = Hive::new(HiveKind::System);
    let overlay_services = overlay.create_key(r"controlset001\services");
    overlay.set_dword(overlay_services, "replaceme", 42);
    let overlay_driver = overlay.create_key(r"ControlSet001\Services\DriverB");
    assert!(overlay.set_key_class(overlay_driver, Some("Overlay driver")));
    let overlay_descriptor = b"overlay-security-descriptor";
    assert!(overlay.set_key_security_descriptor(overlay_driver, overlay_descriptor));
    overlay.set_value(
        overlay_driver,
        "ImagePath",
        RegistryValueType::ExpandSz,
        utf16le_sz(r"system32\driverb.sys"),
    );
    overlay.finish_clean_import();

    let composed = compose_hive_overlay(&persistent, &overlay).expect("compose SYSTEM overlay");
    let composed_services = composed
        .open_key(r"ControlSet001\Services")
        .expect("composed services");
    assert_eq!(
        composed.query_dword(composed_services, "BaseOnly"),
        Some(11)
    );
    assert_eq!(
        composed.query_dword(composed_services, "ReplaceMe"),
        Some(42)
    );
    assert_eq!(
        composed.key_class(composed_services),
        Some("Persistent services")
    );
    assert_eq!(
        composed.key_security_descriptor(composed_services),
        Some(persistent_descriptor.as_slice())
    );
    assert_eq!(
        composed.query_dword(
            composed
                .open_key(r"ControlSet001\Services\DriverA")
                .expect("persistent driver"),
            "Start"
        ),
        Some(3)
    );
    let composed_driver = composed
        .open_key(r"ControlSet001\Services\DriverB")
        .expect("overlay driver");
    assert_eq!(composed.key_class(composed_driver), Some("Overlay driver"));
    assert_eq!(
        composed.key_security_descriptor(composed_driver),
        Some(overlay_descriptor.as_slice())
    );
    assert_eq!(
        composed
            .query_value(composed_driver, "ImagePath")
            .map(|(value_type, _)| value_type),
        Some(RegistryValueType::ExpandSz)
    );
    assert_eq!(composed.sequence, 0);
    assert_eq!(composed.generation, 0);
    assert_eq!(composed.dirty_count(), 0);

    assert_eq!(persistent.query_dword(services, "ReplaceMe"), Some(12));
    assert!(persistent
        .open_key(r"ControlSet001\Services\DriverB")
        .is_none());
    assert!(overlay.query_value(overlay_services, "BaseOnly").is_none());
}

#[test]
fn hive_overlay_rejects_a_different_hive_kind_without_mutating_inputs() {
    let mut system = Hive::new(HiveKind::System);
    let system_key = system.create_key(r"ControlSet001\Services\Kept");
    system.set_dword(system_key, "Start", 1);
    system.finish_clean_import();

    let mut software = Hive::new(HiveKind::Software);
    software.create_key(r"Classes\WrongKind");
    software.finish_clean_import();

    assert!(matches!(
        compose_hive_overlay(&system, &software),
        Err(HiveOverlayError::KindMismatch)
    ));
    assert_eq!(system.query_dword(system_key, "Start"), Some(1));
    assert!(software.open_key(r"Classes\WrongKind").is_some());
}

#[test]
fn hive_overlay_rejects_a_cyclic_source_without_mutating_the_base() {
    let mut base = Hive::new(HiveKind::System);
    let base_key = base.create_key(r"ControlSet001\Services\Kept");
    base.set_dword(base_key, "Start", 1);
    base.finish_clean_import();

    let mut overlay = Hive::new(HiveKind::System);
    let loop_key = overlay.create_key(r"ControlSet001\Services\Loop");
    if let Some(Cell::Key(key)) = overlay
        .cells
        .get_mut(loop_key.0 as usize)
        .and_then(|cell| cell.as_mut())
    {
        key.subkeys.push(loop_key);
    }

    assert!(matches!(
        compose_hive_overlay(&base, &overlay),
        Err(HiveOverlayError::InvalidSource)
    ));
    assert_eq!(base.query_dword(base_key, "Start"), Some(1));
    assert!(base.open_key(r"ControlSet001\Services\Loop").is_none());
}

#[test]
fn system_hive_resolves_current_control_set_without_a_default() {
    let mut hive = Hive::new(HiveKind::System);
    hive.create_key(r"ControlSet001\Services\Inactive");
    hive.create_key(r"ControlSet002\Services\Active");
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 2);

    let selected = hive.current_control_set().expect("selected control set");
    assert_eq!(selected.number(), 2);
    assert_eq!(selected.as_str(), "ControlSet002");

    let missing_select = Hive::new(HiveKind::System);
    assert_eq!(
        missing_select.current_control_set(),
        Err(CurrentControlSetError::SelectKeyMissing)
    );

    let mut missing_current = Hive::new(HiveKind::System);
    missing_current.create_key("Select");
    missing_current.create_key("ControlSet001");
    assert_eq!(
        missing_current.current_control_set(),
        Err(CurrentControlSetError::CurrentValueMissing)
    );

    let mut wrong_type = Hive::new(HiveKind::System);
    let select = wrong_type.create_key("Select");
    wrong_type.set_value(
        select,
        "Current",
        RegistryValueType::Binary,
        1u32.to_le_bytes().to_vec(),
    );
    wrong_type.create_key("ControlSet001");
    assert_eq!(
        wrong_type.current_control_set(),
        Err(CurrentControlSetError::CurrentValueInvalid)
    );

    let mut zero = Hive::new(HiveKind::System);
    let select = zero.create_key("Select");
    zero.set_dword(select, "Current", 0);
    zero.create_key("ControlSet000");
    assert_eq!(
        zero.current_control_set(),
        Err(CurrentControlSetError::CurrentValueInvalid)
    );

    let mut missing_target = Hive::new(HiveKind::System);
    let select = missing_target.create_key("Select");
    missing_target.set_dword(select, "Current", 7);
    assert_eq!(
        missing_target.current_control_set(),
        Err(CurrentControlSetError::TargetKeyMissing)
    );

    assert_eq!(
        Hive::new(HiveKind::Software).current_control_set(),
        Err(CurrentControlSetError::WrongHiveKind)
    );
}

#[test]
fn system_hive_overlay_rebases_selected_subtree_and_preserves_base_selection() {
    let mut base = Hive::new(HiveKind::System);
    let select = base.create_key("Select");
    base.set_dword(select, "Current", 2);
    base.set_dword(select, "Default", 2);
    let inactive = base.create_key(r"ControlSet001\Services\Inactive");
    base.set_dword(inactive, "BaseOnly", 1);
    let active = base.create_key(r"ControlSet002\Services\Persistent");
    base.set_dword(active, "BaseOnly", 2);
    base.finish_clean_import();

    let mut generated = Hive::new(HiveKind::System);
    let select = generated.create_key("Select");
    generated.set_dword(select, "Current", 1);
    generated.set_dword(select, "Default", 1);
    let generated_service = generated.create_key(r"ControlSet001\Services\Generated");
    generated.set_dword(generated_service, "Start", 1);
    generated.finish_clean_import();

    let composed =
        compose_system_hive_overlay(&base, &generated).expect("compose selected control set");
    let selected = composed
        .current_control_set()
        .expect("base selection retained");
    assert_eq!(selected.as_str(), "ControlSet002");
    let composed_select = composed.open_key("Select").unwrap();
    assert_eq!(composed.query_dword(composed_select, "Current"), Some(2));
    assert_eq!(composed.query_dword(composed_select, "Default"), Some(2));
    assert!(composed
        .open_key(r"ControlSet002\Services\Generated")
        .is_some());
    assert!(composed
        .open_key(r"ControlSet001\Services\Generated")
        .is_none());
    assert_eq!(
        composed.query_dword(
            composed
                .open_key(r"ControlSet001\Services\Inactive")
                .unwrap(),
            "BaseOnly"
        ),
        Some(1)
    );
    assert_eq!(
        composed.query_dword(
            composed
                .open_key(r"ControlSet002\Services\Persistent")
                .unwrap(),
            "BaseOnly"
        ),
        Some(2)
    );
    assert_eq!(composed.generation, 0);
    assert_eq!(composed.sequence, 0);
    assert_eq!(composed.dirty_count(), 0);
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
    let mut system = mountable_system_hive();
    system.create_key(r"ControlSet002\Services");
    let select = system.open_key("Select").unwrap();
    system.set_dword(select, "Current", 2);
    mt.mount_with_current_control_set(SYSTEM_HIVE_PATH, 1, system.current_control_set().unwrap());
    mt.mount(r"\Registry\Machine\Software", 2);
    // Services resolves through the selected identity carried by this exact mount generation.
    let (hive, rel) = mt
        .resolve(r"\Registry\Machine\System\CurrentControlSet\Services\Foo")
        .unwrap();
    assert_eq!(hive, 1);
    assert_eq!(rel, r"\ControlSet002\Services\Foo");
    assert_eq!(
        mt.resolve(r"\Registry\Machine\System\Other\CurrentControlSet\Foo")
            .unwrap()
            .1,
        r"\Other\CurrentControlSet\Foo"
    );
    // Longest-mount-root wins.
    assert_eq!(mt.resolve(r"\Registry\Machine\Software\X").unwrap().0, 2);
    assert!(mt.owns_path(r"\Registry\Machine\Software\Missing"));
    // Unmounted path → None.
    assert!(mt.resolve(r"\Registry\User\Foo").is_none());
    assert!(!mt.owns_path(r"\Registry\User\Foo"));

    let mut unselected = HiveMountTable::new();
    unselected.mount(SYSTEM_HIVE_PATH, 7);
    assert!(unselected.owns_path(r"\Registry\Machine\System\CurrentControlSet\Services"));
    assert!(unselected
        .resolve(r"\Registry\Machine\System\CurrentControlSet\Services")
        .is_none());
}

#[test]
fn mutable_hive_set_rejects_invalid_system_replacement_atomically() {
    let mut selected = mountable_system_hive();
    selected.create_key(r"ControlSet001\Services\Live");
    let mut set = MutableHiveSet::new();
    set.mount(SYSTEM_HIVE_PATH, 1, selected).unwrap();

    let invalid = Hive::new(HiveKind::System);
    assert_eq!(
        set.mount(SYSTEM_HIVE_PATH, 1, invalid),
        Err(CurrentControlSetError::SelectKeyMissing)
    );
    assert!(set
        .resolve_key(r"\Registry\Machine\System\CurrentControlSet\Services\Live")
        .is_some());
    assert_eq!(
        set.hive(1).unwrap().current_control_set().unwrap().number(),
        1
    );
}

#[test]
fn mutable_hive_set_resolves_mutates_and_unmounts_hives() {
    let mut system = mountable_system_hive();
    system.create_key(r"ControlSet001\Services");
    let mut software = Hive::new(HiveKind::Software);
    software.create_key(r"Microsoft");

    let mut set = MutableHiveSet::new();
    set.mount(SYSTEM_HIVE_PATH, 1, system).unwrap();
    set.mount(r"\Registry\Machine\Software", 2, software)
        .unwrap();
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
    let mut system = mountable_system_hive();
    system.create_key(r"ControlSet001\Services");
    let mut set = MutableHiveSet::new();
    set.mount(SYSTEM_HIVE_PATH, 1, system).unwrap();
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
    let mut system = mountable_system_hive();
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
    set.mount(SYSTEM_HIVE_PATH, 1, system).unwrap();
    set.mount(r"\Registry\Machine\Software", 2, software)
        .unwrap();
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
fn subtree_image_roundtrips_selected_key_as_hive_root() {
    let mut h = Hive::new(HiveKind::System);
    let services = h.create_key(r"ControlSet001\Services");
    assert!(h.set_key_class(services, Some("Services Root")));
    assert!(h.set_value(
        services,
        "RootValue",
        RegistryValueType::Dword,
        7u32.to_le_bytes().to_vec()
    ));
    let descriptor =
        b"\x01\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    assert!(h.set_key_security_descriptor(services, descriptor));
    let afd = h.create_key(r"ControlSet001\Services\Afd\Parameters");
    assert!(h.set_value(
        afd,
        "DeviceName",
        RegistryValueType::Sz,
        utf16le_sz(r"\Device\Afd")
    ));
    let sibling = h.create_key(r"ControlSet001\Control");
    assert!(h.set_value(
        sibling,
        "DoNotSave",
        RegistryValueType::Dword,
        1u32.to_le_bytes().to_vec()
    ));

    let image = try_encode_subtree_image(&h, services).expect("encode subtree");
    let decoded = decode_image(&image).expect("decode subtree image");
    assert_eq!(decoded.kind, HiveKind::System);
    assert_eq!(decoded.key_class(decoded.root()), Some("Services Root"));
    assert_eq!(
        decoded.key_security_descriptor(decoded.root()),
        Some(&descriptor[..])
    );
    assert_eq!(
        decoded.query_value(decoded.root(), "RootValue"),
        Some((RegistryValueType::Dword, &7u32.to_le_bytes()[..]))
    );
    assert!(
        decoded.open_key(r"ControlSet001").is_none(),
        "ancestors outside the selected subtree must not be serialized"
    );
    let decoded_afd = decoded
        .open_key(r"Afd\Parameters")
        .expect("subtree child preserved");
    assert_eq!(
        decoded.query_value(decoded_afd, "DeviceName"),
        Some((RegistryValueType::Sz, utf16le_sz(r"\Device\Afd").as_slice()))
    );
    assert!(
        decoded.open_key(r"Control").is_none(),
        "siblings outside the selected subtree must not be serialized"
    );
}

#[test]
fn subtree_image_rejects_invalid_root() {
    let h = Hive::new(HiveKind::Software);
    assert_eq!(
        try_encode_subtree_image(&h, CellId(999)),
        Err(HiveSubtreeEncodeError::InvalidRoot)
    );
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
fn config_manager_import_skips_cyclic_hive_subtrees() {
    let mut h = Hive::new(HiveKind::System);
    let svc = h.create_key(r"ControlSet001\Services\Loop");
    h.set_value(
        svc,
        "ImagePath",
        RegistryValueType::ExpandSz,
        utf16le_sz(r"system32\drivers\loop.sys"),
    );
    h.set_dword(svc, "Type", nt_config_manager::SERVICE_KERNEL_DRIVER);
    h.set_dword(svc, "Start", nt_config_manager::SERVICE_SYSTEM_START);
    h.set_dword(svc, "ErrorControl", 1);
    let child = h.create_key(r"ControlSet001\Services\Loop\Child");
    if let Some(Cell::Key(key)) = h
        .cells
        .get_mut(child.0 as usize)
        .and_then(|cell| cell.as_mut())
    {
        key.subkeys.push(svc);
    }

    let mut cm = nt_config_manager::ConfigManager::new();
    assert_eq!(
        import_control_set_services_into_config_manager(&h, &mut cm, "ControlSet001"),
        1
    );
    assert!(cm
        .registry()
        .open_key(r"\Registry\Machine\System\CurrentControlSet\Services\Loop\Child")
        .is_some());
    assert!(cm
        .registry()
        .open_key(r"\Registry\Machine\System\CurrentControlSet\Services\Loop\Child\Loop")
        .is_none());
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
fn manager_live_apply_can_share_value_payload_while_log_replays_bytes() {
    let mut mgr = HiveManager::new(MemoryHiveIoProvider::new());
    let mut hive = mgr.boot(HiveKind::System).unwrap();
    mgr.mutate(
        &mut hive,
        HiveLogOp::CreateKey {
            path: r"ControlSet001\Enum\PCI\VEN_8086",
        },
    )
    .unwrap();
    mgr.mutate(
        &mut hive,
        HiveLogOp::CreateKey {
            path: r"ControlSet002\Enum\PCI\VEN_8086",
        },
    )
    .unwrap();

    let mut large = alloc::vec::Vec::new();
    large.resize(128 * 1024, 0x7b);
    large[0] = 0x31;
    let last = large.len() - 1;
    large[last] = 0xd4;
    mgr.mutate(
        &mut hive,
        HiveLogOp::SetValue {
            path: r"ControlSet001\Enum\PCI\VEN_8086",
            name: "AllocConfig",
            value_type: RegistryValueType::ResourceList,
            data: &large,
        },
    )
    .unwrap();

    let source_key = hive
        .open_key(r"ControlSet001\Enum\PCI\VEN_8086")
        .expect("source key");
    let dest_key = hive
        .open_key(r"ControlSet002\Enum\PCI\VEN_8086")
        .expect("destination key");
    let (source_value, _, _, source_data) = hive.value_ref_by_index(source_key, 0).unwrap();
    let source_ptr = source_data.as_ptr();
    let source_log_data = source_data.to_vec();
    mgr.mutate_with_live_apply(
        &mut hive,
        HiveLogOp::SetValue {
            path: r"ControlSet002\Enum\PCI\VEN_8086",
            name: "AllocConfig",
            value_type: RegistryValueType::ResourceList,
            data: &source_log_data,
        },
        |hive| {
            hive.set_value_from_existing_value(
                dest_key,
                "AllocConfig",
                RegistryValueType::ResourceList,
                source_value,
            )
        },
    )
    .unwrap();

    let source_data = hive.query_value(source_key, "AllocConfig").unwrap().1;
    let dest_data = hive.query_value(dest_key, "AllocConfig").unwrap().1;
    assert_eq!(source_data.as_ptr(), source_ptr);
    assert_eq!(dest_data.as_ptr(), source_ptr);
    assert_eq!(dest_data[0], 0x31);
    assert_eq!(dest_data[dest_data.len() - 1], 0xd4);

    mgr.mutate_with_live_apply(
        &mut hive,
        HiveLogOp::SetValue {
            path: r"ControlSet002\Enum\PCI\VEN_8086",
            name: "ReplayOnly",
            value_type: RegistryValueType::Dword,
            data: &99u32.to_le_bytes(),
        },
        |_| false,
    )
    .unwrap();
    assert_eq!(hive.query_dword(dest_key, "ReplayOnly"), Some(99));

    mgr.provider_mut().crash();
    let provider = mgr.into_provider();
    let booted = HiveManager::new(provider).boot(HiveKind::System).unwrap();
    let booted_dest = booted
        .open_key(r"ControlSet002\Enum\PCI\VEN_8086")
        .expect("booted destination key");
    let booted_data = booted.query_value(booted_dest, "AllocConfig").unwrap().1;
    assert_eq!(booted_data[0], 0x31);
    assert_eq!(booted_data[booted_data.len() - 1], 0xd4);
    assert_eq!(booted.query_dword(booted_dest, "ReplayOnly"), Some(99));
}

#[test]
fn manager_live_apply_replays_repeated_setup_style_mutations() {
    let mut provider = MemoryHiveIoProvider::new();
    let mut hive = Hive::new(HiveKind::System);

    for (service, start, group) in [
        ("Ndis", 0u32, "NDIS Wrapper"),
        ("Tcpip", 1u32, "PNP_TDI"),
        ("Afd", 1u32, "TDI"),
    ] {
        let path = alloc::format!(r"ControlSet001\Services\{}", service);
        {
            let mut manager = HiveManager::for_live_hive(provider, &hive);
            manager
                .mutate_with_live_apply(&mut hive, HiveLogOp::CreateKey { path: &path }, |hive| {
                    hive.create_key(&path);
                    true
                })
                .unwrap();
            provider = manager.into_provider();
        }

        let key = hive.open_key(&path).expect("service key");
        for (name, value) in [("Type", 1u32), ("Start", start), ("ErrorControl", 1u32)] {
            let data = value.to_le_bytes();
            let mut manager = HiveManager::for_live_hive(provider, &hive);
            manager
                .mutate_with_live_apply(
                    &mut hive,
                    HiveLogOp::SetValue {
                        path: &path,
                        name,
                        value_type: RegistryValueType::Dword,
                        data: &data,
                    },
                    |hive| hive.set_value(key, name, RegistryValueType::Dword, data.to_vec()),
                )
                .unwrap();
            provider = manager.into_provider();
        }

        let image_path = alloc::format!(r"system32\drivers\{}.sys", service.to_ascii_lowercase());
        for (name, value_type, value) in [
            (
                "ImagePath",
                RegistryValueType::ExpandSz,
                utf16le_sz(&image_path),
            ),
            ("Group", RegistryValueType::Sz, utf16le_sz(group)),
        ] {
            let mut manager = HiveManager::for_live_hive(provider, &hive);
            manager
                .mutate_with_live_apply(
                    &mut hive,
                    HiveLogOp::SetValue {
                        path: &path,
                        name,
                        value_type,
                        data: &value,
                    },
                    |hive| hive.set_value(key, name, value_type, value.clone()),
                )
                .unwrap();
            provider = manager.into_provider();
        }
    }

    assert!(provider.get_status().log_len > 0);
    let booted = HiveManager::new(provider).boot(HiveKind::System).unwrap();
    let tcpip = booted
        .open_key(r"ControlSet001\Services\Tcpip")
        .expect("Tcpip key");
    assert_eq!(booted.query_dword(tcpip, "Type"), Some(1));
    assert_eq!(booted.query_dword(tcpip, "Start"), Some(1));
    let (ty, data) = booted.query_value(tcpip, "Group").expect("Tcpip Group");
    assert_eq!(ty, RegistryValueType::Sz);
    assert_eq!(data, utf16le_sz("PNP_TDI"));
}

struct LiveApplySetupSeedTarget {
    provider: Option<MemoryHiveIoProvider>,
    hive: Hive,
}

impl LiveApplySetupSeedTarget {
    fn new(kind: HiveKind) -> Self {
        let mut hive = Hive::new(kind);
        if kind == HiveKind::System {
            let select = hive.create_key("Select");
            hive.set_dword(select, "Current", 1);
            hive.create_key("ControlSet001");
            hive.finish_clean_import();
        }
        Self {
            provider: Some(MemoryHiveIoProvider::new()),
            hive,
        }
    }

    fn booted(self, kind: HiveKind) -> Hive {
        HiveManager::new(self.provider.expect("provider"))
            .boot(kind)
            .expect("boot live-apply hive")
    }

    fn with_manager<F>(&mut self, f: F) -> bool
    where
        F: FnOnce(&mut HiveManager<MemoryHiveIoProvider>, &mut Hive) -> bool,
    {
        let provider = self.provider.take().expect("provider");
        let mut manager = HiveManager::for_live_hive(provider, &self.hive);
        let changed = f(&mut manager, &mut self.hive);
        self.provider = Some(manager.into_provider());
        changed
    }

    fn system_rel_path(&self, path: &str) -> String {
        let components: Vec<&str> = path.split('\\').filter(|part| !part.is_empty()).collect();
        let start = if components.len() >= 3
            && components[0].eq_ignore_ascii_case("Registry")
            && components[1].eq_ignore_ascii_case("Machine")
            && components[2].eq_ignore_ascii_case("System")
        {
            3
        } else {
            0
        };
        let relative = components[start..].join("\\");
        self.hive
            .current_control_set()
            .expect("mounted SYSTEM test hive selection")
            .resolve_relative_path(&relative)
    }
}

impl ReactOsSetupSeedTarget for LiveApplySetupSeedTarget {
    fn create_key(&mut self, path: &str) -> bool {
        let path = self.system_rel_path(path);
        self.with_manager(|manager, hive| {
            manager
                .mutate_with_live_apply(hive, HiveLogOp::CreateKey { path: &path }, |hive| {
                    hive.create_key(&path);
                    true
                })
                .is_ok()
        })
    }

    fn set_value(
        &mut self,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> bool {
        if self.value_matches(path, name, value_type, &data) {
            return false;
        }
        let path = self.system_rel_path(path);
        self.with_manager(|manager, hive| {
            let key = hive.create_key(&path);
            let live_data = data.clone();
            manager
                .mutate_with_live_apply(
                    hive,
                    HiveLogOp::SetValue {
                        path: &path,
                        name,
                        value_type,
                        data: &data,
                    },
                    |hive| hive.set_value(key, name, value_type, live_data),
                )
                .is_ok()
        })
    }

    fn has_value(&self, path: &str, name: &str) -> bool {
        let path = self.system_rel_path(path);
        self.hive
            .open_key(&path)
            .and_then(|key| self.hive.query_value(key, name))
            .is_some()
    }

    fn value_matches(
        &self,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: &[u8],
    ) -> bool {
        let path = self.system_rel_path(path);
        self.hive
            .open_key(&path)
            .and_then(|key| self.hive.query_value(key, name))
            .is_some_and(|(ty, existing)| ty == value_type && existing == data)
    }
}

#[test]
fn manager_live_apply_replays_reactos_print_setup_seed() {
    let mut target = LiveApplySetupSeedTarget::new(HiveKind::System);

    let stats = seed_reactos_print_setup_into_target(&mut target);
    assert_eq!(
        stats,
        ReactOsPrintSetupSeedStats {
            root_values: 6,
            environment_values: 2,
            print_processor_values: 2,
            monitor_values: 1,
        }
    );

    assert!(target
        .hive
        .open_key(r"ControlSet001\Control\Print\Environments\Windows x64")
        .is_some());

    let booted = target.booted(HiveKind::System);
    let env = booted
        .open_key(r"ControlSet001\Control\Print\Environments\Windows x64")
        .expect("Windows x64 print environment");
    let (ty, data) = booted.query_value(env, "Directory").expect("Directory");
    assert_eq!(ty, RegistryValueType::Sz);
    assert_eq!(data, utf16le_sz("x64"));

    let processor = booted
        .open_key(r"ControlSet001\Control\Print\Environments\Windows x64\Print Processors\winprint")
        .expect("x64 winprint processor");
    let (ty, data) = booted.query_value(processor, "Driver").expect("Driver");
    assert_eq!(ty, RegistryValueType::Sz);
    assert_eq!(data, utf16le_sz("winprint.dll"));

    let monitor = booted
        .open_key(r"ControlSet001\Control\Print\Monitors\Local Port")
        .expect("local port monitor");
    let (ty, data) = booted.query_value(monitor, "Driver").expect("Driver");
    assert_eq!(ty, RegistryValueType::Sz);
    assert_eq!(data, utf16le_sz("localmon.dll"));
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

struct ReadFaultHiveIoProvider {
    image: Option<Vec<u8>>,
    log: Vec<u8>,
    fail_primary_read: bool,
    fail_log_read: bool,
}

impl ReadFaultHiveIoProvider {
    fn fail_primary_read() -> Self {
        Self {
            image: None,
            log: Vec::new(),
            fail_primary_read: true,
            fail_log_read: false,
        }
    }

    fn fail_log_read(image: Vec<u8>) -> Self {
        Self {
            image: Some(image),
            log: Vec::new(),
            fail_primary_read: false,
            fail_log_read: true,
        }
    }
}

impl HiveIoProvider for ReadFaultHiveIoProvider {
    fn provider_kind(&self) -> HiveIoProviderKind {
        HiveIoProviderKind::FaultInjection
    }

    fn read_primary_image(&mut self) -> Result<Option<Vec<u8>>, HiveIoError> {
        if self.fail_primary_read {
            return Err(HiveIoError::Io);
        }
        Ok(self.image.clone())
    }

    fn write_primary_image_atomic(&mut self, bytes: &[u8]) -> Result<(), HiveIoError> {
        self.image = Some(bytes.to_vec());
        Ok(())
    }

    fn read_log(&mut self) -> Result<Vec<u8>, HiveIoError> {
        if self.fail_log_read {
            return Err(HiveIoError::Io);
        }
        Ok(self.log.clone())
    }

    fn append_log_record(&mut self, bytes: &[u8]) -> Result<(), HiveIoError> {
        self.log.extend_from_slice(bytes);
        Ok(())
    }

    fn truncate_log(&mut self) -> Result<(), HiveIoError> {
        self.log.clear();
        Ok(())
    }

    fn flush_image(&mut self) -> Result<(), HiveIoError> {
        Ok(())
    }

    fn flush_log(&mut self) -> Result<(), HiveIoError> {
        Ok(())
    }

    fn get_status(&self) -> HiveIoStatus {
        HiveIoStatus {
            image_present: self.image.is_some(),
            log_len: self.log.len(),
        }
    }
}

#[test]
fn manager_boot_reports_provider_read_faults() {
    let mut primary_fault = HiveManager::new(ReadFaultHiveIoProvider::fail_primary_read());
    assert!(matches!(
        primary_fault.boot(HiveKind::System),
        Err(HiveBootError::Io(HiveIoError::Io))
    ));

    let image = encode_image(&Hive::new(HiveKind::System));
    let mut log_fault = HiveManager::new(ReadFaultHiveIoProvider::fail_log_read(image));
    assert!(matches!(
        log_fault.boot(HiveKind::System),
        Err(HiveBootError::Io(HiveIoError::Io))
    ));
}

#[test]
fn live_hive_managers_continue_log_sequence_across_calls() {
    let provider = MemoryHiveIoProvider::new();
    let mut mgr = HiveManager::new(provider);
    let mut hive = mgr.boot(HiveKind::System).unwrap();
    let mut provider = mgr.into_provider();

    for (name, value) in [("First", 1u32), ("Second", 2u32)] {
        let mut mgr = HiveManager::for_live_hive(provider, &hive);
        mgr.mutate(
            &mut hive,
            HiveLogOp::SetValue {
                path: r"ControlSet001\Services\Tcpip",
                name,
                value_type: RegistryValueType::Dword,
                data: &value.to_le_bytes(),
            },
        )
        .unwrap();
        provider = mgr.into_provider();
    }

    let booted = HiveManager::new(provider).boot(HiveKind::System).unwrap();
    let key = booted.open_key(r"ControlSet001\Services\Tcpip").unwrap();
    assert_eq!(booted.query_dword(key, "First"), Some(1));
    assert_eq!(booted.query_dword(key, "Second"), Some(2));
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

#[test]
fn try_flush_reports_io_fault_and_preserves_replay_log() {
    let mut mgr = HiveManager::new(FaultInjectionHiveIoProvider::new().fail_image_write_after(1));
    let mut hive = mgr.boot(HiveKind::System).unwrap();
    mgr.mutate(
        &mut hive,
        HiveLogOp::SetValue {
            path: r"ControlSet001\Services\Net",
            name: "Start",
            value_type: RegistryValueType::Dword,
            data: &2u32.to_le_bytes(),
        },
    )
    .unwrap();

    assert_eq!(
        mgr.try_flush(&mut hive),
        Err(HiveFlushError::Io(HiveIoError::Io))
    );

    let provider = mgr.into_provider();
    let booted = HiveManager::new(provider).boot(HiveKind::System).unwrap();
    let key = booted.open_key(r"ControlSet001\Services\Net").unwrap();
    assert_eq!(booted.query_dword(key, "Start"), Some(2));
}
