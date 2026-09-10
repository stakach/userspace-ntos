use super::*;
use nt_config_manager::{encode_sz, SERVICE_DEMAND_START};

const PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Services\Device";
const PHYSICAL: &str = r"\Registry\Machine\System\ControlSet002\Services\Device";

fn string(hive: &mut Hive, key: CellId, name: &str, value: &str) {
    assert!(hive.set_value(key, name, RegistryValueType::Sz, encode_sz(value)));
}

fn server(incarnation: u32) -> CmServer {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 2);
    let service = hive.create_key(r"ControlSet002\Services\Device");
    hive.set_dword(service, "Type", 1);
    hive.set_dword(service, "Start", SERVICE_DEMAND_START);
    string(
        &mut hive,
        service,
        "ImagePath",
        r"system32\drivers\real.sys",
    );
    let device = hive.create_key(r"ControlSet002\Enum\PCI\VEN_1234\0");
    string(&mut hive, device, "Service", "Device");
    string(&mut hive, device, "PdoName", r"\Device\RealPdo");
    string(&mut hive, device, "Driver", r"{Class}\0001");
    let linkage = hive.create_key(r"ControlSet002\Control\Class\{Class}\0001\Linkage");
    string(&mut hive, linkage, "Export", r"\Device\RealExport");
    hive.finish_clean_import();
    let control_set = hive.current_control_set().unwrap();
    let cm = config_manager_from_system_hive(&hive, &control_set);
    let mut server =
        CmServer::with_config_for_incarnation(cm, NonZeroU32::new(incarnation).unwrap());
    server.system_hive = Some(MountedSystemHive {
        identity: server.identities.take().unwrap(),
        hardware_profile: nt_hive_core::HardwareProfileAlias::capture(&hive, &control_set)
            .unwrap(),
        hive,
        generation: 7,
        current_control_set: control_set,
    });
    server
}

fn payload(bytes: &[u8]) -> (u64, &str, &[u8]) {
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_MAGIC
    );
    assert_eq!(
        u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
        CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_VERSION
    );
    assert_eq!(u16::from_le_bytes(bytes[6..8].try_into().unwrap()), 32);
    let generation = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let path_len = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
    let binding_len = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
    assert_eq!(&bytes[24..32], &[0; 8]);
    assert_eq!(bytes.len(), 32 + path_len + binding_len);
    (
        generation,
        core::str::from_utf8(&bytes[32..32 + path_len]).unwrap(),
        &bytes[32 + path_len..],
    )
}

fn query(server: &CmServer, path: &str) -> Result<Vec<u8>, i32> {
    capture(
        server.system_hive.as_ref().ok_or(STATUS_DEVICE_NOT_READY)?,
        path,
        nt_config_abi::CM_RETAINED_SNAPSHOT_MAX_BYTES,
    )
}

#[test]
fn mounted_binding_matches_existing_policy_without_acquiring_leases() {
    let mut server = server(1);
    let binding = server.cm.driver_service_binding("Device").unwrap();
    let expected = encode_driver_service_binding(&server.cm, &binding).unwrap();
    let bytes = query(&server, PATH).unwrap();
    assert_eq!(payload(&bytes), (7, PHYSICAL, expected.as_slice()));
    assert_eq!(server.system_key_leases.outstanding_count(), 0);
}

#[test]
fn encoded_envelope_quota_is_checked_before_blob_allocation() {
    let server = server(1);
    let mounted = server.system_hive.as_ref().unwrap();
    let expected = query(&server, PATH).unwrap();
    assert_eq!(capture(mounted, PATH, expected.len()).unwrap(), expected);
    assert_eq!(
        capture(mounted, PATH, expected.len() - 1),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(
        capture(mounted, PATH, 0),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
}

#[test]
fn mirror_overrides_deleted_rows_and_injected_devices_cannot_change_mounted_answer() {
    let mut server = server(1);
    let expected = query(&server, PATH).unwrap();
    let service = server
        .cm
        .registry()
        .open_key(&alloc::format!("{}\\Device", SERVICES_PATH))
        .unwrap();
    server.cm.registry_mut().set_dword(service, "Type", 0x10);
    server.cm.registry_mut().set_value(
        service,
        "ImagePath",
        RegistryValueType::Sz,
        encode_sz("wrong.exe"),
    );
    let linkage = server
        .cm
        .registry()
        .open_key(&alloc::format!(
            "{}\\{{Class}}\\0001\\Linkage",
            CONTROL_CLASS_PATH
        ))
        .unwrap();
    server.cm.registry_mut().set_value(
        linkage,
        "Export",
        RegistryValueType::Sz,
        encode_sz("wrong export"),
    );
    let extra = server
        .cm
        .registry_mut()
        .create_key(&alloc::format!("{}\\ROOT\\Injected\\0", ENUM_PATH));
    server.cm.registry_mut().set_value(
        extra,
        "Service",
        RegistryValueType::Sz,
        encode_sz("Device"),
    );
    assert_eq!(query(&server, PATH).unwrap(), expected);
    assert!(server.cm.registry_mut().delete_key(service, true));
    assert_eq!(query(&server, PATH).unwrap(), expected);
}

#[test]
fn only_exact_active_services_children_are_admitted() {
    let mut server = server(1);
    server
        .system_hive
        .as_mut()
        .unwrap()
        .hive
        .create_key(r"ControlSet001\Services\Device");
    server
        .system_hive
        .as_mut()
        .unwrap()
        .hive
        .create_key(r"ControlSet002\Services\Device\Child");
    for path in [
        r"\Registry\Machine\System\ControlSet001\Services\Device",
        r"\Registry\Machine\System\CurrentControlSet\Services\Device\Child",
        r"\Registry\Machine\System\CurrentControlSet\Services",
    ] {
        assert_eq!(query(&server, path), Err(STATUS_OBJECT_PATH_SYNTAX_BAD));
    }
    assert!(query(&server, PHYSICAL).is_ok());
    assert!(query(&server, &PATH.to_ascii_lowercase()).is_ok());
}

#[test]
fn incomplete_disabled_and_non_driver_services_do_not_get_launch_defaults() {
    let mut server = server(1);
    let key = server
        .system_hive
        .as_mut()
        .unwrap()
        .hive
        .open_key(r"ControlSet002\Services\Device")
        .unwrap();
    server
        .system_hive
        .as_mut()
        .unwrap()
        .hive
        .set_dword(key, "Start", 4);
    assert_eq!(query(&server, PATH), Err(STATUS_OBJECT_NAME_NOT_FOUND));
    let hive = &mut server.system_hive.as_mut().unwrap().hive;
    hive.set_dword(key, "Start", 3);
    hive.set_dword(key, "Type", 0x10);
    assert_eq!(query(&server, PATH), Err(STATUS_OBJECT_NAME_NOT_FOUND));
    let hive = &mut server.system_hive.as_mut().unwrap().hive;
    hive.set_dword(key, "Type", 1);
    assert!(hive.delete_value(key, "ImagePath"));
    assert_eq!(query(&server, PATH), Err(STATUS_OBJECT_NAME_NOT_FOUND));
}

#[test]
fn projection_depth_and_bytes_are_bounded() {
    let mut server = server(1);
    let mut path = String::from(r"ControlSet002\Enum");
    for _ in 0..=MAX_ENUM_DEPTH {
        path.push_str("\\x");
    }
    server.system_hive.as_mut().unwrap().hive.create_key(&path);
    assert_eq!(query(&server, PATH), Err(STATUS_INSUFFICIENT_RESOURCES));
    let mut budget = ProjectionBudget {
        keys: 0,
        bytes: MAX_PROJECTED_BYTES,
    };
    assert_eq!(budget.bytes(1), Err(STATUS_INSUFFICIENT_RESOURCES));
}

#[test]
fn unicode_service_paths_are_not_truncated_to_ascii() {
    let mut server = server(1);
    let hive = &mut server.system_hive.as_mut().unwrap().hive;
    let key = hive.create_key("ControlSet002\\Services\\D\u{e9}vice");
    hive.set_dword(key, "Type", 1);
    hive.set_dword(key, "Start", 3);
    string(hive, key, "ImagePath", "system32\\drivers\\d\u{e9}vice.sys");
    let bytes = query(
        &server,
        "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\D\u{e9}vice",
    )
    .unwrap();
    assert!(payload(&bytes).1.ends_with("D\u{e9}vice"));
}
