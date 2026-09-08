use super::*;
use alloc::vec;
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
        hive,
        generation: 7,
        current_control_set: control_set,
    });
    server
}

fn request(path: &str, operation: u16, token: u64, offset: usize, capacity: usize) -> Vec<u8> {
    let header = CmActiveDriverServiceRequest {
        abi_size: core::mem::size_of::<CmActiveDriverServiceRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        operation,
        _reserved: 0,
        value_offset: offset as u32,
        chunk_capacity: capacity as u32,
        path_offset: core::mem::size_of::<CmActiveDriverServiceRequest>() as u32,
        path_len_bytes: (path.encode_utf16().count() * 2) as u32,
        transfer_token: token,
    };
    let mut bytes = header.as_bytes().to_vec();
    for unit in path.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn begin(server: &mut CmServer, path: &str, capacity: usize) -> (CmReply, Vec<u8>) {
    let mut out = vec![0; capacity];
    let reply = server.dispatch(
        opcode::CM_OP_QUERY_ACTIVE_DRIVER_SERVICE,
        &request(path, driver_service_transfer::BEGIN, 0, 0, capacity),
        &mut out,
    );
    if reply.status == STATUS_SUCCESS {
        out.truncate(reply.information as usize);
    }
    (reply, out)
}

fn finish(server: &mut CmServer, path: &str, first: CmReply, mut bytes: Vec<u8>) -> Vec<u8> {
    while bytes.len() < first.detail0 as usize {
        let mut output = [0; 31];
        let reply = server.dispatch(
            opcode::CM_OP_QUERY_ACTIVE_DRIVER_SERVICE,
            &request(
                path,
                driver_service_transfer::PULL,
                first.detail1,
                bytes.len(),
                output.len(),
            ),
            &mut output,
        );
        assert_eq!(reply.status, STATUS_SUCCESS);
        assert_eq!(reply.detail0, first.detail0);
        assert_eq!(reply.detail1, first.detail1);
        bytes.extend_from_slice(&output[..reply.information as usize]);
    }
    bytes
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

#[test]
fn mounted_binding_matches_existing_policy_without_acquiring_leases() {
    let mut server = server(1);
    let binding = server.cm.driver_service_binding("Device").unwrap();
    let expected = encode_driver_service_binding(&server.cm, &binding).unwrap();
    let (reply, bytes) = begin(&mut server, PATH, 4096);
    assert_eq!(reply.status, STATUS_SUCCESS);
    assert_eq!(reply.detail1, 0);
    assert_eq!(payload(&bytes), (7, PHYSICAL, expected.as_slice()));
    assert_eq!(server.system_key_leases.outstanding_count(), 0);
}

#[test]
fn mirror_overrides_deleted_rows_and_injected_devices_cannot_change_mounted_answer() {
    let mut server = server(1);
    let expected = begin(&mut server, PATH, 4096).1;
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
    assert_eq!(begin(&mut server, PATH, 4096).1, expected);
    assert!(server.cm.registry_mut().delete_key(service, true));
    assert_eq!(begin(&mut server, PATH, 4096).1, expected);
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
        assert_eq!(
            begin(&mut server, path, 4096).0.status,
            STATUS_OBJECT_PATH_SYNTAX_BAD
        );
    }
    assert_eq!(begin(&mut server, PHYSICAL, 4096).0.status, STATUS_SUCCESS);
    assert_eq!(
        begin(&mut server, &PATH.to_ascii_lowercase(), 4096)
            .0
            .status,
        STATUS_SUCCESS
    );
}

#[test]
fn incomplete_disabled_and_non_driver_services_do_not_get_launch_defaults() {
    let mut server = server(1);
    let mounted = server.system_hive.as_mut().unwrap();
    let key = mounted
        .hive
        .open_key(r"ControlSet002\Services\Device")
        .unwrap();
    mounted.hive.set_dword(key, "Start", 4);
    assert_eq!(
        begin(&mut server, PATH, 4096).0.status,
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    let hive = &mut server.system_hive.as_mut().unwrap().hive;
    hive.set_dword(key, "Start", 3);
    hive.set_dword(key, "Type", 0x10);
    assert_eq!(
        begin(&mut server, PATH, 4096).0.status,
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    let hive = &mut server.system_hive.as_mut().unwrap().hive;
    hive.set_dword(key, "Type", 1);
    assert!(hive.delete_value(key, "ImagePath"));
    assert_eq!(
        begin(&mut server, PATH, 4096).0.status,
        STATUS_OBJECT_NAME_NOT_FOUND
    );
}

#[test]
fn snapshots_are_concurrent_immutable_and_bound_to_the_original_path() {
    let mut server = server(1);
    let expected = begin(&mut server, PATH, 4096).1;
    let (a, a_bytes) = begin(&mut server, PATH, 13);
    let (b, b_bytes) = begin(&mut server, PHYSICAL, 17);
    assert_ne!(a.detail1, b.detail1);
    let wrong = server.dispatch(
        opcode::CM_OP_QUERY_ACTIVE_DRIVER_SERVICE,
        &request(PHYSICAL, driver_service_transfer::PULL, a.detail1, 13, 1),
        &mut [0],
    );
    assert_eq!(wrong.status, STATUS_INVALID_PARAMETER);
    let mounted = server.system_hive.as_mut().unwrap();
    let service = mounted
        .hive
        .open_key(r"ControlSet002\Services\Device")
        .unwrap();
    string(
        &mut mounted.hive,
        service,
        "ImagePath",
        r"system32\drivers\updated.sys",
    );
    mounted.generation += 1;
    assert_eq!(finish(&mut server, PHYSICAL, b, b_bytes), expected);
    assert_eq!(finish(&mut server, PATH, a, a_bytes), expected);
    let updated = begin(&mut server, PATH, 4096).1;
    assert_ne!(updated, expected);
    assert_eq!(payload(&updated).0, 8);
}

#[test]
fn transfer_identity_survives_moves_but_not_cm_restart_or_reconstruction() {
    let mut first = server(1);
    let (old, _) = begin(&mut first, PATH, 1);
    let mut second = server(2);
    let (new, bytes) = begin(&mut second, PATH, 1);
    assert_ne!(old.detail1, new.detail1);
    let reply = second.dispatch(
        opcode::CM_OP_QUERY_ACTIVE_DRIVER_SERVICE,
        &request(PATH, driver_service_transfer::PULL, old.detail1, 1, 1),
        &mut [0],
    );
    assert_eq!(reply.status, STATUS_INVALID_PARAMETER);
    let mut moved = second;
    assert_eq!(payload(&finish(&mut moved, PATH, new, bytes)).0, 7);
    let mut reconstructed = CmServer::new_with_identity_source(first.identities.clone());
    reconstructed.system_hive = first.system_hive.take();
    let (replacement, _) = begin(&mut reconstructed, PATH, 1);
    assert_ne!(old.detail1, replacement.detail1);
}

#[test]
fn malformed_envelope_and_removed_legacy_operations_cannot_acquire_owners() {
    let mut server = server(1);
    let mut input = request(PATH, driver_service_transfer::BEGIN, 0, 0, 1);
    input.push(0);
    assert_eq!(
        server
            .dispatch(opcode::CM_OP_QUERY_ACTIVE_DRIVER_SERVICE, &input, &mut [0])
            .status,
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        begin(&mut server, "\0", 1).0.status,
        STATUS_INVALID_PARAMETER
    );
    // Former 24-byte OPEN/CLOSE envelopes are not accepted as 16-byte resolve requests.
    for operation in [1u16, 2] {
        let mut old = [0u8; 24];
        old[..2].copy_from_slice(&24u16.to_le_bytes());
        old[2..4].copy_from_slice(&CM_ABI_VERSION.to_le_bytes());
        old[4..6].copy_from_slice(&operation.to_le_bytes());
        old[6..8].copy_from_slice(&hive_mount::SYSTEM.to_le_bytes());
        assert_eq!(
            server
                .dispatch(opcode::CM_OP_RESOLVE_SYSTEM_HIVE_PATH, &old, &mut [])
                .status,
            STATUS_INVALID_PARAMETER
        );
    }
    assert_eq!(server.system_key_leases.outstanding_count(), 0);
}

#[test]
fn projection_depth_and_bytes_are_bounded_and_failure_does_not_retire_another_reader() {
    let mut server = server(1);
    let expected = begin(&mut server, PATH, 4096).1;
    let (held, bytes) = begin(&mut server, PATH, 1);
    let mut path = String::from(r"ControlSet002\Enum");
    for _ in 0..=MAX_ENUM_DEPTH {
        path.push_str("\\x");
    }
    server.system_hive.as_mut().unwrap().hive.create_key(&path);
    assert_eq!(
        begin(&mut server, PATH, 4096).0.status,
        STATUS_INSUFFICIENT_RESOURCES
    );
    assert_eq!(finish(&mut server, PATH, held, bytes), expected);
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
    let path = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\D\u{e9}vice";
    let (reply, bytes) = begin(&mut server, path, 4096);
    assert_eq!(reply.status, STATUS_SUCCESS);
    assert!(payload(&bytes).1.ends_with("D\u{e9}vice"));
}
