use super::*;
use nt_config_manager::ConfigManager;

const GUID: &str = "{9a7b0b24-6e57-4c51-ad3c-6d9f5f0e0001}";

/// A Config Manager with two devnodes each exposing the test interface (one enabled, one not).
fn fixture() -> ConfigManager {
    let mut cm = ConfigManager::new();
    let d0 = cm.register_devnode(r"Root\Test\0000", Some("Svc"), None, &[], &[]);
    let d1 = cm.register_devnode(r"Root\Test\0001", Some("Svc"), None, &[], &[]);
    cm.register_interface(d0, GUID, "", true); // enabled
    let i1 = cm.register_interface(d1, GUID, "", true);
    cm.set_interface_state(i1, false); // disabled
    cm
}

fn multi_sz_paths(list: &[u16]) -> alloc::vec::Vec<String> {
    let mut out = alloc::vec::Vec::new();
    let mut cur = alloc::vec::Vec::new();
    for &u in list {
        if u == 0 {
            if cur.is_empty() {
                break; // final NUL
            }
            out.push(
                char::decode_utf16(cur.iter().copied())
                    .map(|r| r.unwrap())
                    .collect::<String>(),
            );
            cur.clear();
        } else {
            cur.push(u);
        }
    }
    out
}

#[test]
fn cfgmgr_list_enabled_only() {
    let cm = fixture();
    // PRESENT (default): only the enabled interface.
    let size = cm_get_device_interface_list_size(
        &cm,
        Some(GUID),
        None,
        CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
    )
    .unwrap();
    let list = cm_get_device_interface_list(
        &cm,
        Some(GUID),
        None,
        size,
        CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
    )
    .unwrap();
    assert_eq!(list.len() as u32, size);
    let paths = multi_sz_paths(&list);
    assert_eq!(paths.len(), 1);
    assert!(paths[0].starts_with(r"\\?\")); // Win32 device path form
    assert!(paths[0].contains("Test#0000"));
    // ALL_DEVICES: both interfaces.
    let all = cm_get_device_interface_list(
        &cm,
        Some(GUID),
        None,
        4096,
        CM_GET_DEVICE_INTERFACE_LIST_ALL_DEVICES,
    )
    .unwrap();
    assert_eq!(multi_sz_paths(&all).len(), 2);
}

#[test]
fn cfgmgr_empty_list_is_single_nul() {
    let cm = ConfigManager::new();
    let size = cm_get_device_interface_list_size(&cm, Some(GUID), None, 0).unwrap();
    assert_eq!(size, 1); // just the terminating NUL
    let list = cm_get_device_interface_list(&cm, Some(GUID), None, 1, 0).unwrap();
    assert_eq!(list, alloc::vec![0u16]);
}

#[test]
fn cfgmgr_edge_cases() {
    let cm = fixture();
    // Null GUID / buffer sizing / bad flags (spec §9.4).
    assert_eq!(
        cm_get_device_interface_list_size(&cm, None, None, 0),
        Err(ConfigRet::InvalidPointer)
    );
    assert_eq!(
        cm_get_device_interface_list_size(&cm, Some(GUID), None, 0x8000),
        Err(ConfigRet::InvalidFlag)
    );
    let size = cm_get_device_interface_list_size(&cm, Some(GUID), None, 0).unwrap();
    assert_eq!(
        cm_get_device_interface_list(&cm, Some(GUID), None, size - 1, 0),
        Err(ConfigRet::BufferSmall)
    );
    assert_eq!(
        configret_to_win32_error(ConfigRet::BufferSmall),
        ERROR_INSUFFICIENT_BUFFER
    );
}

#[test]
fn cfgmgr_device_id_filter() {
    let cm = fixture();
    // Filter to a specific devnode instance (case-insensitive, spec §9.3).
    let list =
        cm_get_device_interface_list(&cm, Some(GUID), Some(r"root\test\0000"), 4096, 0).unwrap();
    assert_eq!(multi_sz_paths(&list).len(), 1);
    // A device with no *enabled* interface → empty.
    let list =
        cm_get_device_interface_list(&cm, Some(GUID), Some(r"Root\Test\0001"), 4096, 0).unwrap();
    assert_eq!(multi_sz_paths(&list).len(), 0);
}

#[test]
fn setupapi_enumerate_and_detail() {
    let cm = fixture();
    let mut sets = DevInfoSets::new();
    // SetupDiGetClassDevs requires DIGCF_DEVICEINTERFACE.
    assert!(!sets
        .get_class_devs(&cm, Some(GUID), DIGCF_PRESENT)
        .is_valid());
    let h = sets.get_class_devs(&cm, Some(GUID), DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    assert!(h.is_valid());
    // Enumerate: index 0 present, index 1 past the (single enabled) interface.
    let e0 = sets.enum_device_interfaces(h, 0).unwrap();
    assert_eq!(e0.guid, GUID);
    assert!(sets.enum_device_interfaces(h, 1).is_none()); // ERROR_NO_MORE_ITEMS
                                                          // Two-call detail: sizing then fetch.
    let (err, required) = sets.get_device_interface_detail(h, 0, 0).unwrap_err();
    assert_eq!(err, ERROR_INSUFFICIENT_BUFFER);
    assert!(required > 0);
    let path = sets.get_device_interface_detail(h, 0, required).unwrap();
    assert_eq!(path.len() as u32, required);
    let s: String = char::decode_utf16(path[..path.len() - 1].iter().copied())
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(s, e0.device_path);
    assert!(s.starts_with(r"\\?\"));
    // Destroy invalidates the handle.
    assert!(sets.destroy_device_info_list(h));
    assert!(sets.enum_device_interfaces(h, 0).is_none());
    assert!(!sets.destroy_device_info_list(h)); // double-destroy fails
}

#[test]
fn device_path_maps_nt_to_win32() {
    assert_eq!(
        device_path(r"\??\{guid}#Root#Test#0000"),
        r"\\?\{guid}#Root#Test#0000"
    );
    assert_eq!(device_path("no-prefix"), "no-prefix");
}
