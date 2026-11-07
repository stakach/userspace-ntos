use super::*;

const DISPLAY_GUID: &str = "{9A7B0B24-6E57-4C51-AD3C-6D9F5F0E0001}";
const OTHER_GUID: &str = "{9A7B0B24-6E57-4C51-AD3C-6D9F5F0E0002}";

fn multistring(paths: &[&str]) -> Vec<u16> {
    let mut encoded = Vec::new();
    for path in paths {
        encoded.extend(path.encode_utf16());
        encoded.push(0);
    }
    encoded.push(0);
    encoded
}

#[test]
fn kernel_interface_query_filters_exact_devnode_class_and_enabled_state() {
    let mut cm = ConfigManager::new();
    let first = cm.register_devnode(r"ROOT\DISPLAY\0000", Some("DisplaySvc"), None, &[], &[]);
    let second = cm.register_devnode(r"ROOT\DISPLAY\0001", Some("DisplaySvc"), None, &[], &[]);
    let first_interface = cm.register_interface(first, DISPLAY_GUID, "", true).unwrap();
    let second_interface = cm.register_interface(second, DISPLAY_GUID, "Port1", false).unwrap();
    cm.register_interface(first, OTHER_GUID, "", true).unwrap();
    let first_path = cm.interface(first_interface).unwrap().symbolic_link.clone();
    let second_path = cm.interface(second_interface).unwrap().symbolic_link.clone();

    assert_eq!(
        cm.kernel_device_interface_multi_sz(&DISPLAY_GUID.to_ascii_lowercase(), None, false),
        Ok(multistring(&[&first_path]))
    );
    assert_eq!(
        cm.kernel_device_interface_multi_sz(DISPLAY_GUID, Some(first), true),
        Ok(multistring(&[&first_path]))
    );
    assert_eq!(
        cm.kernel_device_interface_multi_sz(DISPLAY_GUID, Some(second), false),
        Ok(multistring(&[]))
    );
    assert_eq!(
        cm.kernel_device_interface_multi_sz(DISPLAY_GUID, Some(second), true),
        Ok(multistring(&[&second_path]))
    );
    assert_eq!(
        cm.kernel_device_interface_multi_sz(DISPLAY_GUID, None, true),
        Ok(multistring(&[&first_path, &second_path]))
    );
    assert!(first_path.starts_with(r"\??\"));
    assert!(second_path.starts_with(r"\??\"));
}

#[test]
fn kernel_interface_query_rejects_unowned_devnode_and_invalid_class() {
    let cm = ConfigManager::new();
    assert_eq!(
        cm.kernel_device_interface_multi_sz(DISPLAY_GUID, Some(u64::MAX), false),
        Err(DeviceInterfaceQueryError::UnknownDevnode)
    );
    assert_eq!(
        cm.kernel_device_interface_multi_sz("invalid-guid", None, false),
        Err(DeviceInterfaceQueryError::InvalidGuid)
    );
    assert_eq!(
        cm.kernel_device_interface_multi_sz(DISPLAY_GUID, None, false),
        Ok(alloc::vec![0])
    );
}
