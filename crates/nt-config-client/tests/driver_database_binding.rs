use std::collections::BTreeMap;

use nt_config_client::{
    resolve_driver_database_binding, HiveKeySnapshot, HiveSubkeySnapshot, HiveValueSnapshot,
};

const ROOT: &str = r"\Registry\Machine\System\DriverDatabase";
const MISSING: i32 = 0xc000_0034u32 as i32;

fn key(path: &str, subkeys: &[&str], values: &[(&str, u32, Vec<u8>)]) -> HiveKeySnapshot {
    HiveKeySnapshot {
        mount_generation: 7,
        path: path.into(),
        class_name: None,
        security_descriptor: None,
        subkeys: subkeys
            .iter()
            .map(|name| HiveSubkeySnapshot {
                name: (*name).into(),
                class_name: None,
            })
            .collect(),
        values: values
            .iter()
            .map(|(name, value_type, data)| HiveValueSnapshot {
                name: (*name).into(),
                value_type: *value_type,
                data: data.clone(),
            })
            .collect(),
    }
}

fn sz(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn fixture() -> BTreeMap<String, HiveKeySnapshot> {
    let mut keys = BTreeMap::new();
    for (id, inf, package, config, service, guid) in [
        (
            "*PNP0303",
            "keyboard.inf",
            "keyboard.inf_amd64_cb5e7786929726a6",
            "PS2_Inst.NT",
            "i8042prt",
            0x4D36E96Bu32,
        ),
        (
            "*PNP0F13",
            "msmouse.inf",
            "msmouse.inf_amd64_45e9a8938dc38d9c",
            "PS2_Inst",
            "i8042prt",
            0x4D36E96Fu32,
        ),
    ] {
        let device = format!(r"{}\DeviceIds\{}", ROOT, id);
        keys.insert(device.clone(), key(&device, &[], &[(inf, 3, vec![1])]));
        let package_path = format!(r"{}\DriverPackages\{}", ROOT, package);
        let mut version = vec![0; 24];
        version[8..12].copy_from_slice(&guid.to_le_bytes());
        version[12..14].copy_from_slice(&0xE325u16.to_le_bytes());
        version[14..16].copy_from_slice(&0x11CEu16.to_le_bytes());
        version[16..24].copy_from_slice(&[0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18]);
        keys.insert(
            package_path.clone(),
            key(&package_path, &[], &[("Version", 3, version)]),
        );
        let descriptor = format!(r"{}\Descriptors\{}", package_path, id);
        keys.insert(
            descriptor.clone(),
            key(&descriptor, &[], &[("Configuration", 1, sz(config))]),
        );
        let configuration = format!(r"{}\Configurations\{}", package_path, config);
        keys.insert(
            configuration.clone(),
            key(&configuration, &[], &[("Service", 1, sz(service))]),
        );
    }
    let packages = format!(r"{}\DriverPackages", ROOT);
    keys.insert(
        packages.clone(),
        key(
            &packages,
            &[
                "keyboard.inf_amd64_cb5e7786929726a6",
                "msmouse.inf_amd64_45e9a8938dc38d9c",
            ],
            &[],
        ),
    );
    keys
}

#[test]
fn released_ps2_ids_resolve_exact_driver_packages() {
    let keys = fixture();
    for (id, class) in [
        ("*PNP0303", "{4D36E96B-E325-11CE-BFC1-08002BE10318}"),
        ("*PNP0F13", "{4D36E96F-E325-11CE-BFC1-08002BE10318}"),
    ] {
        let binding =
            resolve_driver_database_binding(id, 7, |path| keys.get(path).cloned().ok_or(MISSING))
                .unwrap()
                .unwrap();
        assert_eq!(binding.matched_id, id);
        assert_eq!(binding.service_name.as_deref(), Some("i8042prt"));
        assert_eq!(binding.class_guid, class);
    }
    assert_eq!(
        resolve_driver_database_binding("*PNP9999", 7, |path| {
            keys.get(path).cloned().ok_or(MISSING)
        })
        .unwrap(),
        None
    );
    assert_eq!(
        resolve_driver_database_binding(r"ACPI\PNP0303", 7, |path| {
            keys.get(path).cloned().ok_or(MISSING)
        })
        .unwrap(),
        None
    );
}

#[test]
fn installed_driverless_configuration_is_a_valid_binding() {
    let mut keys = fixture();
    let id = r"ACPI\FixedButton";
    let inf = "machine.inf";
    let package = "machine.inf_amd64_797c32efce4700bd";
    let device = format!(r"{}\DeviceIds\{}", ROOT, id);
    keys.insert(device.clone(), key(&device, &[], &[(inf, 3, vec![1])]));
    let packages = format!(r"{}\DriverPackages", ROOT);
    keys.get_mut(&packages)
        .unwrap()
        .subkeys
        .push(HiveSubkeySnapshot {
            name: package.into(),
            class_name: None,
        });
    let package_path = format!(r"{}\{}", packages, package);
    let mut version = vec![0; 24];
    version[8..12].copy_from_slice(&0x4D36E97Du32.to_le_bytes());
    keys.insert(
        package_path.clone(),
        key(&package_path, &[], &[("Version", 3, version)]),
    );
    let descriptor = format!(r"{}\Descriptors\{}", package_path, id);
    keys.insert(
        descriptor.clone(),
        key(&descriptor, &[], &[("Configuration", 1, sz("NO_DRV"))]),
    );
    let configuration = format!(r"{}\Configurations\NO_DRV", package_path);
    keys.insert(configuration.clone(), key(&configuration, &[], &[]));
    let binding =
        resolve_driver_database_binding(id, 7, |path| keys.get(path).cloned().ok_or(MISSING))
            .unwrap()
            .unwrap();
    assert_eq!(binding.matched_id, id);
    assert_eq!(binding.service_name, None);
}
