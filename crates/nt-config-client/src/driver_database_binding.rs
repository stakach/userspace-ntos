//! Resolve a device's installed driver through the mounted SYSTEM DriverDatabase.

use alloc::{format, string::String};

use crate::{
    decode_terminated_reg_sz, CriticalDeviceBinding, HiveKeySnapshot, STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_NOT_FOUND,
};

const ROOT: &str = r"\Registry\Machine\System\DriverDatabase";
const STATUS_REVISION_MISMATCH: i32 = 0xC000_0059u32 as i32;

fn valid_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && !component
            .chars()
            .any(|character| matches!(character, '\\' | '/' | '\0'))
}

fn valid_device_id(id: &str) -> bool {
    id.split('\\').all(valid_component)
}

fn checked_snapshot(
    snapshot: HiveKeySnapshot,
    path: &str,
    generation: u64,
) -> Result<HiveKeySnapshot, i32> {
    if snapshot.mount_generation != generation {
        return Err(STATUS_REVISION_MISMATCH);
    }
    if !snapshot.path.eq_ignore_ascii_case(path) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(snapshot)
}

fn one_string(snapshot: &HiveKeySnapshot, name: &str) -> Result<String, i32> {
    let mut values = snapshot
        .values
        .iter()
        .filter(|value| value.name.eq_ignore_ascii_case(name));
    let value = values.next().ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    if values.next().is_some() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    decode_terminated_reg_sz(value.value_type, &value.data)
        .filter(|value| !value.is_empty())
        .ok_or(STATUS_INVALID_PARAMETER)
}

fn optional_string(snapshot: &HiveKeySnapshot, name: &str) -> Result<Option<String>, i32> {
    match one_string(snapshot, name) {
        Ok(value) => Ok(Some(value)),
        Err(STATUS_OBJECT_NAME_NOT_FOUND) => Ok(None),
        Err(status) => Err(status),
    }
}

fn class_guid(snapshot: &HiveKeySnapshot) -> Result<String, i32> {
    let mut values = snapshot
        .values
        .iter()
        .filter(|value| value.name.eq_ignore_ascii_case("Version"));
    let version = values.next().ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    if values.next().is_some() || version.value_type != 3 || version.data.len() < 24 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // Version holds an eight-byte package header followed by a little-endian setup-class GUID.
    let guid = &version.data[8..24];
    Ok(format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        u32::from_le_bytes(guid[0..4].try_into().unwrap()),
        u16::from_le_bytes(guid[4..6].try_into().unwrap()),
        u16::from_le_bytes(guid[6..8].try_into().unwrap()),
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15]
    ))
}

/// Follow the exact DeviceIds → INF → package descriptor → configuration chain.
/// A missing device ID or descriptor is not an installed binding; malformed or ambiguous
/// installed policy is an error rather than a reason to guess a service.
pub fn resolve_driver_database_binding<F>(
    id: &str,
    expected_generation: u64,
    mut lookup: F,
) -> Result<Option<CriticalDeviceBinding>, i32>
where
    F: FnMut(&str) -> Result<HiveKeySnapshot, i32>,
{
    if !valid_device_id(id) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let device_path = format!(r"{}\DeviceIds\{}", ROOT, id);
    let device = match lookup(&device_path) {
        Ok(snapshot) => checked_snapshot(snapshot, &device_path, expected_generation)?,
        Err(STATUS_OBJECT_NAME_NOT_FOUND) => return Ok(None),
        Err(status) => return Err(status),
    };
    let packages_path = format!(r"{}\DriverPackages", ROOT);
    let packages = checked_snapshot(lookup(&packages_path)?, &packages_path, expected_generation)?;
    let mut selected = None;
    for inf in &device.values {
        if inf.value_type != 3 || inf.data.is_empty() || !valid_component(&inf.name) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        for package in &packages.subkeys {
            let name = package.name.as_str();
            if !name
                .get(..inf.name.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&inf.name))
                || name.as_bytes().get(inf.name.len()) != Some(&b'_')
            {
                continue;
            }
            if !valid_component(name) {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let package_path = format!(r"{}\{}", packages_path, name);
            let descriptor_path = format!(r"{}\Descriptors\{}", package_path, id);
            let descriptor = match lookup(&descriptor_path) {
                Ok(snapshot) => checked_snapshot(snapshot, &descriptor_path, expected_generation)?,
                Err(STATUS_OBJECT_NAME_NOT_FOUND) => continue,
                Err(status) => return Err(status),
            };
            let configuration = one_string(&descriptor, "Configuration")?;
            if !valid_component(&configuration) {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let config_path = format!(r"{}\Configurations\{}", package_path, configuration);
            let config =
                checked_snapshot(lookup(&config_path)?, &config_path, expected_generation)?;
            let package =
                checked_snapshot(lookup(&package_path)?, &package_path, expected_generation)?;
            let binding = CriticalDeviceBinding {
                mount_generation: expected_generation,
                matched_id: String::from(id),
                class_guid: class_guid(&package)?,
                service_name: optional_string(&config, "Service")?,
            };
            if selected.replace(binding).is_some() {
                return Err(STATUS_INVALID_PARAMETER);
            }
        }
    }
    Ok(selected)
}
