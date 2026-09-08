//! A service-path query captures one mounted-hive authority, without acquiring key leases.

use super::*;
use nt_config_abi::{
    CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES, CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_MAGIC,
    CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_VERSION,
};
use nt_config_manager::{
    RegistryKeyId, RegistryValue, CONTROL_CLASS_PATH, ENUM_PATH, SERVICES_PATH,
};

const MAX_ENUM_DEPTH: usize = 64;
const MAX_ENUM_KEYS: usize = 16_384;
const MAX_PROJECTED_BYTES: usize = 4 * 1024 * 1024;
const STATUS_OBJECT_PATH_SYNTAX_BAD: i32 = 0xc000_003bu32 as i32;

struct ProjectionBudget {
    keys: usize,
    bytes: usize,
}

impl ProjectionBudget {
    fn bytes(&mut self, count: usize) -> Result<(), i32> {
        self.bytes = self
            .bytes
            .checked_add(count)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        if self.bytes > MAX_PROJECTED_BYTES {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        Ok(())
    }
}

fn copy_values(
    hive: &Hive,
    source: CellId,
    cm: &mut ConfigManager,
    target: RegistryKeyId,
    names: &[&str],
    budget: &mut ProjectionBudget,
) -> Result<(), i32> {
    for name in names {
        let Some((kind, value)) = hive.query_value(source, name) else {
            continue;
        };
        budget.bytes(value.len())?;
        let mut data = Vec::new();
        data.try_reserve_exact(value.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        data.extend_from_slice(value);
        if !cm.registry_mut().set_value(target, name, kind, data) {
            return Err(STATUS_REGISTRY_CORRUPT);
        }
    }
    Ok(())
}

fn mounted_string(hive: &Hive, key: CellId, name: &str) -> Option<String> {
    let (value_type, data) = hive.query_value(key, name)?;
    RegistryValue {
        name: String::new(),
        value_type,
        data: data.into(),
    }
    .as_string()
}

fn project_enum(
    hive: &Hive,
    key: CellId,
    instance: &mut String,
    depth: usize,
    service: &str,
    control_set: &str,
    cm: &mut ConfigManager,
    budget: &mut ProjectionBudget,
) -> Result<(), i32> {
    if depth > MAX_ENUM_DEPTH || budget.keys == MAX_ENUM_KEYS {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    budget.keys += 1;
    // Only the mounted Service value can admit a devnode into this snapshot.
    if !instance.is_empty() {
        if let Some((_, value)) = hive.query_value(key, "Service") {
            budget.bytes(value.len())?;
        }
        if mounted_string(hive, key, "Service")
            .is_some_and(|value| value.eq_ignore_ascii_case(service))
        {
            budget.bytes(instance.len())?;
            let path = alloc::format!("{}\\{}", ENUM_PATH, instance);
            let target = cm.registry_mut().create_key(&path);
            copy_values(
                hive,
                key,
                cm,
                target,
                &[
                    "Service",
                    "PdoName",
                    "Driver",
                    "HardwareID",
                    "CompatibleIDs",
                ],
                budget,
            )?;
            if let Some(driver) = cm.registry().query_string(target, "Driver") {
                if driver.len() > CM_MAX_HIVE_PATH_UNITS * 4 {
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
                // Linkage has the same mounted authority as the selected Enum row.
                let source = alloc::format!("{}\\Control\\Class\\{}\\Linkage", control_set, driver);
                if let Some(source) = hive.open_key(&source) {
                    let destination = alloc::format!("{}\\{}\\Linkage", CONTROL_CLASS_PATH, driver);
                    let destination = cm.registry_mut().create_key(&destination);
                    copy_values(hive, source, cm, destination, &["Export"], budget)?;
                }
            }
        }
    }
    for index in 0..hive.subkey_count(key) {
        let name = hive
            .subkey_name_by_index(key, index)
            .ok_or(STATUS_REGISTRY_CORRUPT)?;
        let child = hive.open_subkey(key, name).ok_or(STATUS_REGISTRY_CORRUPT)?;
        let old_len = instance.len();
        let extra = name
            .len()
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        if old_len
            .checked_add(extra)
            .is_none_or(|len| len > CM_MAX_HIVE_PATH_UNITS * 4)
        {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        instance
            .try_reserve(extra)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        if old_len != 0 {
            instance.push('\\');
        }
        instance.push_str(name);
        project_enum(
            hive,
            child,
            instance,
            depth + 1,
            service,
            control_set,
            cm,
            budget,
        )?;
        instance.truncate(old_len);
    }
    Ok(())
}

pub(super) fn capture(
    mounted: &MountedSystemHive,
    path: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, i32> {
    let hive = &mounted.hive;
    let relative = system_hive_relative_path(path, &mounted.current_control_set)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let candidate = hive
        .open_key(&relative)
        .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let services_path = alloc::format!("{}\\Services", mounted.current_control_set.as_str());
    let services = hive
        .open_key(&services_path)
        .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let canonical = hive.key_path(candidate).ok_or(STATUS_REGISTRY_CORRUPT)?;
    let service_name = canonical
        .rsplit('\\')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if hive.open_subkey(services, service_name) != Some(candidate) {
        return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
    }
    let envelope_bytes = CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES
        .checked_add(SYSTEM_HIVE_PATH.len())
        .and_then(|length| length.checked_add(canonical.len()))
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let binding_budget = max_bytes
        .checked_sub(envelope_bytes)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    if binding_budget < CM_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }

    // This private projection reuses typed registry policy. Its real, temporary RegistryKeyIds
    // never escape into the snapshot, and no data is read from the mutable CM mirror.
    let mut cm = ConfigManager::new();
    let mut budget = ProjectionBudget { keys: 0, bytes: 0 };
    let service_key =
        cm.registry_mut()
            .create_key(&alloc::format!("{}\\{}", SERVICES_PATH, service_name));
    copy_values(
        hive,
        candidate,
        &mut cm,
        service_key,
        &[
            "Type",
            "Start",
            "ImagePath",
            "ObjectName",
            "ErrorControl",
            "Group",
            "ClassGUID",
            "Tag",
        ],
        &mut budget,
    )?;
    // Reject disabled/non-driver/incomplete service records before traversing Enum.
    cm.service_start_spec(service_name)
        .filter(|spec| matches!(spec, nt_config_manager::ServiceStartSpec::Driver(_)))
        .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let enum_path = alloc::format!("{}\\Enum", mounted.current_control_set.as_str());
    if let Some(enum_key) = hive.open_key(&enum_path) {
        project_enum(
            hive,
            enum_key,
            &mut String::new(),
            0,
            service_name,
            mounted.current_control_set.as_str(),
            &mut cm,
            &mut budget,
        )?;
    }
    let binding = cm
        .driver_service_binding(service_name)
        .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    if driver_service_binding_encoded_len(&cm, &binding).ok_or(STATUS_INSUFFICIENT_RESOURCES)?
        > binding_budget
    {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let binding =
        encode_driver_service_binding(&cm, &binding).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let physical = alloc::format!("{}{}", SYSTEM_HIVE_PATH, canonical);
    let total = CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES
        .checked_add(physical.len())
        .and_then(|length| length.checked_add(binding.len()))
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    if total > max_bytes {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let path_len = u32::try_from(physical.len()).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let binding_len = u32::try_from(binding.len()).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(total)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    push_u32(&mut output, CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_MAGIC);
    push_u16(&mut output, CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_VERSION);
    push_u16(
        &mut output,
        CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES as u16,
    );
    output.extend_from_slice(&mounted.generation.to_le_bytes());
    push_u32(&mut output, path_len);
    push_u32(&mut output, binding_len);
    output.extend_from_slice(&0u64.to_le_bytes());
    output.extend_from_slice(physical.as_bytes());
    output.extend_from_slice(&binding);
    Ok(output)
}

#[cfg(test)]
mod tests;
