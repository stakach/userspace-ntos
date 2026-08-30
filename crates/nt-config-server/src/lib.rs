//! Transport-agnostic NT Configuration Manager (registry) service dispatcher.
//!
//! Decodes a wire request ([`nt_config_abi`]) and drives the `nt-config-manager`
//! core, returning a [`CmReply`]. Wrapping the registry authority behind SURT lets
//! it run as an isolated service the executive/PnP/SCM reach over rings. The current
//! ABI exposes path-addressed keys, DWORD and raw typed values, semantic devnode property queries,
//! and opaque leases for stable native handles into the mounted SYSTEM hive.

#![no_std]

extern crate alloc;

mod key_lease;
mod mutation;
mod snapshot;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use key_lease::{SystemKeyLeaseBank, SystemKeyLeaseError};
use mutation::{decode_mutation_journal, HiveMutation, MutationLeaseBank, MutationLeaseError};
use snapshot::{SnapshotBank, SnapshotChunk, SnapshotPool};

use nt_config_abi::{
    device_action_kind, device_action_service, device_action_transfer, device_property_transfer,
    driver_service_class, driver_service_transfer, hive_checkpoint_transfer, hive_import_transfer,
    hive_key_lease_operation, hive_key_transfer, hive_mount, hive_mutation_transfer, key_flags,
    launch_plan_kind, launch_plan_transfer, leased_hive_record_kind, network_plan_kind, opcode,
    pnp_query_kind, pnp_query_transfer, read_utf16, win32_service_plan_kind,
    win32_service_process_kind, CmDeviceActionRequest, CmDevicePropertyRequest,
    CmDriverServiceRequest, CmEnumerateKeyRequest, CmHiveCheckpointHeader, CmHiveCheckpointRequest,
    CmHiveExportHeader, CmHiveImportRequest, CmHiveKeyLeaseRequest, CmHiveKeyRequest,
    CmHiveMutationRequest, CmKeyRequest, CmLaunchPlanRequest, CmLeasedHiveKeyRequest,
    CmLeasedHiveRecordRequest, CmPnpQueryRequest, CmRawValueRequest, CmReply, CmValueRequest,
    CM_ABI_VERSION, CM_DEVICE_ACTION_CHUNK_BYTES, CM_DEVICE_ACTION_SNAPSHOT_HEADER_BYTES,
    CM_DEVICE_ACTION_SNAPSHOT_MAGIC, CM_DEVICE_ACTION_SNAPSHOT_VERSION,
    CM_DEVICE_PROPERTY_CHUNK_BYTES, CM_DRIVER_SERVICE_CHUNK_BYTES,
    CM_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES, CM_DRIVER_SERVICE_SNAPSHOT_MAGIC,
    CM_DRIVER_SERVICE_SNAPSHOT_VERSION, CM_HIVE_CHECKPOINT_CHUNK_BYTES,
    CM_HIVE_CHECKPOINT_HEADER_BYTES, CM_HIVE_CHECKPOINT_MAGIC, CM_HIVE_CHECKPOINT_VERSION,
    CM_HIVE_EXPORT_HEADER_BYTES, CM_HIVE_EXPORT_MAGIC, CM_HIVE_EXPORT_VERSION,
    CM_HIVE_IMPORT_CHUNK_BYTES, CM_HIVE_KEY_CHUNK_BYTES, CM_HIVE_KEY_RECORD_HEADER_BYTES,
    CM_HIVE_KEY_RECORD_MAGIC, CM_HIVE_KEY_RECORD_VERSION, CM_HIVE_KEY_SNAPSHOT_HEADER_BYTES,
    CM_HIVE_KEY_SNAPSHOT_MAGIC, CM_HIVE_KEY_SNAPSHOT_VERSION, CM_HIVE_MUTATION_CHUNK_BYTES,
    CM_LAUNCH_PLAN_CHUNK_BYTES, CM_LAUNCH_PLAN_SNAPSHOT_HEADER_BYTES,
    CM_LAUNCH_PLAN_SNAPSHOT_MAGIC, CM_LAUNCH_PLAN_SNAPSHOT_VERSION, CM_MAX_HIVE_PATH_UNITS,
    CM_MAX_HIVE_VALUE_NAME_UNITS, CM_MAX_INSTANCE_UNITS, CM_MAX_PNP_AUX_BYTES,
    CM_MAX_SERVICE_UNITS, CM_NETWORK_PLAN_SNAPSHOT_HEADER_BYTES, CM_NETWORK_PLAN_SNAPSHOT_MAGIC,
    CM_NETWORK_PLAN_SNAPSHOT_VERSION, CM_OPTIONAL_BLOB_ABSENT, CM_OPTIONAL_STRING_ABSENT,
    CM_OPTIONAL_U32_ABSENT, CM_PNP_QUERY_SNAPSHOT_HEADER_BYTES, CM_PNP_QUERY_SNAPSHOT_MAGIC,
    CM_PNP_QUERY_SNAPSHOT_VERSION, CM_WIN32_SERVICE_PLAN_SNAPSHOT_HEADER_BYTES,
    CM_WIN32_SERVICE_PLAN_SNAPSHOT_MAGIC, CM_WIN32_SERVICE_PLAN_SNAPSHOT_VERSION,
};
use nt_config_manager::{
    device_property, ConfigManager, CriticalDeviceBindingError, DeviceActionEvent,
    DeviceActionIntent, DeviceActionJournal, DeviceActionJournalError, DeviceActionKind,
    DevicePropertySource, DriverServiceBinding, DriverServiceClass, RegistryTransaction,
    RegistryValueType, Win32ServiceProcessKind, Win32ServiceProcessLaunch, SERVICE_BOOT_START,
    SERVICE_DEMAND_START, SERVICE_SYSTEM_START,
};
use nt_hive_core::{
    collect_reactos_network_adapter_bindings, decode_image, encode_log_record, try_encode_image,
    try_encode_subtree_image, CellId, CurrentControlSet, Hive, HiveEncodeError, HiveKind,
    HiveLogOp, HiveSubtreeEncodeError, HiveTransaction, ReactOsNetworkAdapterBinding,
    SYSTEM_HIVE_PATH,
};

/// CM admits multiple immutable key readers, but abandoned transfers must not retain an unbounded
/// share of the isolated service heap. Admission failure never retires an existing reader.
const MAX_OUTSTANDING_HIVE_KEY_SNAPSHOTS: usize = 32;
const MAX_RETAINED_HIVE_KEY_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_HANDLE: i32 = 0xC000_0008u32 as i32;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;
const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001Au32 as i32;
const STATUS_NO_SUCH_DEVICE: i32 = 0xC000_000Eu32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_KEY_DELETED: i32 = 0xC000_017Cu32 as i32;
const STATUS_REVISION_MISMATCH: i32 = 0xC000_0059u32 as i32;
const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;
const STATUS_DEVICE_NOT_READY: i32 = 0xC000_00A3u32 as i32;
const STATUS_CANNOT_DELETE: i32 = 0xC000_0121u32 as i32;
const STATUS_INVALID_SYSTEM_SERVICE: i32 = 0xC000_001Cu32 as i32;
const STATUS_NOT_SUPPORTED: i32 = 0xC000_00BBu32 as i32;
const STATUS_REGISTRY_CORRUPT: i32 = 0xC000_014Cu32 as i32;
const STATUS_DEVICE_BUSY: i32 = 0x8000_0011u32 as i32;

/// Max UTF-16 units in a decoded key path / value name.
const MAX_NAME_UNITS: usize = 512;

fn reply(status: i32, detail0: u64) -> CmReply {
    reply_with_info(status, 0, detail0, 0)
}

fn reply_with_info(status: i32, information: u32, detail0: u64, detail1: u64) -> CmReply {
    CmReply {
        status,
        information,
        detail0,
        detail1,
    }
}

fn device_action_journal_status(error: DeviceActionJournalError) -> i32 {
    match error {
        DeviceActionJournalError::InvalidGeneration => STATUS_REVISION_MISMATCH,
        DeviceActionJournalError::InsufficientResources => STATUS_INSUFFICIENT_RESOURCES,
        DeviceActionJournalError::PendingInstance => STATUS_DEVICE_BUSY,
        DeviceActionJournalError::AlreadySeeded
        | DeviceActionJournalError::DuplicateInstance
        | DeviceActionJournalError::InvalidTransition
        | DeviceActionJournalError::StaleAcknowledgement => STATUS_INVALID_PARAMETER,
    }
}

fn critical_device_binding_status(error: CriticalDeviceBindingError) -> i32 {
    match error {
        CriticalDeviceBindingError::InvalidId => STATUS_INVALID_PARAMETER,
        CriticalDeviceBindingError::MalformedBinding => STATUS_REGISTRY_CORRUPT,
        CriticalDeviceBindingError::InsufficientResources => STATUS_INSUFFICIENT_RESOURCES,
    }
}

fn snapshot_reply(chunk: SnapshotChunk) -> CmReply {
    reply_with_info(
        STATUS_SUCCESS,
        chunk.written as u32,
        chunk.needed as u64,
        chunk.token,
    )
}

fn decode(buf: &[u8], offset: u32, len_bytes: u32) -> Option<String> {
    let mut units = [0u16; MAX_NAME_UNITS];
    let n = read_utf16(buf, offset, len_bytes, &mut units)?;
    Some(String::from_utf16_lossy(&units[..n]))
}

fn request_slice(buf: &[u8], offset: u32, len_bytes: u32) -> Option<&[u8]> {
    let start = offset as usize;
    let len = len_bytes as usize;
    let end = start.checked_add(len)?;
    if end <= buf.len() {
        Some(&buf[start..end])
    } else {
        None
    }
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_string(out: &mut Vec<u8>, value: &str) -> Option<()> {
    push_u32(out, u32::try_from(value.len()).ok()?);
    out.extend_from_slice(value.as_bytes());
    Some(())
}

fn push_optional_string(out: &mut Vec<u8>, value: Option<&str>) -> Option<()> {
    match value {
        Some(value) => push_string(out, value),
        None => {
            push_u32(out, CM_OPTIONAL_STRING_ABSENT);
            Some(())
        }
    }
}

fn push_blob(out: &mut Vec<u8>, value: &[u8]) -> Option<()> {
    push_u32(out, u32::try_from(value.len()).ok()?);
    out.extend_from_slice(value);
    Some(())
}

fn push_optional_blob(out: &mut Vec<u8>, value: Option<&[u8]>) -> Option<()> {
    match value {
        Some(value) => push_blob(out, value),
        None => {
            push_u32(out, CM_OPTIONAL_BLOB_ABSENT);
            Some(())
        }
    }
}

fn push_optional_u32(out: &mut Vec<u8>, value: Option<u32>) {
    push_u32(out, value.unwrap_or(CM_OPTIONAL_U32_ABSENT));
}

fn system_hive_relative_path(
    path: &str,
    current_control_set: &CurrentControlSet,
) -> Option<String> {
    let mut components = path.split('\\').filter(|component| !component.is_empty());
    if !components.next()?.eq_ignore_ascii_case("Registry")
        || !components.next()?.eq_ignore_ascii_case("Machine")
        || !components.next()?.eq_ignore_ascii_case("System")
    {
        return None;
    }
    let mut relative = String::new();
    if let Some(first) = components.next() {
        relative.push_str(if first.eq_ignore_ascii_case("CurrentControlSet") {
            current_control_set.as_str()
        } else {
            first
        });
    }
    for component in components {
        relative.push('\\');
        relative.push_str(component);
    }
    Some(relative)
}

fn config_manager_from_system_hive(
    hive: &Hive,
    current_control_set: &CurrentControlSet,
) -> ConfigManager {
    let mut cm = ConfigManager::new();
    let _ = nt_hive_core::import_control_set_services_into_config_manager(
        hive,
        &mut cm,
        current_control_set.as_str(),
    );
    let _ = nt_hive_core::import_control_set_service_group_order_into_config_manager(
        hive,
        &mut cm,
        current_control_set.as_str(),
    );
    let _ = nt_hive_core::import_control_set_enum_into_config_manager(
        hive,
        &mut cm,
        current_control_set.as_str(),
    );
    let _ = nt_hive_core::import_control_set_class_into_config_manager(
        hive,
        &mut cm,
        current_control_set.as_str(),
    );
    let _ = nt_hive_core::import_control_set_network_into_config_manager(
        hive,
        &mut cm,
        current_control_set.as_str(),
    );
    cm
}

fn apply_system_hive_mutation(
    transaction: &mut HiveTransaction<'_>,
    current_control_set: &CurrentControlSet,
    mutation: &HiveMutation,
) -> Result<(), i32> {
    let relative = |path: &str| {
        system_hive_relative_path(path, current_control_set).ok_or(STATUS_INVALID_PARAMETER)
    };
    match mutation {
        HiveMutation::CreateKey { path } => {
            transaction.create_key(&relative(&path)?);
            Ok(())
        }
        HiveMutation::SetValue {
            path,
            name,
            value_type,
            data,
        } => {
            let value_type =
                RegistryValueType::from_u32(*value_type).ok_or(STATUS_INVALID_PARAMETER)?;
            let key = transaction
                .open_key(&relative(&path)?)
                .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
            transaction
                .set_value(key, name, value_type, data.clone())
                .then_some(())
                .ok_or(STATUS_INVALID_PARAMETER)
        }
        HiveMutation::DeleteValue { path, name } => {
            let key = transaction
                .open_key(&relative(&path)?)
                .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
            transaction
                .delete_value(key, name)
                .then_some(())
                .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)
        }
        HiveMutation::DeleteKey { path } => {
            let key = transaction
                .open_key(&relative(&path)?)
                .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
            match transaction.delete_key(key) {
                Ok(()) => Ok(()),
                Err(nt_hive_core::DeleteKeyError::NotFound) => Err(STATUS_OBJECT_NAME_NOT_FOUND),
                Err(nt_hive_core::DeleteKeyError::CannotDelete) => Err(STATUS_CANNOT_DELETE),
            }
        }
        HiveMutation::SetKeyClass { path, class_name } => {
            let key = transaction
                .open_key(&relative(&path)?)
                .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
            transaction
                .set_key_class(key, class_name.as_deref())
                .then_some(())
                .ok_or(STATUS_INVALID_PARAMETER)
        }
        HiveMutation::SetKeySecurity { path, descriptor } => {
            let key = transaction
                .open_key(&relative(&path)?)
                .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
            transaction
                .set_key_security_descriptor(key, descriptor)
                .then_some(())
                .ok_or(STATUS_INVALID_PARAMETER)
        }
        HiveMutation::PublishDeviceAction { .. } => Ok(()),
    }
}

fn semantic_system_registry_path(
    path: &str,
    current_control_set: &CurrentControlSet,
) -> Result<Option<(String, bool)>, i32> {
    let relative =
        system_hive_relative_path(path, current_control_set).ok_or(STATUS_INVALID_PARAMETER)?;
    let mut components = relative
        .split('\\')
        .filter(|component| !component.is_empty());
    let Some(control_set) = components.next() else {
        return Ok(None);
    };
    if !control_set.eq_ignore_ascii_case(current_control_set.as_str()) {
        return Ok(None);
    }
    let Some(root) = components.next() else {
        return Ok(None);
    };
    let mut semantic = String::from(r"\Registry\Machine\System\CurrentControlSet");
    semantic.push('\\');
    semantic.push_str(root);
    let affects_enum = root.eq_ignore_ascii_case("Enum");
    let included = if root.eq_ignore_ascii_case("Services") || affects_enum {
        true
    } else if root.eq_ignore_ascii_case("Control") {
        let Some(control_root) = components.next() else {
            return Ok(None);
        };
        semantic.push('\\');
        semantic.push_str(control_root);
        control_root.eq_ignore_ascii_case("ServiceGroupOrder")
            || control_root.eq_ignore_ascii_case("Class")
            || control_root.eq_ignore_ascii_case("Network")
    } else {
        false
    };
    if !included {
        return Ok(None);
    }
    for component in components {
        semantic.push('\\');
        semantic.push_str(component);
    }
    Ok(Some((semantic, affects_enum)))
}

fn project_system_hive_mutations(
    registry: &mut RegistryTransaction<'_>,
    current_control_set: &CurrentControlSet,
    mutations: &[HiveMutation],
) -> Result<bool, i32> {
    let mut enum_changed = false;
    for mutation in mutations {
        let path = match mutation {
            HiveMutation::CreateKey { path }
            | HiveMutation::SetValue { path, .. }
            | HiveMutation::DeleteValue { path, .. }
            | HiveMutation::DeleteKey { path }
            | HiveMutation::SetKeyClass { path, .. }
            | HiveMutation::SetKeySecurity { path, .. } => path,
            HiveMutation::PublishDeviceAction { .. } => continue,
        };
        let Some((path, affects_enum)) = semantic_system_registry_path(path, current_control_set)?
        else {
            continue;
        };
        enum_changed |= affects_enum;
        match mutation {
            HiveMutation::CreateKey { .. } => {
                registry.create_key(&path);
            }
            HiveMutation::SetValue {
                name,
                value_type,
                data,
                ..
            } => {
                let value_type =
                    RegistryValueType::from_u32(*value_type).ok_or(STATUS_INVALID_PARAMETER)?;
                let key = registry.open_key(&path).ok_or(STATUS_REGISTRY_CORRUPT)?;
                if !registry.set_value(key, name, value_type, data.clone()) {
                    return Err(STATUS_REGISTRY_CORRUPT);
                }
            }
            HiveMutation::DeleteValue { name, .. } => {
                let key = registry.open_key(&path).ok_or(STATUS_REGISTRY_CORRUPT)?;
                if !registry.delete_value(key, name) {
                    return Err(STATUS_REGISTRY_CORRUPT);
                }
            }
            HiveMutation::DeleteKey { .. } => {
                let key = registry.open_key(&path).ok_or(STATUS_REGISTRY_CORRUPT)?;
                if !registry.delete_key(key, false) {
                    return Err(STATUS_REGISTRY_CORRUPT);
                }
            }
            HiveMutation::SetKeyClass { .. } | HiveMutation::SetKeySecurity { .. } => {
                // Class and security metadata remain authoritative in the mounted hive. The
                // semantic ConfigManager registry does not model either attribute.
            }
            HiveMutation::PublishDeviceAction { .. } => unreachable!(),
        }
    }
    Ok(enum_changed)
}

fn encode_hive_key_snapshot(
    hive: &Hive,
    mount_generation: u64,
    current_control_set: &CurrentControlSet,
    path: &str,
) -> Option<Vec<u8>> {
    let relative = system_hive_relative_path(path, current_control_set)?;
    let key = hive.open_key(&relative)?;
    encode_hive_key_snapshot_from_key(hive, mount_generation, key, path)
}

fn encode_hive_key_snapshot_from_key(
    hive: &Hive,
    mount_generation: u64,
    key: CellId,
    path: &str,
) -> Option<Vec<u8>> {
    let subkey_count = hive.subkey_count(key);
    let value_count = hive.value_count(key);
    let mut out = Vec::new();
    push_u32(&mut out, CM_HIVE_KEY_SNAPSHOT_MAGIC);
    push_u16(&mut out, CM_HIVE_KEY_SNAPSHOT_VERSION);
    push_u16(&mut out, 0);
    out.extend_from_slice(&mount_generation.to_le_bytes());
    push_u32(&mut out, u32::try_from(subkey_count).ok()?);
    push_u32(&mut out, u32::try_from(value_count).ok()?);
    debug_assert_eq!(out.len(), CM_HIVE_KEY_SNAPSHOT_HEADER_BYTES);
    push_string(&mut out, path)?;
    push_optional_string(&mut out, hive.key_class(key))?;
    push_optional_blob(&mut out, hive.key_security_descriptor(key))?;
    for index in 0..subkey_count {
        push_string(&mut out, hive.subkey_name_by_index(key, index)?)?;
        push_optional_string(&mut out, hive.subkey_class_by_index(key, index))?;
    }
    for index in 0..value_count {
        let (name, value_type, data) = hive.value_by_index(key, index)?;
        push_string(&mut out, name)?;
        push_u32(&mut out, value_type as u32);
        push_blob(&mut out, data)?;
    }
    Some(out)
}

fn utf16_byte_len(value: &str) -> Option<u32> {
    u32::try_from(value.encode_utf16().count().checked_mul(2)?).ok()
}

fn begin_hive_key_record(record_kind: u16, mount_generation: u64, index: u32) -> Vec<u8> {
    let mut out = Vec::new();
    push_u32(&mut out, CM_HIVE_KEY_RECORD_MAGIC);
    push_u16(&mut out, CM_HIVE_KEY_RECORD_VERSION);
    push_u16(&mut out, record_kind);
    out.extend_from_slice(&mount_generation.to_le_bytes());
    push_u32(&mut out, index);
    push_u32(&mut out, 0);
    debug_assert_eq!(out.len(), CM_HIVE_KEY_RECORD_HEADER_BYTES);
    out
}

#[derive(Copy, Clone)]
struct HiveKeyInformationStats {
    subkey_count: u32,
    max_subkey_name_bytes: u32,
    max_subkey_class_bytes: u32,
    value_count: u32,
    max_value_name_bytes: u32,
    max_value_data_bytes: u32,
}

fn hive_key_information_stats(hive: &Hive, key: CellId) -> Option<HiveKeyInformationStats> {
    let subkey_count = hive.subkey_count(key);
    let value_count = hive.value_count(key);
    let mut max_subkey_name_bytes = 0u32;
    let mut max_subkey_class_bytes = 0u32;
    for index in 0..subkey_count {
        max_subkey_name_bytes =
            max_subkey_name_bytes.max(utf16_byte_len(hive.subkey_name_by_index(key, index)?)?);
        if let Some(class_name) = hive.subkey_class_by_index(key, index) {
            max_subkey_class_bytes = max_subkey_class_bytes.max(utf16_byte_len(class_name)?);
        }
    }
    let mut max_value_name_bytes = 0u32;
    let mut max_value_data_bytes = 0u32;
    for index in 0..value_count {
        let (name, _, data) = hive.value_by_index(key, index)?;
        max_value_name_bytes = max_value_name_bytes.max(utf16_byte_len(name)?);
        max_value_data_bytes = max_value_data_bytes.max(u32::try_from(data.len()).ok()?);
    }
    Some(HiveKeyInformationStats {
        subkey_count: u32::try_from(subkey_count).ok()?,
        max_subkey_name_bytes,
        max_subkey_class_bytes,
        value_count: u32::try_from(value_count).ok()?,
        max_value_name_bytes,
        max_value_data_bytes,
    })
}

fn push_hive_key_information_stats(out: &mut Vec<u8>, stats: HiveKeyInformationStats) {
    push_u32(out, stats.subkey_count);
    push_u32(out, stats.max_subkey_name_bytes);
    push_u32(out, stats.max_subkey_class_bytes);
    push_u32(out, stats.value_count);
    push_u32(out, stats.max_value_name_bytes);
    push_u32(out, stats.max_value_data_bytes);
}

fn encode_hive_key_information_record(
    hive: &Hive,
    mount_generation: u64,
    key: CellId,
    path: &str,
) -> Option<Vec<u8>> {
    let stats = hive_key_information_stats(hive, key)?;
    let mut out = begin_hive_key_record(
        leased_hive_record_kind::KEY_INFORMATION,
        mount_generation,
        0,
    );
    push_hive_key_information_stats(&mut out, stats);
    push_string(&mut out, path)?;
    push_optional_string(&mut out, hive.key_class(key))?;
    push_optional_blob(&mut out, hive.key_security_descriptor(key))?;
    Some(out)
}

fn encode_hive_subkey_record(
    hive: &Hive,
    mount_generation: u64,
    key: CellId,
    index: u32,
) -> Result<Vec<u8>, i32> {
    let index_usize = usize::try_from(index).map_err(|_| STATUS_NO_MORE_ENTRIES)?;
    let name = hive
        .subkey_name_by_index(key, index_usize)
        .ok_or(STATUS_NO_MORE_ENTRIES)?;
    let child = hive
        .open_subkey(key, name)
        .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let stats = hive_key_information_stats(hive, child).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let mut out = begin_hive_key_record(
        leased_hive_record_kind::SUBKEY_BY_INDEX,
        mount_generation,
        index,
    );
    push_string(&mut out, name).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    push_optional_string(&mut out, hive.subkey_class_by_index(key, index_usize))
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    push_hive_key_information_stats(&mut out, stats);
    Ok(out)
}

fn encode_hive_value_record(
    hive: &Hive,
    mount_generation: u64,
    key: CellId,
    record_kind: u16,
    index: u32,
    requested_name: Option<&str>,
) -> Result<Vec<u8>, i32> {
    let (name, value_type, data) = if let Some(requested_name) = requested_name {
        let mut found = None;
        for candidate in 0..hive.value_count(key) {
            let Some(value) = hive.value_by_index(key, candidate) else {
                continue;
            };
            if value.0.eq_ignore_ascii_case(requested_name) {
                found = Some(value);
                break;
            }
        }
        found.ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?
    } else {
        hive.value_by_index(
            key,
            usize::try_from(index).map_err(|_| STATUS_NO_MORE_ENTRIES)?,
        )
        .ok_or(STATUS_NO_MORE_ENTRIES)?
    };
    let mut out = begin_hive_key_record(record_kind, mount_generation, index);
    push_string(&mut out, name).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    push_u32(&mut out, value_type as u32);
    push_blob(&mut out, data).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    Ok(out)
}

fn encode_driver_service_binding(
    cm: &ConfigManager,
    binding: &DriverServiceBinding,
) -> Option<Vec<u8>> {
    let class = match binding.service.class {
        DriverServiceClass::Device => driver_service_class::DEVICE,
        DriverServiceClass::FileSystem => driver_service_class::FILE_SYSTEM,
    };
    let mut out = Vec::new();
    push_u32(&mut out, CM_DRIVER_SERVICE_SNAPSHOT_MAGIC);
    push_u16(&mut out, CM_DRIVER_SERVICE_SNAPSHOT_VERSION);
    push_u16(&mut out, class);
    push_u32(&mut out, binding.service.start_type);
    push_u32(&mut out, u32::try_from(binding.devnodes.len()).ok()?);
    debug_assert_eq!(out.len(), CM_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES);
    push_string(&mut out, &binding.service.service_name)?;
    push_string(&mut out, &binding.service.image_path)?;
    push_string(&mut out, &binding.service.driver_object_path)?;
    push_optional_string(&mut out, binding.service.class_guid.as_deref())?;
    push_optional_u32(&mut out, binding.service.error_control);
    push_optional_string(&mut out, binding.service.load_order_group.as_deref())?;
    push_optional_u32(&mut out, binding.service.tag);
    for devnode in &binding.devnodes {
        push_string(&mut out, &devnode.instance_id)?;
        push_optional_string(&mut out, devnode.pdo_name.as_deref())?;
        push_optional_string(&mut out, devnode.driver_key.as_deref())?;
        let linkage_export = cm.devnode_linkage_export(devnode);
        push_optional_string(&mut out, linkage_export.as_deref())?;
        push_u32(&mut out, u32::try_from(devnode.hardware_ids.len()).ok()?);
        for id in &devnode.hardware_ids {
            push_string(&mut out, id)?;
        }
        push_u32(&mut out, u32::try_from(devnode.compatible_ids.len()).ok()?);
        for id in &devnode.compatible_ids {
            push_string(&mut out, id)?;
        }
    }
    Some(out)
}

fn encode_driver_launch_plan(
    cm: &ConfigManager,
    generation: u64,
    plan_kind: u16,
    bindings: &[DriverServiceBinding],
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    push_u32(&mut out, CM_LAUNCH_PLAN_SNAPSHOT_MAGIC);
    push_u16(&mut out, CM_LAUNCH_PLAN_SNAPSHOT_VERSION);
    push_u16(&mut out, plan_kind);
    out.extend_from_slice(&generation.to_le_bytes());
    push_u32(&mut out, u32::try_from(bindings.len()).ok()?);
    push_u32(&mut out, 0);
    debug_assert_eq!(out.len(), CM_LAUNCH_PLAN_SNAPSHOT_HEADER_BYTES);
    for binding in bindings {
        let encoded = encode_driver_service_binding(cm, binding)?;
        push_blob(&mut out, &encoded)?;
    }
    Some(out)
}

fn encode_win32_service_launch_plan(
    generation: u64,
    plan_kind: u16,
    launches: &[Win32ServiceProcessLaunch],
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    push_u32(&mut out, CM_WIN32_SERVICE_PLAN_SNAPSHOT_MAGIC);
    push_u16(&mut out, CM_WIN32_SERVICE_PLAN_SNAPSHOT_VERSION);
    push_u16(&mut out, plan_kind);
    out.extend_from_slice(&generation.to_le_bytes());
    push_u32(&mut out, u32::try_from(launches.len()).ok()?);
    push_u32(&mut out, 0);
    debug_assert_eq!(out.len(), CM_WIN32_SERVICE_PLAN_SNAPSHOT_HEADER_BYTES);
    for launch in launches {
        push_string(&mut out, &launch.service_name)?;
        push_string(&mut out, &launch.executable_path)?;
        push_string(&mut out, &launch.nt_image_path)?;
        push_string(&mut out, &launch.command_line)?;
        push_u16(
            &mut out,
            match launch.process_kind {
                Win32ServiceProcessKind::Own => win32_service_process_kind::OWN,
                Win32ServiceProcessKind::Shared => win32_service_process_kind::SHARED,
            },
        );
        push_u16(&mut out, u16::from(launch.interactive));
        push_optional_string(&mut out, launch.account_name.as_deref())?;
        push_optional_string(&mut out, launch.display_name.as_deref())?;
        push_u32(&mut out, u32::try_from(launch.dependencies.len()).ok()?);
        for dependency in &launch.dependencies {
            push_string(&mut out, dependency)?;
        }
    }
    Some(out)
}

fn encode_pnp_query_snapshot(
    generation: u64,
    query_kind: u16,
    strings: &[String],
    payload: &[u8],
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    push_u32(&mut out, CM_PNP_QUERY_SNAPSHOT_MAGIC);
    push_u16(&mut out, CM_PNP_QUERY_SNAPSHOT_VERSION);
    push_u16(&mut out, query_kind);
    out.extend_from_slice(&generation.to_le_bytes());
    push_u32(&mut out, u32::try_from(strings.len()).ok()?);
    push_u32(&mut out, u32::try_from(payload.len()).ok()?);
    debug_assert_eq!(out.len(), CM_PNP_QUERY_SNAPSHOT_HEADER_BYTES);
    for value in strings {
        push_string(&mut out, value)?;
    }
    out.extend_from_slice(payload);
    Some(out)
}

fn encode_network_adapter_plan(
    generation: u64,
    plan_kind: u16,
    adapters: &[ReactOsNetworkAdapterBinding],
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    push_u32(&mut out, CM_NETWORK_PLAN_SNAPSHOT_MAGIC);
    push_u16(&mut out, CM_NETWORK_PLAN_SNAPSHOT_VERSION);
    push_u16(&mut out, plan_kind);
    out.extend_from_slice(&generation.to_le_bytes());
    push_u32(&mut out, u32::try_from(adapters.len()).ok()?);
    push_u32(&mut out, 0);
    debug_assert_eq!(out.len(), CM_NETWORK_PLAN_SNAPSHOT_HEADER_BYTES);
    for adapter in adapters {
        for value in [
            &adapter.instance_id,
            &adapter.class_key_path,
            &adapter.linkage_key_path,
            &adapter.interface_name,
            &adapter.device_name,
            &adapter.tcpip_export_name,
            &adapter.driver_desc,
            &adapter.component_id,
        ] {
            push_string(&mut out, value)?;
        }
    }
    Some(out)
}

fn encode_device_action_event(event: &DeviceActionEvent) -> Option<Vec<u8>> {
    let kind = match event.kind {
        DeviceActionKind::Arrival => device_action_kind::ARRIVAL,
        DeviceActionKind::Change => device_action_kind::CHANGE,
        DeviceActionKind::Removal => device_action_kind::REMOVAL,
    };
    let service_present = if event.publication.service_name.is_some() {
        device_action_service::PRESENT
    } else {
        device_action_service::ABSENT
    };
    let mut out = Vec::new();
    push_u32(&mut out, CM_DEVICE_ACTION_SNAPSHOT_MAGIC);
    push_u16(&mut out, CM_DEVICE_ACTION_SNAPSHOT_VERSION);
    push_u16(&mut out, kind);
    out.extend_from_slice(&event.mount_generation.to_le_bytes());
    out.extend_from_slice(&event.sequence.to_le_bytes());
    push_u16(&mut out, service_present);
    push_u16(&mut out, 0);
    push_u32(&mut out, 0);
    debug_assert_eq!(out.len(), CM_DEVICE_ACTION_SNAPSHOT_HEADER_BYTES);

    push_string(&mut out, &event.publication.instance_id)?;
    if let Some(service_name) = &event.publication.service_name {
        push_string(&mut out, service_name)?;
    }
    push_optional_string(&mut out, event.publication.pdo_name.as_deref())?;
    push_optional_string(&mut out, event.publication.driver_key.as_deref())?;
    push_optional_string(&mut out, event.publication.linkage_export.as_deref())?;
    push_u32(
        &mut out,
        u32::try_from(event.publication.hardware_ids.len()).ok()?,
    );
    for id in &event.publication.hardware_ids {
        push_string(&mut out, id)?;
    }
    push_u32(
        &mut out,
        u32::try_from(event.publication.compatible_ids.len()).ok()?,
    );
    for id in &event.publication.compatible_ids {
        push_string(&mut out, id)?;
    }
    Some(out)
}

fn device_action_intents(mutations: &[HiveMutation]) -> Result<Vec<DeviceActionIntent>, i32> {
    let mut actions = Vec::new();
    for mutation in mutations {
        let HiveMutation::PublishDeviceAction { kind, instance_id } = mutation else {
            continue;
        };
        let kind = match *kind {
            device_action_kind::ARRIVAL => DeviceActionKind::Arrival,
            device_action_kind::CHANGE => DeviceActionKind::Change,
            device_action_kind::REMOVAL => DeviceActionKind::Removal,
            _ => return Err(STATUS_INVALID_PARAMETER),
        };
        actions
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        actions.push(DeviceActionIntent {
            kind,
            instance_id: instance_id.clone(),
        });
    }
    Ok(actions)
}

struct DevicePropertySnapshotKey {
    instance: String,
    property: u32,
    output_capacity: u32,
}

struct HiveImport {
    token: u64,
    mount: u16,
    total_len: usize,
    value: Vec<u8>,
}

enum HiveKeySnapshotIdentity {
    Path(String),
    Lease(u64),
    LeaseRecord(u64),
}

struct HiveKeySnapshotKey {
    mount: u16,
    identity: HiveKeySnapshotIdentity,
}

struct HiveExportSnapshotKey {
    mount: u16,
    key_lease_token: u64,
}

struct PnpQuerySnapshotKey {
    query_kind: u16,
    selector: u32,
    instance: String,
    auxiliary: Vec<u8>,
}

#[derive(Copy, Clone)]
struct DeviceActionSnapshotKey {
    mount_generation: u64,
    sequence: u64,
}

struct DeviceActionClaim {
    token: u64,
    key: DeviceActionSnapshotKey,
    value: Vec<u8>,
    offset: usize,
    complete: bool,
}

static NEXT_DEVICE_ACTION_CLAIM_TOKEN: AtomicU64 = AtomicU64::new(1);

fn take_device_action_claim_token() -> Option<u64> {
    NEXT_DEVICE_ACTION_CLAIM_TOKEN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |token| {
            token.checked_add(1)
        })
        .ok()
        .filter(|token| *token != 0)
}

struct MountedSystemHive {
    hive: Hive,
    generation: u64,
    current_control_set: CurrentControlSet,
}

struct PreparedSystemHiveMutation {
    token: u64,
    expected_generation: u64,
    next_generation: u64,
    semantic_journal_len: usize,
    mutations: Vec<HiveMutation>,
    durable_journal: Vec<u8>,
}

struct PreparedSystemHiveCheckpoint {
    token: u64,
    mount_generation: u64,
    hive_sequence: u64,
    image_generation: u64,
    value: Vec<u8>,
    offset: usize,
}

/// The Configuration Manager service: the registry authority + the wire dispatcher.
pub struct CmServer {
    cm: ConfigManager,
    device_property_snapshots: SnapshotBank<DevicePropertySnapshotKey>,
    driver_service_snapshots: SnapshotBank<String>,
    system_hive: Option<MountedSystemHive>,
    hive_imports: Vec<HiveImport>,
    next_hive_import_token: u64,
    system_mutation_leases: MutationLeaseBank,
    prepared_system_mutation: Option<PreparedSystemHiveMutation>,
    prepared_system_checkpoint: Option<PreparedSystemHiveCheckpoint>,
    next_system_checkpoint_token: u64,
    system_key_leases: SystemKeyLeaseBank,
    hive_key_snapshots: SnapshotPool<HiveKeySnapshotKey>,
    hive_export_snapshots: SnapshotPool<HiveExportSnapshotKey>,
    driver_launch_plan_snapshots: SnapshotBank<u16>,
    win32_service_launch_plan_snapshots: SnapshotBank<u16>,
    pnp_query_snapshots: SnapshotBank<PnpQuerySnapshotKey>,
    network_adapter_plan_snapshots: SnapshotBank<u16>,
    device_action_journal: DeviceActionJournal,
    device_action_claim: Option<DeviceActionClaim>,
}

impl Default for CmServer {
    fn default() -> Self {
        Self::new()
    }
}

impl CmServer {
    pub fn new() -> Self {
        Self {
            cm: ConfigManager::new(),
            device_property_snapshots: SnapshotBank::new(),
            driver_service_snapshots: SnapshotBank::new(),
            system_hive: None,
            hive_imports: Vec::new(),
            next_hive_import_token: 1,
            system_mutation_leases: MutationLeaseBank::new(),
            prepared_system_mutation: None,
            prepared_system_checkpoint: None,
            next_system_checkpoint_token: 1,
            system_key_leases: SystemKeyLeaseBank::new(),
            hive_key_snapshots: SnapshotPool::with_limits(
                MAX_OUTSTANDING_HIVE_KEY_SNAPSHOTS,
                MAX_RETAINED_HIVE_KEY_SNAPSHOT_BYTES,
            ),
            hive_export_snapshots: SnapshotPool::with_limits(
                MAX_OUTSTANDING_HIVE_KEY_SNAPSHOTS,
                MAX_RETAINED_HIVE_KEY_SNAPSHOT_BYTES,
            ),
            driver_launch_plan_snapshots: SnapshotBank::new(),
            win32_service_launch_plan_snapshots: SnapshotBank::new(),
            pnp_query_snapshots: SnapshotBank::new(),
            network_adapter_plan_snapshots: SnapshotBank::new(),
            device_action_journal: DeviceActionJournal::new(),
            device_action_claim: None,
        }
    }

    /// Build a server around an already-seeded Configuration Manager.
    pub fn with_config(cm: ConfigManager) -> Self {
        Self {
            cm,
            device_property_snapshots: SnapshotBank::new(),
            driver_service_snapshots: SnapshotBank::new(),
            system_hive: None,
            hive_imports: Vec::new(),
            next_hive_import_token: 1,
            system_mutation_leases: MutationLeaseBank::new(),
            prepared_system_mutation: None,
            prepared_system_checkpoint: None,
            next_system_checkpoint_token: 1,
            system_key_leases: SystemKeyLeaseBank::new(),
            hive_key_snapshots: SnapshotPool::with_limits(
                MAX_OUTSTANDING_HIVE_KEY_SNAPSHOTS,
                MAX_RETAINED_HIVE_KEY_SNAPSHOT_BYTES,
            ),
            hive_export_snapshots: SnapshotPool::with_limits(
                MAX_OUTSTANDING_HIVE_KEY_SNAPSHOTS,
                MAX_RETAINED_HIVE_KEY_SNAPSHOT_BYTES,
            ),
            driver_launch_plan_snapshots: SnapshotBank::new(),
            win32_service_launch_plan_snapshots: SnapshotBank::new(),
            pnp_query_snapshots: SnapshotBank::new(),
            network_adapter_plan_snapshots: SnapshotBank::new(),
            device_action_journal: DeviceActionJournal::new(),
            device_action_claim: None,
        }
    }

    /// Direct read access to the registry authority.
    pub fn config(&self) -> &ConfigManager {
        &self.cm
    }

    /// Direct access to the registry authority (for seeding hives at boot).
    pub fn config_mut(&mut self) -> &mut ConfigManager {
        &mut self.cm
    }

    /// Decode + dispatch one wire request. `out_buf` carries variable-length value data for raw
    /// queries; scalar results ride in `detail0`.
    pub fn dispatch(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        match opcode {
            opcode::CM_OP_PING => reply(STATUS_SUCCESS, 0),
            opcode::CM_OP_CREATE_KEY => self.op_create_key(in_buf),
            opcode::CM_OP_OPEN_KEY => self.op_open_key(in_buf),
            opcode::CM_OP_SET_DWORD => self.op_set_dword(in_buf),
            opcode::CM_OP_QUERY_DWORD => self.op_query_dword(in_buf),
            opcode::CM_OP_SET_VALUE => self.op_set_value(in_buf),
            opcode::CM_OP_QUERY_VALUE => self.op_query_value(in_buf, out_buf),
            opcode::CM_OP_ENUMERATE_KEY => self.op_enumerate_key(in_buf, out_buf),
            opcode::CM_OP_QUERY_DEVICE_PROPERTY => self.op_query_device_property(in_buf, out_buf),
            opcode::CM_OP_QUERY_DRIVER_SERVICE => self.op_query_driver_service(in_buf, out_buf),
            opcode::CM_OP_IMPORT_HIVE => self.op_import_hive(in_buf),
            opcode::CM_OP_MUTATE_SYSTEM_HIVE => self.op_mutate_system_hive(in_buf, out_buf),
            opcode::CM_OP_CHECKPOINT_SYSTEM_HIVE => self.op_checkpoint_system_hive(in_buf, out_buf),
            opcode::CM_OP_QUERY_HIVE_KEY => self.op_query_hive_key(in_buf, out_buf),
            opcode::CM_OP_SYSTEM_HIVE_KEY_LEASE => self.op_system_hive_key_lease(in_buf, out_buf),
            opcode::CM_OP_QUERY_LEASED_HIVE_KEY => self.op_query_leased_hive_key(in_buf, out_buf),
            opcode::CM_OP_QUERY_LEASED_HIVE_RECORD => {
                self.op_query_leased_hive_record(in_buf, out_buf)
            }
            opcode::CM_OP_EXPORT_LEASED_HIVE => self.op_export_leased_hive(in_buf, out_buf),
            opcode::CM_OP_QUERY_LAUNCH_PLAN => self.op_query_launch_plan(in_buf, out_buf),
            opcode::CM_OP_QUERY_WIN32_SERVICE_PLAN => {
                self.op_query_win32_service_plan(in_buf, out_buf)
            }
            opcode::CM_OP_QUERY_PNP => self.op_query_pnp(in_buf, out_buf),
            opcode::CM_OP_QUERY_NETWORK_PLAN => self.op_query_network_plan(in_buf, out_buf),
            opcode::CM_OP_DEVICE_ACTION => self.op_device_action(in_buf, out_buf),
            _ => reply(STATUS_INVALID_SYSTEM_SERVICE, 0),
        }
    }

    fn op_create_key(&mut self, buf: &[u8]) -> CmReply {
        let Some(req) = CmKeyRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        if req.flags & !key_flags::VOLATILE != 0 {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let Some(path) = decode(buf, req.path_offset, req.path_len_bytes) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let created = self.cm.registry().open_key(&path).is_none();
        let key = self.cm.registry_mut().create_key(&path);
        if created && req.flags & key_flags::VOLATILE != 0 {
            self.cm.registry_mut().set_volatile(key, true);
        }
        reply_with_info(STATUS_SUCCESS, 0, key, created as u64)
    }

    fn op_open_key(&mut self, buf: &[u8]) -> CmReply {
        let Some(req) = CmKeyRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        if req.flags != 0 {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let Some(path) = decode(buf, req.path_offset, req.path_len_bytes) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        match self.cm.registry().open_key(&path) {
            Some(key) => reply(STATUS_SUCCESS, key),
            None => reply(STATUS_OBJECT_NAME_NOT_FOUND, 0),
        }
    }

    fn op_enumerate_key(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmEnumerateKeyRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let Some(path) = decode(buf, req.path_offset, req.path_len_bytes) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let Some(key) = self.cm.registry().open_key(&path) else {
            return reply(STATUS_OBJECT_NAME_NOT_FOUND, 0);
        };
        let subkeys = self.cm.registry().enum_subkeys(key);
        let Some(name) = subkeys.get(req.index as usize) else {
            return reply(STATUS_NO_MORE_ENTRIES, 0);
        };
        let mut name_bytes = Vec::with_capacity(name.len() * 2);
        for unit in name.encode_utf16() {
            name_bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let needed = name_bytes.len();
        if out_buf.len() < needed {
            return reply_with_info(STATUS_BUFFER_TOO_SMALL, needed as u32, 0, 0);
        }
        out_buf[..needed].copy_from_slice(&name_bytes);
        reply_with_info(STATUS_SUCCESS, needed as u32, 0, 0)
    }

    fn op_set_dword(&mut self, buf: &[u8]) -> CmReply {
        let Some(req) = CmValueRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let (Some(key_path), Some(name)) = (
            decode(buf, req.key_offset, req.key_len_bytes),
            decode(buf, req.name_offset, req.name_len_bytes),
        ) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let key = self.cm.registry_mut().create_key(&key_path);
        if self.cm.registry_mut().set_dword(key, &name, req.dword) {
            reply(STATUS_SUCCESS, 0)
        } else {
            reply(STATUS_INVALID_PARAMETER, 0)
        }
    }

    fn op_query_dword(&mut self, buf: &[u8]) -> CmReply {
        let Some(req) = CmValueRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let (Some(key_path), Some(name)) = (
            decode(buf, req.key_offset, req.key_len_bytes),
            decode(buf, req.name_offset, req.name_len_bytes),
        ) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let Some(key) = self.cm.registry().open_key(&key_path) else {
            return reply(STATUS_OBJECT_NAME_NOT_FOUND, 0);
        };
        match self.cm.registry().query_dword(key, &name) {
            Some(v) => reply(STATUS_SUCCESS, v as u64),
            None => reply(STATUS_OBJECT_NAME_NOT_FOUND, 0),
        }
    }

    fn op_set_value(&mut self, buf: &[u8]) -> CmReply {
        let Some(req) = CmRawValueRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let (Some(key_path), Some(name), Some(data)) = (
            decode(buf, req.key_offset, req.key_len_bytes),
            decode(buf, req.name_offset, req.name_len_bytes),
            request_slice(buf, req.data_offset, req.data_len_bytes),
        ) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let Some(value_type) = RegistryValueType::from_u32(req.value_type) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let key = self.cm.registry_mut().create_key(&key_path);
        if self
            .cm
            .registry_mut()
            .set_value(key, &name, value_type, Vec::from(data))
        {
            reply(STATUS_SUCCESS, 0)
        } else {
            reply(STATUS_INVALID_PARAMETER, 0)
        }
    }

    fn op_query_value(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmRawValueRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let (Some(key_path), Some(name)) = (
            decode(buf, req.key_offset, req.key_len_bytes),
            decode(buf, req.name_offset, req.name_len_bytes),
        ) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let Some(key) = self.cm.registry().open_key(&key_path) else {
            return reply(STATUS_OBJECT_NAME_NOT_FOUND, 0);
        };
        let Some(value) = self.cm.registry().query_value(key, &name) else {
            return reply(STATUS_OBJECT_NAME_NOT_FOUND, 0);
        };
        let needed = value.data.len();
        let value_type = value.value_type as u32 as u64;
        if out_buf.len() < needed {
            return reply_with_info(STATUS_BUFFER_OVERFLOW, needed as u32, value_type, 0);
        }
        out_buf[..needed].copy_from_slice(&value.data);
        reply_with_info(STATUS_SUCCESS, needed as u32, value_type, 0)
    }

    fn op_query_device_property(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmDevicePropertyRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmDevicePropertyRequest>();
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || req._reserved != 0
            || req.instance_offset as usize != header_size
            || req.instance_len_bytes == 0
            || req.instance_len_bytes % 2 != 0
            || req.instance_len_bytes as usize > CM_MAX_INSTANCE_UNITS * 2
            || (req.instance_offset as usize).checked_add(req.instance_len_bytes as usize)
                != Some(buf.len())
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }

        let mut units = [0u16; CM_MAX_INSTANCE_UNITS];
        let Some(unit_count) =
            read_utf16(buf, req.instance_offset, req.instance_len_bytes, &mut units)
        else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let units = &units[..unit_count];
        if units.contains(&0) {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let Ok(instance) = String::from_utf16(units) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };

        match device_property::source(req.property) {
            DevicePropertySource::Invalid => return reply(STATUS_INVALID_PARAMETER, 0),
            DevicePropertySource::External => return reply(STATUS_NOT_SUPPORTED, 0),
            DevicePropertySource::Configuration => {}
        }
        let chunk_capacity = req.chunk_capacity as usize;
        if chunk_capacity > CM_DEVICE_PROPERTY_CHUNK_BYTES
            || chunk_capacity > out_buf.len()
            || req.chunk_capacity > req.output_capacity
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        match req.operation {
            device_property_transfer::BEGIN => {
                if req.transfer_token != 0
                    || req.value_offset != 0
                    || (req.chunk_capacity == 0 && req.output_capacity != 0)
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(value) = self.cm.device_property_bytes(&instance, req.property) else {
                    return reply(STATUS_OBJECT_NAME_NOT_FOUND, 0);
                };
                let needed = value.len();
                let Ok(needed_u32) = u32::try_from(needed) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                self.device_property_snapshots.clear();
                if req.output_capacity < needed_u32 {
                    return reply_with_info(STATUS_BUFFER_TOO_SMALL, 0, needed as u64, 0);
                }
                let Some(chunk) = self.device_property_snapshots.begin(
                    DevicePropertySnapshotKey {
                        instance,
                        property: req.property,
                        output_capacity: req.output_capacity,
                    },
                    value,
                    chunk_capacity,
                    out_buf,
                ) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                snapshot_reply(chunk)
            }
            device_property_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(chunk) = self.device_property_snapshots.pull(
                    req.transfer_token,
                    req.value_offset as usize,
                    chunk_capacity,
                    out_buf,
                    |key| {
                        key.instance == instance
                            && key.property == req.property
                            && key.output_capacity == req.output_capacity
                    },
                ) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                snapshot_reply(chunk)
            }
            device_property_transfer::ABORT => {
                if req.transfer_token == 0
                    || req.value_offset != 0
                    || req.chunk_capacity != 0
                    || !self
                        .device_property_snapshots
                        .abort(req.transfer_token, |key| {
                            key.instance == instance
                                && key.property == req.property
                                && key.output_capacity == req.output_capacity
                        })
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                reply(STATUS_SUCCESS, 0)
            }
            _ => reply(STATUS_INVALID_PARAMETER, 0),
        }
    }

    fn op_query_driver_service(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmDriverServiceRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmDriverServiceRequest>();
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || req._reserved != 0
            || req.service_offset as usize != header_size
            || req.service_len_bytes == 0
            || req.service_len_bytes % 2 != 0
            || req.service_len_bytes as usize > CM_MAX_SERVICE_UNITS * 2
            || (req.service_offset as usize).checked_add(req.service_len_bytes as usize)
                != Some(buf.len())
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let chunk_capacity = req.chunk_capacity as usize;
        if chunk_capacity > CM_DRIVER_SERVICE_CHUNK_BYTES || chunk_capacity > out_buf.len() {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }

        let mut units = [0u16; CM_MAX_SERVICE_UNITS];
        let Some(unit_count) =
            read_utf16(buf, req.service_offset, req.service_len_bytes, &mut units)
        else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let units = &units[..unit_count];
        if units.contains(&0) {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let Ok(service) = String::from_utf16(units) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };

        match req.operation {
            driver_service_transfer::BEGIN => {
                if req.transfer_token != 0 || req.value_offset != 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(binding) = self.cm.driver_service_binding(&service) else {
                    return reply(STATUS_OBJECT_NAME_NOT_FOUND, 0);
                };
                let Some(value) = encode_driver_service_binding(&self.cm, &binding) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                let needed = value.len();
                let Ok(needed_u32) = u32::try_from(needed) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                let Some(chunk) =
                    self.driver_service_snapshots
                        .begin(service, value, chunk_capacity, out_buf)
                else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                debug_assert_eq!(chunk.needed, needed_u32 as usize);
                snapshot_reply(chunk)
            }
            driver_service_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(chunk) = self.driver_service_snapshots.pull(
                    req.transfer_token,
                    req.value_offset as usize,
                    chunk_capacity,
                    out_buf,
                    |key| key.eq_ignore_ascii_case(&service),
                ) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                snapshot_reply(chunk)
            }
            driver_service_transfer::ABORT => {
                if req.transfer_token == 0
                    || req.value_offset != 0
                    || req.chunk_capacity != 0
                    || !self
                        .driver_service_snapshots
                        .abort(req.transfer_token, |key| key.eq_ignore_ascii_case(&service))
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                reply(STATUS_SUCCESS, 0)
            }
            _ => reply(STATUS_INVALID_PARAMETER, 0),
        }
    }

    fn op_import_hive(&mut self, buf: &[u8]) -> CmReply {
        let Some(req) = CmHiveImportRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmHiveImportRequest>();
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || req.mount != hive_mount::SYSTEM
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let Ok(total_len) = usize::try_from(req.total_len_bytes) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        match req.operation {
            hive_import_transfer::BEGIN => {
                if req.transfer_token != 0
                    || req.value_offset != 0
                    || req.chunk_offset != 0
                    || req.chunk_len_bytes != 0
                    || total_len == 0
                    || buf.len() != header_size
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                if self.prepared_system_mutation.is_some()
                    || self.prepared_system_checkpoint.is_some()
                {
                    return reply(STATUS_DEVICE_BUSY, 0);
                }
                let token = self.next_hive_import_token;
                let Some(next_token) = token.checked_add(1) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                if token == 0 || self.hive_imports.try_reserve(1).is_err() {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                }
                let mut value = Vec::new();
                if value.try_reserve_exact(total_len).is_err() {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                }
                self.next_hive_import_token = next_token;
                self.hive_imports.push(HiveImport {
                    token,
                    mount: req.mount,
                    total_len,
                    value,
                });
                reply_with_info(STATUS_SUCCESS, 0, total_len as u64, token)
            }
            hive_import_transfer::PUSH => {
                let chunk_len = req.chunk_len_bytes as usize;
                let chunk_offset = req.chunk_offset as usize;
                let Some(chunk_end) = chunk_offset.checked_add(chunk_len) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                if req.transfer_token == 0
                    || chunk_len == 0
                    || chunk_len > CM_HIVE_IMPORT_CHUNK_BYTES
                    || chunk_offset != header_size
                    || chunk_end != buf.len()
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(import) = self.hive_imports.iter_mut().find(|import| {
                    import.token == req.transfer_token
                        && import.mount == req.mount
                        && import.total_len == total_len
                }) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                if import.value.len() != req.value_offset as usize
                    || import.value.len().checked_add(chunk_len).is_none()
                    || import.value.len() + chunk_len > import.total_len
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                import
                    .value
                    .extend_from_slice(&buf[chunk_offset..chunk_end]);
                reply_with_info(
                    STATUS_SUCCESS,
                    req.chunk_len_bytes,
                    import.value.len() as u64,
                    req.transfer_token,
                )
            }
            hive_import_transfer::COMMIT => {
                if req.transfer_token == 0
                    || req.chunk_offset != 0
                    || req.chunk_len_bytes != 0
                    || buf.len() != header_size
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                if self.prepared_system_mutation.is_some()
                    || self.prepared_system_checkpoint.is_some()
                {
                    return reply(STATUS_DEVICE_BUSY, 0);
                }
                let Some(index) = self.hive_imports.iter().position(|import| {
                    import.token == req.transfer_token
                        && import.mount == req.mount
                        && import.total_len == total_len
                }) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                let import = &self.hive_imports[index];
                if import.value.len() != import.total_len
                    || req.value_offset as usize != import.total_len
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Ok(hive) = decode_image(&import.value) else {
                    return reply(STATUS_REGISTRY_CORRUPT, 0);
                };
                if hive.kind != HiveKind::System {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Ok(current_control_set) = hive.current_control_set() else {
                    return reply(STATUS_REGISTRY_CORRUPT, 0);
                };
                let current_generation = self
                    .system_hive
                    .as_ref()
                    .map(|mounted| mounted.generation)
                    .unwrap_or(0);
                let Some(generation) = current_generation.checked_add(1) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                let mut cm = config_manager_from_system_hive(&hive, &current_control_set);
                if current_generation == 0 {
                    let publications = cm.devnode_publications();
                    if let Err(error) = self.device_action_journal.seed(generation, &publications) {
                        return reply(device_action_journal_status(error), current_generation);
                    }
                }
                self.system_mutation_leases.invalidate();
                self.system_key_leases.invalidate();
                self.cm = cm;
                self.system_hive = Some(MountedSystemHive {
                    hive,
                    generation,
                    current_control_set,
                });
                self.hive_imports.swap_remove(index);
                reply_with_info(STATUS_SUCCESS, 0, generation, req.transfer_token)
            }
            hive_import_transfer::ABORT => {
                if req.transfer_token == 0
                    || req.value_offset != 0
                    || req.chunk_offset != 0
                    || req.chunk_len_bytes != 0
                    || buf.len() != header_size
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(index) = self.hive_imports.iter().position(|import| {
                    import.token == req.transfer_token
                        && import.mount == req.mount
                        && import.total_len == total_len
                }) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                self.hive_imports.swap_remove(index);
                reply(STATUS_SUCCESS, 0)
            }
            _ => reply(STATUS_INVALID_PARAMETER, 0),
        }
    }

    fn encode_system_hive_mutation_log_record(
        mutation: &HiveMutation,
        current_control_set: &CurrentControlSet,
        sequence: u64,
    ) -> Result<Vec<u8>, i32> {
        let path = match mutation {
            HiveMutation::CreateKey { path }
            | HiveMutation::SetValue { path, .. }
            | HiveMutation::DeleteValue { path, .. }
            | HiveMutation::DeleteKey { path }
            | HiveMutation::SetKeyClass { path, .. }
            | HiveMutation::SetKeySecurity { path, .. } => path,
            HiveMutation::PublishDeviceAction { .. } => return Err(STATUS_INVALID_PARAMETER),
        };
        let relative =
            system_hive_relative_path(path, current_control_set).ok_or(STATUS_INVALID_PARAMETER)?;
        let record = match mutation {
            HiveMutation::CreateKey { .. } => {
                encode_log_record(&HiveLogOp::CreateKey { path: &relative }, sequence)
            }
            HiveMutation::SetValue {
                name,
                value_type,
                data,
                ..
            } => {
                let value_type =
                    RegistryValueType::from_u32(*value_type).ok_or(STATUS_INVALID_PARAMETER)?;
                encode_log_record(
                    &HiveLogOp::SetValue {
                        path: &relative,
                        name,
                        value_type,
                        data,
                    },
                    sequence,
                )
            }
            HiveMutation::DeleteValue { name, .. } => encode_log_record(
                &HiveLogOp::DeleteValue {
                    path: &relative,
                    name,
                },
                sequence,
            ),
            HiveMutation::DeleteKey { .. } => {
                encode_log_record(&HiveLogOp::DeleteKey { path: &relative }, sequence)
            }
            HiveMutation::SetKeyClass { class_name, .. } => encode_log_record(
                &HiveLogOp::SetKeyClass {
                    path: &relative,
                    class_name: class_name.as_deref(),
                },
                sequence,
            ),
            HiveMutation::SetKeySecurity { descriptor, .. } => encode_log_record(
                &HiveLogOp::SetKeySecurityDescriptor {
                    path: &relative,
                    descriptor,
                },
                sequence,
            ),
            HiveMutation::PublishDeviceAction { .. } => return Err(STATUS_INVALID_PARAMETER),
        };
        Ok(record)
    }

    fn prepare_system_hive_mutations(
        &mut self,
        mutations: &[HiveMutation],
    ) -> Result<Vec<u8>, i32> {
        let (system_hive, cm) = (&mut self.system_hive, &mut self.cm);
        let mounted = system_hive.as_mut().ok_or(STATUS_DEVICE_NOT_READY)?;
        let previous_control_set = mounted.current_control_set.clone();
        let mut transaction = mounted.hive.begin_transaction();
        let mut durable_journal = Vec::new();
        for mutation in mutations {
            let previous_sequence = transaction.hive().sequence;
            apply_system_hive_mutation(&mut transaction, &previous_control_set, mutation)?;
            let sequence = transaction.hive().sequence;
            if sequence == previous_sequence {
                continue;
            }
            let record = Self::encode_system_hive_mutation_log_record(
                mutation,
                &previous_control_set,
                sequence,
            )?;
            durable_journal
                .try_reserve_exact(record.len())
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            durable_journal.extend_from_slice(&record);
        }
        let current_control_set = transaction
            .current_control_set()
            .map_err(|_| STATUS_REGISTRY_CORRUPT)?;

        if previous_control_set == current_control_set {
            let mut registry = cm.registry_mut().begin_transaction();
            let _ = project_system_hive_mutations(&mut registry, &current_control_set, mutations)?;
        } else {
            let _ = config_manager_from_system_hive(transaction.hive(), &current_control_set);
        }
        // Both validation transactions roll back here. Publication happens only after the caller
        // has made `durable_journal` stable.
        Ok(durable_journal)
    }

    fn commit_system_hive_mutations(
        &mut self,
        mutations: &[HiveMutation],
        next_generation: u64,
    ) -> Result<bool, i32> {
        let mounted = self.system_hive.as_mut().ok_or(STATUS_DEVICE_NOT_READY)?;
        let previous_control_set = mounted.current_control_set.clone();
        let mut transaction = mounted.hive.begin_transaction();
        for mutation in mutations {
            apply_system_hive_mutation(&mut transaction, &previous_control_set, mutation)?;
        }
        let current_control_set = transaction
            .current_control_set()
            .map_err(|_| STATUS_REGISTRY_CORRUPT)?;

        let actions = device_action_intents(mutations)?;
        let mut topology = if previous_control_set != current_control_set || !actions.is_empty() {
            Some(config_manager_from_system_hive(
                transaction.hive(),
                &current_control_set,
            ))
        } else {
            None
        };
        if !actions.is_empty() {
            let publications = topology.as_mut().unwrap().devnode_publications();
            self.device_action_journal
                .publish_actions(next_generation, &publications, &actions)
                .map_err(device_action_journal_status)?;
        }

        if previous_control_set == current_control_set {
            let mut registry = self.cm.registry_mut().begin_transaction();
            let enum_changed =
                project_system_hive_mutations(&mut registry, &current_control_set, mutations)?;
            transaction.commit();
            registry.commit();
            if enum_changed {
                self.cm.refresh_registry_devnodes();
            }
        } else {
            transaction.commit();
            self.cm = topology.unwrap();
        }
        mounted.generation = next_generation;
        mounted.current_control_set = current_control_set;
        Ok(self.device_action_journal.pending_len() != 0)
    }

    fn op_mutate_system_hive(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmHiveMutationRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmHiveMutationRequest>();
        let Ok(journal_len) = usize::try_from(req.journal_len_bytes) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let Ok(chunk_len) = usize::try_from(req.chunk_len_bytes) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || req.mount != hive_mount::SYSTEM
            || chunk_len > CM_HIVE_MUTATION_CHUNK_BYTES
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let Some(current_generation) = self.system_hive.as_ref().map(|hive| hive.generation) else {
            return reply(STATUS_DEVICE_NOT_READY, 0);
        };

        match req.operation {
            hive_mutation_transfer::BEGIN => {
                if req.lease_token != 0
                    || req.expected_generation == 0
                    || req.expected_generation != current_generation
                    || req.journal_offset != 0
                    || req.chunk_offset != 0
                    || req.chunk_len_bytes != 0
                    || buf.len() != header_size
                {
                    return reply(
                        if req.expected_generation != 0
                            && req.expected_generation != current_generation
                        {
                            STATUS_REVISION_MISMATCH
                        } else {
                            STATUS_INVALID_PARAMETER
                        },
                        current_generation,
                    );
                }
                if self.prepared_system_mutation.is_some()
                    || self.prepared_system_checkpoint.is_some()
                {
                    return reply(STATUS_DEVICE_BUSY, current_generation);
                }
                match self
                    .system_mutation_leases
                    .begin(current_generation, journal_len)
                {
                    Ok(token) => reply_with_info(STATUS_SUCCESS, 0, current_generation, token),
                    Err(MutationLeaseError::Busy) => reply(STATUS_DEVICE_BUSY, current_generation),
                    Err(MutationLeaseError::Exhausted) => {
                        reply(STATUS_INSUFFICIENT_RESOURCES, current_generation)
                    }
                    Err(_) => reply(STATUS_INVALID_PARAMETER, current_generation),
                }
            }
            hive_mutation_transfer::APPEND => {
                if req.lease_token == 0
                    || req.expected_generation == 0
                    || req.chunk_offset as usize != header_size
                    || chunk_len == 0
                    || header_size.checked_add(chunk_len) != Some(buf.len())
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                if req.expected_generation != current_generation {
                    self.system_mutation_leases.invalidate();
                    return reply(STATUS_REVISION_MISMATCH, current_generation);
                }
                let chunk = &buf[header_size..];
                match self.system_mutation_leases.append(
                    req.lease_token,
                    req.expected_generation,
                    journal_len,
                    req.journal_offset as usize,
                    chunk,
                ) {
                    Ok(()) => reply_with_info(
                        STATUS_SUCCESS,
                        chunk_len as u32,
                        current_generation,
                        req.lease_token,
                    ),
                    Err(_) => reply(STATUS_INVALID_PARAMETER, current_generation),
                }
            }
            hive_mutation_transfer::PREPARE => {
                if req.lease_token == 0
                    || req.expected_generation == 0
                    || req.journal_offset as usize != journal_len
                    || req.chunk_offset != 0
                    || req.chunk_len_bytes != 0
                    || buf.len() != header_size
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                if req.expected_generation != current_generation {
                    self.system_mutation_leases.invalidate();
                    return reply(STATUS_REVISION_MISMATCH, current_generation);
                }
                let journal = match self.system_mutation_leases.commit(
                    req.lease_token,
                    req.expected_generation,
                    journal_len,
                ) {
                    Ok(journal) => journal,
                    Err(MutationLeaseError::Incomplete) => {
                        return reply(STATUS_INVALID_PARAMETER, current_generation);
                    }
                    Err(_) => return reply(STATUS_INVALID_PARAMETER, current_generation),
                };
                let Some(mutations) = decode_mutation_journal(&journal) else {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                };
                let Some(next_generation) = current_generation.checked_add(1) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, current_generation);
                };
                let durable_journal = match self.prepare_system_hive_mutations(&mutations) {
                    Ok(journal) => journal,
                    Err(status) => return reply(status, current_generation),
                };
                let Ok(durable_len) = u32::try_from(durable_journal.len()) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, current_generation);
                };
                self.prepared_system_mutation = Some(PreparedSystemHiveMutation {
                    token: req.lease_token,
                    expected_generation: current_generation,
                    next_generation,
                    semantic_journal_len: journal_len,
                    mutations,
                    durable_journal,
                });
                reply_with_info(
                    STATUS_SUCCESS,
                    durable_len,
                    next_generation,
                    req.lease_token,
                )
            }
            hive_mutation_transfer::PULL => {
                if req.lease_token == 0
                    || req.expected_generation == 0
                    || req.chunk_offset != 0
                    || chunk_len == 0
                    || chunk_len > out_buf.len()
                    || buf.len() != header_size
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                if req.expected_generation != current_generation {
                    return reply(STATUS_REVISION_MISMATCH, current_generation);
                }
                let Some(prepared) = self.prepared_system_mutation.as_ref() else {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                };
                if prepared.token != req.lease_token
                    || prepared.expected_generation != req.expected_generation
                    || prepared.semantic_journal_len != journal_len
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let offset = req.journal_offset as usize;
                if offset > prepared.durable_journal.len() {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let end = core::cmp::min(
                    offset.saturating_add(chunk_len),
                    prepared.durable_journal.len(),
                );
                let written = end - offset;
                out_buf[..written].copy_from_slice(&prepared.durable_journal[offset..end]);
                reply_with_info(
                    STATUS_SUCCESS,
                    written as u32,
                    prepared.durable_journal.len() as u64,
                    prepared.token,
                )
            }
            hive_mutation_transfer::COMMIT => {
                if req.lease_token == 0
                    || req.expected_generation == 0
                    || req.journal_offset as usize != journal_len
                    || req.chunk_offset != 0
                    || req.chunk_len_bytes != 0
                    || buf.len() != header_size
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                if req.expected_generation != current_generation {
                    return reply(STATUS_REVISION_MISMATCH, current_generation);
                }
                let Some(prepared) = self.prepared_system_mutation.take() else {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                };
                if prepared.token != req.lease_token
                    || prepared.expected_generation != req.expected_generation
                    || prepared.semantic_journal_len != journal_len
                {
                    self.prepared_system_mutation = Some(prepared);
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let has_pending_device_action = match self
                    .commit_system_hive_mutations(&prepared.mutations, prepared.next_generation)
                {
                    Ok(has_pending) => has_pending,
                    Err(status) => {
                        self.prepared_system_mutation = Some(prepared);
                        return reply(status, current_generation);
                    }
                };
                reply_with_info(
                    STATUS_SUCCESS,
                    u32::from(has_pending_device_action),
                    prepared.next_generation,
                    prepared.token,
                )
            }
            hive_mutation_transfer::ABORT => {
                if req.lease_token == 0
                    || req.expected_generation == 0
                    || req.journal_offset != 0
                    || req.chunk_offset != 0
                    || req.chunk_len_bytes != 0
                    || buf.len() != header_size
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let prepared_matches =
                    self.prepared_system_mutation
                        .as_ref()
                        .is_some_and(|prepared| {
                            prepared.token == req.lease_token
                                && prepared.expected_generation == req.expected_generation
                                && prepared.semantic_journal_len == journal_len
                        });
                let aborted = if prepared_matches {
                    self.prepared_system_mutation = None;
                    true
                } else {
                    self.system_mutation_leases.abort(
                        req.lease_token,
                        req.expected_generation,
                        journal_len,
                    )
                };
                if !aborted {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                reply(STATUS_SUCCESS, current_generation)
            }
            _ => reply(STATUS_INVALID_PARAMETER, current_generation),
        }
    }

    fn op_checkpoint_system_hive(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmHiveCheckpointRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmHiveCheckpointRequest>();
        let chunk_capacity = req.chunk_capacity as usize;
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || req.mount != hive_mount::SYSTEM
            || buf.len() != header_size
            || chunk_capacity > CM_HIVE_CHECKPOINT_CHUNK_BYTES
            || chunk_capacity > out_buf.len()
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let Some(current_generation) = self.system_hive.as_ref().map(|hive| hive.generation) else {
            return reply(STATUS_DEVICE_NOT_READY, 0);
        };
        if req.expected_generation == 0 || req.expected_generation != current_generation {
            return reply(
                if req.expected_generation == 0 {
                    STATUS_INVALID_PARAMETER
                } else {
                    STATUS_REVISION_MISMATCH
                },
                current_generation,
            );
        }

        match req.operation {
            hive_checkpoint_transfer::BEGIN => {
                if req.transfer_token != 0 || req.value_offset != 0 || chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                if self.prepared_system_checkpoint.is_some()
                    || self.prepared_system_mutation.is_some()
                    || self.system_mutation_leases.is_busy()
                    || !self.hive_imports.is_empty()
                {
                    return reply(STATUS_DEVICE_BUSY, current_generation);
                }
                let mounted = self.system_hive.as_mut().unwrap();
                if mounted.hive.dirty_count() == 0 {
                    return reply_with_info(STATUS_SUCCESS, 0, current_generation, 0);
                }
                let hive_sequence = mounted.hive.sequence;
                let previous_image_generation = mounted.hive.generation;
                let image_generation = previous_image_generation.saturating_add(1);
                mounted.hive.generation = image_generation;
                let image_result = try_encode_image(&mounted.hive);
                mounted.hive.generation = previous_image_generation;
                let image = match image_result {
                    Ok(image) => image,
                    Err(_) => return reply(STATUS_INSUFFICIENT_RESOURCES, current_generation),
                };
                let Ok(image_len_bytes) = u32::try_from(image.len()) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, current_generation);
                };
                let checkpoint_header = CmHiveCheckpointHeader {
                    magic: CM_HIVE_CHECKPOINT_MAGIC,
                    version: CM_HIVE_CHECKPOINT_VERSION,
                    header_size: CM_HIVE_CHECKPOINT_HEADER_BYTES as u16,
                    mount_generation: current_generation,
                    hive_sequence,
                    image_generation,
                    image_len_bytes,
                    _reserved: 0,
                };
                let Some(total_len) = CM_HIVE_CHECKPOINT_HEADER_BYTES.checked_add(image.len())
                else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, current_generation);
                };
                let mut value = Vec::new();
                if value.try_reserve_exact(total_len).is_err() {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, current_generation);
                }
                value.extend_from_slice(checkpoint_header.as_bytes());
                value.extend_from_slice(&image);
                let token = self.next_system_checkpoint_token;
                let Some(next_token) = token.checked_add(1) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, current_generation);
                };
                if token == 0 {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, current_generation);
                }
                let written = core::cmp::min(chunk_capacity, value.len());
                out_buf[..written].copy_from_slice(&value[..written]);
                self.next_system_checkpoint_token = next_token;
                self.prepared_system_checkpoint = Some(PreparedSystemHiveCheckpoint {
                    token,
                    mount_generation: current_generation,
                    hive_sequence,
                    image_generation,
                    value,
                    offset: written,
                });
                reply_with_info(STATUS_SUCCESS, written as u32, total_len as u64, token)
            }
            hive_checkpoint_transfer::PULL => {
                if req.transfer_token == 0 || chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let Some(prepared) = self.prepared_system_checkpoint.as_mut() else {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                };
                if prepared.token != req.transfer_token
                    || prepared.mount_generation != req.expected_generation
                    || prepared.offset != req.value_offset as usize
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let end = core::cmp::min(
                    prepared.offset.saturating_add(chunk_capacity),
                    prepared.value.len(),
                );
                let written = end - prepared.offset;
                out_buf[..written].copy_from_slice(&prepared.value[prepared.offset..end]);
                prepared.offset = end;
                reply_with_info(
                    STATUS_SUCCESS,
                    written as u32,
                    prepared.value.len() as u64,
                    prepared.token,
                )
            }
            hive_checkpoint_transfer::ACK => {
                if req.transfer_token == 0 || chunk_capacity != 0 {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let Some(prepared) = self.prepared_system_checkpoint.take() else {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                };
                if prepared.token != req.transfer_token
                    || prepared.mount_generation != req.expected_generation
                    || prepared.offset != prepared.value.len()
                    || req.value_offset as usize != prepared.value.len()
                {
                    self.prepared_system_checkpoint = Some(prepared);
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let mounted = self.system_hive.as_mut().unwrap();
                if mounted.generation != prepared.mount_generation
                    || !mounted
                        .hive
                        .acknowledge_checkpoint(prepared.hive_sequence, prepared.image_generation)
                {
                    self.prepared_system_checkpoint = Some(prepared);
                    return reply(STATUS_REVISION_MISMATCH, current_generation);
                }
                reply_with_info(STATUS_SUCCESS, 0, current_generation, req.transfer_token)
            }
            hive_checkpoint_transfer::ABORT => {
                if req.transfer_token == 0 || req.value_offset != 0 || chunk_capacity != 0 {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let matches = self
                    .prepared_system_checkpoint
                    .as_ref()
                    .is_some_and(|prepared| {
                        prepared.token == req.transfer_token
                            && prepared.mount_generation == req.expected_generation
                    });
                if !matches {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                self.prepared_system_checkpoint = None;
                reply(STATUS_SUCCESS, current_generation)
            }
            _ => reply(STATUS_INVALID_PARAMETER, current_generation),
        }
    }

    fn op_query_hive_key(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmHiveKeyRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmHiveKeyRequest>();
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || req.mount != hive_mount::SYSTEM
            || req.path_offset as usize != header_size
            || req.path_len_bytes == 0
            || req.path_len_bytes % 2 != 0
            || req.path_len_bytes as usize > CM_MAX_HIVE_PATH_UNITS * 2
            || header_size.checked_add(req.path_len_bytes as usize) != Some(buf.len())
            || req.chunk_capacity as usize > CM_HIVE_KEY_CHUNK_BYTES
            || req.chunk_capacity as usize > out_buf.len()
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let mut units = [0u16; CM_MAX_HIVE_PATH_UNITS];
        let Some(unit_count) = read_utf16(buf, req.path_offset, req.path_len_bytes, &mut units)
        else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let units = &units[..unit_count];
        if units.contains(&0) {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let Ok(path) = String::from_utf16(units) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };

        match req.operation {
            hive_key_transfer::BEGIN => {
                if req.transfer_token != 0 || req.value_offset != 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(mounted) = self.system_hive.as_ref() else {
                    return reply(STATUS_DEVICE_NOT_READY, 0);
                };
                let Some(relative) = system_hive_relative_path(&path, &mounted.current_control_set)
                else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                if mounted.hive.open_key(&relative).is_none() {
                    return reply(STATUS_OBJECT_NAME_NOT_FOUND, 0);
                }
                let Some(value) = encode_hive_key_snapshot(
                    &mounted.hive,
                    mounted.generation,
                    &mounted.current_control_set,
                    &path,
                ) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                let Some(chunk) = self.hive_key_snapshots.begin(
                    HiveKeySnapshotKey {
                        mount: req.mount,
                        identity: HiveKeySnapshotIdentity::Path(path),
                    },
                    value,
                    req.chunk_capacity as usize,
                    out_buf,
                ) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                snapshot_reply(chunk)
            }
            hive_key_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(chunk) = self.hive_key_snapshots.pull(
                    req.transfer_token,
                    req.value_offset as usize,
                    req.chunk_capacity as usize,
                    out_buf,
                    |key| {
                        key.mount == req.mount
                            && matches!(
                                &key.identity,
                                HiveKeySnapshotIdentity::Path(snapshot_path)
                                    if snapshot_path.eq_ignore_ascii_case(&path)
                            )
                    },
                ) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                snapshot_reply(chunk)
            }
            hive_key_transfer::ABORT => {
                if req.transfer_token == 0 || req.value_offset != 0 || req.chunk_capacity != 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                if !self.hive_key_snapshots.abort(req.transfer_token, |key| {
                    key.mount == req.mount
                        && matches!(
                            &key.identity,
                            HiveKeySnapshotIdentity::Path(snapshot_path)
                                if snapshot_path.eq_ignore_ascii_case(&path)
                        )
                }) {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                reply(STATUS_SUCCESS, 0)
            }
            _ => reply(STATUS_INVALID_PARAMETER, 0),
        }
    }

    fn op_system_hive_key_lease(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmHiveKeyLeaseRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmHiveKeyLeaseRequest>();
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || req.mount != hive_mount::SYSTEM
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let current_generation = self
            .system_hive
            .as_ref()
            .map(|mounted| mounted.generation)
            .unwrap_or(0);
        match req.operation {
            hive_key_lease_operation::RESOLVE => {
                if req.lease_token != 0
                    || req.path_offset as usize != header_size
                    || req.path_len_bytes == 0
                    || req.path_len_bytes % 2 != 0
                    || req.path_len_bytes as usize > CM_MAX_HIVE_PATH_UNITS * 2
                    || header_size.checked_add(req.path_len_bytes as usize) != Some(buf.len())
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let mut units = [0u16; CM_MAX_HIVE_PATH_UNITS];
                let Some(unit_count) =
                    read_utf16(buf, req.path_offset, req.path_len_bytes, &mut units)
                else {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                };
                let units = &units[..unit_count];
                if units.contains(&0) {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let Ok(path) = String::from_utf16(units) else {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                };
                let Some(mounted) = self.system_hive.as_ref() else {
                    return reply(STATUS_DEVICE_NOT_READY, 0);
                };
                let Some(relative) = system_hive_relative_path(&path, &mounted.current_control_set)
                else {
                    return reply(STATUS_INVALID_PARAMETER, mounted.generation);
                };
                let mut physical_path = String::from(SYSTEM_HIVE_PATH);
                if !relative.is_empty() {
                    physical_path.push('\\');
                    physical_path.push_str(&relative);
                }
                let path_bytes = physical_path.as_bytes();
                if path_bytes.len() > out_buf.len() {
                    return reply_with_info(
                        STATUS_BUFFER_TOO_SMALL,
                        path_bytes.len() as u32,
                        mounted.generation,
                        0,
                    );
                }
                out_buf[..path_bytes.len()].copy_from_slice(path_bytes);
                reply_with_info(
                    STATUS_SUCCESS,
                    path_bytes.len() as u32,
                    mounted.generation,
                    0,
                )
            }
            hive_key_lease_operation::OPEN => {
                if req.lease_token != 0
                    || req.path_offset as usize != header_size
                    || req.path_len_bytes == 0
                    || req.path_len_bytes % 2 != 0
                    || req.path_len_bytes as usize > CM_MAX_HIVE_PATH_UNITS * 2
                    || header_size.checked_add(req.path_len_bytes as usize) != Some(buf.len())
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let mut units = [0u16; CM_MAX_HIVE_PATH_UNITS];
                let Some(unit_count) =
                    read_utf16(buf, req.path_offset, req.path_len_bytes, &mut units)
                else {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                };
                let units = &units[..unit_count];
                if units.contains(&0) {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let Ok(path) = String::from_utf16(units) else {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                };
                let Some(mounted) = self.system_hive.as_ref() else {
                    return reply(STATUS_DEVICE_NOT_READY, 0);
                };
                let Some(relative) = system_hive_relative_path(&path, &mounted.current_control_set)
                else {
                    return reply(STATUS_INVALID_PARAMETER, mounted.generation);
                };
                let Some(key) = mounted.hive.open_key(&relative) else {
                    return reply(STATUS_OBJECT_NAME_NOT_FOUND, mounted.generation);
                };
                let mut physical_path = String::from(SYSTEM_HIVE_PATH);
                if !relative.is_empty() {
                    physical_path.push('\\');
                    physical_path.push_str(&relative);
                }
                let path_bytes = physical_path.as_bytes();
                let path_len = path_bytes.len();
                if path_len > out_buf.len() {
                    return reply_with_info(
                        STATUS_BUFFER_TOO_SMALL,
                        path_len as u32,
                        mounted.generation,
                        0,
                    );
                }
                out_buf[..path_len].copy_from_slice(path_bytes);
                match self.system_key_leases.open(key, physical_path) {
                    Ok(token) => {
                        reply_with_info(STATUS_SUCCESS, path_len as u32, mounted.generation, token)
                    }
                    Err(SystemKeyLeaseError::Exhausted) => {
                        reply(STATUS_INSUFFICIENT_RESOURCES, mounted.generation)
                    }
                    Err(SystemKeyLeaseError::Invalid) => {
                        reply(STATUS_INVALID_PARAMETER, mounted.generation)
                    }
                }
            }
            hive_key_lease_operation::CLOSE => {
                if req.lease_token == 0
                    || req.path_offset != 0
                    || req.path_len_bytes != 0
                    || buf.len() != header_size
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                match self.system_key_leases.close(req.lease_token) {
                    Ok(()) => {
                        reply_with_info(STATUS_SUCCESS, 0, current_generation, req.lease_token)
                    }
                    Err(_) => reply(STATUS_INVALID_HANDLE, current_generation),
                }
            }
            _ => reply(STATUS_INVALID_PARAMETER, current_generation),
        }
    }

    fn op_query_leased_hive_key(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmLeasedHiveKeyRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmLeasedHiveKeyRequest>();
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || req.mount != hive_mount::SYSTEM
            || buf.len() != header_size
            || req.key_lease_token == 0
            || req.chunk_capacity as usize > CM_HIVE_KEY_CHUNK_BYTES
            || req.chunk_capacity as usize > out_buf.len()
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        match req.operation {
            hive_key_transfer::BEGIN => {
                if req.transfer_token != 0 || req.value_offset != 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(lease) = self.system_key_leases.get(req.key_lease_token) else {
                    return reply(STATUS_INVALID_HANDLE, 0);
                };
                let key = lease.key;
                let physical_path = lease.physical_path.clone();
                let Some(mounted) = self.system_hive.as_ref() else {
                    return reply(STATUS_DEVICE_NOT_READY, 0);
                };
                if mounted.hive.key_path(key).is_none() {
                    return reply(STATUS_OBJECT_NAME_NOT_FOUND, mounted.generation);
                }
                let Some(value) = encode_hive_key_snapshot_from_key(
                    &mounted.hive,
                    mounted.generation,
                    key,
                    &physical_path,
                ) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, mounted.generation);
                };
                let Some(chunk) = self.hive_key_snapshots.begin(
                    HiveKeySnapshotKey {
                        mount: req.mount,
                        identity: HiveKeySnapshotIdentity::Lease(req.key_lease_token),
                    },
                    value,
                    req.chunk_capacity as usize,
                    out_buf,
                ) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, mounted.generation);
                };
                snapshot_reply(chunk)
            }
            hive_key_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(chunk) = self.hive_key_snapshots.pull(
                    req.transfer_token,
                    req.value_offset as usize,
                    req.chunk_capacity as usize,
                    out_buf,
                    |key| {
                        key.mount == req.mount
                            && matches!(
                                key.identity,
                                HiveKeySnapshotIdentity::Lease(token)
                                    if token == req.key_lease_token
                            )
                    },
                ) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                snapshot_reply(chunk)
            }
            hive_key_transfer::ABORT => {
                if req.transfer_token == 0 || req.value_offset != 0 || req.chunk_capacity != 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                if !self.hive_key_snapshots.abort(req.transfer_token, |key| {
                    key.mount == req.mount
                        && matches!(
                            key.identity,
                            HiveKeySnapshotIdentity::Lease(token)
                                if token == req.key_lease_token
                        )
                }) {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                reply(STATUS_SUCCESS, 0)
            }
            _ => reply(STATUS_INVALID_PARAMETER, 0),
        }
    }

    fn op_export_leased_hive(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmLeasedHiveKeyRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmLeasedHiveKeyRequest>();
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || req.mount != hive_mount::SYSTEM
            || buf.len() != header_size
            || req.key_lease_token == 0
            || req.chunk_capacity as usize > CM_HIVE_KEY_CHUNK_BYTES
            || req.chunk_capacity as usize > out_buf.len()
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        match req.operation {
            hive_key_transfer::BEGIN => {
                if req.transfer_token != 0 || req.value_offset != 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(lease) = self.system_key_leases.get(req.key_lease_token) else {
                    return reply(STATUS_INVALID_HANDLE, 0);
                };
                let key = lease.key;
                let Some(mounted) = self.system_hive.as_ref() else {
                    return reply(STATUS_DEVICE_NOT_READY, 0);
                };
                if mounted.hive.key_path(key).is_none() {
                    return reply(STATUS_KEY_DELETED, mounted.generation);
                }
                let image = if key == mounted.hive.root() {
                    match try_encode_image(&mounted.hive) {
                        Ok(image) => image,
                        Err(HiveEncodeError::OutOfMemory | HiveEncodeError::SizeOverflow) => {
                            return reply(STATUS_INSUFFICIENT_RESOURCES, mounted.generation);
                        }
                    }
                } else {
                    match try_encode_subtree_image(&mounted.hive, key) {
                        Ok(image) => image,
                        Err(HiveSubtreeEncodeError::InvalidRoot) => {
                            return reply(STATUS_KEY_DELETED, mounted.generation);
                        }
                        Err(HiveSubtreeEncodeError::Encode(
                            HiveEncodeError::OutOfMemory | HiveEncodeError::SizeOverflow,
                        )) => {
                            return reply(STATUS_INSUFFICIENT_RESOURCES, mounted.generation);
                        }
                    }
                };
                let image_len = image.len();
                let Ok(image_len_bytes) = u32::try_from(image_len) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, mounted.generation);
                };
                let export_header = CmHiveExportHeader {
                    magic: CM_HIVE_EXPORT_MAGIC,
                    version: CM_HIVE_EXPORT_VERSION,
                    header_size: CM_HIVE_EXPORT_HEADER_BYTES as u16,
                    mount_generation: mounted.generation,
                    image_len_bytes,
                    _reserved: 0,
                };
                let Some(total_len) = CM_HIVE_EXPORT_HEADER_BYTES.checked_add(image_len) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, mounted.generation);
                };
                let mut value = Vec::new();
                if value.try_reserve_exact(total_len).is_err() {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, mounted.generation);
                }
                value.extend_from_slice(export_header.as_bytes());
                value.extend_from_slice(&image);
                let Some(chunk) = self.hive_export_snapshots.begin(
                    HiveExportSnapshotKey {
                        mount: req.mount,
                        key_lease_token: req.key_lease_token,
                    },
                    value,
                    req.chunk_capacity as usize,
                    out_buf,
                ) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, mounted.generation);
                };
                snapshot_reply(chunk)
            }
            hive_key_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(chunk) = self.hive_export_snapshots.pull(
                    req.transfer_token,
                    req.value_offset as usize,
                    req.chunk_capacity as usize,
                    out_buf,
                    |key| key.mount == req.mount && key.key_lease_token == req.key_lease_token,
                ) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                snapshot_reply(chunk)
            }
            hive_key_transfer::ABORT => {
                if req.transfer_token == 0 || req.value_offset != 0 || req.chunk_capacity != 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                if !self.hive_export_snapshots.abort(req.transfer_token, |key| {
                    key.mount == req.mount && key.key_lease_token == req.key_lease_token
                }) {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                reply(STATUS_SUCCESS, 0)
            }
            _ => reply(STATUS_INVALID_PARAMETER, 0),
        }
    }

    fn op_query_leased_hive_record(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmLeasedHiveRecordRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmLeasedHiveRecordRequest>();
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || req.mount != hive_mount::SYSTEM
            || req._reserved != 0
            || req.key_lease_token == 0
            || req.chunk_capacity as usize > CM_HIVE_KEY_CHUNK_BYTES
            || req.chunk_capacity as usize > out_buf.len()
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        match req.operation {
            hive_key_transfer::BEGIN => {
                if req.transfer_token != 0 || req.value_offset != 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let value_name = match req.record_kind {
                    leased_hive_record_kind::KEY_INFORMATION => {
                        if req.index != 0
                            || req.name_offset != 0
                            || req.name_len_bytes != 0
                            || buf.len() != header_size
                        {
                            return reply(STATUS_INVALID_PARAMETER, 0);
                        }
                        None
                    }
                    leased_hive_record_kind::VALUE_BY_NAME => {
                        if req.index != 0
                            || req.name_offset as usize != header_size
                            || req.name_len_bytes % 2 != 0
                            || req.name_len_bytes as usize > CM_MAX_HIVE_VALUE_NAME_UNITS * 2
                            || header_size.checked_add(req.name_len_bytes as usize)
                                != Some(buf.len())
                        {
                            return reply(STATUS_INVALID_PARAMETER, 0);
                        }
                        let mut units = [0u16; CM_MAX_HIVE_VALUE_NAME_UNITS];
                        let Some(unit_count) =
                            read_utf16(buf, req.name_offset, req.name_len_bytes, &mut units)
                        else {
                            return reply(STATUS_INVALID_PARAMETER, 0);
                        };
                        let units = &units[..unit_count];
                        if units.contains(&0) {
                            return reply(STATUS_INVALID_PARAMETER, 0);
                        }
                        let Ok(name) = String::from_utf16(units) else {
                            return reply(STATUS_INVALID_PARAMETER, 0);
                        };
                        Some(name)
                    }
                    leased_hive_record_kind::SUBKEY_BY_INDEX
                    | leased_hive_record_kind::VALUE_BY_INDEX => {
                        if req.name_offset != 0
                            || req.name_len_bytes != 0
                            || buf.len() != header_size
                        {
                            return reply(STATUS_INVALID_PARAMETER, 0);
                        }
                        None
                    }
                    _ => return reply(STATUS_INVALID_PARAMETER, 0),
                };
                let Some(lease) = self.system_key_leases.get(req.key_lease_token) else {
                    return reply(STATUS_INVALID_HANDLE, 0);
                };
                let key = lease.key;
                let physical_path = lease.physical_path.clone();
                let Some(mounted) = self.system_hive.as_ref() else {
                    return reply(STATUS_DEVICE_NOT_READY, 0);
                };
                if mounted.hive.key_path(key).is_none() {
                    return reply(STATUS_OBJECT_NAME_NOT_FOUND, mounted.generation);
                }
                let value = match req.record_kind {
                    leased_hive_record_kind::KEY_INFORMATION => encode_hive_key_information_record(
                        &mounted.hive,
                        mounted.generation,
                        key,
                        &physical_path,
                    )
                    .ok_or(STATUS_INSUFFICIENT_RESOURCES),
                    leased_hive_record_kind::VALUE_BY_NAME => encode_hive_value_record(
                        &mounted.hive,
                        mounted.generation,
                        key,
                        req.record_kind,
                        0,
                        value_name.as_deref(),
                    ),
                    leased_hive_record_kind::SUBKEY_BY_INDEX => {
                        encode_hive_subkey_record(&mounted.hive, mounted.generation, key, req.index)
                    }
                    leased_hive_record_kind::VALUE_BY_INDEX => encode_hive_value_record(
                        &mounted.hive,
                        mounted.generation,
                        key,
                        req.record_kind,
                        req.index,
                        None,
                    ),
                    _ => return reply(STATUS_INVALID_PARAMETER, mounted.generation),
                };
                let value = match value {
                    Ok(value) => value,
                    Err(status) => return reply(status, mounted.generation),
                };
                let Some(chunk) = self.hive_key_snapshots.begin(
                    HiveKeySnapshotKey {
                        mount: req.mount,
                        identity: HiveKeySnapshotIdentity::LeaseRecord(req.key_lease_token),
                    },
                    value,
                    req.chunk_capacity as usize,
                    out_buf,
                ) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, mounted.generation);
                };
                snapshot_reply(chunk)
            }
            hive_key_transfer::PULL => {
                if req.transfer_token == 0
                    || req.chunk_capacity == 0
                    || req.index != 0
                    || req.name_offset != 0
                    || req.name_len_bytes != 0
                    || req.record_kind != 0
                    || buf.len() != header_size
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(chunk) = self.hive_key_snapshots.pull(
                    req.transfer_token,
                    req.value_offset as usize,
                    req.chunk_capacity as usize,
                    out_buf,
                    |key| {
                        key.mount == req.mount
                            && matches!(
                                key.identity,
                                HiveKeySnapshotIdentity::LeaseRecord(token)
                                    if token == req.key_lease_token
                            )
                    },
                ) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                snapshot_reply(chunk)
            }
            hive_key_transfer::ABORT => {
                if req.transfer_token == 0
                    || req.value_offset != 0
                    || req.chunk_capacity != 0
                    || req.index != 0
                    || req.name_offset != 0
                    || req.name_len_bytes != 0
                    || req.record_kind != 0
                    || buf.len() != header_size
                    || !self.hive_key_snapshots.abort(req.transfer_token, |key| {
                        key.mount == req.mount
                            && matches!(
                                key.identity,
                                HiveKeySnapshotIdentity::LeaseRecord(token)
                                    if token == req.key_lease_token
                            )
                    })
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                reply(STATUS_SUCCESS, 0)
            }
            _ => reply(STATUS_INVALID_PARAMETER, 0),
        }
    }

    fn op_query_launch_plan(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmLaunchPlanRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmLaunchPlanRequest>();
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || buf.len() != header_size
            || req.chunk_capacity as usize > CM_LAUNCH_PLAN_CHUNK_BYTES
            || req.chunk_capacity as usize > out_buf.len()
            || !matches!(
                req.plan_kind,
                launch_plan_kind::BOOT_SYSTEM_DRIVERS | launch_plan_kind::DEMAND_DRIVERS
            )
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }

        match req.operation {
            launch_plan_transfer::BEGIN => {
                if req.transfer_token != 0 || req.value_offset != 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(generation) = self.system_hive.as_ref().map(|mounted| mounted.generation)
                else {
                    return reply(STATUS_DEVICE_NOT_READY, 0);
                };
                let starts: &[u32] = match req.plan_kind {
                    launch_plan_kind::BOOT_SYSTEM_DRIVERS => {
                        &[SERVICE_BOOT_START, SERVICE_SYSTEM_START]
                    }
                    launch_plan_kind::DEMAND_DRIVERS => &[SERVICE_DEMAND_START],
                    _ => return reply(STATUS_INVALID_PARAMETER, 0),
                };
                let bindings = self.cm.driver_service_bindings_by_start(starts);
                let Some(value) =
                    encode_driver_launch_plan(&self.cm, generation, req.plan_kind, &bindings)
                else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                let Some(chunk) = self.driver_launch_plan_snapshots.begin(
                    req.plan_kind,
                    value,
                    req.chunk_capacity as usize,
                    out_buf,
                ) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                snapshot_reply(chunk)
            }
            launch_plan_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(chunk) = self.driver_launch_plan_snapshots.pull(
                    req.transfer_token,
                    req.value_offset as usize,
                    req.chunk_capacity as usize,
                    out_buf,
                    |plan_kind| *plan_kind == req.plan_kind,
                ) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                snapshot_reply(chunk)
            }
            launch_plan_transfer::ABORT => {
                if req.transfer_token == 0
                    || req.value_offset != 0
                    || req.chunk_capacity != 0
                    || !self
                        .driver_launch_plan_snapshots
                        .abort(req.transfer_token, |plan_kind| *plan_kind == req.plan_kind)
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                reply(STATUS_SUCCESS, 0)
            }
            _ => reply(STATUS_INVALID_PARAMETER, 0),
        }
    }

    fn op_query_win32_service_plan(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmLaunchPlanRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmLaunchPlanRequest>();
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || buf.len() != header_size
            || req.chunk_capacity as usize > CM_LAUNCH_PLAN_CHUNK_BYTES
            || req.chunk_capacity as usize > out_buf.len()
            || !matches!(
                req.plan_kind,
                win32_service_plan_kind::AUTO_START | win32_service_plan_kind::DEMAND_START
            )
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }

        match req.operation {
            launch_plan_transfer::BEGIN => {
                if req.transfer_token != 0 || req.value_offset != 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(generation) = self.system_hive.as_ref().map(|mounted| mounted.generation)
                else {
                    return reply(STATUS_DEVICE_NOT_READY, 0);
                };
                let launches = match req.plan_kind {
                    win32_service_plan_kind::AUTO_START => {
                        self.cm.auto_start_win32_service_process_launches()
                    }
                    win32_service_plan_kind::DEMAND_START => {
                        self.cm.demand_start_win32_service_process_launches()
                    }
                    _ => return reply(STATUS_INVALID_PARAMETER, 0),
                };
                let Some(value) =
                    encode_win32_service_launch_plan(generation, req.plan_kind, &launches)
                else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                let Some(chunk) = self.win32_service_launch_plan_snapshots.begin(
                    req.plan_kind,
                    value,
                    req.chunk_capacity as usize,
                    out_buf,
                ) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                snapshot_reply(chunk)
            }
            launch_plan_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(chunk) = self.win32_service_launch_plan_snapshots.pull(
                    req.transfer_token,
                    req.value_offset as usize,
                    req.chunk_capacity as usize,
                    out_buf,
                    |plan_kind| *plan_kind == req.plan_kind,
                ) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                snapshot_reply(chunk)
            }
            launch_plan_transfer::ABORT => {
                if req.transfer_token == 0
                    || req.value_offset != 0
                    || req.chunk_capacity != 0
                    || !self
                        .win32_service_launch_plan_snapshots
                        .abort(req.transfer_token, |plan_kind| *plan_kind == req.plan_kind)
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                reply(STATUS_SUCCESS, 0)
            }
            _ => reply(STATUS_INVALID_PARAMETER, 0),
        }
    }

    fn op_query_network_plan(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmLaunchPlanRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmLaunchPlanRequest>();
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || buf.len() != header_size
            || req.chunk_capacity as usize > CM_LAUNCH_PLAN_CHUNK_BYTES
            || req.chunk_capacity as usize > out_buf.len()
            || req.plan_kind != network_plan_kind::ADAPTER_BINDINGS
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }

        match req.operation {
            launch_plan_transfer::BEGIN => {
                if req.transfer_token != 0 || req.value_offset != 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(generation) = self.system_hive.as_ref().map(|mounted| mounted.generation)
                else {
                    return reply(STATUS_DEVICE_NOT_READY, 0);
                };
                self.cm.refresh_registry_devnodes();
                let adapters = collect_reactos_network_adapter_bindings(&self.cm);
                let Some(value) = encode_network_adapter_plan(
                    generation,
                    network_plan_kind::ADAPTER_BINDINGS,
                    &adapters,
                ) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                let Some(chunk) = self.network_adapter_plan_snapshots.begin(
                    req.plan_kind,
                    value,
                    req.chunk_capacity as usize,
                    out_buf,
                ) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                snapshot_reply(chunk)
            }
            launch_plan_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(chunk) = self.network_adapter_plan_snapshots.pull(
                    req.transfer_token,
                    req.value_offset as usize,
                    req.chunk_capacity as usize,
                    out_buf,
                    |plan_kind| *plan_kind == req.plan_kind,
                ) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                snapshot_reply(chunk)
            }
            launch_plan_transfer::ABORT => {
                if req.transfer_token == 0
                    || req.value_offset != 0
                    || req.chunk_capacity != 0
                    || !self
                        .network_adapter_plan_snapshots
                        .abort(req.transfer_token, |plan_kind| *plan_kind == req.plan_kind)
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                reply(STATUS_SUCCESS, 0)
            }
            _ => reply(STATUS_INVALID_PARAMETER, 0),
        }
    }

    fn op_device_action(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmDeviceActionRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmDeviceActionRequest>();
        let chunk_capacity = req.chunk_capacity as usize;
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || req._reserved != 0
            || buf.len() != header_size
            || chunk_capacity > CM_DEVICE_ACTION_CHUNK_BYTES
            || chunk_capacity > out_buf.len()
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let current_generation = self
            .system_hive
            .as_ref()
            .map(|mounted| mounted.generation)
            .unwrap_or(0);
        if current_generation == 0 {
            return reply(STATUS_DEVICE_NOT_READY, 0);
        }

        match req.operation {
            device_action_transfer::BEGIN => {
                if req.value_offset != 0
                    || chunk_capacity == 0
                    || req.mount_generation != 0
                    || req.event_sequence != 0
                    || req.transfer_token != 0
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                if self.device_action_claim.is_some() {
                    return reply(STATUS_DEVICE_BUSY, current_generation);
                }
                let Some(event) = self.device_action_journal.peek() else {
                    return reply(STATUS_NO_MORE_ENTRIES, current_generation);
                };
                let key = DeviceActionSnapshotKey {
                    mount_generation: event.mount_generation,
                    sequence: event.sequence,
                };
                let Some(value) = encode_device_action_event(event) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, current_generation);
                };
                let Some(token) = take_device_action_claim_token() else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, current_generation);
                };
                let needed = value.len();
                let written = core::cmp::min(needed, chunk_capacity);
                out_buf[..written].copy_from_slice(&value[..written]);
                let complete = written == needed;
                self.device_action_claim = Some(DeviceActionClaim {
                    token,
                    key,
                    value: if complete { Vec::new() } else { value },
                    offset: written,
                    complete,
                });
                reply_with_info(STATUS_SUCCESS, written as u32, needed as u64, token)
            }
            device_action_transfer::PULL => {
                if chunk_capacity == 0
                    || req.mount_generation == 0
                    || req.event_sequence == 0
                    || req.transfer_token == 0
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let Some(claim) = self.device_action_claim.as_mut() else {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                };
                if claim.token != req.transfer_token
                    || claim.key.mount_generation != req.mount_generation
                    || claim.key.sequence != req.event_sequence
                    || claim.complete
                    || claim.offset != req.value_offset as usize
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let needed = claim.value.len();
                let written = core::cmp::min(needed - claim.offset, chunk_capacity);
                out_buf[..written]
                    .copy_from_slice(&claim.value[claim.offset..claim.offset + written]);
                claim.offset += written;
                if claim.offset == needed {
                    claim.complete = true;
                    claim.value = Vec::new();
                }
                reply_with_info(STATUS_SUCCESS, written as u32, needed as u64, claim.token)
            }
            device_action_transfer::ABORT => {
                if req.value_offset != 0
                    || chunk_capacity != 0
                    || req.mount_generation == 0
                    || req.event_sequence == 0
                    || req.transfer_token == 0
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let matches = self.device_action_claim.as_ref().is_some_and(|claim| {
                    claim.token == req.transfer_token
                        && claim.key.mount_generation == req.mount_generation
                        && claim.key.sequence == req.event_sequence
                });
                if !matches {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                self.device_action_claim = None;
                reply(STATUS_SUCCESS, current_generation)
            }
            device_action_transfer::ACK => {
                if req.value_offset != 0
                    || chunk_capacity != 0
                    || req.mount_generation == 0
                    || req.event_sequence == 0
                    || req.transfer_token == 0
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let claim_matches = self.device_action_claim.as_ref().is_some_and(|claim| {
                    claim.token == req.transfer_token
                        && claim.key.mount_generation == req.mount_generation
                        && claim.key.sequence == req.event_sequence
                        && claim.complete
                });
                if !claim_matches {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let head_matches = self.device_action_journal.peek().is_some_and(|event| {
                    event.mount_generation == req.mount_generation
                        && event.sequence == req.event_sequence
                });
                if !head_matches {
                    return reply(STATUS_REVISION_MISMATCH, current_generation);
                }
                if let Err(error) = self.device_action_journal.acknowledge(req.event_sequence) {
                    return reply(device_action_journal_status(error), current_generation);
                }
                self.device_action_claim = None;
                reply_with_info(
                    STATUS_SUCCESS,
                    u32::from(self.device_action_journal.pending_len() != 0),
                    current_generation,
                    req.event_sequence,
                )
            }
            _ => reply(STATUS_INVALID_PARAMETER, current_generation),
        }
    }

    fn op_query_pnp(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmPnpQueryRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmPnpQueryRequest>();
        let instance_len = req.instance_len_bytes as usize;
        let auxiliary_len = req.auxiliary_len_bytes as usize;
        let Some(auxiliary_offset) = header_size.checked_add(instance_len) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let Some(total_len) = auxiliary_offset.checked_add(auxiliary_len) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || req._reserved != 0
            || instance_len > CM_MAX_INSTANCE_UNITS * 2
            || instance_len % 2 != 0
            || auxiliary_len > CM_MAX_PNP_AUX_BYTES
            || req.instance_offset as usize != header_size
            || req.auxiliary_offset as usize != auxiliary_offset
            || buf.len() != total_len
            || req.chunk_capacity as usize > CM_LAUNCH_PLAN_CHUNK_BYTES
            || req.chunk_capacity as usize > out_buf.len()
            || !matches!(
                req.query_kind,
                pnp_query_kind::DEVICE_EXISTS
                    | pnp_query_kind::ENUMERATE_DEVNODE
                    | pnp_query_kind::INTERFACE_LINKS
                    | pnp_query_kind::DYNAMIC_PROPERTY
                    | pnp_query_kind::RELATED_DEVICE
                    | pnp_query_kind::DEVICE_DEPTH
                    | pnp_query_kind::BUS_RELATIONS
                    | pnp_query_kind::CRITICAL_DEVICE_BINDING
            )
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let instance = if instance_len == 0 {
            String::new()
        } else {
            let Some(instance) = decode(buf, req.instance_offset, req.instance_len_bytes) else {
                return reply(STATUS_INVALID_PARAMETER, 0);
            };
            if instance.is_empty() || instance.chars().any(|ch| ch == '\0') {
                return reply(STATUS_INVALID_PARAMETER, 0);
            }
            instance
        };
        let Some(auxiliary) = request_slice(buf, req.auxiliary_offset, req.auxiliary_len_bytes)
        else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let shape_valid = match req.query_kind {
            pnp_query_kind::ENUMERATE_DEVNODE => instance.is_empty() && auxiliary.is_empty(),
            pnp_query_kind::INTERFACE_LINKS => {
                !instance.is_empty() && req.selector == 0 && auxiliary.len() == 16
            }
            pnp_query_kind::DYNAMIC_PROPERTY | pnp_query_kind::RELATED_DEVICE => {
                !instance.is_empty() && auxiliary.is_empty()
            }
            pnp_query_kind::DEVICE_EXISTS
            | pnp_query_kind::DEVICE_DEPTH
            | pnp_query_kind::BUS_RELATIONS
            | pnp_query_kind::CRITICAL_DEVICE_BINDING => {
                !instance.is_empty() && req.selector == 0 && auxiliary.is_empty()
            }
            _ => false,
        };
        if !shape_valid {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }

        match req.operation {
            pnp_query_transfer::BEGIN => {
                if req.transfer_token != 0 || req.value_offset != 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(generation) = self.system_hive.as_ref().map(|mounted| mounted.generation)
                else {
                    return reply(STATUS_DEVICE_NOT_READY, 0);
                };
                self.cm.refresh_registry_devnodes();
                let (strings, payload) = match req.query_kind {
                    pnp_query_kind::DEVICE_EXISTS => {
                        if !self.cm.pnp_device_exists(&instance) {
                            return reply(STATUS_NO_SUCH_DEVICE, 0);
                        }
                        (Vec::new(), Vec::new())
                    }
                    pnp_query_kind::ENUMERATE_DEVNODE => {
                        let Some(devnode) = self.cm.devnodes().get(req.selector as usize) else {
                            return reply(STATUS_NO_MORE_ENTRIES, 0);
                        };
                        (alloc::vec![devnode.instance_id.clone()], Vec::new())
                    }
                    pnp_query_kind::INTERFACE_LINKS => {
                        let Ok(guid) = <&[u8; 16]>::try_from(auxiliary) else {
                            return reply(STATUS_INVALID_PARAMETER, 0);
                        };
                        let Some(links) = self
                            .cm
                            .pnp_enabled_interface_links_by_guid_bytes(guid, &instance)
                        else {
                            return reply(STATUS_NO_SUCH_DEVICE, 0);
                        };
                        (links, Vec::new())
                    }
                    pnp_query_kind::DYNAMIC_PROPERTY => {
                        if !self.cm.pnp_device_exists(&instance) {
                            return reply(STATUS_NO_SUCH_DEVICE, 0);
                        }
                        let Some(payload) =
                            self.cm.pnp_dynamic_property_bytes(&instance, req.selector)
                        else {
                            return reply(STATUS_OBJECT_NAME_NOT_FOUND, 0);
                        };
                        (Vec::new(), payload)
                    }
                    pnp_query_kind::RELATED_DEVICE => {
                        let Some(related) = self.cm.pnp_related_device(&instance, req.selector)
                        else {
                            return reply(STATUS_NO_SUCH_DEVICE, 0);
                        };
                        (alloc::vec![related], Vec::new())
                    }
                    pnp_query_kind::DEVICE_DEPTH => {
                        let Some(depth) = self.cm.pnp_device_depth(&instance) else {
                            return reply(STATUS_NO_SUCH_DEVICE, 0);
                        };
                        (Vec::new(), depth.to_le_bytes().to_vec())
                    }
                    pnp_query_kind::BUS_RELATIONS => {
                        let Some(relations) = self.cm.pnp_bus_relation_instances(&instance) else {
                            return reply(STATUS_NO_SUCH_DEVICE, 0);
                        };
                        (relations, Vec::new())
                    }
                    pnp_query_kind::CRITICAL_DEVICE_BINDING => {
                        let binding = match self.cm.resolve_critical_device_id(&instance) {
                            Ok(Some(binding)) => binding,
                            Ok(None) => return reply(STATUS_OBJECT_NAME_NOT_FOUND, 0),
                            Err(error) => return reply(critical_device_binding_status(error), 0),
                        };
                        let mut strings = alloc::vec![binding.matched_id, binding.class_guid];
                        if let Some(service_name) = binding.service_name {
                            strings.push(service_name);
                        }
                        (strings, Vec::new())
                    }
                    _ => return reply(STATUS_INVALID_PARAMETER, 0),
                };
                let Some(value) =
                    encode_pnp_query_snapshot(generation, req.query_kind, &strings, &payload)
                else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                let Some(chunk) = self.pnp_query_snapshots.begin(
                    PnpQuerySnapshotKey {
                        query_kind: req.query_kind,
                        selector: req.selector,
                        instance,
                        auxiliary: auxiliary.to_vec(),
                    },
                    value,
                    req.chunk_capacity as usize,
                    out_buf,
                ) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                snapshot_reply(chunk)
            }
            pnp_query_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(chunk) = self.pnp_query_snapshots.pull(
                    req.transfer_token,
                    req.value_offset as usize,
                    req.chunk_capacity as usize,
                    out_buf,
                    |key| {
                        key.query_kind == req.query_kind
                            && key.selector == req.selector
                            && key.instance == instance
                            && key.auxiliary == auxiliary
                    },
                ) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                snapshot_reply(chunk)
            }
            pnp_query_transfer::ABORT => {
                if req.transfer_token == 0
                    || req.value_offset != 0
                    || req.chunk_capacity != 0
                    || !self.pnp_query_snapshots.abort(req.transfer_token, |key| {
                        key.query_kind == req.query_kind
                            && key.selector == req.selector
                            && key.instance == instance
                            && key.auxiliary == auxiliary
                    })
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                reply(STATUS_SUCCESS, 0)
            }
            _ => reply(STATUS_INVALID_PARAMETER, 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use nt_config_abi::{
        device_property_transfer, driver_service_transfer, CmDevicePropertyRequest,
        CmDriverServiceRequest, CM_ABI_VERSION,
    };
    use nt_config_manager::{
        encode_sz, PropertyValue, ENUM_PATH, SERVICES_PATH, SERVICE_DEMAND_START,
    };
    use nt_hive_core::{encode_image, Hive, HiveKind};

    const INSTANCE: &str = r"PCI\VEN_8086&DEV_100E\0001";

    fn request(instance: &str, property: u32, output_capacity: u32) -> Vec<u8> {
        let instance_bytes = utf16(instance);
        request_with_bytes(&instance_bytes, property, output_capacity)
    }

    fn utf16(value: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn key_request(path: &str, flags: u16) -> Vec<u8> {
        let path_bytes = utf16(path);
        let header_size = core::mem::size_of::<CmKeyRequest>();
        let header = CmKeyRequest {
            abi_size: header_size as u16,
            flags,
            path_offset: header_size as u32,
            path_len_bytes: path_bytes.len() as u32,
        };
        let mut bytes = Vec::from(header.as_bytes());
        bytes.extend_from_slice(&path_bytes);
        bytes
    }

    fn request_with_bytes(instance_bytes: &[u8], property: u32, output_capacity: u32) -> Vec<u8> {
        request_bank(
            instance_bytes,
            property,
            output_capacity,
            device_property_transfer::BEGIN,
            0,
            0,
            core::cmp::min(output_capacity, CM_DEVICE_PROPERTY_CHUNK_BYTES as u32),
        )
    }

    fn request_bank(
        instance_bytes: &[u8],
        property: u32,
        output_capacity: u32,
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
    ) -> Vec<u8> {
        let header_size = core::mem::size_of::<CmDevicePropertyRequest>();
        let header = CmDevicePropertyRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            _reserved: 0,
            property,
            output_capacity,
            value_offset,
            chunk_capacity,
            instance_offset: header_size as u32,
            instance_len_bytes: instance_bytes.len() as u32,
            transfer_token,
        };
        let mut bytes = Vec::from(header.as_bytes());
        bytes.extend_from_slice(instance_bytes);
        bytes
    }

    fn driver_request(
        service: &str,
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
    ) -> Vec<u8> {
        let service_bytes = utf16(service);
        let header_size = core::mem::size_of::<CmDriverServiceRequest>();
        let header = CmDriverServiceRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            _reserved: 0,
            value_offset,
            chunk_capacity,
            service_offset: header_size as u32,
            service_len_bytes: service_bytes.len() as u32,
            transfer_token,
        };
        let mut bytes = Vec::from(header.as_bytes());
        bytes.extend_from_slice(&service_bytes);
        bytes
    }

    fn hive_import_request(
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        total_len_bytes: u32,
        chunk: &[u8],
    ) -> Vec<u8> {
        let header_size = core::mem::size_of::<CmHiveImportRequest>();
        let header = CmHiveImportRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            mount: hive_mount::SYSTEM,
            value_offset,
            chunk_offset: if chunk.is_empty() {
                0
            } else {
                header_size as u32
            },
            chunk_len_bytes: chunk.len() as u32,
            total_len_bytes,
            transfer_token,
        };
        let mut bytes = Vec::from(header.as_bytes());
        bytes.extend_from_slice(chunk);
        bytes
    }

    fn hive_key_request(
        path: &str,
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
    ) -> Vec<u8> {
        let path_bytes = utf16(path);
        let header_size = core::mem::size_of::<CmHiveKeyRequest>();
        let header = CmHiveKeyRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            mount: hive_mount::SYSTEM,
            value_offset,
            chunk_capacity,
            path_offset: header_size as u32,
            path_len_bytes: path_bytes.len() as u32,
            transfer_token,
        };
        let mut bytes = Vec::from(header.as_bytes());
        bytes.extend_from_slice(&path_bytes);
        bytes
    }

    fn hive_checkpoint_request(
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
        expected_generation: u64,
    ) -> Vec<u8> {
        let header = CmHiveCheckpointRequest {
            abi_size: core::mem::size_of::<CmHiveCheckpointRequest>() as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            mount: hive_mount::SYSTEM,
            value_offset,
            chunk_capacity,
            expected_generation,
            transfer_token,
        };
        Vec::from(header.as_bytes())
    }

    fn begin_hive_import(server: &mut CmServer, image: &[u8]) -> u64 {
        let response = server.dispatch(
            opcode::CM_OP_IMPORT_HIVE,
            &hive_import_request(hive_import_transfer::BEGIN, 0, 0, image.len() as u32, &[]),
            &mut [],
        );
        assert_eq!(response.status, STATUS_SUCCESS);
        assert_ne!(response.detail1, 0);
        response.detail1
    }

    fn push_hive_import(server: &mut CmServer, token: u64, image: &[u8]) {
        let mut offset = 0usize;
        while offset < image.len() {
            let end = core::cmp::min(offset + CM_HIVE_IMPORT_CHUNK_BYTES, image.len());
            let response = server.dispatch(
                opcode::CM_OP_IMPORT_HIVE,
                &hive_import_request(
                    hive_import_transfer::PUSH,
                    token,
                    offset as u32,
                    image.len() as u32,
                    &image[offset..end],
                ),
                &mut [],
            );
            assert_eq!(response.status, STATUS_SUCCESS);
            assert_eq!(response.detail0, end as u64);
            offset = end;
        }
    }

    fn commit_hive_import(server: &mut CmServer, token: u64, image: &[u8]) -> u64 {
        let response = server.dispatch(
            opcode::CM_OP_IMPORT_HIVE,
            &hive_import_request(
                hive_import_transfer::COMMIT,
                token,
                image.len() as u32,
                image.len() as u32,
                &[],
            ),
            &mut [],
        );
        assert_eq!(response.status, STATUS_SUCCESS);
        assert_eq!(response.detail1, token);
        response.detail0
    }

    fn publish_hive(server: &mut CmServer, image: &[u8]) -> u64 {
        let token = begin_hive_import(server, image);
        push_hive_import(server, token, image);
        commit_hive_import(server, token, image)
    }

    fn device_action_request(
        operation: u16,
        mount_generation: u64,
        event_sequence: u64,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
    ) -> CmDeviceActionRequest {
        CmDeviceActionRequest {
            abi_size: core::mem::size_of::<CmDeviceActionRequest>() as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            _reserved: 0,
            value_offset,
            chunk_capacity,
            mount_generation,
            event_sequence,
            transfer_token,
        }
    }

    fn publish_test_device_action(server: &mut CmServer) {
        let instance_path =
            String::from(r"\Registry\Machine\System\ControlSet001\Enum\ROOT\CLAIM\0000");
        let mutations = [
            HiveMutation::CreateKey {
                path: instance_path.clone(),
            },
            HiveMutation::SetValue {
                path: instance_path,
                name: String::from("PdoName"),
                value_type: RegistryValueType::Sz as u32,
                data: encode_sz(r"\Device\ClaimPdo0"),
            },
            HiveMutation::PublishDeviceAction {
                kind: device_action_kind::ARRIVAL,
                instance_id: String::from(r"ROOT\CLAIM\0000"),
            },
        ];
        assert_eq!(server.commit_system_hive_mutations(&mutations, 2), Ok(true));
    }

    fn selected_system_hive(number: u32) -> Hive {
        let mut hive = Hive::new(HiveKind::System);
        let select = hive.create_key("Select");
        hive.set_dword(select, "Current", number);
        hive.create_key(&alloc::format!("ControlSet{number:03}"));
        hive
    }

    fn server() -> CmServer {
        let mut cm = ConfigManager::new();
        let key = cm
            .registry_mut()
            .create_key(&alloc::format!(r"{}\{}", ENUM_PATH, INSTANCE));
        cm.registry_mut()
            .set_string(key, "PdoName", r"\Device\NTPNP_PCI0001");
        cm.registry_mut()
            .set_string(key, "FriendlyName", "Intel Test Adapter");
        CmServer::with_config(cm)
    }

    #[test]
    fn create_key_preserves_volatile_option_and_disposition() {
        let path = r"\Registry\Machine\Hardware\ACPI\DSDT";
        let request = key_request(path, key_flags::VOLATILE);
        let mut server = server();
        let created = server.dispatch(opcode::CM_OP_CREATE_KEY, &request, &mut []);
        assert_eq!(created.status, STATUS_SUCCESS);
        assert_eq!(created.detail1, 1);
        assert!(server.cm.registry().is_volatile(created.detail0));

        let opened = server.dispatch(opcode::CM_OP_CREATE_KEY, &request, &mut []);
        assert_eq!(opened.status, STATUS_SUCCESS);
        assert_eq!(opened.detail0, created.detail0);
        assert_eq!(opened.detail1, 0);
        assert!(server.cm.registry().is_volatile(opened.detail0));
    }

    #[test]
    fn device_property_query_is_semantic_and_capacity_bounded() {
        let expected = encode_sz("Intel Test Adapter");
        let success_request = request(
            &INSTANCE.to_ascii_lowercase(),
            device_property::FRIENDLY_NAME,
            expected.len() as u32,
        );
        let mut out = vec![0xa5; 4096];
        let response = server().dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &success_request,
            &mut out,
        );
        assert_eq!(response.status, STATUS_SUCCESS);
        assert_eq!(response.information as usize, expected.len());
        assert_eq!(response.detail0 as usize, expected.len());
        assert_eq!(response.detail1, 0);
        assert_eq!(&out[..expected.len()], expected.as_slice());

        let small_request = request(INSTANCE, device_property::FRIENDLY_NAME, 2);
        let mut out = vec![0xa5; 4096];
        let response = server().dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &small_request,
            &mut out,
        );
        assert_eq!(response.status, STATUS_BUFFER_TOO_SMALL);
        assert_eq!(response.information, 0);
        assert_eq!(response.detail0 as usize, expected.len());
        assert!(out.iter().all(|byte| *byte == 0xa5));

        let framed_request = request(INSTANCE, device_property::FRIENDLY_NAME, 4096);
        let mut out = [0xa5; 2];
        let response = server().dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &framed_request,
            &mut out,
        );
        assert_eq!(response.status, STATUS_INVALID_PARAMETER);
        assert_eq!(response.information, 0);
        assert_eq!(out, [0xa5; 2]);
    }

    #[test]
    fn device_action_claim_is_exclusive_completed_and_restart_distinct() {
        let image = encode_image(&selected_system_hive(1));
        let mut server = CmServer::new();
        assert_eq!(publish_hive(&mut server, &image), 1);
        publish_test_device_action(&mut server);

        let mut first = [0u8; CM_DEVICE_ACTION_SNAPSHOT_HEADER_BYTES];
        let begin = server.dispatch(
            opcode::CM_OP_DEVICE_ACTION,
            device_action_request(
                device_action_transfer::BEGIN,
                0,
                0,
                0,
                0,
                first.len() as u32,
            )
            .as_bytes(),
            &mut first,
        );
        assert_eq!(begin.status, STATUS_SUCCESS);
        assert_ne!(begin.detail1, 0);
        assert!(begin.detail0 as usize > first.len());

        let competing = server.dispatch(
            opcode::CM_OP_DEVICE_ACTION,
            device_action_request(device_action_transfer::BEGIN, 0, 0, 0, 0, 32).as_bytes(),
            &mut [0u8; 32],
        );
        assert_eq!(competing.status, STATUS_DEVICE_BUSY);

        let wrong_abort = server.dispatch(
            opcode::CM_OP_DEVICE_ACTION,
            device_action_request(device_action_transfer::ABORT, 2, 2, begin.detail1, 0, 0)
                .as_bytes(),
            &mut [],
        );
        assert_eq!(wrong_abort.status, STATUS_INVALID_PARAMETER);
        let abort = server.dispatch(
            opcode::CM_OP_DEVICE_ACTION,
            device_action_request(device_action_transfer::ABORT, 2, 1, begin.detail1, 0, 0)
                .as_bytes(),
            &mut [],
        );
        assert_eq!(abort.status, STATUS_SUCCESS);

        let begin = server.dispatch(
            opcode::CM_OP_DEVICE_ACTION,
            device_action_request(device_action_transfer::BEGIN, 0, 0, 0, 0, 32).as_bytes(),
            &mut [0u8; 32],
        );
        assert_eq!(begin.status, STATUS_SUCCESS);
        let premature_ack = server.dispatch(
            opcode::CM_OP_DEVICE_ACTION,
            device_action_request(device_action_transfer::ACK, 2, 1, begin.detail1, 0, 0)
                .as_bytes(),
            &mut [],
        );
        assert_eq!(premature_ack.status, STATUS_INVALID_PARAMETER);

        let total = begin.detail0 as usize;
        let mut tail = vec![0u8; total - 32];
        let pull = server.dispatch(
            opcode::CM_OP_DEVICE_ACTION,
            device_action_request(
                device_action_transfer::PULL,
                2,
                1,
                begin.detail1,
                32,
                tail.len() as u32,
            )
            .as_bytes(),
            &mut tail,
        );
        assert_eq!(pull.status, STATUS_SUCCESS);
        assert_eq!(pull.information as usize, tail.len());
        let ack = server.dispatch(
            opcode::CM_OP_DEVICE_ACTION,
            device_action_request(device_action_transfer::ACK, 2, 1, begin.detail1, 0, 0)
                .as_bytes(),
            &mut [],
        );
        assert_eq!(ack.status, STATUS_SUCCESS);
        assert_eq!(ack.information, 0);

        let mut replacement = CmServer::new();
        assert_eq!(publish_hive(&mut replacement, &image), 1);
        publish_test_device_action(&mut replacement);
        let replacement_begin = replacement.dispatch(
            opcode::CM_OP_DEVICE_ACTION,
            device_action_request(device_action_transfer::BEGIN, 0, 0, 0, 0, 4096).as_bytes(),
            &mut [0u8; 4096],
        );
        assert_eq!(replacement_begin.status, STATUS_SUCCESS);
        assert_ne!(replacement_begin.detail1, begin.detail1);
        let stale_ack = replacement.dispatch(
            opcode::CM_OP_DEVICE_ACTION,
            device_action_request(device_action_transfer::ACK, 2, 1, begin.detail1, 0, 0)
                .as_bytes(),
            &mut [],
        );
        assert_eq!(stale_ack.status, STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn device_property_query_distinguishes_policy_and_absence() {
        let mut out = [0u8; 128];
        let response = server().dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &request(INSTANCE, device_property::BUS_NUMBER, out.len() as u32),
            &mut out,
        );
        assert_eq!(response.status, STATUS_NOT_SUPPORTED);

        let response = server().dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &request(INSTANCE, 23, out.len() as u32),
            &mut out,
        );
        assert_eq!(response.status, STATUS_INVALID_PARAMETER);

        let response = server().dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &request(
                r"PCI\VEN_1234&DEV_5678\MISSING",
                device_property::FRIENDLY_NAME,
                out.len() as u32,
            ),
            &mut out,
        );
        assert_eq!(response.status, STATUS_OBJECT_NAME_NOT_FOUND);

        let response = server().dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &request(INSTANCE, device_property::CLASS_NAME, out.len() as u32),
            &mut out,
        );
        assert_eq!(response.status, STATUS_OBJECT_NAME_NOT_FOUND);
    }

    #[test]
    fn device_property_query_rejects_malformed_envelopes() {
        let mut out = [0u8; 128];
        assert_eq!(
            server()
                .dispatch(opcode::CM_OP_QUERY_DEVICE_PROPERTY, &[0; 19], &mut out)
                .status,
            STATUS_INVALID_PARAMETER
        );

        let valid = request(INSTANCE, device_property::FRIENDLY_NAME, out.len() as u32);
        for mutate in [
            |header: &mut CmDevicePropertyRequest| header.abi_size -= 1,
            |header: &mut CmDevicePropertyRequest| header.abi_version += 1,
            |header: &mut CmDevicePropertyRequest| header.instance_offset += 2,
            |header: &mut CmDevicePropertyRequest| header.instance_len_bytes -= 1,
        ] {
            let mut malformed = valid.clone();
            let mut header = CmDevicePropertyRequest::from_bytes(&malformed).unwrap();
            mutate(&mut header);
            malformed[..core::mem::size_of::<CmDevicePropertyRequest>()]
                .copy_from_slice(header.as_bytes());
            assert_eq!(
                server()
                    .dispatch(opcode::CM_OP_QUERY_DEVICE_PROPERTY, &malformed, &mut out)
                    .status,
                STATUS_INVALID_PARAMETER
            );
        }

        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(
            server()
                .dispatch(opcode::CM_OP_QUERY_DEVICE_PROPERTY, &trailing, &mut out)
                .status,
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            server()
                .dispatch(
                    opcode::CM_OP_QUERY_DEVICE_PROPERTY,
                    &request_with_bytes(&[0, 0], device_property::FRIENDLY_NAME, 128),
                    &mut out,
                )
                .status,
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            server()
                .dispatch(
                    opcode::CM_OP_QUERY_DEVICE_PROPERTY,
                    &request_with_bytes(&[0, 0xd8], device_property::FRIENDLY_NAME, 128),
                    &mut out,
                )
                .status,
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            server()
                .dispatch(
                    opcode::CM_OP_QUERY_DEVICE_PROPERTY,
                    &request_with_bytes(
                        &vec![b'A'; CM_MAX_INSTANCE_UNITS * 2 + 2],
                        device_property::FRIENDLY_NAME,
                        128,
                    ),
                    &mut out,
                )
                .status,
            STATUS_INVALID_PARAMETER
        );

        for mutate in [
            |header: &mut CmDevicePropertyRequest| header._reserved = 1,
            |header: &mut CmDevicePropertyRequest| header.operation = 0,
            |header: &mut CmDevicePropertyRequest| header.transfer_token = 1,
            |header: &mut CmDevicePropertyRequest| header.value_offset = 1,
            |header: &mut CmDevicePropertyRequest| {
                header.chunk_capacity = CM_DEVICE_PROPERTY_CHUNK_BYTES as u32 + 1
            },
        ] {
            let mut malformed = valid.clone();
            let mut header = CmDevicePropertyRequest::from_bytes(&malformed).unwrap();
            mutate(&mut header);
            malformed[..core::mem::size_of::<CmDevicePropertyRequest>()]
                .copy_from_slice(header.as_bytes());
            assert_eq!(
                server()
                    .dispatch(opcode::CM_OP_QUERY_DEVICE_PROPERTY, &malformed, &mut out)
                    .status,
                STATUS_INVALID_PARAMETER
            );
        }
    }

    #[test]
    fn device_property_banks_are_one_immutable_snapshot() {
        let mut server = server();
        let original = "A".repeat(3000);
        let replacement = "B".repeat(3000);
        let key = server
            .config_mut()
            .registry_mut()
            .create_key(&alloc::format!(r"{}\{}", ENUM_PATH, INSTANCE));
        server
            .config_mut()
            .registry_mut()
            .set_string(key, "FriendlyName", &original);
        let expected = encode_sz(&original);
        let instance_bytes = utf16(INSTANCE);
        let mut first = [0xa5; CM_DEVICE_PROPERTY_CHUNK_BYTES];
        let begin = server.dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &request_bank(
                &instance_bytes,
                device_property::FRIENDLY_NAME,
                expected.len() as u32,
                device_property_transfer::BEGIN,
                0,
                0,
                CM_DEVICE_PROPERTY_CHUNK_BYTES as u32,
            ),
            &mut first,
        );
        assert_eq!(begin.status, STATUS_SUCCESS);
        assert_ne!(begin.detail1, 0);
        assert_eq!(begin.information as usize, first.len());

        server
            .config_mut()
            .registry_mut()
            .set_string(key, "FriendlyName", &replacement);
        let tail_len = expected.len() - first.len();
        let mut tail = vec![0xa5; tail_len];
        let pull = server.dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &request_bank(
                &instance_bytes,
                device_property::FRIENDLY_NAME,
                expected.len() as u32,
                device_property_transfer::PULL,
                begin.detail1,
                first.len() as u32,
                tail_len as u32,
            ),
            &mut tail,
        );
        assert_eq!(pull.status, STATUS_SUCCESS);
        assert_eq!(pull.detail1, begin.detail1);
        let mut assembled = Vec::from(first);
        assembled.extend_from_slice(&tail);
        assert_eq!(assembled, expected);

        let stale = server.dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &request_bank(
                &instance_bytes,
                device_property::FRIENDLY_NAME,
                expected.len() as u32,
                device_property_transfer::PULL,
                begin.detail1,
                expected.len() as u32,
                1,
            ),
            &mut [0u8; 1],
        );
        assert_eq!(stale.status, STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn driver_service_banks_are_one_live_immutable_snapshot() {
        let mut cm = ConfigManager::new();
        cm.register_service(
            "Pending",
            r"system32\drivers\pending.sys",
            None,
            None,
            SERVICE_DEMAND_START,
            1,
        );
        for index in 0..72 {
            let instance = alloc::format!(r"ROOT\PENDING\{index:04}");
            let hardware = alloc::format!(r"ROOT\PENDING_{index:04}_{}", "H".repeat(64));
            cm.register_devnode(&instance, Some("Pending"), None, &[hardware.as_str()], &[]);
        }
        let mut server = CmServer::with_config(cm);
        let expected_binding = server
            .config_mut()
            .driver_service_binding("Pending")
            .unwrap();
        let expected = encode_driver_service_binding(server.config(), &expected_binding).unwrap();
        assert!(expected.len() > CM_DRIVER_SERVICE_CHUNK_BYTES);

        let mut first = [0xa5; CM_DRIVER_SERVICE_CHUNK_BYTES];
        let begin = server.dispatch(
            opcode::CM_OP_QUERY_DRIVER_SERVICE,
            &driver_request(
                "pending",
                driver_service_transfer::BEGIN,
                0,
                0,
                CM_DRIVER_SERVICE_CHUNK_BYTES as u32,
            ),
            &mut first,
        );
        assert_eq!(begin.status, STATUS_SUCCESS);
        assert_eq!(begin.detail0 as usize, expected.len());
        assert_ne!(begin.detail1, 0);

        let service_key = server
            .config()
            .registry()
            .open_key(&alloc::format!(r"{}\Pending", SERVICES_PATH))
            .unwrap();
        server.config_mut().registry_mut().set_string(
            service_key,
            "ImagePath",
            r"system32\drivers\replacement.sys",
        );

        let mut assembled = Vec::from(first);
        assembled.truncate(begin.information as usize);
        while assembled.len() < expected.len() {
            let remaining = expected.len() - assembled.len();
            let bank_len = core::cmp::min(remaining, CM_DRIVER_SERVICE_CHUNK_BYTES);
            let mut bank = vec![0xa5; bank_len];
            let pull = server.dispatch(
                opcode::CM_OP_QUERY_DRIVER_SERVICE,
                &driver_request(
                    "Pending",
                    driver_service_transfer::PULL,
                    begin.detail1,
                    assembled.len() as u32,
                    bank_len as u32,
                ),
                &mut bank,
            );
            assert_eq!(pull.status, STATUS_SUCCESS);
            assembled.extend_from_slice(&bank[..pull.information as usize]);
        }
        assert_eq!(assembled, expected);
        assert_eq!(
            server
                .config_mut()
                .driver_service_binding("Pending")
                .unwrap()
                .service
                .image_path,
            r"system32\drivers\replacement.sys"
        );
    }

    #[test]
    fn hive_import_tokens_are_independent_and_abort_exactly_one_upload() {
        let mut first = selected_system_hive(1);
        first.create_key(r"ControlSet001\Services\First");
        first.finish_clean_import();
        let first = encode_image(&first);
        let mut second = selected_system_hive(1);
        second.create_key(r"ControlSet001\Services\Second");
        second.finish_clean_import();
        let second = encode_image(&second);

        let mut server = CmServer::new();
        let first_token = begin_hive_import(&mut server, &first);
        let second_token = begin_hive_import(&mut server, &second);
        assert_ne!(first_token, second_token);
        push_hive_import(&mut server, second_token, &second);
        push_hive_import(&mut server, first_token, &first);
        assert_eq!(commit_hive_import(&mut server, first_token, &first), 1);
        let abort = server.dispatch(
            opcode::CM_OP_IMPORT_HIVE,
            &hive_import_request(
                hive_import_transfer::ABORT,
                second_token,
                0,
                second.len() as u32,
                &[],
            ),
            &mut [],
        );
        assert_eq!(abort.status, STATUS_SUCCESS);
        assert_eq!(server.hive_imports.len(), 0);
        assert!(server
            .system_hive
            .as_ref()
            .unwrap()
            .hive
            .open_key(r"ControlSet001\Services\First")
            .is_some());
        assert!(server
            .system_hive
            .as_ref()
            .unwrap()
            .hive
            .open_key(r"ControlSet001\Services\Second")
            .is_none());
    }

    #[test]
    fn prepared_system_mutation_blocks_mount_replacement() {
        let first = encode_image(&selected_system_hive(1));
        let second = encode_image(&selected_system_hive(2));
        let mut server = CmServer::new();
        assert_eq!(publish_hive(&mut server, &first), 1);

        server.prepared_system_mutation = Some(PreparedSystemHiveMutation {
            token: 1,
            expected_generation: 1,
            next_generation: 2,
            semantic_journal_len: 0,
            mutations: Vec::new(),
            durable_journal: Vec::new(),
        });
        let begin = server.dispatch(
            opcode::CM_OP_IMPORT_HIVE,
            &hive_import_request(hive_import_transfer::BEGIN, 0, 0, second.len() as u32, &[]),
            &mut [],
        );
        assert_eq!(begin.status, STATUS_DEVICE_BUSY);
        server.prepared_system_mutation = None;

        let token = begin_hive_import(&mut server, &second);
        push_hive_import(&mut server, token, &second);
        server.prepared_system_mutation = Some(PreparedSystemHiveMutation {
            token: 2,
            expected_generation: 1,
            next_generation: 2,
            semantic_journal_len: 0,
            mutations: Vec::new(),
            durable_journal: Vec::new(),
        });
        let commit = server.dispatch(
            opcode::CM_OP_IMPORT_HIVE,
            &hive_import_request(
                hive_import_transfer::COMMIT,
                token,
                second.len() as u32,
                second.len() as u32,
                &[],
            ),
            &mut [],
        );
        assert_eq!(commit.status, STATUS_DEVICE_BUSY);
        assert_eq!(server.system_hive.as_ref().unwrap().generation, 1);
        assert_eq!(server.hive_imports.len(), 1);

        server.prepared_system_mutation = None;
        assert_eq!(commit_hive_import(&mut server, token, &second), 2);
    }

    #[test]
    fn system_checkpoint_is_single_flight_and_acknowledges_exact_image() {
        let mut hive = selected_system_hive(1);
        let key = hive.create_key(r"ControlSet001\Services\Checkpointed");
        assert!(hive.set_value(
            key,
            "Payload",
            RegistryValueType::Binary,
            vec![0x5a; CM_HIVE_CHECKPOINT_CHUNK_BYTES + 73],
        ));
        hive.finish_clean_import();
        let mut server = CmServer::new();
        assert_eq!(publish_hive(&mut server, &encode_image(&hive)), 1);
        let mutations = [HiveMutation::SetValue {
            path: String::from(r"\Registry\Machine\System\CurrentControlSet\Services\Checkpointed"),
            name: String::from("Start"),
            value_type: RegistryValueType::Dword as u32,
            data: 2u32.to_le_bytes().to_vec(),
        }];
        assert_eq!(
            server.commit_system_hive_mutations(&mutations, 2),
            Ok(false)
        );

        let mut first = [0u8; 257];
        let begin = server.dispatch(
            opcode::CM_OP_CHECKPOINT_SYSTEM_HIVE,
            &hive_checkpoint_request(hive_checkpoint_transfer::BEGIN, 0, 0, first.len() as u32, 2),
            &mut first,
        );
        assert_eq!(begin.status, STATUS_SUCCESS);
        assert_ne!(begin.detail1, 0);
        assert!(begin.detail0 as usize > CM_HIVE_CHECKPOINT_CHUNK_BYTES);

        let replacement = encode_image(&selected_system_hive(2));
        let blocked_import = server.dispatch(
            opcode::CM_OP_IMPORT_HIVE,
            &hive_import_request(
                hive_import_transfer::BEGIN,
                0,
                0,
                replacement.len() as u32,
                &[],
            ),
            &mut [],
        );
        assert_eq!(blocked_import.status, STATUS_DEVICE_BUSY);
        let blocked_mutation = CmHiveMutationRequest {
            abi_size: core::mem::size_of::<CmHiveMutationRequest>() as u16,
            abi_version: CM_ABI_VERSION,
            operation: hive_mutation_transfer::BEGIN,
            mount: hive_mount::SYSTEM,
            journal_offset: 0,
            chunk_offset: 0,
            chunk_len_bytes: 0,
            journal_len_bytes: 1,
            expected_generation: 2,
            lease_token: 0,
        };
        assert_eq!(
            server
                .dispatch(
                    opcode::CM_OP_MUTATE_SYSTEM_HIVE,
                    blocked_mutation.as_bytes(),
                    &mut [],
                )
                .status,
            STATUS_DEVICE_BUSY
        );

        let premature_ack = server.dispatch(
            opcode::CM_OP_CHECKPOINT_SYSTEM_HIVE,
            &hive_checkpoint_request(
                hive_checkpoint_transfer::ACK,
                begin.detail1,
                begin.information,
                0,
                2,
            ),
            &mut [],
        );
        assert_eq!(premature_ack.status, STATUS_INVALID_PARAMETER);
        assert!(server.system_hive.as_ref().unwrap().hive.dirty_count() > 0);

        let mut value = Vec::from(&first[..begin.information as usize]);
        while value.len() < begin.detail0 as usize {
            let capacity = core::cmp::min(
                CM_HIVE_CHECKPOINT_CHUNK_BYTES,
                begin.detail0 as usize - value.len(),
            );
            let mut chunk = vec![0u8; capacity];
            let pull = server.dispatch(
                opcode::CM_OP_CHECKPOINT_SYSTEM_HIVE,
                &hive_checkpoint_request(
                    hive_checkpoint_transfer::PULL,
                    begin.detail1,
                    value.len() as u32,
                    capacity as u32,
                    2,
                ),
                &mut chunk,
            );
            assert_eq!(pull.status, STATUS_SUCCESS);
            value.extend_from_slice(&chunk[..pull.information as usize]);
        }
        let header = CmHiveCheckpointHeader::from_bytes(&value).unwrap();
        assert_eq!(header.magic, CM_HIVE_CHECKPOINT_MAGIC);
        assert_eq!(header.mount_generation, 2);
        assert_eq!(
            header.image_len_bytes as usize,
            value.len() - header.header_size as usize
        );
        let checkpoint_hive = decode_image(&value[header.header_size as usize..]).unwrap();
        assert_eq!(checkpoint_hive.sequence, header.hive_sequence);
        assert_eq!(checkpoint_hive.generation, header.image_generation);
        let key = checkpoint_hive
            .open_key(r"ControlSet001\Services\Checkpointed")
            .unwrap();
        assert_eq!(checkpoint_hive.query_dword(key, "Start"), Some(2));

        let ack = server.dispatch(
            opcode::CM_OP_CHECKPOINT_SYSTEM_HIVE,
            &hive_checkpoint_request(
                hive_checkpoint_transfer::ACK,
                begin.detail1,
                value.len() as u32,
                0,
                2,
            ),
            &mut [],
        );
        assert_eq!(ack.status, STATUS_SUCCESS);
        let mounted = server.system_hive.as_ref().unwrap();
        assert_eq!(mounted.generation, 2);
        assert_eq!(mounted.hive.generation, header.image_generation);
        assert_eq!(mounted.hive.dirty_count(), 0);
    }

    #[test]
    fn mounted_system_hive_uses_its_selected_control_set_for_keys_and_semantics() {
        let mut hive = selected_system_hive(2);
        let inactive = hive.create_key(r"ControlSet001\Services\Inactive");
        hive.set_value(
            inactive,
            "ImagePath",
            RegistryValueType::ExpandSz,
            encode_sz(r"system32\drivers\inactive.sys"),
        );
        hive.set_dword(inactive, "Type", 1);
        hive.set_dword(inactive, "Start", SERVICE_DEMAND_START);
        let active = hive.create_key(r"ControlSet002\Services\Active");
        hive.set_value(
            active,
            "ImagePath",
            RegistryValueType::ExpandSz,
            encode_sz(r"system32\drivers\active.sys"),
        );
        hive.set_dword(active, "Type", 1);
        hive.set_dword(active, "Start", SERVICE_DEMAND_START);
        hive.finish_clean_import();

        let mut server = CmServer::new();
        assert_eq!(publish_hive(&mut server, &encode_image(&hive)), 1);
        let mounted = server.system_hive.as_ref().unwrap();
        assert_eq!(mounted.current_control_set.as_str(), "ControlSet002");
        assert!(server.config().service_metadata("Active").is_some());
        assert!(server.config().service_metadata("Inactive").is_none());

        let mut current_out = vec![0u8; CM_HIVE_KEY_CHUNK_BYTES];
        let current = server.dispatch(
            opcode::CM_OP_QUERY_HIVE_KEY,
            &hive_key_request(
                r"\Registry\Machine\System\CurrentControlSet\Services\Active",
                hive_key_transfer::BEGIN,
                0,
                0,
                CM_HIVE_KEY_CHUNK_BYTES as u32,
            ),
            &mut current_out,
        );
        assert_eq!(current.status, STATUS_SUCCESS);
        let mut explicit_out = vec![0u8; CM_HIVE_KEY_CHUNK_BYTES];
        let explicit = server.dispatch(
            opcode::CM_OP_QUERY_HIVE_KEY,
            &hive_key_request(
                r"\Registry\Machine\System\ControlSet002\Services\Active",
                hive_key_transfer::BEGIN,
                0,
                0,
                CM_HIVE_KEY_CHUNK_BYTES as u32,
            ),
            &mut explicit_out,
        );
        assert_eq!(explicit.status, STATUS_SUCCESS);
        let missing = server.dispatch(
            opcode::CM_OP_QUERY_HIVE_KEY,
            &hive_key_request(
                r"\Registry\Machine\System\CurrentControlSet\Services\Inactive",
                hive_key_transfer::BEGIN,
                0,
                0,
                CM_HIVE_KEY_CHUNK_BYTES as u32,
            ),
            &mut current_out,
        );
        assert_eq!(missing.status, STATUS_OBJECT_NAME_NOT_FOUND);
    }

    #[test]
    fn invalid_control_set_import_preserves_the_live_mount_generation() {
        let mut stable = selected_system_hive(1);
        stable.create_key(r"ControlSet001\Services\Stable");
        stable.finish_clean_import();
        let stable_image = encode_image(&stable);
        let mut server = CmServer::new();
        assert_eq!(publish_hive(&mut server, &stable_image), 1);

        let mut invalid = Hive::new(HiveKind::System);
        invalid.create_key(r"ControlSet001\Services\Replacement");
        invalid.finish_clean_import();
        let invalid_image = encode_image(&invalid);
        let token = begin_hive_import(&mut server, &invalid_image);
        push_hive_import(&mut server, token, &invalid_image);
        let response = server.dispatch(
            opcode::CM_OP_IMPORT_HIVE,
            &hive_import_request(
                hive_import_transfer::COMMIT,
                token,
                invalid_image.len() as u32,
                invalid_image.len() as u32,
                &[],
            ),
            &mut [],
        );
        assert_eq!(response.status, STATUS_REGISTRY_CORRUPT);
        let mounted = server.system_hive.as_ref().unwrap();
        assert_eq!(mounted.generation, 1);
        assert_eq!(mounted.current_control_set.as_str(), "ControlSet001");
        assert!(mounted
            .hive
            .open_key(r"ControlSet001\Services\Stable")
            .is_some());
        assert!(mounted
            .hive
            .open_key(r"ControlSet001\Services\Replacement")
            .is_none());
        assert_eq!(server.hive_imports.len(), 1);
    }

    #[test]
    fn hive_key_snapshot_survives_atomic_mount_replacement() {
        let path = r"\Registry\Machine\System\CurrentControlSet\Services\Stable";
        let mut first = selected_system_hive(1);
        let key = first.create_key(r"ControlSet001\Services\Stable");
        assert!(first.set_value(
            key,
            "Payload",
            nt_hive_core::RegistryValueType::Binary,
            vec![0x11; 9_000],
        ));
        first.finish_clean_import();
        let first_image = encode_image(&first);
        let mut second = selected_system_hive(2);
        let key = second.create_key(r"ControlSet002\Services\Stable");
        assert!(second.set_value(
            key,
            "Payload",
            nt_hive_core::RegistryValueType::Binary,
            vec![0x22; 9_000],
        ));
        second.finish_clean_import();
        let second_image = encode_image(&second);

        let mut server = CmServer::new();
        assert_eq!(publish_hive(&mut server, &first_image), 1);
        let mounted = server.system_hive.as_ref().unwrap();
        let expected = encode_hive_key_snapshot(
            &mounted.hive,
            mounted.generation,
            &mounted.current_control_set,
            path,
        )
        .expect("snapshot");
        let mut first_bank = [0u8; 64];
        let begin = server.dispatch(
            opcode::CM_OP_QUERY_HIVE_KEY,
            &hive_key_request(path, hive_key_transfer::BEGIN, 0, 0, 64),
            &mut first_bank,
        );
        assert_eq!(begin.status, STATUS_SUCCESS);
        assert_ne!(begin.detail1, 0);
        assert_eq!(publish_hive(&mut server, &second_image), 2);

        let mut assembled = Vec::from(&first_bank[..begin.information as usize]);
        while assembled.len() < expected.len() {
            let bank_len = core::cmp::min(64, expected.len() - assembled.len());
            let mut bank = vec![0u8; bank_len];
            let pull = server.dispatch(
                opcode::CM_OP_QUERY_HIVE_KEY,
                &hive_key_request(
                    path,
                    hive_key_transfer::PULL,
                    begin.detail1,
                    assembled.len() as u32,
                    bank_len as u32,
                ),
                &mut bank,
            );
            assert_eq!(pull.status, STATUS_SUCCESS);
            assembled.extend_from_slice(&bank[..pull.information as usize]);
        }
        assert_eq!(assembled, expected);
        let mounted = server.system_hive.as_ref().unwrap();
        assert_eq!(mounted.generation, 2);
        assert_eq!(mounted.current_control_set.as_str(), "ControlSet002");
    }

    #[test]
    fn hive_key_snapshot_admission_preserves_existing_readers() {
        let path = r"\Registry\Machine\System\CurrentControlSet\Services\Stable";
        let mut hive = selected_system_hive(1);
        let key = hive.create_key(r"ControlSet001\Services\Stable");
        assert!(hive.set_value(
            key,
            "Payload",
            nt_hive_core::RegistryValueType::Binary,
            vec![0x5a; CM_HIVE_KEY_CHUNK_BYTES + 1],
        ));
        hive.finish_clean_import();

        let mut server = CmServer::new();
        assert_eq!(publish_hive(&mut server, &encode_image(&hive)), 1);
        let mut tokens = Vec::new();
        for _ in 0..MAX_OUTSTANDING_HIVE_KEY_SNAPSHOTS {
            let mut out = [0u8; 64];
            let begin = server.dispatch(
                opcode::CM_OP_QUERY_HIVE_KEY,
                &hive_key_request(path, hive_key_transfer::BEGIN, 0, 0, 64),
                &mut out,
            );
            assert_eq!(begin.status, STATUS_SUCCESS);
            assert_ne!(begin.detail1, 0);
            tokens.push(begin.detail1);
        }

        let rejected = server.dispatch(
            opcode::CM_OP_QUERY_HIVE_KEY,
            &hive_key_request(path, hive_key_transfer::BEGIN, 0, 0, 64),
            &mut [0u8; 64],
        );
        assert_eq!(rejected.status, STATUS_INSUFFICIENT_RESOURCES);

        let first = tokens[0];
        let pulled = server.dispatch(
            opcode::CM_OP_QUERY_HIVE_KEY,
            &hive_key_request(path, hive_key_transfer::PULL, first, 64, 64),
            &mut [0u8; 64],
        );
        assert_eq!(pulled.status, STATUS_SUCCESS);
        assert_eq!(pulled.detail1, first);
    }

    #[test]
    fn semantic_system_paths_follow_only_the_selected_imported_subtrees() {
        let hive = selected_system_hive(2);
        let current_control_set = hive.current_control_set().unwrap();
        assert_eq!(
            semantic_system_registry_path(
                r"\Registry\Machine\System\CurrentControlSet\Services\Live",
                &current_control_set,
            )
            .unwrap(),
            Some((
                String::from(r"\Registry\Machine\System\CurrentControlSet\Services\Live"),
                false,
            ))
        );
        assert_eq!(
            semantic_system_registry_path(
                r"\Registry\Machine\System\ControlSet002\Enum\ROOT\LIVE\0000",
                &current_control_set,
            )
            .unwrap(),
            Some((
                String::from(r"\Registry\Machine\System\CurrentControlSet\Enum\ROOT\LIVE\0000"),
                true,
            ))
        );
        assert_eq!(
            semantic_system_registry_path(
                r"\Registry\Machine\System\ControlSet001\Services\Inactive",
                &current_control_set,
            )
            .unwrap(),
            None
        );
        assert_eq!(
            semantic_system_registry_path(
                r"\Registry\Machine\System\CurrentControlSet\Control\Print",
                &current_control_set,
            )
            .unwrap(),
            None
        );
        assert_eq!(
            semantic_system_registry_path(
                r"\Registry\Machine\System\CurrentControlSet\Setup",
                &current_control_set,
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn system_mutation_commit_preserves_live_pnp_state_and_updates_semantics() {
        let mut hive = selected_system_hive(1);
        let enum_key = hive.create_key(&alloc::format!(r"ControlSet001\Enum\{INSTANCE}"));
        assert!(hive.set_value(
            enum_key,
            "PdoName",
            RegistryValueType::Sz,
            encode_sz(r"\Device\NTPNP_PCI0001"),
        ));
        hive.finish_clean_import();

        let mut server = CmServer::new();
        assert_eq!(publish_hive(&mut server, &encode_image(&hive)), 1);
        let devnode = server.config().devnode(INSTANCE).unwrap().id;
        assert!(server.config_mut().set_legacy_property(
            devnode,
            device_property::FRIENDLY_NAME,
            PropertyValue::string("runtime property"),
        ));
        let interface = server
            .config_mut()
            .register_interface(
                devnode,
                "{4D36E972-E325-11CE-BFC1-08002BE10318}",
                "runtime",
                true,
            )
            .unwrap();
        let interface_link = server
            .config()
            .interface(interface)
            .unwrap()
            .symbolic_link
            .clone();

        let service_path =
            String::from(r"\Registry\Machine\System\CurrentControlSet\Services\RuntimeSvc");
        let enum_path =
            alloc::format!(r"\Registry\Machine\System\CurrentControlSet\Enum\{INSTANCE}");
        let mutations = vec![
            HiveMutation::CreateKey {
                path: service_path.clone(),
            },
            HiveMutation::SetValue {
                path: service_path.clone(),
                name: String::from("ImagePath"),
                value_type: RegistryValueType::ExpandSz as u32,
                data: encode_sz(r"system32\drivers\runtime.sys"),
            },
            HiveMutation::SetValue {
                path: service_path.clone(),
                name: String::from("Type"),
                value_type: RegistryValueType::Dword as u32,
                data: 1u32.to_le_bytes().to_vec(),
            },
            HiveMutation::SetValue {
                path: service_path,
                name: String::from("Start"),
                value_type: RegistryValueType::Dword as u32,
                data: SERVICE_DEMAND_START.to_le_bytes().to_vec(),
            },
            HiveMutation::SetValue {
                path: enum_path,
                name: String::from("FriendlyName"),
                value_type: RegistryValueType::Sz as u32,
                data: encode_sz("updated by transaction"),
            },
            HiveMutation::CreateKey {
                path: String::from(
                    r"\Registry\Machine\System\CurrentControlSet\Control\Print\IgnoredByCm",
                ),
            },
        ];
        assert_eq!(
            server.commit_system_hive_mutations(&mutations, 2),
            Ok(false)
        );

        let mounted = server.system_hive.as_ref().unwrap();
        assert_eq!(mounted.generation, 2);
        assert!(mounted
            .hive
            .open_key(r"ControlSet001\Control\Print\IgnoredByCm")
            .is_some());
        assert!(server
            .config()
            .registry()
            .open_key(r"\Registry\Machine\System\CurrentControlSet\Control\Print\IgnoredByCm")
            .is_none());
        assert_eq!(
            server
                .config()
                .service_metadata("RuntimeSvc")
                .unwrap()
                .image_path
                .as_deref(),
            Some(r"system32\drivers\runtime.sys")
        );
        let refreshed = server.config().devnode(INSTANCE).unwrap();
        assert_eq!(refreshed.id, devnode);
        assert_eq!(
            server
                .config()
                .query_legacy_property(devnode, device_property::FRIENDLY_NAME)
                .unwrap()
                .as_string()
                .as_deref(),
            Some("runtime property")
        );
        assert_eq!(
            server.config().interface(interface).unwrap().symbolic_link,
            interface_link
        );
    }
}
