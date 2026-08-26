//! Transport-agnostic NT Configuration Manager (registry) service dispatcher.
//!
//! Decodes a wire request ([`nt_config_abi`]) and drives the `nt-config-manager`
//! core, returning a [`CmReply`]. Wrapping the registry authority behind SURT lets
//! it run as an isolated service the executive/PnP/SCM reach over rings. The current
//! ABI exposes path-addressed keys, DWORD and raw typed values, and semantic devnode
//! property queries.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use nt_config_abi::{
    device_property_transfer, driver_service_class, driver_service_transfer, hive_import_transfer,
    hive_key_transfer, hive_mount, launch_plan_kind, launch_plan_transfer, opcode, pnp_query_kind,
    pnp_query_transfer, read_utf16, win32_service_plan_kind, win32_service_process_kind,
    CmDevicePropertyRequest, CmDriverServiceRequest, CmEnumerateKeyRequest, CmHiveImportRequest,
    CmHiveKeyRequest, CmKeyRequest, CmLaunchPlanRequest, CmPnpQueryRequest, CmRawValueRequest,
    CmReply, CmValueRequest, CM_ABI_VERSION, CM_DEVICE_PROPERTY_CHUNK_BYTES,
    CM_DRIVER_SERVICE_CHUNK_BYTES, CM_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES,
    CM_DRIVER_SERVICE_SNAPSHOT_MAGIC, CM_DRIVER_SERVICE_SNAPSHOT_VERSION,
    CM_HIVE_IMPORT_CHUNK_BYTES, CM_HIVE_KEY_CHUNK_BYTES, CM_HIVE_KEY_SNAPSHOT_HEADER_BYTES,
    CM_HIVE_KEY_SNAPSHOT_MAGIC, CM_HIVE_KEY_SNAPSHOT_VERSION, CM_LAUNCH_PLAN_CHUNK_BYTES,
    CM_LAUNCH_PLAN_SNAPSHOT_HEADER_BYTES, CM_LAUNCH_PLAN_SNAPSHOT_MAGIC,
    CM_LAUNCH_PLAN_SNAPSHOT_VERSION, CM_MAX_HIVE_PATH_UNITS, CM_MAX_INSTANCE_UNITS,
    CM_MAX_PNP_AUX_BYTES, CM_MAX_SERVICE_UNITS, CM_OPTIONAL_BLOB_ABSENT, CM_OPTIONAL_STRING_ABSENT,
    CM_OPTIONAL_U32_ABSENT, CM_PNP_QUERY_SNAPSHOT_HEADER_BYTES, CM_PNP_QUERY_SNAPSHOT_MAGIC,
    CM_PNP_QUERY_SNAPSHOT_VERSION, CM_WIN32_SERVICE_PLAN_SNAPSHOT_HEADER_BYTES,
    CM_WIN32_SERVICE_PLAN_SNAPSHOT_MAGIC, CM_WIN32_SERVICE_PLAN_SNAPSHOT_VERSION,
};
use nt_config_manager::{
    device_property, ConfigManager, DevicePropertySource, DriverServiceBinding, DriverServiceClass,
    RegistryValueType, Win32ServiceProcessKind, Win32ServiceProcessLaunch, SERVICE_BOOT_START,
    SERVICE_DEMAND_START, SERVICE_SYSTEM_START,
};
use nt_hive_core::{decode_image, CurrentControlSet, Hive, HiveKind};

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;
const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001Au32 as i32;
const STATUS_NO_SUCH_DEVICE: i32 = 0xC000_000Eu32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;
const STATUS_DEVICE_NOT_READY: i32 = 0xC000_00A3u32 as i32;
const STATUS_INVALID_SYSTEM_SERVICE: i32 = 0xC000_001Cu32 as i32;
const STATUS_NOT_SUPPORTED: i32 = 0xC000_00BBu32 as i32;
const STATUS_REGISTRY_CORRUPT: i32 = 0xC000_014Cu32 as i32;

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

fn encode_hive_key_snapshot(
    hive: &Hive,
    mount_generation: u64,
    current_control_set: &CurrentControlSet,
    path: &str,
) -> Option<Vec<u8>> {
    let relative = system_hive_relative_path(path, current_control_set)?;
    let key = hive.open_key(&relative)?;
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

struct DevicePropertySnapshot {
    token: u64,
    instance: String,
    property: u32,
    output_capacity: u32,
    value: Vec<u8>,
    offset: usize,
}

struct DriverServiceSnapshot {
    token: u64,
    service: String,
    value: Vec<u8>,
    offset: usize,
}

struct HiveImport {
    token: u64,
    mount: u16,
    total_len: usize,
    value: Vec<u8>,
}

struct HiveKeySnapshot {
    token: u64,
    mount: u16,
    path: String,
    value: Vec<u8>,
    offset: usize,
}

struct DriverLaunchPlanSnapshot {
    token: u64,
    plan_kind: u16,
    value: Vec<u8>,
    offset: usize,
}

struct Win32ServiceLaunchPlanSnapshot {
    token: u64,
    plan_kind: u16,
    value: Vec<u8>,
    offset: usize,
}

struct PnpQuerySnapshot {
    token: u64,
    query_kind: u16,
    selector: u32,
    instance: String,
    auxiliary: Vec<u8>,
    value: Vec<u8>,
    offset: usize,
}

struct MountedSystemHive {
    hive: Hive,
    generation: u64,
    current_control_set: CurrentControlSet,
}

/// The Configuration Manager service: the registry authority + the wire dispatcher.
pub struct CmServer {
    cm: ConfigManager,
    device_property_snapshot: Option<DevicePropertySnapshot>,
    next_device_property_token: u64,
    driver_service_snapshot: Option<DriverServiceSnapshot>,
    next_driver_service_token: u64,
    system_hive: Option<MountedSystemHive>,
    hive_imports: Vec<HiveImport>,
    next_hive_import_token: u64,
    hive_key_snapshots: Vec<HiveKeySnapshot>,
    next_hive_key_token: u64,
    driver_launch_plan_snapshot: Option<DriverLaunchPlanSnapshot>,
    next_driver_launch_plan_token: u64,
    win32_service_launch_plan_snapshot: Option<Win32ServiceLaunchPlanSnapshot>,
    next_win32_service_launch_plan_token: u64,
    pnp_query_snapshot: Option<PnpQuerySnapshot>,
    next_pnp_query_token: u64,
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
            device_property_snapshot: None,
            next_device_property_token: 1,
            driver_service_snapshot: None,
            next_driver_service_token: 1,
            system_hive: None,
            hive_imports: Vec::new(),
            next_hive_import_token: 1,
            hive_key_snapshots: Vec::new(),
            next_hive_key_token: 1,
            driver_launch_plan_snapshot: None,
            next_driver_launch_plan_token: 1,
            win32_service_launch_plan_snapshot: None,
            next_win32_service_launch_plan_token: 1,
            pnp_query_snapshot: None,
            next_pnp_query_token: 1,
        }
    }

    /// Build a server around an already-seeded Configuration Manager.
    pub fn with_config(cm: ConfigManager) -> Self {
        Self {
            cm,
            device_property_snapshot: None,
            next_device_property_token: 1,
            driver_service_snapshot: None,
            next_driver_service_token: 1,
            system_hive: None,
            hive_imports: Vec::new(),
            next_hive_import_token: 1,
            hive_key_snapshots: Vec::new(),
            next_hive_key_token: 1,
            driver_launch_plan_snapshot: None,
            next_driver_launch_plan_token: 1,
            win32_service_launch_plan_snapshot: None,
            next_win32_service_launch_plan_token: 1,
            pnp_query_snapshot: None,
            next_pnp_query_token: 1,
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
            opcode::CM_OP_QUERY_HIVE_KEY => self.op_query_hive_key(in_buf, out_buf),
            opcode::CM_OP_QUERY_LAUNCH_PLAN => self.op_query_launch_plan(in_buf, out_buf),
            opcode::CM_OP_QUERY_WIN32_SERVICE_PLAN => {
                self.op_query_win32_service_plan(in_buf, out_buf)
            }
            opcode::CM_OP_QUERY_PNP => self.op_query_pnp(in_buf, out_buf),
            _ => reply(STATUS_INVALID_SYSTEM_SERVICE, 0),
        }
    }

    fn op_create_key(&mut self, buf: &[u8]) -> CmReply {
        let Some(req) = CmKeyRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let Some(path) = decode(buf, req.path_offset, req.path_len_bytes) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let key = self.cm.registry_mut().create_key(&path);
        reply(STATUS_SUCCESS, key)
    }

    fn op_open_key(&mut self, buf: &[u8]) -> CmReply {
        let Some(req) = CmKeyRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
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
                self.device_property_snapshot = None;
                if req.output_capacity < needed_u32 {
                    return reply_with_info(STATUS_BUFFER_TOO_SMALL, 0, needed as u64, 0);
                }
                let written = core::cmp::min(needed, chunk_capacity);
                out_buf[..written].copy_from_slice(&value[..written]);
                if written == needed {
                    return reply_with_info(STATUS_SUCCESS, written as u32, needed as u64, 0);
                }
                let token = self.next_device_property_token;
                if token == 0 {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                }
                self.next_device_property_token = token.checked_add(1).unwrap_or(0);
                self.device_property_snapshot = Some(DevicePropertySnapshot {
                    token,
                    instance,
                    property: req.property,
                    output_capacity: req.output_capacity,
                    value,
                    offset: written,
                });
                reply_with_info(STATUS_SUCCESS, written as u32, needed as u64, token)
            }
            device_property_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(snapshot) = self.device_property_snapshot.as_mut() else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                if snapshot.token != req.transfer_token
                    || snapshot.instance != instance
                    || snapshot.property != req.property
                    || snapshot.output_capacity != req.output_capacity
                    || snapshot.offset != req.value_offset as usize
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let needed = snapshot.value.len();
                let written = core::cmp::min(needed - snapshot.offset, chunk_capacity);
                let end = snapshot.offset + written;
                out_buf[..written].copy_from_slice(&snapshot.value[snapshot.offset..end]);
                snapshot.offset = end;
                if end == needed {
                    self.device_property_snapshot = None;
                }
                reply_with_info(
                    STATUS_SUCCESS,
                    written as u32,
                    needed as u64,
                    req.transfer_token,
                )
            }
            device_property_transfer::ABORT => {
                if req.transfer_token == 0
                    || req.value_offset != 0
                    || req.chunk_capacity != 0
                    || self
                        .device_property_snapshot
                        .as_ref()
                        .is_none_or(|snapshot| {
                            snapshot.token != req.transfer_token
                                || snapshot.instance != instance
                                || snapshot.property != req.property
                                || snapshot.output_capacity != req.output_capacity
                        })
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                self.device_property_snapshot = None;
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
                self.driver_service_snapshot = None;
                let written = core::cmp::min(needed, chunk_capacity);
                out_buf[..written].copy_from_slice(&value[..written]);
                if written == needed {
                    return reply_with_info(STATUS_SUCCESS, written as u32, needed as u64, 0);
                }
                let token = self.next_driver_service_token;
                if token == 0 {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                }
                self.next_driver_service_token = token.checked_add(1).unwrap_or(0);
                self.driver_service_snapshot = Some(DriverServiceSnapshot {
                    token,
                    service,
                    value,
                    offset: written,
                });
                reply_with_info(STATUS_SUCCESS, written as u32, needed_u32 as u64, token)
            }
            driver_service_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(snapshot) = self.driver_service_snapshot.as_mut() else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                if snapshot.token != req.transfer_token
                    || !snapshot.service.eq_ignore_ascii_case(&service)
                    || snapshot.offset != req.value_offset as usize
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let needed = snapshot.value.len();
                let written = core::cmp::min(needed - snapshot.offset, chunk_capacity);
                let end = snapshot.offset + written;
                out_buf[..written].copy_from_slice(&snapshot.value[snapshot.offset..end]);
                snapshot.offset = end;
                if end == needed {
                    self.driver_service_snapshot = None;
                }
                reply_with_info(
                    STATUS_SUCCESS,
                    written as u32,
                    needed as u64,
                    req.transfer_token,
                )
            }
            driver_service_transfer::ABORT => {
                if req.transfer_token == 0
                    || req.value_offset != 0
                    || req.chunk_capacity != 0
                    || self
                        .driver_service_snapshot
                        .as_ref()
                        .is_none_or(|snapshot| {
                            snapshot.token != req.transfer_token
                                || !snapshot.service.eq_ignore_ascii_case(&service)
                        })
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                self.driver_service_snapshot = None;
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
                let cm = config_manager_from_system_hive(&hive, &current_control_set);
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
                let needed = value.len();
                let written = core::cmp::min(needed, req.chunk_capacity as usize);
                out_buf[..written].copy_from_slice(&value[..written]);
                if written == needed {
                    return reply_with_info(STATUS_SUCCESS, written as u32, needed as u64, 0);
                }
                let token = self.next_hive_key_token;
                let Some(next_token) = token.checked_add(1) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                if token == 0 || self.hive_key_snapshots.try_reserve(1).is_err() {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                }
                self.next_hive_key_token = next_token;
                self.hive_key_snapshots.push(HiveKeySnapshot {
                    token,
                    mount: req.mount,
                    path,
                    value,
                    offset: written,
                });
                reply_with_info(STATUS_SUCCESS, written as u32, needed as u64, token)
            }
            hive_key_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(index) = self.hive_key_snapshots.iter().position(|snapshot| {
                    snapshot.token == req.transfer_token
                        && snapshot.mount == req.mount
                        && snapshot.path.eq_ignore_ascii_case(&path)
                        && snapshot.offset == req.value_offset as usize
                }) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                let snapshot = &mut self.hive_key_snapshots[index];
                let needed = snapshot.value.len();
                let written = core::cmp::min(needed - snapshot.offset, req.chunk_capacity as usize);
                let end = snapshot.offset + written;
                out_buf[..written].copy_from_slice(&snapshot.value[snapshot.offset..end]);
                snapshot.offset = end;
                if end == needed {
                    self.hive_key_snapshots.swap_remove(index);
                }
                reply_with_info(
                    STATUS_SUCCESS,
                    written as u32,
                    needed as u64,
                    req.transfer_token,
                )
            }
            hive_key_transfer::ABORT => {
                if req.transfer_token == 0 || req.value_offset != 0 || req.chunk_capacity != 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(index) = self.hive_key_snapshots.iter().position(|snapshot| {
                    snapshot.token == req.transfer_token
                        && snapshot.mount == req.mount
                        && snapshot.path.eq_ignore_ascii_case(&path)
                }) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                self.hive_key_snapshots.swap_remove(index);
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
                let needed = value.len();
                let written = core::cmp::min(needed, req.chunk_capacity as usize);
                out_buf[..written].copy_from_slice(&value[..written]);
                self.driver_launch_plan_snapshot = None;
                if written == needed {
                    return reply_with_info(STATUS_SUCCESS, written as u32, needed as u64, 0);
                }
                let token = self.next_driver_launch_plan_token;
                let Some(next_token) = token.checked_add(1) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                if token == 0 {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                }
                self.next_driver_launch_plan_token = next_token;
                self.driver_launch_plan_snapshot = Some(DriverLaunchPlanSnapshot {
                    token,
                    plan_kind: req.plan_kind,
                    value,
                    offset: written,
                });
                reply_with_info(STATUS_SUCCESS, written as u32, needed as u64, token)
            }
            launch_plan_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(snapshot) = self.driver_launch_plan_snapshot.as_mut() else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                if snapshot.token != req.transfer_token
                    || snapshot.plan_kind != req.plan_kind
                    || snapshot.offset != req.value_offset as usize
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let needed = snapshot.value.len();
                let written = core::cmp::min(needed - snapshot.offset, req.chunk_capacity as usize);
                let end = snapshot.offset + written;
                out_buf[..written].copy_from_slice(&snapshot.value[snapshot.offset..end]);
                snapshot.offset = end;
                if end == needed {
                    self.driver_launch_plan_snapshot = None;
                }
                reply_with_info(
                    STATUS_SUCCESS,
                    written as u32,
                    needed as u64,
                    req.transfer_token,
                )
            }
            launch_plan_transfer::ABORT => {
                if req.transfer_token == 0
                    || req.value_offset != 0
                    || req.chunk_capacity != 0
                    || self
                        .driver_launch_plan_snapshot
                        .as_ref()
                        .is_none_or(|snapshot| {
                            snapshot.token != req.transfer_token
                                || snapshot.plan_kind != req.plan_kind
                        })
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                self.driver_launch_plan_snapshot = None;
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
                let needed = value.len();
                let written = core::cmp::min(needed, req.chunk_capacity as usize);
                out_buf[..written].copy_from_slice(&value[..written]);
                self.win32_service_launch_plan_snapshot = None;
                if written == needed {
                    return reply_with_info(STATUS_SUCCESS, written as u32, needed as u64, 0);
                }
                let token = self.next_win32_service_launch_plan_token;
                let Some(next_token) = token.checked_add(1) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                if token == 0 {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                }
                self.next_win32_service_launch_plan_token = next_token;
                self.win32_service_launch_plan_snapshot = Some(Win32ServiceLaunchPlanSnapshot {
                    token,
                    plan_kind: req.plan_kind,
                    value,
                    offset: written,
                });
                reply_with_info(STATUS_SUCCESS, written as u32, needed as u64, token)
            }
            launch_plan_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(snapshot) = self.win32_service_launch_plan_snapshot.as_mut() else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                if snapshot.token != req.transfer_token
                    || snapshot.plan_kind != req.plan_kind
                    || snapshot.offset != req.value_offset as usize
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let needed = snapshot.value.len();
                let written = core::cmp::min(needed - snapshot.offset, req.chunk_capacity as usize);
                let end = snapshot.offset + written;
                out_buf[..written].copy_from_slice(&snapshot.value[snapshot.offset..end]);
                snapshot.offset = end;
                if end == needed {
                    self.win32_service_launch_plan_snapshot = None;
                }
                reply_with_info(
                    STATUS_SUCCESS,
                    written as u32,
                    needed as u64,
                    req.transfer_token,
                )
            }
            launch_plan_transfer::ABORT => {
                if req.transfer_token == 0
                    || req.value_offset != 0
                    || req.chunk_capacity != 0
                    || self
                        .win32_service_launch_plan_snapshot
                        .as_ref()
                        .is_none_or(|snapshot| {
                            snapshot.token != req.transfer_token
                                || snapshot.plan_kind != req.plan_kind
                        })
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                self.win32_service_launch_plan_snapshot = None;
                reply(STATUS_SUCCESS, 0)
            }
            _ => reply(STATUS_INVALID_PARAMETER, 0),
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
            | pnp_query_kind::BUS_RELATIONS => {
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
                    _ => return reply(STATUS_INVALID_PARAMETER, 0),
                };
                let Some(value) =
                    encode_pnp_query_snapshot(generation, req.query_kind, &strings, &payload)
                else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                let needed = value.len();
                let written = core::cmp::min(needed, req.chunk_capacity as usize);
                out_buf[..written].copy_from_slice(&value[..written]);
                self.pnp_query_snapshot = None;
                if written == needed {
                    return reply_with_info(STATUS_SUCCESS, written as u32, needed as u64, 0);
                }
                let token = self.next_pnp_query_token;
                let Some(next_token) = token.checked_add(1) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                };
                if token == 0 {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                }
                self.next_pnp_query_token = next_token;
                self.pnp_query_snapshot = Some(PnpQuerySnapshot {
                    token,
                    query_kind: req.query_kind,
                    selector: req.selector,
                    instance,
                    auxiliary: auxiliary.to_vec(),
                    value,
                    offset: written,
                });
                reply_with_info(STATUS_SUCCESS, written as u32, needed as u64, token)
            }
            pnp_query_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(snapshot) = self.pnp_query_snapshot.as_mut() else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                if snapshot.token != req.transfer_token
                    || snapshot.query_kind != req.query_kind
                    || snapshot.selector != req.selector
                    || snapshot.instance != instance
                    || snapshot.auxiliary != auxiliary
                    || snapshot.offset != req.value_offset as usize
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let needed = snapshot.value.len();
                let written = core::cmp::min(needed - snapshot.offset, req.chunk_capacity as usize);
                let end = snapshot.offset + written;
                out_buf[..written].copy_from_slice(&snapshot.value[snapshot.offset..end]);
                snapshot.offset = end;
                if end == needed {
                    self.pnp_query_snapshot = None;
                }
                reply_with_info(
                    STATUS_SUCCESS,
                    written as u32,
                    needed as u64,
                    req.transfer_token,
                )
            }
            pnp_query_transfer::ABORT => {
                if req.transfer_token == 0
                    || req.value_offset != 0
                    || req.chunk_capacity != 0
                    || self.pnp_query_snapshot.as_ref().is_none_or(|snapshot| {
                        snapshot.token != req.transfer_token
                            || snapshot.query_kind != req.query_kind
                            || snapshot.selector != req.selector
                            || snapshot.instance != instance
                            || snapshot.auxiliary != auxiliary
                    })
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                self.pnp_query_snapshot = None;
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
    use nt_config_manager::{encode_sz, ENUM_PATH, SERVICES_PATH, SERVICE_DEMAND_START};
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
}
