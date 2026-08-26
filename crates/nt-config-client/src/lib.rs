//! Ergonomic client for the NT Configuration Manager (registry) service ABI.
//!
//! Encodes each call into the [`nt_config_abi`] wire form, hands it to a pluggable
//! [`Backend`] (SURT rings on the kernel; in-process in tests), and decodes the
//! [`CmReply`]. Supports path-addressed keys plus DWORD and raw typed values. Mirrors
//! `nt-object-client`, with semantic devnode property queries that preserve required
//! output length across the shared-frame transport.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use nt_config_abi::{
    device_property_transfer, driver_service_class, driver_service_transfer, hive_import_transfer,
    hive_key_transfer, hive_mount, launch_plan_kind, launch_plan_transfer, opcode, pnp_query_kind,
    pnp_query_transfer, win32_service_plan_kind, win32_service_process_kind,
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

/// A pluggable transport: send `opcode` + `in_buf`, receive a `CmReply` (+ optional
/// `out_buf` for future variable-length replies).
pub trait Backend {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> CmReply;
}

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QueryError {
    pub status: i32,
    pub required_len: usize,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DriverServiceClass {
    Device,
    FileSystem,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriverServiceDevnode {
    pub instance_id: String,
    pub pdo_name: Option<String>,
    pub driver_key: Option<String>,
    pub linkage_export: Option<String>,
    pub hardware_ids: Vec<String>,
    pub compatible_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriverServiceBinding {
    pub service_name: String,
    pub image_path: String,
    pub driver_object_path: String,
    pub class_guid: Option<String>,
    pub class: DriverServiceClass,
    pub start_type: u32,
    pub error_control: Option<u32>,
    pub load_order_group: Option<String>,
    pub tag: Option<u32>,
    pub devnodes: Vec<DriverServiceDevnode>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriverLaunchPlanSnapshot {
    pub mount_generation: u64,
    pub plan_kind: u16,
    pub bindings: Vec<DriverServiceBinding>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Win32ServiceProcessKind {
    Own,
    Shared,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Win32ServiceProcessLaunch {
    pub service_name: String,
    pub executable_path: String,
    pub nt_image_path: String,
    pub command_line: String,
    pub process_kind: Win32ServiceProcessKind,
    pub interactive: bool,
    pub account_name: Option<String>,
    pub display_name: Option<String>,
    pub dependencies: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Win32ServiceLaunchPlanSnapshot {
    pub mount_generation: u64,
    pub plan_kind: u16,
    pub launches: Vec<Win32ServiceProcessLaunch>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PnpQuerySnapshot {
    pub mount_generation: u64,
    pub query_kind: u16,
    pub strings: Vec<String>,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiveSubkeySnapshot {
    pub name: String,
    pub class_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiveValueSnapshot {
    pub name: String,
    pub value_type: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiveKeySnapshot {
    pub mount_generation: u64,
    pub path: String,
    pub class_name: Option<String>,
    pub security_descriptor: Option<Vec<u8>>,
    pub subkeys: Vec<HiveSubkeySnapshot>,
    pub values: Vec<HiveValueSnapshot>,
}

struct SnapshotReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(len)?;
        let value = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(value)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn optional_u32(&mut self) -> Option<Option<u32>> {
        let value = self.u32()?;
        Some((value != CM_OPTIONAL_U32_ABSENT).then_some(value))
    }

    fn string_with_len(&mut self, len: u32) -> Option<String> {
        let bytes = self.take(usize::try_from(len).ok()?)?;
        Some(core::str::from_utf8(bytes).ok()?.into())
    }

    fn string(&mut self) -> Option<String> {
        let len = self.u32()?;
        (len != CM_OPTIONAL_STRING_ABSENT).then(|| self.string_with_len(len))?
    }

    fn optional_string(&mut self) -> Option<Option<String>> {
        let len = self.u32()?;
        if len == CM_OPTIONAL_STRING_ABSENT {
            Some(None)
        } else {
            self.string_with_len(len).map(Some)
        }
    }

    fn blob_with_len(&mut self, len: u32) -> Option<Vec<u8>> {
        Some(Vec::from(self.take(usize::try_from(len).ok()?)?))
    }

    fn blob(&mut self) -> Option<Vec<u8>> {
        let len = self.u32()?;
        (len != CM_OPTIONAL_BLOB_ABSENT).then(|| self.blob_with_len(len))?
    }

    fn optional_blob(&mut self) -> Option<Option<Vec<u8>>> {
        let len = self.u32()?;
        if len == CM_OPTIONAL_BLOB_ABSENT {
            Some(None)
        } else {
            self.blob_with_len(len).map(Some)
        }
    }

    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn decode_hive_key_snapshot(bytes: &[u8]) -> Option<HiveKeySnapshot> {
    if bytes.len() < CM_HIVE_KEY_SNAPSHOT_HEADER_BYTES {
        return None;
    }
    let mut reader = SnapshotReader::new(bytes);
    if reader.u32()? != CM_HIVE_KEY_SNAPSHOT_MAGIC
        || reader.u16()? != CM_HIVE_KEY_SNAPSHOT_VERSION
        || reader.u16()? != 0
    {
        return None;
    }
    let mount_generation = reader.u64()?;
    let subkey_count = usize::try_from(reader.u32()?).ok()?;
    let value_count = usize::try_from(reader.u32()?).ok()?;
    let path = reader.string()?;
    let class_name = reader.optional_string()?;
    let security_descriptor = reader.optional_blob()?;
    let mut subkeys = Vec::new();
    subkeys.try_reserve_exact(subkey_count).ok()?;
    for _ in 0..subkey_count {
        subkeys.push(HiveSubkeySnapshot {
            name: reader.string()?,
            class_name: reader.optional_string()?,
        });
    }
    let mut values = Vec::new();
    values.try_reserve_exact(value_count).ok()?;
    for _ in 0..value_count {
        values.push(HiveValueSnapshot {
            name: reader.string()?,
            value_type: reader.u32()?,
            data: reader.blob()?,
        });
    }
    reader.finished().then_some(HiveKeySnapshot {
        mount_generation,
        path,
        class_name,
        security_descriptor,
        subkeys,
        values,
    })
}

fn decode_driver_service_binding(bytes: &[u8]) -> Option<DriverServiceBinding> {
    if bytes.len() < CM_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES {
        return None;
    }
    let mut reader = SnapshotReader::new(bytes);
    if reader.u32()? != CM_DRIVER_SERVICE_SNAPSHOT_MAGIC
        || reader.u16()? != CM_DRIVER_SERVICE_SNAPSHOT_VERSION
    {
        return None;
    }
    let class = match reader.u16()? {
        driver_service_class::DEVICE => DriverServiceClass::Device,
        driver_service_class::FILE_SYSTEM => DriverServiceClass::FileSystem,
        _ => return None,
    };
    let start_type = reader.u32()?;
    let devnode_count = usize::try_from(reader.u32()?).ok()?;
    let service_name = reader.string()?;
    let image_path = reader.string()?;
    let driver_object_path = reader.string()?;
    let class_guid = reader.optional_string()?;
    let error_control = reader.optional_u32()?;
    let load_order_group = reader.optional_string()?;
    let tag = reader.optional_u32()?;
    let mut devnodes = Vec::new();
    devnodes.try_reserve_exact(devnode_count).ok()?;
    for _ in 0..devnode_count {
        let instance_id = reader.string()?;
        let pdo_name = reader.optional_string()?;
        let driver_key = reader.optional_string()?;
        let linkage_export = reader.optional_string()?;
        let hardware_count = usize::try_from(reader.u32()?).ok()?;
        let mut hardware_ids = Vec::new();
        hardware_ids.try_reserve_exact(hardware_count).ok()?;
        for _ in 0..hardware_count {
            hardware_ids.push(reader.string()?);
        }
        let compatible_count = usize::try_from(reader.u32()?).ok()?;
        let mut compatible_ids = Vec::new();
        compatible_ids.try_reserve_exact(compatible_count).ok()?;
        for _ in 0..compatible_count {
            compatible_ids.push(reader.string()?);
        }
        devnodes.push(DriverServiceDevnode {
            instance_id,
            pdo_name,
            driver_key,
            linkage_export,
            hardware_ids,
            compatible_ids,
        });
    }
    reader.finished().then_some(DriverServiceBinding {
        service_name,
        image_path,
        driver_object_path,
        class_guid,
        class,
        start_type,
        error_control,
        load_order_group,
        tag,
        devnodes,
    })
}

fn decode_driver_launch_plan(bytes: &[u8]) -> Option<DriverLaunchPlanSnapshot> {
    if bytes.len() < CM_LAUNCH_PLAN_SNAPSHOT_HEADER_BYTES {
        return None;
    }
    let mut reader = SnapshotReader::new(bytes);
    if reader.u32()? != CM_LAUNCH_PLAN_SNAPSHOT_MAGIC
        || reader.u16()? != CM_LAUNCH_PLAN_SNAPSHOT_VERSION
    {
        return None;
    }
    let plan_kind = reader.u16()?;
    if !matches!(
        plan_kind,
        launch_plan_kind::BOOT_SYSTEM_DRIVERS | launch_plan_kind::DEMAND_DRIVERS
    ) {
        return None;
    }
    let mount_generation = reader.u64()?;
    if mount_generation == 0 {
        return None;
    }
    let binding_count = usize::try_from(reader.u32()?).ok()?;
    if reader.u32()? != 0 {
        return None;
    }
    let mut bindings = Vec::new();
    bindings.try_reserve_exact(binding_count).ok()?;
    for _ in 0..binding_count {
        let encoded = reader.blob()?;
        bindings.push(decode_driver_service_binding(&encoded)?);
    }
    reader.finished().then_some(DriverLaunchPlanSnapshot {
        mount_generation,
        plan_kind,
        bindings,
    })
}

fn decode_win32_service_launch_plan(bytes: &[u8]) -> Option<Win32ServiceLaunchPlanSnapshot> {
    if bytes.len() < CM_WIN32_SERVICE_PLAN_SNAPSHOT_HEADER_BYTES {
        return None;
    }
    let mut reader = SnapshotReader::new(bytes);
    if reader.u32()? != CM_WIN32_SERVICE_PLAN_SNAPSHOT_MAGIC
        || reader.u16()? != CM_WIN32_SERVICE_PLAN_SNAPSHOT_VERSION
    {
        return None;
    }
    let plan_kind = reader.u16()?;
    if !matches!(
        plan_kind,
        win32_service_plan_kind::AUTO_START | win32_service_plan_kind::DEMAND_START
    ) {
        return None;
    }
    let mount_generation = reader.u64()?;
    if mount_generation == 0 {
        return None;
    }
    let launch_count = usize::try_from(reader.u32()?).ok()?;
    if reader.u32()? != 0 {
        return None;
    }
    let mut launches = Vec::new();
    launches.try_reserve_exact(launch_count).ok()?;
    for _ in 0..launch_count {
        let service_name = reader.string()?;
        let executable_path = reader.string()?;
        let nt_image_path = reader.string()?;
        let command_line = reader.string()?;
        let process_kind = match reader.u16()? {
            win32_service_process_kind::OWN => Win32ServiceProcessKind::Own,
            win32_service_process_kind::SHARED => Win32ServiceProcessKind::Shared,
            _ => return None,
        };
        let interactive = match reader.u16()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let account_name = reader.optional_string()?;
        let display_name = reader.optional_string()?;
        let dependency_count = usize::try_from(reader.u32()?).ok()?;
        let mut dependencies = Vec::new();
        dependencies.try_reserve_exact(dependency_count).ok()?;
        for _ in 0..dependency_count {
            dependencies.push(reader.string()?);
        }
        launches.push(Win32ServiceProcessLaunch {
            service_name,
            executable_path,
            nt_image_path,
            command_line,
            process_kind,
            interactive,
            account_name,
            display_name,
            dependencies,
        });
    }
    reader.finished().then_some(Win32ServiceLaunchPlanSnapshot {
        mount_generation,
        plan_kind,
        launches,
    })
}

fn decode_pnp_query_snapshot(bytes: &[u8]) -> Option<PnpQuerySnapshot> {
    if bytes.len() < CM_PNP_QUERY_SNAPSHOT_HEADER_BYTES {
        return None;
    }
    let mut reader = SnapshotReader::new(bytes);
    if reader.u32()? != CM_PNP_QUERY_SNAPSHOT_MAGIC
        || reader.u16()? != CM_PNP_QUERY_SNAPSHOT_VERSION
    {
        return None;
    }
    let query_kind = reader.u16()?;
    if !matches!(
        query_kind,
        pnp_query_kind::DEVICE_EXISTS
            | pnp_query_kind::ENUMERATE_DEVNODE
            | pnp_query_kind::INTERFACE_LINKS
            | pnp_query_kind::DYNAMIC_PROPERTY
            | pnp_query_kind::RELATED_DEVICE
            | pnp_query_kind::DEVICE_DEPTH
            | pnp_query_kind::BUS_RELATIONS
    ) {
        return None;
    }
    let mount_generation = reader.u64()?;
    if mount_generation == 0 {
        return None;
    }
    let string_count = usize::try_from(reader.u32()?).ok()?;
    let payload_bytes = usize::try_from(reader.u32()?).ok()?;
    let mut strings = Vec::new();
    strings.try_reserve_exact(string_count).ok()?;
    for _ in 0..string_count {
        strings.push(reader.string()?);
    }
    let payload = Vec::from(reader.take(payload_bytes)?);
    reader.finished().then_some(PnpQuerySnapshot {
        mount_generation,
        query_kind,
        strings,
        payload,
    })
}

fn utf16_bytes(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

/// The ergonomic Configuration Manager client.
pub struct ConfigClient<B> {
    backend: B,
}

impl<B: Backend> ConfigClient<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn ping(&mut self) -> bool {
        self.backend.call(opcode::CM_OP_PING, &[], &mut []).status == STATUS_SUCCESS
    }

    /// Create (or get) a key by full path. `Ok(key_id)`.
    pub fn create_key(&mut self, path: &str) -> Result<u64, i32> {
        let r = self.key_op(opcode::CM_OP_CREATE_KEY, path);
        if r.status == STATUS_SUCCESS {
            Ok(r.detail0)
        } else {
            Err(r.status)
        }
    }

    /// Whether a key exists at `path`.
    pub fn open_key(&mut self, path: &str) -> bool {
        self.key_op(opcode::CM_OP_OPEN_KEY, path).status == STATUS_SUCCESS
    }

    /// Enumerate an immediate subkey name by index into `out` as UTF-16LE bytes without a NUL.
    pub fn enumerate_key(&mut self, path: &str, index: u32, out: &mut [u8]) -> Result<usize, i32> {
        let r = self.enumerate_key_op(path, index, out);
        if r.status == STATUS_SUCCESS {
            Ok(r.information as usize)
        } else {
            Err(r.status)
        }
    }

    /// Set a DWORD value on a key (created if absent).
    pub fn set_dword(&mut self, key_path: &str, name: &str, value: u32) -> Result<(), i32> {
        let r = self.value_op(opcode::CM_OP_SET_DWORD, key_path, name, value);
        if r.status == STATUS_SUCCESS {
            Ok(())
        } else {
            Err(r.status)
        }
    }

    /// Query a DWORD value.
    pub fn query_dword(&mut self, key_path: &str, name: &str) -> Result<u32, i32> {
        let r = self.value_op(opcode::CM_OP_QUERY_DWORD, key_path, name, 0);
        if r.status == STATUS_SUCCESS {
            Ok(r.detail0 as u32)
        } else {
            Err(r.status)
        }
    }

    /// Set a raw typed registry value. The key is created if absent, matching `set_dword`.
    pub fn set_value(
        &mut self,
        key_path: &str,
        name: &str,
        value_type: u32,
        data: &[u8],
    ) -> Result<(), i32> {
        let r = self.raw_value_op(
            opcode::CM_OP_SET_VALUE,
            key_path,
            name,
            value_type,
            data,
            &mut [],
        );
        if r.status == STATUS_SUCCESS {
            Ok(())
        } else {
            Err(r.status)
        }
    }

    /// Query a raw typed registry value into `out`. Returns `(REG_* type, bytes_written)`.
    pub fn query_value(
        &mut self,
        key_path: &str,
        name: &str,
        out: &mut [u8],
    ) -> Result<(u32, usize), i32> {
        let r = self.raw_value_op(opcode::CM_OP_QUERY_VALUE, key_path, name, 0, &[], out);
        if r.status == STATUS_SUCCESS {
            Ok((r.detail0 as u32, r.information as usize))
        } else {
            Err(r.status)
        }
    }

    /// Query a legacy device property by stable devnode instance path. Errors retain the exact
    /// required length so native `IoGetDeviceProperty` callers can report and retry correctly.
    pub fn query_device_property(
        &mut self,
        instance: &str,
        property: u32,
        out: &mut [u8],
    ) -> Result<usize, QueryError> {
        let instance_bytes = utf16_bytes(instance);
        if instance_bytes.is_empty()
            || instance_bytes.len() > CM_MAX_INSTANCE_UNITS * 2
            || instance.chars().any(|ch| ch == '\0')
        {
            return Err(QueryError {
                status: STATUS_INVALID_PARAMETER,
                required_len: 0,
            });
        }
        let Ok(output_capacity) = u32::try_from(out.len()) else {
            return Err(QueryError {
                status: STATUS_INVALID_PARAMETER,
                required_len: 0,
            });
        };
        let mut offset = 0usize;
        let mut total = None;
        let mut token = 0u64;
        let mut staged = Vec::new();
        let mut reply_bytes = [0u8; CM_DEVICE_PROPERTY_CHUNK_BYTES];
        loop {
            let chunk_capacity = core::cmp::min(
                out.len().saturating_sub(offset),
                CM_DEVICE_PROPERTY_CHUNK_BYTES,
            );
            let operation = if token == 0 {
                device_property_transfer::BEGIN
            } else {
                device_property_transfer::PULL
            };
            let response = match self.device_property_call(
                &instance_bytes,
                property,
                output_capacity,
                operation,
                token,
                offset as u32,
                chunk_capacity as u32,
                &mut reply_bytes[..chunk_capacity],
            ) {
                Ok(response) => response,
                Err(error) => {
                    self.abort_device_property(&instance_bytes, property, output_capacity, token);
                    return Err(error);
                }
            };
            let required_len = match usize::try_from(response.detail0) {
                Ok(required_len) => required_len,
                Err(_) => {
                    self.abort_device_property(&instance_bytes, property, output_capacity, token);
                    return Err(QueryError {
                        status: STATUS_INVALID_PARAMETER,
                        required_len: 0,
                    });
                }
            };
            if response.status != STATUS_SUCCESS {
                self.abort_device_property(&instance_bytes, property, output_capacity, token);
                return Err(QueryError {
                    status: response.status,
                    required_len,
                });
            }
            let written = response.information as usize;
            let reply_token_valid = if token == 0 {
                (written == required_len && response.detail1 == 0)
                    || (written < required_len && response.detail1 != 0)
            } else {
                response.detail1 == token
            };
            if !reply_token_valid
                || total.is_some_and(|expected| expected != required_len)
                || required_len > out.len()
                || written > chunk_capacity
                || offset
                    .checked_add(written)
                    .is_none_or(|end| end > required_len)
                || (offset < required_len && written == 0)
            {
                self.abort_device_property(
                    &instance_bytes,
                    property,
                    output_capacity,
                    if token == 0 { response.detail1 } else { token },
                );
                return Err(QueryError {
                    status: STATUS_INVALID_PARAMETER,
                    required_len,
                });
            }
            if total.is_none() {
                if staged.try_reserve_exact(required_len).is_err() {
                    self.abort_device_property(
                        &instance_bytes,
                        property,
                        output_capacity,
                        response.detail1,
                    );
                    return Err(QueryError {
                        status: STATUS_INSUFFICIENT_RESOURCES,
                        required_len,
                    });
                }
                staged.resize(required_len, 0);
            }
            total = Some(required_len);
            staged[offset..offset + written].copy_from_slice(&reply_bytes[..written]);
            offset += written;
            if offset == required_len {
                out[..required_len].copy_from_slice(&staged[..required_len]);
                return Ok(required_len);
            }
            if token == 0 {
                token = response.detail1;
            }
        }
    }

    /// Resolve one driver service and every currently bound devnode from the live Configuration
    /// Manager authority. The immutable semantic snapshot is reassembled across any number of
    /// shared reply frames before it is decoded.
    pub fn query_driver_service(&mut self, service: &str) -> Result<DriverServiceBinding, i32> {
        let service_bytes = utf16_bytes(service);
        if service_bytes.is_empty()
            || service_bytes.len() > CM_MAX_SERVICE_UNITS * 2
            || service.chars().any(|ch| ch == '\0')
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut value = Vec::new();
        let mut expected_total = None;
        let mut token = 0u64;
        let mut reply_bytes = [0u8; CM_DRIVER_SERVICE_CHUNK_BYTES];
        loop {
            let operation = if token == 0 {
                driver_service_transfer::BEGIN
            } else {
                driver_service_transfer::PULL
            };
            let offset = value.len();
            let response = match self.driver_service_call(
                &service_bytes,
                operation,
                token,
                u32::try_from(offset).map_err(|_| STATUS_INVALID_PARAMETER)?,
                CM_DRIVER_SERVICE_CHUNK_BYTES as u32,
                &mut reply_bytes,
            ) {
                Ok(response) => response,
                Err(status) => {
                    self.abort_driver_service(&service_bytes, token);
                    return Err(status);
                }
            };
            if response.status != STATUS_SUCCESS {
                self.abort_driver_service(&service_bytes, token);
                return Err(response.status);
            }
            let total = usize::try_from(response.detail0).map_err(|_| STATUS_INVALID_PARAMETER)?;
            let written = response.information as usize;
            let reply_token_valid = if token == 0 {
                (written == total && response.detail1 == 0)
                    || (written < total && response.detail1 != 0)
            } else {
                response.detail1 == token
            };
            if total < CM_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES
                || expected_total.is_some_and(|expected| expected != total)
                || !reply_token_valid
                || written > reply_bytes.len()
                || offset.checked_add(written).is_none_or(|end| end > total)
                || (offset < total && written == 0)
            {
                self.abort_driver_service(
                    &service_bytes,
                    if token == 0 { response.detail1 } else { token },
                );
                return Err(STATUS_INVALID_PARAMETER);
            }
            if expected_total.is_none() {
                if value.try_reserve_exact(total).is_err() {
                    self.abort_driver_service(&service_bytes, response.detail1);
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
                expected_total = Some(total);
            }
            value.extend_from_slice(&reply_bytes[..written]);
            if value.len() == total {
                return decode_driver_service_binding(&value).ok_or(STATUS_INVALID_PARAMETER);
            }
            if token == 0 {
                token = response.detail1;
            }
        }
    }

    /// Atomically publish one complete `nt-hive-core` SYSTEM image in the isolated
    /// Configuration Manager. No partial image becomes visible.
    pub fn import_system_hive(&mut self, image: &[u8]) -> Result<u64, i32> {
        let total_len = u32::try_from(image.len()).map_err(|_| STATUS_INVALID_PARAMETER)?;
        if total_len == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let begin = self.hive_import_call(hive_import_transfer::BEGIN, 0, 0, total_len, &[])?;
        if begin.status != STATUS_SUCCESS
            || begin.information != 0
            || begin.detail0 != image.len() as u64
            || begin.detail1 == 0
        {
            return Err(if begin.status == STATUS_SUCCESS {
                STATUS_INVALID_PARAMETER
            } else {
                begin.status
            });
        }
        let token = begin.detail1;
        let mut offset = 0usize;
        while offset < image.len() {
            let end = core::cmp::min(offset + CM_HIVE_IMPORT_CHUNK_BYTES, image.len());
            let response = match self.hive_import_call(
                hive_import_transfer::PUSH,
                token,
                offset as u32,
                total_len,
                &image[offset..end],
            ) {
                Ok(response) => response,
                Err(status) => {
                    self.abort_hive_import(token, total_len);
                    return Err(status);
                }
            };
            if response.status != STATUS_SUCCESS
                || response.information as usize != end - offset
                || response.detail0 != end as u64
                || response.detail1 != token
            {
                self.abort_hive_import(token, total_len);
                return Err(if response.status == STATUS_SUCCESS {
                    STATUS_INVALID_PARAMETER
                } else {
                    response.status
                });
            }
            offset = end;
        }
        let commit = match self.hive_import_call(
            hive_import_transfer::COMMIT,
            token,
            total_len,
            total_len,
            &[],
        ) {
            Ok(response) => response,
            Err(status) => {
                self.abort_hive_import(token, total_len);
                return Err(status);
            }
        };
        if commit.status != STATUS_SUCCESS || commit.detail0 == 0 || commit.detail1 != token {
            self.abort_hive_import(token, total_len);
            return Err(if commit.status == STATUS_SUCCESS {
                STATUS_INVALID_PARAMETER
            } else {
                commit.status
            });
        }
        Ok(commit.detail0)
    }

    /// Read a complete immutable snapshot of one key in the CM-owned mounted SYSTEM hive.
    pub fn query_system_hive_key(&mut self, path: &str) -> Result<HiveKeySnapshot, i32> {
        let path_bytes = utf16_bytes(path);
        if path_bytes.is_empty()
            || path_bytes.len() > CM_MAX_HIVE_PATH_UNITS * 2
            || path.chars().any(|ch| ch == '\0')
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut value = Vec::new();
        let mut expected_total = None;
        let mut token = 0u64;
        let mut reply_bytes = [0u8; CM_HIVE_KEY_CHUNK_BYTES];
        loop {
            let operation = if token == 0 {
                hive_key_transfer::BEGIN
            } else {
                hive_key_transfer::PULL
            };
            let offset = value.len();
            let response = match self.hive_key_call(
                &path_bytes,
                operation,
                token,
                u32::try_from(offset).map_err(|_| STATUS_INVALID_PARAMETER)?,
                CM_HIVE_KEY_CHUNK_BYTES as u32,
                &mut reply_bytes,
            ) {
                Ok(response) => response,
                Err(status) => {
                    self.abort_hive_key(&path_bytes, token);
                    return Err(status);
                }
            };
            if response.status != STATUS_SUCCESS {
                self.abort_hive_key(&path_bytes, token);
                return Err(response.status);
            }
            let total = usize::try_from(response.detail0).map_err(|_| STATUS_INVALID_PARAMETER)?;
            let written = response.information as usize;
            let reply_token_valid = if token == 0 {
                (written == total && response.detail1 == 0)
                    || (written < total && response.detail1 != 0)
            } else {
                response.detail1 == token
            };
            if total < CM_HIVE_KEY_SNAPSHOT_HEADER_BYTES
                || expected_total.is_some_and(|expected| expected != total)
                || !reply_token_valid
                || written > reply_bytes.len()
                || offset.checked_add(written).is_none_or(|end| end > total)
                || (offset < total && written == 0)
            {
                self.abort_hive_key(
                    &path_bytes,
                    if token == 0 { response.detail1 } else { token },
                );
                return Err(STATUS_INVALID_PARAMETER);
            }
            if expected_total.is_none() {
                if value.try_reserve_exact(total).is_err() {
                    self.abort_hive_key(&path_bytes, response.detail1);
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
                expected_total = Some(total);
            }
            value.extend_from_slice(&reply_bytes[..written]);
            if value.len() == total {
                return decode_hive_key_snapshot(&value).ok_or(STATUS_INVALID_PARAMETER);
            }
            if token == 0 {
                token = response.detail1;
            }
        }
    }

    /// Read one complete ordered driver plan from the current mounted SYSTEM generation.
    pub fn query_driver_launch_plan(
        &mut self,
        plan_kind: u16,
    ) -> Result<DriverLaunchPlanSnapshot, i32> {
        if !matches!(
            plan_kind,
            launch_plan_kind::BOOT_SYSTEM_DRIVERS | launch_plan_kind::DEMAND_DRIVERS
        ) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let value = self.query_launch_plan_bytes(
            opcode::CM_OP_QUERY_LAUNCH_PLAN,
            plan_kind,
            CM_LAUNCH_PLAN_SNAPSHOT_HEADER_BYTES,
        )?;
        decode_driver_launch_plan(&value).ok_or(STATUS_INVALID_PARAMETER)
    }

    pub fn query_win32_service_launch_plan(
        &mut self,
        plan_kind: u16,
    ) -> Result<Win32ServiceLaunchPlanSnapshot, i32> {
        if !matches!(
            plan_kind,
            win32_service_plan_kind::AUTO_START | win32_service_plan_kind::DEMAND_START
        ) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let value = self.query_launch_plan_bytes(
            opcode::CM_OP_QUERY_WIN32_SERVICE_PLAN,
            plan_kind,
            CM_WIN32_SERVICE_PLAN_SNAPSHOT_HEADER_BYTES,
        )?;
        decode_win32_service_launch_plan(&value).ok_or(STATUS_INVALID_PARAMETER)
    }

    pub fn query_pnp(
        &mut self,
        query_kind: u16,
        selector: u32,
        instance: &str,
        auxiliary: &[u8],
    ) -> Result<PnpQuerySnapshot, i32> {
        let instance_valid = !instance.chars().any(|ch| ch == '\0')
            && instance.encode_utf16().count() <= CM_MAX_INSTANCE_UNITS;
        let shape_valid = match query_kind {
            pnp_query_kind::ENUMERATE_DEVNODE => instance.is_empty() && auxiliary.is_empty(),
            pnp_query_kind::INTERFACE_LINKS => {
                !instance.is_empty() && selector == 0 && auxiliary.len() == 16
            }
            pnp_query_kind::DYNAMIC_PROPERTY | pnp_query_kind::RELATED_DEVICE => {
                !instance.is_empty() && auxiliary.is_empty()
            }
            pnp_query_kind::DEVICE_EXISTS
            | pnp_query_kind::DEVICE_DEPTH
            | pnp_query_kind::BUS_RELATIONS => {
                !instance.is_empty() && selector == 0 && auxiliary.is_empty()
            }
            _ => false,
        };
        if !instance_valid || !shape_valid || auxiliary.len() > CM_MAX_PNP_AUX_BYTES {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let instance_bytes = utf16_bytes(instance);
        let mut value = Vec::new();
        let mut expected_total = None;
        let mut token = 0u64;
        let mut reply_bytes = [0u8; CM_LAUNCH_PLAN_CHUNK_BYTES];
        loop {
            let operation = if token == 0 {
                pnp_query_transfer::BEGIN
            } else {
                pnp_query_transfer::PULL
            };
            let offset = value.len();
            let response = match self.pnp_query_call(
                query_kind,
                selector,
                &instance_bytes,
                auxiliary,
                operation,
                token,
                u32::try_from(offset).map_err(|_| STATUS_INVALID_PARAMETER)?,
                CM_LAUNCH_PLAN_CHUNK_BYTES as u32,
                &mut reply_bytes,
            ) {
                Ok(response) => response,
                Err(status) => {
                    self.abort_pnp_query(query_kind, selector, &instance_bytes, auxiliary, token);
                    return Err(status);
                }
            };
            if response.status != STATUS_SUCCESS {
                self.abort_pnp_query(query_kind, selector, &instance_bytes, auxiliary, token);
                return Err(response.status);
            }
            let total = usize::try_from(response.detail0).map_err(|_| STATUS_INVALID_PARAMETER)?;
            let written = response.information as usize;
            let reply_token_valid = if token == 0 {
                (written == total && response.detail1 == 0)
                    || (written < total && response.detail1 != 0)
            } else {
                response.detail1 == token
            };
            if total < CM_PNP_QUERY_SNAPSHOT_HEADER_BYTES
                || expected_total.is_some_and(|expected| expected != total)
                || !reply_token_valid
                || written > reply_bytes.len()
                || offset.checked_add(written).is_none_or(|end| end > total)
                || (offset < total && written == 0)
            {
                self.abort_pnp_query(
                    query_kind,
                    selector,
                    &instance_bytes,
                    auxiliary,
                    if token == 0 { response.detail1 } else { token },
                );
                return Err(STATUS_INVALID_PARAMETER);
            }
            if expected_total.is_none() {
                if value.try_reserve_exact(total).is_err() {
                    self.abort_pnp_query(
                        query_kind,
                        selector,
                        &instance_bytes,
                        auxiliary,
                        response.detail1,
                    );
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
                expected_total = Some(total);
            }
            value.extend_from_slice(&reply_bytes[..written]);
            if value.len() == total {
                let snapshot = decode_pnp_query_snapshot(&value).ok_or(STATUS_INVALID_PARAMETER)?;
                if snapshot.query_kind != query_kind {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                return Ok(snapshot);
            }
            if token == 0 {
                token = response.detail1;
            }
        }
    }

    fn query_launch_plan_bytes(
        &mut self,
        query_opcode: u16,
        plan_kind: u16,
        minimum_bytes: usize,
    ) -> Result<Vec<u8>, i32> {
        let mut value = Vec::new();
        let mut expected_total = None;
        let mut token = 0u64;
        let mut reply_bytes = [0u8; CM_LAUNCH_PLAN_CHUNK_BYTES];
        loop {
            let operation = if token == 0 {
                launch_plan_transfer::BEGIN
            } else {
                launch_plan_transfer::PULL
            };
            let offset = value.len();
            let response = match self.launch_plan_call(
                query_opcode,
                plan_kind,
                operation,
                token,
                u32::try_from(offset).map_err(|_| STATUS_INVALID_PARAMETER)?,
                CM_LAUNCH_PLAN_CHUNK_BYTES as u32,
                &mut reply_bytes,
            ) {
                Ok(response) => response,
                Err(status) => {
                    self.abort_launch_plan(query_opcode, plan_kind, token);
                    return Err(status);
                }
            };
            if response.status != STATUS_SUCCESS {
                self.abort_launch_plan(query_opcode, plan_kind, token);
                return Err(response.status);
            }
            let total = usize::try_from(response.detail0).map_err(|_| STATUS_INVALID_PARAMETER)?;
            let written = response.information as usize;
            let reply_token_valid = if token == 0 {
                (written == total && response.detail1 == 0)
                    || (written < total && response.detail1 != 0)
            } else {
                response.detail1 == token
            };
            if total < minimum_bytes
                || expected_total.is_some_and(|expected| expected != total)
                || !reply_token_valid
                || written > reply_bytes.len()
                || offset.checked_add(written).is_none_or(|end| end > total)
                || (offset < total && written == 0)
            {
                self.abort_launch_plan(
                    query_opcode,
                    plan_kind,
                    if token == 0 { response.detail1 } else { token },
                );
                return Err(STATUS_INVALID_PARAMETER);
            }
            if expected_total.is_none() {
                if value.try_reserve_exact(total).is_err() {
                    self.abort_launch_plan(query_opcode, plan_kind, response.detail1);
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
                expected_total = Some(total);
            }
            value.extend_from_slice(&reply_bytes[..written]);
            if value.len() == total {
                return Ok(value);
            }
            if token == 0 {
                token = response.detail1;
            }
        }
    }

    fn driver_service_call(
        &mut self,
        service_bytes: &[u8],
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
        reply_bytes: &mut [u8],
    ) -> Result<CmReply, i32> {
        let header_size = core::mem::size_of::<CmDriverServiceRequest>();
        let header = CmDriverServiceRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            _reserved: 0,
            value_offset,
            chunk_capacity,
            service_offset: header_size as u32,
            service_len_bytes: u32::try_from(service_bytes.len())
                .map_err(|_| STATUS_INVALID_PARAMETER)?,
            transfer_token,
        };
        let mut request = Vec::new();
        request
            .try_reserve_exact(header_size.saturating_add(service_bytes.len()))
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        request.extend_from_slice(header.as_bytes());
        request.extend_from_slice(service_bytes);
        Ok(self
            .backend
            .call(opcode::CM_OP_QUERY_DRIVER_SERVICE, &request, reply_bytes))
    }

    fn abort_driver_service(&mut self, service_bytes: &[u8], transfer_token: u64) {
        if transfer_token == 0 {
            return;
        }
        let _ = self.driver_service_call(
            service_bytes,
            driver_service_transfer::ABORT,
            transfer_token,
            0,
            0,
            &mut [],
        );
    }

    fn hive_import_call(
        &mut self,
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        total_len_bytes: u32,
        chunk: &[u8],
    ) -> Result<CmReply, i32> {
        if chunk.len() > CM_HIVE_IMPORT_CHUNK_BYTES {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let header_size = core::mem::size_of::<CmHiveImportRequest>();
        let chunk_offset = if chunk.is_empty() {
            0
        } else {
            header_size as u32
        };
        let header = CmHiveImportRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            mount: hive_mount::SYSTEM,
            value_offset,
            chunk_offset,
            chunk_len_bytes: u32::try_from(chunk.len()).map_err(|_| STATUS_INVALID_PARAMETER)?,
            total_len_bytes,
            transfer_token,
        };
        let mut request = Vec::new();
        request
            .try_reserve_exact(header_size.saturating_add(chunk.len()))
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        request.extend_from_slice(header.as_bytes());
        request.extend_from_slice(chunk);
        Ok(self
            .backend
            .call(opcode::CM_OP_IMPORT_HIVE, &request, &mut []))
    }

    fn abort_hive_import(&mut self, transfer_token: u64, total_len_bytes: u32) {
        if transfer_token == 0 {
            return;
        }
        let _ = self.hive_import_call(
            hive_import_transfer::ABORT,
            transfer_token,
            0,
            total_len_bytes,
            &[],
        );
    }

    fn hive_key_call(
        &mut self,
        path_bytes: &[u8],
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
        reply_bytes: &mut [u8],
    ) -> Result<CmReply, i32> {
        let header_size = core::mem::size_of::<CmHiveKeyRequest>();
        let header = CmHiveKeyRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            mount: hive_mount::SYSTEM,
            value_offset,
            chunk_capacity,
            path_offset: header_size as u32,
            path_len_bytes: u32::try_from(path_bytes.len())
                .map_err(|_| STATUS_INVALID_PARAMETER)?,
            transfer_token,
        };
        let mut request = Vec::new();
        request
            .try_reserve_exact(header_size.saturating_add(path_bytes.len()))
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        request.extend_from_slice(header.as_bytes());
        request.extend_from_slice(path_bytes);
        Ok(self
            .backend
            .call(opcode::CM_OP_QUERY_HIVE_KEY, &request, reply_bytes))
    }

    fn abort_hive_key(&mut self, path_bytes: &[u8], transfer_token: u64) {
        if transfer_token == 0 {
            return;
        }
        let _ = self.hive_key_call(
            path_bytes,
            hive_key_transfer::ABORT,
            transfer_token,
            0,
            0,
            &mut [],
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn pnp_query_call(
        &mut self,
        query_kind: u16,
        selector: u32,
        instance_bytes: &[u8],
        auxiliary: &[u8],
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
        reply_bytes: &mut [u8],
    ) -> Result<CmReply, i32> {
        let header_size = core::mem::size_of::<CmPnpQueryRequest>();
        let auxiliary_offset = header_size
            .checked_add(instance_bytes.len())
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let request_header = CmPnpQueryRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            query_kind,
            value_offset,
            chunk_capacity,
            selector,
            instance_offset: header_size as u32,
            instance_len_bytes: u32::try_from(instance_bytes.len())
                .map_err(|_| STATUS_INVALID_PARAMETER)?,
            auxiliary_offset: u32::try_from(auxiliary_offset)
                .map_err(|_| STATUS_INVALID_PARAMETER)?,
            auxiliary_len_bytes: u32::try_from(auxiliary.len())
                .map_err(|_| STATUS_INVALID_PARAMETER)?,
            _reserved: 0,
            transfer_token,
        };
        let mut request = Vec::new();
        request
            .try_reserve_exact(auxiliary_offset.saturating_add(auxiliary.len()))
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        request.extend_from_slice(request_header.as_bytes());
        request.extend_from_slice(instance_bytes);
        request.extend_from_slice(auxiliary);
        Ok(self
            .backend
            .call(opcode::CM_OP_QUERY_PNP, &request, reply_bytes))
    }

    fn abort_pnp_query(
        &mut self,
        query_kind: u16,
        selector: u32,
        instance_bytes: &[u8],
        auxiliary: &[u8],
        transfer_token: u64,
    ) {
        if transfer_token == 0 {
            return;
        }
        let _ = self.pnp_query_call(
            query_kind,
            selector,
            instance_bytes,
            auxiliary,
            pnp_query_transfer::ABORT,
            transfer_token,
            0,
            0,
            &mut [],
        );
    }

    fn launch_plan_call(
        &mut self,
        query_opcode: u16,
        plan_kind: u16,
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
        reply_bytes: &mut [u8],
    ) -> Result<CmReply, i32> {
        let header_size = core::mem::size_of::<CmLaunchPlanRequest>();
        let request = CmLaunchPlanRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            plan_kind,
            value_offset,
            chunk_capacity,
            transfer_token,
        };
        Ok(self
            .backend
            .call(query_opcode, request.as_bytes(), reply_bytes))
    }

    fn abort_launch_plan(&mut self, query_opcode: u16, plan_kind: u16, transfer_token: u64) {
        if transfer_token == 0 {
            return;
        }
        let _ = self.launch_plan_call(
            query_opcode,
            plan_kind,
            launch_plan_transfer::ABORT,
            transfer_token,
            0,
            0,
            &mut [],
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn device_property_call(
        &mut self,
        instance_bytes: &[u8],
        property: u32,
        output_capacity: u32,
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
        reply_bytes: &mut [u8],
    ) -> Result<CmReply, QueryError> {
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
        let mut request = Vec::new();
        request
            .try_reserve_exact(header_size.saturating_add(instance_bytes.len()))
            .map_err(|_| QueryError {
                status: STATUS_INSUFFICIENT_RESOURCES,
                required_len: 0,
            })?;
        request.extend_from_slice(header.as_bytes());
        request.extend_from_slice(instance_bytes);
        Ok(self
            .backend
            .call(opcode::CM_OP_QUERY_DEVICE_PROPERTY, &request, reply_bytes))
    }

    fn abort_device_property(
        &mut self,
        instance_bytes: &[u8],
        property: u32,
        output_capacity: u32,
        transfer_token: u64,
    ) {
        if transfer_token == 0 {
            return;
        }
        let _ = self.device_property_call(
            instance_bytes,
            property,
            output_capacity,
            device_property_transfer::ABORT,
            transfer_token,
            0,
            0,
            &mut [],
        );
    }

    fn key_op(&mut self, op: u16, path: &str) -> CmReply {
        let path_bytes = utf16_bytes(path);
        let hdr = CmKeyRequest {
            abi_size: core::mem::size_of::<CmKeyRequest>() as u16,
            _pad: 0,
            path_offset: core::mem::size_of::<CmKeyRequest>() as u32,
            path_len_bytes: path_bytes.len() as u32,
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(hdr.as_bytes());
        buf.extend_from_slice(&path_bytes);
        self.backend.call(op, &buf, &mut [])
    }

    fn enumerate_key_op(&mut self, path: &str, index: u32, out: &mut [u8]) -> CmReply {
        let path_bytes = utf16_bytes(path);
        let hdr = CmEnumerateKeyRequest {
            abi_size: core::mem::size_of::<CmEnumerateKeyRequest>() as u16,
            _pad: 0,
            index,
            path_offset: core::mem::size_of::<CmEnumerateKeyRequest>() as u32,
            path_len_bytes: path_bytes.len() as u32,
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(hdr.as_bytes());
        buf.extend_from_slice(&path_bytes);
        self.backend.call(opcode::CM_OP_ENUMERATE_KEY, &buf, out)
    }

    fn value_op(&mut self, op: u16, key_path: &str, name: &str, dword: u32) -> CmReply {
        let key_bytes = utf16_bytes(key_path);
        let name_bytes = utf16_bytes(name);
        let base = core::mem::size_of::<CmValueRequest>() as u32;
        let hdr = CmValueRequest {
            abi_size: base as u16,
            _pad: 0,
            dword,
            key_offset: base,
            key_len_bytes: key_bytes.len() as u32,
            name_offset: base + key_bytes.len() as u32,
            name_len_bytes: name_bytes.len() as u32,
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(hdr.as_bytes());
        buf.extend_from_slice(&key_bytes);
        buf.extend_from_slice(&name_bytes);
        self.backend.call(op, &buf, &mut [])
    }

    fn raw_value_op(
        &mut self,
        op: u16,
        key_path: &str,
        name: &str,
        value_type: u32,
        data: &[u8],
        out: &mut [u8],
    ) -> CmReply {
        let key_bytes = utf16_bytes(key_path);
        let name_bytes = utf16_bytes(name);
        let base = core::mem::size_of::<CmRawValueRequest>() as u32;
        let data_offset = base + key_bytes.len() as u32 + name_bytes.len() as u32;
        let hdr = CmRawValueRequest {
            abi_size: base as u16,
            _pad: 0,
            value_type,
            key_offset: base,
            key_len_bytes: key_bytes.len() as u32,
            name_offset: base + key_bytes.len() as u32,
            name_len_bytes: name_bytes.len() as u32,
            data_offset,
            data_len_bytes: data.len() as u32,
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(hdr.as_bytes());
        buf.extend_from_slice(&key_bytes);
        buf.extend_from_slice(&name_bytes);
        buf.extend_from_slice(data);
        self.backend.call(op, &buf, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;
    use nt_config_manager::{
        device_property, encode_sz, ConfigManager, RegistryValueType, ENUM_PATH,
        SERVICE_AUTO_START, SERVICE_BOOT_START, SERVICE_DEMAND_START, SERVICE_FILE_SYSTEM_DRIVER,
        SERVICE_INTERACTIVE_PROCESS, SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_WIN32_SHARE_PROCESS,
    };
    use nt_config_server::CmServer;
    use nt_hive_core::{encode_image, Hive, HiveKind};

    /// In-process backend: dispatch straight into the server (no ring).
    struct Direct {
        server: CmServer,
    }

    /// Model the integrated service: dispatch into a whole page even when the final caller's slice
    /// is smaller, then copy completion bytes exactly as `RingChannel` does.
    struct Framed {
        server: CmServer,
    }
    impl Backend for Framed {
        fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> CmReply {
            let mut frame = [0u8; 4096];
            let reply = self.server.dispatch(opcode, in_buf, &mut frame);
            let copy_len = core::cmp::min(reply.information as usize, out_buf.len());
            out_buf[..copy_len].copy_from_slice(&frame[..copy_len]);
            reply
        }
    }
    impl Backend for Direct {
        fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> CmReply {
            self.server.dispatch(opcode, in_buf, out_buf)
        }
    }

    fn client() -> ConfigClient<Direct> {
        client_with_server(CmServer::new())
    }

    fn client_with_server(server: CmServer) -> ConfigClient<Direct> {
        ConfigClient::new(Direct { server })
    }

    #[test]
    fn ping() {
        assert!(client().ping());
    }

    #[test]
    fn mounted_system_hive_import_and_complete_key_snapshot_cross_frames() {
        let mut hive = Hive::new(HiveKind::System);
        let select = hive.create_key("Select");
        hive.set_dword(select, "Current", 1);
        let key = hive.create_key(r"ControlSet001\Services\Large");
        assert!(hive.set_key_class(key, Some("DriverServiceClass")));
        let security = vec![0x5au8; 5_000];
        assert!(hive.set_key_security_descriptor(key, &security));
        let large_value = vec![0xa5u8; 9_000];
        assert!(hive.set_value(
            key,
            "Payload",
            nt_hive_core::RegistryValueType::Binary,
            large_value.clone(),
        ));
        for index in 0..73 {
            let child = hive.create_subkey(key, &format!("Child{index:04}"));
            assert!(hive.set_key_class(child, Some("ChildClass")));
        }
        hive.finish_clean_import();
        let image = encode_image(&hive);
        assert!(image.len() > CM_HIVE_IMPORT_CHUNK_BYTES);

        let mut client = ConfigClient::new(Framed {
            server: CmServer::new(),
        });
        assert_eq!(client.import_system_hive(&image), Ok(1));
        let snapshot = client
            .query_system_hive_key(r"\Registry\Machine\System\CurrentControlSet\Services\Large")
            .unwrap();
        assert_eq!(snapshot.mount_generation, 1);
        assert_eq!(snapshot.class_name.as_deref(), Some("DriverServiceClass"));
        assert_eq!(
            snapshot.security_descriptor.as_deref(),
            Some(security.as_slice())
        );
        assert_eq!(snapshot.subkeys.len(), 73);
        assert_eq!(snapshot.subkeys[0].name, "Child0000");
        assert_eq!(
            snapshot.subkeys[0].class_name.as_deref(),
            Some("ChildClass")
        );
        assert_eq!(snapshot.values.len(), 1);
        assert_eq!(snapshot.values[0].name, "Payload");
        assert_eq!(
            snapshot.values[0].value_type,
            nt_hive_core::RegistryValueType::Binary as u32
        );
        assert_eq!(snapshot.values[0].data, large_value);

        let selected = client
            .query_system_hive_key(r"\Registry\Machine\System\ControlSet001\Services\Large")
            .unwrap();
        assert_eq!(selected.mount_generation, snapshot.mount_generation);
        assert_eq!(selected.values, snapshot.values);
    }

    #[test]
    fn mounted_system_driver_plans_are_ordered_generation_bound_snapshots() {
        let mut hive = Hive::new(HiveKind::System);
        let select = hive.create_key("Select");
        hive.set_dword(select, "Current", 1);
        for (name, image, service_type, start) in [
            (
                "BootDevice",
                r"system32\drivers\bootdev.sys",
                SERVICE_KERNEL_DRIVER,
                SERVICE_BOOT_START,
            ),
            (
                "SystemFsd",
                r"system32\drivers\systemfs.sys",
                SERVICE_FILE_SYSTEM_DRIVER,
                SERVICE_SYSTEM_START,
            ),
            (
                "DemandDevice",
                r"system32\drivers\demand.sys",
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
            ),
        ] {
            let service = hive.create_key(&format!(r"ControlSet001\Services\{name}"));
            hive.set_dword(service, "Type", service_type);
            hive.set_dword(service, "Start", start);
            assert!(hive.set_value(
                service,
                "ImagePath",
                nt_hive_core::RegistryValueType::ExpandSz,
                encode_sz(image),
            ));
            hive.set_dword(service, "ErrorControl", 1);
            hive.set_dword(service, "Tag", start + 7);
            assert!(hive.set_value(
                service,
                "Group",
                nt_hive_core::RegistryValueType::Sz,
                encode_sz(if start == SERVICE_SYSTEM_START {
                    "File System"
                } else {
                    "Base"
                }),
            ));
        }
        for (instance, service) in [
            (r"ROOT\BOOTDEV\0000", "BootDevice"),
            (r"ROOT\DEMAND\0000", "DemandDevice"),
        ] {
            let devnode = hive.create_key(&format!(r"ControlSet001\Enum\{instance}"));
            assert!(hive.set_value(
                devnode,
                "Service",
                nt_hive_core::RegistryValueType::Sz,
                encode_sz(service),
            ));
        }
        for (name, image, service_type, start) in [
            (
                "AutoShared",
                r"%SystemRoot%\system32\svchost.exe -k netsvcs",
                SERVICE_WIN32_SHARE_PROCESS,
                SERVICE_AUTO_START,
            ),
            (
                "DemandOwn",
                r"system32\demand.exe /service",
                SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
                SERVICE_DEMAND_START,
            ),
        ] {
            let service = hive.create_key(&format!(r"ControlSet001\Services\{name}"));
            hive.set_dword(service, "Type", service_type);
            hive.set_dword(service, "Start", start);
            assert!(hive.set_value(
                service,
                "ImagePath",
                nt_hive_core::RegistryValueType::ExpandSz,
                encode_sz(image),
            ));
        }
        hive.finish_clean_import();

        let mut client = ConfigClient::new(Framed {
            server: CmServer::new(),
        });
        assert_eq!(client.import_system_hive(&encode_image(&hive)), Ok(1));
        let interface_guid = "{4d36e972-e325-11ce-bfc1-08002be10318}";
        let interface_guid_bytes =
            nt_config_manager::guid_text_to_memory_bytes(interface_guid).unwrap();
        let boot_devnode = client
            .backend
            .server
            .config()
            .devnode(r"ROOT\BOOTDEV\0000")
            .unwrap()
            .id;
        let interface = client
            .backend
            .server
            .config_mut()
            .register_interface(boot_devnode, interface_guid, "net", true)
            .unwrap();
        let expected_link = client
            .backend
            .server
            .config()
            .interface(interface)
            .unwrap()
            .symbolic_link
            .clone();
        let boot = client
            .query_driver_launch_plan(launch_plan_kind::BOOT_SYSTEM_DRIVERS)
            .expect("boot driver plan");
        assert_eq!(boot.mount_generation, 1);
        assert_eq!(boot.plan_kind, launch_plan_kind::BOOT_SYSTEM_DRIVERS);
        assert_eq!(boot.bindings.len(), 2);
        assert_eq!(boot.bindings[0].service_name, "BootDevice");
        assert_eq!(boot.bindings[0].error_control, Some(1));
        assert_eq!(boot.bindings[0].load_order_group.as_deref(), Some("Base"));
        assert_eq!(boot.bindings[0].tag, Some(7));
        assert_eq!(boot.bindings[0].devnodes.len(), 1);
        assert_eq!(boot.bindings[1].service_name, "SystemFsd");
        assert_eq!(boot.bindings[1].class, DriverServiceClass::FileSystem);
        assert_eq!(
            boot.bindings[1].load_order_group.as_deref(),
            Some("File System")
        );

        let demand = client
            .query_driver_launch_plan(launch_plan_kind::DEMAND_DRIVERS)
            .expect("demand driver plan");
        assert_eq!(demand.mount_generation, 1);
        assert_eq!(demand.bindings.len(), 1);
        assert_eq!(demand.bindings[0].service_name, "DemandDevice");
        assert_eq!(demand.bindings[0].devnodes.len(), 1);

        let auto_services = client
            .query_win32_service_launch_plan(win32_service_plan_kind::AUTO_START)
            .expect("auto-start service plan");
        assert_eq!(auto_services.mount_generation, 1);
        assert_eq!(auto_services.launches.len(), 1);
        assert_eq!(auto_services.launches[0].service_name, "AutoShared");
        assert_eq!(
            auto_services.launches[0].nt_image_path,
            r"\SystemRoot\system32\svchost.exe"
        );
        assert_eq!(
            auto_services.launches[0].process_kind,
            Win32ServiceProcessKind::Shared
        );

        let demand_services = client
            .query_win32_service_launch_plan(win32_service_plan_kind::DEMAND_START)
            .expect("demand-start service plan");
        assert_eq!(demand_services.mount_generation, 1);
        assert_eq!(demand_services.launches.len(), 1);
        assert_eq!(demand_services.launches[0].service_name, "DemandOwn");
        assert!(demand_services.launches[0].interactive);

        let exists = client
            .query_pnp(pnp_query_kind::DEVICE_EXISTS, 0, r"ROOT\BOOTDEV\0000", &[])
            .expect("device exists");
        assert_eq!(exists.mount_generation, 1);
        assert!(exists.strings.is_empty() && exists.payload.is_empty());
        let enumerated = client
            .query_pnp(pnp_query_kind::ENUMERATE_DEVNODE, 0, "", &[])
            .expect("enumerate devnode");
        assert_eq!(enumerated.strings, vec![String::from(r"ROOT\BOOTDEV\0000")]);
        let property = client
            .query_pnp(
                pnp_query_kind::DYNAMIC_PROPERTY,
                nt_config_manager::pnp_property::ENUMERATOR_NAME,
                r"ROOT\BOOTDEV\0000",
                &[],
            )
            .expect("dynamic property");
        assert_eq!(property.payload, encode_sz("ROOT"));
        let parent = client
            .query_pnp(
                pnp_query_kind::RELATED_DEVICE,
                nt_config_manager::pnp_relation::PARENT,
                r"ROOT\BOOTDEV\0000",
                &[],
            )
            .expect("parent relation");
        assert_eq!(
            parent.strings,
            vec![String::from(nt_config_manager::PNP_ROOT_DEVICE_INSTANCE)]
        );
        let depth = client
            .query_pnp(pnp_query_kind::DEVICE_DEPTH, 0, r"ROOT\BOOTDEV\0000", &[])
            .expect("device depth");
        assert_eq!(depth.payload, 1u32.to_le_bytes());
        let relations = client
            .query_pnp(
                pnp_query_kind::BUS_RELATIONS,
                0,
                nt_config_manager::PNP_ROOT_DEVICE_INSTANCE,
                &[],
            )
            .expect("root bus relations");
        assert_eq!(relations.strings.len(), 2);
        let interfaces = client
            .query_pnp(
                pnp_query_kind::INTERFACE_LINKS,
                0,
                r"ROOT\BOOTDEV\0000",
                &interface_guid_bytes,
            )
            .expect("enabled interface links");
        assert_eq!(interfaces.strings, vec![expected_link]);
    }

    #[test]
    fn corrupt_hive_import_does_not_replace_published_mount() {
        let mut hive = Hive::new(HiveKind::System);
        let select = hive.create_key("Select");
        hive.set_dword(select, "Current", 1);
        let key = hive.create_key(r"ControlSet001\Services\Stable");
        assert!(hive.set_dword(key, "Start", 3));
        hive.finish_clean_import();
        let image = encode_image(&hive);

        let mut client = ConfigClient::new(Framed {
            server: CmServer::new(),
        });
        assert_eq!(client.import_system_hive(&image), Ok(1));
        let mut corrupt = image.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xff;
        assert!(client.import_system_hive(&corrupt).is_err());
        let stable = client
            .query_system_hive_key(r"\Registry\Machine\System\CurrentControlSet\Services\Stable")
            .unwrap();
        assert_eq!(stable.mount_generation, 1);
        assert_eq!(stable.values[0].name, "Start");
        assert_eq!(stable.values[0].data, 3u32.to_le_bytes());
    }

    #[test]
    fn create_set_query_dword_roundtrip() {
        let mut c = client();
        let k = r"\Registry\Machine\System\CurrentControlSet\Services\Demo";
        assert!(c.create_key(k).is_ok());
        assert!(c.open_key(k));
        assert!(c.set_dword(k, "Start", 3).is_ok());
        assert_eq!(c.query_dword(k, "Start"), Ok(3));
        // set_dword auto-creates the key.
        let k2 = r"\Registry\Machine\Software\Demo2";
        assert!(c.set_dword(k2, "Answer", 42).is_ok());
        assert_eq!(c.query_dword(k2, "Answer"), Ok(42));
    }

    #[test]
    fn set_query_raw_value_roundtrip() {
        let mut c = client();
        let k = r"\Registry\Machine\Hardware\DeviceMap\Video";
        let data = b"v\0i\0d\0e\0o\0\0\0";
        assert!(c.set_value(k, r"\Device\Video0", 1, data).is_ok());
        let mut out = [0u8; 32];
        assert_eq!(
            c.query_value(k, r"\Device\Video0", &mut out),
            Ok((1, data.len()))
        );
        assert_eq!(&out[..data.len()], data);
    }

    #[test]
    fn seeded_config_manager_services_are_visible() {
        let mut cm = ConfigManager::new();
        cm.register_typed_service(
            "RpcSs",
            r"%SystemRoot%\system32\svchost.exe -k rpcss",
            SERVICE_WIN32_SHARE_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        let mut c = client_with_server(CmServer::with_config(cm));
        let key = r"\Registry\Machine\System\CurrentControlSet\Services\RpcSs";
        assert!(c.open_key(key));
        assert_eq!(c.query_dword(key, "Type"), Ok(SERVICE_WIN32_SHARE_PROCESS));
        assert_eq!(c.query_dword(key, "Start"), Ok(SERVICE_AUTO_START));

        let expected = encode_sz(r"%SystemRoot%\system32\svchost.exe -k rpcss");
        let mut out = [0u8; 128];
        assert_eq!(
            c.query_value(key, "ImagePath", &mut out),
            Ok((1, expected.len()))
        );
        assert_eq!(&out[..expected.len()], expected.as_slice());
    }

    #[test]
    fn driver_service_query_is_live_and_reassembles_unbounded_devnodes() {
        let mut cm = ConfigManager::new();
        cm.register_service(
            "Pending",
            r"system32\drivers\pending.sys",
            None,
            Some("{4D36E97D-E325-11CE-BFC1-08002BE10318}"),
            3,
            1,
        );
        for index in 0..72 {
            let instance = format!(r"ROOT\PENDING\{index:04}");
            let hardware = format!(r"ROOT\PENDING_{index:04}_{}", "H".repeat(64));
            cm.register_devnode(&instance, Some("Pending"), None, &[hardware.as_str()], &[]);
        }
        let mut client = ConfigClient::new(Framed {
            server: CmServer::with_config(cm),
        });

        let service_key = r"\Registry\Machine\System\CurrentControlSet\Services\Pending";
        let changed_image = r"system32\drivers\pending-changed.sys";
        assert!(client
            .set_value(
                service_key,
                "ImagePath",
                RegistryValueType::Sz as u32,
                &encode_sz(changed_image),
            )
            .is_ok());
        let late_instance = r"ROOT\PENDING\9999";
        let late_key = format!(r"{}\{}", ENUM_PATH, late_instance);
        assert!(client.create_key(&late_key).is_ok());
        assert!(client
            .set_value(
                &late_key,
                "Service",
                RegistryValueType::Sz as u32,
                &encode_sz("Pending"),
            )
            .is_ok());

        let binding = client.query_driver_service("pending").unwrap();
        assert_eq!(binding.service_name, "Pending");
        assert_eq!(binding.image_path, changed_image);
        assert_eq!(binding.class, DriverServiceClass::Device);
        assert_eq!(binding.start_type, 3);
        assert_eq!(binding.devnodes.len(), 73);
        assert_eq!(binding.devnodes.last().unwrap().instance_id, late_instance);
    }

    #[test]
    fn enumerate_key_returns_case_preserved_subkey_names() {
        let mut c = client();
        let parent = r"\Registry\Machine\System\CurrentControlSet\Services";
        assert!(c.create_key(&format!(r"{}\Tcpip", parent)).is_ok());
        assert!(c.create_key(&format!(r"{}\Ndis", parent)).is_ok());
        let mut out = [0u8; 32];
        let n0 = c.enumerate_key(parent, 0, &mut out).unwrap();
        let first = String::from_utf16_lossy(
            &out[..n0]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        );
        let n1 = c.enumerate_key(parent, 1, &mut out).unwrap();
        let second = String::from_utf16_lossy(
            &out[..n1]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        );
        assert_eq!(first, "Tcpip");
        assert_eq!(second, "Ndis");
        assert!(c.enumerate_key(parent, 2, &mut out).is_err());
    }

    #[test]
    fn missing_key_and_value() {
        let mut c = client();
        assert!(!c.open_key(r"\Registry\Machine\Nope"));
        assert!(c.query_dword(r"\Registry\Machine\Nope", "X").is_err());
        c.create_key(r"\Registry\Machine\Empty").unwrap();
        assert!(c
            .query_dword(r"\Registry\Machine\Empty", "Missing")
            .is_err());
    }

    fn device_property_server() -> CmServer {
        let mut cm = ConfigManager::new();
        let instance = r"PCI\VEN_8086&DEV_100E\0001";
        let key = cm
            .registry_mut()
            .create_key(&format!(r"{}\{}", ENUM_PATH, instance));
        cm.registry_mut()
            .set_string(key, "PdoName", r"\Device\NTPNP_PCI0001");
        cm.registry_mut()
            .set_string(key, "FriendlyName", "Intel Test Adapter");
        CmServer::with_config(cm)
    }

    #[test]
    fn device_property_query_roundtrip_preserves_semantics() {
        let mut client = client_with_server(device_property_server());
        let mut out = [0u8; 128];
        let written = client
            .query_device_property(
                r"pci\ven_8086&dev_100e\0001",
                device_property::FRIENDLY_NAME,
                &mut out,
            )
            .unwrap();
        let expected = encode_sz("Intel Test Adapter");
        assert_eq!(written, expected.len());
        assert_eq!(&out[..written], expected.as_slice());

        let external = client
            .query_device_property(
                r"PCI\VEN_8086&DEV_100E\0001",
                device_property::BUS_NUMBER,
                &mut out,
            )
            .unwrap_err();
        assert_eq!(external.status, 0xC000_00BBu32 as i32);
        assert_eq!(external.required_len, 0);

        let invalid = client
            .query_device_property(r"PCI\VEN_8086&DEV_100E\0001", 23, &mut out)
            .unwrap_err();
        assert_eq!(invalid.status, STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn device_property_query_honors_final_slice_capacity() {
        let mut client = ConfigClient::new(Framed {
            server: device_property_server(),
        });
        let mut out = [0xa5; 2];
        let error = client
            .query_device_property(
                r"PCI\VEN_8086&DEV_100E\0001",
                device_property::FRIENDLY_NAME,
                &mut out,
            )
            .unwrap_err();
        assert_eq!(error.status, 0xC000_0023u32 as i32);
        assert_eq!(error.required_len, encode_sz("Intel Test Adapter").len());
        assert_eq!(out, [0xa5; 2]);
    }

    #[test]
    fn device_property_query_reassembles_multiple_reply_frames() {
        let mut cm = ConfigManager::new();
        let key = cm
            .registry_mut()
            .create_key(&format!(r"{}\{}", ENUM_PATH, r"PCI\VEN_8086&DEV_100E\0001"));
        let mut expected = vec![0u8; CM_DEVICE_PROPERTY_CHUNK_BYTES * 2 + 132];
        let content_len = expected.len() - 4;
        for pair in expected[..content_len].chunks_exact_mut(2) {
            pair.copy_from_slice(&u16::from(b'A').to_le_bytes());
        }
        assert!(cm.registry_mut().set_value(
            key,
            "HardwareID",
            RegistryValueType::MultiSz,
            expected.clone(),
        ));
        let mut client = ConfigClient::new(Framed {
            server: CmServer::with_config(cm),
        });
        let mut out = vec![0xa5; expected.len()];
        assert_eq!(
            client.query_device_property(
                r"PCI\VEN_8086&DEV_100E\0001",
                device_property::HARDWARE_ID,
                &mut out,
            ),
            Ok(expected.len())
        );
        assert_eq!(out, expected);
    }

    #[test]
    fn device_property_query_rejects_invalid_client_paths() {
        let mut client = client_with_server(device_property_server());
        let mut out = [0u8; 8];
        assert_eq!(
            client
                .query_device_property("", device_property::FRIENDLY_NAME, &mut out)
                .unwrap_err()
                .status,
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            client
                .query_device_property("PCI\0DEVICE", device_property::FRIENDLY_NAME, &mut out)
                .unwrap_err()
                .status,
            STATUS_INVALID_PARAMETER
        );
        let oversized = "A".repeat(CM_MAX_INSTANCE_UNITS + 1);
        assert_eq!(
            client
                .query_device_property(&oversized, device_property::FRIENDLY_NAME, &mut out)
                .unwrap_err()
                .status,
            STATUS_INVALID_PARAMETER
        );
    }
}
