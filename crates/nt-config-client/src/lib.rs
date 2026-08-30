//! Ergonomic client for the NT Configuration Manager (registry) service ABI.
//!
//! Encodes each call into the [`nt_config_abi`] wire form, hands it to a pluggable
//! [`Backend`] (SURT rings on the kernel; in-process in tests), and decodes the
//! [`CmReply`]. Supports path-addressed keys plus DWORD and raw typed values. Mirrors
//! `nt-object-client`, with semantic devnode property queries that preserve required output length
//! across the shared-frame transport and CM-owned SYSTEM key leases for native registry handles.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use nt_config_abi::{
    device_action_kind, device_action_service, device_action_transfer, device_property_transfer,
    driver_service_class, driver_service_transfer, hive_checkpoint_transfer, hive_import_transfer,
    hive_key_lease_operation, hive_key_transfer, hive_mount, hive_mutation_flags,
    hive_mutation_kind, hive_mutation_transfer, launch_plan_kind, launch_plan_transfer,
    leased_hive_record_kind, network_plan_kind, opcode, pnp_query_kind, pnp_query_transfer,
    win32_service_plan_kind, win32_service_process_kind, CmDeviceActionRequest,
    CmDevicePropertyRequest, CmDriverServiceRequest, CmEnumerateKeyRequest, CmHiveCheckpointHeader,
    CmHiveCheckpointRequest, CmHiveExportHeader, CmHiveImportRequest, CmHiveKeyLeaseRequest,
    CmHiveKeyRequest, CmHiveMutationRecord, CmHiveMutationRequest, CmKeyRequest,
    CmLaunchPlanRequest, CmLeasedHiveKeyRequest, CmLeasedHiveRecordRequest, CmPnpQueryRequest,
    CmRawValueRequest, CmReply, CmValueRequest, CM_ABI_VERSION, CM_DEVICE_ACTION_CHUNK_BYTES,
    CM_DEVICE_ACTION_SNAPSHOT_HEADER_BYTES, CM_DEVICE_ACTION_SNAPSHOT_MAGIC,
    CM_DEVICE_ACTION_SNAPSHOT_VERSION, CM_DEVICE_PROPERTY_CHUNK_BYTES,
    CM_DRIVER_SERVICE_CHUNK_BYTES, CM_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES,
    CM_DRIVER_SERVICE_SNAPSHOT_MAGIC, CM_DRIVER_SERVICE_SNAPSHOT_VERSION,
    CM_HIVE_CHECKPOINT_CHUNK_BYTES, CM_HIVE_CHECKPOINT_HEADER_BYTES, CM_HIVE_CHECKPOINT_MAGIC,
    CM_HIVE_CHECKPOINT_VERSION, CM_HIVE_EXPORT_HEADER_BYTES, CM_HIVE_EXPORT_MAGIC,
    CM_HIVE_EXPORT_VERSION, CM_HIVE_IMPORT_CHUNK_BYTES, CM_HIVE_KEY_CHUNK_BYTES,
    CM_HIVE_KEY_RECORD_HEADER_BYTES, CM_HIVE_KEY_RECORD_MAGIC, CM_HIVE_KEY_RECORD_VERSION,
    CM_HIVE_KEY_SNAPSHOT_HEADER_BYTES, CM_HIVE_KEY_SNAPSHOT_MAGIC, CM_HIVE_KEY_SNAPSHOT_VERSION,
    CM_HIVE_MUTATION_CHUNK_BYTES, CM_HIVE_MUTATION_RECORD_HEADER_BYTES, CM_LAUNCH_PLAN_CHUNK_BYTES,
    CM_LAUNCH_PLAN_SNAPSHOT_HEADER_BYTES, CM_LAUNCH_PLAN_SNAPSHOT_MAGIC,
    CM_LAUNCH_PLAN_SNAPSHOT_VERSION, CM_MAX_HIVE_PATH_UNITS, CM_MAX_HIVE_VALUE_NAME_UNITS,
    CM_MAX_INSTANCE_UNITS, CM_MAX_PNP_AUX_BYTES, CM_MAX_SERVICE_UNITS,
    CM_NETWORK_PLAN_SNAPSHOT_HEADER_BYTES, CM_NETWORK_PLAN_SNAPSHOT_MAGIC,
    CM_NETWORK_PLAN_SNAPSHOT_VERSION, CM_OPTIONAL_BLOB_ABSENT, CM_OPTIONAL_STRING_ABSENT,
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
const STATUS_DEVICE_NOT_READY: i32 = 0xC000_00A3u32 as i32;
const STATUS_OBJECT_PATH_SYNTAX_BAD: i32 = 0xC000_003Bu32 as i32;
const STATUS_REGISTRY_CORRUPT: i32 = 0xC000_014Cu32 as i32;
const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001Au32 as i32;
#[cfg(test)]
const STATUS_DEVICE_BUSY: i32 = 0x8000_0011u32 as i32;
const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QueryError {
    pub status: i32,
    pub required_len: usize,
}

/// One operation in an atomic, generation-checked mutation of the CM-owned SYSTEM hive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemHiveMutation<'a> {
    CreateKey {
        path: &'a str,
    },
    SetValue {
        path: &'a str,
        name: &'a str,
        value_type: u32,
        data: &'a [u8],
    },
    DeleteValue {
        path: &'a str,
        name: &'a str,
    },
    DeleteKey {
        path: &'a str,
    },
    SetKeyClass {
        path: &'a str,
        class_name: Option<&'a str>,
    },
    SetKeySecurity {
        path: &'a str,
        descriptor: &'a [u8],
    },
    /// Publish one explicit bus/PnP topology transition in the same CM generation as the
    /// accompanying Enum mutations. This marker does not directly modify a registry cell.
    PublishDeviceAction {
        kind: DeviceActionKind,
        instance_id: &'a str,
    },
}

/// One fully validated SYSTEM mutation whose CM-owned replay records must be made durable before
/// publication. The token and lengths are opaque protocol identity; callers persist
/// `durable_journal` and pass the complete value back to [`ConfigClient::publish_system_hive_mutation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedSystemHiveMutation {
    pub expected_generation: u64,
    pub next_generation: u64,
    pub lease_token: u64,
    pub semantic_journal_len: u32,
    pub durable_journal: Vec<u8>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SystemHivePublishOutcome {
    pub generation: u64,
    pub has_pending_device_action: bool,
}

/// One immutable CM-owned SYSTEM checkpoint image. The image is not acknowledged by CM until the
/// caller has atomically replaced and flushed its durable primary and replay log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedSystemHiveCheckpoint {
    pub mount_generation: u64,
    pub hive_sequence: u64,
    pub image_generation: u64,
    pub transfer_token: u64,
    pub transfer_len: u32,
    pub image: Vec<u8>,
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

/// One driver service proven to be an immediate child of the mounted SYSTEM hive's active
/// `CurrentControlSet\Services` key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveDriverServiceBinding {
    pub mount_generation: u64,
    pub physical_path: String,
    pub binding: DriverServiceBinding,
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceActionKind {
    Arrival,
    Change,
    Removal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceActionPublication {
    pub instance_id: String,
    pub service_name: Option<String>,
    pub pdo_name: Option<String>,
    pub driver_key: Option<String>,
    pub linkage_export: Option<String>,
    pub hardware_ids: Vec<String>,
    pub compatible_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceActionEvent {
    pub mount_generation: u64,
    pub sequence: u64,
    pub claim_token: u64,
    pub kind: DeviceActionKind,
    pub publication: DeviceActionPublication,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkAdapterBinding {
    pub instance_id: String,
    pub class_key_path: String,
    pub linkage_key_path: String,
    pub interface_name: String,
    pub device_name: String,
    pub tcpip_export_name: String,
    pub driver_desc: String,
    pub component_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkAdapterPlanSnapshot {
    pub mount_generation: u64,
    pub adapters: Vec<NetworkAdapterBinding>,
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

/// Opaque CM-owned identity for one open key in the mounted SYSTEM hive.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SystemHiveKeyLease {
    pub token: u64,
    pub opened_generation: u64,
}

/// A newly acquired SYSTEM key lease and its CM-resolved physical namespace identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedSystemHiveKey {
    pub lease: SystemHiveKeyLease,
    pub physical_path: String,
}

/// A SYSTEM namespace path resolved by the mounted CM generation without acquiring a key lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedSystemHivePath {
    pub mount_generation: u64,
    pub physical_path: String,
}

/// One immutable standalone hive image captured from an exact CM-owned SYSTEM key lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportedSystemHive {
    pub mount_generation: u64,
    pub image: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeasedHiveKeyInformation {
    pub mount_generation: u64,
    pub path: String,
    pub class_name: Option<String>,
    pub security_descriptor: Option<Vec<u8>>,
    pub subkey_count: u32,
    pub max_subkey_name_bytes: u32,
    pub max_subkey_class_bytes: u32,
    pub value_count: u32,
    pub max_value_name_bytes: u32,
    pub max_value_data_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeasedHiveSubkey {
    pub mount_generation: u64,
    pub index: u32,
    pub name: String,
    pub class_name: Option<String>,
    pub subkey_count: u32,
    pub max_subkey_name_bytes: u32,
    pub max_subkey_class_bytes: u32,
    pub value_count: u32,
    pub max_value_name_bytes: u32,
    pub max_value_data_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeasedHiveValue {
    pub mount_generation: u64,
    pub index: u32,
    pub name: String,
    pub value_type: u32,
    pub data: Vec<u8>,
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

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
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

enum LeasedHiveRecord {
    Key(LeasedHiveKeyInformation),
    Subkey(LeasedHiveSubkey),
    Value(LeasedHiveValue),
}

fn decode_leased_hive_record(bytes: &[u8]) -> Option<LeasedHiveRecord> {
    if bytes.len() < CM_HIVE_KEY_RECORD_HEADER_BYTES {
        return None;
    }
    let mut reader = SnapshotReader::new(bytes);
    if reader.u32()? != CM_HIVE_KEY_RECORD_MAGIC || reader.u16()? != CM_HIVE_KEY_RECORD_VERSION {
        return None;
    }
    let record_kind = reader.u16()?;
    let mount_generation = reader.u64()?;
    let index = reader.u32()?;
    if mount_generation == 0 || reader.u32()? != 0 {
        return None;
    }
    let record = match record_kind {
        leased_hive_record_kind::KEY_INFORMATION => {
            if index != 0 {
                return None;
            }
            let subkey_count = reader.u32()?;
            let max_subkey_name_bytes = reader.u32()?;
            let max_subkey_class_bytes = reader.u32()?;
            let value_count = reader.u32()?;
            let max_value_name_bytes = reader.u32()?;
            let max_value_data_bytes = reader.u32()?;
            LeasedHiveRecord::Key(LeasedHiveKeyInformation {
                mount_generation,
                path: reader.string()?,
                class_name: reader.optional_string()?,
                security_descriptor: reader.optional_blob()?,
                subkey_count,
                max_subkey_name_bytes,
                max_subkey_class_bytes,
                value_count,
                max_value_name_bytes,
                max_value_data_bytes,
            })
        }
        leased_hive_record_kind::SUBKEY_BY_INDEX => LeasedHiveRecord::Subkey(LeasedHiveSubkey {
            mount_generation,
            index,
            name: reader.string()?,
            class_name: reader.optional_string()?,
            subkey_count: reader.u32()?,
            max_subkey_name_bytes: reader.u32()?,
            max_subkey_class_bytes: reader.u32()?,
            value_count: reader.u32()?,
            max_value_name_bytes: reader.u32()?,
            max_value_data_bytes: reader.u32()?,
        }),
        leased_hive_record_kind::VALUE_BY_NAME | leased_hive_record_kind::VALUE_BY_INDEX => {
            LeasedHiveRecord::Value(LeasedHiveValue {
                mount_generation,
                index,
                name: reader.string()?,
                value_type: reader.u32()?,
                data: reader.blob()?,
            })
        }
        _ => return None,
    };
    reader.finished().then_some(record)
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

fn decode_device_action_identity(bytes: &[u8]) -> Option<(u64, u64)> {
    if bytes.len() < CM_DEVICE_ACTION_SNAPSHOT_HEADER_BYTES {
        return None;
    }
    let mut reader = SnapshotReader::new(bytes);
    if reader.u32()? != CM_DEVICE_ACTION_SNAPSHOT_MAGIC
        || reader.u16()? != CM_DEVICE_ACTION_SNAPSHOT_VERSION
    {
        return None;
    }
    let kind = reader.u16()?;
    let mount_generation = reader.u64()?;
    let sequence = reader.u64()?;
    let service_present = reader.u16()?;
    let reserved0 = reader.u16()?;
    let reserved1 = reader.u32()?;
    if !matches!(
        kind,
        device_action_kind::ARRIVAL | device_action_kind::CHANGE | device_action_kind::REMOVAL
    ) || mount_generation == 0
        || sequence == 0
        || !matches!(
            service_present,
            device_action_service::ABSENT | device_action_service::PRESENT
        )
        || reserved0 != 0
        || reserved1 != 0
    {
        return None;
    }
    Some((mount_generation, sequence))
}

fn decode_device_action_event(bytes: &[u8]) -> Option<DeviceActionEvent> {
    let (mount_generation, sequence) = decode_device_action_identity(bytes)?;
    let mut reader = SnapshotReader::new(bytes);
    if reader.u32()? != CM_DEVICE_ACTION_SNAPSHOT_MAGIC
        || reader.u16()? != CM_DEVICE_ACTION_SNAPSHOT_VERSION
    {
        return None;
    }
    let kind = match reader.u16()? {
        device_action_kind::ARRIVAL => DeviceActionKind::Arrival,
        device_action_kind::CHANGE => DeviceActionKind::Change,
        device_action_kind::REMOVAL => DeviceActionKind::Removal,
        _ => return None,
    };
    if reader.u64()? != mount_generation || reader.u64()? != sequence {
        return None;
    }
    let service_present = reader.u16()?;
    if !matches!(
        service_present,
        device_action_service::ABSENT | device_action_service::PRESENT
    ) {
        return None;
    }
    if reader.u16()? != 0 || reader.u32()? != 0 {
        return None;
    }
    let instance_id = reader.string()?;
    if instance_id.is_empty() {
        return None;
    }
    let service_name = if service_present == device_action_service::PRESENT {
        let service_name = reader.string()?;
        if service_name.is_empty() {
            return None;
        }
        Some(service_name)
    } else {
        None
    };
    let pdo_name = reader.optional_string()?;
    let driver_key = reader.optional_string()?;
    let linkage_export = reader.optional_string()?;
    let hardware_count = usize::try_from(reader.u32()?).ok()?;
    if hardware_count > reader.remaining() / core::mem::size_of::<u32>() {
        return None;
    }
    let mut hardware_ids = Vec::new();
    hardware_ids.try_reserve_exact(hardware_count).ok()?;
    for _ in 0..hardware_count {
        hardware_ids.push(reader.string()?);
    }
    let compatible_count = usize::try_from(reader.u32()?).ok()?;
    if compatible_count > reader.remaining() / core::mem::size_of::<u32>() {
        return None;
    }
    let mut compatible_ids = Vec::new();
    compatible_ids.try_reserve_exact(compatible_count).ok()?;
    for _ in 0..compatible_count {
        compatible_ids.push(reader.string()?);
    }
    reader.finished().then_some(DeviceActionEvent {
        mount_generation,
        sequence,
        claim_token: 0,
        kind,
        publication: DeviceActionPublication {
            instance_id,
            service_name,
            pdo_name,
            driver_key,
            linkage_export,
            hardware_ids,
            compatible_ids,
        },
    })
}

fn decode_network_adapter_plan(bytes: &[u8]) -> Option<NetworkAdapterPlanSnapshot> {
    if bytes.len() < CM_NETWORK_PLAN_SNAPSHOT_HEADER_BYTES {
        return None;
    }
    let mut reader = SnapshotReader::new(bytes);
    if reader.u32()? != CM_NETWORK_PLAN_SNAPSHOT_MAGIC
        || reader.u16()? != CM_NETWORK_PLAN_SNAPSHOT_VERSION
        || reader.u16()? != network_plan_kind::ADAPTER_BINDINGS
    {
        return None;
    }
    let mount_generation = reader.u64()?;
    if mount_generation == 0 {
        return None;
    }
    let adapter_count = usize::try_from(reader.u32()?).ok()?;
    if reader.u32()? != 0 {
        return None;
    }
    let mut adapters = Vec::new();
    adapters.try_reserve_exact(adapter_count).ok()?;
    for _ in 0..adapter_count {
        adapters.push(NetworkAdapterBinding {
            instance_id: reader.string()?,
            class_key_path: reader.string()?,
            linkage_key_path: reader.string()?,
            interface_name: reader.string()?,
            device_name: reader.string()?,
            tcpip_export_name: reader.string()?,
            driver_desc: reader.string()?,
            component_id: reader.string()?,
        });
    }
    reader.finished().then_some(NetworkAdapterPlanSnapshot {
        mount_generation,
        adapters,
    })
}

fn utf16_bytes(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

fn immediate_registry_child_name<'a>(path: &'a str, parent: &str) -> Option<&'a str> {
    let path = path.strip_prefix('\\')?;
    let parent = parent.strip_prefix('\\')?;
    if path.is_empty()
        || parent.is_empty()
        || path.ends_with('\\')
        || parent.ends_with('\\')
        || path.contains("\\\\")
        || parent.contains("\\\\")
    {
        return None;
    }
    let mut path_components = path.split('\\');
    for parent_component in parent.split('\\') {
        if !path_components
            .next()?
            .eq_ignore_ascii_case(parent_component)
        {
            return None;
        }
    }
    let child = path_components.next()?;
    (!child.is_empty() && path_components.next().is_none()).then_some(child)
}

fn append_hive_mutation_record(
    journal: &mut Vec<u8>,
    kind: u16,
    flags: u16,
    value_type: u32,
    path: &str,
    name: &str,
    data: &[u8],
) -> Result<(), i32> {
    let path = utf16_bytes(path);
    let name = utf16_bytes(name);
    if path.len() > CM_MAX_HIVE_PATH_UNITS * 2 || name.len() > CM_MAX_HIVE_VALUE_NAME_UNITS * 2 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let path_len_bytes = u32::try_from(path.len()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let name_len_bytes = u32::try_from(name.len()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let data_len_bytes = u32::try_from(data.len()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let additional = CM_HIVE_MUTATION_RECORD_HEADER_BYTES
        .checked_add(path.len())
        .and_then(|len| len.checked_add(name.len()))
        .and_then(|len| len.checked_add(data.len()))
        .ok_or(STATUS_INVALID_PARAMETER)?;
    journal
        .try_reserve(additional)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let header = CmHiveMutationRecord {
        kind,
        flags,
        value_type,
        path_len_bytes,
        name_len_bytes,
        data_len_bytes,
        _reserved: 0,
    };
    journal.extend_from_slice(header.as_bytes());
    journal.extend_from_slice(&path);
    journal.extend_from_slice(&name);
    journal.extend_from_slice(data);
    Ok(())
}

fn encode_hive_mutation_journal(mutations: &[SystemHiveMutation<'_>]) -> Result<Vec<u8>, i32> {
    if mutations.is_empty() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut journal = Vec::new();
    for mutation in mutations {
        match *mutation {
            SystemHiveMutation::CreateKey { path } => append_hive_mutation_record(
                &mut journal,
                hive_mutation_kind::CREATE_KEY,
                0,
                0,
                path,
                "",
                &[],
            )?,
            SystemHiveMutation::SetValue {
                path,
                name,
                value_type,
                data,
            } => append_hive_mutation_record(
                &mut journal,
                hive_mutation_kind::SET_VALUE,
                0,
                value_type,
                path,
                name,
                data,
            )?,
            SystemHiveMutation::DeleteValue { path, name } => append_hive_mutation_record(
                &mut journal,
                hive_mutation_kind::DELETE_VALUE,
                0,
                0,
                path,
                name,
                &[],
            )?,
            SystemHiveMutation::DeleteKey { path } => append_hive_mutation_record(
                &mut journal,
                hive_mutation_kind::DELETE_KEY,
                0,
                0,
                path,
                "",
                &[],
            )?,
            SystemHiveMutation::SetKeyClass { path, class_name } => {
                let class_data = class_name.map(utf16_bytes);
                append_hive_mutation_record(
                    &mut journal,
                    hive_mutation_kind::SET_KEY_CLASS,
                    if class_name.is_some() {
                        hive_mutation_flags::CLASS_PRESENT
                    } else {
                        0
                    },
                    0,
                    path,
                    "",
                    class_data.as_deref().unwrap_or(&[]),
                )?;
            }
            SystemHiveMutation::SetKeySecurity { path, descriptor } => {
                append_hive_mutation_record(
                    &mut journal,
                    hive_mutation_kind::SET_KEY_SECURITY,
                    0,
                    0,
                    path,
                    "",
                    descriptor,
                )?;
            }
            SystemHiveMutation::PublishDeviceAction { kind, instance_id } => {
                let kind = match kind {
                    DeviceActionKind::Arrival => device_action_kind::ARRIVAL,
                    DeviceActionKind::Change => device_action_kind::CHANGE,
                    DeviceActionKind::Removal => device_action_kind::REMOVAL,
                };
                append_hive_mutation_record(
                    &mut journal,
                    hive_mutation_kind::PUBLISH_DEVICE_ACTION,
                    0,
                    u32::from(kind),
                    instance_id,
                    "",
                    &[],
                )?;
            }
        }
    }
    u32::try_from(journal.len()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    Ok(journal)
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

    /// Resolve a driver service only when `service_path` names an immediate child of the mounted
    /// active `CurrentControlSet\Services` key. All leases are released before this returns.
    pub fn query_active_driver_service_by_registry_path(
        &mut self,
        service_path: &str,
    ) -> Result<ActiveDriverServiceBinding, i32> {
        const ACTIVE_SERVICES_PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Services";

        let active_services = self.open_system_hive_key_with_path(ACTIVE_SERVICES_PATH)?;
        let candidate = match self.open_system_hive_key_with_path(service_path) {
            Ok(candidate) => candidate,
            Err(status) => {
                let _ = self.close_system_hive_key(active_services.lease);
                return Err(status);
            }
        };
        let generation = active_services.lease.opened_generation;
        let validation = (|| {
            if candidate.lease.opened_generation != generation {
                return Err(STATUS_DEVICE_NOT_READY);
            }
            let service_name = immediate_registry_child_name(
                &candidate.physical_path,
                &active_services.physical_path,
            )
            .ok_or(STATUS_OBJECT_PATH_SYNTAX_BAD)?;
            let binding = self.query_driver_service(service_name)?;
            if !binding.service_name.eq_ignore_ascii_case(service_name) {
                return Err(STATUS_REGISTRY_CORRUPT);
            }
            let information = self.query_leased_system_hive_key_information(candidate.lease)?;
            if information.mount_generation != generation {
                return Err(STATUS_DEVICE_NOT_READY);
            }
            if !information
                .path
                .eq_ignore_ascii_case(&candidate.physical_path)
            {
                return Err(STATUS_REGISTRY_CORRUPT);
            }
            Ok(ActiveDriverServiceBinding {
                mount_generation: generation,
                physical_path: candidate.physical_path.clone(),
                binding,
            })
        })();

        // Both identities must be released even when one close fails. A validation failure remains
        // the primary error, while a successful validation also requires stable close generations.
        let candidate_close = self.close_system_hive_key(candidate.lease);
        let active_services_close = self.close_system_hive_key(active_services.lease);
        let resolved = match validation {
            Ok(resolved) => resolved,
            Err(status) => return Err(status),
        };
        if candidate_close? != generation || active_services_close? != generation {
            return Err(STATUS_DEVICE_NOT_READY);
        }
        Ok(resolved)
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

    /// Upload and validate `mutations` against exactly `expected_generation` of CM's mounted SYSTEM
    /// hive. No mutation is visible yet. The returned replay journal is encoded by CM from the
    /// physical control-set identity it validated and must be made durable before publication.
    pub fn prepare_system_hive_mutation(
        &mut self,
        expected_generation: u64,
        mutations: &[SystemHiveMutation<'_>],
    ) -> Result<PreparedSystemHiveMutation, i32> {
        if expected_generation == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let journal = encode_hive_mutation_journal(mutations)?;
        let journal_len = u32::try_from(journal.len()).map_err(|_| STATUS_INVALID_PARAMETER)?;
        let begin = self.hive_mutation_call(
            hive_mutation_transfer::BEGIN,
            0,
            expected_generation,
            0,
            journal_len,
            &[],
        )?;
        if begin.status != STATUS_SUCCESS
            || begin.information != 0
            || begin.detail0 != expected_generation
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
        while offset < journal.len() {
            let end = core::cmp::min(offset + CM_HIVE_MUTATION_CHUNK_BYTES, journal.len());
            let response = match self.hive_mutation_call(
                hive_mutation_transfer::APPEND,
                token,
                expected_generation,
                offset as u32,
                journal_len,
                &journal[offset..end],
            ) {
                Ok(response) => response,
                Err(status) => {
                    self.abort_hive_mutation(token, expected_generation, journal_len);
                    return Err(status);
                }
            };
            if response.status != STATUS_SUCCESS
                || response.information as usize != end - offset
                || response.detail0 != expected_generation
                || response.detail1 != token
            {
                self.abort_hive_mutation(token, expected_generation, journal_len);
                return Err(if response.status == STATUS_SUCCESS {
                    STATUS_INVALID_PARAMETER
                } else {
                    response.status
                });
            }
            offset = end;
        }
        let prepare = match self.hive_mutation_call(
            hive_mutation_transfer::PREPARE,
            token,
            expected_generation,
            journal_len,
            journal_len,
            &[],
        ) {
            Ok(response) => response,
            Err(status) => {
                self.abort_hive_mutation(token, expected_generation, journal_len);
                return Err(status);
            }
        };
        let durable_len = prepare.information as usize;
        if prepare.status != STATUS_SUCCESS
            || prepare.detail0 != expected_generation.saturating_add(1)
            || prepare.detail1 != token
        {
            self.abort_hive_mutation(token, expected_generation, journal_len);
            return Err(if prepare.status == STATUS_SUCCESS {
                STATUS_INVALID_PARAMETER
            } else {
                prepare.status
            });
        }
        let mut durable_journal = Vec::new();
        if durable_journal.try_reserve_exact(durable_len).is_err() {
            self.abort_hive_mutation(token, expected_generation, journal_len);
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let mut offset = 0usize;
        let mut chunk = [0u8; CM_HIVE_MUTATION_CHUNK_BYTES];
        while offset < durable_len {
            let capacity = core::cmp::min(chunk.len(), durable_len - offset);
            let response = match self.hive_mutation_control_call(
                hive_mutation_transfer::PULL,
                token,
                expected_generation,
                offset as u32,
                journal_len,
                capacity as u32,
                &mut chunk[..capacity],
            ) {
                Ok(response) => response,
                Err(status) => {
                    self.abort_hive_mutation(token, expected_generation, journal_len);
                    return Err(status);
                }
            };
            let written = response.information as usize;
            if response.status != STATUS_SUCCESS
                || written == 0
                || written > capacity
                || response.detail0 as usize != durable_len
                || response.detail1 != token
            {
                self.abort_hive_mutation(token, expected_generation, journal_len);
                return Err(if response.status == STATUS_SUCCESS {
                    STATUS_INVALID_PARAMETER
                } else {
                    response.status
                });
            }
            durable_journal.extend_from_slice(&chunk[..written]);
            offset += written;
        }
        Ok(PreparedSystemHiveMutation {
            expected_generation,
            next_generation: prepare.detail0,
            lease_token: token,
            semantic_journal_len: journal_len,
            durable_journal,
        })
    }

    /// Publish a prepared mutation after its CM-owned replay journal has been made durable.
    pub fn publish_system_hive_mutation(
        &mut self,
        prepared: &PreparedSystemHiveMutation,
    ) -> Result<SystemHivePublishOutcome, i32> {
        let response = self.hive_mutation_call(
            hive_mutation_transfer::COMMIT,
            prepared.lease_token,
            prepared.expected_generation,
            prepared.semantic_journal_len,
            prepared.semantic_journal_len,
            &[],
        )?;
        if response.status != STATUS_SUCCESS
            || response.information > 1
            || response.detail0 != prepared.next_generation
            || response.detail1 != prepared.lease_token
        {
            return Err(if response.status == STATUS_SUCCESS {
                STATUS_INVALID_PARAMETER
            } else {
                response.status
            });
        }
        Ok(SystemHivePublishOutcome {
            generation: response.detail0,
            has_pending_device_action: response.information != 0,
        })
    }

    /// Discard an uploaded or prepared mutation that has not been published.
    pub fn abort_prepared_system_hive_mutation(&mut self, prepared: &PreparedSystemHiveMutation) {
        self.abort_hive_mutation(
            prepared.lease_token,
            prepared.expected_generation,
            prepared.semantic_journal_len,
        );
    }

    /// Export one immutable checkpoint of the exact live SYSTEM generation. `None` means CM has no
    /// dirty sequence to checkpoint. A returned image must be made durable before acknowledgement.
    pub fn prepare_system_hive_checkpoint(
        &mut self,
        expected_generation: u64,
    ) -> Result<Option<PreparedSystemHiveCheckpoint>, i32> {
        if expected_generation == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut chunk = [0u8; CM_HIVE_CHECKPOINT_CHUNK_BYTES];
        let begin = self.hive_checkpoint_call(
            hive_checkpoint_transfer::BEGIN,
            0,
            expected_generation,
            0,
            chunk.len() as u32,
            &mut chunk,
        )?;
        if begin.status != STATUS_SUCCESS {
            return Err(begin.status);
        }
        if begin.information == 0 && begin.detail0 == expected_generation && begin.detail1 == 0 {
            return Ok(None);
        }
        let total_len = begin.detail0 as usize;
        let first_len = begin.information as usize;
        let token = begin.detail1;
        if token == 0
            || first_len == 0
            || first_len > chunk.len()
            || total_len < CM_HIVE_CHECKPOINT_HEADER_BYTES
            || first_len > total_len
            || u32::try_from(total_len).is_err()
        {
            if token != 0 {
                self.abort_hive_checkpoint(token, expected_generation);
            }
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut value = Vec::new();
        if value.try_reserve_exact(total_len).is_err() {
            self.abort_hive_checkpoint(token, expected_generation);
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        value.extend_from_slice(&chunk[..first_len]);
        while value.len() < total_len {
            let capacity = core::cmp::min(chunk.len(), total_len - value.len());
            let pull = match self.hive_checkpoint_call(
                hive_checkpoint_transfer::PULL,
                token,
                expected_generation,
                value.len() as u32,
                capacity as u32,
                &mut chunk[..capacity],
            ) {
                Ok(response) => response,
                Err(status) => {
                    self.abort_hive_checkpoint(token, expected_generation);
                    return Err(status);
                }
            };
            let written = pull.information as usize;
            if pull.status != STATUS_SUCCESS
                || written == 0
                || written > capacity
                || pull.detail0 as usize != total_len
                || pull.detail1 != token
            {
                self.abort_hive_checkpoint(token, expected_generation);
                return Err(if pull.status == STATUS_SUCCESS {
                    STATUS_INVALID_PARAMETER
                } else {
                    pull.status
                });
            }
            value.extend_from_slice(&chunk[..written]);
        }
        let Some(header) = CmHiveCheckpointHeader::from_bytes(&value) else {
            self.abort_hive_checkpoint(token, expected_generation);
            return Err(STATUS_INVALID_PARAMETER);
        };
        let image_len = header.image_len_bytes as usize;
        if header.magic != CM_HIVE_CHECKPOINT_MAGIC
            || header.version != CM_HIVE_CHECKPOINT_VERSION
            || header.header_size as usize != CM_HIVE_CHECKPOINT_HEADER_BYTES
            || header.mount_generation != expected_generation
            || header._reserved != 0
            || CM_HIVE_CHECKPOINT_HEADER_BYTES.checked_add(image_len) != Some(total_len)
        {
            self.abort_hive_checkpoint(token, expected_generation);
            return Err(STATUS_INVALID_PARAMETER);
        }
        value.copy_within(CM_HIVE_CHECKPOINT_HEADER_BYTES..total_len, 0);
        value.truncate(image_len);
        Ok(Some(PreparedSystemHiveCheckpoint {
            mount_generation: header.mount_generation,
            hive_sequence: header.hive_sequence,
            image_generation: header.image_generation,
            transfer_token: token,
            transfer_len: total_len as u32,
            image: value,
        }))
    }

    /// Acknowledge that a prepared checkpoint image and empty replay log are durable.
    pub fn acknowledge_system_hive_checkpoint(
        &mut self,
        prepared: &PreparedSystemHiveCheckpoint,
    ) -> Result<(), i32> {
        let response = self.hive_checkpoint_call(
            hive_checkpoint_transfer::ACK,
            prepared.transfer_token,
            prepared.mount_generation,
            prepared.transfer_len,
            0,
            &mut [],
        )?;
        if response.status != STATUS_SUCCESS
            || response.information != 0
            || response.detail0 != prepared.mount_generation
            || response.detail1 != prepared.transfer_token
        {
            return Err(if response.status == STATUS_SUCCESS {
                STATUS_INVALID_PARAMETER
            } else {
                response.status
            });
        }
        Ok(())
    }

    /// Discard a checkpoint whose image was not durably installed.
    pub fn abort_system_hive_checkpoint(&mut self, prepared: &PreparedSystemHiveCheckpoint) {
        self.abort_hive_checkpoint(prepared.transfer_token, prepared.mount_generation);
    }

    /// Acquire one stable CM-owned key identity from the mounted SYSTEM hive.
    pub fn open_system_hive_key(&mut self, path: &str) -> Result<SystemHiveKeyLease, i32> {
        self.open_system_hive_key_with_path(path)
            .map(|opened| opened.lease)
    }

    /// Resolve `CurrentControlSet` through CM's mounted SYSTEM identity. The target itself may be
    /// absent, which lets native create operations select their durable physical path before the
    /// mutation is submitted.
    pub fn resolve_system_hive_path(&mut self, path: &str) -> Result<ResolvedSystemHivePath, i32> {
        let path_bytes = utf16_bytes(path);
        if path_bytes.is_empty()
            || path_bytes.len() > CM_MAX_HIVE_PATH_UNITS * 2
            || path.chars().any(|ch| ch == '\0')
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let header_size = core::mem::size_of::<CmHiveKeyLeaseRequest>();
        let request_header = CmHiveKeyLeaseRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation: hive_key_lease_operation::RESOLVE,
            mount: hive_mount::SYSTEM,
            path_offset: header_size as u32,
            path_len_bytes: u32::try_from(path_bytes.len())
                .map_err(|_| STATUS_INVALID_PARAMETER)?,
            lease_token: 0,
        };
        let mut request = Vec::new();
        request
            .try_reserve_exact(header_size.saturating_add(path_bytes.len()))
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        request.extend_from_slice(request_header.as_bytes());
        request.extend_from_slice(&path_bytes);
        let mut reply_path = [0u8; CM_MAX_HIVE_PATH_UNITS * 4];
        let response = self.backend.call(
            opcode::CM_OP_SYSTEM_HIVE_KEY_LEASE,
            &request,
            &mut reply_path,
        );
        if response.status != STATUS_SUCCESS {
            return Err(response.status);
        }
        let path_len = response.information as usize;
        if response.detail0 == 0
            || response.detail1 != 0
            || path_len == 0
            || path_len > reply_path.len()
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let Ok(physical_path) = core::str::from_utf8(&reply_path[..path_len]) else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        if physical_path.chars().any(|ch| ch == '\0') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(ResolvedSystemHivePath {
            mount_generation: response.detail0,
            physical_path: String::from(physical_path),
        })
    }

    /// Acquire a stable CM-owned key identity and the physical path selected at open time.
    pub fn open_system_hive_key_with_path(
        &mut self,
        path: &str,
    ) -> Result<OpenedSystemHiveKey, i32> {
        let path_bytes = utf16_bytes(path);
        if path_bytes.is_empty()
            || path_bytes.len() > CM_MAX_HIVE_PATH_UNITS * 2
            || path.chars().any(|ch| ch == '\0')
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let header_size = core::mem::size_of::<CmHiveKeyLeaseRequest>();
        let request_header = CmHiveKeyLeaseRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation: hive_key_lease_operation::OPEN,
            mount: hive_mount::SYSTEM,
            path_offset: header_size as u32,
            path_len_bytes: u32::try_from(path_bytes.len())
                .map_err(|_| STATUS_INVALID_PARAMETER)?,
            lease_token: 0,
        };
        let mut request = Vec::new();
        request
            .try_reserve_exact(header_size.saturating_add(path_bytes.len()))
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        request.extend_from_slice(request_header.as_bytes());
        request.extend_from_slice(&path_bytes);
        let mut reply_path = [0u8; CM_MAX_HIVE_PATH_UNITS * 4];
        let response = self.backend.call(
            opcode::CM_OP_SYSTEM_HIVE_KEY_LEASE,
            &request,
            &mut reply_path,
        );
        if response.status != STATUS_SUCCESS {
            return Err(response.status);
        }
        let path_len = response.information as usize;
        if response.detail0 == 0
            || response.detail1 == 0
            || path_len == 0
            || path_len > reply_path.len()
        {
            if response.detail0 != 0 && response.detail1 != 0 {
                let _ = self.close_system_hive_key(SystemHiveKeyLease {
                    token: response.detail1,
                    opened_generation: response.detail0,
                });
            }
            return Err(STATUS_INVALID_PARAMETER);
        }
        let lease = SystemHiveKeyLease {
            token: response.detail1,
            opened_generation: response.detail0,
        };
        let Ok(physical_path) = core::str::from_utf8(&reply_path[..path_len]) else {
            let _ = self.close_system_hive_key(lease);
            return Err(STATUS_INVALID_PARAMETER);
        };
        if physical_path.chars().any(|ch| ch == '\0') {
            let _ = self.close_system_hive_key(lease);
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(OpenedSystemHiveKey {
            lease,
            physical_path: String::from(physical_path),
        })
    }

    /// Release exactly one CM-owned SYSTEM key identity.
    pub fn close_system_hive_key(&mut self, lease: SystemHiveKeyLease) -> Result<u64, i32> {
        if lease.token == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let header_size = core::mem::size_of::<CmHiveKeyLeaseRequest>();
        let request = CmHiveKeyLeaseRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation: hive_key_lease_operation::CLOSE,
            mount: hive_mount::SYSTEM,
            path_offset: 0,
            path_len_bytes: 0,
            lease_token: lease.token,
        };
        let response = self.backend.call(
            opcode::CM_OP_SYSTEM_HIVE_KEY_LEASE,
            request.as_bytes(),
            &mut [],
        );
        if response.status != STATUS_SUCCESS {
            return Err(response.status);
        }
        if response.detail0 == 0 || response.detail1 != lease.token {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(response.detail0)
    }

    /// Read a complete immutable snapshot through one CM-owned SYSTEM key identity.
    pub fn query_leased_system_hive_key(
        &mut self,
        lease: SystemHiveKeyLease,
    ) -> Result<HiveKeySnapshot, i32> {
        if lease.token == 0 {
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
            let response = match self.leased_hive_key_call(
                lease.token,
                operation,
                token,
                u32::try_from(offset).map_err(|_| STATUS_INVALID_PARAMETER)?,
                CM_HIVE_KEY_CHUNK_BYTES as u32,
                &mut reply_bytes,
            ) {
                Ok(response) => response,
                Err(status) => {
                    self.abort_leased_hive_key(lease.token, token);
                    return Err(status);
                }
            };
            if response.status != STATUS_SUCCESS {
                self.abort_leased_hive_key(lease.token, token);
                return Err(response.status);
            }
            let total = usize::try_from(response.detail0).map_err(|_| STATUS_INVALID_PARAMETER)?;
            let written = response.information as usize;
            let reply_token_valid = if token == 0 {
                response.detail1 != 0
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
                self.abort_leased_hive_key(
                    lease.token,
                    if token == 0 { response.detail1 } else { token },
                );
                return Err(STATUS_INVALID_PARAMETER);
            }
            if expected_total.is_none() {
                if value.try_reserve_exact(total).is_err() {
                    self.abort_leased_hive_key(lease.token, response.detail1);
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

    /// Export the exact leased key and its descendants as a standalone SYSTEM hive image.
    /// Unlike checkpointing, this works for clean generations and does not alter CM dirty state.
    pub fn export_leased_system_hive(
        &mut self,
        lease: SystemHiveKeyLease,
    ) -> Result<ExportedSystemHive, i32> {
        if lease.token == 0 {
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
            let response = match self.leased_hive_export_call(
                lease.token,
                operation,
                token,
                u32::try_from(offset).map_err(|_| STATUS_INVALID_PARAMETER)?,
                CM_HIVE_KEY_CHUNK_BYTES as u32,
                &mut reply_bytes,
            ) {
                Ok(response) => response,
                Err(status) => {
                    self.abort_leased_hive_export(lease.token, token);
                    return Err(status);
                }
            };
            if response.status != STATUS_SUCCESS {
                self.abort_leased_hive_export(lease.token, token);
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
            if total < CM_HIVE_EXPORT_HEADER_BYTES
                || expected_total.is_some_and(|expected| expected != total)
                || !reply_token_valid
                || written > reply_bytes.len()
                || offset.checked_add(written).is_none_or(|end| end > total)
                || (offset < total && written == 0)
            {
                self.abort_leased_hive_export(
                    lease.token,
                    if token == 0 { response.detail1 } else { token },
                );
                return Err(STATUS_INVALID_PARAMETER);
            }
            if expected_total.is_none() {
                if value.try_reserve_exact(total).is_err() {
                    self.abort_leased_hive_export(lease.token, response.detail1);
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
                expected_total = Some(total);
            }
            value.extend_from_slice(&reply_bytes[..written]);
            if value.len() == total {
                let Some(header) = CmHiveExportHeader::from_bytes(&value) else {
                    return Err(STATUS_INVALID_PARAMETER);
                };
                let image_len = header.image_len_bytes as usize;
                if header.magic != CM_HIVE_EXPORT_MAGIC
                    || header.version != CM_HIVE_EXPORT_VERSION
                    || header.header_size as usize != CM_HIVE_EXPORT_HEADER_BYTES
                    || header.mount_generation == 0
                    || header._reserved != 0
                    || CM_HIVE_EXPORT_HEADER_BYTES.checked_add(image_len) != Some(total)
                {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                value.copy_within(CM_HIVE_EXPORT_HEADER_BYTES..total, 0);
                value.truncate(image_len);
                let hive =
                    nt_hive_core::decode_image(&value).map_err(|_| STATUS_REGISTRY_CORRUPT)?;
                if hive.kind != nt_hive_core::HiveKind::System {
                    return Err(STATUS_REGISTRY_CORRUPT);
                }
                return Ok(ExportedSystemHive {
                    mount_generation: header.mount_generation,
                    image: value,
                });
            }
            if token == 0 {
                token = response.detail1;
            }
        }
    }

    pub fn query_leased_system_hive_key_information(
        &mut self,
        lease: SystemHiveKeyLease,
    ) -> Result<LeasedHiveKeyInformation, i32> {
        match decode_leased_hive_record(&self.query_leased_hive_record_bytes(
            lease,
            leased_hive_record_kind::KEY_INFORMATION,
            0,
            None,
        )?) {
            Some(LeasedHiveRecord::Key(information)) => Ok(information),
            _ => Err(STATUS_INVALID_PARAMETER),
        }
    }

    pub fn query_leased_system_hive_value(
        &mut self,
        lease: SystemHiveKeyLease,
        name: &str,
    ) -> Result<LeasedHiveValue, i32> {
        match decode_leased_hive_record(&self.query_leased_hive_record_bytes(
            lease,
            leased_hive_record_kind::VALUE_BY_NAME,
            0,
            Some(name),
        )?) {
            Some(LeasedHiveRecord::Value(value)) => Ok(value),
            _ => Err(STATUS_INVALID_PARAMETER),
        }
    }

    pub fn enumerate_leased_system_hive_subkey(
        &mut self,
        lease: SystemHiveKeyLease,
        index: u32,
    ) -> Result<LeasedHiveSubkey, i32> {
        match decode_leased_hive_record(&self.query_leased_hive_record_bytes(
            lease,
            leased_hive_record_kind::SUBKEY_BY_INDEX,
            index,
            None,
        )?) {
            Some(LeasedHiveRecord::Subkey(subkey)) if subkey.index == index => Ok(subkey),
            _ => Err(STATUS_INVALID_PARAMETER),
        }
    }

    pub fn enumerate_leased_system_hive_value(
        &mut self,
        lease: SystemHiveKeyLease,
        index: u32,
    ) -> Result<LeasedHiveValue, i32> {
        match decode_leased_hive_record(&self.query_leased_hive_record_bytes(
            lease,
            leased_hive_record_kind::VALUE_BY_INDEX,
            index,
            None,
        )?) {
            Some(LeasedHiveRecord::Value(value)) if value.index == index => Ok(value),
            _ => Err(STATUS_INVALID_PARAMETER),
        }
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

    pub fn query_network_adapter_plan(&mut self) -> Result<NetworkAdapterPlanSnapshot, i32> {
        let value = self.query_launch_plan_bytes(
            opcode::CM_OP_QUERY_NETWORK_PLAN,
            network_plan_kind::ADAPTER_BINDINGS,
            CM_NETWORK_PLAN_SNAPSHOT_HEADER_BYTES,
        )?;
        decode_network_adapter_plan(&value).ok_or(STATUS_INVALID_PARAMETER)
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

    /// Peek and stream the next immutable CM-owned device action without acknowledging it.
    pub fn next_device_action(&mut self) -> Result<Option<DeviceActionEvent>, i32> {
        let mut value = Vec::new();
        let mut expected_total = None;
        let mut identity = None;
        let mut token = 0u64;
        let mut reply_bytes = [0u8; CM_DEVICE_ACTION_CHUNK_BYTES];
        loop {
            let operation = if token == 0 {
                device_action_transfer::BEGIN
            } else {
                device_action_transfer::PULL
            };
            let offset = value.len();
            let (mount_generation, event_sequence) = identity.unwrap_or((0, 0));
            let response = self.device_action_call(
                operation,
                mount_generation,
                event_sequence,
                token,
                u32::try_from(offset).map_err(|_| STATUS_INVALID_PARAMETER)?,
                CM_DEVICE_ACTION_CHUNK_BYTES as u32,
                &mut reply_bytes,
            );
            if token == 0 && response.status == STATUS_NO_MORE_ENTRIES {
                return Ok(None);
            }
            if response.status != STATUS_SUCCESS {
                self.abort_device_action(mount_generation, event_sequence, token);
                return Err(response.status);
            }
            let total = usize::try_from(response.detail0).map_err(|_| STATUS_INVALID_PARAMETER)?;
            let written = response.information as usize;
            let reply_token_valid = if token == 0 {
                response.detail1 != 0
            } else {
                response.detail1 == token
            };
            if total < CM_DEVICE_ACTION_SNAPSHOT_HEADER_BYTES
                || expected_total.is_some_and(|expected| expected != total)
                || !reply_token_valid
                || written > reply_bytes.len()
                || offset.checked_add(written).is_none_or(|end| end > total)
                || (offset < total && written == 0)
            {
                self.abort_device_action(
                    mount_generation,
                    event_sequence,
                    if token == 0 { response.detail1 } else { token },
                );
                return Err(STATUS_INVALID_PARAMETER);
            }
            if expected_total.is_none() {
                let Some(first_identity) = decode_device_action_identity(&reply_bytes[..written])
                else {
                    self.abort_device_action(0, 0, response.detail1);
                    return Err(STATUS_INVALID_PARAMETER);
                };
                if value.try_reserve_exact(total).is_err() {
                    self.abort_device_action(first_identity.0, first_identity.1, response.detail1);
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
                identity = Some(first_identity);
                expected_total = Some(total);
                token = response.detail1;
            }
            value.extend_from_slice(&reply_bytes[..written]);
            if value.len() == total {
                let mut event =
                    decode_device_action_event(&value).ok_or(STATUS_INVALID_PARAMETER)?;
                if Some((event.mount_generation, event.sequence)) != identity {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                event.claim_token = token;
                return Ok(Some(event));
            }
        }
    }

    /// Retire only the exact journal head after its PnP action has reached a terminal state.
    pub fn acknowledge_device_action(&mut self, event: &DeviceActionEvent) -> Result<bool, i32> {
        if event.mount_generation == 0 || event.sequence == 0 || event.claim_token == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let response = self.device_action_call(
            device_action_transfer::ACK,
            event.mount_generation,
            event.sequence,
            event.claim_token,
            0,
            0,
            &mut [],
        );
        if response.status != STATUS_SUCCESS {
            return Err(response.status);
        }
        if response.detail0 < event.mount_generation || response.detail1 != event.sequence {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if response.information > 1 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(response.information != 0)
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

    fn hive_mutation_call(
        &mut self,
        operation: u16,
        lease_token: u64,
        expected_generation: u64,
        journal_offset: u32,
        journal_len_bytes: u32,
        chunk: &[u8],
    ) -> Result<CmReply, i32> {
        if chunk.len() > CM_HIVE_MUTATION_CHUNK_BYTES {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let header_size = core::mem::size_of::<CmHiveMutationRequest>();
        let chunk_offset = if chunk.is_empty() {
            0
        } else {
            header_size as u32
        };
        let header = CmHiveMutationRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            mount: hive_mount::SYSTEM,
            journal_offset,
            chunk_offset,
            chunk_len_bytes: u32::try_from(chunk.len()).map_err(|_| STATUS_INVALID_PARAMETER)?,
            journal_len_bytes,
            expected_generation,
            lease_token,
        };
        let mut request = Vec::new();
        request
            .try_reserve_exact(header_size.saturating_add(chunk.len()))
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        request.extend_from_slice(header.as_bytes());
        request.extend_from_slice(chunk);
        Ok(self
            .backend
            .call(opcode::CM_OP_MUTATE_SYSTEM_HIVE, &request, &mut []))
    }

    fn hive_mutation_control_call(
        &mut self,
        operation: u16,
        lease_token: u64,
        expected_generation: u64,
        journal_offset: u32,
        journal_len_bytes: u32,
        chunk_capacity: u32,
        reply_bytes: &mut [u8],
    ) -> Result<CmReply, i32> {
        if chunk_capacity == 0
            || chunk_capacity as usize > CM_HIVE_MUTATION_CHUNK_BYTES
            || chunk_capacity as usize > reply_bytes.len()
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let header_size = core::mem::size_of::<CmHiveMutationRequest>();
        let header = CmHiveMutationRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            mount: hive_mount::SYSTEM,
            journal_offset,
            chunk_offset: 0,
            chunk_len_bytes: chunk_capacity,
            journal_len_bytes,
            expected_generation,
            lease_token,
        };
        Ok(self.backend.call(
            opcode::CM_OP_MUTATE_SYSTEM_HIVE,
            header.as_bytes(),
            reply_bytes,
        ))
    }

    fn abort_hive_mutation(
        &mut self,
        lease_token: u64,
        expected_generation: u64,
        journal_len_bytes: u32,
    ) {
        if lease_token == 0 {
            return;
        }
        let _ = self.hive_mutation_call(
            hive_mutation_transfer::ABORT,
            lease_token,
            expected_generation,
            0,
            journal_len_bytes,
            &[],
        );
    }

    fn hive_checkpoint_call(
        &mut self,
        operation: u16,
        transfer_token: u64,
        expected_generation: u64,
        value_offset: u32,
        chunk_capacity: u32,
        out: &mut [u8],
    ) -> Result<CmReply, i32> {
        if chunk_capacity as usize > CM_HIVE_CHECKPOINT_CHUNK_BYTES
            || chunk_capacity as usize > out.len()
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
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
        Ok(self
            .backend
            .call(opcode::CM_OP_CHECKPOINT_SYSTEM_HIVE, header.as_bytes(), out))
    }

    fn abort_hive_checkpoint(&mut self, transfer_token: u64, expected_generation: u64) {
        let _ = self.hive_checkpoint_call(
            hive_checkpoint_transfer::ABORT,
            transfer_token,
            expected_generation,
            0,
            0,
            &mut [],
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

    fn leased_hive_key_call(
        &mut self,
        key_lease_token: u64,
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
        reply_bytes: &mut [u8],
    ) -> Result<CmReply, i32> {
        if key_lease_token == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let header_size = core::mem::size_of::<CmLeasedHiveKeyRequest>();
        let request = CmLeasedHiveKeyRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            mount: hive_mount::SYSTEM,
            value_offset,
            chunk_capacity,
            key_lease_token,
            transfer_token,
        };
        Ok(self.backend.call(
            opcode::CM_OP_QUERY_LEASED_HIVE_KEY,
            request.as_bytes(),
            reply_bytes,
        ))
    }

    fn leased_hive_export_call(
        &mut self,
        key_lease_token: u64,
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
        reply_bytes: &mut [u8],
    ) -> Result<CmReply, i32> {
        if key_lease_token == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let header_size = core::mem::size_of::<CmLeasedHiveKeyRequest>();
        let request = CmLeasedHiveKeyRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            mount: hive_mount::SYSTEM,
            value_offset,
            chunk_capacity,
            key_lease_token,
            transfer_token,
        };
        Ok(self.backend.call(
            opcode::CM_OP_EXPORT_LEASED_HIVE,
            request.as_bytes(),
            reply_bytes,
        ))
    }

    fn abort_leased_hive_export(&mut self, key_lease_token: u64, transfer_token: u64) {
        if key_lease_token == 0 || transfer_token == 0 {
            return;
        }
        let _ = self.leased_hive_export_call(
            key_lease_token,
            hive_key_transfer::ABORT,
            transfer_token,
            0,
            0,
            &mut [],
        );
    }

    fn abort_leased_hive_key(&mut self, key_lease_token: u64, transfer_token: u64) {
        if key_lease_token == 0 || transfer_token == 0 {
            return;
        }
        let _ = self.leased_hive_key_call(
            key_lease_token,
            hive_key_transfer::ABORT,
            transfer_token,
            0,
            0,
            &mut [],
        );
    }

    fn query_leased_hive_record_bytes(
        &mut self,
        lease: SystemHiveKeyLease,
        record_kind: u16,
        index: u32,
        name: Option<&str>,
    ) -> Result<Vec<u8>, i32> {
        if lease.token == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let name_bytes = match name {
            Some(name)
                if !name.chars().any(|ch| ch == '\0')
                    && name.encode_utf16().count() <= CM_MAX_HIVE_VALUE_NAME_UNITS =>
            {
                Some(utf16_bytes(name))
            }
            Some(_) => return Err(STATUS_INVALID_PARAMETER),
            None => None,
        };
        let mut value = Vec::new();
        let mut expected_total = None;
        let mut token = 0u64;
        let mut reply_bytes = [0u8; CM_HIVE_KEY_CHUNK_BYTES];
        loop {
            let begin = token == 0;
            let operation = if begin {
                hive_key_transfer::BEGIN
            } else {
                hive_key_transfer::PULL
            };
            let offset = value.len();
            let response = match self.leased_hive_record_call(
                lease.token,
                operation,
                token,
                u32::try_from(offset).map_err(|_| STATUS_INVALID_PARAMETER)?,
                CM_HIVE_KEY_CHUNK_BYTES as u32,
                if begin { record_kind } else { 0 },
                if begin { index } else { 0 },
                if begin { name_bytes.as_deref() } else { None },
                &mut reply_bytes,
            ) {
                Ok(response) => response,
                Err(status) => {
                    self.abort_leased_hive_record(lease.token, token);
                    return Err(status);
                }
            };
            if response.status != STATUS_SUCCESS {
                self.abort_leased_hive_record(lease.token, token);
                return Err(response.status);
            }
            let total = usize::try_from(response.detail0).map_err(|_| STATUS_INVALID_PARAMETER)?;
            let written = response.information as usize;
            let reply_token_valid = if begin {
                (written == total && response.detail1 == 0)
                    || (written < total && response.detail1 != 0)
            } else {
                response.detail1 == token
            };
            if total < CM_HIVE_KEY_RECORD_HEADER_BYTES
                || expected_total.is_some_and(|expected| expected != total)
                || !reply_token_valid
                || written > reply_bytes.len()
                || offset.checked_add(written).is_none_or(|end| end > total)
                || (offset < total && written == 0)
            {
                self.abort_leased_hive_record(
                    lease.token,
                    if begin { response.detail1 } else { token },
                );
                return Err(STATUS_INVALID_PARAMETER);
            }
            if expected_total.is_none() {
                if value.try_reserve_exact(total).is_err() {
                    self.abort_leased_hive_record(lease.token, response.detail1);
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
                expected_total = Some(total);
            }
            value.extend_from_slice(&reply_bytes[..written]);
            if value.len() == total {
                return Ok(value);
            }
            if begin {
                token = response.detail1;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn leased_hive_record_call(
        &mut self,
        key_lease_token: u64,
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
        record_kind: u16,
        index: u32,
        name_bytes: Option<&[u8]>,
        reply_bytes: &mut [u8],
    ) -> Result<CmReply, i32> {
        if key_lease_token == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let header_size = core::mem::size_of::<CmLeasedHiveRecordRequest>();
        let name_offset = name_bytes.map_or(0, |_| header_size as u32);
        let request_header = CmLeasedHiveRecordRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            mount: hive_mount::SYSTEM,
            key_lease_token,
            transfer_token,
            value_offset,
            chunk_capacity,
            index,
            name_offset,
            name_len_bytes: u32::try_from(name_bytes.map_or(0, <[u8]>::len))
                .map_err(|_| STATUS_INVALID_PARAMETER)?,
            record_kind,
            _reserved: 0,
        };
        let mut request = Vec::new();
        request
            .try_reserve_exact(header_size.saturating_add(name_bytes.map_or(0, <[u8]>::len)))
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        request.extend_from_slice(request_header.as_bytes());
        if let Some(name_bytes) = name_bytes {
            request.extend_from_slice(name_bytes);
        }
        Ok(self.backend.call(
            opcode::CM_OP_QUERY_LEASED_HIVE_RECORD,
            &request,
            reply_bytes,
        ))
    }

    fn abort_leased_hive_record(&mut self, key_lease_token: u64, transfer_token: u64) {
        if key_lease_token == 0 || transfer_token == 0 {
            return;
        }
        let _ = self.leased_hive_record_call(
            key_lease_token,
            hive_key_transfer::ABORT,
            transfer_token,
            0,
            0,
            0,
            0,
            None,
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

    fn device_action_call(
        &mut self,
        operation: u16,
        mount_generation: u64,
        event_sequence: u64,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
        reply_bytes: &mut [u8],
    ) -> CmReply {
        let header_size = core::mem::size_of::<CmDeviceActionRequest>();
        let request = CmDeviceActionRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            _reserved: 0,
            value_offset,
            chunk_capacity,
            mount_generation,
            event_sequence,
            transfer_token,
        };
        self.backend
            .call(opcode::CM_OP_DEVICE_ACTION, request.as_bytes(), reply_bytes)
    }

    fn abort_device_action(
        &mut self,
        mount_generation: u64,
        event_sequence: u64,
        transfer_token: u64,
    ) {
        if mount_generation == 0 || event_sequence == 0 || transfer_token == 0 {
            return;
        }
        let _ = self.device_action_call(
            device_action_transfer::ABORT,
            mount_generation,
            event_sequence,
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
        device_property, encode_multi_sz, encode_sz, ConfigManager, RegistryValueType, ENUM_PATH,
        SERVICE_AUTO_START, SERVICE_BOOT_START, SERVICE_DEMAND_START, SERVICE_FILE_SYSTEM_DRIVER,
        SERVICE_INTERACTIVE_PROCESS, SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_WIN32_SHARE_PROCESS,
    };
    use nt_config_server::CmServer;
    use nt_hive_core::{decode_image, encode_image, try_replay_log, Hive, HiveKind};

    /// In-process backend: dispatch straight into the server (no ring).
    struct Direct {
        server: CmServer,
    }

    struct TrackingDirect {
        server: CmServer,
        successful_opens: usize,
        successful_closes: usize,
        skew_second_open_generation: bool,
        skew_first_close_generation: bool,
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
    impl Backend for TrackingDirect {
        fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> CmReply {
            let lease_operation = if opcode == opcode::CM_OP_SYSTEM_HIVE_KEY_LEASE {
                CmHiveKeyLeaseRequest::from_bytes(in_buf).map(|request| request.operation)
            } else {
                None
            };
            let mut reply = self.server.dispatch(opcode, in_buf, out_buf);
            if reply.status == STATUS_SUCCESS {
                match lease_operation {
                    Some(hive_key_lease_operation::OPEN) => {
                        self.successful_opens += 1;
                        if self.skew_second_open_generation && self.successful_opens == 2 {
                            reply.detail0 = reply.detail0.saturating_add(1);
                        }
                    }
                    Some(hive_key_lease_operation::CLOSE) => {
                        self.successful_closes += 1;
                        if self.skew_first_close_generation && self.successful_closes == 1 {
                            reply.detail0 = reply.detail0.saturating_add(1);
                        }
                    }
                    _ => {}
                }
            }
            reply
        }
    }

    fn client() -> ConfigClient<Direct> {
        client_with_server(CmServer::new())
    }

    fn client_with_server(server: CmServer) -> ConfigClient<Direct> {
        ConfigClient::new(Direct { server })
    }

    fn tracking_client(
        skew_second_open_generation: bool,
        skew_first_close_generation: bool,
    ) -> ConfigClient<TrackingDirect> {
        ConfigClient::new(TrackingDirect {
            server: CmServer::new(),
            successful_opens: 0,
            successful_closes: 0,
            skew_second_open_generation,
            skew_first_close_generation,
        })
    }

    fn active_driver_service_identity_hive() -> Hive {
        let mut hive = Hive::new(HiveKind::System);
        let select = hive.create_key("Select");
        hive.set_dword(select, "Current", 2);
        for (control_set, image_path) in [
            ("ControlSet001", r"system32\drivers\inactive.sys"),
            ("ControlSet002", r"system32\drivers\active.sys"),
        ] {
            let service = hive.create_key(&format!(r"{control_set}\Services\Stable"));
            hive.set_dword(service, "Type", SERVICE_KERNEL_DRIVER);
            hive.set_dword(service, "Start", SERVICE_DEMAND_START);
            assert!(hive.set_value(
                service,
                "ImagePath",
                RegistryValueType::ExpandSz,
                encode_sz(image_path),
            ));
        }
        hive.create_key(r"ControlSet002\Services\Stable\Parameters");
        hive.finish_clean_import();
        hive
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
    fn system_key_lease_preserves_physical_identity_until_close_or_mount_replacement() {
        const STATUS_INVALID_HANDLE: i32 = 0xC000_0008u32 as i32;
        const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001Au32 as i32;

        let mut hive = Hive::new(HiveKind::System);
        let select = hive.create_key("Select");
        hive.set_dword(select, "Current", 1);
        let first = hive.create_key(r"ControlSet001\Services\Stable");
        hive.set_dword(first, "Identity", 1);
        let large_value = vec![0x5Au8; CM_HIVE_KEY_CHUNK_BYTES * 2 + 97];
        assert!(hive.set_value(
            first,
            "LargeValue",
            RegistryValueType::Binary,
            large_value.clone(),
        ));
        assert!(hive.set_key_class(first, Some("StableClass")));
        assert!(hive.set_key_security_descriptor(first, b"stable-security"));
        let child = hive.create_key(r"ControlSet001\Services\Stable\Child");
        assert!(hive.set_key_class(child, Some("ChildClass")));
        let grandchild = hive.create_subkey(child, "Grandchild");
        assert!(hive.set_key_class(grandchild, Some("GrandchildClass")));
        hive.set_dword(child, "ChildValue", 7);
        let second = hive.create_key(r"ControlSet002\Services\Stable");
        hive.set_dword(second, "Identity", 2);
        hive.finish_clean_import();

        let mut client = client();
        assert_eq!(client.import_system_hive(&encode_image(&hive)), Ok(1));
        assert_eq!(client.prepare_system_hive_checkpoint(1), Ok(None));
        let root = client
            .open_system_hive_key(r"\Registry\Machine\System")
            .unwrap();
        let exported_root = client.export_leased_system_hive(root).unwrap();
        assert_eq!(exported_root.mount_generation, 1);
        let decoded_root = decode_image(&exported_root.image).unwrap();
        assert_eq!(decoded_root.kind, HiveKind::System);
        assert!(decoded_root
            .open_key(r"ControlSet001\Services\Stable")
            .is_some());
        assert!(decoded_root
            .open_key(r"ControlSet002\Services\Stable")
            .is_some());
        assert_eq!(client.prepare_system_hive_checkpoint(1), Ok(None));
        assert_eq!(client.close_system_hive_key(root), Ok(1));
        let resolved_absent = client
            .resolve_system_hive_path(
                r"\Registry\Machine\System\CurrentControlSet\Services\Absent\Child",
            )
            .unwrap();
        assert_eq!(resolved_absent.mount_generation, 1);
        assert_eq!(
            resolved_absent.physical_path,
            r"\Registry\Machine\System\ControlSet001\Services\Absent\Child"
        );
        let resolved_explicit = client
            .resolve_system_hive_path(r"\Registry\Machine\System\ControlSet002\Services\Absent")
            .unwrap();
        assert_eq!(
            resolved_explicit.physical_path,
            r"\Registry\Machine\System\ControlSet002\Services\Absent"
        );
        assert_eq!(
            client.resolve_system_hive_path(r"\Registry\Machine\Software\WrongHive"),
            Err(STATUS_INVALID_PARAMETER)
        );
        let opened = client
            .open_system_hive_key_with_path(
                r"\Registry\Machine\System\CurrentControlSet\Services\Stable",
            )
            .unwrap();
        assert_eq!(
            opened.physical_path,
            r"\Registry\Machine\System\ControlSet001\Services\Stable"
        );
        let lease = opened.lease;
        assert_eq!(lease.opened_generation, 1);
        let exported = client.export_leased_system_hive(lease).unwrap();
        assert_eq!(exported.mount_generation, 1);
        let exported_hive = decode_image(&exported.image).unwrap();
        assert_eq!(
            exported_hive.key_class(exported_hive.root()),
            Some("StableClass")
        );
        assert!(exported_hive.open_key("Child\\Grandchild").is_some());
        assert!(exported_hive
            .open_key(r"ControlSet002\Services\Stable")
            .is_none());
        let information = client
            .query_leased_system_hive_key_information(lease)
            .unwrap();
        assert_eq!(information.mount_generation, 1);
        assert_eq!(information.path, opened.physical_path);
        assert_eq!(information.class_name.as_deref(), Some("StableClass"));
        assert_eq!(
            information.security_descriptor.as_deref(),
            Some(&b"stable-security"[..])
        );
        assert_eq!(information.subkey_count, 1);
        assert_eq!(information.value_count, 2);
        assert_eq!(information.max_value_data_bytes, large_value.len() as u32);
        let named = client
            .query_leased_system_hive_value(lease, "identity")
            .unwrap();
        assert_eq!(named.mount_generation, 1);
        assert_eq!(named.name, "Identity");
        assert_eq!(named.value_type, RegistryValueType::Dword as u32);
        assert_eq!(named.data, 1u32.to_le_bytes());
        let large = client
            .query_leased_system_hive_value(lease, "LargeValue")
            .unwrap();
        assert_eq!(large.data, large_value);
        let subkey = client
            .enumerate_leased_system_hive_subkey(lease, 0)
            .unwrap();
        assert_eq!(subkey.name, "Child");
        assert_eq!(subkey.class_name.as_deref(), Some("ChildClass"));
        assert_eq!(subkey.subkey_count, 1);
        assert_eq!(subkey.max_subkey_name_bytes, 20);
        assert_eq!(subkey.max_subkey_class_bytes, 30);
        assert_eq!(subkey.value_count, 1);
        assert_eq!(subkey.max_value_name_bytes, 20);
        assert_eq!(subkey.max_value_data_bytes, 4);
        assert_eq!(
            client.enumerate_leased_system_hive_subkey(lease, 1),
            Err(STATUS_NO_MORE_ENTRIES)
        );
        let value = client.enumerate_leased_system_hive_value(lease, 0).unwrap();
        assert_eq!(value.name, "Identity");
        assert_eq!(value.data, 1u32.to_le_bytes());
        assert_eq!(
            client.enumerate_leased_system_hive_value(lease, 2),
            Err(STATUS_NO_MORE_ENTRIES)
        );
        let leased = client.query_leased_system_hive_key(lease).unwrap();
        assert_eq!(
            leased.path,
            r"\Registry\Machine\System\ControlSet001\Services\Stable"
        );
        assert_eq!(leased.mount_generation, 1);

        let prepared = client
            .prepare_system_hive_mutation(
                1,
                &[
                    SystemHiveMutation::SetValue {
                        path: r"\Registry\Machine\System\ControlSet001\Services\Stable",
                        name: "LeasedMutation",
                        value_type: RegistryValueType::Dword as u32,
                        data: &17u32.to_le_bytes(),
                    },
                    SystemHiveMutation::SetValue {
                        path: r"\Registry\Machine\System\Select",
                        name: "Current",
                        value_type: RegistryValueType::Dword as u32,
                        data: &2u32.to_le_bytes(),
                    },
                ],
            )
            .unwrap();
        let outcome = client.publish_system_hive_mutation(&prepared).unwrap();
        assert_eq!(outcome.generation, 2);
        assert!(!outcome.has_pending_device_action);
        let resolved_after_selection_change = client
            .resolve_system_hive_path(r"\Registry\Machine\System\CurrentControlSet\Services\Absent")
            .unwrap();
        assert_eq!(resolved_after_selection_change.mount_generation, 2);
        assert_eq!(
            resolved_after_selection_change.physical_path,
            r"\Registry\Machine\System\ControlSet002\Services\Absent"
        );

        let leased = client.query_leased_system_hive_key(lease).unwrap();
        assert_eq!(leased.mount_generation, 2);
        assert_eq!(
            leased.path,
            r"\Registry\Machine\System\ControlSet001\Services\Stable"
        );
        assert!(leased
            .values
            .iter()
            .any(|value| value.name == "LeasedMutation"));
        let selected = client
            .query_system_hive_key(r"\Registry\Machine\System\CurrentControlSet\Services\Stable")
            .unwrap();
        assert!(selected.path.contains("CurrentControlSet"));
        assert_eq!(
            selected
                .values
                .iter()
                .find(|value| value.name == "Identity")
                .map(|value| value.data.as_slice()),
            Some(2u32.to_le_bytes().as_slice())
        );

        assert_eq!(client.close_system_hive_key(lease), Ok(2));
        assert_eq!(
            client.query_leased_system_hive_key(lease),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            client.export_leased_system_hive(lease),
            Err(STATUS_INVALID_HANDLE)
        );

        let stale = client
            .open_system_hive_key(r"\Registry\Machine\System\ControlSet002\Services\Stable")
            .unwrap();
        assert_eq!(client.import_system_hive(&encode_image(&hive)), Ok(3));
        assert_eq!(
            client.query_leased_system_hive_key(stale),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            client.close_system_hive_key(stale),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    #[test]
    fn system_hive_mutation_is_streamed_atomic_and_updates_semantic_views() {
        const STATUS_REVISION_MISMATCH: i32 = 0xC000_0059u32 as i32;
        const STATUS_CANNOT_DELETE: i32 = 0xC000_0121u32 as i32;
        const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;

        let mut hive = Hive::new(HiveKind::System);
        let select = hive.create_key("Select");
        hive.set_dword(select, "Current", 1);
        let existing = hive.create_key(r"ControlSet001\Services\Existing");
        hive.set_dword(existing, "DeleteMe", 1);
        hive.create_subkey(existing, "Child");
        let obsolete = hive.create_key(r"ControlSet001\Services\Obsolete");
        hive.set_dword(obsolete, "Value", 1);
        hive.finish_clean_import();
        let mut replayed = hive.clone();

        let mut client = ConfigClient::new(Framed {
            server: CmServer::new(),
        });
        assert_eq!(client.import_system_hive(&encode_image(&hive)), Ok(1));

        let service_path = r"\Registry\Machine\System\CurrentControlSet\Services\DynamicService";
        let existing_path = r"\Registry\Machine\System\CurrentControlSet\Services\Existing";
        let obsolete_path = r"\Registry\Machine\System\CurrentControlSet\Services\Obsolete";
        let image = encode_sz(r"system32\dynamic.exe /service");
        let payload = vec![0x5a; CM_HIVE_MUTATION_CHUNK_BYTES * 2 + 37];
        let security = vec![0xa5; 96];
        let prepared = client
            .prepare_system_hive_mutation(
                1,
                &[
                    SystemHiveMutation::CreateKey { path: service_path },
                    SystemHiveMutation::SetValue {
                        path: service_path,
                        name: "Type",
                        value_type: RegistryValueType::Dword as u32,
                        data: &SERVICE_WIN32_OWN_PROCESS.to_le_bytes(),
                    },
                    SystemHiveMutation::SetValue {
                        path: service_path,
                        name: "Start",
                        value_type: RegistryValueType::Dword as u32,
                        data: &SERVICE_AUTO_START.to_le_bytes(),
                    },
                    SystemHiveMutation::SetValue {
                        path: service_path,
                        name: "ImagePath",
                        value_type: RegistryValueType::ExpandSz as u32,
                        data: &image,
                    },
                    SystemHiveMutation::SetValue {
                        path: service_path,
                        name: "Payload",
                        value_type: RegistryValueType::Binary as u32,
                        data: &payload,
                    },
                    SystemHiveMutation::SetKeyClass {
                        path: service_path,
                        class_name: Some("ServiceClass"),
                    },
                    SystemHiveMutation::SetKeySecurity {
                        path: service_path,
                        descriptor: &security,
                    },
                    SystemHiveMutation::DeleteValue {
                        path: existing_path,
                        name: "DeleteMe",
                    },
                    SystemHiveMutation::DeleteKey {
                        path: obsolete_path,
                    },
                ],
            )
            .unwrap();
        assert_eq!(prepared.expected_generation, 1);
        assert_eq!(prepared.next_generation, 2);
        assert!(prepared.durable_journal.len() > CM_HIVE_MUTATION_CHUNK_BYTES);
        assert_eq!(
            client.query_system_hive_key(service_path),
            Err(STATUS_OBJECT_NAME_NOT_FOUND),
            "a prepared mutation must remain invisible until storage acknowledges it"
        );
        let replayed_sequence =
            try_replay_log(&mut replayed, &prepared.durable_journal, 0).unwrap();
        assert!(replayed_sequence != 0);
        let replayed_service = replayed
            .open_key(r"ControlSet001\Services\DynamicService")
            .unwrap();
        assert_eq!(
            replayed.query_value(replayed_service, "Payload").unwrap().1,
            payload.as_slice()
        );
        assert!(replayed
            .open_key(r"ControlSet001\Services\Obsolete")
            .is_none());

        let outcome = client.publish_system_hive_mutation(&prepared).unwrap();
        assert_eq!(outcome.generation, 2);
        assert!(!outcome.has_pending_device_action);

        let snapshot = client.query_system_hive_key(service_path).unwrap();
        assert_eq!(snapshot.mount_generation, 2);
        assert_eq!(snapshot.class_name.as_deref(), Some("ServiceClass"));
        assert_eq!(
            snapshot.security_descriptor.as_deref(),
            Some(security.as_slice())
        );
        assert_eq!(
            snapshot
                .values
                .iter()
                .find(|value| value.name == "Payload")
                .map(|value| value.data.as_slice()),
            Some(payload.as_slice())
        );
        assert!(client
            .query_system_hive_key(existing_path)
            .unwrap()
            .values
            .iter()
            .all(|value| value.name != "DeleteMe"));
        assert_eq!(
            client.query_system_hive_key(obsolete_path),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        let services = client
            .query_win32_service_launch_plan(win32_service_plan_kind::AUTO_START)
            .unwrap();
        assert_eq!(services.mount_generation, 2);
        assert_eq!(services.launches.len(), 1);
        assert_eq!(services.launches[0].service_name, "DynamicService");

        let checkpoint = client
            .prepare_system_hive_checkpoint(2)
            .unwrap()
            .expect("dirty SYSTEM checkpoint");
        assert!(checkpoint.image.len() > CM_HIVE_CHECKPOINT_CHUNK_BYTES);
        let checkpoint_hive = decode_image(&checkpoint.image).unwrap();
        assert_eq!(checkpoint_hive.sequence, checkpoint.hive_sequence);
        assert_eq!(checkpoint_hive.generation, checkpoint.image_generation);
        assert_eq!(
            client.prepare_system_hive_checkpoint(2),
            Err(STATUS_DEVICE_BUSY)
        );
        client.abort_system_hive_checkpoint(&checkpoint);
        let checkpoint = client
            .prepare_system_hive_checkpoint(2)
            .unwrap()
            .expect("aborted checkpoint must remain dirty");
        client
            .acknowledge_system_hive_checkpoint(&checkpoint)
            .unwrap();
        assert_eq!(client.prepare_system_hive_checkpoint(2), Ok(None));

        let rejected_path = r"\Registry\Machine\System\CurrentControlSet\Services\MustRemainAbsent";
        assert_eq!(
            client.prepare_system_hive_mutation(
                2,
                &[
                    SystemHiveMutation::CreateKey {
                        path: rejected_path,
                    },
                    SystemHiveMutation::DeleteKey {
                        path: existing_path,
                    },
                ],
            ),
            Err(STATUS_CANNOT_DELETE)
        );
        assert_eq!(
            client.query_system_hive_key(rejected_path),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            client.prepare_system_hive_mutation(
                1,
                &[SystemHiveMutation::CreateKey {
                    path: rejected_path,
                }],
            ),
            Err(STATUS_REVISION_MISMATCH)
        );
        assert_eq!(
            client
                .query_system_hive_key(service_path)
                .unwrap()
                .mount_generation,
            2
        );
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
            if name == "BootDevice" {
                assert!(hive.set_value(
                    service,
                    "ClassGUID",
                    nt_hive_core::RegistryValueType::Sz,
                    encode_sz("{4d36e972-e325-11ce-bfc1-08002be10318}"),
                ));
            }
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
            if service == "BootDevice" {
                assert!(hive.set_value(
                    devnode,
                    "Driver",
                    nt_hive_core::RegistryValueType::Sz,
                    encode_sz(r"{4d36e972-e325-11ce-bfc1-08002be10318}\0001"),
                ));
            }
        }
        let net_class = hive
            .create_key(r"ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001");
        for (name, value) in [("NetCfgInstanceId", "NIC_BOOT"), ("DriverDesc", "Boot NIC")] {
            assert!(hive.set_value(
                net_class,
                name,
                nt_hive_core::RegistryValueType::Sz,
                encode_sz(value),
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
        let network = client
            .query_network_adapter_plan()
            .expect("network adapter plan");
        assert_eq!(network.mount_generation, 1);
        assert_eq!(network.adapters.len(), 1);
        assert_eq!(network.adapters[0].instance_id, r"ROOT\BOOTDEV\0000");
        assert_eq!(network.adapters[0].interface_name, "NIC_BOOT");
        assert_eq!(network.adapters[0].device_name, r"\Device\NIC_BOOT");
        assert_eq!(network.adapters[0].driver_desc, "Boot NIC");
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
    fn active_driver_service_registry_path_requires_exact_active_physical_child() {
        const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;

        let mut client = tracking_client(false, false);
        assert_eq!(
            client.import_system_hive(&encode_image(&active_driver_service_identity_hive())),
            Ok(1)
        );

        let resolved = client
            .query_active_driver_service_by_registry_path(
                r"\Registry\Machine\System\CurrentControlSet\Services\stable",
            )
            .unwrap();
        assert_eq!(resolved.mount_generation, 1);
        assert!(resolved
            .physical_path
            .eq_ignore_ascii_case(r"\Registry\Machine\System\ControlSet002\Services\Stable"));
        assert_eq!(resolved.binding.service_name, "Stable");
        assert_eq!(resolved.binding.image_path, r"system32\drivers\active.sys");

        let direct_active = client
            .query_active_driver_service_by_registry_path(
                r"\registry\machine\system\controlset002\services\STABLE",
            )
            .unwrap();
        assert_eq!(direct_active.binding.service_name, "Stable");
        assert_eq!(
            client.query_active_driver_service_by_registry_path(
                r"\Registry\Machine\System\ControlSet001\Services\Stable",
            ),
            Err(STATUS_OBJECT_PATH_SYNTAX_BAD)
        );
        assert_eq!(
            client.query_active_driver_service_by_registry_path(
                r"\Registry\Machine\System\CurrentControlSet\Services\Stable\Parameters",
            ),
            Err(STATUS_OBJECT_PATH_SYNTAX_BAD)
        );
        assert_eq!(
            client.query_active_driver_service_by_registry_path(
                r"\Registry\Machine\System\CurrentControlSet\Services\Missing",
            ),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            client.backend.successful_opens,
            client.backend.successful_closes
        );
    }

    #[test]
    fn active_driver_service_registry_path_fences_generation_and_closes_both_leases() {
        let image = encode_image(&active_driver_service_identity_hive());
        let service_path = r"\Registry\Machine\System\CurrentControlSet\Services\Stable";

        let mut open_skew = tracking_client(true, false);
        assert_eq!(open_skew.import_system_hive(&image), Ok(1));
        assert_eq!(
            open_skew.query_active_driver_service_by_registry_path(service_path),
            Err(STATUS_DEVICE_NOT_READY)
        );
        assert_eq!(open_skew.backend.successful_opens, 2);
        assert_eq!(open_skew.backend.successful_closes, 2);

        let mut close_skew = tracking_client(false, true);
        assert_eq!(close_skew.import_system_hive(&image), Ok(1));
        assert_eq!(
            close_skew.query_active_driver_service_by_registry_path(service_path),
            Err(STATUS_DEVICE_NOT_READY)
        );
        assert_eq!(close_skew.backend.successful_opens, 2);
        assert_eq!(close_skew.backend.successful_closes, 2);

        let mut primary_error = tracking_client(false, true);
        assert_eq!(primary_error.import_system_hive(&image), Ok(1));
        assert_eq!(
            primary_error.query_active_driver_service_by_registry_path(
                r"\Registry\Machine\System\ControlSet001\Services\Stable",
            ),
            Err(STATUS_OBJECT_PATH_SYNTAX_BAD),
            "a physical-identity validation error remains primary when close fencing also fails"
        );
        assert_eq!(primary_error.backend.successful_opens, 2);
        assert_eq!(primary_error.backend.successful_closes, 2);
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

    #[test]
    fn device_action_streams_live_binding_and_requires_exact_ack() {
        let mut hive = Hive::new(HiveKind::System);
        let select = hive.create_key("Select");
        hive.set_dword(select, "Current", 1);
        hive.create_key("ControlSet001");
        hive.finish_clean_import();

        let mut client = ConfigClient::new(Framed {
            server: CmServer::new(),
        });
        assert_eq!(client.import_system_hive(&encode_image(&hive)), Ok(1));
        assert_eq!(client.next_device_action(), Ok(None));

        let service_path = r"\Registry\Machine\System\ControlSet001\Services\LateDriver";
        let instance_path = r"\Registry\Machine\System\ControlSet001\Enum\ROOT\LATE\0000";
        let service_type = SERVICE_KERNEL_DRIVER.to_le_bytes();
        let start_type = SERVICE_DEMAND_START.to_le_bytes();
        let image = encode_sz(r"system32\drivers\late.sys");
        let service_name = encode_sz("LateDriver");
        let pdo_name = encode_sz(r"\Device\LatePdo0");
        let hardware_ids: Vec<String> = (0..96)
            .map(|index| format!(r"ROOT\LATE\HARDWARE_ID_{index:04}_WITH_LONG_IDENTITY"))
            .collect();
        let hardware_refs: Vec<&str> = hardware_ids.iter().map(String::as_str).collect();
        let hardware = encode_multi_sz(&hardware_refs);
        let prepared = client
            .prepare_system_hive_mutation(
                1,
                &[
                    SystemHiveMutation::CreateKey { path: service_path },
                    SystemHiveMutation::SetValue {
                        path: service_path,
                        name: "Type",
                        value_type: RegistryValueType::Dword as u32,
                        data: &service_type,
                    },
                    SystemHiveMutation::SetValue {
                        path: service_path,
                        name: "Start",
                        value_type: RegistryValueType::Dword as u32,
                        data: &start_type,
                    },
                    SystemHiveMutation::SetValue {
                        path: service_path,
                        name: "ImagePath",
                        value_type: RegistryValueType::ExpandSz as u32,
                        data: &image,
                    },
                    SystemHiveMutation::CreateKey {
                        path: instance_path,
                    },
                    SystemHiveMutation::SetValue {
                        path: instance_path,
                        name: "Service",
                        value_type: RegistryValueType::Sz as u32,
                        data: &service_name,
                    },
                    SystemHiveMutation::SetValue {
                        path: instance_path,
                        name: "PdoName",
                        value_type: RegistryValueType::Sz as u32,
                        data: &pdo_name,
                    },
                    SystemHiveMutation::SetValue {
                        path: instance_path,
                        name: "HardwareID",
                        value_type: RegistryValueType::MultiSz as u32,
                        data: &hardware,
                    },
                    SystemHiveMutation::PublishDeviceAction {
                        kind: DeviceActionKind::Arrival,
                        instance_id: r"ROOT\LATE\0000",
                    },
                ],
            )
            .unwrap();
        assert_eq!(
            client.publish_system_hive_mutation(&prepared),
            Ok(SystemHivePublishOutcome {
                generation: 2,
                has_pending_device_action: true,
            })
        );

        let event = client.next_device_action().unwrap().unwrap();
        assert_eq!(event.mount_generation, 2);
        assert_eq!(event.sequence, 1);
        assert_eq!(event.kind, DeviceActionKind::Arrival);
        assert_eq!(event.publication.instance_id, r"ROOT\LATE\0000");
        assert_eq!(event.publication.hardware_ids, hardware_ids);
        assert_eq!(
            event.publication.service_name.as_deref(),
            Some("LateDriver")
        );

        assert_eq!(client.next_device_action(), Err(STATUS_DEVICE_BUSY));
        let mut stale = event.clone();
        stale.sequence += 1;
        assert!(client.acknowledge_device_action(&stale).is_err());
        assert_eq!(client.next_device_action(), Err(STATUS_DEVICE_BUSY));
        assert_eq!(client.acknowledge_device_action(&event), Ok(false));
        assert_eq!(client.next_device_action(), Ok(None));

        let updated_image = encode_sz(r"system32\drivers\late-updated.sys");
        let prepared = client
            .prepare_system_hive_mutation(
                2,
                &[SystemHiveMutation::SetValue {
                    path: service_path,
                    name: "ImagePath",
                    value_type: RegistryValueType::ExpandSz as u32,
                    data: &updated_image,
                }],
            )
            .unwrap();
        assert_eq!(
            client.publish_system_hive_mutation(&prepared),
            Ok(SystemHivePublishOutcome {
                generation: 3,
                has_pending_device_action: false,
            })
        );
        assert_eq!(client.next_device_action(), Ok(None));

        let updated_pdo = encode_sz(r"\Device\LatePdo1");
        let prepared = client
            .prepare_system_hive_mutation(
                3,
                &[
                    SystemHiveMutation::SetValue {
                        path: instance_path,
                        name: "PdoName",
                        value_type: RegistryValueType::Sz as u32,
                        data: &updated_pdo,
                    },
                    SystemHiveMutation::PublishDeviceAction {
                        kind: DeviceActionKind::Change,
                        instance_id: r"ROOT\LATE\0000",
                    },
                ],
            )
            .unwrap();
        assert_eq!(
            client.publish_system_hive_mutation(&prepared),
            Ok(SystemHivePublishOutcome {
                generation: 4,
                has_pending_device_action: true,
            })
        );
        let changed = client.next_device_action().unwrap().unwrap();
        assert_eq!(changed.sequence, 2);
        assert_eq!(changed.kind, DeviceActionKind::Change);
        assert_eq!(
            changed.publication.pdo_name.as_deref(),
            Some(r"\Device\LatePdo1")
        );
        assert_eq!(client.acknowledge_device_action(&changed), Ok(false));

        let prepared = client
            .prepare_system_hive_mutation(
                4,
                &[
                    SystemHiveMutation::DeleteKey {
                        path: instance_path,
                    },
                    SystemHiveMutation::PublishDeviceAction {
                        kind: DeviceActionKind::Removal,
                        instance_id: r"ROOT\LATE\0000",
                    },
                ],
            )
            .unwrap();
        assert_eq!(
            client.publish_system_hive_mutation(&prepared),
            Ok(SystemHivePublishOutcome {
                generation: 5,
                has_pending_device_action: true,
            })
        );
        let removal = client.next_device_action().unwrap().unwrap();
        assert_eq!(removal.sequence, 3);
        assert_eq!(removal.kind, DeviceActionKind::Removal);
        assert_eq!(removal.publication.instance_id, r"ROOT\LATE\0000");
        assert_eq!(removal.publication.hardware_ids, hardware_ids);
        assert_eq!(client.acknowledge_device_action(&removal), Ok(false));
        assert_eq!(client.next_device_action(), Ok(None));
    }
}
