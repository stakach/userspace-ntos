//! Fixed-layout SURT wire ABI for the NT Configuration Manager (registry) service.
//!
//! Every wire struct is `#[repr(C)]`, fixed-width, with UTF-16LE key/value names
//! appended after the fixed header at the given offsets — no raw pointers. Shared by
//! `nt-config-server` (decode/dispatch) + `nt-config-client` (encode). It carries path-addressed
//! operations, semantic devnode queries, and opaque leases for native handles into the mounted
//! SYSTEM hive.

#![no_std]

/// The Configuration Manager's SURT opcode range.
pub const CM_OPCODE_MIN: u16 = 0x2100;
pub const CM_OPCODE_MAX: u16 = 0x21ff;
pub const CM_ABI_VERSION: u16 = 4;
pub const CM_MAX_INSTANCE_UNITS: usize = 512;
/// Maximum property payload carried by one SURT completion frame.
pub const CM_DEVICE_PROPERTY_CHUNK_BYTES: usize = 4096;
/// Maximum service-name units accepted by one semantic driver-binding request.
pub const CM_MAX_SERVICE_UNITS: usize = 512;
/// Maximum payload carried by one driver-binding completion frame.
pub const CM_DRIVER_SERVICE_CHUNK_BYTES: usize = 4096;
pub const CM_DRIVER_SERVICE_SNAPSHOT_MAGIC: u32 = 0x4453_4D43; // `CMSD`
pub const CM_DRIVER_SERVICE_SNAPSHOT_VERSION: u16 = 2;
pub const CM_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES: usize = 16;
/// Maximum payload carried by one SYSTEM-hive import request frame.
pub const CM_HIVE_IMPORT_CHUNK_BYTES: usize = 4064;
/// Maximum journal payload carried by one mounted-hive mutation request frame.
pub const CM_HIVE_MUTATION_CHUNK_BYTES: usize = 4056;
/// Maximum SYSTEM checkpoint bytes returned in one SURT completion frame.
pub const CM_HIVE_CHECKPOINT_CHUNK_BYTES: usize = 4096;
pub const CM_HIVE_CHECKPOINT_MAGIC: u32 = 0x4843_4D43; // `CMCH`
pub const CM_HIVE_CHECKPOINT_VERSION: u16 = 1;
pub const CM_HIVE_CHECKPOINT_HEADER_BYTES: usize = 40;
pub const CM_HIVE_MUTATION_RECORD_HEADER_BYTES: usize = 24;
pub const CM_MAX_HIVE_VALUE_NAME_UNITS: usize = 512;
/// Maximum payload carried by one mounted-hive key snapshot completion frame.
pub const CM_HIVE_KEY_CHUNK_BYTES: usize = 4096;
pub const CM_HIVE_KEY_SNAPSHOT_MAGIC: u32 = 0x4B48_4D43; // `CMHK`
pub const CM_HIVE_KEY_SNAPSHOT_VERSION: u16 = 1;
pub const CM_HIVE_KEY_SNAPSHOT_HEADER_BYTES: usize = 24;
pub const CM_HIVE_KEY_RECORD_MAGIC: u32 = 0x524B_4D43; // `CMKR`
pub const CM_HIVE_KEY_RECORD_VERSION: u16 = 2;
pub const CM_HIVE_KEY_RECORD_HEADER_BYTES: usize = 24;
pub const CM_HIVE_EXPORT_MAGIC: u32 = 0x5845_4D43; // `CMEX`
pub const CM_HIVE_EXPORT_VERSION: u16 = 1;
pub const CM_HIVE_EXPORT_HEADER_BYTES: usize = 24;
pub const CM_MAX_HIVE_PATH_UNITS: usize = 512;
/// Maximum payload carried by one immutable driver launch-plan completion frame.
pub const CM_LAUNCH_PLAN_CHUNK_BYTES: usize = 4096;
pub const CM_LAUNCH_PLAN_SNAPSHOT_MAGIC: u32 = 0x504C_4D43; // `CMLP`
pub const CM_LAUNCH_PLAN_SNAPSHOT_VERSION: u16 = 1;
pub const CM_LAUNCH_PLAN_SNAPSHOT_HEADER_BYTES: usize = 24;
pub const CM_WIN32_SERVICE_PLAN_SNAPSHOT_MAGIC: u32 = 0x5053_4D43; // `CMSP`
pub const CM_WIN32_SERVICE_PLAN_SNAPSHOT_VERSION: u16 = 1;
pub const CM_WIN32_SERVICE_PLAN_SNAPSHOT_HEADER_BYTES: usize = 24;
pub const CM_PNP_QUERY_SNAPSHOT_MAGIC: u32 = 0x5150_4D43; // `CMPQ`
pub const CM_PNP_QUERY_SNAPSHOT_VERSION: u16 = 1;
pub const CM_PNP_QUERY_SNAPSHOT_HEADER_BYTES: usize = 24;
pub const CM_MAX_PNP_AUX_BYTES: usize = 16;
pub const CM_NETWORK_PLAN_SNAPSHOT_MAGIC: u32 = 0x504E_4D43; // `CMNP`
pub const CM_NETWORK_PLAN_SNAPSHOT_VERSION: u16 = 1;
pub const CM_NETWORK_PLAN_SNAPSHOT_HEADER_BYTES: usize = 24;
/// Maximum payload carried by one device-action completion frame.
pub const CM_DEVICE_ACTION_CHUNK_BYTES: usize = 4096;
pub const CM_DEVICE_ACTION_SNAPSHOT_MAGIC: u32 = 0x4144_4D43; // `CMDA`
pub const CM_DEVICE_ACTION_SNAPSHOT_VERSION: u16 = 1;
pub const CM_DEVICE_ACTION_SNAPSHOT_HEADER_BYTES: usize = 32;
pub const CM_OPTIONAL_STRING_ABSENT: u32 = u32::MAX;
pub const CM_OPTIONAL_BLOB_ABSENT: u32 = u32::MAX;
pub const CM_OPTIONAL_U32_ABSENT: u32 = u32::MAX;

pub mod opcode {
    pub const CM_OP_PING: u16 = 0x2100;
    /// Create (or get) a key by full path. Reply `detail0` = key id.
    pub const CM_OP_CREATE_KEY: u16 = 0x2110;
    /// Open an existing key by full path. `status` = SUCCESS if found, else not-found.
    pub const CM_OP_OPEN_KEY: u16 = 0x2111;
    /// Set a DWORD value on a key (created if absent).
    pub const CM_OP_SET_DWORD: u16 = 0x2120;
    /// Query a DWORD value. Reply `detail0` = value; not-found status if absent.
    pub const CM_OP_QUERY_DWORD: u16 = 0x2121;
    /// Set a typed raw value on a key (created if absent).
    pub const CM_OP_SET_VALUE: u16 = 0x2122;
    /// Query a typed raw value. Reply `detail0` = REG_* type, `information` = data bytes.
    pub const CM_OP_QUERY_VALUE: u16 = 0x2123;
    /// Enumerate an existing key's immediate subkey name by index. Reply `information` = name bytes.
    pub const CM_OP_ENUMERATE_KEY: u16 = 0x2130;
    /// Query one legacy device property by stable devnode instance path.
    pub const CM_OP_QUERY_DEVICE_PROPERTY: u16 = 0x2140;
    /// Resolve one live driver service and all registry-bound devnodes.
    pub const CM_OP_QUERY_DRIVER_SERVICE: u16 = 0x2141;
    /// Atomically import and publish one mounted `nt-hive-core` SYSTEM image.
    pub const CM_OP_IMPORT_HIVE: u16 = 0x2150;
    /// Return one immutable, complete mounted-hive key snapshot.
    pub const CM_OP_QUERY_HIVE_KEY: u16 = 0x2151;
    /// Return one immutable, generation-bound ordered driver launch plan.
    pub const CM_OP_QUERY_LAUNCH_PLAN: u16 = 0x2152;
    /// Return one immutable, generation-bound ordered Win32 service launch plan.
    pub const CM_OP_QUERY_WIN32_SERVICE_PLAN: u16 = 0x2153;
    /// Return one immutable, generation-bound semantic PnP query snapshot.
    pub const CM_OP_QUERY_PNP: u16 = 0x2154;
    /// Return one immutable, generation-bound installed network-adapter binding plan.
    pub const CM_OP_QUERY_NETWORK_PLAN: u16 = 0x2155;
    /// Apply one generation-checked atomic mutation journal to the mounted SYSTEM hive.
    pub const CM_OP_MUTATE_SYSTEM_HIVE: u16 = 0x2156;
    /// Acquire or release one opaque, stable key identity in the mounted SYSTEM hive.
    pub const CM_OP_SYSTEM_HIVE_KEY_LEASE: u16 = 0x2157;
    /// Return an immutable snapshot of a key addressed by an owned SYSTEM key lease.
    pub const CM_OP_QUERY_LEASED_HIVE_KEY: u16 = 0x2158;
    /// Return one bounded immutable key/value record addressed by an owned SYSTEM key lease.
    pub const CM_OP_QUERY_LEASED_HIVE_RECORD: u16 = 0x2159;
    /// Export and acknowledge one generation-stamped SYSTEM checkpoint image.
    pub const CM_OP_CHECKPOINT_SYSTEM_HIVE: u16 = 0x215a;
    /// Export an immutable standalone hive image from an exact leased SYSTEM key.
    pub const CM_OP_EXPORT_LEASED_HIVE: u16 = 0x215b;
    /// Peek, stream, and exactly acknowledge the next live PnP device action.
    pub const CM_OP_DEVICE_ACTION: u16 = 0x215c;
}

/// Operation carried by [`CmDevicePropertyRequest::operation`]. Property values are immutable for
/// the lifetime of one begin/pull sequence; abort releases an incomplete snapshot.
pub mod device_property_transfer {
    pub const BEGIN: u16 = 1;
    pub const PULL: u16 = 2;
    pub const ABORT: u16 = 3;
}

/// Operation carried by [`CmDriverServiceRequest::operation`].
pub mod driver_service_transfer {
    pub const BEGIN: u16 = 1;
    pub const PULL: u16 = 2;
    pub const ABORT: u16 = 3;
}

/// Operation carried by [`CmHiveImportRequest::operation`].
pub mod hive_import_transfer {
    pub const BEGIN: u16 = 1;
    pub const PUSH: u16 = 2;
    pub const COMMIT: u16 = 3;
    pub const ABORT: u16 = 4;
}

/// Operation carried by [`CmHiveKeyRequest::operation`].
pub mod hive_key_transfer {
    pub const BEGIN: u16 = 1;
    pub const PULL: u16 = 2;
    pub const ABORT: u16 = 3;
}

/// Operation carried by [`CmHiveKeyLeaseRequest::operation`].
pub mod hive_key_lease_operation {
    pub const OPEN: u16 = 1;
    pub const CLOSE: u16 = 2;
    /// Resolve a SYSTEM namespace path to its physical control-set identity without opening it.
    /// The path need not exist; the reply carries no lease token.
    pub const RESOLVE: u16 = 3;
}

/// Record selector carried by [`CmLeasedHiveRecordRequest::record_kind`].
pub mod leased_hive_record_kind {
    pub const KEY_INFORMATION: u16 = 1;
    pub const VALUE_BY_NAME: u16 = 2;
    pub const SUBKEY_BY_INDEX: u16 = 3;
    pub const VALUE_BY_INDEX: u16 = 4;
}

/// Operation carried by [`CmHiveMutationRequest::operation`].
pub mod hive_mutation_transfer {
    pub const BEGIN: u16 = 1;
    pub const APPEND: u16 = 2;
    /// Validate the complete semantic journal and retain its CM-owned replay records.
    pub const PREPARE: u16 = 3;
    /// Pull one chunk of the prepared replay records into the completion frame.
    pub const PULL: u16 = 4;
    /// Publish the prepared mutation after its replay records are durable.
    pub const COMMIT: u16 = 5;
    pub const ABORT: u16 = 6;
}

/// Operation carried by [`CmHiveCheckpointRequest::operation`].
pub mod hive_checkpoint_transfer {
    pub const BEGIN: u16 = 1;
    pub const PULL: u16 = 2;
    /// Acknowledge that the complete image atomically replaced its durable primary and log.
    pub const ACK: u16 = 3;
    pub const ABORT: u16 = 4;
}

/// Operation encoded in one [`CmHiveMutationRecord`].
pub mod hive_mutation_kind {
    pub const CREATE_KEY: u16 = 1;
    pub const SET_VALUE: u16 = 2;
    pub const DELETE_VALUE: u16 = 3;
    pub const DELETE_KEY: u16 = 4;
    pub const SET_KEY_CLASS: u16 = 5;
    pub const SET_KEY_SECURITY: u16 = 6;
    /// Explicit bus/PnP publication intent. `path` carries the device instance and `value_type`
    /// carries one [`device_action_kind`] value; it does not directly mutate registry cells.
    pub const PUBLISH_DEVICE_ACTION: u16 = 7;
}

pub mod hive_mutation_flags {
    /// Distinguishes an explicitly present empty class from clearing the class metadata.
    pub const CLASS_PRESENT: u16 = 1 << 0;
}

/// Operation carried by [`CmLaunchPlanRequest::operation`].
pub mod launch_plan_transfer {
    pub const BEGIN: u16 = 1;
    pub const PULL: u16 = 2;
    pub const ABORT: u16 = 3;
}

/// Ordered driver plan selected from the live SYSTEM generation.
pub mod launch_plan_kind {
    pub const BOOT_SYSTEM_DRIVERS: u16 = 1;
    pub const DEMAND_DRIVERS: u16 = 2;
}

/// Ordered Win32 service process plan selected from the live SYSTEM generation.
pub mod win32_service_plan_kind {
    pub const AUTO_START: u16 = 1;
    pub const DEMAND_START: u16 = 2;
}

pub mod win32_service_process_kind {
    pub const OWN: u16 = 1;
    pub const SHARED: u16 = 2;
}

pub mod pnp_query_transfer {
    pub const BEGIN: u16 = 1;
    pub const PULL: u16 = 2;
    pub const ABORT: u16 = 3;
}

pub mod pnp_query_kind {
    pub const DEVICE_EXISTS: u16 = 1;
    pub const ENUMERATE_DEVNODE: u16 = 2;
    pub const INTERFACE_LINKS: u16 = 3;
    pub const DYNAMIC_PROPERTY: u16 = 4;
    pub const RELATED_DEVICE: u16 = 5;
    pub const DEVICE_DEPTH: u16 = 6;
    pub const BUS_RELATIONS: u16 = 7;
    pub const CRITICAL_DEVICE_BINDING: u16 = 8;
}

/// Operation carried by [`CmDeviceActionRequest::operation`].
pub mod device_action_transfer {
    pub const BEGIN: u16 = 1;
    pub const PULL: u16 = 2;
    pub const ABORT: u16 = 3;
    pub const ACK: u16 = 4;
}

pub mod device_action_kind {
    pub const ARRIVAL: u16 = 1;
    pub const CHANGE: u16 = 2;
    pub const REMOVAL: u16 = 3;
}

pub mod device_action_service {
    pub const ABSENT: u16 = 0;
    pub const PRESENT: u16 = 1;
}

pub mod network_plan_kind {
    pub const ADAPTER_BINDINGS: u16 = 1;
}

/// Mount identifiers carried by mounted-hive operations.
pub mod hive_mount {
    pub const SYSTEM: u16 = 1;
}

/// Values encoded in the driver-binding snapshot header's `class` field.
pub mod driver_service_class {
    pub const DEVICE: u16 = 1;
    pub const FILE_SYSTEM: u16 = 2;
}

/// The reply every Configuration Manager op returns (field-for-field over `SurtCqe`).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmReply {
    pub status: i32,
    pub information: u32,
    pub detail0: u64,
    pub detail1: u64,
}

pub mod key_flags {
    /// Create the leaf as a volatile key. Ignored when opening an existing key.
    pub const VOLATILE: u16 = 0x0001;
}

/// `create_key` / `open_key`: a single key path (UTF-16LE) at `[path_offset..]`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct CmKeyRequest {
    pub abi_size: u16,
    pub flags: u16,
    pub path_offset: u32,
    pub path_len_bytes: u32,
}

/// `enumerate_key`: a key path plus zero-based subkey index. The returned payload is the selected
/// subkey name as UTF-16LE bytes without a terminating NUL.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct CmEnumerateKeyRequest {
    pub abi_size: u16,
    pub _pad: u16,
    pub index: u32,
    pub path_offset: u32,
    pub path_len_bytes: u32,
}

/// `set_dword` / `query_dword`: a key path + a value name (both UTF-16LE), and the
/// DWORD (used by set; ignored by query).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct CmValueRequest {
    pub abi_size: u16,
    pub _pad: u16,
    pub dword: u32,
    pub key_offset: u32,
    pub key_len_bytes: u32,
    pub name_offset: u32,
    pub name_len_bytes: u32,
}

/// `set_value` / `query_value`: a key path + value name, plus optional raw value bytes. `value_type`
/// is used by set and ignored by query; query returns the type in [`CmReply::detail0`].
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct CmRawValueRequest {
    pub abi_size: u16,
    pub _pad: u16,
    pub value_type: u32,
    pub key_offset: u32,
    pub key_len_bytes: u32,
    pub name_offset: u32,
    pub name_len_bytes: u32,
    pub data_offset: u32,
    pub data_len_bytes: u32,
}

/// `query_device_property`: a stable devnode instance path plus one bank of the caller's logical
/// output. The logical capacity is separate from the chunk capacity because an isolated server
/// sees one shared reply frame rather than the caller's final buffer.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmDevicePropertyRequest {
    pub abi_size: u16,
    pub abi_version: u16,
    pub operation: u16,
    pub _reserved: u16,
    pub property: u32,
    pub output_capacity: u32,
    pub value_offset: u32,
    pub chunk_capacity: u32,
    pub instance_offset: u32,
    pub instance_len_bytes: u32,
    pub transfer_token: u64,
}

/// `query_driver_service`: one service name plus an immutable snapshot-bank cursor.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmDriverServiceRequest {
    pub abi_size: u16,
    pub abi_version: u16,
    pub operation: u16,
    pub _reserved: u16,
    pub value_offset: u32,
    pub chunk_capacity: u32,
    pub service_offset: u32,
    pub service_len_bytes: u32,
    pub transfer_token: u64,
}

/// `import_hive`: a tokenized upload. BEGIN reserves `total_len_bytes`; PUSH carries one chunk at
/// `chunk_offset` and appends it at `value_offset`; COMMIT atomically validates and publishes the
/// complete image; ABORT releases the staged bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmHiveImportRequest {
    pub abi_size: u16,
    pub abi_version: u16,
    pub operation: u16,
    pub mount: u16,
    pub value_offset: u32,
    pub chunk_offset: u32,
    pub chunk_len_bytes: u32,
    pub total_len_bytes: u32,
    pub transfer_token: u64,
}

/// `query_hive_key`: a full NT key path plus an immutable snapshot-bank cursor.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmHiveKeyRequest {
    pub abi_size: u16,
    pub abi_version: u16,
    pub operation: u16,
    pub mount: u16,
    pub value_offset: u32,
    pub chunk_capacity: u32,
    pub path_offset: u32,
    pub path_len_bytes: u32,
    pub transfer_token: u64,
}

/// `system_hive_key_lease`: OPEN resolves a full NT path to one stable hive cell and returns an
/// opaque lease token. CLOSE releases exactly that token. Reply `detail0` is the mount generation
/// and `detail1` is the lease token.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmHiveKeyLeaseRequest {
    pub abi_size: u16,
    pub abi_version: u16,
    pub operation: u16,
    pub mount: u16,
    pub path_offset: u32,
    pub path_len_bytes: u32,
    pub lease_token: u64,
}

/// `query_leased_hive_key`: an immutable snapshot-bank cursor addressed by a previously acquired
/// key lease. The key lease and snapshot-transfer token have independent lifetimes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmLeasedHiveKeyRequest {
    pub abi_size: u16,
    pub abi_version: u16,
    pub operation: u16,
    pub mount: u16,
    pub value_offset: u32,
    pub chunk_capacity: u32,
    pub key_lease_token: u64,
    pub transfer_token: u64,
}

/// Fixed prefix on a lease-bound standalone hive export. The remaining bytes are exactly one
/// `nt-hive-core` image rooted at the leased key.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmHiveExportHeader {
    pub magic: u32,
    pub version: u16,
    pub header_size: u16,
    pub mount_generation: u64,
    pub image_len_bytes: u32,
    pub _reserved: u32,
}

/// `query_leased_hive_record`: a narrow immutable record addressed by a key lease. BEGIN carries
/// the record selector and optional UTF-16 value name; PULL/ABORT use only the two opaque tokens.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmLeasedHiveRecordRequest {
    pub abi_size: u16,
    pub abi_version: u16,
    pub operation: u16,
    pub mount: u16,
    pub key_lease_token: u64,
    pub transfer_token: u64,
    pub value_offset: u32,
    pub chunk_capacity: u32,
    pub index: u32,
    pub name_offset: u32,
    pub name_len_bytes: u32,
    pub record_kind: u16,
    pub _reserved: u16,
}

/// `mutate_system_hive`: a generation-checked journal upload and durability handshake. BEGIN
/// acquires the sole writer lease and reserves `journal_len_bytes`; APPEND carries the next ordered
/// semantic chunk; PREPARE validates it and materialises CM-owned replay records; PULL streams those
/// records to the storage transport; COMMIT publishes one new generation only after storage has
/// acknowledged durability; ABORT releases either an upload or a prepared mutation.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmHiveMutationRequest {
    pub abi_size: u16,
    pub abi_version: u16,
    pub operation: u16,
    pub mount: u16,
    pub journal_offset: u32,
    pub chunk_offset: u32,
    pub chunk_len_bytes: u32,
    pub journal_len_bytes: u32,
    pub expected_generation: u64,
    pub lease_token: u64,
}

/// `checkpoint_system_hive`: a single-flight, generation-checked checkpoint export. BEGIN returns
/// the first bytes of [`CmHiveCheckpointHeader`] followed by the encoded hive image; PULL continues
/// at the exact byte offset; ACK marks the exported sequence clean only after storage made the image
/// and empty replay log durable; ABORT leaves the mounted hive dirty.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmHiveCheckpointRequest {
    pub abi_size: u16,
    pub abi_version: u16,
    pub operation: u16,
    pub mount: u16,
    pub value_offset: u32,
    pub chunk_capacity: u32,
    pub expected_generation: u64,
    pub transfer_token: u64,
}

/// Fixed prefix on every complete SYSTEM checkpoint transfer. The bytes following this header are
/// exactly `image_len_bytes` of `nt-hive-core` image data and are the only bytes written to the
/// durable SYSTEM primary.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmHiveCheckpointHeader {
    pub magic: u32,
    pub version: u16,
    pub header_size: u16,
    pub mount_generation: u64,
    pub hive_sequence: u64,
    pub image_generation: u64,
    pub image_len_bytes: u32,
    pub _reserved: u32,
}

/// Header for one path-addressed operation in a SYSTEM mutation journal. Payload order is UTF-16LE
/// path, UTF-16LE value/class name, then raw data. Lengths exclude terminators.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmHiveMutationRecord {
    pub kind: u16,
    pub flags: u16,
    pub value_type: u32,
    pub path_len_bytes: u32,
    pub name_len_bytes: u32,
    pub data_len_bytes: u32,
    pub _reserved: u32,
}

/// `query_launch_plan`: a plan kind plus an immutable snapshot-bank cursor.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmLaunchPlanRequest {
    pub abi_size: u16,
    pub abi_version: u16,
    pub operation: u16,
    pub plan_kind: u16,
    pub value_offset: u32,
    pub chunk_capacity: u32,
    pub transfer_token: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmPnpQueryRequest {
    pub abi_size: u16,
    pub abi_version: u16,
    pub operation: u16,
    pub query_kind: u16,
    pub value_offset: u32,
    pub chunk_capacity: u32,
    pub selector: u32,
    pub instance_offset: u32,
    pub instance_len_bytes: u32,
    pub auxiliary_offset: u32,
    pub auxiliary_len_bytes: u32,
    pub _reserved: u32,
    pub transfer_token: u64,
}

/// `device_action`: one generation/sequence-bound immutable journal entry. BEGIN peeks the current
/// head, PULL continues its snapshot, ABORT releases only the transfer, and ACK retires only the
/// exact head identity after the kernel PnP action has reached a terminal state.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CmDeviceActionRequest {
    pub abi_size: u16,
    pub abi_version: u16,
    pub operation: u16,
    pub _reserved: u16,
    pub value_offset: u32,
    pub chunk_capacity: u32,
    pub mount_generation: u64,
    pub event_sequence: u64,
    pub transfer_token: u64,
}

macro_rules! wire {
    ($t:ty) => {
        impl $t {
            /// The fixed header as bytes (for prepending before the string payload).
            pub fn as_bytes(&self) -> &[u8] {
                // SAFETY: `#[repr(C)]` POD; no padding beyond declared fields; read-only.
                unsafe {
                    core::slice::from_raw_parts(
                        self as *const _ as *const u8,
                        core::mem::size_of::<$t>(),
                    )
                }
            }
            /// Parse the fixed header from the front of `buf` (unaligned).
            pub fn from_bytes(buf: &[u8]) -> Option<$t> {
                if buf.len() < core::mem::size_of::<$t>() {
                    return None;
                }
                // SAFETY: length checked; unaligned read of a POD `#[repr(C)]` struct.
                Some(unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const $t) })
            }
        }
    };
}
wire!(CmKeyRequest);
wire!(CmEnumerateKeyRequest);
wire!(CmValueRequest);
wire!(CmRawValueRequest);
wire!(CmDevicePropertyRequest);
wire!(CmDriverServiceRequest);
wire!(CmHiveImportRequest);
wire!(CmHiveKeyRequest);
wire!(CmHiveKeyLeaseRequest);
wire!(CmLeasedHiveKeyRequest);
wire!(CmHiveExportHeader);
wire!(CmLeasedHiveRecordRequest);
wire!(CmHiveMutationRequest);
wire!(CmHiveCheckpointRequest);
wire!(CmHiveCheckpointHeader);
wire!(CmHiveMutationRecord);
wire!(CmLaunchPlanRequest);
wire!(CmPnpQueryRequest);
wire!(CmDeviceActionRequest);

/// Decode a UTF-16LE slice of `buf` (at `offset`, `len_bytes` long) into a `str`
/// via the caller's scratch — returns the u16 units. Used by the server.
pub fn read_utf16(buf: &[u8], offset: u32, len_bytes: u32, out: &mut [u16]) -> Option<usize> {
    let (o, l) = (offset as usize, len_bytes as usize);
    if l % 2 != 0 || o.checked_add(l)? > buf.len() || l / 2 > out.len() {
        return None;
    }
    for (i, slot) in out.iter_mut().enumerate().take(l / 2) {
        *slot = u16::from_le_bytes([buf[o + i * 2], buf[o + i * 2 + 1]]);
    }
    Some(l / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_property_request_has_stable_wire_layout() {
        assert_eq!(opcode::CM_OP_QUERY_DEVICE_PROPERTY, 0x2140);
        assert!((CM_OPCODE_MIN..=CM_OPCODE_MAX).contains(&opcode::CM_OP_QUERY_DEVICE_PROPERTY));
        assert_eq!(core::mem::size_of::<CmDevicePropertyRequest>(), 40);

        let request = CmDevicePropertyRequest {
            abi_size: 40,
            abi_version: CM_ABI_VERSION,
            operation: device_property_transfer::PULL,
            _reserved: 0,
            property: 0x1122_3344,
            output_capacity: 0x5566_7788,
            value_offset: 0x99aa_bbcc,
            chunk_capacity: 0xddee_ff00,
            instance_offset: 40,
            instance_len_bytes: 0x99aa_bbcc,
            transfer_token: 0x1122_3344_5566_7788,
        };
        assert_eq!(
            request.as_bytes(),
            &[
                40, 0, 4, 0, 2, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0xcc,
                0xbb, 0xaa, 0x99, 0x00, 0xff, 0xee, 0xdd, 40, 0, 0, 0, 0xcc, 0xbb, 0xaa, 0x99,
                0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
            ]
        );
        assert_eq!(
            CmDevicePropertyRequest::from_bytes(request.as_bytes()),
            Some(request)
        );
    }

    #[test]
    fn driver_service_request_has_stable_wire_layout() {
        assert_eq!(opcode::CM_OP_QUERY_DRIVER_SERVICE, 0x2141);
        assert!((CM_OPCODE_MIN..=CM_OPCODE_MAX).contains(&opcode::CM_OP_QUERY_DRIVER_SERVICE));
        assert_eq!(core::mem::size_of::<CmDriverServiceRequest>(), 32);

        let request = CmDriverServiceRequest {
            abi_size: 32,
            abi_version: CM_ABI_VERSION,
            operation: driver_service_transfer::PULL,
            _reserved: 0,
            value_offset: 0x1122_3344,
            chunk_capacity: 0x5566_7788,
            service_offset: 32,
            service_len_bytes: 0x99aa_bbcc,
            transfer_token: 0x1122_3344_5566_7788,
        };
        assert_eq!(
            request.as_bytes(),
            &[
                32, 0, 4, 0, 2, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 32, 0, 0,
                0, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
            ]
        );
        assert_eq!(
            CmDriverServiceRequest::from_bytes(request.as_bytes()),
            Some(request)
        );
    }

    #[test]
    fn mounted_hive_requests_have_stable_wire_layout() {
        assert_eq!(opcode::CM_OP_IMPORT_HIVE, 0x2150);
        assert_eq!(opcode::CM_OP_QUERY_HIVE_KEY, 0x2151);
        assert_eq!(opcode::CM_OP_QUERY_LAUNCH_PLAN, 0x2152);
        assert_eq!(opcode::CM_OP_QUERY_WIN32_SERVICE_PLAN, 0x2153);
        assert_eq!(opcode::CM_OP_QUERY_PNP, 0x2154);
        assert_eq!(opcode::CM_OP_QUERY_NETWORK_PLAN, 0x2155);
        assert_eq!(opcode::CM_OP_SYSTEM_HIVE_KEY_LEASE, 0x2157);
        assert_eq!(opcode::CM_OP_QUERY_LEASED_HIVE_KEY, 0x2158);
        assert_eq!(opcode::CM_OP_QUERY_LEASED_HIVE_RECORD, 0x2159);
        assert_eq!(opcode::CM_OP_CHECKPOINT_SYSTEM_HIVE, 0x215a);
        assert_eq!(opcode::CM_OP_DEVICE_ACTION, 0x215c);
        assert_eq!(CM_HIVE_KEY_RECORD_VERSION, 2);
        assert_eq!(core::mem::size_of::<CmHiveImportRequest>(), 32);
        assert_eq!(core::mem::size_of::<CmHiveKeyRequest>(), 32);
        assert_eq!(core::mem::size_of::<CmHiveKeyLeaseRequest>(), 24);
        assert_eq!(core::mem::size_of::<CmLeasedHiveKeyRequest>(), 32);
        assert_eq!(core::mem::size_of::<CmLeasedHiveRecordRequest>(), 48);
        assert_eq!(core::mem::size_of::<CmHiveCheckpointRequest>(), 32);
        assert_eq!(core::mem::size_of::<CmHiveCheckpointHeader>(), 40);
        assert_eq!(core::mem::size_of::<CmDeviceActionRequest>(), 40);
        assert_eq!(CM_HIVE_CHECKPOINT_HEADER_BYTES, 40);

        let import = CmHiveImportRequest {
            abi_size: 32,
            abi_version: CM_ABI_VERSION,
            operation: hive_import_transfer::PUSH,
            mount: hive_mount::SYSTEM,
            value_offset: 0x1122_3344,
            chunk_offset: 32,
            chunk_len_bytes: 0x5566_7788,
            total_len_bytes: 0x99aa_bbcc,
            transfer_token: 0x1122_3344_5566_7788,
        };
        assert_eq!(
            CmHiveImportRequest::from_bytes(import.as_bytes()),
            Some(import)
        );

        let query = CmHiveKeyRequest {
            abi_size: 32,
            abi_version: CM_ABI_VERSION,
            operation: hive_key_transfer::PULL,
            mount: hive_mount::SYSTEM,
            value_offset: 0x1122_3344,
            chunk_capacity: 0x5566_7788,
            path_offset: 32,
            path_len_bytes: 0x99aa_bbcc,
            transfer_token: 0x1122_3344_5566_7788,
        };
        assert_eq!(CmHiveKeyRequest::from_bytes(query.as_bytes()), Some(query));

        let lease = CmHiveKeyLeaseRequest {
            abi_size: 24,
            abi_version: CM_ABI_VERSION,
            operation: hive_key_lease_operation::OPEN,
            mount: hive_mount::SYSTEM,
            path_offset: 24,
            path_len_bytes: 0x1122_3344,
            lease_token: 0x0102_0304_0506_0708,
        };
        assert_eq!(
            CmHiveKeyLeaseRequest::from_bytes(lease.as_bytes()),
            Some(lease)
        );

        let leased_query = CmLeasedHiveKeyRequest {
            abi_size: 32,
            abi_version: CM_ABI_VERSION,
            operation: hive_key_transfer::PULL,
            mount: hive_mount::SYSTEM,
            value_offset: 0x1122_3344,
            chunk_capacity: 0x5566_7788,
            key_lease_token: 0x0102_0304_0506_0708,
            transfer_token: 0x1112_1314_1516_1718,
        };
        assert_eq!(
            CmLeasedHiveKeyRequest::from_bytes(leased_query.as_bytes()),
            Some(leased_query)
        );

        let plan = CmLaunchPlanRequest {
            abi_size: 24,
            abi_version: CM_ABI_VERSION,
            operation: launch_plan_transfer::PULL,
            plan_kind: launch_plan_kind::BOOT_SYSTEM_DRIVERS,
            value_offset: 0x1122_3344,
            chunk_capacity: 0x5566_7788,
            transfer_token: 0x1122_3344_5566_7788,
        };
        assert_eq!(core::mem::size_of::<CmLaunchPlanRequest>(), 24);
        assert_eq!(CmLaunchPlanRequest::from_bytes(plan.as_bytes()), Some(plan));

        let pnp = CmPnpQueryRequest {
            abi_size: 48,
            abi_version: CM_ABI_VERSION,
            operation: pnp_query_transfer::BEGIN,
            query_kind: pnp_query_kind::DEVICE_DEPTH,
            value_offset: 0,
            chunk_capacity: 4096,
            selector: 0,
            instance_offset: 48,
            instance_len_bytes: 8,
            auxiliary_offset: 56,
            auxiliary_len_bytes: 16,
            _reserved: 0,
            transfer_token: 0,
        };
        assert_eq!(core::mem::size_of::<CmPnpQueryRequest>(), 48);
        assert_eq!(CmPnpQueryRequest::from_bytes(pnp.as_bytes()), Some(pnp));

        let checkpoint = CmHiveCheckpointRequest {
            abi_size: 32,
            abi_version: CM_ABI_VERSION,
            operation: hive_checkpoint_transfer::PULL,
            mount: hive_mount::SYSTEM,
            value_offset: 0x1122_3344,
            chunk_capacity: 0x5566_7788,
            expected_generation: 0x0102_0304_0506_0708,
            transfer_token: 0x1112_1314_1516_1718,
        };
        assert_eq!(
            CmHiveCheckpointRequest::from_bytes(checkpoint.as_bytes()),
            Some(checkpoint)
        );
    }

    #[test]
    fn mounted_hive_mutation_has_stable_wire_layout() {
        assert_eq!(opcode::CM_OP_MUTATE_SYSTEM_HIVE, 0x2156);
        assert_eq!(opcode::CM_OP_EXPORT_LEASED_HIVE, 0x215b);
        assert_eq!(hive_key_lease_operation::RESOLVE, 3);
        assert_eq!(core::mem::size_of::<CmHiveExportHeader>(), 24);
        assert_eq!(CM_HIVE_EXPORT_HEADER_BYTES, 24);
        assert_eq!(core::mem::size_of::<CmHiveMutationRequest>(), 40);
        assert_eq!(core::mem::size_of::<CmHiveMutationRecord>(), 24);
        assert_eq!(CM_HIVE_MUTATION_RECORD_HEADER_BYTES, 24);

        let request = CmHiveMutationRequest {
            abi_size: 40,
            abi_version: CM_ABI_VERSION,
            operation: hive_mutation_transfer::APPEND,
            mount: hive_mount::SYSTEM,
            journal_offset: 0x1122_3344,
            chunk_offset: 40,
            chunk_len_bytes: 0x5566_7788,
            journal_len_bytes: 0x99aa_bbcc,
            expected_generation: 0x0102_0304_0506_0708,
            lease_token: 0x1112_1314_1516_1718,
        };
        assert_eq!(
            CmHiveMutationRequest::from_bytes(request.as_bytes()),
            Some(request)
        );
        assert_eq!(
            request.as_bytes(),
            &[
                40, 0, 4, 0, 2, 0, 1, 0, 0x44, 0x33, 0x22, 0x11, 40, 0, 0, 0, 0x88, 0x77, 0x66,
                0x55, 0xcc, 0xbb, 0xaa, 0x99, 8, 7, 6, 5, 4, 3, 2, 1, 0x18, 0x17, 0x16, 0x15, 0x14,
                0x13, 0x12, 0x11,
            ]
        );
    }
}
