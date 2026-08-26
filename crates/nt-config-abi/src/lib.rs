//! Fixed-layout SURT wire ABI for the NT Configuration Manager (registry) service.
//!
//! Every wire struct is `#[repr(C)]`, fixed-width, with UTF-16LE key/value names
//! appended after the fixed header at the given offsets — no raw pointers. Shared by
//! `nt-config-server` (decode/dispatch) + `nt-config-client` (encode). A first
//! path-addressed cut (keys by full path, not handles) plus semantic devnode queries;
//! handles come later.

#![no_std]

/// The Configuration Manager's SURT opcode range.
pub const CM_OPCODE_MIN: u16 = 0x2100;
pub const CM_OPCODE_MAX: u16 = 0x21ff;
pub const CM_ABI_VERSION: u16 = 2;
pub const CM_MAX_INSTANCE_UNITS: usize = 512;
/// Maximum property payload carried by one SURT completion frame.
pub const CM_DEVICE_PROPERTY_CHUNK_BYTES: usize = 4096;
/// Maximum service-name units accepted by one semantic driver-binding request.
pub const CM_MAX_SERVICE_UNITS: usize = 512;
/// Maximum payload carried by one driver-binding completion frame.
pub const CM_DRIVER_SERVICE_CHUNK_BYTES: usize = 4096;
pub const CM_DRIVER_SERVICE_SNAPSHOT_MAGIC: u32 = 0x4453_4D43; // `CMSD`
pub const CM_DRIVER_SERVICE_SNAPSHOT_VERSION: u16 = 1;
pub const CM_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES: usize = 16;
/// Maximum payload carried by one SYSTEM-hive import request frame.
pub const CM_HIVE_IMPORT_CHUNK_BYTES: usize = 4064;
/// Maximum payload carried by one mounted-hive key snapshot completion frame.
pub const CM_HIVE_KEY_CHUNK_BYTES: usize = 4096;
pub const CM_HIVE_KEY_SNAPSHOT_MAGIC: u32 = 0x4B48_4D43; // `CMHK`
pub const CM_HIVE_KEY_SNAPSHOT_VERSION: u16 = 1;
pub const CM_HIVE_KEY_SNAPSHOT_HEADER_BYTES: usize = 24;
pub const CM_MAX_HIVE_PATH_UNITS: usize = 512;
pub const CM_OPTIONAL_STRING_ABSENT: u32 = u32::MAX;
pub const CM_OPTIONAL_BLOB_ABSENT: u32 = u32::MAX;

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

/// `create_key` / `open_key`: a single key path (UTF-16LE) at `[path_offset..]`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct CmKeyRequest {
    pub abi_size: u16,
    pub _pad: u16,
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
                40, 0, 2, 0, 2, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0xcc,
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
                32, 0, 2, 0, 2, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 32, 0, 0,
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
        assert_eq!(core::mem::size_of::<CmHiveImportRequest>(), 32);
        assert_eq!(core::mem::size_of::<CmHiveKeyRequest>(), 32);

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
    }
}
