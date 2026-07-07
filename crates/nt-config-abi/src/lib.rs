//! Fixed-layout SURT wire ABI for the NT Configuration Manager (registry) service.
//!
//! Every wire struct is `#[repr(C)]`, fixed-width, with UTF-16LE key/value names
//! appended after the fixed header at the given offsets — no raw pointers. Shared by
//! `nt-config-server` (decode/dispatch) + `nt-config-client` (encode). A first
//! path-addressed cut (keys by full path, not handles); handles come later.

#![no_std]

/// The Configuration Manager's SURT opcode range.
pub const CM_OPCODE_MIN: u16 = 0x2100;
pub const CM_OPCODE_MAX: u16 = 0x21ff;

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

macro_rules! wire {
    ($t:ty) => {
        impl $t {
            /// The fixed header as bytes (for prepending before the string payload).
            pub fn as_bytes(&self) -> &[u8] {
                // SAFETY: `#[repr(C)]` POD; no padding beyond declared fields; read-only.
                unsafe {
                    core::slice::from_raw_parts(self as *const _ as *const u8, core::mem::size_of::<$t>())
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
wire!(CmValueRequest);

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
