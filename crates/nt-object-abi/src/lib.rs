//! # `nt-object-abi` — Object Manager service-mode wire ABI
//!
//! The fixed-layout structs and opcodes exchanged when the Object Manager runs
//! as an isolated seL4 component reached over SURT. Everything here is
//! transport-agnostic: opcodes and `request_id`/`object_id`/etc. ride in the
//! SURT SQE/CQE fields; the variable-length payloads (paths, names) live in
//! registered buffers described by the request structs below.
//!
//! Invariants for every wire struct (spec §12.4): `#[repr(C)]`, fixed-width
//! integers only, no Rust references, no raw pointers, explicit length fields,
//! UTF-16 for names/paths. Sizes/alignments are asserted at compile time so a
//! layout change can't slip through.

#![no_std]

/// ABI version. Bump on any incompatible wire change.
pub const OB_ABI_VERSION: u32 = 1;

/// The reserved SURT opcode range for the Object Manager protocol (spec §12).
pub const OB_OPCODE_MIN: u16 = 0x2000;
pub const OB_OPCODE_MAX: u16 = 0x20ff;

/// Object Manager SURT opcodes.
pub mod opcode {
    pub const OB_OP_PING: u16 = 0x2000;
    pub const OB_OP_REGISTER_CLIENT: u16 = 0x2001;
    pub const OB_OP_CLOSE_CLIENT: u16 = 0x2002;

    pub const OB_OP_CREATE_OBJECT: u16 = 0x2010;
    pub const OB_OP_OPEN_OBJECT: u16 = 0x2011;
    pub const OB_OP_CLOSE_HANDLE: u16 = 0x2012;
    pub const OB_OP_REFERENCE_HANDLE: u16 = 0x2013;
    pub const OB_OP_DEREFERENCE_OBJECT: u16 = 0x2014;
    pub const OB_OP_MAKE_TEMPORARY: u16 = 0x2015;

    pub const OB_OP_CREATE_DIRECTORY: u16 = 0x2020;
    pub const OB_OP_CREATE_SYMBOLIC_LINK: u16 = 0x2021;
    pub const OB_OP_QUERY_SYMBOLIC_LINK: u16 = 0x2022;

    pub const OB_OP_LOOKUP_PATH: u16 = 0x2030;
    pub const OB_OP_QUERY_OBJECT: u16 = 0x2031;
    pub const OB_OP_QUERY_DIRECTORY: u16 = 0x2032;

    /// Deferred — see spec §12.1.
    pub const OB_OP_DUPLICATE_HANDLE: u16 = 0x2040;
}

/// True if `op` is an Object Manager opcode.
#[inline]
pub const fn is_ob_opcode(op: u16) -> bool {
    op >= OB_OPCODE_MIN && op <= OB_OPCODE_MAX
}

/// Reserved / null object id on the wire.
pub const OB_NULL_OBJECT_ID: u64 = 0;

// ---------------------------------------------------------------------------
// Request payloads (in registered buffers). Names/paths are UTF-16 code units
// at `*_offset` for `*_len_bytes` bytes within the same buffer.
// ---------------------------------------------------------------------------

/// `OB_OP_CREATE_OBJECT` payload.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ObCreateObjectRequest {
    /// Size of this struct as the sender knew it (forward-compat guard).
    pub abi_size: u16,
    /// `OBJ_*` attribute flags.
    pub obj_attributes: u16,
    /// Requested access mask.
    pub desired_access: u32,
    /// Object type id.
    pub type_id: u64,
    /// Optional root directory handle (0 = none / absolute name).
    pub root_directory: u64,
    /// Byte offset of the (optional) UTF-16 name within the buffer.
    pub name_offset: u32,
    /// Length in bytes of the UTF-16 name (0 = unnamed).
    pub name_len_bytes: u32,
}

/// `OB_OP_OPEN_OBJECT` payload.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ObOpenObjectRequest {
    pub abi_size: u16,
    pub flags: u16,
    pub desired_access: u32,
    /// Expected object type id (0 = any).
    pub expected_type: u64,
    pub path_offset: u32,
    pub path_len_bytes: u32,
}

/// `OB_OP_CREATE_DIRECTORY` payload.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ObCreateDirectoryRequest {
    pub abi_size: u16,
    pub obj_attributes: u16,
    pub desired_access: u32,
    pub path_offset: u32,
    pub path_len_bytes: u32,
}

/// `OB_OP_CREATE_SYMBOLIC_LINK` payload — link path + target path both in-buffer.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ObCreateSymbolicLinkRequest {
    pub abi_size: u16,
    pub obj_attributes: u16,
    pub desired_access: u32,
    pub link_offset: u32,
    pub link_len_bytes: u32,
    pub target_offset: u32,
    pub target_len_bytes: u32,
}

/// `OB_OP_LOOKUP_PATH` payload.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ObLookupPathRequest {
    pub abi_size: u16,
    pub flags: u16,
    pub path_offset: u32,
    pub path_len_bytes: u32,
}

/// `OB_OP_CLOSE_HANDLE` payload.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ObCloseHandleRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    pub _reserved2: u32,
    pub handle: u64,
}

/// A generic reply carried in the SURT CQE (spec §12.3). `status` is an
/// `NTSTATUS` as `i32`; `detail0`/`detail1` carry a handle or object id split
/// (low/high) or a scalar result, per opcode.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ObReply {
    pub status: i32,
    pub information: u32,
    pub detail0: u64,
    pub detail1: u64,
}

// ---------------------------------------------------------------------------
// Compile-time layout guarantees.
// ---------------------------------------------------------------------------
const _: () = {
    use core::mem::{align_of, size_of};
    assert!(size_of::<ObCreateObjectRequest>() == 32);
    assert!(size_of::<ObOpenObjectRequest>() == 24);
    assert!(size_of::<ObCreateDirectoryRequest>() == 16);
    assert!(size_of::<ObCreateSymbolicLinkRequest>() == 24);
    assert!(size_of::<ObLookupPathRequest>() == 12);
    assert!(size_of::<ObCloseHandleRequest>() == 16);
    assert!(size_of::<ObReply>() == 24);
    // 8-byte alignment (u64 fields) except the all-32-bit ones.
    assert!(align_of::<ObOpenObjectRequest>() == 8);
    assert!(align_of::<ObLookupPathRequest>() == 4);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcodes_in_range() {
        assert!(is_ob_opcode(opcode::OB_OP_PING));
        assert!(is_ob_opcode(opcode::OB_OP_OPEN_OBJECT));
        assert!(is_ob_opcode(opcode::OB_OP_DUPLICATE_HANDLE));
        assert!(!is_ob_opcode(0x1fff));
        assert!(!is_ob_opcode(0x2100));
    }

    #[test]
    fn version_is_one() {
        assert_eq!(OB_ABI_VERSION, 1);
    }
}
