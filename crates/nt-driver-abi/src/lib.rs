//! # `nt-driver-abi` — the I/O Manager ↔ Driver Host wire protocol
//!
//! The `DH_OP_*` SURT opcodes + fixed-layout request/reply structs the I/O Manager
//! uses to drive a Driver Host: load/start/stop/unload, IRP dispatch/completion/
//! cancel, device + symbolic-link creation, and fault reports (spec §7.5).
//! Variable data (UTF-16 names/paths) follows the fixed header inline. `no_std`.

#![no_std]

use bytemuck::{Pod, Zeroable};

/// The Driver Host protocol version.
pub const DH_ABI_VERSION: u32 = 1;

/// `DH_OP_*` opcodes (spec §7.5, range `0x3000..=0x30ff`).
pub mod opcode {
    // Control + status.
    pub const DH_OP_PING: u32 = 0x3000;
    pub const DH_OP_LOAD_DRIVER: u32 = 0x3001;
    pub const DH_OP_START_DRIVER: u32 = 0x3002;
    pub const DH_OP_STOP_DRIVER: u32 = 0x3003;
    pub const DH_OP_UNLOAD_DRIVER: u32 = 0x3004;
    pub const DH_OP_QUERY_IMPORTS: u32 = 0x3005;
    pub const DH_OP_QUERY_STATUS: u32 = 0x3006;
    pub const DH_OP_FAULT_REPORT: u32 = 0x3007;

    // IRP path.
    pub const DH_OP_DISPATCH_IRP: u32 = 0x3010;
    pub const DH_OP_COMPLETE_IRP: u32 = 0x3011;
    pub const DH_OP_CANCEL_IRP: u32 = 0x3012;
    pub const DH_OP_MAP_BUFFER: u32 = 0x3013;
    pub const DH_OP_UNMAP_BUFFER: u32 = 0x3014;

    // Device + symbolic-link creation (driver -> I/O Manager).
    pub const DH_OP_CREATE_DEVICE: u32 = 0x3020;
    pub const DH_OP_DELETE_DEVICE: u32 = 0x3021;
    pub const DH_OP_CREATE_SYMBOLIC_LINK: u32 = 0x3022;
    pub const DH_OP_DELETE_SYMBOLIC_LINK: u32 = 0x3023;

    // Tracing.
    pub const DH_OP_TRACE_EVENT: u32 = 0x3030;
}

/// `DH_OP_CREATE_DEVICE` request (spec §11.1). The device name (UTF-16LE,
/// `name_units` code units) follows this header inline.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct DhCreateDeviceRequest {
    pub device_type: u32,
    pub characteristics: u32,
    pub flags: u32,
    pub extension_size: u32,
    /// UTF-16 code units of the device name that follow (0 = unnamed).
    pub name_units: u32,
    /// Non-zero if the device is exclusive.
    pub exclusive: u32,
}

/// `DH_OP_CREATE_DEVICE` reply: the canonical ids the I/O Manager assigned.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct DhCreateDeviceReply {
    pub status: i32,
    pub _reserved: u32,
    pub device_id: u64,
    /// Object Manager object id if named (0 otherwise).
    pub object_id: u64,
}

/// `DH_OP_DELETE_DEVICE` request.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct DhDeleteDeviceRequest {
    pub device_id: u64,
}

/// `DH_OP_CREATE_SYMBOLIC_LINK` / `DH_OP_DELETE_SYMBOLIC_LINK` request (spec §11.3).
/// The link path then the target path (both UTF-16LE) follow this header inline.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct DhSymbolicLinkRequest {
    pub link_units: u32,
    /// UTF-16 code units of the target that follow (0 for a delete).
    pub target_units: u32,
}

/// A bare status reply (`DH_OP_DELETE_*`, `DH_OP_CREATE_SYMBOLIC_LINK`).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct DhStatusReply {
    pub status: i32,
    pub _reserved: u32,
}

const _: () = {
    use core::mem::size_of;
    assert!(size_of::<DhCreateDeviceRequest>() == 24);
    assert!(size_of::<DhCreateDeviceReply>() == 24);
    assert!(size_of::<DhDeleteDeviceRequest>() == 8);
    assert!(size_of::<DhSymbolicLinkRequest>() == 8);
    assert!(size_of::<DhStatusReply>() == 8);
};
