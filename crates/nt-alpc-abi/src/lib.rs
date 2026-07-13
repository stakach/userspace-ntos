//! # `nt-alpc-abi` — ALPC (`NtAlpc*`, Vista+/Win7) ABI + service wire structs
//!
//! Two layers:
//!
//! 1. **The native ALPC ABI** — the documented `#[repr(C)]` x64 layouts the
//!    `NtAlpc*` syscalls take (`PORT_MESSAGE`, `ALPC_PORT_ATTRIBUTES`,
//!    `ALPC_MESSAGE_ATTRIBUTES` + the per-attribute structs). Sizes are asserted
//!    at compile time. Source: phnt (`ntlpcapi.h`) + Windows Internals 6e ch.3.
//!    NT5 (`references/nt5`) predates ALPC; ReactOS has only ntdll *stubs* — so
//!    these are the documented (undocumented-by-MS) structures, not derived from
//!    the reference trees.
//!
//! 2. **The SURT service-mode wire structs** — the request/reply structs the
//!    executive exchanges with the isolated port-service component for the ALPC
//!    control plane, mirroring `nt-lpc-abi`. Names/blobs ride at `*_offset`/
//!    `*_len_bytes` in the data frame; one [`AlpcReply`] rides the CQE.
//!
//! Invariants for every wire struct: `#[repr(C)]`, fixed-width integers only, no
//! Rust references / raw pointers, explicit length fields, UTF-16 for names.

#![no_std]

/// ABI version. Bump on any incompatible wire change.
pub const ALPC_ABI_VERSION: u32 = 1;

// ===========================================================================
// 1. Native ALPC ABI (x64 documented layouts)
// ===========================================================================

/// `PORT_MESSAGE` — the 40-byte (x64) message header shared by LPC and ALPC.
/// The union fields are flattened to their most-used members; the aliases
/// (`u1.Length`@0, `u2.ZeroInit`@4, `CallbackId`@32) overlap by construction.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct PortMessage {
    /// `u1.s1.DataLength` — payload bytes after the 40-byte header.
    pub data_length: u16,
    /// `u1.s1.TotalLength` — header + payload.
    pub total_length: u16,
    /// `u2.s2.Type` — the `PORT_MESSAGE` type (LPC_REQUEST / LPC_REPLY / …).
    pub msg_type: u16,
    /// `u2.s2.DataInfoOffset`.
    pub data_info_offset: u16,
    /// `ClientId.UniqueProcess`.
    pub client_process: u64,
    /// `ClientId.UniqueThread`.
    pub client_thread: u64,
    /// `MessageId`.
    pub message_id: u32,
    pub _pad: u32,
    /// `ClientViewSize` (alias `CallbackId` in the low 32 bits).
    pub client_view_size: u64,
}

/// `SECURITY_QUALITY_OF_SERVICE` (x64: 12 bytes incl. tail pad).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct SecurityQualityOfService {
    pub length: u32,
    pub impersonation_level: u32,
    pub context_tracking_mode: u8,
    pub effective_only: u8,
    pub _pad: u16,
}

/// `ALPC_PORT_ATTRIBUTES` — x64, 72 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcPortAttributes {
    pub flags: u32,
    pub security_qos: SecurityQualityOfService,
    pub max_message_length: u64,
    pub memory_bandwidth: u64,
    pub max_pool_usage: u64,
    pub max_section_size: u64,
    pub max_view_size: u64,
    pub max_total_section_size: u64,
    pub dup_object_types: u32,
    /// x64-only trailing reserved word.
    pub reserved: u32,
}

/// `ALPC_MESSAGE_ATTRIBUTES` header — 8 bytes. The per-attribute structs follow
/// in memory in a fixed order determined by the set `ValidAttributes` bits.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcMessageAttributes {
    pub allocated_attributes: u32,
    pub valid_attributes: u32,
}

/// `ALPC_DATA_VIEW_ATTR` — x64, 32 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcDataViewAttr {
    pub flags: u32,
    pub _pad: u32,
    pub section_handle: u64,
    pub view_base: u64,
    pub view_size: u64,
}

/// `ALPC_HANDLE_ATTR` — x64, 24 bytes (single-handle Win7 form).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcHandleAttr {
    pub flags: u32,
    pub _pad: u32,
    pub handle: u64,
    pub object_type: u32,
    pub desired_access: u32,
}

/// `ALPC_CONTEXT_ATTR` — x64, 32 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcContextAttr {
    pub port_context: u64,
    pub message_context: u64,
    pub sequence: u32,
    pub message_id: u32,
    pub callback_id: u32,
    pub _pad: u32,
}

/// `ALPC_SECURITY_ATTR` — x64, 24 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcSecurityAttr {
    pub flags: u32,
    pub _pad: u32,
    pub qos: u64,
    pub context_handle: u64,
}

/// `ALPC_TOKEN_ATTR` — x64, 24 bytes. NB: uncertain layout (not in the phnt
/// version audited; from Windows Internals). Present for completeness; the token
/// attribute does not bridge to LPC so its exact layout is non-load-bearing here.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcTokenAttr {
    pub token_id: u64,
    pub authentication_id: u64,
    pub modified_id: u64,
}

/// `ALPC_MESSAGE_*_ATTRIBUTE` present-flags (the `ValidAttributes`/
/// `AllocatedAttributes` bitmask). Win7 set; DIRECT/WORK_ON_BEHALF are Win8+.
pub mod msg_attr_flag {
    pub const SECURITY: u32 = 0x8000_0000;
    pub const VIEW: u32 = 0x4000_0000;
    pub const CONTEXT: u32 = 0x2000_0000;
    pub const HANDLE: u32 = 0x1000_0000;
    /// Reserved on the audited phnt; named TOKEN on Win8+.
    pub const TOKEN: u32 = 0x0800_0000;
}

/// `ALPC_PORFLG_*` — the upper `ALPC_PORT_ATTRIBUTES.Flags` group.
pub mod port_flag {
    pub const NONE: u32 = 0x0;
    /// Classic-LPC compatibility mode — the port accepts LPC-shaped traffic.
    pub const LPC_MODE: u32 = 0x1000;
    pub const ALLOW_IMPERSONATION: u32 = 0x1_0000;
    pub const ALLOW_LPC_REQUESTS: u32 = 0x2_0000;
    pub const WAITABLE_PORT: u32 = 0x4_0000;
    pub const ALLOW_DUP_OBJECT: u32 = 0x8_0000;
}

/// `PORT_MESSAGE.Type` values (shared with LPC).
pub mod msg_type {
    pub const REQUEST: u16 = 1;
    pub const REPLY: u16 = 2;
    pub const DATAGRAM: u16 = 3;
    pub const PORT_CLOSED: u16 = 5;
    pub const CONNECTION_REQUEST: u16 = 10;
    pub const CONNECTION_REFUSED: u16 = 11;
}

// ===========================================================================
// 2. SURT service-mode wire structs (executive ↔ isolated port service)
// ===========================================================================

/// The reserved SURT opcode range for ALPC (fresh block after LPC's 0x2200).
pub const ALPC_OPCODE_MIN: u16 = 0x2300;
pub const ALPC_OPCODE_MAX: u16 = 0x23ff;

/// ALPC SURT opcodes.
pub mod opcode {
    pub const ALPC_OP_PING: u16 = 0x2300;
    pub const ALPC_OP_CREATE_PORT: u16 = 0x2301;
    pub const ALPC_OP_CONNECT_PORT: u16 = 0x2302;
    pub const ALPC_OP_ACCEPT_CONNECT: u16 = 0x2303;
    pub const ALPC_OP_SEND_RECEIVE: u16 = 0x2304;
    pub const ALPC_OP_DISCONNECT_PORT: u16 = 0x2305;
    pub const ALPC_OP_RECEIVE: u16 = 0x2306;
    // Port sections / views (defined; server-modeled in the first increment).
    pub const ALPC_OP_CREATE_PORT_SECTION: u16 = 0x2307;
    pub const ALPC_OP_DELETE_PORT_SECTION: u16 = 0x2308;
    pub const ALPC_OP_CREATE_SECTION_VIEW: u16 = 0x2309;
    pub const ALPC_OP_DELETE_SECTION_VIEW: u16 = 0x230a;
    pub const ALPC_OP_CLOSE_PORT: u16 = 0x230b;
    // Section-view data plane: write/read bytes THROUGH a mapped view into the
    // section's shared backing store (the ALPC big-data / WOW64 mechanism).
    pub const ALPC_OP_WRITE_SECTION_VIEW: u16 = 0x230c;
    pub const ALPC_OP_READ_SECTION_VIEW: u16 = 0x230d;
}

/// `AlpcSendReceiveRequest.flags` bits.
pub mod send_flag {
    /// On a receive, serialize the received `ALPC_MESSAGE_ATTRIBUTES` (the 8-byte
    /// header + the per-attribute structs, in the fixed SECURITY,VIEW,CONTEXT,
    /// HANDLE,TOKEN order) into the FRONT of the reply frame, before the message
    /// body. `AlpcSendReceiveRequest.valid_attributes` is read as the receiver's
    /// `AllocatedAttributes` (which attributes it has buffer space for); the
    /// returned `ValidAttributes` = allocated & present.
    pub const RECV_ATTRIBUTES: u32 = 0x1;
}

/// True if `op` is an ALPC opcode.
#[inline]
pub const fn is_alpc_opcode(op: u16) -> bool {
    op >= ALPC_OPCODE_MIN && op <= ALPC_OPCODE_MAX
}

/// `ALPC_OP_CREATE_PORT` — create a named (or unnamed) ALPC port.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcCreatePortRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    /// `ALPC_PORT_ATTRIBUTES.Flags` (e.g. `LPC_MODE`).
    pub port_flags: u32,
    pub max_message_length: u32,
    pub name_offset: u32,
    pub name_len_bytes: u32,
    pub _reserved2: u32,
}

/// `ALPC_OP_CONNECT_PORT` — connect to a named ALPC port, carrying the connect
/// `PORT_MESSAGE` payload + the client's message attributes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcConnectPortRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    /// `IMAGE_SUBSYSTEM_*` if the connector chose to advertise one (0 otherwise).
    pub subsystem_type: u32,
    pub connect_flags: u32,
    pub name_offset: u32,
    pub name_len_bytes: u32,
    /// The connect `PORT_MESSAGE` (header + payload) — the ALPC connect blob.
    pub message_offset: u32,
    pub message_len_bytes: u32,
    /// Bitmask of `ALPC_MESSAGE_*_ATTRIBUTE` valid on the connect message.
    pub valid_attributes: u32,
    /// The serialized attribute payload (see [`msg_attr_flag`]).
    pub attr_offset: u32,
    pub attr_len_bytes: u32,
}

/// `ALPC_OP_ACCEPT_CONNECT` — accept (or refuse) a pending connection.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcAcceptConnectRequest {
    pub abi_size: u16,
    /// Non-zero = accept.
    pub accept: u16,
    pub _reserved: u32,
    pub connection_id: u64,
    pub port_context: u64,
}

/// `ALPC_OP_SEND_RECEIVE` / `ALPC_OP_RECEIVE` — send a `PORT_MESSAGE` and/or
/// receive the next one. The send message rides at `message_offset`; a received
/// message + its projected attributes are written to the reply frame.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcSendReceiveRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    pub flags: u32,
    pub port_handle: u64,
    pub message_offset: u32,
    pub message_len_bytes: u32,
    pub valid_attributes: u32,
    pub attr_offset: u32,
    pub attr_len_bytes: u32,
    pub _reserved2: u32,
}

/// `ALPC_OP_CREATE_PORT_SECTION` — create a shared-memory section on a port.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcCreatePortSectionRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    pub flags: u32,
    pub port_handle: u64,
    pub section_handle: u64,
    pub section_size: u64,
}

/// `ALPC_OP_CREATE_SECTION_VIEW` — map a view of a port section.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcCreateSectionViewRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    pub flags: u32,
    pub port_handle: u64,
    pub alpc_section_handle: u64,
    pub view_size: u64,
}

/// `ALPC_OP_WRITE_SECTION_VIEW` / `ALPC_OP_READ_SECTION_VIEW` — transfer bytes
/// THROUGH a mapped section view into (write) or out of (read) the section's
/// shared backing store. On a write the payload rides at `data_offset` in the
/// request frame; on a read `data_len_bytes` bytes are returned in the reply
/// frame. `view_offset` is the byte offset WITHIN the view.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcViewIoRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    pub flags: u32,
    /// The `ViewBase` returned by `ALPC_OP_CREATE_SECTION_VIEW`.
    pub view_base: u64,
    /// Byte offset within the view.
    pub view_offset: u64,
    /// Where the write payload sits in the request frame (write only).
    pub data_offset: u32,
    /// Number of bytes to write (from the request frame) or read (into the reply).
    pub data_len_bytes: u32,
}

/// `ALPC_OP_DISCONNECT_PORT` / `ALPC_OP_CLOSE_PORT` / `ALPC_OP_DELETE_*` —
/// tear-down ops keyed by a single handle/id.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcHandleRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    pub flags: u32,
    /// A port handle, connection id, section handle, or view base per the op.
    pub handle: u64,
}

/// A generic reply carried in the SURT CQE. `status` is an `NTSTATUS` as `i32`.
/// Per op: `detail0` = a handle (port / comm-port / section), `detail1` = a
/// connection id or received-message type; `information` = out-payload byte
/// length written to the reply frame.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AlpcReply {
    pub status: i32,
    pub information: u32,
    pub detail0: u64,
    pub detail1: u64,
}

// ---------------------------------------------------------------------------
// Compile-time layout guarantees.
// ---------------------------------------------------------------------------
const _: () = {
    use core::mem::size_of;
    // Native ALPC ABI (x64).
    assert!(size_of::<PortMessage>() == 40);
    assert!(size_of::<SecurityQualityOfService>() == 12);
    assert!(size_of::<AlpcPortAttributes>() == 72);
    assert!(size_of::<AlpcMessageAttributes>() == 8);
    assert!(size_of::<AlpcDataViewAttr>() == 32);
    assert!(size_of::<AlpcHandleAttr>() == 24);
    assert!(size_of::<AlpcContextAttr>() == 32);
    assert!(size_of::<AlpcSecurityAttr>() == 24);
    assert!(size_of::<AlpcTokenAttr>() == 24);
    // Service wire structs.
    assert!(size_of::<AlpcCreatePortRequest>() == 24);
    assert!(size_of::<AlpcConnectPortRequest>() == 40);
    assert!(size_of::<AlpcAcceptConnectRequest>() == 24);
    assert!(size_of::<AlpcSendReceiveRequest>() == 40);
    assert!(size_of::<AlpcCreatePortSectionRequest>() == 32);
    assert!(size_of::<AlpcCreateSectionViewRequest>() == 32);
    assert!(size_of::<AlpcViewIoRequest>() == 32);
    assert!(size_of::<AlpcHandleRequest>() == 16);
    assert!(size_of::<AlpcReply>() == 24);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcodes_in_range() {
        assert!(is_alpc_opcode(opcode::ALPC_OP_PING));
        assert!(is_alpc_opcode(opcode::ALPC_OP_CLOSE_PORT));
        assert!(!is_alpc_opcode(0x22ff));
        assert!(!is_alpc_opcode(0x2400));
    }

    #[test]
    fn attr_flags_distinct() {
        // The four bridging-relevant flags must be distinct single bits.
        let all = msg_attr_flag::SECURITY
            | msg_attr_flag::VIEW
            | msg_attr_flag::CONTEXT
            | msg_attr_flag::HANDLE
            | msg_attr_flag::TOKEN;
        assert_eq!(all.count_ones(), 5);
        // HANDLE and TOKEN are distinct (the audit corrected a collision).
        assert_ne!(msg_attr_flag::HANDLE, msg_attr_flag::TOKEN);
    }
}
