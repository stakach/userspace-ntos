//! # `nt-lpc-abi` — NT LPC service-mode wire ABI
//!
//! The fixed-layout structs and opcodes exchanged when NT LPC (Local Procedure
//! Call — the `\SmApiPort` / `\Windows\ApiPort` ports) runs as an **isolated
//! seL4 component** reached over SURT. This mirrors [`nt-object-abi`]: opcodes +
//! `request_id`/detail fields ride in the SURT SQE/CQE; variable-length payloads
//! (port names, connection-info blobs, `PORT_MESSAGE`s) live in the request/reply
//! data frames, addressed by the `*_offset`/`*_len_bytes` fields below.
//!
//! Invariants for every wire struct: `#[repr(C)]`, fixed-width integers only, no
//! Rust references / raw pointers, explicit length fields, UTF-16 for names.
//! Sizes/alignments are asserted at compile time.
//!
//! Only the CONNECT rendezvous ops (create/connect/accept/complete) are load-
//! bearing today (path A); the request/reply message ops are defined so the
//! message loop is a later fill-in, not an ABI change.

#![no_std]

/// ABI version. Bump on any incompatible wire change.
pub const LPC_ABI_VERSION: u32 = 1;

/// The reserved SURT opcode range for the LPC protocol (fresh block after
/// object 0x2000 / config 0x2100).
pub const LPC_OPCODE_MIN: u16 = 0x2200;
pub const LPC_OPCODE_MAX: u16 = 0x22ff;

/// LPC SURT opcodes.
pub mod opcode {
    pub const LPC_OP_PING: u16 = 0x2200;

    // Connection rendezvous (path A: create + connect).
    pub const LPC_OP_CREATE_PORT: u16 = 0x2201;
    pub const LPC_OP_CONNECT_PORT: u16 = 0x2202;
    pub const LPC_OP_ACCEPT_CONNECT: u16 = 0x2203;
    pub const LPC_OP_COMPLETE_CONNECT: u16 = 0x2204;

    // Message loop (path B / bulk — defined, not yet implemented server-side).
    pub const LPC_OP_REPLY_WAIT_RECEIVE: u16 = 0x2205;
    pub const LPC_OP_REQUEST_WAIT_REPLY: u16 = 0x2206;
    pub const LPC_OP_REPLY_PORT: u16 = 0x2207;
    pub const LPC_OP_LISTEN_PORT: u16 = 0x2208;

    pub const LPC_OP_CLOSE_PORT: u16 = 0x2209;
}

/// True if `op` is an LPC opcode.
#[inline]
pub const fn is_lpc_opcode(op: u16) -> bool {
    op >= LPC_OPCODE_MIN && op <= LPC_OPCODE_MAX
}

/// LPC `PORT_MESSAGE.u2.s2.Type` values (dispatch key on a received message).
pub mod msg_type {
    pub const LPC_REQUEST: u16 = 1;
    pub const LPC_REPLY: u16 = 2;
    pub const LPC_PORT_CLOSED: u16 = 5;
    pub const LPC_CONNECTION_REQUEST: u16 = 10;
    pub const LPC_CONNECTION_REFUSED: u16 = 11;
}

// ---------------------------------------------------------------------------
// Request payloads. Names / blobs are at `*_offset` for `*_len_bytes` bytes in
// the same buffer (names UTF-16, blobs raw).
// ---------------------------------------------------------------------------

/// `LPC_OP_CREATE_PORT` — create a named (or unnamed) port.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcCreatePortRequest {
    pub abi_size: u16,
    /// Reserved (OBJECT_ATTRIBUTES flags).
    pub flags: u16,
    pub max_connection_info: u32,
    pub max_message: u32,
    pub max_pool: u32,
    /// Byte offset of the UTF-16 port name (0-length = unnamed communication port).
    pub name_offset: u32,
    pub name_len_bytes: u32,
}

/// `LPC_OP_CONNECT_PORT` — connect to a named port; carries the connection-info blob.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcConnectPortRequest {
    pub abi_size: u16,
    pub flags: u16,
    /// `IMAGE_SUBSYSTEM_*` from the `SB_CONNECTION_INFO` (0 = plain client).
    pub subsystem_type: u32,
    pub name_offset: u32,
    pub name_len_bytes: u32,
    pub conninfo_offset: u32,
    pub conninfo_len_bytes: u32,
}

/// `LPC_OP_ACCEPT_CONNECT` — the server accepts (or refuses) a pending connection.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcAcceptConnectRequest {
    pub abi_size: u16,
    /// Non-zero = accept, zero = refuse.
    pub accept: u16,
    pub _reserved: u32,
    pub connection_id: u64,
    /// Opaque server cookie returned by future receives on this connection.
    pub port_context: u64,
}

/// `LPC_OP_COMPLETE_CONNECT` — the server completes an accepted connection,
/// unblocking the connector.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcCompleteConnectRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    pub _reserved2: u32,
    /// The connection to complete (or the server comm-port handle).
    pub connection_id: u64,
}

/// `LPC_OP_REPLY_WAIT_RECEIVE` / `LPC_OP_LISTEN_PORT` — receive the next message
/// (optionally sending `reply_msg` first). Received message is written to the
/// reply data frame.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcReceiveRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    pub _reserved2: u32,
    pub port_handle: u64,
    pub reply_msg_offset: u32,
    pub reply_msg_len_bytes: u32,
}

/// `LPC_OP_REQUEST_WAIT_REPLY` / `LPC_OP_REPLY_PORT` — send a request/reply.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcMessageRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    pub _reserved2: u32,
    pub port_handle: u64,
    pub msg_offset: u32,
    pub msg_len_bytes: u32,
}

/// `LPC_OP_CLOSE_PORT` — close a port handle.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcClosePortRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    pub _reserved2: u32,
    pub port_handle: u64,
}

/// A generic reply carried in the SURT CQE. `status` is an `NTSTATUS` as `i32`.
/// Per op: `detail0` = a handle (port / comm-port), `detail1` = a connection id
/// or received-message type; `information` = out-payload byte length.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcReply {
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
    assert!(size_of::<LpcCreatePortRequest>() == 24);
    assert!(size_of::<LpcConnectPortRequest>() == 24);
    assert!(size_of::<LpcAcceptConnectRequest>() == 24);
    assert!(size_of::<LpcCompleteConnectRequest>() == 16);
    assert!(size_of::<LpcReceiveRequest>() == 24);
    assert!(size_of::<LpcMessageRequest>() == 24);
    assert!(size_of::<LpcClosePortRequest>() == 16);
    assert!(size_of::<LpcReply>() == 24);
    assert!(align_of::<LpcAcceptConnectRequest>() == 8);
    assert!(align_of::<LpcCreatePortRequest>() == 4);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcodes_in_range() {
        assert!(is_lpc_opcode(opcode::LPC_OP_PING));
        assert!(is_lpc_opcode(opcode::LPC_OP_CONNECT_PORT));
        assert!(is_lpc_opcode(opcode::LPC_OP_CLOSE_PORT));
        assert!(!is_lpc_opcode(0x21ff));
        assert!(!is_lpc_opcode(0x2300));
    }

    #[test]
    fn version_is_one() {
        assert_eq!(LPC_ABI_VERSION, 1);
    }
}
