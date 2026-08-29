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
//! The connection rendezvous and request/reply message operations are both live. Kernel-generated
//! typed messages use a distinct request-port operation so they retain their kernel message type.

#![no_std]

/// ABI version. Bump on any incompatible wire change.
pub const LPC_ABI_VERSION: u32 = 9;

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

    pub const LPC_OP_QUERY_HANDLE: u16 = 0x220a;

    // Kernel-internal LpcRequestPort: preserve a kernel message type such as LPC_CLIENT_DIED.
    pub const LPC_OP_REQUEST_PORT: u16 = 0x220b;

    // Validate a server-held request before native LPC client impersonation.
    pub const LPC_OP_QUERY_REQUEST: u16 = 0x220c;

    // Complete or cancel one synchronous request by its kernel-authored message identity.
    pub const LPC_OP_RECEIVE_REPLY: u16 = 0x220d;
    pub const LPC_OP_CANCEL_REQUEST: u16 = 0x220e;

    // Kernel-held connection-port reference and typed synchronous request plane. These operations
    // are not exposed as native user services; the executive uses them for facilities such as the
    // default hard-error port, whose kernel reference survives the registering user handle.
    pub const LPC_OP_RETAIN_CONNECTION_PORT: u16 = 0x220f;
    pub const LPC_OP_RELEASE_CONNECTION_PORT: u16 = 0x2210;
    pub const LPC_OP_KERNEL_REQUEST_WAIT_REPLY: u16 = 0x2211;

    // Kernel-held reference to the concrete connection or client communication-port object named
    // by a user handle. This is used for process exception-port ownership.
    pub const LPC_OP_RETAIN_PORT_OBJECT: u16 = 0x2212;
    pub const LPC_OP_RELEASE_PORT_OBJECT: u16 = 0x2213;
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
    pub const LPC_DATAGRAM: u16 = 3;
    pub const LPC_PORT_CLOSED: u16 = 5;
    pub const LPC_CLIENT_DIED: u16 = 6;
    pub const LPC_EXCEPTION: u16 = 7;
    pub const LPC_DEBUG_EVENT: u16 = 8;
    pub const LPC_ERROR_EVENT: u16 = 9;
    pub const LPC_CONNECTION_REQUEST: u16 = 10;
    pub const LPC_CONNECTION_REFUSED: u16 = 11;
}

/// `LPC_OP_QUERY_HANDLE` endpoint codes.
pub mod handle_endpoint {
    pub const NONE: u16 = 0;
    pub const LISTEN_PORT: u16 = 1;
    pub const CLIENT_COMM_PORT: u16 = 2;
    pub const SERVER_COMM_PORT: u16 = 3;
}

/// `LPC_OP_QUERY_HANDLE` connection-state codes. Zero means "not a connection".
pub mod connection_state {
    pub const NONE: u16 = 0;
    pub const PENDING: u16 = 1;
    pub const RECEIVED: u16 = 2;
    pub const ACCEPTED: u16 = 3;
    pub const CONNECTED: u16 = 4;
    pub const REFUSED: u16 = 5;
}

pub const LPC_QUERY_HANDLE_NAME_MAX_UNITS: usize = 64;

/// Native x64 `PORT_MESSAGE` fixed header size.
pub const PORT_MESSAGE_HEADER_LEN: usize = 0x28;
/// Largest complete native message carried by the current LPC data-frame ABI.
pub const PORT_MESSAGE_MAX_LEN: usize = 512;
/// Native x64 `CLIENT_DIED_MSG`: one `PORT_MESSAGE` followed by the thread create time.
pub const CLIENT_DIED_MESSAGE_LEN: usize = PORT_MESSAGE_HEADER_LEN + core::mem::size_of::<i64>();

/// Native x64 `PORT_VIEW` size.
pub const PORT_VIEW_LEN: usize = 0x30;
/// Native x64 `REMOTE_PORT_VIEW` size.
pub const REMOTE_PORT_VIEW_LEN: usize = 0x18;

/// Kernel-captured input fields from a native x64 `PORT_VIEW`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortViewCapture {
    pub section_handle: u64,
    pub section_offset: u64,
    pub view_size: u64,
}

/// Bases produced after one offered section is mapped into its owner and peer processes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MappedPortView {
    pub owner_base: u64,
    pub peer_base: u64,
    pub view_size: u64,
}

/// Native result fields for a full `PORT_VIEW`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortViewResult {
    pub view_size: u64,
    pub view_base: u64,
    pub view_remote_base: u64,
}

/// Native result fields for a `REMOTE_PORT_VIEW`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RemotePortViewResult {
    pub view_size: u64,
    pub view_base: u64,
}

/// Results returned to the two participants after both independently optional views are mapped.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectionViewResults {
    pub connector_view: Option<PortViewResult>,
    pub acceptor_client_view: Option<RemotePortViewResult>,
    pub acceptor_view: Option<PortViewResult>,
    pub connector_server_view: Option<RemotePortViewResult>,
}

/// Associate owner and peer bases with the four native LPC view outputs.
pub const fn connection_view_results(
    connector_offered: Option<MappedPortView>,
    acceptor_offered: Option<MappedPortView>,
) -> ConnectionViewResults {
    let (connector_view, acceptor_client_view) = match connector_offered {
        Some(mapped) => (
            Some(PortViewResult {
                view_size: mapped.view_size,
                view_base: mapped.owner_base,
                view_remote_base: mapped.peer_base,
            }),
            Some(RemotePortViewResult {
                view_size: mapped.view_size,
                view_base: mapped.peer_base,
            }),
        ),
        None => (None, None),
    };
    let (acceptor_view, connector_server_view) = match acceptor_offered {
        Some(mapped) => (
            Some(PortViewResult {
                view_size: mapped.view_size,
                view_base: mapped.owner_base,
                view_remote_base: mapped.peer_base,
            }),
            Some(RemotePortViewResult {
                view_size: mapped.view_size,
                view_base: mapped.peer_base,
            }),
        ),
        None => (None, None),
    };
    ConnectionViewResults {
        connector_view,
        acceptor_client_view,
        acceptor_view,
        connector_server_view,
    }
}

/// Structural or section-geometry failure while capturing a native LPC view.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PortViewError {
    InvalidLength,
    MisalignedSectionOffset,
    ViewOutsideSection,
}

/// Capture and validate the pointer-free fields of a native x64 `PORT_VIEW`.
///
/// Handle lookup and access checks remain kernel responsibilities. This helper validates the
/// fixed native layout and the geometry after the kernel has resolved the referenced section.
pub fn capture_port_view(
    bytes: &[u8; PORT_VIEW_LEN],
    section_size: u64,
) -> Result<PortViewCapture, PortViewError> {
    if u32::from_le_bytes(bytes[0..4].try_into().unwrap()) != PORT_VIEW_LEN as u32 {
        return Err(PortViewError::InvalidLength);
    }
    let section_offset = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as u64;
    let requested_size = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    if section_offset & 0xfff != 0 {
        return Err(PortViewError::MisalignedSectionOffset);
    }
    if section_offset >= section_size {
        return Err(PortViewError::ViewOutsideSection);
    }
    let remaining = section_size - section_offset;
    let view_size = if requested_size == 0 {
        remaining
    } else if requested_size <= remaining {
        requested_size
    } else {
        return Err(PortViewError::ViewOutsideSection);
    };
    Ok(PortViewCapture {
        section_handle: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        section_offset,
        view_size,
    })
}

/// Validate the caller-initialized header of a native x64 `REMOTE_PORT_VIEW` output.
pub fn validate_remote_port_view(bytes: &[u8; REMOTE_PORT_VIEW_LEN]) -> bool {
    u32::from_le_bytes(bytes[0..4].try_into().unwrap()) == REMOTE_PORT_VIEW_LEN as u32
}

/// Publish the mapping result fields in a captured native x64 `PORT_VIEW`.
pub fn publish_port_view(
    bytes: &mut [u8; PORT_VIEW_LEN],
    view_size: u64,
    view_base: u64,
    view_remote_base: u64,
) {
    bytes[24..32].copy_from_slice(&view_size.to_le_bytes());
    bytes[32..40].copy_from_slice(&view_base.to_le_bytes());
    bytes[40..48].copy_from_slice(&view_remote_base.to_le_bytes());
}

/// Publish the mapping result fields in a native x64 `REMOTE_PORT_VIEW`.
pub fn publish_remote_port_view(
    bytes: &mut [u8; REMOTE_PORT_VIEW_LEN],
    view_size: u64,
    view_base: u64,
) {
    bytes[8..16].copy_from_slice(&view_size.to_le_bytes());
    bytes[16..24].copy_from_slice(&view_base.to_le_bytes());
}

/// Validate the length pair at the start of a native x64 `PORT_MESSAGE` and return the complete
/// message length. `DataLength` may leave alignment padding before `TotalLength`, but it may not
/// extend past the captured message.
pub fn port_message_total_length(header: [u8; 4]) -> Option<usize> {
    let data_length = u16::from_le_bytes([header[0], header[1]]) as usize;
    let total_length = u16::from_le_bytes([header[2], header[3]]) as usize;
    if !(PORT_MESSAGE_HEADER_LEN..=PORT_MESSAGE_MAX_LEN).contains(&total_length)
        || data_length.checked_add(PORT_MESSAGE_HEADER_LEN)? > total_length
    {
        return None;
    }
    Some(total_length)
}

/// Validate a native connection-request message supplied to `NtAcceptConnectPort` and return the
/// broker connection identity plus the exact server-authored connection-information bytes. The
/// payload excludes any alignment padding between `DataLength` and `TotalLength`.
pub fn connection_request_response(message: &[u8]) -> Option<(u64, &[u8])> {
    let header: [u8; 4] = message.get(..4)?.try_into().ok()?;
    let total_length = port_message_total_length(header)?;
    if total_length != message.len()
        || u16::from_le_bytes(message.get(4..6)?.try_into().ok()?)
            != msg_type::LPC_CONNECTION_REQUEST
    {
        return None;
    }
    let connection_id = u32::from_le_bytes(message.get(0x18..0x1c)?.try_into().ok()?) as u64;
    if connection_id == 0 {
        return None;
    }
    let data_length = u16::from_le_bytes(header[..2].try_into().ok()?) as usize;
    let data_end = PORT_MESSAGE_HEADER_LEN.checked_add(data_length)?;
    Some((
        connection_id,
        message.get(PORT_MESSAGE_HEADER_LEN..data_end)?,
    ))
}

/// Build the kernel-generated message sent to every port registered through
/// `NtRegisterThreadTerminatePort`. The unused `PORT_MESSAGE` identity and callback fields remain
/// zero, matching `PspExitThread`; the only payload is the terminating thread's creation time.
pub fn client_died_message(create_time_100ns: i64) -> [u8; CLIENT_DIED_MESSAGE_LEN] {
    let mut message = [0u8; CLIENT_DIED_MESSAGE_LEN];
    message[0..2].copy_from_slice(
        &((CLIENT_DIED_MESSAGE_LEN - PORT_MESSAGE_HEADER_LEN) as u16).to_le_bytes(),
    );
    message[2..4].copy_from_slice(&(CLIENT_DIED_MESSAGE_LEN as u16).to_le_bytes());
    message[4..6].copy_from_slice(&msg_type::LPC_CLIENT_DIED.to_le_bytes());
    message[PORT_MESSAGE_HEADER_LEN..].copy_from_slice(&create_time_100ns.to_le_bytes());
    message
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
    /// Kernel-supplied creator `CLIENT_ID.UniqueProcess`.
    pub server_process: u64,
    /// Kernel-supplied creator `CLIENT_ID.UniqueThread`.
    pub server_thread: u64,
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
    /// Kernel-supplied connector `CLIENT_ID.UniqueProcess`.
    pub client_process: u64,
    /// Kernel-supplied connector `CLIENT_ID.UniqueThread`.
    pub client_thread: u64,
    /// Kernel-captured `SECURITY_QUALITY_OF_SERVICE.ImpersonationLevel`.
    pub impersonation_level: u32,
    /// Normalized non-zero when the captured tracking mode is dynamic.
    pub dynamic_tracking: u8,
    /// Normalized non-zero when only enabled privileges/groups may be used.
    pub effective_only: u8,
    pub _reserved2: u16,
}

/// Broker transport metadata prepended to connection information returned by
/// `LPC_OP_REPLY_WAIT_RECEIVE` for an `LPC_CONNECTION_REQUEST`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcConnectionRequestMetadata {
    pub abi_size: u16,
    pub _reserved: u16,
    pub subsystem_type: u32,
    pub client_process: u64,
    pub client_thread: u64,
    pub conninfo_len_bytes: u32,
    pub _reserved2: u32,
}

/// Broker-authored trailer returned after an ordinary received `PORT_MESSAGE`. It carries exact
/// connection provenance without changing the native message bytes or exposing a broker pointer.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcDataMessageMetadata {
    pub abi_size: u16,
    pub _reserved: u16,
    pub _reserved2: u32,
    pub connection_id: u64,
    pub client_process: u64,
    pub client_thread: u64,
    pub port_context: u64,
}

/// `LPC_OP_ACCEPT_CONNECT` — the server accepts (or refuses) a pending connection.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcAcceptConnectRequest {
    pub abi_size: u16,
    /// Non-zero = accept, zero = refuse.
    pub accept: u16,
    /// [`LPC_ACCEPT_RESPONSE_INFO`] means the inline blob replaces the original request bytes.
    pub flags: u32,
    pub connection_id: u64,
    /// Opaque server cookie returned by future receives on this connection.
    pub port_context: u64,
    pub conninfo_offset: u32,
    pub conninfo_len_bytes: u32,
}

/// The accept request carries server-authored connection information, including an intentional
/// empty response. Without this flag the original request bytes are returned unchanged.
pub const LPC_ACCEPT_RESPONSE_INFO: u32 = 1;

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

/// `LPC_OP_REQUEST_WAIT_REPLY` / `LPC_OP_REPLY_PORT` / `LPC_OP_REQUEST_PORT` — send a message.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcMessageRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    pub _reserved2: u32,
    pub port_handle: u64,
    pub msg_offset: u32,
    pub msg_len_bytes: u32,
    /// Kernel-supplied sender identity. The broker overwrites request headers with these fields.
    pub client_process: u64,
    pub client_thread: u64,
}

/// `LPC_OP_QUERY_REQUEST` — validate a server-held request by its native header identity.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcQueryRequestRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    pub message_id: u32,
    pub port_handle: u64,
    pub client_process: u64,
    pub client_thread: u64,
}

/// `LPC_OP_RECEIVE_REPLY` / `LPC_OP_CANCEL_REQUEST` — identify one client-side synchronous
/// request. The kernel obtains `message_id` from the reply to `LPC_OP_REQUEST_WAIT_REPLY`; user
/// mode never chooses it.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcRequestIdentityRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    pub message_id: u32,
    pub port_handle: u64,
    pub client_process: u64,
    pub client_thread: u64,
}

/// Broker-authored connection and QoS state for a validated server-held request.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcQueryRequestResponse {
    pub abi_size: u16,
    pub _reserved: u16,
    pub message_id: u32,
    pub connection_id: u64,
    pub client_process: u64,
    pub client_thread: u64,
    pub impersonation_level: u32,
    pub dynamic_tracking: u8,
    pub effective_only: u8,
    pub _reserved2: u16,
}

/// `LPC_OP_CLOSE_PORT` or one of the kernel retain/release operations — identify one port
/// endpoint.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcClosePortRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    pub _reserved2: u32,
    pub port_handle: u64,
}

/// `LPC_OP_QUERY_HANDLE` — resolve a broker handle to its live endpoint identity.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcQueryHandleRequest {
    pub abi_size: u16,
    pub _reserved: u16,
    pub _reserved2: u32,
    pub port_handle: u64,
}

/// `LPC_OP_QUERY_HANDLE` reply payload.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LpcQueryHandleResponse {
    pub abi_size: u16,
    pub endpoint: u16,
    pub state: u16,
    pub name_len_units: u16,
    pub connection_id: u64,
    pub server_process: u64,
    pub server_thread: u64,
    pub client_process: u64,
    pub client_thread: u64,
    pub max_connection_info: u32,
    pub max_message: u32,
    pub max_pool_usage: u32,
    pub impersonation_level: u32,
    pub dynamic_tracking: u8,
    pub effective_only: u8,
    /// Non-zero for communication ports whose connector QoS is present.
    pub security_present: u8,
    pub _reserved3: u8,
    pub _reserved4: u32,
    pub name: [u16; LPC_QUERY_HANDLE_NAME_MAX_UNITS],
}

impl Default for LpcQueryHandleResponse {
    fn default() -> Self {
        Self {
            abi_size: core::mem::size_of::<Self>() as u16,
            endpoint: handle_endpoint::NONE,
            state: connection_state::NONE,
            name_len_units: 0,
            connection_id: 0,
            server_process: 0,
            server_thread: 0,
            client_process: 0,
            client_thread: 0,
            max_connection_info: 0,
            max_message: 0,
            max_pool_usage: 0,
            impersonation_level: 0,
            dynamic_tracking: 0,
            effective_only: 0,
            security_present: 0,
            _reserved3: 0,
            _reserved4: 0,
            name: [0; LPC_QUERY_HANDLE_NAME_MAX_UNITS],
        }
    }
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
    assert!(size_of::<LpcCreatePortRequest>() == 40);
    assert!(size_of::<LpcConnectPortRequest>() == 48);
    assert!(size_of::<LpcConnectionRequestMetadata>() == 32);
    assert!(size_of::<LpcDataMessageMetadata>() == 40);
    assert!(size_of::<LpcAcceptConnectRequest>() == 32);
    assert!(size_of::<LpcCompleteConnectRequest>() == 16);
    assert!(size_of::<LpcReceiveRequest>() == 24);
    assert!(size_of::<LpcMessageRequest>() == 40);
    assert!(size_of::<LpcQueryRequestRequest>() == 32);
    assert!(size_of::<LpcRequestIdentityRequest>() == 32);
    assert!(size_of::<LpcQueryRequestResponse>() == 40);
    assert!(size_of::<LpcClosePortRequest>() == 16);
    assert!(size_of::<LpcQueryHandleRequest>() == 16);
    assert!(size_of::<LpcQueryHandleResponse>() == 200);
    assert!(size_of::<LpcReply>() == 24);
    assert!(align_of::<LpcAcceptConnectRequest>() == 8);
    assert!(align_of::<LpcCreatePortRequest>() == 8);
    assert!(align_of::<LpcQueryHandleResponse>() == 8);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcodes_in_range() {
        assert!(is_lpc_opcode(opcode::LPC_OP_PING));
        assert!(is_lpc_opcode(opcode::LPC_OP_CONNECT_PORT));
        assert!(is_lpc_opcode(opcode::LPC_OP_CLOSE_PORT));
        assert!(is_lpc_opcode(opcode::LPC_OP_QUERY_HANDLE));
        assert!(is_lpc_opcode(opcode::LPC_OP_REQUEST_PORT));
        assert!(is_lpc_opcode(opcode::LPC_OP_QUERY_REQUEST));
        assert!(is_lpc_opcode(opcode::LPC_OP_RECEIVE_REPLY));
        assert!(is_lpc_opcode(opcode::LPC_OP_CANCEL_REQUEST));
        assert!(!is_lpc_opcode(0x21ff));
        assert!(!is_lpc_opcode(0x2300));
    }

    #[test]
    fn native_port_message_lengths_are_bounded_and_self_consistent() {
        assert_eq!(port_message_total_length([4, 0, 44, 0]), Some(44));
        assert_eq!(port_message_total_length([0, 0, 40, 0]), Some(40));
        assert_eq!(port_message_total_length([5, 0, 44, 0]), None);
        assert_eq!(port_message_total_length([0, 0, 39, 0]), None);
        assert_eq!(port_message_total_length([0, 0, 1, 2]), None);
    }

    #[test]
    fn connection_response_uses_server_payload_and_excludes_padding() {
        let mut message = [0u8; PORT_MESSAGE_HEADER_LEN + 12];
        let total_length = message.len() as u16;
        message[0..2].copy_from_slice(&8_u16.to_le_bytes());
        message[2..4].copy_from_slice(&total_length.to_le_bytes());
        message[4..6].copy_from_slice(&msg_type::LPC_CONNECTION_REQUEST.to_le_bytes());
        message[0x18..0x1c].copy_from_slice(&0x1234_u32.to_le_bytes());
        message[PORT_MESSAGE_HEADER_LEN..PORT_MESSAGE_HEADER_LEN + 8]
            .copy_from_slice(b"response");
        message[PORT_MESSAGE_HEADER_LEN + 8..].fill(0xcc);

        assert_eq!(
            connection_request_response(&message),
            Some((0x1234, &b"response"[..]))
        );

        message[4..6].copy_from_slice(&msg_type::LPC_REQUEST.to_le_bytes());
        assert_eq!(connection_request_response(&message), None);
        message[4..6].copy_from_slice(&msg_type::LPC_CONNECTION_REQUEST.to_le_bytes());
        message[0x18..0x1c].fill(0);
        assert_eq!(connection_request_response(&message), None);
        assert_eq!(connection_request_response(&message[..message.len() - 1]), None);
    }

    #[test]
    fn client_died_message_has_native_header_and_create_time() {
        let create_time = 0x0123_4567_89ab_cdef_i64;
        let message = client_died_message(create_time);
        assert_eq!(message.len(), 48);
        assert_eq!(u16::from_le_bytes(message[0..2].try_into().unwrap()), 8);
        assert_eq!(u16::from_le_bytes(message[2..4].try_into().unwrap()), 48);
        assert_eq!(
            u16::from_le_bytes(message[4..6].try_into().unwrap()),
            msg_type::LPC_CLIENT_DIED
        );
        assert!(message[6..PORT_MESSAGE_HEADER_LEN]
            .iter()
            .all(|byte| *byte == 0));
        assert_eq!(
            i64::from_le_bytes(message[PORT_MESSAGE_HEADER_LEN..].try_into().unwrap()),
            create_time
        );
    }

    #[test]
    fn native_port_view_capture_validates_layout_and_section_geometry() {
        let mut bytes = [0u8; PORT_VIEW_LEN];
        bytes[0..4].copy_from_slice(&(PORT_VIEW_LEN as u32).to_le_bytes());
        bytes[8..16].copy_from_slice(&0x44_u64.to_le_bytes());
        bytes[16..20].copy_from_slice(&0x2000_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x3000_u64.to_le_bytes());
        assert_eq!(
            capture_port_view(&bytes, 0x8000),
            Ok(PortViewCapture {
                section_handle: 0x44,
                section_offset: 0x2000,
                view_size: 0x3000,
            })
        );

        bytes[0..4].copy_from_slice(&0x28_u32.to_le_bytes());
        assert_eq!(
            capture_port_view(&bytes, 0x8000),
            Err(PortViewError::InvalidLength)
        );
        bytes[0..4].copy_from_slice(&(PORT_VIEW_LEN as u32).to_le_bytes());
        bytes[16..20].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            capture_port_view(&bytes, 0x8000),
            Err(PortViewError::MisalignedSectionOffset)
        );
        bytes[16..20].copy_from_slice(&0x2000_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0_u64.to_le_bytes());
        assert_eq!(
            capture_port_view(&bytes, 0x8000),
            Ok(PortViewCapture {
                section_handle: 0x44,
                section_offset: 0x2000,
                view_size: 0x6000,
            })
        );
        bytes[24..32].copy_from_slice(&0x7000_u64.to_le_bytes());
        assert_eq!(
            capture_port_view(&bytes, 0x8000),
            Err(PortViewError::ViewOutsideSection)
        );
    }

    #[test]
    fn native_port_view_results_update_only_output_fields() {
        let mut port = [0x5a; PORT_VIEW_LEN];
        publish_port_view(&mut port, 0x4000, 0x1000_0000, 0x2000_0000);
        assert!(port[..24].iter().all(|byte| *byte == 0x5a));
        assert_eq!(u64::from_le_bytes(port[24..32].try_into().unwrap()), 0x4000);
        assert_eq!(
            u64::from_le_bytes(port[32..40].try_into().unwrap()),
            0x1000_0000
        );
        assert_eq!(
            u64::from_le_bytes(port[40..48].try_into().unwrap()),
            0x2000_0000
        );

        let mut remote = [0x6b; REMOTE_PORT_VIEW_LEN];
        remote[0..4].copy_from_slice(&(REMOTE_PORT_VIEW_LEN as u32).to_le_bytes());
        assert!(validate_remote_port_view(&remote));
        publish_remote_port_view(&mut remote, 0x5000, 0x3000_0000);
        assert_eq!(
            &remote[..8],
            &[REMOTE_PORT_VIEW_LEN as u8, 0, 0, 0, 0x6b, 0x6b, 0x6b, 0x6b,]
        );
        assert_eq!(
            u64::from_le_bytes(remote[8..16].try_into().unwrap()),
            0x5000
        );
        assert_eq!(
            u64::from_le_bytes(remote[16..24].try_into().unwrap()),
            0x3000_0000
        );
        remote[0] = 0;
        assert!(!validate_remote_port_view(&remote));
    }

    #[test]
    fn bidirectional_connection_views_preserve_owner_and_peer_orientation() {
        let results = connection_view_results(
            Some(MappedPortView {
                owner_base: 0x1000_0000,
                peer_base: 0x2000_0000,
                view_size: 0x4000,
            }),
            Some(MappedPortView {
                owner_base: 0x3000_0000,
                peer_base: 0x4000_0000,
                view_size: 0x8000,
            }),
        );
        assert_eq!(
            results.connector_view,
            Some(PortViewResult {
                view_size: 0x4000,
                view_base: 0x1000_0000,
                view_remote_base: 0x2000_0000,
            })
        );
        assert_eq!(
            results.acceptor_client_view,
            Some(RemotePortViewResult {
                view_size: 0x4000,
                view_base: 0x2000_0000,
            })
        );
        assert_eq!(
            results.acceptor_view,
            Some(PortViewResult {
                view_size: 0x8000,
                view_base: 0x3000_0000,
                view_remote_base: 0x4000_0000,
            })
        );
        assert_eq!(
            results.connector_server_view,
            Some(RemotePortViewResult {
                view_size: 0x8000,
                view_base: 0x4000_0000,
            })
        );
        assert_eq!(
            connection_view_results(None, None),
            ConnectionViewResults::default()
        );
    }

    #[test]
    fn version_is_current() {
        assert_eq!(LPC_ABI_VERSION, 9);
    }
}
