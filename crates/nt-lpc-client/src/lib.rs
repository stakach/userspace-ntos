//! # `nt-lpc-client` — the NT LPC client stub
//!
//! An ergonomic Rust API over the LPC connection-broker ABI. It encodes each
//! control-plane call into an `nt-lpc-abi` request buffer, sends it through a
//! [`Backend`], and decodes the [`LpcReply`]. The backend is pluggable: an
//! in-process `Direct` backend (calling the server directly, for tests) or a
//! SURT backend (the executive-side transport to the isolated `lpc-server`
//! component). This crate depends on neither the server nor SURT.
//!
//! Both connection rendezvous and the LPC message data plane are exposed. The executive remains
//! responsible for parking synchronous callers while the peer user thread handles a request.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::convert::TryFrom;
use core::mem::size_of;

use bytemuck::Pod;
use nt_lpc_abi::{
    msg_type, opcode, LpcAcceptConnectRequest, LpcCompleteConnectRequest, LpcConnectPortRequest,
    LpcConnectionRequestMetadata, LpcCreatePortRequest, LpcMessageRequest, LpcQueryHandleRequest,
    LpcQueryHandleResponse, LpcQueryRequestRequest, LpcQueryRequestResponse, LpcReceiveRequest,
    LpcReply, LpcRequestIdentityRequest, LPC_ACCEPT_RESPONSE_INFO,
};
use nt_status::NtStatus;

/// A transport that carries one request to the LPC server and returns the reply.
pub trait Backend {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> LpcReply;
}

/// The outcome of a connect: either the connection completed (a client comm-port
/// `handle`) or it is `pending` a receiver (path B — the executive parks the
/// connector, `connection_id` identifies which to wake on complete).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConnectResult {
    pub handle: u64,
    pub connection_id: u64,
    pub pending: bool,
}

/// A completed connection and the exact connection-information accepted by the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompleteConnectResult {
    pub handle: u64,
    pub connection_id: u64,
    pub connection_info: Vec<u8>,
}

/// The outcome of a receive: a delivered connection request (or message).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveResult {
    pub connection_id: u64,
    pub msg_type: u16,
    pub subsystem_type: u32,
    pub client_process: u64,
    pub client_thread: u64,
    pub port_context: u64,
    pub connection_info: Vec<u8>,
}

/// A broker-owned handle identity returned by `LPC_OP_QUERY_HANDLE`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandleQueryResult {
    pub endpoint: u16,
    pub state: u16,
    pub connection_id: u64,
    pub server_process: u64,
    pub server_thread: u64,
    pub client_process: u64,
    pub client_thread: u64,
    pub max_connection_info: u32,
    pub max_message: u32,
    pub max_pool_usage: u32,
    pub impersonation_level: u32,
    pub dynamic_tracking: bool,
    pub effective_only: bool,
    pub security_present: bool,
    pub name: Vec<u16>,
}

/// Broker-authored state for a synchronous request currently held by a server.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RequestQueryResult {
    pub connection_id: u64,
    pub client_process: u64,
    pub client_thread: u64,
    pub message_id: u32,
    pub impersonation_level: u32,
    pub dynamic_tracking: bool,
    pub effective_only: bool,
}

/// The LPC client.
pub struct LpcClient<B> {
    backend: B,
}

impl<B: Backend> LpcClient<B> {
    /// Wrap a transport backend.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Access the backend (e.g. to reach the server in a `Direct` backend).
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Liveness check.
    pub fn ping(&mut self) -> bool {
        NtStatus(self.backend.call(opcode::LPC_OP_PING, &[], &mut []).status).is_success()
    }

    /// Create a (named or unnamed) port; returns its handle.
    pub fn create_port(
        &mut self,
        name: &[u16],
        max_connection_info: u32,
        max_message: u32,
        max_pool: u32,
    ) -> Result<u64, NtStatus> {
        self.create_port_with_owner(name, max_connection_info, max_message, max_pool, 0, 0)
    }

    /// Create a named port while preserving the creator identity supplied by the kernel.
    pub fn create_port_with_owner(
        &mut self,
        name: &[u16],
        max_connection_info: u32,
        max_message: u32,
        max_pool: u32,
        server_process: u64,
        server_thread: u64,
    ) -> Result<u64, NtStatus> {
        let hdr = size_of::<LpcCreatePortRequest>();
        let req = LpcCreatePortRequest {
            abi_size: hdr as u16,
            flags: 0,
            max_connection_info,
            max_message,
            max_pool,
            name_offset: hdr as u32,
            name_len_bytes: byte_len(name)?,
            server_process,
            server_thread,
        };
        let buf = pack_units::<LPC_CONTROL_BUF_LEN, _>(&req, name)?;
        let r = self
            .backend
            .call(opcode::LPC_OP_CREATE_PORT, buf.as_slice(), &mut []);
        NtStatus(r.status).to_result()?;
        Ok(r.detail0)
    }

    /// Connect to a named port, carrying the connection-info blob + subsystem type.
    pub fn connect_port(
        &mut self,
        name: &[u16],
        subsystem_type: u32,
        conn_info: &[u8],
    ) -> Result<ConnectResult, NtStatus> {
        self.connect_port_with_client_id(name, subsystem_type, conn_info, 0, 0)
    }

    /// Connect while preserving the caller identity supplied by the kernel.
    pub fn connect_port_with_client_id(
        &mut self,
        name: &[u16],
        subsystem_type: u32,
        conn_info: &[u8],
        client_process: u64,
        client_thread: u64,
    ) -> Result<ConnectResult, NtStatus> {
        self.connect_port_with_client_security(
            name,
            subsystem_type,
            conn_info,
            client_process,
            client_thread,
            0,
            false,
            false,
        )
    }

    /// Connect while preserving caller identity and kernel-captured security QoS.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_port_with_client_security(
        &mut self,
        name: &[u16],
        subsystem_type: u32,
        conn_info: &[u8],
        client_process: u64,
        client_thread: u64,
        impersonation_level: u32,
        dynamic_tracking: bool,
        effective_only: bool,
    ) -> Result<ConnectResult, NtStatus> {
        let hdr = size_of::<LpcConnectPortRequest>();
        let name_len = byte_len(name)?;
        let conn_info_len =
            u32::try_from(conn_info.len()).map_err(|_| NtStatus::BUFFER_TOO_SMALL)?;
        let req = LpcConnectPortRequest {
            abi_size: hdr as u16,
            flags: 0,
            subsystem_type,
            name_offset: hdr as u32,
            name_len_bytes: name_len,
            conninfo_offset: u32_len(
                hdr.checked_add(name_len as usize)
                    .ok_or(NtStatus::BUFFER_TOO_SMALL)?,
            )?,
            conninfo_len_bytes: conn_info_len,
            client_process,
            client_thread,
            impersonation_level,
            dynamic_tracking: u8::from(dynamic_tracking),
            effective_only: u8::from(effective_only),
            _reserved2: 0,
        };
        let buf = pack_units_and_bytes::<LPC_CONTROL_BUF_LEN, _>(&req, name, conn_info)?;
        let r = self
            .backend
            .call(opcode::LPC_OP_CONNECT_PORT, buf.as_slice(), &mut []);
        NtStatus(r.status).to_result()?;
        Ok(ConnectResult {
            handle: r.detail0,
            connection_id: r.detail1,
            pending: r.status == NtStatus::PENDING.raw(),
        })
    }

    /// Accept (or refuse) a pending connection; returns the server comm-port handle.
    pub fn accept_connect(
        &mut self,
        connection_id: u64,
        accept: bool,
        port_context: u64,
    ) -> Result<u64, NtStatus> {
        let req = LpcAcceptConnectRequest {
            abi_size: size_of::<LpcAcceptConnectRequest>() as u16,
            accept: u16::from(accept),
            flags: 0,
            connection_id,
            port_context,
            conninfo_offset: 0,
            conninfo_len_bytes: 0,
        };
        let r = self.backend.call(
            opcode::LPC_OP_ACCEPT_CONNECT,
            bytemuck::bytes_of(&req),
            &mut [],
        );
        NtStatus(r.status).to_result()?;
        Ok(r.detail0)
    }

    /// Accept (or refuse) a pending connection and commit the connection-information bytes
    /// authored by the server.
    pub fn accept_connect_with_info(
        &mut self,
        connection_id: u64,
        accept: bool,
        port_context: u64,
        connection_info: &[u8],
    ) -> Result<u64, NtStatus> {
        let header = size_of::<LpcAcceptConnectRequest>();
        let req = LpcAcceptConnectRequest {
            abi_size: header as u16,
            accept: u16::from(accept),
            flags: LPC_ACCEPT_RESPONSE_INFO,
            connection_id,
            port_context,
            conninfo_offset: header as u32,
            conninfo_len_bytes: u32_len(connection_info.len())?,
        };
        let buf = pack_bytes::<LPC_CONTROL_BUF_LEN, _>(&req, connection_info)?;
        let r = self
            .backend
            .call(opcode::LPC_OP_ACCEPT_CONNECT, buf.as_slice(), &mut []);
        NtStatus(r.status).to_result()?;
        Ok(r.detail0)
    }

    /// Complete an accepted connection and return the server-approved connection information.
    pub fn complete_connect(
        &mut self,
        connection_id: u64,
    ) -> Result<CompleteConnectResult, NtStatus> {
        let req = LpcCompleteConnectRequest {
            abi_size: size_of::<LpcCompleteConnectRequest>() as u16,
            _reserved: 0,
            _reserved2: 0,
            connection_id,
        };
        let mut out = [0u8; 512];
        let r = self.backend.call(
            opcode::LPC_OP_COMPLETE_CONNECT,
            bytemuck::bytes_of(&req),
            &mut out,
        );
        NtStatus(r.status).to_result()?;
        let returned = r.information as usize;
        if returned > out.len() {
            return Err(NtStatus::BUFFER_TOO_SMALL);
        }
        Ok(CompleteConnectResult {
            handle: r.detail0,
            connection_id: r.detail1,
            connection_info: out[..returned].to_vec(),
        })
    }

    /// Close a broker-owned listen or communication-port handle.
    pub fn close_port(&mut self, port_handle: u64) -> Result<(), NtStatus> {
        let req = nt_lpc_abi::LpcClosePortRequest {
            abi_size: size_of::<nt_lpc_abi::LpcClosePortRequest>() as u16,
            _reserved: 0,
            _reserved2: 0,
            port_handle,
        };
        let reply = self
            .backend
            .call(opcode::LPC_OP_CLOSE_PORT, bytemuck::bytes_of(&req), &mut []);
        NtStatus(reply.status).to_result()
    }

    /// Resolve a broker handle to the live endpoint identity recorded by the port core.
    pub fn query_handle(&mut self, port_handle: u64) -> Result<HandleQueryResult, NtStatus> {
        let req = LpcQueryHandleRequest {
            abi_size: size_of::<LpcQueryHandleRequest>() as u16,
            _reserved: 0,
            _reserved2: 0,
            port_handle,
        };
        let mut out = [0u8; size_of::<LpcQueryHandleResponse>()];
        let r = self.backend.call(
            opcode::LPC_OP_QUERY_HANDLE,
            bytemuck::bytes_of(&req),
            &mut out,
        );
        NtStatus(r.status).to_result()?;
        if r.information as usize != size_of::<LpcQueryHandleResponse>() {
            return Err(NtStatus::BUFFER_TOO_SMALL);
        }
        let response: LpcQueryHandleResponse =
            bytemuck::try_pod_read_unaligned(&out).map_err(|_| NtStatus::INVALID_PARAMETER)?;
        if response.abi_size as usize != size_of::<LpcQueryHandleResponse>() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let name_len = response.name_len_units as usize;
        if name_len > response.name.len() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(HandleQueryResult {
            endpoint: response.endpoint,
            state: response.state,
            connection_id: response.connection_id,
            server_process: response.server_process,
            server_thread: response.server_thread,
            client_process: response.client_process,
            client_thread: response.client_thread,
            max_connection_info: response.max_connection_info,
            max_message: response.max_message,
            max_pool_usage: response.max_pool_usage,
            impersonation_level: response.impersonation_level,
            dynamic_tracking: response.dynamic_tracking != 0,
            effective_only: response.effective_only != 0,
            security_present: response.security_present != 0,
            name: response.name[..name_len].to_vec(),
        })
    }

    /// Validate that a native request identity is currently held by the supplied server port.
    pub fn query_request(
        &mut self,
        port_handle: u64,
        client_process: u64,
        client_thread: u64,
        message_id: u32,
    ) -> Result<RequestQueryResult, NtStatus> {
        let req = LpcQueryRequestRequest {
            abi_size: size_of::<LpcQueryRequestRequest>() as u16,
            _reserved: 0,
            message_id,
            port_handle,
            client_process,
            client_thread,
        };
        let mut out = [0u8; size_of::<LpcQueryRequestResponse>()];
        let reply = self.backend.call(
            opcode::LPC_OP_QUERY_REQUEST,
            bytemuck::bytes_of(&req),
            &mut out,
        );
        NtStatus(reply.status).to_result()?;
        if reply.information as usize != size_of::<LpcQueryRequestResponse>() {
            return Err(NtStatus::BUFFER_TOO_SMALL);
        }
        let response: LpcQueryRequestResponse =
            bytemuck::try_pod_read_unaligned(&out).map_err(|_| NtStatus::INVALID_PARAMETER)?;
        if response.abi_size as usize != size_of::<LpcQueryRequestResponse>()
            || response.message_id != message_id
            || response.client_process != client_process
            || response.client_thread != client_thread
        {
            return Err(NtStatus::REPLY_MESSAGE_MISMATCH);
        }
        Ok(RequestQueryResult {
            connection_id: response.connection_id,
            client_process: response.client_process,
            client_thread: response.client_thread,
            message_id: response.message_id,
            impersonation_level: response.impersonation_level,
            dynamic_tracking: response.dynamic_tracking != 0,
            effective_only: response.effective_only != 0,
        })
    }

    /// Receive the next message on a port (the connection-request rendezvous drain).
    pub fn reply_wait_receive(&mut self, port_handle: u64) -> Result<ReceiveResult, NtStatus> {
        self.reply_wait_receive_with_reply(port_handle, &[])
    }

    /// Atomically send the previous reply, if any, then receive the next connection or data
    /// message. `connection_info` carries the exact received bytes for ordinary data messages too.
    pub fn reply_wait_receive_with_reply(
        &mut self,
        port_handle: u64,
        reply_msg: &[u8],
    ) -> Result<ReceiveResult, NtStatus> {
        let header = size_of::<LpcReceiveRequest>();
        let reply_msg_len = u32_len(reply_msg.len())?;
        let req = LpcReceiveRequest {
            abi_size: size_of::<LpcReceiveRequest>() as u16,
            _reserved: 0,
            _reserved2: 0,
            port_handle,
            reply_msg_offset: if reply_msg.is_empty() {
                0
            } else {
                header as u32
            },
            reply_msg_len_bytes: reply_msg_len,
        };
        let buf = pack_bytes::<LPC_CONTROL_BUF_LEN, _>(&req, reply_msg)?;
        let mut out = [0u8; 512];
        let r = self
            .backend
            .call(opcode::LPC_OP_REPLY_WAIT_RECEIVE, buf.as_slice(), &mut out);
        if r.status == NtStatus::PENDING.raw() {
            return Err(NtStatus::PENDING);
        }
        NtStatus(r.status).to_result()?;
        let msg_type = r.detail1 as u16;
        let is_connection = msg_type == msg_type::LPC_CONNECTION_REQUEST;
        let (subsystem_type, client_process, client_thread, connection_info) = if is_connection {
            let metadata_size = size_of::<LpcConnectionRequestMetadata>();
            let returned = r.information as usize;
            if returned < metadata_size || returned > out.len() {
                return Err(NtStatus::BUFFER_TOO_SMALL);
            }
            let metadata: LpcConnectionRequestMetadata =
                bytemuck::try_pod_read_unaligned(&out[..metadata_size])
                    .map_err(|_| NtStatus::INVALID_PARAMETER)?;
            if metadata.abi_size as usize != metadata_size {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let conninfo_len = metadata.conninfo_len_bytes as usize;
            if metadata_size.checked_add(conninfo_len) != Some(returned) {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            (
                metadata.subsystem_type,
                metadata.client_process,
                metadata.client_thread,
                out[metadata_size..returned].to_vec(),
            )
        } else {
            (
                (r.detail1 >> 32) as u32,
                0,
                0,
                out[..(r.information as usize).min(out.len())].to_vec(),
            )
        };
        Ok(ReceiveResult {
            connection_id: if is_connection { r.detail0 } else { 0 },
            msg_type,
            subsystem_type,
            client_process,
            client_thread,
            port_context: if is_connection { 0 } else { r.detail0 },
            connection_info,
        })
    }

    /// Send an LPC request. An empty result means the peer has not replied yet; the executive can
    /// run the peer and then receive the response on the same communication handle.
    pub fn request_wait_reply(
        &mut self,
        port_handle: u64,
        message: &[u8],
    ) -> Result<Vec<u8>, NtStatus> {
        self.request_wait_reply_with_client_id(port_handle, message, 0, 0)
    }

    /// Send a synchronous request with the kernel-supplied identity of the calling thread.
    pub fn request_wait_reply_with_client_id(
        &mut self,
        port_handle: u64,
        message: &[u8],
        client_process: u64,
        client_thread: u64,
    ) -> Result<Vec<u8>, NtStatus> {
        self.begin_request_wait_reply_with_client_id(
            port_handle,
            message,
            client_process,
            client_thread,
        )
        .map(|_| Vec::new())
    }

    /// Queue one synchronous request and return the broker-authored message id that owns its
    /// eventual reply. The executive must retain this identity with the blocked syscall.
    pub fn begin_request_wait_reply_with_client_id(
        &mut self,
        port_handle: u64,
        message: &[u8],
        client_process: u64,
        client_thread: u64,
    ) -> Result<u32, NtStatus> {
        let header = size_of::<LpcMessageRequest>();
        let request = LpcMessageRequest {
            abi_size: header as u16,
            _reserved: 0,
            _reserved2: 0,
            port_handle,
            msg_offset: header as u32,
            msg_len_bytes: u32_len(message.len())?,
            client_process,
            client_thread,
        };
        let buf = pack_bytes::<LPC_MESSAGE_BUF_LEN, _>(&request, message)?;
        let mut out = [0u8; 512];
        let reply = self
            .backend
            .call(opcode::LPC_OP_REQUEST_WAIT_REPLY, buf.as_slice(), &mut out);
        if reply.status != NtStatus::PENDING.raw() && reply.status != NtStatus::SUCCESS.raw() {
            return Err(NtStatus(reply.status));
        }
        u32::try_from(reply.detail0)
            .ok()
            .filter(|message_id| *message_id != 0)
            .ok_or(NtStatus::UNSUCCESSFUL)
    }

    /// Poll one exact synchronous request reply without consuming other traffic on the client
    /// communication port.
    pub fn receive_reply(
        &mut self,
        port_handle: u64,
        client_process: u64,
        client_thread: u64,
        message_id: u32,
    ) -> Result<Option<Vec<u8>>, NtStatus> {
        let request = LpcRequestIdentityRequest {
            abi_size: size_of::<LpcRequestIdentityRequest>() as u16,
            _reserved: 0,
            message_id,
            port_handle,
            client_process,
            client_thread,
        };
        let mut out = [0u8; 512];
        let reply = self.backend.call(
            opcode::LPC_OP_RECEIVE_REPLY,
            bytemuck::bytes_of(&request),
            &mut out,
        );
        if reply.status == NtStatus::PENDING.raw() {
            return Ok(None);
        }
        NtStatus(reply.status).to_result()?;
        Ok(Some(
            out[..(reply.information as usize).min(out.len())].to_vec(),
        ))
    }

    /// Cancel one exact request during continuation rollback or thread teardown.
    pub fn cancel_request(
        &mut self,
        port_handle: u64,
        client_process: u64,
        client_thread: u64,
        message_id: u32,
    ) -> Result<bool, NtStatus> {
        let request = LpcRequestIdentityRequest {
            abi_size: size_of::<LpcRequestIdentityRequest>() as u16,
            _reserved: 0,
            message_id,
            port_handle,
            client_process,
            client_thread,
        };
        let reply = self.backend.call(
            opcode::LPC_OP_CANCEL_REQUEST,
            bytemuck::bytes_of(&request),
            &mut [],
        );
        NtStatus(reply.status).to_result()?;
        Ok(reply.detail0 != 0)
    }

    /// Send an LPC reply without receiving another message.
    pub fn reply_port(&mut self, port_handle: u64, message: &[u8]) -> Result<(), NtStatus> {
        self.send_message(opcode::LPC_OP_REPLY_PORT, port_handle, message, 0, 0)
            .map(|_| ())
    }

    /// Kernel `LpcRequestPort` — enqueue a typed kernel message without converting it to an LPC
    /// request or reply. This is used for messages such as `LPC_CLIENT_DIED`.
    pub fn request_port(&mut self, port_handle: u64, message: &[u8]) -> Result<(), NtStatus> {
        self.send_message(opcode::LPC_OP_REQUEST_PORT, port_handle, message, 0, 0)
            .map(|_| ())
    }

    fn send_message(
        &mut self,
        opcode: u16,
        port_handle: u64,
        message: &[u8],
        client_process: u64,
        client_thread: u64,
    ) -> Result<Vec<u8>, NtStatus> {
        let header = size_of::<LpcMessageRequest>();
        let message_len = u32_len(message.len())?;
        let req = LpcMessageRequest {
            abi_size: header as u16,
            _reserved: 0,
            _reserved2: 0,
            port_handle,
            msg_offset: header as u32,
            msg_len_bytes: message_len,
            client_process,
            client_thread,
        };
        let buf = pack_bytes::<LPC_MESSAGE_BUF_LEN, _>(&req, message)?;
        let mut out = [0u8; 512];
        let r = self.backend.call(opcode, buf.as_slice(), &mut out);
        if opcode == opcode::LPC_OP_REQUEST_WAIT_REPLY && r.status == NtStatus::PENDING.raw() {
            return Ok(Vec::new());
        }
        NtStatus(r.status).to_result()?;
        Ok(out[..(r.information as usize).min(out.len())].to_vec())
    }
}

/// The LPC connection-request message type (re-exported for callers).
pub const LPC_CONNECTION_REQUEST: u16 = msg_type::LPC_CONNECTION_REQUEST;

// --- encode helpers --------------------------------------------------------

const LPC_CONTROL_BUF_LEN: usize = 1024;
const LPC_MESSAGE_BUF_LEN: usize = 1024;

struct StackBuf<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> StackBuf<N> {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn byte_len(units: &[u16]) -> Result<u32, NtStatus> {
    let bytes = units
        .len()
        .checked_mul(2)
        .ok_or(NtStatus::BUFFER_TOO_SMALL)?;
    u32_len(bytes)
}

fn u32_len(len: usize) -> Result<u32, NtStatus> {
    u32::try_from(len).map_err(|_| NtStatus::BUFFER_TOO_SMALL)
}

fn pack_units<const N: usize, T: Pod>(req: &T, units: &[u16]) -> Result<StackBuf<N>, NtStatus> {
    let mut buf = StackBuf {
        bytes: [0; N],
        len: bytemuck::bytes_of(req)
            .len()
            .checked_add(
                units
                    .len()
                    .checked_mul(2)
                    .ok_or(NtStatus::BUFFER_TOO_SMALL)?,
            )
            .ok_or(NtStatus::BUFFER_TOO_SMALL)?,
    };
    if buf.len > N {
        return Err(NtStatus::BUFFER_TOO_SMALL);
    }
    let header = bytemuck::bytes_of(req);
    buf.bytes[..header.len()].copy_from_slice(header);
    let mut pos = header.len();
    for &u in units {
        let le = u.to_le_bytes();
        buf.bytes[pos] = le[0];
        buf.bytes[pos + 1] = le[1];
        pos += 2;
    }
    Ok(buf)
}

fn pack_units_and_bytes<const N: usize, T: Pod>(
    req: &T,
    units: &[u16],
    tail: &[u8],
) -> Result<StackBuf<N>, NtStatus> {
    let unit_bytes = units
        .len()
        .checked_mul(2)
        .ok_or(NtStatus::BUFFER_TOO_SMALL)?;
    let total = bytemuck::bytes_of(req)
        .len()
        .checked_add(unit_bytes)
        .and_then(|n| n.checked_add(tail.len()))
        .ok_or(NtStatus::BUFFER_TOO_SMALL)?;
    if total > N {
        return Err(NtStatus::BUFFER_TOO_SMALL);
    }

    let mut buf = StackBuf {
        bytes: [0; N],
        len: total,
    };
    let header = bytemuck::bytes_of(req);
    buf.bytes[..header.len()].copy_from_slice(header);
    let mut pos = header.len();
    for &u in units {
        let le = u.to_le_bytes();
        buf.bytes[pos] = le[0];
        buf.bytes[pos + 1] = le[1];
        pos += 2;
    }
    buf.bytes[pos..pos + tail.len()].copy_from_slice(tail);
    Ok(buf)
}

fn pack_bytes<const N: usize, T: Pod>(req: &T, tail: &[u8]) -> Result<StackBuf<N>, NtStatus> {
    let total = bytemuck::bytes_of(req)
        .len()
        .checked_add(tail.len())
        .ok_or(NtStatus::BUFFER_TOO_SMALL)?;
    if total > N {
        return Err(NtStatus::BUFFER_TOO_SMALL);
    }
    let mut buf = StackBuf {
        bytes: [0; N],
        len: total,
    };
    let header = bytemuck::bytes_of(req);
    buf.bytes[..header.len()].copy_from_slice(header);
    buf.bytes[header.len()..total].copy_from_slice(tail);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::vec::Vec;
    use nt_lpc_abi::{LpcConnectPortRequest, LpcCreatePortRequest};
    use std::vec;

    #[derive(Default)]
    struct CaptureBackend {
        calls: Vec<(u16, Vec<u8>)>,
        reply: LpcReply,
    }

    impl Backend for CaptureBackend {
        fn call(&mut self, opcode: u16, in_buf: &[u8], _out_buf: &mut [u8]) -> LpcReply {
            self.calls.push((opcode, in_buf.to_vec()));
            self.reply
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn create_port_encodes_header_and_name_without_heap_payload_builder() {
        let backend = CaptureBackend {
            calls: Vec::new(),
            reply: LpcReply {
                status: NtStatus::SUCCESS.raw(),
                detail0: 0x4c50_0000_0001,
                ..Default::default()
            },
        };
        let mut client = LpcClient::new(backend);
        let name = wide(r"\ErrorLogPort");

        assert_eq!(client.create_port(&name, 0, 512, 0), Ok(0x4c50_0000_0001));

        let (opcode, payload) = &client.backend_mut().calls[0];
        assert_eq!(*opcode, opcode::LPC_OP_CREATE_PORT);
        let req = bytemuck::from_bytes::<LpcCreatePortRequest>(
            &payload[..size_of::<LpcCreatePortRequest>()],
        );
        assert_eq!(req.abi_size as usize, size_of::<LpcCreatePortRequest>());
        assert_eq!(req.max_message, 512);
        assert_eq!(req.name_offset as usize, size_of::<LpcCreatePortRequest>());
        assert_eq!(req.name_len_bytes as usize, name.len() * 2);
        assert_eq!(req.server_process, 0);
        assert_eq!(req.server_thread, 0);

        let mut encoded = Vec::new();
        for unit in &name {
            encoded.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(&payload[req.name_offset as usize..], encoded.as_slice());
    }

    #[test]
    fn create_port_preserves_kernel_supplied_owner_identity() {
        let backend = CaptureBackend {
            calls: Vec::new(),
            reply: LpcReply {
                status: NtStatus::SUCCESS.raw(),
                detail0: 0x4c50_0000_0001,
                ..Default::default()
            },
        };
        let mut client = LpcClient::new(backend);
        let name = wide(r"\Windows\ApiPort");
        assert!(client
            .create_port_with_owner(&name, 0x88, 0x148, 0, 12, 24)
            .is_ok());
        let payload = &client.backend_mut().calls[0].1;
        let req = bytemuck::from_bytes::<LpcCreatePortRequest>(
            &payload[..size_of::<LpcCreatePortRequest>()],
        );
        assert_eq!(req.server_process, 12);
        assert_eq!(req.server_thread, 24);
    }

    #[test]
    fn connect_port_rejects_payloads_that_do_not_fit_control_frame() {
        let backend = CaptureBackend::default();
        let mut client = LpcClient::new(backend);
        let too_long = vec![0u16; LPC_CONTROL_BUF_LEN];

        assert_eq!(
            client.connect_port(&too_long, 0, &[]),
            Err(NtStatus::BUFFER_TOO_SMALL)
        );
        assert!(client.backend_mut().calls.is_empty());
    }

    #[test]
    fn connect_port_encodes_name_and_connection_info() {
        let backend = CaptureBackend {
            calls: Vec::new(),
            reply: LpcReply {
                status: NtStatus::PENDING.raw(),
                detail1: 42,
                ..Default::default()
            },
        };
        let mut client = LpcClient::new(backend);
        let name = wide(r"\Windows\ApiPort");
        let conn_info = [1u8, 2, 3, 4, 5];

        let result = client
            .connect_port_with_client_id(&name, 3, &conn_info, 0x44, 0x88)
            .unwrap();
        assert!(result.pending);
        assert_eq!(result.connection_id, 42);

        let (opcode, payload) = &client.backend_mut().calls[0];
        assert_eq!(*opcode, opcode::LPC_OP_CONNECT_PORT);
        let req = bytemuck::from_bytes::<LpcConnectPortRequest>(
            &payload[..size_of::<LpcConnectPortRequest>()],
        );
        assert_eq!(req.subsystem_type, 3);
        assert_eq!(req.name_offset as usize, size_of::<LpcConnectPortRequest>());
        assert_eq!(req.name_len_bytes as usize, name.len() * 2);
        assert_eq!(
            req.conninfo_offset as usize,
            size_of::<LpcConnectPortRequest>() + name.len() * 2
        );
        assert_eq!(req.conninfo_len_bytes as usize, conn_info.len());
        assert_eq!(req.client_process, 0x44);
        assert_eq!(req.client_thread, 0x88);
        assert_eq!(req.impersonation_level, 0);
        assert_eq!(req.dynamic_tracking, 0);
        assert_eq!(req.effective_only, 0);
        assert_eq!(
            &payload[req.conninfo_offset as usize..],
            conn_info.as_slice()
        );
    }

    #[test]
    fn secure_connect_preserves_kernel_captured_qos() {
        let backend = CaptureBackend {
            calls: Vec::new(),
            reply: LpcReply {
                status: NtStatus::PENDING.raw(),
                detail1: 7,
                ..Default::default()
            },
        };
        let mut client = LpcClient::new(backend);
        client
            .connect_port_with_client_security(
                &wide(r"\Windows\ApiPort"),
                2,
                &[],
                12,
                24,
                2,
                true,
                true,
            )
            .unwrap();
        let payload = &client.backend_mut().calls[0].1;
        let req = bytemuck::from_bytes::<LpcConnectPortRequest>(
            &payload[..size_of::<LpcConnectPortRequest>()],
        );
        assert_eq!(req.impersonation_level, 2);
        assert_eq!(req.dynamic_tracking, 1);
        assert_eq!(req.effective_only, 1);
    }
}
