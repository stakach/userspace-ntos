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
use core::mem::size_of;

use bytemuck::Pod;
use nt_lpc_abi::{
    msg_type, opcode, LpcAcceptConnectRequest, LpcCompleteConnectRequest, LpcConnectPortRequest,
    LpcCreatePortRequest, LpcMessageRequest, LpcReceiveRequest, LpcReply,
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

/// The outcome of a receive: a delivered connection request (or message).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveResult {
    pub connection_id: u64,
    pub msg_type: u16,
    pub subsystem_type: u32,
    pub port_context: u64,
    pub connection_info: Vec<u8>,
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
        let hdr = size_of::<LpcCreatePortRequest>();
        let req = LpcCreatePortRequest {
            abi_size: hdr as u16,
            flags: 0,
            max_connection_info,
            max_message,
            max_pool,
            name_offset: hdr as u32,
            name_len_bytes: byte_len(name),
        };
        let buf = pack(&req, name);
        let r = self.backend.call(opcode::LPC_OP_CREATE_PORT, &buf, &mut []);
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
        let hdr = size_of::<LpcConnectPortRequest>();
        let req = LpcConnectPortRequest {
            abi_size: hdr as u16,
            flags: 0,
            subsystem_type,
            name_offset: hdr as u32,
            name_len_bytes: byte_len(name),
            conninfo_offset: (hdr + name.len() * 2) as u32,
            conninfo_len_bytes: conn_info.len() as u32,
        };
        let mut buf = bytemuck::bytes_of(&req).to_vec();
        push_units(&mut buf, name);
        buf.extend_from_slice(conn_info);
        let r = self
            .backend
            .call(opcode::LPC_OP_CONNECT_PORT, &buf, &mut []);
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
            _reserved: 0,
            connection_id,
            port_context,
        };
        let buf = bytemuck::bytes_of(&req).to_vec();
        let r = self
            .backend
            .call(opcode::LPC_OP_ACCEPT_CONNECT, &buf, &mut []);
        NtStatus(r.status).to_result()?;
        Ok(r.detail0)
    }

    /// Complete an accepted connection; returns `(client_handle, connection_id)`.
    pub fn complete_connect(&mut self, connection_id: u64) -> Result<(u64, u64), NtStatus> {
        let req = LpcCompleteConnectRequest {
            abi_size: size_of::<LpcCompleteConnectRequest>() as u16,
            _reserved: 0,
            _reserved2: 0,
            connection_id,
        };
        let buf = bytemuck::bytes_of(&req).to_vec();
        let r = self
            .backend
            .call(opcode::LPC_OP_COMPLETE_CONNECT, &buf, &mut []);
        NtStatus(r.status).to_result()?;
        Ok((r.detail0, r.detail1))
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
        let req = LpcReceiveRequest {
            abi_size: size_of::<LpcReceiveRequest>() as u16,
            _reserved: 0,
            _reserved2: 0,
            port_handle,
            reply_msg_offset: if reply_msg.is_empty() { 0 } else { header as u32 },
            reply_msg_len_bytes: reply_msg.len() as u32,
        };
        let mut buf = bytemuck::bytes_of(&req).to_vec();
        buf.extend_from_slice(reply_msg);
        let mut out = [0u8; 512];
        let r = self
            .backend
            .call(opcode::LPC_OP_REPLY_WAIT_RECEIVE, &buf, &mut out);
        NtStatus(r.status).to_result()?;
        Ok(ReceiveResult {
            connection_id: r.detail0,
            msg_type: r.detail1 as u16,
            subsystem_type: (r.detail1 >> 32) as u32,
            port_context: r.detail0,
            connection_info: out[..(r.information as usize).min(out.len())].to_vec(),
        })
    }

    /// Send an LPC request. An empty result means the peer has not replied yet; the executive can
    /// run the peer and then receive the response on the same communication handle.
    pub fn request_wait_reply(
        &mut self,
        port_handle: u64,
        message: &[u8],
    ) -> Result<Vec<u8>, NtStatus> {
        self.send_message(opcode::LPC_OP_REQUEST_WAIT_REPLY, port_handle, message)
    }

    /// Send an LPC reply without receiving another message.
    pub fn reply_port(&mut self, port_handle: u64, message: &[u8]) -> Result<(), NtStatus> {
        self.send_message(opcode::LPC_OP_REPLY_PORT, port_handle, message)
            .map(|_| ())
    }

    fn send_message(
        &mut self,
        opcode: u16,
        port_handle: u64,
        message: &[u8],
    ) -> Result<Vec<u8>, NtStatus> {
        let header = size_of::<LpcMessageRequest>();
        let req = LpcMessageRequest {
            abi_size: header as u16,
            _reserved: 0,
            _reserved2: 0,
            port_handle,
            msg_offset: header as u32,
            msg_len_bytes: message.len() as u32,
        };
        let mut buf = bytemuck::bytes_of(&req).to_vec();
        buf.extend_from_slice(message);
        let mut out = [0u8; 512];
        let r = self.backend.call(opcode, &buf, &mut out);
        NtStatus(r.status).to_result()?;
        Ok(out[..(r.information as usize).min(out.len())].to_vec())
    }
}

/// The LPC connection-request message type (re-exported for callers).
pub const LPC_CONNECTION_REQUEST: u16 = msg_type::LPC_CONNECTION_REQUEST;

// --- encode helpers --------------------------------------------------------

fn byte_len(units: &[u16]) -> u32 {
    (units.len() * 2) as u32
}

fn pack<T: Pod>(req: &T, units: &[u16]) -> Vec<u8> {
    let mut buf = bytemuck::bytes_of(req).to_vec();
    push_units(&mut buf, units);
    buf
}

fn push_units(buf: &mut Vec<u8>, units: &[u16]) {
    for &u in units {
        buf.extend_from_slice(&u.to_le_bytes());
    }
}
