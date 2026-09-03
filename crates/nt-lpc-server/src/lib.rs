//! # `nt-lpc-server` — the classic-LPC adapter over the unified port core
//!
//! The LPC (`\SmApiPort`, `\Windows\ApiPort`, …) API surface, translated onto the
//! shared [`nt_port_core::PortCore`]. This crate owns only the **LPC wire ABI**
//! (`nt-lpc-abi` request/reply structs) decode/encode; the port namespace and the
//! connection rendezvous state machine live in the core, so the ALPC adapter
//! (`nt-alpc`) driving the *same* core interoperates automatically (the LPC↔ALPC
//! bridge). Zero unsafe; fully host-testable.
//!
//! Every request is decoded + bounds-checked with `bytemuck::try_pod_read_unaligned`
//! and explicit slice checks: a malformed request can never panic; it returns an
//! error reply.
//!
//! ## Connection and message broker
//!
//! The core owns the port namespace + the connection rendezvous + each
//! connection's identity and message queues. Classic LPC requests and replies are relayed through
//! this component, which applies the kernel-owned `PORT_MESSAGE.Type` transitions before enqueuing
//! them. Kernel `LpcRequestPort` traffic has a distinct operation so typed notifications are not
//! mistaken for user replies.
//!
//! ## Accept policy
//!
//! [`AcceptPolicy::AutoAccept`] makes a connect complete synchronously (the core
//! models the acceptor). [`AcceptPolicy::Manual`] is the authentic path: connect
//! leaves the connection `Pending` for a real receiver to drain via receive →
//! accept → complete. Both are host-tested; switching is a policy swap.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::mem::size_of;

use bytemuck::Pod;
use nt_lpc_abi::{
    connection_state, handle_endpoint, opcode, LpcAcceptConnectRequest, LpcClosePortRequest,
    LpcCompleteConnectRequest, LpcConnectPortRequest, LpcConnectionRequestMetadata,
    LpcCreatePortRequest, LpcDataMessageMetadata, LpcMessageRequest, LpcQueryHandleRequest,
    LpcQueryHandleResponse, LpcQueryRequestRequest, LpcQueryRequestResponse, LpcReceiveRequest,
    LpcReply, LpcRequestIdentityRequest, LPC_ACCEPT_RESPONSE_INFO, LPC_QUERY_HANDLE_NAME_MAX_UNITS,
};
use nt_port_core::{
    ClientId, ConnectOutcome, ConnectionSecurity, MessageAttrs, MessageIdentity, PortApi, PortCore,
    PortHandleEndpoint, PortLimits, ReceiveOutcome,
};
use nt_status::NtStatus;

/// Re-exported from the unified core so existing `nt_lpc_server::{AcceptPolicy,
/// ConnState}` imports keep working.
pub use nt_port_core::{AcceptPolicy, ConnState};

/// The LPC service: the classic-LPC ABI adapter wrapping a [`PortCore`].
pub struct Server {
    core: PortCore,
    next_message_id: u32,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    /// A new LPC server over a fresh port core (interim `AutoAccept` policy).
    pub fn new() -> Self {
        Self {
            core: PortCore::new(),
            next_message_id: 1,
        }
    }

    /// Wrap an existing (possibly ALPC-shared) core — the seam that lets the
    /// isolated port-service component drive one core through both adapters.
    pub fn with_core(core: PortCore) -> Self {
        Self {
            core,
            next_message_id: 1,
        }
    }

    /// Shared access to the underlying core (so an ALPC adapter can drive the
    /// same namespace — the bridge).
    pub fn core_mut(&mut self) -> &mut PortCore {
        &mut self.core
    }

    /// Swap the accept policy (path B flips this to `Manual`).
    pub fn set_accept_policy(&mut self, p: AcceptPolicy) {
        self.core.set_accept_policy(p);
    }

    /// The current accept policy.
    pub fn accept_policy(&self) -> AcceptPolicy {
        self.core.accept_policy()
    }

    /// Number of registered ports (for tests / diagnostics).
    pub fn port_count(&self) -> usize {
        self.core.port_count()
    }

    /// State of a connection by id (for tests).
    pub fn connection_state(&self, id: u64) -> Option<ConnState> {
        self.core.connection_state(id)
    }

    /// The subsystem type the connector advertised.
    pub fn connection_subsystem_type(&self, id: u64) -> Option<u32> {
        self.core.connection_subsystem_type(id)
    }

    /// The folded name of the port a connection targets.
    pub fn connection_port_name(&self, id: u64) -> Option<&[u16]> {
        self.core.connection_port_name(id)
    }

    /// Dispatch one LPC request. `in_buf` = the typed request struct at offset 0
    /// then inline UTF-16 name / blob payloads; `out_buf` receives any received
    /// message. Always returns a reply — a bad request yields an error status,
    /// never a panic.
    pub fn dispatch(&mut self, op: u16, in_buf: &[u8], out_buf: &mut [u8]) -> LpcReply {
        match self.try_dispatch(op, in_buf, out_buf) {
            Ok(r) => r,
            Err(status) => reply(status, 0, 0, 0),
        }
    }

    fn try_dispatch(
        &mut self,
        op: u16,
        in_buf: &[u8],
        out_buf: &mut [u8],
    ) -> Result<LpcReply, NtStatus> {
        match op {
            opcode::LPC_OP_PING => Ok(ok()),
            opcode::LPC_OP_CREATE_PORT => self.op_create_port(in_buf),
            opcode::LPC_OP_CONNECT_PORT => self.op_connect_port(in_buf),
            opcode::LPC_OP_ACCEPT_CONNECT => self.op_accept_connect(in_buf),
            opcode::LPC_OP_COMPLETE_CONNECT => self.op_complete_connect(in_buf, out_buf),
            opcode::LPC_OP_REPLY_WAIT_RECEIVE | opcode::LPC_OP_LISTEN_PORT => {
                self.op_receive(in_buf, out_buf)
            }
            opcode::LPC_OP_CLOSE_PORT => self.op_close_port(in_buf),
            // Message plane over the shared core. LPC carries no ALPC message attributes.
            opcode::LPC_OP_REQUEST_WAIT_REPLY => self.op_request_wait_reply(in_buf, out_buf),
            opcode::LPC_OP_REPLY_PORT => self.op_reply_port(in_buf),
            opcode::LPC_OP_REQUEST_PORT => self.op_request_port(in_buf),
            opcode::LPC_OP_QUERY_HANDLE => self.op_query_handle(in_buf, out_buf),
            opcode::LPC_OP_QUERY_REQUEST => self.op_query_request(in_buf, out_buf),
            opcode::LPC_OP_RECEIVE_REPLY => self.op_receive_reply(in_buf, out_buf),
            opcode::LPC_OP_CANCEL_REQUEST => self.op_cancel_request(in_buf),
            opcode::LPC_OP_RETAIN_CONNECTION_PORT => self.op_retain_connection_port(in_buf),
            opcode::LPC_OP_RELEASE_CONNECTION_PORT => self.op_release_connection_port(in_buf),
            opcode::LPC_OP_RETAIN_PORT_OBJECT => self.op_retain_port_object(in_buf),
            opcode::LPC_OP_RELEASE_PORT_OBJECT => self.op_release_port_object(in_buf),
            opcode::LPC_OP_KERNEL_REQUEST_WAIT_REPLY => {
                self.op_kernel_request_wait_reply(in_buf, out_buf)
            }
            opcode::LPC_OP_RETAINED_REQUEST_WAIT_REPLY => {
                self.op_retained_request_wait_reply(in_buf, out_buf)
            }
            opcode::LPC_OP_RETAINED_REQUEST_PORT => self.op_retained_request_port(in_buf),
            _ => Err(NtStatus::NOT_IMPLEMENTED),
        }
    }

    // --- ops (LPC ABI ↔ core) ---------------------------------------------

    fn op_create_port(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcCreatePortRequest = read_req(buf)?;
        let name = read_name(buf, req.name_offset, req.name_len_bytes)?;
        let handle = self.core.create_port_with_owner_and_limits(
            &name,
            PortApi::Lpc,
            nt_port_core::ClientId {
                process: req.server_process,
                thread: req.server_thread,
            },
            PortLimits {
                max_connection_info: req.max_connection_info,
                max_message: req.max_message,
                max_pool_usage: req.max_pool,
            },
        )?;
        Ok(reply(NtStatus::SUCCESS, 0, handle, 0))
    }

    fn op_connect_port(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcConnectPortRequest = read_req(buf)?;
        let name = read_name(buf, req.name_offset, req.name_len_bytes)?;
        let conn_info = read_blob(buf, req.conninfo_offset, req.conninfo_len_bytes)?;
        match self.core.connect_with_client_id_and_security(
            &name,
            PortApi::Lpc,
            req.subsystem_type,
            conn_info,
            nt_port_core::ClientId {
                process: req.client_process,
                thread: req.client_thread,
            },
            ConnectionSecurity {
                impersonation_level: req.impersonation_level,
                dynamic_tracking: req.dynamic_tracking != 0,
                effective_only: req.effective_only != 0,
            },
        )? {
            ConnectOutcome::Completed {
                client_handle,
                connection_id,
            } => Ok(reply(NtStatus::SUCCESS, 0, client_handle, connection_id)),
            ConnectOutcome::Pending { connection_id } => {
                Ok(reply(NtStatus::PENDING, 0, 0, connection_id))
            }
        }
    }

    fn op_accept_connect(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcAcceptConnectRequest = read_req(buf)?;
        let sh = if req.flags & LPC_ACCEPT_RESPONSE_INFO != 0 {
            if req.flags != LPC_ACCEPT_RESPONSE_INFO {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let response_info = read_blob(buf, req.conninfo_offset, req.conninfo_len_bytes)?;
            self.core.accept_with_connection_info(
                req.connection_id,
                req.accept != 0,
                req.port_context,
                response_info,
            )?
        } else {
            if req.flags != 0 || req.conninfo_offset != 0 || req.conninfo_len_bytes != 0 {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            self.core
                .accept(req.connection_id, req.accept != 0, req.port_context)?
        };
        Ok(reply(NtStatus::SUCCESS, 0, sh, req.connection_id))
    }

    fn op_complete_connect(
        &mut self,
        buf: &[u8],
        out_buf: &mut [u8],
    ) -> Result<LpcReply, NtStatus> {
        let req: LpcCompleteConnectRequest = read_req(buf)?;
        let (client_handle, conn_id) = self.core.complete(req.connection_id)?;
        let response_info = self
            .core
            .connection_response_info(conn_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if response_info.len() > out_buf.len() {
            return Err(NtStatus::BUFFER_TOO_SMALL);
        }
        out_buf[..response_info.len()].copy_from_slice(response_info);
        Ok(reply(
            NtStatus::SUCCESS,
            response_info.len() as u32,
            client_handle,
            conn_id,
        ))
    }

    fn op_receive(&mut self, buf: &[u8], out_buf: &mut [u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcReceiveRequest = read_req(buf)?;
        if req.reply_msg_len_bytes != 0 {
            let reply_msg = read_blob(buf, req.reply_msg_offset, req.reply_msg_len_bytes)?;
            let reply_msg = message_with_type(reply_msg, nt_lpc_abi::msg_type::LPC_REPLY)?;
            let identity = message_identity_of(&reply_msg)?;
            self.core.send_reply_message(
                req.port_handle,
                &reply_msg,
                MessageAttrs::default(),
                identity,
            )?;
        }
        // A connection request on a listen port takes priority (the SM rendezvous
        // path — behavior preserved); else a data message on a comm port.
        let conn_try = self.core.receive(req.port_handle);
        if let Ok(ReceiveOutcome::ConnectionRequest {
            connection_id,
            msg_type,
        }) = conn_try
        {
            let info = self.core.connection_info(connection_id).unwrap_or(&[]);
            let subsystem_type = self
                .core
                .connection_subsystem_type(connection_id)
                .unwrap_or(0);
            let client_id = self
                .core
                .connection_client_id(connection_id)
                .unwrap_or_default();
            let metadata = LpcConnectionRequestMetadata {
                abi_size: core::mem::size_of::<LpcConnectionRequestMetadata>() as u16,
                _reserved: 0,
                subsystem_type,
                client_process: client_id.process,
                client_thread: client_id.thread,
                conninfo_len_bytes: info.len() as u32,
                _reserved2: 0,
            };
            let metadata_bytes = bytemuck::bytes_of(&metadata);
            let total = metadata_bytes
                .len()
                .checked_add(info.len())
                .ok_or(NtStatus::BUFFER_TOO_SMALL)?;
            if total > out_buf.len() {
                return Err(NtStatus::BUFFER_TOO_SMALL);
            }
            out_buf[..metadata_bytes.len()].copy_from_slice(metadata_bytes);
            out_buf[metadata_bytes.len()..total].copy_from_slice(info);
            return Ok(reply(
                NtStatus::SUCCESS,
                total as u32,
                connection_id,
                msg_type as u64 | ((subsystem_type as u64) << 32),
            ));
        }
        let valid_receive_port = conn_try.is_ok();
        match self.core.receive_message(req.port_handle) {
            Ok(Some(m)) => {
                let metadata = LpcDataMessageMetadata {
                    abi_size: core::mem::size_of::<LpcDataMessageMetadata>() as u16,
                    _reserved: 0,
                    _reserved2: 0,
                    connection_id: m.provenance.connection_id,
                    client_process: m.provenance.client.process,
                    client_thread: m.provenance.client.thread,
                    port_context: m.port_context,
                };
                let metadata = bytemuck::bytes_of(&metadata);
                let total = m
                    .bytes
                    .len()
                    .checked_add(metadata.len())
                    .ok_or(NtStatus::BUFFER_TOO_SMALL)?;
                if total > out_buf.len() {
                    return Err(NtStatus::BUFFER_TOO_SMALL);
                }
                out_buf[..m.bytes.len()].copy_from_slice(&m.bytes);
                out_buf[m.bytes.len()..total].copy_from_slice(metadata);
                Ok(reply(
                    NtStatus::SUCCESS,
                    total as u32,
                    m.port_context,
                    msg_type_of(&m.bytes) as u64,
                ))
            }
            Ok(None) => Ok(reply(NtStatus::PENDING, 0, 0, 0)),
            Err(e) => {
                if valid_receive_port {
                    Ok(reply(NtStatus::PENDING, 0, 0, 0))
                } else {
                    Err(e)
                }
            }
        }
    }

    /// `NtRequestWaitReplyPort` — send a message then receive the reply (if any).
    fn op_request_wait_reply(
        &mut self,
        buf: &[u8],
        out_buf: &mut [u8],
    ) -> Result<LpcReply, NtStatus> {
        let req: LpcMessageRequest = read_req(buf)?;
        let msg = read_blob(buf, req.msg_offset, req.msg_len_bytes)?;
        let identity = MessageIdentity {
            client: ClientId {
                process: req.client_process,
                thread: req.client_thread,
            },
            message_id: self.allocate_message_id(),
        };
        let msg = message_with_request_identity(msg, identity)?;
        self.core
            .send_request_message(req.port_handle, &msg, MessageAttrs::default(), identity)?;
        match self.core.receive_reply_message(req.port_handle, identity)? {
            Some(m) => {
                let n = m.bytes.len().min(out_buf.len());
                out_buf[..n].copy_from_slice(&m.bytes[..n]);
                Ok(reply(
                    NtStatus::SUCCESS,
                    n as u32,
                    identity.message_id as u64,
                    msg_type_of(&m.bytes) as u64,
                ))
            }
            None => Ok(reply(NtStatus::PENDING, 0, identity.message_id as u64, 0)),
        }
    }

    fn op_kernel_request_wait_reply(
        &mut self,
        buf: &[u8],
        out_buf: &mut [u8],
    ) -> Result<LpcReply, NtStatus> {
        let req: LpcMessageRequest = read_req(buf)?;
        let msg = read_blob(buf, req.msg_offset, req.msg_len_bytes)?;
        let identity = MessageIdentity {
            client: ClientId {
                process: req.client_process,
                thread: req.client_thread,
            },
            message_id: self.allocate_message_id(),
        };
        let msg = message_with_kernel_request_identity(msg, identity)?;
        self.core.send_kernel_request_message(
            req.port_handle,
            &msg,
            MessageAttrs::default(),
            identity,
        )?;
        match self.core.receive_reply_message(req.port_handle, identity)? {
            Some(message) => {
                let n = message.bytes.len().min(out_buf.len());
                out_buf[..n].copy_from_slice(&message.bytes[..n]);
                Ok(reply(
                    NtStatus::SUCCESS,
                    n as u32,
                    identity.message_id as u64,
                    msg_type_of(&message.bytes) as u64,
                ))
            }
            None => Ok(reply(NtStatus::PENDING, 0, identity.message_id as u64, 0)),
        }
    }

    fn op_retained_request_wait_reply(
        &mut self,
        buf: &[u8],
        out_buf: &mut [u8],
    ) -> Result<LpcReply, NtStatus> {
        let req: LpcMessageRequest = read_req(buf)?;
        let msg = read_blob(buf, req.msg_offset, req.msg_len_bytes)?;
        let identity = MessageIdentity {
            client: ClientId {
                process: req.client_process,
                thread: req.client_thread,
            },
            message_id: self.allocate_message_id(),
        };
        let msg = message_with_request_identity(msg, identity)?;
        self.core.send_kernel_request_message(
            req.port_handle,
            &msg,
            MessageAttrs::default(),
            identity,
        )?;
        match self.core.receive_reply_message(req.port_handle, identity)? {
            Some(message) => {
                let n = message.bytes.len().min(out_buf.len());
                out_buf[..n].copy_from_slice(&message.bytes[..n]);
                Ok(reply(
                    NtStatus::SUCCESS,
                    n as u32,
                    identity.message_id as u64,
                    msg_type_of(&message.bytes) as u64,
                ))
            }
            None => Ok(reply(NtStatus::PENDING, 0, identity.message_id as u64, 0)),
        }
    }

    fn op_retained_request_port(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcMessageRequest = read_req(buf)?;
        let msg = read_blob(buf, req.msg_offset, req.msg_len_bytes)?;
        let msg_type = msg_type_of(msg);
        let msg = if msg_type == 0 {
            message_with_type(msg, nt_lpc_abi::msg_type::LPC_DATAGRAM)?
        } else if (nt_lpc_abi::msg_type::LPC_DATAGRAM..=nt_lpc_abi::msg_type::LPC_CLIENT_DIED)
            .contains(&msg_type)
        {
            validated_port_message(msg)?
        } else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        self.core.send_retained_message(
            req.port_handle,
            &msg,
            MessageAttrs::default(),
            ClientId {
                process: req.client_process,
                thread: req.client_thread,
            },
        )?;
        Ok(ok())
    }

    fn op_receive_reply(&mut self, buf: &[u8], out_buf: &mut [u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcRequestIdentityRequest = read_req(buf)?;
        let identity = MessageIdentity {
            client: ClientId {
                process: req.client_process,
                thread: req.client_thread,
            },
            message_id: req.message_id,
        };
        match self.core.receive_reply_message(req.port_handle, identity)? {
            Some(message) => {
                let n = message.bytes.len().min(out_buf.len());
                out_buf[..n].copy_from_slice(&message.bytes[..n]);
                Ok(reply(
                    NtStatus::SUCCESS,
                    n as u32,
                    identity.message_id as u64,
                    msg_type_of(&message.bytes) as u64,
                ))
            }
            None => Ok(reply(NtStatus::PENDING, 0, identity.message_id as u64, 0)),
        }
    }

    fn op_cancel_request(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcRequestIdentityRequest = read_req(buf)?;
        let identity = MessageIdentity {
            client: ClientId {
                process: req.client_process,
                thread: req.client_thread,
            },
            message_id: req.message_id,
        };
        let cancelled = self
            .core
            .cancel_request_message(req.port_handle, identity)?;
        Ok(reply(
            NtStatus::SUCCESS,
            0,
            u64::from(cancelled),
            identity.message_id as u64,
        ))
    }

    /// `NtReplyPort` — send a message (no receive).
    fn op_reply_port(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcMessageRequest = read_req(buf)?;
        let msg = read_blob(buf, req.msg_offset, req.msg_len_bytes)?;
        let msg = message_with_type(msg, nt_lpc_abi::msg_type::LPC_REPLY)?;
        let identity = message_identity_of(&msg)?;
        self.core
            .send_reply_message(req.port_handle, &msg, MessageAttrs::default(), identity)?;
        Ok(ok())
    }

    /// Kernel `LpcRequestPort` — preserve an explicitly typed kernel notification, or normalize
    /// the type-zero form to `LPC_DATAGRAM` as the NT kernel does.
    fn op_request_port(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcMessageRequest = read_req(buf)?;
        let msg = read_blob(buf, req.msg_offset, req.msg_len_bytes)?;
        let msg_type = msg_type_of(msg);
        let msg = if msg_type == 0 {
            message_with_type(msg, nt_lpc_abi::msg_type::LPC_DATAGRAM)?
        } else if (nt_lpc_abi::msg_type::LPC_DATAGRAM..=nt_lpc_abi::msg_type::LPC_CLIENT_DIED)
            .contains(&msg_type)
        {
            validated_port_message(msg)?
        } else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        self.core
            .send_message(req.port_handle, &msg, MessageAttrs::default())?;
        Ok(ok())
    }

    fn op_close_port(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcClosePortRequest = read_req(buf)?;
        self.core.close_port(req.port_handle);
        Ok(ok())
    }

    fn op_retain_connection_port(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcClosePortRequest = read_req(buf)?;
        let retained = self.core.retain_connection_port(req.port_handle)?;
        Ok(reply(NtStatus::SUCCESS, 0, retained, 0))
    }

    fn op_release_connection_port(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcClosePortRequest = read_req(buf)?;
        self.core.release_connection_port(req.port_handle)?;
        Ok(ok())
    }

    fn op_retain_port_object(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcClosePortRequest = read_req(buf)?;
        let retained = self.core.retain_port_object(req.port_handle)?;
        Ok(reply(NtStatus::SUCCESS, 0, retained, 0))
    }

    fn op_release_port_object(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcClosePortRequest = read_req(buf)?;
        self.core.release_port_object(req.port_handle)?;
        Ok(ok())
    }

    fn op_query_handle(&mut self, buf: &[u8], out_buf: &mut [u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcQueryHandleRequest = read_req(buf)?;
        let info = self
            .core
            .handle_info(req.port_handle)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        if out_buf.len() < size_of::<LpcQueryHandleResponse>() {
            return Err(NtStatus::BUFFER_TOO_SMALL);
        }
        if info.port_name.len() > LPC_QUERY_HANDLE_NAME_MAX_UNITS {
            return Err(NtStatus::BUFFER_TOO_SMALL);
        }
        let mut response = LpcQueryHandleResponse {
            abi_size: size_of::<LpcQueryHandleResponse>() as u16,
            endpoint: endpoint_code(info.endpoint),
            state: state_code(info.state),
            name_len_units: info.port_name.len() as u16,
            connection_id: info.connection_id,
            server_process: info.server_id.process,
            server_thread: info.server_id.thread,
            client_process: info.client_id.map(|client| client.process).unwrap_or(0),
            client_thread: info.client_id.map(|client| client.thread).unwrap_or(0),
            max_connection_info: info.limits.max_connection_info,
            max_message: info.limits.max_message,
            max_pool_usage: info.limits.max_pool_usage,
            impersonation_level: info
                .security
                .map(|security| security.impersonation_level)
                .unwrap_or(0),
            dynamic_tracking: info
                .security
                .map(|security| u8::from(security.dynamic_tracking))
                .unwrap_or(0),
            effective_only: info
                .security
                .map(|security| u8::from(security.effective_only))
                .unwrap_or(0),
            security_present: u8::from(info.security.is_some()),
            _reserved3: 0,
            _reserved4: 0,
            name: [0; LPC_QUERY_HANDLE_NAME_MAX_UNITS],
        };
        response.name[..info.port_name.len()].copy_from_slice(info.port_name);
        out_buf[..size_of::<LpcQueryHandleResponse>()]
            .copy_from_slice(bytemuck::bytes_of(&response));
        Ok(reply(
            NtStatus::SUCCESS,
            size_of::<LpcQueryHandleResponse>() as u32,
            0,
            0,
        ))
    }

    fn op_query_request(&mut self, buf: &[u8], out_buf: &mut [u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcQueryRequestRequest = read_req(buf)?;
        let identity = MessageIdentity {
            client: ClientId {
                process: req.client_process,
                thread: req.client_thread,
            },
            message_id: req.message_id,
        };
        let info = self.core.delivered_request(req.port_handle, identity)?;
        let response = LpcQueryRequestResponse {
            abi_size: size_of::<LpcQueryRequestResponse>() as u16,
            _reserved: 0,
            message_id: req.message_id,
            connection_id: info.connection_id,
            client_process: info.client.process,
            client_thread: info.client.thread,
            impersonation_level: info.security.impersonation_level,
            dynamic_tracking: u8::from(info.security.dynamic_tracking),
            effective_only: u8::from(info.security.effective_only),
            _reserved2: 0,
        };
        let response_bytes = bytemuck::bytes_of(&response);
        if out_buf.len() < response_bytes.len() {
            return Err(NtStatus::BUFFER_TOO_SMALL);
        }
        out_buf[..response_bytes.len()].copy_from_slice(response_bytes);
        Ok(reply(
            NtStatus::SUCCESS,
            response_bytes.len() as u32,
            info.connection_id,
            req.message_id as u64,
        ))
    }

    fn allocate_message_id(&mut self) -> u32 {
        let message_id = self.next_message_id.max(1);
        self.next_message_id = message_id.wrapping_add(1).max(1);
        message_id
    }
}

// --- decode helpers (all bounds-checked; never panic) ----------------------

fn read_req<T: Pod>(buf: &[u8]) -> Result<T, NtStatus> {
    let slice = buf
        .get(0..size_of::<T>())
        .ok_or(NtStatus::INVALID_PARAMETER)?;
    bytemuck::try_pod_read_unaligned(slice).map_err(|_| NtStatus::INVALID_PARAMETER)
}

/// Read a UTF-16 name at `offset..offset+len_bytes`. Case-folding is done by the
/// core on lookup.
fn read_name(buf: &[u8], offset: u32, len_bytes: u32) -> Result<Vec<u16>, NtStatus> {
    let bytes = read_blob(buf, offset, len_bytes)?;
    if bytes.len() % 2 != 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect())
}

/// Read a raw byte blob at `offset..offset+len_bytes` (empty when `len_bytes==0`).
fn read_blob(buf: &[u8], offset: u32, len_bytes: u32) -> Result<&[u8], NtStatus> {
    if len_bytes == 0 {
        return Ok(&[]);
    }
    let start = offset as usize;
    let end = start
        .checked_add(len_bytes as usize)
        .ok_or(NtStatus::INVALID_PARAMETER)?;
    buf.get(start..end).ok_or(NtStatus::INVALID_PARAMETER)
}

/// The `PORT_MESSAGE.Type` at offset 4 of a framed message (0 if too short).
fn msg_type_of(bytes: &[u8]) -> u16 {
    match bytes.get(4..6) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]),
        None => 0,
    }
}

fn validated_port_message(bytes: &[u8]) -> Result<Vec<u8>, NtStatus> {
    let header: [u8; 4] = bytes
        .get(..4)
        .and_then(|header| header.try_into().ok())
        .ok_or(NtStatus::INVALID_PARAMETER)?;
    let total = nt_lpc_abi::port_message_total_length(header).ok_or(NtStatus::INVALID_PARAMETER)?;
    if total != bytes.len() {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    Ok(bytes.to_vec())
}

fn message_with_type(bytes: &[u8], msg_type: u16) -> Result<Vec<u8>, NtStatus> {
    let mut message = validated_port_message(bytes)?;
    message[4..6].copy_from_slice(&msg_type.to_le_bytes());
    Ok(message)
}

fn message_identity_of(bytes: &[u8]) -> Result<MessageIdentity, NtStatus> {
    let message = validated_port_message(bytes)?;
    let client_process = u64::from_le_bytes(
        message[8..16]
            .try_into()
            .map_err(|_| NtStatus::INVALID_PARAMETER)?,
    );
    let client_thread = u64::from_le_bytes(
        message[16..24]
            .try_into()
            .map_err(|_| NtStatus::INVALID_PARAMETER)?,
    );
    let message_id = u32::from_le_bytes(
        message[24..28]
            .try_into()
            .map_err(|_| NtStatus::INVALID_PARAMETER)?,
    );
    if message_id == 0 {
        return Err(NtStatus::REPLY_MESSAGE_MISMATCH);
    }
    Ok(MessageIdentity {
        client: ClientId {
            process: client_process,
            thread: client_thread,
        },
        message_id,
    })
}

fn message_with_request_identity(
    bytes: &[u8],
    identity: MessageIdentity,
) -> Result<Vec<u8>, NtStatus> {
    let mut message = message_with_type(bytes, nt_lpc_abi::msg_type::LPC_REQUEST)?;
    message[8..16].copy_from_slice(&identity.client.process.to_le_bytes());
    message[16..24].copy_from_slice(&identity.client.thread.to_le_bytes());
    message[24..28].copy_from_slice(&identity.message_id.to_le_bytes());
    message[28..32].fill(0);
    Ok(message)
}

fn message_with_kernel_request_identity(
    bytes: &[u8],
    identity: MessageIdentity,
) -> Result<Vec<u8>, NtStatus> {
    let mut message = validated_port_message(bytes)?;
    if msg_type_of(&message) != nt_lpc_abi::msg_type::LPC_ERROR_EVENT {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    message[8..16].copy_from_slice(&identity.client.process.to_le_bytes());
    message[16..24].copy_from_slice(&identity.client.thread.to_le_bytes());
    message[24..28].copy_from_slice(&identity.message_id.to_le_bytes());
    message[28..32].fill(0);
    Ok(message)
}

fn endpoint_code(endpoint: PortHandleEndpoint) -> u16 {
    match endpoint {
        PortHandleEndpoint::ListenPort => handle_endpoint::LISTEN_PORT,
        PortHandleEndpoint::ClientCommPort => handle_endpoint::CLIENT_COMM_PORT,
        PortHandleEndpoint::ServerCommPort => handle_endpoint::SERVER_COMM_PORT,
    }
}

fn state_code(state: Option<ConnState>) -> u16 {
    match state {
        None => connection_state::NONE,
        Some(ConnState::Pending) => connection_state::PENDING,
        Some(ConnState::Received) => connection_state::RECEIVED,
        Some(ConnState::Accepted) => connection_state::ACCEPTED,
        Some(ConnState::Connected) => connection_state::CONNECTED,
        Some(ConnState::Refused) => connection_state::REFUSED,
    }
}

fn reply(status: NtStatus, information: u32, detail0: u64, detail1: u64) -> LpcReply {
    LpcReply {
        status: status.raw(),
        information,
        detail0,
        detail1,
    }
}

fn ok() -> LpcReply {
    reply(NtStatus::SUCCESS, 0, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use nt_lpc_abi::{connection_state, handle_endpoint, msg_type};
    use nt_lpc_client::LpcClient;

    /// In-process backend: drive the server directly (no transport) — the
    /// host-test equivalent of the SURT ring.
    struct Direct<'a> {
        server: &'a mut Server,
        out: [u8; 512],
    }
    impl nt_lpc_client::Backend for Direct<'_> {
        fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> LpcReply {
            let r = self.server.dispatch(opcode, in_buf, &mut self.out);
            let n = (r.information as usize)
                .min(out_buf.len())
                .min(self.out.len());
            out_buf[..n].copy_from_slice(&self.out[..n]);
            r
        }
    }

    fn utf16(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn port_message(msg_type: u16, payload: &[u8]) -> Vec<u8> {
        let total = nt_lpc_abi::PORT_MESSAGE_HEADER_LEN + payload.len();
        let mut message = vec![0u8; total];
        message[0..2].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        message[2..4].copy_from_slice(&(total as u16).to_le_bytes());
        message[4..6].copy_from_slice(&msg_type.to_le_bytes());
        message[nt_lpc_abi::PORT_MESSAGE_HEADER_LEN..].copy_from_slice(payload);
        message
    }

    #[test]
    fn ping_ok() {
        let mut s = Server::new();
        assert_eq!(
            s.dispatch(opcode::LPC_OP_PING, &[], &mut []).status,
            NtStatus::SUCCESS.raw()
        );
    }

    #[test]
    fn unknown_opcode_not_implemented() {
        let mut s = Server::new();
        assert_eq!(
            s.dispatch(0x22ee, &[], &mut []).status,
            NtStatus::NOT_IMPLEMENTED.raw()
        );
    }

    #[test]
    fn malformed_requests_do_not_panic() {
        let mut s = Server::new();
        assert_eq!(
            s.dispatch(opcode::LPC_OP_CREATE_PORT, &[0u8; 3], &mut [])
                .status,
            NtStatus::INVALID_PARAMETER.raw()
        );
        let bad = LpcCreatePortRequest {
            abi_size: size_of::<LpcCreatePortRequest>() as u16,
            flags: 0,
            max_connection_info: 0,
            max_message: 0,
            max_pool: 0,
            name_offset: 1000,
            name_len_bytes: 8,
            server_process: 0,
            server_thread: 0,
        };
        let buf = bytemuck::bytes_of(&bad).to_vec();
        assert_eq!(
            s.dispatch(opcode::LPC_OP_CREATE_PORT, &buf, &mut []).status,
            NtStatus::INVALID_PARAMETER.raw()
        );
    }

    #[test]
    fn auto_accept_connect_completes() {
        let mut s = Server::new();
        {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            let ph = c
                .create_port(&utf16("\\SmApiPort"), 0x88, 0x148, 0x2400)
                .expect("create");
            assert_ne!(ph, 0);
            let r = c
                .connect_port(&utf16("\\SmApiPort"), 2, &[])
                .expect("connect");
            assert!(!r.pending, "auto-accept must complete synchronously");
            assert_ne!(r.handle, 0, "client comm-port handle must be non-zero");
        }
        assert_eq!(s.connection_state(1), Some(ConnState::Connected));
    }

    #[test]
    fn connect_is_case_insensitive() {
        let mut s = Server::new();
        let mut c = LpcClient::new(Direct {
            server: &mut s,
            out: [0; 512],
        });
        c.create_port(&utf16("\\SmApiPort"), 0, 0, 0).unwrap();
        let r = c.connect_port(&utf16("\\smapiport"), 0, &[]).unwrap();
        assert!(!r.pending);
        assert_ne!(r.handle, 0);
    }

    #[test]
    fn connect_unknown_port_not_found() {
        let mut s = Server::new();
        let mut c = LpcClient::new(Direct {
            server: &mut s,
            out: [0; 512],
        });
        let e = c.connect_port(&utf16("\\NoSuchPort"), 0, &[]).unwrap_err();
        assert_eq!(e, NtStatus::OBJECT_NAME_NOT_FOUND);
    }

    #[test]
    fn create_is_idempotent_for_named_port() {
        let mut s = Server::new();
        let mut c = LpcClient::new(Direct {
            server: &mut s,
            out: [0; 512],
        });
        let a = c.create_port(&utf16("\\SmApiPort"), 0, 0, 0).unwrap();
        let b = c.create_port(&utf16("\\SmApiPort"), 0, 0, 0).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn manual_rendezvous_receive_accept_complete() {
        let mut s = Server::new();
        s.set_accept_policy(AcceptPolicy::Manual);

        let port_handle;
        let conn_id;
        {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            port_handle = c
                .create_port(&utf16("\\SmApiPort"), 0x88, 0x148, 0)
                .unwrap();
            let r = c
                .connect_port_with_client_id(
                    &utf16("\\SmApiPort"),
                    2,
                    b"sb-connect-info",
                    0x44,
                    0x88,
                )
                .unwrap();
            assert!(r.pending, "manual policy must leave the connect pending");
            conn_id = r.connection_id;
        }
        assert_eq!(s.connection_state(conn_id), Some(ConnState::Pending));

        {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            let recv = c.reply_wait_receive(port_handle).unwrap();
            assert_eq!(recv.connection_id, conn_id);
            assert_eq!(recv.msg_type, msg_type::LPC_CONNECTION_REQUEST);
            assert_eq!(recv.subsystem_type, 2);
            assert_eq!(recv.client_process, 0x44);
            assert_eq!(recv.client_thread, 0x88);
            assert_eq!(recv.connection_info, b"sb-connect-info");
            let sh = c.accept_connect(conn_id, true, 0xC0DE).unwrap();
            assert_ne!(sh, 0);
            let completed = c.complete_connect(conn_id).unwrap();
            assert_eq!(completed.connection_id, conn_id);
            assert_ne!(completed.handle, 0);
            assert_eq!(completed.connection_info, b"sb-connect-info");
        }
        assert_eq!(s.connection_state(conn_id), Some(ConnState::Connected));
    }

    #[test]
    fn accept_returns_server_authored_connection_information_on_complete() {
        let mut s = Server::new();
        s.set_accept_policy(AcceptPolicy::Manual);
        let (port, conn_id) = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            let port = c
                .create_port(&utf16("\\Windows\\ApiPort"), 0x88, 0x148, 0)
                .unwrap();
            let pending = c
                .connect_port(&utf16("\\Windows\\ApiPort"), 0, b"client")
                .unwrap();
            (port, pending.connection_id)
        };

        let mut c = LpcClient::new(Direct {
            server: &mut s,
            out: [0; 512],
        });
        assert_eq!(
            c.reply_wait_receive(port).unwrap().connection_info,
            b"client"
        );
        c.accept_connect_with_info(conn_id, true, 0x44, b"server")
            .unwrap();
        let completed = c.complete_connect(conn_id).unwrap();
        assert_eq!(completed.connection_id, conn_id);
        assert_ne!(completed.handle, 0);
        assert_eq!(completed.connection_info, b"server");
    }

    #[test]
    fn srm_two_port_handshake_queues_reverse_lsa_connect() {
        let mut s = Server::new();
        s.set_accept_policy(AcceptPolicy::Manual);

        let (rm_listen, lsa_listen, rm_conn) = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            let lsa_listen = c
                .create_port(&utf16("\\SeLsaCommandPort"), 0, 0x148, 0)
                .unwrap();
            let rm_listen = c
                .create_port(&utf16("\\SeRmCommandPort"), 0, 0x148, 0)
                .unwrap();
            let rm = c.connect_port(&utf16("\\SeRmCommandPort"), 0, &[]).unwrap();
            assert!(rm.pending);
            (rm_listen, lsa_listen, rm.connection_id)
        };

        {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            let rm_request = c.reply_wait_receive(rm_listen).unwrap();
            assert_eq!(rm_request.connection_id, rm_conn);
            assert_eq!(rm_request.msg_type, msg_type::LPC_CONNECTION_REQUEST);
            let rm_server = c.accept_connect(rm_conn, true, 0).unwrap();
            assert_ne!(rm_server, 0);
            let completed = c.complete_connect(rm_server).unwrap();
            assert_ne!(completed.handle, 0);
            assert_eq!(completed.connection_id, rm_conn);

            let lsa = c
                .connect_port(&utf16("\\SeLsaCommandPort"), 0, &[])
                .unwrap();
            assert!(lsa.pending);

            let lsa_request = c.reply_wait_receive(lsa_listen).unwrap();
            assert_eq!(lsa_request.connection_id, lsa.connection_id);
            assert_eq!(lsa_request.msg_type, msg_type::LPC_CONNECTION_REQUEST);
            let lsa_server = c.accept_connect(lsa.connection_id, true, 0).unwrap();
            assert_ne!(lsa_server, 0);
            let completed = c.complete_connect(lsa_server).unwrap();
            assert_ne!(completed.handle, 0);
            assert_eq!(completed.connection_id, lsa.connection_id);
            assert_eq!(
                c.reply_wait_receive(lsa_server).unwrap_err(),
                NtStatus::PENDING
            );
        }
    }

    #[test]
    fn query_handle_reports_broker_endpoint_identity() {
        let mut s = Server::new();
        s.set_accept_policy(AcceptPolicy::Manual);
        let listen;
        let conn_id;
        {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            listen = c
                .create_port_with_owner(
                    &utf16("\\LsaAuthenticationPort"),
                    0x88,
                    0x148,
                    0x2400,
                    0x120,
                    0x124,
                )
                .unwrap();
            conn_id = c
                .connect_port_with_client_security(
                    &utf16("\\LSAAUTHENTICATIONPORT"),
                    0,
                    &[],
                    0x44,
                    0x48,
                    2,
                    true,
                    true,
                )
                .unwrap()
                .connection_id;
        }
        let (client, server) = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            c.reply_wait_receive(listen).unwrap();
            let server = c.accept_connect(conn_id, true, 0).unwrap();
            let client = c.complete_connect(server).unwrap().handle;
            (client, server)
        };
        let mut c = LpcClient::new(Direct {
            server: &mut s,
            out: [0; 512],
        });
        let listen_info = c.query_handle(listen).unwrap();
        assert_eq!(listen_info.endpoint, handle_endpoint::LISTEN_PORT);
        assert_eq!(listen_info.connection_id, 0);
        assert_eq!(listen_info.state, connection_state::NONE);
        assert_eq!(listen_info.name, utf16("\\lsaauthenticationport"));
        assert_eq!(listen_info.server_process, 0x120);
        assert_eq!(listen_info.server_thread, 0x124);
        assert_eq!(listen_info.client_process, 0);
        assert_eq!(listen_info.client_thread, 0);
        assert_eq!(listen_info.max_connection_info, 0x88);
        assert_eq!(listen_info.max_message, 0x148);
        assert_eq!(listen_info.max_pool_usage, 0x2400);
        assert!(!listen_info.security_present);

        let client_info = c.query_handle(client).unwrap();
        assert_eq!(client_info.endpoint, handle_endpoint::CLIENT_COMM_PORT);
        assert_eq!(client_info.connection_id, conn_id);
        assert_eq!(client_info.state, connection_state::CONNECTED);
        assert_eq!(client_info.name, utf16("\\lsaauthenticationport"));
        assert_eq!(client_info.server_process, 0x120);
        assert_eq!(client_info.server_thread, 0x124);
        assert_eq!(client_info.client_process, 0x44);
        assert_eq!(client_info.client_thread, 0x48);
        assert_eq!(client_info.max_connection_info, 0x88);
        assert_eq!(client_info.max_message, 0x148);
        assert_eq!(client_info.max_pool_usage, 0x2400);
        assert_eq!(client_info.impersonation_level, 2);
        assert!(client_info.dynamic_tracking);
        assert!(client_info.effective_only);
        assert!(client_info.security_present);

        let server_info = c.query_handle(server).unwrap();
        assert_eq!(server_info.endpoint, handle_endpoint::SERVER_COMM_PORT);
        assert_eq!(server_info.connection_id, conn_id);
        assert_eq!(server_info.state, connection_state::CONNECTED);
        assert_eq!(server_info.name, utf16("\\lsaauthenticationport"));
        assert_eq!(server_info.server_process, 0x120);
        assert_eq!(server_info.server_thread, 0x124);
        assert_eq!(server_info.client_process, 0x44);
        assert_eq!(server_info.client_thread, 0x48);
        assert_eq!(server_info.max_message, 0x148);
        assert_eq!(server_info.impersonation_level, 2);
        assert!(server_info.dynamic_tracking);
        assert!(server_info.effective_only);
        assert!(server_info.security_present);

        assert_eq!(
            c.query_handle(0xfeed).unwrap_err(),
            NtStatus::INVALID_HANDLE
        );
    }

    /// The core-backed LPC request plane stamps an authoritative sender and message id.
    #[test]
    fn lpc_message_plane_roundtrip() {
        let mut s = Server::new();
        s.set_accept_policy(AcceptPolicy::Manual);
        // Full rendezvous → Connected with both comm handles.
        let (ph, cid) = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            let ph = c.create_port(&utf16("\\P"), 0, 0x148, 0).unwrap();
            let r = c.connect_port(&utf16("\\P"), 0, &[]).unwrap();
            (ph, r.connection_id)
        };
        let sh = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            c.reply_wait_receive(ph).unwrap();
            let sh = c.accept_connect(cid, true, 0).unwrap();
            let ch = c.complete_connect(cid).unwrap().handle;
            assert_ne!(ch, 0);
            sh
        };
        // The client comm-port handle: a re-complete returns it (idempotent).
        let (client_h, _) = s.core_mut().complete(cid).unwrap();

        // Client sends a synchronous request. The adapter owns its header identity.
        let message = port_message(msg_type::LPC_REQUEST, b"ping");
        let mut c = LpcClient::new(Direct {
            server: &mut s,
            out: [0; 512],
        });
        assert!(c.request_wait_reply(client_h, &message).unwrap().is_empty());

        // Server receives it via REPLY_WAIT_RECEIVE on its comm handle.
        let recv = LpcReceiveRequest {
            abi_size: size_of::<LpcReceiveRequest>() as u16,
            _reserved: 0,
            _reserved2: 0,
            port_handle: sh,
            reply_msg_offset: 0,
            reply_msg_len_bytes: 0,
        };
        let rbuf = bytemuck::bytes_of(&recv).to_vec();
        let mut out = [0u8; 128];
        let r = c
            .backend_mut()
            .server
            .dispatch(opcode::LPC_OP_REPLY_WAIT_RECEIVE, &rbuf, &mut out);
        assert_eq!(r.status, NtStatus::SUCCESS.raw());
        assert_eq!(
            r.information,
            (message.len() + size_of::<LpcDataMessageMetadata>()) as u32
        );
        assert_eq!(msg_type_of(&out), msg_type::LPC_REQUEST);
        assert_ne!(u32::from_le_bytes(out[24..28].try_into().unwrap()), 0);
        assert_eq!(
            &out[nt_lpc_abi::PORT_MESSAGE_HEADER_LEN..message.len()],
            b"ping"
        );
        let metadata: LpcDataMessageMetadata = bytemuck::pod_read_unaligned(
            &out[message.len()..message.len() + size_of::<LpcDataMessageMetadata>()],
        );
        assert_eq!(metadata.connection_id, cid);
        assert_eq!(r.detail0, 0, "LPC surfaces no attributes");
    }

    #[test]
    fn client_died_frame_reaches_the_listen_port_unchanged() {
        let mut s = Server::new();
        s.set_accept_policy(AcceptPolicy::Manual);
        let (listen, connection) = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            let listen = c
                .create_port(&utf16("\\Windows\\ApiPort"), 0, 0x148, 0)
                .unwrap();
            let pending = c
                .connect_port(&utf16("\\Windows\\ApiPort"), 2, &[])
                .unwrap();
            (listen, pending.connection_id)
        };
        let client = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            c.reply_wait_receive(listen).unwrap();
            let server = c.accept_connect(connection, true, 0x1234).unwrap();
            c.complete_connect(server).unwrap().handle
        };

        let mut message = nt_lpc_abi::client_died_message(0x1122_3344_5566_7788);
        message[8..16].copy_from_slice(&24u64.to_le_bytes());
        message[16..24].copy_from_slice(&872u64.to_le_bytes());
        let received = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            c.request_port(client, &message).unwrap();
            c.reply_wait_receive(listen).unwrap()
        };
        assert_eq!(received.connection_id, connection);
        assert_eq!(received.msg_type, msg_type::LPC_CLIENT_DIED);
        assert_eq!(received.port_context, 0x1234);
        assert_eq!(received.connection_info, message);
    }

    #[test]
    fn request_port_normalizes_type_zero_to_datagram() {
        let mut s = Server::new();
        s.set_accept_policy(AcceptPolicy::Manual);
        let (listen, connection) = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            let listen = c
                .create_port(&utf16("\\Windows\\ApiPort"), 0, 0x148, 0)
                .unwrap();
            let pending = c
                .connect_port(&utf16("\\Windows\\ApiPort"), 2, &[])
                .unwrap();
            (listen, pending.connection_id)
        };
        let client = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            c.reply_wait_receive(listen).unwrap();
            let server = c.accept_connect(connection, true, 0x1234).unwrap();
            c.complete_connect(server).unwrap().handle
        };

        let mut message = port_message(0, b"datagram");
        message[8..16].copy_from_slice(&24u64.to_le_bytes());
        message[16..24].copy_from_slice(&100u64.to_le_bytes());
        let received = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            c.request_port(client, &message).unwrap();
            c.reply_wait_receive(listen).unwrap()
        };
        message[4..6].copy_from_slice(&msg_type::LPC_DATAGRAM.to_le_bytes());
        assert_eq!(received.connection_id, connection);
        assert_eq!(received.msg_type, msg_type::LPC_DATAGRAM);
        assert_eq!(received.port_context, 0x1234);
        assert_eq!(received.connection_info, message);
    }

    #[test]
    fn synchronous_request_reply_uses_listen_port_and_context() {
        let mut s = Server::new();
        s.set_accept_policy(AcceptPolicy::Manual);
        let (listen, connection) = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            let listen = c.create_port(&utf16("\\SmApiPort"), 0, 0x148, 0).unwrap();
            let pending = c
                .connect_port_with_client_id(&utf16("\\SmApiPort"), 0, &[], 0x120, 0x124)
                .unwrap();
            (listen, pending.connection_id)
        };
        let (client, server) = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            c.reply_wait_receive(listen).unwrap();
            let server = c.accept_connect(connection, true, 0x5a5a).unwrap();
            let client = c.complete_connect(connection).unwrap().handle;
            (client, server)
        };
        assert_ne!(server, 0);

        {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            let request_message = port_message(0, b"request");
            let queued_message_id = c
                .begin_request_wait_reply_with_client_id(client, &request_message, 0x120, 0x124)
                .unwrap()
                .message_id();
            let request = c.reply_wait_receive(listen).unwrap();
            assert_eq!(request.connection_id, connection);
            assert_eq!(request.client_process, 0x120);
            assert_eq!(request.client_thread, 0x124);
            assert_eq!(request.msg_type, msg_type::LPC_REQUEST);
            assert_eq!(
                &request.connection_info[nt_lpc_abi::PORT_MESSAGE_HEADER_LEN..],
                b"request"
            );
            assert_eq!(request.port_context, 0x5a5a);
            assert_eq!(
                u64::from_le_bytes(request.connection_info[8..16].try_into().unwrap()),
                0x120
            );
            assert_eq!(
                u64::from_le_bytes(request.connection_info[16..24].try_into().unwrap()),
                0x124
            );
            let message_id =
                u32::from_le_bytes(request.connection_info[24..28].try_into().unwrap());
            assert_eq!(message_id, queued_message_id);
            let query = c.query_request(listen, 0x120, 0x124, message_id).unwrap();
            assert_eq!(query.connection_id, connection);

            let mut response_message = port_message(msg_type::LPC_REQUEST, b"response");
            response_message[8..28].copy_from_slice(&request.connection_info[8..28]);
            let next = c
                .reply_wait_receive_with_reply(listen, &response_message)
                .unwrap_err();
            assert_eq!(next, NtStatus::PENDING);
            assert_eq!(
                c.query_request(listen, 0x120, 0x124, message_id),
                Err(NtStatus::REPLY_MESSAGE_MISMATCH)
            );
            let response = c
                .receive_reply(client, 0x120, 0x124, message_id)
                .unwrap()
                .unwrap();
            assert_eq!(
                &response[nt_lpc_abi::PORT_MESSAGE_HEADER_LEN..],
                b"response"
            );
        }
    }

    #[test]
    fn retained_connection_port_preserves_typed_kernel_request() {
        let mut server = Server::new();
        server.set_accept_policy(AcceptPolicy::Manual);
        let mut client = LpcClient::new(Direct {
            server: &mut server,
            out: [0; 512],
        });
        let listen = client
            .create_port(&utf16("\\Windows\\ApiPort"), 0, 0x148, 0)
            .unwrap();
        let retained = client.retain_connection_port(listen).unwrap();
        let request = port_message(msg_type::LPC_ERROR_EVENT, b"hard-error");
        let message_id = client
            .begin_kernel_request_wait_reply(retained, &request, 0x220, 0x224)
            .unwrap()
            .message_id();

        let received = client.reply_wait_receive(listen).unwrap();
        assert_eq!(received.connection_id, 0);
        assert_eq!(received.client_process, 0x220);
        assert_eq!(received.client_thread, 0x224);
        assert_eq!(received.msg_type, msg_type::LPC_ERROR_EVENT);
        assert_eq!(
            u32::from_le_bytes(received.connection_info[24..28].try_into().unwrap()),
            message_id
        );
        let mut reply = received.connection_info;
        reply[4..6].copy_from_slice(&msg_type::LPC_REPLY.to_le_bytes());
        assert_eq!(
            client.reply_wait_receive_with_reply(listen, &reply),
            Err(NtStatus::PENDING)
        );
        assert_eq!(
            client
                .receive_reply(retained, 0x220, 0x224, message_id)
                .unwrap(),
            Some(reply)
        );
        client.close_port(listen).unwrap();
        client.release_connection_port(retained).unwrap();
        assert_eq!(server.port_count(), 0);
    }

    #[test]
    fn retained_port_object_routes_process_exception_connection_port() {
        let mut server = Server::new();
        server.set_accept_policy(AcceptPolicy::Manual);
        let mut client = LpcClient::new(Direct {
            server: &mut server,
            out: [0; 512],
        });
        let listen = client
            .create_port(&utf16("\\Windows\\ApiPort"), 0, 0x148, 0)
            .unwrap();
        let retained = client.retain_port_object(listen).unwrap();
        let request = port_message(msg_type::LPC_ERROR_EVENT, b"process-hard-error");
        let message_id = client
            .begin_kernel_request_wait_reply(retained, &request, 0x330, 0x334)
            .unwrap()
            .message_id();
        let received = client.reply_wait_receive(listen).unwrap();
        assert_eq!(received.connection_id, 0);
        assert_eq!(received.client_process, 0x330);
        assert_eq!(received.msg_type, msg_type::LPC_ERROR_EVENT);
        let mut reply = received.connection_info;
        reply[4..6].copy_from_slice(&msg_type::LPC_REPLY.to_le_bytes());
        assert_eq!(
            client.reply_wait_receive_with_reply(listen, &reply),
            Err(NtStatus::PENDING)
        );
        assert_eq!(
            client
                .receive_reply(retained, 0x330, 0x334, message_id)
                .unwrap(),
            Some(reply)
        );
        client.release_port_object(retained).unwrap();
        client.close_port(listen).unwrap();
        assert_eq!(server.port_count(), 0);
    }

    #[test]
    fn retained_communication_port_preserves_typed_kernel_request_after_user_close() {
        let mut server = Server::new();
        server.set_accept_policy(AcceptPolicy::Manual);
        let mut client = LpcClient::new(Direct {
            server: &mut server,
            out: [0; 512],
        });
        let listen = client
            .create_port(&utf16("\\ProcessExceptionPort"), 0, 0x148, 0)
            .unwrap();
        let pending = client
            .connect_port_with_client_id(&utf16("\\ProcessExceptionPort"), 0, &[], 0x330, 0x334)
            .unwrap();
        client.reply_wait_receive(listen).unwrap();
        let server_port = client
            .accept_connect(pending.connection_id, true, 0x7788)
            .unwrap();
        let client_port = client
            .complete_connect(pending.connection_id)
            .unwrap()
            .handle;
        let retained = client.retain_port_object(client_port).unwrap();
        client.close_port(client_port).unwrap();

        let request = port_message(msg_type::LPC_ERROR_EVENT, b"process-hard-error");
        let message_id = client
            .begin_kernel_request_wait_reply(retained, &request, 0x330, 0x334)
            .unwrap()
            .message_id();
        let received = client.reply_wait_receive(listen).unwrap();
        assert_eq!(received.connection_id, pending.connection_id);
        assert_eq!(received.client_process, 0x330);
        assert_eq!(received.client_thread, 0x334);
        assert_eq!(received.msg_type, msg_type::LPC_ERROR_EVENT);
        assert_eq!(received.port_context, 0x7788);
        assert_eq!(
            u32::from_le_bytes(received.connection_info[24..28].try_into().unwrap()),
            message_id
        );

        let mut reply = received.connection_info;
        reply[4..6].copy_from_slice(&msg_type::LPC_REPLY.to_le_bytes());
        assert_eq!(
            client.reply_wait_receive_with_reply(listen, &reply),
            Err(NtStatus::PENDING)
        );
        assert_eq!(
            client
                .receive_reply(retained, 0x330, 0x334, message_id)
                .unwrap(),
            Some(reply)
        );

        client.release_port_object(retained).unwrap();
        assert_eq!(
            client.release_port_object(retained),
            Err(NtStatus::INVALID_PORT_HANDLE)
        );
        client.close_port(server_port).unwrap();
        client.close_port(listen).unwrap();
        assert_eq!(server.port_count(), 0);
    }

    #[test]
    fn retained_communication_port_routes_ordinary_request_after_user_close() {
        let mut server = Server::new();
        server.set_accept_policy(AcceptPolicy::Manual);
        let mut client = LpcClient::new(Direct {
            server: &mut server,
            out: [0; 512],
        });
        let listen = client
            .create_port(&utf16("\\Windows\\ApiPort"), 0, 0x148, 0)
            .unwrap();
        let pending = client
            .connect_port_with_client_id(&utf16("\\Windows\\ApiPort"), 0, &[], 0x440, 0x444)
            .unwrap();
        client.reply_wait_receive(listen).unwrap();
        let server_port = client
            .accept_connect(pending.connection_id, true, 0x9911)
            .unwrap();
        let client_port = client
            .complete_connect(pending.connection_id)
            .unwrap()
            .handle;
        let retained = client.retain_port_object(client_port).unwrap();
        client.close_port(client_port).unwrap();

        let request = port_message(0, b"create-system-thread");
        let result = client
            .begin_retained_request_wait_reply(retained, &request, 0x440, 0x444)
            .unwrap();
        let message_id = result.message_id();
        assert!(matches!(
            result,
            nt_lpc_client::BeginRequestWaitReply::Pending { .. }
        ));
        let received = client.reply_wait_receive(listen).unwrap();
        assert_eq!(received.connection_id, pending.connection_id);
        assert_eq!(received.client_process, 0x440);
        assert_eq!(received.client_thread, 0x444);
        assert_eq!(received.msg_type, msg_type::LPC_REQUEST);
        assert_eq!(received.port_context, 0x9911);
        assert_eq!(
            &received.connection_info[nt_lpc_abi::PORT_MESSAGE_HEADER_LEN..],
            b"create-system-thread"
        );

        let mut reply = received.connection_info;
        reply[4..6].copy_from_slice(&msg_type::LPC_REPLY.to_le_bytes());
        assert_eq!(
            client.reply_wait_receive_with_reply(listen, &reply),
            Err(NtStatus::PENDING)
        );
        assert_eq!(
            client.receive_reply(retained, 0x440, 0x445, message_id),
            Err(NtStatus::REPLY_MESSAGE_MISMATCH)
        );
        assert_eq!(
            client
                .receive_reply(retained, 0x440, 0x444, message_id)
                .unwrap(),
            Some(reply)
        );

        client.release_port_object(retained).unwrap();
        client.close_port(server_port).unwrap();
        client.close_port(listen).unwrap();
        assert_eq!(server.port_count(), 0);
    }

    #[test]
    fn retained_communication_port_routes_datagram_after_user_close() {
        let mut server = Server::new();
        server.set_accept_policy(AcceptPolicy::Manual);
        let mut client = LpcClient::new(Direct {
            server: &mut server,
            out: [0; 512],
        });
        let listen = client
            .create_port(&utf16("\\Windows\\ApiPort"), 0, 0x148, 0)
            .unwrap();
        let pending = client
            .connect_port_with_client_id(&utf16("\\Windows\\ApiPort"), 0, &[], 0x550, 0x554)
            .unwrap();
        client.reply_wait_receive(listen).unwrap();
        let server_port = client
            .accept_connect(pending.connection_id, true, 0)
            .unwrap();
        let client_port = client
            .complete_connect(pending.connection_id)
            .unwrap()
            .handle;
        let retained = client.retain_port_object(client_port).unwrap();
        client.close_port(client_port).unwrap();

        client
            .retained_request_port(retained, &port_message(0, b"notify"), 0x550, 0x554)
            .unwrap();
        let received = client.reply_wait_receive(listen).unwrap();
        assert_eq!(received.msg_type, msg_type::LPC_DATAGRAM);
        assert_eq!(received.client_process, 0x550);
        assert_eq!(received.client_thread, 0x554);
        assert_eq!(
            &received.connection_info[nt_lpc_abi::PORT_MESSAGE_HEADER_LEN..],
            b"notify"
        );

        client.release_port_object(retained).unwrap();
        client.close_port(server_port).unwrap();
        client.close_port(listen).unwrap();
        assert_eq!(server.port_count(), 0);
    }

    #[test]
    fn hard_error_request_opcode_still_rejects_an_ordinary_request() {
        let mut server = Server::new();
        let mut client = LpcClient::new(Direct {
            server: &mut server,
            out: [0; 512],
        });
        let listen = client
            .create_port(&utf16("\\Windows\\ApiPort"), 0, 0x148, 0)
            .unwrap();
        let retained = client.retain_port_object(listen).unwrap();
        assert_eq!(
            client.begin_kernel_request_wait_reply(
                retained,
                &port_message(0, b"not-a-hard-error"),
                0x660,
                0x664,
            ),
            Err(NtStatus::INVALID_PARAMETER)
        );
        client.release_port_object(retained).unwrap();
        client.close_port(listen).unwrap();
    }

    #[test]
    fn server_comm_reply_then_receive_uses_shared_connection_port() {
        let mut s = Server::new();
        s.set_accept_policy(AcceptPolicy::Manual);
        let (listen, first_connection) = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            let listen = c
                .create_port(&utf16("\\Windows\\ApiPort"), 0, 0x148, 0)
                .unwrap();
            let pending = c
                .connect_port(&utf16("\\Windows\\ApiPort"), 2, &[])
                .unwrap();
            (listen, pending.connection_id)
        };
        let first_server = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            c.reply_wait_receive(listen).unwrap();
            let server = c.accept_connect(first_connection, true, 0x1111).unwrap();
            c.complete_connect(server).unwrap();
            server
        };
        let second_connection = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            c.connect_port(&utf16("\\Windows\\ApiPort"), 2, &[])
                .unwrap()
                .connection_id
        };

        let mut c = LpcClient::new(Direct {
            server: &mut s,
            out: [0; 512],
        });
        let received = c.reply_wait_receive(first_server).unwrap();
        assert_eq!(received.connection_id, second_connection);
        assert_eq!(received.msg_type, msg_type::LPC_CONNECTION_REQUEST);
    }
}
