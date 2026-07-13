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
//! ## Control plane only — this is a connection BROKER
//!
//! The core owns the port namespace + the connection rendezvous + each
//! connection's identity. It is **NOT on the steady-state message path**: in the
//! live executive the data plane (NtRequestWaitReplyPort / NtReplyWaitReceivePort
//! / NtReplyPort traffic) is served DIRECTLY between endpoints against a cached
//! connection record — never relayed through this component. So the message
//! opcodes here return `NOT_IMPLEMENTED`; the core's message model is used by the
//! host-tested bridge, not the live LPC path.
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
    opcode, LpcAcceptConnectRequest, LpcClosePortRequest, LpcCompleteConnectRequest,
    LpcConnectPortRequest, LpcCreatePortRequest, LpcMessageRequest, LpcReceiveRequest, LpcReply,
};
use nt_port_core::{ConnectOutcome, MessageAttrs, PortApi, PortCore, ReceiveOutcome};
use nt_status::NtStatus;

/// Re-exported from the unified core so existing `nt_lpc_server::{AcceptPolicy,
/// ConnState}` imports keep working.
pub use nt_port_core::{AcceptPolicy, ConnState};

/// The LPC service: the classic-LPC ABI adapter wrapping a [`PortCore`].
pub struct Server {
    core: PortCore,
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
        }
    }

    /// Wrap an existing (possibly ALPC-shared) core — the seam that lets the
    /// isolated port-service component drive one core through both adapters.
    pub fn with_core(core: PortCore) -> Self {
        Self { core }
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
            opcode::LPC_OP_COMPLETE_CONNECT => self.op_complete_connect(in_buf),
            opcode::LPC_OP_REPLY_WAIT_RECEIVE | opcode::LPC_OP_LISTEN_PORT => {
                self.op_receive(in_buf, out_buf)
            }
            opcode::LPC_OP_CLOSE_PORT => self.op_close_port(in_buf),
            // Message plane over the shared core. In the live executive smss/csrss
            // LPC traffic is served by the executive-direct data plane (this path is
            // bypassed); these core-backed ops exist so the LPC↔ALPC bridge — where
            // both sides must meet in ONE core — is exercisable (host tests + the
            // live bridge microtest). LPC carries NO message attributes.
            opcode::LPC_OP_REQUEST_WAIT_REPLY => self.op_request_wait_reply(in_buf, out_buf),
            opcode::LPC_OP_REPLY_PORT => self.op_reply_port(in_buf),
            _ => Err(NtStatus::NOT_IMPLEMENTED),
        }
    }

    // --- ops (LPC ABI ↔ core) ---------------------------------------------

    fn op_create_port(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcCreatePortRequest = read_req(buf)?;
        let name = read_name(buf, req.name_offset, req.name_len_bytes)?;
        let handle = self.core.create_port(&name, PortApi::Lpc);
        Ok(reply(NtStatus::SUCCESS, 0, handle, 0))
    }

    fn op_connect_port(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcConnectPortRequest = read_req(buf)?;
        let name = read_name(buf, req.name_offset, req.name_len_bytes)?;
        let conn_info = read_blob(buf, req.conninfo_offset, req.conninfo_len_bytes)?;
        match self
            .core
            .connect(&name, PortApi::Lpc, req.subsystem_type, conn_info)?
        {
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
        let sh = self
            .core
            .accept(req.connection_id, req.accept != 0, req.port_context)?;
        Ok(reply(NtStatus::SUCCESS, 0, sh, req.connection_id))
    }

    fn op_complete_connect(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcCompleteConnectRequest = read_req(buf)?;
        let (client_handle, conn_id) = self.core.complete(req.connection_id)?;
        Ok(reply(NtStatus::SUCCESS, 0, client_handle, conn_id))
    }

    fn op_receive(&mut self, buf: &[u8], out_buf: &mut [u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcReceiveRequest = read_req(buf)?;
        // A connection request on a listen port takes priority (the SM rendezvous
        // path — behavior preserved); else a data message on a comm port.
        let conn_try = self.core.receive(req.port_handle);
        if let Ok(ReceiveOutcome::ConnectionRequest {
            connection_id,
            msg_type,
        }) = conn_try
        {
            return Ok(reply(NtStatus::SUCCESS, 0, connection_id, msg_type as u64));
        }
        let is_listen_port = conn_try.is_ok(); // valid listen port, nothing pending
        match self.core.receive_message(req.port_handle) {
            Ok(Some(m)) => {
                let n = m.bytes.len().min(out_buf.len());
                out_buf[..n].copy_from_slice(&m.bytes[..n]);
                // detail0 = 0 (LPC surfaces no attributes); detail1 = PORT_MESSAGE type.
                Ok(reply(NtStatus::SUCCESS, n as u32, 0, msg_type_of(&m.bytes) as u64))
            }
            Ok(None) => Ok(reply(NtStatus::PENDING, 0, 0, 0)),
            Err(e) => {
                if is_listen_port {
                    Ok(reply(NtStatus::PENDING, 0, 0, 0))
                } else {
                    Err(e)
                }
            }
        }
    }

    /// `NtRequestWaitReplyPort` — send a message then receive the reply (if any).
    fn op_request_wait_reply(&mut self, buf: &[u8], out_buf: &mut [u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcMessageRequest = read_req(buf)?;
        let msg = read_blob(buf, req.msg_offset, req.msg_len_bytes)?;
        self.core
            .send_message(req.port_handle, msg, MessageAttrs::default())?;
        match self.core.receive_message(req.port_handle)? {
            Some(m) => {
                let n = m.bytes.len().min(out_buf.len());
                out_buf[..n].copy_from_slice(&m.bytes[..n]);
                Ok(reply(NtStatus::SUCCESS, n as u32, 0, msg_type_of(&m.bytes) as u64))
            }
            None => Ok(ok()),
        }
    }

    /// `NtReplyPort` — send a message (no receive).
    fn op_reply_port(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcMessageRequest = read_req(buf)?;
        let msg = read_blob(buf, req.msg_offset, req.msg_len_bytes)?;
        self.core
            .send_message(req.port_handle, msg, MessageAttrs::default())?;
        Ok(ok())
    }

    fn op_close_port(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcClosePortRequest = read_req(buf)?;
        self.core.close_port(req.port_handle);
        Ok(ok())
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
    use nt_lpc_abi::msg_type;
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
            let r = c.connect_port(&utf16("\\SmApiPort"), 2, &[]).unwrap();
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
            let sh = c.accept_connect(conn_id, true, 0xC0DE).unwrap();
            assert_ne!(sh, 0);
            let (client_handle, done_id) = c.complete_connect(conn_id).unwrap();
            assert_eq!(done_id, conn_id);
            assert_ne!(client_handle, 0);
        }
        assert_eq!(s.connection_state(conn_id), Some(ConnState::Connected));
    }

    /// The core-backed LPC message plane (REPLY_PORT send + REPLY_WAIT_RECEIVE
    /// data receive) — used by the bridge, bypassed by the live executive.
    #[test]
    fn lpc_message_plane_roundtrip() {
        use nt_lpc_abi::LpcMessageRequest;
        let mut s = Server::new();
        s.set_accept_policy(AcceptPolicy::Manual);
        // Full rendezvous → Connected with both comm handles.
        let (ph, cid) = {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            let ph = c.create_port(&utf16("\\P"), 0, 0, 0).unwrap();
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
            let (ch, _) = c.complete_connect(cid).unwrap();
            assert_ne!(ch, 0);
            sh
        };
        // The client comm-port handle: a re-complete returns it (idempotent).
        let (client_h, _) = s.core_mut().complete(cid).unwrap();

        // Client sends "ping" via REPLY_PORT (send-only).
        let send = LpcMessageRequest {
            abi_size: size_of::<LpcMessageRequest>() as u16,
            _reserved: 0,
            _reserved2: 0,
            port_handle: client_h,
            msg_offset: size_of::<LpcMessageRequest>() as u32,
            msg_len_bytes: 4,
        };
        let mut buf = bytemuck::bytes_of(&send).to_vec();
        buf.extend_from_slice(b"ping");
        let r = s.dispatch(opcode::LPC_OP_REPLY_PORT, &buf, &mut []);
        assert_eq!(r.status, NtStatus::SUCCESS.raw());

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
        let mut out = [0u8; 64];
        let r = s.dispatch(opcode::LPC_OP_REPLY_WAIT_RECEIVE, &rbuf, &mut out);
        assert_eq!(r.status, NtStatus::SUCCESS.raw());
        assert_eq!(r.information, 4);
        assert_eq!(&out[..4], b"ping");
        assert_eq!(r.detail0, 0, "LPC surfaces no attributes");
    }
}
