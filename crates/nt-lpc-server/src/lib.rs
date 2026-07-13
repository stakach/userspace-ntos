//! # `nt-lpc-server` — the isolated NT LPC service state machine
//!
//! The transport-agnostic half of LPC service mode: it owns the **port
//! namespace** (`\SmApiPort`, `\Windows\ApiPort`, …) and the **connection
//! rendezvous state machine** (NtCreatePort → NtConnectPort →
//! NtAcceptConnectPort → NtCompleteConnectPort). A SURT binding (the executive
//! and the `lpc-server` component) feeds it opcodes and request/reply buffers;
//! this crate does no transport and has zero unsafe, so it is fully
//! host-testable — the payoff of isolating LPC.
//!
//! Every request is decoded + bounds-checked with `bytemuck::try_pod_read_unaligned`
//! and explicit slice checks: a malformed request can never panic; it returns an
//! error reply.
//!
//! ## Control plane only — this is a connection BROKER
//!
//! The server owns the port namespace + the connection rendezvous + each
//! connection's *identity*. It is **NOT on the steady-state message path**: it is
//! consulted only at create / connect / accept / complete / disconnect. The DATA
//! plane (NtRequestWaitReplyPort / NtReplyWaitReceivePort / NtReplyPort message
//! traffic) is served DIRECTLY between the endpoints — executive-local cross-badge
//! delivery now (the executive caches the connection produced by CONNECT), a
//! delegated peer-to-peer SURT ring later — never relayed through this server.
//! So the message opcodes are intentionally `NOT_IMPLEMENTED` here: the executive
//! serves them against its cached connection record. Per-connection state is kept
//! minimal (identity + accept policy + peer refs); there are no data-message
//! queues in the server. This mirrors real Windows (the kernel is the medium; the
//! SM process is not a relay) and is idiomatic seL4 capability delegation (the
//! broker mints/grants the channel, peers use it directly).
//!
//! ## Accept policy (interim, path A)
//!
//! The default [`AcceptPolicy::AutoAccept`] makes a connect to a registered port
//! complete synchronously — the server MODELS the acceptor (there is no live
//! smss worker thread yet to run the real accept). This is an explicit,
//! documented interim policy. [`AcceptPolicy::Manual`] is the authentic path
//! (path B): connect leaves the connection `Pending` for a real receiver to
//! drain via receive → accept → complete. The full accept/complete machinery is
//! implemented + host-tested under both policies, so switching to B is a policy
//! swap, not a rewrite.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::mem::size_of;

use bytemuck::Pod;
use nt_lpc_abi::{
    msg_type, opcode, LpcAcceptConnectRequest, LpcClosePortRequest, LpcCompleteConnectRequest,
    LpcConnectPortRequest, LpcCreatePortRequest, LpcReceiveRequest, LpcReply,
};
use nt_status::NtStatus;

/// How the server resolves a connect on a registered port.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcceptPolicy {
    /// Interim (path A): connect completes immediately; the server models the
    /// acceptor. Use while smss's SM-loop threads don't run.
    AutoAccept,
    /// Authentic (path B): connect leaves the connection `Pending` for a real
    /// receiver (smss's SmpApiLoop) to accept + complete.
    Manual,
}

/// A connection's lifecycle.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnState {
    /// Connect issued; awaiting a receiver to drain + accept it (path B).
    Pending,
    /// Delivered to a receiver but not yet accepted.
    Received,
    /// Accepted by the server, awaiting complete.
    Accepted,
    /// Completed — the connector is unblocked.
    Connected,
    /// Refused by the server.
    Refused,
}

/// Base for allocated port / comm-port handles (distinct, recognizable range —
/// `"LP"` — so an LPC handle never looks like a fake object handle).
const LPC_HANDLE_BASE: u64 = 0x0000_4C50_0000_0001;

struct Port {
    handle: u64,
    /// Folded (lowercase) UTF-16 name; empty = unnamed communication port.
    name: Vec<u16>,
    named: bool,
    /// Connection ids awaiting a receiver (path B FIFO).
    pending: Vec<u64>,
}

struct Connection {
    id: u64,
    /// Folded name of the server port connected to.
    port_name: Vec<u16>,
    subsystem_type: u32,
    state: ConnState,
    /// Client-side comm-port handle (returned to the connector on complete).
    client_handle: u64,
    /// Server-side comm-port handle (from accept).
    server_handle: u64,
    port_context: u64,
}

/// The LPC service: a port namespace + connection rendezvous.
pub struct Server {
    ports: Vec<Port>,
    connections: Vec<Connection>,
    next_handle: u64,
    next_conn_id: u64,
    accept_policy: AcceptPolicy,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    /// A new LPC server with an empty namespace and the interim `AutoAccept`
    /// policy (path A).
    pub fn new() -> Self {
        Self {
            ports: Vec::new(),
            connections: Vec::new(),
            next_handle: LPC_HANDLE_BASE,
            next_conn_id: 1,
            accept_policy: AcceptPolicy::AutoAccept,
        }
    }

    /// Swap the accept policy (path B flips this to `Manual`).
    pub fn set_accept_policy(&mut self, p: AcceptPolicy) {
        self.accept_policy = p;
    }

    /// The current accept policy.
    pub fn accept_policy(&self) -> AcceptPolicy {
        self.accept_policy
    }

    /// Number of registered ports (for tests / diagnostics).
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// State of a connection by id (for tests).
    pub fn connection_state(&self, id: u64) -> Option<ConnState> {
        self.connections
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.state)
    }

    /// The subsystem type the connector advertised (broker identity — the accept
    /// validation + the message plane read this).
    pub fn connection_subsystem_type(&self, id: u64) -> Option<u32> {
        self.connections
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.subsystem_type)
    }

    /// The folded name of the port a connection targets (broker identity).
    pub fn connection_port_name(&self, id: u64) -> Option<&[u16]> {
        self.connections
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.port_name.as_slice())
    }

    /// Dispatch one request. `in_buf` = the typed request struct at offset 0 +
    /// inline UTF-16 name / blob payloads; `out_buf` receives any received
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
            // Request/reply message loop = path B / bulk.
            opcode::LPC_OP_REQUEST_WAIT_REPLY | opcode::LPC_OP_REPLY_PORT => {
                Err(NtStatus::NOT_IMPLEMENTED)
            }
            _ => Err(NtStatus::NOT_IMPLEMENTED),
        }
    }

    // --- ops ---------------------------------------------------------------

    fn op_create_port(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcCreatePortRequest = read_req(buf)?;
        let name = read_name(buf, req.name_offset, req.name_len_bytes)?;
        let named = !name.is_empty();
        // Idempotent for a named port: SmpInit / csrsrv may re-create; return the
        // existing handle rather than a spurious collision (interim server).
        if named {
            if let Some(p) = self.ports.iter().find(|p| p.name == name) {
                return Ok(reply(NtStatus::SUCCESS, 0, p.handle, 0));
            }
        }
        let handle = self.alloc_handle();
        self.ports.push(Port {
            handle,
            name,
            named,
            pending: Vec::new(),
        });
        Ok(reply(NtStatus::SUCCESS, 0, handle, 0))
    }

    fn op_connect_port(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcConnectPortRequest = read_req(buf)?;
        let name = read_name(buf, req.name_offset, req.name_len_bytes)?;
        // The port must exist (smss's \SmApiPort registered via create).
        let port_idx = self
            .ports
            .iter()
            .position(|p| p.named && p.name == name)
            .ok_or(NtStatus::OBJECT_NAME_NOT_FOUND)?;

        let id = self.next_conn_id;
        self.next_conn_id += 1;

        match self.accept_policy {
            AcceptPolicy::AutoAccept => {
                // Interim: the server models the acceptor — complete synchronously.
                let client_handle = self.alloc_handle();
                self.connections.push(Connection {
                    id,
                    port_name: name,
                    subsystem_type: req.subsystem_type,
                    state: ConnState::Connected,
                    client_handle,
                    server_handle: 0,
                    port_context: 0,
                });
                Ok(reply(NtStatus::SUCCESS, 0, client_handle, id))
            }
            AcceptPolicy::Manual => {
                // Authentic: leave Pending; a receiver drains + accepts + completes.
                self.ports[port_idx].pending.push(id);
                self.connections.push(Connection {
                    id,
                    port_name: name,
                    subsystem_type: req.subsystem_type,
                    state: ConnState::Pending,
                    client_handle: 0,
                    server_handle: 0,
                    port_context: 0,
                });
                // detail1 = connection id; the executive parks the connector.
                Ok(reply(NtStatus::PENDING, 0, 0, id))
            }
        }
    }

    fn op_accept_connect(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcAcceptConnectRequest = read_req(buf)?;
        let conn = self
            .connections
            .iter_mut()
            .find(|c| c.id == req.connection_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if req.accept == 0 {
            conn.state = ConnState::Refused;
            return Ok(reply(NtStatus::SUCCESS, 0, 0, conn.id));
        }
        conn.state = ConnState::Accepted;
        conn.port_context = req.port_context;
        if conn.server_handle == 0 {
            conn.server_handle = self.next_handle;
            self.next_handle += 1;
        }
        let sh = conn.server_handle;
        let id = conn.id;
        Ok(reply(NtStatus::SUCCESS, 0, sh, id))
    }

    fn op_complete_connect(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcCompleteConnectRequest = read_req(buf)?;
        // The arg may be a connection id or the server comm-port handle.
        let conn = self
            .connections
            .iter_mut()
            .find(|c| c.id == req.connection_id || c.server_handle == req.connection_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        conn.state = ConnState::Connected;
        if conn.client_handle == 0 {
            conn.client_handle = self.next_handle;
            self.next_handle += 1;
        }
        // detail0 = client comm-port handle (to write to the connector's
        // *PortHandle); detail1 = connection id (which parked connector to wake).
        Ok(reply(NtStatus::SUCCESS, 0, conn.client_handle, conn.id))
    }

    fn op_receive(&mut self, buf: &[u8], out_buf: &mut [u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcReceiveRequest = read_req(buf)?;
        let port = self
            .ports
            .iter_mut()
            .find(|p| p.handle == req.port_handle)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        if port.pending.is_empty() {
            // No message — the executive parks the receiver (path B). PENDING is
            // a success status, so the client treats it as "would block".
            return Ok(reply(NtStatus::PENDING, 0, 0, 0));
        }
        let conn_id = port.pending.remove(0);
        if let Some(conn) = self.connections.iter_mut().find(|c| c.id == conn_id) {
            if conn.state == ConnState::Pending {
                conn.state = ConnState::Received;
            }
        }
        // Deliver a minimal connection-request notification: detail0 = connection
        // id, detail1 = LPC_CONNECTION_REQUEST. (The real PORT_MESSAGE/SB blob
        // marshaling into out_buf is the bulk; the len is 0 for now.)
        let _ = out_buf;
        Ok(reply(
            NtStatus::SUCCESS,
            0,
            conn_id,
            msg_type::LPC_CONNECTION_REQUEST as u64,
        ))
    }

    fn op_close_port(&mut self, buf: &[u8]) -> Result<LpcReply, NtStatus> {
        let req: LpcClosePortRequest = read_req(buf)?;
        // A no-op if unknown (idempotent close); remove if a real port handle.
        if let Some(pos) = self.ports.iter().position(|p| p.handle == req.port_handle) {
            self.ports.remove(pos);
        }
        Ok(ok())
    }

    fn alloc_handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }
}

// --- decode helpers (all bounds-checked; never panic) ----------------------

fn read_req<T: Pod>(buf: &[u8]) -> Result<T, NtStatus> {
    let slice = buf
        .get(0..size_of::<T>())
        .ok_or(NtStatus::INVALID_PARAMETER)?;
    bytemuck::try_pod_read_unaligned(slice).map_err(|_| NtStatus::INVALID_PARAMETER)
}

/// Read a UTF-16 name at `offset..offset+len_bytes`, folded to lowercase for
/// case-insensitive matching (NT object names fold ASCII).
fn read_name(buf: &[u8], offset: u32, len_bytes: u32) -> Result<Vec<u16>, NtStatus> {
    let start = offset as usize;
    let end = start
        .checked_add(len_bytes as usize)
        .ok_or(NtStatus::INVALID_PARAMETER)?;
    let bytes = buf.get(start..end).ok_or(NtStatus::INVALID_PARAMETER)?;
    if bytes.len() % 2 != 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|c| fold(u16::from_le_bytes([c[0], c[1]])))
        .collect())
}

#[inline]
fn fold(u: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&u) {
        u + 0x20
    } else {
        u
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
        // Truncated create request.
        assert_eq!(
            s.dispatch(opcode::LPC_OP_CREATE_PORT, &[0u8; 3], &mut [])
                .status,
            NtStatus::INVALID_PARAMETER.raw()
        );
        // Name offset/len past the buffer.
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

    /// Path A: create \SmApiPort, connect (auto-accept) → SUCCESS + a real handle.
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
        // The connection is Connected.
        assert_eq!(s.connection_state(1), Some(ConnState::Connected));
    }

    /// Case-insensitive port-name match (NT object names fold).
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

    /// Path B seam: Manual policy leaves the connection Pending, then a receiver
    /// drains it and the server accepts + completes — the authentic rendezvous.
    #[test]
    fn manual_rendezvous_receive_accept_complete() {
        let mut s = Server::new();
        s.set_accept_policy(AcceptPolicy::Manual);

        // smss creates the port.
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
            // csrss connects → Pending.
            let r = c.connect_port(&utf16("\\SmApiPort"), 2, &[]).unwrap();
            assert!(r.pending, "manual policy must leave the connect pending");
            conn_id = r.connection_id;
        }
        assert_eq!(s.connection_state(conn_id), Some(ConnState::Pending));

        // smss's receiver drains the connection request.
        {
            let mut c = LpcClient::new(Direct {
                server: &mut s,
                out: [0; 512],
            });
            let recv = c.reply_wait_receive(port_handle).unwrap();
            assert_eq!(recv.connection_id, conn_id);
            assert_eq!(recv.msg_type, msg_type::LPC_CONNECTION_REQUEST);
            // smss accepts then completes.
            let sh = c.accept_connect(conn_id, true, 0xC0DE).unwrap();
            assert_ne!(sh, 0);
            let (client_handle, done_id) = c.complete_connect(conn_id).unwrap();
            assert_eq!(done_id, conn_id);
            assert_ne!(client_handle, 0);
        }
        assert_eq!(s.connection_state(conn_id), Some(ConnState::Connected));
    }
}
