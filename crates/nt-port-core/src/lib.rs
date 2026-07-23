//! # `nt-port-core` — the unified NT port core
//!
//! LPC (NT5 classic `NtConnectPort`/`NtCreatePort`/…) and ALPC (Vista+/Win7
//! `NtAlpc*`) are two API surfaces over the **same underlying port concept**.
//! This crate is that concept, factored out so both the [`nt-lpc-server`] and the
//! [`nt-alpc`] adapters drive ONE core — which is what makes the **LPC↔ALPC
//! bridge automatic**: a classic-LPC client and an ALPC host that name the same
//! port share a single [`PortCore`] connection object, so a message from one
//! reaches the other with no relaying.
//!
//! The core owns:
//! * the **port namespace** (named server ports + allocated comm-port handles),
//! * the **connection rendezvous state machine** (create → connect → accept →
//!   complete → disconnect), and
//! * a minimal **PORT_MESSAGE data model** (per-connection bidirectional message
//!   queues carrying the framed bytes + an API-neutral [`MessageAttrs`] set).
//!
//! It is **API-neutral**: no LPC/ALPC wire structs, no opcodes, no transport.
//! Adapters translate their ABI to/from these methods. Zero `unsafe`; fully
//! host-testable.
//!
//! ## Where the message model is (and is NOT) used
//!
//! In the live executive the steady-state LPC message plane is served by DIRECT
//! cross-badge delivery against a cached connection record (the broker is not a
//! relay). The [`PortCore`] message queues here are the API-neutral model the
//! adapters share and the **host-tested bridge** exercises; the executive's
//! direct path is an optimization layered on top and does not route through them.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use nt_status::NtStatus;

/// PORT_MESSAGE `u2.s2.Type` values — the dispatch key shared by LPC and ALPC
/// (both frame messages with the same 40-byte x64 `PORT_MESSAGE` header).
pub mod port_message_type {
    pub const REQUEST: u16 = 1;
    pub const REPLY: u16 = 2;
    pub const DATAGRAM: u16 = 3;
    pub const PORT_CLOSED: u16 = 5;
    pub const CLIENT_DIED: u16 = 6;
    pub const CONNECTION_REQUEST: u16 = 10;
    pub const CONNECTION_REFUSED: u16 = 11;
}

/// How the core resolves a connect on a registered port.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcceptPolicy {
    /// Interim: connect completes immediately; the core models the acceptor
    /// (used while there is no live server worker thread to run the real accept).
    AutoAccept,
    /// Authentic: connect leaves the connection `Pending` for a real receiver to
    /// drain via receive → accept → complete.
    Manual,
}

/// A connection's lifecycle.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnState {
    /// Connect issued; awaiting a receiver to drain + accept it.
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

/// Which API surface an endpoint of a connection speaks. Purely informational —
/// the core treats both identically; the tag lets adapters and diagnostics see
/// that a bridge is in effect (e.g. LPC client ↔ ALPC server).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PortApi {
    Lpc,
    Alpc,
}

/// The outcome of [`PortCore::connect`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// The connect completed synchronously (`AutoAccept`).
    Completed { client_handle: u64, connection_id: u64 },
    /// The connect is parked awaiting a receiver (`Manual`).
    Pending { connection_id: u64 },
}

/// The outcome of [`PortCore::receive`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReceiveOutcome {
    /// A pending connection request was delivered.
    ConnectionRequest { connection_id: u64, msg_type: u16 },
    /// Nothing pending — the caller should park (a "would block").
    WouldBlock,
}

/// An API-neutral projection of the ALPC message-attribute set — the greatest
/// common denominator the core carries alongside a `PORT_MESSAGE`. Adapters map
/// their API attributes to/from this; the LPC adapter always uses
/// [`MessageAttrs::default`] (empty). This is the load-bearing type for the
/// **bridge degradation policy** (see the crate `nt-alpc` docs):
///
/// * `context` (the ALPC context attribute's `PortContext`) BRIDGES — it maps to
///   the connection port context / rides the `PORT_MESSAGE` header, so it
///   survives crossing to an LPC peer.
/// * `view`, `handles`, `security`, `token` DO NOT bridge to LPC (classic LPC has
///   no per-message equivalent). Crossing to an LPC peer they are DROPPED and the
///   loss is recorded in the receiving adapter; crossing FROM an LPC peer the
///   ALPC receiver sees them absent (`ValidAttributes` cleared).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MessageAttrs {
    /// ALPC context attribute `PortContext` (bridges).
    pub context: Option<u64>,
    /// ALPC data-view attribute: `(section_handle, view_base, view_size)`
    /// (does not bridge to LPC — dropped, `degraded` set on the receiver).
    pub view: Option<DataView>,
    /// ALPC handle attribute: handles to duplicate across the port
    /// (does not bridge to LPC).
    pub handles: Vec<u64>,
    /// ALPC security attribute: an opaque security-context id
    /// (does not bridge to LPC).
    pub security: Option<u64>,
    /// ALPC token attribute present (does not bridge to LPC).
    pub token: Option<u64>,
}

impl MessageAttrs {
    /// True if any non-bridging attribute is present (used to flag degradation
    /// when the message crosses to an LPC peer).
    pub fn has_non_bridging(&self) -> bool {
        self.view.is_some()
            || !self.handles.is_empty()
            || self.security.is_some()
            || self.token.is_some()
    }
}

/// An ALPC data-view descriptor as carried by the core (opaque section id +
/// geometry).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DataView {
    pub section_handle: u64,
    pub view_base: u64,
    pub view_size: u64,
}

/// A queued `PORT_MESSAGE`: the framed bytes plus the API-neutral attributes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueuedMessage {
    pub bytes: Vec<u8>,
    pub attrs: MessageAttrs,
    /// Accepted connection PortContext used only for classic LPC listen-port routing.
    pub port_context: u64,
}

/// Base for allocated port / comm-port handles (a distinct, recognizable range —
/// ASCII `"LP"` — so a port handle never looks like a fake object handle).
const PORT_HANDLE_BASE: u64 = 0x0000_4C50_0000_0001;

/// The maximum length of a stored connection-info blob (guards against an
/// oversized connect payload growing core state without bound).
pub const MAX_CONNINFO: usize = 512;

struct Port {
    handle: u64,
    /// Folded (lowercase) UTF-16 name; empty = unnamed communication port.
    name: Vec<u16>,
    named: bool,
    api: PortApi,
    /// Connection ids awaiting a receiver (Manual-policy FIFO).
    pending: Vec<u64>,
    /// Connection whose request was most recently received through this listen port. LPC's
    /// `NtReplyWaitReceivePort` replies through the listen handle, so the core retains this routing
    /// identity until the server sends that reply.
    reply_connection: Option<u64>,
}

struct Connection {
    id: u64,
    /// Folded name of the server port connected to.
    port_name: Vec<u16>,
    subsystem_type: u32,
    /// Opaque connection-info blob from the connector (SB_CONNECTION_INFO for an
    /// LPC connector, the ALPC ConnectionInformation blob for an ALPC connector).
    /// Passed through byte-for-byte to the acceptor — the bridge connection-info
    /// mapping.
    conn_info: Vec<u8>,
    state: ConnState,
    client_api: PortApi,
    server_api: PortApi,
    /// Client-side comm-port handle (returned to the connector on complete).
    client_handle: u64,
    /// Server-side comm-port handle (from accept).
    server_handle: u64,
    port_context: u64,
    /// Messages destined FOR the client (sent BY the server).
    client_inbox: Vec<QueuedMessage>,
    /// Messages destined FOR the server (sent BY the client).
    server_inbox: Vec<QueuedMessage>,
}

/// The unified port core: a port namespace + connection rendezvous + message
/// model, driven identically by the LPC and ALPC adapters.
pub struct PortCore {
    ports: Vec<Port>,
    connections: Vec<Connection>,
    next_handle: u64,
    next_conn_id: u64,
    accept_policy: AcceptPolicy,
}

impl Default for PortCore {
    fn default() -> Self {
        Self::new()
    }
}

impl PortCore {
    /// A new core with an empty namespace and the interim `AutoAccept` policy.
    pub fn new() -> Self {
        Self {
            ports: Vec::new(),
            connections: Vec::new(),
            next_handle: PORT_HANDLE_BASE,
            next_conn_id: 1,
            accept_policy: AcceptPolicy::AutoAccept,
        }
    }

    /// Swap the accept policy.
    pub fn set_accept_policy(&mut self, p: AcceptPolicy) {
        self.accept_policy = p;
    }

    /// The current accept policy.
    pub fn accept_policy(&self) -> AcceptPolicy {
        self.accept_policy
    }

    /// Number of registered ports.
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// State of a connection by id.
    pub fn connection_state(&self, id: u64) -> Option<ConnState> {
        self.conn(id).map(|c| c.state)
    }

    /// The subsystem type the connector advertised.
    pub fn connection_subsystem_type(&self, id: u64) -> Option<u32> {
        self.conn(id).map(|c| c.subsystem_type)
    }

    /// The folded name of the port a connection targets.
    pub fn connection_port_name(&self, id: u64) -> Option<&[u16]> {
        self.conn(id).map(|c| c.port_name.as_slice())
    }

    /// The opaque connection-info blob (the bridge connection-info passthrough).
    pub fn connection_info(&self, id: u64) -> Option<&[u8]> {
        self.conn(id).map(|c| c.conn_info.as_slice())
    }

    /// The `(client_api, server_api)` of a connection — a cross-API pair means
    /// the bridge is in effect.
    pub fn connection_apis(&self, id: u64) -> Option<(PortApi, PortApi)> {
        self.conn(id).map(|c| (c.client_api, c.server_api))
    }

    /// The API a registered named port was created under.
    pub fn port_api(&self, name: &[u16]) -> Option<PortApi> {
        let folded = fold_name(name);
        self.ports
            .iter()
            .find(|p| p.named && p.name == folded)
            .map(|p| p.api)
    }

    // --- connection rendezvous --------------------------------------------

    /// Create a (named or unnamed) port under `api`; returns its handle. Named
    /// ports are idempotent (re-create returns the existing handle).
    pub fn create_port(&mut self, name: &[u16], api: PortApi) -> u64 {
        let name = fold_name(name);
        let named = !name.is_empty();
        if named {
            if let Some(p) = self.ports.iter().find(|p| p.name == name) {
                return p.handle;
            }
        }
        let handle = self.alloc_handle();
        self.ports.push(Port {
            handle,
            name,
            named,
            api,
            pending: Vec::new(),
            reply_connection: None,
        });
        handle
    }

    /// Connect to a named port as `client_api`, carrying the subsystem type and
    /// an opaque connection-info blob. The blob is stored (capped at
    /// [`MAX_CONNINFO`]) and passed through to the acceptor unchanged.
    pub fn connect(
        &mut self,
        name: &[u16],
        client_api: PortApi,
        subsystem_type: u32,
        conn_info: &[u8],
    ) -> Result<ConnectOutcome, NtStatus> {
        let name = fold_name(name);
        let port_idx = self
            .ports
            .iter()
            .position(|p| p.named && p.name == name)
            .ok_or(NtStatus::OBJECT_NAME_NOT_FOUND)?;
        let server_api = self.ports[port_idx].api;

        let id = self.next_conn_id;
        self.next_conn_id += 1;

        let stored: Vec<u8> = conn_info.iter().take(MAX_CONNINFO).copied().collect();

        match self.accept_policy {
            AcceptPolicy::AutoAccept => {
                let client_handle = self.alloc_handle();
                self.connections.push(Connection::new(
                    id,
                    name,
                    subsystem_type,
                    stored,
                    ConnState::Connected,
                    client_api,
                    server_api,
                    client_handle,
                ));
                Ok(ConnectOutcome::Completed {
                    client_handle,
                    connection_id: id,
                })
            }
            AcceptPolicy::Manual => {
                self.ports[port_idx].pending.push(id);
                self.connections.push(Connection::new(
                    id,
                    name,
                    subsystem_type,
                    stored,
                    ConnState::Pending,
                    client_api,
                    server_api,
                    0,
                ));
                Ok(ConnectOutcome::Pending { connection_id: id })
            }
        }
    }

    /// Receive the next pending connection request on a server port.
    pub fn receive(&mut self, port_handle: u64) -> Result<ReceiveOutcome, NtStatus> {
        let port = self
            .ports
            .iter_mut()
            .find(|p| p.handle == port_handle)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        if port.pending.is_empty() {
            return Ok(ReceiveOutcome::WouldBlock);
        }
        let conn_id = port.pending.remove(0);
        if let Some(conn) = self.connections.iter_mut().find(|c| c.id == conn_id) {
            if conn.state == ConnState::Pending {
                conn.state = ConnState::Received;
            }
        }
        Ok(ReceiveOutcome::ConnectionRequest {
            connection_id: conn_id,
            msg_type: port_message_type::CONNECTION_REQUEST,
        })
    }

    /// Accept (or refuse) a pending connection. On accept, returns the server
    /// comm-port handle; on refuse, returns `0`.
    pub fn accept(
        &mut self,
        connection_id: u64,
        accept: bool,
        port_context: u64,
    ) -> Result<u64, NtStatus> {
        let next = self.next_handle;
        let conn = self
            .connections
            .iter_mut()
            .find(|c| c.id == connection_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if !accept {
            conn.state = ConnState::Refused;
            return Ok(0);
        }
        conn.state = ConnState::Accepted;
        conn.port_context = port_context;
        if conn.server_handle == 0 {
            conn.server_handle = next;
            self.next_handle += 1;
        }
        Ok(self.conn(connection_id).map(|c| c.server_handle).unwrap_or(0))
    }

    /// Complete an accepted connection (by connection id OR server comm-port
    /// handle), unblocking the connector. Returns `(client_handle, connection_id)`.
    pub fn complete(&mut self, id_or_server_handle: u64) -> Result<(u64, u64), NtStatus> {
        let next = self.next_handle;
        let conn = self
            .connections
            .iter_mut()
            .find(|c| c.id == id_or_server_handle || c.server_handle == id_or_server_handle)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        conn.state = ConnState::Connected;
        if conn.client_handle == 0 {
            conn.client_handle = next;
            self.next_handle += 1;
        }
        Ok((conn.client_handle, conn.id))
    }

    /// Close a port handle (idempotent). Does not tear down live connections.
    pub fn close_port(&mut self, port_handle: u64) {
        if let Some(pos) = self.ports.iter().position(|p| p.handle == port_handle) {
            self.ports.remove(pos);
        }
    }

    /// Disconnect a connection by id (marks it refused/closed). Idempotent.
    pub fn disconnect(&mut self, connection_id: u64) {
        if let Some(conn) = self.connections.iter_mut().find(|c| c.id == connection_id) {
            conn.state = ConnState::Refused;
        }
    }

    // --- message model ----------------------------------------------------

    /// Send a `PORT_MESSAGE` from the endpoint identified by `from_handle` (a
    /// client or server comm-port handle) to the peer, carrying `attrs`. The
    /// message is enqueued on the peer's inbox; [`receive_message`] pops it.
    ///
    /// [`receive_message`]: PortCore::receive_message
    pub fn send_message(
        &mut self,
        from_handle: u64,
        bytes: &[u8],
        attrs: MessageAttrs,
    ) -> Result<(), NtStatus> {
        let mut msg = QueuedMessage {
            bytes: bytes.to_vec(),
            attrs,
            port_context: 0,
        };
        for conn in self.connections.iter_mut() {
            if conn.state != ConnState::Connected {
                continue;
            }
            if from_handle != 0 && conn.client_handle == from_handle {
                msg.port_context = conn.port_context;
                conn.server_inbox.push(msg);
                return Ok(());
            }
            if from_handle != 0 && conn.server_handle == from_handle {
                conn.client_inbox.push(msg);
                return Ok(());
            }
        }
        if let Some(port) = self.ports.iter_mut().find(|port| port.handle == from_handle) {
            let connection_id = port.reply_connection.take().ok_or(NtStatus::INVALID_HANDLE)?;
            let conn = self
                .connections
                .iter_mut()
                .find(|conn| conn.id == connection_id && conn.state == ConnState::Connected)
                .ok_or(NtStatus::INVALID_HANDLE)?;
            conn.client_inbox.push(msg);
            return Ok(());
        }
        Err(NtStatus::INVALID_HANDLE)
    }

    /// Receive the next `PORT_MESSAGE` for the endpoint identified by `handle`.
    /// Returns `Ok(None)` when the inbox is empty (would-block).
    pub fn receive_message(&mut self, handle: u64) -> Result<Option<QueuedMessage>, NtStatus> {
        for conn in self.connections.iter_mut() {
            if handle != 0 && conn.client_handle == handle {
                return Ok(if conn.client_inbox.is_empty() {
                    None
                } else {
                    Some(conn.client_inbox.remove(0))
                });
            }
            if handle != 0 && conn.server_handle == handle {
                return Ok(if conn.server_inbox.is_empty() {
                    None
                } else {
                    Some(conn.server_inbox.remove(0))
                });
            }
        }
        if let Some(port_index) = self.ports.iter().position(|port| port.handle == handle) {
            let connection_index = self.connections.iter().position(|conn| {
                conn.state == ConnState::Connected
                    && conn.server_api == self.ports[port_index].api
                    && conn.port_name == self.ports[port_index].name
                    && !conn.server_inbox.is_empty()
            });
            if let Some(connection_index) = connection_index {
                let connection_id = self.connections[connection_index].id;
                let message = self.connections[connection_index].server_inbox.remove(0);
                self.ports[port_index].reply_connection = Some(connection_id);
                return Ok(Some(message));
            }
            return Ok(None);
        }
        Err(NtStatus::INVALID_HANDLE)
    }

    // --- internals --------------------------------------------------------

    fn conn(&self, id: u64) -> Option<&Connection> {
        self.connections.iter().find(|c| c.id == id)
    }

    fn alloc_handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }
}

impl Connection {
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: u64,
        port_name: Vec<u16>,
        subsystem_type: u32,
        conn_info: Vec<u8>,
        state: ConnState,
        client_api: PortApi,
        server_api: PortApi,
        client_handle: u64,
    ) -> Self {
        Self {
            id,
            port_name,
            subsystem_type,
            conn_info,
            state,
            client_api,
            server_api,
            client_handle,
            server_handle: 0,
            port_context: 0,
            client_inbox: Vec::new(),
            server_inbox: Vec::new(),
        }
    }
}

/// Fold a UTF-16 name to lowercase ASCII for case-insensitive matching (NT
/// object names fold ASCII).
fn fold_name(name: &[u16]) -> Vec<u16> {
    name.iter().map(|&u| fold(u)).collect()
}

#[inline]
fn fold(u: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&u) {
        u + 0x20
    } else {
        u
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn auto_accept_completes_synchronously() {
        let mut core = PortCore::new();
        core.create_port(&utf16("\\SmApiPort"), PortApi::Lpc);
        let out = core
            .connect(&utf16("\\SmApiPort"), PortApi::Lpc, 2, &[])
            .unwrap();
        match out {
            ConnectOutcome::Completed {
                client_handle,
                connection_id,
            } => {
                assert_ne!(client_handle, 0);
                assert_eq!(core.connection_state(connection_id), Some(ConnState::Connected));
            }
            _ => panic!("auto-accept must complete"),
        }
    }

    #[test]
    fn create_named_is_idempotent() {
        let mut core = PortCore::new();
        let a = core.create_port(&utf16("\\SmApiPort"), PortApi::Lpc);
        let b = core.create_port(&utf16("\\smapiport"), PortApi::Lpc);
        assert_eq!(a, b, "named ports fold + dedup");
    }

    #[test]
    fn connect_unknown_port_not_found() {
        let mut core = PortCore::new();
        let e = core
            .connect(&utf16("\\Nope"), PortApi::Lpc, 0, &[])
            .unwrap_err();
        assert_eq!(e, NtStatus::OBJECT_NAME_NOT_FOUND);
    }

    #[test]
    fn manual_rendezvous_receive_accept_complete() {
        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let ph = core.create_port(&utf16("\\SmApiPort"), PortApi::Lpc);
        let cid = match core
            .connect(&utf16("\\SmApiPort"), PortApi::Lpc, 2, &[])
            .unwrap()
        {
            ConnectOutcome::Pending { connection_id } => connection_id,
            _ => panic!("manual must be pending"),
        };
        assert_eq!(core.connection_state(cid), Some(ConnState::Pending));
        match core.receive(ph).unwrap() {
            ReceiveOutcome::ConnectionRequest {
                connection_id,
                msg_type,
            } => {
                assert_eq!(connection_id, cid);
                assert_eq!(msg_type, port_message_type::CONNECTION_REQUEST);
            }
            _ => panic!("expected a connection request"),
        }
        let sh = core.accept(cid, true, 0xC0DE).unwrap();
        assert_ne!(sh, 0);
        let (ch, done) = core.complete(cid).unwrap();
        assert_eq!(done, cid);
        assert_ne!(ch, 0);
        assert_eq!(core.connection_state(cid), Some(ConnState::Connected));
    }

    #[test]
    fn conninfo_passthrough() {
        let mut core = PortCore::new();
        core.create_port(&utf16("\\P"), PortApi::Lpc);
        let blob = [1u8, 2, 3, 4, 5];
        let out = core
            .connect(&utf16("\\P"), PortApi::Lpc, 7, &blob)
            .unwrap();
        let cid = match out {
            ConnectOutcome::Completed { connection_id, .. } => connection_id,
            ConnectOutcome::Pending { connection_id } => connection_id,
        };
        assert_eq!(core.connection_info(cid), Some(&blob[..]));
        assert_eq!(core.connection_subsystem_type(cid), Some(7));
    }

    #[test]
    fn message_roundtrip_each_way() {
        // Manual rendezvous gives a Connected connection with BOTH comm-port
        // handles allocated — the precondition for the message plane.
        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let ph = core.create_port(&utf16("\\P"), PortApi::Lpc);
        let cid = match core.connect(&utf16("\\P"), PortApi::Lpc, 0, &[]).unwrap() {
            ConnectOutcome::Pending { connection_id } => connection_id,
            _ => unreachable!(),
        };
        core.receive(ph).unwrap();
        let sh = core.accept(cid, true, 0).unwrap();
        let (ch, _) = core.complete(cid).unwrap();
        // client -> server
        core.send_message(ch, b"ping", MessageAttrs::default()).unwrap();
        let got = core.receive_message(sh).unwrap().unwrap();
        assert_eq!(got.bytes, b"ping");
        // server -> client
        core.send_message(sh, b"pong", MessageAttrs::default()).unwrap();
        let got = core.receive_message(ch).unwrap().unwrap();
        assert_eq!(got.bytes, b"pong");
        // drained
        assert!(core.receive_message(ch).unwrap().is_none());
    }

    #[test]
    fn listen_port_reply_routes_to_the_requesting_connection() {
        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let ph = core.create_port(&utf16("\\P"), PortApi::Lpc);
        let mut clients = [0u64; 2];
        for (index, context) in [0x1111, 0x2222].into_iter().enumerate() {
            let cid = match core.connect(&utf16("\\P"), PortApi::Lpc, 0, &[]).unwrap() {
                ConnectOutcome::Pending { connection_id } => connection_id,
                _ => unreachable!(),
            };
            core.receive(ph).unwrap();
            core.accept(cid, true, context).unwrap();
            clients[index] = core.complete(cid).unwrap().0;
        }

        core.send_message(clients[1], b"second", MessageAttrs::default())
            .unwrap();
        let request = core.receive_message(ph).unwrap().unwrap();
        assert_eq!(request.bytes, b"second");
        assert_eq!(request.attrs.context, None);
        assert_eq!(request.port_context, 0x2222);
        core.send_message(ph, b"reply", MessageAttrs::default()).unwrap();

        assert!(core.receive_message(clients[0]).unwrap().is_none());
        assert_eq!(
            core.receive_message(clients[1]).unwrap().unwrap().bytes,
            b"reply"
        );
    }
}
