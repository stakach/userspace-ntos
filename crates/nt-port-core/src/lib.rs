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
//! In the live executive the isolated broker owns connection identity and the
//! queued message plane. Typed executive continuations retain blocked native
//! callers while real user-mode server threads receive and reply through these
//! queues. Every queued message therefore carries immutable source-connection
//! provenance; no adapter may infer a peer from a port-wide cursor.

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
    pub const EXCEPTION: u16 = 7;
    pub const DEBUG_EVENT: u16 = 8;
    pub const ERROR_EVENT: u16 = 9;
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

/// Which endpoint a live port-core handle names.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PortHandleEndpoint {
    /// A named listen port created by `NtCreatePort`.
    ListenPort,
    /// The connector's communication-port handle.
    ClientCommPort,
    /// The server's accepted communication-port handle.
    ServerCommPort,
}

/// Kernel-supplied identity of the thread that initiated a port connection.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientId {
    pub process: u64,
    pub thread: u64,
}

/// Limits fixed by the server when it creates a connection port and inherited by every
/// communication-port endpoint accepted from it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortLimits {
    pub max_connection_info: u32,
    pub max_message: u32,
    pub max_pool_usage: u32,
}

impl Default for PortLimits {
    fn default() -> Self {
        Self {
            max_connection_info: MAX_CONNINFO as u32,
            max_message: DEFAULT_MAX_MESSAGE_LENGTH,
            max_pool_usage: 0,
        }
    }
}

/// Security quality of service captured when a client connects. This is connection state, not a
/// caller pointer: a later impersonation request must use the values captured at connect time.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectionSecurity {
    pub impersonation_level: u32,
    pub dynamic_tracking: bool,
    pub effective_only: bool,
}

/// A borrowed description of a live port-core handle.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortHandleInfo<'a> {
    pub endpoint: PortHandleEndpoint,
    /// API surface spoken by this endpoint. Cross-API connections may report different values for
    /// their client and server communication handles.
    pub api: PortApi,
    /// Zero for listen ports; the broker connection id for communication ports.
    pub connection_id: u64,
    /// `None` for listen ports.
    pub state: Option<ConnState>,
    /// Folded target/listen port name.
    pub port_name: &'a [u16],
    /// Kernel-supplied identity of the process/thread that created the named listen port.
    pub server_id: ClientId,
    /// Kernel-supplied connector identity. Listen ports have no connector.
    pub client_id: Option<ClientId>,
    /// Limits inherited from the named connection port.
    pub limits: PortLimits,
    /// Captured connector QoS. Listen ports have no connector and therefore report `None`.
    pub security: Option<ConnectionSecurity>,
}

/// The outcome of [`PortCore::connect`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// The connect completed synchronously (`AutoAccept`).
    Completed {
        client_handle: u64,
        connection_id: u64,
    },
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

/// Immutable broker provenance attached when a message enters a connection queue.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MessageProvenance {
    pub connection_id: u64,
    /// The connector identity for this connection. Server-side receives use it as the native
    /// `CLIENT_ID`; client-side receives retain it for correlation with the same transaction.
    pub client: ClientId,
}

/// A queued `PORT_MESSAGE`: the framed bytes, API-neutral attributes, and exact source connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueuedMessage {
    pub bytes: Vec<u8>,
    pub attrs: MessageAttrs,
    pub provenance: MessageProvenance,
    /// Accepted connection PortContext returned to classic LPC server receives.
    pub port_context: u64,
    /// Kernel-authored identity for a synchronous client request. Attribute-only ALPC traffic and
    /// kernel datagrams carry `None`.
    pub request_identity: Option<MessageIdentity>,
}

/// Broker-owned storage for a queued message. The charge is fixed when the message enters the
/// broker so later queue capacity changes cannot silently alter the port's accounted usage.
struct StoredMessage {
    message: QueuedMessage,
    pool_charge: u32,
}

/// Identity stamped into a synchronous request by the trusted API adapter. The connection id is
/// derived by the core from the client communication handle and is never supplied by user mode.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MessageIdentity {
    pub client: ClientId,
    pub message_id: u32,
}

#[derive(Copy, Clone)]
struct DeliveredRequest {
    identity: MessageIdentity,
    pool_charge: u32,
}

/// Broker-owned security and connection identity for one request currently held by a server.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DeliveredRequestInfo {
    pub connection_id: u64,
    pub client: ClientId,
    pub security: ConnectionSecurity,
}

/// Base for allocated port / comm-port handles (a distinct, recognizable range —
/// ASCII `"LP"` — so a port handle never looks like a fake object handle).
const PORT_HANDLE_BASE: u64 = 0x0000_4C50_0000_0001;

/// The maximum length of a stored connection-info blob (guards against an
/// oversized connect payload growing core state without bound).
pub const MAX_CONNINFO: usize = 512;
/// Default used by API-neutral test helpers. Native adapters always provide their caller's limit.
pub const DEFAULT_MAX_MESSAGE_LENGTH: u32 = 512;

const POOL_ALLOCATION_ALIGNMENT: usize = 16;

fn aligned_pool_charge(bytes: usize) -> Result<u32, NtStatus> {
    let aligned = bytes
        .checked_add(POOL_ALLOCATION_ALIGNMENT - 1)
        .map(|value| value & !(POOL_ALLOCATION_ALIGNMENT - 1))
        .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
    u32::try_from(aligned).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)
}

fn queued_message_pool_charge(bytes: usize, attrs: &MessageAttrs) -> Result<u32, NtStatus> {
    let handle_bytes = attrs
        .handles
        .len()
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
    core::mem::size_of::<QueuedMessage>()
        .checked_add(bytes)
        .and_then(|bytes| bytes.checked_add(handle_bytes))
        .ok_or(NtStatus::INSUFFICIENT_RESOURCES)
        .and_then(aligned_pool_charge)
}

fn delivered_request_pool_charge() -> u32 {
    aligned_pool_charge(core::mem::size_of::<DeliveredRequest>())
        .expect("a fixed broker request record fits in ULONG accounting")
}

struct Port {
    object_id: u64,
    handle: u64,
    user_open: bool,
    /// Folded (lowercase) UTF-16 name; empty = unnamed communication port.
    name: Vec<u16>,
    named: bool,
    api: PortApi,
    owner: ClientId,
    limits: PortLimits,
    pool_account: usize,
    /// Connection ids awaiting a receiver (Manual-policy FIFO).
    pending: Vec<u64>,
}

/// A kernel reference to a connection port plus its direct synchronous message plane. NT uses a
/// referenced connection-port object for facilities such as the default hard-error port: no user
/// connection handshake is created, but server receive threads drain the typed request from the
/// ordinary connection port and reply by its broker-authored identity.
struct KernelPortEndpoint {
    handle: u64,
    port_object_id: u64,
    server_inbox: Vec<StoredMessage>,
    client_inbox: Vec<StoredMessage>,
    delivered_requests: Vec<DeliveredRequest>,
}

/// A kernel reference to one exact client communication-port object. Unlike a user handle this
/// endpoint survives handle-table teardown; synchronous requests owned by it are identified
/// explicitly so releasing one reference cannot consume another reference's traffic.
struct KernelCommunicationEndpoint {
    handle: u64,
    connection_id: u64,
    outstanding_requests: Vec<MessageIdentity>,
}

struct Connection {
    id: u64,
    /// Folded name of the server port connected to.
    port_name: Vec<u16>,
    subsystem_type: u32,
    client_id: ClientId,
    server_id: ClientId,
    limits: PortLimits,
    pool_account: usize,
    security: ConnectionSecurity,
    /// Opaque connection-info blob from the connector (SB_CONNECTION_INFO for an
    /// LPC connector, the ALPC ConnectionInformation blob for an ALPC connector).
    /// Passed through byte-for-byte to the acceptor — the bridge connection-info
    /// mapping.
    conn_info: Vec<u8>,
    /// Connection-information returned to the connector after the server accepts the request.
    /// This starts as an exact copy of the request and is replaced when the acceptor commits a
    /// mutated connection message.
    response_info: Vec<u8>,
    state: ConnState,
    client_api: PortApi,
    server_api: PortApi,
    /// Client-side comm-port handle (returned to the connector on complete).
    client_handle: u64,
    client_open: bool,
    client_kernel_refs: u32,
    /// Server-side comm-port handle (from accept).
    server_handle: u64,
    server_open: bool,
    port_context: u64,
    /// Messages destined FOR the client (sent BY the server).
    client_inbox: Vec<StoredMessage>,
    /// Messages destined FOR the server (sent BY the client).
    server_inbox: Vec<StoredMessage>,
    /// Requests actually delivered to a server thread and still awaiting a matching reply.
    delivered_requests: Vec<DeliveredRequest>,
}

struct PoolAccount {
    limit: u32,
    usage: u32,
}

/// The unified port core: a port namespace + connection rendezvous + message
/// model, driven identically by the LPC and ALPC adapters.
pub struct PortCore {
    ports: Vec<Port>,
    connections: Vec<Connection>,
    kernel_endpoints: Vec<KernelPortEndpoint>,
    kernel_communication_endpoints: Vec<KernelCommunicationEndpoint>,
    pool_accounts: Vec<PoolAccount>,
    next_handle: u64,
    next_port_object_id: u64,
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
            kernel_endpoints: Vec::new(),
            kernel_communication_endpoints: Vec::new(),
            pool_accounts: Vec::new(),
            next_handle: PORT_HANDLE_BASE,
            next_port_object_id: 1,
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

    /// The kernel-supplied identity of the connecting thread.
    pub fn connection_client_id(&self, id: u64) -> Option<ClientId> {
        self.conn(id).map(|c| c.client_id)
    }

    /// The folded name of the port a connection targets.
    pub fn connection_port_name(&self, id: u64) -> Option<&[u16]> {
        self.conn(id).map(|c| c.port_name.as_slice())
    }

    /// Limits inherited by a connection from its named server port.
    pub fn connection_limits(&self, id: u64) -> Option<PortLimits> {
        self.conn(id).map(|c| c.limits)
    }

    /// Current broker allocation charge against the listen port inherited by this connection.
    pub fn connection_pool_usage(&self, id: u64) -> Option<u32> {
        let account = self.conn(id)?.pool_account;
        self.pool_accounts.get(account).map(|account| account.usage)
    }

    /// Security quality of service captured when the connection was initiated.
    pub fn connection_security(&self, id: u64) -> Option<ConnectionSecurity> {
        self.conn(id).map(|c| c.security)
    }

    /// The opaque connection-info blob (the bridge connection-info passthrough).
    pub fn connection_info(&self, id: u64) -> Option<&[u8]> {
        self.conn(id).map(|c| c.conn_info.as_slice())
    }

    /// The server-approved connection-information returned when the connection completes.
    pub fn connection_response_info(&self, id: u64) -> Option<&[u8]> {
        self.conn(id).map(|c| c.response_info.as_slice())
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
            .find(|p| p.user_open && p.named && p.name == folded)
            .map(|p| p.api)
    }

    /// Resolve a port-core handle to the live listen/communication endpoint it names.
    pub fn handle_info(&self, handle: u64) -> Option<PortHandleInfo<'_>> {
        if handle == 0 {
            return None;
        }
        if let Some(port) = self
            .ports
            .iter()
            .find(|port| port.user_open && port.handle == handle)
        {
            return Some(PortHandleInfo {
                endpoint: PortHandleEndpoint::ListenPort,
                api: port.api,
                connection_id: 0,
                state: None,
                port_name: port.name.as_slice(),
                server_id: port.owner,
                client_id: None,
                limits: port.limits,
                security: None,
            });
        }
        self.connections.iter().find_map(|conn| {
            if conn.client_open && conn.client_handle == handle {
                Some(PortHandleInfo {
                    endpoint: PortHandleEndpoint::ClientCommPort,
                    api: conn.client_api,
                    connection_id: conn.id,
                    state: Some(conn.state),
                    port_name: conn.port_name.as_slice(),
                    server_id: conn.server_id,
                    client_id: Some(conn.client_id),
                    limits: conn.limits,
                    security: Some(conn.security),
                })
            } else if conn.server_open && conn.server_handle == handle {
                Some(PortHandleInfo {
                    endpoint: PortHandleEndpoint::ServerCommPort,
                    api: conn.server_api,
                    connection_id: conn.id,
                    state: Some(conn.state),
                    port_name: conn.port_name.as_slice(),
                    server_id: conn.server_id,
                    client_id: Some(conn.client_id),
                    limits: conn.limits,
                    security: Some(conn.security),
                })
            } else {
                None
            }
        })
    }

    // --- connection rendezvous --------------------------------------------

    /// Create a (named or unnamed) port under `api`; returns its handle. Named
    /// ports are idempotent (re-create returns the existing handle).
    pub fn create_port(&mut self, name: &[u16], api: PortApi) -> u64 {
        self.create_port_with_owner(name, api, ClientId::default())
    }

    /// Create a port while preserving the kernel-supplied identity of its owning server.
    pub fn create_port_with_owner(&mut self, name: &[u16], api: PortApi, owner: ClientId) -> u64 {
        self.create_port_with_owner_and_limits(name, api, owner, PortLimits::default())
            .expect("default port limits are valid")
    }

    /// Create a port with explicit server limits.
    pub fn create_port_with_limits(
        &mut self,
        name: &[u16],
        api: PortApi,
        limits: PortLimits,
    ) -> Result<u64, NtStatus> {
        self.create_port_with_owner_and_limits(name, api, ClientId::default(), limits)
    }

    /// Create a port while preserving both its kernel-supplied owner and native limits.
    pub fn create_port_with_owner_and_limits(
        &mut self,
        name: &[u16],
        api: PortApi,
        owner: ClientId,
        limits: PortLimits,
    ) -> Result<u64, NtStatus> {
        if limits.max_connection_info as usize > MAX_CONNINFO
            || limits.max_message > u16::MAX as u32
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let name = fold_name(name);
        let named = !name.is_empty();
        if named {
            if let Some(port_index) = self.ports.iter().position(|port| port.name == name) {
                if self.ports[port_index].user_open {
                    return Ok(self.ports[port_index].handle);
                }
                return Err(NtStatus::OBJECT_NAME_COLLISION);
            }
        }
        let handle = self.alloc_handle();
        let object_id = self.next_port_object_id;
        self.next_port_object_id += 1;
        let pool_account = self.pool_accounts.len();
        self.pool_accounts.push(PoolAccount {
            limit: limits.max_pool_usage,
            usage: 0,
        });
        self.ports.push(Port {
            object_id,
            handle,
            user_open: true,
            name,
            named,
            api,
            owner,
            limits,
            pool_account,
            pending: Vec::new(),
        });
        Ok(handle)
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
        self.connect_with_client_id(
            name,
            client_api,
            subsystem_type,
            conn_info,
            ClientId::default(),
        )
    }

    /// Connect with the kernel-supplied process/thread identity that must appear in the server's
    /// `LPC_CONNECTION_REQUEST` header.
    pub fn connect_with_client_id(
        &mut self,
        name: &[u16],
        client_api: PortApi,
        subsystem_type: u32,
        conn_info: &[u8],
        client_id: ClientId,
    ) -> Result<ConnectOutcome, NtStatus> {
        self.connect_with_client_id_and_security(
            name,
            client_api,
            subsystem_type,
            conn_info,
            client_id,
            ConnectionSecurity::default(),
        )
    }

    /// Connect while preserving the caller identity and QoS already captured by the kernel.
    pub fn connect_with_client_id_and_security(
        &mut self,
        name: &[u16],
        client_api: PortApi,
        subsystem_type: u32,
        conn_info: &[u8],
        client_id: ClientId,
        security: ConnectionSecurity,
    ) -> Result<ConnectOutcome, NtStatus> {
        let name = fold_name(name);
        let port_idx = self
            .ports
            .iter()
            .position(|p| p.user_open && p.named && p.name == name)
            .ok_or(NtStatus::OBJECT_NAME_NOT_FOUND)?;
        let server_api = self.ports[port_idx].api;
        let server_id = self.ports[port_idx].owner;
        let limits = self.ports[port_idx].limits;
        let pool_account = self.ports[port_idx].pool_account;

        let id = self.next_conn_id;
        self.next_conn_id += 1;

        let stored: Vec<u8> = conn_info
            .iter()
            .take(limits.max_connection_info as usize)
            .copied()
            .collect();

        match self.accept_policy {
            AcceptPolicy::AutoAccept => {
                let client_handle = self.alloc_handle();
                self.connections.push(Connection::new(
                    id,
                    name,
                    subsystem_type,
                    client_id,
                    server_id,
                    limits,
                    pool_account,
                    security,
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
                    client_id,
                    server_id,
                    limits,
                    pool_account,
                    security,
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
        if self.connections.iter().any(|connection| {
            port_handle != 0
                && connection.server_open
                && connection.server_handle == port_handle
                && connection.server_api == PortApi::Alpc
        }) {
            return Ok(ReceiveOutcome::WouldBlock);
        }
        let port_index = self
            .ports
            .iter()
            .position(|port| port.user_open && port.handle == port_handle)
            .or_else(|| self.connection_port_index_for_server_handle(port_handle))
            .ok_or(NtStatus::INVALID_HANDLE)?;
        let port = &mut self.ports[port_index];
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
        self.accept_inner(connection_id, accept, port_context, None)
    }

    /// Accept (or refuse) a pending connection and commit the connection-information bytes
    /// authored by the server. Those exact bytes are returned to the connector on complete.
    pub fn accept_with_connection_info(
        &mut self,
        connection_id: u64,
        accept: bool,
        port_context: u64,
        response_info: &[u8],
    ) -> Result<u64, NtStatus> {
        let connection = self
            .conn(connection_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        // NT returns the server-authored bytes through the connector's original connection
        // message. The acceptor may shorten that payload, but it cannot grow the allocation.
        if response_info.len() > connection.conn_info.len() {
            return Err(NtStatus::BUFFER_TOO_SMALL);
        }
        self.accept_inner(connection_id, accept, port_context, Some(response_info))
    }

    fn accept_inner(
        &mut self,
        connection_id: u64,
        accept: bool,
        port_context: u64,
        response_info: Option<&[u8]>,
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
        if let Some(response_info) = response_info {
            conn.response_info.clear();
            conn.response_info.extend_from_slice(response_info);
        }
        if conn.server_handle == 0 {
            conn.server_handle = next;
            self.next_handle += 1;
        }
        conn.server_open = true;
        Ok(self
            .conn(connection_id)
            .map(|c| c.server_handle)
            .unwrap_or(0))
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
        conn.client_open = true;
        Ok((conn.client_handle, conn.id))
    }

    /// Close a listen or communication-port handle. Communication endpoints own independent
    /// references: closing the server endpoint disconnects future traffic but does not discard a
    /// reply that was already committed to the still-open client endpoint.
    pub fn close_port(&mut self, port_handle: u64) {
        if let Some(pos) = self
            .ports
            .iter()
            .position(|port| port.user_open && port.handle == port_handle)
        {
            self.ports[pos].user_open = false;
            let object_id = self.ports[pos].object_id;
            if !self
                .kernel_endpoints
                .iter()
                .any(|endpoint| endpoint.port_object_id == object_id)
            {
                self.ports.remove(pos);
            }
            return;
        }
        if let Some(connection_index) = self.connections.iter().position(|connection| {
            port_handle != 0 && connection.client_open && connection.client_handle == port_handle
        }) {
            self.connections[connection_index].client_open = false;
            if self.connections[connection_index].client_kernel_refs == 0 {
                self.release_connection_storage(connection_index, true, true, true);
                self.connections[connection_index].state = ConnState::Refused;
            }
            return;
        }
        if let Some(connection_index) = self.connections.iter().position(|connection| {
            port_handle != 0 && connection.server_open && connection.server_handle == port_handle
        }) {
            self.release_connection_storage(connection_index, false, true, true);
            let connection = &mut self.connections[connection_index];
            connection.server_open = false;
            connection.state = ConnState::Refused;
        }
    }

    /// Retain a live connection-port object for a kernel facility and return a private endpoint
    /// handle. Closing the registering user handle no longer destroys the object; releasing this
    /// endpoint drops the final kernel reference and all messages owned by it.
    pub fn retain_connection_port(&mut self, port_handle: u64) -> Result<u64, NtStatus> {
        let port_object_id = self
            .ports
            .iter()
            .find(|port| port.user_open && port.handle == port_handle)
            .map(|port| port.object_id)
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        let handle = self.alloc_handle();
        self.kernel_endpoints.push(KernelPortEndpoint {
            handle,
            port_object_id,
            server_inbox: Vec::new(),
            client_inbox: Vec::new(),
            delivered_requests: Vec::new(),
        });
        Ok(handle)
    }

    /// Release one exact kernel endpoint. This is idempotence-sensitive: a stale or duplicate
    /// release fails and can never release another retained connection-port object.
    pub fn release_connection_port(&mut self, endpoint_handle: u64) -> Result<(), NtStatus> {
        let endpoint_index = self
            .kernel_endpoints
            .iter()
            .position(|endpoint| endpoint.handle == endpoint_handle)
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        let port_object_id = self.kernel_endpoints[endpoint_index].port_object_id;
        let port_index = self
            .ports
            .iter()
            .position(|port| port.object_id == port_object_id)
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        let account = self.ports[port_index].pool_account;
        let released_charge = self.kernel_endpoints[endpoint_index]
            .server_inbox
            .iter()
            .chain(self.kernel_endpoints[endpoint_index].client_inbox.iter())
            .map(|message| message.pool_charge)
            .chain(
                self.kernel_endpoints[endpoint_index]
                    .delivered_requests
                    .iter()
                    .map(|request| request.pool_charge),
            )
            .try_fold(0u32, |total, charge| total.checked_add(charge))
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        self.replace_pool_charge(account, released_charge, 0)?;
        self.kernel_endpoints.remove(endpoint_index);
        if !self.ports[port_index].user_open
            && !self
                .kernel_endpoints
                .iter()
                .any(|other| other.port_object_id == port_object_id)
        {
            self.ports.remove(port_index);
        }
        Ok(())
    }

    /// Retain one live client communication-port object for a kernel owner and return a private
    /// endpoint handle. The reference is bound to the exact connection, not to the caller's user
    /// handle value, and therefore survives closing that handle.
    pub fn retain_communication_port(&mut self, port_handle: u64) -> Result<u64, NtStatus> {
        let connection_index = self
            .connections
            .iter()
            .position(|connection| {
                connection.state == ConnState::Connected
                    && connection.client_open
                    && connection.server_open
                    && port_handle != 0
                    && connection.client_handle == port_handle
            })
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        let refs = self.connections[connection_index]
            .client_kernel_refs
            .checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        let connection_id = self.connections[connection_index].id;
        let handle = self.alloc_handle();
        self.connections[connection_index].client_kernel_refs = refs;
        self.kernel_communication_endpoints
            .push(KernelCommunicationEndpoint {
                handle,
                connection_id,
                outstanding_requests: Vec::new(),
            });
        Ok(handle)
    }

    /// Release one exact retained communication endpoint. Its in-flight requests are cancelled,
    /// while traffic belonging to other references on the same connection remains intact.
    pub fn release_communication_port(&mut self, endpoint_handle: u64) -> Result<(), NtStatus> {
        let endpoint_index = self
            .kernel_communication_endpoints
            .iter()
            .position(|endpoint| endpoint.handle == endpoint_handle)
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        let connection_id = self.kernel_communication_endpoints[endpoint_index].connection_id;
        let connection_index = self
            .connections
            .iter()
            .position(|connection| connection.id == connection_id)
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        let released_charge = {
            let identities = self.kernel_communication_endpoints[endpoint_index]
                .outstanding_requests
                .as_slice();
            let connection = &self.connections[connection_index];
            connection
                .server_inbox
                .iter()
                .chain(connection.client_inbox.iter())
                .filter(|message| {
                    message
                        .message
                        .request_identity
                        .is_some_and(|identity| identities.contains(&identity))
                })
                .map(|message| message.pool_charge)
                .chain(
                    connection
                        .delivered_requests
                        .iter()
                        .filter(|request| identities.contains(&request.identity))
                        .map(|request| request.pool_charge),
                )
                .try_fold(0u32, |total, charge| total.checked_add(charge))
                .ok_or(NtStatus::INVALID_PARAMETER)?
        };
        let account = self.connections[connection_index].pool_account;
        self.replace_pool_charge(account, released_charge, 0)?;
        let identities = self.kernel_communication_endpoints[endpoint_index]
            .outstanding_requests
            .as_slice();
        let connection = &mut self.connections[connection_index];
        connection.server_inbox.retain(|message| {
            !message
                .message
                .request_identity
                .is_some_and(|identity| identities.contains(&identity))
        });
        connection.client_inbox.retain(|message| {
            !message
                .message
                .request_identity
                .is_some_and(|identity| identities.contains(&identity))
        });
        connection
            .delivered_requests
            .retain(|request| !identities.contains(&request.identity));
        self.kernel_communication_endpoints.remove(endpoint_index);
        self.connections[connection_index].client_kernel_refs -= 1;
        if !self.connections[connection_index].client_open
            && self.connections[connection_index].client_kernel_refs == 0
        {
            self.release_connection_storage(connection_index, true, true, true);
            self.connections[connection_index].state = ConnState::Refused;
        }
        Ok(())
    }

    /// Retain the concrete LPC port object named by a user handle. Connection ports and client
    /// communication ports use different message planes internally, but the kernel object
    /// reference returned here is intentionally opaque to its owner.
    pub fn retain_port_object(&mut self, port_handle: u64) -> Result<u64, NtStatus> {
        if self
            .ports
            .iter()
            .any(|port| port.user_open && port.handle == port_handle)
        {
            self.retain_connection_port(port_handle)
        } else if self.connections.iter().any(|connection| {
            connection.state == ConnState::Connected
                && connection.client_open
                && connection.server_open
                && port_handle != 0
                && connection.client_handle == port_handle
        }) {
            self.retain_communication_port(port_handle)
        } else {
            Err(NtStatus::INVALID_PORT_HANDLE)
        }
    }

    /// Release one opaque retained port-object endpoint by its broker identity. Endpoint handles
    /// are allocated from one namespace, so this resolves one concrete object without probing or
    /// falling through to a different user handle.
    pub fn release_port_object(&mut self, endpoint_handle: u64) -> Result<(), NtStatus> {
        if self
            .kernel_endpoints
            .iter()
            .any(|endpoint| endpoint.handle == endpoint_handle)
        {
            self.release_connection_port(endpoint_handle)
        } else if self
            .kernel_communication_endpoints
            .iter()
            .any(|endpoint| endpoint.handle == endpoint_handle)
        {
            self.release_communication_port(endpoint_handle)
        } else {
            Err(NtStatus::INVALID_PORT_HANDLE)
        }
    }

    /// Disconnect a connection by id (marks it refused/closed). Idempotent.
    pub fn disconnect(&mut self, connection_id: u64) {
        if let Some(connection_index) = self.connections.iter().position(|c| c.id == connection_id)
        {
            self.release_connection_storage(connection_index, true, true, true);
            let conn = &mut self.connections[connection_index];
            conn.state = ConnState::Refused;
            conn.client_open = false;
            conn.server_open = false;
        }
    }

    // --- message model ----------------------------------------------------

    /// Send a `PORT_MESSAGE` from the communication endpoint identified by `from_handle` to its
    /// exact peer, carrying `attrs`. Listen-port handles are rejected: they identify a namespace
    /// endpoint, not one connection, and must never acquire implicit routing state from a receive.
    /// The message is enqueued on the peer's inbox; [`receive_message`] pops it.
    ///
    /// [`receive_message`]: PortCore::receive_message
    pub fn send_message(
        &mut self,
        from_handle: u64,
        bytes: &[u8],
        attrs: MessageAttrs,
    ) -> Result<(), NtStatus> {
        if let Some(connection_index) = self.connections.iter().position(|connection| {
            connection.state == ConnState::Connected
                && connection.server_open
                && from_handle != 0
                && ((connection.client_open && connection.client_handle == from_handle)
                    || (connection.client_live() && connection.server_handle == from_handle))
        }) {
            let connection = &self.connections[connection_index];
            if bytes.len() > connection.limits.max_message as usize {
                return Err(NtStatus::PORT_MESSAGE_TOO_LONG);
            }
            let from_client = connection.client_handle == from_handle;
            let account = connection.pool_account;
            let provenance = MessageProvenance {
                connection_id: connection.id,
                client: connection.client_id,
            };
            let port_context = from_client.then_some(connection.port_context).unwrap_or(0);
            let stored = self.allocate_stored_message(
                account,
                0,
                bytes,
                attrs,
                provenance,
                port_context,
                None,
            )?;
            if from_client {
                self.connections[connection_index].server_inbox.push(stored);
            } else {
                self.connections[connection_index].client_inbox.push(stored);
            }
            return Ok(());
        }
        Err(NtStatus::INVALID_PORT_HANDLE)
    }

    /// Queue a synchronous request from a client communication port. The adapter has already
    /// replaced the user header with `identity`; the core verifies that its process matches the
    /// connection owner and binds it to the connection selected by `from_handle`.
    pub fn send_request_message(
        &mut self,
        from_handle: u64,
        bytes: &[u8],
        attrs: MessageAttrs,
        identity: MessageIdentity,
    ) -> Result<(), NtStatus> {
        if identity.message_id == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let connection_index = self
            .connections
            .iter()
            .position(|connection| {
                connection.state == ConnState::Connected
                    && connection.client_open
                    && connection.server_open
                    && from_handle != 0
                    && connection.client_handle == from_handle
            })
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        let conn = &self.connections[connection_index];
        if identity.client.process != conn.client_id.process {
            return Err(NtStatus::REPLY_MESSAGE_MISMATCH);
        }
        if bytes.len() > conn.limits.max_message as usize {
            return Err(NtStatus::PORT_MESSAGE_TOO_LONG);
        }
        let account = conn.pool_account;
        let provenance = MessageProvenance {
            connection_id: conn.id,
            client: conn.client_id,
        };
        let port_context = conn.port_context;
        let stored = self.allocate_stored_message(
            account,
            0,
            bytes,
            attrs,
            provenance,
            port_context,
            Some(identity),
        )?;
        self.connections[connection_index].server_inbox.push(stored);
        Ok(())
    }

    /// Queue a synchronous request through a kernel-retained connection or communication port.
    /// Message-type normalization is owned by the protocol adapter. Raw user communication handles
    /// are deliberately not accepted here.
    pub fn send_kernel_request_message(
        &mut self,
        endpoint_handle: u64,
        bytes: &[u8],
        attrs: MessageAttrs,
        identity: MessageIdentity,
    ) -> Result<(), NtStatus> {
        if identity.message_id == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if let Some(endpoint_index) = self
            .kernel_endpoints
            .iter()
            .position(|endpoint| endpoint.handle == endpoint_handle)
        {
            let port = self
                .ports
                .iter()
                .find(|port| port.object_id == self.kernel_endpoints[endpoint_index].port_object_id)
                .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
            if bytes.len() > port.limits.max_message as usize {
                return Err(NtStatus::PORT_MESSAGE_TOO_LONG);
            }
            let stored = self.allocate_stored_message(
                port.pool_account,
                0,
                bytes,
                attrs,
                MessageProvenance {
                    connection_id: 0,
                    client: identity.client,
                },
                0,
                Some(identity),
            )?;
            self.kernel_endpoints[endpoint_index]
                .server_inbox
                .push(stored);
            return Ok(());
        }

        let endpoint_index = self
            .kernel_communication_endpoints
            .iter()
            .position(|endpoint| endpoint.handle == endpoint_handle)
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        if self.kernel_communication_endpoints[endpoint_index]
            .outstanding_requests
            .contains(&identity)
        {
            return Err(NtStatus::REPLY_MESSAGE_MISMATCH);
        }
        let connection_id = self.kernel_communication_endpoints[endpoint_index].connection_id;
        let connection_index = self
            .connections
            .iter()
            .position(|connection| {
                connection.id == connection_id
                    && connection.state == ConnState::Connected
                    && connection.client_kernel_refs != 0
                    && connection.server_open
            })
            .ok_or(NtStatus::PORT_DISCONNECTED)?;
        let connection = &self.connections[connection_index];
        if bytes.len() > connection.limits.max_message as usize {
            return Err(NtStatus::PORT_MESSAGE_TOO_LONG);
        }
        let stored = self.allocate_stored_message(
            connection.pool_account,
            0,
            bytes,
            attrs,
            MessageProvenance {
                connection_id,
                client: identity.client,
            },
            connection.port_context,
            Some(identity),
        )?;
        self.connections[connection_index].server_inbox.push(stored);
        self.kernel_communication_endpoints[endpoint_index]
            .outstanding_requests
            .push(identity);
        Ok(())
    }

    /// Queue a datagram through a kernel-retained connection or communication port. Unlike a
    /// synchronous request, this carries no reply identity and therefore owns no outstanding-request
    /// entry on the retained reference.
    pub fn send_retained_message(
        &mut self,
        endpoint_handle: u64,
        bytes: &[u8],
        attrs: MessageAttrs,
        client: ClientId,
    ) -> Result<(), NtStatus> {
        if let Some(endpoint_index) = self
            .kernel_endpoints
            .iter()
            .position(|endpoint| endpoint.handle == endpoint_handle)
        {
            let port = self
                .ports
                .iter()
                .find(|port| port.object_id == self.kernel_endpoints[endpoint_index].port_object_id)
                .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
            if bytes.len() > port.limits.max_message as usize {
                return Err(NtStatus::PORT_MESSAGE_TOO_LONG);
            }
            let stored = self.allocate_stored_message(
                port.pool_account,
                0,
                bytes,
                attrs,
                MessageProvenance {
                    connection_id: 0,
                    client,
                },
                0,
                None,
            )?;
            self.kernel_endpoints[endpoint_index]
                .server_inbox
                .push(stored);
            return Ok(());
        }

        let endpoint = self
            .kernel_communication_endpoints
            .iter()
            .find(|endpoint| endpoint.handle == endpoint_handle)
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        let connection_index = self
            .connections
            .iter()
            .position(|connection| {
                connection.id == endpoint.connection_id
                    && connection.state == ConnState::Connected
                    && connection.client_kernel_refs != 0
                    && connection.server_open
            })
            .ok_or(NtStatus::PORT_DISCONNECTED)?;
        let connection = &self.connections[connection_index];
        if bytes.len() > connection.limits.max_message as usize {
            return Err(NtStatus::PORT_MESSAGE_TOO_LONG);
        }
        let stored = self.allocate_stored_message(
            connection.pool_account,
            0,
            bytes,
            attrs,
            MessageProvenance {
                connection_id: connection.id,
                client,
            },
            connection.port_context,
            None,
        )?;
        self.connections[connection_index].server_inbox.push(stored);
        Ok(())
    }

    /// Receive only the reply for one kernel-authored synchronous request. Unrelated datagrams and
    /// replies remain queued, so concurrent waiters on one communication port cannot consume each
    /// other's completion.
    pub fn receive_reply_message(
        &mut self,
        from_handle: u64,
        identity: MessageIdentity,
    ) -> Result<Option<QueuedMessage>, NtStatus> {
        if identity.message_id == 0 {
            return Err(NtStatus::REPLY_MESSAGE_MISMATCH);
        }
        if let Some(endpoint_index) = self
            .kernel_endpoints
            .iter()
            .position(|endpoint| endpoint.handle == from_handle)
        {
            if let Some(message_index) = self.kernel_endpoints[endpoint_index]
                .client_inbox
                .iter()
                .position(|message| message.message.request_identity == Some(identity))
            {
                let stored = self.kernel_endpoints[endpoint_index]
                    .client_inbox
                    .remove(message_index);
                let account = self
                    .ports
                    .iter()
                    .find(|port| {
                        port.object_id == self.kernel_endpoints[endpoint_index].port_object_id
                    })
                    .map(|port| port.pool_account)
                    .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
                self.replace_pool_charge(account, stored.pool_charge, 0)?;
                return Ok(Some(stored.message));
            }
            return Ok(None);
        }
        if let Some(endpoint_index) = self
            .kernel_communication_endpoints
            .iter()
            .position(|endpoint| endpoint.handle == from_handle)
        {
            if !self.kernel_communication_endpoints[endpoint_index]
                .outstanding_requests
                .contains(&identity)
            {
                return Err(NtStatus::REPLY_MESSAGE_MISMATCH);
            }
            let connection_id = self.kernel_communication_endpoints[endpoint_index].connection_id;
            let connection_index = self
                .connections
                .iter()
                .position(|connection| connection.id == connection_id)
                .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
            if let Some(message_index) = self.connections[connection_index]
                .client_inbox
                .iter()
                .position(|message| message.message.request_identity == Some(identity))
            {
                let stored = self.connections[connection_index]
                    .client_inbox
                    .remove(message_index);
                let account = self.connections[connection_index].pool_account;
                self.replace_pool_charge(account, stored.pool_charge, 0)?;
                let request_index = self.kernel_communication_endpoints[endpoint_index]
                    .outstanding_requests
                    .iter()
                    .position(|request| *request == identity)
                    .expect("the retained endpoint owns the matched reply");
                self.kernel_communication_endpoints[endpoint_index]
                    .outstanding_requests
                    .remove(request_index);
                return Ok(Some(stored.message));
            }
            let connection = &self.connections[connection_index];
            return if connection.state == ConnState::Connected && connection.server_open {
                Ok(None)
            } else {
                Err(NtStatus::PORT_DISCONNECTED)
            };
        }
        let connection_index = self
            .connections
            .iter()
            .position(|connection| {
                connection.client_open
                    && from_handle != 0
                    && connection.client_handle == from_handle
            })
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        if self.connections[connection_index].client_id.process != identity.client.process {
            return Err(NtStatus::REPLY_MESSAGE_MISMATCH);
        }
        if let Some(message_index) = self.connections[connection_index]
            .client_inbox
            .iter()
            .position(|message| message.message.request_identity == Some(identity))
        {
            let stored = self.connections[connection_index]
                .client_inbox
                .remove(message_index);
            let account = self.connections[connection_index].pool_account;
            self.replace_pool_charge(account, stored.pool_charge, 0)
                .expect("dequeued broker reply was previously charged");
            return Ok(Some(stored.message));
        }
        let connection = &self.connections[connection_index];
        if connection.state == ConnState::Connected && connection.server_open {
            Ok(None)
        } else {
            Err(NtStatus::PORT_DISCONNECTED)
        }
    }

    /// Roll back one synchronous request when its kernel continuation cannot be retained. The
    /// request may still be queued, held by the server, or already answered; exactly that identity
    /// is removed without disturbing other traffic on the connection.
    pub fn cancel_request_message(
        &mut self,
        from_handle: u64,
        identity: MessageIdentity,
    ) -> Result<bool, NtStatus> {
        if identity.message_id == 0 {
            return Err(NtStatus::REPLY_MESSAGE_MISMATCH);
        }
        if let Some(endpoint_index) = self
            .kernel_endpoints
            .iter()
            .position(|endpoint| endpoint.handle == from_handle)
        {
            let removed_charge = {
                let endpoint = &mut self.kernel_endpoints[endpoint_index];
                if let Some(index) = endpoint
                    .server_inbox
                    .iter()
                    .position(|message| message.message.request_identity == Some(identity))
                {
                    Some(endpoint.server_inbox.remove(index).pool_charge)
                } else if let Some(index) = endpoint
                    .delivered_requests
                    .iter()
                    .position(|request| request.identity == identity)
                {
                    Some(endpoint.delivered_requests.remove(index).pool_charge)
                } else {
                    endpoint
                        .client_inbox
                        .iter()
                        .position(|message| message.message.request_identity == Some(identity))
                        .map(|index| endpoint.client_inbox.remove(index).pool_charge)
                }
            };
            if let Some(charge) = removed_charge {
                let account = self
                    .ports
                    .iter()
                    .find(|port| {
                        port.object_id == self.kernel_endpoints[endpoint_index].port_object_id
                    })
                    .map(|port| port.pool_account)
                    .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
                self.replace_pool_charge(account, charge, 0)?;
                return Ok(true);
            }
            return Ok(false);
        }
        if let Some(endpoint_index) = self
            .kernel_communication_endpoints
            .iter()
            .position(|endpoint| endpoint.handle == from_handle)
        {
            let Some(request_index) = self.kernel_communication_endpoints[endpoint_index]
                .outstanding_requests
                .iter()
                .position(|request| *request == identity)
            else {
                return Ok(false);
            };
            let connection_id = self.kernel_communication_endpoints[endpoint_index].connection_id;
            let connection_index = self
                .connections
                .iter()
                .position(|connection| connection.id == connection_id)
                .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
            let removed_charge = Self::remove_request_from_connection(
                &mut self.connections[connection_index],
                identity,
            );
            self.kernel_communication_endpoints[endpoint_index]
                .outstanding_requests
                .remove(request_index);
            if let Some(charge) = removed_charge {
                let account = self.connections[connection_index].pool_account;
                self.replace_pool_charge(account, charge, 0)?;
                return Ok(true);
            }
            return Ok(false);
        }
        let connection_index = self
            .connections
            .iter()
            .position(|connection| {
                connection.client_open
                    && from_handle != 0
                    && connection.client_handle == from_handle
            })
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        if self.connections[connection_index].client_id.process != identity.client.process {
            return Err(NtStatus::REPLY_MESSAGE_MISMATCH);
        }

        let removed_charge = {
            let connection = &mut self.connections[connection_index];
            if let Some(index) = connection
                .server_inbox
                .iter()
                .position(|message| message.message.request_identity == Some(identity))
            {
                Some(connection.server_inbox.remove(index).pool_charge)
            } else if let Some(index) = connection
                .delivered_requests
                .iter()
                .position(|request| request.identity == identity)
            {
                Some(connection.delivered_requests.remove(index).pool_charge)
            } else {
                connection
                    .client_inbox
                    .iter()
                    .position(|message| message.message.request_identity == Some(identity))
                    .map(|index| connection.client_inbox.remove(index).pool_charge)
            }
        };
        if let Some(charge) = removed_charge {
            let account = self.connections[connection_index].pool_account;
            self.replace_pool_charge(account, charge, 0)
                .expect("cancelled broker request was previously charged");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Send a reply only when its client/message identity names a request that this server endpoint
    /// actually received and has not already answered.
    pub fn send_reply_message(
        &mut self,
        from_handle: u64,
        bytes: &[u8],
        attrs: MessageAttrs,
        identity: MessageIdentity,
    ) -> Result<(), NtStatus> {
        if identity.message_id == 0 {
            return Err(NtStatus::REPLY_MESSAGE_MISMATCH);
        }
        if let Some(connection_index) = self.connections.iter().position(|connection| {
            connection.state == ConnState::Connected
                && connection.client_live()
                && connection.server_open
                && from_handle != 0
                && connection.server_handle == from_handle
        }) {
            let connection = &self.connections[connection_index];
            let delivered_index = connection
                .delivered_requests
                .iter()
                .position(|request| request.identity == identity)
                .ok_or(NtStatus::REPLY_MESSAGE_MISMATCH)?;
            if bytes.len() > connection.limits.max_message as usize {
                return Err(NtStatus::PORT_MESSAGE_TOO_LONG);
            }
            let old_charge = connection.delivered_requests[delivered_index].pool_charge;
            let account = connection.pool_account;
            let provenance = MessageProvenance {
                connection_id: connection.id,
                client: identity.client,
            };
            let stored = self.allocate_stored_message(
                account,
                old_charge,
                bytes,
                attrs,
                provenance,
                0,
                Some(identity),
            )?;
            let connection = &mut self.connections[connection_index];
            connection.delivered_requests.remove(delivered_index);
            connection.client_inbox.push(stored);
            return Ok(());
        }

        let port = self
            .ports
            .iter()
            .find(|port| port.user_open && port.handle == from_handle)
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        if let Some(endpoint_index) = self.kernel_endpoints.iter().position(|endpoint| {
            endpoint.port_object_id == port.object_id
                && endpoint
                    .delivered_requests
                    .iter()
                    .any(|request| request.identity == identity)
        }) {
            if bytes.len() > port.limits.max_message as usize {
                return Err(NtStatus::PORT_MESSAGE_TOO_LONG);
            }
            let delivered_index = self.kernel_endpoints[endpoint_index]
                .delivered_requests
                .iter()
                .position(|request| request.identity == identity)
                .expect("matching retained-port request was selected");
            let old_charge = self.kernel_endpoints[endpoint_index].delivered_requests
                [delivered_index]
                .pool_charge;
            let account = port.pool_account;
            let stored = self.allocate_stored_message(
                account,
                old_charge,
                bytes,
                attrs,
                MessageProvenance {
                    connection_id: 0,
                    client: identity.client,
                },
                0,
                Some(identity),
            )?;
            self.kernel_endpoints[endpoint_index]
                .delivered_requests
                .remove(delivered_index);
            self.kernel_endpoints[endpoint_index]
                .client_inbox
                .push(stored);
            return Ok(());
        }
        let connection_index = self
            .connections
            .iter()
            .position(|connection| {
                connection.state == ConnState::Connected
                    && connection.client_live()
                    && connection.server_open
                    && connection.server_api == port.api
                    && connection.port_name == port.name
                    && connection
                        .delivered_requests
                        .iter()
                        .any(|request| request.identity == identity)
            })
            .ok_or(NtStatus::REPLY_MESSAGE_MISMATCH)?;
        let connection = &self.connections[connection_index];
        if bytes.len() > connection.limits.max_message as usize {
            return Err(NtStatus::PORT_MESSAGE_TOO_LONG);
        }
        let delivered_index = connection
            .delivered_requests
            .iter()
            .position(|request| request.identity == identity)
            .expect("matching delivered request was selected");
        let old_charge = connection.delivered_requests[delivered_index].pool_charge;
        let account = connection.pool_account;
        let provenance = MessageProvenance {
            connection_id: connection.id,
            client: identity.client,
        };
        let stored = self.allocate_stored_message(
            account,
            old_charge,
            bytes,
            attrs,
            provenance,
            0,
            Some(identity),
        )?;
        let connection = &mut self.connections[connection_index];
        connection.delivered_requests.remove(delivered_index);
        connection.client_inbox.push(stored);
        Ok(())
    }

    /// Resolve one request currently held by a server. Client communication handles are rejected;
    /// a listen port may match any accepted connection created from it, while a server communication
    /// handle may match only its own connection.
    pub fn delivered_request(
        &self,
        port_handle: u64,
        identity: MessageIdentity,
    ) -> Result<DeliveredRequestInfo, NtStatus> {
        if identity.message_id == 0 {
            return Err(NtStatus::REPLY_MESSAGE_MISMATCH);
        }
        if self.connections.iter().any(|connection| {
            port_handle != 0 && connection.client_open && connection.client_handle == port_handle
        }) {
            return Err(NtStatus::INVALID_PORT_HANDLE);
        }
        if let Some(connection) = self.connections.iter().find(|connection| {
            port_handle != 0 && connection.server_open && connection.server_handle == port_handle
        }) {
            if connection.state != ConnState::Connected {
                return Err(NtStatus::PORT_DISCONNECTED);
            }
            return connection
                .delivered_requests
                .iter()
                .any(|request| request.identity == identity)
                .then_some(DeliveredRequestInfo {
                    connection_id: connection.id,
                    client: identity.client,
                    security: connection.security,
                })
                .ok_or(NtStatus::REPLY_MESSAGE_MISMATCH);
        }
        let port = self
            .ports
            .iter()
            .find(|port| port.user_open && port.handle == port_handle)
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        if self.kernel_endpoints.iter().any(|endpoint| {
            endpoint.port_object_id == port.object_id
                && endpoint
                    .delivered_requests
                    .iter()
                    .any(|request| request.identity == identity)
        }) {
            return Ok(DeliveredRequestInfo {
                connection_id: 0,
                client: identity.client,
                security: ConnectionSecurity::default(),
            });
        }
        self.connections
            .iter()
            .find(|connection| {
                connection.state == ConnState::Connected
                    && connection.client_live()
                    && connection.server_open
                    && connection.server_api == port.api
                    && connection.port_name == port.name
                    && connection
                        .delivered_requests
                        .iter()
                        .any(|request| request.identity == identity)
            })
            .map(|connection| DeliveredRequestInfo {
                connection_id: connection.id,
                client: identity.client,
                security: connection.security,
            })
            .ok_or(NtStatus::REPLY_MESSAGE_MISMATCH)
    }

    /// Receive the next `PORT_MESSAGE` for the endpoint identified by `handle`.
    /// Returns `Ok(None)` when the inbox is empty (would-block).
    pub fn receive_message(&mut self, handle: u64) -> Result<Option<QueuedMessage>, NtStatus> {
        if let Some(connection_index) = self.connections.iter().position(|connection| {
            handle != 0 && connection.client_open && connection.client_handle == handle
        }) {
            if !self.connections[connection_index].client_inbox.is_empty() {
                let stored = self.connections[connection_index].client_inbox.remove(0);
                let account = self.connections[connection_index].pool_account;
                self.replace_pool_charge(account, stored.pool_charge, 0)
                    .expect("dequeued broker message was previously charged");
                return Ok(Some(stored.message));
            }
            let conn = &self.connections[connection_index];
            return if conn.state == ConnState::Connected && conn.server_open {
                Ok(None)
            } else {
                Err(NtStatus::PORT_DISCONNECTED)
            };
        }
        if let Some(connection_index) = self.connections.iter().position(|connection| {
            handle != 0
                && connection.server_open
                && connection.server_handle == handle
                && connection.server_api == PortApi::Alpc
        }) {
            if !self.connections[connection_index].server_inbox.is_empty() {
                return Ok(self.dequeue_server_message(connection_index));
            }
            let connection = &self.connections[connection_index];
            return if connection.state == ConnState::Connected && connection.client_live() {
                Ok(None)
            } else {
                Err(NtStatus::PORT_DISCONNECTED)
            };
        }
        let port_index = self
            .ports
            .iter()
            .position(|port| port.user_open && port.handle == handle)
            .or_else(|| self.connection_port_index_for_server_handle(handle));
        if let Some(port_index) = port_index {
            let port_object_id = self.ports[port_index].object_id;
            if let Some(endpoint_index) = self.kernel_endpoints.iter().position(|endpoint| {
                endpoint.port_object_id == port_object_id && !endpoint.server_inbox.is_empty()
            }) {
                return Ok(self.dequeue_kernel_server_message(endpoint_index));
            }
            let connection_index = self.connections.iter().position(|conn| {
                conn.state == ConnState::Connected
                    && conn.client_live()
                    && conn.server_open
                    && conn.server_api == self.ports[port_index].api
                    && conn.port_name == self.ports[port_index].name
                    && !conn.server_inbox.is_empty()
            });
            if let Some(connection_index) = connection_index {
                return Ok(self.dequeue_server_message(connection_index));
            }
            return Ok(None);
        }
        Err(NtStatus::INVALID_HANDLE)
    }

    fn dequeue_kernel_server_message(&mut self, endpoint_index: usize) -> Option<QueuedMessage> {
        if self.kernel_endpoints[endpoint_index]
            .server_inbox
            .is_empty()
        {
            return None;
        }
        let stored = self.kernel_endpoints[endpoint_index].server_inbox.remove(0);
        let port_object_id = self.kernel_endpoints[endpoint_index].port_object_id;
        let account = self
            .ports
            .iter()
            .find(|port| port.object_id == port_object_id)
            .expect("a retained kernel endpoint keeps its connection port alive")
            .pool_account;
        if let Some(identity) = stored.message.request_identity {
            if !self.kernel_endpoints[endpoint_index]
                .delivered_requests
                .iter()
                .any(|request| request.identity == identity)
            {
                let delivered_charge = delivered_request_pool_charge();
                self.replace_pool_charge(account, stored.pool_charge, delivered_charge)
                    .expect("a delivered request record is smaller than its queued message");
                self.kernel_endpoints[endpoint_index]
                    .delivered_requests
                    .push(DeliveredRequest {
                        identity,
                        pool_charge: delivered_charge,
                    });
            } else {
                self.replace_pool_charge(account, stored.pool_charge, 0)
                    .expect("dequeued duplicate kernel request was previously charged");
            }
        } else {
            self.replace_pool_charge(account, stored.pool_charge, 0)
                .expect("dequeued kernel datagram was previously charged");
        }
        Some(stored.message)
    }

    /// Classic LPC server communication ports reply to one client but receive from their associated
    /// named connection port. ALPC server handles are exact endpoints and never use this alias.
    fn connection_port_index_for_server_handle(&self, handle: u64) -> Option<usize> {
        let connection = self.connections.iter().find(|connection| {
            handle != 0
                && connection.server_open
                && connection.server_handle == handle
                && connection.server_api == PortApi::Lpc
        })?;
        self.ports
            .iter()
            .position(|port| port.api == connection.server_api && port.name == connection.port_name)
    }

    fn dequeue_server_message(&mut self, connection_index: usize) -> Option<QueuedMessage> {
        if self.connections[connection_index].server_inbox.is_empty() {
            return None;
        }
        let stored = self.connections[connection_index].server_inbox.remove(0);
        let account = self.connections[connection_index].pool_account;
        if let Some(identity) = stored.message.request_identity {
            if !self.connections[connection_index]
                .delivered_requests
                .iter()
                .any(|request| request.identity == identity)
            {
                let delivered_charge = delivered_request_pool_charge();
                self.replace_pool_charge(account, stored.pool_charge, delivered_charge)
                    .expect("a delivered request record is smaller than its queued message");
                self.connections[connection_index]
                    .delivered_requests
                    .push(DeliveredRequest {
                        identity,
                        pool_charge: delivered_charge,
                    });
            } else {
                self.replace_pool_charge(account, stored.pool_charge, 0)
                    .expect("dequeued duplicate request was previously charged");
            }
        } else {
            self.replace_pool_charge(account, stored.pool_charge, 0)
                .expect("dequeued broker datagram was previously charged");
        }
        Some(stored.message)
    }

    // --- internals --------------------------------------------------------

    fn replace_pool_charge(
        &mut self,
        account_index: usize,
        old_charge: u32,
        new_charge: u32,
    ) -> Result<(), NtStatus> {
        let account = self
            .pool_accounts
            .get_mut(account_index)
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        let without_old = account
            .usage
            .checked_sub(old_charge)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let usage = without_old
            .checked_add(new_charge)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        // Native callers use zero when they do not request a private port quota. Such ports still
        // participate in accounting; only the explicit upper-bound check is disabled.
        if account.limit != 0 && usage > account.limit {
            return Err(NtStatus::INSUFFICIENT_RESOURCES);
        }
        account.usage = usage;
        Ok(())
    }

    fn allocate_stored_message(
        &mut self,
        account_index: usize,
        replaced_charge: u32,
        bytes: &[u8],
        attrs: MessageAttrs,
        provenance: MessageProvenance,
        port_context: u64,
        request_identity: Option<MessageIdentity>,
    ) -> Result<StoredMessage, NtStatus> {
        let pool_charge = queued_message_pool_charge(bytes.len(), &attrs)?;
        self.replace_pool_charge(account_index, replaced_charge, pool_charge)?;

        let mut owned_bytes = Vec::new();
        if owned_bytes.try_reserve_exact(bytes.len()).is_err() {
            self.replace_pool_charge(account_index, pool_charge, replaced_charge)
                .expect("failed allocation leaves the previous broker charge intact");
            return Err(NtStatus::INSUFFICIENT_RESOURCES);
        }
        owned_bytes.extend_from_slice(bytes);
        Ok(StoredMessage {
            message: QueuedMessage {
                bytes: owned_bytes,
                attrs,
                provenance,
                port_context,
                request_identity,
            },
            pool_charge,
        })
    }

    fn release_connection_storage(
        &mut self,
        connection_index: usize,
        clear_client: bool,
        clear_server: bool,
        clear_delivered: bool,
    ) {
        let (account, charge) = {
            let connection = &mut self.connections[connection_index];
            let mut charge = 0u32;
            if clear_client {
                charge = charge.saturating_add(
                    connection
                        .client_inbox
                        .iter()
                        .map(|message| message.pool_charge)
                        .sum(),
                );
                connection.client_inbox.clear();
            }
            if clear_server {
                charge = charge.saturating_add(
                    connection
                        .server_inbox
                        .iter()
                        .map(|message| message.pool_charge)
                        .sum(),
                );
                connection.server_inbox.clear();
            }
            if clear_delivered {
                charge = charge.saturating_add(
                    connection
                        .delivered_requests
                        .iter()
                        .map(|request| request.pool_charge)
                        .sum(),
                );
                connection.delivered_requests.clear();
            }
            (connection.pool_account, charge)
        };
        self.replace_pool_charge(account, charge, 0)
            .expect("released broker allocations were previously charged");
    }

    fn remove_request_from_connection(
        connection: &mut Connection,
        identity: MessageIdentity,
    ) -> Option<u32> {
        if let Some(index) = connection
            .server_inbox
            .iter()
            .position(|message| message.message.request_identity == Some(identity))
        {
            Some(connection.server_inbox.remove(index).pool_charge)
        } else if let Some(index) = connection
            .delivered_requests
            .iter()
            .position(|request| request.identity == identity)
        {
            Some(connection.delivered_requests.remove(index).pool_charge)
        } else {
            connection
                .client_inbox
                .iter()
                .position(|message| message.message.request_identity == Some(identity))
                .map(|index| connection.client_inbox.remove(index).pool_charge)
        }
    }

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
        client_id: ClientId,
        server_id: ClientId,
        limits: PortLimits,
        pool_account: usize,
        security: ConnectionSecurity,
        conn_info: Vec<u8>,
        state: ConnState,
        client_api: PortApi,
        server_api: PortApi,
        client_handle: u64,
    ) -> Self {
        let response_info = conn_info.clone();
        Self {
            id,
            port_name,
            subsystem_type,
            client_id,
            server_id,
            limits,
            pool_account,
            security,
            conn_info,
            response_info,
            state,
            client_api,
            server_api,
            client_handle,
            client_open: client_handle != 0,
            client_kernel_refs: 0,
            server_handle: 0,
            server_open: state == ConnState::Connected,
            port_context: 0,
            client_inbox: Vec::new(),
            server_inbox: Vec::new(),
            delivered_requests: Vec::new(),
        }
    }

    fn client_live(&self) -> bool {
        self.client_open || self.client_kernel_refs != 0
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
                assert_eq!(
                    core.connection_state(connection_id),
                    Some(ConnState::Connected)
                );
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
    fn handle_info_resolves_listen_client_and_server_handles() {
        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let owner = ClientId {
            process: 0x120,
            thread: 0x124,
        };
        let limits = PortLimits::default();
        let security = ConnectionSecurity::default();
        let listen =
            core.create_port_with_owner(&utf16("\\LsaAuthenticationPort"), PortApi::Lpc, owner);
        let cid = match core
            .connect(&utf16("\\LSAAUTHENTICATIONPORT"), PortApi::Lpc, 0, &[])
            .unwrap()
        {
            ConnectOutcome::Pending { connection_id } => connection_id,
            _ => unreachable!(),
        };
        core.receive(listen).unwrap();
        let server = core.accept(cid, true, 0).unwrap();
        let (client, _) = core.complete(server).unwrap();

        assert_eq!(
            core.handle_info(listen),
            Some(PortHandleInfo {
                endpoint: PortHandleEndpoint::ListenPort,
                api: PortApi::Lpc,
                connection_id: 0,
                state: None,
                port_name: &utf16("\\lsaauthenticationport"),
                server_id: owner,
                client_id: None,
                limits,
                security: None,
            })
        );
        assert_eq!(
            core.handle_info(client),
            Some(PortHandleInfo {
                endpoint: PortHandleEndpoint::ClientCommPort,
                api: PortApi::Lpc,
                connection_id: cid,
                state: Some(ConnState::Connected),
                port_name: &utf16("\\lsaauthenticationport"),
                server_id: owner,
                client_id: Some(ClientId::default()),
                limits,
                security: Some(security),
            })
        );
        assert_eq!(
            core.handle_info(server),
            Some(PortHandleInfo {
                endpoint: PortHandleEndpoint::ServerCommPort,
                api: PortApi::Lpc,
                connection_id: cid,
                state: Some(ConnState::Connected),
                port_name: &utf16("\\lsaauthenticationport"),
                server_id: owner,
                client_id: Some(ClientId::default()),
                limits,
                security: Some(security),
            })
        );
        assert_eq!(core.handle_info(0xdead), None);
    }

    #[test]
    fn conninfo_passthrough() {
        let mut core = PortCore::new();
        core.create_port(&utf16("\\P"), PortApi::Lpc);
        let blob = [1u8, 2, 3, 4, 5];
        let client_id = ClientId {
            process: 0x44,
            thread: 0x88,
        };
        let out = core
            .connect_with_client_id(&utf16("\\P"), PortApi::Lpc, 7, &blob, client_id)
            .unwrap();
        let cid = match out {
            ConnectOutcome::Completed { connection_id, .. } => connection_id,
            ConnectOutcome::Pending { connection_id } => connection_id,
        };
        assert_eq!(core.connection_info(cid), Some(&blob[..]));
        assert_eq!(core.connection_subsystem_type(cid), Some(7));
        assert_eq!(core.connection_client_id(cid), Some(client_id));
    }

    #[test]
    fn accepted_connection_info_is_committed_separately_from_request() {
        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let port = core.create_port(&utf16("\\P"), PortApi::Lpc);
        let request = b"client request";
        let response = b"server reply";
        let cid = match core
            .connect(&utf16("\\P"), PortApi::Lpc, 0, request)
            .unwrap()
        {
            ConnectOutcome::Pending { connection_id } => connection_id,
            _ => unreachable!(),
        };
        core.receive(port).unwrap();
        core.accept_with_connection_info(cid, true, 0, response)
            .unwrap();
        core.complete(cid).unwrap();

        assert_eq!(core.connection_info(cid), Some(request.as_slice()));
        assert_eq!(
            core.connection_response_info(cid),
            Some(response.as_slice())
        );
    }

    #[test]
    fn accepted_connection_info_cannot_grow_connectors_message() {
        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let port = core.create_port(&utf16("\\SmApiPort"), PortApi::Lpc);
        let cid = match core
            .connect(&utf16("\\SmApiPort"), PortApi::Lpc, 0, b"four")
            .unwrap()
        {
            ConnectOutcome::Pending { connection_id } => connection_id,
            _ => unreachable!(),
        };
        core.receive(port).unwrap();
        assert_eq!(
            core.accept_with_connection_info(cid, true, 0, b"too-long"),
            Err(NtStatus::BUFFER_TOO_SMALL)
        );
        assert_eq!(core.connection_state(cid), Some(ConnState::Received));
    }

    #[test]
    fn port_limits_and_connection_security_are_inherited_and_enforced() {
        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let limits = PortLimits {
            max_connection_info: 4,
            max_message: 44,
            max_pool_usage: 0x2400,
        };
        let security = ConnectionSecurity {
            impersonation_level: 2,
            dynamic_tracking: true,
            effective_only: true,
        };
        let listen = core
            .create_port_with_limits(&utf16("\\P"), PortApi::Lpc, limits)
            .unwrap();
        let connection = match core
            .connect_with_client_id_and_security(
                &utf16("\\P"),
                PortApi::Lpc,
                0,
                b"truncated",
                ClientId::default(),
                security,
            )
            .unwrap()
        {
            ConnectOutcome::Pending { connection_id } => connection_id,
            _ => unreachable!(),
        };
        assert_eq!(core.connection_info(connection), Some(&b"trun"[..]));
        assert_eq!(core.connection_limits(connection), Some(limits));
        assert_eq!(core.connection_security(connection), Some(security));

        core.receive(listen).unwrap();
        let server = core.accept(connection, true, 0).unwrap();
        let client = core.complete(connection).unwrap().0;
        assert_eq!(core.handle_info(client).unwrap().limits, limits);
        assert_eq!(core.handle_info(server).unwrap().security, Some(security));
        assert_eq!(
            core.send_message(client, &[0; 45], MessageAttrs::default()),
            Err(NtStatus::PORT_MESSAGE_TOO_LONG)
        );
        core.send_message(client, &[0; 44], MessageAttrs::default())
            .unwrap();
    }

    #[test]
    fn max_pool_usage_is_shared_and_released_when_messages_leave_the_broker() {
        fn connect(core: &mut PortCore, listen: u64) -> (u64, u64) {
            let connection = match core.connect(&utf16("\\P"), PortApi::Lpc, 0, &[]).unwrap() {
                ConnectOutcome::Pending { connection_id } => connection_id,
                _ => unreachable!(),
            };
            core.receive(listen).unwrap();
            let server = core.accept(connection, true, 0).unwrap();
            let client = core.complete(connection).unwrap().0;
            (server, client)
        }

        // Measure the broker's aligned allocation charge rather than encoding a host layout in
        // the test. The limited port below must permit exactly one such allocation.
        let mut probe = PortCore::new();
        probe.set_accept_policy(AcceptPolicy::Manual);
        let probe_listen = probe.create_port(&utf16("\\P"), PortApi::Lpc);
        let (_, probe_client) = connect(&mut probe, probe_listen);
        probe
            .send_message(probe_client, b"one", MessageAttrs::default())
            .unwrap();
        let one_message_charge = probe.connection_pool_usage(1).unwrap();
        assert_ne!(one_message_charge, 0);

        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let listen = core
            .create_port_with_limits(
                &utf16("\\P"),
                PortApi::Lpc,
                PortLimits {
                    max_connection_info: 0,
                    max_message: 64,
                    max_pool_usage: one_message_charge,
                },
            )
            .unwrap();
        let (server_a, client_a) = connect(&mut core, listen);
        let (_, client_b) = connect(&mut core, listen);

        core.send_message(client_a, b"one", MessageAttrs::default())
            .unwrap();
        assert_eq!(core.connection_pool_usage(1), Some(one_message_charge));
        assert_eq!(core.connection_pool_usage(2), Some(one_message_charge));
        assert_eq!(
            core.send_message(client_b, b"two", MessageAttrs::default()),
            Err(NtStatus::INSUFFICIENT_RESOURCES)
        );
        assert_eq!(core.connection_pool_usage(1), Some(one_message_charge));

        assert_eq!(
            core.receive_message(server_a).unwrap().unwrap().bytes,
            b"one"
        );
        assert_eq!(core.connection_pool_usage(1), Some(0));
        core.send_message(client_b, b"two", MessageAttrs::default())
            .unwrap();
    }

    #[test]
    fn quota_failed_reply_preserves_the_delivered_request() {
        let client_id = ClientId {
            process: 0x120,
            thread: 0x124,
        };

        // Obtain the exact charge of the queued request so the limited port can admit it while a
        // materially larger reply cannot fit.
        let mut probe = PortCore::new();
        probe.set_accept_policy(AcceptPolicy::Manual);
        let probe_listen = probe.create_port(&utf16("\\P"), PortApi::Lpc);
        let probe_connection = match probe
            .connect_with_client_id(&utf16("\\P"), PortApi::Lpc, 0, &[], client_id)
            .unwrap()
        {
            ConnectOutcome::Pending { connection_id } => connection_id,
            _ => unreachable!(),
        };
        probe.receive(probe_listen).unwrap();
        let _probe_server = probe.accept(probe_connection, true, 0).unwrap();
        let probe_client = probe.complete(probe_connection).unwrap().0;
        let identity = MessageIdentity {
            client: client_id,
            message_id: 7,
        };
        probe
            .send_request_message(probe_client, b"request", MessageAttrs::default(), identity)
            .unwrap();
        let request_charge = probe.connection_pool_usage(probe_connection).unwrap();

        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let listen = core
            .create_port_with_limits(
                &utf16("\\P"),
                PortApi::Lpc,
                PortLimits {
                    max_connection_info: 0,
                    max_message: 512,
                    max_pool_usage: request_charge,
                },
            )
            .unwrap();
        let connection = match core
            .connect_with_client_id(&utf16("\\P"), PortApi::Lpc, 0, &[], client_id)
            .unwrap()
        {
            ConnectOutcome::Pending { connection_id } => connection_id,
            _ => unreachable!(),
        };
        core.receive(listen).unwrap();
        let server = core.accept(connection, true, 0).unwrap();
        let client = core.complete(connection).unwrap().0;
        core.send_request_message(client, b"request", MessageAttrs::default(), identity)
            .unwrap();
        core.receive_message(server).unwrap().unwrap();
        let delivered_charge = core.connection_pool_usage(connection).unwrap();
        assert!(delivered_charge < request_charge);

        assert_eq!(
            core.send_reply_message(server, &[0; 512], MessageAttrs::default(), identity),
            Err(NtStatus::INSUFFICIENT_RESOURCES)
        );
        assert_eq!(
            core.connection_pool_usage(connection),
            Some(delivered_charge)
        );
        assert!(core.delivered_request(server, identity).is_ok());

        core.send_reply_message(server, b"ok", MessageAttrs::default(), identity)
            .unwrap();
        assert_eq!(core.receive_message(client).unwrap().unwrap().bytes, b"ok");
        assert_eq!(core.connection_pool_usage(connection), Some(0));
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
        core.send_message(ch, b"ping", MessageAttrs::default())
            .unwrap();
        let got = core.receive_message(sh).unwrap().unwrap();
        assert_eq!(got.bytes, b"ping");
        // server -> client
        core.send_message(sh, b"pong", MessageAttrs::default())
            .unwrap();
        let got = core.receive_message(ch).unwrap().unwrap();
        assert_eq!(got.bytes, b"pong");
        // drained
        assert!(core.receive_message(ch).unwrap().is_none());
    }

    #[test]
    fn delivered_request_identity_controls_impersonation_and_reply() {
        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let security = ConnectionSecurity {
            impersonation_level: 2,
            dynamic_tracking: true,
            effective_only: true,
        };
        let client_id = ClientId {
            process: 0x120,
            thread: 0x124,
        };
        let listen = core.create_port(&utf16("\\P"), PortApi::Lpc);
        let connection = match core
            .connect_with_client_id_and_security(
                &utf16("\\P"),
                PortApi::Lpc,
                0,
                &[],
                client_id,
                security,
            )
            .unwrap()
        {
            ConnectOutcome::Pending { connection_id } => connection_id,
            _ => unreachable!(),
        };
        core.receive(listen).unwrap();
        let server = core.accept(connection, true, 0).unwrap();
        let client = core.complete(connection).unwrap().0;
        let identity = MessageIdentity {
            client: client_id,
            message_id: 7,
        };

        core.send_request_message(client, b"request", MessageAttrs::default(), identity)
            .unwrap();
        assert_eq!(
            core.delivered_request(listen, identity),
            Err(NtStatus::REPLY_MESSAGE_MISMATCH),
            "queued requests are not impersonable before a server receives them"
        );
        assert_eq!(
            core.receive_message(server)
                .unwrap()
                .unwrap()
                .request_identity,
            Some(identity)
        );
        assert_eq!(
            core.delivered_request(server, identity).unwrap(),
            DeliveredRequestInfo {
                connection_id: connection,
                client: client_id,
                security,
            }
        );
        assert_eq!(
            core.delivered_request(
                server,
                MessageIdentity {
                    message_id: 8,
                    ..identity
                }
            ),
            Err(NtStatus::REPLY_MESSAGE_MISMATCH)
        );
        assert_eq!(
            core.delivered_request(client, identity),
            Err(NtStatus::INVALID_PORT_HANDLE)
        );

        core.send_reply_message(server, b"reply", MessageAttrs::default(), identity)
            .unwrap();
        assert_eq!(
            core.delivered_request(server, identity),
            Err(NtStatus::REPLY_MESSAGE_MISMATCH),
            "a completed request cannot be impersonated or replied to again"
        );
        assert_eq!(
            core.receive_message(client).unwrap().unwrap().bytes,
            b"reply"
        );
        core.close_port(client);
        assert_eq!(core.connection_state(connection), Some(ConnState::Refused));
        assert_eq!(
            core.delivered_request(server, identity),
            Err(NtStatus::PORT_DISCONNECTED)
        );
    }

    #[test]
    fn server_close_preserves_an_already_committed_client_reply() {
        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let client_id = ClientId {
            process: 0x120,
            thread: 0x124,
        };
        let listen = core.create_port(&utf16("\\P"), PortApi::Lpc);
        let connection = match core
            .connect_with_client_id(&utf16("\\P"), PortApi::Lpc, 0, &[], client_id)
            .unwrap()
        {
            ConnectOutcome::Pending { connection_id } => connection_id,
            _ => unreachable!(),
        };
        core.receive(listen).unwrap();
        let server = core.accept(connection, true, 0).unwrap();
        let client = core.complete(connection).unwrap().0;
        let identity = MessageIdentity {
            client: client_id,
            message_id: 9,
        };
        core.send_request_message(client, b"request", MessageAttrs::default(), identity)
            .unwrap();
        core.receive_message(server).unwrap().unwrap();
        core.send_reply_message(server, b"reply", MessageAttrs::default(), identity)
            .unwrap();

        core.close_port(server);
        assert!(core.handle_info(server).is_none());
        assert!(core.handle_info(client).is_some());
        assert_eq!(
            core.receive_message(client).unwrap().unwrap().bytes,
            b"reply"
        );
        assert_eq!(
            core.receive_message(client),
            Err(NtStatus::PORT_DISCONNECTED)
        );
    }

    #[test]
    fn synchronous_replies_are_received_and_cancelled_by_exact_identity() {
        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let client_id = ClientId {
            process: 0x120,
            thread: 0x124,
        };
        let listen = core.create_port(&utf16("\\P"), PortApi::Lpc);
        let connection = match core
            .connect_with_client_id(&utf16("\\P"), PortApi::Lpc, 0, &[], client_id)
            .unwrap()
        {
            ConnectOutcome::Pending { connection_id } => connection_id,
            _ => unreachable!(),
        };
        core.receive(listen).unwrap();
        let server = core.accept(connection, true, 0).unwrap();
        let client = core.complete(connection).unwrap().0;
        let first = MessageIdentity {
            client: ClientId {
                thread: 0x130,
                ..client_id
            },
            message_id: 7,
        };
        let second = MessageIdentity {
            client: ClientId {
                thread: 0x134,
                ..client_id
            },
            message_id: 8,
        };
        core.send_request_message(client, b"first", MessageAttrs::default(), first)
            .unwrap();
        core.send_request_message(client, b"second", MessageAttrs::default(), second)
            .unwrap();
        assert_eq!(
            core.receive_message(server).unwrap().unwrap().bytes,
            b"first"
        );
        assert_eq!(
            core.receive_message(server).unwrap().unwrap().bytes,
            b"second"
        );
        core.send_reply_message(server, b"second-reply", MessageAttrs::default(), second)
            .unwrap();
        core.send_reply_message(server, b"first-reply", MessageAttrs::default(), first)
            .unwrap();

        assert_eq!(
            core.receive_reply_message(client, first)
                .unwrap()
                .unwrap()
                .bytes,
            b"first-reply"
        );
        assert!(core.cancel_request_message(client, second).unwrap());
        assert!(core
            .receive_reply_message(client, second)
            .unwrap()
            .is_none());
        assert!(!core.cancel_request_message(client, second).unwrap());
    }

    #[test]
    fn retained_connection_port_carries_typed_kernel_request_and_owns_lifetime() {
        let mut core = PortCore::new();
        let listen = core.create_port(&utf16("\\Windows\\ApiPort"), PortApi::Lpc);
        let kernel = core.retain_connection_port(listen).unwrap();
        let identity = MessageIdentity {
            client: ClientId {
                process: 0x220,
                thread: 0x224,
            },
            message_id: 17,
        };

        core.send_kernel_request_message(kernel, b"hard-error", MessageAttrs::default(), identity)
            .unwrap();
        let received = core.receive_message(listen).unwrap().unwrap();
        assert_eq!(received.bytes, b"hard-error");
        assert_eq!(received.provenance.connection_id, 0);
        assert_eq!(received.provenance.client, identity.client);
        assert_eq!(received.request_identity, Some(identity));
        assert_eq!(
            core.delivered_request(listen, identity).unwrap().client,
            identity.client
        );

        core.send_reply_message(listen, b"response", MessageAttrs::default(), identity)
            .unwrap();
        core.close_port(listen);
        assert!(core.handle_info(listen).is_none());
        assert_eq!(
            core.connect(&utf16("\\Windows\\ApiPort"), PortApi::Lpc, 0, &[]),
            Err(NtStatus::OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            core.create_port_with_limits(
                &utf16("\\Windows\\ApiPort"),
                PortApi::Lpc,
                PortLimits::default()
            ),
            Err(NtStatus::OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            core.receive_reply_message(kernel, identity)
                .unwrap()
                .unwrap()
                .bytes,
            b"response"
        );
        assert_eq!(core.port_count(), 1);
        core.release_connection_port(kernel).unwrap();
        assert_eq!(core.port_count(), 0);
        assert_eq!(
            core.release_connection_port(kernel),
            Err(NtStatus::INVALID_PORT_HANDLE)
        );
    }

    #[test]
    fn retained_communication_port_survives_user_close_and_releases_exact_requests() {
        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let listen = core.create_port(&utf16("\\ProcessExceptionPort"), PortApi::Lpc);
        let connection = match core
            .connect(&utf16("\\ProcessExceptionPort"), PortApi::Lpc, 0, &[])
            .unwrap()
        {
            ConnectOutcome::Pending { connection_id } => connection_id,
            _ => unreachable!(),
        };
        core.receive(listen).unwrap();
        let server = core.accept(connection, true, 0x7788).unwrap();
        let client = core.complete(connection).unwrap().0;
        let first_endpoint = core.retain_communication_port(client).unwrap();
        let second_endpoint = core.retain_communication_port(client).unwrap();
        core.close_port(client);
        assert!(core.handle_info(client).is_none());
        assert_eq!(
            core.connection_state(connection),
            Some(ConnState::Connected)
        );

        let first = MessageIdentity {
            client: ClientId {
                process: 0x330,
                thread: 0x334,
            },
            message_id: 17,
        };
        let second = MessageIdentity {
            client: ClientId {
                process: 0x440,
                thread: 0x444,
            },
            message_id: 18,
        };
        core.send_kernel_request_message(first_endpoint, b"first", MessageAttrs::default(), first)
            .unwrap();
        core.send_kernel_request_message(
            second_endpoint,
            b"second",
            MessageAttrs::default(),
            second,
        )
        .unwrap();
        let received = core.receive_message(server).unwrap().unwrap();
        assert_eq!(received.bytes, b"first");
        assert_eq!(received.port_context, 0x7788);
        assert_eq!(received.provenance.client, first.client);
        core.send_reply_message(server, b"reply", MessageAttrs::default(), first)
            .unwrap();

        core.release_communication_port(second_endpoint).unwrap();
        assert_eq!(
            core.connection_state(connection),
            Some(ConnState::Connected)
        );
        assert!(core.receive_message(server).unwrap().is_none());
        assert_eq!(
            core.receive_reply_message(first_endpoint, first)
                .unwrap()
                .unwrap()
                .bytes,
            b"reply"
        );
        assert_eq!(core.connection_pool_usage(connection), Some(0));
        assert_eq!(
            core.release_communication_port(second_endpoint),
            Err(NtStatus::INVALID_PORT_HANDLE)
        );

        core.release_communication_port(first_endpoint).unwrap();
        assert_eq!(core.connection_state(connection), Some(ConnState::Refused));
        assert_eq!(
            core.send_message(server, b"stale", MessageAttrs::default()),
            Err(NtStatus::INVALID_PORT_HANDLE)
        );
    }

    #[test]
    fn concurrent_datagrams_carry_exact_provenance_without_a_listen_port_cursor() {
        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let ph = core.create_port(&utf16("\\P"), PortApi::Lpc);
        let mut clients = [0u64; 2];
        let mut servers = [0u64; 2];
        let mut connections = [0u64; 2];
        for (index, context) in [0x1111, 0x2222].into_iter().enumerate() {
            let cid = match core.connect(&utf16("\\P"), PortApi::Lpc, 0, &[]).unwrap() {
                ConnectOutcome::Pending { connection_id } => connection_id,
                _ => unreachable!(),
            };
            core.receive(ph).unwrap();
            servers[index] = core.accept(cid, true, context).unwrap();
            clients[index] = core.complete(cid).unwrap().0;
            connections[index] = cid;
        }

        core.send_message(clients[1], b"from-b", MessageAttrs::default())
            .unwrap();
        core.send_message(clients[0], b"from-a", MessageAttrs::default())
            .unwrap();
        let received = [
            core.receive_message(ph).unwrap().unwrap(),
            core.receive_message(ph).unwrap().unwrap(),
        ];
        for message in received {
            let (connection, context) = if message.bytes == b"from-a" {
                (connections[0], 0x1111)
            } else {
                assert_eq!(message.bytes, b"from-b");
                (connections[1], 0x2222)
            };
            assert_eq!(message.provenance.connection_id, connection);
            assert_eq!(message.port_context, context);
        }

        assert_eq!(
            core.send_message(ph, b"ambiguous", MessageAttrs::default()),
            Err(NtStatus::INVALID_PORT_HANDLE),
            "a listen handle never acquires an implicit reply target"
        );
        core.send_message(servers[0], b"reply-a", MessageAttrs::default())
            .unwrap();
        core.send_message(servers[1], b"reply-b", MessageAttrs::default())
            .unwrap();

        assert_eq!(
            core.receive_message(clients[0]).unwrap().unwrap().bytes,
            b"reply-a"
        );
        assert_eq!(
            core.receive_message(clients[1]).unwrap().unwrap().bytes,
            b"reply-b"
        );

        core.disconnect(connections[1]);
        assert_eq!(
            core.send_message(servers[1], b"stale", MessageAttrs::default()),
            Err(NtStatus::INVALID_PORT_HANDLE),
            "a stale communication handle cannot reuse prior receive provenance"
        );
    }

    #[test]
    fn server_comm_port_receives_from_its_connection_port() {
        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let listen = core.create_port(&utf16("\\P"), PortApi::Lpc);

        let first_connection = match core.connect(&utf16("\\P"), PortApi::Lpc, 0, &[]).unwrap() {
            ConnectOutcome::Pending { connection_id } => connection_id,
            _ => unreachable!(),
        };
        core.receive(listen).unwrap();
        let first_server = core.accept(first_connection, true, 0x1111).unwrap();
        let first_client = core.complete(first_connection).unwrap().0;

        let second_connection = match core.connect(&utf16("\\P"), PortApi::Lpc, 0, &[]).unwrap() {
            ConnectOutcome::Pending { connection_id } => connection_id,
            _ => unreachable!(),
        };
        assert_eq!(
            core.receive(first_server).unwrap(),
            ReceiveOutcome::ConnectionRequest {
                connection_id: second_connection,
                msg_type: port_message_type::CONNECTION_REQUEST,
            }
        );
        let second_server = core.accept(second_connection, true, 0x2222).unwrap();
        let second_client = core.complete(second_connection).unwrap().0;

        core.send_message(first_client, b"first", MessageAttrs::default())
            .unwrap();
        let received = core.receive_message(first_server).unwrap().unwrap();
        assert_eq!(received.bytes, b"first");
        assert_eq!(received.provenance.connection_id, first_connection);
        core.send_message(second_client, b"second", MessageAttrs::default())
            .unwrap();
        let received = core.receive_message(first_server).unwrap().unwrap();
        assert_eq!(received.bytes, b"second");
        assert_eq!(received.provenance.connection_id, second_connection);
        assert_eq!(received.port_context, 0x2222);

        core.send_message(second_server, b"reply", MessageAttrs::default())
            .unwrap();
        assert_eq!(
            core.receive_message(second_client).unwrap().unwrap().bytes,
            b"reply"
        );
    }

    #[test]
    fn alpc_server_comm_ports_receive_only_their_connection() {
        let mut core = PortCore::new();
        core.set_accept_policy(AcceptPolicy::Manual);
        let listen = core.create_port(&utf16("\\A"), PortApi::Alpc);
        let mut connections = [0u64; 2];
        let mut clients = [0u64; 2];
        let mut servers = [0u64; 2];

        for index in 0..2 {
            let connection = match core.connect(&utf16("\\A"), PortApi::Alpc, 0, &[]).unwrap() {
                ConnectOutcome::Pending { connection_id } => connection_id,
                _ => unreachable!(),
            };
            assert_eq!(
                core.receive(listen).unwrap(),
                ReceiveOutcome::ConnectionRequest {
                    connection_id: connection,
                    msg_type: port_message_type::CONNECTION_REQUEST,
                }
            );
            servers[index] = core.accept(connection, true, 0).unwrap();
            clients[index] = core.complete(connection).unwrap().0;
            connections[index] = connection;
        }

        core.send_message(clients[0], b"first", MessageAttrs::default())
            .unwrap();
        core.send_message(clients[1], b"second", MessageAttrs::default())
            .unwrap();
        let second = core.receive_message(servers[1]).unwrap().unwrap();
        assert_eq!(second.bytes, b"second");
        assert_eq!(second.provenance.connection_id, connections[1]);
        let first = core.receive_message(servers[0]).unwrap().unwrap();
        assert_eq!(first.bytes, b"first");
        assert_eq!(first.provenance.connection_id, connections[0]);

        let third_connection = match core.connect(&utf16("\\A"), PortApi::Alpc, 0, &[]).unwrap() {
            ConnectOutcome::Pending { connection_id } => connection_id,
            _ => unreachable!(),
        };
        assert_eq!(
            core.receive(servers[0]).unwrap(),
            ReceiveOutcome::WouldBlock
        );
        assert_eq!(
            core.receive(listen).unwrap(),
            ReceiveOutcome::ConnectionRequest {
                connection_id: third_connection,
                msg_type: port_message_type::CONNECTION_REQUEST,
            }
        );
    }
}
