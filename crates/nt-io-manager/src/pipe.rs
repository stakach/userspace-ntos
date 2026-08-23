//! The named-pipe connection data plane (NPFS `NP_FCB` / `NP_CCB` model).
//!
//! A faithful, host-testable port of the ReactOS NPFS connection object
//! (`references/reactos/drivers/filesystems/npfs/`). This is the *symmetric
//! connection* that a server end and a client end share: two directional byte
//! (or message) queues and a pipe-state machine. It is the load-bearing
//! correctness that `rpcrt4`'s Ndr marshalling depends on — a real connection
//! object at the far side of a pipe handle, not a synthetic mint.
//!
//! Model (mapping to NPFS):
//! * [`PipeRegistry`] — the volume: a set of named pipes ([`PipeFcb`]) keyed by
//!   name, mirroring the NPFS prefix table + `NP_VCB`.
//! * [`PipeFcb`] — `NP_FCB`: one named pipe (config: max instances, type, quotas,
//!   duplex direction). Owns a list of connection instances.
//! * [`PipeConnection`] — `NP_CCB`: ONE connection instance = a server end + a
//!   client end paired, plus `DataQueue[2]` (the two directional queues) and the
//!   `NamedPipeState`.
//!
//! The two queues follow NPFS's convention exactly (`read.c`/`write.c`):
//! * `DataQueue[INBOUND]`  = client → server bytes (server reads it, client writes it)
//! * `DataQueue[OUTBOUND]` = server → client bytes (client reads it, server writes it)
//!
//! Single-threaded (`&mut self`); no `unsafe`.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use nt_status::NtStatus;

// --- NPFS constants (references/reactos/sdk/include/ndk/iotypes.h) ----------

/// `FILE_PIPE_BYTE_STREAM_TYPE` / `FILE_PIPE_MESSAGE_TYPE`.
pub const FILE_PIPE_BYTE_STREAM_TYPE: u32 = 0x0000_0000;
pub const FILE_PIPE_MESSAGE_TYPE: u32 = 0x0000_0001;
/// `FILE_PIPE_*_MODE` (read mode).
pub const FILE_PIPE_BYTE_STREAM_MODE: u32 = 0x0000_0000;
pub const FILE_PIPE_MESSAGE_MODE: u32 = 0x0000_0001;
/// `FILE_PIPE_*_OPERATION` (completion mode).
pub const FILE_PIPE_QUEUE_OPERATION: u32 = 0x0000_0000;
pub const FILE_PIPE_COMPLETE_OPERATION: u32 = 0x0000_0001;
/// `FILE_PIPE_INBOUND` / `OUTBOUND` / `FULL_DUPLEX` (`NamedPipeConfiguration`).
/// Also the `DataQueue[2]` index convention: `INBOUND`=client→server,
/// `OUTBOUND`=server→client.
pub const FILE_PIPE_INBOUND: usize = 0x0000_0000;
pub const FILE_PIPE_OUTBOUND: usize = 0x0000_0001;
pub const FILE_PIPE_FULL_DUPLEX: u32 = 0x0000_0002;
/// `FILE_PIPE_CLIENT_END` / `FILE_PIPE_SERVER_END` (the `NamedPipeEnd`).
pub const FILE_PIPE_CLIENT_END: usize = 0x0000_0000;
pub const FILE_PIPE_SERVER_END: usize = 0x0000_0001;

// --- Pipe-specific NTSTATUS not in nt-status ------------------------------

/// `STATUS_PIPE_NOT_AVAILABLE` (0xC00000AC): no listening server instance.
pub const STATUS_PIPE_NOT_AVAILABLE: NtStatus = NtStatus(0xC000_00ACu32 as i32);
/// `STATUS_PIPE_BUSY` (0xC00000AE): all instances are busy.
pub const STATUS_PIPE_BUSY: NtStatus = NtStatus(0xC000_00AEu32 as i32);
/// `STATUS_INVALID_PIPE_STATE` (0xC00000AD): operation invalid for this pipe state/mode.
pub const STATUS_INVALID_PIPE_STATE: NtStatus = NtStatus(0xC000_00ADu32 as i32);
/// `STATUS_PIPE_DISCONNECTED` (0xC00000B0): the peer end disconnected.
pub const STATUS_PIPE_DISCONNECTED: NtStatus = NtStatus(0xC000_00B0u32 as i32);
/// `STATUS_PIPE_LISTENING` (0xC00000B3): FSCTL_PIPE_LISTEN, no client yet.
pub const STATUS_PIPE_LISTENING: NtStatus = NtStatus(0xC000_00B3u32 as i32);
/// `STATUS_PIPE_CONNECTED` (0xC00000B2): already connected.
pub const STATUS_PIPE_CONNECTED: NtStatus = NtStatus(0xC000_00B2u32 as i32);
/// `STATUS_INSTANCE_NOT_AVAILABLE` (0xC00000AB): the max-instances limit hit.
pub const STATUS_INSTANCE_NOT_AVAILABLE: NtStatus = NtStatus(0xC000_00ABu32 as i32);
/// `STATUS_PENDING` (0x00000103): an async pipe read/write/transceive IRP is queued.
pub const STATUS_PENDING: NtStatus = NtStatus(0x0000_0103);

/// The named-pipe connection state machine (`FILE_PIPE_*_STATE`,
/// `NP_CCB.NamedPipeState`).
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum PipeState {
    /// A server instance exists but is not listening, usually after a peer disconnect.
    #[default]
    Disconnected,
    /// The server end is waiting (FSCTL_PIPE_LISTEN) for a client to connect.
    Listening,
    /// Both ends are attached; data flows.
    Connected,
    /// One end has begun closing; the other still drains the queue.
    Closing,
}

impl PipeState {
    /// The raw `FILE_PIPE_*_STATE` value a hosted binary reads.
    pub fn to_raw(self) -> u32 {
        match self {
            PipeState::Disconnected => 0x0000_0001,
            PipeState::Listening => 0x0000_0002,
            PipeState::Connected => 0x0000_0003,
            PipeState::Closing => 0x0000_0004,
        }
    }
}

/// Which end of a connection a CCB handle refers to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PipeEnd {
    /// The listening/serving end (`FILE_PIPE_SERVER_END`).
    Server,
    /// The connecting end (`FILE_PIPE_CLIENT_END`).
    Client,
}

impl PipeEnd {
    /// The raw `FILE_PIPE_*_END` value.
    pub fn to_raw(self) -> usize {
        match self {
            PipeEnd::Server => FILE_PIPE_SERVER_END,
            PipeEnd::Client => FILE_PIPE_CLIENT_END,
        }
    }
}

/// Decode the primary CCB pointer portion of a ReactOS NPFS endpoint `FILE_OBJECT.FsContext`.
///
/// ReactOS `NpSetFileObject` stores `Ccb | FILE_PIPE_SERVER_END` for server endpoints and plain
/// `Ccb | FILE_PIPE_CLIENT_END` for client endpoints. `0` and `1` are not pipe CCB endpoints.
pub fn pipe_endpoint_primary_context(file_id: u64) -> Option<u64> {
    let primary = file_id & !1;
    if primary == 0 {
        None
    } else {
        Some(primary)
    }
}

/// Decode the named-pipe end bit from a ReactOS NPFS endpoint `FILE_OBJECT.FsContext`.
pub fn pipe_endpoint_end(file_id: u64) -> Option<PipeEnd> {
    pipe_endpoint_primary_context(file_id)?;
    if (file_id & 1) == FILE_PIPE_SERVER_END as u64 {
        Some(PipeEnd::Server)
    } else {
        Some(PipeEnd::Client)
    }
}

/// Encode a ReactOS NPFS endpoint `FILE_OBJECT.FsContext` for a CCB primary pointer and end.
pub fn pipe_endpoint_file_id(primary_context: u64, end: PipeEnd) -> Option<u64> {
    if primary_context == 0 || (primary_context & 1) != 0 {
        None
    } else {
        Some(primary_context | end.to_raw() as u64)
    }
}

/// Return the server endpoint id for the same NPFS CCB as `file_id`.
pub fn pipe_server_file_id_for_endpoint(file_id: u64) -> Option<u64> {
    pipe_endpoint_file_id(pipe_endpoint_primary_context(file_id)?, PipeEnd::Server)
}

/// One directional data queue (`NP_DATA_QUEUE`). We model it as a byte ring plus
/// per-message boundaries: byte-mode reads ignore the boundaries and drain bytes;
/// message-mode reads return exactly one queued message at a time.
#[derive(Default)]
struct DataQueue {
    /// The queued bytes, in FIFO order (front = next to read).
    bytes: VecDeque<u8>,
    /// Per-message lengths (message mode). `msgs[i]` bytes at the front form the
    /// i-th message. Empty ⇒ pure byte stream.
    msgs: VecDeque<usize>,
    /// The `OutboundQuota`/`InboundQuota` byte budget for this queue.
    quota: usize,
}

impl DataQueue {
    fn new(quota: usize) -> Self {
        Self {
            bytes: VecDeque::new(),
            msgs: VecDeque::new(),
            quota,
        }
    }

    fn bytes_in_queue(&self) -> usize {
        self.bytes.len()
    }

    /// Enqueue `data` as one write. In message mode a message boundary is
    /// recorded; in byte mode the bytes coalesce into the stream. Rejects a write
    /// that would exceed the quota (returns the bytes actually accepted — NPFS
    /// blocks/partial-writes, we accept-what-fits which is faithful for the
    /// synchronous RPC path).
    fn enqueue(&mut self, data: &[u8], message_mode: bool) -> usize {
        let room = self.quota.saturating_sub(self.bytes.len());
        let n = room.min(data.len());
        if n == 0 {
            return 0;
        }
        self.bytes.extend(&data[..n]);
        if message_mode {
            self.msgs.push_back(n);
        }
        n
    }

    /// Dequeue up to `max` bytes. In message mode a single read returns at most
    /// one message; if the caller's buffer is smaller than the message the
    /// remainder stays queued (NPFS returns `STATUS_BUFFER_OVERFLOW`, surfaced by
    /// the caller via `more`). Returns `(bytes, more_of_this_message)`.
    fn dequeue(&mut self, max: usize, message_mode: bool) -> (Vec<u8>, bool) {
        if self.bytes.is_empty() || max == 0 {
            return (Vec::new(), false);
        }
        let take = if message_mode {
            // One message at a time.
            let msg_len = *self.msgs.front().unwrap_or(&self.bytes.len());
            msg_len.min(max)
        } else {
            max.min(self.bytes.len())
        };
        let mut out = Vec::with_capacity(take);
        for _ in 0..take {
            out.push(self.bytes.pop_front().unwrap());
        }
        let mut more = false;
        if message_mode {
            if let Some(front) = self.msgs.front_mut() {
                if take >= *front {
                    self.msgs.pop_front();
                } else {
                    *front -= take;
                    more = true; // message truncated → BUFFER_OVERFLOW semantics
                }
            }
        } else {
            // Byte-mode reads still consume bytes from message-type pipes. Keep the
            // message-boundary queue aligned so a later read-mode switch cannot see
            // a stale boundary for bytes that were already drained.
            let mut remaining = take;
            while remaining != 0 {
                let Some(front) = self.msgs.front_mut() else {
                    break;
                };
                if remaining >= *front {
                    remaining -= *front;
                    self.msgs.pop_front();
                } else {
                    *front -= remaining;
                    break;
                }
            }
        }
        (out, more)
    }
}

/// A single connection instance (`NP_CCB`): a server end + a client end sharing
/// two directional data queues + the pipe state.
pub struct PipeConnection {
    /// Stable id within the owning FCB. This mirrors a CCB identity rather than a vector slot.
    id: usize,
    /// `NP_CCB.NamedPipeState`.
    pub state: PipeState,
    /// Whether the server end has an attached open (`FileObject[SERVER_END]`).
    server_attached: bool,
    /// Whether the client end has an attached open (`FileObject[CLIENT_END]`).
    client_attached: bool,
    /// `NP_CCB.DataQueue[2]`. `[INBOUND]`=client→server, `[OUTBOUND]`=server→client.
    queues: [DataQueue; 2],
    /// Per-end read mode (`NP_CCB.ReadMode[2]`): byte vs message.
    read_message_mode: [bool; 2],
    /// Per-end completion mode (`NP_CCB.CompletionMode[2]`).
    completion_mode: [u32; 2],
    /// Whether an exact transceive read is queued for each endpoint. NPFS rejects a second
    /// transaction on that endpoint until the retained read completes or is cancelled.
    transceive_pending: [bool; 2],
    /// The pipe's write type (byte-stream vs message) from the FCB config.
    write_message_mode: bool,
    /// The pipe's duplex direction (`FILE_PIPE_INBOUND/OUTBOUND/FULL_DUPLEX`).
    configuration: u32,
}

impl PipeConnection {
    fn new(params: &PipeParams) -> Self {
        let msg = params.pipe_type == FILE_PIPE_MESSAGE_TYPE;
        let server_msg = params.read_mode == FILE_PIPE_MESSAGE_MODE;
        PipeConnection {
            id: 0,
            state: PipeState::Disconnected,
            server_attached: true, // created by the server side
            client_attached: false,
            queues: [
                DataQueue::new(params.inbound_quota),
                DataQueue::new(params.outbound_quota),
            ],
            read_message_mode: [false, server_msg],
            completion_mode: [FILE_PIPE_QUEUE_OPERATION, params.completion_mode],
            transceive_pending: [false; 2],
            write_message_mode: msg,
            configuration: params.configuration,
        }
    }

    /// The queue a given end READS from.
    fn read_queue_idx(end: PipeEnd) -> usize {
        match end {
            PipeEnd::Server => FILE_PIPE_INBOUND, // server reads client→server
            PipeEnd::Client => FILE_PIPE_OUTBOUND, // client reads server→client
        }
    }

    /// The queue a given end WRITES to.
    fn write_queue_idx(end: PipeEnd) -> usize {
        match end {
            PipeEnd::Server => FILE_PIPE_OUTBOUND, // server writes server→client
            PipeEnd::Client => FILE_PIPE_INBOUND,  // client writes client→server
        }
    }

    /// True once both ends are attached and CONNECTED.
    pub fn is_connected(&self) -> bool {
        self.state == PipeState::Connected
    }

    /// Bytes available for `end` to read right now.
    pub fn readable_bytes(&self, end: PipeEnd) -> usize {
        self.queues[Self::read_queue_idx(end)].bytes_in_queue()
    }
}

/// The write-type / read-mode direction check NPFS applies in `read.c`/`write.c`:
/// a half-duplex pipe rejects the wrong-direction operation.
fn direction_ok_read(end: PipeEnd, configuration: u32) -> bool {
    // read.c:70 — reject SERVER_END read on OUTBOUND, CLIENT_END read on INBOUND
    !((end == PipeEnd::Server && configuration == FILE_PIPE_OUTBOUND as u32)
        || (end == PipeEnd::Client && configuration == FILE_PIPE_INBOUND as u32))
}

fn direction_ok_write(end: PipeEnd, configuration: u32) -> bool {
    // write.c:82 — reject SERVER_END write on INBOUND, CLIENT_END write on OUTBOUND
    !((end == PipeEnd::Server && configuration == FILE_PIPE_INBOUND as u32)
        || (end == PipeEnd::Client && configuration == FILE_PIPE_OUTBOUND as u32))
}

/// The pipe config a `NtCreateNamedPipeFile` carries (`NP_FCB` fields).
#[derive(Copy, Clone, Debug)]
pub struct PipeParams {
    /// `MaximumInstances` (`FILE_PIPE_UNLIMITED_INSTANCES` = `u32::MAX`).
    pub max_instances: u32,
    /// `NamedPipeType`: byte-stream vs message.
    pub pipe_type: u32,
    /// `NamedPipeConfiguration`: INBOUND / OUTBOUND / FULL_DUPLEX.
    pub configuration: u32,
    /// Initial server-end read mode from `NAMED_PIPE_CREATE_PARAMETERS.ReadMode`.
    pub read_mode: u32,
    /// Initial server-end completion mode from `NAMED_PIPE_CREATE_PARAMETERS.CompletionMode`.
    pub completion_mode: u32,
    /// The client→server queue quota.
    pub inbound_quota: usize,
    /// The server→client queue quota.
    pub outbound_quota: usize,
}

impl Default for PipeParams {
    fn default() -> Self {
        // Full-duplex byte-stream, 4 KiB each way — the rpcrt4 ncacn_np default.
        PipeParams {
            max_instances: u32::MAX,
            pipe_type: FILE_PIPE_BYTE_STREAM_TYPE,
            configuration: FILE_PIPE_FULL_DUPLEX,
            read_mode: FILE_PIPE_BYTE_STREAM_MODE,
            completion_mode: FILE_PIPE_QUEUE_OPERATION,
            inbound_quota: 4096,
            outbound_quota: 4096,
        }
    }
}

/// `FILE_PIPE_INFORMATION` for `NtQueryInformationFile`/`NtSetInformationFile`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PipeInformation {
    pub read_mode: u32,
    pub completion_mode: u32,
}

/// A named pipe (`NP_FCB`): a name + its config + the live connection instances.
pub struct PipeFcb {
    /// The full pipe name (e.g. `\Device\NamedPipe\lsarpc` or just `lsarpc`).
    pub name: String,
    /// The pipe config all instances share.
    pub params: PipeParams,
    /// Stable per-FCB connection id allocator. Vector indices may move when closed instances are
    /// removed; CCB handles must not.
    next_connection_id: usize,
    /// The live connection instances (`NP_FCB.CcbList`).
    connections: Vec<PipeConnection>,
}

impl PipeFcb {
    fn current_instances(&self) -> u32 {
        self.connections.len() as u32
    }
}

/// A handle to one end of one connection: `(pipe index, stable connection id, end)`.
/// This is the "CCB pointer + NamedPipeEnd" a FILE_OBJECT decodes to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PipeHandle {
    fcb: usize,
    conn: usize,
    end: PipeEnd,
}

impl PipeHandle {
    /// Which end this handle refers to.
    pub fn end(&self) -> PipeEnd {
        self.end
    }
}

/// The named-pipe volume (`NP_VCB`): all named pipes, keyed by name. The single
/// owner of every [`PipeConnection`]; hands out [`PipeHandle`]s to the ends.
#[derive(Default)]
pub struct PipeRegistry {
    pipes: Vec<PipeFcb>,
}

impl PipeRegistry {
    /// A fresh, empty named-pipe volume.
    pub fn new() -> Self {
        PipeRegistry { pipes: Vec::new() }
    }

    fn find_fcb(&self, name: &str) -> Option<usize> {
        self.pipes.iter().position(|p| p.name == name)
    }

    /// `IRP_MJ_CREATE_NAMED_PIPE` / `NtCreateNamedPipeFile` — create (or add a new
    /// instance to) the server side of a named pipe. Returns a SERVER-end handle
    /// in the `Listening` state.
    ///
    /// Mirrors `NpCreateServerEnd`: the first create makes the FCB; subsequent
    /// creates add another instance up to `MaximumInstances`.
    pub fn create_server_pipe(
        &mut self,
        name: &str,
        params: PipeParams,
    ) -> Result<PipeHandle, NtStatus> {
        if !valid_pipe_type(params.pipe_type)
            || !valid_pipe_mode(params.read_mode)
            || !valid_completion_mode(params.completion_mode)
            || (params.pipe_type == FILE_PIPE_BYTE_STREAM_TYPE
                && params.read_mode == FILE_PIPE_MESSAGE_MODE)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let fcb_idx = match self.find_fcb(name) {
            Some(idx) => {
                // Additional instance — enforce MaximumInstances.
                let fcb = &self.pipes[idx];
                if fcb.current_instances() >= fcb.params.max_instances {
                    return Err(STATUS_INSTANCE_NOT_AVAILABLE);
                }
                idx
            }
            None => {
                self.pipes.push(PipeFcb {
                    name: String::from(name),
                    params,
                    next_connection_id: 1,
                    connections: Vec::new(),
                });
                self.pipes.len() - 1
            }
        };
        let fcb = &mut self.pipes[fcb_idx];
        let mut conn = PipeConnection::new(&fcb.params);
        conn.id = fcb.next_connection_id;
        fcb.next_connection_id = fcb.next_connection_id.checked_add(1).unwrap_or(1).max(1);
        conn.state = PipeState::Listening;
        let conn_id = conn.id;
        fcb.connections.push(conn);
        Ok(PipeHandle {
            fcb: fcb_idx,
            conn: conn_id,
            end: PipeEnd::Server,
        })
    }

    /// `FSCTL_PIPE_LISTEN` — a server end waits for a client. Transitions
    /// `Disconnected → Listening`.
    ///
    /// Returns `STATUS_PIPE_LISTENING` (pending) if no client yet, or
    /// `STATUS_PIPE_CONNECTED` if the connect already paired this instance.
    pub fn listen(&mut self, h: PipeHandle) -> Result<NtStatus, NtStatus> {
        let conn = self.conn_mut(h)?;
        if h.end != PipeEnd::Server {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        match conn.state {
            PipeState::Connected => Ok(STATUS_PIPE_CONNECTED),
            PipeState::Disconnected | PipeState::Listening => {
                conn.state = PipeState::Listening;
                Ok(STATUS_PIPE_LISTENING)
            }
            PipeState::Closing => Err(STATUS_PIPE_DISCONNECTED),
        }
    }

    /// `IRP_MJ_CREATE` on `\??\pipe\NAME` / `NtCreateFile` — the client connect.
    /// Pairs with a listening server instance and transitions it to `Connected`.
    /// Returns a CLIENT-end handle.
    ///
    /// Mirrors `NpCreateClientEnd`: find the FCB by name, find a
    /// `FILE_PIPE_LISTENING_STATE` server instance, attach the client end. A
    /// disconnected-but-not-listening server instance is not available to clients;
    /// callers such as `WaitNamedPipe` retry or wait until a listening instance exists.
    pub fn connect_client(&mut self, name: &str) -> Result<PipeHandle, NtStatus> {
        let fcb_idx = self.find_fcb(name).ok_or(NtStatus::OBJECT_NAME_NOT_FOUND)?;
        let fcb = &mut self.pipes[fcb_idx];
        let conn_idx = fcb
            .connections
            .iter()
            .position(|c| c.state == PipeState::Listening && !c.client_attached);
        let Some(conn_idx) = conn_idx else {
            // No available server instance.
            return Err(STATUS_PIPE_NOT_AVAILABLE);
        };
        let conn = &mut fcb.connections[conn_idx];
        conn.client_attached = true;
        conn.read_message_mode[FILE_PIPE_CLIENT_END] = false;
        conn.completion_mode[FILE_PIPE_CLIENT_END] = FILE_PIPE_QUEUE_OPERATION;
        conn.state = PipeState::Connected;
        let conn_id = conn.id;
        Ok(PipeHandle {
            fcb: fcb_idx,
            conn: conn_id,
            end: PipeEnd::Client,
        })
    }

    /// `IRP_MJ_WRITE` — write `data` from `h`'s end; it queues to the OTHER end's
    /// read queue. Returns the number of bytes accepted.
    pub fn pipe_write(&mut self, h: PipeHandle, data: &[u8]) -> Result<usize, NtStatus> {
        let config = self.conn(h)?.configuration;
        if !direction_ok_write(h.end, config) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let conn = self.conn_mut(h)?;
        if conn.state != PipeState::Connected {
            return Err(STATUS_PIPE_DISCONNECTED);
        }
        let msg = conn.write_message_mode;
        let qidx = PipeConnection::write_queue_idx(h.end);
        let accepted = conn.queues[qidx].enqueue(data, msg);
        if accepted != 0 {
            let reader = match h.end {
                PipeEnd::Server => PipeEnd::Client,
                PipeEnd::Client => PipeEnd::Server,
            };
            conn.transceive_pending[reader.to_raw()] = false;
        }
        Ok(accepted)
    }

    /// `IRP_MJ_READ` — read up to `max` bytes for `h`'s end from its read queue
    /// (filled by the other end's writes). Returns `(bytes, more)` where `more`
    /// indicates a truncated message (BUFFER_OVERFLOW) in message mode.
    pub fn pipe_read(&mut self, h: PipeHandle, max: usize) -> Result<(Vec<u8>, bool), NtStatus> {
        let config = self.conn(h)?.configuration;
        if !direction_ok_read(h.end, config) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let end_idx = h.end.to_raw();
        let conn = self.conn_mut(h)?;
        // A read on a disconnected/closing pipe with no data drains, then errors.
        let msg = conn.read_message_mode[end_idx];
        let qidx = PipeConnection::read_queue_idx(h.end);
        let (bytes, more) = conn.queues[qidx].dequeue(max, msg);
        if bytes.is_empty() && conn.state != PipeState::Connected {
            return Err(STATUS_PIPE_DISCONNECTED);
        }
        Ok((bytes, more))
    }

    /// `FSCTL_PIPE_TRANSCEIVE` — write then read in one op (the RPC request/reply
    /// primitive). Writes `out`, then reads up to `max` bytes.
    pub fn transceive(
        &mut self,
        h: PipeHandle,
        out: &[u8],
        max: usize,
    ) -> Result<(usize, Vec<u8>, bool), NtStatus> {
        {
            let conn = self.conn(h)?;
            if conn.state != PipeState::Connected {
                return Err(STATUS_INVALID_PIPE_STATE);
            }
            if conn.configuration != FILE_PIPE_FULL_DUPLEX
                || !conn.read_message_mode[h.end.to_raw()]
            {
                return Err(STATUS_INVALID_PIPE_STATE);
            }
            if conn.transceive_pending[h.end.to_raw()] || conn.readable_bytes(h.end) != 0 {
                return Err(STATUS_PIPE_BUSY);
            }
        }
        let written = self.pipe_write(h, out)?;
        let (bytes, more) = self.pipe_read(h, max)?;
        if bytes.is_empty() {
            self.conn_mut(h)?.transceive_pending[h.end.to_raw()] = true;
            return Err(STATUS_PENDING);
        }
        Ok((written, bytes, more))
    }

    /// `IRP_MJ_CLEANUP`/disconnect — detach `h`'s end. If both ends are gone the
    /// connection is removed; otherwise it transitions to `Closing` (the peer may
    /// still drain queued bytes) then `Disconnected`.
    pub fn disconnect(&mut self, h: PipeHandle) -> Result<(), NtStatus> {
        let fcb = self.pipes.get_mut(h.fcb).ok_or(NtStatus::INVALID_HANDLE)?;
        let conn_idx = fcb
            .connections
            .iter()
            .position(|conn| conn.id == h.conn)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        let conn = &mut fcb.connections[conn_idx];
        match h.end {
            PipeEnd::Server => conn.server_attached = false,
            PipeEnd::Client => conn.client_attached = false,
        }
        if !conn.server_attached && !conn.client_attached {
            fcb.connections.remove(conn_idx);
        } else {
            // The peer's read queue KEEPS its buffered bytes (the peer may still
            // drain what the gone end already wrote — NPFS's `Closing` semantics);
            // only *future* writes from the gone end are impossible, which the
            // `Connected`-state guard in `pipe_write` already enforces.
            conn.state = PipeState::Closing;
        }
        Ok(())
    }

    /// The connection state for a handle (for `NtQueryInformationFile`
    /// FilePipeLocalInformation, and tests).
    pub fn state(&self, h: PipeHandle) -> Result<PipeState, NtStatus> {
        Ok(self.conn(h)?.state)
    }

    /// Bytes available to read for `h`'s end right now.
    pub fn readable_bytes(&self, h: PipeHandle) -> Result<usize, NtStatus> {
        Ok(self.conn(h)?.readable_bytes(h.end))
    }

    /// `FilePipeInformation` query for one end of a named-pipe connection.
    pub fn query_pipe_information(&self, h: PipeHandle) -> Result<PipeInformation, NtStatus> {
        let conn = self.conn(h)?;
        let end = h.end.to_raw();
        Ok(PipeInformation {
            read_mode: if conn.read_message_mode[end] {
                FILE_PIPE_MESSAGE_MODE
            } else {
                FILE_PIPE_BYTE_STREAM_MODE
            },
            completion_mode: conn.completion_mode[end],
        })
    }

    /// `FilePipeInformation` set for one end of a named-pipe connection.
    pub fn set_pipe_information(
        &mut self,
        h: PipeHandle,
        information: PipeInformation,
    ) -> Result<(), NtStatus> {
        if !valid_pipe_mode(information.read_mode)
            || !valid_completion_mode(information.completion_mode)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let conn = self.conn_mut(h)?;
        if information.read_mode == FILE_PIPE_MESSAGE_MODE && !conn.write_message_mode {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let end = h.end.to_raw();
        conn.read_message_mode[end] = information.read_mode == FILE_PIPE_MESSAGE_MODE;
        conn.completion_mode[end] = information.completion_mode;
        Ok(())
    }

    // --- internals ---------------------------------------------------------

    fn conn(&self, h: PipeHandle) -> Result<&PipeConnection, NtStatus> {
        self.pipes
            .get(h.fcb)
            .and_then(|f| f.connections.iter().find(|conn| conn.id == h.conn))
            .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn conn_mut(&mut self, h: PipeHandle) -> Result<&mut PipeConnection, NtStatus> {
        self.pipes
            .get_mut(h.fcb)
            .and_then(|f| f.connections.iter_mut().find(|conn| conn.id == h.conn))
            .ok_or(NtStatus::INVALID_HANDLE)
    }
}

fn valid_pipe_type(pipe_type: u32) -> bool {
    matches!(
        pipe_type,
        FILE_PIPE_BYTE_STREAM_TYPE | FILE_PIPE_MESSAGE_TYPE
    )
}

fn valid_pipe_mode(mode: u32) -> bool {
    matches!(mode, FILE_PIPE_BYTE_STREAM_MODE | FILE_PIPE_MESSAGE_MODE)
}

fn valid_completion_mode(mode: u32) -> bool {
    matches!(
        mode,
        FILE_PIPE_QUEUE_OPERATION | FILE_PIPE_COMPLETE_OPERATION
    )
}

// ─── BATCH 34: the async ncacn_np SERVER completion edge ──────────────────────────────────────────
//
// rpcrt4's ncacn_np SERVER is async/event-driven: it does NOT block on a plain pipe read. It posts an
// OVERLAPPED `NtFsControlFile(FSCTL_PIPE_LISTEN)` on the server pipe end — which returns STATUS_PENDING
// while no client is connected (NpSetListeningPipeState → IoMarkIrpPending, see the real npfs
// statesup.c:222) — carrying an EVENT handle for completion, then parks on
// `NtWaitForMultipleObjects([mgr_event, listen_event])`. When a client connects (IRP_MJ_CREATE), npfs
// completes the queued listen IRP with SUCCESS; the RPC layer's completion event must then be SIGNALLED
// so the server's wait-array wakes → it reads the client's bind PDU → rpcrt4 emits bind_ack.
//
// The executive needs a small record keyed by the SERVER end's npfs `file_id` that carries the obj_ns
// EVENT index to signal (resolved at listen time, in the server's own handle table) + the listen IOSB
// VA to fill on completion. This is the pure, host-tested model of that record + its table; the
// executive wires the signal through its EXISTING `wait_wake_event_set` (NtSetEvent → WOKE parked
// waiter) path, exactly like an `NtSetEvent`.

/// A growable fid -> pipe-name-hash map. The executive records both server and client pipe
/// FILE_OBJECT ids here so later async LISTEN, WAIT, and trace paths can stay name-scoped without a
/// fixed cap or wildcard matching.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PipeFidName {
    pub file_id: u64,
    pub name_hash: u64,
}

#[derive(Clone, Debug)]
pub struct PipeFidNameTable {
    entries: Vec<PipeFidName>,
}

impl Default for PipeFidNameTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PipeFidNameTable {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn ensure_capacity(&mut self) -> bool {
        self.entries.len() < self.entries.capacity() || self.entries.try_reserve(1).is_ok()
    }

    pub fn capacity(&self) -> usize {
        self.entries.capacity()
    }

    pub fn remember(&mut self, file_id: u64, name_hash: u64) -> Result<(), ()> {
        if file_id == 0 || name_hash == 0 {
            return Err(());
        }
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.file_id == file_id)
        {
            entry.name_hash = name_hash;
            return Ok(());
        }
        if self.entries.len() == self.entries.capacity() {
            let reserve = if self.entries.capacity() == 0 { 32 } else { 1 };
            self.entries.try_reserve(reserve).map_err(|_| ())?;
        }
        self.entries.push(PipeFidName { file_id, name_hash });
        Ok(())
    }

    pub fn name_hash(&self, file_id: u64) -> Option<u64> {
        self.entries
            .iter()
            .find(|entry| entry.file_id == file_id)
            .map(|entry| entry.name_hash)
    }

    pub fn contains_name_hash(&self, name_hash: u64) -> bool {
        name_hash != 0
            && self
                .entries
                .iter()
                .any(|entry| entry.name_hash == name_hash)
    }

    pub fn forget(&mut self, file_id: u64) -> bool {
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.file_id == file_id)
        {
            self.entries.swap_remove(index);
            true
        } else {
            false
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Exact server pipe endpoints that accepted a client before the server posted its async
/// `FSCTL_PIPE_LISTEN` IRP.
///
/// Win32 explicitly allows the client `CreateFile("\\\\.\\pipe\\...")` to win the race against
/// `ConnectNamedPipe`. The later server-side connect/listen then completes immediately for that
/// same server endpoint. This table is only the cross-syscall edge; the pipe FSD still owns the
/// actual connected CCB and byte queues.
#[derive(Clone, Debug)]
pub struct PipePreconnectedServerTable {
    server_file_ids: Vec<u64>,
}

impl Default for PipePreconnectedServerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PipePreconnectedServerTable {
    pub const fn new() -> Self {
        Self {
            server_file_ids: Vec::new(),
        }
    }

    pub fn ensure_capacity(&mut self) -> bool {
        self.server_file_ids.len() < self.server_file_ids.capacity()
            || self.server_file_ids.try_reserve(1).is_ok()
    }

    pub fn capacity(&self) -> usize {
        self.server_file_ids.capacity()
    }

    /// Record a server endpoint whose client side already connected. Idempotent for the same fid.
    pub fn remember(&mut self, server_file_id: u64) -> Result<bool, ()> {
        if server_file_id == 0 {
            return Err(());
        }
        if self.server_file_ids.contains(&server_file_id) {
            return Ok(false);
        }
        if self.server_file_ids.len() == self.server_file_ids.capacity() {
            let reserve = if self.server_file_ids.capacity() == 0 {
                32
            } else {
                1
            };
            self.server_file_ids.try_reserve(reserve).map_err(|_| ())?;
        }
        self.server_file_ids.push(server_file_id);
        Ok(true)
    }

    /// Consume the preconnected edge exactly once when the server posts `FSCTL_PIPE_LISTEN`.
    pub fn take(&mut self, server_file_id: u64) -> bool {
        if let Some(index) = self
            .server_file_ids
            .iter()
            .position(|&entry| entry == server_file_id)
        {
            self.server_file_ids.swap_remove(index);
            true
        } else {
            false
        }
    }

    pub fn remove(&mut self, server_file_id: u64) -> bool {
        self.take(server_file_id)
    }

    pub fn contains(&self, server_file_id: u64) -> bool {
        server_file_id != 0 && self.server_file_ids.contains(&server_file_id)
    }

    pub fn len(&self) -> usize {
        self.server_file_ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.server_file_ids.is_empty()
    }
}

/// A tiny stable FNV-1a hash of a pipe leaf name (UTF-16 units, case-insensitive on ASCII). Used to
/// match a pipe name without relying on a fixed string table.
pub fn pipe_name_hash(name16: &[u16]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &w in name16 {
        let c = if (b'A' as u16..=b'Z' as u16).contains(&w) {
            w + 32
        } else {
            w
        };
        h ^= c as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn dx() -> PipeRegistry {
        PipeRegistry::new()
    }

    fn message_params() -> PipeParams {
        PipeParams {
            pipe_type: FILE_PIPE_MESSAGE_TYPE,
            read_mode: FILE_PIPE_MESSAGE_MODE,
            ..PipeParams::default()
        }
    }

    fn set_message_read(registry: &mut PipeRegistry, handle: PipeHandle) {
        registry
            .set_pipe_information(
                handle,
                PipeInformation {
                    read_mode: FILE_PIPE_MESSAGE_MODE,
                    completion_mode: FILE_PIPE_QUEUE_OPERATION,
                },
            )
            .unwrap();
    }

    #[test]
    fn create_listening_then_connect_reaches_connected() {
        let mut r = dx();
        let s = r
            .create_server_pipe("lsarpc", PipeParams::default())
            .unwrap();
        assert_eq!(r.state(s).unwrap(), PipeState::Listening);
        assert_eq!(r.listen(s).unwrap(), STATUS_PIPE_LISTENING);
        assert_eq!(r.state(s).unwrap(), PipeState::Listening);
        let c = r.connect_client("lsarpc").unwrap();
        assert_eq!(c.end(), PipeEnd::Client);
        assert_eq!(r.state(s).unwrap(), PipeState::Connected);
        assert_eq!(r.state(c).unwrap(), PipeState::Connected);
        assert!(r.conn(s).unwrap().is_connected());
    }

    #[test]
    fn message_pipe_client_connect_defaults_to_byte_read_mode() {
        let mut r = dx();
        let s = r.create_server_pipe("rpc", message_params()).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("rpc").unwrap();

        assert_eq!(
            r.query_pipe_information(s).unwrap(),
            PipeInformation {
                read_mode: FILE_PIPE_MESSAGE_MODE,
                completion_mode: FILE_PIPE_QUEUE_OPERATION,
            }
        );
        assert_eq!(
            r.query_pipe_information(c).unwrap(),
            PipeInformation {
                read_mode: FILE_PIPE_BYTE_STREAM_MODE,
                completion_mode: FILE_PIPE_QUEUE_OPERATION,
            }
        );

        r.pipe_write(s, b"HELLO").unwrap();
        let (part, more) = r.pipe_read(c, 3).unwrap();
        assert_eq!(&part, b"HEL");
        assert!(
            !more,
            "client read mode is byte stream until user mode changes it"
        );
        assert_eq!(r.pipe_read(c, 8).unwrap().0, b"LO");
    }

    #[test]
    fn file_pipe_information_switches_client_to_message_read_mode() {
        let mut r = dx();
        let s = r.create_server_pipe("rpc", message_params()).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("rpc").unwrap();

        set_message_read(&mut r, c);
        assert_eq!(
            r.query_pipe_information(c).unwrap(),
            PipeInformation {
                read_mode: FILE_PIPE_MESSAGE_MODE,
                completion_mode: FILE_PIPE_QUEUE_OPERATION,
            }
        );
        r.pipe_write(s, b"HELLO").unwrap();
        let (part, more) = r.pipe_read(c, 3).unwrap();
        assert_eq!(&part, b"HEL");
        assert!(more);
        assert_eq!(r.pipe_read(c, 8).unwrap().0, b"LO");
    }

    #[test]
    fn byte_read_consumes_message_boundaries_before_mode_switch() {
        let mut r = dx();
        let s = r.create_server_pipe("rpc", message_params()).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("rpc").unwrap();

        r.pipe_write(s, b"HELLO").unwrap();
        assert_eq!(r.pipe_read(c, 5).unwrap().0, b"HELLO");
        set_message_read(&mut r, c);
        r.pipe_write(s, b"ABC").unwrap();
        let (got, more) = r.pipe_read(c, 8).unwrap();
        assert_eq!(&got, b"ABC");
        assert!(
            !more,
            "drained byte-mode data must not leave a stale message boundary"
        );
    }

    #[test]
    fn byte_stream_pipe_rejects_message_read_mode() {
        let mut r = dx();
        let s = r.create_server_pipe("byte", PipeParams::default()).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("byte").unwrap();

        assert_eq!(
            r.set_pipe_information(
                c,
                PipeInformation {
                    read_mode: FILE_PIPE_MESSAGE_MODE,
                    completion_mode: FILE_PIPE_QUEUE_OPERATION,
                },
            )
            .unwrap_err(),
            NtStatus::INVALID_PARAMETER
        );
    }

    #[test]
    fn server_write_client_read_exact_bytes() {
        let mut r = dx();
        let s = r.create_server_pipe("p", PipeParams::default()).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("p").unwrap();
        let msg = b"NDR marshalled bytes";
        assert_eq!(r.pipe_write(s, msg).unwrap(), msg.len());
        assert_eq!(r.readable_bytes(c).unwrap(), msg.len());
        let (got, more) = r.pipe_read(c, 256).unwrap();
        assert_eq!(&got, msg);
        assert!(!more);
    }

    #[test]
    fn client_write_server_read_exact_bytes() {
        let mut r = dx();
        let s = r.create_server_pipe("p", PipeParams::default()).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("p").unwrap();
        let req = b"RPC bind request";
        assert_eq!(r.pipe_write(c, req).unwrap(), req.len());
        let (got, _) = r.pipe_read(s, 256).unwrap();
        assert_eq!(&got, req);
    }

    #[test]
    fn message_mode_client_write_server_partial_read_overflow() {
        // BATCH 37: rpcrt4's ncacn_np server reads a DCE/RPC bind PDU from a MESSAGE-mode pipe by
        // first reading only the 16-byte common header of the (72-byte) message, which must return the
        // FIRST 16 bytes WITH a truncation flag (npfs STATUS_BUFFER_OVERFLOW), leaving the remaining
        // 56 bytes queued for the next read. The executive's pipe re-drive must copy those partial
        // bytes to the reader even though the status is not SUCCESS — this reproduces that contract.
        let mut r = dx();
        let params = message_params();
        let s = r.create_server_pipe("ntsvcs", params).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("ntsvcs").unwrap();
        // A 72-byte "bind PDU": a recognizable header then filler.
        let mut bind: Vec<u8> = [
            0x05u8, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00,
        ]
        .to_vec();
        bind.extend((16u8..72).map(|i| i));
        assert_eq!(r.pipe_write(c, &bind).unwrap(), 72);
        // Server reads only the 16-byte common header → the FIRST 16 real bytes + truncation flag.
        let (hdr, more) = r.pipe_read(s, 16).unwrap();
        assert_eq!(
            &hdr,
            &bind[..16],
            "partial read must return the real header bytes, not garbage"
        );
        assert!(
            more,
            "a 16-of-72 message read must flag BUFFER_OVERFLOW (more)"
        );
        // The remaining 56 bytes of the SAME message are still queued and read next.
        let (rest, more2) = r.pipe_read(s, 256).unwrap();
        assert_eq!(&rest, &bind[16..]);
        assert!(!more2);
    }

    #[test]
    fn pending_read_completed_by_peer_write_returns_queue_bytes_not_stale() {
        // BATCH 38 — reproduces the pending-read/peer-write RECONCILE contract that the executive's
        // synthetic-IRP npfs host was violating. A server read issued when the queue is EMPTY must NOT
        // return a stale/uninitialized buffer; once the peer (client) writes, the SAME logical read must
        // return the REAL queued bytes. The clean DataQueue model is the source of truth: a read that
        // finds nothing yields empty (the executive parks the caller), and the later write fills the
        // queue so the re-driven read drains the ACTUAL bytes. (The executive bug was reading the read
        // IRP's ORIGINAL buffer instead of the buffer npfs REASSIGNED into AssociatedIrp.SystemBuffer on
        // completion, so the reader got 16 zero bytes; this model asserts the byte-exact reconcile.)
        let mut r = dx();
        let params = message_params();
        let s = r.create_server_pipe("ntsvcs", params).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("ntsvcs").unwrap();
        // Server reads FIRST (queue empty) — models the read that goes STATUS_PENDING and parks.
        let (empty, more0) = r.pipe_read(s, 16).unwrap();
        assert!(
            empty.is_empty(),
            "a read of an empty queue must return NO bytes (not stale garbage)"
        );
        assert!(!more0);
        // Peer write arrives; the re-driven read must now return the REAL queued header bytes.
        let bind: Vec<u8> = [
            0x05u8, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00,
        ]
        .to_vec();
        assert_eq!(r.pipe_write(c, &bind).unwrap(), 16);
        let (hdr, more) = r.pipe_read(s, 16).unwrap();
        assert_eq!(
            &hdr, &bind,
            "re-driven read must drain the ACTUAL queue bytes, not a stale buffer"
        );
        assert!(
            !more,
            "an exact-size read of a 16-byte message does not overflow"
        );
    }

    #[test]
    fn write_72_then_read_16_then_read_56_message_partial() {
        // BATCH 38 — the rpcrt4 header-then-body read pattern against a MESSAGE-mode pipe: a 72-byte
        // write, a 16-byte read (returns the first 16 WITH overflow), then a 56-byte read (drains the
        // rest, no overflow). Asserts the message-mode partial-read semantics the reconcile relies on.
        let mut r = dx();
        let params = message_params();
        let s = r.create_server_pipe("p", params).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("p").unwrap();
        let mut bind: Vec<u8> = [
            0x05u8, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00,
        ]
        .to_vec();
        bind.extend(16u8..72);
        assert_eq!(r.pipe_write(c, &bind).unwrap(), 72);
        let (h, more1) = r.pipe_read(s, 16).unwrap();
        assert_eq!(&h, &bind[..16]);
        assert!(more1, "16-of-72 must flag BUFFER_OVERFLOW (more)");
        let (rest, more2) = r.pipe_read(s, 56).unwrap();
        assert_eq!(
            &rest,
            &bind[16..],
            "the remaining 56 bytes of the SAME message"
        );
        assert!(!more2, "the message is now fully drained");
        assert_eq!(r.readable_bytes(s).unwrap(), 0);
    }

    #[test]
    fn bidirectional_queues_are_isolated() {
        let mut r = dx();
        let s = r.create_server_pipe("p", PipeParams::default()).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("p").unwrap();
        r.pipe_write(s, b"s2c").unwrap();
        r.pipe_write(c, b"c2s").unwrap();
        // Each end reads only the other's writes; no crosstalk.
        let (at_c, _) = r.pipe_read(c, 16).unwrap();
        let (at_s, _) = r.pipe_read(s, 16).unwrap();
        assert_eq!(&at_c, b"s2c");
        assert_eq!(&at_s, b"c2s");
        // Both drained.
        assert_eq!(r.readable_bytes(c).unwrap(), 0);
        assert_eq!(r.readable_bytes(s).unwrap(), 0);
    }

    #[test]
    fn create_starts_listening_and_client_connect_pairs() {
        let mut r = dx();
        let s = r.create_server_pipe("p", PipeParams::default()).unwrap();
        // ReactOS NPFS `NtCreateNamedPipeFile` initializes new CCBs in
        // FILE_PIPE_LISTENING_STATE, and `NpCreateClientEnd` only connects to
        // listening instances.
        assert_eq!(r.state(s).unwrap(), PipeState::Listening);
        let c = r.connect_client("p").unwrap();
        assert_eq!(r.state(s).unwrap(), PipeState::Connected);
        assert_eq!(r.listen(s).unwrap(), STATUS_PIPE_CONNECTED);
        r.pipe_write(s, b"hi").unwrap();
        assert_eq!(r.pipe_read(c, 8).unwrap().0, b"hi");
    }

    #[test]
    fn connect_without_server_fails() {
        let mut r = dx();
        assert_eq!(
            r.connect_client("nope").unwrap_err(),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
    }

    #[test]
    fn second_client_finds_no_instance() {
        let mut r = dx();
        let s = r.create_server_pipe("p", PipeParams::default()).unwrap();
        r.listen(s).unwrap();
        let _c1 = r.connect_client("p").unwrap();
        // Only one instance; the second connect has nothing to pair with.
        assert_eq!(
            r.connect_client("p").unwrap_err(),
            STATUS_PIPE_NOT_AVAILABLE
        );
    }

    #[test]
    fn multiple_instances_pair_independently() {
        let mut r = dx();
        let p = PipeParams {
            max_instances: 2,
            ..PipeParams::default()
        };
        let s1 = r.create_server_pipe("ntsvcs", p).unwrap();
        let s2 = r.create_server_pipe("ntsvcs", p).unwrap();
        r.listen(s1).unwrap();
        r.listen(s2).unwrap();
        let c1 = r.connect_client("ntsvcs").unwrap();
        let c2 = r.connect_client("ntsvcs").unwrap();
        // Distinct connections.
        assert_ne!((s1.conn, c1.conn), (s2.conn, c2.conn));
        r.pipe_write(s1, b"one").unwrap();
        r.pipe_write(s2, b"two").unwrap();
        assert_eq!(r.pipe_read(c1, 8).unwrap().0, b"one");
        assert_eq!(r.pipe_read(c2, 8).unwrap().0, b"two");
    }

    #[test]
    fn closing_one_instance_does_not_retarget_other_handles() {
        let mut r = dx();
        let p = PipeParams {
            max_instances: 2,
            ..PipeParams::default()
        };
        let s1 = r.create_server_pipe("ntsvcs", p).unwrap();
        let s2 = r.create_server_pipe("ntsvcs", p).unwrap();
        r.listen(s1).unwrap();
        r.listen(s2).unwrap();
        let c1 = r.connect_client("ntsvcs").unwrap();
        let c2 = r.connect_client("ntsvcs").unwrap();

        r.pipe_write(s2, b"second").unwrap();
        r.disconnect(c1).unwrap();
        r.disconnect(s1).unwrap();

        assert_eq!(r.state(s1).unwrap_err(), NtStatus::INVALID_HANDLE);
        assert_eq!(r.state(s2).unwrap(), PipeState::Connected);
        assert_eq!(r.state(c2).unwrap(), PipeState::Connected);
        assert_eq!(r.pipe_read(c2, 16).unwrap().0, b"second");
    }

    #[test]
    fn max_instances_enforced() {
        let mut r = dx();
        let p = PipeParams {
            max_instances: 1,
            ..PipeParams::default()
        };
        r.create_server_pipe("x", p).unwrap();
        assert_eq!(
            r.create_server_pipe("x", p).unwrap_err(),
            STATUS_INSTANCE_NOT_AVAILABLE
        );
    }

    #[test]
    fn transceive_round_trips() {
        // Model an RPC request/reply. The first transceive queues the request and pends because the
        // reply is not available yet; the later read drains the reply bytes.
        let mut r = dx();
        let params = message_params();
        let s = r.create_server_pipe("p", params).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("p").unwrap();
        set_message_read(&mut r, c);
        assert_eq!(r.transceive(c, b"req", 16), Err(STATUS_PENDING));
        // Server reads it and writes the reply.
        assert_eq!(r.pipe_read(s, 16).unwrap().0, b"req");
        r.pipe_write(s, b"reply").unwrap();
        let (reply, _more) = r.pipe_read(c, 16).unwrap();
        assert_eq!(&reply, b"reply");
    }

    #[test]
    fn transceive_without_reply_pends_after_queuing_request() {
        let mut r = dx();
        let params = message_params();
        let s = r.create_server_pipe("ntcontrol", params).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("ntcontrol").unwrap();
        set_message_read(&mut r, c);

        assert_eq!(r.transceive(c, b"svc-control", 4), Err(STATUS_PENDING));
        assert_eq!(
            r.transceive(c, b"duplicate", 4),
            Err(STATUS_PIPE_BUSY),
            "the retained read, not an executive slot, enforces one transaction per endpoint"
        );

        let (request, more) = r.pipe_read(s, 64).unwrap();
        assert_eq!(&request, b"svc-control");
        assert!(!more);
        assert_eq!(r.readable_bytes(c).unwrap(), 0);
    }

    #[test]
    fn zero_output_transceive_still_queues_its_exact_read() {
        let mut r = dx();
        let s = r.create_server_pipe("zero", message_params()).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("zero").unwrap();
        set_message_read(&mut r, c);

        assert_eq!(r.transceive(c, b"request", 0), Err(STATUS_PENDING));
        assert_eq!(r.transceive(c, b"second", 0), Err(STATUS_PIPE_BUSY));
        assert_eq!(r.pipe_read(s, 64).unwrap().0, b"request");
        r.pipe_write(s, b"response").unwrap();
        assert_eq!(r.transceive(c, b"third", 0), Err(STATUS_PIPE_BUSY));
        assert_eq!(r.pipe_read(c, 64).unwrap().0, b"response");
        assert_eq!(r.transceive(c, b"third", 0), Err(STATUS_PENDING));
        assert_eq!(r.pipe_read(s, 64).unwrap().0, b"third");
    }

    #[test]
    fn transceive_rejects_unread_reply_without_writing_request() {
        let mut r = dx();
        let params = message_params();
        let s = r.create_server_pipe("busy", params).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("busy").unwrap();
        set_message_read(&mut r, c);

        r.pipe_write(s, b"old-reply").unwrap();
        assert_eq!(r.transceive(c, b"new-request", 16), Err(STATUS_PIPE_BUSY));
        assert_eq!(r.readable_bytes(c).unwrap(), b"old-reply".len());
        assert_eq!(r.readable_bytes(s).unwrap(), 0);
    }

    #[test]
    fn message_mode_reads_one_message_at_a_time() {
        let mut r = dx();
        let p = message_params();
        let s = r.create_server_pipe("m", p).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("m").unwrap();
        set_message_read(&mut r, c);
        r.pipe_write(s, b"AAA").unwrap();
        r.pipe_write(s, b"BB").unwrap();
        // First read returns exactly the first message, not both coalesced.
        assert_eq!(r.pipe_read(c, 64).unwrap().0, b"AAA");
        assert_eq!(r.pipe_read(c, 64).unwrap().0, b"BB");
    }

    #[test]
    fn message_mode_truncation_reports_more() {
        let mut r = dx();
        let p = message_params();
        let s = r.create_server_pipe("m", p).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("m").unwrap();
        set_message_read(&mut r, c);
        r.pipe_write(s, b"HELLO").unwrap();
        let (part1, more1) = r.pipe_read(c, 3).unwrap();
        assert_eq!(&part1, b"HEL");
        assert!(more1); // BUFFER_OVERFLOW: message continues
        let (part2, more2) = r.pipe_read(c, 3).unwrap();
        assert_eq!(&part2, b"LO");
        assert!(!more2);
    }

    #[test]
    fn byte_mode_coalesces_writes() {
        let mut r = dx();
        let s = r.create_server_pipe("b", PipeParams::default()).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("b").unwrap();
        r.pipe_write(s, b"AB").unwrap();
        r.pipe_write(s, b"CD").unwrap();
        // Byte stream: a single read can span both writes.
        assert_eq!(r.pipe_read(c, 64).unwrap().0, b"ABCD");
    }

    #[test]
    fn disconnect_client_marks_closing_then_read_errors() {
        let mut r = dx();
        let s = r.create_server_pipe("p", PipeParams::default()).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("p").unwrap();
        r.pipe_write(c, b"tail").unwrap();
        r.disconnect(c).unwrap();
        // The server can still drain the bytes the client already wrote.
        assert_eq!(r.pipe_read(s, 16).unwrap().0, b"tail");
        // Then further reads on the now-closing pipe error.
        assert_eq!(r.pipe_read(s, 16).unwrap_err(), STATUS_PIPE_DISCONNECTED);
    }

    #[test]
    fn disconnect_both_ends_removes_connection() {
        let mut r = dx();
        let s = r.create_server_pipe("p", PipeParams::default()).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("p").unwrap();
        r.disconnect(c).unwrap();
        r.disconnect(s).unwrap();
        // The connection slot is gone; the pipe FCB survives (a server could
        // create a fresh instance), but this handle no longer resolves.
        assert_eq!(r.state(s).unwrap_err(), NtStatus::INVALID_HANDLE);
    }

    #[test]
    fn write_on_disconnected_pipe_errors() {
        let mut r = dx();
        let s = r.create_server_pipe("p", PipeParams::default()).unwrap();
        // Not connected yet.
        assert_eq!(r.pipe_write(s, b"x").unwrap_err(), STATUS_PIPE_DISCONNECTED);
    }

    #[test]
    fn quota_limits_accepted_bytes() {
        let mut r = dx();
        let p = PipeParams {
            outbound_quota: 4,
            ..PipeParams::default()
        };
        let s = r.create_server_pipe("q", p).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("q").unwrap();
        // Server→client queue holds only 4 bytes.
        assert_eq!(r.pipe_write(s, b"ABCDEFGH").unwrap(), 4);
        assert_eq!(r.pipe_read(c, 64).unwrap().0, b"ABCD");
    }

    #[test]
    fn half_duplex_inbound_rejects_wrong_direction() {
        let mut r = dx();
        let p = PipeParams {
            configuration: FILE_PIPE_INBOUND as u32,
            ..PipeParams::default()
        };
        let s = r.create_server_pipe("hd", p).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("hd").unwrap();
        // INBOUND pipe: client→server allowed, server→client rejected.
        assert_eq!(r.pipe_write(c, b"ok").unwrap(), 2);
        assert_eq!(
            r.pipe_write(s, b"no").unwrap_err(),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(r.pipe_read(s, 8).unwrap().0, b"ok");
    }

    #[test]
    fn reactos_npfs_endpoint_file_ids_decode_and_pair() {
        let ccb = 0x1000_4000;
        let client_fid = pipe_endpoint_file_id(ccb, PipeEnd::Client).unwrap();
        let server_fid = pipe_endpoint_file_id(ccb, PipeEnd::Server).unwrap();

        assert_eq!(client_fid, ccb | FILE_PIPE_CLIENT_END as u64);
        assert_eq!(server_fid, ccb | FILE_PIPE_SERVER_END as u64);
        assert_eq!(pipe_endpoint_primary_context(client_fid), Some(ccb));
        assert_eq!(pipe_endpoint_primary_context(server_fid), Some(ccb));
        assert_eq!(pipe_endpoint_end(client_fid), Some(PipeEnd::Client));
        assert_eq!(pipe_endpoint_end(server_fid), Some(PipeEnd::Server));
        assert_eq!(
            pipe_server_file_id_for_endpoint(client_fid),
            Some(server_fid)
        );
        assert_eq!(
            pipe_server_file_id_for_endpoint(server_fid),
            Some(server_fid)
        );

        assert_eq!(pipe_endpoint_primary_context(0), None);
        assert_eq!(pipe_endpoint_primary_context(1), None);
        assert_eq!(pipe_endpoint_end(0), None);
        assert_eq!(pipe_server_file_id_for_endpoint(1), None);
        assert_eq!(pipe_endpoint_file_id(0, PipeEnd::Client), None);
        assert_eq!(pipe_endpoint_file_id(1, PipeEnd::Server), None);
    }

    #[test]
    fn pipe_fid_name_table_grows_updates_and_rejects_zero() {
        let ntsvcs: std::vec::Vec<u16> = "\\ntsvcs".encode_utf16().collect();
        let lsarpc: std::vec::Vec<u16> = "\\lsarpc".encode_utf16().collect();
        let ntsvcs_hash = pipe_name_hash(&ntsvcs);
        let lsarpc_hash = pipe_name_hash(&lsarpc);
        let mut table = PipeFidNameTable::new();

        assert!(table.is_empty());
        assert!(table.remember(0, ntsvcs_hash).is_err());
        assert!(table.remember(0x10, 0).is_err());
        for i in 0..40 {
            table.remember(0x100 + i, ntsvcs_hash).unwrap();
        }
        assert_eq!(table.len(), 40);
        assert_eq!(table.name_hash(0x123), Some(ntsvcs_hash));
        assert!(table.contains_name_hash(ntsvcs_hash));
        assert!(!table.contains_name_hash(0));

        table.remember(0x123, lsarpc_hash).unwrap();
        assert_eq!(table.len(), 40, "updating a fid does not duplicate it");
        assert_eq!(table.name_hash(0x123), Some(lsarpc_hash));
        assert!(table.contains_name_hash(lsarpc_hash));
        assert!(table.forget(0x123));
        assert_eq!(table.name_hash(0x123), None);
        assert_eq!(table.len(), 39);
        assert!(!table.forget(0x123));
    }

    #[test]
    fn pipe_provider_tables_reserve_publication_without_late_growth() {
        let mut names = PipeFidNameTable::new();
        assert!(names.ensure_capacity());
        let names_capacity = names.capacity();
        names.remember(0x101, 0xA1).unwrap();
        assert_eq!(names.capacity(), names_capacity);

        let mut preconnected = PipePreconnectedServerTable::new();
        assert!(preconnected.ensure_capacity());
        let preconnected_capacity = preconnected.capacity();
        assert_eq!(preconnected.remember(0x101), Ok(true));
        assert_eq!(preconnected.capacity(), preconnected_capacity);
    }

    #[test]
    fn pipe_preconnected_server_table_consumes_exactly_once() {
        let mut table = PipePreconnectedServerTable::new();

        assert!(table.remember(0).is_err());
        assert!(table.is_empty());

        assert_eq!(table.remember(0x301), Ok(true));
        assert_eq!(table.remember(0x301), Ok(false));
        assert!(table.contains(0x301));
        assert!(!table.contains(0x303));
        assert_eq!(table.len(), 1);

        assert!(table.take(0x301));
        assert!(!table.take(0x301));
        assert!(table.is_empty());
    }

    #[test]
    fn half_duplex_outbound_rejects_wrong_direction_read() {
        // The READ direction check (read.c:70): on an OUTBOUND pipe the server may NOT read (it only
        // writes); the client may. Only the WRITE direction was covered before — this exercises the
        // read-side direction_ok_read branch.
        let mut r = dx();
        let p = PipeParams {
            configuration: FILE_PIPE_OUTBOUND as u32,
            ..PipeParams::default()
        };
        let s = r.create_server_pipe("hdo", p).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("hdo").unwrap();
        // OUTBOUND: server→client allowed, client→server write rejected.
        assert_eq!(r.pipe_write(s, b"ok").unwrap(), 2);
        assert_eq!(
            r.pipe_write(c, b"no").unwrap_err(),
            NtStatus::INVALID_PARAMETER
        );
        // Server READ is the wrong direction on an OUTBOUND pipe → rejected.
        assert_eq!(r.pipe_read(s, 8).unwrap_err(), NtStatus::INVALID_PARAMETER);
        // Client read of the server's write is allowed.
        assert_eq!(r.pipe_read(c, 8).unwrap().0, b"ok");
    }

    #[test]
    fn read_zero_max_returns_empty_without_draining() {
        // A zero-length read must return no bytes and NOT touch the queue (dequeue max==0 early-out).
        let mut r = dx();
        let s = r.create_server_pipe("z", PipeParams::default()).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("z").unwrap();
        r.pipe_write(s, b"keepme").unwrap();
        let (got, more) = r.pipe_read(c, 0).unwrap();
        assert!(got.is_empty());
        assert!(!more);
        // Nothing was consumed.
        assert_eq!(r.readable_bytes(c).unwrap(), 6);
        assert_eq!(r.pipe_read(c, 64).unwrap().0, b"keepme");
    }

    #[test]
    fn write_to_full_queue_accepts_zero() {
        // enqueue on a queue with NO room returns 0 (the room==0 early-out) — a second write once the
        // quota is exhausted is accepted-what-fits = nothing, not a panic or overwrite.
        let mut r = dx();
        let p = PipeParams {
            outbound_quota: 4,
            ..PipeParams::default()
        };
        let s = r.create_server_pipe("full", p).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("full").unwrap();
        assert_eq!(r.pipe_write(s, b"ABCD").unwrap(), 4); // fills the quota exactly
        assert_eq!(
            r.pipe_write(s, b"EF").unwrap(),
            0,
            "no room left → 0 accepted"
        );
        // The queued bytes are intact and untouched by the rejected write.
        assert_eq!(r.pipe_read(c, 64).unwrap().0, b"ABCD");
    }

    #[test]
    fn transceive_requires_full_duplex_message_mode() {
        // ReactOS NpTransceive checks full-duplex + message read mode before attempting the write.
        // On an INBOUND pipe the transaction is invalid and must not queue request bytes.
        let mut r = dx();
        let p = PipeParams {
            configuration: FILE_PIPE_INBOUND as u32,
            ..PipeParams::default()
        };
        let s = r.create_server_pipe("inb", p).unwrap();
        r.listen(s).unwrap();
        let _c = r.connect_client("inb").unwrap();
        assert_eq!(
            r.transceive(s, b"x", 16).unwrap_err(),
            STATUS_INVALID_PIPE_STATE
        );
    }

    #[test]
    fn transceive_on_disconnected_pipe_errors() {
        // ReactOS NpTransceive decodes the CCB, then rejects a non-connected pipe state before writing.
        let mut r = dx();
        let s = r.create_server_pipe("d", PipeParams::default()).unwrap();
        assert_eq!(
            r.transceive(s, b"x", 16).unwrap_err(),
            STATUS_INVALID_PIPE_STATE
        );
    }
}
