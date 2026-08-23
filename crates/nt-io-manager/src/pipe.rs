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

const FILE_PIPE_WAIT_NAME_OFFSET: usize = 14;

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
        Ok(conn.queues[qidx].enqueue(data, msg))
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
            if conn.readable_bytes(h.end) != 0 {
                return Err(STATUS_PIPE_BUSY);
            }
        }
        let written = self.pipe_write(h, out)?;
        let (bytes, more) = self.pipe_read(h, max)?;
        if bytes.is_empty() && max != 0 {
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

// ─────────────────────────────────────────────────────────────────────────────
// Pipe-pending completion: the cross-thread park/re-drive bookkeeping (BATCH 33)
// ─────────────────────────────────────────────────────────────────────────────
//
// The live executive runs the REAL isolated npfs.sys as its pipe data plane. A
// blocking pipe read / FSCTL_PIPE_LISTEN / TRANSCEIVE on an empty pipe returns
// STATUS_PENDING and, previously, was returned straight to the caller with no
// re-drive — so a server listener parked on its receive never woke when the peer
// wrote, and the client's own read got RPC_X_BAD_STUB_DATA.
//
// The fix generalizes the EVENT park/wake edge (a caller blocks with its seL4
// reply cap withheld; a later signal replies to that cap to wake the thread) to
// pipe data. The seL4-cap side (steal REPLY_MAIN, snapshot RCX/RSP/RFLAGS, send
// on the stolen cap) stays in the executive — it needs kernel invocations. The
// PURE bookkeeping (which reads are parked, their npfs file-id + user
// buffer/IOSB VAs + owning process + resume context) lives here so it is
// host-testable: park-on-empty, re-drive-on-peer-write, re-armable (a slot frees
// after a wake and can be re-parked for the next PDU), and bidirectional (server
// and client sides park independently, keyed by their own file-id).
//
// The executive does NOT need a peer→reader map: each waiter carries the exact
// canonical IRP retained by npfs. On a progress edge it pumps the driver
// completion broker and probes those exact ids; `complete` frees only the slots
// whose terminal completion was delivered.

pub const IO_DELIVERY_BUFFER_PUBLISHED: u16 = 1 << 0;
pub const IO_DELIVERY_IOSB_PUBLISHED: u16 = 1 << 1;
pub const IO_DELIVERY_APC_PUBLISHED: u16 = 1 << 2;
pub const IO_DELIVERY_FILE_PUBLISHED: u16 = 1 << 3;
pub const IO_DELIVERY_IOCP_PUBLISHED: u16 = 1 << 4;
pub const IO_DELIVERY_EVENT_PUBLISHED: u16 = 1 << 5;
pub const IO_DELIVERY_REPLY_CLAIMED: u16 = 1 << 6;
pub const IO_DELIVERY_REPLY_PUBLISHED: u16 = 1 << 7;

/// One parked pipe read awaiting peer data. All fields are the executive-side
/// context needed to complete the read when data arrives: the owning device id,
/// exact canonical IRP, the npfs `file_id` used for file-completion bookkeeping,
/// the owning process index + thread id (whose VSpace/stack-mirror the bytes land in), the
/// user `buffer`/`iosb` VAs, the buffer length, the seL4 reply cap held for the
/// blocked thread, and its native-syscall resume context (RCX/RSP/RFLAGS). The
/// pure table treats them as opaque values. `file_id` participates in the
/// table's duplicate-waiter policy; completion ownership is always `irp_id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PipeWaiter {
    /// NT I/O manager device id that owns `file_id`.
    pub device_id: u64,
    /// npfs `FsContext` of the READING end this waiter is blocked on (the slot key).
    pub file_id: u64,
    /// Exact generation-protected canonical IRP retained by the I/O Manager.
    pub irp_id: u64,
    /// Completion surfaces already published for this exact IRP.
    pub delivery_state: u16,
    /// Owning process index (which VSpace / stack-mirror to write the bytes into).
    pub pi: u32,
    /// The blocked thread id (for diagnostics / targeted cancel).
    pub tid: u64,
    /// The caller's fault-EP badge (which per-thread reply/mirror context to restore).
    pub badge: u64,
    /// User buffer VA the read data must be copied into.
    pub buffer_va: u64,
    /// User buffer capacity (bytes).
    pub buffer_len: u32,
    /// User IO_STATUS_BLOCK VA (status + information written on completion).
    pub iosb_va: u64,
    /// Optional user APC normal routine to queue when the IRP completes.
    pub apc_routine: u64,
    /// Caller APC/OVERLAPPED context copied into an associated completion-port packet.
    pub apc_context: u64,
    /// Whether the initiating operation tagged its event handle to suppress IOCP notification.
    pub completion_port_suppressed: bool,
    /// Executive event-object index to signal on completion (`u64::MAX` for no event).
    pub event_obj_idx: u64,
    /// The stolen seL4 MCS reply cap that resumes the blocked thread.
    /// Zero identifies asynchronous I/O whose initiating syscall already returned STATUS_PENDING.
    pub reply_cap: u64,
    /// Native-syscall resume context: RCX (return IP), RSP, RFLAGS.
    pub resume_ip: u64,
    pub resume_sp: u64,
    pub resume_flags: u64,
    /// `true` if this waiter parked on FSCTL_PIPE_TRANSCEIVE (must re-read then
    /// return via the FSCTL output path), `false` for a plain NtReadFile.
    pub is_transceive: bool,
    /// `true` for a pending NtWriteFile. Write completions carry no read buffer.
    pub is_write: bool,
}

const PIPE_TABLE_DEFAULT_INITIAL_RESERVE: usize = 16;

/// Reset-safe table of parked pipe reads/writes.
///
/// The first reservation size is not a hard NT limit. Real service startup can legitimately have many
/// RPC servers and driver control pipes with pending reads at once, so the table grows on demand.
/// Parking fails only if allocation for the next waiter record fails.
#[derive(Clone, Debug)]
pub struct PipeWaiterTable {
    slots: Vec<Option<PipeWaiter>>,
    initial_reserve: usize,
}

impl Default for PipeWaiterTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PipeWaiterTable {
    pub const fn new() -> Self {
        Self::with_initial_reserve(PIPE_TABLE_DEFAULT_INITIAL_RESERVE)
    }

    pub const fn with_initial_reserve(initial_reserve: usize) -> Self {
        Self {
            slots: Vec::new(),
            initial_reserve,
        }
    }

    fn grow_reservation(&mut self) -> bool {
        if self.slots.len() == self.slots.capacity() {
            let reserve = if self.slots.capacity() == 0 {
                self.initial_reserve.max(1)
            } else {
                1
            };
            if self.slots.try_reserve(reserve).is_err() {
                return false;
            }
        }
        true
    }

    /// Clear stale records and reserve the configured bootstrap storage before an allocator
    /// watermark is taken. The executive keeps this table alive across syscall-loop rewinds.
    pub fn reset(&mut self) -> bool {
        self.slots.clear();
        if self.slots.capacity() < self.initial_reserve {
            let additional = self.initial_reserve - self.slots.capacity();
            if self.slots.try_reserve(additional).is_err() {
                return false;
            }
        }
        true
    }

    /// Ensure one future [`park`](Self::park) call can record a distinct waiter without allocating at
    /// the post-IRP park point. The executive calls this before issuing an operation that may pend, so a
    /// successful NPFS pending IRP always has storage for its completion owner.
    pub fn ensure_capacity(&mut self) -> bool {
        if self.slots.iter().any(|slot| slot.is_none()) || self.slots.len() < self.slots.capacity()
        {
            return true;
        }
        self.grow_reservation()
    }

    /// Park `w` in a free slot. Returns the slot index, or `None` if the table cannot allocate the next
    /// record.
    ///
    /// Re-armable by construction: a slot freed by [`complete_exact`](Self::complete_exact) or
    /// [`cancel_thread`](Self::cancel_thread) becomes `None` and is immediately
    /// reusable for the next PDU's read on the same or a different file-id.
    pub fn park(&mut self, w: PipeWaiter) -> Option<usize> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(w);
                return Some(i);
            }
        }
        if !self.grow_reservation() {
            return None;
        }
        self.slots.push(Some(w));
        Some(self.slots.len() - 1)
    }

    /// Number of currently parked waiters.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(|s| s.is_none())
    }

    pub fn has_capacity(&self) -> bool {
        self.slots.iter().any(|slot| slot.is_none()) || self.slots.len() < self.slots.capacity()
    }

    pub fn capacity(&self) -> usize {
        self.slots.capacity()
    }

    /// Whether `tid` currently owns any retained pending read/transceive IRP.
    pub fn has_thread(&self, tid: u64) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.is_some_and(|waiter| waiter.tid == tid))
    }

    /// A snapshot copy of every parked waiter, for the executive to re-drive on a
    /// peer write. Copies (not references) so the executive can call npfs +
    /// `complete` without borrowing the table across its `&mut self` npfs route.
    /// Order is stable (slot order) so re-drives are deterministic.
    pub fn drain_all(&self) -> impl Iterator<Item = (usize, PipeWaiter)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.map(|w| (i, w)))
    }

    /// The parked waiter in `slot`, if any (peek without removing).
    pub fn get(&self, slot: usize) -> Option<PipeWaiter> {
        self.slots.get(slot).copied().flatten()
    }

    /// Remove `slot` only when it still names the snapshotted canonical IRP.
    pub fn complete_exact(&mut self, slot: usize, irp_id: u64) -> Option<PipeWaiter> {
        let entry = self.slots.get_mut(slot)?;
        if entry.is_some_and(|waiter| waiter.irp_id == irp_id) {
            entry.take()
        } else {
            None
        }
    }

    /// Record one successfully published completion surface for the exact waiter generation.
    pub fn mark_delivery_exact(&mut self, slot: usize, irp_id: u64, flag: u16) -> Option<u16> {
        let waiter = self.slots.get_mut(slot)?.as_mut()?;
        if waiter.irp_id != irp_id {
            return None;
        }
        waiter.delivery_state |= flag;
        Some(waiter.delivery_state)
    }

    /// Atomically transfer the exact waiter's reply cap to the completion publisher. `Some(None)`
    /// means another publisher already owns it; `None` means the slot generation did not match.
    pub fn claim_reply_cap_exact(&mut self, slot: usize, irp_id: u64) -> Option<Option<u64>> {
        let waiter = self.slots.get_mut(slot)?.as_mut()?;
        if waiter.irp_id != irp_id {
            return None;
        }
        if waiter.delivery_state & IO_DELIVERY_REPLY_CLAIMED != 0 {
            return Some(None);
        }
        let reply_cap = core::mem::replace(&mut waiter.reply_cap, 0);
        waiter.delivery_state |= IO_DELIVERY_REPLY_CLAIMED;
        Some(Some(reply_cap))
    }

    /// Cancel + free any waiter owned by `tid`, invoking `complete` with every removed waiter. This
    /// is the thread-teardown form: the caller owns completing or abandoning the retained I/O in the
    /// real driver before releasing the table slot.
    pub fn cancel_thread_with<F>(&mut self, tid: u64, mut complete: F) -> usize
    where
        F: FnMut(PipeWaiter),
    {
        let mut count = 0;
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|waiter| waiter.delivery_state == 0 && waiter.tid == tid) {
                let waiter = slot.take().unwrap();
                complete(waiter);
                count += 1;
            }
        }
        count
    }

    /// Cancel + free any waiter owned by `tid` for `file_id`, invoking `complete` with every removed
    /// waiter. This models `NtCancelIoFile`: only IRPs issued by the current thread for the target
    /// FILE_OBJECT are cancelled, and the caller owns finalizing the waiter surfaces.
    pub fn cancel_thread_file_with<F>(&mut self, tid: u64, file_id: u64, mut complete: F) -> usize
    where
        F: FnMut(PipeWaiter),
    {
        let mut count = 0;
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|waiter| {
                waiter.delivery_state == 0 && waiter.tid == tid && waiter.file_id == file_id
            }) {
                let waiter = slot.take().unwrap();
                complete(waiter);
                count += 1;
            }
        }
        count
    }

    /// Is there already a parked read on `file_id`? (Guards double-parking the
    /// same reading end — a listener that re-issues its read while still parked.)
    pub fn parked_on(&self, file_id: u64) -> bool {
        self.slots
            .iter()
            .any(|s| s.is_some_and(|w| w.file_id == file_id && w.delivery_state == 0))
    }

    /// Whether `file_id` already has a parked waiter **in this DIRECTION** (`is_write`).
    ///
    /// ★ Why direction matters. `parked_on` alone says "this connection already has an outstanding
    /// operation", and using it to gate a new park makes a connection strictly half-duplex. That is
    /// wrong for the one shape every rpcrt4 ncacn_np SERVER has: `RPCRT4_io_thread` keeps a READ
    /// pending on the connection for the next PDU while `RPCRT4_worker_thread` writes the RESPONSE
    /// on the SAME connection. Refusing the write there is not a hang but a silent functional
    /// degrade — the caller gets `STATUS_INSUFFICIENT_RESOURCES` for an I/O that should merely have
    /// completed later. That is precisely how the LSA self-RPC lost its 48-byte `LsarOpenPolicy`
    /// RESPONSE, so `LsaOpenPolicy` never returned to samsrv.
    ///
    /// One pending read AND one pending write per connection is exactly what the completion broker
    /// supports: `pipe_write_redrive` completes each waiter by its distinct canonical IRP id, so
    /// the two never collide.
    pub fn parked_on_dir(&self, file_id: u64, is_write: bool) -> bool {
        self.slots.iter().any(|s| {
            s.is_some_and(|w| {
                w.file_id == file_id && w.is_write == is_write && w.delivery_state == 0
            })
        })
    }
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

/// Availability of server pipe instances by exact server FILE_OBJECT and name.
///
/// The fid-name table answers "does this pipe name exist in the namespace?". This table answers the
/// stronger `FSCTL_PIPE_WAIT` question: "is there a server instance a client can connect to right
/// now?". A fresh `NtCreateNamedPipeFile` starts in `Listening` state, so it is available before
/// user mode posts an explicit `FSCTL_PIPE_LISTEN`. A successful client create consumes exactly the
/// accepted server fid, leaving other same-name instances available.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PipeServerAvailability {
    pub server_file_id: u64,
    pub name_hash: u64,
    pub available: bool,
}

#[derive(Clone, Debug)]
pub struct PipeServerAvailabilityTable {
    entries: Vec<PipeServerAvailability>,
}

impl Default for PipeServerAvailabilityTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PipeServerAvailabilityTable {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn mark_available(&mut self, server_file_id: u64, name_hash: u64) -> Result<(), ()> {
        if server_file_id == 0 || name_hash == 0 {
            return Err(());
        }
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.server_file_id == server_file_id)
        {
            entry.name_hash = name_hash;
            entry.available = true;
            return Ok(());
        }
        if self.entries.len() == self.entries.capacity() {
            let reserve = if self.entries.capacity() == 0 { 32 } else { 1 };
            self.entries.try_reserve(reserve).map_err(|_| ())?;
        }
        self.entries.push(PipeServerAvailability {
            server_file_id,
            name_hash,
            available: true,
        });
        Ok(())
    }

    pub fn consume(&mut self, server_file_id: u64) -> bool {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.server_file_id == server_file_id)
        {
            let was_available = entry.available;
            entry.available = false;
            was_available
        } else {
            false
        }
    }

    pub fn remove(&mut self, server_file_id: u64) -> bool {
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.server_file_id == server_file_id)
        {
            self.entries.swap_remove(index);
            true
        } else {
            false
        }
    }

    pub fn available_name(&self, name_hash: u64) -> bool {
        name_hash != 0
            && self
                .entries
                .iter()
                .any(|entry| entry.available && entry.name_hash == name_hash)
    }

    pub fn is_available(&self, server_file_id: u64) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.server_file_id == server_file_id && entry.available)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn available_len(&self) -> usize {
        self.entries.iter().filter(|entry| entry.available).count()
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

/// A pending async server-side `FSCTL_PIPE_LISTEN` awaiting a client connect. Keyed by the SERVER
/// end's npfs `file_id`. On peer connect the executive consumes its exact IRP completion, fills
/// `iosb_va` in the server's VSpace, and signals `event_obj_idx`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AsyncListen {
    /// NT I/O manager device id that owns `server_file_id`.
    pub device_id: u64,
    /// npfs `FsContext` of the SERVER end that posted FSCTL_PIPE_LISTEN (the slot key).
    pub server_file_id: u64,
    /// Exact generation-protected canonical listen IRP retained by the I/O Manager.
    pub irp_id: u64,
    /// Completion surfaces already published for this exact IRP.
    pub delivery_state: u16,
    /// The obj_ns EVENT index (resolved in the SERVER's handle table at listen time) to SIGNAL on
    /// completion — the overlapped listen's completion Event. `u64::MAX` = no event (rare).
    pub event_obj_idx: u64,
    /// The server process index (whose VSpace the listen IOSB is written into).
    pub pi: u32,
    /// The thread that issued this pending listen IRP.
    pub tid: u64,
    /// The listener thread's fault-EP badge (for the mirror-context switch during the IOSB copyout).
    pub badge: u64,
    /// The listen IO_STATUS_BLOCK VA (filled `{Status=SUCCESS, Information=0}` on completion).
    pub iosb_va: u64,
    /// Optional user APC normal routine to queue when the listen completes.
    pub apc_routine: u64,
    /// The I/O completion key/APC context passed to NtFsControlFile.
    pub apc_context: u64,
    /// Whether the initiating operation tagged its event handle to suppress IOCP notification.
    pub completion_port_suppressed: bool,
    /// A stable hash of the SERVER pipe leaf name (`\ntsvcs`, `\lsarpc`, ...). This is used by
    /// `FSCTL_PIPE_WAIT` readiness probes before a client owns a connected CCB. Client connects
    /// complete async listens by the exact server-end fid chosen by NPFS, not by this hash.
    pub name_hash: u64,
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

/// Decode the variable-sized `FILE_PIPE_WAIT_FOR_BUFFER` payload used by
/// `FSCTL_PIPE_WAIT`. The returned name is the caller-provided pipe suffix; the
/// object-manager/NPFS bridge is responsible for applying its namespace prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipeWaitRequest {
    /// Timeout from `FILE_PIPE_WAIT_FOR_BUFFER::Timeout` in NT 100ns units.
    pub timeout_100ns: i64,
    /// `FILE_PIPE_WAIT_FOR_BUFFER::TimeoutSpecified`.
    pub timeout_specified: bool,
    /// Caller-provided pipe suffix, without the NPFS root prefix.
    pub name: Vec<u16>,
}

pub fn decode_pipe_wait_request(input: &[u8]) -> Result<PipeWaitRequest, NtStatus> {
    if input.len() < FILE_PIPE_WAIT_NAME_OFFSET + 2 {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    let timeout_100ns = i64::from_le_bytes([
        input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
    ]);
    let name_len = u32::from_le_bytes([input[8], input[9], input[10], input[11]]) as usize;
    if name_len == 0
        || name_len & 1 != 0
        || name_len > 0xFFFE
        || FILE_PIPE_WAIT_NAME_OFFSET
            .checked_add(name_len)
            .is_none_or(|end| end > input.len())
    {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    let name = &input[FILE_PIPE_WAIT_NAME_OFFSET..FILE_PIPE_WAIT_NAME_OFFSET + name_len];
    Ok(PipeWaitRequest {
        timeout_100ns,
        timeout_specified: input[12] != 0,
        name: name
            .chunks_exact(2)
            .map(|word| u16::from_le_bytes([word[0], word[1]]))
            .collect(),
    })
}

pub fn decode_pipe_wait_name(input: &[u8]) -> Result<Vec<u16>, NtStatus> {
    Ok(decode_pipe_wait_request(input)?.name)
}

/// A pending `FSCTL_PIPE_WAIT` issued on the NPFS root/control file. Native NPFS keeps these in
/// `NP_VCB::WaitQueue` and completes them when a matching pipe instance becomes available.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PipeNameWaiter {
    /// Process-local NPFS root/control handle that issued this `FSCTL_PIPE_WAIT`.
    pub root_handle: u64,
    pub name_hash: u64,
    pub pi: u32,
    pub tid: u64,
    pub badge: u64,
    pub iosb_va: u64,
    pub event_obj_idx: u64,
    pub reply_cap: u64,
    pub resume_ip: u64,
    pub resume_sp: u64,
    pub resume_flags: u64,
    /// Absolute monotonic deadline in 100ns units, or `u64::MAX` for an unbounded wait.
    pub deadline_100ns: u64,
}

/// Reset-safe wait queue for root `FSCTL_PIPE_WAIT` requests.
///
/// Native NPFS keeps a VCB wait queue; service waves can have many named-pipe root waits
/// outstanding at once, so this table grows on demand and refuses only when it cannot allocate
/// another waiter record.
#[derive(Clone, Debug)]
pub struct PipeNameWaiterTable {
    slots: Vec<Option<PipeNameWaiter>>,
    allocation_failures: u64,
    store_failures: u64,
}

impl Default for PipeNameWaiterTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PipeNameWaiterTable {
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            allocation_failures: 0,
            store_failures: 0,
        }
    }

    fn grow_reservation(&mut self) -> bool {
        if self.slots.len() == self.slots.capacity() {
            if self.slots.try_reserve(1).is_err() {
                self.allocation_failures = self.allocation_failures.saturating_add(1);
                return false;
            }
        }
        true
    }

    pub fn reset(&mut self, initial_reserve: usize) -> bool {
        self.slots.clear();
        if self.slots.capacity() < initial_reserve {
            let additional = initial_reserve - self.slots.capacity();
            if self.slots.try_reserve(additional).is_err() {
                self.allocation_failures = self.allocation_failures.saturating_add(1);
                return false;
            }
        }
        true
    }

    /// Ensure one future [`arm`](Self::arm) can record a distinct waiter without allocating at the
    /// point where the executive has already decided to park the caller.
    pub fn ensure_capacity(&mut self) -> bool {
        if self.slots.iter().any(|slot| slot.is_none()) || self.slots.len() < self.slots.capacity()
        {
            return true;
        }
        self.grow_reservation()
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    pub fn records(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(|slot| slot.is_none())
    }

    pub fn has_capacity(&self) -> bool {
        self.slots.iter().any(|slot| slot.is_none()) || self.slots.len() < self.slots.capacity()
    }

    pub fn capacity(&self) -> usize {
        self.slots.capacity()
    }

    pub fn allocation_failures(&self) -> u64 {
        self.allocation_failures
    }

    pub fn store_failures(&self) -> u64 {
        self.store_failures
    }

    pub fn has_thread(&self, tid: u64) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.is_some_and(|waiter| waiter.tid == tid))
    }

    pub fn arm(&mut self, waiter: PipeNameWaiter) -> Option<usize> {
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(waiter);
                return Some(index);
            }
        }
        if !self.grow_reservation() {
            self.store_failures = self.store_failures.saturating_add(1);
            return None;
        }
        self.slots.push(Some(waiter));
        Some(self.slots.len() - 1)
    }

    pub fn complete_by_name(&mut self, name_hash: u64) -> Option<PipeNameWaiter> {
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|waiter| waiter.name_hash == name_hash) {
                return slot.take();
            }
        }
        None
    }

    pub fn pop_due(&mut self, now_100ns: u64) -> Option<PipeNameWaiter> {
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|waiter| waiter.deadline_100ns <= now_100ns) {
                return slot.take();
            }
        }
        None
    }

    pub fn next_deadline(&self) -> Option<u64> {
        self.slots
            .iter()
            .filter_map(|slot| slot.map(|waiter| waiter.deadline_100ns))
            .filter(|deadline| *deadline != u64::MAX)
            .min()
    }

    pub fn cancel_thread_collect_reply_caps(&mut self, tid: u64, out: &mut [u64]) -> usize {
        let mut count = 0;
        for slot in &mut self.slots {
            if let Some(waiter) = *slot {
                if waiter.tid == tid {
                    if count < out.len() {
                        out[count] = waiter.reply_cap;
                    }
                    *slot = None;
                    count += 1;
                }
            }
        }
        count
    }

    /// Cancel + free all waiters owned by `tid`, invoking `complete` with every removed waiter.
    /// This avoids any separate fixed-size scratch array in callers.
    pub fn cancel_thread_with<F>(&mut self, tid: u64, mut complete: F) -> usize
    where
        F: FnMut(PipeNameWaiter),
    {
        let mut count = 0;
        for slot in &mut self.slots {
            if slot.is_some_and(|waiter| waiter.tid == tid) {
                let waiter = slot.take().unwrap();
                complete(waiter);
                count += 1;
            }
        }
        count
    }

    /// Cancel one thread's pending root `FSCTL_PIPE_WAIT` requests for the specified root handle.
    pub fn cancel_thread_handle_with<F>(
        &mut self,
        tid: u64,
        root_handle: u64,
        mut complete: F,
    ) -> usize
    where
        F: FnMut(PipeNameWaiter),
    {
        let mut count = 0;
        for slot in &mut self.slots {
            if slot.is_some_and(|waiter| waiter.tid == tid && waiter.root_handle == root_handle) {
                let waiter = slot.take().unwrap();
                complete(waiter);
                count += 1;
            }
        }
        count
    }
}

/// Reset-safe table of pending async server listens.
///
/// ReactOS/NT does not impose a tiny global cap on `FSCTL_PIPE_LISTEN` IRPs: service startup can
/// legitimately have many RPC servers listening before clients drain them. The first reservation
/// size is just bootstrap storage; the table grows on demand and returns `None` only if the
/// allocation for another listen record fails.
#[derive(Clone, Debug)]
pub struct AsyncListenTable {
    slots: Vec<Option<AsyncListen>>,
    initial_reserve: usize,
}

impl Default for AsyncListenTable {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncListenTable {
    pub const fn new() -> Self {
        Self::with_initial_reserve(PIPE_TABLE_DEFAULT_INITIAL_RESERVE)
    }

    pub const fn with_initial_reserve(initial_reserve: usize) -> Self {
        Self {
            slots: Vec::new(),
            initial_reserve,
        }
    }

    /// Clear stale records and reserve the configured bootstrap storage before an allocator
    /// watermark is taken. The executive keeps this table alive across syscall-loop rewinds.
    pub fn reset(&mut self) -> bool {
        self.slots.clear();
        if self.slots.capacity() < self.initial_reserve {
            let additional = self.initial_reserve - self.slots.capacity();
            if self.slots.try_reserve(additional).is_err() {
                return false;
            }
        }
        true
    }

    /// Whether `tid` currently owns any retained pending listen IRP.
    pub fn has_thread(&self, tid: u64) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.is_some_and(|listen| listen.tid == tid))
    }

    /// Remove active listens issued by `tid`. Terminal delivery/ACK records are never cancelled.
    pub fn cancel_thread_with<F>(&mut self, tid: u64, mut complete: F) -> usize
    where
        F: FnMut(AsyncListen),
    {
        let mut count = 0;
        for slot in &mut self.slots {
            if slot.is_some_and(|listen| listen.delivery_state == 0 && listen.tid == tid) {
                let listen = slot.take().unwrap();
                complete(listen);
                count += 1;
            }
        }
        count
    }

    /// Cancel one thread's pending listen IRPs for one server file object, invoking `complete` with
    /// every removed listen. This is the file-scoped form used by `NtCancelIoFile`.
    pub fn cancel_thread_file_with<F>(&mut self, tid: u64, file_id: u64, mut complete: F) -> usize
    where
        F: FnMut(AsyncListen),
    {
        let mut count = 0;
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|listen| {
                listen.delivery_state == 0 && listen.tid == tid && listen.server_file_id == file_id
            }) {
                let listen = slot.take().unwrap();
                complete(listen);
                count += 1;
            }
        }
        count
    }

    /// Record a pending async listen. A server end cannot own two active listen IRPs, but a terminal
    /// generation retained for delivery/ACK does not block re-arming. Returns `None` for an active
    /// duplicate or an allocation failure.
    pub fn arm(&mut self, l: AsyncListen) -> Option<usize> {
        if self.armed(l.server_file_id) {
            return None;
        }
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(l);
                return Some(i);
            }
        }
        if self.slots.len() == self.slots.capacity() {
            let reserve = if self.slots.capacity() == 0 {
                self.initial_reserve.max(1)
            } else {
                1
            };
            if self.slots.try_reserve(reserve).is_err() {
                return None;
            }
        }
        self.slots.push(Some(l));
        Some(self.slots.len() - 1)
    }

    /// Number of pending listens.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(|s| s.is_none())
    }

    pub fn capacity(&self) -> usize {
        self.slots.capacity()
    }

    /// A snapshot copy of every pending listen (slot, record), for the executive to complete+signal.
    pub fn drain_all(&self) -> impl Iterator<Item = (usize, AsyncListen)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.map(|l| (i, l)))
    }

    /// The currently pending listen for one server end. A terminal record retained only for
    /// delivery/ACK retry does not prevent the server from posting its next listen.
    pub fn find_active(&self, server_file_id: u64) -> Option<(usize, AsyncListen)> {
        self.slots.iter().enumerate().find_map(|(slot, entry)| {
            entry
                .filter(|listen| {
                    listen.server_file_id == server_file_id && listen.delivery_state == 0
                })
                .map(|listen| (slot, listen))
        })
    }

    /// Is there a pending listen on `server_file_id`?
    pub fn armed(&self, server_file_id: u64) -> bool {
        self.find_active(server_file_id).is_some()
    }

    /// Is there a pending listen matching `name_hash` without consuming it?
    ///
    /// This is the `FSCTL_PIPE_WAIT` check: user mode asks whether a named pipe has a listening
    /// instance before it opens the client end. Matching is exact and nonzero, but leaves the
    /// pending listen armed for the later client create.
    pub fn armed_name(&self, name_hash: u64) -> bool {
        name_hash != 0
            && self.slots.iter().any(|slot| {
                slot.is_some_and(|l| {
                    l.delivery_state == 0 && l.name_hash != 0 && l.name_hash == name_hash
                })
            })
    }

    /// Complete only the exact listen generation observed by the caller.
    pub fn complete_exact(&mut self, slot: usize, irp_id: u64) -> Option<AsyncListen> {
        let entry = self.slots.get_mut(slot)?;
        if entry.is_some_and(|listen| listen.irp_id == irp_id) {
            entry.take()
        } else {
            None
        }
    }

    /// Record one successfully published completion surface for the exact listen generation.
    pub fn mark_delivery_exact(&mut self, slot: usize, irp_id: u64, flag: u16) -> Option<u16> {
        let listen = self.slots.get_mut(slot)?.as_mut()?;
        if listen.irp_id != irp_id {
            return None;
        }
        listen.delivery_state |= flag;
        Some(listen.delivery_state)
    }

    /// The `server_file_id` recorded in `slot`, if any (peek without removing).
    pub fn get_slot_id(&self, slot: usize) -> Option<u64> {
        self.slots
            .get(slot)
            .copied()
            .flatten()
            .map(|l| l.server_file_id)
    }
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

    fn wtr(file_id: u64, pi: u32, tid: u64) -> PipeWaiter {
        PipeWaiter {
            device_id: 0xD00D,
            file_id,
            irp_id: 0x1_0000 + file_id,
            delivery_state: 0,
            pi,
            tid,
            badge: pi as u64,
            buffer_va: 0x1000 + file_id,
            buffer_len: 256,
            iosb_va: 0x2000 + file_id,
            apc_routine: 0,
            apc_context: 0,
            completion_port_suppressed: false,
            event_obj_idx: u64::MAX,
            reply_cap: 0x40 + file_id,
            resume_ip: 0x3000 + file_id,
            resume_sp: 0x4000 + file_id,
            resume_flags: 0x202,
            is_transceive: false,
            is_write: false,
        }
    }

    fn complete_waiter(table: &mut PipeWaiterTable, slot: usize) -> Option<PipeWaiter> {
        let irp_id = table.get(slot)?.irp_id;
        table.complete_exact(slot, irp_id)
    }

    fn active_listen(table: &AsyncListenTable, file_id: u64) -> Option<AsyncListen> {
        table.find_active(file_id).map(|(_, listen)| listen)
    }

    fn complete_listen(table: &mut AsyncListenTable, file_id: u64) -> Option<AsyncListen> {
        let (slot, listen) = table.find_active(file_id)?;
        table.complete_exact(slot, listen.irp_id)
    }

    #[test]
    fn pipe_waiter_park_on_empty_records_context() {
        let mut t = PipeWaiterTable::new();
        assert!(t.is_empty());
        let slot = t.park(wtr(0xAA, 3, 7)).unwrap();
        assert_eq!(t.len(), 1);
        assert!(t.parked_on(0xAA));
        assert!(!t.parked_on(0xBB));
        assert!(t.has_thread(7));
        assert!(!t.has_thread(8));
        let w = t.get(slot).unwrap();
        assert_eq!(w.file_id, 0xAA);
        assert_eq!(w.pi, 3);
        assert_eq!(w.reply_cap, 0x40 + 0xAA);
        assert_eq!(w.buffer_va, 0x1000 + 0xAA);
        assert_eq!(w.iosb_va, 0x2000 + 0xAA);
    }

    #[test]
    fn pipe_waiter_delivery_progress_is_exact_and_idempotent() {
        let mut t = PipeWaiterTable::new();
        let waiter = wtr(0xAA, 3, 7);
        let slot = t.park(waiter).unwrap();
        assert_eq!(
            t.mark_delivery_exact(slot, waiter.irp_id + 1, IO_DELIVERY_APC_PUBLISHED),
            None
        );
        assert_eq!(
            t.mark_delivery_exact(slot, waiter.irp_id, IO_DELIVERY_APC_PUBLISHED),
            Some(IO_DELIVERY_APC_PUBLISHED)
        );
        assert_eq!(
            t.mark_delivery_exact(slot, waiter.irp_id, IO_DELIVERY_FILE_PUBLISHED),
            Some(IO_DELIVERY_APC_PUBLISHED | IO_DELIVERY_FILE_PUBLISHED)
        );
        assert_eq!(
            t.get(slot).unwrap().delivery_state,
            IO_DELIVERY_APC_PUBLISHED | IO_DELIVERY_FILE_PUBLISHED
        );
    }

    #[test]
    fn delivered_waiter_does_not_block_next_operation() {
        let mut t = PipeWaiterTable::new();
        let first = wtr(0xAA, 3, 7);
        let first_slot = t.park(first).unwrap();
        t.mark_delivery_exact(first_slot, first.irp_id, IO_DELIVERY_EVENT_PUBLISHED)
            .unwrap();
        assert!(!t.parked_on(0xAA));
        assert!(!t.parked_on_dir(0xAA, false));

        let mut second = wtr(0xAA, 3, 7);
        second.irp_id += 1;
        let second_slot = t.park(second).unwrap();
        assert!(t.parked_on_dir(0xAA, false));
        assert_eq!(t.len(), 2);
        let mut delivered_first = first;
        delivered_first.delivery_state = IO_DELIVERY_EVENT_PUBLISHED;
        assert_eq!(
            t.complete_exact(first_slot, first.irp_id),
            Some(delivered_first)
        );
        assert_eq!(t.get(second_slot), Some(second));
    }

    #[test]
    fn asynchronous_pipe_waiter_does_not_own_a_reply_cap() {
        let mut t = PipeWaiterTable::new();
        let mut waiter = wtr(0xAA, 3, 7);
        waiter.reply_cap = 0;
        waiter.apc_context = 0xDEAD;
        waiter.event_obj_idx = 9;
        let slot = t.park(waiter).unwrap();
        let pending = t.get(slot).unwrap();
        assert_eq!(pending.reply_cap, 0);
        assert_eq!(pending.apc_context, 0xDEAD);
        assert_eq!(pending.event_obj_idx, 9);
        assert!(t.parked_on(0xAA));
    }

    #[test]
    fn pipe_waiter_wake_on_peer_write_drains_and_completes() {
        // The server listener parks reading server-fid; a peer write re-drives:
        // drain_all yields the parked read, and complete() frees it after the
        // executive fills the bytes + replies.
        let mut t = PipeWaiterTable::new();
        let slot = t.park(wtr(0xAA, 3, 7)).unwrap();
        let drained: std::vec::Vec<_> = t.drain_all().collect();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, slot);
        assert_eq!(drained[0].1.file_id, 0xAA);
        // Executive re-read npfs (got data), copied it out, replied → complete.
        let done = complete_waiter(&mut t, slot).unwrap();
        assert_eq!(done.file_id, 0xAA);
        assert!(t.is_empty());
        // Double-complete is benign (a racing write re-drive).
        assert!(complete_waiter(&mut t, slot).is_none());
    }

    #[test]
    fn pipe_waiter_re_armable_across_successive_pdus() {
        // MSRPC is multi-round-trip: after the bind_ack reply the listener loops
        // back and re-parks on the SAME reading end for the request PDU. The slot
        // freed by the first completion must be re-usable.
        let mut t = PipeWaiterTable::new();
        let s1 = t.park(wtr(0xAA, 3, 7)).unwrap();
        complete_waiter(&mut t, s1).unwrap(); // bind read satisfied
        assert!(t.is_empty());
        let s2 = t.park(wtr(0xAA, 3, 7)).unwrap(); // request read re-parks
        assert_eq!(t.len(), 1);
        assert!(t.parked_on(0xAA));
        complete_waiter(&mut t, s2).unwrap();
        assert!(t.is_empty());
    }

    #[test]
    fn pipe_waiter_bidirectional_client_and_server_park_independently() {
        // Both ends can be parked at once (server reading the request, client
        // reading the response), keyed by their own file-id; completing one does
        // not disturb the other.
        let mut t = PipeWaiterTable::new();
        let server = t.park(wtr(0xAA, 3, 7)).unwrap(); // svc listener reads server end
        let client = t.park(wtr(0xBB, 2, 4)).unwrap(); // winlogon reads client end
        assert_eq!(t.len(), 2);
        assert!(t.parked_on(0xAA) && t.parked_on(0xBB));
        // A write re-drives both; only the one whose npfs re-read has data completes.
        let all: std::vec::Vec<_> = t.drain_all().collect();
        assert_eq!(all.len(), 2);
        // Complete the server side only (client still PENDING).
        assert_eq!(complete_waiter(&mut t, server).unwrap().file_id, 0xAA);
        assert_eq!(t.len(), 1);
        assert!(t.parked_on(0xBB));
        assert!(!t.parked_on(0xAA));
        // Client completes on the next write.
        assert_eq!(complete_waiter(&mut t, client).unwrap().file_id, 0xBB);
        assert!(t.is_empty());
    }

    #[test]
    fn pipe_waiter_grows_past_initial_reservation() {
        // The initial reservation is only bootstrap storage. More concurrent RPC/driver pipe
        // waiters grow the table instead of returning a synthetic out-of-resources status.
        let mut t = PipeWaiterTable::with_initial_reserve(2);
        assert!(t.ensure_capacity());
        assert!(t.park(wtr(0xAA, 3, 7)).is_some());
        assert!(t.park(wtr(0xBB, 3, 8)).is_some());
        assert!(t.park(wtr(0xCC, 3, 9)).is_some());
        assert_eq!(t.len(), 3);
        assert!(t.capacity() >= 3);
        // Freeing one re-opens a slot.
        complete_waiter(&mut t, 0).unwrap();
        let reused = t.park(wtr(0xDD, 3, 10)).unwrap();
        assert_eq!(reused, 0);
    }

    #[test]
    fn pipe_waiter_cancel_thread_frees_all_its_slots() {
        let mut t = PipeWaiterTable::new();
        t.park(wtr(0xAA, 3, 7)).unwrap();
        t.park(wtr(0xBB, 3, 7)).unwrap(); // same tid, 2nd end
        t.park(wtr(0xCC, 2, 4)).unwrap(); // different thread
        let mut cancelled = std::vec::Vec::new();
        assert_eq!(
            t.cancel_thread_with(7, |waiter| cancelled.push(waiter.file_id)),
            2
        );
        assert_eq!(cancelled, std::vec![0xAA, 0xBB]);
        assert_eq!(t.len(), 1);
        assert!(t.parked_on(0xCC));
    }

    #[test]
    fn pipe_waiter_cancel_thread_callback_releases_every_waiter() {
        let mut t = PipeWaiterTable::new();
        t.park(wtr(0xAA, 3, 7)).unwrap();
        t.park(wtr(0xBB, 3, 7)).unwrap();
        t.park(wtr(0xCC, 2, 4)).unwrap();

        let mut cancelled = std::vec::Vec::new();
        assert_eq!(
            t.cancel_thread_with(7, |waiter| {
                cancelled.push((waiter.device_id, waiter.file_id, waiter.tid))
            }),
            2
        );
        assert_eq!(cancelled, std::vec![(0xD00D, 0xAA, 7), (0xD00D, 0xBB, 7)]);
        assert_eq!(t.len(), 1);
        assert!(!t.parked_on(0xAA));
        assert!(!t.parked_on(0xBB));
        assert!(t.parked_on(0xCC));
    }

    #[test]
    fn pipe_waiter_cancel_thread_file_only_removes_matching_file_object() {
        let mut t = PipeWaiterTable::new();
        t.park(wtr(0xAA, 3, 7)).unwrap();
        t.park(wtr(0xBB, 3, 7)).unwrap();
        t.park(wtr(0xAA, 3, 8)).unwrap();

        let mut cancelled = std::vec::Vec::new();
        assert_eq!(
            t.cancel_thread_file_with(7, 0xAA, |waiter| cancelled.push(waiter.file_id)),
            1
        );
        assert_eq!(cancelled, std::vec![0xAA]);
        let remaining: std::vec::Vec<_> = t
            .drain_all()
            .map(|(_, waiter)| (waiter.tid, waiter.file_id))
            .collect();
        assert_eq!(remaining, std::vec![(7, 0xBB), (8, 0xAA)]);
        assert_eq!(t.len(), 2);
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

        let (request, more) = r.pipe_read(s, 64).unwrap();
        assert_eq!(&request, b"svc-control");
        assert!(!more);
        assert_eq!(r.readable_bytes(c).unwrap(), 0);
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

    // ─── BATCH 34: async ncacn_np server listen-completion table ──────────────────────────────────

    fn al(server_file_id: u64, event_obj_idx: u64) -> AsyncListen {
        AsyncListen {
            device_id: 0xD00D,
            server_file_id,
            irp_id: 0x2_0000 + server_file_id,
            delivery_state: 0,
            event_obj_idx,
            pi: 3,
            tid: 77,
            badge: 7,
            iosb_va: 0x9000 + server_file_id,
            apc_routine: 0,
            apc_context: 0,
            completion_port_suppressed: false,
            name_hash: 0,
        }
    }

    fn al_named(server_file_id: u64, event_obj_idx: u64, name: &[u16]) -> AsyncListen {
        AsyncListen {
            name_hash: pipe_name_hash(name),
            ..al(server_file_id, event_obj_idx)
        }
    }

    fn pnw(name: &[u16], tid: u64, reply_cap: u64, deadline_100ns: u64) -> PipeNameWaiter {
        PipeNameWaiter {
            root_handle: 0x80,
            name_hash: pipe_name_hash(name),
            pi: 3,
            tid,
            badge: 7,
            iosb_va: 0xA000 + tid,
            event_obj_idx: u64::MAX,
            reply_cap,
            resume_ip: 0x4000 + tid,
            resume_sp: 0x5000 + tid,
            resume_flags: 0x202,
            deadline_100ns,
        }
    }

    #[test]
    fn async_listen_arm_records_and_finds() {
        let mut t = AsyncListenTable::new();
        assert!(t.is_empty());
        let slot = t.arm(al(0xE802D50, 42)).unwrap();
        assert_eq!(t.len(), 1);
        assert!(t.armed(0xE802D50));
        assert!(!t.armed(0xDEAD));
        let l = active_listen(&t, 0xE802D50).unwrap();
        assert_eq!(l.event_obj_idx, 42);
        assert_eq!(l.pi, 3);
        assert_eq!(l.tid, 77);
        assert!(t.has_thread(77));
        assert!(!t.has_thread(78));
        assert_eq!(l.iosb_va, 0x9000 + 0xE802D50);
        assert_eq!(t.get_slot_id(slot), Some(0xE802D50));
    }

    #[test]
    fn async_listen_delivery_progress_is_exact() {
        let mut t = AsyncListenTable::new();
        let listen = al(0xE802D50, 42);
        let slot = t.arm(listen).unwrap();
        assert_eq!(
            t.mark_delivery_exact(slot, listen.irp_id + 1, IO_DELIVERY_EVENT_PUBLISHED,),
            None
        );
        assert_eq!(
            t.mark_delivery_exact(slot, listen.irp_id, IO_DELIVERY_EVENT_PUBLISHED,),
            Some(IO_DELIVERY_EVENT_PUBLISHED)
        );
    }

    #[test]
    fn async_listen_rearms_while_prior_generation_awaits_ack() {
        let mut t = AsyncListenTable::new();
        let first = al(0xE802D50, 42);
        let first_slot = t.arm(first).unwrap();
        t.mark_delivery_exact(first_slot, first.irp_id, IO_DELIVERY_EVENT_PUBLISHED)
            .unwrap();

        let mut second = al(0xE802D50, 99);
        second.irp_id += 1;
        let second_slot = t
            .arm(second)
            .expect("terminal generation does not block rearm");
        assert_eq!(t.find_active(0xE802D50), Some((second_slot, second)));
        assert_eq!(t.len(), 2);

        let mut delivered_first = first;
        delivered_first.delivery_state = IO_DELIVERY_EVENT_PUBLISHED;
        assert_eq!(
            t.complete_exact(first_slot, first.irp_id),
            Some(delivered_first)
        );
        assert_eq!(t.find_active(0xE802D50), Some((second_slot, second)));
    }

    #[test]
    fn async_listen_complete_signals_event_and_frees() {
        // The core Part-B edge modeled: a peer connect completes the server's pending listen; the
        // executive then signals `event_obj_idx` via its NtSetEvent wake path. complete() yields the
        // record (carrying the event to signal + the iosb to fill) exactly once, then the slot is free.
        let mut t = AsyncListenTable::new();
        t.arm(al(0xE802D50, 42)).unwrap();
        let done = complete_listen(&mut t, 0xE802D50).expect("armed listen completes");
        assert_eq!(done.event_obj_idx, 42, "carries the event index to SIGNAL");
        assert_eq!(
            done.iosb_va,
            0x9000 + 0xE802D50,
            "carries the listen IOSB to fill"
        );
        // Consumed exactly once — no double-signal.
        assert!(complete_listen(&mut t, 0xE802D50).is_none());
        assert!(t.is_empty());
    }

    #[test]
    fn async_listen_rearm_requires_prior_completion() {
        let mut t = AsyncListenTable::new();
        t.arm(al(0xE802D50, 42)).unwrap();
        assert!(t.arm(al(0xE802D50, 99)).is_none());
        assert_eq!(active_listen(&t, 0xE802D50).unwrap().event_obj_idx, 42);
        complete_listen(&mut t, 0xE802D50).unwrap();
        t.arm(al(0xE802D50, 99)).unwrap();
        assert_eq!(active_listen(&t, 0xE802D50).unwrap().event_obj_idx, 99);
    }

    #[test]
    fn async_listen_cancel_thread_removes_owned_irps() {
        let mut t = AsyncListenTable::new();
        t.arm(al(0xA, 1)).unwrap();
        let mut other = al(0xB, 2);
        other.tid = 88;
        t.arm(other).unwrap();

        let mut cancelled = std::vec::Vec::new();
        assert_eq!(
            t.cancel_thread_with(77, |listen| cancelled.push(listen.server_file_id)),
            1
        );
        assert_eq!(cancelled, std::vec![0xA]);
        assert!(!t.has_thread(77));
        assert!(t.has_thread(88));
        assert!(t.armed(0xB));
    }

    #[test]
    fn async_listen_drain_all_and_free() {
        let mut t = AsyncListenTable::new();
        let s0 = t.arm(al(0xA, 1)).unwrap();
        let _s1 = t.arm(al(0xB, 2)).unwrap();
        let drained: std::vec::Vec<_> = t.drain_all().collect();
        assert_eq!(drained.len(), 2);
        let first = t.drain_all().find(|(slot, _)| *slot == s0).unwrap().1;
        t.complete_exact(s0, first.irp_id).unwrap();
        assert_eq!(t.len(), 1);
        assert!(!t.armed(0xA));
        assert!(t.armed(0xB));
    }

    #[test]
    fn async_listen_grows_past_initial_reservation() {
        let mut t = AsyncListenTable::with_initial_reserve(2);
        assert!(t.arm(al(1, 10)).is_some());
        assert!(t.arm(al(2, 20)).is_some());
        // Third DISTINCT server end grows the table. A real allocation failure would still return
        // None, but the model no longer has an artificial two-listen ceiling.
        assert!(t.arm(al(3, 30)).is_some());
        assert_eq!(t.len(), 3);
        assert!(t.armed(3));
    }

    #[test]
    fn async_listen_cancel_thread_callback_releases_every_record() {
        let mut t = AsyncListenTable::new();
        t.arm(al(0xA, 1)).unwrap();
        t.arm(al(0xB, 2)).unwrap();
        t.arm(al(0xC, 3)).unwrap();

        let mut cancelled = std::vec::Vec::new();
        assert_eq!(
            t.cancel_thread_with(77, |listen| {
                cancelled.push((
                    listen.device_id,
                    listen.server_file_id,
                    listen.event_obj_idx,
                ))
            }),
            3
        );
        assert_eq!(
            cancelled,
            std::vec![(0xD00D, 0xA, 1), (0xD00D, 0xB, 2), (0xD00D, 0xC, 3)]
        );
        assert!(t.is_empty());
    }

    #[test]
    fn async_listen_cancel_thread_file_only_removes_matching_listen() {
        let mut t = AsyncListenTable::new();
        t.arm(al(0xA, 1)).unwrap();
        t.arm(al(0xB, 2)).unwrap();
        let mut cancelled = std::vec::Vec::new();

        assert_eq!(
            t.cancel_thread_file_with(77, 0xA, |listen| {
                cancelled.push((listen.server_file_id, listen.event_obj_idx));
            }),
            1
        );
        assert_eq!(cancelled, std::vec![(0xA, 1)]);
        assert!(!t.armed(0xA));
        assert!(t.armed(0xB));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn async_listen_complete_exact_fid_is_specific() {
        // A client connect exposes the exact accepted server CCB. Completing by fid must not touch
        // other pending listens, even when names differ or multiple listeners are armed.
        let ntsvcs: std::vec::Vec<u16> = "\\ntsvcs".encode_utf16().collect();
        let lsarpc: std::vec::Vec<u16> = "\\lsarpc".encode_utf16().collect();
        let samr: std::vec::Vec<u16> = "\\samr".encode_utf16().collect();
        let mut t = AsyncListenTable::new();
        t.arm(al_named(0xA, 1, &ntsvcs)).unwrap();
        t.arm(al_named(0xB, 2, &lsarpc)).unwrap();
        t.arm(al_named(0xC, 3, &samr)).unwrap();
        let done = complete_listen(&mut t, 0xA).unwrap();
        assert_eq!(done.event_obj_idx, 1);
        assert_eq!(t.len(), 2, "lsarpc + samr listens are untouched");
        assert!(t.armed(0xB));
        assert!(t.armed(0xC));
        // Case-insensitive match.
        let ntsvcs_uc: std::vec::Vec<u16> = "\\NTSVCS".encode_utf16().collect();
        assert_eq!(pipe_name_hash(&ntsvcs), pipe_name_hash(&ntsvcs_uc));
        assert!(complete_listen(&mut t, 0xDEAD).is_none());
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn async_listen_armed_name_peeks_without_consuming() {
        let ntsvcs: std::vec::Vec<u16> = "\\ntsvcs".encode_utf16().collect();
        let lsarpc: std::vec::Vec<u16> = "\\lsarpc".encode_utf16().collect();
        let mut t = AsyncListenTable::new();
        t.arm(al_named(0xA, 1, &ntsvcs)).unwrap();

        assert!(t.armed_name(pipe_name_hash(&ntsvcs)));
        assert!(!t.armed_name(pipe_name_hash(&lsarpc)));
        assert!(!t.armed_name(0));
        assert_eq!(t.len(), 1, "wait probing must not consume the listen");

        let done = complete_listen(&mut t, 0xA).unwrap();
        assert_eq!(done.server_file_id, 0xA);
        assert!(t.is_empty());
    }

    #[test]
    fn decode_pipe_wait_name_reads_variable_suffix() {
        let name: std::vec::Vec<u16> = "net\\NtControlPipe1".encode_utf16().collect();
        let mut input = std::vec![0u8; FILE_PIPE_WAIT_NAME_OFFSET + name.len() * 2];
        input[0..8].copy_from_slice(&(-50_000_000i64).to_le_bytes());
        input[8..12].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
        input[12] = 1;
        for (index, unit) in name.iter().enumerate() {
            input[FILE_PIPE_WAIT_NAME_OFFSET + index * 2
                ..FILE_PIPE_WAIT_NAME_OFFSET + index * 2 + 2]
                .copy_from_slice(&unit.to_le_bytes());
        }

        assert_eq!(decode_pipe_wait_name(&input).unwrap(), name);
        let request = decode_pipe_wait_request(&input).unwrap();
        assert_eq!(request.name, name);
        assert_eq!(request.timeout_100ns, -50_000_000);
        assert!(request.timeout_specified);
    }

    #[test]
    fn decode_pipe_wait_name_rejects_malformed_lengths() {
        assert_eq!(
            decode_pipe_wait_name(&[0u8; FILE_PIPE_WAIT_NAME_OFFSET]).unwrap_err(),
            NtStatus::INVALID_PARAMETER
        );

        let mut odd = [0u8; FILE_PIPE_WAIT_NAME_OFFSET + 3];
        odd[8..12].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(
            decode_pipe_wait_name(&odd).unwrap_err(),
            NtStatus::INVALID_PARAMETER
        );

        let mut overrun = [0u8; FILE_PIPE_WAIT_NAME_OFFSET + 2];
        overrun[8..12].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            decode_pipe_wait_name(&overrun).unwrap_err(),
            NtStatus::INVALID_PARAMETER
        );
    }

    #[test]
    fn async_listen_complete_exact_fid_does_not_need_name_hash() {
        // The accept edge is the exact server fid returned by NPFS, so it can complete a listen even if
        // name metadata is unavailable. Name hashes are only the pre-open WaitNamedPipe probe surface.
        let ntsvcs: std::vec::Vec<u16> = "\\ntsvcs".encode_utf16().collect();
        let mut t = AsyncListenTable::new();
        t.arm(al(0xA, 1)).unwrap(); // al() leaves name_hash == 0
        assert!(!t.armed_name(pipe_name_hash(&ntsvcs)));
        assert!(!t.armed_name(0));
        assert_eq!(complete_listen(&mut t, 0xA).unwrap().event_obj_idx, 1);
        assert!(t.is_empty());

        let lsarpc: std::vec::Vec<u16> = "\\lsarpc".encode_utf16().collect();
        let mut t2 = AsyncListenTable::new();
        t2.arm(al_named(0xB, 2, &lsarpc)).unwrap();
        assert!(!t2.armed_name(0));
        assert_eq!(t2.len(), 1);
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
    fn pipe_server_availability_tracks_create_connect_and_cleanup() {
        let eventlog: std::vec::Vec<u16> = "\\EventLog".encode_utf16().collect();
        let eventlog_hash = pipe_name_hash(&eventlog);
        let mut table = PipeServerAvailabilityTable::new();

        assert!(table.mark_available(0, eventlog_hash).is_err());
        assert!(table.mark_available(0x101, 0).is_err());
        assert!(!table.available_name(eventlog_hash));

        table.mark_available(0x101, eventlog_hash).unwrap();
        assert!(table.available_name(eventlog_hash));
        assert!(table.is_available(0x101));
        assert_eq!(table.len(), 1);
        assert_eq!(table.available_len(), 1);

        assert!(table.consume(0x101));
        assert!(
            !table.consume(0x101),
            "consuming an already connected instance is idempotent"
        );
        assert!(!table.available_name(eventlog_hash));
        assert_eq!(table.len(), 1);
        assert_eq!(table.available_len(), 0);

        table.mark_available(0x101, eventlog_hash).unwrap();
        assert!(table.available_name(eventlog_hash));
        assert!(table.remove(0x101));
        assert!(table.is_empty());
        assert!(!table.available_name(eventlog_hash));
    }

    #[test]
    fn pipe_server_availability_consumes_exact_same_name_instance() {
        let ntsvcs: std::vec::Vec<u16> = "\\ntsvcs".encode_utf16().collect();
        let ntsvcs_hash = pipe_name_hash(&ntsvcs);
        let mut table = PipeServerAvailabilityTable::new();

        table.mark_available(0x201, ntsvcs_hash).unwrap();
        table.mark_available(0x203, ntsvcs_hash).unwrap();
        assert_eq!(table.available_len(), 2);
        assert!(table.available_name(ntsvcs_hash));

        assert!(table.consume(0x201));
        assert!(!table.is_available(0x201));
        assert!(table.is_available(0x203));
        assert!(table.available_name(ntsvcs_hash));
        assert_eq!(table.available_len(), 1);

        assert!(table.consume(0x203));
        assert!(!table.available_name(ntsvcs_hash));
        assert_eq!(table.available_len(), 0);
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
    fn client_connect_before_listen_completes_late_armed_exact_server() {
        let control_pipe: std::vec::Vec<u16> = "\\net\\NtControlPipe0".encode_utf16().collect();
        let mut preconnected = PipePreconnectedServerTable::new();
        let mut listens = AsyncListenTable::new();

        preconnected.remember(0x401).unwrap();
        preconnected.remember(0x403).unwrap();
        listens
            .arm(al_named(0x401, 0x77, &control_pipe))
            .expect("late listen arms");

        assert!(preconnected.take(0x401));
        let completed = complete_listen(&mut listens, 0x401).expect("accepted endpoint completes");
        assert_eq!(completed.server_file_id, 0x401);
        assert_eq!(completed.event_obj_idx, 0x77);

        assert!(
            preconnected.contains(0x403),
            "other accepted endpoints remain distinct"
        );
        assert!(!preconnected.take(0x401), "the completion edge is one-shot");
        assert!(listens.is_empty());
    }

    #[test]
    fn async_listen_same_name_instances_complete_by_exact_fid() {
        // Two instances of the SAME named pipe are not interchangeable once NPFS has accepted a client.
        // The executive must complete the server fid for the accepted CCB, even if that is not slot 0.
        let ntsvcs: std::vec::Vec<u16> = "\\ntsvcs".encode_utf16().collect();
        let mut t = AsyncListenTable::new();
        t.arm(al_named(0xA, 1, &ntsvcs)).unwrap();
        t.arm(al_named(0xB, 2, &ntsvcs)).unwrap();
        let accepted = complete_listen(&mut t, 0xB).unwrap();
        assert_eq!(accepted.server_file_id, 0xB);
        assert_eq!(accepted.event_obj_idx, 2);
        assert_eq!(t.len(), 1, "the other same-named instance stays armed");
        let remaining = complete_listen(&mut t, 0xA).unwrap();
        assert_eq!(remaining.event_obj_idx, 1);
        assert!(t.is_empty());
        assert!(complete_listen(&mut t, 0xA).is_none());
    }

    #[test]
    fn pipe_name_waiter_complete_by_name_is_specific_and_rearmable() {
        let eventlog: std::vec::Vec<u16> = "\\EventLog".encode_utf16().collect();
        let ntsvcs: std::vec::Vec<u16> = "\\ntsvcs".encode_utf16().collect();
        let mut t = PipeNameWaiterTable::new();
        t.arm(pnw(&eventlog, 10, 0x30, u64::MAX)).unwrap();
        t.arm(pnw(&ntsvcs, 11, 0x31, u64::MAX)).unwrap();

        let done = t.complete_by_name(pipe_name_hash(&eventlog)).unwrap();
        assert_eq!(done.tid, 10);
        assert_eq!(done.reply_cap, 0x30);
        assert_eq!(t.len(), 1);
        assert!(t.complete_by_name(pipe_name_hash(&eventlog)).is_none());
        assert!(t.complete_by_name(0).is_none());

        t.arm(pnw(&eventlog, 12, 0x32, u64::MAX)).unwrap();
        assert_eq!(
            t.complete_by_name(pipe_name_hash(&eventlog)).unwrap().tid,
            12
        );
        assert_eq!(t.complete_by_name(pipe_name_hash(&ntsvcs)).unwrap().tid, 11);
        assert!(t.is_empty());
    }

    #[test]
    fn pipe_name_waiter_table_grows_beyond_initial_reservation() {
        let eventlog: std::vec::Vec<u16> = "\\EventLog".encode_utf16().collect();
        let ntsvcs: std::vec::Vec<u16> = "\\ntsvcs".encode_utf16().collect();
        let samr: std::vec::Vec<u16> = "\\samr".encode_utf16().collect();
        let mut t = PipeNameWaiterTable::new();

        assert!(t.reset(1));
        assert!(t.ensure_capacity());
        assert!(t.arm(pnw(&eventlog, 10, 0x30, u64::MAX)).is_some());
        assert!(t.arm(pnw(&ntsvcs, 11, 0x31, 200)).is_some());
        assert!(t.arm(pnw(&samr, 12, 0x32, 300)).is_some());
        assert_eq!(t.len(), 3);
        assert_eq!(t.records(), 3);
        assert!(t.capacity() >= 3);
        assert_eq!(t.allocation_failures(), 0);
        assert_eq!(t.store_failures(), 0);

        assert_eq!(
            t.complete_by_name(pipe_name_hash(&ntsvcs))
                .unwrap()
                .reply_cap,
            0x31
        );
        assert_eq!(t.len(), 2);
        assert!(t.has_capacity());
        assert!(t.arm(pnw(&ntsvcs, 13, 0x33, u64::MAX)).is_some());
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn pipe_name_waiter_pop_due_ignores_unbounded_waits() {
        let eventlog: std::vec::Vec<u16> = "\\EventLog".encode_utf16().collect();
        let ntsvcs: std::vec::Vec<u16> = "\\ntsvcs".encode_utf16().collect();
        let mut t = PipeNameWaiterTable::new();
        t.arm(pnw(&eventlog, 10, 0x30, u64::MAX)).unwrap();
        t.arm(pnw(&ntsvcs, 11, 0x31, 150)).unwrap();

        assert_eq!(t.next_deadline(), Some(150));
        assert!(t.pop_due(149).is_none());
        let due = t.pop_due(150).unwrap();
        assert_eq!(due.tid, 11);
        assert_eq!(t.next_deadline(), None);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn pipe_name_waiter_cancel_thread_collects_reply_caps() {
        let eventlog: std::vec::Vec<u16> = "\\EventLog".encode_utf16().collect();
        let ntsvcs: std::vec::Vec<u16> = "\\ntsvcs".encode_utf16().collect();
        let mut t = PipeNameWaiterTable::new();
        t.arm(pnw(&eventlog, 10, 0x30, u64::MAX)).unwrap();
        t.arm(pnw(&ntsvcs, 10, 0x31, 200)).unwrap();
        t.arm(pnw(&ntsvcs, 11, 0x32, 300)).unwrap();

        let mut caps = [0u64; 4];
        assert_eq!(t.cancel_thread_collect_reply_caps(10, &mut caps), 2);
        assert_eq!(&caps[..2], &[0x30, 0x31]);
        assert!(!t.has_thread(10));
        assert!(t.has_thread(11));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn pipe_name_waiter_cancel_thread_handle_only_removes_matching_waits() {
        let eventlog: std::vec::Vec<u16> = "\\EventLog".encode_utf16().collect();
        let ntsvcs: std::vec::Vec<u16> = "\\ntsvcs".encode_utf16().collect();
        let mut t = PipeNameWaiterTable::new();
        let mut first = pnw(&eventlog, 10, 0x30, u64::MAX);
        first.root_handle = 0x80;
        let mut second = pnw(&ntsvcs, 10, 0x31, 200);
        second.root_handle = 0x84;
        let mut third = pnw(&eventlog, 11, 0x32, 300);
        third.root_handle = 0x80;
        t.arm(first).unwrap();
        t.arm(second).unwrap();
        t.arm(third).unwrap();

        let mut cancelled = std::vec::Vec::new();
        assert_eq!(
            t.cancel_thread_handle_with(10, 0x80, |waiter| {
                cancelled.push((waiter.tid, waiter.root_handle, waiter.reply_cap));
            }),
            1
        );
        assert_eq!(cancelled, std::vec![(10, 0x80, 0x30)]);
        assert_eq!(t.len(), 2);
        assert!(t.has_thread(10));
        assert!(t.has_thread(11));
    }

    #[test]
    fn pipe_waiter_cancel_thread_clears_parked_on_and_reopens_slot() {
        // cancel_thread_with must clear the parked_on() key AND free the slot for immediate re-park
        // after the caller has finalized the real pending IRP.
        let mut t = PipeWaiterTable::with_initial_reserve(2);
        t.park(wtr(0xAA, 3, 7)).unwrap();
        t.park(wtr(0xBB, 3, 7)).unwrap();
        assert!(t.parked_on(0xAA));
        assert_eq!(t.cancel_thread_with(7, |_| {}), 2);
        assert!(!t.parked_on(0xAA), "cancel clears the parked_on key");
        assert!(!t.parked_on(0xBB));
        assert!(t.is_empty());
        // Both freed slots are immediately re-usable, and additional concurrent waiters grow the table.
        assert!(t.park(wtr(0xCC, 2, 4)).is_some());
        assert!(t.park(wtr(0xDD, 2, 4)).is_some());
        assert!(t.park(wtr(0xEE, 2, 4)).is_some());
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn pipe_waiter_parked_on_dir_is_full_duplex_per_connection() {
        // ★ THE rpcrt4 ncacn_np SERVER SHAPE. `RPCRT4_io_thread` keeps a READ pending on the
        // connection while `RPCRT4_worker_thread` writes the RESPONSE on the SAME connection. The
        // executive gates a park on "does this connection already have one of these outstanding?" —
        // which must be asked PER DIRECTION, or the write is refused with
        // STATUS_INSUFFICIENT_RESOURCES and the response is silently lost (the wall that stopped
        // `LsaOpenPolicy` from returning).
        let mut t = PipeWaiterTable::new();
        let mut read = wtr(0xAA, 4, 26);
        read.is_write = false;
        t.park(read).unwrap();

        // Same connection, same direction: already outstanding.
        assert!(t.parked_on_dir(0xAA, false));
        // Same connection, OTHER direction: free — this is the case `parked_on` got wrong.
        assert!(!t.parked_on_dir(0xAA, true));
        // The direction-blind predicate cannot tell the two apart.
        assert!(t.parked_on(0xAA));

        let mut write = wtr(0xAA, 4, 25);
        write.is_write = true;
        t.park(write).unwrap();
        assert!(t.parked_on_dir(0xAA, true));
        assert!(t.parked_on_dir(0xAA, false));
        assert_eq!(t.len(), 2, "one read + one write on ONE connection");

        // A different connection is unaffected in both directions.
        assert!(!t.parked_on_dir(0xBB, false));
        assert!(!t.parked_on_dir(0xBB, true));

        // Completing the write frees only the write direction.
        let (slot, _) = t.drain_all().find(|(_, w)| w.is_write).unwrap();
        complete_waiter(&mut t, slot).unwrap();
        assert!(!t.parked_on_dir(0xAA, true));
        assert!(t.parked_on_dir(0xAA, false), "the pending read survives");
    }

    #[test]
    fn pipe_waiter_cancel_thread_no_match_is_noop() {
        // cancel_thread_with for a tid with no parked waiters frees nothing and disturbs nobody.
        let mut t = PipeWaiterTable::new();
        t.park(wtr(0xAA, 3, 7)).unwrap();
        assert_eq!(t.cancel_thread_with(999, |_| {}), 0);
        assert_eq!(t.len(), 1);
        assert!(t.parked_on(0xAA));
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

    #[test]
    fn drain_all_order_is_stable_slot_order() {
        // The executive re-drives parked readers in a DETERMINISTIC order (slot order) so a peer write
        // re-issues reads reproducibly. Freeing a middle slot and re-parking reuses the low slot.
        let mut t = PipeWaiterTable::new();
        let s0 = t.park(wtr(0xA0, 1, 1)).unwrap();
        let _s1 = t.park(wtr(0xA1, 1, 2)).unwrap();
        let _s2 = t.park(wtr(0xA2, 1, 3)).unwrap();
        let ids: std::vec::Vec<u64> = t.drain_all().map(|(_, w)| w.file_id).collect();
        assert_eq!(ids, [0xA0, 0xA1, 0xA2]);
        // Free the FIRST; a re-park fills the now-lowest free slot (slot 0).
        complete_waiter(&mut t, s0).unwrap();
        let s_new = t.park(wtr(0xB0, 1, 9)).unwrap();
        assert_eq!(s_new, 0, "the lowest free slot is reused");
        let ids2: std::vec::Vec<u64> = t.drain_all().map(|(_, w)| w.file_id).collect();
        assert_eq!(ids2, [0xB0, 0xA1, 0xA2]);
    }
}
