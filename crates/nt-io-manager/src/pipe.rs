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
/// `FILE_PIPE_*_MODE` (read/completion mode).
pub const FILE_PIPE_BYTE_STREAM_MODE: u32 = 0x0000_0000;
pub const FILE_PIPE_MESSAGE_MODE: u32 = 0x0000_0001;
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
/// `STATUS_PIPE_DISCONNECTED` (0xC00000B0): the peer end disconnected.
pub const STATUS_PIPE_DISCONNECTED: NtStatus = NtStatus(0xC000_00B0u32 as i32);
/// `STATUS_PIPE_LISTENING` (0xC00000B3): FSCTL_PIPE_LISTEN, no client yet.
pub const STATUS_PIPE_LISTENING: NtStatus = NtStatus(0xC000_00B3u32 as i32);
/// `STATUS_PIPE_CONNECTED` (0xC00000B4): already connected.
pub const STATUS_PIPE_CONNECTED: NtStatus = NtStatus(0xC000_00B4u32 as i32);
/// `STATUS_INSTANCE_NOT_AVAILABLE` (0xC00000AB): the max-instances limit hit.
pub const STATUS_INSTANCE_NOT_AVAILABLE: NtStatus = NtStatus(0xC000_00ABu32 as i32);

/// The named-pipe connection state machine (`FILE_PIPE_*_STATE`,
/// `NP_CCB.NamedPipeState`).
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum PipeState {
    /// A server instance exists but is not yet listening (freshly created, or the
    /// peer disconnected).
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
        }
        (out, more)
    }
}

/// A single connection instance (`NP_CCB`): a server end + a client end sharing
/// two directional data queues + the pipe state.
pub struct PipeConnection {
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
    /// The pipe's write type (byte-stream vs message) from the FCB config.
    write_message_mode: bool,
    /// The pipe's duplex direction (`FILE_PIPE_INBOUND/OUTBOUND/FULL_DUPLEX`).
    configuration: u32,
}

impl PipeConnection {
    fn new(params: &PipeParams) -> Self {
        let msg = params.pipe_type == FILE_PIPE_MESSAGE_TYPE;
        PipeConnection {
            state: PipeState::Disconnected,
            server_attached: true, // created by the server side
            client_attached: false,
            queues: [
                DataQueue::new(params.inbound_quota),
                DataQueue::new(params.outbound_quota),
            ],
            read_message_mode: [msg, msg],
            write_message_mode: msg,
            configuration: params.configuration,
        }
    }

    /// The queue a given end READS from.
    fn read_queue_idx(end: PipeEnd) -> usize {
        match end {
            PipeEnd::Server => FILE_PIPE_INBOUND,   // server reads client→server
            PipeEnd::Client => FILE_PIPE_OUTBOUND,  // client reads server→client
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
            inbound_quota: 4096,
            outbound_quota: 4096,
        }
    }
}

/// A named pipe (`NP_FCB`): a name + its config + the live connection instances.
pub struct PipeFcb {
    /// The full pipe name (e.g. `\Device\NamedPipe\lsarpc` or just `lsarpc`).
    pub name: String,
    /// The pipe config all instances share.
    pub params: PipeParams,
    /// The live connection instances (`NP_FCB.CcbList`).
    connections: Vec<PipeConnection>,
}

impl PipeFcb {
    fn current_instances(&self) -> u32 {
        self.connections.len() as u32
    }
}

/// A handle to one end of one connection: `(pipe index, connection index, end)`.
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
    /// in the `Disconnected` state (the caller then issues FSCTL_PIPE_LISTEN).
    ///
    /// Mirrors `NpCreateServerEnd`: the first create makes the FCB; subsequent
    /// creates add another instance up to `MaximumInstances`.
    pub fn create_server_pipe(
        &mut self,
        name: &str,
        params: PipeParams,
    ) -> Result<PipeHandle, NtStatus> {
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
                    connections: Vec::new(),
                });
                self.pipes.len() - 1
            }
        };
        let fcb = &mut self.pipes[fcb_idx];
        let conn = PipeConnection::new(&fcb.params);
        fcb.connections.push(conn);
        Ok(PipeHandle {
            fcb: fcb_idx,
            conn: fcb.connections.len() - 1,
            end: PipeEnd::Server,
        })
    }

    /// `FSCTL_PIPE_LISTEN` — a server end waits for a client. Transitions
    /// `Disconnected → Listening`. If a client is already waiting (connect raced
    /// ahead) NPFS would pair immediately; in our synchronous model the client
    /// connect does the pairing, so listen just arms the instance.
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
    /// Pairs with a listening (or freshly-created) server instance and transitions
    /// it to `Connected`. Returns a CLIENT-end handle.
    ///
    /// Mirrors `NpCreateClientEnd`: find the FCB by name, find an available server
    /// instance (Listening preferred, else Disconnected), attach the client end.
    pub fn connect_client(&mut self, name: &str) -> Result<PipeHandle, NtStatus> {
        let fcb_idx = self.find_fcb(name).ok_or(NtStatus::OBJECT_NAME_NOT_FOUND)?;
        let fcb = &mut self.pipes[fcb_idx];
        // Prefer a Listening instance; NPFS also allows connecting to a
        // just-created Disconnected server instance (the listen may not have run
        // yet in our synchronous ordering).
        let conn_idx = fcb
            .connections
            .iter()
            .position(|c| c.state == PipeState::Listening && !c.client_attached)
            .or_else(|| {
                fcb.connections
                    .iter()
                    .position(|c| c.state == PipeState::Disconnected && !c.client_attached)
            });
        let Some(conn_idx) = conn_idx else {
            // No available server instance.
            return Err(STATUS_PIPE_NOT_AVAILABLE);
        };
        let conn = &mut fcb.connections[conn_idx];
        conn.client_attached = true;
        conn.state = PipeState::Connected;
        Ok(PipeHandle {
            fcb: fcb_idx,
            conn: conn_idx,
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
        let written = self.pipe_write(h, out)?;
        let (bytes, more) = self.pipe_read(h, max)?;
        Ok((written, bytes, more))
    }

    /// `IRP_MJ_CLEANUP`/disconnect — detach `h`'s end. If both ends are gone the
    /// connection is removed; otherwise it transitions to `Closing` (the peer may
    /// still drain queued bytes) then `Disconnected`.
    pub fn disconnect(&mut self, h: PipeHandle) -> Result<(), NtStatus> {
        let fcb = self
            .pipes
            .get_mut(h.fcb)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        let conn = fcb
            .connections
            .get_mut(h.conn)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        match h.end {
            PipeEnd::Server => conn.server_attached = false,
            PipeEnd::Client => conn.client_attached = false,
        }
        if !conn.server_attached && !conn.client_attached {
            fcb.connections.remove(h.conn);
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

    // --- internals ---------------------------------------------------------

    fn conn(&self, h: PipeHandle) -> Result<&PipeConnection, NtStatus> {
        self.pipes
            .get(h.fcb)
            .and_then(|f| f.connections.get(h.conn))
            .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn conn_mut(&mut self, h: PipeHandle) -> Result<&mut PipeConnection, NtStatus> {
        self.pipes
            .get_mut(h.fcb)
            .and_then(|f| f.connections.get_mut(h.conn))
            .ok_or(NtStatus::INVALID_HANDLE)
    }
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
// The executive does NOT have a peer→reader map (npfs pairs the ends internally
// by name), so on ANY pipe write it re-drives EVERY parked reader: it re-issues
// each parked read against npfs and completes the ones that now return data —
// npfs's own FCB pairing decides which reader actually has bytes. `drain_all`
// hands the executive the full set of parked waiters to re-drive; `complete`
// frees the slots that were satisfied. Idempotent: a re-read that is still
// PENDING leaves the waiter parked (the executive simply doesn't call
// `complete` for it).

/// One parked pipe read awaiting peer data. All fields are the executive-side
/// context needed to complete the read when data arrives: the npfs `file_id`
/// (the reading end's `FsContext`) to re-issue the read against, the owning
/// process index + thread id (whose VSpace/stack-mirror the bytes land in), the
/// user `buffer`/`iosb` VAs, the buffer length, the seL4 reply cap held for the
/// blocked thread, and its native-syscall resume context (RCX/RSP/RFLAGS). The
/// pure table treats them as opaque `u64`s — only `file_id` participates in the
/// table's own logic (as the slot key); the rest are carried verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PipeWaiter {
    /// npfs `FsContext` of the READING end this waiter is blocked on (the slot key).
    pub file_id: u64,
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
    /// The stolen seL4 MCS reply cap that resumes the blocked thread.
    pub reply_cap: u64,
    /// Native-syscall resume context: RCX (return IP), RSP, RFLAGS.
    pub resume_ip: u64,
    pub resume_sp: u64,
    pub resume_flags: u64,
    /// `true` if this waiter parked on FSCTL_PIPE_TRANSCEIVE (must re-read then
    /// return via the FSCTL output path), `false` for a plain NtReadFile.
    pub is_transceive: bool,
}

/// A fixed-capacity, heap-free, reset-safe table of parked pipe reads. Mirrors
/// the executive's `PENDING_IRPS` / event-waiter-table style (a `.bss` static, no
/// allocation, bounded). Parking past capacity fails (the caller then returns the
/// PENDING status directly — degraded, never a hang), exactly like the event
/// waiter pool exhausting.
#[derive(Clone, Debug)]
pub struct PipeWaiterTable<const N: usize> {
    slots: [Option<PipeWaiter>; N],
}

impl<const N: usize> Default for PipeWaiterTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PipeWaiterTable<N> {
    pub const fn new() -> Self {
        Self { slots: [None; N] }
    }

    /// Park `w` in a free slot. Returns the slot index, or `None` if the table is
    /// full (caller degrades to returning PENDING directly — never a hang).
    ///
    /// Re-armable by construction: a slot freed by [`complete`](Self::complete) or
    /// [`cancel_thread`](Self::cancel_thread) becomes `None` and is immediately
    /// reusable for the next PDU's read on the same or a different file-id.
    pub fn park(&mut self, w: PipeWaiter) -> Option<usize> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(w);
                return Some(i);
            }
        }
        None
    }

    /// Number of currently parked waiters.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(|s| s.is_none())
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

    /// Free `slot` after its read was satisfied (the executive re-read npfs,
    /// copied the bytes into the waiter's buffer, and replied to its reply cap).
    /// Returns the freed waiter, or `None` if the slot was already empty (a
    /// double-complete — benign, the write re-drive may race a slot).
    pub fn complete(&mut self, slot: usize) -> Option<PipeWaiter> {
        self.slots.get_mut(slot).and_then(|s| s.take())
    }

    /// Cancel + free any waiter owned by `tid` (thread teardown). Returns the
    /// count freed.
    pub fn cancel_thread(&mut self, tid: u64) -> usize {
        let mut n = 0;
        for slot in self.slots.iter_mut() {
            if slot.map(|w| w.tid) == Some(tid) {
                *slot = None;
                n += 1;
            }
        }
        n
    }

    /// Is there already a parked read on `file_id`? (Guards double-parking the
    /// same reading end — a listener that re-issues its read while still parked.)
    pub fn parked_on(&self, file_id: u64) -> bool {
        self.slots
            .iter()
            .any(|s| s.map(|w| w.file_id) == Some(file_id))
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

/// A pending async server-side `FSCTL_PIPE_LISTEN` awaiting a client connect. Keyed by the SERVER
/// end's npfs `file_id`. On the peer connect/write the executive completes it: fills `iosb_va` with
/// SUCCESS (in the server's VSpace) and signals `event_obj_idx` (waking the server's wait-array).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AsyncListen {
    /// npfs `FsContext` of the SERVER end that posted FSCTL_PIPE_LISTEN (the slot key).
    pub server_file_id: u64,
    /// The obj_ns EVENT index (resolved in the SERVER's handle table at listen time) to SIGNAL on
    /// completion — the overlapped listen's completion Event. `u64::MAX` = no event (rare).
    pub event_obj_idx: u64,
    /// The server process index (whose VSpace the listen IOSB is written into).
    pub pi: u32,
    /// The listener thread's fault-EP badge (for the mirror-context switch during the IOSB copyout).
    pub badge: u64,
    /// The listen IO_STATUS_BLOCK VA (filled `{Status=SUCCESS, Information=0}` on completion).
    pub iosb_va: u64,
    /// A stable hash of the SERVER pipe leaf name (`\ntsvcs`, `\lsarpc`, …). A client connect
    /// completes ONLY the listen whose `name_hash` matches the connected pipe — so connecting to
    /// `\ntsvcs` does NOT spuriously wake `\lsarpc`/`\samr` servers. 0 = unset (matches any).
    pub name_hash: u64,
}

/// A tiny stable FNV-1a hash of a pipe leaf name (UTF-16 units, case-insensitive on ASCII). Used to
/// match a client connect to the specific armed server listen for the same pipe name.
pub fn pipe_name_hash(name16: &[u16]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &w in name16 {
        let c = if (b'A' as u16..=b'Z' as u16).contains(&w) { w + 32 } else { w };
        h ^= c as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// A fixed-capacity, heap-free, reset-safe table of pending async server listens. Same `.bss` static
/// shape as [`PipeWaiterTable`]. One entry per server pipe end awaiting a client connect.
#[derive(Clone, Debug)]
pub struct AsyncListenTable<const N: usize> {
    slots: [Option<AsyncListen>; N],
}

impl<const N: usize> Default for AsyncListenTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AsyncListenTable<N> {
    pub const fn new() -> Self {
        Self { slots: [None; N] }
    }

    /// Record a pending async listen. If an entry already exists for `server_file_id`, it is REPLACED
    /// (a re-armed listen after a prior completion updates the event/iosb). Returns the slot index, or
    /// `None` if the table is full.
    pub fn arm(&mut self, l: AsyncListen) -> Option<usize> {
        // Replace an existing entry for the same server end (re-arm).
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.map(|e| e.server_file_id) == Some(l.server_file_id) {
                *slot = Some(l);
                return Some(i);
            }
        }
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(l);
                return Some(i);
            }
        }
        None
    }

    /// Number of pending listens.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(|s| s.is_none())
    }

    /// A snapshot copy of every pending listen (slot, record), for the executive to complete+signal.
    pub fn drain_all(&self) -> impl Iterator<Item = (usize, AsyncListen)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.map(|l| (i, l)))
    }

    /// The pending listen on `server_file_id`, if any (peek).
    pub fn find(&self, server_file_id: u64) -> Option<AsyncListen> {
        self.slots
            .iter()
            .find_map(|s| s.filter(|l| l.server_file_id == server_file_id))
    }

    /// Is there a pending listen on `server_file_id`?
    pub fn armed(&self, server_file_id: u64) -> bool {
        self.find(server_file_id).is_some()
    }

    /// Complete + free the listen on `server_file_id` (a client connected). Returns the completed
    /// record so the caller can signal its event + fill its IOSB. `None` if none was armed.
    pub fn complete(&mut self, server_file_id: u64) -> Option<AsyncListen> {
        for slot in self.slots.iter_mut() {
            if slot.map(|l| l.server_file_id) == Some(server_file_id) {
                return slot.take();
            }
        }
        None
    }

    /// Free by slot index (used after a `drain_all` completion pass).
    pub fn free(&mut self, slot: usize) -> Option<AsyncListen> {
        self.slots.get_mut(slot).and_then(|s| s.take())
    }

    /// The `server_file_id` recorded in `slot`, if any (peek without removing).
    pub fn get_slot_id(&self, slot: usize) -> Option<u64> {
        self.slots.get(slot).copied().flatten().map(|l| l.server_file_id)
    }

    /// Complete + free the FIRST pending listen matching `name_hash` (a client connected to that
    /// specific pipe name). `name_hash == 0` or a stored `name_hash == 0` matches any (unset). Returns
    /// the completed record so the caller can signal its event + fill its IOSB. `None` if no match —
    /// so a connect to `\ntsvcs` does NOT complete `\lsarpc`/`\samr` server listens. Idempotent: the
    /// matched listen is consumed once; a fresh re-arm (re-post) is a NEW record.
    pub fn complete_by_name(&mut self, name_hash: u64) -> Option<AsyncListen> {
        for slot in self.slots.iter_mut() {
            if let Some(l) = *slot {
                if name_hash == 0 || l.name_hash == 0 || l.name_hash == name_hash {
                    return slot.take();
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn dx() -> PipeRegistry {
        PipeRegistry::new()
    }

    fn wtr(file_id: u64, pi: u32, tid: u64) -> PipeWaiter {
        PipeWaiter {
            file_id,
            pi,
            tid,
            badge: pi as u64,
            buffer_va: 0x1000 + file_id,
            buffer_len: 256,
            iosb_va: 0x2000 + file_id,
            reply_cap: 0x40 + file_id,
            resume_ip: 0x3000 + file_id,
            resume_sp: 0x4000 + file_id,
            resume_flags: 0x202,
            is_transceive: false,
        }
    }

    #[test]
    fn pipe_waiter_park_on_empty_records_context() {
        let mut t = PipeWaiterTable::<8>::new();
        assert!(t.is_empty());
        let slot = t.park(wtr(0xAA, 3, 7)).unwrap();
        assert_eq!(t.len(), 1);
        assert!(t.parked_on(0xAA));
        assert!(!t.parked_on(0xBB));
        let w = t.get(slot).unwrap();
        assert_eq!(w.file_id, 0xAA);
        assert_eq!(w.pi, 3);
        assert_eq!(w.reply_cap, 0x40 + 0xAA);
        assert_eq!(w.buffer_va, 0x1000 + 0xAA);
        assert_eq!(w.iosb_va, 0x2000 + 0xAA);
    }

    #[test]
    fn pipe_waiter_wake_on_peer_write_drains_and_completes() {
        // The server listener parks reading server-fid; a peer write re-drives:
        // drain_all yields the parked read, and complete() frees it after the
        // executive fills the bytes + replies.
        let mut t = PipeWaiterTable::<8>::new();
        let slot = t.park(wtr(0xAA, 3, 7)).unwrap();
        let drained: std::vec::Vec<_> = t.drain_all().collect();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, slot);
        assert_eq!(drained[0].1.file_id, 0xAA);
        // Executive re-read npfs (got data), copied it out, replied → complete.
        let done = t.complete(slot).unwrap();
        assert_eq!(done.file_id, 0xAA);
        assert!(t.is_empty());
        // Double-complete is benign (a racing write re-drive).
        assert!(t.complete(slot).is_none());
    }

    #[test]
    fn pipe_waiter_re_armable_across_successive_pdus() {
        // MSRPC is multi-round-trip: after the bind_ack reply the listener loops
        // back and re-parks on the SAME reading end for the request PDU. The slot
        // freed by the first completion must be re-usable.
        let mut t = PipeWaiterTable::<4>::new();
        let s1 = t.park(wtr(0xAA, 3, 7)).unwrap();
        t.complete(s1).unwrap(); // bind read satisfied
        assert!(t.is_empty());
        let s2 = t.park(wtr(0xAA, 3, 7)).unwrap(); // request read re-parks
        assert_eq!(t.len(), 1);
        assert!(t.parked_on(0xAA));
        t.complete(s2).unwrap();
        assert!(t.is_empty());
    }

    #[test]
    fn pipe_waiter_bidirectional_client_and_server_park_independently() {
        // Both ends can be parked at once (server reading the request, client
        // reading the response), keyed by their own file-id; completing one does
        // not disturb the other.
        let mut t = PipeWaiterTable::<8>::new();
        let server = t.park(wtr(0xAA, 3, 7)).unwrap(); // svc listener reads server end
        let client = t.park(wtr(0xBB, 2, 4)).unwrap(); // winlogon reads client end
        assert_eq!(t.len(), 2);
        assert!(t.parked_on(0xAA) && t.parked_on(0xBB));
        // A write re-drives both; only the one whose npfs re-read has data completes.
        let all: std::vec::Vec<_> = t.drain_all().collect();
        assert_eq!(all.len(), 2);
        // Complete the server side only (client still PENDING).
        assert_eq!(t.complete(server).unwrap().file_id, 0xAA);
        assert_eq!(t.len(), 1);
        assert!(t.parked_on(0xBB));
        assert!(!t.parked_on(0xAA));
        // Client completes on the next write.
        assert_eq!(t.complete(client).unwrap().file_id, 0xBB);
        assert!(t.is_empty());
    }

    #[test]
    fn pipe_waiter_park_fails_when_full_never_hangs() {
        // Capacity exhaustion returns None (caller degrades to returning PENDING
        // directly), never overwrites a live waiter.
        let mut t = PipeWaiterTable::<2>::new();
        assert!(t.park(wtr(0xAA, 3, 7)).is_some());
        assert!(t.park(wtr(0xBB, 3, 8)).is_some());
        assert!(t.park(wtr(0xCC, 3, 9)).is_none());
        assert_eq!(t.len(), 2);
        // Freeing one re-opens a slot.
        t.complete(0).unwrap();
        assert!(t.park(wtr(0xCC, 3, 9)).is_some());
    }

    #[test]
    fn pipe_waiter_cancel_thread_frees_all_its_slots() {
        let mut t = PipeWaiterTable::<8>::new();
        t.park(wtr(0xAA, 3, 7)).unwrap();
        t.park(wtr(0xBB, 3, 7)).unwrap(); // same tid, 2nd end
        t.park(wtr(0xCC, 2, 4)).unwrap(); // different thread
        assert_eq!(t.cancel_thread(7), 2);
        assert_eq!(t.len(), 1);
        assert!(t.parked_on(0xCC));
    }

    #[test]
    fn create_then_connect_reaches_connected() {
        let mut r = dx();
        let s = r
            .create_server_pipe("lsarpc", PipeParams::default())
            .unwrap();
        assert_eq!(r.state(s).unwrap(), PipeState::Disconnected);
        assert_eq!(r.listen(s).unwrap(), STATUS_PIPE_LISTENING);
        assert_eq!(r.state(s).unwrap(), PipeState::Listening);
        let c = r.connect_client("lsarpc").unwrap();
        assert_eq!(c.end(), PipeEnd::Client);
        assert_eq!(r.state(s).unwrap(), PipeState::Connected);
        assert_eq!(r.state(c).unwrap(), PipeState::Connected);
        assert!(r.conn(s).unwrap().is_connected());
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
        let params = PipeParams {
            pipe_type: FILE_PIPE_MESSAGE_TYPE,
            ..PipeParams::default()
        };
        let s = r.create_server_pipe("ntsvcs", params).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("ntsvcs").unwrap();
        // A 72-byte "bind PDU": a recognizable header then filler.
        let mut bind: Vec<u8> = [0x05u8, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00,
                                 0x00, 0x01, 0x00, 0x00, 0x00].to_vec();
        bind.extend((16u8..72).map(|i| i));
        assert_eq!(r.pipe_write(c, &bind).unwrap(), 72);
        // Server reads only the 16-byte common header → the FIRST 16 real bytes + truncation flag.
        let (hdr, more) = r.pipe_read(s, 16).unwrap();
        assert_eq!(&hdr, &bind[..16], "partial read must return the real header bytes, not garbage");
        assert!(more, "a 16-of-72 message read must flag BUFFER_OVERFLOW (more)");
        // The remaining 56 bytes of the SAME message are still queued and read next.
        let (rest, more2) = r.pipe_read(s, 256).unwrap();
        assert_eq!(&rest, &bind[16..]);
        assert!(!more2);
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
    fn connect_before_listen_still_pairs() {
        let mut r = dx();
        let s = r.create_server_pipe("p", PipeParams::default()).unwrap();
        // Client connects before the server calls FSCTL_PIPE_LISTEN.
        let c = r.connect_client("p").unwrap();
        assert_eq!(r.state(s).unwrap(), PipeState::Connected);
        // A subsequent listen reports already-connected.
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
        // Model an RPC: client transceives a request, server reads it and replies,
        // then the client's transceive read returns the reply. Because our
        // transceive is synchronous, we do it in two coordinated steps.
        let mut r = dx();
        let s = r.create_server_pipe("p", PipeParams::default()).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("p").unwrap();
        // Client writes request.
        r.pipe_write(c, b"req").unwrap();
        // Server reads it and writes the reply.
        assert_eq!(r.pipe_read(s, 16).unwrap().0, b"req");
        r.pipe_write(s, b"reply").unwrap();
        // Client transceive (write nothing more, read the reply).
        let (_w, reply, _more) = r.transceive(c, b"", 16).unwrap();
        assert_eq!(&reply, b"reply");
    }

    #[test]
    fn message_mode_reads_one_message_at_a_time() {
        let mut r = dx();
        let p = PipeParams {
            pipe_type: FILE_PIPE_MESSAGE_TYPE,
            ..PipeParams::default()
        };
        let s = r.create_server_pipe("m", p).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("m").unwrap();
        r.pipe_write(s, b"AAA").unwrap();
        r.pipe_write(s, b"BB").unwrap();
        // First read returns exactly the first message, not both coalesced.
        assert_eq!(r.pipe_read(c, 64).unwrap().0, b"AAA");
        assert_eq!(r.pipe_read(c, 64).unwrap().0, b"BB");
    }

    #[test]
    fn message_mode_truncation_reports_more() {
        let mut r = dx();
        let p = PipeParams {
            pipe_type: FILE_PIPE_MESSAGE_TYPE,
            ..PipeParams::default()
        };
        let s = r.create_server_pipe("m", p).unwrap();
        r.listen(s).unwrap();
        let c = r.connect_client("m").unwrap();
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
        assert_eq!(
            r.pipe_write(s, b"x").unwrap_err(),
            STATUS_PIPE_DISCONNECTED
        );
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
            server_file_id,
            event_obj_idx,
            pi: 3,
            badge: 7,
            iosb_va: 0x9000 + server_file_id,
            name_hash: 0,
        }
    }

    fn al_named(server_file_id: u64, event_obj_idx: u64, name: &[u16]) -> AsyncListen {
        AsyncListen {
            name_hash: pipe_name_hash(name),
            ..al(server_file_id, event_obj_idx)
        }
    }

    #[test]
    fn async_listen_arm_records_and_finds() {
        let mut t = AsyncListenTable::<8>::new();
        assert!(t.is_empty());
        let slot = t.arm(al(0xE802D50, 42)).unwrap();
        assert_eq!(t.len(), 1);
        assert!(t.armed(0xE802D50));
        assert!(!t.armed(0xDEAD));
        let l = t.find(0xE802D50).unwrap();
        assert_eq!(l.event_obj_idx, 42);
        assert_eq!(l.pi, 3);
        assert_eq!(l.iosb_va, 0x9000 + 0xE802D50);
        assert_eq!(t.get_slot_id(slot), Some(0xE802D50));
    }

    #[test]
    fn async_listen_complete_signals_event_and_frees() {
        // The core Part-B edge modeled: a peer connect completes the server's pending listen; the
        // executive then signals `event_obj_idx` via its NtSetEvent wake path. complete() yields the
        // record (carrying the event to signal + the iosb to fill) exactly once, then the slot is free.
        let mut t = AsyncListenTable::<8>::new();
        t.arm(al(0xE802D50, 42)).unwrap();
        let done = t.complete(0xE802D50).expect("armed listen completes");
        assert_eq!(done.event_obj_idx, 42, "carries the event index to SIGNAL");
        assert_eq!(done.iosb_va, 0x9000 + 0xE802D50, "carries the listen IOSB to fill");
        // Consumed exactly once — no double-signal.
        assert!(t.complete(0xE802D50).is_none());
        assert!(t.is_empty());
    }

    #[test]
    fn async_listen_rearm_replaces_same_server() {
        // rpcrt4 re-posts FSCTL_PIPE_LISTEN with a fresh completion event after the previous connect
        // completed (successive clients). Re-arming the same server end REPLACES the record (no leak),
        // so the NEXT connect signals the NEW event, not a stale one.
        let mut t = AsyncListenTable::<8>::new();
        t.arm(al(0xE802D50, 42)).unwrap();
        t.arm(al(0xE802D50, 99)).unwrap(); // re-arm same server, new event
        assert_eq!(t.len(), 1, "re-arm does not leak a second slot");
        assert_eq!(t.find(0xE802D50).unwrap().event_obj_idx, 99);
    }

    #[test]
    fn async_listen_drain_all_and_free() {
        let mut t = AsyncListenTable::<8>::new();
        let s0 = t.arm(al(0xA, 1)).unwrap();
        let _s1 = t.arm(al(0xB, 2)).unwrap();
        let drained: std::vec::Vec<_> = t.drain_all().collect();
        assert_eq!(drained.len(), 2);
        t.free(s0);
        assert_eq!(t.len(), 1);
        assert!(!t.armed(0xA));
        assert!(t.armed(0xB));
    }

    #[test]
    fn async_listen_full_never_hangs() {
        let mut t = AsyncListenTable::<2>::new();
        assert!(t.arm(al(1, 10)).is_some());
        assert!(t.arm(al(2, 20)).is_some());
        // Third DISTINCT server end → table full → None (caller degrades, never a hang).
        assert!(t.arm(al(3, 30)).is_none());
    }

    #[test]
    fn async_listen_complete_by_name_is_specific() {
        // The key regression guard: a client connecting to \ntsvcs must complete ONLY the \ntsvcs
        // server listen, NOT the \lsarpc/\samr ones (spuriously waking them makes their rpcrt4 loop).
        let ntsvcs: std::vec::Vec<u16> = "\\ntsvcs".encode_utf16().collect();
        let lsarpc: std::vec::Vec<u16> = "\\lsarpc".encode_utf16().collect();
        let samr: std::vec::Vec<u16> = "\\samr".encode_utf16().collect();
        let mut t = AsyncListenTable::<8>::new();
        t.arm(al_named(0xA, 1, &ntsvcs)).unwrap();
        t.arm(al_named(0xB, 2, &lsarpc)).unwrap();
        t.arm(al_named(0xC, 3, &samr)).unwrap();
        // Connect to \ntsvcs → completes ONLY the ntsvcs listen (event 1).
        let done = t.complete_by_name(pipe_name_hash(&ntsvcs)).unwrap();
        assert_eq!(done.event_obj_idx, 1);
        assert_eq!(t.len(), 2, "lsarpc + samr listens are untouched");
        assert!(t.armed(0xB));
        assert!(t.armed(0xC));
        // Case-insensitive match.
        let ntsvcs_uc: std::vec::Vec<u16> = "\\NTSVCS".encode_utf16().collect();
        assert_eq!(pipe_name_hash(&ntsvcs), pipe_name_hash(&ntsvcs_uc));
        // A connect to a name with NO armed listen completes nothing.
        let unknown: std::vec::Vec<u16> = "\\nope".encode_utf16().collect();
        assert!(t.complete_by_name(pipe_name_hash(&unknown)).is_none());
        assert_eq!(t.len(), 2);
    }
}
