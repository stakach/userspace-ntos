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

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn dx() -> PipeRegistry {
        PipeRegistry::new()
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
}
