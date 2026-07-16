//! `Csr*` — the CSR (Client/Server Runtime) client stubs (8 imported exports).
//!
//! The Win32 subsystem (csrss) is reached from a client process over an **LPC port** (`\Windows\
//! ApiPort`). The `Csr*` client exports build a **`CSR_API_MESSAGE`** — a `PORT_MESSAGE` header + a
//! CSR-specific body (API number + argument union) — optionally carrying a **capture buffer** for
//! the pointer arguments (CSR can't dereference client pointers directly, so variable-length args
//! are copied into a self-describing buffer whose internal pointers are relocated to server
//! address space on receipt), and then issue `NtRequestWaitReplyPort` on the CSR port.
//!
//! This module implements the **message construction + capture-buffer marshalling** (host-tested)
//! and models the connection handshake. The actual port send is the **LPC seam** over
//! [`nt_port_core`] (wired later — `project_alpc`): [`CsrPort::call_server`] builds the message and
//! routes it through the seam, which returns `STATUS_NOT_IMPLEMENTED` until the LPC transport is
//! connected — never a faked round-trip.

use alloc::vec::Vec;

use nt_port_core::PortApi;

use crate::NtStatus;
use crate::STATUS_NOT_IMPLEMENTED;

/// `STATUS_INVALID_PARAMETER`.
pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000D;
/// `STATUS_BUFFER_TOO_SMALL`.
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023;

/// The x64 `PORT_MESSAGE` header size (bytes) — the frame every LPC/CSR message carries. Shared by
/// LPC and ALPC (`nt-port-core` docs).
pub const PORT_MESSAGE_HEADER_LEN: usize = 0x28;

/// A CSR API number: `(ServerDllIndex << 16) | ApiIndex` (the `CSR_MAKE_API_NUMBER` encoding). The
/// server-dll index selects basesrv/winsrv/…; the api index selects the routine within it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CsrApiNumber(pub u32);

impl CsrApiNumber {
    /// Build an API number from a server-dll index + an API index (`CSR_MAKE_API_NUMBER`).
    pub const fn make(server_dll_index: u16, api_index: u16) -> Self {
        CsrApiNumber(((server_dll_index as u32) << 16) | api_index as u32)
    }
    /// The server-dll index (high 16 bits).
    pub const fn server_dll_index(self) -> u16 {
        (self.0 >> 16) as u16
    }
    /// The API index (low 16 bits).
    pub const fn api_index(self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }
}

/// A pointer argument captured into a [`CaptureBuffer`]: its offset within the buffer's data region
/// and its length. On receipt CSR relocates the message field that referenced it to
/// `server_base + offset`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CapturedPointer {
    /// Byte offset of the captured data within the buffer's data region.
    pub offset: usize,
    /// Byte length of the captured data.
    pub length: usize,
}

/// A `CSR_CAPTURE_BUFFER`: a self-describing buffer that carries the client's pointer arguments so
/// CSR can access them without dereferencing client pointers. Layout mirrors the real structure
/// closely enough for the marshalling to be exercised: a header (size + pointer count) + a pointer-
/// offset array + the packed data region.
///
/// `CsrAllocateCaptureBuffer(count, size)` sizes it for `count` pointers and `size` data bytes;
/// `CsrCaptureMessageBuffer` packs one pointer arg; `CsrFreeCaptureBuffer` drops it (here = `Drop`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureBuffer {
    /// The maximum number of pointer arguments this buffer was sized for.
    pub max_pointers: usize,
    /// The captured pointers, in capture order.
    pub pointers: Vec<CapturedPointer>,
    /// The packed data region (all captured pointer payloads concatenated, 8-byte aligned).
    pub data: Vec<u8>,
    /// The data-region capacity this buffer was sized for.
    pub capacity: usize,
}

impl CaptureBuffer {
    /// `CsrAllocateCaptureBuffer(PointerCount, Size)` — allocate a capture buffer sized for
    /// `pointer_count` pointer args and `size` bytes of packed data.
    pub fn allocate(pointer_count: usize, size: usize) -> Self {
        CaptureBuffer {
            max_pointers: pointer_count,
            pointers: Vec::with_capacity(pointer_count),
            data: Vec::with_capacity(size),
            capacity: size,
        }
    }

    /// `CsrCaptureMessageBuffer(CaptureBuffer, Buffer, Length, CapturedBuffer*)` — pack `bytes` into
    /// the buffer (8-byte aligned) and record the pointer. Returns the [`CapturedPointer`] (the
    /// server-relocatable descriptor) or an error if the buffer is out of pointer slots / capacity.
    pub fn capture(&mut self, bytes: &[u8]) -> Result<CapturedPointer, NtStatus> {
        if self.pointers.len() >= self.max_pointers {
            return Err(STATUS_INVALID_PARAMETER);
        }
        // Align the data region to 8 bytes before packing (CSR packs aligned).
        while !self.data.len().is_multiple_of(8) {
            self.data.push(0);
        }
        let offset = self.data.len();
        // Reject if a hard capacity was set and this capture would exceed it.
        if self.capacity != 0 && offset + bytes.len() > self.capacity {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        self.data.extend_from_slice(bytes);
        let p = CapturedPointer { offset, length: bytes.len() };
        self.pointers.push(p);
        Ok(p)
    }

    /// The total wire size of this capture buffer (header + pointer array + aligned data).
    pub fn wire_size(&self) -> usize {
        // header: max_pointers (u32) + used data length (u32) — modelled as 16 bytes for x64
        // alignment; pointer array: 8 bytes each (offset); data region.
        16 + self.pointers.len() * 8 + self.data.len()
    }
}

/// A `CSR_API_MESSAGE`: the `PORT_MESSAGE` header + the CSR body (API number + a fixed argument
/// block) + an optional [`CaptureBuffer`]. This is exactly what `CsrClientCallServer` sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsrApiMessage {
    /// The API number (`CSR_MAKE_API_NUMBER`).
    pub api_number: CsrApiNumber,
    /// The fixed in-line argument block (the CSR API's argument union, register-width slots).
    pub args: Vec<u64>,
    /// The optional capture buffer for pointer args.
    pub capture: Option<CaptureBuffer>,
}

impl CsrApiMessage {
    /// Build a `CSR_API_MESSAGE` for `api` with the given fixed args + optional capture buffer.
    pub fn new(api: CsrApiNumber, args: Vec<u64>, capture: Option<CaptureBuffer>) -> Self {
        CsrApiMessage { api_number: api, args, capture }
    }

    /// The total data length (`PORT_MESSAGE` `u1.s1.DataLength`) of this message: the CSR body plus
    /// any capture buffer. Used to fill the `PORT_MESSAGE` header before sending.
    pub fn data_length(&self) -> usize {
        // API number (u32, padded to 8) + args + capture wire size.
        8 + self.args.len() * 8 + self.capture.as_ref().map_or(0, |c| c.wire_size())
    }

    /// The total message length (header + data).
    pub fn total_length(&self) -> usize {
        PORT_MESSAGE_HEADER_LEN + self.data_length()
    }
}

/// A CSR client port: the client half of the connection to `\Windows\ApiPort`. Built by
/// `CsrClientConnectToServer` (the process-init CSR connect) and used by `CsrClientCallServer` for
/// every subsequent API call.
#[derive(Clone, Debug)]
pub struct CsrPort {
    /// The CSR port name (`\Windows\ApiPort`, folded UTF-16).
    pub name: Vec<u16>,
    /// The API dialect (CSR is classic LPC).
    pub api: PortApi,
    /// The connected comm-port handle (0 = not yet connected).
    pub handle: u64,
    /// The client's CSR process id (from `CsrClientConnectToServer` / `CsrGetProcessId`).
    pub process_id: u64,
}

impl CsrPort {
    /// `CsrClientConnectToServer(ObjectDirectory, ServerDllIndex, ConnectionInfo, …)` — model the
    /// client-side connect: name the CSR port + record the server-dll index. The actual
    /// `NtConnectPort`/`NtSecureConnectPort` is the LPC seam (returns the port unconnected here;
    /// `handle == 0` until wired).
    pub fn connect(port_name: &[u16]) -> Self {
        CsrPort {
            name: port_name.to_vec(),
            api: PortApi::Lpc,
            handle: 0,
            process_id: 0,
        }
    }

    /// Whether the port is connected (a comm-port handle has been assigned).
    pub fn is_connected(&self) -> bool {
        self.handle != 0
    }

    /// `CsrClientCallServer(Message, CaptureBuffer, ApiNumber, DataLength)` — build the
    /// `CSR_API_MESSAGE` and issue `NtRequestWaitReplyPort` on the CSR port. The message construction
    /// is done + returned; the send is the **LPC seam** (returns `STATUS_NOT_IMPLEMENTED` until the
    /// port transport is wired — never a faked reply).
    pub fn call_server(&self, msg: &CsrApiMessage) -> (CsrApiMessage, NtStatus) {
        // The message is fully built here (host-tested). The round-trip is the seam.
        let status = if self.is_connected() {
            // Real path: NtRequestWaitReplyPort(self.handle, &request, &reply) — Step 6 / LPC wire.
            STATUS_NOT_IMPLEMENTED
        } else {
            // Not connected → cannot send. Honest failure (not a fabricated success).
            STATUS_INVALID_PARAMETER
        };
        (msg.clone(), status)
    }

    /// `CsrGetProcessId()` — the client's CSR process id (assigned at connect).
    pub fn get_process_id(&self) -> u64 {
        self.process_id
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    #[test]
    fn api_number_encoding() {
        // BASESRV (index 0), CreateProcess (api 0) etc.
        let a = CsrApiNumber::make(0, 5);
        assert_eq!(a.server_dll_index(), 0);
        assert_eq!(a.api_index(), 5);
        let b = CsrApiNumber::make(2, 0x10);
        assert_eq!(b.server_dll_index(), 2);
        assert_eq!(b.api_index(), 0x10);
        assert_eq!(b.0, (2 << 16) | 0x10);
    }

    #[test]
    fn capture_buffer_packs_and_relocates() {
        let mut cb = CaptureBuffer::allocate(2, 64);
        let p1 = cb.capture(b"C:\\Windows").unwrap();
        assert_eq!(p1.offset, 0);
        assert_eq!(p1.length, 10);
        // Second capture is 8-byte aligned after the first.
        let p2 = cb.capture(b"cmd.exe").unwrap();
        assert_eq!(p2.offset, 16); // 10 -> aligned up to 16
        assert_eq!(p2.length, 7);
        assert_eq!(cb.pointers.len(), 2);
        // The packed data holds both payloads.
        assert_eq!(&cb.data[0..10], b"C:\\Windows");
        assert_eq!(&cb.data[16..23], b"cmd.exe");
    }

    #[test]
    fn capture_buffer_rejects_overflow() {
        let mut cb = CaptureBuffer::allocate(1, 8);
        // First pointer OK.
        assert!(cb.capture(b"ab").is_ok());
        // Second pointer exceeds the pointer count.
        assert_eq!(cb.capture(b"cd"), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn capture_buffer_rejects_capacity_overflow() {
        let mut cb = CaptureBuffer::allocate(4, 8);
        assert_eq!(cb.capture(b"0123456789ABCDEF"), Err(STATUS_BUFFER_TOO_SMALL));
    }

    #[test]
    fn api_message_lengths() {
        let mut cb = CaptureBuffer::allocate(1, 32);
        cb.capture(b"path").unwrap();
        let msg = CsrApiMessage::new(CsrApiNumber::make(0, 3), vec![0xdead, 0xbeef], Some(cb));
        // data = 8 (api) + 16 (2 args) + capture.wire_size()
        let expected_data = 8 + 16 + msg.capture.as_ref().unwrap().wire_size();
        assert_eq!(msg.data_length(), expected_data);
        assert_eq!(msg.total_length(), PORT_MESSAGE_HEADER_LEN + expected_data);
    }

    #[test]
    fn call_server_seam_is_honest() {
        let port = CsrPort::connect(&[b'A' as u16, b'p' as u16, b'i' as u16]);
        assert!(!port.is_connected());
        let msg = CsrApiMessage::new(CsrApiNumber::make(0, 1), vec![], None);
        // Not connected → honest failure, message still built.
        let (built, status) = port.call_server(&msg);
        assert_eq!(built, msg);
        assert_eq!(status, STATUS_INVALID_PARAMETER);

        // Connected → the send seam is unimplemented (NOT a fabricated success).
        let mut connected = port.clone();
        connected.handle = 0x1234;
        let (_built2, status2) = connected.call_server(&msg);
        assert_eq!(status2, STATUS_NOT_IMPLEMENTED);
    }
}
