//! # `nt-io-server` — the I/O Manager service dispatcher
//!
//! The transport-agnostic half of I/O service mode: it wraps an [`IoManager`] and
//! turns decoded wire requests into I/O Manager calls. A SURT binding (the
//! `io-manager` component) feeds it opcodes + request/response buffers; this crate
//! does **no** transport itself, so it is fully host-testable.
//!
//! v0.1 uses an **inline** buffer model: a request's variable data (an open path,
//! write bytes, IOCTL input) follows the fixed header in the request buffer, and
//! read/IOCTL output is written into the reply buffer. (Zero-copy registered SURT
//! buffers are a later optimisation.) Requests are bounds-checked with
//! `bytemuck::try_pod_read_unaligned` + explicit slice checks — a malformed or
//! truncated request returns an error reply, never a panic.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::mem::size_of;

use bytemuck::Pod;
use nt_io_abi::opcodes::client;
use nt_io_abi::{
    IoCancelRequest, IoDeviceControlRequest, IoFileRequest, IoOpenRequest, IoReadWriteRequest,
    IoReply,
};
use nt_io_manager::{CreateOptions, IoManager, IrpId, ObjectManagerPort, ShareAccess};
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, HandleValue, NtPath};

/// The I/O Manager service: an [`IoManager`] plus a wire-request dispatcher.
pub struct IoServer<P> {
    io: IoManager<P>,
}

impl<P: ObjectManagerPort> IoServer<P> {
    /// Wrap an I/O Manager (already set up with its drivers/devices).
    pub fn new(io: IoManager<P>) -> Self {
        Self { io }
    }

    /// Borrow the underlying I/O Manager (to create drivers/devices, etc.).
    pub fn io_mut(&mut self) -> &mut IoManager<P> {
        &mut self.io
    }

    /// A new client connection: register it (its handles live in the Object
    /// Manager) and return the assigned id.
    pub fn connect(&mut self) -> ClientId {
        self.io.register_client()
    }

    /// A client disconnected or faulted: free its IRPs + files + close it.
    pub fn disconnect(&mut self, client: ClientId) -> Result<(), NtStatus> {
        self.io.disconnect_client(client)
    }

    /// Drive pending IRP completions (the transport calls this from its loop).
    pub fn pump(&mut self) -> usize {
        self.io.pump()
    }

    /// Dispatch one request from `client`. `in_buf` holds the typed request + any
    /// inline payload; `out_buf` receives read/IOCTL output. Always returns a
    /// reply — a bad request yields an error status, never a panic.
    pub fn dispatch(
        &mut self,
        client: ClientId,
        opcode: u16,
        in_buf: &[u8],
        out_buf: &mut [u8],
    ) -> IoReply {
        match self.try_dispatch(client, opcode, in_buf, out_buf) {
            Ok(r) => r,
            Err(status) => reply(status, 0, 0),
        }
    }

    fn try_dispatch(
        &mut self,
        client: ClientId,
        opcode: u16,
        in_buf: &[u8],
        out_buf: &mut [u8],
    ) -> Result<IoReply, NtStatus> {
        match opcode {
            client::IO_OP_PING => Ok(ok()),
            client::IO_OP_OPEN => self.op_open(client, in_buf),
            client::IO_OP_READ => self.op_read(client, in_buf, out_buf),
            client::IO_OP_WRITE => self.op_write(client, in_buf),
            client::IO_OP_DEVICE_CONTROL => self.op_ioctl(client, in_buf, out_buf, false),
            client::IO_OP_INTERNAL_CONTROL => self.op_ioctl(client, in_buf, out_buf, true),
            client::IO_OP_CLEANUP => self.op_cleanup(client, in_buf),
            client::IO_OP_CLOSE => self.op_close(client, in_buf),
            client::IO_OP_FLUSH => self.op_flush(client, in_buf),
            client::IO_OP_CANCEL => self.op_cancel(client, in_buf),
            _ => Err(NtStatus::NOT_IMPLEMENTED),
        }
    }

    fn op_open(&mut self, client: ClientId, in_buf: &[u8]) -> Result<IoReply, NtStatus> {
        let req: IoOpenRequest = read_req(in_buf)?;
        let path = read_path(in_buf, req.path_offset, req.path_len_bytes)?;
        let handle = self.io.open(
            client,
            &path,
            AccessMask::from_bits_retain(req.desired_access),
            ShareAccess::from_bits_retain(req.share_access),
            CreateOptions::from_bits_retain(req.create_options),
            req.create_disposition,
        )?;
        Ok(reply(NtStatus::SUCCESS, 0, handle.0))
    }

    fn op_read(
        &mut self,
        client: ClientId,
        in_buf: &[u8],
        out_buf: &mut [u8],
    ) -> Result<IoReply, NtStatus> {
        let req: IoReadWriteRequest = read_req(in_buf)?;
        let n = (req.len as usize).min(out_buf.len());
        let info = self.io.read(
            client,
            HandleValue(req.file_handle),
            req.offset,
            &mut out_buf[..n],
        )?;
        Ok(reply(NtStatus::SUCCESS, info, 0))
    }

    fn op_write(&mut self, client: ClientId, in_buf: &[u8]) -> Result<IoReply, NtStatus> {
        let req: IoReadWriteRequest = read_req(in_buf)?;
        let data = read_inline(in_buf, size_of::<IoReadWriteRequest>(), req.len as usize)?;
        let info = self
            .io
            .write(client, HandleValue(req.file_handle), req.offset, data)?;
        Ok(reply(NtStatus::SUCCESS, info, 0))
    }

    fn op_ioctl(
        &mut self,
        client: ClientId,
        in_buf: &[u8],
        out_buf: &mut [u8],
        internal: bool,
    ) -> Result<IoReply, NtStatus> {
        let req: IoDeviceControlRequest = read_req(in_buf)?;
        let input = read_inline(
            in_buf,
            size_of::<IoDeviceControlRequest>(),
            req.input_len as usize,
        )?;
        let n = (req.output_len as usize).min(out_buf.len());
        let handle = HandleValue(req.file_handle);
        let info = if internal {
            self.io.internal_device_control(
                client,
                handle,
                req.ioctl_code,
                input,
                &mut out_buf[..n],
            )?
        } else {
            self.io
                .device_control(client, handle, req.ioctl_code, input, &mut out_buf[..n])?
        };
        Ok(reply(NtStatus::SUCCESS, info, 0))
    }

    fn op_cleanup(&mut self, client: ClientId, in_buf: &[u8]) -> Result<IoReply, NtStatus> {
        let req: IoFileRequest = read_req(in_buf)?;
        self.io.cleanup(client, HandleValue(req.file_handle))?;
        Ok(ok())
    }

    fn op_close(&mut self, client: ClientId, in_buf: &[u8]) -> Result<IoReply, NtStatus> {
        let req: IoFileRequest = read_req(in_buf)?;
        self.io.close(client, HandleValue(req.file_handle))?;
        Ok(ok())
    }

    fn op_flush(&mut self, client: ClientId, in_buf: &[u8]) -> Result<IoReply, NtStatus> {
        let req: IoFileRequest = read_req(in_buf)?;
        self.io.flush(client, HandleValue(req.file_handle))?;
        Ok(ok())
    }

    fn op_cancel(&mut self, client: ClientId, in_buf: &[u8]) -> Result<IoReply, NtStatus> {
        let req: IoCancelRequest = read_req(in_buf)?;
        // Best-effort: the client correlates a request by its IRP id. The
        // library's cancel is a safe no-op for an unknown/already-final IRP.
        self.io.cancel(client, IrpId(req.request_id))?;
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

fn read_inline(buf: &[u8], offset: usize, len: usize) -> Result<&[u8], NtStatus> {
    let end = offset.checked_add(len).ok_or(NtStatus::INVALID_PARAMETER)?;
    buf.get(offset..end).ok_or(NtStatus::INVALID_PARAMETER)
}

fn read_path(buf: &[u8], offset: u32, len_bytes: u32) -> Result<NtPath, NtStatus> {
    let bytes = read_inline(buf, offset as usize, len_bytes as usize)?;
    if bytes.len() % 2 != 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    NtPath::parse(&units)
}

fn reply(status: NtStatus, information: u64, detail0: u64) -> IoReply {
    IoReply {
        status: status.raw(),
        flags: 0,
        information,
        detail0,
        detail1: 0,
    }
}

fn ok() -> IoReply {
    reply(NtStatus::SUCCESS, 0, 0)
}
