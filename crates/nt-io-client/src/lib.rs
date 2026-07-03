//! # `nt-io-client` — the I/O Manager client stub
//!
//! An ergonomic Rust API over the I/O Manager service ABI. Each call encodes an
//! `nt-io-abi` request (with any inline path/data), sends it through a
//! [`Backend`], and decodes the [`IoReply`]. The backend is pluggable: an
//! in-process `DirectBackend` (calling the server, for tests / library mode) or a
//! SURT backend (for a real isolated component). This crate depends on neither the
//! server nor SURT.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::mem::size_of;

use nt_io_abi::opcodes::client;
use nt_io_abi::{
    IoCancelRequest, IoDeviceControlRequest, IoFileRequest, IoOpenRequest, IoReadWriteRequest,
    IoReply,
};
use nt_status::NtStatus;
use nt_types::{AccessMask, HandleValue};

/// A transport carrying one request to the I/O Manager and returning the reply.
/// `out_buf` receives read / IOCTL output payloads.
pub trait Backend {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> IoReply;
}

/// The I/O Manager client.
pub struct IoClient<B> {
    backend: B,
}

impl<B: Backend> IoClient<B> {
    /// Wrap a transport backend.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Access the backend (e.g. to reach the server in `DirectBackend`).
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Liveness check.
    pub fn ping(&mut self) -> NtStatus {
        NtStatus(self.backend.call(client::IO_OP_PING, &[], &mut []).status)
    }

    /// Open (create) a file on `path`, returning its handle.
    pub fn open(
        &mut self,
        path: &str,
        desired_access: AccessMask,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
    ) -> Result<HandleValue, NtStatus> {
        let units: Vec<u16> = path.encode_utf16().collect();
        let req = IoOpenRequest {
            abi_size: size_of::<IoOpenRequest>() as u16,
            flags: 0,
            desired_access: desired_access.bits(),
            share_access,
            create_disposition,
            create_options,
            path_offset: size_of::<IoOpenRequest>() as u32,
            path_len_bytes: (units.len() * 2) as u32,
        };
        let mut buf = bytemuck::bytes_of(&req).to_vec();
        for u in &units {
            buf.extend_from_slice(&u.to_le_bytes());
        }
        let r = self.backend.call(client::IO_OP_OPEN, &buf, &mut []);
        NtStatus(r.status).to_result()?;
        Ok(HandleValue(r.detail0))
    }

    /// Read up to `out.len()` bytes at `offset` into `out`; returns the count.
    pub fn read(
        &mut self,
        handle: HandleValue,
        offset: u64,
        out: &mut [u8],
    ) -> Result<u64, NtStatus> {
        let req = rw_request(handle, offset, out.len() as u32);
        let buf = bytemuck::bytes_of(&req).to_vec();
        let r = self.backend.call(client::IO_OP_READ, &buf, out);
        NtStatus(r.status).to_result()?;
        Ok(r.information)
    }

    /// Write `data` at `offset`; returns the count written.
    pub fn write(
        &mut self,
        handle: HandleValue,
        offset: u64,
        data: &[u8],
    ) -> Result<u64, NtStatus> {
        let req = rw_request(handle, offset, data.len() as u32);
        let mut buf = bytemuck::bytes_of(&req).to_vec();
        buf.extend_from_slice(data);
        let r = self.backend.call(client::IO_OP_WRITE, &buf, &mut []);
        NtStatus(r.status).to_result()?;
        Ok(r.information)
    }

    /// Buffered device control; returns the number of output bytes.
    pub fn device_control(
        &mut self,
        handle: HandleValue,
        ioctl_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<u64, NtStatus> {
        self.ioctl(
            client::IO_OP_DEVICE_CONTROL,
            handle,
            ioctl_code,
            input,
            output,
        )
    }

    /// Buffered internal device control.
    pub fn internal_device_control(
        &mut self,
        handle: HandleValue,
        ioctl_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<u64, NtStatus> {
        self.ioctl(
            client::IO_OP_INTERNAL_CONTROL,
            handle,
            ioctl_code,
            input,
            output,
        )
    }

    fn ioctl(
        &mut self,
        opcode: u16,
        handle: HandleValue,
        ioctl_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<u64, NtStatus> {
        let req = IoDeviceControlRequest {
            abi_size: size_of::<IoDeviceControlRequest>() as u16,
            flags: 0,
            ioctl_code,
            file_handle: handle.0,
            input_buffer_id: 0,
            input_offset: 0,
            output_buffer_id: 0,
            output_offset: 0,
            input_len: input.len() as u32,
            output_len: output.len() as u32,
        };
        let mut buf = bytemuck::bytes_of(&req).to_vec();
        buf.extend_from_slice(input);
        let r = self.backend.call(opcode, &buf, output);
        NtStatus(r.status).to_result()?;
        Ok(r.information)
    }

    /// Cleanup (release the user handle).
    pub fn cleanup(&mut self, handle: HandleValue) -> Result<(), NtStatus> {
        self.file_op(client::IO_OP_CLEANUP, handle)
    }

    /// Close (final dereference).
    pub fn close(&mut self, handle: HandleValue) -> Result<(), NtStatus> {
        self.file_op(client::IO_OP_CLOSE, handle)
    }

    /// Flush the file's buffers.
    pub fn flush(&mut self, handle: HandleValue) -> Result<(), NtStatus> {
        self.file_op(client::IO_OP_FLUSH, handle)
    }

    fn file_op(&mut self, opcode: u16, handle: HandleValue) -> Result<(), NtStatus> {
        let req = IoFileRequest {
            abi_size: size_of::<IoFileRequest>() as u16,
            flags: 0,
            _reserved: 0,
            file_handle: handle.0,
        };
        let buf = bytemuck::bytes_of(&req).to_vec();
        NtStatus(self.backend.call(opcode, &buf, &mut []).status).to_result()
    }

    /// Cancel an in-flight request by its id (best-effort).
    pub fn cancel(&mut self, request_id: u64) -> Result<(), NtStatus> {
        let req = IoCancelRequest {
            abi_size: size_of::<IoCancelRequest>() as u16,
            flags: 0,
            _reserved: 0,
            request_id,
        };
        let buf = bytemuck::bytes_of(&req).to_vec();
        NtStatus(
            self.backend
                .call(client::IO_OP_CANCEL, &buf, &mut [])
                .status,
        )
        .to_result()
    }
}

fn rw_request(handle: HandleValue, offset: u64, len: u32) -> IoReadWriteRequest {
    IoReadWriteRequest {
        abi_size: size_of::<IoReadWriteRequest>() as u16,
        flags: 0,
        len,
        file_handle: handle.0,
        buffer_id: 0,
        offset,
        key: 0,
        _reserved: 0,
    }
}
