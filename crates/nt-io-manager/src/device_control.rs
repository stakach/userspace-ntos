//! Device-control (IOCTL) requests (spec §14.3, §17.4).
//!
//! v0.1 supports the buffered model (`METHOD_BUFFERED`) only: the input occupies
//! the `SystemBuffer`, the driver writes its output into it, and the result is
//! copied back to the caller's output buffer. Other transfer methods return
//! `STATUS_NOT_SUPPORTED`.

use alloc::vec;
use alloc::vec::Vec;

use nt_io_abi::{ioctl, major};
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, HandleValue};

use crate::irp::{DeviceControlParameters, IoParameters};
use crate::object_port::ObjectManagerPort;
use crate::read_write::validate_transfer;
use crate::IoManager;

/// The access an IOCTL requires, from its `CTL_CODE` access bits.
fn ioctl_required_access(code: u32) -> AccessMask {
    let a = ioctl::access(code);
    let mut req = AccessMask::empty();
    if a & ioctl::FILE_READ_ACCESS != 0 {
        req |= AccessMask::GENERIC_READ;
    }
    if a & ioctl::FILE_WRITE_ACCESS != 0 {
        req |= AccessMask::GENERIC_WRITE;
    }
    req
}

impl<P: ObjectManagerPort> IoManager<P> {
    /// Buffered device control (`IRP_MJ_DEVICE_CONTROL`, spec §17.4). Returns the
    /// number of output bytes produced.
    pub fn device_control(
        &mut self,
        client: ClientId,
        handle: HandleValue,
        ioctl_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<u64, NtStatus> {
        self.ioctl(client, handle, ioctl_code, input, output, false)
    }

    /// Buffered internal device control (`IRP_MJ_INTERNAL_DEVICE_CONTROL`).
    pub fn internal_device_control(
        &mut self,
        client: ClientId,
        handle: HandleValue,
        ioctl_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<u64, NtStatus> {
        self.ioctl(client, handle, ioctl_code, input, output, true)
    }

    fn ioctl(
        &mut self,
        client: ClientId,
        handle: HandleValue,
        ioctl_code: u32,
        input: &[u8],
        output: &mut [u8],
        internal: bool,
    ) -> Result<u64, NtStatus> {
        // v0.1: buffered method only.
        if ioctl::method(ioctl_code) != ioctl::METHOD_BUFFERED {
            return Err(NtStatus::NOT_SUPPORTED);
        }
        validate_transfer(input.len())?;
        validate_transfer(output.len())?;

        let (file_id, device_id) =
            self.reference_open_file(client, handle, ioctl_required_access(ioctl_code))?;

        // Buffered: one SystemBuffer holds the input, then receives the output.
        let cap = input.len().max(output.len());
        let mut sysbuf: Vec<u8> = vec![0u8; cap];
        sysbuf[..input.len()].copy_from_slice(input);

        let dc = DeviceControlParameters {
            ioctl_code,
            input_len: input.len() as u32,
            output_len: output.len() as u32,
        };
        let (fn_major, params) = if internal {
            (
                major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
                IoParameters::InternalDeviceControl(dc),
            )
        } else {
            (
                major::IRP_MJ_DEVICE_CONTROL,
                IoParameters::DeviceControl(dc),
            )
        };

        let info = self.build_and_dispatch_sync(
            client,
            device_id,
            Some(file_id),
            fn_major,
            params,
            &mut sysbuf,
        )?;
        let n = (info as usize).min(output.len());
        output[..n].copy_from_slice(&sysbuf[..n]);
        Ok(info)
    }
}
