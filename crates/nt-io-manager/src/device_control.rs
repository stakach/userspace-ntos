//! Device-control (IOCTL) requests (spec §14.3, §17.4).
//!
//! Buffered controls use `SystemBuffer`, direct controls use buffered input plus
//! an MDL-style direct output buffer, and neither controls use a Type3 input
//! buffer plus `UserBuffer`. Backends whose transport cannot carry separate
//! buffers must fail closed instead of collapsing methods.

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
        validate_transfer(input.len())?;
        validate_transfer(output.len())?;

        let (file_id, device_id) =
            self.reference_open_file(client, handle, ioctl_required_access(ioctl_code))?;

        let method = ioctl::method(ioctl_code);
        let mut sysbuf: Vec<u8> = Vec::new();
        let mut direct: Vec<u8> = Vec::new();
        let mut type3: Vec<u8> = Vec::new();
        let mut user: Vec<u8> = Vec::new();
        match method {
            ioctl::METHOD_BUFFERED => {
                sysbuf.resize(input.len().max(output.len()), 0);
                sysbuf[..input.len()].copy_from_slice(input);
            }
            ioctl::METHOD_IN_DIRECT => {
                sysbuf.extend_from_slice(input);
                // METHOD_IN_DIRECT grants the driver read access to the second buffer, so preserve
                // its caller-supplied contents before dispatch.
                direct.extend_from_slice(output);
            }
            ioctl::METHOD_OUT_DIRECT => {
                sysbuf.extend_from_slice(input);
                direct.resize(output.len(), 0);
            }
            ioctl::METHOD_NEITHER => {
                type3.extend_from_slice(input);
                user.resize(output.len(), 0);
            }
            _ => unreachable!("CTL_CODE method is two bits"),
        }

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

        let direct_buffer = matches!(method, ioctl::METHOD_IN_DIRECT | ioctl::METHOD_OUT_DIRECT)
            .then_some(direct.as_mut_slice());
        let type3_input_buffer = (method == ioctl::METHOD_NEITHER).then_some(type3.as_mut_slice());
        let user_buffer = (method == ioctl::METHOD_NEITHER).then_some(user.as_mut_slice());
        let info = self.build_and_dispatch_sync_with_transfer_buffers(
            client,
            device_id,
            Some(file_id),
            fn_major,
            params,
            input.len().min(u32::MAX as usize) as u32,
            output.len().min(u32::MAX as usize) as u32,
            &mut sysbuf,
            direct_buffer,
            type3_input_buffer,
            user_buffer,
        )?;
        let n = (info as usize).min(output.len());
        match method {
            ioctl::METHOD_BUFFERED => output[..n].copy_from_slice(&sysbuf[..n]),
            ioctl::METHOD_IN_DIRECT | ioctl::METHOD_OUT_DIRECT => {
                output[..n].copy_from_slice(&direct[..n])
            }
            ioctl::METHOD_NEITHER => output[..n].copy_from_slice(&user[..n]),
            _ => unreachable!("CTL_CODE method is two bits"),
        }
        Ok(info)
    }
}
