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
use crate::{DeviceId, ExternalDispatchResult, FileId, IoManager};

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

/// Buffered completion follows NT_ERROR, not NT_SUCCESS: warnings can carry output. Direct and
/// neither buffers model caller memory, whose writes are independent of IoStatus.Information.
pub(crate) fn device_control_output_len(
    method: u32,
    status: NtStatus,
    information: u64,
    capacity: u64,
) -> u64 {
    if method == ioctl::METHOD_BUFFERED {
        const STATUS_VERIFY_REQUIRED: u32 = 0x8000_0016;
        let raw = status.raw() as u32;
        if raw >> 30 == 3 || raw == STATUS_VERIFY_REQUIRED {
            0
        } else {
            information.min(capacity)
        }
    } else {
        capacity
    }
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

    /// Build a File-less device-control IRP for a canonical Device object.
    ///
    /// This is the I/O Manager analogue of `IoBuildDeviceIoControlRequest`: kernel code already
    /// holds Device-object authority, so no user handle or access check is involved. The raw driver
    /// completion is preserved so warnings such as `STATUS_BUFFER_OVERFLOW` retain their
    /// `IoStatus.Information` value. A pending result retains the canonical IRP id for the normal
    /// completion engine.
    pub fn device_control_device(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        ioctl_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<ExternalDispatchResult, NtStatus> {
        self.ioctl_device(client, device_id, ioctl_code, input, output, false)
    }

    /// Build a File-less internal-device-control IRP for a canonical Device object.
    pub fn internal_device_control_device(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        ioctl_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<ExternalDispatchResult, NtStatus> {
        self.ioctl_device(client, device_id, ioctl_code, input, output, true)
    }

    /// Build a File-less control for the exact supplied Device object, without entering devices
    /// attached above it. This models `IoBuildDeviceIoControlRequest` followed by
    /// `IoCallDriver(DeviceObject, Irp)` when the caller already holds Device-object authority.
    ///
    /// Buffered completion copies at most `min(Information, output.len())` bytes for non-error
    /// statuses other than VERIFY_REQUIRED. Direct/neither buffer writes are preserved regardless
    /// of status or Information. The raw status and Information are returned unchanged.
    /// Pending requests retain an IRP id; the caller must wait for terminal completion, copy with
    /// [`IoManager::copy_completed_device_control_output`], and acknowledge only after consuming
    /// the result. Captured direct/neither buffers do not expose original caller addresses.
    pub fn device_control_exact_device(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        ioctl_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<ExternalDispatchResult, NtStatus> {
        self.ioctl_target(
            client, device_id, None, ioctl_code, input, output, false, false, true,
        )
    }

    /// File-less internal control for the exact supplied Device object. See
    /// [`IoManager::device_control_exact_device`] for target and completion ownership semantics.
    pub fn internal_device_control_exact_device(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        ioctl_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<ExternalDispatchResult, NtStatus> {
        self.ioctl_target(
            client, device_id, None, ioctl_code, input, output, true, false, true,
        )
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
        let (file_id, device_id) =
            self.reference_open_file(client, handle, ioctl_required_access(ioctl_code))?;

        let completion = self.ioctl_target(
            client,
            device_id,
            Some(file_id),
            ioctl_code,
            input,
            output,
            internal,
            false,
            false,
        )?;
        match completion {
            ExternalDispatchResult::Completed {
                status,
                information,
                ..
            } if status.is_success() => Ok(information),
            ExternalDispatchResult::Completed { status, .. } => Err(status),
            ExternalDispatchResult::Pending { .. } => Err(NtStatus::PENDING),
        }
    }

    fn ioctl_device(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        ioctl_code: u32,
        input: &[u8],
        output: &mut [u8],
        internal: bool,
    ) -> Result<ExternalDispatchResult, NtStatus> {
        self.ioctl_target(
            client, device_id, None, ioctl_code, input, output, internal, false, false,
        )
    }

    /// Dispatch a File-less METHOD_BUFFERED control and copy the complete zero-initialized output
    /// capacity on an inline completion, independently of `IoStatus.Information`.
    ///
    /// Some standard kernel IOCTL contracts return a structured error/overflow payload while
    /// leaving Information at zero. Callers must still validate the terminal status and the
    /// contract-specific header. A pending request uses
    /// [`IoManager::copy_completed_buffered_device_control_payload`] before strict acknowledgement.
    pub fn buffered_device_control_device_payload(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        ioctl_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<ExternalDispatchResult, NtStatus> {
        if ioctl::method(ioctl_code) != ioctl::METHOD_BUFFERED {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.ioctl_target(
            client, device_id, None, ioctl_code, input, output, false, true, false,
        )
    }

    /// Dispatch a File-less METHOD_BUFFERED control to the exact supplied device object.
    ///
    /// This models `IoCallDriver(DeviceObject, Irp)`: attached devices above `device_id` are not
    /// entered. It is intended for kernel subsystems that retain authenticated provider-object
    /// authority, such as ACPI PDO method evaluation.
    pub fn buffered_device_control_exact_device_payload(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        ioctl_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<ExternalDispatchResult, NtStatus> {
        if ioctl::method(ioctl_code) != ioctl::METHOD_BUFFERED {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.ioctl_target(
            client, device_id, None, ioctl_code, input, output, false, true, true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn ioctl_target(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        file_id: Option<FileId>,
        ioctl_code: u32,
        input: &[u8],
        output: &mut [u8],
        internal: bool,
        copy_full_buffered_output: bool,
        exact_device: bool,
    ) -> Result<ExternalDispatchResult, NtStatus> {
        validate_transfer(input.len())?;
        validate_transfer(output.len())?;

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
                direct.extend_from_slice(output);
            }
            ioctl::METHOD_NEITHER => {
                type3.extend_from_slice(input);
                user.extend_from_slice(output);
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
        let completion = if exact_device {
            self.build_and_dispatch_external_to_exact_device_with_transfer_buffers(
                client,
                device_id,
                file_id,
                fn_major,
                params,
                input.len().min(u32::MAX as usize) as u32,
                output.len().min(u32::MAX as usize) as u32,
                &mut sysbuf,
                direct_buffer,
                type3_input_buffer,
                user_buffer,
            )?
        } else {
            self.build_and_dispatch_external_with_transfer_buffers(
                client,
                device_id,
                file_id,
                fn_major,
                params,
                input.len().min(u32::MAX as usize) as u32,
                output.len().min(u32::MAX as usize) as u32,
                &mut sysbuf,
                direct_buffer,
                type3_input_buffer,
                user_buffer,
            )?
        };
        if let ExternalDispatchResult::Completed {
            status,
            information,
            ..
        } = completion
        {
            let n = if copy_full_buffered_output {
                debug_assert_eq!(method, ioctl::METHOD_BUFFERED);
                output.len()
            } else {
                device_control_output_len(method, status, information, output.len() as u64) as usize
            };
            match method {
                ioctl::METHOD_BUFFERED => output[..n].copy_from_slice(&sysbuf[..n]),
                ioctl::METHOD_IN_DIRECT | ioctl::METHOD_OUT_DIRECT => {
                    output[..n].copy_from_slice(&direct[..n])
                }
                ioctl::METHOD_NEITHER => output[..n].copy_from_slice(&user[..n]),
                _ => unreachable!("CTL_CODE method is two bits"),
            }
        }
        Ok(completion)
    }
}
