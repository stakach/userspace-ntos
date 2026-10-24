//! Paired native preparation and retained-output contracts.

use super::{
    ExternalFileIrpBuffers, ExternalFileIrpOutputCapture, ExternalFileIrpRequest, IoManager,
    IoParameters, NtStatus, ObjectManagerPort, PreparedExternalFileIrp,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalFileIrpDispatchPolicy {
    /// Existing File operations enter the current top of stack and capture Information bytes.
    File,
    /// File-backed direct/neither controls enter the File's stack but retain caller-buffer writes
    /// independently of IoStatus.Information.
    FileDeviceControl,
    /// Kernel File-less controls enter the exact Device and retain method-aware output capture.
    DeviceControlAtDevice,
    /// File-less METHOD_NEITHER control whose input bytes are modified by the driver.
    MutableMethodNeitherInputAtDevice,
    /// File-less `IRP_MJ_SCSI` at one authenticated PDO, with a pointer-free SRB packet.
    ScsiAtDevice,
}

/// The retained Type3InputBuffer return occupies one preallocated page in the provider.
pub const MAX_MUTABLE_METHOD_NEITHER_INPUT: usize = 4096;

impl ExternalFileIrpDispatchPolicy {
    pub const fn output_capture(self) -> ExternalFileIrpOutputCapture {
        match self {
            Self::File => ExternalFileIrpOutputCapture::Information,
            Self::FileDeviceControl => ExternalFileIrpOutputCapture::DeviceControl,
            Self::DeviceControlAtDevice => ExternalFileIrpOutputCapture::DeviceControl,
            Self::MutableMethodNeitherInputAtDevice => {
                ExternalFileIrpOutputCapture::MethodNeitherInput
            }
            Self::ScsiAtDevice => ExternalFileIrpOutputCapture::Scsi,
        }
    }

    pub fn prepare<P: ObjectManagerPort>(
        self,
        manager: &mut IoManager<P>,
        request: ExternalFileIrpRequest,
        buffers: ExternalFileIrpBuffers,
    ) -> Result<PreparedExternalFileIrp, NtStatus> {
        if self == Self::MutableMethodNeitherInputAtDevice {
            let eligible = match &request.parameters {
                IoParameters::DeviceControl(p) | IoParameters::InternalDeviceControl(p) => {
                    nt_io_abi::ioctl::method(p.ioctl_code) == nt_io_abi::ioctl::METHOD_NEITHER
                        && p.output_len == 0
                        && p.input_len as usize == buffers.input().len()
                        && buffers.input().len() <= MAX_MUTABLE_METHOD_NEITHER_INPUT
                        && buffers.output().is_empty()
                }
                _ => false,
            };
            if !eligible {
                return Err(NtStatus::INVALID_PARAMETER);
            }
        }
        match self {
            Self::File | Self::FileDeviceControl => {
                manager.prepare_external_file_irp_owned(request, buffers)
            }
            Self::DeviceControlAtDevice | Self::MutableMethodNeitherInputAtDevice => {
                manager.prepare_external_device_control_irp_owned_at_device(request, buffers)
            }
            Self::ScsiAtDevice => {
                manager.prepare_external_scsi_irp_owned_at_device(request, buffers)
            }
        }
    }
}
