//! Paired native preparation and retained-output contracts.

use super::{
    ExternalFileIrpBuffers, ExternalFileIrpOutputCapture, ExternalFileIrpRequest, IoManager,
    NtStatus, ObjectManagerPort, PreparedExternalFileIrp,
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
}

impl ExternalFileIrpDispatchPolicy {
    pub const fn output_capture(self) -> ExternalFileIrpOutputCapture {
        match self {
            Self::File => ExternalFileIrpOutputCapture::Information,
            Self::FileDeviceControl => ExternalFileIrpOutputCapture::DeviceControl,
            Self::DeviceControlAtDevice => ExternalFileIrpOutputCapture::DeviceControl,
        }
    }

    pub fn prepare<P: ObjectManagerPort>(
        self,
        manager: &mut IoManager<P>,
        request: ExternalFileIrpRequest,
        buffers: ExternalFileIrpBuffers,
    ) -> Result<PreparedExternalFileIrp, NtStatus> {
        match self {
            Self::File | Self::FileDeviceControl => {
                manager.prepare_external_file_irp_owned(request, buffers)
            }
            Self::DeviceControlAtDevice => {
                manager.prepare_external_device_control_irp_owned_at_device(request, buffers)
            }
        }
    }
}
