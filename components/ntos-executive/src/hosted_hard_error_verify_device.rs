//! Hosted `IoSetHardErrorOrVerifyDevice` entry point.
//!
//! The root service owns the IRP, device, and ETHREAD admission and performs the
//! projection write while those owners remain serialized. This void export cannot
//! report rejection to a driver; invalid ownership is a contract violation.

use super::*;

const SET_HARD_ERROR_OR_VERIFY_DEVICE: u64 = 14;

/// `VOID IoSetHardErrorOrVerifyDevice(PIRP Irp, PDEVICE_OBJECT DeviceObject)`.
pub(super) extern "win64" fn io_set_hard_error_or_verify_device(irp: u64, device: u64) {
    let (label, status, reserved0, reserved1, reserved2) = unsafe {
        call_on4(
            (FSD_SERVICE_SOURCE_IRP_LABEL << 12) | 4,
            SET_HARD_ERROR_OR_VERIFY_DEVICE,
            irp,
            device,
            0,
        )
    };
    if label != 0 || status as u32 as i32 != STATUS_SUCCESS
        || reserved0 != 0 || reserved1 != 0 || reserved2 != 0
    {
        unsafe {
            crate::provider_bugcheck::report(
                0xc4,
                [FSD_SERVICE_SOURCE_IRP_LABEL, SET_HARD_ERROR_OR_VERIFY_DEVICE, irp, status],
            )
        }
    }
}

pub(super) fn bind(reg: &mut DriverExportRegistry) {
    reg.bind(
        "IoSetHardErrorOrVerifyDevice",
        io_set_hard_error_or_verify_device as *const () as usize as u64,
    );
}
