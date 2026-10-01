//! Select the real win32k source-IRP transport by its pinned next WDM stack.

use super::*;
use nt_io_abi::major;

/// Route only source-ledger IRPs with an authenticated next WDM stack.
pub(super) extern "win64" fn iof_call_driver(device: u64, irp: u64) -> i32 {
    unsafe {
        let Some(source) = source_irp::retain_dispatch(irp) else {
            return STATUS_INVALID_PARAMETER_I32;
        };
        let next_major = read_volatile(
            (irp + source.cursor.next_stack_offset as u64) as *const u8,
        );
        let ticket = source.ticket;
        let native_generation = source.allocation.native.allocation_generation;
        if !source_irp::release_dispatch(source) {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, next_major as u64, 1]);
        }
        match next_major {
            major::IRP_MJ_DEVICE_CONTROL | major::IRP_MJ_INTERNAL_DEVICE_CONTROL => {
                source_irp_call::iof_call_driver(device, irp)
            }
            major::IRP_MJ_PNP => source_pnp_call::iof_call_driver(device, irp),
            major::IRP_MJ_READ | major::IRP_MJ_WRITE => {
                source_fsd_call::iof_call_driver(device, irp)
            }
            _ => {
                if !source_irp::retire_unentered(irp, ticket, native_generation) {
                    crate::provider_bugcheck::report(
                        0xc4,
                        [W32_SOURCE_IOCTL_LABEL, irp, next_major as u64, 2],
                    );
                }
                STATUS_NOT_SUPPORTED_I32
            }
        }
    }
}
