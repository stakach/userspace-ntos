//! Hosted WDM projection allocation for isolated driver components.
//!
//! The canonical I/O Manager owns driver/device ids and namespace records. A hosted ReactOS driver
//! still receives component-local WDM object memory. This module owns that compatibility allocation
//! and linking boundary so ntoskrnl trampolines do not open-code object construction.

use core::ptr::{read_unaligned, write_unaligned};

use nt_io_manager::{write_wdm_device_object, WdmDeviceObjectInit, WDM_X64_DEVICE_OBJECT_SIZE};

const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;

pub(crate) struct HostedDeviceProjection {
    device_object: u64,
}

impl HostedDeviceProjection {
    pub(crate) fn device_object(&self) -> u64 {
        self.device_object
    }
}

/// Allocate and link a component-local x64 `DEVICE_OBJECT` plus optional device extension.
///
/// `allocate`/`free` must operate in the hosted driver's pool address space. On success, the new
/// device is inserted at `DriverObject->DeviceObject`; on failure, any allocation made here is
/// released before returning the NTSTATUS.
pub(crate) unsafe fn create_hosted_device_projection(
    driver_object: u64,
    extension_size: u64,
    device_type: u32,
    allocate: unsafe fn(u64) -> u64,
    free: unsafe fn(u64),
) -> Result<HostedDeviceProjection, i32> {
    let Some(allocation_len) = (WDM_X64_DEVICE_OBJECT_SIZE as u64).checked_add(extension_size)
    else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let Ok(allocation_len_usize) = usize::try_from(allocation_len) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let device_object = allocate(allocation_len);
    if device_object == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }

    let next_device = if driver_object != 0 {
        read_unaligned((driver_object + 8) as *const u64)
    } else {
        0
    };
    let device_extension = if extension_size != 0 {
        device_object + WDM_X64_DEVICE_OBJECT_SIZE as u64
    } else {
        0
    };

    let device_bytes =
        core::slice::from_raw_parts_mut(device_object as *mut u8, allocation_len_usize);
    if write_wdm_device_object(
        device_bytes,
        WdmDeviceObjectInit {
            driver_object,
            next_device,
            device_extension,
            device_type,
        },
    )
    .is_err()
    {
        free(device_object);
        return Err(STATUS_INVALID_PARAMETER);
    }

    if driver_object != 0 {
        write_unaligned((driver_object + 8) as *mut u64, device_object);
    }

    Ok(HostedDeviceProjection { device_object })
}
