//! Hosted WDM projection allocation for isolated driver components.
//!
//! The canonical I/O Manager owns driver/device ids and namespace records. A hosted ReactOS driver
//! still receives component-local WDM object memory. This module owns that compatibility allocation
//! and linking boundary so ntoskrnl trampolines do not open-code object construction.

use core::ptr::{read_unaligned, write_unaligned};

use nt_io_manager::{write_wdm_device_object, WdmDeviceObjectInit, WDM_X64_DEVICE_OBJECT_SIZE};

const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;
const WDM_X64_DRIVER_OBJECT_DEVICE_OBJECT_OFFSET: u64 = 0x08;
const WDM_X64_DEVICE_OBJECT_DRIVER_OBJECT_OFFSET: u64 = 0x08;
const WDM_X64_DEVICE_OBJECT_NEXT_DEVICE_OFFSET: u64 = 0x10;
const WDM_X64_DEVICE_OBJECT_ATTACHED_DEVICE_OFFSET: u64 = 0x18;
const WDM_X64_DEVICE_OBJECT_STACK_SIZE_OFFSET: u64 = 0x4c;

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
    flags: u32,
    characteristics: u32,
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
            flags,
            characteristics,
            device_type,
            stack_size: 1,
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

/// Unlink and release a component-local `DEVICE_OBJECT` allocated by
/// [`create_hosted_device_projection`].
///
/// The caller is responsible for checking canonical I/O Manager lifetime first. This only mutates the
/// hosted driver's local WDM list (`DriverObject->DeviceObject` / `DeviceObject->NextDevice`) and
/// returns the allocation to the hosted pool.
pub(crate) unsafe fn delete_hosted_device_projection(device_object: u64, free: unsafe fn(u64)) {
    if device_object == 0 {
        return;
    }

    let driver_object =
        read_unaligned((device_object + WDM_X64_DEVICE_OBJECT_DRIVER_OBJECT_OFFSET) as *const u64);
    let next_device =
        read_unaligned((device_object + WDM_X64_DEVICE_OBJECT_NEXT_DEVICE_OFFSET) as *const u64);
    if driver_object != 0 {
        unlink_driver_device(driver_object, device_object, next_device);
    }

    write_unaligned(device_object as *mut u16, 0);
    free(device_object);
}

/// Component-local half of `IoAttachDeviceToDeviceStack`.
///
/// Returns the lower device object that `source_device` attached to, matching the WDM API. The
/// canonical I/O Manager stack should be updated by the caller when both pointers correspond to
/// registered devices.
pub(crate) unsafe fn attach_hosted_device_projection(
    source_device: u64,
    target_device: u64,
) -> Option<u64> {
    if source_device == 0 || target_device == 0 || source_device == target_device {
        return None;
    }

    let mut lower = target_device;
    let mut guard = 0usize;
    loop {
        let upper =
            read_unaligned((lower + WDM_X64_DEVICE_OBJECT_ATTACHED_DEVICE_OFFSET) as *const u64);
        if upper == 0 {
            break;
        }
        if upper == source_device || guard >= 1024 {
            return None;
        }
        lower = upper;
        guard += 1;
    }

    let lower_stack =
        read_unaligned((lower + WDM_X64_DEVICE_OBJECT_STACK_SIZE_OFFSET) as *const u8);
    let source_stack = lower_stack.max(1).saturating_add(1);
    write_unaligned(
        (lower + WDM_X64_DEVICE_OBJECT_ATTACHED_DEVICE_OFFSET) as *mut u64,
        source_device,
    );
    write_unaligned(
        (source_device + WDM_X64_DEVICE_OBJECT_ATTACHED_DEVICE_OFFSET) as *mut u64,
        0,
    );
    write_unaligned(
        (source_device + WDM_X64_DEVICE_OBJECT_STACK_SIZE_OFFSET) as *mut u8,
        source_stack,
    );
    Some(lower)
}

/// Component-local half of `IoDetachDevice`.
pub(crate) unsafe fn detach_hosted_device_projection(lower_device: u64) {
    if lower_device == 0 {
        return;
    }
    let upper =
        read_unaligned((lower_device + WDM_X64_DEVICE_OBJECT_ATTACHED_DEVICE_OFFSET) as *const u64);
    if upper != 0 {
        write_unaligned(
            (lower_device + WDM_X64_DEVICE_OBJECT_ATTACHED_DEVICE_OFFSET) as *mut u64,
            0,
        );
        write_unaligned(
            (upper + WDM_X64_DEVICE_OBJECT_STACK_SIZE_OFFSET) as *mut u8,
            1,
        );
    }
}

pub(crate) unsafe fn hosted_attached_device(lower_device: u64) -> u64 {
    if lower_device == 0 {
        return 0;
    }
    read_unaligned((lower_device + WDM_X64_DEVICE_OBJECT_ATTACHED_DEVICE_OFFSET) as *const u64)
}

unsafe fn unlink_driver_device(driver_object: u64, device_object: u64, next_device: u64) {
    let head_slot = (driver_object + WDM_X64_DRIVER_OBJECT_DEVICE_OBJECT_OFFSET) as *mut u64;
    let head = read_unaligned(head_slot as *const u64);
    if head == device_object {
        write_unaligned(head_slot, next_device);
        return;
    }

    let mut current = head;
    let mut guard = 0usize;
    while current != 0 && guard < 1024 {
        let next_slot = (current + WDM_X64_DEVICE_OBJECT_NEXT_DEVICE_OFFSET) as *mut u64;
        let candidate = read_unaligned(next_slot as *const u64);
        if candidate == device_object {
            write_unaligned(next_slot, next_device);
            return;
        }
        current = candidate;
        guard += 1;
    }
}
