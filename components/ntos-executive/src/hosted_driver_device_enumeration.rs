//! Counted enumeration of one driver's admitted DEVICE_OBJECT projections.

use super::*;

const DRIVER_OBJECT_DEVICE_OBJECT: u64 = 0x08;
const DEVICE_OBJECT_DRIVER_OBJECT: u64 = 0x08;
const DEVICE_OBJECT_NEXT_DEVICE: u64 = 0x10;
const MAX_DRIVER_DEVICES: usize = 1024;

/// `NTSTATUS IoEnumerateDeviceObjectList(PDRIVER_OBJECT, PDEVICE_OBJECT*, ULONG, PULONG)`.
/// Every returned pointer owns one canonical Ob reference. The caller must release each with
/// ObfDereferenceObject/ObDereferenceObject; failure leaves no unowned published pointers.
pub(super) extern "win64" fn s_io_enumerate_device_object_list(
    driver_object: u64,
    device_list: u64,
    device_list_size: u32,
    actual_count_out: u64,
) -> i32 {
    if driver_object == 0 || actual_count_out == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        if driver_object != read_volatile((FSD_SHARED_VADDR + SH_DRVOBJ) as *const u64)
            || component_pool_allocation_capacity(driver_object)
                .is_none_or(|capacity| capacity < WDM_X64_DRIVER_OBJECT_SIZE as u64)
        {
            return STATUS_INVALID_PARAMETER;
        }
        let mut held = [0u64; MAX_DRIVER_DEVICES];
        let mut count = 0usize;
        let mut device = read_unaligned((driver_object + DRIVER_OBJECT_DEVICE_OBJECT) as *const u64);
        while device != 0 {
            if count == MAX_DRIVER_DEVICES
                || !consumer_device_object_in_local_pool(device)
                || read_unaligned((device + DEVICE_OBJECT_DRIVER_OBJECT) as *const u64)
                    != driver_object
                || held[..count].contains(&device)
            {
                for address in held[..count].iter().copied() {
                    s_obf_dereference_object(address);
                }
                return STATUS_INVALID_DEVICE_REQUEST;
            }
            // This root-acknowledged reference keeps the projection live while its NextDevice
            // pointer is read and while the complete caller-visible list is prepared.
            s_obf_reference_object(device);
            held[count] = device;
            count += 1;
            device = read_unaligned((device + DEVICE_OBJECT_NEXT_DEVICE) as *const u64);
        }
        write_unaligned(actual_count_out as *mut u32, count as u32);
        let bytes = count * core::mem::size_of::<u64>();
        if bytes > device_list_size as usize {
            for address in held[..count].iter().copied() {
                s_obf_dereference_object(address);
            }
            return STATUS_BUFFER_TOO_SMALL;
        }
        if device_list != 0 {
            if device_list.checked_add(bytes as u64).is_none() {
                for address in held[..count].iter().copied() {
                    s_obf_dereference_object(address);
                }
                return STATUS_INVALID_PARAMETER;
            }
            for (index, address) in held[..count].iter().copied().enumerate() {
                write_unaligned((device_list + index as u64 * 8) as *mut u64, address);
            }
        } else {
            // A count-only query publishes no pointers and therefore transfers no references.
            for address in held[..count].iter().copied() {
                s_obf_dereference_object(address);
            }
        }
        STATUS_SUCCESS
    }
}
