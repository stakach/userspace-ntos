//! Return a fresh NT physical RAM run array from the boot adapter's retained firmware map.
//!
//! The caller owns the pool allocation and releases it with ExFreePool. Reserved and ACPI
//! firmware extents are excluded; a zero pair terminates the copied array.

use nt_compat_exports::configuration::{
    physical_memory_ranges_from_firmware, PhysicalMemoryRange,
};

pub(super) extern "win64" fn mm_get_physical_memory_ranges() -> u64 {
    let firmware = crate::loader_firmware_memory_map();
    let Some(bytes) = firmware
        .len()
        .checked_add(1)
        .and_then(|count| count.checked_mul(core::mem::size_of::<PhysicalMemoryRange>()))
        .and_then(|bytes| u64::try_from(bytes).ok())
    else {
        return 0;
    };
    let allocated = unsafe { super::pool_alloc(bytes) };
    if allocated == 0 {
        return 0;
    }
    let output = unsafe {
        core::slice::from_raw_parts_mut(
            allocated as *mut PhysicalMemoryRange,
            firmware.len() + 1,
        )
    };
    if physical_memory_ranges_from_firmware(firmware, output).is_err() {
        unsafe { super::pool_free(allocated) };
        return 0;
    }
    allocated
}
