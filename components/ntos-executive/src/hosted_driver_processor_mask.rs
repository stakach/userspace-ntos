//! KeQueryActiveProcessors projects the processor topology captured from boot information.

use super::*;

pub(super) const fn active_processor_mask(count: u64) -> u64 {
    nt_kernel_exec::processor_topology::active_processor_mask(count)
}

/// KAFFINITY KeQueryActiveProcessors(void).
pub(super) extern "win64" fn query_active_processors() -> u64 {
    active_processor_mask(crate::SYSTEM_PROCESSOR_COUNT.load(Ordering::Acquire))
}

/// `ULONG KeQueryActiveProcessorCountEx(USHORT GroupNumber)`.
pub(super) extern "win64" fn query_active_processor_count_ex(group: u16) -> u32 {
    nt_kernel_exec::processor_topology::active_processor_count_for_group(
        crate::SYSTEM_PROCESSOR_COUNT.load(Ordering::Acquire), group,
    )
}

/// `ULONG KeGetCurrentProcessorNumberEx(PPROCESSOR_NUMBER)`.
pub(super) extern "win64" fn current_processor_number_ex(number: u64) -> u32 {
    let count = crate::SYSTEM_PROCESSOR_COUNT.load(Ordering::Acquire);
    let Some(index) = nt_kernel_exec::processor_topology::single_processor_index(count) else {
        unsafe { crate::provider_bugcheck::report(0xc4, [count, number, 0x50524f43, 0]); }
    };
    if number != 0 {
        if number.checked_add(4).is_none() {
            unsafe { crate::provider_bugcheck::report(0xc4, [count, number, 0x50524f43, 1]); }
        }
        // PROCESSOR_NUMBER: USHORT Group, UCHAR Number, UCHAR Reserved.
        unsafe { write_unaligned(number as *mut u32, index); }
    }
    index
}

/// `NTSTATUS KeGetProcessorNumberFromIndex(ULONG, PPROCESSOR_NUMBER)`.
pub(super) extern "win64" fn processor_number_from_index(index: u32, number: u64) -> i32 {
    let count = crate::SYSTEM_PROCESSOR_COUNT.load(Ordering::Acquire);
    let Some(encoded) = nt_kernel_exec::processor_topology::processor_number_for_index(count, index)
        else { return STATUS_INVALID_PARAMETER; };
    if number == 0 || number.checked_add(4).is_none() {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe { write_unaligned(number as *mut u32, encoded); }
    0
}
