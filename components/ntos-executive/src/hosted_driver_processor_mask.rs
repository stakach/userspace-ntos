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
