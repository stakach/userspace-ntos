//! KeQueryActiveProcessors projects the processor topology captured from boot information.

use super::*;

pub(super) const fn active_processor_mask(count: u64) -> u64 {
    let count = if count == 0 { 1 } else if count > 64 { 64 } else { count };
    if count == 64 { u64::MAX } else { (1u64 << count) - 1 }
}

/// KAFFINITY KeQueryActiveProcessors(void).
pub(super) extern "win64" fn query_active_processors() -> u64 {
    active_processor_mask(crate::SYSTEM_PROCESSOR_COUNT.load(Ordering::Acquire))
}
