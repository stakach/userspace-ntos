//! x64 processor-group projection for one NT processor group.

/// This host currently admits at most one 64-processor NT group.
pub const fn active_processor_count(count: u64) -> u32 {
    if count == 0 { 1 } else if count > 64 { 64 } else { count as u32 }
}

pub const fn active_processor_mask(count: u64) -> u64 {
    let count = active_processor_count(count);
    if count == 64 { u64::MAX } else { (1u64 << count) - 1 }
}

/// `ALL_PROCESSOR_GROUPS` is 0xffff. A nonzero concrete group does not exist.
pub const fn active_processor_count_for_group(count: u64, group: u16) -> u32 {
    if group == 0 || group == u16::MAX { active_processor_count(count) } else { 0 }
}
