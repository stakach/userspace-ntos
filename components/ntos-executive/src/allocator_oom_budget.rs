//! Fixed diagnostic emission budget; no allocation or per-frontier fairness guarantee.
pub const OOM_EMISSION_LIMIT: usize = 32;

pub fn next_oom_emission(emitted: usize) -> Option<usize> {
    (emitted < OOM_EMISSION_LIMIT).then(|| emitted + 1)
}

/// Durable allocations at least this large are reported as `[alloc-large]`.
pub const LARGE_ALLOCATION_BYTES: usize = 256 * 1024;
/// Reports per power-of-two size class. A table that doubles lands in a new class each time,
/// so a repeated buffer size cannot use up the reports its growth needs.
pub const LARGE_EMISSIONS_PER_CLASS: usize = 8;
const LARGE_CLASS_BITS: u32 = 4;
const LARGE_CLASSES: u32 = usize::BITS / LARGE_CLASS_BITS;
const _: () = assert!(LARGE_EMISSIONS_PER_CLASS < 1 << LARGE_CLASS_BITS);

/// `state` packs one count per size class, starting at zero. Returns the state to store when
/// an allocation of `size` bytes should be reported.
pub fn next_large_emission(state: usize, size: usize) -> Option<usize> {
    if size < LARGE_ALLOCATION_BYTES {
        return None;
    }
    let class = (size.ilog2() - LARGE_ALLOCATION_BYTES.ilog2()).min(LARGE_CLASSES - 1);
    let shift = class * LARGE_CLASS_BITS;
    let emitted = (state >> shift) & ((1 << LARGE_CLASS_BITS) - 1);
    (emitted < LARGE_EMISSIONS_PER_CLASS).then(|| state + (1 << shift))
}
