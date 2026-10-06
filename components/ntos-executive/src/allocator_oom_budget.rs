//! Fixed diagnostic emission budget; no allocation or per-frontier fairness guarantee.
pub const OOM_EMISSION_LIMIT: usize = 32;

pub fn next_oom_emission(emitted: usize) -> Option<usize> {
    (emitted < OOM_EMISSION_LIMIT).then(|| emitted + 1)
}
