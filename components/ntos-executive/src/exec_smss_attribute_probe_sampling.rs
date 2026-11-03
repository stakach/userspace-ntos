//! Pure sampling policy for SMSS attribute diagnostics.

pub(crate) const NORMAL_SAMPLE_LIMIT: u64 = 16;
pub(crate) const FAILURE_SAMPLE_LIMIT: u64 = 256;

pub(crate) fn sample_failure(ordinal: u64) -> bool {
    ordinal < FAILURE_SAMPLE_LIMIT || ordinal.is_power_of_two()
}
