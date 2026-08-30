//! Arithmetic for calibrated TSC-backed kernel stalls.

/// Convert a requested microsecond interval to TSC cycles, rounding up so a nonzero stall cannot
/// complete early. A zero frequency is not a timing authority and integer overflow fails closed.
pub fn cycles_for_microseconds(microseconds: u32, frequency_hz: u64) -> Option<u64> {
    if microseconds == 0 {
        return Some(0);
    }
    if frequency_hz == 0 {
        return None;
    }
    let numerator = (microseconds as u128)
        .checked_mul(frequency_hz as u128)?
        .checked_add(999_999)?;
    u64::try_from(numerator / 1_000_000).ok()
}

/// Test an elapsed TSC interval using wrapping subtraction, matching the architectural counter's
/// modulo-2^64 behavior.
pub const fn interval_elapsed(start: u64, now: u64, required_cycles: u64) -> bool {
    now.wrapping_sub(start) >= required_cycles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_microseconds_with_ceil_semantics() {
        assert_eq!(cycles_for_microseconds(0, 0), Some(0));
        assert_eq!(cycles_for_microseconds(1, 1_000_000_000), Some(1000));
        assert_eq!(cycles_for_microseconds(1, 1_000_001), Some(2));
        assert_eq!(cycles_for_microseconds(250, 2_400_000_000), Some(600_000));
        assert_eq!(cycles_for_microseconds(1, 0), None);
    }

    #[test]
    fn elapsed_test_handles_counter_wrap() {
        let start = u64::MAX - 4;
        assert!(!interval_elapsed(start, 2, 8));
        assert!(interval_elapsed(start, 3, 8));
    }
}
