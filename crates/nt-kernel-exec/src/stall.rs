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

/// Wait for a finite NT relative interval using the calibrated monotonic TSC.
/// `yield_once` relinquishes the provider lane between reads; the caller retains
/// its in-flight dispatch and returns only after the requested time has elapsed.
/// Invalid intervals or an unavailable clock fail instead of reporting success.
pub fn wait_relative_100ns(
    interval_100ns: i64,
    frequency_hz: u64,
    mut read_tsc: impl FnMut() -> u64,
    mut yield_once: impl FnMut(),
) -> Option<()> {
    if interval_100ns > 0 || frequency_hz == 0 {
        return None;
    }
    if interval_100ns == 0 {
        yield_once();
        return Some(());
    }
    let required_cycles = u64::try_from(
        (interval_100ns.unsigned_abs() as u128)
            .checked_mul(frequency_hz as u128)?
            .checked_add(9_999_999)?
            / 10_000_000,
    ).ok()?;
    let start = read_tsc();
    while !interval_elapsed(start, read_tsc(), required_cycles) {
        yield_once();
    }
    Some(())
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

    #[test]
    fn provider_relative_delay_yields_until_calibrated_monotonic_deadline() {
        use core::cell::Cell;

        let counter = Cell::new(100u64);
        let yields = Cell::new(0u32);
        // 100 ms at 1 GHz requires 100 million cycles. The first 50 ms
        // yield must not complete the request; the second must.
        assert_eq!(
            wait_relative_100ns(
                -1_000_000,
                1_000_000_000,
                || counter.get(),
                || {
                    yields.set(yields.get() + 1);
                    counter.set(counter.get() + 50_000_000);
                },
            ),
            Some(())
        );
        assert_eq!(yields.get(), 2);
        assert_eq!(counter.get(), 100_000_100);

        // A missing calibrated clock is never turned into early success.
        assert_eq!(wait_relative_100ns(-1_000_000, 0, || counter.get(), || panic!("yielded")), None);
    }
}
