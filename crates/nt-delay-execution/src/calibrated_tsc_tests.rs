use super::{CalibratedTscEpoch, TscClockError, TscDrift};

#[test]
fn tsc_requires_invariant_capability_and_calibrated_frequency() {
    assert_eq!(
        CalibratedTscEpoch::admit(false, 2_500_000_000, 100, 1_000),
        Err(TscClockError::NotInvariant),
    );
    assert_eq!(
        CalibratedTscEpoch::admit(true, 0, 100, 1_000),
        Err(TscClockError::Uncalibrated),
    );
}

#[test]
fn tsc_conversion_uses_hpet_epoch_and_checked_fractional_scale() {
    let epoch = CalibratedTscEpoch::admit(true, 2_500_000_000, 100, 1_000).unwrap();
    assert_eq!(epoch.time_100ns(100), Ok(1_000));
    assert_eq!(epoch.time_100ns(25_000_100), Ok(101_000)); // ten milliseconds
    assert_eq!(epoch.time_100ns(350), Ok(1_001)); // 250 cycles per 100 ns
    assert_eq!(epoch.time_100ns(349), Ok(1_000));
    assert_eq!(epoch.time_100ns(99), Err(TscClockError::CounterRegressed));
}

#[test]
fn tsc_conversion_refuses_overflow_instead_of_saturating() {
    let epoch = CalibratedTscEpoch::admit(true, 10_000_000, 10, u64::MAX - 5).unwrap();
    assert_eq!(epoch.time_100ns(15), Ok(u64::MAX));
    assert_eq!(epoch.time_100ns(16), Err(TscClockError::TimeOverflow));
    let wide = CalibratedTscEpoch::admit(true, 1, 0, 0).unwrap();
    assert_eq!(wide.time_100ns(u64::MAX), Err(TscClockError::TimeOverflow));
}

#[test]
fn tsc_regression_and_prior_time_disagreement_refuse_fast_clock() {
    let epoch = CalibratedTscEpoch::admit(true, 10_000_000, 10, 1_000).unwrap();
    assert_eq!(epoch.time_100ns_after(20, 21, 1_010), Err(TscClockError::CounterRegressed));
    assert_eq!(epoch.time_100ns_after(21, 20, 1_012), Err(TscClockError::TimeRegressed));
    assert_eq!(epoch.time_100ns_after(21, 20, 1_010), Ok(1_011));
}

#[test]
fn drift_check_marks_fast_clock_unusable_without_inventing_reference_time() {
    let epoch = CalibratedTscEpoch::admit(true, 10_000_000, 10, 1_000).unwrap();
    assert_eq!(epoch.drift_100ns(110, 1_105, 5), Ok(TscDrift::Within(5)));
    assert_eq!(epoch.drift_100ns(110, 1_106, 5), Ok(TscDrift::Exceeded(6)));
    assert_eq!(epoch.drift_100ns(110, 1_094, 5), Ok(TscDrift::Exceeded(6)));
    assert_eq!(epoch.drift_100ns(110, 999, 5), Err(TscClockError::ReferenceRegressed));
}
