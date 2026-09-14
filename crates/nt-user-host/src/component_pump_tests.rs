use super::*;

#[test]
fn counters_and_depth_follow_the_active_snapshot_across_yields() {
    let mut active = ComponentPumpAccounting::new(true);
    for slice in 1..=4 {
        active.record_fault();
        active.record_fault();
        active.record_demand();
        active.record_assert_skip();
        assert_eq!(
            active.after_slice(true, false),
            PumpDepthDisposition::Retained
        );
        let carried = active;
        assert_eq!(carried.faults(), slice * 2);
        assert_eq!(carried.demand(), slice);
        assert_eq!(carried.assert_skips(), slice);
        assert!(carried.owns_depth());
        // Budgets observe the whole invocation, not a fresh counter for each receive slice.
        assert_eq!(carried.demand() >= 3, slice >= 3);
        assert_eq!(carried.assert_skips() >= 2, slice >= 2);
        active = carried;
    }
    assert_eq!(
        active.after_slice(false, false),
        PumpDepthDisposition::Released
    );
    assert_eq!(active.faults(), 8);
    assert_eq!(active.demand(), 4);
    assert_eq!(active.assert_skips(), 4);
    assert!(!active.owns_depth());
}

#[test]
fn all_counters_saturate_without_reopening_budget() {
    let mut accounting = ComponentPumpAccounting {
        faults: u64::MAX - 1,
        demand: u64::MAX - 1,
        assert_skips: u64::MAX - 1,
        owns_depth: true,
    };
    for _ in 0..3 {
        accounting.record_fault();
        accounting.record_demand();
        accounting.record_assert_skip();
        assert_eq!(accounting.faults(), u64::MAX);
        assert_eq!(accounting.demand(), u64::MAX);
        assert_eq!(accounting.assert_skips(), u64::MAX);
        assert_eq!(
            accounting.after_slice(true, false),
            PumpDepthDisposition::Retained
        );
    }
}

#[test]
fn final_release_or_suspension_consumes_depth_once_per_active_snapshot() {
    for suspended in [false, true] {
        let mut accounting = ComponentPumpAccounting::new(true);
        assert_eq!(
            accounting.after_slice(true, false),
            PumpDepthDisposition::Retained
        );
        assert_eq!(
            accounting.after_slice(false, suspended),
            if suspended {
                PumpDepthDisposition::Suspended
            } else {
                PumpDepthDisposition::Released
            }
        );
        assert!(!accounting.owns_depth());
        for (yielded, suspended) in [(false, false), (false, true), (true, false), (true, true)] {
            assert_eq!(
                accounting.after_slice(yielded, suspended),
                PumpDepthDisposition::None
            );
        }
    }
}

#[test]
fn unowned_bootstrap_depth_stays_unowned_while_counters_accumulate() {
    let mut accounting = ComponentPumpAccounting::new(false);
    for (yielded, suspended) in [(true, false), (false, true), (false, false)] {
        accounting.record_fault();
        accounting.record_demand();
        accounting.record_assert_skip();
        assert_eq!(
            accounting.after_slice(yielded, suspended),
            PumpDepthDisposition::None
        );
        assert!(!accounting.owns_depth());
    }
    assert_eq!(accounting.faults(), 3);
    assert_eq!(accounting.demand(), 3);
    assert_eq!(accounting.assert_skips(), 3);
}

#[test]
fn yield_never_releases_or_transfers_depth() {
    let mut accounting = ComponentPumpAccounting::new(true);
    assert_eq!(
        accounting.after_slice(true, true),
        PumpDepthDisposition::Retained
    );
    assert!(accounting.owns_depth());
    assert_eq!(
        accounting.after_slice(false, true),
        PumpDepthDisposition::Suspended
    );
}
