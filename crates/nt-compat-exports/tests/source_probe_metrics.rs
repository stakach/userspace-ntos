use nt_compat_exports::source_probe_metrics::Snapshot;

fn expected() -> Snapshot {
    Snapshot { ioctl: [8; 4], read: [2; 4], write: [2; 4], methods: [2; 4] }
}

#[test]
fn twelve_native_operations_require_every_commit_and_retirement() {
    let delta = expected();
    assert!(delta.proves_twelve_operations());
    for field in 0..4 {
        let mut missing = delta;
        missing.ioctl[field] -= 1;
        assert!(!missing.proves_twelve_operations());
        let mut missing = delta;
        missing.read[field] -= 1;
        assert!(!missing.proves_twelve_operations());
        let mut missing = delta;
        missing.write[field] -= 1;
        assert!(!missing.proves_twelve_operations());
        let mut missing = delta;
        missing.methods[field] -= 1;
        assert!(!missing.proves_twelve_operations());
    }
    let mut unrelated = delta;
    unrelated.ioctl[0] += 1;
    assert!(!unrelated.proves_twelve_operations());
}

#[test]
fn baseline_is_subtracted_without_counting_earlier_or_later_io() {
    let before = Snapshot { ioctl: [19; 4], read: [4; 4], write: [7; 4], methods: [6; 4] };
    let after = Snapshot { ioctl: [27; 4], read: [6; 4], write: [9; 4], methods: [8; 4] };
    assert_eq!(after.delta_since(before), Some(expected()));
    assert!(after.delta_since(before).unwrap().proves_twelve_operations());
    let mut regressed = after;
    regressed.read[3] = 3;
    assert_eq!(regressed.delta_since(before), None);
}

#[test]
fn delayed_retirement_is_incomplete_until_the_real_counter_advances() {
    let before = Snapshot::default();
    let mut after = expected();
    after.ioctl[3] = 7;
    assert!(!after.delta_since(before).unwrap().proves_twelve_operations());
    after.ioctl[3] += 1;
    assert!(after.delta_since(before).unwrap().proves_twelve_operations());
}
