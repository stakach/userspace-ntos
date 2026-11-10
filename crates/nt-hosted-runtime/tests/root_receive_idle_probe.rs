use nt_hosted_runtime::{RootReceiveIdleObservation, RootReceiveIdleProbe};

fn idle() -> RootReceiveIdleObservation {
    RootReceiveIdleObservation {
        physical_shot_armed: false,
        physical_shot_due: false,
        callback_depth: 0,
        continuation_depth: 0,
        dispatch_depth: 0,
        suspended_components: 0,
    }
}

#[test]
fn no_shot_at_receive_is_sampled_without_adding_a_wake() {
    let probe = RootReceiveIdleProbe::new(1, 2, 100);
    assert!(probe.observe(idle(), 1));
    assert!(!probe.observe(idle(), 2));
    assert!(probe.observe(idle(), 101));
    assert!(!probe.observe(idle(), 102));
    assert!(probe.observe(idle(), 201));
    assert!(!probe.observe(idle(), 301));
}

#[test]
fn changed_owner_has_separate_budget_from_periodic_idle_sample() {
    let probe = RootReceiveIdleProbe::new(1, 1, 100);
    assert!(probe.observe(idle(), 1));
    let callback = RootReceiveIdleObservation { dispatch_depth: 1, ..idle() };
    assert!(!probe.observe(callback, 2));
    assert!(probe.observe(callback, 101));
    assert!(!probe.observe(callback, 102));
    assert!(!probe.observe(callback, 201));
}

#[test]
fn armed_future_shot_is_not_reported_but_overdue_shot_is() {
    let probe = RootReceiveIdleProbe::new(4, 4, 100);
    let armed = RootReceiveIdleObservation { physical_shot_armed: true, ..idle() };
    assert!(!probe.observe(armed, 1));
    assert!(probe.observe(RootReceiveIdleObservation {
        physical_shot_due: true, ..armed
    }, 2));
    assert!(!probe.observe(armed, 3));
    assert!(probe.observe(idle(), 4));
}
