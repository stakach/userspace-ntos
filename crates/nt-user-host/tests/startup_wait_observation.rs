use nt_user_host::startup_wait_observation::{
    StartupWaitKind, StartupWaitObservation, StartupWakeCause,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Owner { process: u64, thread: u64, generation: u64, sequence: u64 }

#[test]
fn stale_generation_cannot_select_or_inherit_a_replacement_wait() {
    let first = Owner { process: 7, thread: 84, generation: 12, sequence: 33 };
    let stale = Owner { generation: 11, ..first };
    let replacement = Owner { sequence: 34, ..first };
    let mut wait = StartupWaitObservation::new(first, StartupWaitKind::Alpc, 0x55, 0x99, 100);
    assert_eq!(wait.parked_age_100ns(first, 200), Some(100));
    assert_eq!(wait.snapshot(stale), None);
    assert!(!wait.mark_selected(stale, 225, StartupWakeCause::AlpcTerminal),
        "a stale generation cannot select another owner's retained Reply");
    assert!(!wait.mark_selected(replacement, 225, StartupWakeCause::AlpcTerminal));
    assert_eq!(wait.snapshot(first).unwrap().selected_at_100ns, None);
    assert!(wait.mark_selected(first, 250, StartupWakeCause::AlpcTerminal));
    assert!(!wait.mark_selected(first, 260, StartupWakeCause::AlpcTerminal));
    assert!(!wait.mark_replied(stale, 270));
    assert!(wait.mark_replied(first, 300));
    assert_eq!(wait.phase_ages_100ns(first), Some((150, 50)));
    assert_eq!(wait.phase_ages_100ns(stale), None);
    let newer = StartupWaitObservation::new(replacement, StartupWaitKind::Delay, 0, 0xa0, 400);
    assert_eq!(newer.parked_age_100ns(replacement, 410), Some(10));
    assert_eq!(newer.snapshot(first), None);
}

#[test]
fn invalid_phase_times_cannot_be_reported_as_progress() {
    let owner = Owner { process: 7, thread: 84, generation: 12, sequence: 35 };
    let mut wait = StartupWaitObservation::new(owner, StartupWaitKind::Object, 76, 0xb0, 100);
    assert!(!wait.mark_selected(owner, 99, StartupWakeCause::ObjectSignaled));
    assert!(!wait.mark_replied(owner, 110));
    assert_eq!(wait.parked_age_100ns(owner, 99), None);
    assert!(wait.mark_selected(owner, 120, StartupWakeCause::ObjectSignaled));
    assert!(!wait.mark_replied(owner, 119));
    assert!(wait.mark_replied(owner, 130));
    assert_eq!(wait.phase_ages_100ns(owner), Some((20, 10)));
}
