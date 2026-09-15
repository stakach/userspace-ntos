use super::*;

#[test]
fn intervals_require_a_positive_bounded_yield() {
    for (minimum, maximum) in [(0, 0), (0, 10), (20, 10)] {
        assert!(matches!(
            ResumeWake::new(minimum, maximum),
            Err(ResumeWakeError::InvalidIntervals)
        ));
    }
    assert!(ResumeWake::new(1, 1).is_ok());
    assert!(ResumeWake::new(u64::MAX, u64::MAX).is_ok());
}

#[test]
fn repeated_scans_and_failed_timer_programming_do_not_acknowledge_or_postpone_work() {
    let mut wake = ResumeWake::new(10, 40).unwrap();
    assert_eq!(wake.next_deadline(), None);
    wake.reconcile(true, 0);
    for now in [0, 10, 1_000] {
        wake.reconcile(true, now);
        // Deadline observation is also the only state access a failed timer programmer needs.
        assert_eq!(wake.next_deadline(), Some(0));
    }
    let mut pass = wake.begin_pass(1_000).unwrap().unwrap();
    assert_eq!(wake.next_deadline(), None);
    wake.finish_pass(&mut pass, 1_010, false, true).unwrap();
    assert_eq!(wake.next_deadline(), None);
}

#[test]
fn readiness_during_backoff_cannot_restart_the_deadline() {
    let mut wake = ResumeWake::new(10, 40).unwrap();
    wake.reconcile(true, 100);
    let mut now = 100;
    for delay in [10, 20, 40, 40, 40] {
        let mut pass = wake.begin_pass(now).unwrap().unwrap();
        wake.finish_pass(&mut pass, now, true, false).unwrap();
        assert_eq!(wake.next_deadline(), Some(now + delay));
        wake.reconcile(true, now + 1);
        assert_eq!(wake.next_deadline(), Some(now + delay));
        assert!(wake.begin_pass(now + delay - 1).unwrap().is_none());
        now += delay;
    }
    let mut pass = wake.begin_pass(now).unwrap().unwrap();
    wake.finish_pass(&mut pass, now, true, true).unwrap();
    assert_eq!(wake.next_deadline(), Some(now + 10));
    let mut pass = wake.begin_pass(now + 10).unwrap().unwrap();
    wake.finish_pass(&mut pass, now + 10, true, false).unwrap();
    assert_eq!(wake.next_deadline(), Some(now + 20));
}

#[test]
fn running_pass_excludes_reentry_and_requires_fresh_post_effect_scan() {
    let mut wake = ResumeWake::new(10, 40).unwrap();
    wake.reconcile(true, 100);
    let mut pass = wake.begin_pass(100).unwrap().unwrap();
    for has_work in [false, true, false] {
        wake.reconcile(has_work, 200);
        assert!(wake.is_running());
        assert!(wake.begin_pass(200).unwrap().is_none());
        assert_eq!(wake.next_deadline(), None);
    }
    wake.finish_pass(&mut pass, 200, true, true).unwrap();
    assert_eq!(wake.next_deadline(), Some(210));
    assert!(!wake.is_running());
}

#[test]
fn foreign_and_consumed_tickets_cannot_finish_a_current_pass() {
    let mut first = ResumeWake::new(10, 40).unwrap();
    let mut second = ResumeWake::new(10, 40).unwrap();
    first.reconcile(true, 0);
    second.reconcile(true, 0);
    let mut a = first.begin_pass(0).unwrap().unwrap();
    let mut b = second.begin_pass(0).unwrap().unwrap();
    assert_eq!(
        second.finish_pass(&mut a, 1, false, true),
        Err(ResumeWakeError::WrongPass)
    );
    assert!(second.is_running());
    first.finish_pass(&mut a, 1, false, true).unwrap();
    first.reconcile(true, 2);
    let mut next = first.begin_pass(2).unwrap().unwrap();
    assert_eq!(
        first.finish_pass(&mut a, 2, false, true),
        Err(ResumeWakeError::WrongPass)
    );
    assert!(first.is_running());
    first.finish_pass(&mut next, 2, false, true).unwrap();
    second.finish_pass(&mut b, 2, false, true).unwrap();
}

#[test]
fn dropping_a_ticket_retains_uncertain_execution() {
    let mut wake = ResumeWake::new(10, 40).unwrap();
    wake.reconcile(true, 0);
    drop(wake.begin_pass(0).unwrap().unwrap());
    wake.reconcile(false, 10);
    wake.reconcile(true, 20);
    assert!(wake.is_running());
    assert!(wake.begin_pass(100).unwrap().is_none());
}

#[test]
fn disappearing_work_cancels_pending_wake_and_resets_backoff() {
    let mut wake = ResumeWake::new(10, 40).unwrap();
    wake.reconcile(true, 100);
    let mut pass = wake.begin_pass(100).unwrap().unwrap();
    wake.finish_pass(&mut pass, 100, true, false).unwrap();
    wake.reconcile(false, 105);
    assert_eq!(wake.next_deadline(), None);
    wake.reconcile(true, 106);
    assert_eq!(wake.next_deadline(), Some(106));
    let mut pass = wake.begin_pass(106).unwrap().unwrap();
    wake.finish_pass(&mut pass, 106, true, false).unwrap();
    assert_eq!(wake.next_deadline(), Some(116));
}

#[test]
fn exhausted_identity_and_overflow_preserve_pending_or_running_ownership() {
    let mut wake = ResumeWake::new(10, 40).unwrap();
    wake.reconcile(true, 100);
    for invalid in [0, u64::MAX] {
        let counter = AtomicU64::new(invalid);
        assert!(matches!(
            wake.begin_pass_with_counter(100, &counter),
            Err(ResumeWakeError::IdentityExhausted)
        ));
        assert_eq!(wake.next_deadline(), Some(100));
        assert_eq!(counter.load(Ordering::Relaxed), invalid);
    }
    let mut pass = wake.begin_pass(100).unwrap().unwrap();
    assert_eq!(
        wake.finish_pass(&mut pass, u64::MAX - 5, true, true),
        Err(ResumeWakeError::DeadlineOverflow)
    );
    assert!(wake.is_running());
    assert_eq!(wake.next_deadline(), None);
    wake.finish_pass(&mut pass, u64::MAX, false, true).unwrap();
    assert!(!wake.is_running());
}
