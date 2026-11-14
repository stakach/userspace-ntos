use super::*;

const PERIOD: u64 = KERNEL_JOB_WAIT_HEARTBEAT_100NS;

/// A stand-in for the retained result slot of one kernel job.
#[derive(Debug, Default, Eq, PartialEq)]
struct Job(Option<u32>);

fn returned(job: &Job) -> Option<u32> {
    job.0
}

fn key(command: u64, thread: u64) -> (u64, u64) {
    (command, thread)
}

#[test]
fn parked_callout_is_reported_pending_and_never_dispatched_again() {
    let mut callouts = PendingPsCallouts::new();
    assert_eq!(callouts.settle(&key(1, 600), returned), PsCalloutState::Absent);
    callouts.retain(key(1, 600), Job(None), 10).unwrap();
    // Every retry of the same retirement finds the same parked callout: no second entry.
    for _ in 0..3 {
        assert_eq!(callouts.settle(&key(1, 600), returned), PsCalloutState::Pending);
        assert_eq!(callouts.len(), 1);
    }
    let (refused_key, refused_job) = callouts.retain(key(1, 600), Job(Some(7)), 11).unwrap_err();
    assert_eq!((refused_key, refused_job), (key(1, 600), Job(Some(7))));
    assert_eq!(callouts.settle(&key(1, 600), returned), PsCalloutState::Pending);
}

#[test]
fn granted_callout_returns_exactly_once_and_only_to_its_own_retirement() {
    let mut callouts = PendingPsCallouts::new();
    callouts.retain(key(1, 600), Job(None), 10).unwrap();
    callouts.retain(key(2, 600), Job(None), 10).unwrap();
    callouts.retain(key(1, 604), Job(None), 10).unwrap();
    assert_eq!(callouts.next_returned(returned), None);

    // The wait is granted and the provider really returns through its own completion.
    callouts.job_mut(&key(1, 600)).unwrap().0 = Some(0xc000_0001);
    assert_eq!(callouts.next_returned(returned), Some(&key(1, 600)));
    assert_eq!(callouts.nth_returned(1, returned), None);
    callouts.job_mut(&key(1, 604)).unwrap().0 = Some(0);
    assert_eq!(callouts.nth_returned(1, returned), Some(&key(1, 604)));
    callouts.job_mut(&key(1, 604)).unwrap().0 = None;
    assert_eq!(callouts.settle(&key(2, 600), returned), PsCalloutState::Pending);
    assert_eq!(callouts.settle(&key(1, 604), returned), PsCalloutState::Pending);
    assert_eq!(
        callouts.settle(&key(1, 600), returned),
        PsCalloutState::Returned(0xc000_0001)
    );
    // Consumed: a later retirement of the same identity is a fresh callout, not this result.
    assert_eq!(callouts.settle(&key(1, 600), returned), PsCalloutState::Absent);
    assert_eq!(callouts.next_returned(returned), None);
    assert_eq!(callouts.len(), 2);
}

#[test]
fn a_wait_that_is_never_granted_stays_owned_and_is_reported_every_period() {
    let mut callouts = PendingPsCallouts::new();
    callouts.retain(key(1, 600), Job(None), 100).unwrap();
    assert_eq!(callouts.next_heartbeat(100 + PERIOD - 1, returned), None);
    assert_eq!(
        callouts.next_heartbeat(100 + PERIOD, returned),
        Some((&key(1, 600), PERIOD))
    );
    // Reported once per period, with its real age, and never released by reporting.
    assert_eq!(callouts.next_heartbeat(100 + PERIOD + 1, returned), None);
    assert_eq!(
        callouts.next_heartbeat(100 + 3 * PERIOD, returned),
        Some((&key(1, 600), 3 * PERIOD))
    );
    assert_eq!(callouts.settle(&key(1, 600), returned), PsCalloutState::Pending);
    assert_eq!(callouts.len(), 1);
}

#[test]
fn returned_callouts_are_not_reported_as_waiting() {
    let mut callouts = PendingPsCallouts::new();
    callouts.retain(key(1, 600), Job(Some(0)), 100).unwrap();
    callouts.retain(key(1, 604), Job(None), 100).unwrap();
    assert_eq!(
        callouts.next_heartbeat(100 + PERIOD, returned),
        Some((&key(1, 604), PERIOD))
    );
    assert_eq!(callouts.next_heartbeat(100 + PERIOD, returned), None);
}

#[test]
fn heartbeat_clock_fires_once_per_period_and_tolerates_a_stepped_clock() {
    let mut heartbeat = KernelJobWaitHeartbeat::new(1_000);
    assert_eq!(heartbeat.due(1_000), None);
    assert_eq!(heartbeat.due(1_000 + PERIOD - 1), None);
    assert_eq!(heartbeat.due(1_000 + PERIOD), Some(PERIOD));
    assert_eq!(heartbeat.due(1_000 + PERIOD), None);
    assert_eq!(heartbeat.due(1_000 + 2 * PERIOD + 5), Some(2 * PERIOD + 5));
    // A clock that reads earlier than the origin reports nothing and does not underflow.
    assert_eq!(heartbeat.due(10), None);
}
