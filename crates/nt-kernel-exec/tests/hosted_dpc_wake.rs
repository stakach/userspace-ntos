use nt_component_suspension::ResumeWake;
use nt_kernel_exec::{HostedDpcOwner, HostedDpcTable};

#[test]
fn pre_dispatch_abort_preserves_exact_activation_through_retry_backoff() {
    let owner = HostedDpcOwner::new(1, 2, 3).unwrap();
    let mut dpcs = HostedDpcTable::new();
    let id = dpcs.register(owner, 10, 20, 30).unwrap();
    dpcs.queue(id, 40, 50).unwrap();
    let mut wake = ResumeWake::new(10, 40).unwrap();
    wake.reconcile(dpcs.has_queued(), 100);
    let mut pass = wake.begin_pass(100).unwrap().unwrap();
    let first = dpcs.begin_next(owner).unwrap().unwrap();
    dpcs.abort(first).unwrap();
    wake.finish_pass(&mut pass, 101, dpcs.has_queued(), false)
        .unwrap();
    assert_eq!(wake.next_deadline(), Some(111));
    assert!(wake.begin_pass(110).unwrap().is_none());
    let mut retry = wake.begin_pass(111).unwrap().unwrap();
    let retained = dpcs.begin_next(owner).unwrap().unwrap();
    assert_eq!(retained, first);
    dpcs.complete(retained).unwrap();
    wake.finish_pass(&mut retry, 112, dpcs.has_queued(), true)
        .unwrap();
    assert_eq!(wake.next_deadline(), None);
}

#[test]
fn busy_queue_retains_deadline_and_nested_scans_cannot_claim_a_pass() {
    let owner = HostedDpcOwner::new(1, 2, 3).unwrap();
    let mut dpcs = HostedDpcTable::new();
    let id = dpcs.register(owner, 10, 20, 30).unwrap();
    dpcs.queue(id, 0, 0).unwrap();
    let mut wake = ResumeWake::new(10, 40).unwrap();
    wake.reconcile(dpcs.has_queued(), 100);
    let mut pass = wake.begin_pass(100).unwrap().unwrap();
    wake.reconcile(dpcs.has_queued(), 101);
    assert!(wake.begin_pass(101).unwrap().is_none());
    wake.finish_pass(&mut pass, 101, dpcs.has_queued(), false)
        .unwrap();
    for now in 102..111 {
        wake.reconcile(dpcs.has_queued(), now);
        assert_eq!(wake.next_deadline(), Some(111));
        assert!(wake.begin_pass(now).unwrap().is_none());
    }
    let mut retry = wake.begin_pass(111).unwrap().unwrap();
    let activation = dpcs.begin_next(owner).unwrap().unwrap();
    dpcs.complete(activation).unwrap();
    wake.finish_pass(&mut retry, 112, dpcs.has_queued(), true)
        .unwrap();
    assert_eq!(wake.next_deadline(), None);
}

#[test]
fn self_requeue_retains_paced_wake_without_an_unrelated_event() {
    let owner = HostedDpcOwner::new(1, 2, 3).unwrap();
    let mut dpcs = HostedDpcTable::new();
    let id = dpcs.register(owner, 10, 20, 30).unwrap();
    dpcs.queue(id, 0, 0).unwrap();
    let mut wake = ResumeWake::new(10, 40).unwrap();
    wake.reconcile(dpcs.has_queued(), 100);
    let mut pass = wake.begin_pass(100).unwrap().unwrap();
    let activation = dpcs.begin_next(owner).unwrap().unwrap();
    // An empty intermediate queue does not acknowledge a running pass.
    wake.reconcile(dpcs.has_queued(), 101);
    dpcs.queue(id, 0, 0).unwrap();
    dpcs.complete(activation).unwrap();
    wake.finish_pass(&mut pass, 102, dpcs.has_queued(), true)
        .unwrap();
    assert_eq!(wake.next_deadline(), Some(112));
    // Timer observation (including a failed hardware program) consumes nothing.
    assert_eq!(wake.next_deadline(), Some(112));
    assert!(wake.begin_pass(111).unwrap().is_none());
    let mut next = wake.begin_pass(112).unwrap().unwrap();
    let activation = dpcs.begin_next(owner).unwrap().unwrap();
    dpcs.complete(activation).unwrap();
    wake.finish_pass(&mut next, 113, dpcs.has_queued(), true)
        .unwrap();
    assert_eq!(wake.next_deadline(), None);
}

#[test]
fn repeated_due_observations_preserve_the_queued_activation_and_retry_deadline() {
    let owner = HostedDpcOwner::new(1, 2, 3).unwrap();
    let mut dpcs = HostedDpcTable::new();
    let id = dpcs.register(owner, 10, 20, 30).unwrap();
    dpcs.queue(id, 40, 50).unwrap();
    let mut wake = ResumeWake::new(10, 40).unwrap();
    wake.reconcile(dpcs.has_queued(), 100);
    let mut pass = wake.begin_pass(100).unwrap().unwrap();
    let original = dpcs.begin_next(owner).unwrap().unwrap();
    dpcs.abort(original).unwrap();
    wake.finish_pass(&mut pass, 101, dpcs.has_queued(), false)
        .unwrap();

    // Repeated timer scans, including overdue scans, must not acknowledge or postpone demand.
    for now in 102..120 {
        wake.reconcile(dpcs.has_queued(), now);
        assert_eq!(wake.next_deadline(), Some(111));
        assert_eq!(
            wake.next_deadline().is_some_and(|due| due <= now),
            now >= 111
        );
        assert!(!wake.is_running());
        assert!(dpcs.has_queued());
    }
    let mut retry = wake.begin_pass(120).unwrap().unwrap();
    let retained = dpcs.begin_next(owner).unwrap().unwrap();
    assert_eq!(retained, original);
    dpcs.complete(retained).unwrap();
    wake.finish_pass(&mut retry, 121, dpcs.has_queued(), true)
        .unwrap();
    assert_eq!(wake.next_deadline(), None);
    assert!(dpcs.begin_next(owner).unwrap().is_none());
}

#[test]
fn cancelling_last_queued_dpc_retires_wake_and_new_work_starts_fresh() {
    let owner = HostedDpcOwner::new(1, 2, 3).unwrap();
    let mut dpcs = HostedDpcTable::new();
    let id = dpcs.register(owner, 10, 20, 30).unwrap();
    let mut wake = ResumeWake::new(10, 40).unwrap();
    dpcs.queue(id, 0, 0).unwrap();
    wake.reconcile(dpcs.has_queued(), 100);
    assert!(dpcs.remove(id).unwrap());
    wake.reconcile(dpcs.has_queued(), 101);
    assert_eq!(wake.next_deadline(), None);
    dpcs.queue(id, 0, 0).unwrap();
    wake.reconcile(dpcs.has_queued(), 200);
    assert_eq!(wake.next_deadline(), Some(200));
}
