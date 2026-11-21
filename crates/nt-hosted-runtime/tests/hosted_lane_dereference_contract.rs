//! ObfDereferenceObject at DISPATCH_LEVEL: one reference drops in the lane service, and final
//! deletion is deferred to a PASSIVE_LEVEL worker that runs it exactly once.

use nt_hosted_runtime::{
    HostedDereferenceObjectKind, HostedEventProjectionLifetime, HostedIrqArenaToken,
    HostedIrqLaneDirection, HostedIrqLaneIdentity, HostedLaneDeferredDeletions,
    HostedLaneDereference,
};

fn lane() -> HostedIrqLaneIdentity {
    HostedIrqLaneIdentity::new(7, 70, 3).unwrap()
}

fn service(sequence: u64) -> HostedIrqArenaToken {
    HostedIrqArenaToken {
        lane_generation: 3,
        transaction: 11,
        sequence,
        depth: 0,
        direction: HostedIrqLaneDirection::Service,
    }
}

fn recorded(sequence: u64, payload: u64) -> HostedLaneDeferredDeletions<u64> {
    let mut queue = HostedLaneDeferredDeletions::new();
    assert!(queue.try_reserve());
    assert!(queue.record(lane(), service(sequence), payload));
    queue
}

#[test]
fn object_kinds_round_trip_and_reject_unknown_words() {
    for kind in [
        HostedDereferenceObjectKind::Device,
        HostedDereferenceObjectKind::File,
        HostedDereferenceObjectKind::Event,
        HostedDereferenceObjectKind::Object,
    ] {
        assert_eq!(HostedDereferenceObjectKind::from_raw(kind as u64), Some(kind));
    }
    assert_eq!(HostedDereferenceObjectKind::from_raw(0), None);
    assert_eq!(HostedDereferenceObjectKind::from_raw(5), None);
}

#[test]
fn non_final_lane_dereference_completes_inline() {
    let mut lifetime = HostedEventProjectionLifetime::new().unwrap();
    assert!(lifetime.retain_reference());
    assert_eq!(lifetime.lane_dereference(), Some(HostedLaneDereference::Completed(1)));
    assert_eq!(lifetime.references(), 1);
    assert_eq!(lifetime.pending_acknowledgements(), 0, "no acknowledgement is left pending");
    assert!(!lifetime.retirable());
}

#[test]
fn a_parked_wait_keeps_the_last_reference_release_inline() {
    let mut lifetime = HostedEventProjectionLifetime::new().unwrap();
    assert!(lifetime.retain_wait());
    assert_eq!(lifetime.lane_dereference(), Some(HostedLaneDereference::Completed(0)));
    assert_eq!(lifetime.pending_acknowledgements(), 0);
    assert!(!lifetime.retirable(), "the wait still owns the body");
}

#[test]
fn final_lane_dereference_keeps_the_body_owned_until_its_worker_runs() {
    let mut lifetime = HostedEventProjectionLifetime::new().unwrap();
    assert_eq!(lifetime.lane_dereference(), Some(HostedLaneDereference::DeferredFinal));
    assert_eq!(lifetime.references(), 0);
    assert!(!lifetime.retirable(), "the deferred deletion still owns the body");
    assert!(!lifetime.retain_reference());
    assert_eq!(lifetime.lane_dereference(), None, "no reference is left to drop");
    // The PASSIVE worker completes the deferred acknowledgement exactly once.
    assert_eq!(lifetime.complete_dereference_ack(), Some(0));
    assert!(lifetime.retirable());
    assert_eq!(lifetime.complete_dereference_ack(), None);
}

#[test]
fn final_deletion_runs_once_only_after_the_lane_acknowledges() {
    let mut queue = recorded(5, 0x2000);
    let mut runs = Vec::new();
    assert_eq!(queue.run_ready(|payload| { runs.push(payload); true }), 0);
    assert!(runs.is_empty(), "the service result is not yet acknowledged");
    assert!(queue.observe(lane(), service(5), true));
    assert_eq!(queue.run_ready(|payload| { runs.push(payload); true }), 1);
    assert_eq!(runs, [0x2000]);
    assert!(queue.is_empty());
    assert_eq!(queue.run_ready(|payload| { runs.push(payload); true }), 0);
    assert_eq!(runs, [0x2000], "a completed deletion never runs again");
}

#[test]
fn an_uncertain_exchange_parks_the_deletion_without_replay() {
    let mut queue = recorded(5, 0x2000);
    assert!(queue.observe(lane(), service(5), false));
    assert!(!queue.observe(lane(), service(5), true), "a later ACK cannot revive it");
    assert_eq!(queue.run_ready(|_| panic!("uncertain deletion replayed")), 0);
    assert_eq!(queue.len(), 1, "the owner and its storage stay retained");
}

#[test]
fn a_refused_effect_is_retained_and_retried() {
    let mut queue = recorded(5, 0x2000);
    assert!(queue.observe(lane(), service(5), true));
    assert_eq!(queue.run_ready(|_| false), 0);
    assert!(queue.has_ready());
    assert_eq!(queue.run_ready(|_| true), 1);
    assert!(queue.is_empty());
}

#[test]
fn observation_matches_only_the_exact_lane_and_token() {
    let mut queue = recorded(5, 0x2000);
    assert!(!queue.observe(lane(), service(6), true));
    let other = HostedIrqLaneIdentity::new(7, 71, 3).unwrap();
    assert!(!queue.observe(other, service(5), true));
    assert!(!queue.has_ready());
}

#[test]
fn recording_needs_a_reserved_slot_and_a_unique_service_token() {
    let mut queue = HostedLaneDeferredDeletions::<u64>::new();
    assert!(!queue.record(lane(), service(5), 1), "no reserved slot");
    assert!(queue.try_reserve());
    let mut dispatch = service(5);
    dispatch.direction = HostedIrqLaneDirection::Dispatch;
    assert!(!queue.record(lane(), dispatch, 1));
    let mut stale = service(5);
    stale.lane_generation = 2;
    assert!(!queue.record(lane(), stale, 1));
    assert!(queue.record(lane(), service(5), 1));
    assert!(queue.try_reserve());
    assert!(!queue.record(lane(), service(5), 2), "one token owns one deletion");
}
