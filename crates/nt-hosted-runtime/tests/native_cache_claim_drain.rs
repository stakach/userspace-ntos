use nt_hosted_runtime::{drain_cached_claims, CacheClaimStep};
use std::cell::RefCell;
use std::collections::VecDeque;

#[test]
fn completes_consecutive_cached_claims_before_one_physical_attempt() {
    let claims = RefCell::new(VecDeque::from([1, 2, 3, 4, 5]));
    let visited = RefCell::new(Vec::new());
    let progress = drain_cached_claims(8,
        || claims.borrow_mut().pop_front(),
        |claim| {
            visited.borrow_mut().push(claim);
            if claim < 4 { CacheClaimStep::Cached } else { CacheClaimStep::Stop(1) }
        });
    assert_eq!(progress, 4);
    assert_eq!(*visited.borrow(), [1, 2, 3, 4]);
    assert_eq!(*claims.borrow(), VecDeque::from([5]));
}

#[test]
fn uncertain_or_deferred_attempt_stops_without_replaying_a_claim() {
    for stop_progress in [0, 1] {
        let claims = RefCell::new(VecDeque::from([1, 2, 3]));
        let visited = RefCell::new(Vec::new());
        let progress = drain_cached_claims(8,
            || claims.borrow_mut().pop_front(),
            |claim| {
                visited.borrow_mut().push(claim);
                if claim == 1 { CacheClaimStep::Cached }
                else { CacheClaimStep::Stop(stop_progress) }
            });
        assert_eq!(progress, 1 + stop_progress);
        assert_eq!(*visited.borrow(), [1, 2]);
        assert_eq!(*claims.borrow(), VecDeque::from([3]));
    }
}

#[test]
fn snapshot_selection_stops_before_a_later_cached_sector() {
    // The owner alternates sector and snapshot selection. A snapshot is a physical
    // attempt, so a later cached sector must wait for another root turn.
    let claims = RefCell::new(VecDeque::from(["sector", "snapshot", "sector"]));
    let visited = RefCell::new(Vec::new());
    assert_eq!(drain_cached_claims(8,
        || claims.borrow_mut().pop_front(),
        |claim| {
            visited.borrow_mut().push(claim);
            if claim == "sector" { CacheClaimStep::Cached }
            else { CacheClaimStep::Stop(1) }
        }), 2);
    assert_eq!(*visited.borrow(), ["sector", "snapshot"]);
    assert_eq!(*claims.borrow(), VecDeque::from(["sector"]));
}

#[test]
fn finite_cap_returns_control_with_cached_work_remaining() {
    let claims = RefCell::new(VecDeque::from([1, 2, 3, 4]));
    assert_eq!(drain_cached_claims(3,
        || claims.borrow_mut().pop_front(),
        |_| CacheClaimStep::Cached), 3);
    assert_eq!(*claims.borrow(), VecDeque::from([4]));
    assert_eq!(drain_cached_claims::<(), _, _>(0, || panic!("zero cap claimed work"),
        |_| CacheClaimStep::Cached), 0);
}
