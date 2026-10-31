use nt_hosted_runtime::RpcOp6ExchangeTracker;

#[test]
fn pairs_serial_requests_by_opposite_pipe_endpoint_without_response_call_id() {
    let mut tracker = RpcOp6ExchangeTracker::<2>::new();
    assert!(tracker.record_request(0x100, 7, 10));
    assert!(tracker.record_request(0x200, 9, 20));

    // A different pipe or the request endpoint cannot consume a pending request.
    assert_eq!(tracker.complete_response(0x300, 30), None);
    assert_eq!(tracker.complete_response(0x100, 30), None);
    assert_eq!(tracker.complete_response(0x101, 40), Some((7, 30)));
    assert_eq!(tracker.complete_response(0x201, 50), Some((9, 30)));

    // LiberNT response headers carry call_id 1 even for later requests. The sequence on this
    // pipe, rather than that response field, pairs the next request with the next response.
    assert!(tracker.record_request(0x100, 8, 60));
    assert_eq!(tracker.complete_response(0x101, 90), Some((8, 30)));
    let counts = tracker.counts();
    assert_eq!((counts.requests, counts.completed, counts.orphan_responses), (3, 3, 0));
}

#[test]
fn rejects_overlap_and_counts_orphan_without_replacing_a_request() {
    let mut tracker = RpcOp6ExchangeTracker::<1>::new();
    assert!(tracker.record_request(0x100, 1, 10));
    assert!(!tracker.record_request(0x100, 2, 11));
    assert_eq!(tracker.complete_response(0x101, 20), Some((1, 10)));
    assert_eq!(tracker.complete_response(0x101, 21), None);
    assert!(tracker.record_request(0x100, 2, 30));
    assert_eq!(tracker.complete_response(0x101, 40), Some((2, 10)));
    let counts = tracker.counts();
    assert_eq!((counts.requests, counts.completed, counts.overlapping_requests, counts.orphan_responses), (2, 2, 1, 1));
}

#[test]
fn bounded_tracker_does_not_replace_an_existing_pipe() {
    let mut tracker = RpcOp6ExchangeTracker::<1>::new();
    assert!(tracker.record_request(0x100, 1, 10));
    assert!(!tracker.record_request(0x200, 1, 11));
    assert_eq!(tracker.complete_response(0x101, 20), Some((1, 10)));
    assert!(!tracker.record_request(0x200, 2, 30));
    assert!(tracker.record_request(0x100, 2, 40));
    assert_eq!(tracker.complete_response(0x101, 50), Some((2, 10)));
    assert_eq!(tracker.counts().overflow, 2);
}
