use super::*;
use crate::{ContinueReparkOutcome, ContinueReparkPhase, SharedContinueRepark};

fn retired_outer_callback() -> (
    Lanes,
    peer_registry::PeerRoute,
    LaneDispatchIdentity,
    u64,
) {
    let (mut lanes, _peers, route, dispatch, terminal, _receiver) = setup(true);
    ack_all(&mut lanes, terminal);
    let retired = lanes.finish_shared_terminal(route, dispatch, terminal, 40, Ok(()))
        .unwrap().unwrap();
    assert_eq!(retired.suspension.continuation, 123);
    assert_eq!(lanes.phase(dispatch.lane()), Ok(LanePhase::Running));
    assert_eq!(lanes.external_top(dispatch.lane()), Ok(Some(77)));
    (lanes, route, dispatch, 40)
}

#[test]
fn acknowledged_physical_continue_is_never_reentered_after_pure_repark_refusal() {
    let (mut lanes, route, dispatch, reply) = retired_outer_callback();
    let lane = dispatch.lane();
    let token = 77;
    let mut return_owner = SharedContinueRepark::new(route, dispatch, reply, token).unwrap();

    assert!(return_owner.begin_continue(route, dispatch, reply + 1, token).is_err());
    assert!(return_owner.begin_continue(route, dispatch, reply, token + 1).is_err());
    assert_eq!(return_owner.phase(), ContinueReparkPhase::Ready);
    let attempt = return_owner.begin_continue(route, dispatch, reply, token).unwrap();
    assert_eq!(return_owner.phase(), ContinueReparkPhase::ContinueEntered);
    return_owner.record_continue(attempt, ContinueReparkOutcome::Acknowledged).unwrap();
    assert_eq!(return_owner.phase(), ContinueReparkPhase::ContinueAcknowledged);
    assert!(return_owner.begin_continue(route, dispatch, reply, token).is_err());

    // A temporary lane phase refusal is memory-only. It may retry the repark, never the Call.
    lanes.suspend_running(lane, reply, 88).unwrap();
    assert!(return_owner.repark_exact(route, dispatch, reply, token, &mut lanes).is_err());
    assert_eq!(return_owner.phase(), ContinueReparkPhase::ContinueAcknowledged);
    assert!(return_owner.begin_continue(route, dispatch, reply, token).is_err());
    lanes.resume_external(lane, reply, 88).unwrap();
    lanes.retire_external_running(lane, reply, 88).unwrap();
    return_owner.repark_exact(route, dispatch, reply, token, &mut lanes).unwrap();
    assert_eq!(return_owner.phase(), ContinueReparkPhase::Done);
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    assert_eq!(lanes.external_top(lane), Ok(Some(token)));
    assert!(return_owner.repark_exact(route, dispatch, reply, token, &mut lanes).is_err());
    assert!(return_owner.begin_continue(route, dispatch, reply, token).is_err());
}

#[test]
fn uncertain_physical_continue_retains_identity_and_fences_both_stages() {
    let (mut lanes, route, dispatch, reply) = retired_outer_callback();
    let token = 77;
    let mut return_owner = SharedContinueRepark::new(route, dispatch, reply, token).unwrap();
    let attempt = return_owner.begin_continue(route, dispatch, reply, token).unwrap();
    return_owner.record_continue(attempt, ContinueReparkOutcome::Indeterminate).unwrap();
    assert_eq!(return_owner.phase(), ContinueReparkPhase::Indeterminate);
    assert!(return_owner.begin_continue(route, dispatch, reply, token).is_err());
    assert!(return_owner.repark_exact(route, dispatch, reply, token, &mut lanes).is_err());
    assert_eq!(lanes.phase(dispatch.lane()), Ok(LanePhase::Running));
    assert_eq!(lanes.external_top(dispatch.lane()), Ok(Some(token)));
}
