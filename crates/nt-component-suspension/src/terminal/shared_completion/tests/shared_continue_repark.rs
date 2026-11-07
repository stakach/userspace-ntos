use super::*;
use crate::{ContinueReparkOutcome, ContinueReparkPhase, SharedContinueRepark};

fn retired_outer_callback() -> (
    Lanes,
    peer_registry::PeerRoute,
    LaneDispatchIdentity,
    u64,
    peer_registry::PeerRegistry,
    IngressReceiver<ReceivedMessage>,
) {
    let (mut lanes, peers, route, dispatch, terminal, receiver) = setup(true);
    ack_all(&mut lanes, terminal);
    let retired = lanes.finish_shared_terminal(route, dispatch, terminal, 40, Ok(()))
        .unwrap().unwrap();
    assert_eq!(retired.suspension.continuation, 123);
    assert_eq!(lanes.phase(dispatch.lane()), Ok(LanePhase::Running));
    assert_eq!(lanes.external_top(dispatch.lane()), Ok(Some(77)));
    (lanes, route, dispatch, 40, peers, receiver)
}

#[test]
fn acknowledged_physical_continue_is_never_reentered_after_pure_repark_refusal() {
    let (mut lanes, route, dispatch, reply, mut peers, mut receiver) = retired_outer_callback();
    let lane = dispatch.lane();
    let token = 77;
    let mut return_owner = SharedContinueRepark::new(route, dispatch, reply, token).unwrap();

    assert!(return_owner.begin_continue(route, dispatch, reply + 1, token).is_err());
    assert!(return_owner.begin_continue(route, dispatch, reply, token + 1).is_err());
    assert_eq!(return_owner.phase(), ContinueReparkPhase::Ready);
    let attempt = return_owner.begin_continue(route, dispatch, reply, token).unwrap();
    assert_eq!(return_owner.phase(), ContinueReparkPhase::ContinueEntered);
    return_owner.record_continue(attempt,
        ContinueReparkOutcome::Acknowledged { next_reply: 41 }).unwrap();
    assert_eq!(return_owner.phase(), ContinueReparkPhase::ContinueAcknowledged);
    assert!(return_owner.begin_continue(route, dispatch, reply, token).is_err());

    let mut pending = None;
    receiver.adopt_interim_call(
        route, dispatch, 41, &mut lanes, &mut peers, &mut pending,
        |_, observed| Ok::<_, u8>(if observed == reply {
            ReplyBindingObservation::Free
        } else {
            ReplyBindingObservation::BoundToTarget
        }),
    ).unwrap();

    // A temporary lane phase refusal is memory-only. It may retry the repark, never the Call.
    lanes.suspend_running(lane, 41, 88).unwrap();
    assert!(return_owner.repark_exact(route, dispatch, reply, token, &mut lanes).is_err());
    assert_eq!(return_owner.phase(), ContinueReparkPhase::ContinueAcknowledged);
    assert!(return_owner.begin_continue(route, dispatch, reply, token).is_err());
    lanes.resume_external(lane, 41, 88).unwrap();
    lanes.retire_external_running(lane, 41, 88).unwrap();
    return_owner.repark_exact(route, dispatch, reply, token, &mut lanes).unwrap();
    assert_eq!(return_owner.phase(), ContinueReparkPhase::Done);
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    assert_eq!(lanes.external_top(lane), Ok(Some(token)));
    assert!(return_owner.repark_exact(route, dispatch, reply, token, &mut lanes).is_err());
    assert!(return_owner.begin_continue(route, dispatch, reply, token).is_err());
}

#[test]
fn acknowledged_continue_reparks_after_exact_interim_reply_adoption() {
    let (mut lanes, mut peers, route, dispatch, terminal, mut receiver) = setup(true);
    ack_all(&mut lanes, terminal);
    lanes.finish_shared_terminal(route, dispatch, terminal, 40, Ok(()))
        .unwrap().unwrap();
    let lane = dispatch.lane();
    let token = 77;
    let mut return_owner = SharedContinueRepark::new(route, dispatch, 40, token).unwrap();
    let attempt = return_owner.begin_continue(route, dispatch, 40, token).unwrap();
    return_owner.record_continue(attempt,
        ContinueReparkOutcome::Acknowledged { next_reply: 41 }).unwrap();

    // The native continue admits the next exact Call with its own bound Reply.
    let mut pending = None;
    receiver.adopt_interim_call(
        route, dispatch, 41, &mut lanes, &mut peers, &mut pending,
        |_, reply| Ok::<_, u8>(if reply == 40 {
            ReplyBindingObservation::Free
        } else {
            ReplyBindingObservation::BoundToTarget
        }),
    ).unwrap();
    assert_eq!(lanes.binding(lane).unwrap().reply_object, 41);
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));
    assert!(lanes.validate_ingress_execution(IngressExecutionOwner::Idle).is_err());

    // The acknowledged continue is never replayed; repark uses the new
    // canonical Reply and keeps the outer callback token owned.
    return_owner.repark_exact(route, dispatch, 40, token, &mut lanes).unwrap();
    assert_eq!(return_owner.phase(), ContinueReparkPhase::Done);
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    assert_eq!(lanes.external_top(lane), Ok(Some(token)));
    assert!(return_owner.begin_continue(route, dispatch, 40, token).is_err());
}

#[test]
fn acknowledged_continue_rejects_a_different_new_reply_without_replaying() {
    let (mut lanes, route, dispatch, reply, mut peers, mut receiver) =
        retired_outer_callback();
    let token = 77;
    let mut return_owner = SharedContinueRepark::new(route, dispatch, reply, token).unwrap();
    let attempt = return_owner.begin_continue(route, dispatch, reply, token).unwrap();
    return_owner.record_continue(attempt,
        ContinueReparkOutcome::Acknowledged { next_reply: 42 }).unwrap();
    let mut pending = None;
    receiver.adopt_interim_call(
        route, dispatch, 41, &mut lanes, &mut peers, &mut pending,
        |_, observed| Ok::<_, u8>(if observed == reply {
            ReplyBindingObservation::Free
        } else {
            ReplyBindingObservation::BoundToTarget
        }),
    ).unwrap();

    assert_eq!(return_owner.repark_exact(route, dispatch, reply, token, &mut lanes),
        Err(crate::LaneError::WrongBinding));
    assert_eq!(return_owner.phase(), ContinueReparkPhase::ContinueAcknowledged);
    assert_eq!(lanes.phase(dispatch.lane()), Ok(LanePhase::Running));
    assert!(return_owner.begin_continue(route, dispatch, reply, token).is_err());
}

#[test]
fn uncertain_physical_continue_retains_identity_and_fences_both_stages() {
    let (mut lanes, route, dispatch, reply, _peers, _receiver) = retired_outer_callback();
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
