//! A scheduler pass may temporarily park its parent, but the exact route,
//! dispatch and Reply must return before the retained receive can continue.

use super::*;
use crate::{
    InlineIrqCheckpoint, InlineIrqCheckpointError, InlineIrqCheckpointMismatch,
    InlineIrqCheckpointObservation, IngressExecutionOwner,
};

fn observation(f: &Fixture, dispatch: LaneDispatchIdentity) -> InlineIrqCheckpointObservation {
    let lane = dispatch.lane();
    InlineIrqCheckpointObservation {
        route: f.lanes.peer_route(lane).unwrap(),
        dispatch: f.lanes.active_dispatch_identity(lane).unwrap(),
        reply: Some(f.lanes.binding(lane).unwrap().reply_object),
        execution: f.lanes.running().map(|running| {
            IngressExecutionOwner::Dispatch(
                f.lanes.active_dispatch_identity(running).unwrap().unwrap(),
            )
        }),
    }
}

#[test]
fn inline_irq_checkpoint_rejects_each_preflight_identity_before_scheduler_entry() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let reply = f.lanes.binding(dispatch.lane()).unwrap().reply_object;
    let before = observation(&f, dispatch);

    // The existing native preflight asks only whether *a* Dispatch owns
    // execution. Record that behavior while the live phase remains unknown;
    // the post-scheduler check still requires the captured exact dispatch.
    let mut other = Fixture::new();
    let (_, other_dispatch) = other.parent(2);
    let mut other_running = before;
    other_running.execution = Some(IngressExecutionOwner::Dispatch(other_dispatch));
    let mut captured = InlineIrqCheckpoint::begin(route, dispatch, reply, other_running).unwrap();
    assert_eq!(
        captured.verify_after(other_running),
        Err(InlineIrqCheckpointError::PostRestore(
            InlineIrqCheckpointMismatch::ExecutionOwner,
        ))
    );

    let mut missing_route = before;
    missing_route.route = None;
    assert!(matches!(
        InlineIrqCheckpoint::begin(route, dispatch, reply, missing_route),
        Err(InlineIrqCheckpointError::Preflight(InlineIrqCheckpointMismatch::Route))
    ));
    let mut missing_dispatch = before;
    missing_dispatch.dispatch = None;
    assert!(matches!(
        InlineIrqCheckpoint::begin(route, dispatch, reply, missing_dispatch),
        Err(InlineIrqCheckpointError::Preflight(InlineIrqCheckpointMismatch::Dispatch))
    ));
    let mut wrong_reply = before;
    wrong_reply.reply = Some(reply + 1);
    assert!(matches!(
        InlineIrqCheckpoint::begin(route, dispatch, reply, wrong_reply),
        Err(InlineIrqCheckpointError::Preflight(InlineIrqCheckpointMismatch::Reply))
    ));
}

#[test]
fn inline_irq_checkpoint_retains_parent_until_exact_nested_restore() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let reply = f.lanes.binding(dispatch.lane()).unwrap().reply_object;
    let mut checkpoint = InlineIrqCheckpoint::begin(
        route, dispatch, reply, observation(&f, dispatch),
    )
    .unwrap();

    let mut parent = f.receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    let parked = observation(&f, dispatch);
    assert_eq!(parked.route, Some(route));
    assert_eq!(parked.dispatch, Some(dispatch));
    assert_eq!(parked.reply, Some(reply));
    assert_eq!(parked.execution, None);
    assert_eq!(
        checkpoint.verify_after(parked),
        Err(InlineIrqCheckpointError::PostRestore(
            InlineIrqCheckpointMismatch::ExecutionOwner,
        ))
    );
    assert!(!checkpoint.is_complete());

    f.receiver
        .resume_nested_execution(&mut parent, &mut f.lanes, &f.peers, bound)
        .unwrap();
    let restored = observation(&f, dispatch);
    let mut replaced_reply = restored;
    replaced_reply.reply = Some(reply + 1);
    assert_eq!(
        checkpoint.verify_after(replaced_reply),
        Err(InlineIrqCheckpointError::PostRestore(
            InlineIrqCheckpointMismatch::Reply,
        ))
    );
    assert!(!checkpoint.is_complete());
    assert_eq!(checkpoint.verify_after(restored), Ok(()));
    assert!(checkpoint.is_complete());
}
