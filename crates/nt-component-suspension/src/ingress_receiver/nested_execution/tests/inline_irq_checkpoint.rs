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
fn inline_irq_checkpoint_admits_idle_receiver_without_parent_or_reply_replay() {
    let mut f = Fixture::new();
    let call_reply = f.receiver.reply();
    let (route, dispatch) = f.parent(1);
    let reply = f.lanes.binding(dispatch.lane()).unwrap().reply_object;
    let retained_reply_owner = f.receiver.retained_reply_owner(call_reply);
    assert!(retained_reply_owner.is_some());
    assert_eq!(f.receiver.stored_message(route, call_reply), Ok(&1));
    assert_eq!(f.receiver.stored_reply_acknowledged(route, dispatch, call_reply), Ok(false));

    // A suspended dispatch retains its exact route, epoch and Reply while the
    // reusable receiver has no running parent for the IRQ scheduler to park.
    f.lanes.suspend_running(dispatch.lane(), reply, 77).unwrap();
    assert_eq!(f.lanes.running(), None);
    assert!(!f.lanes.execution_busy());
    let mut idle = observation(&f, dispatch);
    assert_eq!(idle.route, Some(route));
    assert_eq!(idle.dispatch, Some(dispatch));
    assert_eq!(idle.reply, Some(reply));
    idle.execution = Some(IngressExecutionOwner::Idle);

    let mut checkpoint = InlineIrqCheckpoint::begin(route, dispatch, reply, idle).unwrap();
    assert!(!checkpoint.is_complete());
    // The no-parent scheduler pass returns the same idle receiver and cannot
    // consume or replace the retained Call's Reply.
    assert_eq!(checkpoint.verify_after(idle), Ok(()));
    assert!(checkpoint.is_complete());
    assert_eq!(checkpoint.verify_after(idle), Err(InlineIrqCheckpointError::Consumed));
    assert_eq!(f.lanes.running(), None);
    assert_eq!(f.lanes.peer_route(dispatch.lane()), Ok(Some(route)));
    assert_eq!(f.lanes.active_dispatch_identity(dispatch.lane()), Ok(Some(dispatch)));
    assert_eq!(f.lanes.binding(dispatch.lane()).unwrap().reply_object, reply);
    assert_eq!(f.receiver.retained_reply_owner(call_reply), retained_reply_owner);
    assert_eq!(f.receiver.stored_message(route, call_reply), Ok(&1));
    assert_eq!(f.receiver.stored_reply_acknowledged(route, dispatch, call_reply), Ok(false));
}

#[test]
fn inline_irq_checkpoint_rejects_unknown_or_changed_idle_owner() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let reply = f.lanes.binding(dispatch.lane()).unwrap().reply_object;
    f.lanes.suspend_running(dispatch.lane(), reply, 77).unwrap();
    let mut idle = observation(&f, dispatch);
    idle.execution = Some(IngressExecutionOwner::Idle);

    let mut unknown = idle;
    unknown.execution = None;
    assert!(matches!(
        InlineIrqCheckpoint::begin(route, dispatch, reply, unknown),
        Err(InlineIrqCheckpointError::Preflight(
            InlineIrqCheckpointMismatch::ExecutionOwner,
        ))
    ));
    let mut foreign = idle;
    foreign.execution = Some(IngressExecutionOwner::Startup(route));
    assert!(matches!(
        InlineIrqCheckpoint::begin(route, dispatch, reply, foreign),
        Err(InlineIrqCheckpointError::Preflight(
            InlineIrqCheckpointMismatch::ExecutionOwner,
        ))
    ));

    let mut checkpoint = InlineIrqCheckpoint::begin(route, dispatch, reply, idle).unwrap();
    let mut changed = idle;
    changed.execution = Some(IngressExecutionOwner::Dispatch(dispatch));
    assert_eq!(
        checkpoint.verify_after(changed),
        Err(InlineIrqCheckpointError::PostRestore(
            InlineIrqCheckpointMismatch::ExecutionOwner,
        ))
    );
    assert!(!checkpoint.is_complete());
    assert_eq!(checkpoint.verify_after(idle), Ok(()));
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
