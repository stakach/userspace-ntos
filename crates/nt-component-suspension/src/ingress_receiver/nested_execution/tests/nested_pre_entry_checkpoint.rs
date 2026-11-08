use super::*;
use alloc::boxed::Box;
use crate::{
    NestedPreEntryCheckpoint, NestedPreEntryChildReceipt, NestedPreEntryError,
    NestedPreEntryPhase, NestedPreEntryRestoreEffect, NestedPreEntryParentParkReceipt,
    NestedPreEntryParentRestoreReceipt, NestedExecutionIdentity, SuspensionKey,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Packet { address: u64, allocation_id: u64, generation: u64 }

#[derive(Debug)]
struct TerminalAck(Packet);

// Test-only stand-in for a move-only receipt issued after the source owner validates a terminal.
unsafe impl NestedPreEntryChildReceipt<Packet> for TerminalAck {
    fn child_key(&self) -> Packet { self.0 }
}

#[derive(Debug)]
struct ParkedPage(NestedExecutionIdentity);
unsafe impl NestedPreEntryParentParkReceipt for ParkedPage {
    fn scope_identity(&self) -> NestedExecutionIdentity { self.0 }
}

#[derive(Debug)]
struct RestoredPage(NestedExecutionIdentity);
unsafe impl NestedPreEntryParentRestoreReceipt for RestoredPage {
    fn scope_identity(&self) -> NestedExecutionIdentity { self.0 }
}

fn parent_and_checkpoint(
    f: &mut Fixture, packet: Packet,
) -> (PeerRoute, LaneDispatchIdentity, NestedPreEntryCheckpoint<Packet>) {
    let (route, dispatch) = f.parent(1);
    let owner = receive_owner(dispatch);
    let lane = dispatch.lane();
    let reply = f.lanes.binding(lane).unwrap().reply_object;
    let key = SuspensionKey::provider_wait(11);
    f.lanes.admit_running(lane, reply, key, 1, owner, 123).unwrap();
    f.lanes.select(key, 0).unwrap();
    f.lanes.begin_resume(lane, reply, key).unwrap();
    let checkpoint = NestedPreEntryCheckpoint::from_resuming(
        &f.lanes, route, dispatch, reply, key, owner, packet,
    ).unwrap();
    (route, dispatch, checkpoint)
}

#[test]
fn resuming_parent_requires_exact_park_and_child_ack_before_restore() {
    let mut f = Fixture::new();
    let packet = Packet { address: 0x1000, allocation_id: 7, generation: 4 };
    let (route, dispatch, mut checkpoint) = parent_and_checkpoint(&mut f, packet);
    assert!(f.lanes.fresh_dispatch_busy());
    assert_eq!(checkpoint.phase(), NestedPreEntryPhase::ResumingCandidate);
    let mut scope = f.receiver.suspend_for_nested_execution(
        route, dispatch, &mut f.lanes, &f.peers, bound,
    ).unwrap();
    checkpoint.park(&mut f.lanes, &scope, ParkedPage(scope.identity())).unwrap();
    assert_eq!(checkpoint.phase(), NestedPreEntryPhase::Parked);
    assert!(!f.lanes.fresh_dispatch_busy(), "an exact parked parent must admit its local child");
    assert!(f.receiver.resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound).is_err(),
        "the parent scope cannot restore before the child settles");
    let reply = Box::new(9u64);
    assert_eq!(checkpoint.reserve_child(packet, reply).unwrap().as_ref(), &9);
    checkpoint.child_started(packet).unwrap();
    assert_eq!(checkpoint.begin_restore(&f.lanes, &scope), Err(NestedPreEntryError::InvalidPhase));
    checkpoint.acknowledge_child(TerminalAck(packet)).unwrap();
    checkpoint.begin_restore(&f.lanes, &scope).unwrap();
    checkpoint.restore_applied(&mut f.lanes, &scope, RestoredPage(scope.identity())).unwrap();
    assert_eq!(checkpoint.phase(), NestedPreEntryPhase::ParentActive);
    f.receiver.resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound).unwrap();
}

#[test]
fn wrong_packet_generation_duplicate_and_uncertain_effect_cannot_resume_parent() {
    let mut f = Fixture::new();
    let packet = Packet { address: 0x1000, allocation_id: 7, generation: 4 };
    let stale = Packet { generation: 3, ..packet };
    let (route, dispatch, mut checkpoint) = parent_and_checkpoint(&mut f, packet);
    let scope = f.receiver.suspend_for_nested_execution(
        route, dispatch, &mut f.lanes, &f.peers, bound,
    ).unwrap();
    checkpoint.park(&mut f.lanes, &scope, ParkedPage(scope.identity())).unwrap();
    assert!(!f.lanes.fresh_dispatch_busy());
    let reply = Box::new(0xaceu64);
    let (error, reply) = checkpoint.reserve_child(stale, reply).unwrap_err();
    assert_eq!(error, NestedPreEntryError::WrongChild);
    assert_eq!(*reply, 0xace);
    checkpoint.reserve_child(packet, reply).unwrap();
    let (error, reply) = checkpoint.reserve_child(packet, Box::new(0xbeefu64)).unwrap_err();
    assert_eq!(error, NestedPreEntryError::InvalidPhase);
    assert_eq!(*reply, 0xbeef);
    checkpoint.child_started(packet).unwrap();
    assert_eq!(checkpoint.acknowledge_child(TerminalAck(stale)).unwrap_err().0, NestedPreEntryError::WrongChild);
    assert_eq!(checkpoint.begin_restore(&f.lanes, &scope), Err(NestedPreEntryError::InvalidPhase));
    checkpoint.acknowledge_child(TerminalAck(packet)).unwrap();
    assert_eq!(checkpoint.acknowledge_child(TerminalAck(packet)).unwrap_err().0, NestedPreEntryError::InvalidPhase);
    checkpoint.begin_restore(&f.lanes, &scope).unwrap();
    assert_eq!(checkpoint.finish_restore(&mut f.lanes, NestedPreEntryRestoreEffect::Uncertain), Err(NestedPreEntryError::Uncertain));
    assert_eq!(checkpoint.phase(), NestedPreEntryPhase::Uncertain);
    assert_eq!(checkpoint.restore_applied(&mut f.lanes, &scope, RestoredPage(scope.identity())).unwrap_err().0,
        NestedPreEntryError::Uncertain);
    assert!(f.lanes.fresh_dispatch_busy());
}

#[test]
fn no_effect_park_keeps_parent_resuming_and_reply_retained() {
    let mut f = Fixture::new();
    let packet = Packet { address: 0x1000, allocation_id: 7, generation: 4 };
    let (_route, _dispatch, mut checkpoint) = parent_and_checkpoint(&mut f, packet);
    checkpoint.park_no_effect().unwrap();
    assert_eq!(checkpoint.phase(), NestedPreEntryPhase::ResumingCandidate);
    let reply = Box::new(0xaceu64);
    let (error, reply) = checkpoint.reserve_child(packet, reply).unwrap_err();
    assert_eq!(error, NestedPreEntryError::InvalidPhase);
    assert_eq!(*reply, 0xace);
    assert!(f.lanes.fresh_dispatch_busy());
    checkpoint.park_uncertain().unwrap();
    assert_eq!(checkpoint.phase(), NestedPreEntryPhase::Uncertain);
    assert_eq!(checkpoint.reserve_child(packet, reply).unwrap_err().0, NestedPreEntryError::Uncertain);
}

#[test]
fn checkpoint_rejects_wrong_parent_reply_and_uncertain_child() {
    let mut f = Fixture::new();
    let packet = Packet { address: 0x1000, allocation_id: 7, generation: 4 };
    let (route, dispatch, mut checkpoint) = parent_and_checkpoint(&mut f, packet);
    let owner = receive_owner(dispatch);
    let key = SuspensionKey::provider_wait(11);
    let reply = f.lanes.binding(dispatch.lane()).unwrap().reply_object;
    assert!(matches!(
        NestedPreEntryCheckpoint::from_resuming(
            &f.lanes, route, dispatch, reply + 1, key, owner, packet,
        ),
        Err(NestedPreEntryError::WrongParent),
    ));
    let scope = f.receiver.suspend_for_nested_execution(
        route, dispatch, &mut f.lanes, &f.peers, bound,
    ).unwrap();
    checkpoint.park(&mut f.lanes, &scope, ParkedPage(scope.identity())).unwrap();
    checkpoint.reserve_child(packet, Box::new(1u64)).unwrap();
    checkpoint.child_no_effect(packet).unwrap();
    assert_eq!(checkpoint.phase(), NestedPreEntryPhase::ChildReserved);
    checkpoint.child_uncertain(&mut f.lanes, packet).unwrap();
    assert_eq!(checkpoint.phase(), NestedPreEntryPhase::Uncertain);
    assert!(f.lanes.fresh_dispatch_busy(), "an uncertain child must quarantine the page");
    assert_eq!(checkpoint.child_started(packet), Err(NestedPreEntryError::Uncertain));
    assert_eq!(checkpoint.acknowledge_child(TerminalAck(packet)).unwrap_err().0,
        NestedPreEntryError::Uncertain);
    assert_eq!(checkpoint.begin_restore(&f.lanes, &scope), Err(NestedPreEntryError::Uncertain));
    assert!(f.lanes.fresh_dispatch_busy());
    // The independent receiver is not checkpoint-aware; the native coordinator retains `scope`.
}

#[test]
fn park_and_restore_require_exact_native_scope_receipts() {
    let mut f = Fixture::new();
    let packet = Packet { address: 0x1000, allocation_id: 7, generation: 4 };
    let (route, dispatch, mut checkpoint) = parent_and_checkpoint(&mut f, packet);
    let mut scope = f.receiver.suspend_for_nested_execution(
        route, dispatch, &mut f.lanes, &f.peers, bound,
    ).unwrap();
    let mut foreign = Fixture::new();
    let (foreign_route, foreign_dispatch) = foreign.parent(2);
    let foreign_scope = foreign.receiver.suspend_for_nested_execution(
        foreign_route, foreign_dispatch, &mut foreign.lanes, &foreign.peers, bound,
    ).unwrap();
    let (error, receipt) = checkpoint.park(
        &mut f.lanes, &scope, ParkedPage(foreign_scope.identity()),
    ).unwrap_err();
    assert_eq!(error, NestedPreEntryError::WrongParent);
    assert_eq!(receipt.scope_identity(), foreign_scope.identity());
    assert!(f.lanes.fresh_dispatch_busy());
    assert_eq!(checkpoint.phase(), NestedPreEntryPhase::ResumingCandidate);
    checkpoint.park(&mut f.lanes, &scope, ParkedPage(scope.identity())).unwrap();
    checkpoint.reserve_child(packet, Box::new(1u64)).unwrap();
    checkpoint.child_started(packet).unwrap();
    checkpoint.acknowledge_child(TerminalAck(packet)).unwrap();
    checkpoint.begin_restore(&f.lanes, &scope).unwrap();
    let (error, receipt) = checkpoint.restore_applied(
        &mut f.lanes, &scope, RestoredPage(foreign_scope.identity()),
    ).unwrap_err();
    assert_eq!(error, NestedPreEntryError::WrongParent);
    assert_eq!(receipt.scope_identity(), foreign_scope.identity());
    assert!(f.receiver.resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound).is_err());
    checkpoint.restore_applied(&mut f.lanes, &scope, RestoredPage(scope.identity())).unwrap();
    f.receiver.resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound).unwrap();
}

#[test]
fn entered_child_uncertainty_quarantines_parked_parent() {
    let mut f = Fixture::new();
    let packet = Packet { address: 0x1000, allocation_id: 7, generation: 4 };
    let (route, dispatch, mut checkpoint) = parent_and_checkpoint(&mut f, packet);
    let mut scope = f.receiver.suspend_for_nested_execution(
        route, dispatch, &mut f.lanes, &f.peers, bound,
    ).unwrap();
    checkpoint.park(&mut f.lanes, &scope, ParkedPage(scope.identity())).unwrap();
    checkpoint.reserve_child(packet, Box::new(1u64)).unwrap();
    checkpoint.child_started(packet).unwrap();
    checkpoint.child_uncertain(&mut f.lanes, packet).unwrap();
    assert_eq!(checkpoint.phase(), NestedPreEntryPhase::Uncertain);
    assert!(f.lanes.fresh_dispatch_busy());
    assert!(f.receiver.resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound).is_err());
}
