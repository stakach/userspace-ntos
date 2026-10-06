use super::*;
use crate::process_identity::{ProcessGeneration, ProcessIdentity};
use nt_component_suspension::{
    ComponentIngress, ComponentSuspensionLanes, IngressReceiveDisposition, IngressReceiver,
    IngressReplyObservation, IngressReplyPool, LaneBinding, ReplyBindingObservation,
};
use nt_component_suspension::peer_registry::PeerRegistry;

fn free(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::Free)
}
fn spare_free(_: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::Free)
}
fn bound(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::BoundToTarget)
}
fn binding() -> ThreadBinding<u8> {
    ThreadBinding {
        pi: 7,
        process: ProcessIdentity {
            pid: 304,
            generation: ProcessGeneration::Hosted(2),
        },
        tid: 312,
        badge: 614,
        role: 0,
        tcb: 10,
        reservations: None,
    }
}

struct Child {
    receiver: IngressReceiver<u64>,
    call: Option<ExternalIngress<u64>>,
}
impl Child {
    fn new(reply: u64, executor: u64) -> Self {
        let lanes = ComponentSuspensionLanes::<(), (), ()>::new(1, 1);
        let mut receiver = IngressReceiver::new(20, reply, 1).unwrap();
        let mut pool = IngressReplyPool::new(20, 1).unwrap();
        pool.insert(
            ComponentIngress::new(20, reply + 1).unwrap(),
            &receiver,
            &lanes,
            spare_free,
        )
        .ok()
        .unwrap();
        receiver.begin_receive(&lanes).unwrap();
        receiver.capture(123).ok().unwrap();
        receiver
            .resolve(IngressReceiveDisposition::Call)
            .ok()
            .unwrap();
        let call = pool
            .retain_external(&mut receiver, &lanes, executor, spare_free, bound)
            .unwrap();
        Self {
            receiver,
            call: Some(call),
        }
    }
    fn settle(&mut self) -> ExternalSettlement {
        self.call
            .as_mut()
            .unwrap()
            .reply_owned(bound, |_| IngressReplyObservation::Acknowledged)
            .unwrap();
        self.receiver
            .finish_external_with_settlement(&mut self.call, free)
            .unwrap()
            .2
    }
}

struct Parent {
    lanes: ComponentSuspensionLanes<(), (), ()>,
    peers: PeerRegistry,
    receiver: IngressReceiver<u64>,
    scope: NestedExecutionScope,
}
impl Parent {
    fn new() -> Self {
        let mut lanes = ComponentSuspensionLanes::new(1, 1);
        let mut peers = PeerRegistry::new(50, 1);
        let (_, mut registration) = lanes
            .allocate_shared_staged(
                &mut peers,
                17,
                1,
                LaneBinding {
                    executor_id: 100,
                    receive_endpoint: 50,
                    reply_object: 200,
                },
            )
            .unwrap();
        let route = peers
            .publish_lane(&mut registration, 17, 1, &lanes)
            .unwrap();
        let dispatch = lanes.begin_bootstrap_dispatch(route, &peers, free).unwrap();
        let mut receiver = IngressReceiver::new(50, 60, 1).unwrap();
        let scope = receiver
            .suspend_for_nested_execution(route, dispatch, &mut lanes, &peers, free)
            .unwrap();
        Self {
            lanes,
            peers,
            receiver,
            scope,
        }
    }
    fn repark(&mut self) -> NestedExecutionScope {
        self.receiver
            .resume_nested_execution(&mut self.scope, &mut self.lanes, &self.peers, free)
            .unwrap();
        self.receiver
            .suspend_for_nested_execution(
                self.scope.route(),
                self.scope.dispatch(),
                &mut self.lanes,
                &self.peers,
                free,
            )
            .unwrap()
    }
}

#[test]
fn prepare_requires_the_original_held_call_and_real_matching_executor() {
    let mut child = Child::new(30, 10);
    for tcb in [0, 1, 11] {
        let mut wrong = binding();
        wrong.tcb = tcb;
        assert_eq!(
            ReceiveChildBarrier::prepare(child.call.as_ref().unwrap(), wrong).unwrap_err(),
            BarrierError::WrongChild
        );
    }
    let barrier = ReceiveChildBarrier::prepare(child.call.as_ref().unwrap(), binding()).unwrap();
    assert_eq!(barrier.child(), binding());
    assert_eq!(
        barrier.admission_key(),
        child.call.as_ref().unwrap().admission_key()
    );
    child
        .call
        .as_mut()
        .unwrap()
        .reply_owned(bound, |_| IngressReplyObservation::Acknowledged)
        .unwrap();
    assert_eq!(
        ReceiveChildBarrier::prepare(child.call.as_ref().unwrap(), binding()).unwrap_err(),
        BarrierError::WrongChild
    );
}

#[test]
fn parent_binding_requires_actual_scope_and_matching_dispatch_once() {
    let child = Child::new(30, 10);
    let parent = Parent::new();
    let other = Parent::new();
    let mut barrier =
        ReceiveChildBarrier::prepare(child.call.as_ref().unwrap(), binding()).unwrap();
    assert_eq!(
        barrier.bind_parent(&parent.scope, other.scope.dispatch()),
        Err(BarrierError::WrongParent)
    );
    assert_eq!(
        barrier.begin_restore(&parent.scope).unwrap_err(),
        BarrierError::Unbound
    );
    barrier
        .bind_parent(&parent.scope, parent.scope.dispatch())
        .unwrap();
    assert_eq!(
        barrier.bind_parent(&parent.scope, parent.scope.dispatch()),
        Err(BarrierError::AlreadyBound)
    );
    assert_eq!(
        barrier.begin_restore(&parent.scope).unwrap_err(),
        BarrierError::Unsettled
    );
}

#[test]
fn mismatching_child_generation_badge_tcb_or_role_returns_same_receipt() {
    let mut child = Child::new(30, 10);
    let parent = Parent::new();
    let mut barrier =
        ReceiveChildBarrier::prepare(child.call.as_ref().unwrap(), binding()).unwrap();
    barrier
        .bind_parent(&parent.scope, parent.scope.dispatch())
        .unwrap();
    let mut receipt = child.settle();
    let key = receipt.admission_key();
    for field in 0..6 {
        let mut wrong = binding();
        match field {
            0 => wrong.process.generation = ProcessGeneration::Hosted(3),
            1 => wrong.badge += 1,
            2 => wrong.tcb += 1,
            3 => wrong.role += 1,
            4 => wrong.tid += 1,
            _ => wrong.pi += 1,
        }
        let (error, retained) = barrier.accept_settlement(wrong, receipt).unwrap_err();
        assert_eq!(error, BarrierError::WrongChild);
        assert_eq!(retained.admission_key(), key);
        receipt = retained;
    }
    barrier.accept_settlement(binding(), receipt).unwrap();
    let permit = barrier.begin_restore(&parent.scope).unwrap();
    assert_eq!(permit.child(), binding());
    assert_eq!(permit.admission_key(), key);
}

#[test]
fn other_store_reservation_or_reply_cannot_settle_the_child_barrier() {
    for reply in [30, 31] {
        let child = Child::new(30, 10);
        let mut other = Child::new(reply, 10);
        let parent = Parent::new();
        let mut barrier =
            ReceiveChildBarrier::prepare(child.call.as_ref().unwrap(), binding()).unwrap();
        barrier
            .bind_parent(&parent.scope, parent.scope.dispatch())
            .unwrap();
        let receipt = other.settle();
        let key = receipt.admission_key();
        let (error, retained) = barrier.accept_settlement(binding(), receipt).unwrap_err();
        assert_eq!(error, BarrierError::WrongAdmission);
        assert_eq!(retained.admission_key(), key);
        assert_eq!(
            barrier.begin_restore(&parent.scope).unwrap_err(),
            BarrierError::Unsettled
        );
    }
}

#[test]
fn settlement_cannot_be_attached_before_parent_parking() {
    let mut child = Child::new(30, 10);
    let mut barrier =
        ReceiveChildBarrier::prepare(child.call.as_ref().unwrap(), binding()).unwrap();
    let receipt = child.settle();
    let key = receipt.admission_key();
    let (error, receipt) = barrier.accept_settlement(binding(), receipt).unwrap_err();
    assert_eq!(error, BarrierError::Unbound);
    assert_eq!(receipt.admission_key(), key);
    let parent = Parent::new();
    barrier
        .bind_parent(&parent.scope, parent.scope.dispatch())
        .unwrap();
    barrier.accept_settlement(binding(), receipt).unwrap();
    assert!(barrier.begin_restore(&parent.scope).is_ok());
}

#[test]
fn different_epoch_or_scope_nonce_cannot_authorize_parent_restore() {
    let mut child = Child::new(30, 10);
    let mut parent = Parent::new();
    let other = Parent::new();
    let mut barrier =
        ReceiveChildBarrier::prepare(child.call.as_ref().unwrap(), binding()).unwrap();
    barrier
        .bind_parent(&parent.scope, parent.scope.dispatch())
        .unwrap();
    barrier
        .accept_settlement(binding(), child.settle())
        .unwrap();
    assert_eq!(
        barrier.begin_restore(&other.scope).unwrap_err(),
        BarrierError::WrongParent
    );
    let newer = parent.repark();
    assert_eq!(newer.dispatch(), parent.scope.dispatch());
    assert_ne!(newer.identity(), parent.scope.identity());
    assert_eq!(
        barrier.begin_restore(&newer).unwrap_err(),
        BarrierError::WrongParent
    );
    assert_eq!(
        barrier.begin_restore(&parent.scope).unwrap_err(),
        BarrierError::WrongParent
    );
}

#[test]
fn issued_restore_permit_is_sticky_even_if_native_restore_is_uncertain() {
    let mut child = Child::new(30, 10);
    let parent = Parent::new();
    let mut barrier =
        ReceiveChildBarrier::prepare(child.call.as_ref().unwrap(), binding()).unwrap();
    barrier
        .bind_parent(&parent.scope, parent.scope.dispatch())
        .unwrap();
    barrier
        .accept_settlement(binding(), child.settle())
        .unwrap();
    let permit = barrier.begin_restore(&parent.scope).unwrap();
    assert_eq!(permit.parent(), parent.scope.identity());
    assert!(permit.matches_scope(&parent.scope));
    assert!(!permit.matches_scope(&Parent::new().scope));
    // Native retains this permit through an entered effect; no replacement is issued.
    assert_eq!(
        barrier.begin_restore(&parent.scope).unwrap_err(),
        BarrierError::Consumed
    );
    drop(permit);
    assert_eq!(
        barrier.begin_restore(&parent.scope).unwrap_err(),
        BarrierError::Consumed
    );
}

#[test]
fn acknowledgement_without_free_or_failed_reconciliation_keeps_barrier_unsettled() {
    let mut child = Child::new(30, 10);
    let parent = Parent::new();
    let mut barrier =
        ReceiveChildBarrier::prepare(child.call.as_ref().unwrap(), binding()).unwrap();
    barrier
        .bind_parent(&parent.scope, parent.scope.dispatch())
        .unwrap();
    child
        .call
        .as_mut()
        .unwrap()
        .reply_owned(bound, |_| IngressReplyObservation::Acknowledged)
        .unwrap();
    assert!(child
        .receiver
        .finish_external_with_settlement(&mut child.call, bound)
        .is_err());
    assert!(child
        .receiver
        .finish_external_with_settlement(&mut child.call, |_, _| Err(7u8))
        .is_err());
    assert_eq!(
        child.call.as_ref().unwrap().admission_key(),
        barrier.admission_key()
    );
    assert_eq!(
        barrier.begin_restore(&parent.scope).unwrap_err(),
        BarrierError::Unsettled
    );
    let (_, _, receipt) = child
        .receiver
        .finish_external_with_settlement(&mut child.call, free)
        .unwrap();
    barrier.accept_settlement(binding(), receipt).unwrap();
    assert!(barrier.begin_restore(&parent.scope).is_ok());
}
