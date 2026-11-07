use super::*;
use crate::process_identity::{ProcessGeneration, ProcessIdentity};
use crate::thread_binding::ThreadBinding;
use nt_component_suspension::{
    peer_registry::PeerRegistry, ComponentIngress, ComponentSuspensionLanes, ExternalIngress,
    IngressReceiveDisposition, IngressReceiver, IngressReplyObservation, IngressReplyPool,
    LaneBinding, NestedExecutionScope, ReplyBindingObservation,
};

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
    fn new(reply: u64) -> Self {
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
        receiver.capture(191).ok().unwrap();
        receiver
            .resolve(IngressReceiveDisposition::Call)
            .ok()
            .unwrap();
        let call = pool
            .retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap();
        Self {
            receiver,
            call: Some(call),
        }
    }

    fn settle(&mut self) -> nt_component_suspension::ExternalSettlement {
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

fn new_parent() -> NestedExecutionScope {
    let mut lanes = ComponentSuspensionLanes::<(), (), ()>::new(1, 1);
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
    let mut receiver = IngressReceiver::<u64>::new(50, 60, 1).unwrap();
    receiver
        .suspend_for_nested_execution(route, dispatch, &mut lanes, &peers, free)
        .unwrap()
}

#[test]
fn undelivered_unwind_seals_exact_prepared_child_without_delivery() {
    let child = Child::new(83);
    let foreign = Child::new(93);
    let call = child.call.as_ref().unwrap();
    let mut pass = RootIngressPass::prepare(call, binding()).unwrap();
    assert_eq!(
        pass.begin_undelivered_unwind(binding(), foreign.call.as_ref().unwrap()).unwrap_err(),
        PassError::WrongChild,
    );
    let mut foreign_binding = binding();
    foreign_binding.tid += 1;
    assert_eq!(pass.begin_undelivered_unwind(foreign_binding, call).unwrap_err(), PassError::WrongChild);
    let token = pass.begin_undelivered_unwind(binding(), call).unwrap();
    assert_eq!(token.child(), binding());
    assert_eq!(token.admission_key(), call.admission_key());
    let parent = new_parent();
    assert_eq!(pass.bind_parent(&parent, parent.dispatch()).unwrap_err(), PassError::AlreadyBound);
    assert!(pass.is_undelivered_unwind(&token));
    assert_eq!(unsafe { pass.deliver(binding(), call) }.unwrap_err(), PassError::InvalidPhase);
    assert_eq!(pass.begin_undelivered_unwind(binding(), call).unwrap_err(), PassError::Consumed);
}

#[test]
fn selected_import_entry_seals_one_attempt_until_positive_delivery() {
    let child = Child::new(113);
    let parent = new_parent();
    let call = child.call.as_ref().unwrap();
    let mut pass = RootIngressPass::prepare(call, binding()).unwrap();
    pass.bind_parent(&parent, parent.dispatch()).unwrap();
    let mut foreign_binding = binding();
    foreign_binding.tid += 1;
    assert_eq!(pass.begin_import(foreign_binding, call).unwrap_err(), PassError::WrongChild);
    pass.begin_import(binding(), call).unwrap();
    assert_eq!(pass.begin_import(binding(), call).unwrap_err(), PassError::Consumed);
    assert_eq!(pass.begin_restore(&parent).unwrap_err(), PassError::Unsettled);
    // A false/uncertain native callback leaves this phase sealed. Only a positive observation
    // of that same attempt may make the child an ordinary delivered root event.
    unsafe { pass.deliver(binding(), call) }.unwrap();
    assert_eq!(pass.begin_import(binding(), call).unwrap_err(), PassError::Consumed);
}

#[test]
fn acknowledged_child_checkpoints_exact_parent_once() {
    let mut child = Child::new(30);
    let mut foreign_child = Child::new(60);
    let parent = new_parent();
    let key = child.call.as_ref().unwrap().admission_key();
    let mut pass = RootIngressPass::prepare(child.call.as_ref().unwrap(), binding()).unwrap();
    pass.bind_parent(&parent, parent.dispatch()).unwrap();
    assert_eq!(
        unsafe { pass.deliver(binding(), foreign_child.call.as_ref().unwrap()) }
            .unwrap_err(),
        PassError::WrongChild,
    );
    pass.begin_import(binding(), child.call.as_ref().unwrap()).unwrap();
    unsafe { pass.deliver(binding(), child.call.as_ref().unwrap()) }
        .unwrap();
    assert_eq!(
        pass.begin_restore(&parent).unwrap_err(),
        PassError::Unsettled
    );
    let foreign_settlement = foreign_child.settle();
    let (error, returned) = pass
        .acknowledge_settlement(binding(), foreign_settlement)
        .unwrap_err();
    assert_eq!(error, PassError::WrongChild);
    assert_ne!(returned.admission_key(), key);
    assert_eq!(
        pass.begin_restore(&parent).unwrap_err(),
        PassError::Unsettled
    );
    let settled = child.settle();
    pass.acknowledge_settlement(binding(), settled).unwrap();
    let permit = pass.begin_restore(&parent).unwrap();
    assert_eq!(permit.parent(), parent.identity());
    assert_eq!(permit.child(), binding());
    assert_eq!(permit.admission_key(), key);
    assert_eq!(permit.checkpoint().parent(), parent.identity());
    assert_eq!(permit.checkpoint().child(), key);
    assert!(permit.settlement().is_some());
    // Native supplies the positive physical restore observation; the exact nonclone child
    // settlement must survive the transfer into the resulting receipt.
    let mut restored = unsafe { permit.acknowledge_restore() };
    assert!(!restored.parked_child());
    assert_eq!(restored.take_settlement().unwrap().admission_key(), key);
    assert!(!restored.parked_child());
    assert_eq!(
        pass.begin_restore(&parent).unwrap_err(),
        PassError::Consumed
    );
}

#[test]
fn parked_child_restores_parent_but_keeps_its_reply_for_later_settlement() {
    let mut child = Child::new(40);
    let parent = new_parent();
    let key = child.call.as_ref().unwrap().admission_key();
    let mut pass = RootIngressPass::prepare(child.call.as_ref().unwrap(), binding()).unwrap();
    pass.bind_parent(&parent, parent.dispatch()).unwrap();
    pass.begin_import(binding(), child.call.as_ref().unwrap()).unwrap();
    unsafe { pass.deliver(binding(), child.call.as_ref().unwrap()) }
        .unwrap();
    pass.begin_park(binding(), child.call.as_ref().unwrap())
        .unwrap();
    assert_eq!(
        pass.begin_restore(&parent).unwrap_err(),
        PassError::Unsettled
    );
    let mut wrong = binding();
    wrong.tcb += 1;
    assert_eq!(
        unsafe { pass.acknowledge_park(wrong, child.call.as_ref().unwrap()) }
            .unwrap_err(),
        PassError::WrongChild,
    );
    assert_eq!(
        pass.begin_restore(&parent).unwrap_err(),
        PassError::Unsettled
    );
    // Native calls acknowledge_park only after its RootReplyPark::commit succeeds.
    unsafe { pass.acknowledge_park(binding(), child.call.as_ref().unwrap()) }
        .unwrap();
    let permit = pass.begin_restore(&parent).unwrap();
    assert_eq!(permit.parent(), parent.identity());
    assert_eq!(permit.checkpoint().parent(), parent.identity());
    assert_eq!(permit.checkpoint().child(), key);
    assert!(permit.settlement().is_none());
    assert_eq!(
        pass.begin_restore(&parent).unwrap_err(),
        PassError::Consumed
    );
    assert!(child.call.as_ref().unwrap().can_park());
    let later = child.settle();
    assert_eq!(later.admission_key(), key);
}

#[test]
fn unknown_park_refuses_until_exact_later_settlement() {
    let mut child = Child::new(50);
    let parent = new_parent();
    let foreign_parent = new_parent();
    let mut pass = RootIngressPass::prepare(child.call.as_ref().unwrap(), binding()).unwrap();
    pass.bind_parent(&parent, parent.dispatch()).unwrap();
    pass.begin_import(binding(), child.call.as_ref().unwrap()).unwrap();
    unsafe { pass.deliver(binding(), child.call.as_ref().unwrap()) }
        .unwrap();
    pass.begin_park(binding(), child.call.as_ref().unwrap())
        .unwrap();
    assert_eq!(
        pass.begin_park(binding(), child.call.as_ref().unwrap())
            .unwrap_err(),
        PassError::InvalidPhase
    );
    assert_eq!(
        pass.begin_restore(&parent).unwrap_err(),
        PassError::Unsettled
    );
    assert_eq!(
        pass.begin_restore(&foreign_parent).unwrap_err(),
        PassError::WrongParent
    );
    assert!(child.call.as_ref().unwrap().can_park());
    // A later positive child settlement reconciles uncertainty without replaying park.
    pass.acknowledge_settlement(binding(), child.settle())
        .unwrap();
    assert_eq!(
        pass.begin_restore(&foreign_parent).unwrap_err(),
        PassError::WrongParent
    );
    assert_eq!(
        pass.begin_restore(&parent).unwrap().parent(),
        parent.identity()
    );
}
