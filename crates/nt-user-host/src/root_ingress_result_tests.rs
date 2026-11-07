use super::*;
use crate::process_identity::{ProcessGeneration, ProcessIdentity};
use crate::root_ingress_pass::RootIngressPass;
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

fn binding(tcb: u64, badge: u64) -> ThreadBinding<u8> {
    ThreadBinding {
        pi: 7,
        process: ProcessIdentity { pid: 304, generation: ProcessGeneration::Hosted(2) },
        tid: 312,
        badge,
        role: 0,
        tcb,
        reservations: None,
    }
}

struct Child {
    receiver: IngressReceiver<u64>,
    call: Option<ExternalIngress<u64>>,
}

impl Child {
    fn new(reply: u64, tcb: u64) -> Self {
        let lanes = ComponentSuspensionLanes::<(), (), ()>::new(1, 1);
        let mut receiver = IngressReceiver::new(20, reply, 1).unwrap();
        let mut pool = IngressReplyPool::new(20, 1).unwrap();
        pool.insert(ComponentIngress::new(20, reply + 1).unwrap(), &receiver, &lanes, spare_free)
            .ok().unwrap();
        receiver.begin_receive(&lanes).unwrap();
        receiver.capture(191).ok().unwrap();
        receiver.resolve(IngressReceiveDisposition::Call).ok().unwrap();
        let call = pool.retain_external(&mut receiver, &lanes, tcb, spare_free, bound).unwrap();
        Self { receiver, call: Some(call) }
    }

    fn settle(&mut self) -> nt_component_suspension::ExternalSettlement {
        self.call.as_mut().unwrap()
            .reply_owned(bound, |_| IngressReplyObservation::Acknowledged).unwrap();
        self.receiver.finish_external_with_settlement(&mut self.call, free).unwrap().2
    }
}

fn new_parent() -> NestedExecutionScope {
    let mut lanes = ComponentSuspensionLanes::<(), (), ()>::new(1, 1);
    let mut peers = PeerRegistry::new(50, 1);
    let (_, mut registration) = lanes.allocate_shared_staged(
        &mut peers, 17, 1,
        LaneBinding { executor_id: 100, receive_endpoint: 50, reply_object: 200 },
    ).unwrap();
    let route = peers.publish_lane(&mut registration, 17, 1, &lanes).unwrap();
    let dispatch = lanes.begin_bootstrap_dispatch(route, &peers, free).unwrap();
    let mut receiver = IngressReceiver::<u64>::new(50, 60, 1).unwrap();
    receiver.suspend_for_nested_execution(route, dispatch, &mut lanes, &peers, free).unwrap()
}

fn restored(child: &Child, child_binding: ThreadBinding<u8>, parent: &NestedExecutionScope)
    -> crate::root_ingress_pass::RootIngressRestored<u8>
{
    let call = child.call.as_ref().unwrap();
    let mut pass = RootIngressPass::prepare(call, child_binding).unwrap();
    pass.bind_parent(parent, parent.dispatch()).unwrap();
    pass.begin_import(child_binding, call).unwrap();
    unsafe { pass.deliver(child_binding, call) }.unwrap();
    pass.begin_park(child_binding, call).unwrap();
    unsafe { pass.acknowledge_park(child_binding, call) }.unwrap();
    // The native test adapter supplies the positive physical restore observation.
    unsafe { pass.begin_restore(parent).unwrap().acknowledge_restore() }
}

#[test]
fn result_binds_exact_child_and_full_payload_before_park() {
    let child = Child::new(30, 10);
    let foreign = Child::new(60, 11);
    let parent = new_parent();
    let owner = RootIngressResult::prepare(
        child.call.as_ref().unwrap(), binding(10, 614), parent.identity(), 4, [1, 2, 3, 4],
    ).unwrap();
    assert_eq!(owner.admission_key(), child.call.as_ref().unwrap().admission_key());
    assert_eq!(owner.binding(), binding(10, 614));
    assert_eq!(owner.reply(), 30);
    assert_eq!(owner.parent(), parent.identity());
    assert_eq!(owner.payload(), (4, [1, 2, 3, 4]));
    assert_eq!(RootIngressResult::prepare(
        child.call.as_ref().unwrap(), binding(11, 614), parent.identity(), 4, [1, 2, 3, 4],
    ).unwrap_err(), ResultError::WrongChild);
    assert_eq!(RootIngressResult::prepare(
        foreign.call.as_ref().unwrap(), binding(10, 614), parent.identity(), 4, [1, 2, 3, 4],
    ).unwrap_err(), ResultError::WrongChild);
}

#[test]
fn wrong_or_duplicate_delivery_cannot_replay_reply() {
    let child = Child::new(40, 10);
    let foreign = Child::new(70, 11);
    let parent = new_parent();
    let foreign_parent = new_parent();
    let receipt = restored(&child, binding(10, 614), &parent);
    let foreign_receipt = restored(&foreign, binding(11, 615), &parent);
    let wrong_parent_receipt = restored(&child, binding(10, 614), &foreign_parent);
    let mut owner = RootIngressResult::prepare(
        child.call.as_ref().unwrap(), binding(10, 614), parent.identity(), 1, [0x103, 0, 0, 0],
    ).unwrap();
    assert_eq!(owner.begin_delivery(binding(10, 614), child.call.as_ref().unwrap(), &foreign_receipt)
        .unwrap_err(), ResultError::WrongChild);
    assert_eq!(owner.begin_delivery(binding(10, 614), foreign.call.as_ref().unwrap(), &receipt)
        .unwrap_err(),
        ResultError::WrongChild);
    assert_eq!(owner.begin_delivery(binding(10, 614), child.call.as_ref().unwrap(), &wrong_parent_receipt)
        .unwrap_err(), ResultError::WrongParent);
    assert_eq!(owner.begin_delivery(binding(10, 614), child.call.as_ref().unwrap(), &receipt).unwrap(),
        (1, [0x103, 0, 0, 0]));
    assert_eq!(owner.begin_delivery(binding(10, 614), child.call.as_ref().unwrap(), &receipt).unwrap_err(),
        ResultError::AlreadyEntered);
    assert_eq!(owner.payload(), (1, [0x103, 0, 0, 0]));
}

#[test]
fn uncertain_send_retains_owner_until_exact_settlement_without_replay() {
    let mut child = Child::new(50, 10);
    let mut foreign = Child::new(80, 11);
    let parent = new_parent();
    let receipt = restored(&child, binding(10, 614), &parent);
    let mut owner = RootIngressResult::prepare(
        child.call.as_ref().unwrap(), binding(10, 614), parent.identity(), 1, [0x103, 0, 0, 0],
    ).unwrap();
    owner.update_status(binding(10, 614), child.call.as_ref().unwrap(), &receipt, 0xC000_0001).unwrap();
    assert_eq!(owner.begin_delivery(binding(10, 614), child.call.as_ref().unwrap(), &receipt).unwrap(),
        (1, [0xC000_0001, 0, 0, 0]));
    assert_eq!(owner.update_status(binding(10, 614), child.call.as_ref().unwrap(), &receipt, 0)
        .unwrap_err(), ResultError::InvalidPhase);
    assert_eq!(owner.begin_delivery(binding(10, 614), child.call.as_ref().unwrap(), &receipt).unwrap_err(),
        ResultError::AlreadyEntered);
    let foreign_key = foreign.call.as_ref().unwrap().admission_key();
    let foreign_receipt = foreign.settle();
    let (error, returned) = owner.acknowledge_settlement(binding(10, 614), foreign_receipt)
        .unwrap_err();
    assert_eq!(error, ResultError::WrongChild);
    assert_eq!(returned.admission_key(), foreign_key);
    let settlement = child.settle();
    let child_key = settlement.admission_key();
    owner.acknowledge_settlement(binding(10, 614), settlement).unwrap();
    assert!(owner.is_settled());
    assert_eq!(owner.take_settlement().unwrap().admission_key(), child_key);
    assert!(owner.is_settled());
}
