use super::*;
use crate::{IngressReplyObservation, LaneBinding};

type Lanes = ComponentSuspensionLanes<u64, u32, ()>;

fn bound(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::BoundToTarget)
}
fn free(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::Free)
}
fn no_query(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    panic!("preflight refusal must not query")
}

struct Fixture {
    lanes: Lanes,
    peers: PeerRegistry,
    receiver: IngressReceiver<u64>,
    displaced: alloc::vec::Vec<ComponentIngress<u64>>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            lanes: Lanes::new(4, 4),
            peers: PeerRegistry::new(20, 4),
            receiver: IngressReceiver::new(20, 40, 4).unwrap(),
            displaced: alloc::vec::Vec::new(),
        }
    }

    fn parent(&mut self, domain: u64) -> (PeerRoute, LaneDispatchIdentity) {
        let (_, mut registration) = self
            .lanes
            .allocate_shared_staged(
                &mut self.peers,
                domain,
                1,
                LaneBinding {
                    executor_id: 100 + domain,
                    receive_endpoint: 20,
                    reply_object: 200 + domain,
                },
            )
            .unwrap();
        let route = self
            .peers
            .publish_lane(&mut registration, domain, 1, &self.lanes)
            .unwrap();
        let dispatch = self
            .lanes
            .begin_bootstrap_dispatch(route, &self.peers, free)
            .unwrap();
        let reply = self.receiver.reply();
        self.receiver
            .begin_receive_for_owner(&self.lanes, IngressExecutionOwner::Dispatch(dispatch))
            .unwrap();
        self.receiver.capture(domain).ok().unwrap();
        self.receiver
            .resolve(IngressReceiveDisposition::Call)
            .ok()
            .unwrap();
        self.receiver
            .retain(
                &self.lanes,
                ComponentIngress::new(20, reply + 1).unwrap(),
                &mut self.peers,
                route.badge(),
                bound,
            )
            .ok()
            .unwrap();
        let mut displaced = None;
        self.receiver
            .adopt_bootstrap_call(
                route,
                dispatch,
                reply,
                &mut self.lanes,
                &self.peers,
                &mut displaced,
                |_, cap| {
                    Ok::<_, u8>(if cap == reply {
                        ReplyBindingObservation::BoundToTarget
                    } else {
                        ReplyBindingObservation::Free
                    })
                },
            )
            .unwrap();
        self.displaced.push(displaced.unwrap());
        (route, dispatch)
    }

    fn ack(&mut self, route: PeerRoute, dispatch: LaneDispatchIdentity) {
        self.receiver
            .reply_stored(route, dispatch, &self.lanes, bound, |_| {
                IngressReplyObservation::Acknowledged
            })
            .unwrap();
    }
}

#[test]
fn held_parent_keeps_epoch_call_and_tokens_through_nested_dispatch() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    f.lanes.suspend_running(dispatch.lane(), 40, 77).unwrap();
    f.lanes.resume_external(dispatch.lane(), 40, 77).unwrap();
    let mut scope = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    assert_eq!(
        f.lanes.active_dispatch_identity(dispatch.lane()),
        Ok(Some(dispatch))
    );
    assert_eq!(f.peers.state(route).unwrap().1, 1);
    assert_eq!(f.lanes.external_top(dispatch.lane()), Ok(Some(77)));
    assert!(f
        .receiver
        .begin_receive_for_owner(&f.lanes, IngressExecutionOwner::Dispatch(dispatch))
        .is_err());
    assert!(f.lanes.resume_external(dispatch.lane(), 40, 77).is_err());
    let (child, child_dispatch) = f.parent(2);
    assert_eq!(
        f.receiver
            .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, no_query),
        Err(NestedExecutionError::Busy)
    );
    f.ack(child, child_dispatch);
    assert_eq!(
        f.receiver
            .complete_stored(child, child_dispatch, &mut f.lanes, &mut f.peers, free),
        Ok(2)
    );
    f.receiver
        .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound)
        .unwrap();
    assert!(scope.is_consumed());
    assert_eq!(f.lanes.running(), Some(dispatch.lane()));
    assert_eq!(f.lanes.external_top(dispatch.lane()), Ok(Some(77)));
    assert_eq!(
        f.receiver
            .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, no_query),
        Err(NestedExecutionError::Consumed)
    );
    f.lanes
        .retire_external_running(dispatch.lane(), 40, 77)
        .unwrap();
    f.ack(route, dispatch);
    assert_eq!(
        f.receiver
            .complete_stored(route, dispatch, &mut f.lanes, &mut f.peers, free),
        Ok(1)
    );
}

#[test]
fn acknowledged_parent_uses_free_proof_and_can_complete_only_after_restore() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    f.ack(route, dispatch);
    let mut scope = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, free)
        .unwrap();
    assert!(f
        .receiver
        .complete_stored(route, dispatch, &mut f.lanes, &mut f.peers, no_query)
        .is_err());
    assert_eq!(
        f.receiver
            .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound),
        Err(NestedExecutionError::BindingMismatch)
    );
    assert!(!scope.is_consumed());
    f.receiver
        .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, free)
        .unwrap();
    assert_eq!(
        f.receiver
            .complete_stored(route, dispatch, &mut f.lanes, &mut f.peers, free),
        Ok(1)
    );
}

#[test]
fn queries_fail_without_losing_parent_or_scope() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    assert!(matches!(
        f.receiver
            .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, |_, _| Err(7)),
        Err(NestedExecutionError::Query(7))
    ));
    assert_eq!(f.lanes.running(), Some(dispatch.lane()));
    assert!(matches!(
        f.receiver
            .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, free),
        Err(NestedExecutionError::BindingMismatch)
    ));
    let mut scope = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    assert_eq!(
        f.receiver
            .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, |_, _| Err(8)),
        Err(NestedExecutionError::Query(8))
    );
    assert_eq!(f.lanes.running(), None);
    assert!(!scope.is_consumed());
    f.receiver
        .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound)
        .unwrap();
}

#[test]
fn uncertain_reply_cannot_release_execution_fence() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    f.receiver
        .reply_stored(route, dispatch, &f.lanes, bound, |_| {
            IngressReplyObservation::Indeterminate
        })
        .unwrap();
    assert!(matches!(
        f.receiver
            .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, no_query),
        Err(NestedExecutionError::InvalidReplyState)
    ));
    assert_eq!(f.lanes.running(), Some(dispatch.lane()));
}

#[test]
fn resumed_wait_frame_is_unchanged_and_not_selectable_while_nested() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let lane = dispatch.lane();
    let key = crate::SuspensionKey::provider_wait(9);
    let owner = crate::SuspensionOwner {
        provider_domain: 1,
        provider_generation: 1,
        dispatch_id: dispatch.epoch(),
        caller: crate::SuspensionCaller::Kernel { lane },
    };
    f.lanes.admit_running(lane, 40, key, 1, owner, 99).unwrap();
    f.lanes.select(key, 5).unwrap();
    f.lanes.begin_resume(lane, 40, key).unwrap();
    let frame = f.lanes.frame(lane, key).unwrap().unwrap().clone();
    let mut scope = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    assert!(f.lanes.next_resumable().is_none());
    assert!(f.lanes.begin_resume(lane, 40, key).is_err());
    assert!(f.lanes.rollback_admission(lane, 40, key).is_err());
    assert_eq!(f.lanes.frame(lane, key).unwrap().unwrap(), &frame);
    f.receiver
        .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound)
        .unwrap();
    assert_eq!(f.lanes.frame(lane, key).unwrap().unwrap(), &frame);
}

#[test]
fn nested_scopes_restore_in_lifo_order_across_domains() {
    let mut f = Fixture::new();
    let (first, first_dispatch) = f.parent(1);
    let mut outer = f
        .receiver
        .suspend_for_nested_execution(first, first_dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    let (second, second_dispatch) = f.parent(2);
    let mut inner = f
        .receiver
        .suspend_for_nested_execution(second, second_dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    assert_eq!(
        f.receiver
            .resume_nested_execution(&mut outer, &mut f.lanes, &f.peers, no_query),
        Err(NestedExecutionError::Busy)
    );
    f.receiver
        .resume_nested_execution(&mut inner, &mut f.lanes, &f.peers, bound)
        .unwrap();
    f.ack(second, second_dispatch);
    f.receiver
        .complete_stored(second, second_dispatch, &mut f.lanes, &mut f.peers, free)
        .unwrap();
    f.receiver
        .resume_nested_execution(&mut outer, &mut f.lanes, &f.peers, bound)
        .unwrap();
    assert_eq!(f.lanes.running(), Some(first_dispatch.lane()));
}

#[test]
fn foreign_registry_receiver_and_changed_binding_cannot_restore_scope() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let foreign = PeerRegistry::new(20, 4);
    assert!(matches!(
        f.receiver
            .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &foreign, no_query),
        Err(NestedExecutionError::WrongOwner)
    ));
    let mut scope = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    let mut other = IngressReceiver::<u64>::new(20, 60, 4).unwrap();
    assert_eq!(
        other.resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, no_query),
        Err(NestedExecutionError::WrongOwner)
    );
    f.lanes
        .lane_mut(dispatch.lane())
        .unwrap()
        .binding
        .reply_object = 99;
    assert_eq!(
        f.receiver
            .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, no_query),
        Err(NestedExecutionError::WrongOwner)
    );
    f.lanes
        .lane_mut(dispatch.lane())
        .unwrap()
        .binding
        .reply_object = 40;
    f.receiver
        .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound)
        .unwrap();
}

#[test]
fn bootstrap_before_first_call_can_lend_execution_without_fake_admission() {
    let mut f = Fixture::new();
    let (_, mut registration) = f
        .lanes
        .allocate_shared_staged(
            &mut f.peers,
            9,
            1,
            LaneBinding {
                executor_id: 109,
                receive_endpoint: 20,
                reply_object: 209,
            },
        )
        .unwrap();
    let route = f
        .peers
        .publish_lane(&mut registration, 9, 1, &f.lanes)
        .unwrap();
    let dispatch = f
        .lanes
        .begin_bootstrap_dispatch(route, &f.peers, free)
        .unwrap();
    let mut scope = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, free)
        .unwrap();
    let (child, child_dispatch) = f.parent(2);
    f.ack(child, child_dispatch);
    f.receiver
        .complete_stored(child, child_dispatch, &mut f.lanes, &mut f.peers, free)
        .unwrap();
    f.receiver
        .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, free)
        .unwrap();
    assert_eq!(f.lanes.running(), Some(dispatch.lane()));
    assert_eq!(
        f.lanes.lane(dispatch.lane()).unwrap().bootstrap_dispatch,
        Some((dispatch, 209))
    );
    assert_eq!(f.peers.state(route).unwrap().1, 0);
}
