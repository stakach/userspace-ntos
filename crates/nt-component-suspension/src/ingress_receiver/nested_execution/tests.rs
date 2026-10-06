use super::*;
use crate::{IngressReplyObservation, LaneBinding};

type Lanes = ComponentSuspensionLanes<u64, u32, ()>;

fn child_settlement() -> crate::ExternalSettlement {
    let lanes = ComponentSuspensionLanes::<u64, u32>::new(1, 2);
    let mut receiver = IngressReceiver::new(20, 300, 1).unwrap();
    let mut pool = crate::IngressReplyPool::new(20, 2).unwrap();
    pool.insert(
        ComponentIngress::new(20, 301).unwrap(),
        &receiver,
        &lanes,
        |_| Ok::<_, u8>(ReplyBindingObservation::Free),
    )
    .ok()
    .unwrap();
    receiver.begin_receive(&lanes).unwrap();
    receiver.capture(7).ok().unwrap();
    receiver
        .resolve(IngressReceiveDisposition::Call)
        .ok()
        .unwrap();
    let mut pending = Some(
        pool.retain_external(
            &mut receiver,
            &lanes,
            999,
            |_| Ok::<_, u8>(ReplyBindingObservation::Free),
            bound,
        )
        .unwrap(),
    );
    pending
        .as_mut()
        .unwrap()
        .reply_owned(bound, |_| IngressReplyObservation::Acknowledged)
        .unwrap();
    receiver
        .finish_external_with_settlement(&mut pending, free)
        .unwrap()
        .2
}

#[test]
fn repeated_receive_reuses_full_depth_slot_and_requires_a_new_settlement() {
    let mut f = Fixture::new();
    f.lanes = Lanes::new(4, 1);
    let (route, dispatch) = f.parent(1);
    let owner = receive_owner(dispatch);
    let reply = f.lanes.binding(dispatch.lane()).unwrap().reply_object;
    f.lanes
        .reserve_receive_capacity(dispatch.lane(), reply, owner)
        .unwrap();
    let mut first = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    let settled = child_settlement();
    let key = crate::SuspensionKey::receive(settled.admission_key().admission_sequence());
    f.lanes
        .admit_receive_owned(&first, key, 1, owner, settled.admission_key(), 123)
        .unwrap();
    f.lanes
        .begin_receive_restore(&first, key, owner, &settled, 0)
        .unwrap();
    f.receiver
        .resume_nested_execution(&mut first, &mut f.lanes, &f.peers, bound)
        .unwrap();
    f.lanes
        .reserve_receive_rearm_capacity(dispatch.lane(), reply, key, owner)
        .unwrap();
    let mut second = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    let next = child_settlement();
    let next_key = crate::SuspensionKey::receive(next.admission_key().admission_sequence());
    assert_eq!(
        f.lanes
            .rearm_receive_owned(&second, key, next_key, 2, owner, next.admission_key(), 456),
        Ok(123)
    );
    assert_eq!(f.lanes.suspension_count(dispatch.lane()), Ok(1));
    assert!(f.lanes.frame(dispatch.lane(), key).unwrap().is_none());
    assert_eq!(
        f.lanes
            .frame(dispatch.lane(), next_key)
            .unwrap()
            .unwrap()
            .continuation,
        456
    );
    assert_eq!(
        f.lanes.active_dispatch_identity(dispatch.lane()),
        Ok(Some(dispatch))
    );
    assert!(f
        .receiver
        .resume_nested_execution(&mut second, &mut f.lanes, &f.peers, no_query)
        .is_err());
    assert!(f
        .lanes
        .begin_receive_restore(&second, next_key, owner, &settled, 0)
        .is_err());
    f.lanes
        .begin_receive_restore(&second, next_key, owner, &next, 0)
        .unwrap();
    f.receiver
        .resume_nested_execution(&mut second, &mut f.lanes, &f.peers, bound)
        .unwrap();
    assert!(f
        .lanes
        .rearm_receive_owned(
            &second,
            next_key,
            key,
            3,
            owner,
            settled.admission_key(),
            789
        )
        .is_err());
}

#[test]
fn receive_rearm_refusals_preserve_the_old_frame_and_offered_continuation() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let owner = receive_owner(dispatch);
    let reply = f.lanes.binding(dispatch.lane()).unwrap().reply_object;
    f.lanes
        .reserve_receive_capacity(dispatch.lane(), reply, owner)
        .unwrap();
    let mut first = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    let settled = child_settlement();
    let key = crate::SuspensionKey::receive(settled.admission_key().admission_sequence());
    f.lanes
        .admit_receive_owned(&first, key, 1, owner, settled.admission_key(), 123)
        .unwrap();
    let next = child_settlement();
    let next_key = crate::SuspensionKey::receive(next.admission_key().admission_sequence());
    let before = f
        .lanes
        .frame(dispatch.lane(), key)
        .unwrap()
        .unwrap()
        .clone();
    assert!(matches!(
        f.lanes
            .rearm_receive_owned(&first, key, next_key, 2, owner, next.admission_key(), 456),
        Err((_, 456))
    ));
    assert_eq!(f.lanes.frame(dispatch.lane(), key).unwrap(), Some(&before));
    f.lanes
        .begin_receive_restore(&first, key, owner, &settled, 0)
        .unwrap();
    f.receiver
        .resume_nested_execution(&mut first, &mut f.lanes, &f.peers, bound)
        .unwrap();
    f.lanes
        .reserve_receive_rearm_capacity(dispatch.lane(), reply, key, owner)
        .unwrap();
    let second = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    let before = f
        .lanes
        .frame(dispatch.lane(), key)
        .unwrap()
        .unwrap()
        .clone();
    let mut wrong = owner;
    wrong.dispatch_id += 1;
    for (offered_key, sequence, offered_owner, child) in [
        (next_key, 2, wrong, next.admission_key()),
        (next_key, 1, owner, next.admission_key()),
        (
            crate::SuspensionKey::provider_wait(next_key.id),
            2,
            owner,
            next.admission_key(),
        ),
        (next_key, 2, owner, settled.admission_key()),
        (key, 2, owner, settled.admission_key()),
    ] {
        assert!(matches!(
            f.lanes.rearm_receive_owned(
                &second,
                key,
                offered_key,
                sequence,
                offered_owner,
                child,
                456
            ),
            Err((_, 456))
        ));
        assert_eq!(f.lanes.frame(dispatch.lane(), key).unwrap(), Some(&before));
    }
    assert!(matches!(
        f.lanes
            .rearm_receive_owned(&first, key, next_key, 2, owner, next.admission_key(), 456),
        Err((_, 456))
    ));
    assert_eq!(f.lanes.frame(dispatch.lane(), key).unwrap(), Some(&before));
    assert!(f.lanes.frame(dispatch.lane(), next_key).unwrap().is_none());
}

fn receive_owner(dispatch: LaneDispatchIdentity) -> crate::SuspensionOwner {
    crate::SuspensionOwner {
        provider_domain: 1,
        provider_generation: 1,
        dispatch_id: dispatch.epoch(),
        caller: crate::SuspensionCaller::Kernel {
            lane: dispatch.lane(),
        },
    }
}

#[test]
fn receive_frame_mut_cannot_replace_the_sealed_child_settlement_fence() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let owner = receive_owner(dispatch);
    let reply = f.lanes.binding(dispatch.lane()).unwrap().reply_object;
    f.lanes
        .reserve_receive_capacity(dispatch.lane(), reply, owner)
        .unwrap();
    let mut scope = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    let receipt = child_settlement();
    let key = crate::SuspensionKey::receive(1);
    f.lanes
        .admit_receive_owned(&scope, key, 1, owner, receipt.admission_key(), 123)
        .unwrap();
    assert!(f
        .receiver
        .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, no_query,)
        .is_err());

    // An ordinary frame is legitimately obtainable through the public stack API. Replacing the
    // whole Receive frame would erase its private admission even though field mutation cannot.
    let mut ordinary = crate::ComponentSuspensionStack::<u64, u32>::new(1);
    let ordinary_key = crate::SuspensionKey::provider_wait(2);
    ordinary.admit_owned(ordinary_key, 2, owner, 456).unwrap();
    let replacement = ordinary.get(ordinary_key).unwrap().clone();
    let denied = match f.lanes.frame_mut(dispatch.lane(), key) {
        Err(crate::LaneError::InvalidPhase) => true,
        Ok(Some(frame)) => {
            *frame = replacement;
            // Current unsafe contract actually allows restoration without submitting the receipt.
            f.receiver
                .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound)
                .expect("replacement counterexample must reach unauthorized restoration");
            false
        }
        _ => panic!("Receive mutable access must be explicitly refused"),
    };
    assert!(
        denied,
        "public frame_mut must refuse replacement of a sealed Receive admission"
    );
    assert!(!scope.is_consumed());
    assert_eq!(
        f.lanes
            .frame(dispatch.lane(), key)
            .unwrap()
            .unwrap()
            .continuation,
        123
    );
}

#[test]
fn receive_continuation_updates_require_exact_owner_and_keep_settlement_metadata_private() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let owner = receive_owner(dispatch);
    let reply = f.lanes.binding(dispatch.lane()).unwrap().reply_object;
    f.lanes
        .reserve_receive_capacity(dispatch.lane(), reply, owner)
        .unwrap();
    let mut scope = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    let receipt = child_settlement();
    let key = crate::SuspensionKey::receive(1);
    f.lanes
        .admit_receive_owned(&scope, key, 1, owner, receipt.admission_key(), 123)
        .unwrap();
    let mut wrong = owner;
    wrong.provider_generation += 1;
    assert!(matches!(
        f.lanes.continuation_mut(dispatch.lane(), key, wrong),
        Err(crate::LaneError::WrongBinding)
    ));
    *f.lanes
        .continuation_mut(dispatch.lane(), key, owner)
        .unwrap()
        .unwrap() = 456;
    let frame = f.lanes.frame(dispatch.lane(), key).unwrap().unwrap();
    assert_eq!(
        (
            frame.key,
            frame.owner,
            frame.admission_sequence,
            frame.continuation
        ),
        (key, owner, 1, 456)
    );
    assert_eq!(frame.phase, crate::SuspensionPhase::Waiting);
    assert!(f
        .receiver
        .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, no_query)
        .is_err());

    // A cloned sealed frame cannot expose a raw mutable admission through the standalone stack.
    let cloned = f
        .lanes
        .frame(dispatch.lane(), key)
        .unwrap()
        .unwrap()
        .clone();
    let mut stack = crate::ComponentSuspensionStack::<u64, u32>::new(1);
    let ordinary_key = crate::SuspensionKey::provider_wait(2);
    stack.admit_owned(ordinary_key, 2, owner, 0).unwrap();
    *stack.get_mut(ordinary_key).unwrap() = cloned;
    assert!(stack.get_mut(key).is_none());
    f.lanes
        .begin_receive_restore(&scope, key, owner, &receipt, 0)
        .unwrap();
    f.receiver
        .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound)
        .unwrap();
}

#[test]
fn receive_requires_exact_settled_child_and_cannot_use_generic_resume() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let owner = receive_owner(dispatch);
    f.lanes
        .reserve_receive_capacity(
            dispatch.lane(),
            f.lanes.binding(dispatch.lane()).unwrap().reply_object,
            owner,
        )
        .unwrap();
    let mut scope = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    let receipt = child_settlement();
    let key = crate::SuspensionKey::receive(1);
    f.lanes
        .admit_receive_owned(&scope, key, 1, owner, receipt.admission_key(), 123)
        .unwrap();
    assert_eq!(
        f.lanes
            .frame(dispatch.lane(), key)
            .unwrap()
            .unwrap()
            .continuation,
        123
    );
    assert_eq!(f.lanes.select(key, 0), Err(crate::LaneError::InvalidPhase));
    assert_eq!(f.lanes.cancel(key, 0), Err(crate::LaneError::InvalidPhase));
    assert!(f.lanes.next_resumable().is_none());
    assert!(f
        .receiver
        .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, no_query)
        .is_err());
    let wrong = child_settlement();
    assert_eq!(
        f.lanes.begin_receive_restore(&scope, key, owner, &wrong, 0),
        Err(crate::LaneError::WrongBinding)
    );
    let mut changed = owner;
    changed.provider_generation += 1;
    assert_eq!(
        f.lanes
            .begin_receive_restore(&scope, key, changed, &receipt, 0),
        Err(crate::LaneError::WrongBinding)
    );
    f.lanes
        .begin_receive_restore(&scope, key, owner, &receipt, 0)
        .unwrap();
    assert!(f
        .lanes
        .begin_receive_restore(&scope, key, owner, &receipt, 0)
        .is_err());
    assert!(matches!(
        f.lanes.phase(dispatch.lane()),
        Ok(LanePhase::NestedExecution(_))
    ));
    assert_eq!(
        f.receiver
            .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, |_, _| Err(9)),
        Err(NestedExecutionError::Query(9))
    );
    assert!(!scope.is_consumed());
    f.receiver
        .resume_nested_execution(&mut scope, &mut f.lanes, &f.peers, bound)
        .unwrap();
    f.lanes
        .retain_terminal_running(
            dispatch.lane(),
            f.lanes.binding(dispatch.lane()).unwrap().reply_object,
            key,
            owner,
            (),
        )
        .unwrap();
}

#[test]
fn receive_admission_is_capacity_scoped_and_preserves_rejected_continuation() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let scope = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    let receipt = child_settlement();
    let owner = receive_owner(dispatch);
    for key in [
        crate::SuspensionKey::provider_wait(1),
        crate::SuspensionKey::lpc_request(1),
    ] {
        assert_eq!(
            f.lanes
                .admit_receive_owned(&scope, key, 1, owner, receipt.admission_key(), 123),
            Err((crate::LaneError::InvalidIdentity, 123))
        );
    }
    assert_eq!(
        f.lanes.admit_receive_owned(
            &scope,
            crate::SuspensionKey::receive(1),
            1,
            owner,
            receipt.admission_key(),
            123
        ),
        Err((crate::LaneError::NoCapacity, 123))
    );
    assert!(f
        .lanes
        .frame(dispatch.lane(), crate::SuspensionKey::receive(1))
        .unwrap()
        .is_none());
    assert!(matches!(
        f.lanes.phase(dispatch.lane()),
        Ok(LanePhase::NestedExecution(_))
    ));
}

#[test]
fn receive_restore_obeys_scope_order_and_private_settlement_state() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let owner = receive_owner(dispatch);
    let reply = f.lanes.binding(dispatch.lane()).unwrap().reply_object;
    f.lanes
        .reserve_receive_capacity(dispatch.lane(), reply, owner)
        .unwrap();
    let mut outer = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    let receipt = child_settlement();
    let key = crate::SuspensionKey::receive(1);
    f.lanes
        .admit_receive_owned(&outer, key, 1, owner, receipt.admission_key(), 123)
        .unwrap();
    // Even deliberately corrupting the phase internally cannot fabricate settlement authority.
    f.lanes
        .lane_mut(dispatch.lane())
        .unwrap()
        .suspensions
        .get_mut_internal(key)
        .unwrap()
        .phase = crate::SuspensionPhase::Resuming {
        completion: 0,
        cancelled: false,
    };
    assert!(f
        .receiver
        .resume_nested_execution(&mut outer, &mut f.lanes, &f.peers, no_query)
        .is_err());
    f.lanes
        .lane_mut(dispatch.lane())
        .unwrap()
        .suspensions
        .get_mut_internal(key)
        .unwrap()
        .phase = crate::SuspensionPhase::Waiting;
    let (inner_route, inner_dispatch) = f.parent(2);
    let mut inner = f
        .receiver
        .suspend_for_nested_execution(inner_route, inner_dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    assert_eq!(
        f.lanes
            .begin_receive_restore(&outer, key, owner, &receipt, 0),
        Err(crate::LaneError::Busy)
    );
    assert!(f
        .lanes
        .begin_receive_restore(&inner, key, owner, &receipt, 0)
        .is_err());
    f.receiver
        .resume_nested_execution(&mut inner, &mut f.lanes, &f.peers, bound)
        .unwrap();
    f.ack(inner_route, inner_dispatch);
    f.receiver
        .complete_stored(
            inner_route,
            inner_dispatch,
            &mut f.lanes,
            &mut f.peers,
            free,
        )
        .unwrap();
    f.lanes
        .begin_receive_restore(&outer, key, owner, &receipt, 0)
        .unwrap();
    f.receiver
        .resume_nested_execution(&mut outer, &mut f.lanes, &f.peers, bound)
        .unwrap();
    assert!(f
        .lanes
        .begin_receive_restore(&outer, key, owner, &receipt, 0)
        .is_err());
}

#[test]
fn raw_stack_cannot_construct_or_resume_receive() {
    let mut stack = crate::ComponentSuspensionStack::<u64, u32>::new(2);
    let mut f = Fixture::new();
    let (_, dispatch) = f.parent(1);
    let key = crate::SuspensionKey::receive(1);
    assert_eq!(
        stack.admit_owned(key, 1, receive_owner(dispatch), 123),
        Err((crate::SuspensionError::InvalidPhase, 123))
    );
    assert_eq!(
        stack.begin_resume(key),
        Err(crate::SuspensionError::InvalidPhase)
    );
}

#[test]
fn scope_identity_survives_consumption_but_distinguishes_same_dispatch_reparking() {
    let mut f = Fixture::new();
    let (route, dispatch) = f.parent(1);
    let mut first = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    let identity = first.identity();
    assert_eq!((identity.route(), identity.dispatch()), (route, dispatch));
    f.receiver
        .resume_nested_execution(&mut first, &mut f.lanes, &f.peers, bound)
        .unwrap();
    assert!(first.is_consumed());
    assert_eq!(first.identity(), identity);
    let second = f
        .receiver
        .suspend_for_nested_execution(route, dispatch, &mut f.lanes, &f.peers, bound)
        .unwrap();
    assert_eq!(second.dispatch(), first.dispatch());
    assert_ne!(second.identity(), identity);
}

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
