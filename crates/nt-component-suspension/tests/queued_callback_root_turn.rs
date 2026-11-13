//! A parked queued callback needs the same exact root ingress and retry authority as
//! AddDevice, while its physical child receipt remains one-use and owned separately.

use nt_component_suspension::{
    RetainedChildDispatch, RetainedChildDispatchError, RootChildArrival, RootChildTurn,
    RootChildTurnAction, RootChildTurnError,
};

#[derive(Debug, Eq, PartialEq)]
struct DeferredIngress {
    reply: Box<u64>,
    generation: u64,
}

#[test]
fn queued_callback_turn_retains_exact_ingress_across_stale_wakes() {
    // Route, dispatch, Reply, and generation must all match. A reused queue index
    // or numeric Reply is not enough to select the parked native callback.
    let exact = (7_u64, 11_u64, 13_u64, 17_u64);
    let recycled = (7, 11, 13, 18);
    let mut turn = RootChildTurn::new(exact);
    let ingress = DeferredIngress {
        reply: Box::new(13),
        generation: 17,
    };
    let (_, ingress) = turn.retain_ingress(recycled, ingress).unwrap_err();
    turn.retain_ingress(exact, ingress).unwrap();
    let (_, second) = turn
        .retain_ingress(
            exact,
            DeferredIngress {
                reply: Box::new(99),
                generation: 17,
            },
        )
        .unwrap_err();
    assert_eq!(*second.reply, 99);
    assert_eq!(
        turn.retained_ingress(recycled),
        Err(RootChildTurnError::WrongOwner)
    );

    let deadline = turn.arm_retry(exact, 100, 25).unwrap();
    assert_eq!(deadline, 125);
    assert_eq!(
        turn.observe_arrival(exact, RootChildArrival::Timer { now: 124 }),
        Ok(RootChildTurnAction::RetrySelected)
    );
    assert_eq!(
        turn.retry_deadline(exact),
        Ok(Some(125)),
        "a stale timer cannot consume the later exact retry deadline"
    );
    assert_eq!(
        turn.observe_arrival(recycled, RootChildArrival::Timer { now: 125 }),
        Err(RootChildTurnError::WrongOwner)
    );
    assert_eq!(turn.retry_deadline(exact), Ok(Some(125)));
    assert_eq!(
        turn.observe_arrival(exact, RootChildArrival::RetainedCall),
        Ok(RootChildTurnAction::KeepWaiting)
    );
    assert_eq!(
        turn.observe_arrival(exact, RootChildArrival::Timer { now: 125 }),
        Ok(RootChildTurnAction::RetrySelected)
    );
    assert_eq!(turn.retry_deadline(exact), Ok(None));

    let turn = turn.settle(recycled).unwrap_err();
    let retained = turn.settle(exact).unwrap().unwrap();
    assert_eq!((*retained.reply, retained.generation), (13, 17));
}

#[test]
fn queued_callback_child_receipt_is_deposited_and_consumed_once() {
    let exact = (7_u64, 11_u64, 13_u64, 17_u64);
    let foreign_reply = (7, 11, 14, 17);
    let mut callback = RetainedChildDispatch::retain(exact, Box::new(13_u64));
    callback.park_for_child(exact).unwrap();
    let (_, receipt) = callback
        .record_child_step(foreign_reply, Box::new(31_u64))
        .unwrap_err();
    assert_eq!(*receipt, 31);
    callback.record_child_step(exact, receipt).unwrap();
    let (error, duplicate) = callback.record_child_step(exact, Box::new(32)).unwrap_err();
    assert_eq!(error, RetainedChildDispatchError::InvalidPhase);
    assert_eq!(*duplicate, 32);
    callback.begin_restore(exact).unwrap();
    assert_eq!(
        *callback.take_child_step_for_native_restore(exact).unwrap(),
        31
    );
    assert!(callback.take_child_step_for_native_restore(exact).is_err());
    callback.acknowledge_restore(exact).unwrap();
    let (owner, terminal) = callback.finish_terminal(exact, Box::new(41)).unwrap();
    assert_eq!((*owner, *terminal), (13, 41));
}

#[test]
fn two_unrelated_calls_remain_owned_during_one_callback_wait() {
    let owner = (7_u64, 11_u64, 13_u64, 17_u64);
    let stale_generation = (7, 11, 13, 18);
    let mut turn = RootChildTurn::new(owner);
    turn.retain_ingress(
        owner,
        vec![DeferredIngress {
            reply: Box::new(101),
            generation: 1,
        }],
    )
    .unwrap();
    assert_eq!(
        turn.observe_arrival(owner, RootChildArrival::RetainedCall),
        Ok(RootChildTurnAction::KeepWaiting)
    );
    let second = DeferredIngress {
        reply: Box::new(102),
        generation: 2,
    };
    assert_eq!(
        turn.retained_ingress_mut(stale_generation),
        Err(RootChildTurnError::WrongOwner)
    );
    turn.retained_ingress_mut(owner)
        .unwrap()
        .unwrap()
        .push(second);
    assert_eq!(
        turn.observe_arrival(owner, RootChildArrival::RetainedCall),
        Ok(RootChildTurnAction::KeepWaiting)
    );
    let turn = turn.settle(stale_generation).unwrap_err();
    let retained = turn.settle(owner).unwrap().unwrap();
    assert_eq!(retained.len(), 2);
    assert_eq!((*retained[0].reply, retained[0].generation), (101, 1));
    assert_eq!((*retained[1].reply, retained[1].generation), (102, 2));
}

#[test]
fn nested_callback_b_waits_without_discarding_older_callback_a() {
    let older = (7_u64, 11_u64, 13_u64, 17_u64);
    let newer = (7_u64, 12_u64, 14_u64, 18_u64);
    let mut turns = Vec::new();
    let mut a = RootChildTurn::new(older);
    a.retain_ingress(
        older,
        vec![DeferredIngress {
            reply: Box::new(101),
            generation: 1,
        }],
    )
    .unwrap();
    a.arm_retry(older, 100, 25).unwrap();
    turns.push(a);
    let mut b = RootChildTurn::new(newer);
    b.retain_ingress(
        newer,
        vec![DeferredIngress {
            reply: Box::new(102),
            generation: 2,
        }],
    )
    .unwrap();
    turns.push(b);

    // The top of the physical queue stack is B. A stale A wake cannot settle B.
    assert_eq!(turns.last().unwrap().owner(), newer);
    assert_eq!(
        turns.last().unwrap().retained_ingress(older),
        Err(RootChildTurnError::WrongOwner)
    );
    let b = turns.pop().unwrap();
    let b_ingress = b.settle(newer).unwrap().unwrap();
    assert_eq!(*b_ingress[0].reply, 102);
    assert_eq!(turns.last().unwrap().owner(), older);
    assert_eq!(turns.last().unwrap().retry_deadline(older), Ok(Some(125)));
    let a = turns.pop().unwrap();
    let a_ingress = a.settle(older).unwrap().unwrap();
    assert_eq!(*a_ingress[0].reply, 101);
}
