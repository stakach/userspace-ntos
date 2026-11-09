//! A parked queued callback needs the same exact root ingress and retry authority as
//! AddDevice, while its physical child receipt remains one-use and owned separately.

use nt_component_suspension::{
    RetainedChildDispatch, RetainedChildDispatchError, RootChildArrival,
    RootChildTurn, RootChildTurnAction, RootChildTurnError,
};

#[derive(Debug, Eq, PartialEq)]
struct DeferredIngress { reply: Box<u64>, generation: u64 }

#[test]
fn queued_callback_turn_retains_exact_ingress_across_stale_wakes() {
    // Route, dispatch, Reply, and generation must all match. A reused queue index
    // or numeric Reply is not enough to select the parked native callback.
    let exact = (7_u64, 11_u64, 13_u64, 17_u64);
    let recycled = (7, 11, 13, 18);
    let mut turn = RootChildTurn::new(exact);
    let ingress = DeferredIngress { reply: Box::new(13), generation: 17 };
    let (_, ingress) = turn.retain_ingress(recycled, ingress).unwrap_err();
    turn.retain_ingress(exact, ingress).unwrap();
    let (_, second) = turn.retain_ingress(exact,
        DeferredIngress { reply: Box::new(99), generation: 17 }).unwrap_err();
    assert_eq!(*second.reply, 99);
    assert_eq!(turn.retained_ingress(recycled), Err(RootChildTurnError::WrongOwner));

    let deadline = turn.arm_retry(exact, 100, 25).unwrap();
    assert_eq!(deadline, 125);
    assert_eq!(turn.observe_arrival(exact, RootChildArrival::Timer { now: 124 }),
        Ok(RootChildTurnAction::RetrySelected));
    assert_eq!(turn.retry_deadline(exact), Ok(Some(125)),
        "a stale timer cannot consume the later exact retry deadline");
    assert_eq!(turn.observe_arrival(recycled, RootChildArrival::Timer { now: 125 }),
        Err(RootChildTurnError::WrongOwner));
    assert_eq!(turn.retry_deadline(exact), Ok(Some(125)));
    assert_eq!(turn.observe_arrival(exact, RootChildArrival::RetainedCall),
        Ok(RootChildTurnAction::KeepWaiting));
    assert_eq!(turn.observe_arrival(exact, RootChildArrival::Timer { now: 125 }),
        Ok(RootChildTurnAction::RetrySelected));
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
    let (_, receipt) = callback.record_child_step(foreign_reply, Box::new(31_u64))
        .unwrap_err();
    assert_eq!(*receipt, 31);
    callback.record_child_step(exact, receipt).unwrap();
    let (error, duplicate) = callback.record_child_step(exact, Box::new(32)).unwrap_err();
    assert_eq!(error, RetainedChildDispatchError::InvalidPhase);
    assert_eq!(*duplicate, 32);
    callback.begin_restore(exact).unwrap();
    assert_eq!(*callback.take_child_step_for_native_restore(exact).unwrap(), 31);
    assert!(callback.take_child_step_for_native_restore(exact).is_err());
    callback.acknowledge_restore(exact).unwrap();
    let (owner, terminal) = callback.finish_terminal(exact, Box::new(41)).unwrap();
    assert_eq!((*owner, *terminal), (13, 41));
}
