use nt_driver_start::{
    AddDeviceRootTurn, PendingOperationTable, RootArrival, RootTurnAction, RootTurnError,
};

#[derive(Debug, Eq, PartialEq)]
struct OriginalIngress { badge: u64, reply: u64, binding_generation: u64 }

#[test]
fn exact_parked_turn_retains_current_ingress_and_rejects_reused_slot() {
    let mut table = PendingOperationTable::with_capacity(1);
    let first = table.reserve().unwrap();
    table.publish(first, ()).unwrap();
    let mut turn = AddDeviceRootTurn::new(first);
    let ingress = OriginalIngress { badge: 0x1234, reply: 0x55, binding_generation: 7 };
    turn.retain_ingress(first, ingress).unwrap();
    assert_eq!(turn.retained_ingress(first), Ok(Some(&OriginalIngress {
        badge: 0x1234, reply: 0x55, binding_generation: 7,
    })));

    table.take(first.slot()).unwrap();
    let reused = table.reserve().unwrap();
    table.publish(reused, ()).unwrap();
    assert_eq!(first.slot(), reused.slot());
    assert_ne!(first, reused);
    assert_eq!(turn.retained_ingress(reused), Err(RootTurnError::WrongOwner));
    let turn = turn.settle(reused).err().expect("wrong generation retains the turn");
    assert_eq!(turn.settle(first).unwrap(), Some(OriginalIngress {
        badge: 0x1234, reply: 0x55, binding_generation: 7,
    }));
}

#[test]
fn notification_turn_keeps_ingress_held_until_exact_parent_settles() {
    let mut table = PendingOperationTable::with_capacity(1);
    let owner = table.reserve().unwrap();
    table.publish(owner, ()).unwrap();
    let mut turn = AddDeviceRootTurn::new(owner);
    let ingress = OriginalIngress { badge: 0x1234, reply: 0x55, binding_generation: 7 };
    turn.retain_ingress(owner, ingress).unwrap();
    let deadline = turn.arm_retry(owner, 100, 1_000).unwrap();
    assert_eq!(deadline, 1_100);
    assert_eq!(turn.retry_deadline(owner), Ok(Some(deadline)));
    assert_eq!(turn.observe_arrival(owner, RootArrival::Timer { now: 1_099 }),
        Ok(RootTurnAction::RetrySelected));
    assert_eq!(turn.retained_ingress(owner).unwrap().unwrap().reply, 0x55);
    assert_eq!(turn.retry_deadline(owner), Ok(Some(deadline)));
    assert_eq!(turn.observe_arrival(owner, RootArrival::Timer { now: 1_100 }),
        Ok(RootTurnAction::RetrySelected));
    assert_eq!(turn.retry_deadline(owner), Ok(None));
    assert_eq!(turn.settle(owner).unwrap(), Some(OriginalIngress {
        badge: 0x1234, reply: 0x55, binding_generation: 7,
    }));
}

#[test]
fn retained_call_is_not_a_parent_completion_or_ingress_replay() {
    let mut table = PendingOperationTable::with_capacity(1);
    let owner = table.reserve().unwrap();
    table.publish(owner, ()).unwrap();
    let mut turn = AddDeviceRootTurn::new(owner);
    let ingress = OriginalIngress { badge: 0x1234, reply: 0x55, binding_generation: 7 };
    turn.retain_ingress(owner, ingress).unwrap();
    assert_eq!(turn.observe_arrival(owner, RootArrival::RetainedCall),
        Ok(RootTurnAction::KeepWaiting));
    assert_eq!(turn.retained_ingress(owner).unwrap().unwrap().reply, 0x55);
    assert_eq!(turn.observe_arrival(owner, RootArrival::Irq),
        Ok(RootTurnAction::RetrySelected));
    assert_eq!(turn.settle(owner).unwrap(), Some(OriginalIngress {
        badge: 0x1234, reply: 0x55, binding_generation: 7,
    }));
}
