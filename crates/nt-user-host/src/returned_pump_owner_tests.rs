use super::returned_pump_owner::{
    ReturnedPumpError, ReturnedPumpKey, ReturnedPumpObservation, ReturnedPumpOwner,
    ReturnedPumpPhase,
};
use super::retained_owner_table::RetainedOwnerTable;
use alloc::boxed::Box;
use nt_component_suspension::{
    peer_registry::{PeerIdentity, PeerRegistry}, ComponentSuspensionLanes, LaneBinding,
};
use nt_user_callback::{DispatchContext, SharedPageClientIdentity};

fn key() -> ReturnedPumpKey {
    let binding = LaneBinding { executor_id: 101, receive_endpoint: 102, reply_object: 103 };
    let mut lanes = ComponentSuspensionLanes::<u64, u64, u64>::new(2, 2);
    let lane = lanes.allocate(binding).unwrap();
    lanes.begin_dispatch(lane, binding.reply_object).unwrap();
    let physical = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    let mut peers = PeerRegistry::new(binding.receive_endpoint, 1);
    let mut staged = peers.stage(PeerIdentity {
        domain: 11, domain_generation: 12, executor: binding.executor_id, lane,
    }).unwrap();
    let route = peers.publish(&mut staged).unwrap();
    let dispatch = DispatchContext { lane, dispatch_id: 13, ssn: 0x1007,
        ..DispatchContext::EMPTY };
    let client = SharedPageClientIdentity { pi: 8, pid: 14, generation: 15,
        tid: 16, badge: 17, tcb: 18 };
    ReturnedPumpKey::new(route, physical, dispatch, client, binding.reply_object, 19).unwrap()
}

#[test]
fn active_bundle_is_retained_before_pump_and_uncertain_capture_keeps_both_owners() {
    let key = key();
    let mut table = RetainedOwnerTable::<ReturnedPumpKey,
        ReturnedPumpOwner<Box<u64>, Box<u64>>>::new();
    let reservation = table.reserve().unwrap();
    let ticket = table.retain(reservation, key,
        ReturnedPumpOwner::active(key, Box::new(51))).ok().unwrap();
    assert_eq!(table.get(ticket).unwrap().phase(), ReturnedPumpPhase::Active);
    assert_eq!(**table.get(ticket).unwrap().continuation(), 51);
    assert!(table.get(ticket).unwrap().pump().is_none());
    assert!(table.transition_held(ticket, |mut owner| {
        assert!(matches!(owner.record_return(key, 104, 104, Box::new(61)),
            ReturnedPumpObservation::Accepted));
        owner.quarantine_capture().unwrap();
        Ok::<_, ((), _)>(owner)
    }).is_ok());
    let owner = table.get(ticket).unwrap();
    assert_eq!(owner.phase(), ReturnedPumpPhase::Quarantined);
    assert_eq!(owner.replies().unwrap().current, 104);
    assert_eq!(owner.replies().unwrap().returned, 104);
    assert_eq!(**owner.continuation(), 51);
    assert_eq!(**owner.pump().unwrap(), 61);
    let owner = table.take(ticket).unwrap();
    let (_, owner) = owner.into_returned(key).err().unwrap();
    table.restore(ticket, owner).ok().unwrap();
    assert_eq!(**table.get(ticket).unwrap().pump().unwrap(), 61);
}

#[test]
fn wrong_parent_or_reply_quarantines_the_returned_pump_without_replay() {
    let key = key();
    let foreign = ReturnedPumpKey::new(key.route(), key.physical_dispatch(),
        DispatchContext { dispatch_id: key.win32k_dispatch().dispatch_id + 1,
            ..key.win32k_dispatch() }, key.client(), key.initial_reply(), key.attempt())
        .unwrap();
    let mut owner = ReturnedPumpOwner::active(key, Box::new(71u64));
    assert!(matches!(owner.record_return(foreign, 104, 104, Box::new(81u64)),
        ReturnedPumpObservation::Quarantined(ReturnedPumpError::WrongIdentity)));
    assert_eq!(owner.phase(), ReturnedPumpPhase::Quarantined);
    assert_eq!(**owner.pump().unwrap(), 81);
    assert!(owner.into_returned(key).is_err());

    let mut reply_mismatch = ReturnedPumpOwner::active(key, Box::new(91u64));
    assert!(matches!(reply_mismatch.record_return(key, 104, 105, Box::new(101u64)),
        ReturnedPumpObservation::Quarantined(ReturnedPumpError::ReplyMismatch)));
    assert_eq!(**reply_mismatch.pump().unwrap(), 101);
    assert_eq!(reply_mismatch.replies().unwrap().current, 104);
    assert_eq!(reply_mismatch.replies().unwrap().returned, 105);
}

#[test]
fn exact_return_can_move_once_and_refusal_returns_the_same_bundle() {
    let key = key();
    let foreign = ReturnedPumpKey::new(key.route(), key.physical_dispatch(),
        key.win32k_dispatch(), key.client(), key.initial_reply(), key.attempt() + 1).unwrap();
    let mut table = RetainedOwnerTable::<ReturnedPumpKey,
        ReturnedPumpOwner<Box<u64>, Box<u64>>>::new();
    let reservation = table.reserve().unwrap();
    let ticket = table.retain(reservation, key,
        ReturnedPumpOwner::active(key, Box::new(111u64))).ok().unwrap();
    assert!(table.transition_held(ticket, |mut owner| {
        assert!(matches!(owner.record_return(key, 112, 112, Box::new(113u64)),
            ReturnedPumpObservation::Accepted));
        Ok::<_, ((), _)>(owner)
    }).is_ok());
    let owner = table.take(ticket).unwrap();
    let (error, owner) = owner.into_returned(foreign).err().unwrap();
    assert_eq!(error, ReturnedPumpError::WrongIdentity);
    table.restore(ticket, owner).ok().unwrap();
    assert_eq!(table.get(ticket).unwrap().phase(), ReturnedPumpPhase::Returned);
    let owner = table.take(ticket).unwrap();
    let (continuation, pump, reply) = owner.into_returned(key).ok().unwrap();
    assert_eq!((*continuation, *pump, reply), (111, 113, 112));
    table.finish_taken(ticket).unwrap();
    assert!(table.take(ticket).is_none());
}

#[test]
fn duplicate_return_preserves_the_offered_pump() {
    let key = key();
    let mut owner = ReturnedPumpOwner::active(key, Box::new(121u64));
    assert!(matches!(owner.record_return(key, 122, 122, Box::new(123u64)),
        ReturnedPumpObservation::Accepted));
    let offered = match owner.record_return(key, 124, 124, Box::new(125u64)) {
        ReturnedPumpObservation::Refused(ReturnedPumpError::InvalidPhase, pump) => pump,
        _ => panic!("duplicate return must not displace the original pump"),
    };
    assert_eq!(*offered, 125);
    assert_eq!(**owner.pump().unwrap(), 123);
}

#[test]
fn failed_source_observation_quarantines_the_physical_return_before_retirement() {
    let key = key();
    let mut owner = ReturnedPumpOwner::active(key, Box::new(301u64));
    assert!(matches!(owner.record_return(key, 302, 302, Box::new(303u64)),
        ReturnedPumpObservation::Accepted));
    assert_eq!(owner.capture_or_quarantine(|_, _| None::<u64>),
        Err(ReturnedPumpError::Quarantined));
    assert_eq!(owner.phase(), ReturnedPumpPhase::Quarantined);
    assert_eq!(**owner.continuation(), 301);
    assert_eq!(**owner.pump().unwrap(), 303);
    assert_eq!(owner.replies().unwrap().current, 302);
    assert_eq!(owner.replies().unwrap().returned, 302);
    assert!(owner.into_returned(key).is_err(), "an uncertain source return cannot retire");
}
