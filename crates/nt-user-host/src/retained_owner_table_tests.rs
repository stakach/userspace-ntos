use super::retained_owner_table::{RetainedOwnerFinishError, RetainedOwnerTable, RetainedOwnerTransitionError};
use alloc::boxed::Box;

#[derive(Debug, Eq, PartialEq)]
struct ReturnedPump {
    reply: Box<u64>,
    result: u64,
}

#[test]
fn reserved_capacity_retains_returned_pump_and_reply_on_capture_refusal() {
    let mut owners = RetainedOwnerTable::<u64, ReturnedPump>::new();
    let reservation = owners.reserve().unwrap();
    let capacity = owners.capacity();
    let ticket = owners.retain(reservation, 17, ReturnedPump {
        reply: Box::new(0xabc), result: 42,
    }).unwrap();
    let reply_address = &*owners.get(ticket).unwrap().reply as *const u64;
    assert_eq!(owners.transition_held(ticket, |owner| {
        Err::<ReturnedPump, _>(("capture refused", owner))
    }), Err(RetainedOwnerTransitionError::Refused("capture refused")));
    let held = owners.get(ticket).unwrap();
    assert_eq!(held.result, 42);
    assert_eq!(*held.reply, 0xabc);
    assert!(core::ptr::eq(&*held.reply, reply_address));
    assert_eq!(owners.capacity(), capacity);
}

#[test]
fn ticket_generation_and_table_identity_exclude_stale_and_foreign_owners() {
    let mut owners = RetainedOwnerTable::<u64, Box<u64>>::new();
    let old = owners.reserve().unwrap();
    assert!(owners.cancel_reservation(old));
    let fresh = owners.reserve().unwrap();
    assert_ne!(old, fresh);
    let (_, value) = owners.retain(old, 9, Box::new(11)).unwrap_err();
    let ticket = owners.retain(fresh, 9, value).unwrap();
    let mut foreign = RetainedOwnerTable::<u64, Box<u64>>::new();
    let foreign_reservation = foreign.reserve().unwrap();
    let foreign_ticket = foreign.retain(foreign_reservation, 9, Box::new(13)).unwrap();
    assert!(owners.take(foreign_ticket).is_none());
    assert_eq!(**owners.get(ticket).unwrap(), 11);
}

#[test]
fn one_shot_take_and_exact_restore_preserve_the_reply_bundle() {
    let mut owners = RetainedOwnerTable::<u64, ReturnedPump>::new();
    let reservation = owners.reserve().unwrap();
    let ticket = owners.retain(reservation, 21, ReturnedPump {
        reply: Box::new(0xdef), result: 99,
    }).unwrap();
    let owner = owners.take(ticket).unwrap();
    assert!(owners.take(ticket).is_none());
    assert!(owners.get(ticket).is_none());
    let mut foreign = RetainedOwnerTable::<u64, ReturnedPump>::new();
    let foreign_reservation = foreign.reserve().unwrap();
    let foreign_ticket = foreign.retain(foreign_reservation, 21, ReturnedPump {
        reply: Box::new(0xaaa), result: 1,
    }).unwrap();
    let owner = owners.restore(foreign_ticket, owner).unwrap_err();
    owners.restore(ticket, owner).unwrap();
    assert_eq!(*owners.take(ticket).unwrap().reply, 0xdef);
}

#[test]
fn taken_slot_recycles_only_after_exact_downstream_acknowledgement() {
    let mut owners = RetainedOwnerTable::<u64, Box<u64>>::new();
    let first = owners.reserve().unwrap();
    let first_ticket = owners.retain(first, 41, Box::new(0xbeef)).unwrap();
    assert_eq!(owners.finish_taken(first_ticket), Err(RetainedOwnerFinishError::StaleTicket));
    let bundle = owners.take(first_ticket).unwrap();
    let second = owners.reserve().unwrap();
    assert_ne!(second.slot(), first.slot());
    let second_ticket = owners.retain(second, 42, Box::new(0xcafe)).unwrap();
    let mut foreign = RetainedOwnerTable::<u64, Box<u64>>::new();
    let foreign_reservation = foreign.reserve().unwrap();
    let foreign_ticket = foreign.retain(foreign_reservation, 41, Box::new(0)).unwrap();
    assert_eq!(owners.finish_taken(foreign_ticket), Err(RetainedOwnerFinishError::StaleTicket));
    assert!(owners.get(second_ticket).is_some());
    assert_eq!(*bundle, 0xbeef);
    owners.finish_taken(first_ticket).unwrap();
    assert_eq!(owners.finish_taken(first_ticket), Err(RetainedOwnerFinishError::StaleTicket));
    let third = owners.reserve().unwrap();
    assert_eq!(third.slot(), first.slot());
    assert_ne!(third, first);
    let third_ticket = owners.retain(third, 43, Box::new(0xf00d)).unwrap();
    assert_eq!(owners.finish_taken(first_ticket), Err(RetainedOwnerFinishError::StaleTicket));
    assert_eq!(**owners.get(third_ticket).unwrap(), 0xf00d);
}
