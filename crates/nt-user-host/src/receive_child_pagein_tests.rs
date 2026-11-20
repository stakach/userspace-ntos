use super::*;

type Turn = ReceiveChildPageIn<u64, u64, u64>;

const CHILD: u64 = 312;
const ADMISSION: u64 = 0x51;
const PARENT: u64 = 0x77;
const PAGE: u64 = 0x7ff6_1000;

fn admitted() -> Turn {
    Turn::admit(CHILD, ADMISSION, PARENT, PAGE).unwrap()
}

const EVENTS: [ReceiveChildRootEvent; 3] = [
    ReceiveChildRootEvent::Notification,
    ReceiveChildRootEvent::SelectedChild,
    ReceiveChildRootEvent::Unrelated,
];

#[test]
fn admission_requires_one_exact_page() {
    assert_eq!(Turn::admit(CHILD, ADMISSION, PARENT, PAGE + 8).err(),
        Some(ReceiveChildPageInError::Unaligned));
    let turn = admitted();
    assert_eq!((turn.child(), turn.admission(), turn.parent(), turn.page()),
        (CHILD, ADMISSION, PARENT, PAGE));
}

#[test]
fn owned_read_admits_only_notifications_to_the_root() {
    let mut turn = admitted();
    for _ in 0..2 {
        assert_eq!(turn.root_action(ReceiveChildRootEvent::Notification),
            ReceiveChildRootAction::ServicePageIn);
        // The page-in owns the child's Reply: a second delivery of its Call is not authority.
        assert_eq!(turn.root_action(ReceiveChildRootEvent::SelectedChild),
            ReceiveChildRootAction::RefuseIdentity);
        // Unrelated ingress stays in its own row; it never enters while the parent is held.
        assert_eq!(turn.root_action(ReceiveChildRootEvent::Unrelated),
            ReceiveChildRootAction::DeferUnrelated);
        if turn.page_mapped().is_err() { break; }
    }
}

#[test]
fn child_reply_is_entered_once_and_only_after_the_page_is_mapped() {
    let mut turn = admitted();
    assert_eq!(turn.enter_reply(), Err(ReceiveChildPageInError::WrongPhase),
        "a Pending or unpublished read cannot reply to the child");
    turn.page_mapped().unwrap();
    assert_eq!(turn.page_mapped(), Err(ReceiveChildPageInError::WrongPhase));
    turn.enter_reply().unwrap();
    assert_eq!(turn.enter_reply(), Err(ReceiveChildPageInError::WrongPhase),
        "an entered Reply is never sent again");
    // An entered but unacknowledged Reply still owns the root until its exact settlement.
    assert_eq!(turn.root_action(ReceiveChildRootEvent::Notification),
        ReceiveChildRootAction::ServicePageIn);
}

#[test]
fn settlement_is_one_receipt_for_the_exact_child_and_held_parent() {
    let turn = admitted();
    let (error, mut turn) = turn.acknowledge().err().unwrap();
    assert_eq!(error, ReceiveChildPageInError::WrongPhase,
        "no settlement before the one child Reply");
    turn.page_mapped().unwrap();
    let (error, mut turn) = turn.acknowledge().err().unwrap();
    assert_eq!(error, ReceiveChildPageInError::WrongPhase);
    turn.enter_reply().unwrap();
    let settled = turn.acknowledge().unwrap();
    assert_eq!((settled.child(), settled.admission(), settled.parent(), settled.page()),
        (CHILD, ADMISSION, PARENT, PAGE));
}

#[test]
fn failure_or_uncertainty_retains_every_owner_and_stops_the_root() {
    for mapped in [false, true] {
        for entered in [false, true] {
            if entered && !mapped { continue; }
            let mut turn = admitted();
            if mapped { turn.page_mapped().unwrap(); }
            if entered { turn.enter_reply().unwrap(); }
            turn.retain(0xc000_0185);
            turn.retain(0xc000_009a);
            assert_eq!(turn.retained_status(), Some(0xc000_0185),
                "the first uncertain status is retained");
            for event in EVENTS {
                assert_eq!(turn.root_action(event), ReceiveChildRootAction::StopRetained,
                    "no cancellation settlement exists for a held Receive parent");
            }
            assert_eq!(turn.page_mapped(), Err(ReceiveChildPageInError::Retained));
            assert_eq!(turn.enter_reply(), Err(ReceiveChildPageInError::Retained));
            let (error, turn) = turn.acknowledge().err().unwrap();
            assert_eq!(error, ReceiveChildPageInError::Retained);
            assert_eq!(turn.child(), CHILD);
        }
    }
}

// Boot 44719389234 (multicore): the child's Reply was sent, and the child ran on another core
// and delivered its next fault before the root acknowledged the page-in. The root refused that
// delivery as a duplicate and exited. A delivery after the Reply is the child's next event.
#[test]
fn a_childs_next_delivery_after_its_reply_settles_the_page_in_first() {
    let mut turn = admitted();
    turn.page_mapped().unwrap();
    assert_eq!(turn.root_action(ReceiveChildRootEvent::SelectedChild),
        ReceiveChildRootAction::RefuseIdentity, "before the Reply the child cannot deliver again");
    turn.enter_reply().unwrap();
    assert_eq!(turn.root_action(ReceiveChildRootEvent::SelectedChild),
        ReceiveChildRootAction::SettleFirst);
    assert_eq!(turn.root_action(ReceiveChildRootEvent::Unrelated),
        ReceiveChildRootAction::DeferUnrelated);
    assert!(turn.acknowledge().is_ok());
}
