use super::*;
use crate::{
    ComponentIngress, ComponentSuspensionLanes, IngressReceiveDisposition, IngressReceiver,
    IngressReplyObservation, ReplyBindingObservation,
};

type Lanes = ComponentSuspensionLanes<(), (), ()>;

fn retain(
    receiver: &mut IngressReceiver<u64>,
    lanes: &Lanes,
    replacement: ComponentIngress<u64>,
    message: u64,
) -> ExternalIngress<u64> {
    receiver.begin_receive(lanes).unwrap();
    receiver.capture(message).ok().unwrap();
    receiver
        .resolve(IngressReceiveDisposition::Call)
        .ok()
        .unwrap();
    receiver
        .retain_external(lanes, replacement, 10, |_, _| {
            Ok::<_, ()>(ReplyBindingObservation::BoundToTarget)
        })
        .ok()
        .unwrap()
}

fn finish(
    receiver: &mut IngressReceiver<u64>,
    pending: &mut Option<ExternalIngress<u64>>,
) -> ComponentIngress<u64> {
    pending
        .as_mut()
        .unwrap()
        .reply_owned(
            |_, _| Ok::<_, ()>(ReplyBindingObservation::BoundToTarget),
            |_| IngressReplyObservation::Acknowledged,
        )
        .unwrap();
    receiver
        .finish_external(pending, |_, _| Ok::<_, ()>(ReplyBindingObservation::Free))
        .unwrap()
        .0
}

#[test]
fn recurring_reused_low_slot_cannot_starve_older_retained_fault() {
    let lanes = Lanes::new(1, 2);
    let mut receiver = IngressReceiver::new(20, 30, 2).unwrap();
    let mut recurring = Some(retain(
        &mut receiver,
        &lanes,
        ComponentIngress::new(20, 31).unwrap(),
        1,
    ));
    let fault = retain(
        &mut receiver,
        &lanes,
        ComponentIngress::new(20, 32).unwrap(),
        2,
    );
    assert!(recurring.as_ref().unwrap().admission_sequence() < fault.admission_sequence());
    assert_eq!(
        oldest_external_ingress([(0, recurring.as_ref().unwrap()), (1, &fault),]),
        Some(0)
    );

    for _ in 0..8 {
        let old_sequence = recurring.as_ref().unwrap().admission_sequence();
        let spare = finish(&mut receiver, &mut recurring);
        recurring = Some(retain(&mut receiver, &lanes, spare, 1));
        assert!(recurring.as_ref().unwrap().admission_sequence() > old_sequence);
        assert!(recurring.as_ref().unwrap().admission_sequence() > fault.admission_sequence());
        assert_eq!(
            oldest_external_ingress([(0, recurring.as_ref().unwrap()), (1, &fault),]),
            Some(1),
            "a newly admitted low-slot Call overtook the retained fault"
        );
        assert!(receiver.excludes_reply(fault.reply()));
    }
}

#[test]
fn external_selection_observes_without_effects_and_handles_holes() {
    let lanes = Lanes::new(1, 2);
    let mut receiver = IngressReceiver::new(20, 30, 2).unwrap();
    let older = retain(
        &mut receiver,
        &lanes,
        ComponentIngress::new(20, 31).unwrap(),
        7,
    );
    let newer = retain(
        &mut receiver,
        &lanes,
        ComponentIngress::new(20, 32).unwrap(),
        8,
    );
    assert_eq!(oldest_external_ingress::<u64>(core::iter::empty()), None);
    assert_eq!(oldest_external_ingress([(19, &older)]), Some(19));
    let before = (
        older.admission_sequence(),
        newer.admission_sequence(),
        receiver.available(),
    );
    for _ in 0..16 {
        assert_eq!(
            oldest_external_ingress([(4, &older), (90, &newer)]),
            Some(4)
        );
        assert_eq!(*older.message(), 7);
        assert_eq!(*newer.message(), 8);
        assert!(older.can_park() && newer.can_park());
        assert!(!older.is_acknowledged() && !newer.is_acknowledged());
        assert!(receiver.excludes_reply(older.reply()));
        assert!(receiver.excludes_reply(newer.reply()));
        assert_eq!(
            before,
            (
                older.admission_sequence(),
                newer.admission_sequence(),
                receiver.available()
            )
        );
    }
}

#[test]
fn external_order_is_global_across_receiver_stores_not_local_slots() {
    let lanes = Lanes::new(1, 2);
    let mut first = IngressReceiver::new(20, 30, 1).unwrap();
    let older = retain(
        &mut first,
        &lanes,
        ComponentIngress::new(20, 31).unwrap(),
        7,
    );
    let mut second = IngressReceiver::new(40, 50, 1).unwrap();
    let newer = retain(
        &mut second,
        &lanes,
        ComponentIngress::new(40, 51).unwrap(),
        8,
    );
    assert!(older.admission_sequence() < newer.admission_sequence());
    assert_eq!(oldest_external_ingress([(0, &newer), (5, &older)]), Some(5));
}

#[test]
fn receive_selection_skips_older_sealed_call_without_transferring_its_reply() {
    let lanes = Lanes::new(1, 2);
    let mut receiver = IngressReceiver::new(20, 30, 2).unwrap();
    let older = retain(&mut receiver, &lanes, ComponentIngress::new(20, 31).unwrap(), 7);
    let younger = retain(&mut receiver, &lanes, ComponentIngress::new(20, 32).unwrap(), 8);
    assert!(older.admission_sequence() < younger.admission_sequence());

    for _ in 0..2 {
        assert_eq!(
            oldest_receive_external_ingress([
                (4, &older, ExternalReceiveState { settlement_prepared: true, ..Default::default() }),
                (90, &younger, ExternalReceiveState::default()),
            ]),
            Some(90),
        );
    }
    assert!(receiver.excludes_reply(older.reply()));
    assert!(receiver.excludes_reply(younger.reply()));
    assert!(older.can_park() && younger.can_park());
}

#[test]
fn receive_selection_skips_older_stop_entered_call_and_preserves_ordinal_order() {
    let lanes = Lanes::new(1, 2);
    let mut receiver = IngressReceiver::new(20, 30, 3).unwrap();
    let mut older = retain(&mut receiver, &lanes, ComponentIngress::new(20, 31).unwrap(), 7);
    let middle = retain(&mut receiver, &lanes, ComponentIngress::new(20, 32).unwrap(), 8);
    let younger = retain(&mut receiver, &lanes, ComponentIngress::new(20, 33).unwrap(), 9);
    assert!(older.admission_sequence() < middle.admission_sequence());
    assert!(middle.admission_sequence() < younger.admission_sequence());
    assert_eq!(older.stop_owned(|_| Err::<(), u8>(7)), Err(crate::ExternalIngressError::Stop(7)));
    assert!(older.stop_started() && !older.can_park());

    assert_eq!(
        oldest_receive_external_ingress([
            (4, &older, ExternalReceiveState::default()),
            (1, &younger, ExternalReceiveState::default()),
            (90, &middle, ExternalReceiveState::default()),
        ]),
        Some(90),
    );
    assert!(receiver.excludes_reply(older.reply()));
    assert!(receiver.excludes_reply(middle.reply()));
    assert!(receiver.excludes_reply(younger.reply()));
}

#[test]
fn receive_fault_selection_keeps_older_ordinary_call_and_selects_younger_fault() {
    let lanes = Lanes::new(1, 2);
    let mut receiver = IngressReceiver::new(20, 30, 2).unwrap();
    let ordinary = retain(&mut receiver, &lanes, ComponentIngress::new(20, 31).unwrap(), 0x4e54_007);
    let fault = retain(&mut receiver, &lanes, ComponentIngress::new(20, 32).unwrap(), (6 << 12) | 4);
    assert!(ordinary.admission_sequence() < fault.admission_sequence());
    assert_eq!(
        oldest_receive_external_ingress_matching([
            (2, &ordinary, ExternalReceiveState::default()),
            (9, &fault, ExternalReceiveState::default()),
        ], |call| *call.message() == ((6 << 12) | 4)),
        Some(9),
    );
    assert!(receiver.excludes_reply(ordinary.reply()));
    assert!(receiver.excludes_reply(fault.reply()));
    assert!(ordinary.can_park() && fault.can_park());
}

#[test]
fn receive_fault_selection_orders_matching_calls_by_admission_not_slot() {
    let lanes = Lanes::new(1, 2);
    let mut receiver = IngressReceiver::new(20, 30, 3).unwrap();
    let ordinary = retain(&mut receiver, &lanes, ComponentIngress::new(20, 31).unwrap(), 0x4e54_007);
    let first_fault = retain(&mut receiver, &lanes, ComponentIngress::new(20, 32).unwrap(), (6 << 12) | 4);
    let later_fault = retain(&mut receiver, &lanes, ComponentIngress::new(20, 33).unwrap(), (6 << 12) | 4);
    assert!(first_fault.admission_sequence() < later_fault.admission_sequence());
    assert_eq!(
        oldest_receive_external_ingress_matching([
            (1, &later_fault, ExternalReceiveState::default()),
            (2, &ordinary, ExternalReceiveState::default()),
            (90, &first_fault, ExternalReceiveState::default()),
        ], |call| *call.message() == ((6 << 12) | 4)),
        Some(90),
    );
    assert!(receiver.excludes_reply(first_fault.reply()));
    assert!(receiver.excludes_reply(later_fault.reply()));
}

#[test]
fn receive_fault_selection_skips_sealed_and_stop_entered_older_faults() {
    let lanes = Lanes::new(1, 2);
    let mut receiver = IngressReceiver::new(20, 30, 3).unwrap();
    let sealed = retain(&mut receiver, &lanes, ComponentIngress::new(20, 31).unwrap(), (6 << 12) | 4);
    let mut stopped = retain(&mut receiver, &lanes, ComponentIngress::new(20, 32).unwrap(), (6 << 12) | 4);
    let eligible = retain(&mut receiver, &lanes, ComponentIngress::new(20, 33).unwrap(), (6 << 12) | 4);
    assert_eq!(stopped.stop_owned(|_| Err::<(), u8>(7)), Err(crate::ExternalIngressError::Stop(7)));
    assert_eq!(
        oldest_receive_external_ingress_matching([
            (3, &sealed, ExternalReceiveState { settlement_prepared: true, ..Default::default() }),
            (8, &stopped, ExternalReceiveState::default()),
            (13, &eligible, ExternalReceiveState::default()),
        ], |call| *call.message() == ((6 << 12) | 4)),
        Some(13),
    );
    assert!(receiver.excludes_reply(sealed.reply()));
    assert!(receiver.excludes_reply(stopped.reply()));
    assert!(receiver.excludes_reply(eligible.reply()));
}
