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
