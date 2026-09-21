use super::*;
use crate::{IngressReplyObservation, IngressReplyPool, IpcBufferSnapshot, ReceivedMessage};

#[path = "stop_tests.rs"]
mod stop_tests;

#[path = "restart_tests.rs"]
mod restart_tests;

type Lanes = ComponentSuspensionLanes<(), (), ()>;
fn bound(tcb: u64, reply: u64) -> Result<ReplyBindingObservation, u8> {
    assert_eq!((tcb, reply), (10, 30));
    Ok(ReplyBindingObservation::BoundToTarget)
}
fn free(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::Free)
}
fn no_query(_: u64, _: u64) -> Result<ReplyBindingObservation, u8> {
    panic!("must not query")
}
fn spare_free(_: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::Free)
}

fn fixture(
    resolve: bool,
) -> (
    Lanes,
    IngressReceiver<ReceivedMessage>,
    IngressReplyPool<ReceivedMessage>,
) {
    let lanes = Lanes::new(1, 2);
    let mut receiver = IngressReceiver::new(20, 30, 1).unwrap();
    let mut pool = IngressReplyPool::new(20, 2).unwrap();
    pool.insert(
        ComponentIngress::new(20, 40).unwrap(),
        &receiver,
        &lanes,
        spare_free,
    )
    .ok()
    .unwrap();
    receiver.begin_receive(&lanes).unwrap();
    receiver
        .capture(ReceivedMessage::new(
            27,
            (9 << 12) | 5,
            [1, 2, 3, 4],
            IpcBufferSnapshot::capture(|index| if index == 5 { 55 } else { 99 }),
        ))
        .ok()
        .unwrap();
    if resolve {
        receiver
            .resolve(IngressReceiveDisposition::Call)
            .ok()
            .unwrap();
    }
    (lanes, receiver, pool)
}

#[test]
fn parking_requires_original_held_call_without_reply_or_stop_entry() {
    for phase in 0..4 {
        let (lanes, mut receiver, mut pool) = fixture(true);
        let mut call = pool
            .retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap();
        assert!(call.can_park());
        match phase {
            0 => {
                call.reply_owned(bound, |_| IngressReplyObservation::Acknowledged)
                    .unwrap();
            }
            1 => {
                call.reply_owned(bound, |_| IngressReplyObservation::Indeterminate)
                    .unwrap();
            }
            2 => {
                call.stop_owned(|_| Ok::<_, u8>(())).unwrap();
            }
            _ => {
                assert!(call.stop_owned(|_| Err(7u8)).is_err());
            }
        }
        assert!(!call.can_park());
    }
}

#[test]
fn foreign_call_keeps_full_payload_and_reply_exclusion_until_ack_and_free() {
    let (lanes, mut receiver, mut pool) = fixture(true);
    let mut pending = Some(
        pool.retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap(),
    );
    let call = pending.as_ref().unwrap();
    assert_eq!(call.reply(), 30);
    assert_eq!(call.executor(), 10);
    assert_eq!(call.message().word(4), Some(55));
    assert_eq!(call.message().badge(), 27);
    assert_eq!(receiver.reply(), 40);
    assert!(receiver.excludes_reply(30));
    assert_eq!(receiver.available(), 0);
    assert!(receiver.begin_receive(&lanes).is_err());
    assert!(matches!(
        receiver.finish_external(&mut pending, no_query),
        Err(ExternalIngressError::NotAcknowledged)
    ));
    pending
        .as_mut()
        .unwrap()
        .reply_owned(bound, |_| IngressReplyObservation::Acknowledged)
        .unwrap();
    assert!(matches!(
        receiver.finish_external(&mut pending, |_, _| Err(7u8)),
        Err(ExternalIngressError::Query(7))
    ));
    assert!(pending.is_some());
    assert!(receiver.excludes_reply(30));
    let (owner, message) = receiver.finish_external(&mut pending, free).unwrap();
    assert_eq!(message.word(4), Some(55));
    assert!(pending.is_none());
    assert!(!receiver.excludes_reply(30));
    assert_eq!(receiver.available(), 1);
    let mut spare = Some(owner);
    pool.insert_pending(&mut spare, &receiver, &lanes, spare_free)
        .unwrap();
    assert!(spare.is_none());
    assert!(pool.excludes_reply(30));
}

#[test]
fn refused_authentication_or_unclassified_receive_restores_same_replacement() {
    for resolved in [false, true] {
        let (lanes, mut receiver, mut pool) = fixture(resolved);
        assert!(pool
            .retain_external(&mut receiver, &lanes, 10, spare_free, |_, _| Ok::<_, u8>(
                ReplyBindingObservation::BoundElsewhere
            ))
            .is_err());
        assert_eq!(receiver.reply(), 30);
        assert_eq!(pool.len(), 1);
        assert!(pool.excludes_reply(40));
        assert_eq!(receiver.available(), 0);
        assert!(receiver.phase().is_some());
    }
}

#[test]
fn uncertain_foreign_reply_cannot_replay_or_release_exclusion() {
    let (lanes, mut receiver, mut pool) = fixture(true);
    let mut pending = Some(
        pool.retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap(),
    );
    pending
        .as_mut()
        .unwrap()
        .reply_owned(bound, |_| IngressReplyObservation::Indeterminate)
        .unwrap();
    assert!(pending
        .as_mut()
        .unwrap()
        .reply_owned(no_query, |_| panic!("cannot replay"))
        .is_err());
    assert!(receiver.finish_external(&mut pending, no_query).is_err());
    assert!(pending.is_some());
    assert!(receiver.excludes_reply(30));
    let alias = ComponentIngress::new(20, 30).unwrap();
    assert!(pool
        .insert(alias, &receiver, &lanes, |_| -> Result<_, u8> {
            panic!("alias must not query")
        })
        .is_err());
}

#[test]
fn no_effects_reply_can_retry_but_wrong_receiver_cannot_finish() {
    let (lanes, mut receiver, mut pool) = fixture(true);
    let mut pending = Some(
        pool.retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap(),
    );
    pending
        .as_mut()
        .unwrap()
        .reply_owned(bound, |_| IngressReplyObservation::NoEffects)
        .unwrap();
    assert_eq!(pending.as_ref().unwrap().message().word(4), Some(55));
    pending
        .as_mut()
        .unwrap()
        .reply_owned(bound, |_| IngressReplyObservation::Acknowledged)
        .unwrap();
    let mut foreign = IngressReceiver::<ReceivedMessage>::new(20, 50, 1).unwrap();
    assert!(matches!(
        foreign.finish_external(&mut pending, no_query),
        Err(ExternalIngressError::WrongOwner)
    ));
    assert!(pending.is_some());
    assert!(matches!(
        receiver.finish_external(&mut pending, bound),
        Err(ExternalIngressError::NotFree)
    ));
    let (_ready, _message) = receiver.finish_external(&mut pending, free).unwrap();
}

#[test]
fn hosted_reply_preserves_unrelated_component_running_fence() {
    let (mut lanes, mut receiver, mut pool) = fixture(true);
    let mut pending = Some(
        pool.retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap(),
    );
    let lane = lanes
        .allocate(crate::LaneBinding {
            executor_id: 50,
            receive_endpoint: 60,
            reply_object: 70,
        })
        .unwrap();
    lanes.begin_dispatch(lane, 70).unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap();
    pending
        .as_mut()
        .unwrap()
        .reply_owned(bound, |_| IngressReplyObservation::Acknowledged)
        .unwrap();
    let (_ready, _message) = receiver.finish_external(&mut pending, free).unwrap();
    assert_eq!(lanes.running(), Some(lane));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(dispatch));
}
