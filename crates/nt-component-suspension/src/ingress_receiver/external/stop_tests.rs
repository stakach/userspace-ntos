use super::*;

#[test]
fn free_without_stop_ack_never_authorizes_cancellation() {
    let (lanes, mut receiver, mut pool) = fixture(true);
    let mut pending = Some(
        pool.retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap(),
    );
    assert!(matches!(
        receiver.finish_cancelled_external(&mut pending, no_query),
        Err(ExternalIngressError::NotStopped)
    ));
    assert!(receiver.excludes_reply(30));
    assert!(pending.is_some());
}

#[test]
fn uncertain_stop_is_entered_before_effect_and_cannot_replay_or_finish() {
    let (lanes, mut receiver, mut pool) = fixture(true);
    let mut pending = Some(
        pool.retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap(),
    );
    assert_eq!(
        pending.as_mut().unwrap().stop_owned(|executor| {
            assert_eq!(executor, 10);
            Err(7u8)
        }),
        Err(ExternalIngressError::Stop(7))
    );
    assert!(pending.as_ref().unwrap().stop_started());
    assert!(!pending.as_ref().unwrap().is_stopped());
    assert_eq!(
        pending
            .as_mut()
            .unwrap()
            .stop_owned(|_| -> Result<(), u8> { panic!("stop must not replay") }),
        Err(ExternalIngressError::StopEntered)
    );
    assert!(pending
        .as_mut()
        .unwrap()
        .reply_owned(no_query, |_| panic!("stopped Reply cannot run"))
        .is_err());
    assert!(receiver
        .finish_cancelled_external(&mut pending, no_query)
        .is_err());
    assert!(receiver.finish_external(&mut pending, no_query).is_err());
    assert!(receiver.excludes_reply(30));
}

#[test]
fn acknowledged_stop_cancels_uncertain_reply_without_claiming_ack_or_replay() {
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
    pending
        .as_mut()
        .unwrap()
        .stop_owned(|_| Ok::<_, u8>(()))
        .unwrap();
    assert!(pending.as_ref().unwrap().is_stopped());
    assert!(!pending.as_ref().unwrap().is_acknowledged());
    pending
        .as_mut()
        .unwrap()
        .stop_owned(|_| -> Result<(), u8> { panic!("ACKed stop is idempotent") })
        .unwrap();
    assert!(pending
        .as_mut()
        .unwrap()
        .reply_owned(no_query, |_| panic!("uncertain Reply cannot replay"))
        .is_err());
    assert!(receiver.finish_external(&mut pending, no_query).is_err());
    let (owner, message) = receiver
        .finish_cancelled_external(&mut pending, free)
        .unwrap();
    assert_eq!(message.word(4), Some(55));
    assert!(owner.is_ready());
    assert!(pending.is_none());
    assert!(!receiver.excludes_reply(30));
    let mut spare = Some(owner);
    pool.insert_pending(&mut spare, &receiver, &lanes, spare_free)
        .unwrap();
}

#[test]
fn foreign_receiver_and_failed_free_query_preserve_stop_ack_and_payload() {
    let (lanes, mut receiver, mut pool) = fixture(true);
    let mut pending = Some(
        pool.retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap(),
    );
    pending
        .as_mut()
        .unwrap()
        .stop_owned(|_| Ok::<_, u8>(()))
        .unwrap();
    let mut foreign = IngressReceiver::<ReceivedMessage>::new(20, 50, 1).unwrap();
    assert!(matches!(
        foreign.finish_cancelled_external(&mut pending, no_query),
        Err(ExternalIngressError::WrongOwner)
    ));
    assert!(matches!(
        receiver.finish_cancelled_external(&mut pending, |_, _| Err(8u8)),
        Err(ExternalIngressError::Query(8))
    ));
    assert!(matches!(
        receiver.finish_cancelled_external(&mut pending, bound),
        Err(ExternalIngressError::NotFree)
    ));
    assert!(pending.as_ref().unwrap().is_stopped());
    assert_eq!(pending.as_ref().unwrap().message().word(4), Some(55));
    assert!(receiver.excludes_reply(30));
    let (_ready, _message) = receiver
        .finish_cancelled_external(&mut pending, free)
        .unwrap();
}
