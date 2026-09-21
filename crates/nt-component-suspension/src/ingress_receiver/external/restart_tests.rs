use super::*;
use crate::ExternalRestartObservation as Restart;

#[test]
fn free_without_restart_ack_cannot_finish_a_held_call() {
    let (lanes, mut receiver, mut pool) = fixture(true);
    let mut pending = Some(
        pool.retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap(),
    );
    assert!(matches!(
        receiver.finish_restarted_external(&mut pending, no_query),
        Err(ExternalIngressError::NotRestarted)
    ));
    assert!(receiver.excludes_reply(30));
    assert!(pending.as_ref().unwrap().can_park());
}

#[test]
fn restart_ack_is_not_reply_ack_or_stop_and_requires_free_before_release() {
    let (lanes, mut receiver, mut pool) = fixture(true);
    let mut pending = Some(
        pool.retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap(),
    );
    assert_eq!(
        pending.as_mut().unwrap().restart_owned(bound, |tcb| {
            assert_eq!(tcb, 10);
            Restart::Acknowledged
        }),
        Ok(Restart::Acknowledged)
    );
    let call = pending.as_ref().unwrap();
    assert!(call.is_restarted());
    assert!(!call.is_acknowledged());
    assert!(!call.is_stopped());
    assert!(!call.can_park());
    assert!(receiver.finish_external(&mut pending, no_query).is_err());
    assert!(receiver
        .finish_cancelled_external(&mut pending, no_query)
        .is_err());
    assert!(matches!(
        receiver.finish_restarted_external(&mut pending, bound),
        Err(ExternalIngressError::NotFree)
    ));
    assert!(receiver.excludes_reply(30));
    let (ready, message) = receiver
        .finish_restarted_external(&mut pending, free)
        .unwrap();
    assert!(ready.is_ready());
    assert_eq!(message.word(4), Some(55));
    assert!(pending.is_none());
    assert!(!receiver.excludes_reply(30));
    pool.insert_pending(&mut Some(ready), &receiver, &lanes, spare_free)
        .unwrap();
}

#[test]
fn acknowledged_restart_cannot_replay_even_after_a_free_query_failure() {
    let (lanes, mut receiver, mut pool) = fixture(true);
    let mut pending = Some(
        pool.retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap(),
    );
    pending
        .as_mut()
        .unwrap()
        .restart_owned(bound, |_| Restart::Acknowledged)
        .unwrap();
    assert!(matches!(
        receiver.finish_restarted_external(&mut pending, |_, _| Err(9u8)),
        Err(ExternalIngressError::Query(9))
    ));
    assert_eq!(
        pending
            .as_mut()
            .unwrap()
            .restart_owned(no_query, |_| panic!("no replay")),
        Err(ExternalIngressError::RestartEntered)
    );
    assert!(pending
        .as_mut()
        .unwrap()
        .reply_owned(no_query, |_| panic!("no Reply after restart"))
        .is_err());
    assert!(receiver.excludes_reply(30));
    let (_ready, _message) = receiver
        .finish_restarted_external(&mut pending, free)
        .unwrap();
}

#[test]
fn rejected_restart_preserves_held_call_for_a_real_failure_reply() {
    let (lanes, mut receiver, mut pool) = fixture(true);
    let mut pending = Some(
        pool.retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap(),
    );
    assert_eq!(
        pending
            .as_mut()
            .unwrap()
            .restart_owned(bound, |_| Restart::Rejected(7)),
        Ok(Restart::Rejected(7))
    );
    assert!(pending.as_ref().unwrap().can_park());
    assert!(receiver.excludes_reply(30));
    assert_eq!(
        pending
            .as_mut()
            .unwrap()
            .reply_owned(bound, |_| IngressReplyObservation::Acknowledged),
        Ok(IngressReplyObservation::Acknowledged)
    );
    let (_ready, _message) = receiver.finish_external(&mut pending, free).unwrap();
}

#[test]
fn uncertain_restart_keeps_payload_and_exclusion_without_replay_or_false_completion() {
    let (lanes, mut receiver, mut pool) = fixture(true);
    let mut pending = Some(
        pool.retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap(),
    );
    assert_eq!(
        pending
            .as_mut()
            .unwrap()
            .restart_owned(bound, |_| Restart::Indeterminate),
        Ok(Restart::Indeterminate)
    );
    assert!(!pending.as_ref().unwrap().can_park());
    assert_eq!(pending.as_ref().unwrap().message().word(4), Some(55));
    assert_eq!(
        pending
            .as_mut()
            .unwrap()
            .restart_owned(no_query, |_| panic!("no replay")),
        Err(ExternalIngressError::RestartEntered)
    );
    assert!(pending
        .as_mut()
        .unwrap()
        .reply_owned(no_query, |_| panic!("no Reply"))
        .is_err());
    assert!(receiver
        .finish_restarted_external(&mut pending, no_query)
        .is_err());
    assert!(receiver.finish_external(&mut pending, no_query).is_err());
    assert!(receiver.excludes_reply(30));
    // Only an independently acknowledged physical Stop can cancel uncertain restart work.
    pending
        .as_mut()
        .unwrap()
        .stop_owned(|_| Ok::<_, u8>(()))
        .unwrap();
    let (_ready, _message) = receiver
        .finish_cancelled_external(&mut pending, free)
        .unwrap();
}

#[test]
fn restart_authentication_and_foreign_receiver_refusals_do_not_consume_owner() {
    let (lanes, mut receiver, mut pool) = fixture(true);
    let mut pending = Some(
        pool.retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap(),
    );
    assert_eq!(
        pending
            .as_mut()
            .unwrap()
            .restart_owned(free, |_| panic!("unbound")),
        Err(ExternalIngressError::NotBound)
    );
    assert!(pending.as_ref().unwrap().can_park());
    pending
        .as_mut()
        .unwrap()
        .restart_owned(bound, |_| Restart::Acknowledged)
        .unwrap();
    let mut foreign = IngressReceiver::<ReceivedMessage>::new(20, 50, 1).unwrap();
    assert!(matches!(
        foreign.finish_restarted_external(&mut pending, no_query),
        Err(ExternalIngressError::WrongOwner)
    ));
    assert!(pending.as_ref().unwrap().is_restarted());
    assert!(receiver.excludes_reply(30));
}

#[test]
fn reply_or_stop_entry_prevents_context_restart() {
    for stop in [false, true] {
        let (lanes, mut receiver, mut pool) = fixture(true);
        let mut call = pool
            .retain_external(&mut receiver, &lanes, 10, spare_free, bound)
            .unwrap();
        if stop {
            call.stop_owned(|_| Ok::<_, u8>(())).unwrap();
        } else {
            call.reply_owned(bound, |_| IngressReplyObservation::Indeterminate)
                .unwrap();
        }
        assert!(call
            .restart_owned(no_query, |_| panic!("conflicting effect"))
            .is_err());
    }
}
