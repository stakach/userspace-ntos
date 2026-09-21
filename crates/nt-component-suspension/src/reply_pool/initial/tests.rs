use super::*;
use crate::IngressReceiveDisposition;

type Lanes = ComponentSuspensionLanes<(), (), ()>;
fn free(_: u64) -> Result<ReplyBindingObservation, u8> {
    Ok(ReplyBindingObservation::Free)
}
fn no_query(_: u64) -> Result<ReplyBindingObservation, u8> {
    panic!("preflight refusal")
}
fn fixture() -> (Lanes, IngressReceiver<u64>, IngressReplyPool<u64>) {
    let lanes = Lanes::new(1, 2);
    let receiver = IngressReceiver::new(20, 30, 2).unwrap();
    let mut pool = IngressReplyPool::new(20, 1).unwrap();
    pool.insert(
        ComponentIngress::new(20, 40).unwrap(),
        &receiver,
        &lanes,
        free,
    )
    .ok()
    .unwrap();
    (lanes, receiver, pool)
}

#[test]
fn unique_initial_transfer_recovers_capacity_for_repeated_retirement_churn() {
    let (lanes, receiver, mut pool) = fixture();
    for _ in 0..10 {
        let owner = pool.take_initial_reply(&receiver, &lanes, free).unwrap();
        assert_eq!(owner.reply(), 40);
        assert!(owner.is_ready());
        assert!(pool.is_empty());
        assert!(matches!(
            pool.take_initial_reply(&receiver, &lanes, no_query),
            Err(ReplyPoolError::Empty)
        ));
        let mut pending = Some(owner);
        pool.insert_pending(&mut pending, &receiver, &lanes, free)
            .unwrap();
        assert!(pending.is_none());
        assert_eq!(pool.len(), 1);
    }
}

#[test]
fn active_receive_refuses_without_query_or_removing_owner() {
    let (lanes, mut receiver, mut pool) = fixture();
    receiver.begin_receive(&lanes).unwrap();
    assert!(matches!(
        pool.take_initial_reply(&receiver, &lanes, no_query),
        Err(ReplyPoolError::NotReady)
    ));
    receiver.capture(99).ok().unwrap();
    receiver
        .resolve(IngressReceiveDisposition::Call)
        .ok()
        .unwrap();
    assert!(matches!(
        pool.take_initial_reply(&receiver, &lanes, no_query),
        Err(ReplyPoolError::NotReady)
    ));
    assert_eq!(pool.len(), 1);
    assert_eq!(receiver.reply(), 30);
}

#[test]
fn failed_or_nonfree_query_retains_same_initial_owner() {
    let (lanes, receiver, mut pool) = fixture();
    assert!(matches!(
        pool.take_initial_reply(&receiver, &lanes, |_| Err(7u8)),
        Err(ReplyPoolError::Query(7))
    ));
    assert!(matches!(
        pool.take_initial_reply(&receiver, &lanes, |_| Ok::<_, u8>(
            ReplyBindingObservation::BoundElsewhere
        )),
        Err(ReplyPoolError::NotFree)
    ));
    assert_eq!(pool.len(), 1);
    assert!(pool.excludes_reply(40));
}

#[test]
fn foreign_held_reply_exclusion_prevents_initial_alias_transfer() {
    let (lanes, mut receiver, mut pool) = fixture();
    receiver.begin_receive(&lanes).unwrap();
    receiver.capture(99).ok().unwrap();
    receiver
        .resolve(IngressReceiveDisposition::Call)
        .ok()
        .unwrap();
    let external = pool
        .retain_external(&mut receiver, &lanes, 10, free, |_, _| {
            Ok::<_, u8>(ReplyBindingObservation::BoundToTarget)
        })
        .unwrap();
    assert_eq!(external.reply(), 30);
    // Inject a counterfeit pool entry to exercise extraction's independent exclusion check.
    pool.entries.push(ComponentIngress::new(20, 30).unwrap());
    assert!(matches!(
        pool.take_initial_reply(&receiver, &lanes, no_query),
        Err(ReplyPoolError::ReplyInUse)
    ));
    assert_eq!(pool.len(), 1);
    assert!(receiver.excludes_reply(30));
}
