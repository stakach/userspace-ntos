//! A producer owns one ring slot from reservation through publication. The consumer may
//! claim only published entries in sequence order, even when producers finish out of order.

use nt_component_suspension::HostedWorkQueueAdmission;
use std::sync::{Arc, Barrier};

#[test]
fn concurrent_producers_reserve_distinct_slots() {
    let queue = Arc::new(HostedWorkQueueAdmission::<2>::new());
    let start = Arc::new(Barrier::new(3));
    let producers: Vec<_> = (0..2)
        .map(|_| {
            let queue = Arc::clone(&queue);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                queue.reserve().expect("each producer must own a free slot")
            })
        })
        .collect();
    start.wait();
    let first = producers.into_iter().map(|producer| producer.join().unwrap())
        .collect::<Vec<_>>();
    assert_ne!(first[0].sequence(), first[1].sequence());
    assert_ne!(first[0].slot(), first[1].slot());
    assert!(queue.reserve().is_err(), "unpublished reservations still occupy slots");
}

#[test]
fn unpublished_head_blocks_consumption_and_cannot_be_replayed() {
    let queue = HostedWorkQueueAdmission::<2>::new();
    let first = queue.reserve().unwrap();
    let second = queue.reserve().unwrap();

    // The native producer writes its payload between reserve and publish. Publishing a
    // later slot must not expose an uninitialized earlier slot or skip its owner.
    queue.publish(second).unwrap();
    assert!(queue.claim_ready().is_none());

    queue.publish(first).unwrap();
    assert!(queue.publish(first).is_err(), "a reservation publishes only once");
    let claimed_first = queue.claim_ready().expect("first entry becomes visible");
    assert_eq!(claimed_first.sequence(), first.sequence());
    assert_eq!(claimed_first.slot(), first.slot());
    let claimed_second = queue.claim_ready().expect("a second published entry is independent");
    assert_eq!(claimed_second.sequence(), second.sequence());
    assert_eq!(claimed_second.slot(), second.slot());
    assert!(queue.claim_ready().is_none(), "an entered claim cannot be handed out twice");
    assert!(queue.acknowledge(claimed_first).is_ok());
    assert!(queue.acknowledge(claimed_first).is_err(), "claim ACK is one use");
    assert!(queue.acknowledge(claimed_second).is_ok());
    assert!(queue.claim_ready().is_none());
}

#[test]
fn parked_claim_does_not_block_a_second_worker_but_fences_slot_reuse() {
    let queue = HostedWorkQueueAdmission::<2>::new();
    let first = queue.reserve().unwrap();
    let second = queue.reserve().unwrap();
    queue.publish(first).unwrap();
    queue.publish(second).unwrap();

    let first_ready = queue.claim_ready().unwrap();
    let second_ready = queue.claim_ready()
        .expect("a parked callback cannot block an independent worker");
    assert_eq!(second_ready.sequence(), second.sequence());
    queue.acknowledge(second_ready).unwrap();
    assert!(queue.reserve().is_err(),
        "the earlier live callback still fences ring reuse");
    queue.acknowledge(first_ready).unwrap();

    let next = queue.reserve().expect("contiguous ACKs release capacity");
    assert_eq!(next.slot(), first.slot());
    assert!(queue.publish(first).is_err(), "stale reservation cannot publish a reused slot");
    assert!(queue.acknowledge(first_ready).is_err(), "stale claim cannot retire a reused slot");
    queue.publish(next).unwrap();
    queue.acknowledge(queue.claim_ready().unwrap()).unwrap();
}

#[test]
fn another_queue_cannot_publish_or_acknowledge_an_identical_slot_generation() {
    let first = HostedWorkQueueAdmission::<1>::new();
    let other = HostedWorkQueueAdmission::<1>::new();
    let first_reservation = first.reserve().unwrap();
    let other_reservation = other.reserve().unwrap();
    assert_eq!(first_reservation.sequence(), other_reservation.sequence());
    assert_eq!(first_reservation.slot(), other_reservation.slot());
    assert!(other.publish(first_reservation).is_err());
    other.publish(other_reservation).unwrap();
    let other_ready = other.claim_ready().unwrap();
    assert!(first.acknowledge(other_ready).is_err());
    assert!(first.claim_ready().is_none(), "failed foreign ACK preserves ownership");
    first.publish(first_reservation).unwrap();
    first.acknowledge(first.claim_ready().unwrap()).unwrap();
    other.acknowledge(other_ready).unwrap();
}

#[test]
fn peek_does_not_claim_or_skip_a_published_head() {
    let queue = HostedWorkQueueAdmission::<2>::new();
    let first = queue.reserve().unwrap();
    let second = queue.reserve().unwrap();
    queue.publish(second).unwrap();
    assert!(queue.peek_ready().is_none(), "a later published slot cannot bypass the reserved head");
    queue.publish(first).unwrap();
    let pending = queue.peek_ready().expect("published head can be inspected");
    assert_eq!((pending.sequence(), pending.slot()), (first.sequence(), first.slot()));
    assert_eq!(queue.peek_ready(), Some(pending), "inspection cannot consume the head");
    let claimed = queue.claim_ready().unwrap();
    assert_eq!((claimed.sequence(), claimed.slot()), (first.sequence(), first.slot()));
    assert_eq!(queue.peek_ready().unwrap().sequence(), second.sequence());
    queue.acknowledge(claimed).unwrap();
    queue.acknowledge(queue.claim_ready().unwrap()).unwrap();
}
