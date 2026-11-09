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
    assert!(queue.claim_ready().is_none(), "an entered claim cannot be handed out twice");
    assert!(queue.acknowledge(claimed_first).is_ok());
    assert!(queue.acknowledge(claimed_first).is_err(), "claim ACK is one use");

    let claimed_second = queue.claim_ready().expect("second entry follows first");
    assert_eq!(claimed_second.sequence(), second.sequence());
    assert_eq!(claimed_second.slot(), second.slot());
    assert!(queue.acknowledge(claimed_second).is_ok());
    assert!(queue.claim_ready().is_none());
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
