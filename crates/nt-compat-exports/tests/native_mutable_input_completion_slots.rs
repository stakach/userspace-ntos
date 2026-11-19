//! METHOD_NEITHER input completion snapshots must never spin on a holder (boot 44460274197).
//!
//! CPU0 spun forever in `complete_hosted_irp_with_owner` (IoCompleteRequest for mouclass's
//! IOCTL_INTERNAL_MOUSE_CONNECT) on a global `AtomicBool` lock whose holder could not run.

#[path = "../../../components/ntos-executive/src/phase_slots.rs"]
mod phase_slots;

use phase_slots::{PhaseSlots, CLAIMING, EMPTY};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

const RESERVED: u64 = 1;
const CAPTURING: u64 = 7;
const CAPTURED: u64 = 2;

/// The old design: one global spin lock taken by every reserve/capture/copy/ack.
fn old_acquire_bounded(lock: &AtomicBool, budget: Duration) -> bool {
    let start = Instant::now();
    while lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        if start.elapsed() > budget {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

#[test]
fn a_global_spin_lock_strands_the_completion_path_behind_a_stalled_holder() {
    // The root holds the lock across reserve()'s allocation and cannot run again (parked, or a
    // lower priority than the spinning completion thread on the same core).
    let lock = AtomicBool::new(true);
    assert!(!old_acquire_bounded(&lock, Duration::from_millis(50)),
        "IoCompleteRequest's capture never acquires the lock");
}

#[test]
fn a_stalled_claimer_never_blocks_another_irps_completion() {
    let slots = Arc::new(PhaseSlots::<4>::new());
    // IRP 7 was reserved and published before provider entry.
    let seven = slots.claim(7).unwrap();
    slots.publish(seven, RESERVED);
    // The root is preempted while claiming a slot for IRP 9 and never publishes it.
    let nine = slots.claim(9).unwrap();
    assert_eq!(slots.phase(nine), CLAIMING);

    let barrier = Arc::new(Barrier::new(2));
    let completion = {
        let (slots, barrier) = (slots.clone(), barrier.clone());
        std::thread::spawn(move || {
            barrier.wait();
            // IoCompleteRequest for IRP 7 captures its own published slot without waiting.
            let (index, phase) = slots.find_published(7).expect("published reservation");
            assert_eq!(phase, RESERVED);
            assert!(slots.transition(index, RESERVED, CAPTURING));
            slots.publish(index, CAPTURED);
            // IRP 9's half-claimed slot is simply unavailable, never waited on.
            assert!(slots.find_published(9).is_none());
            assert!(slots.owned(9));
        })
    };
    barrier.wait();
    let start = Instant::now();
    completion.join().unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(slots.phase(seven), CAPTURED);
}

#[test]
fn phases_are_exclusive_and_keys_unique() {
    let slots = PhaseSlots::<2>::new();
    let a = slots.claim(1).unwrap();
    slots.publish(a, RESERVED);
    assert!(slots.claim(1).is_none(), "one owner per canonical IRP");
    assert!(!slots.transition(a, CAPTURED, EMPTY), "only the current phase moves");
    assert!(slots.transition(a, RESERVED, CAPTURING));
    assert!(!slots.transition(a, RESERVED, CAPTURING), "a second capture loses");
    slots.publish(a, EMPTY);
    assert!(!slots.owned(1));
    let b = slots.claim(2).unwrap();
    let c = slots.claim(3).unwrap();
    assert_ne!(b, c);
    assert!(slots.claim(4).is_none(), "full table refuses, never waits");
}

#[test]
fn the_completion_snapshot_owner_has_no_spin_lock() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_mutable_input_completion.rs");
    assert!(!source.contains("SNAPSHOT_LOCK"));
    assert!(!source.contains("spin_loop"));
    assert!(source.contains("PhaseSlots"));
}

/// A driver's registry write during StartDevice must not fail with STATUS_DEVICE_BUSY because
/// another writer holds SYSTEM. In boot 44416320584, `cm-busy-begin` refusals failed Disk's
/// StartDevice with 0x80000011 and i8042prt's with 0xc0000033.
#[test]
fn cm_busy_begin_is_retried_for_provider_callers_too() {
    let work = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    let branch = work
        .split("attempt.outcome_status() == Some(nt_status::NtStatus::DEVICE_BUSY.raw() as i32)")
        .nth(1)
        .expect("busy BEGIN branch")
        .split("attempts.retry_acknowledged_busy(attempt)?;")
        .next()
        .unwrap();
    assert!(!branch.contains("Caller::Hosted"), "busy retry is not limited to hosted callers");
    assert!(branch.contains("!work.cancelled"));
}
