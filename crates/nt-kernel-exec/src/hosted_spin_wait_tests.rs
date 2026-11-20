extern crate std;

use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

const HOLDER: u64 = 0x1000;
const WAITER: u64 = 0x2000;

/// The root services one lane at a time. The holder lane is blocked in a root call (for example
/// IoCompleteRequest while it holds the class device's spin lock); before answering it the root
/// is servicing a nested provider callback on the waiter lane, which acquires the same lock.
/// The waiter must hand the root back without spinning, so the root can answer the holder.
#[test]
fn waiter_parks_so_the_root_can_finish_the_holder_lanes_blocked_call() {
    let word = AtomicU64::new(0);
    assert_eq!(acquire(&word, HOLDER), Ok(Acquire::Acquired));
    let mut holder_call_answered = false;

    // Nested service of the waiter lane: it must return to the root.
    let observed = match acquire(&word, WAITER) {
        Ok(Acquire::Park { observed, holder }) => {
            assert_eq!(holder, HOLDER, "contention names the holder lane");
            observed
        }
        other => panic!("waiter did not park while the holder is blocked in a root call: {other:?}"),
    };
    assert!(!wait_satisfied(word.load(Ordering::Acquire), observed));

    // The root unwinds the waiter's wait and answers the holder's pending call.
    holder_call_answered = !holder_call_answered;
    assert!(holder_call_answered);
    // The holder releases; WAITERS tells it to ask the root to wake the parked lane.
    assert_eq!(release(&word, HOLDER), Ok(true));
    assert!(wait_satisfied(word.load(Ordering::Acquire), observed));
    // The woken waiter retries and acquires.
    assert_eq!(acquire(&word, WAITER), Ok(Acquire::Acquired));
    assert_eq!(holder(word.load(Ordering::Relaxed)), Some(WAITER));
    assert_eq!(release(&word, WAITER), Ok(false), "no parked lane remains");
}

#[test]
fn a_change_of_holder_also_satisfies_a_parked_wait() {
    let word = AtomicU64::new(0);
    acquire(&word, HOLDER).unwrap();
    let Ok(Acquire::Park { observed, .. }) = acquire(&word, WAITER) else { panic!() };
    // Another lane takes the lock before the waiter is resumed; the waiter retries and re-parks
    // on the new holder instead of waiting for a value that will never return.
    assert_eq!(release(&word, HOLDER), Ok(true));
    assert_eq!(acquire(&word, 0x3000), Ok(Acquire::Acquired));
    assert!(wait_satisfied(word.load(Ordering::Relaxed), observed));
    assert!(matches!(acquire(&word, WAITER), Ok(Acquire::Park { holder: 0x3000, .. })));
    assert_eq!(release(&word, 0x3000), Ok(true));
}

#[test]
fn exact_ownership_reentrancy_and_owner_tokens_are_enforced() {
    let word = AtomicU64::new(0);
    assert_eq!(acquire(&word, 0), Err(SpinError::InvalidOwner));
    assert_eq!(acquire(&word, HOLDER | 1), Err(SpinError::InvalidOwner));
    acquire(&word, HOLDER).unwrap();
    assert_eq!(acquire(&word, HOLDER), Err(SpinError::Reentrant));
    assert_eq!(try_acquire(&word, HOLDER), Err(SpinError::Reentrant));
    assert_eq!(release(&word, WAITER), Err(SpinError::NotOwner));
    assert_eq!(try_acquire(&word, WAITER), Ok(false));
    assert_eq!(release(&word, HOLDER), Ok(false));
    assert_eq!(release(&word, HOLDER), Err(SpinError::NotOwner));
    let stray = AtomicU64::new(WAITERS);
    assert_eq!(try_acquire(&stray, HOLDER), Err(SpinError::InvalidWord));
}

#[test]
fn concurrent_lanes_exclude_each_other_without_spinning_on_a_held_word() {
    use std::sync::{Arc, Condvar, Mutex};
    let word = Arc::new(AtomicU64::new(0));
    let inside = Arc::new(AtomicU64::new(0));
    // A root-side wait/wake model: parked lanes block on a condvar until a release wakes them.
    let gate = Arc::new((Mutex::new(0u64), Condvar::new()));
    let lanes: std::vec::Vec<_> = (1..=4u64).map(|lane| {
        let (word, inside, gate) = (word.clone(), inside.clone(), gate.clone());
        std::thread::spawn(move || {
            let owner = lane << 12;
            for _ in 0..500 {
                loop {
                    match acquire(&word, owner).unwrap() {
                        Acquire::Acquired => break,
                        Acquire::Park { observed, .. } => {
                            let (lock, wake) = &*gate;
                            let mut generation = lock.lock().unwrap();
                            while !wait_satisfied(word.load(Ordering::Acquire), observed) {
                                generation = wake.wait(generation).unwrap();
                            }
                        }
                    }
                }
                assert_eq!(inside.fetch_add(1, Ordering::SeqCst), 0);
                inside.fetch_sub(1, Ordering::SeqCst);
                if release(&word, owner).unwrap() {
                    let (lock, wake) = &*gate;
                    *lock.lock().unwrap() += 1;
                    wake.notify_all();
                }
            }
        })
    }).collect();
    for lane in lanes { lane.join().unwrap(); }
    assert_eq!(word.load(Ordering::Relaxed), 0);
}

// Boots 44717077667, 44735317922 and 44748352997 boot 1 (#423): mouclass's ClassRead lane held
// DeviceExtension->SpinLock and was stopped in its IoCompleteRequest root call. Inside that call
// the root drained i8042's DPC, whose ClassCallback found the lock held. A DPC lane cannot park
// (it has no provider wait owner), so it spun and yielded, and the root never answered the
// holder. A per-domain IRQL byte did not catch it (74aae474): other lanes rewrite that byte.
// The domain is one processor: its DPC may not start while any of its spin locks is held.
#[test]
fn a_dpc_never_starts_while_a_stopped_lane_of_its_domain_holds_a_spin_lock() {
    const CLASS_READ: u64 = 0x1000_f000_000;
    const DPC_LANE: u64 = 0x1001_1000_000;
    let held = AtomicU64::new(0);
    let device_lock = AtomicU64::new(0);
    // ClassRead takes the lock, then calls the root (IoCompleteRequest) and stops there.
    assert_eq!(acquire(&device_lock, CLASS_READ), Ok(Acquire::Acquired));
    note_acquired(&held);
    // While it is stopped, the root's DPC pass may not start the domain's DPC.
    assert!(!dpc_may_start(held.load(Ordering::Acquire)));
    // Had it started, the DPC's ClassCallback could only wait on a holder that cannot run.
    assert!(matches!(acquire(&device_lock, DPC_LANE),
        Ok(Acquire::Park { holder: CLASS_READ, .. })));
    // The root answers IoCompleteRequest; ClassRead releases.
    assert!(release(&device_lock, CLASS_READ).unwrap(), "the would-be waiter was published");
    note_released(&held).unwrap();
    // The next DPC pass starts the queued DPC, and ClassCallback takes the lock.
    assert!(dpc_may_start(held.load(Ordering::Acquire)));
    assert_eq!(acquire(&device_lock, DPC_LANE), Ok(Acquire::Acquired));
}

#[test]
fn an_unbalanced_release_cannot_wrap_the_domain_count() {
    let held = AtomicU64::new(0);
    assert_eq!(note_released(&held), Err(SpinError::NotOwner));
    assert!(dpc_may_start(held.load(Ordering::Acquire)), "the count stays at zero");
    note_acquired(&held);
    note_acquired(&held);
    note_released(&held).unwrap();
    assert!(!dpc_may_start(held.load(Ordering::Acquire)), "one of two locks is still held");
}
