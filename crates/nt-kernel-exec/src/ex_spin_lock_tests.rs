extern crate std;

use super::*;
use core::sync::atomic::{AtomicU32, Ordering};
use std::vec::Vec;

#[test]
fn shared_owners_count_and_release() {
    let lock = AtomicU32::new(0);
    assert_eq!(try_acquire_shared(&lock), Ok(true));
    assert_eq!(try_acquire_shared(&lock), Ok(true));
    assert_eq!(lock.load(Ordering::Relaxed), 2);
    assert_eq!(release_shared(&lock), Ok(()));
    assert_eq!(release_shared(&lock), Ok(()));
    assert_eq!(lock.load(Ordering::Relaxed), 0);
    assert_eq!(release_shared(&lock), Err(ExSpinLockError::NotShared));
}

#[test]
fn exclusive_claim_blocks_new_shared_owners_until_drained() {
    let lock = AtomicU32::new(0);
    assert_eq!(try_acquire_shared(&lock), Ok(true));
    assert_eq!(try_claim_exclusive(&lock), Ok(true));
    assert_eq!(exclusive_drained(&lock), Ok(false));
    // A claimant stops later readers: writers are not starved by a reader stream.
    assert_eq!(try_acquire_shared(&lock), Ok(false));
    assert_eq!(try_claim_exclusive(&lock), Ok(false));
    // The undrained claimant does not own the lock yet.
    assert_eq!(release_exclusive(&lock), Err(ExSpinLockError::NotExclusive));
    assert_eq!(release_shared(&lock), Ok(()));
    assert_eq!(exclusive_drained(&lock), Ok(true));
    assert_eq!(release_exclusive(&lock), Ok(()));
    assert_eq!(lock.load(Ordering::Relaxed), 0);
    assert_eq!(try_acquire_shared(&lock), Ok(true));
}

#[test]
fn exclusive_release_requires_exclusive_owner() {
    let lock = AtomicU32::new(0);
    assert_eq!(release_exclusive(&lock), Err(ExSpinLockError::NotExclusive));
    assert_eq!(exclusive_drained(&lock), Err(ExSpinLockError::NotExclusive));
    assert_eq!(try_acquire_shared(&lock), Ok(true));
    assert_eq!(release_exclusive(&lock), Err(ExSpinLockError::NotExclusive));
}

#[test]
fn try_exclusive_succeeds_only_on_a_free_lock() {
    let lock = AtomicU32::new(0);
    assert_eq!(try_acquire_exclusive(&lock), Ok(true));
    assert_eq!(try_acquire_exclusive(&lock), Ok(false));
    assert_eq!(try_acquire_shared(&lock), Ok(false));
    assert_eq!(release_exclusive(&lock), Ok(()));
    assert_eq!(try_acquire_shared(&lock), Ok(true));
    assert_eq!(try_acquire_exclusive(&lock), Ok(false));
}

#[test]
fn conversion_requires_sole_shared_owner_and_no_claimant() {
    let lock = AtomicU32::new(0);
    assert_eq!(try_convert_shared_exclusive(&lock), Err(ExSpinLockError::NotShared));
    assert_eq!(try_acquire_shared(&lock), Ok(true));
    assert_eq!(try_acquire_shared(&lock), Ok(true));
    assert_eq!(try_convert_shared_exclusive(&lock), Ok(false));
    assert_eq!(lock.load(Ordering::Relaxed), 2, "a refused conversion keeps shared ownership");
    assert_eq!(release_shared(&lock), Ok(()));
    assert_eq!(try_convert_shared_exclusive(&lock), Ok(true));
    assert_eq!(lock.load(Ordering::Relaxed), EXCLUSIVE);
    assert_eq!(release_exclusive(&lock), Ok(()));

    // A pending exclusive claimant is not displaced by a converting reader.
    assert_eq!(try_acquire_shared(&lock), Ok(true));
    assert_eq!(try_claim_exclusive(&lock), Ok(true));
    assert_eq!(try_convert_shared_exclusive(&lock), Ok(false));
    assert_eq!(release_shared(&lock), Ok(()));
    assert_eq!(exclusive_drained(&lock), Ok(true));
}

#[test]
fn malformed_words_and_overflow_are_refused() {
    let lock = AtomicU32::new(0x4000_0000);
    assert_eq!(try_acquire_shared(&lock), Err(ExSpinLockError::InvalidWord));
    assert_eq!(try_claim_exclusive(&lock), Err(ExSpinLockError::InvalidWord));
    assert_eq!(try_acquire_exclusive(&lock), Err(ExSpinLockError::InvalidWord));
    assert_eq!(release_shared(&lock), Err(ExSpinLockError::InvalidWord));
    assert_eq!(release_exclusive(&lock), Err(ExSpinLockError::InvalidWord));
    let full = AtomicU32::new(SHARED_MASK);
    assert_eq!(try_acquire_shared(&full), Err(ExSpinLockError::SharedCountOverflow));
    assert_eq!(full.load(Ordering::Relaxed), SHARED_MASK);
}

#[test]
fn concurrent_readers_and_writers_exclude_each_other() {
    use std::sync::Arc;
    use std::sync::atomic::AtomicI64;
    let lock = Arc::new(AtomicU32::new(0));
    // Positive: reader count; -1: one writer.
    let occupancy = Arc::new(AtomicI64::new(0));
    let threads: Vec<_> = (0..6).map(|index| {
        let lock = Arc::clone(&lock);
        let occupancy = Arc::clone(&occupancy);
        std::thread::spawn(move || {
            for _ in 0..2_000 {
                if index % 2 == 0 {
                    while !try_claim_exclusive(&lock).unwrap() { std::thread::yield_now(); }
                    while !exclusive_drained(&lock).unwrap() { std::thread::yield_now(); }
                    assert_eq!(occupancy.compare_exchange(0, -1, Ordering::SeqCst, Ordering::SeqCst), Ok(0));
                    occupancy.store(0, Ordering::SeqCst);
                    release_exclusive(&lock).unwrap();
                } else {
                    while !try_acquire_shared(&lock).unwrap() { std::thread::yield_now(); }
                    assert!(occupancy.fetch_add(1, Ordering::SeqCst) >= 0);
                    occupancy.fetch_sub(1, Ordering::SeqCst);
                    release_shared(&lock).unwrap();
                }
            }
        })
    }).collect();
    for thread in threads { thread.join().unwrap(); }
    assert_eq!(lock.load(Ordering::Relaxed), 0);
}
