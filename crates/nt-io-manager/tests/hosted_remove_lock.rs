//! A driver remove lock retains each admitted I/O until removal drains it.

use nt_io_manager::remove_lock::{valid_remove_lock_size, Acquire, RemoveLockState};

#[test]
fn admitted_io_drains_before_remove_completes() {
    let lock = RemoveLockState::new();
    assert_eq!(lock.acquire(), Acquire::Acquired);
    assert_eq!(lock.acquire(), Acquire::Acquired);
    assert_eq!(lock.acquire(), Acquire::Acquired); // the removing IRP owns one reference
    assert!(!lock.begin_remove_and_wait(), "two admitted I/O owners remain");
    assert!(matches!(lock.acquire(), Acquire::DeletePending { .. }));
    assert!(!lock.release(), "one admitted I/O owner remains");
    assert!(lock.release(), "last release must wake remove waiter");
    assert!(matches!(lock.acquire(), Acquire::DeletePending { .. }));
}

#[test]
fn remove_without_outstanding_io_completes_immediately() {
    let lock = RemoveLockState::new();
    assert_eq!(lock.acquire(), Acquire::Acquired); // the removing IRP
    assert!(lock.begin_remove_and_wait());
    assert!(matches!(lock.acquire(), Acquire::DeletePending { .. }));
}

#[test]
fn descriptor_size_is_exact_for_free_and_checked_x64_abi() {
    assert!(valid_remove_lock_size(32));
    assert!(valid_remove_lock_size(120));
    for size in [0, 8, 31, 33, 119, 121] {
        assert!(!valid_remove_lock_size(size));
    }
}

#[test]
fn double_release_is_rejected() {
    let lock = RemoveLockState::new();
    assert_eq!(lock.acquire(), Acquire::Acquired);
    assert!(lock.begin_remove_and_wait());
    assert!(std::panic::catch_unwind(|| lock.release()).is_err());
}

#[test]
fn concurrent_acquire_and_removal_always_account_for_last_reference() {
    use std::sync::{Arc, Barrier};

    for _ in 0..128 {
        let lock = Arc::new(RemoveLockState::new());
        assert_eq!(lock.acquire(), Acquire::Acquired); // removing IRP
        let barrier = Arc::new(Barrier::new(2));
        let raced_lock = Arc::clone(&lock);
        let raced_barrier = Arc::clone(&barrier);
        let racer = std::thread::spawn(move || {
            raced_barrier.wait();
            match raced_lock.acquire() {
                Acquire::Acquired => raced_lock.release(),
                Acquire::DeletePending { wake_remove_waiter } => wake_remove_waiter,
            }
        });
        barrier.wait();
        let drained_now = lock.begin_remove_and_wait();
        let final_wake = racer.join().expect("racer completed");
        assert!(drained_now || final_wake, "outstanding acquisition did not wake removal");
        assert!(matches!(lock.acquire(), Acquire::DeletePending { .. }));
    }
}
