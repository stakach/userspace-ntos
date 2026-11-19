//! NT rundown reference semantics used by the pinned LiberNT win32k.sys imports.

use nt_kernel_exec::{ExRundownRef, ExRundownWaitBlock, ExRundownRelease};

#[test]
fn rundown_wait_closes_admission_and_drains_existing_holders() {
    let reference = ExRundownRef::new();
    assert!(reference.acquire());
    assert!(reference.acquire());

    let waiter = ExRundownWaitBlock::new();
    assert!(unsafe { reference.begin_wait(&waiter) });
    assert!(!reference.acquire(), "no new reference may enter after wait starts");
    assert_eq!(waiter.remaining(), 2);

    assert_eq!(unsafe { reference.release() }, ExRundownRelease::Pending);
    assert_eq!(waiter.remaining(), 1);
    assert_eq!(unsafe { reference.release() }, ExRundownRelease::WakeWaiter);
    assert_eq!(waiter.remaining(), 0);
    unsafe { reference.finish_wait(&waiter) };
    assert!(!reference.acquire(), "completed rundown remains closed");
}

#[test]
fn empty_wait_and_reinitialize_follow_nt_descriptor_lifecycle() {
    let reference = ExRundownRef::new();
    let waiter = ExRundownWaitBlock::new();
    assert!(!unsafe { reference.begin_wait(&waiter) });
    assert!(!unsafe { reference.begin_wait(&waiter) });
    assert!(!reference.acquire());
    assert!(reference.reinitialize());
    assert!(reference.acquire());
    assert_eq!(unsafe { reference.release() }, ExRundownRelease::Released);
    assert!(reference.acquire());
    assert_eq!(unsafe { reference.release() }, ExRundownRelease::Released);
    unsafe { reference.initialize() };
    assert!(reference.acquire());
}

/// #394: the rundown wait sleeps through the caller domain's own delay (a timed wait root
/// can schedule) between observations, never an untimed yield. Each delay lets a holder run.
#[test]
fn rundown_wait_sleeps_through_the_caller_delay_until_holders_release() {
    let reference = ExRundownRef::new();
    for _ in 0..3 { assert!(reference.acquire()); }
    let mut delays = 0;
    reference.wait_for_release_with(|| {
        delays += 1;
        assert!(!reference.acquire(), "admission stays closed while the wait sleeps");
        let _ = unsafe { reference.release() };
    });
    assert_eq!(delays, 3, "one delay per observation with a holder outstanding");
    assert!(reference.is_completed());
    assert!(!reference.acquire());
}

#[test]
fn rundown_wait_with_no_holder_completes_without_a_delay() {
    let reference = ExRundownRef::new();
    let mut delays = 0;
    reference.wait_for_release_with(|| delays += 1);
    assert_eq!(delays, 0);
    assert!(reference.is_completed());
}
