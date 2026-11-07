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
