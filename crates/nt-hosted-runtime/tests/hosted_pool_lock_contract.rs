use core::sync::atomic::{AtomicU64, Ordering};
use nt_hosted_runtime::{
    release_hosted_pool_lock, try_acquire_hosted_pool_lock, HostedPoolLockHolder,
    HOSTED_POOL_LOCK_FREE,
};

const HOLDER_STACK: u64 = 0x1000_f01f_240;

/// One unit of root work that needs the component's pool metadata, retained across a refusal
/// together with the exact pool identity and the work's owner.
struct RetainedPoolWork {
    pool_generation: u64,
    owner: u64,
    completions: u64,
}

impl RetainedPoolWork {
    /// A busy pool returns without waiting. The work stays owned by this record.
    fn attempt(&mut self, lock: &AtomicU64, pool_generation: u64) -> bool {
        assert_eq!(pool_generation, self.pool_generation, "retained work names one exact pool");
        if try_acquire_hosted_pool_lock(lock, HostedPoolLockHolder::Root).is_err() {
            return false;
        }
        self.completions += 1;
        release_hosted_pool_lock(lock, HostedPoolLockHolder::Root).unwrap();
        true
    }
}

#[test]
fn root_refuses_a_suspended_component_holder_and_completes_once_after_it_runs() {
    let lock = AtomicU64::new(HOSTED_POOL_LOCK_FREE);
    let holder = HostedPoolLockHolder::Component { stack_pointer: HOLDER_STACK };
    try_acquire_hosted_pool_lock(&lock, holder).unwrap();
    let held = lock.load(Ordering::Relaxed);

    // The holder is suspended (or execution-held, or preempted below root's priority): it cannot
    // run until root returns. Every root attempt is one bounded refusal naming the holder.
    let mut work = RetainedPoolWork { pool_generation: 7, owner: 0x44, completions: 0 };
    for _ in 0..1024 {
        assert!(!work.attempt(&lock, 7));
        assert_eq!(try_acquire_hosted_pool_lock(&lock, HostedPoolLockHolder::Root), Err(holder));
    }
    assert_eq!(lock.load(Ordering::Relaxed), held, "a refusal has no effect on the lock word");
    assert_eq!((work.owner, work.completions), (0x44, 0), "ownership is retained, nothing ran");

    // Root returned to its loop; the holder ran and released its own hold.
    release_hosted_pool_lock(&lock, holder).unwrap();
    assert!(work.attempt(&lock, 7));
    assert_eq!(work.completions, 1);
    assert_eq!(lock.load(Ordering::Relaxed), HOSTED_POOL_LOCK_FREE);
}

#[test]
fn the_lock_word_names_its_holder_side_and_thread() {
    let lock = AtomicU64::new(HOSTED_POOL_LOCK_FREE);
    assert_eq!(HostedPoolLockHolder::decode(lock.load(Ordering::Relaxed)), None);

    try_acquire_hosted_pool_lock(&lock, HostedPoolLockHolder::Root).unwrap();
    assert_eq!(HostedPoolLockHolder::decode(lock.load(Ordering::Relaxed)),
        Some(HostedPoolLockHolder::Root));
    let component = HostedPoolLockHolder::Component { stack_pointer: HOLDER_STACK };
    assert_eq!(try_acquire_hosted_pool_lock(&lock, component), Err(HostedPoolLockHolder::Root));
    release_hosted_pool_lock(&lock, HostedPoolLockHolder::Root).unwrap();

    try_acquire_hosted_pool_lock(&lock, component).unwrap();
    assert_eq!(HostedPoolLockHolder::decode(lock.load(Ordering::Relaxed)), Some(component));

    // A zero stack is still a held word; an untagged legacy word is held by an unknown side.
    let zero_stack = HostedPoolLockHolder::Component { stack_pointer: 0 };
    assert_ne!(zero_stack.word(), HOSTED_POOL_LOCK_FREE);
    assert_eq!(HostedPoolLockHolder::decode(1), Some(HostedPoolLockHolder::Unknown(1)));
}

#[test]
fn a_release_only_clears_the_releasers_own_hold() {
    let lock = AtomicU64::new(HOSTED_POOL_LOCK_FREE);
    let component = HostedPoolLockHolder::Component { stack_pointer: HOLDER_STACK };
    try_acquire_hosted_pool_lock(&lock, component).unwrap();
    assert_eq!(release_hosted_pool_lock(&lock, HostedPoolLockHolder::Root), Err(Some(component)));
    let other = HostedPoolLockHolder::Component { stack_pointer: HOLDER_STACK + 0x1000 };
    assert_eq!(release_hosted_pool_lock(&lock, other), Err(Some(component)));
    assert_eq!(HostedPoolLockHolder::decode(lock.load(Ordering::Relaxed)), Some(component));
    release_hosted_pool_lock(&lock, component).unwrap();
    assert_eq!(release_hosted_pool_lock(&lock, component), Err(None));
}
