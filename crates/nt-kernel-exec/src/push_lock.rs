//! NT x64 push-lock word policy, following ReactOS ntoskrnl/ex/pushlock.c.
//!
//! These functions have no native effects. Acquisition/release candidates require a successful
//! exact-word CAS before ownership or queue publication is acknowledged. A failed CAS requires
//! a fresh plan; it never authorizes waking, parking, or decrementing a saved share count again.
//! Wake delivery lets a waiter retry acquisition, not assume ownership.

pub const LOCKED: u64 = 1;
pub const WAITING: u64 = 2;
pub const WAKING: u64 = 4;
pub const MULTIPLE_SHARED: u64 = 8;
pub const PTR_BITS: u64 = 15;
pub const SHARE_INC: u64 = 16;
pub const WAITER_EXCLUSIVE: u32 = 1;
pub const WAITER_WAIT: u32 = 2;
pub const WAIT_BLOCK_BYTES: usize = 64;
pub const NEXT_OFFSET: usize = 24;
pub const LAST_OFFSET: usize = 32;
pub const PREVIOUS_OFFSET: usize = 40;
pub const SHARE_COUNT_OFFSET: usize = 48;
pub const FLAGS_OFFSET: usize = 52;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushLockError {
    InvalidWord,
    WaitBlockAlignment,
    SharedCountOverflow,
    NotExclusive,
    NotShared,
    InvalidSharedCount,
    WakeNotOwned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcquireDecision { Acquire { new: u64 }, Queue(QueuePlan) }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueuePlan {
    pub new: u64,
    pub next: u64,
    pub last: u64,
    pub saved_shared: i32,
    pub flags: u32,
    pub needs_optimize: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleasePlan { pub new: u64, pub wake: bool }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeDecision {
    /// The lock was reacquired. CAS clears WAKING, preserving its owner and waiter head.
    Relocked { new: u64 },
    /// While owning WAKING, detach the oldest exclusive node through atomic queue links,
    /// then fetch-and !WAKING. Unlike the other decisions this is NOT an exact-word CAS:
    /// the final fetch-and must preserve any concurrent prepend and barging LOCKED bit.
    /// `new` describes the observed word with WAKING cleared, not an overwrite value.
    DetachOldest { new: u64 },
    /// CAS to zero must succeed before detaching/signaling all waiter nodes.
    DetachAll { new: u64 },
}

fn validate(old: u64) -> Result<(), PushLockError> {
    if old & WAITING != 0 {
        if old & !PTR_BITS == 0 || (old & MULTIPLE_SHARED != 0 && old & LOCKED == 0) {
            return Err(PushLockError::InvalidWord);
        }
    } else if old & (WAKING | MULTIPLE_SHARED) != 0 || (old & LOCKED == 0 && old != 0) {
        return Err(PushLockError::InvalidWord);
    }
    Ok(())
}

pub fn shared_count(old: u64) -> Result<Option<u64>, PushLockError> {
    validate(old)?;
    Ok((old & WAITING == 0).then_some(old >> 4))
}

pub fn waiter_head(old: u64) -> Result<Option<u64>, PushLockError> {
    validate(old)?;
    Ok((old & WAITING != 0).then_some(old & !PTR_BITS))
}

fn queue(old: u64, node: u64, exclusive: bool) -> Result<QueuePlan, PushLockError> {
    if node == 0 || node & PTR_BITS != 0 { return Err(PushLockError::WaitBlockAlignment); }
    let flags = WAITER_WAIT | if exclusive { WAITER_EXCLUSIVE } else { 0 };
    if old & WAITING != 0 {
        Ok(QueuePlan {
            new: node | (old & (LOCKED | MULTIPLE_SHARED)) | WAITING | WAKING,
            next: old & !PTR_BITS, last: 0, saved_shared: 0, flags,
            needs_optimize: old & WAKING == 0,
        })
    } else {
        let shared = old >> 4;
        let saved_shared = if exclusive && shared > 1 {
            i32::try_from(shared).map_err(|_| PushLockError::SharedCountOverflow)?
        } else { 0 };
        Ok(QueuePlan {
            new: node | LOCKED | WAITING | if saved_shared > 0 { MULTIPLE_SHARED } else { 0 },
            next: 0, last: node, saved_shared, flags, needs_optimize: false,
        })
    }
}

pub fn acquire_exclusive(old: u64, node: u64) -> Result<AcquireDecision, PushLockError> {
    validate(old)?;
    if old & LOCKED == 0 {
        Ok(AcquireDecision::Acquire { new: old | LOCKED })
    } else { queue(old, node, true).map(AcquireDecision::Queue) }
}

pub fn acquire_shared(old: u64, node: u64) -> Result<AcquireDecision, PushLockError> {
    validate(old)?;
    if old & LOCKED == 0 || (old & WAITING == 0 && old >> 4 != 0) {
        let new = if old & WAITING == 0 {
            (old | LOCKED).checked_add(SHARE_INC).ok_or(PushLockError::SharedCountOverflow)?
        } else { old | LOCKED };
        Ok(AcquireDecision::Acquire { new })
    } else { queue(old, node, false).map(AcquireDecision::Queue) }
}

fn release_waiting(old: u64) -> ReleasePlan {
    ReleasePlan {
        new: (old & !(LOCKED | MULTIPLE_SHARED)) | WAKING,
        wake: old & WAKING == 0,
    }
}

pub fn release_exclusive(old: u64) -> Result<ReleasePlan, PushLockError> {
    validate(old)?;
    if old & LOCKED == 0 || old & MULTIPLE_SHARED != 0
        || (old & WAITING == 0 && old >> 4 != 0)
    { return Err(PushLockError::NotExclusive); }
    Ok(if old & WAITING != 0 { release_waiting(old) }
        else { ReleasePlan { new: 0, wake: false } })
}

pub fn release_shared_no_waiters(old: u64) -> Result<ReleasePlan, PushLockError> {
    validate(old)?;
    if old & WAITING != 0 || old >> 4 == 0 { return Err(PushLockError::NotShared); }
    Ok(ReleasePlan { new: if old >> 4 == 1 { 0 } else { old - SHARE_INC }, wake: false })
}

/// `remaining_sharecount` is the result of ONE native atomic decrement in the oldest exclusive
/// waiter when MULTIPLE_SHARED is set, or zero otherwise. Once it reaches zero, retry only the
/// word CAS using this function: do not decrement that waiter again after concurrent enqueue.
pub fn release_shared_waiting(old: u64, remaining_sharecount: i32)
    -> Result<Option<ReleasePlan>, PushLockError>
{
    validate(old)?;
    if old & (LOCKED | WAITING) != (LOCKED | WAITING) { return Err(PushLockError::NotShared); }
    if remaining_sharecount < 0 || (old & MULTIPLE_SHARED == 0 && remaining_sharecount != 0) {
        return Err(PushLockError::InvalidSharedCount);
    }
    Ok(if remaining_sharecount > 0 { None } else { Some(release_waiting(old)) })
}

/// A successful CAS to the returned word grants WAKING responsibility exactly once.
pub fn try_wake(old: u64) -> Result<Option<u64>, PushLockError> {
    validate(old)?;
    Ok(if old & WAITING != 0 && old & (LOCKED | WAKING) == 0 { Some(old | WAKING) } else { None })
}

pub fn wake_action(old: u64, oldest_exclusive: bool, has_previous: bool)
    -> Result<WakeDecision, PushLockError>
{
    validate(old)?;
    if old & (WAITING | WAKING) != (WAITING | WAKING) { return Err(PushLockError::WakeNotOwned); }
    Ok(if old & LOCKED != 0 { WakeDecision::Relocked { new: old & !WAKING } }
        else if oldest_exclusive && has_previous { WakeDecision::DetachOldest { new: old & !WAKING } }
        else { WakeDecision::DetachAll { new: 0 } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

    fn queue(decision: AcquireDecision) -> QueuePlan {
        match decision { AcquireDecision::Queue(plan) => plan, _ => panic!("expected queue") }
    }

    #[test]
    fn nt_low_bits_distinguish_shared_count_from_waiter_pointer() {
        assert_eq!((LOCKED, WAITING, WAKING, MULTIPLE_SHARED, SHARE_INC), (1, 2, 4, 8, 16));
        assert_eq!(acquire_exclusive(0, 0), Ok(AcquireDecision::Acquire { new: 1 }));
        assert_eq!(acquire_shared(0, 0), Ok(AcquireDecision::Acquire { new: 17 }));
        assert_eq!(shared_count(49), Ok(Some(3)));
        assert_eq!(shared_count(0x1000 | LOCKED | WAITING), Ok(None));
        assert_eq!(waiter_head(0x1000 | LOCKED | WAITING), Ok(Some(0x1000)));
    }

    #[test]
    fn first_exclusive_waiter_saves_multiple_shared_acquisitions() {
        let plan = queue(acquire_exclusive(49, 0x1000).unwrap());
        assert_eq!(plan, QueuePlan { new: 0x100b, next: 0, last: 0x1000,
            saved_shared: 3, flags: WAITER_EXCLUSIVE | WAITER_WAIT, needs_optimize: false });
        let single = queue(acquire_exclusive(17, 0x1000).unwrap());
        assert_eq!(single.saved_shared, 0);
        assert_eq!(single.new, 0x1003);
    }

    #[test]
    fn enqueue_preserves_representation_and_claims_one_waking_owner() {
        let plan = queue(acquire_exclusive(0x100b, 0x2000).unwrap());
        assert_eq!((plan.new, plan.next, plan.last, plan.saved_shared), (0x200f, 0x1000, 0, 0));
        assert!(plan.needs_optimize);
        let next = queue(acquire_exclusive(plan.new, 0x3000).unwrap());
        assert_eq!(next.new, 0x300f);
        assert!(!next.needs_optimize);
        assert_eq!(try_wake(0x300f), Ok(None));
    }

    #[test]
    fn shared_acquisition_counts_readers_or_queues_behind_exclusive_owner() {
        assert_eq!(acquire_shared(17, 0), Ok(AcquireDecision::Acquire { new: 33 }));
        let plan = queue(acquire_shared(1, 0x1000).unwrap());
        assert_eq!(plan, QueuePlan { new: 0x1003, next: 0, last: 0x1000,
            saved_shared: 0, flags: WAITER_WAIT, needs_optimize: false });
        assert_eq!(acquire_shared(0x1006, 0), Ok(AcquireDecision::Acquire { new: 0x1007 }));
        assert_eq!(release_shared_waiting(0x1007, 0), Ok(Some(ReleasePlan { new: 0x1006, wake: false })));
    }

    #[test]
    fn detach_oldest_fetch_and_keeps_concurrent_prepend_and_barger() {
        let lock = AtomicU64::new(0x2006);
        assert_eq!(wake_action(0x2006, true, true), Ok(WakeDecision::DetachOldest { new: 0x2002 }));
        lock.compare_exchange(0x2006, 0x2007, Ordering::AcqRel, Ordering::Acquire).unwrap();
        let enqueue = queue(acquire_exclusive(0x2007, 0x3000).unwrap());
        lock.compare_exchange(0x2007, enqueue.new, Ordering::AcqRel, Ordering::Acquire).unwrap();
        // Native adapter detaches links before this operation while retaining WAKING ownership.
        assert_eq!(lock.fetch_and(!WAKING, Ordering::AcqRel), 0x3007);
        assert_eq!(lock.load(Ordering::Acquire), 0x3003);
    }

    #[test]
    fn final_shared_release_consumes_saved_count_once_then_owns_wake() {
        assert_eq!(release_shared_waiting(0x100b, 2), Ok(None));
        assert_eq!(release_shared_waiting(0x100b, 1), Ok(None));
        assert_eq!(release_shared_waiting(0x100b, 0), Ok(Some(ReleasePlan { new: 0x1006, wake: true })));
        assert_eq!(release_shared_waiting(0x200f, 0), Ok(Some(ReleasePlan { new: 0x2006, wake: false })));
        assert_eq!(release_shared_waiting(0x1003, 0), Ok(Some(ReleasePlan { new: 0x1006, wake: true })));
        assert!(release_shared_waiting(0x1003, 1).is_err());
    }

    #[test]
    fn shared_without_waiters_releases_count_not_pointer() {
        assert_eq!(release_shared_no_waiters(49), Ok(ReleasePlan { new: 33, wake: false }));
        assert_eq!(release_shared_no_waiters(17), Ok(ReleasePlan { new: 0, wake: false }));
        assert!(release_shared_no_waiters(1).is_err());
        assert!(release_shared_no_waiters(0x1003).is_err());
    }

    #[test]
    fn try_wake_claims_only_unlocked_unowned_waiting_word() {
        assert_eq!(try_wake(0), Ok(None));
        assert_eq!(try_wake(0x1003), Ok(None));
        assert_eq!(try_wake(0x1006), Ok(None));
        assert_eq!(try_wake(0x1002), Ok(Some(0x1006)));
        assert_eq!(wake_action(0x1003, true, false), Err(PushLockError::WakeNotOwned));
    }

    #[test]
    fn concurrent_enqueue_makes_release_cas_fail_without_wake_effect() {
        let lock = AtomicU64::new(0x1003);
        let release = release_exclusive(lock.load(Ordering::Acquire)).unwrap();
        let enqueue = queue(acquire_exclusive(0x1003, 0x2000).unwrap());
        lock.compare_exchange(0x1003, enqueue.new, Ordering::AcqRel, Ordering::Acquire).unwrap();
        assert_eq!(lock.compare_exchange(0x1003, release.new, Ordering::AcqRel, Ordering::Acquire), Err(0x2007));
        let retry = release_exclusive(lock.load(Ordering::Acquire)).unwrap();
        assert_eq!(retry, ReleasePlan { new: 0x2006, wake: false });
        assert_eq!(lock.load(Ordering::Acquire), 0x2007);
    }

    #[test]
    fn wake_is_retry_not_handoff_and_barger_can_own_lock() {
        assert_eq!(wake_action(0x2006, true, true), Ok(WakeDecision::DetachOldest { new: 0x2002 }));
        assert_eq!(wake_action(0x2006, true, false), Ok(WakeDecision::DetachAll { new: 0 }));
        assert_eq!(wake_action(0x2006, false, true), Ok(WakeDecision::DetachAll { new: 0 }));
        assert_eq!(acquire_exclusive(0x2002, 0), Ok(AcquireDecision::Acquire { new: 0x2003 }));
        let retry = acquire_exclusive(0x2003, 0x3000).unwrap();
        assert!(matches!(retry, AcquireDecision::Queue(_)));
        assert_eq!(wake_action(0x2007, true, true), Ok(WakeDecision::Relocked { new: 0x2003 }));
    }

    #[test]
    fn failed_wake_cas_rechecks_barging_and_new_head_without_detach() {
        let lock = AtomicU64::new(0x1006);
        let old_action = wake_action(0x1006, false, true).unwrap();
        assert_eq!(old_action, WakeDecision::DetachAll { new: 0 });
        lock.compare_exchange(0x1006, 0x1007, Ordering::AcqRel, Ordering::Acquire).unwrap();
        let new_head = queue(acquire_exclusive(0x1007, 0x2000).unwrap());
        lock.compare_exchange(0x1007, new_head.new, Ordering::AcqRel, Ordering::Acquire).unwrap();
        assert_eq!(lock.compare_exchange(0x1006, 0, Ordering::AcqRel, Ordering::Acquire), Err(0x2007));
        assert_eq!(wake_action(0x2007, false, true), Ok(WakeDecision::Relocked { new: 0x2003 }));
    }

    #[test]
    fn rejected_and_no_effect_operations_do_not_modify_native_word() {
        let lock = AtomicU64::new(1);
        assert_eq!(acquire_exclusive(1, 0x1001), Err(PushLockError::WaitBlockAlignment));
        assert!(release_exclusive(17).is_err());
        assert!(shared_count(16).is_err());
        assert!(waiter_head(WAITING).is_err());
        assert!(acquire_shared(u64::MAX & !(WAITING | WAKING | MULTIPLE_SHARED), 0).is_err());
        assert_eq!(lock.load(Ordering::Acquire), 1);
        assert_eq!((WAIT_BLOCK_BYTES, NEXT_OFFSET, LAST_OFFSET, PREVIOUS_OFFSET, SHARE_COUNT_OFFSET, FLAGS_OFFSET),
            (64, 24, 32, 40, 48, 52));
    }
}
