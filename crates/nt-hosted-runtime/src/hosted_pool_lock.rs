//! Holder-tagged admission for the pool lock word that the root executor and a hosted
//! component's threads share in the component's pool page.
//!
//! Every hosted thread runs on root's processor below root's priority, and root can hold a
//! component thread's execution. A component holder observed by root therefore cannot run until
//! root returns, so root attempts exactly once and treats `Err(holder)` as a no-effects refusal.
//! The word names its holder so a refusal can say who owns the pool.

use core::sync::atomic::{AtomicU64, Ordering};

pub const HOSTED_POOL_LOCK_FREE: u64 = 0;

const ROOT_WORD: u64 = 1 << 63;
const COMPONENT_TAG: u64 = 1 << 62;
const STACK_MASK: u64 = COMPONENT_TAG - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedPoolLockHolder {
    Root,
    /// A component thread, named by its stack pointer at acquisition.
    Component { stack_pointer: u64 },
    /// A held word written by neither tagged side.
    Unknown(u64),
}

impl HostedPoolLockHolder {
    pub const fn word(self) -> u64 {
        match self {
            Self::Root => ROOT_WORD,
            Self::Component { stack_pointer } => COMPONENT_TAG | (stack_pointer & STACK_MASK),
            Self::Unknown(word) => word,
        }
    }

    pub const fn decode(word: u64) -> Option<Self> {
        if word == HOSTED_POOL_LOCK_FREE {
            None
        } else if word == ROOT_WORD {
            Some(Self::Root)
        } else if word & (ROOT_WORD | COMPONENT_TAG) == COMPONENT_TAG {
            Some(Self::Component { stack_pointer: word & STACK_MASK })
        } else {
            Some(Self::Unknown(word))
        }
    }
}

/// One strong attempt. `Err` names the current holder and leaves the word unchanged.
pub fn try_acquire_hosted_pool_lock(
    lock: &AtomicU64,
    holder: HostedPoolLockHolder,
) -> Result<(), HostedPoolLockHolder> {
    lock.compare_exchange(HOSTED_POOL_LOCK_FREE, holder.word(), Ordering::Acquire, Ordering::Relaxed)
        .map(|_| ())
        .map_err(|word| HostedPoolLockHolder::decode(word).unwrap_or(HostedPoolLockHolder::Unknown(word)))
}

/// Clears only `holder`'s own hold. `Err` reports the actual holder (`None` when already free).
pub fn release_hosted_pool_lock(
    lock: &AtomicU64,
    holder: HostedPoolLockHolder,
) -> Result<(), Option<HostedPoolLockHolder>> {
    lock.compare_exchange(holder.word(), HOSTED_POOL_LOCK_FREE, Ordering::Release, Ordering::Relaxed)
        .map(|_| ())
        .map_err(HostedPoolLockHolder::decode)
}
