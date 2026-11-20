//! NT x64 `EX_SPIN_LOCK` reader/writer spin-lock word.
//!
//! The 32-bit word holds the exclusive bit (bit 31), a WAITERS bit (bit 30) and the shared owner
//! count (bits 0..29). An exclusive acquirer first claims bit 31, which immediately stops new
//! shared acquisitions, then waits for the already admitted shared owners to drain. A shared owner
//! may convert only when it is the sole owner.
//!
//! Hosted driver lanes never spin across lanes (see `hosted_spin_wait`): a lane that cannot make
//! progress marks WAITERS on the exact word it observed and parks in the root until the word
//! changes. Every release that clears WAITERS reports that parked lanes must be woken.
//!
//! These functions perform only atomic word operations; none blocks or yields.

use core::sync::atomic::{AtomicU32, Ordering};

pub const EXCLUSIVE: u32 = 0x8000_0000;
pub const WAITERS: u32 = 0x4000_0000;
pub const SHARED_MASK: u32 = 0x3fff_ffff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExSpinLockError {
    /// Another shared owner would overflow the shared count.
    SharedCountOverflow,
    /// A shared release found no shared owner.
    NotShared,
    /// An exclusive release, or drain poll, found that the caller does not own bit 31.
    NotExclusive,
}

/// Attempt one shared acquisition. `false` means an exclusive owner or claimant holds bit 31.
pub fn try_acquire_shared(lock: &AtomicU32) -> Result<bool, ExSpinLockError> {
    let mut value = lock.load(Ordering::Relaxed);
    loop {
        if value & EXCLUSIVE != 0 { return Ok(false); }
        if value & SHARED_MASK == SHARED_MASK { return Err(ExSpinLockError::SharedCountOverflow); }
        match lock.compare_exchange_weak(value, value + 1, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => return Ok(true),
            Err(observed) => value = observed,
        }
    }
}

/// Attempt to claim bit 31. A successful claim blocks new shared owners; the caller now owns the
/// claim and must wait for [`exclusive_drained`] until the admitted shared owners have released.
pub fn try_claim_exclusive(lock: &AtomicU32) -> Result<bool, ExSpinLockError> {
    let mut value = lock.load(Ordering::Relaxed);
    loop {
        if value & EXCLUSIVE != 0 { return Ok(false); }
        match lock.compare_exchange_weak(value, value | EXCLUSIVE, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => return Ok(true),
            Err(observed) => value = observed,
        }
    }
}

/// For the bit-31 claimant only: `true` once no shared owner remains and ownership is exclusive.
pub fn exclusive_drained(lock: &AtomicU32) -> Result<bool, ExSpinLockError> {
    let value = lock.load(Ordering::Acquire);
    if value & EXCLUSIVE == 0 { return Err(ExSpinLockError::NotExclusive); }
    Ok(value & SHARED_MASK == 0)
}

/// `ExTryAcquireSpinLockExclusiveAtDpcLevel`: succeed only on a free lock.
pub fn try_acquire_exclusive(lock: &AtomicU32) -> Result<bool, ExSpinLockError> {
    let mut value = lock.load(Ordering::Relaxed);
    loop {
        if value & !WAITERS != 0 { return Ok(false); }
        match lock.compare_exchange_weak(value, value | EXCLUSIVE, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => return Ok(true),
            Err(observed) => value = observed,
        }
    }
}

/// `ExTryConvertSharedSpinLockExclusive`: the caller's shared ownership becomes exclusive only
/// when it is the sole shared owner and no exclusive claimant exists. On `false` the caller still
/// owns its shared acquisition.
pub fn try_convert_shared_exclusive(lock: &AtomicU32) -> Result<bool, ExSpinLockError> {
    let mut value = lock.load(Ordering::Relaxed);
    loop {
        if value & SHARED_MASK == 0 { return Err(ExSpinLockError::NotShared); }
        if value & !WAITERS != 1 { return Ok(false); }
        match lock.compare_exchange_weak(value, (value & WAITERS) | EXCLUSIVE, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => return Ok(true),
            Err(observed) => value = observed,
        }
    }
}

/// Publish WAITERS on the exact word a blocked lane observed. `Some(value)` is the word the root
/// waits to change; `None` means it already changed and the caller retries at once.
pub fn mark_waiting(lock: &AtomicU32, observed: u32) -> Result<Option<u32>, ExSpinLockError> {
    if observed & WAITERS != 0 { return Ok((lock.load(Ordering::Relaxed) == observed).then_some(observed)); }
    Ok(lock.compare_exchange(observed, observed | WAITERS, Ordering::Relaxed, Ordering::Relaxed)
        .ok().map(|_| observed | WAITERS))
}

/// Release one shared owner. `true` means parked lanes must be woken.
pub fn release_shared(lock: &AtomicU32) -> Result<bool, ExSpinLockError> {
    let mut value = lock.load(Ordering::Relaxed);
    loop {
        if value & SHARED_MASK == 0 { return Err(ExSpinLockError::NotShared); }
        match lock.compare_exchange_weak(value, (value - 1) & !WAITERS, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return Ok(value & WAITERS != 0),
            Err(observed) => value = observed,
        }
    }
}

/// Release exclusive ownership. Only the drained exclusive word is owned. `true` means parked
/// lanes must be woken.
pub fn release_exclusive(lock: &AtomicU32) -> Result<bool, ExSpinLockError> {
    let mut value = lock.load(Ordering::Relaxed);
    loop {
        if value & !WAITERS != EXCLUSIVE { return Err(ExSpinLockError::NotExclusive); }
        match lock.compare_exchange_weak(value, 0, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return Ok(value & WAITERS != 0),
            Err(observed) => value = observed,
        }
    }
}

#[cfg(test)]
#[path = "ex_spin_lock_tests.rs"]
mod tests;
