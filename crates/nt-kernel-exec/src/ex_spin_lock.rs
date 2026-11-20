//! NT x64 `EX_SPIN_LOCK` reader/writer spin-lock word.
//!
//! The 32-bit word holds the exclusive bit (bit 31) and the shared owner count (bits 0..30).
//! An exclusive acquirer first claims bit 31, which immediately stops new shared acquisitions,
//! then waits for the already admitted shared owners to drain. Exclusive ownership is the
//! exact word `EXCLUSIVE`. A shared owner may convert only when it is the sole owner.
//!
//! These functions perform only atomic word operations. The native adapter owns IRQL changes
//! and decides how to wait between attempts; no attempt here blocks or yields.

use core::sync::atomic::{AtomicU32, Ordering};

pub const EXCLUSIVE: u32 = 0x8000_0000;
pub const SHARED_MASK: u32 = 0x3fff_ffff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExSpinLockError {
    /// The word has bits that no valid lock state produces.
    InvalidWord,
    /// Another shared owner would overflow the shared count.
    SharedCountOverflow,
    /// A shared release found no shared owner.
    NotShared,
    /// An exclusive release, or drain poll, found that the caller does not own bit 31.
    NotExclusive,
}

fn validate(value: u32) -> Result<u32, ExSpinLockError> {
    if value & !(EXCLUSIVE | SHARED_MASK) != 0 { Err(ExSpinLockError::InvalidWord) } else { Ok(value) }
}

/// Attempt one shared acquisition. `false` means an exclusive owner or claimant holds bit 31.
pub fn try_acquire_shared(lock: &AtomicU32) -> Result<bool, ExSpinLockError> {
    let mut value = validate(lock.load(Ordering::Relaxed))?;
    loop {
        if value & EXCLUSIVE != 0 { return Ok(false); }
        if value == SHARED_MASK { return Err(ExSpinLockError::SharedCountOverflow); }
        match lock.compare_exchange_weak(value, value + 1, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => return Ok(true),
            Err(observed) => value = validate(observed)?,
        }
    }
}

/// Attempt to claim bit 31. A successful claim blocks new shared owners; the caller now owns the
/// claim and must poll [`exclusive_drained`] until the admitted shared owners have released.
pub fn try_claim_exclusive(lock: &AtomicU32) -> Result<bool, ExSpinLockError> {
    let mut value = validate(lock.load(Ordering::Relaxed))?;
    loop {
        if value & EXCLUSIVE != 0 { return Ok(false); }
        match lock.compare_exchange_weak(value, value | EXCLUSIVE, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => return Ok(true),
            Err(observed) => value = validate(observed)?,
        }
    }
}

/// For the bit-31 claimant only: `true` once no shared owner remains and ownership is exclusive.
pub fn exclusive_drained(lock: &AtomicU32) -> Result<bool, ExSpinLockError> {
    let value = validate(lock.load(Ordering::Acquire))?;
    if value & EXCLUSIVE == 0 { return Err(ExSpinLockError::NotExclusive); }
    Ok(value == EXCLUSIVE)
}

/// `ExTryAcquireSpinLockExclusiveAtDpcLevel`: succeed only on a free lock.
pub fn try_acquire_exclusive(lock: &AtomicU32) -> Result<bool, ExSpinLockError> {
    match lock.compare_exchange(0, EXCLUSIVE, Ordering::Acquire, Ordering::Relaxed) {
        Ok(_) => Ok(true),
        Err(observed) => validate(observed).map(|_| false),
    }
}

/// `ExTryConvertSharedSpinLockExclusive`: the caller's shared ownership becomes exclusive only
/// when it is the sole shared owner and no exclusive claimant exists. On `false` the caller still
/// owns its shared acquisition.
pub fn try_convert_shared_exclusive(lock: &AtomicU32) -> Result<bool, ExSpinLockError> {
    match lock.compare_exchange(1, EXCLUSIVE, Ordering::Acquire, Ordering::Relaxed) {
        Ok(_) => Ok(true),
        Err(observed) => {
            let value = validate(observed)?;
            if value & SHARED_MASK == 0 { Err(ExSpinLockError::NotShared) } else { Ok(false) }
        }
    }
}

/// Release one shared owner. An exclusive claimant waiting for drain keeps bit 31.
pub fn release_shared(lock: &AtomicU32) -> Result<(), ExSpinLockError> {
    let mut value = validate(lock.load(Ordering::Relaxed))?;
    loop {
        if value & SHARED_MASK == 0 { return Err(ExSpinLockError::NotShared); }
        match lock.compare_exchange_weak(value, value - 1, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return Ok(()),
            Err(observed) => value = validate(observed)?,
        }
    }
}

/// Release exclusive ownership. Only the drained exclusive word is owned.
pub fn release_exclusive(lock: &AtomicU32) -> Result<(), ExSpinLockError> {
    match lock.compare_exchange(EXCLUSIVE, 0, Ordering::Release, Ordering::Relaxed) {
        Ok(_) => Ok(()),
        Err(observed) => validate(observed).and(Err(ExSpinLockError::NotExclusive)),
    }
}

#[cfg(test)]
#[path = "ex_spin_lock_tests.rs"]
mod tests;
