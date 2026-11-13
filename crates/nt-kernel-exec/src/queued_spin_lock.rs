//! Atomic lock word for the x64 in-stack queued spin-lock ABI.
//!
//! The handle address is the owner token. A second handle cannot acquire the
//! same lock until the first releases it, and a stale or foreign handle cannot
//! release it. The native adapter owns the WDK handle layout and IRQL change.
//! The ReactOS x64 implementation of this ABI also acquires a regular spin
//! lock; it does not link a FIFO waiter queue.

use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueuedSpinError {
    InvalidHandle,
    Reentrant,
    NotOwner,
}

/// Attempt one acquisition without blocking the caller's hosted execution lane.
pub fn try_acquire(lock: &AtomicU64, handle: u64) -> Result<bool, QueuedSpinError> {
    if handle == 0 { return Err(QueuedSpinError::InvalidHandle); }
    match lock.compare_exchange(0, handle, Ordering::Acquire, Ordering::Relaxed) {
        Ok(_) => Ok(true),
        Err(owner) if owner == handle => Err(QueuedSpinError::Reentrant),
        Err(_) => Ok(false),
    }
}

/// Release only the exact handle that acquired this lock word.
pub fn release(lock: &AtomicU64, handle: u64) -> Result<(), QueuedSpinError> {
    if handle == 0 { return Err(QueuedSpinError::InvalidHandle); }
    lock.compare_exchange(handle, 0, Ordering::Release, Ordering::Relaxed)
        .map(|_| ())
        .map_err(|_| QueuedSpinError::NotOwner)
}
