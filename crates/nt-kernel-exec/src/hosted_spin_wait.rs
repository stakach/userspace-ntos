//! Spin-style lock words shared by the lanes of a hosted driver domain.
//!
//! A hosted lane is a thread that may block in a root call while it holds a driver spin lock.
//! The root is single-threaded, so another lane that spins for that lock can occupy the root's
//! nested service of the spinner forever while the holder's root call is never answered.
//! A contended acquire therefore never spins across lanes: it publishes WAITERS and returns
//! `Park`, a root-visible wait that is satisfied when the word changes. A release that observes
//! WAITERS must ask the root to wake parked lanes.
//!
//! Word: `owner | HELD | WAITERS`. `owner` is a nonzero 8-aligned lane token (an in-stack queued
//! handle, or the lane's identity) kept for contention diagnostics and exact release.

use core::sync::atomic::{AtomicU64, Ordering};

pub const HELD: u64 = 1;
pub const WAITERS: u64 = 2;
const FLAGS: u64 = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpinError {
    InvalidOwner,
    /// The calling lane already owns this word; NT would deadlock.
    Reentrant,
    NotOwner,
    InvalidWord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Acquire {
    Acquired,
    /// Park until the word differs from `observed`, then retry. `holder` names the owner lane.
    Park { observed: u64, holder: u64 },
}

fn valid_owner(owner: u64) -> Result<(), SpinError> {
    if owner == 0 || owner & FLAGS != 0 { Err(SpinError::InvalidOwner) } else { Ok(()) }
}

/// The owner lane token recorded in a held word.
pub const fn holder(value: u64) -> Option<u64> {
    if value & HELD != 0 { Some(value & !FLAGS) } else { None }
}

/// Attempt the lock once without waiting.
pub fn try_acquire(word: &AtomicU64, owner: u64) -> Result<bool, SpinError> {
    valid_owner(owner)?;
    match word.compare_exchange(0, owner | HELD, Ordering::Acquire, Ordering::Relaxed) {
        Ok(_) => Ok(true),
        Err(value) if holder(value) == Some(owner) => Err(SpinError::Reentrant),
        Err(value) if value & HELD == 0 => Err(SpinError::InvalidWord),
        Err(_) => Ok(false),
    }
}

/// Acquire, or publish WAITERS and return the exact value the root must wait to change.
pub fn acquire(word: &AtomicU64, owner: u64) -> Result<Acquire, SpinError> {
    valid_owner(owner)?;
    loop {
        if try_acquire(word, owner)? { return Ok(Acquire::Acquired); }
        let value = word.load(Ordering::Relaxed);
        let Some(holder) = holder(value) else { continue };
        if holder == owner { return Err(SpinError::Reentrant); }
        if value & WAITERS != 0
            || word.compare_exchange(value, value | WAITERS, Ordering::Relaxed, Ordering::Relaxed).is_ok()
        {
            return Ok(Acquire::Park { observed: value | WAITERS, holder });
        }
    }
}

/// Release by the exact owner. `true` means parked lanes must be woken through the root.
pub fn release(word: &AtomicU64, owner: u64) -> Result<bool, SpinError> {
    valid_owner(owner)?;
    let value = word.load(Ordering::Relaxed);
    if holder(value) != Some(owner) { return Err(SpinError::NotOwner); }
    // Only this owner can clear HELD; a concurrent waiter can only add WAITERS.
    let previous = word.swap(0, Ordering::Release);
    if holder(previous) != Some(owner) { return Err(SpinError::NotOwner); }
    Ok(previous & WAITERS != 0)
}

/// Root readiness for a parked lane: any change of the word lets it retry.
pub const fn wait_satisfied(current: u64, observed: u64) -> bool {
    current != observed
}

#[cfg(test)]
#[path = "hosted_spin_wait_tests.rs"]
mod tests;
