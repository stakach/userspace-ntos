//! Atomic KSPIN_LOCK state shared by all generic hosted driver acquire/release forms.

use super::*;

fn word(lock: u64) -> &'static AtomicU64 {
    if lock == 0 || lock & (core::mem::align_of::<AtomicU64>() as u64 - 1) != 0 {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x5350_494e, lock, 0, 0]); }
    }
    unsafe { &*(lock as *const AtomicU64) }
}

pub(super) extern "win64" fn initialize(lock: u64) {
    word(lock).store(0, Ordering::Release);
}

fn try_acquire(lock: u64) -> bool {
    word(lock).compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
}

fn acquire(lock: u64) {
    while !try_acquire(lock) {
        core::hint::spin_loop();
        // A single hosted logical CPU may need to schedule the current owner before the
        // lock can become free. Yield without clearing this caller's DISPATCH_LEVEL state.
        crate::yield_now();
    }
}

fn release(lock: u64) {
    if word(lock).compare_exchange(1, 0, Ordering::Release, Ordering::Relaxed).is_err() {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x5350_494e, lock, 1, 0]); }
    }
}

/// `KIRQL KeAcquireSpinLockRaiseToDpc(PKSPIN_LOCK)`.
pub(super) extern "win64" fn acquire_raise_to_dpc(lock: u64) -> u8 {
    let old = unsafe { hosted_raise_irql(DISPATCH_LEVEL) };
    acquire(lock);
    old
}

/// `VOID KeReleaseSpinLock(PKSPIN_LOCK, KIRQL)`.
pub(super) extern "win64" fn release_restore_irql(lock: u64, old_irql: u8) {
    release(lock);
    unsafe { hosted_lower_irql(old_irql); }
}

/// `VOID KeAcquireSpinLockAtDpcLevel(PKSPIN_LOCK)`.
pub(super) extern "win64" fn acquire_at_dpc(lock: u64) {
    let irql = unsafe { hosted_current_irql() };
    if irql < DISPATCH_LEVEL {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x5350_494e, lock, irql as u64, 2]); }
    }
    acquire(lock);
}

/// `VOID KeReleaseSpinLockFromDpcLevel(PKSPIN_LOCK)`.
pub(super) extern "win64" fn release_from_dpc(lock: u64) {
    let irql = unsafe { hosted_current_irql() };
    if irql < DISPATCH_LEVEL {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x5350_494e, lock, irql as u64, 3]); }
    }
    release(lock);
}

/// `BOOLEAN KeTryToAcquireSpinLockAtDpcLevel(PKSPIN_LOCK)`.
pub(super) extern "win64" fn try_acquire_at_dpc(lock: u64) -> u8 {
    let irql = unsafe { hosted_current_irql() };
    if irql < DISPATCH_LEVEL {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x5350_494e, lock, irql as u64, 4]); }
    }
    u8::from(try_acquire(lock))
}
