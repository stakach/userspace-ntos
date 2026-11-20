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

fn fault(lock: u64, detail: u64) -> ! {
    unsafe { crate::provider_bugcheck::report(0xc4, [0x5350_494e, lock, detail, 5]); }
}

fn try_acquire(lock: u64) -> bool {
    nt_kernel_exec::hosted_spin_wait::try_acquire(word(lock), hosted_driver_spin_wait::lane_token())
        .unwrap_or_else(|error| fault(lock, error as u64))
}

/// Acquire for the calling lane. Contention parks in the root rather than spinning, because the
/// holder may be another lane blocked in a root call (see `hosted_driver_spin_wait`).
pub(super) fn acquire_word(lock: u64) {
    hosted_driver_spin_wait::acquire(word(lock), lock, hosted_driver_spin_wait::lane_token())
        .unwrap_or_else(|error| fault(lock, error as u64));
}

/// NT KeReleaseSpinLock does not identify the releasing thread; only a held word is released.
pub(super) fn release_word(lock: u64) {
    let previous = word(lock).swap(0, Ordering::Release);
    if previous & nt_kernel_exec::hosted_spin_wait::HELD == 0 {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x5350_494e, lock, 1, 0]); }
    }
    if previous & nt_kernel_exec::hosted_spin_wait::WAITERS != 0 {
        hosted_driver_spin_wait::wake(lock);
    }
}

/// `KIRQL KeAcquireSpinLockRaiseToDpc(PKSPIN_LOCK)`.
pub(super) extern "win64" fn acquire_raise_to_dpc(lock: u64) -> u8 {
    let old = unsafe { hosted_raise_irql(DISPATCH_LEVEL) };
    acquire_word(lock);
    old
}

/// `VOID KeReleaseSpinLock(PKSPIN_LOCK, KIRQL)`.
pub(super) extern "win64" fn release_restore_irql(lock: u64, old_irql: u8) {
    release_word(lock);
    unsafe { hosted_lower_irql(old_irql); }
}

/// `VOID KeAcquireSpinLockAtDpcLevel(PKSPIN_LOCK)`.
pub(super) extern "win64" fn acquire_at_dpc(lock: u64) {
    let irql = unsafe { hosted_current_irql() };
    if irql < DISPATCH_LEVEL {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x5350_494e, lock, irql as u64, 2]); }
    }
    acquire_word(lock);
}

/// `VOID KeReleaseSpinLockFromDpcLevel(PKSPIN_LOCK)`.
pub(super) extern "win64" fn release_from_dpc(lock: u64) {
    let irql = unsafe { hosted_current_irql() };
    if irql < DISPATCH_LEVEL {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x5350_494e, lock, irql as u64, 3]); }
    }
    release_word(lock);
}

/// `BOOLEAN KeTryToAcquireSpinLockAtDpcLevel(PKSPIN_LOCK)`.
pub(super) extern "win64" fn try_acquire_at_dpc(lock: u64) -> u8 {
    let irql = unsafe { hosted_current_irql() };
    if irql < DISPATCH_LEVEL {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x5350_494e, lock, irql as u64, 4]); }
    }
    u8::from(try_acquire(lock))
}
