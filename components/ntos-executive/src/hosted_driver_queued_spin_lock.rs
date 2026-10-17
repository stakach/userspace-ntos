//! Driver-local queued spin locks with exact in-stack handle ownership.

use super::*;
use core::sync::atomic::AtomicU64;

const LOCK_HANDLE_NEXT_OFF: u64 = 0;
const LOCK_HANDLE_LOCK_OFF: u64 = 8;
const LOCK_HANDLE_OLD_IRQL_OFF: u64 = 16;
const LOCK_HANDLE_BYTES: u64 = 24;

fn invalid(lock: u64, handle: u64, phase: u64) -> ! {
    unsafe { crate::provider_bugcheck::report(0xc4, [lock, handle, phase, 0]); }
}

/// `VOID KeAcquireInStackQueuedSpinLock(PKSPIN_LOCK, PKLOCK_QUEUE_HANDLE)`.
pub(super) extern "win64" fn acquire(lock: u64, handle: u64) {
    if lock == 0 || handle == 0 || lock & 7 != 0 || handle & 7 != 0
        || lock.checked_add(8).is_none() || handle.checked_add(LOCK_HANDLE_BYTES).is_none()
    { invalid(lock, handle, 1); }
    unsafe {
        if hosted_current_irql() > DISPATCH_LEVEL { invalid(lock, handle, 2); }
        let old_irql = hosted_raise_irql(DISPATCH_LEVEL);
        write_unaligned((handle + LOCK_HANDLE_NEXT_OFF) as *mut u64, 0);
        write_unaligned((handle + LOCK_HANDLE_LOCK_OFF) as *mut u64, lock);
        write_unaligned((handle + LOCK_HANDLE_OLD_IRQL_OFF) as *mut u8, old_irql);
        let word = &*(lock as *const AtomicU64);
        loop {
            match nt_kernel_exec::queued_spin_lock::try_acquire(word, handle) {
                Ok(true) => break,
                Ok(false) => core::hint::spin_loop(),
                Err(_) => invalid(lock, handle, 3),
            }
        }
    }
}

/// `VOID KeReleaseInStackQueuedSpinLock(PKLOCK_QUEUE_HANDLE)`.
pub(super) extern "win64" fn release(handle: u64) {
    if handle == 0 || handle & 7 != 0 || handle.checked_add(LOCK_HANDLE_BYTES).is_none() {
        invalid(0, handle, 4);
    }
    unsafe {
        let lock = read_unaligned((handle + LOCK_HANDLE_LOCK_OFF) as *const u64);
        let old_irql = read_unaligned((handle + LOCK_HANDLE_OLD_IRQL_OFF) as *const u8);
        if lock == 0 || lock & 7 != 0 || old_irql > DISPATCH_LEVEL
            || hosted_current_irql() != DISPATCH_LEVEL
        { invalid(lock, handle, 5); }
        let word = &*(lock as *const AtomicU64);
        if nt_kernel_exec::queued_spin_lock::release(word, handle).is_err() {
            invalid(lock, handle, 6);
        }
        write_unaligned((handle + LOCK_HANDLE_LOCK_OFF) as *mut u64, 0);
        hosted_lower_irql(old_irql);
    }
}
