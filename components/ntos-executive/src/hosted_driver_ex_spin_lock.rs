//! Hosted driver `EX_SPIN_LOCK` reader/writer exports over the `nt_kernel_exec` word policy.

use super::*;
use core::sync::atomic::AtomicU32;
use nt_kernel_exec::ex_spin_lock as policy;

const BUGCHECK_TAG: u64 = 0x4558_5350; // "EXSP"

fn invalid(lock: u64, detail: u64, phase: u64) -> ! {
    unsafe { crate::provider_bugcheck::report(0xc4, [BUGCHECK_TAG, lock, detail, phase]); }
}

fn word(lock: u64) -> &'static AtomicU32 {
    if lock == 0 || lock & 3 != 0 || lock.checked_add(4).is_none() { invalid(lock, 0, 0); }
    unsafe { &*(lock as *const AtomicU32) }
}

fn checked<T>(lock: u64, phase: u64, result: Result<T, policy::ExSpinLockError>) -> T {
    result.unwrap_or_else(|error| invalid(lock, error as u64, phase))
}

fn require_dispatch(lock: u64, phase: u64) {
    let irql = unsafe { hosted_current_irql() };
    if irql < DISPATCH_LEVEL { invalid(lock, irql as u64, phase); }
}

fn raise(lock: u64, phase: u64) -> u8 {
    let irql = unsafe { hosted_current_irql() };
    if irql > DISPATCH_LEVEL { invalid(lock, irql as u64, phase); }
    unsafe { hosted_raise_irql(DISPATCH_LEVEL) }
}

fn lower(lock: u64, old_irql: u8, phase: u64) {
    let irql = unsafe { hosted_current_irql() };
    if irql < DISPATCH_LEVEL || old_irql > irql { invalid(lock, old_irql as u64, phase); }
    unsafe { hosted_lower_irql(old_irql); }
}

/// A blocked lane never spins on another lane, which may hold the lock while blocked in a root
/// call: it marks WAITERS on the exact word it observed and parks in the root until it changes.
fn wait(lock: u64, observed: u32) {
    match checked(lock, 19, policy::mark_waiting(word(lock), observed)) {
        Some(observed) => hosted_driver_spin_wait::park(lock, u64::from(observed), false, 0),
        None => core::hint::spin_loop(),
    }
}

fn wake_if(lock: u64, wake: bool) {
    if wake { hosted_driver_spin_wait::wake(lock); }
}

fn acquire_shared(lock: u64) {
    let word = word(lock);
    loop {
        let observed = word.load(Ordering::Relaxed);
        if checked(lock, 1, policy::try_acquire_shared(word)) {
            hosted_driver_spin_wait::note_acquired();
            return;
        }
        wait(lock, observed);
    }
}

fn acquire_exclusive(lock: u64) {
    let word = word(lock);
    loop {
        let observed = word.load(Ordering::Relaxed);
        if checked(lock, 2, policy::try_claim_exclusive(word)) { break; }
        wait(lock, observed);
    }
    loop {
        let observed = word.load(Ordering::Relaxed);
        if checked(lock, 3, policy::exclusive_drained(word)) {
            hosted_driver_spin_wait::note_acquired();
            return;
        }
        wait(lock, observed);
    }
}

/// `KIRQL ExAcquireSpinLockExclusive(PEX_SPIN_LOCK)`.
pub(super) extern "win64" fn acquire_exclusive_raise(lock: u64) -> u8 {
    let old = raise(lock, 4);
    acquire_exclusive(lock);
    old
}

/// `VOID ExAcquireSpinLockExclusiveAtDpcLevel(PEX_SPIN_LOCK)`.
pub(super) extern "win64" fn acquire_exclusive_at_dpc(lock: u64) {
    require_dispatch(lock, 5);
    acquire_exclusive(lock);
}

/// `KIRQL ExAcquireSpinLockShared(PEX_SPIN_LOCK)`.
pub(super) extern "win64" fn acquire_shared_raise(lock: u64) -> u8 {
    let old = raise(lock, 6);
    acquire_shared(lock);
    old
}

/// `VOID ExAcquireSpinLockSharedAtDpcLevel(PEX_SPIN_LOCK)`.
pub(super) extern "win64" fn acquire_shared_at_dpc(lock: u64) {
    require_dispatch(lock, 7);
    acquire_shared(lock);
}

/// `VOID ExReleaseSpinLockExclusive(PEX_SPIN_LOCK, KIRQL)`.
pub(super) extern "win64" fn release_exclusive_lower(lock: u64, old_irql: u8) {
    let wake = checked(lock, 8, policy::release_exclusive(word(lock)));
    hosted_driver_spin_wait::note_released(lock);
    lower(lock, old_irql, 9);
    wake_if(lock, wake);
}

/// `VOID ExReleaseSpinLockExclusiveFromDpcLevel(PEX_SPIN_LOCK)`.
pub(super) extern "win64" fn release_exclusive_from_dpc(lock: u64) {
    require_dispatch(lock, 10);
    let wake = checked(lock, 8, policy::release_exclusive(word(lock)));
    hosted_driver_spin_wait::note_released(lock);
    wake_if(lock, wake);
}

/// `VOID ExReleaseSpinLockShared(PEX_SPIN_LOCK, KIRQL)`.
pub(super) extern "win64" fn release_shared_lower(lock: u64, old_irql: u8) {
    let wake = checked(lock, 11, policy::release_shared(word(lock)));
    hosted_driver_spin_wait::note_released(lock);
    lower(lock, old_irql, 12);
    wake_if(lock, wake);
}

/// `VOID ExReleaseSpinLockSharedFromDpcLevel(PEX_SPIN_LOCK)`.
pub(super) extern "win64" fn release_shared_from_dpc(lock: u64) {
    require_dispatch(lock, 13);
    let wake = checked(lock, 11, policy::release_shared(word(lock)));
    hosted_driver_spin_wait::note_released(lock);
    wake_if(lock, wake);
}

/// `LOGICAL ExTryAcquireSpinLockSharedAtDpcLevel(PEX_SPIN_LOCK)`.
pub(super) extern "win64" fn try_acquire_shared_at_dpc(lock: u64) -> u32 {
    require_dispatch(lock, 14);
    let acquired = checked(lock, 1, policy::try_acquire_shared(word(lock)));
    if acquired { hosted_driver_spin_wait::note_acquired(); }
    u32::from(acquired)
}

/// `LOGICAL ExTryAcquireSpinLockExclusiveAtDpcLevel(PEX_SPIN_LOCK)`.
pub(super) extern "win64" fn try_acquire_exclusive_at_dpc(lock: u64) -> u32 {
    require_dispatch(lock, 15);
    let acquired = checked(lock, 16, policy::try_acquire_exclusive(word(lock)));
    if acquired { hosted_driver_spin_wait::note_acquired(); }
    u32::from(acquired)
}

/// `LOGICAL ExTryConvertSharedSpinLockExclusive(PEX_SPIN_LOCK)`.
pub(super) extern "win64" fn try_convert_shared_exclusive(lock: u64) -> u32 {
    require_dispatch(lock, 17);
    u32::from(checked(lock, 18, policy::try_convert_shared_exclusive(word(lock))))
}

pub(super) fn bind(reg: &mut DriverExportRegistry) {
    reg.bind("ExAcquireSpinLockExclusive", acquire_exclusive_raise as *const () as usize as u64);
    reg.bind("ExAcquireSpinLockExclusiveAtDpcLevel", acquire_exclusive_at_dpc as *const () as usize as u64);
    reg.bind("ExAcquireSpinLockShared", acquire_shared_raise as *const () as usize as u64);
    reg.bind("ExAcquireSpinLockSharedAtDpcLevel", acquire_shared_at_dpc as *const () as usize as u64);
    reg.bind("ExReleaseSpinLockExclusive", release_exclusive_lower as *const () as usize as u64);
    reg.bind("ExReleaseSpinLockExclusiveFromDpcLevel", release_exclusive_from_dpc as *const () as usize as u64);
    reg.bind("ExReleaseSpinLockShared", release_shared_lower as *const () as usize as u64);
    reg.bind("ExReleaseSpinLockSharedFromDpcLevel", release_shared_from_dpc as *const () as usize as u64);
    reg.bind("ExTryAcquireSpinLockSharedAtDpcLevel", try_acquire_shared_at_dpc as *const () as usize as u64);
    reg.bind("ExTryAcquireSpinLockExclusiveAtDpcLevel", try_acquire_exclusive_at_dpc as *const () as usize as u64);
    reg.bind("ExTryConvertSharedSpinLockExclusive", try_convert_shared_exclusive as *const () as usize as u64);
}
