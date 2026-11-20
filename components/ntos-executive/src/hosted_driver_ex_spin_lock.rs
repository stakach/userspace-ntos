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

// A single hosted logical CPU may need to schedule the current owner before the lock can make
// progress. Yield without clearing this caller's DISPATCH_LEVEL state, as KSPIN_LOCK does.
fn wait() {
    core::hint::spin_loop();
    crate::yield_now();
}

fn acquire_shared(lock: u64) {
    let word = word(lock);
    while !checked(lock, 1, policy::try_acquire_shared(word)) { wait(); }
}

fn acquire_exclusive(lock: u64) {
    let word = word(lock);
    while !checked(lock, 2, policy::try_claim_exclusive(word)) { wait(); }
    while !checked(lock, 3, policy::exclusive_drained(word)) { wait(); }
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
    checked(lock, 8, policy::release_exclusive(word(lock)));
    lower(lock, old_irql, 9);
}

/// `VOID ExReleaseSpinLockExclusiveFromDpcLevel(PEX_SPIN_LOCK)`.
pub(super) extern "win64" fn release_exclusive_from_dpc(lock: u64) {
    require_dispatch(lock, 10);
    checked(lock, 8, policy::release_exclusive(word(lock)));
}

/// `VOID ExReleaseSpinLockShared(PEX_SPIN_LOCK, KIRQL)`.
pub(super) extern "win64" fn release_shared_lower(lock: u64, old_irql: u8) {
    checked(lock, 11, policy::release_shared(word(lock)));
    lower(lock, old_irql, 12);
}

/// `VOID ExReleaseSpinLockSharedFromDpcLevel(PEX_SPIN_LOCK)`.
pub(super) extern "win64" fn release_shared_from_dpc(lock: u64) {
    require_dispatch(lock, 13);
    checked(lock, 11, policy::release_shared(word(lock)));
}

/// `LOGICAL ExTryAcquireSpinLockSharedAtDpcLevel(PEX_SPIN_LOCK)`.
pub(super) extern "win64" fn try_acquire_shared_at_dpc(lock: u64) -> u32 {
    require_dispatch(lock, 14);
    u32::from(checked(lock, 1, policy::try_acquire_shared(word(lock))))
}

/// `LOGICAL ExTryAcquireSpinLockExclusiveAtDpcLevel(PEX_SPIN_LOCK)`.
pub(super) extern "win64" fn try_acquire_exclusive_at_dpc(lock: u64) -> u32 {
    require_dispatch(lock, 15);
    u32::from(checked(lock, 16, policy::try_acquire_exclusive(word(lock))))
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
