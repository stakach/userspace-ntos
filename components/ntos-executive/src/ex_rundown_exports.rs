//! Native `EX_RUNDOWN_REF` exports shared by win32k and hosted driver domains.
//!
//! These direct VAs execute inside the caller's isolated component VSpace. `RunRef` therefore
//! addresses the provider's own descriptor, and the wait block stays on that component's stack
//! until every holder has released it. No provider pointer crosses executive IPC.

use nt_compat_exports::DriverExportRegistry;
use nt_kernel_exec::{ExCacheAwareRundownRef, ExRundownRef, ExRundownWaitBlock};

const CACHE_AWARE_ALIGNMENT: usize = 64;

fn cache_aware_processor_count() -> usize {
    let count = crate::SYSTEM_PROCESSOR_COUNT.load(core::sync::atomic::Ordering::Acquire) as usize;
    assert!((1..=64).contains(&count), "invalid cache-aware rundown processor count");
    count
}

pub(crate) extern "win64" fn ex_size_of_rundown_protection_cache_aware() -> usize {
    ExCacheAwareRundownRef::required_size(cache_aware_processor_count(), CACHE_AWARE_ALIGNMENT)
        .expect("cache-aware rundown size overflow")
}

pub(crate) extern "win64" fn ex_initialize_rundown_protection_cache_aware(
    run_ref: *mut ExCacheAwareRundownRef,
    size: usize,
) {
    assert!(unsafe { ExCacheAwareRundownRef::initialize_in_place(
        run_ref, size, cache_aware_processor_count(), CACHE_AWARE_ALIGNMENT,
    ) }, "invalid cache-aware rundown allocation");
}

pub(crate) extern "win64" fn ex_acquire_rundown_protection_cache_aware(
    run_ref: *const ExCacheAwareRundownRef,
) -> u8 {
    assert!(!run_ref.is_null(), "ExAcquireRundownProtectionCacheAware null descriptor");
    let processor = crate::driver_launch::current_processor_index();
    unsafe { (&*run_ref).acquire(processor) as u8 }
}

pub(crate) extern "win64" fn ex_release_rundown_protection_cache_aware(
    run_ref: *const ExCacheAwareRundownRef,
) {
    assert!(!run_ref.is_null(), "ExReleaseRundownProtectionCacheAware null descriptor");
    let processor = crate::driver_launch::current_processor_index();
    unsafe { (&*run_ref).release(processor) };
}

pub(crate) extern "win64" fn ex_wait_for_rundown_protection_release_cache_aware(
    run_ref: *const ExCacheAwareRundownRef,
) {
    assert!(!run_ref.is_null(), "ExWaitForRundownProtectionReleaseCacheAware null descriptor");
    unsafe { (&*run_ref).wait_for_release_with(crate::yield_now) };
}

pub(crate) extern "win64" fn ex_reinitialize_rundown_protection_cache_aware(
    run_ref: *const ExCacheAwareRundownRef,
) {
    assert!(!run_ref.is_null(), "ExReInitializeRundownProtectionCacheAware null descriptor");
    assert!(unsafe { (&*run_ref).reinitialize() },
        "ExReInitializeRundownProtectionCacheAware requires completed rundown");
}

pub(crate) extern "win64" fn ex_acquire_rundown_protection(run_ref: *const ExRundownRef) -> u8 {
    assert!(!run_ref.is_null(), "ExAcquireRundownProtection null descriptor");
    unsafe { (&*run_ref).acquire() as u8 }
}

pub(crate) extern "win64" fn ex_initialize_rundown_protection(run_ref: *const ExRundownRef) {
    assert!(!run_ref.is_null(), "ExInitializeRundownProtection null descriptor");
    unsafe { (&*run_ref).initialize() }
}

pub(crate) extern "win64" fn ex_reinitialize_rundown_protection(run_ref: *const ExRundownRef) {
    assert!(!run_ref.is_null(), "ExReInitializeRundownProtection null descriptor");
    assert!(unsafe { (&*run_ref).reinitialize() }, "ExReInitializeRundownProtection requires completed rundown");
}

pub(crate) extern "win64" fn ex_release_rundown_protection(run_ref: *const ExRundownRef) {
    assert!(!run_ref.is_null(), "ExReleaseRundownProtection null descriptor");
    let _ = unsafe { (&*run_ref).release() };
}

pub(crate) extern "win64" fn ex_wait_for_rundown_protection_release(run_ref: *const ExRundownRef) {
    assert!(!run_ref.is_null(), "ExWaitForRundownProtectionRelease null descriptor");
    let reference = unsafe { &*run_ref };
    let waiter = ExRundownWaitBlock::new();
    if unsafe { reference.begin_wait(&waiter) } {
        while waiter.remaining() != 0 {
            crate::yield_now();
        }
        unsafe { reference.finish_wait(&waiter) };
    }
}

pub(crate) fn bind_ex_rundown_exports(reg: &mut DriverExportRegistry) {
    reg.bind("ExAcquireRundownProtectionCacheAware", ex_acquire_rundown_protection_cache_aware as usize as u64);
    reg.bind("ExInitializeRundownProtectionCacheAware", ex_initialize_rundown_protection_cache_aware as usize as u64);
    reg.bind("ExReInitializeRundownProtectionCacheAware", ex_reinitialize_rundown_protection_cache_aware as usize as u64);
    reg.bind("ExReleaseRundownProtectionCacheAware", ex_release_rundown_protection_cache_aware as usize as u64);
    reg.bind("ExSizeOfRundownProtectionCacheAware", ex_size_of_rundown_protection_cache_aware as usize as u64);
    reg.bind("ExWaitForRundownProtectionReleaseCacheAware", ex_wait_for_rundown_protection_release_cache_aware as usize as u64);
    reg.bind("ExAcquireRundownProtection", ex_acquire_rundown_protection as usize as u64);
    reg.bind("ExInitializeRundownProtection", ex_initialize_rundown_protection as usize as u64);
    reg.bind("ExReInitializeRundownProtection", ex_reinitialize_rundown_protection as usize as u64);
    reg.bind("ExReleaseRundownProtection", ex_release_rundown_protection as usize as u64);
    reg.bind("ExWaitForRundownProtectionRelease", ex_wait_for_rundown_protection_release as usize as u64);
}
