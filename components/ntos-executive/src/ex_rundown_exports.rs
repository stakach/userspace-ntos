//! Native `EX_RUNDOWN_REF` exports shared by win32k and hosted driver domains.
//!
//! These direct VAs execute inside the caller's isolated component VSpace. `RunRef` therefore
//! addresses the provider's own descriptor, and the wait block stays on that component's stack
//! until every holder has released it. No provider pointer crosses executive IPC.

use nt_compat_exports::DriverExportRegistry;
use nt_kernel_exec::{ExCacheAwareRundownRef, ExRundownExport, ExRundownRef};

const CACHE_AWARE_ALIGNMENT: usize = 64;

/// The caller domain's own `KeDelayExecutionThread`. A rundown wait sleeps through it between
/// observations, so root sees a timed wait instead of an endless yield (#394).
pub(crate) trait RundownWaitDelay {
    /// One relative wait of [`RUNDOWN_WAIT_POLL_100NS`].
    fn delay();
}

/// The release poll interval: 1 ms, NT's timer resolution.
pub(crate) const RUNDOWN_WAIT_POLL_100NS: i64 = 10_000;

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

pub(crate) extern "win64" fn ex_wait_for_rundown_protection_release_cache_aware<D: RundownWaitDelay>(
    run_ref: *const ExCacheAwareRundownRef,
) {
    assert!(!run_ref.is_null(), "ExWaitForRundownProtectionReleaseCacheAware null descriptor");
    unsafe { (&*run_ref).wait_for_release_with(D::delay) };
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

pub(crate) extern "win64" fn ex_wait_for_rundown_protection_release<D: RundownWaitDelay>(
    run_ref: *const ExRundownRef,
) {
    assert!(!run_ref.is_null(), "ExWaitForRundownProtectionRelease null descriptor");
    unsafe { (&*run_ref).wait_for_release_with(D::delay) };
}

/// Bind every [`ExRundownExport`]; the exhaustive match keeps names and implementations paired.
pub(crate) fn bind_ex_rundown_exports<D: RundownWaitDelay>(reg: &mut DriverExportRegistry) {
    for export in ExRundownExport::ALL {
        let va = match export {
            ExRundownExport::AcquireCacheAware => ex_acquire_rundown_protection_cache_aware as *const (),
            ExRundownExport::InitializeCacheAware => ex_initialize_rundown_protection_cache_aware as *const (),
            ExRundownExport::ReInitializeCacheAware => ex_reinitialize_rundown_protection_cache_aware as *const (),
            ExRundownExport::ReleaseCacheAware => ex_release_rundown_protection_cache_aware as *const (),
            ExRundownExport::SizeOfCacheAware => ex_size_of_rundown_protection_cache_aware as *const (),
            ExRundownExport::WaitForReleaseCacheAware =>
                ex_wait_for_rundown_protection_release_cache_aware::<D> as *const (),
            ExRundownExport::Acquire => ex_acquire_rundown_protection as *const (),
            ExRundownExport::Initialize => ex_initialize_rundown_protection as *const (),
            ExRundownExport::ReInitialize => ex_reinitialize_rundown_protection as *const (),
            ExRundownExport::Release => ex_release_rundown_protection as *const (),
            ExRundownExport::WaitForRelease => ex_wait_for_rundown_protection_release::<D> as *const (),
        };
        reg.bind(export.name(), va as usize as u64);
    }
}
