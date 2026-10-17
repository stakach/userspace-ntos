//! Native `EX_RUNDOWN_REF` exports shared by win32k and hosted driver domains.
//!
//! These direct VAs execute inside the caller's isolated component VSpace. `RunRef` therefore
//! addresses the provider's own descriptor, and the wait block stays on that component's stack
//! until every holder has released it. No provider pointer crosses executive IPC.

use nt_compat_exports::DriverExportRegistry;
use nt_kernel_exec::{ExRundownRef, ExRundownWaitBlock};

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
    reg.bind("ExAcquireRundownProtection", ex_acquire_rundown_protection as usize as u64);
    reg.bind("ExInitializeRundownProtection", ex_initialize_rundown_protection as usize as u64);
    reg.bind("ExReInitializeRundownProtection", ex_reinitialize_rundown_protection as usize as u64);
    reg.bind("ExReleaseRundownProtection", ex_release_rundown_protection as usize as u64);
    reg.bind("ExWaitForRundownProtectionRelease", ex_wait_for_rundown_protection_release as usize as u64);
}
