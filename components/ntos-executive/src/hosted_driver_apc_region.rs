//! APC region operations for the authenticated current hosted driver thread.
//!
//! `PsGetCurrentThread` resolves and maps the canonical ETHREAD for this physical
//! caller. The shared executive-sync contract mutates its native KTHREAD APC fields;
//! an unmatched leave or overflow is a driver contract violation, never success.

use super::*;

fn current_thread() -> *mut u8 {
    s_current_thread() as *mut u8
}

fn reject(operation: u64, thread: *mut u8) -> ! {
    unsafe {
        crate::provider_bugcheck::report(
            0xc4,
            [FSD_SERVICE_PS_GET_CURRENT_THREAD_ID_LABEL, operation, thread as u64, 0],
        )
    }
}

/// `VOID KeEnterCriticalRegion(VOID)`.
extern "win64" fn enter_critical_region() {
    let thread = current_thread();
    if unsafe { nt_kernel_exec::executive_sync::enter_critical_region(thread) }.is_err() {
        reject(1, thread);
    }
}

/// `VOID KeLeaveCriticalRegion(VOID)`.
extern "win64" fn leave_critical_region() {
    let thread = current_thread();
    if unsafe { nt_kernel_exec::executive_sync::leave_critical_region(thread) }.is_err() {
        reject(2, thread);
    }
}

/// `VOID KeEnterGuardedRegion(VOID)`.
extern "win64" fn enter_guarded_region() {
    let thread = current_thread();
    if unsafe { nt_kernel_exec::executive_sync::enter_guarded_region(thread) }.is_err() {
        reject(3, thread);
    }
}

/// `VOID KeLeaveGuardedRegion(VOID)`.
extern "win64" fn leave_guarded_region() {
    let thread = current_thread();
    if unsafe { nt_kernel_exec::executive_sync::leave_guarded_region(thread) }.is_err() {
        reject(4, thread);
    }
}

pub(super) fn bind(reg: &mut DriverExportRegistry) {
    reg.bind("KeEnterCriticalRegion", enter_critical_region as usize as u64);
    reg.bind("KeLeaveCriticalRegion", leave_critical_region as usize as u64);
    reg.bind("KeEnterGuardedRegion", enter_guarded_region as usize as u64);
    reg.bind("KeLeaveGuardedRegion", leave_guarded_region as usize as u64);
}
