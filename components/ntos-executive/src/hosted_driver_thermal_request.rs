//! Thermal-request entry points until a processor and policy-device owner exists.

use super::*;

/// `PoCreateThermalRequest` returns a request only after both device owners and
/// the policy engine can retain it. ACPI checks this failure before calling
/// `PoGetThermalRequestSupport` or issuing cooling requests.
pub(super) extern "win64" fn create(
    request_out: u64,
    target_device: u64,
    policy_device: u64,
    reason_context: u64,
    flags: u32,
) -> i32 {
    if request_out == 0 || request_out.checked_add(8).is_none() {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe { write_unaligned(request_out as *mut u64, 0); }
    if target_device == 0 || policy_device == 0 || reason_context == 0 || flags != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_NOT_SUPPORTED
}

/// No thermal-request handle can have been issued while create fails.
pub(super) extern "win64" fn support(request: u64, kind: u32) -> u8 {
    unsafe { crate::provider_bugcheck::report(0xc4, [request, u64::from(kind), 0, 0]); }
}

pub(super) extern "win64" fn set_passive(request: u64, throttle: u8) -> i32 {
    unsafe { crate::provider_bugcheck::report(0xc4, [request, u64::from(throttle), 1, 0]); }
}

pub(super) extern "win64" fn set_active(request: u64, engaged: u8) -> i32 {
    unsafe { crate::provider_bugcheck::report(0xc4, [request, u64::from(engaged), 2, 0]); }
}

pub(super) extern "win64" fn delete(request: u64) {
    unsafe { crate::provider_bugcheck::report(0xc4, [request, 3, 0, 0]); }
}
