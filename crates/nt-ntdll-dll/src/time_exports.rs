//! Clock exports backed by the mapped NT shared-data page and native system query.

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const DYNAMIC_TIME_ZONE_CLASS: u64 = 102;
const DYNAMIC_TIME_ZONE_SIZE: usize = 432;

fn query_unbiased_with(output: *mut u64, read_clock: impl FnOnce() -> u64) -> u32 {
    if output.is_null() {
        return 0;
    }
    // SAFETY: a non-null caller output points to a writable ULONGLONG.
    unsafe { core::ptr::write(output, read_clock()) };
    1
}

/// `RtlQueryUnbiasedInterruptTime(PULONGLONG) -> BOOL`.
///
/// # Safety
/// `output`, when non-null, points to a writable `ULONGLONG`.
#[export_name = "RtlQueryUnbiasedInterruptTime"]
pub unsafe extern "system" fn rtl_query_unbiased_interrupt_time(output: *mut u64) -> u32 {
    query_unbiased_with(output, native_unbiased_clock)
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
fn native_unbiased_clock() -> u64 {
    // SAFETY: every native user process maps the concurrently published shared-data page.
    unsafe {
        nt_ntdll_layout::kuser::read_ksystem_time(
            0x7ffe_0000 as *const u8,
            nt_ntdll_layout::kuser::INTERRUPT_TIME,
        )
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "windows")))]
fn native_unbiased_clock() -> u64 {
    panic!("RtlQueryUnbiasedInterruptTime requires the native shared-data page")
}

fn query_dynamic_with(output: *mut u8, query: impl FnOnce(*mut u8, usize) -> u32) -> u32 {
    if output.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    query(output, DYNAMIC_TIME_ZONE_SIZE)
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
fn native_dynamic_query(output: *mut u8, size: usize) -> u32 {
    // SAFETY: the caller provides a writable RTL_DYNAMIC_TIME_ZONE_INFORMATION.
    unsafe {
        nt_ntdll::trap_stubs::nt_query_system_information(
            DYNAMIC_TIME_ZONE_CLASS,
            output as u64,
            size as u64,
            0,
        ) as u32
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "windows")))]
fn native_dynamic_query(_output: *mut u8, _size: usize) -> u32 {
    STATUS_NOT_IMPLEMENTED
}

/// `RtlQueryDynamicTimeZoneInformation(PRTL_DYNAMIC_TIME_ZONE_INFORMATION) -> NTSTATUS`.
///
/// # Safety
/// `output`, when non-null, points to a writable 432-byte structure.
#[export_name = "RtlQueryDynamicTimeZoneInformation"]
pub unsafe extern "system" fn rtl_query_dynamic_time_zone_information(output: *mut u8) -> u32 {
    query_dynamic_with(output, native_dynamic_query)
}

#[used]
pub static TIME_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = time_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// Only stored in a `#[used]` static.
pub unsafe extern "C" fn time_export_anchor() {
    core::hint::black_box([
        rtl_query_unbiased_interrupt_time as *const () as usize,
        rtl_query_dynamic_time_zone_information as *const () as usize,
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbiased_clock_requires_output_and_copies_exact_value() {
        assert_eq!(
            query_unbiased_with(core::ptr::null_mut(), || panic!("read")),
            0
        );
        let mut value = 0;
        assert_eq!(query_unbiased_with(&mut value, || 987_654_321), 1);
        assert_eq!(value, 987_654_321);
    }

    #[test]
    fn dynamic_zone_passes_exact_class_size_and_errors() {
        assert_eq!(
            query_dynamic_with(core::ptr::null_mut(), |_, _| panic!("query")),
            STATUS_INVALID_PARAMETER
        );
        let mut zone = [0u8; DYNAMIC_TIME_ZONE_SIZE];
        assert_eq!(
            query_dynamic_with(zone.as_mut_ptr(), |out, size| {
                assert_eq!(out, zone.as_mut_ptr());
                assert_eq!(size, 432);
                0xC000_0003
            }),
            0xC000_0003
        );
    }
}
