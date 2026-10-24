//! `RtlQueryPerformance*` wrappers over the native counter service.

type NtStatus = u32;

fn native_success(status: NtStatus) -> u32 {
    u32::from(status & 0x8000_0000 == 0)
}

fn query_counter_with(
    counter: *mut i64,
    query: impl FnOnce(*mut i64, *mut i64) -> NtStatus,
) -> u32 {
    if counter.is_null() {
        return 0;
    }
    native_success(query(counter, core::ptr::null_mut()))
}

fn query_frequency_with(
    frequency: *mut i64,
    query: impl FnOnce(*mut i64, *mut i64) -> NtStatus,
) -> u32 {
    if frequency.is_null() {
        return 0;
    }
    let mut counter = 0i64;
    native_success(query(&mut counter, frequency))
}

#[cfg(target_arch = "x86_64")]
fn query_native(counter: *mut i64, frequency: *mut i64) -> NtStatus {
    // SAFETY: both outputs follow the native NtQueryPerformanceCounter contract. The frequency
    // output may be null; the counter output is always writable.
    unsafe {
        nt_ntdll::trap_stubs::nt_query_performance_counter(counter as u64, frequency as u64)
            as NtStatus
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn query_native(_counter: *mut i64, _frequency: *mut i64) -> NtStatus {
    0xC000_0002 // STATUS_NOT_IMPLEMENTED: no native transport on this target.
}

/// `RtlQueryPerformanceCounter(PLARGE_INTEGER) -> BOOL`.
///
/// # Safety
/// `counter` must point to a writable `LARGE_INTEGER` when non-null.
#[export_name = "RtlQueryPerformanceCounter"]
pub unsafe extern "system" fn rtl_query_performance_counter(counter: *mut i64) -> u32 {
    query_counter_with(counter, query_native)
}

/// `RtlQueryPerformanceFrequency(PLARGE_INTEGER) -> BOOL`.
///
/// # Safety
/// `frequency` must point to a writable `LARGE_INTEGER` when non-null.
#[export_name = "RtlQueryPerformanceFrequency"]
pub unsafe extern "system" fn rtl_query_performance_frequency(frequency: *mut i64) -> u32 {
    query_frequency_with(frequency, query_native)
}

#[used]
pub static PERFORMANCE_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = performance_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// This routine is only stored in a `#[used]` static.
pub unsafe extern "C" fn performance_export_anchor() {
    core::hint::black_box([
        rtl_query_performance_counter as *const () as usize,
        rtl_query_performance_frequency as *const () as usize,
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_uses_first_native_output_and_reports_nt_success() {
        let mut counter = -1i64;
        let mut called = false;
        let result = query_counter_with(&mut counter, |counter, frequency| {
            called = true;
            assert!(frequency.is_null());
            unsafe { *counter = 42 };
            0
        });
        assert_eq!(result, 1);
        assert!(called);
        assert_eq!(counter, 42);

        assert_eq!(
            query_counter_with(core::ptr::null_mut(), |_, _| panic!("called")),
            0
        );
        assert_eq!(query_counter_with(&mut counter, |_, _| 0xC000_0001), 0);
    }

    #[test]
    fn frequency_uses_second_native_output_and_reports_nt_success() {
        let mut frequency = -1i64;
        let mut called = false;
        let result = query_frequency_with(&mut frequency, |counter, output_frequency| {
            called = true;
            assert!(!counter.is_null());
            unsafe {
                *counter = 10;
                *output_frequency = 3_579_545;
            }
            0
        });
        assert_eq!(result, 1);
        assert!(called);
        assert_eq!(frequency, 3_579_545);

        assert_eq!(
            query_frequency_with(core::ptr::null_mut(), |_, _| panic!("called")),
            0
        );
        assert_eq!(query_frequency_with(&mut frequency, |_, _| 0xC000_0001), 0);
    }
}
