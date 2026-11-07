//! Precise system-time query through the native clock service.

fn query_with(query: impl FnOnce(*mut i64) -> u32) -> Result<i64, u32> {
    let mut time = 0i64;
    let status = query(&mut time);
    if status & 0x8000_0000 == 0 {
        Ok(time)
    } else {
        Err(status)
    }
}

#[cfg(target_arch = "x86_64")]
fn query_native(output: *mut i64) -> u32 {
    // SAFETY: output is a writable local LARGE_INTEGER for the duration of the syscall.
    unsafe { nt_ntdll::trap_stubs::nt_query_system_time(output as u64) as u32 }
}

#[cfg(not(target_arch = "x86_64"))]
fn query_native(_output: *mut i64) -> u32 {
    0xC000_0002 // STATUS_NOT_IMPLEMENTED without a native transport.
}

/// `RtlGetSystemTimePrecise() -> LONGLONG` in NT 100 ns units.
#[export_name = "RtlGetSystemTimePrecise"]
pub extern "system" fn rtl_get_system_time_precise() -> i64 {
    match query_with(query_native) {
        Ok(time) => time,
        Err(status) => {
            // This value-returning API cannot encode an NTSTATUS. Raise the
            // exact failure rather than returning a fabricated clock value.
            // SAFETY: the live SEH dispatcher owns the raised status.
            unsafe { crate::exports::rtl_raise_status(status) };
            loop { core::hint::spin_loop(); }
        }
    }
}

#[used]
pub static SYSTEM_TIME_PRECISE_EXPORT_ANCHOR_FN: unsafe extern "C" fn() =
    system_time_precise_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// Only stored in a `#[used]` static.
pub unsafe extern "C" fn system_time_precise_export_anchor() {
    core::hint::black_box(rtl_get_system_time_precise as *const () as usize);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_native_100ns_clock_and_preserves_errors() {
        assert_eq!(query_with(|out| { unsafe { *out = 1337 }; 0 }), Ok(1337));
        assert_eq!(query_with(|_| 0xC000_0005), Err(0xC000_0005));
    }
}
