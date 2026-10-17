//! Released ntdll UTF-8 descriptor, clock, and security-status entries.

use nt_ntdll_layout::UnicodeString;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_NAME_TOO_LONG: u32 = 0xC000_0106;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

/// Initialize a counted UTF-8 descriptor. The source remains caller-owned.
///
/// # Safety
/// `destination` is writable and `source` is null or NUL-terminated.
#[export_name = "RtlInitUTF8String"]
pub unsafe extern "system" fn rtl_init_utf8_string(
    destination: *mut UnicodeString,
    source: *const u8,
) {
    if destination.is_null() {
        return;
    }
    let mut length = 0usize;
    if !source.is_null() {
        // The plain initializer saturates at the largest representable counted string,
        // matching the existing RtlInitAnsiString behavior without wrapping a USHORT.
        while length < u16::MAX as usize - 1 && unsafe { *source.add(length) } != 0 {
            length += 1;
        }
    }
    unsafe {
        (*destination).length = length as u16;
        (*destination).maximum_length = if source.is_null() {
            0
        } else {
            length as u16 + 1
        };
        (*destination).buffer = source as u64;
    }
}

/// Convert a counted UTF-8 string into a terminated UTF-16 string.
///
/// # Safety
/// Descriptors and their referenced buffers meet the `RtlUTF8StringToUnicodeString` ABI.
#[export_name = "RtlUTF8StringToUnicodeString"]
pub unsafe extern "system" fn rtl_utf8_string_to_unicode_string(
    destination: *mut UnicodeString,
    source: *const UnicodeString,
    allocate: u8,
) -> u32 {
    if destination.is_null() || source.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let source = unsafe { &*source };
    if source.length != 0 && source.buffer == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if source.length > source.maximum_length {
        return STATUS_INVALID_PARAMETER;
    }
    let mut required = 0u32;
    // RtlUTF8ToUnicodeN computes the UTF-16 byte count when its destination is null.
    let status = if source.length == 0 {
        STATUS_SUCCESS
    } else {
        unsafe {
            crate::exports::rtl_utf8_to_unicode_n(
                core::ptr::null_mut(),
                0,
                &mut required,
                source.buffer as *const u8,
                source.length as u32,
            )
        }
    };
    if status & 0x8000_0000 != 0 {
        return status;
    }
    let Some(capacity) = required.checked_add(2) else {
        return STATUS_NAME_TOO_LONG;
    };
    if capacity > u16::MAX as u32 {
        return STATUS_NAME_TOO_LONG;
    }
    let output = unsafe { &mut *destination };
    let buffer = if allocate != 0 {
        #[cfg(target_arch = "x86_64")]
        {
            let ptr = unsafe { crate::process_heap_alloc(capacity as usize) };
            if ptr.is_null() {
                return STATUS_NO_MEMORY;
            }
            ptr as *mut u16
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            return STATUS_NOT_IMPLEMENTED;
        }
    } else {
        if output.maximum_length < capacity as u16 || output.buffer == 0 {
            return STATUS_BUFFER_TOO_SMALL;
        }
        output.buffer as *mut u16
    };
    let mut written = 0u32;
    let conversion_status = if source.length == 0 {
        STATUS_SUCCESS
    } else {
        unsafe {
            crate::exports::rtl_utf8_to_unicode_n(
                buffer,
                required,
                &mut written,
                source.buffer as *const u8,
                source.length as u32,
            )
        }
    };
    if conversion_status & 0x8000_0000 != 0 {
        if allocate != 0 {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                crate::process_heap_free(buffer as *mut u8);
            }
        }
        return conversion_status;
    }
    unsafe { core::ptr::write(buffer.add((written / 2) as usize), 0) };
    output.length = written as u16;
    if allocate != 0 {
        output.maximum_length = capacity as u16;
        output.buffer = buffer as u64;
    }
    conversion_status
}

fn query_system_time_with(output: *mut i64, query: impl FnOnce(*mut i64) -> u32) -> u32 {
    if output.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let mut value = 0i64;
    let status = query(&mut value);
    if status & 0x8000_0000 == 0 {
        unsafe { core::ptr::write(output, value) };
    }
    status
}

/// `RtlQuerySystemTime(PLARGE_INTEGER)` returns the native 100 ns clock query status.
///
/// # Safety
/// `output` is writable for one LARGE_INTEGER.
#[export_name = "RtlQuerySystemTime"]
pub unsafe extern "system" fn rtl_query_system_time(output: *mut i64) -> u32 {
    query_system_time_with(output, |value| {
        #[cfg(target_arch = "x86_64")]
        {
            unsafe { nt_ntdll::trap_stubs::nt_query_system_time(value as u64) as u32 }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = value;
            STATUS_NOT_IMPLEMENTED
        }
    })
}

/// The released alias has the same `PLARGE_INTEGER, PTIME_FIELDS` ABI as
/// `RtlTimeToTimeFields` and shares its calendar conversion.
///
/// # Safety
/// `time` and `fields` meet the `RtlTimeToTimeFields` contract.
#[export_name = "RtlSystemTimeToTimeFields"]
pub unsafe extern "system" fn rtl_system_time_to_time_fields(time: *const i64, fields: *mut i16) {
    unsafe { crate::exports::rtl_time_to_time_fields(time, fields) }
}

/// ReactOS leaves this SSPI security-status mapping unimplemented. Preserve
/// success exactly; fail closed for mappings without a verified NT equivalent.
#[export_name = "RtlMapSecurityErrorToNtStatus"]
pub extern "system" fn rtl_map_security_error_to_nt_status(error: u32) -> u32 {
    if error == 0 {
        STATUS_SUCCESS
    } else {
        STATUS_NOT_IMPLEMENTED
    }
}

#[used]
pub static MISC_RTL_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = misc_rtl_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// Only stored in a `#[used]` static.
pub unsafe extern "C" fn misc_rtl_export_anchor() {
    core::hint::black_box([
        rtl_init_utf8_string as *const () as usize,
        rtl_utf8_string_to_unicode_string as *const () as usize,
        rtl_query_system_time as *const () as usize,
        rtl_system_time_to_time_fields as *const () as usize,
        rtl_map_security_error_to_nt_status as *const () as usize,
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_descriptor_counts_bytes_and_keeps_source_pointer() {
        let source = b"caf\xc3\xa9\0";
        let mut descriptor = UnicodeString::default();
        unsafe { rtl_init_utf8_string(&mut descriptor, source.as_ptr()) };
        assert_eq!(descriptor.length, 5);
        assert_eq!(descriptor.maximum_length, 6);
        assert_eq!(descriptor.buffer, source.as_ptr() as u64);
        unsafe { rtl_init_utf8_string(&mut descriptor, core::ptr::null()) };
        assert_eq!(
            (
                descriptor.length,
                descriptor.maximum_length,
                descriptor.buffer
            ),
            (0, 0, 0)
        );
    }

    #[test]
    fn utf8_conversion_counts_utf16_bytes_and_terminator() {
        let source = b"a\xf0\x9f\x98\x80";
        let mut input = UnicodeString::default();
        input.length = 5;
        input.maximum_length = 5;
        input.buffer = source.as_ptr() as u64;
        let mut units = [0u16; 4];
        let mut output = UnicodeString::default();
        output.maximum_length = 8;
        output.buffer = units.as_mut_ptr() as u64;
        let status = unsafe { rtl_utf8_string_to_unicode_string(&mut output, &input, 0) };
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(output.length, 6);
        assert_eq!(units, [b'a' as u16, 0xd83d, 0xde00, 0]);
    }

    #[test]
    fn utf8_conversion_rejects_short_output_without_writing() {
        let source = b"ab";
        let mut input = UnicodeString::default();
        input.length = 2;
        input.maximum_length = 2;
        input.buffer = source.as_ptr() as u64;
        let mut units = [0xa5a5u16; 2];
        let mut output = UnicodeString::default();
        output.maximum_length = 4;
        output.buffer = units.as_mut_ptr() as u64;
        let status = unsafe { rtl_utf8_string_to_unicode_string(&mut output, &input, 0) };
        assert_eq!(status, STATUS_BUFFER_TOO_SMALL);
        assert_eq!(units, [0xa5a5; 2]);
    }

    #[test]
    fn empty_utf8_source_produces_terminated_empty_unicode() {
        let input = UnicodeString::default();
        let mut unit = 0xa5a5u16;
        let mut output = UnicodeString::default();
        output.maximum_length = 2;
        output.buffer = (&mut unit as *mut u16) as u64;
        assert_eq!(
            unsafe { rtl_utf8_string_to_unicode_string(&mut output, &input, 0) },
            STATUS_SUCCESS
        );
        assert_eq!(output.length, 0);
        assert_eq!(unit, 0);
    }

    #[test]
    fn unknown_security_error_fails_closed() {
        assert_eq!(rtl_map_security_error_to_nt_status(0), STATUS_SUCCESS);
        assert_eq!(
            rtl_map_security_error_to_nt_status(0x8009_0308),
            STATUS_NOT_IMPLEMENTED
        );
    }

    #[test]
    fn clock_query_propagates_status_and_does_not_publish_failure_value() {
        let mut output = 42;
        assert_eq!(
            query_system_time_with(&mut output, |_| 0xC000_0005),
            0xC000_0005
        );
        assert_eq!(output, 42);
        assert_eq!(
            query_system_time_with(&mut output, |out| {
                unsafe { *out = 99 };
                0
            }),
            0
        );
        assert_eq!(output, 99);
    }
}
