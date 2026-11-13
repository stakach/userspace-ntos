//! Driver-neutral native RTL contracts needed by storage class drivers.
//!
//! The generic driver export registry binds these functions. Its pool owner
//! supplies the allocation callback for `RtlStringFromGUID`; the resulting
//! buffer is compatible with that owner's `RtlFreeUnicodeString`.

use core::ptr::{read_unaligned, write_unaligned};
use nt_compat_exports::rtl::classpnp::{
    format_guid_utf16, write_version_info, GUID_STRING_CAPACITY_BYTES,
    GUID_STRING_LENGTH_BYTES, VERSION_INFO_BASE_BYTES, VERSION_INFO_EXTENDED_BYTES,
};

const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_NO_MEMORY: i32 = 0xC000_0017u32 as i32;

/// `NTSTATUS RtlGetVersion(PRTL_OSVERSIONINFOW)`.
///
/// A bad size is rejected before forming a slice or writing past the caller's
/// declared layout. The size itself must be readable at the supplied pointer.
pub extern "win64" fn rtl_get_version(version_information: *mut u8) -> i32 {
    if version_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let size = unsafe { read_unaligned(version_information as *const u32) } as usize;
    if !matches!(size, VERSION_INFO_BASE_BYTES | VERSION_INFO_EXTENDED_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    let output = unsafe { core::slice::from_raw_parts_mut(version_information, size) };
    if write_version_info(output).is_some() {
        0
    } else {
        STATUS_INVALID_PARAMETER
    }
}

/// `NTSTATUS RtlStringFromGUID(REFGUID, PUNICODE_STRING)`.
///
/// `allocate` must return memory owned by the same native pool used by the
/// caller's `RtlFreeUnicodeString`. On success, `Buffer` is owned by the caller.
///
/// # Safety
/// Both non-null pointers must name writable/readable native guest memory of
/// their declared sizes, and `allocate` must return at least 78 writable bytes.
pub unsafe fn rtl_string_from_guid_with_pool(
    guid: *const u8,
    output: *mut u8,
    allocate: impl FnOnce(u64) -> u64,
) -> i32 {
    if guid.is_null() || output.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let guid_bytes = unsafe { read_unaligned(guid as *const [u8; 16]) };
    let units = format_guid_utf16(&guid_bytes);
    let buffer = allocate(GUID_STRING_CAPACITY_BYTES as u64);
    if buffer == 0 {
        return STATUS_NO_MEMORY;
    }
    for (index, unit) in units.into_iter().enumerate() {
        unsafe { write_unaligned((buffer + (index * 2) as u64) as *mut u16, unit) };
    }
    unsafe {
        write_unaligned(output as *mut u16, GUID_STRING_LENGTH_BYTES);
        write_unaligned(output.add(2) as *mut u16, GUID_STRING_CAPACITY_BYTES);
        write_unaligned(output.add(8) as *mut u64, buffer);
    }
    0
}
