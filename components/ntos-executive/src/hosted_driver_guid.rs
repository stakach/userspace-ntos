//! Driver-facing GUID text conversion backed by the shared RTL parser.

use super::*;

/// `NTSTATUS RtlGUIDFromString(PCUNICODE_STRING, GUID*)`.
pub(super) extern "win64" fn guid_from_string(source: u64, guid: u64) -> i32 {
    if source == 0 || guid == 0
        || source.checked_add(16).is_none()
        || guid.checked_add(16).is_none()
    {
        return STATUS_INVALID_PARAMETER;
    }
    let (length, maximum_length, buffer) = unsafe {
        (
            read_unaligned(source as *const u16),
            read_unaligned((source + 2) as *const u16),
            read_unaligned((source + 8) as *const u64),
        )
    };
    if length != 76 || maximum_length < length || buffer == 0
        || buffer.checked_add(length as u64).is_none()
    {
        return STATUS_INVALID_PARAMETER;
    }
    let units = unsafe { core::slice::from_raw_parts(buffer as *const u16, 38) };
    let Some(bytes) = nt_compat_exports::rtl::guid::guid_from_string(units) else {
        return STATUS_INVALID_PARAMETER;
    };
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), guid as *mut u8, 16); }
    STATUS_SUCCESS
}
