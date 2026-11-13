//! Kernel `RtlCharToInteger` using the same pure grammar as ntdll.

use super::*;

const MAX_CSTRING_BYTES: usize = 4096;

/// `NTSTATUS RtlCharToInteger(PCSZ, ULONG, PULONG)`.
pub(super) extern "win64" fn char_to_integer(string: u64, base: u32, value: u64) -> i32 {
    if string == 0 { return STATUS_INVALID_PARAMETER; }
    let mut len = 0usize;
    while len < MAX_CSTRING_BYTES {
        let byte = unsafe { read_volatile((string + len as u64) as *const u8) };
        if byte == 0 { break; }
        len += 1;
    }
    if len == MAX_CSTRING_BYTES { return STATUS_INVALID_PARAMETER; }
    let bytes = unsafe { core::slice::from_raw_parts(string as *const u8, len) };
    let Some(parsed) = nt_compat_exports::rtl::char_to_integer(bytes, base) else {
        return STATUS_INVALID_PARAMETER;
    };
    if value == 0 { return STATUS_ACCESS_VIOLATION; }
    unsafe { write_unaligned(value as *mut u32, parsed); }
    STATUS_SUCCESS
}
