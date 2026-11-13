//! Driver `strchr` using the same C-string search as ntdll.

use super::*;

const MAX_CSTRING_BYTES: usize = 4096;

/// `char *strchr(const char *string, int character)`.
pub(super) extern "win64" fn strchr(string: u64, character: i32) -> u64 {
    if string == 0 {
        unsafe { crate::provider_bugcheck::report(0xc4, [string, character as u32 as u64, 0, 0]); }
    }
    for length in 0..MAX_CSTRING_BYTES {
        let Some(address) = string.checked_add(length as u64) else {
            unsafe { crate::provider_bugcheck::report(0xc4, [string, character as u32 as u64, length as u64, 1]); }
        };
        // The ABI requires a readable, terminated C string. Stop at its first NUL so the
        // adapter never reads past the caller's string allocation.
        if unsafe { *(address as *const u8) } == 0 {
            let bytes = unsafe { core::slice::from_raw_parts(string as *const u8, length + 1) };
            return nt_compat_exports::crt::strchr(bytes, character as u8)
                .map(|index| string + index as u64)
                .unwrap_or(0);
        }
    }
    unsafe { crate::provider_bugcheck::report(0xc4, [string, character as u32 as u64, MAX_CSTRING_BYTES as u64, 2]); }
}
