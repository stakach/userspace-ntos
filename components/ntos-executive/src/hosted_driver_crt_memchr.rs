//! Driver `memchr` using the same bounded byte search as ntdll.

use super::*;

/// `void *memchr(const void *buffer, int target, size_t count)`.
pub(super) extern "win64" fn memchr(buffer: u64, target: i32, count: usize) -> u64 {
    if count == 0 { return 0; }
    if buffer == 0 || count > isize::MAX as usize
        || buffer.checked_add(count as u64).is_none()
    {
        unsafe { crate::provider_bugcheck::report(0xc4, [buffer, target as u32 as u64, count as u64, 0]); }
    }
    let bytes = unsafe { core::slice::from_raw_parts(buffer as *const u8, count) };
    nt_compat_exports::crt::memchr(bytes, target as u8, count)
        .map(|index| buffer + index as u64)
        .unwrap_or(0)
}
