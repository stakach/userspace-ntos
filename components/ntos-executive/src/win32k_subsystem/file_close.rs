//! Retained native FILE-handle close from win32k's authenticated syscall lane.

use super::*;

pub(super) unsafe fn close(handle: u64) -> i32 {
    let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
        (W32_FILE_CLOSE_LABEL << 12) | 4,
        handle,
        0,
        0,
        0,
    );
    let canonical_status = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
    if words != 1 || !canonical_status {
        crate::provider_bugcheck::report(0xc4, [W32_FILE_CLOSE_LABEL, handle, words, raw]);
    }
    raw as u32 as i32
}
