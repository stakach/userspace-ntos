//! Kernel-mode cancellation of this win32k thread's routed File I/O.

use super::*;

pub(super) extern "win64" fn cancel_io_file(handle: u64, iosb: u64) -> i32 {
    if iosb == 0 || iosb.checked_add(16).is_none() {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    let (words, raw, _, _, _) = unsafe {
        crate::driver_launch::call_on4_raw((W32_FILE_CANCEL_LABEL << 12) | 4, handle, 0, 0, 0)
    };
    if words != 1 || (raw != raw as u32 as u64 && raw != raw as u32 as i32 as i64 as u64) {
        unsafe {
            crate::provider_bugcheck::report(0xc4, [W32_FILE_CANCEL_LABEL, handle, words, raw])
        }
    }
    let status = raw as u32 as i32;
    unsafe { file_read::release_completed_for_handle(handle) };
    unsafe { file_ioctl::release_completed_for_handle(handle) };
    if status == 0 {
        unsafe {
            write_unaligned(iosb as *mut u32, 0);
            write_unaligned((iosb + 8) as *mut u64, 0);
        }
    }
    status
}
